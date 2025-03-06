```diff
diff --git a/.github/workflows/build-and-run-tests.yml b/.github/workflows/build-and-run-tests.yml
index 8e286db..b6ed7a5 100644
--- a/.github/workflows/build-and-run-tests.yml
+++ b/.github/workflows/build-and-run-tests.yml
@@ -96,3 +96,6 @@ jobs:
         cmake -S c_api_tests -B c_build_gav1
         make -C c_build_gav1
         ctest --test-dir c_build_gav1 -E conformance_tests
+
+    - name: Build and run the heic tests with heic feature enabled
+      run: cargo test --no-default-features --features heic heic
diff --git a/.github/workflows/toml-formatter.yml b/.github/workflows/toml-formatter.yml
new file mode 100644
index 0000000..1b238be
--- /dev/null
+++ b/.github/workflows/toml-formatter.yml
@@ -0,0 +1,24 @@
+name: TOML Formatter
+on:
+  push:
+    branches:
+      - main
+  pull_request:
+
+permissions:
+  contents: read
+
+# Cancel the workflow if a new one is triggered from the same PR, branch, or tag, except on main.
+concurrency:
+  group: ${{ github.workflow }}-${{ github.ref }}
+  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
+
+jobs:
+  toml-formatter:
+    name: "TOML Formatter"
+    runs-on: ubuntu-latest
+
+    steps:
+    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
+    - uses: uncenter/setup-taplo@v1
+    - run: taplo fmt --check
diff --git a/Android.bp b/Android.bp
index 4aaa232..d86eff2 100644
--- a/Android.bp
+++ b/Android.bp
@@ -10,12 +10,28 @@ license {
     ],
 }
 
+rust_bindgen {
+    name: "libcrabbyavif_mediaimage2_bindgen",
+    crate_name: "crabbyavif_mediaimage2_bindgen",
+    wrapper_src: "sys/ndk-sys/mediaimage2_wrapper.hpp",
+    source_stem: "mediaimage2_bindgen",
+    header_libs: [
+        "media_plugin_headers",
+    ],
+    bindgen_flags: [
+        "--allowlist-item=android::MediaImage2?",
+        "--no-recursive-allowlist",
+        "--no-layout-tests",
+        "--no-doc-comments",
+    ],
+}
+
 rust_bindgen {
     name: "libcrabbyavif_ndk_bindgen",
     crate_name: "crabbyavif_ndk_bindgen",
     wrapper_src: "sys/ndk-sys/wrapper.h",
     source_stem: "ndk_media_bindgen",
-    shared_libs: [
+    header_libs: [
         "libmediandk",
     ],
     bindgen_flags: [
@@ -23,7 +39,7 @@ rust_bindgen {
     ],
 }
 
-rust_library_rlib {
+rust_library {
     name: "libndk_sys",
     crate_name: "ndk_sys",
     cargo_env_compat: true,
@@ -45,12 +61,12 @@ rust_bindgen {
     source_stem: "libyuv_bindgen",
     product_available: true,
     vendor_available: true,
-    whole_static_libs: [
+    header_libs: [
         "libyuv",
     ],
 }
 
-rust_library_rlib {
+rust_library {
     name: "liblibyuv_sys",
     crate_name: "libyuv_sys",
     cargo_env_compat: true,
@@ -65,24 +81,31 @@ rust_library_rlib {
     ],
 }
 
-rust_ffi {
+rust_ffi_static {
     name: "libcrabbyavif_ffi",
     crate_name: "crabbyavif",
     cargo_env_compat: true,
     cargo_pkg_version: "0.1.0",
-    srcs: ["src/lib.rs"],
+    srcs: [
+        "src/lib.rs",
+        ":libcrabbyavif_mediaimage2_bindgen",
+    ],
     cfgs: ["android_soong"],
     edition: "2021",
     features: [
         "android_mediacodec",
         "libyuv",
         "capi",
+        "heic",
     ],
     rustlibs: [
         "liblibyuv_sys",
         "libndk_sys",
         "librustutils",
     ],
+    shared_libs: [
+        "libmediandk",
+    ],
     include_dirs: ["include"],
     apex_available: [
         "//apex_available:platform",
diff --git a/Cargo.toml b/Cargo.toml
index 7802f98..d3d77a4 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -1,19 +1,24 @@
-workspace = { members = ["sys/dav1d-sys", "sys/libyuv-sys", "sys/libgav1-sys", "sys/ndk-sys"] }
+workspace = { members = [
+  "sys/dav1d-sys",
+  "sys/libyuv-sys",
+  "sys/libgav1-sys",
+  "sys/ndk-sys",
+] }
 
 [package]
 name = "crabby-avif"
 version = "0.1.0"
-edition = "2021" # Rust version
+edition = "2021"     # Rust version
 
 [lib]
 crate-type = ["rlib", "cdylib"]
 
 [dependencies]
-libc = {version = "0.2.152", optional = true}
-ndk-sys = {version = "0.1.0", path="sys/ndk-sys", optional = true}
-dav1d-sys = {version = "0.1.0", path="sys/dav1d-sys", optional = true}
-libgav1-sys = {version = "0.1.0", path="sys/libgav1-sys", optional = true}
-libyuv-sys = {version = "0.1.0", path="sys/libyuv-sys", optional = true}
+libc = { version = "0.2.152", optional = true }
+ndk-sys = { version = "0.1.0", path = "sys/ndk-sys", optional = true }
+dav1d-sys = { version = "0.1.0", path = "sys/dav1d-sys", optional = true }
+libgav1-sys = { version = "0.1.0", path = "sys/libgav1-sys", optional = true }
+libyuv-sys = { version = "0.1.0", path = "sys/libyuv-sys", optional = true }
 
 [dev-dependencies]
 test-case = "3.3.1"
@@ -34,10 +39,14 @@ dav1d = ["dep:libc", "dep:dav1d-sys"]
 libgav1 = ["dep:libgav1-sys"]
 libyuv = ["dep:libyuv-sys"]
 android_mediacodec = ["dep:ndk-sys"]
+heic = []
 
 [package.metadata.capi.header]
 name = "avif"
 subdirectory = "avif"
 
 [lints.rust]
-unexpected_cfgs = { level = "warn", check-cfg = ['cfg(google3)', 'cfg(android_soong)'] }
+unexpected_cfgs = { level = "warn", check-cfg = [
+  'cfg(google3)',
+  'cfg(android_soong)',
+] }
diff --git a/METADATA b/METADATA
index f411734..5b3ca2e 100644
--- a/METADATA
+++ b/METADATA
@@ -8,14 +8,14 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 9
-    day: 13
+    month: 12
+    day: 6
   }
   homepage: "https://github.com/webmproject/CrabbyAvif"
   identifier {
     type: "Git"
     value: "https://github.com/webmproject/CrabbyAvif.git"
-    version: "adfb834d76c6a064f28bb3a694689fc14a42425e"
+    version: "a6987b0a607470dffd02e0d5ea69cae8af552a89"
     primary_source: true
   }
 }
diff --git a/c_api_tests/CMakeLists.txt b/c_api_tests/CMakeLists.txt
index a05bee9..d10cec7 100644
--- a/c_api_tests/CMakeLists.txt
+++ b/c_api_tests/CMakeLists.txt
@@ -47,6 +47,7 @@ add_avif_gtest(avifclaptest)
 add_avif_gtest(avifcllitest)
 add_avif_gtest(avifdecodetest)
 add_avif_gtest(avifgainmaptest)
+add_avif_gtest(avifimagetest)
 add_avif_gtest(avifincrtest)
 add_avif_gtest(avifiotest)
 add_avif_gtest(avifkeyframetest)
diff --git a/c_api_tests/avifalphanoispetest.cc b/c_api_tests/avifalphanoispetest.cc
index d7963a7..c334066 100644
--- a/c_api_tests/avifalphanoispetest.cc
+++ b/c_api_tests/avifalphanoispetest.cc
@@ -29,6 +29,7 @@ TEST(AvifDecodeTest, AlphaNoIspe) {
   decoder->strictFlags = (avifStrictFlags)AVIF_STRICT_ENABLED &
                          ~(avifStrictFlags)AVIF_STRICT_ALPHA_ISPE_REQUIRED;
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
   EXPECT_EQ(decoder->alphaPresent, AVIF_TRUE);
   EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
   EXPECT_NE(decoder->image->alphaPlane, nullptr);
diff --git a/c_api_tests/avifanimationtest.cc b/c_api_tests/avifanimationtest.cc
index c998bca..a3e4227 100644
--- a/c_api_tests/avifanimationtest.cc
+++ b/c_api_tests/avifanimationtest.cc
@@ -22,6 +22,7 @@ TEST(AvifDecodeTest, AnimatedImage) {
                                  (std::string(data_path) + file_name).c_str()),
             AVIF_RESULT_OK);
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
   EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
   EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
   EXPECT_EQ(decoder->imageCount, 5);
@@ -45,6 +46,7 @@ TEST(AvifDecodeTest, AnimatedImageWithSourceSetToPrimaryItem) {
       avifDecoderSetSource(decoder.get(), AVIF_DECODER_SOURCE_PRIMARY_ITEM),
       AVIF_RESULT_OK);
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
   EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
   EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
   // imageCount is expected to be 1 because we are using primary item as the
@@ -66,6 +68,7 @@ TEST(AvifDecodeTest, AnimatedImageWithAlphaAndMetadata) {
                                  (std::string(data_path) + file_name).c_str()),
             AVIF_RESULT_OK);
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
   EXPECT_EQ(decoder->alphaPresent, AVIF_TRUE);
   EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
   EXPECT_EQ(decoder->imageCount, 5);
diff --git a/c_api_tests/avifcapitest.cc b/c_api_tests/avifcapitest.cc
index 8dca978..bca57dd 100644
--- a/c_api_tests/avifcapitest.cc
+++ b/c_api_tests/avifcapitest.cc
@@ -30,7 +30,15 @@ TEST(AvifDecodeTest, OneShotDecodeFile) {
   EXPECT_EQ(image.height, 770);
   EXPECT_EQ(image.depth, 8);
 
-  // TODO: Add test using same decoder with another read.
+  // Call avifDecoderReadFile with a different file but with the same decoder
+  // instance.
+  file_name = "white_1x1.avif";
+  ASSERT_EQ(avifDecoderReadFile(decoder.get(), &image,
+                                get_file_name(file_name).c_str()),
+            AVIF_RESULT_OK);
+  EXPECT_EQ(image.width, 1);
+  EXPECT_EQ(image.height, 1);
+  EXPECT_EQ(image.depth, 8);
 }
 
 TEST(AvifDecodeTest, OneShotDecodeMemory) {
@@ -98,6 +106,7 @@ TEST(AvifDecodeTest, NthImage) {
                                  (std::string(data_path) + file_name).c_str()),
             AVIF_RESULT_OK);
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
   EXPECT_EQ(decoder->imageCount, 5);
   EXPECT_EQ(avifDecoderNthImage(decoder.get(), 3), AVIF_RESULT_OK);
   EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
diff --git a/c_api_tests/avifcllitest.cc b/c_api_tests/avifcllitest.cc
index bce9867..ac76428 100644
--- a/c_api_tests/avifcllitest.cc
+++ b/c_api_tests/avifcllitest.cc
@@ -36,6 +36,7 @@ TEST(ClliTest, Simple) {
                                    (std::string(data_path) + param.file_name).c_str()),
               AVIF_RESULT_OK);
     ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+    EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
     avifImage* decoded = decoder->image;
     ASSERT_NE(decoded, nullptr);
     ASSERT_EQ(decoded->clli.maxCLL, param.maxCLL);
@@ -56,4 +57,4 @@ int main(int argc, char** argv) {
   }
   avif::data_path = argv[1];
   return RUN_ALL_TESTS();
-}
\ No newline at end of file
+}
diff --git a/c_api_tests/avifdecodetest.cc b/c_api_tests/avifdecodetest.cc
index 285d9d3..8017e97 100644
--- a/c_api_tests/avifdecodetest.cc
+++ b/c_api_tests/avifdecodetest.cc
@@ -23,6 +23,7 @@ TEST(AvifDecodeTest, ColorGridAlphaNoGrid) {
                                  (std::string(data_path) + file_name).c_str()),
             AVIF_RESULT_OK);
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
   EXPECT_EQ(decoder->alphaPresent, AVIF_TRUE);
   EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_FALSE);
   EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
diff --git a/c_api_tests/avifgainmaptest.cc b/c_api_tests/avifgainmaptest.cc
index 5cfb2b4..da14fa1 100644
--- a/c_api_tests/avifgainmaptest.cc
+++ b/c_api_tests/avifgainmaptest.cc
@@ -1,6 +1,8 @@
 // Copyright 2023 Google LLC
 // SPDX-License-Identifier: BSD-2-Clause
 
+#include <string>
+
 #include "avif/avif.h"
 #include "aviftest_helpers.h"
 #include "gtest/gtest.h"
@@ -16,8 +18,7 @@ TEST(GainMapTest, DecodeGainMapGrid) {
       std::string(data_path) + "color_grid_gainmap_different_grid.avif";
   DecoderPtr decoder(avifDecoderCreate());
   ASSERT_NE(decoder, nullptr);
-  decoder->enableDecodingGainMap = true;
-  decoder->enableParsingGainMapMetadata = true;
+  decoder->imageContentToDecode |= AVIF_IMAGE_CONTENT_GAIN_MAP;
 
   avifResult result = avifDecoderSetIOFile(decoder.get(), path.c_str());
   ASSERT_EQ(result, AVIF_RESULT_OK)
@@ -27,23 +28,23 @@ TEST(GainMapTest, DecodeGainMapGrid) {
   result = avifDecoderParse(decoder.get());
   ASSERT_EQ(result, AVIF_RESULT_OK)
       << avifResultToString(result) << " " << decoder->diag.error;
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
   avifImage* decoded = decoder->image;
   ASSERT_NE(decoded, nullptr);
 
   // Verify that the gain map is present and matches the input.
-  EXPECT_TRUE(decoder->gainMapPresent);
+  EXPECT_NE(decoder->image->gainMap, nullptr);
   // Color+alpha: 4x3 grid of 128x200 tiles.
   EXPECT_EQ(decoded->width, 128u * 4u);
   EXPECT_EQ(decoded->height, 200u * 3u);
   EXPECT_EQ(decoded->depth, 10u);
-  ASSERT_NE(decoded->gainMap, nullptr);
   ASSERT_NE(decoded->gainMap->image, nullptr);
   // Gain map: 2x2 grid of 64x80 tiles.
   EXPECT_EQ(decoded->gainMap->image->width, 64u * 2u);
   EXPECT_EQ(decoded->gainMap->image->height, 80u * 2u);
   EXPECT_EQ(decoded->gainMap->image->depth, 8u);
-  EXPECT_EQ(decoded->gainMap->metadata.baseHdrHeadroomN, 6u);
-  EXPECT_EQ(decoded->gainMap->metadata.baseHdrHeadroomD, 2u);
+  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.n, 6u);
+  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.d, 2u);
 
   // Decode the image.
   result = avifDecoderNextImage(decoder.get());
@@ -55,8 +56,7 @@ TEST(GainMapTest, DecodeOriented) {
   const std::string path = std::string(data_path) + "gainmap_oriented.avif";
   DecoderPtr decoder(avifDecoderCreate());
   ASSERT_NE(decoder, nullptr);
-  decoder->enableDecodingGainMap = AVIF_TRUE;
-  decoder->enableParsingGainMapMetadata = AVIF_TRUE;
+  decoder->imageContentToDecode |= AVIF_IMAGE_CONTENT_GAIN_MAP;
   ASSERT_EQ(avifDecoderSetIOFile(decoder.get(), path.c_str()), AVIF_RESULT_OK);
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
 
@@ -69,6 +69,88 @@ TEST(GainMapTest, DecodeOriented) {
             AVIF_TRANSFORM_NONE);
 }
 
+TEST(GainMapTest, IgnoreGainMapButReadMetadata) {
+  const std::string path =
+      std::string(data_path) + "seine_sdr_gainmap_srgb.avif";
+  DecoderPtr decoder(avifDecoderCreate());
+  ASSERT_NE(decoder, nullptr);
+
+  avifResult result = avifDecoderSetIOFile(decoder.get(), path.c_str());
+  ASSERT_EQ(result, AVIF_RESULT_OK)
+      << avifResultToString(result) << " " << decoder->diag.error;
+  result = avifDecoderParse(decoder.get());
+  ASSERT_EQ(result, AVIF_RESULT_OK)
+      << avifResultToString(result) << " " << decoder->diag.error;
+  avifImage* decoded = decoder->image;
+  ASSERT_NE(decoded, nullptr);
+
+  // Verify that the gain map was detected...
+  EXPECT_NE(decoder->image->gainMap, nullptr);
+  // ... but not decoded because enableDecodingGainMap is false by default.
+  EXPECT_EQ(decoded->gainMap->image, nullptr);
+  // Check that the gain map metadata WAS populated.
+  EXPECT_EQ(decoded->gainMap->alternateHdrHeadroom.n, 13);
+  EXPECT_EQ(decoded->gainMap->alternateHdrHeadroom.d, 10);
+}
+
+TEST(GainMapTest, IgnoreColorAndAlpha) {
+  const std::string path =
+      std::string(data_path) + "seine_sdr_gainmap_srgb.avif";
+  DecoderPtr decoder(avifDecoderCreate());
+  ASSERT_NE(decoder, nullptr);
+  decoder->imageContentToDecode = AVIF_IMAGE_CONTENT_GAIN_MAP;
+
+  avifResult result = avifDecoderSetIOFile(decoder.get(), path.c_str());
+  ASSERT_EQ(result, AVIF_RESULT_OK)
+      << avifResultToString(result) << " " << decoder->diag.error;
+  result = avifDecoderParse(decoder.get());
+  ASSERT_EQ(result, AVIF_RESULT_OK)
+      << avifResultToString(result) << " " << decoder->diag.error;
+  result = avifDecoderNextImage(decoder.get());
+  ASSERT_EQ(result, AVIF_RESULT_OK)
+      << avifResultToString(result) << " " << decoder->diag.error;
+  avifImage* decoded = decoder->image;
+  ASSERT_NE(decoded, nullptr);
+
+  // Main image metadata is available.
+  EXPECT_EQ(decoded->width, 400u);
+  EXPECT_EQ(decoded->height, 300u);
+  // But pixels are not.
+  EXPECT_EQ(decoded->yuvRowBytes[0], 0u);
+  EXPECT_EQ(decoded->yuvRowBytes[1], 0u);
+  EXPECT_EQ(decoded->yuvRowBytes[2], 0u);
+  EXPECT_EQ(decoded->alphaRowBytes, 0u);
+  // The gain map was decoded.
+  EXPECT_NE(decoder->image->gainMap, nullptr);
+  ASSERT_NE(decoded->gainMap->image, nullptr);
+  // Including pixels.
+  EXPECT_GT(decoded->gainMap->image->yuvRowBytes[0], 0u);
+}
+
+TEST(GainMapTest, IgnoreAll) {
+  const std::string path =
+      std::string(data_path) + "seine_sdr_gainmap_srgb.avif";
+  DecoderPtr decoder(avifDecoderCreate());
+  ASSERT_NE(decoder, nullptr);
+  decoder->imageContentToDecode = AVIF_IMAGE_CONTENT_NONE;
+
+  avifResult result = avifDecoderSetIOFile(decoder.get(), path.c_str());
+  ASSERT_EQ(result, AVIF_RESULT_OK)
+      << avifResultToString(result) << " " << decoder->diag.error;
+  result = avifDecoderParse(decoder.get());
+  ASSERT_EQ(result, AVIF_RESULT_OK)
+      << avifResultToString(result) << " " << decoder->diag.error;
+  avifImage* decoded = decoder->image;
+  ASSERT_NE(decoded, nullptr);
+
+  EXPECT_NE(decoder->image->gainMap, nullptr);
+  ASSERT_EQ(decoder->image->gainMap->image, nullptr);
+
+  // But trying to access the next image should give an error because both
+  // ignoreColorAndAlpha and enableDecodingGainMap are set.
+  ASSERT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_NO_CONTENT);
+}
+
 // The following two functions use avifDecoderReadFile which is not supported in
 // CAPI yet.
 
@@ -93,8 +175,8 @@ TEST(GainMapTest, DecodeColorGridGainMapNoGrid) {
   // Gain map: single image of size 64x80.
   EXPECT_EQ(decoded->gainMap->image->width, 64u);
   EXPECT_EQ(decoded->gainMap->image->height, 80u);
-  EXPECT_EQ(decoded->gainMap->metadata.baseHdrHeadroomN, 6u);
-  EXPECT_EQ(decoded->gainMap->metadata.baseHdrHeadroomD, 2u);
+  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.n, 6u);
+  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.d, 2u);
 }
 
 TEST(GainMapTest, DecodeColorNoGridGainMapGrid) {
@@ -117,8 +199,8 @@ TEST(GainMapTest, DecodeColorNoGridGainMapGrid) {
   // Gain map: 2x2 grid of 64x80 tiles.
   EXPECT_EQ(decoded->gainMap->image->width, 64u * 2u);
   EXPECT_EQ(decoded->gainMap->image->height, 80u * 2u);
-  EXPECT_EQ(decoded->gainMap->metadata.baseHdrHeadroomN, 6u);
-  EXPECT_EQ(decoded->gainMap->metadata.baseHdrHeadroomD, 2u);
+  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.n, 6u);
+  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.d, 2u);
 }
 */
 
diff --git a/c_api_tests/avifimagetest.cc b/c_api_tests/avifimagetest.cc
new file mode 100644
index 0000000..c947ad3
--- /dev/null
+++ b/c_api_tests/avifimagetest.cc
@@ -0,0 +1,83 @@
+// Copyright 2024 Google LLC
+// SPDX-License-Identifier: BSD-2-Clause
+
+#include <cstring>
+#include <iostream>
+#include <string>
+
+#include "avif/avif.h"
+#include "aviftest_helpers.h"
+#include "gtest/gtest.h"
+
+namespace avif {
+namespace {
+
+// Used to pass the data folder path to the GoogleTest suites.
+const char* data_path = nullptr;
+
+class ImageTest : public testing::TestWithParam<const char*> {};
+
+TEST_P(ImageTest, ImageCopy) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  const char* file_name = GetParam();
+  DecoderPtr decoder(avifDecoderCreate());
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
+                                 (std::string(data_path) + file_name).c_str()),
+            AVIF_RESULT_OK);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+
+  ImagePtr image2(avifImageCreateEmpty());
+  ASSERT_EQ(avifImageCopy(image2.get(), decoder->image, AVIF_PLANES_ALL),
+            AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->image->width, image2->width);
+  EXPECT_EQ(decoder->image->height, image2->height);
+  EXPECT_EQ(decoder->image->depth, image2->depth);
+  EXPECT_EQ(decoder->image->yuvFormat, image2->yuvFormat);
+  EXPECT_EQ(decoder->image->yuvRange, image2->yuvRange);
+  for (int plane = 0; plane < 3; ++plane) {
+    EXPECT_EQ(decoder->image->yuvPlanes[plane] == nullptr,
+              image2->yuvPlanes[plane] == nullptr);
+    if (decoder->image->yuvPlanes[plane] == nullptr) continue;
+    EXPECT_EQ(decoder->image->yuvRowBytes[plane], image2->yuvRowBytes[plane]);
+    EXPECT_NE(decoder->image->yuvPlanes[plane], image2->yuvPlanes[plane]);
+    const auto plane_height = avifImagePlaneHeight(decoder->image, plane);
+    const auto plane_size = plane_height * decoder->image->yuvRowBytes[plane];
+    EXPECT_EQ(memcmp(decoder->image->yuvPlanes[plane], image2->yuvPlanes[plane],
+                     plane_size),
+              0);
+  }
+  EXPECT_EQ(decoder->image->alphaPlane == nullptr,
+            image2->alphaPlane == nullptr);
+  if (decoder->image->alphaPlane != nullptr) {
+    EXPECT_EQ(decoder->image->alphaRowBytes, image2->alphaRowBytes);
+    EXPECT_NE(decoder->image->alphaPlane, image2->alphaPlane);
+    const auto plane_size =
+        decoder->image->height * decoder->image->alphaRowBytes;
+    EXPECT_EQ(
+        memcmp(decoder->image->alphaPlane, image2->alphaPlane, plane_size), 0);
+  }
+}
+
+INSTANTIATE_TEST_SUITE_P(Some, ImageTest,
+                         testing::ValuesIn({"paris_10bpc.avif", "alpha.avif",
+                                            "colors-animated-8bpc.avif"}));
+
+}  // namespace
+}  // namespace avif
+
+int main(int argc, char** argv) {
+  ::testing::InitGoogleTest(&argc, argv);
+  if (argc != 2) {
+    std::cerr << "There must be exactly one argument containing the path to "
+                 "the test data folder"
+              << std::endl;
+    return 1;
+  }
+  avif::data_path = argv[1];
+  return RUN_ALL_TESTS();
+}
diff --git a/c_api_tests/avifiotest.cc b/c_api_tests/avifiotest.cc
index 06a9410..f968933 100644
--- a/c_api_tests/avifiotest.cc
+++ b/c_api_tests/avifiotest.cc
@@ -25,6 +25,7 @@ TEST(AvifDecodeTest, SetRawIO) {
   ASSERT_EQ(avifDecoderSetIOMemory(decoder.get(), data.data(), data.size()),
             AVIF_RESULT_OK);
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
   EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
   EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
   EXPECT_EQ(decoder->imageCount, 5);
@@ -61,6 +62,7 @@ TEST(AvifDecodeTest, SetCustomIO) {
                .data = static_cast<void*>(&ro_data)};
   avifDecoderSetIO(decoder.get(), &io);
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
   EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
   EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
   EXPECT_EQ(decoder->imageCount, 5);
diff --git a/c_api_tests/avifkeyframetest.cc b/c_api_tests/avifkeyframetest.cc
index 4f4aefb..9411ccc 100644
--- a/c_api_tests/avifkeyframetest.cc
+++ b/c_api_tests/avifkeyframetest.cc
@@ -26,6 +26,7 @@ TEST(KeyframeTest, Decode) {
       avifDecoderSetIOFile(decoder.get(), (data_path + file_name).c_str()),
       AVIF_RESULT_OK);
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
 
   // The first frame is always a keyframe.
   EXPECT_TRUE(avifDecoderIsKeyframe(decoder.get(), 0));
diff --git a/c_api_tests/avifmetadatatest.cc b/c_api_tests/avifmetadatatest.cc
index 26f9e2b..179bd96 100644
--- a/c_api_tests/avifmetadatatest.cc
+++ b/c_api_tests/avifmetadatatest.cc
@@ -22,6 +22,7 @@ TEST(MetadataTest, DecoderParseICC) {
   decoder->ignoreXMP = AVIF_TRUE;
   decoder->ignoreExif = AVIF_TRUE;
   EXPECT_EQ(avifDecoderParse(decoder), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
 
   ASSERT_GE(decoder->image->icc.size, 4u);
   EXPECT_EQ(decoder->image->icc.data[0], 0);
@@ -35,6 +36,7 @@ TEST(MetadataTest, DecoderParseICC) {
   decoder->ignoreXMP = AVIF_FALSE;
   decoder->ignoreExif = AVIF_FALSE;
   EXPECT_EQ(avifDecoderParse(decoder), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
 
   ASSERT_GE(decoder->image->exif.size, 4u);
   EXPECT_EQ(decoder->image->exif.data[0], 73);
diff --git a/c_api_tests/avifprogressivetest.cc b/c_api_tests/avifprogressivetest.cc
index 217f67a..577afae 100644
--- a/c_api_tests/avifprogressivetest.cc
+++ b/c_api_tests/avifprogressivetest.cc
@@ -34,6 +34,7 @@ TEST(AvifDecodeTest, Progressive) {
                                    (std::string(data_path) + param.file_name).c_str()),
               AVIF_RESULT_OK);
     ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+    EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
     ASSERT_EQ(decoder->progressiveState, AVIF_PROGRESSIVE_STATE_ACTIVE);
     ASSERT_EQ(static_cast<uint32_t>(decoder->imageCount), param.layer_count);
 
diff --git a/c_api_tests/avifscaletest.cc b/c_api_tests/avifscaletest.cc
index 094794b..e5e2928 100644
--- a/c_api_tests/avifscaletest.cc
+++ b/c_api_tests/avifscaletest.cc
@@ -28,6 +28,7 @@ TEST_P(ScaleTest, Scaling) {
                                  (std::string(data_path) + file_name).c_str()),
             AVIF_RESULT_OK);
   ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
   EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
 
   const uint32_t scaled_width =
diff --git a/cbindgen.toml b/cbindgen.toml
index 9483a9e..ea06850 100644
--- a/cbindgen.toml
+++ b/cbindgen.toml
@@ -59,6 +59,4 @@ include = [
   "avifPlanesFlags",
   "avifStrictFlag",
 ]
-exclude = [
-  "Box"
-]
+exclude = ["Box"]
diff --git a/examples/dec.rs b/examples/dec.rs
index 0f28d33..5c8f7da 100644
--- a/examples/dec.rs
+++ b/examples/dec.rs
@@ -42,8 +42,7 @@ fn main() {
     {
         let settings = Settings {
             strictness: Strictness::None,
-            enable_decoding_gainmap: true,
-            enable_parsing_gainmap_metadata: true,
+            image_content_to_decode: ImageContentType::All,
             allow_progressive: true,
             ..Settings::default()
         };
diff --git a/include/avif/avif.h b/include/avif/avif.h
index 771ff56..68237dd 100644
--- a/include/avif/avif.h
+++ b/include/avif/avif.h
@@ -40,6 +40,14 @@ constexpr static const uint32_t AVIF_STRICT_ALPHA_ISPE_REQUIRED = (1 << 2);
 
 constexpr static const uint32_t AVIF_STRICT_ENABLED = ((AVIF_STRICT_PIXI_REQUIRED | AVIF_STRICT_CLAP_VALID) | AVIF_STRICT_ALPHA_ISPE_REQUIRED);
 
+constexpr static const uint32_t AVIF_IMAGE_CONTENT_NONE = 0;
+
+constexpr static const uint32_t AVIF_IMAGE_CONTENT_COLOR_AND_ALPHA = ((1 << 0) | (1 << 1));
+
+constexpr static const uint32_t AVIF_IMAGE_CONTENT_GAIN_MAP = (1 << 2);
+
+constexpr static const uint32_t AVIF_IMAGE_CONTENT_ALL = (AVIF_IMAGE_CONTENT_COLOR_AND_ALPHA | AVIF_IMAGE_CONTENT_GAIN_MAP);
+
 constexpr static const size_t CRABBY_AVIF_DIAGNOSTICS_ERROR_BUFFER_SIZE = 256;
 
 constexpr static const size_t CRABBY_AVIF_PLANE_COUNT_YUV = 3;
@@ -68,6 +76,11 @@ constexpr static const uint32_t AVIF_COLOR_PRIMARIES_DCI_P3 = 12;
 
 constexpr static const uint32_t AVIF_TRANSFER_CHARACTERISTICS_SMPTE2084 = 16;
 
+enum AndroidMediaCodecOutputColorFormat : int32_t {
+    ANDROID_MEDIA_CODEC_OUTPUT_COLOR_FORMAT_YUV420_FLEXIBLE = 2135033992,
+    ANDROID_MEDIA_CODEC_OUTPUT_COLOR_FORMAT_P010 = 54,
+};
+
 enum avifChromaDownsampling {
     AVIF_CHROMA_DOWNSAMPLING_AUTOMATIC,
     AVIF_CHROMA_DOWNSAMPLING_FASTEST,
@@ -107,6 +120,11 @@ enum avifColorPrimaries : uint16_t {
     AVIF_COLOR_PRIMARIES_EBU3213 = 22,
 };
 
+enum CompressionFormat {
+    COMPRESSION_FORMAT_AVIF = 0,
+    COMPRESSION_FORMAT_HEIC = 1,
+};
+
 enum avifRGBFormat {
     AVIF_RGB_FORMAT_RGB,
     AVIF_RGB_FORMAT_RGBA,
@@ -145,6 +163,8 @@ enum avifPixelFormat {
     AVIF_PIXEL_FORMAT_YUV420 = 3,
     AVIF_PIXEL_FORMAT_YUV400 = 4,
     AVIF_PIXEL_FORMAT_ANDROID_P010 = 5,
+    AVIF_PIXEL_FORMAT_ANDROID_NV12 = 6,
+    AVIF_PIXEL_FORMAT_ANDROID_NV21 = 7,
     AVIF_PIXEL_FORMAT_COUNT,
 };
 
@@ -301,27 +321,30 @@ struct avifImageMirror {
     uint8_t axis;
 };
 
-struct avifGainMapMetadata {
-    int32_t gainMapMinN[3];
-    uint32_t gainMapMinD[3];
-    int32_t gainMapMaxN[3];
-    uint32_t gainMapMaxD[3];
-    uint32_t gainMapGammaN[3];
-    uint32_t gainMapGammaD[3];
-    int32_t baseOffsetN[3];
-    uint32_t baseOffsetD[3];
-    int32_t alternateOffsetN[3];
-    uint32_t alternateOffsetD[3];
-    uint32_t baseHdrHeadroomN;
-    uint32_t baseHdrHeadroomD;
-    uint32_t alternateHdrHeadroomN;
-    uint32_t alternateHdrHeadroomD;
-    avifBool useBaseColorSpace;
+struct Fraction {
+    int32_t n;
+    uint32_t d;
+};
+
+using avifSignedFraction = Fraction;
+
+struct UFraction {
+    uint32_t n;
+    uint32_t d;
 };
 
+using avifUnsignedFraction = UFraction;
+
 struct avifGainMap {
     avifImage *image;
-    avifGainMapMetadata metadata;
+    avifSignedFraction gainMapMin[3];
+    avifSignedFraction gainMapMax[3];
+    avifUnsignedFraction gainMapGamma[3];
+    avifSignedFraction baseOffset[3];
+    avifSignedFraction alternateOffset[3];
+    avifUnsignedFraction baseHdrHeadroom;
+    avifUnsignedFraction alternateHdrHeadroom;
+    avifBool useBaseColorSpace;
     avifRWData altICC;
     avifColorPrimaries altColorPrimaries;
     avifTransferCharacteristics altTransferCharacteristics;
@@ -382,6 +405,8 @@ struct avifDecoderData {
 
 };
 
+using avifImageContentTypeFlags = uint32_t;
+
 struct avifDecoder {
     avifCodecChoice codecChoice;
     int32_t maxThreads;
@@ -407,10 +432,10 @@ struct avifDecoder {
     avifIOStats ioStats;
     avifDiagnostics diag;
     avifDecoderData *data;
-    avifBool gainMapPresent;
-    avifBool enableDecodingGainMap;
-    avifBool enableParsingGainMapMetadata;
+    avifImageContentTypeFlags imageContentToDecode;
     avifBool imageSequenceTrackPresent;
+    AndroidMediaCodecOutputColorFormat androidMediaCodecOutputColorFormat;
+    CompressionFormat compressionFormat;
     Box<Decoder> rust_decoder;
     avifImage image_object;
     avifGainMap gainmap_object;
@@ -548,6 +573,10 @@ avifImage *crabby_avifImageCreate(uint32_t width,
                                   uint32_t depth,
                                   avifPixelFormat yuvFormat);
 
+avifResult crabby_avifImageCopy(avifImage *dstImage,
+                                const avifImage *srcImage,
+                                avifPlanesFlags planes);
+
 avifResult crabby_avifImageAllocatePlanes(avifImage *image, avifPlanesFlags planes);
 
 void crabby_avifImageFreePlanes(avifImage *image, avifPlanesFlags planes);
@@ -601,7 +630,7 @@ avifResult crabby_avifImageScale(avifImage *image,
                                  uint32_t dstHeight,
                                  avifDiagnostics *_diag);
 
-const char *crabby_avifResultToString(avifResult _res);
+const char *crabby_avifResultToString(avifResult res);
 
 avifBool crabby_avifCropRectConvertCleanApertureBox(avifCropRect *cropRect,
                                                     const avifCleanApertureBox *clap,
diff --git a/include/avif/libavif_compat.h b/include/avif/libavif_compat.h
index 69a9da7..0d18a13 100644
--- a/include/avif/libavif_compat.h
+++ b/include/avif/libavif_compat.h
@@ -41,6 +41,7 @@
 #define avifIOCreateMemoryReader crabby_avifIOCreateMemoryReader
 #define avifIODestroy crabby_avifIODestroy
 #define avifImageAllocatePlanes crabby_avifImageAllocatePlanes
+#define avifImageCopy crabby_avifImageCopy
 #define avifImageCreate crabby_avifImageCreate
 #define avifImageCreateEmpty crabby_avifImageCreateEmpty
 #define avifImageDestroy crabby_avifImageDestroy
diff --git a/src/capi/decoder.rs b/src/capi/decoder.rs
index e4773bb..114539d 100644
--- a/src/capi/decoder.rs
+++ b/src/capi/decoder.rs
@@ -48,20 +48,19 @@ pub struct avifDecoder {
     pub duration: f64,
     pub durationInTimescales: u64,
     pub repetitionCount: i32,
-
     pub alphaPresent: avifBool,
-
     pub ioStats: IOStats,
     pub diag: avifDiagnostics,
-    //avifIO * io;
     pub data: *mut avifDecoderData,
-    pub gainMapPresent: avifBool,
-    pub enableDecodingGainMap: avifBool,
-    pub enableParsingGainMapMetadata: avifBool,
-    // avifBool ignoreColorAndAlpha;
+    pub imageContentToDecode: avifImageContentTypeFlags,
     pub imageSequenceTrackPresent: avifBool,
 
-    // TODO: maybe wrap these fields in a private data kind of field?
+    // These fields are not part of libavif. Any new fields that are to be header file compatible
+    // with libavif must be added before this line.
+    pub androidMediaCodecOutputColorFormat: AndroidMediaCodecOutputColorFormat,
+    pub compressionFormat: CompressionFormat,
+
+    // Rust specific fields that are not accessed from the C/C++ layer.
     rust_decoder: Box<Decoder>,
     image_object: avifImage,
     gainmap_object: avifGainMap,
@@ -95,10 +94,10 @@ impl Default for avifDecoder {
             ioStats: Default::default(),
             diag: avifDiagnostics::default(),
             data: std::ptr::null_mut(),
-            gainMapPresent: AVIF_FALSE,
-            enableDecodingGainMap: AVIF_FALSE,
-            enableParsingGainMapMetadata: AVIF_FALSE,
+            imageContentToDecode: AVIF_IMAGE_CONTENT_COLOR_AND_ALPHA,
             imageSequenceTrackPresent: AVIF_FALSE,
+            androidMediaCodecOutputColorFormat: AndroidMediaCodecOutputColorFormat::default(),
+            compressionFormat: CompressionFormat::default(),
             rust_decoder: Box::<Decoder>::default(),
             image_object: avifImage::default(),
             gainmap_image_object: avifImage::default(),
@@ -150,7 +149,6 @@ pub unsafe extern "C" fn crabby_avifDecoderSetSource(
     unsafe {
         (*decoder).requestedSource = source;
     }
-    // TODO: should decoder be reset here in case this is called after parse?
     avifResult::Ok
 }
 
@@ -173,6 +171,12 @@ impl From<&avifDecoder> for Settings {
             }
             Strictness::SpecificInclude(flags)
         };
+        let image_content_to_decode_flags: ImageContentType = match decoder.imageContentToDecode {
+            AVIF_IMAGE_CONTENT_ALL => ImageContentType::All,
+            AVIF_IMAGE_CONTENT_COLOR_AND_ALPHA => ImageContentType::ColorAndAlpha,
+            AVIF_IMAGE_CONTENT_GAIN_MAP => ImageContentType::GainMap,
+            _ => ImageContentType::None,
+        };
         Self {
             source: decoder.requestedSource,
             strictness,
@@ -180,8 +184,7 @@ impl From<&avifDecoder> for Settings {
             allow_incremental: decoder.allowIncremental == AVIF_TRUE,
             ignore_exif: decoder.ignoreExif == AVIF_TRUE,
             ignore_xmp: decoder.ignoreXMP == AVIF_TRUE,
-            enable_decoding_gainmap: decoder.enableDecodingGainMap == AVIF_TRUE,
-            enable_parsing_gainmap_metadata: decoder.enableParsingGainMapMetadata == AVIF_TRUE,
+            image_content_to_decode: image_content_to_decode_flags,
             codec_choice: match decoder.codecChoice {
                 avifCodecChoice::Auto => CodecChoice::Auto,
                 avifCodecChoice::Dav1d => CodecChoice::Dav1d,
@@ -193,6 +196,7 @@ impl From<&avifDecoder> for Settings {
             image_dimension_limit: decoder.imageDimensionLimit,
             image_count_limit: decoder.imageCountLimit,
             max_threads: u32::try_from(decoder.maxThreads).unwrap_or(0),
+            android_mediacodec_output_color_format: decoder.androidMediaCodecOutputColorFormat,
         }
     }
 }
@@ -219,12 +223,14 @@ fn rust_decoder_to_avifDecoder(src: &Decoder, dst: &mut avifDecoder) {
     dst.durationInTimescales = src.duration_in_timescales();
     dst.duration = src.duration();
     dst.ioStats = src.io_stats();
+    dst.compressionFormat = src.compression_format();
 
     if src.gainmap_present() {
-        dst.gainMapPresent = AVIF_TRUE;
         dst.gainmap_image_object = (&src.gainmap().image).into();
         dst.gainmap_object = src.gainmap().into();
-        dst.gainmap_object.image = (&mut dst.gainmap_image_object) as *mut avifImage;
+        if src.settings.image_content_to_decode.gainmap() {
+            dst.gainmap_object.image = (&mut dst.gainmap_image_object) as *mut avifImage;
+        }
         dst.image_object.gainMap = (&mut dst.gainmap_object) as *mut avifGainMap;
     }
     dst.image = (&mut dst.image_object) as *mut avifImage;
diff --git a/src/capi/gainmap.rs b/src/capi/gainmap.rs
index 2707544..098361b 100644
--- a/src/capi/gainmap.rs
+++ b/src/capi/gainmap.rs
@@ -18,66 +18,26 @@ use super::types::*;
 
 use crate::decoder::gainmap::*;
 use crate::image::YuvRange;
+use crate::internal_utils::*;
 use crate::parser::mp4box::*;
 use crate::*;
 
 pub type avifContentLightLevelInformationBox = ContentLightLevelInformation;
-
-#[repr(C)]
-#[derive(Debug, Default)]
-pub struct avifGainMapMetadata {
-    pub gainMapMinN: [i32; 3],
-    pub gainMapMinD: [u32; 3],
-    pub gainMapMaxN: [i32; 3],
-    pub gainMapMaxD: [u32; 3],
-    pub gainMapGammaN: [u32; 3],
-    pub gainMapGammaD: [u32; 3],
-    pub baseOffsetN: [i32; 3],
-    pub baseOffsetD: [u32; 3],
-    pub alternateOffsetN: [i32; 3],
-    pub alternateOffsetD: [u32; 3],
-    pub baseHdrHeadroomN: u32,
-    pub baseHdrHeadroomD: u32,
-    pub alternateHdrHeadroomN: u32,
-    pub alternateHdrHeadroomD: u32,
-    pub useBaseColorSpace: avifBool,
-}
-
-impl From<&GainMapMetadata> for avifGainMapMetadata {
-    fn from(m: &GainMapMetadata) -> Self {
-        avifGainMapMetadata {
-            gainMapMinN: [m.min[0].0, m.min[1].0, m.min[2].0],
-            gainMapMinD: [m.min[0].1, m.min[1].1, m.min[2].1],
-            gainMapMaxN: [m.max[0].0, m.max[1].0, m.max[2].0],
-            gainMapMaxD: [m.max[0].1, m.max[1].1, m.max[2].1],
-            gainMapGammaN: [m.gamma[0].0, m.gamma[1].0, m.gamma[2].0],
-            gainMapGammaD: [m.gamma[0].1, m.gamma[1].1, m.gamma[2].1],
-            baseOffsetN: [m.base_offset[0].0, m.base_offset[1].0, m.base_offset[2].0],
-            baseOffsetD: [m.base_offset[0].1, m.base_offset[1].1, m.base_offset[2].1],
-            alternateOffsetN: [
-                m.alternate_offset[0].0,
-                m.alternate_offset[1].0,
-                m.alternate_offset[2].0,
-            ],
-            alternateOffsetD: [
-                m.alternate_offset[0].1,
-                m.alternate_offset[1].1,
-                m.alternate_offset[2].1,
-            ],
-            baseHdrHeadroomN: m.base_hdr_headroom.0,
-            baseHdrHeadroomD: m.base_hdr_headroom.1,
-            alternateHdrHeadroomN: m.alternate_hdr_headroom.0,
-            alternateHdrHeadroomD: m.alternate_hdr_headroom.1,
-            useBaseColorSpace: m.use_base_color_space as avifBool,
-        }
-    }
-}
+pub type avifSignedFraction = Fraction;
+pub type avifUnsignedFraction = UFraction;
 
 #[repr(C)]
 #[derive(Debug)]
 pub struct avifGainMap {
     pub image: *mut avifImage,
-    pub metadata: avifGainMapMetadata,
+    pub gainMapMin: [avifSignedFraction; 3],
+    pub gainMapMax: [avifSignedFraction; 3],
+    pub gainMapGamma: [avifUnsignedFraction; 3],
+    pub baseOffset: [avifSignedFraction; 3],
+    pub alternateOffset: [avifSignedFraction; 3],
+    pub baseHdrHeadroom: avifUnsignedFraction,
+    pub alternateHdrHeadroom: avifUnsignedFraction,
+    pub useBaseColorSpace: avifBool,
     pub altICC: avifRWData,
     pub altColorPrimaries: ColorPrimaries,
     pub altTransferCharacteristics: TransferCharacteristics,
@@ -92,7 +52,14 @@ impl Default for avifGainMap {
     fn default() -> Self {
         avifGainMap {
             image: std::ptr::null_mut(),
-            metadata: avifGainMapMetadata::default(),
+            gainMapMin: [Fraction(1, 1), Fraction(1, 1), Fraction(1, 1)],
+            gainMapMax: [Fraction(1, 1), Fraction(1, 1), Fraction(1, 1)],
+            gainMapGamma: [UFraction(1, 1), UFraction(1, 1), UFraction(1, 1)],
+            baseOffset: [Fraction(1, 64), Fraction(1, 64), Fraction(1, 64)],
+            alternateOffset: [Fraction(1, 64), Fraction(1, 64), Fraction(1, 64)],
+            baseHdrHeadroom: UFraction(0, 1),
+            alternateHdrHeadroom: UFraction(1, 1),
+            useBaseColorSpace: to_avifBool(false),
             altICC: avifRWData::default(),
             altColorPrimaries: ColorPrimaries::default(),
             altTransferCharacteristics: TransferCharacteristics::default(),
@@ -108,7 +75,14 @@ impl Default for avifGainMap {
 impl From<&GainMap> for avifGainMap {
     fn from(gainmap: &GainMap) -> Self {
         avifGainMap {
-            metadata: (&gainmap.metadata).into(),
+            gainMapMin: gainmap.metadata.min,
+            gainMapMax: gainmap.metadata.max,
+            gainMapGamma: gainmap.metadata.gamma,
+            baseOffset: gainmap.metadata.base_offset,
+            alternateOffset: gainmap.metadata.alternate_offset,
+            baseHdrHeadroom: gainmap.metadata.base_hdr_headroom,
+            alternateHdrHeadroom: gainmap.metadata.alternate_hdr_headroom,
+            useBaseColorSpace: gainmap.metadata.use_base_color_space as avifBool,
             altICC: (&gainmap.alt_icc).into(),
             altColorPrimaries: gainmap.alt_color_primaries,
             altTransferCharacteristics: gainmap.alt_transfer_characteristics,
diff --git a/src/capi/image.rs b/src/capi/image.rs
index e7d4495..67b2ccc 100644
--- a/src/capi/image.rs
+++ b/src/capi/image.rs
@@ -240,6 +240,83 @@ pub unsafe extern "C" fn crabby_avifImageCreate(
     }))
 }
 
+#[no_mangle]
+#[allow(unused)]
+pub unsafe extern "C" fn crabby_avifImageCopy(
+    dstImage: *mut avifImage,
+    srcImage: *const avifImage,
+    planes: avifPlanesFlags,
+) -> avifResult {
+    unsafe {
+        crabby_avifImageFreePlanes(dstImage, avifPlanesFlag::AvifPlanesAll as u32);
+    }
+    let dst = unsafe { &mut (*dstImage) };
+    let src = unsafe { &(*srcImage) };
+    dst.width = src.width;
+    dst.height = src.height;
+    dst.depth = src.depth;
+    dst.yuvFormat = src.yuvFormat;
+    dst.yuvRange = src.yuvRange;
+    dst.yuvChromaSamplePosition = src.yuvChromaSamplePosition;
+    dst.alphaPremultiplied = src.alphaPremultiplied;
+    dst.colorPrimaries = src.colorPrimaries;
+    dst.transferCharacteristics = src.transferCharacteristics;
+    dst.matrixCoefficients = src.matrixCoefficients;
+    dst.clli = src.clli;
+    dst.transformFlags = src.transformFlags;
+    dst.pasp = src.pasp;
+    dst.clap = src.clap;
+    dst.irot = src.irot;
+    dst.imir = src.imir;
+    let res = unsafe { crabby_avifRWDataSet(&mut dst.icc, src.icc.data, src.icc.size) };
+    if res != avifResult::Ok {
+        return res;
+    }
+    let res = unsafe { crabby_avifRWDataSet(&mut dst.exif, src.exif.data, src.exif.size) };
+    if res != avifResult::Ok {
+        return res;
+    }
+    let res = unsafe { crabby_avifRWDataSet(&mut dst.xmp, src.xmp.data, src.xmp.size) };
+    if res != avifResult::Ok {
+        return res;
+    }
+    if (planes & 1) != 0 {
+        for plane in 0usize..3 {
+            if src.yuvPlanes[plane].is_null() || src.yuvRowBytes[plane] == 0 {
+                continue;
+            }
+            let plane_height = unsafe { crabby_avifImagePlaneHeight(srcImage, plane as i32) };
+            let plane_size = match usize_from_u32(src.yuvRowBytes[plane] * plane_height) {
+                Ok(size) => size,
+                Err(_) => return avifResult::UnknownError,
+            };
+            dst.yuvPlanes[plane] = unsafe { crabby_avifAlloc(plane_size) } as *mut _;
+            unsafe {
+                std::ptr::copy_nonoverlapping(
+                    src.yuvPlanes[plane],
+                    dst.yuvPlanes[plane],
+                    plane_size,
+                );
+            }
+            dst.yuvRowBytes[plane] = src.yuvRowBytes[plane];
+            dst.imageOwnsYUVPlanes = AVIF_TRUE;
+        }
+    }
+    if (planes & 2) != 0 && !src.alphaPlane.is_null() && src.alphaRowBytes != 0 {
+        let plane_size = match usize_from_u32(src.alphaRowBytes * src.height) {
+            Ok(size) => size,
+            Err(_) => return avifResult::UnknownError,
+        };
+        dst.alphaPlane = unsafe { crabby_avifAlloc(plane_size) } as *mut _;
+        unsafe {
+            std::ptr::copy_nonoverlapping(src.alphaPlane, dst.alphaPlane, plane_size);
+        }
+        dst.alphaRowBytes = src.alphaRowBytes;
+        dst.imageOwnsAlphaPlane = AVIF_TRUE;
+    }
+    avifResult::Ok
+}
+
 fn avif_image_allocate_planes_helper(
     image: &mut avifImage,
     planes: avifPlanesFlags,
@@ -259,8 +336,9 @@ fn avif_image_allocate_planes_helper(
             image.yuvPlanes[0] = unsafe { crabby_avifAlloc(y_size) as *mut u8 };
         }
         if !image.yuvFormat.is_monochrome() {
-            let csx = image.yuvFormat.chroma_shift_x() as u64;
-            let width = ((image.width as u64) + csx) >> csx;
+            let csx0 = image.yuvFormat.chroma_shift_x().0 as u64;
+            let csx1 = image.yuvFormat.chroma_shift_x().1 as u64;
+            let width = (((image.width as u64) + csx0) >> csx0) << csx1;
             let csy = image.yuvFormat.chroma_shift_y() as u64;
             let height = ((image.height as u64) + csy) >> csy;
             let uv_row_bytes = usize_from_u64(width * channel_size as u64)?;
@@ -324,6 +402,7 @@ pub unsafe extern "C" fn crabby_avifImageFreePlanes(
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifImageDestroy(image: *mut avifImage) {
     unsafe {
+        crabby_avifImageFreePlanes(image, avifPlanesFlag::AvifPlanesAll as u32);
         let _ = Box::from_raw(image);
     }
 }
@@ -388,7 +467,7 @@ pub unsafe extern "C" fn crabby_avifImagePlaneWidth(
                     0
                 } else {
                     let shift_x = (*image).yuvFormat.chroma_shift_x();
-                    ((*image).width + shift_x) >> shift_x
+                    (((*image).width + shift_x.0) >> shift_x.0) << shift_x.1
                 }
             }
             3 => {
@@ -451,12 +530,11 @@ pub unsafe extern "C" fn crabby_avifImageSetViewRect(
         return avifResult::InvalidArgument;
     }
     if !src.yuvFormat.is_monochrome()
-        && ((rect.x & src.yuvFormat.chroma_shift_x()) != 0
+        && ((rect.x & src.yuvFormat.chroma_shift_x().0) != 0
             || (rect.y & src.yuvFormat.chroma_shift_y()) != 0)
     {
         return avifResult::InvalidArgument;
     }
-    // TODO: This is avifimagecopynoalloc.
     *dst = avifImage {
         width: src.width,
         height: src.height,
@@ -483,7 +561,8 @@ pub unsafe extern "C" fn crabby_avifImageSetViewRect(
         if src.yuvPlanes[plane].is_null() {
             continue;
         }
-        let x = if plane == 0 { rect.x } else { rect.x >> src.yuvFormat.chroma_shift_x() };
+        let chroma_shift = src.yuvFormat.chroma_shift_x();
+        let x = if plane == 0 { rect.x } else { (rect.x >> chroma_shift.0) << chroma_shift.1 };
         let y = if plane == 0 { rect.y } else { rect.y >> src.yuvFormat.chroma_shift_y() };
         let offset = match isize_from_u32(y * src.yuvRowBytes[plane] + x * pixel_size) {
             Ok(x) => x,
diff --git a/src/capi/io.rs b/src/capi/io.rs
index 5704d8a..180ce45 100644
--- a/src/capi/io.rs
+++ b/src/capi/io.rs
@@ -42,8 +42,8 @@ impl Default for avifROData {
 #[repr(C)]
 #[derive(Clone, Debug)]
 pub struct avifRWData {
-    data: *mut u8,
-    size: usize,
+    pub data: *mut u8,
+    pub size: usize,
 }
 
 impl Default for avifRWData {
@@ -115,6 +115,9 @@ pub unsafe extern "C" fn crabby_avifRWDataSet(
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifRWDataFree(raw: *mut avifRWData) {
     unsafe {
+        if (*raw).data.is_null() {
+            return;
+        }
         let _ = Box::from_raw(std::slice::from_raw_parts_mut((*raw).data, (*raw).size));
     }
 }
diff --git a/src/capi/reformat.rs b/src/capi/reformat.rs
index 623047b..916e23d 100644
--- a/src/capi/reformat.rs
+++ b/src/capi/reformat.rs
@@ -248,6 +248,11 @@ pub unsafe extern "C" fn crabby_avifImageScale(
     if res.is_err() {
         return to_avifResult(&res);
     }
+    // The scale function is designed to work only for one category at a time.
+    // Restore the width and height to the original values before scaling the
+    // alpha plane.
+    rust_image.width = unsafe { (*image).width };
+    rust_image.height = unsafe { (*image).height };
     let res = rust_image.scale(dstWidth, dstHeight, Category::Alpha);
     if res.is_err() {
         return to_avifResult(&res);
diff --git a/src/capi/types.rs b/src/capi/types.rs
index bd709f7..5a9f81f 100644
--- a/src/capi/types.rs
+++ b/src/capi/types.rs
@@ -136,6 +136,45 @@ impl From<avifResult> for AvifError {
     }
 }
 
+impl avifResult {
+    pub fn to_usize(&self) -> usize {
+        match self {
+            Self::Ok => 0,
+            Self::UnknownError => 1,
+            Self::InvalidFtyp => 2,
+            Self::NoContent => 3,
+            Self::NoYuvFormatSelected => 4,
+            Self::ReformatFailed => 5,
+            Self::UnsupportedDepth => 6,
+            Self::EncodeColorFailed => 7,
+            Self::EncodeAlphaFailed => 8,
+            Self::BmffParseFailed => 9,
+            Self::MissingImageItem => 10,
+            Self::DecodeColorFailed => 11,
+            Self::DecodeAlphaFailed => 12,
+            Self::ColorAlphaSizeMismatch => 13,
+            Self::IspeSizeMismatch => 14,
+            Self::NoCodecAvailable => 15,
+            Self::NoImagesRemaining => 16,
+            Self::InvalidExifPayload => 17,
+            Self::InvalidImageGrid => 18,
+            Self::InvalidCodecSpecificOption => 19,
+            Self::TruncatedData => 20,
+            Self::IoNotSet => 21,
+            Self::IoError => 22,
+            Self::WaitingOnIo => 23,
+            Self::InvalidArgument => 24,
+            Self::NotImplemented => 25,
+            Self::OutOfMemory => 26,
+            Self::CannotChangeSetting => 27,
+            Self::IncompatibleImage => 28,
+            Self::EncodeGainMapFailed => 29,
+            Self::DecodeGainMapFailed => 30,
+            Self::InvalidToneMappedImage => 31,
+        }
+    }
+}
+
 pub type avifBool = c_int;
 pub const AVIF_TRUE: c_int = 1;
 pub const AVIF_FALSE: c_int = 0;
@@ -148,6 +187,13 @@ pub const AVIF_STRICT_ENABLED: u32 =
     AVIF_STRICT_PIXI_REQUIRED | AVIF_STRICT_CLAP_VALID | AVIF_STRICT_ALPHA_ISPE_REQUIRED;
 pub type avifStrictFlags = u32;
 
+pub const AVIF_IMAGE_CONTENT_NONE: u32 = 0;
+pub const AVIF_IMAGE_CONTENT_COLOR_AND_ALPHA: u32 = 1 << 0 | 1 << 1;
+pub const AVIF_IMAGE_CONTENT_GAIN_MAP: u32 = 1 << 2;
+pub const AVIF_IMAGE_CONTENT_ALL: u32 =
+    AVIF_IMAGE_CONTENT_COLOR_AND_ALPHA | AVIF_IMAGE_CONTENT_GAIN_MAP;
+pub type avifImageContentTypeFlags = u32;
+
 #[repr(C)]
 pub struct avifDecoderData {}
 
@@ -229,10 +275,47 @@ pub fn to_avifResult<T>(res: &AvifResult<T>) -> avifResult {
     }
 }
 
+const RESULT_TO_STRING: &[&str] = &[
+    "Ok\0",
+    "Unknown Error\0",
+    "Invalid ftyp\0",
+    "No content\0",
+    "No YUV format selected\0",
+    "Reformat failed\0",
+    "Unsupported depth\0",
+    "Encoding of color planes failed\0",
+    "Encoding of alpha plane failed\0",
+    "BMFF parsing failed\0",
+    "Missing or empty image item\0",
+    "Decoding of color planes failed\0",
+    "Decoding of alpha plane failed\0",
+    "Color and alpha planes size mismatch\0",
+    "Plane sizes don't match ispe values\0",
+    "No codec available\0",
+    "No images remaining\0",
+    "Invalid Exif payload\0",
+    "Invalid image grid\0",
+    "Invalid codec-specific option\0",
+    "Truncated data\0",
+    "IO not set\0",
+    "IO Error\0",
+    "Waiting on IO\0",
+    "Invalid argument\0",
+    "Not implemented\0",
+    "Out of memory\0",
+    "Cannot change some setting during encoding\0",
+    "The image is incompatible with already encoded images\0",
+    "Encoding of gain map planes failed\0",
+    "Decoding of gain map planes failed\0",
+    "Invalid tone mapped image item\0",
+];
+
 #[no_mangle]
-pub unsafe extern "C" fn crabby_avifResultToString(_res: avifResult) -> *const c_char {
-    // TODO: implement this function.
-    std::ptr::null()
+pub unsafe extern "C" fn crabby_avifResultToString(res: avifResult) -> *const c_char {
+    unsafe {
+        std::ffi::CStr::from_bytes_with_nul_unchecked(RESULT_TO_STRING[res.to_usize()].as_bytes())
+            .as_ptr() as *const _
+    }
 }
 
 pub type avifCropRect = CropRect;
diff --git a/src/codecs/android_mediacodec.rs b/src/codecs/android_mediacodec.rs
index d85abc8..317b6ae 100644
--- a/src/codecs/android_mediacodec.rs
+++ b/src/codecs/android_mediacodec.rs
@@ -18,6 +18,7 @@ use crate::decoder::Category;
 use crate::image::Image;
 use crate::image::YuvRange;
 use crate::internal_utils::pixels::*;
+use crate::internal_utils::stream::IStream;
 use crate::internal_utils::*;
 use crate::*;
 
@@ -27,11 +28,12 @@ use std::ffi::CString;
 use std::os::raw::c_char;
 use std::ptr;
 
-#[derive(Debug, Default)]
-pub struct MediaCodec {
-    codec: Option<*mut AMediaCodec>,
-    format: Option<*mut AMediaFormat>,
-    output_buffer_index: Option<usize>,
+#[cfg(android_soong)]
+include!(concat!(env!("OUT_DIR"), "/mediaimage2_bindgen.rs"));
+
+#[derive(Debug)]
+struct MediaFormat {
+    format: *mut AMediaFormat,
 }
 
 macro_rules! c_str {
@@ -41,17 +43,172 @@ macro_rules! c_str {
     };
 }
 
-fn get_i32(format: *mut AMediaFormat, key: *const c_char) -> Option<i32> {
-    let mut value: i32 = 0;
-    match unsafe { AMediaFormat_getInt32(format, key, &mut value as *mut _) } {
-        true => Some(value),
-        false => None,
+#[derive(Debug, Default)]
+struct PlaneInfo {
+    color_format: AndroidMediaCodecOutputColorFormat,
+    offset: [isize; 3],
+    row_stride: [u32; 3],
+    column_stride: [u32; 3],
+}
+
+impl PlaneInfo {
+    fn pixel_format(&self) -> PixelFormat {
+        match self.color_format {
+            AndroidMediaCodecOutputColorFormat::P010 => PixelFormat::AndroidP010,
+            AndroidMediaCodecOutputColorFormat::Yuv420Flexible => {
+                let u_before_v = self.offset[2] == self.offset[1] + 1;
+                let v_before_u = self.offset[1] == self.offset[2] + 1;
+                let is_nv_format = self.column_stride == [1, 2, 2] && (u_before_v || v_before_u);
+                match (is_nv_format, u_before_v) {
+                    (true, true) => PixelFormat::AndroidNv12,
+                    (true, false) => PixelFormat::AndroidNv21,
+                    (false, _) => PixelFormat::Yuv420,
+                }
+            }
+        }
+    }
+
+    fn depth(&self) -> u8 {
+        match self.color_format {
+            AndroidMediaCodecOutputColorFormat::P010 => 16,
+            AndroidMediaCodecOutputColorFormat::Yuv420Flexible => 8,
+        }
     }
 }
 
-fn get_i32_from_str(format: *mut AMediaFormat, key: &str) -> Option<i32> {
-    c_str!(key_str, key_str_tmp, key);
-    get_i32(format, key_str)
+impl MediaFormat {
+    fn get_i32(&self, key: *const c_char) -> Option<i32> {
+        let mut value: i32 = 0;
+        match unsafe { AMediaFormat_getInt32(self.format, key, &mut value as *mut _) } {
+            true => Some(value),
+            false => None,
+        }
+    }
+
+    fn get_i32_from_str(&self, key: &str) -> Option<i32> {
+        c_str!(key_str, key_str_tmp, key);
+        self.get_i32(key_str)
+    }
+
+    fn width(&self) -> AvifResult<i32> {
+        self.get_i32(unsafe { AMEDIAFORMAT_KEY_WIDTH })
+            .ok_or(AvifError::UnknownError("".into()))
+    }
+
+    fn height(&self) -> AvifResult<i32> {
+        self.get_i32(unsafe { AMEDIAFORMAT_KEY_HEIGHT })
+            .ok_or(AvifError::UnknownError("".into()))
+    }
+
+    fn slice_height(&self) -> AvifResult<i32> {
+        self.get_i32(unsafe { AMEDIAFORMAT_KEY_SLICE_HEIGHT })
+            .ok_or(AvifError::UnknownError("".into()))
+    }
+
+    fn stride(&self) -> AvifResult<i32> {
+        self.get_i32(unsafe { AMEDIAFORMAT_KEY_STRIDE })
+            .ok_or(AvifError::UnknownError("".into()))
+    }
+
+    fn color_format(&self) -> AvifResult<i32> {
+        self.get_i32(unsafe { AMEDIAFORMAT_KEY_COLOR_FORMAT })
+            .ok_or(AvifError::UnknownError("".into()))
+    }
+
+    fn color_range(&self) -> YuvRange {
+        // color-range is documented but isn't exposed as a constant in the NDK:
+        // https://developer.android.com/reference/android/media/MediaFormat#KEY_COLOR_RANGE
+        let color_range = self.get_i32_from_str("color-range").unwrap_or(2);
+        if color_range == 0 {
+            YuvRange::Limited
+        } else {
+            YuvRange::Full
+        }
+    }
+
+    fn guess_plane_info(&self) -> AvifResult<PlaneInfo> {
+        let height = self.height()?;
+        let slice_height = self.slice_height().unwrap_or(height);
+        let stride = self.stride()?;
+        let color_format: AndroidMediaCodecOutputColorFormat = self.color_format()?.into();
+        let mut plane_info = PlaneInfo {
+            color_format,
+            ..Default::default()
+        };
+        match color_format {
+            AndroidMediaCodecOutputColorFormat::P010 => {
+                plane_info.row_stride = [
+                    u32_from_i32(stride)?,
+                    u32_from_i32(stride)?,
+                    0, // V plane is not used for P010.
+                ];
+                plane_info.column_stride = [
+                    2, 2, 0, // V plane is not used for P010.
+                ];
+                plane_info.offset = [
+                    0,
+                    isize_from_i32(stride * slice_height)?,
+                    0, // V plane is not used for P010.
+                ];
+            }
+            AndroidMediaCodecOutputColorFormat::Yuv420Flexible => {
+                plane_info.row_stride = [
+                    u32_from_i32(stride)?,
+                    u32_from_i32((stride + 1) / 2)?,
+                    u32_from_i32((stride + 1) / 2)?,
+                ];
+                plane_info.column_stride = [1, 1, 1];
+                plane_info.offset[0] = 0;
+                plane_info.offset[1] = isize_from_i32(stride * slice_height)?;
+                let u_plane_size = isize_from_i32(((stride + 1) / 2) * ((height + 1) / 2))?;
+                // When color format is YUV_420_FLEXIBLE, the V plane comes before the U plane.
+                plane_info.offset[2] = plane_info.offset[1] - u_plane_size;
+            }
+        }
+        Ok(plane_info)
+    }
+
+    fn get_plane_info(&self) -> AvifResult<PlaneInfo> {
+        // When not building for the Android platform, image-data is not available, so simply try to
+        // guess the buffer format based on the available keys in the format.
+        #[cfg(not(android_soong))]
+        return self.guess_plane_info();
+
+        #[cfg(android_soong)]
+        {
+            c_str!(key_str, key_str_tmp, "image-data");
+            let mut data: *mut std::ffi::c_void = ptr::null_mut();
+            let mut size: usize = 0;
+            if !unsafe {
+                AMediaFormat_getBuffer(
+                    self.format,
+                    key_str,
+                    &mut data as *mut _,
+                    &mut size as *mut _,
+                )
+            } {
+                return self.guess_plane_info();
+            }
+            if size != std::mem::size_of::<android_MediaImage2>() {
+                return self.guess_plane_info();
+            }
+            let image_data = unsafe { *(data as *const android_MediaImage2) };
+            if image_data.mType != android_MediaImage2_Type_MEDIA_IMAGE_TYPE_YUV {
+                return self.guess_plane_info();
+            }
+            let planes = unsafe { ptr::read_unaligned(ptr::addr_of!(image_data.mPlane)) };
+            let mut plane_info = PlaneInfo {
+                color_format: self.color_format()?.into(),
+                ..Default::default()
+            };
+            for plane_index in 0usize..3 {
+                plane_info.offset[plane_index] = isize_from_u32(planes[plane_index].mOffset)?;
+                plane_info.row_stride[plane_index] = u32_from_i32(planes[plane_index].mRowInc)?;
+                plane_info.column_stride[plane_index] = u32_from_i32(planes[plane_index].mColInc)?;
+            }
+            return Ok(plane_info);
+        }
+    }
 }
 
 enum CodecInitializer {
@@ -59,51 +216,100 @@ enum CodecInitializer {
     ByMimeType(String),
 }
 
-fn get_codec_initializers(mime_type: &str) -> Vec<CodecInitializer> {
-    let dav1d = String::from("c2.android.av1-dav1d.decoder");
-    let gav1 = String::from("c2.android.av1.decoder");
+#[cfg(android_soong)]
+fn prefer_hardware_decoder(config: &DecoderConfig) -> bool {
+    let prefer_hw = rustutils::system_properties::read_bool(
+        "media.stagefright.thumbnail.prefer_hw_codecs",
+        false,
+    )
+    .unwrap_or(false);
+    if config.codec_config.is_avif() {
+        // We will return true when all of the below conditions are true:
+        // 1) prefer_hw is true.
+        // 2) category is not Alpha and category is not Gainmap. We do not prefer hardware for
+        //    decoding these categories since they generally tend to be monochrome images and using
+        //    hardware for that is unreliable.
+        // 3) profile is 0. As of Sep 2024, there are no AV1 hardware decoders that support
+        //    anything other than profile 0.
+        prefer_hw
+            && config.category != Category::Alpha
+            && config.category != Category::Gainmap
+            && config.codec_config.profile() == 0
+    } else {
+        // We will return true when one of the following conditions are true:
+        // 1) prefer_hw is true.
+        // 2) depth is greater than 8. As of Nov 2024, the default HEVC software decoder on Android
+        //    only supports 8-bit images.
+        prefer_hw || config.depth > 8
+    }
+}
+
+fn get_codec_initializers(config: &DecoderConfig) -> Vec<CodecInitializer> {
     #[cfg(android_soong)]
     {
         // Use a specific decoder if it is requested.
         if let Ok(Some(decoder)) =
             rustutils::system_properties::read("media.crabbyavif.debug.decoder")
         {
-            return vec![CodecInitializer::ByName(decoder)];
-        }
-        // If hardware decoders are allowed, then search by mime type first and then try the
-        // software decoders.
-        let prefer_hw = rustutils::system_properties::read_bool(
-            "media.stagefright.thumbnail.prefer_hw_codecs",
-            false,
-        )
-        .unwrap_or(false);
-        if prefer_hw {
-            return vec![
-                CodecInitializer::ByMimeType(mime_type.to_string()),
-                CodecInitializer::ByName(dav1d),
-                CodecInitializer::ByName(gav1),
-            ];
+            if !decoder.is_empty() {
+                return vec![CodecInitializer::ByName(decoder)];
+            }
         }
     }
-    // Default list of initializers.
-    vec![
-        CodecInitializer::ByName(dav1d),
-        CodecInitializer::ByName(gav1),
-        CodecInitializer::ByMimeType(mime_type.to_string()),
-    ]
+    let dav1d = String::from("c2.android.av1-dav1d.decoder");
+    let gav1 = String::from("c2.android.av1.decoder");
+    let hevc = String::from("c2.android.hevc.decoder");
+    // As of Sep 2024, c2.android.av1.decoder is the only known decoder to support 12-bit AV1. So
+    // prefer that for 12 bit images.
+    let prefer_gav1 = config.depth == 12;
+    let is_avif = config.codec_config.is_avif();
+    let mime_type = if is_avif { MediaCodec::AV1_MIME } else { MediaCodec::HEVC_MIME };
+    let prefer_hw = false;
+    #[cfg(android_soong)]
+    let prefer_hw = prefer_hardware_decoder(config);
+    match (prefer_hw, is_avif, prefer_gav1) {
+        (true, false, _) => vec![
+            CodecInitializer::ByMimeType(mime_type.to_string()),
+            CodecInitializer::ByName(hevc),
+        ],
+        (false, false, _) => vec![
+            CodecInitializer::ByName(hevc),
+            CodecInitializer::ByMimeType(mime_type.to_string()),
+        ],
+        (true, true, true) => vec![
+            CodecInitializer::ByName(gav1),
+            CodecInitializer::ByMimeType(mime_type.to_string()),
+            CodecInitializer::ByName(dav1d),
+        ],
+        (true, true, false) => vec![
+            CodecInitializer::ByMimeType(mime_type.to_string()),
+            CodecInitializer::ByName(dav1d),
+            CodecInitializer::ByName(gav1),
+        ],
+        (false, true, true) => vec![
+            CodecInitializer::ByName(gav1),
+            CodecInitializer::ByName(dav1d),
+            CodecInitializer::ByMimeType(mime_type.to_string()),
+        ],
+        (false, true, false) => vec![
+            CodecInitializer::ByName(dav1d),
+            CodecInitializer::ByName(gav1),
+            CodecInitializer::ByMimeType(mime_type.to_string()),
+        ],
+    }
+}
+
+#[derive(Default)]
+pub struct MediaCodec {
+    codec: Option<*mut AMediaCodec>,
+    format: Option<MediaFormat>,
+    output_buffer_index: Option<usize>,
+    config: Option<DecoderConfig>,
 }
 
 impl MediaCodec {
-    // Flexible YUV 420 format used for 8-bit images:
-    // https://developer.android.com/reference/android/media/MediaCodecInfo.CodecCapabilities#COLOR_FormatYUV420Flexible
-    const YUV_420_FLEXIBLE: i32 = 2135033992;
-    // Old YUV 420 planar format used for 8-bit images. This is not used by newer codecs, but is
-    // there for backwards compatibility with some old codecs:
-    // https://developer.android.com/reference/android/media/MediaCodecInfo.CodecCapabilities#COLOR_FormatYUV420Planar
-    const YUV_420_PLANAR: i32 = 19;
-    // YUV P010 format used for 10-bit images:
-    // https://developer.android.com/reference/android/media/MediaCodecInfo.CodecCapabilities#COLOR_FormatYUVP010
-    const YUV_P010: i32 = 54;
+    const AV1_MIME: &str = "video/av01";
+    const HEVC_MIME: &str = "video/hevc";
 }
 
 impl Decoder for MediaCodec {
@@ -115,7 +321,11 @@ impl Decoder for MediaCodec {
         if format.is_null() {
             return Err(AvifError::UnknownError("".into()));
         }
-        c_str!(mime_type, mime_type_tmp, "video/av01");
+        c_str!(
+            mime_type,
+            mime_type_tmp,
+            if config.codec_config.is_avif() { Self::AV1_MIME } else { Self::HEVC_MIME }
+        );
         unsafe {
             AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, mime_type);
             AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_WIDTH, i32_from_u32(config.width)?);
@@ -127,16 +337,34 @@ impl Decoder for MediaCodec {
             AMediaFormat_setInt32(
                 format,
                 AMEDIAFORMAT_KEY_COLOR_FORMAT,
-                if config.depth == 10 { Self::YUV_P010 } else { Self::YUV_420_FLEXIBLE },
+                if config.depth == 8 {
+                    AndroidMediaCodecOutputColorFormat::Yuv420Flexible
+                } else {
+                    AndroidMediaCodecOutputColorFormat::P010
+                } as i32,
             );
             // low-latency is documented but isn't exposed as a constant in the NDK:
             // https://developer.android.com/reference/android/media/MediaFormat#KEY_LOW_LATENCY
             c_str!(low_latency, low_latency_tmp, "low-latency");
             AMediaFormat_setInt32(format, low_latency, 1);
+            AMediaFormat_setInt32(
+                format,
+                AMEDIAFORMAT_KEY_MAX_INPUT_SIZE,
+                i32_from_usize(config.max_input_size)?,
+            );
+            let codec_specific_data = config.codec_config.raw_data();
+            if !codec_specific_data.is_empty() {
+                AMediaFormat_setBuffer(
+                    format,
+                    AMEDIAFORMAT_KEY_CSD_0,
+                    codec_specific_data.as_ptr() as *const _,
+                    codec_specific_data.len(),
+                );
+            }
         }
 
         let mut codec = ptr::null_mut();
-        for codec_initializer in get_codec_initializers("video/av01") {
+        for codec_initializer in get_codec_initializers(config) {
             codec = match codec_initializer {
                 CodecInitializer::ByName(name) => {
                     c_str!(codec_name, codec_name_tmp, name.as_str());
@@ -175,12 +403,13 @@ impl Decoder for MediaCodec {
             return Err(AvifError::NoCodecAvailable);
         }
         self.codec = Some(codec);
+        self.config = Some(config.clone());
         Ok(())
     }
 
     fn get_next_image(
         &mut self,
-        av1_payload: &[u8],
+        payload: &[u8],
         _spatial_id: u8,
         image: &mut Image,
         category: Category,
@@ -195,42 +424,65 @@ impl Decoder for MediaCodec {
                 AMediaCodec_releaseOutputBuffer(codec, self.output_buffer_index.unwrap(), false);
             }
         }
+        let mut retry_count = 0;
         unsafe {
-            let input_index = AMediaCodec_dequeueInputBuffer(codec, 0);
-            if input_index >= 0 {
-                let mut input_buffer_size: usize = 0;
-                let input_buffer = AMediaCodec_getInputBuffer(
-                    codec,
-                    input_index as usize,
-                    &mut input_buffer_size as *mut _,
-                );
-                if input_buffer.is_null() {
+            while retry_count < 100 {
+                retry_count += 1;
+                let input_index = AMediaCodec_dequeueInputBuffer(codec, 10000);
+                if input_index >= 0 {
+                    let mut input_buffer_size: usize = 0;
+                    let input_buffer = AMediaCodec_getInputBuffer(
+                        codec,
+                        input_index as usize,
+                        &mut input_buffer_size as *mut _,
+                    );
+                    if input_buffer.is_null() {
+                        return Err(AvifError::UnknownError(format!(
+                            "input buffer at index {input_index} was null"
+                        )));
+                    }
+                    let hevc_whole_nal_units = self.hevc_whole_nal_units(payload)?;
+                    let codec_payload = match &hevc_whole_nal_units {
+                        Some(hevc_payload) => hevc_payload,
+                        None => payload,
+                    };
+                    if input_buffer_size < codec_payload.len() {
+                        return Err(AvifError::UnknownError(format!(
+                        "input buffer (size {input_buffer_size}) was not big enough. required size: {}",
+                        codec_payload.len()
+                    )));
+                    }
+                    ptr::copy_nonoverlapping(
+                        codec_payload.as_ptr(),
+                        input_buffer,
+                        codec_payload.len(),
+                    );
+
+                    if AMediaCodec_queueInputBuffer(
+                        codec,
+                        usize_from_isize(input_index)?,
+                        /*offset=*/ 0,
+                        codec_payload.len(),
+                        /*pts=*/ 0,
+                        /*flags=*/ 0,
+                    ) != media_status_t_AMEDIA_OK
+                    {
+                        return Err(AvifError::UnknownError("".into()));
+                    }
+                    break;
+                } else if input_index == AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize {
+                    continue;
+                } else {
                     return Err(AvifError::UnknownError(format!(
-                        "input buffer at index {input_index} was null"
+                        "got input index < 0: {input_index}"
                     )));
                 }
-                ptr::copy_nonoverlapping(av1_payload.as_ptr(), input_buffer, av1_payload.len());
-                if AMediaCodec_queueInputBuffer(
-                    codec,
-                    usize_from_isize(input_index)?,
-                    /*offset=*/ 0,
-                    av1_payload.len(),
-                    /*pts=*/ 0,
-                    /*flags=*/ 0,
-                ) != media_status_t_AMEDIA_OK
-                {
-                    return Err(AvifError::UnknownError("".into()));
-                }
-            } else {
-                return Err(AvifError::UnknownError(format!(
-                    "got input index < 0: {input_index}"
-                )));
             }
         }
         let mut buffer: Option<*mut u8> = None;
         let mut buffer_size: usize = 0;
-        let mut retry_count = 0;
         let mut buffer_info = AMediaCodecBufferInfo::default();
+        retry_count = 0;
         while retry_count < 100 {
             retry_count += 1;
             unsafe {
@@ -255,7 +507,7 @@ impl Decoder for MediaCodec {
                     if format.is_null() {
                         return Err(AvifError::UnknownError("output format was null".into()));
                     }
-                    self.format = Some(format);
+                    self.format = Some(MediaFormat { format });
                     continue;
                 } else if output_index == AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize {
                     continue;
@@ -275,119 +527,49 @@ impl Decoder for MediaCodec {
             return Err(AvifError::UnknownError("format is none".into()));
         }
         let buffer = buffer.unwrap();
-        let format = self.format.unwrap();
-        let width = get_i32(format, unsafe { AMEDIAFORMAT_KEY_WIDTH })
-            .ok_or(AvifError::UnknownError("".into()))?;
-        let height = get_i32(format, unsafe { AMEDIAFORMAT_KEY_HEIGHT })
-            .ok_or(AvifError::UnknownError("".into()))?;
-        let slice_height =
-            get_i32(format, unsafe { AMEDIAFORMAT_KEY_SLICE_HEIGHT }).unwrap_or(height);
-        let stride = get_i32(format, unsafe { AMEDIAFORMAT_KEY_STRIDE })
-            .ok_or(AvifError::UnknownError("".into()))?;
-        let color_format = get_i32(format, unsafe { AMEDIAFORMAT_KEY_COLOR_FORMAT })
-            .ok_or(AvifError::UnknownError("".into()))?;
-        // color-range is documented but isn't exposed as a constant in the NDK:
-        // https://developer.android.com/reference/android/media/MediaFormat#KEY_COLOR_RANGE
-        let color_range = get_i32_from_str(format, "color-range").unwrap_or(2);
+        let format = self.format.unwrap_ref();
+        image.width = format.width()? as u32;
+        image.height = format.height()? as u32;
+        image.yuv_range = format.color_range();
+        let plane_info = format.get_plane_info()?;
+        image.depth = plane_info.depth();
+        image.yuv_format = plane_info.pixel_format();
         match category {
             Category::Alpha => {
                 // TODO: make sure alpha plane matches previous alpha plane.
-                image.width = width as u32;
-                image.height = height as u32;
-                match color_format {
-                    Self::YUV_420_PLANAR | Self::YUV_420_FLEXIBLE => {
-                        image.yuv_format = PixelFormat::Yuv420;
-                        image.depth = 8;
-                    }
-                    Self::YUV_P010 => {
-                        image.yuv_format = PixelFormat::AndroidP010;
-                        image.depth = 10;
-                    }
-                    _ => {
-                        return Err(AvifError::UnknownError(format!(
-                            "unknown color format: {color_format}"
-                        )));
-                    }
-                }
-                image.yuv_range = if color_range == 0 { YuvRange::Limited } else { YuvRange::Full };
-                image.row_bytes[3] = stride as u32;
+                image.row_bytes[3] = plane_info.row_stride[0];
                 image.planes[3] = Some(Pixels::from_raw_pointer(
-                    buffer,
+                    unsafe { buffer.offset(plane_info.offset[0]) },
                     image.depth as u32,
                     image.height,
                     image.row_bytes[3],
                 )?);
             }
             _ => {
-                image.width = width as u32;
-                image.height = height as u32;
-                let reverse_uv;
-                match color_format {
-                    Self::YUV_420_FLEXIBLE => {
-                        reverse_uv = true;
-                        image.yuv_format = PixelFormat::Yuv420;
-                        image.depth = 8;
-                    }
-                    Self::YUV_420_PLANAR => {
-                        reverse_uv = false;
-                        image.yuv_format = PixelFormat::Yuv420;
-                        image.depth = 8;
-                    }
-                    Self::YUV_P010 => {
-                        reverse_uv = false;
-                        image.yuv_format = PixelFormat::AndroidP010;
-                        image.depth = 10;
-                    }
-                    _ => {
-                        return Err(AvifError::UnknownError(format!(
-                            "unknown color format: {color_format}"
-                        )));
-                    }
-                }
-                image.yuv_range = if color_range == 0 { YuvRange::Limited } else { YuvRange::Full };
                 image.chroma_sample_position = ChromaSamplePosition::Unknown;
-
                 image.color_primaries = ColorPrimaries::Unspecified;
                 image.transfer_characteristics = TransferCharacteristics::Unspecified;
                 image.matrix_coefficients = MatrixCoefficients::Unspecified;
 
-                // Populate the Y plane.
-                image.row_bytes[0] = stride as u32;
-                image.planes[0] = Some(Pixels::from_raw_pointer(
-                    buffer,
-                    image.depth as u32,
-                    image.height,
-                    image.row_bytes[0],
-                )?);
-
-                // Populate the UV planes.
-                if image.yuv_format == PixelFormat::Yuv420 {
-                    image.row_bytes[1] = ((stride + 1) / 2) as u32;
-                    image.row_bytes[2] = ((stride + 1) / 2) as u32;
-                    let u_plane_offset = isize_from_i32(stride * slice_height)?;
-                    let (u_index, v_index) = if reverse_uv { (2, 1) } else { (1, 2) };
-                    image.planes[u_index] = Some(Pixels::from_raw_pointer(
-                        unsafe { buffer.offset(u_plane_offset) },
-                        image.depth as u32,
-                        (image.height + 1) / 2,
-                        image.row_bytes[u_index],
-                    )?);
-                    let u_plane_size = isize_from_i32(((stride + 1) / 2) * ((height + 1) / 2))?;
-                    let v_plane_offset = u_plane_offset + u_plane_size;
-                    image.planes[v_index] = Some(Pixels::from_raw_pointer(
-                        unsafe { buffer.offset(v_plane_offset) },
-                        image.depth as u32,
-                        (image.height + 1) / 2,
-                        image.row_bytes[v_index],
-                    )?);
-                } else {
-                    let uv_plane_offset = isize_from_i32(stride * slice_height)?;
-                    image.row_bytes[1] = stride as u32;
-                    image.planes[1] = Some(Pixels::from_raw_pointer(
-                        unsafe { buffer.offset(uv_plane_offset) },
+                for i in 0usize..3 {
+                    if i == 2
+                        && matches!(
+                            image.yuv_format,
+                            PixelFormat::AndroidP010
+                                | PixelFormat::AndroidNv12
+                                | PixelFormat::AndroidNv21
+                        )
+                    {
+                        // V plane is not needed for these formats.
+                        break;
+                    }
+                    image.row_bytes[i] = plane_info.row_stride[i];
+                    let plane_height = if i == 0 { image.height } else { (image.height + 1) / 2 };
+                    image.planes[i] = Some(Pixels::from_raw_pointer(
+                        unsafe { buffer.offset(plane_info.offset[i]) },
                         image.depth as u32,
-                        (image.height + 1) / 2,
-                        image.row_bytes[1],
+                        plane_height,
+                        image.row_bytes[i],
                     )?);
                 }
             }
@@ -396,6 +578,39 @@ impl Decoder for MediaCodec {
     }
 }
 
+impl MediaCodec {
+    fn hevc_whole_nal_units(&self, payload: &[u8]) -> AvifResult<Option<Vec<u8>>> {
+        if !self.config.unwrap_ref().codec_config.is_heic() {
+            return Ok(None);
+        }
+        // For HEVC, MediaCodec expects whole NAL units with each unit prefixed with a start code
+        // of "\x00\x00\x00\x01".
+        let nal_length_size = self.config.unwrap_ref().codec_config.nal_length_size() as usize;
+        let mut offset = 0;
+        let mut hevc_payload = Vec::new();
+        while offset < payload.len() {
+            let payload_slice = &payload[offset..];
+            let mut stream = IStream::create(payload_slice);
+            let nal_length = usize_from_u64(stream.read_uxx(nal_length_size as u8)?)?;
+            let nal_unit_end = checked_add!(nal_length, nal_length_size)?;
+            let nal_unit_range = nal_length_size..nal_unit_end;
+            check_slice_range(payload_slice.len(), &nal_unit_range)?;
+            // Start code.
+            hevc_payload.extend_from_slice(&[0, 0, 0, 1]);
+            // NAL Unit.
+            hevc_payload.extend_from_slice(&payload_slice[nal_unit_range]);
+            offset = checked_add!(offset, nal_unit_end)?;
+        }
+        Ok(Some(hevc_payload))
+    }
+}
+
+impl Drop for MediaFormat {
+    fn drop(&mut self) {
+        unsafe { AMediaFormat_delete(self.format) };
+    }
+}
+
 impl Drop for MediaCodec {
     fn drop(&mut self) {
         if self.codec.is_some() {
@@ -415,9 +630,6 @@ impl Drop for MediaCodec {
             }
             self.codec = None;
         }
-        if self.format.is_some() {
-            unsafe { AMediaFormat_delete(self.format.unwrap()) };
-            self.format = None;
-        }
+        self.format = None;
     }
 }
diff --git a/src/codecs/mod.rs b/src/codecs/mod.rs
index 6e9111b..056cf50 100644
--- a/src/codecs/mod.rs
+++ b/src/codecs/mod.rs
@@ -23,9 +23,11 @@ pub mod android_mediacodec;
 
 use crate::decoder::Category;
 use crate::image::Image;
+use crate::parser::mp4box::CodecConfiguration;
+use crate::AndroidMediaCodecOutputColorFormat;
 use crate::AvifResult;
 
-#[derive(Default)]
+#[derive(Clone, Default)]
 pub struct DecoderConfig {
     pub operating_point: u8,
     pub all_layers: bool,
@@ -33,6 +35,10 @@ pub struct DecoderConfig {
     pub height: u32,
     pub depth: u8,
     pub max_threads: u32,
+    pub max_input_size: usize,
+    pub codec_config: CodecConfiguration,
+    pub category: Category,
+    pub android_mediacodec_output_color_format: AndroidMediaCodecOutputColorFormat,
 }
 
 pub trait Decoder {
diff --git a/src/decoder/item.rs b/src/decoder/item.rs
index 151cba9..3da813e 100644
--- a/src/decoder/item.rs
+++ b/src/decoder/item.rs
@@ -199,20 +199,19 @@ impl Item {
         Ok(())
     }
 
-    #[allow(non_snake_case)]
     pub fn validate_properties(&self, items: &Items, pixi_required: bool) -> AvifResult<()> {
-        let av1C = self
-            .av1C()
+        let codec_config = self
+            .codec_config()
             .ok_or(AvifError::BmffParseFailed("missing av1C property".into()))?;
         if self.item_type == "grid" {
             for grid_item_id in &self.grid_item_ids {
                 let grid_item = items.get(grid_item_id).unwrap();
-                let grid_av1C = grid_item
-                    .av1C()
-                    .ok_or(AvifError::BmffParseFailed("missing av1C property".into()))?;
-                if av1C != grid_av1C {
+                let grid_codec_config = grid_item.codec_config().ok_or(
+                    AvifError::BmffParseFailed("missing codec config property".into()),
+                )?;
+                if codec_config != grid_codec_config {
                     return Err(AvifError::BmffParseFailed(
-                        "av1c of grid items do not match".into(),
+                        "codec config of grid items do not match".into(),
                     ));
                 }
             }
@@ -220,9 +219,9 @@ impl Item {
         match self.pixi() {
             Some(pixi) => {
                 for depth in &pixi.plane_depths {
-                    if *depth != av1C.depth() {
+                    if *depth != codec_config.depth() {
                         return Err(AvifError::BmffParseFailed(
-                            "pixi depth does not match av1C depth".into(),
+                            "pixi depth does not match codec config depth".into(),
                         ));
                     }
                 }
@@ -236,8 +235,7 @@ impl Item {
         Ok(())
     }
 
-    #[allow(non_snake_case)]
-    pub fn av1C(&self) -> Option<&CodecConfiguration> {
+    pub fn codec_config(&self) -> Option<&CodecConfiguration> {
         find_property!(self.properties, CodecConfiguration)
     }
 
@@ -263,6 +261,19 @@ impl Item {
                                    aux_type == "urn:mpeg:hevc:2015:auxid:1")
     }
 
+    pub fn is_image_codec_item(&self) -> bool {
+        [
+            "av01",
+            #[cfg(feature = "heic")]
+            "hvc1",
+        ]
+        .contains(&self.item_type.as_str())
+    }
+
+    pub fn is_image_item(&self) -> bool {
+        self.is_image_codec_item() || self.item_type == "grid"
+    }
+
     pub fn should_skip(&self) -> bool {
         // The item has no payload in idat or mdat. It cannot be a coded image item, a
         // non-identity derived image item, or Exif/XMP metadata.
@@ -270,7 +281,7 @@ impl Item {
             // An essential property isn't supported by libavif. Ignore the whole item.
             || self.has_unsupported_essential_property
             // Probably Exif/XMP or some other data.
-            || (self.item_type != "av01" && self.item_type != "grid")
+            || !self.is_image_item()
             // libavif does not support thumbnails.
             || self.thumbnail_for_id != 0
     }
diff --git a/src/decoder/mod.rs b/src/decoder/mod.rs
index 99a9ce6..b2e6b77 100644
--- a/src/decoder/mod.rs
+++ b/src/decoder/mod.rs
@@ -75,35 +75,40 @@ pub enum CodecChoice {
 }
 
 impl CodecChoice {
-    fn get_codec(&self) -> AvifResult<Codec> {
+    fn get_codec(&self, is_avif: bool) -> AvifResult<Codec> {
         match self {
             CodecChoice::Auto => {
                 // Preferred order of codecs in Auto mode: Android MediaCodec, Dav1d, Libgav1.
-                return CodecChoice::MediaCodec
-                    .get_codec()
-                    .or_else(|_| CodecChoice::Dav1d.get_codec())
-                    .or_else(|_| CodecChoice::Libgav1.get_codec());
+                CodecChoice::MediaCodec
+                    .get_codec(is_avif)
+                    .or_else(|_| CodecChoice::Dav1d.get_codec(is_avif))
+                    .or_else(|_| CodecChoice::Libgav1.get_codec(is_avif))
             }
             CodecChoice::Dav1d => {
-                #[cfg(feature = "dav1d")]
-                {
-                    return Ok(Box::<Dav1d>::default());
+                if !is_avif {
+                    return Err(AvifError::NoCodecAvailable);
                 }
+                #[cfg(feature = "dav1d")]
+                return Ok(Box::<Dav1d>::default());
+                #[cfg(not(feature = "dav1d"))]
+                return Err(AvifError::NoCodecAvailable);
             }
             CodecChoice::Libgav1 => {
-                #[cfg(feature = "libgav1")]
-                {
-                    return Ok(Box::<Libgav1>::default());
+                if !is_avif {
+                    return Err(AvifError::NoCodecAvailable);
                 }
+                #[cfg(feature = "libgav1")]
+                return Ok(Box::<Libgav1>::default());
+                #[cfg(not(feature = "libgav1"))]
+                return Err(AvifError::NoCodecAvailable);
             }
             CodecChoice::MediaCodec => {
                 #[cfg(feature = "android_mediacodec")]
-                {
-                    return Ok(Box::<MediaCodec>::default());
-                }
+                return Ok(Box::<MediaCodec>::default());
+                #[cfg(not(feature = "android_mediacodec"))]
+                return Err(AvifError::NoCodecAvailable);
             }
         }
-        Err(AvifError::NoCodecAvailable)
     }
 }
 
@@ -121,6 +126,29 @@ pub const DEFAULT_IMAGE_SIZE_LIMIT: u32 = 16384 * 16384;
 pub const DEFAULT_IMAGE_DIMENSION_LIMIT: u32 = 32768;
 pub const DEFAULT_IMAGE_COUNT_LIMIT: u32 = 12 * 3600 * 60;
 
+#[derive(Debug, PartialEq)]
+pub enum ImageContentType {
+    None,
+    ColorAndAlpha,
+    GainMap,
+    All,
+}
+
+impl ImageContentType {
+    pub fn categories(&self) -> Vec<Category> {
+        match self {
+            Self::None => vec![],
+            Self::ColorAndAlpha => vec![Category::Color, Category::Alpha],
+            Self::GainMap => vec![Category::Gainmap],
+            Self::All => Category::ALL.to_vec(),
+        }
+    }
+
+    pub fn gainmap(&self) -> bool {
+        matches!(self, Self::GainMap | Self::All)
+    }
+}
+
 #[derive(Debug)]
 pub struct Settings {
     pub source: Source,
@@ -129,13 +157,13 @@ pub struct Settings {
     pub strictness: Strictness,
     pub allow_progressive: bool,
     pub allow_incremental: bool,
-    pub enable_decoding_gainmap: bool,
-    pub enable_parsing_gainmap_metadata: bool,
+    pub image_content_to_decode: ImageContentType,
     pub codec_choice: CodecChoice,
     pub image_size_limit: u32,
     pub image_dimension_limit: u32,
     pub image_count_limit: u32,
     pub max_threads: u32,
+    pub android_mediacodec_output_color_format: AndroidMediaCodecOutputColorFormat,
 }
 
 impl Default for Settings {
@@ -147,13 +175,13 @@ impl Default for Settings {
             strictness: Default::default(),
             allow_progressive: false,
             allow_incremental: false,
-            enable_decoding_gainmap: false,
-            enable_parsing_gainmap_metadata: false,
+            image_content_to_decode: ImageContentType::ColorAndAlpha,
             codec_choice: Default::default(),
             image_size_limit: DEFAULT_IMAGE_SIZE_LIMIT,
             image_dimension_limit: DEFAULT_IMAGE_DIMENSION_LIMIT,
             image_count_limit: DEFAULT_IMAGE_COUNT_LIMIT,
             max_threads: 1,
+            android_mediacodec_output_color_format: AndroidMediaCodecOutputColorFormat::default(),
         }
     }
 }
@@ -277,6 +305,15 @@ pub struct Decoder {
     color_track_id: Option<u32>,
     parse_state: ParseState,
     io_stats: IOStats,
+    compression_format: CompressionFormat,
+}
+
+#[repr(C)]
+#[derive(Clone, Copy, Debug, Default, PartialEq)]
+pub enum CompressionFormat {
+    #[default]
+    Avif = 0,
+    Heic = 1,
 }
 
 #[derive(Clone, Copy, Debug, Default, PartialEq)]
@@ -311,7 +348,7 @@ impl Category {
 macro_rules! find_property {
     ($properties:expr, $property_name:ident) => {
         $properties.iter().find_map(|p| match p {
-            ItemProperty::$property_name(value) => Some(*value),
+            ItemProperty::$property_name(value) => Some(value.clone()),
             _ => None,
         })
     };
@@ -348,6 +385,9 @@ impl Decoder {
     pub fn io_stats(&self) -> IOStats {
         self.io_stats
     }
+    pub fn compression_format(&self) -> CompressionFormat {
+        self.compression_format
+    }
 
     fn parsing_complete(&self) -> bool {
         self.parse_state == ParseState::Complete
@@ -411,23 +451,16 @@ impl Decoder {
             }
         }
 
-        // Make up an alpha item for convenience.
-        // TODO(yguyon): Find another item id if max is used.
-        let alpha_item_id = self
-            .items
-            .keys()
-            .max()
-            .unwrap()
-            .checked_add(1)
-            .ok_or(AvifError::NotImplemented)?;
+        // Make up an alpha item for convenience. For the item_id, choose the first id that is not
+        // found in the actual image. In the very unlikely case that all the item ids are used,
+        // treat this as an image without alpha channel.
+        let alpha_item_id = match (1..u32::MAX).find(|&id| !self.items.contains_key(&id)) {
+            Some(id) => id,
+            None => return Ok(None),
+        };
         let first_item = self.items.get(&alpha_item_indices[0]).unwrap();
-        let properties = match first_item.av1C() {
-            #[allow(non_snake_case)]
-            Some(av1C) => {
-                let mut vector: Vec<ItemProperty> = create_vec_exact(1)?;
-                vector.push(ItemProperty::CodecConfiguration(*av1C));
-                vector
-            }
+        let properties = match first_item.codec_config() {
+            Some(config) => vec![ItemProperty::CodecConfiguration(config.clone())],
             None => return Ok(None),
         };
         let alpha_item = Item {
@@ -525,6 +558,9 @@ impl Decoder {
             self.gainmap.alt_plane_count = pixi.plane_depths.len() as u8;
             self.gainmap.alt_plane_depth = pixi.plane_depths[0];
         }
+        // HEIC files created by Apple have some of these properties set in the Tonemap item. So do
+        // not perform this validation when HEIC is enabled.
+        #[cfg(not(feature = "heic"))]
         if find_property!(tonemap_item.properties, PixelAspectRatio).is_some()
             || find_property!(tonemap_item.properties, CleanAperture).is_some()
             || find_property!(tonemap_item.properties, ImageRotation).is_some()
@@ -655,8 +691,7 @@ impl Decoder {
         }
         let tile_count = self.tile_info[category.usize()].grid_tile_count()? as usize;
         let mut grid_item_ids: Vec<u32> = create_vec_exact(tile_count)?;
-        #[allow(non_snake_case)]
-        let mut first_av1C: Option<CodecConfiguration> = None;
+        let mut first_codec_config: Option<CodecConfiguration> = None;
         // Collect all the dimg items.
         for dimg_item_id in self.items.keys() {
             if *dimg_item_id == item_id {
@@ -669,18 +704,21 @@ impl Decoder {
             if dimg_item.dimg_for_id != item_id {
                 continue;
             }
-            if dimg_item.item_type != "av01" || dimg_item.has_unsupported_essential_property {
+            if !dimg_item.is_image_codec_item() || dimg_item.has_unsupported_essential_property {
                 return Err(AvifError::InvalidImageGrid(
                     "invalid input item in dimg grid".into(),
                 ));
             }
-            if first_av1C.is_none() {
+            if first_codec_config.is_none() {
                 // Adopt the configuration property of the first tile.
                 // validate_properties() makes sure they are all equal.
-                first_av1C = Some(
-                    *dimg_item
-                        .av1C()
-                        .ok_or(AvifError::BmffParseFailed("missing av1C property".into()))?,
+                first_codec_config = Some(
+                    dimg_item
+                        .codec_config()
+                        .ok_or(AvifError::BmffParseFailed(
+                            "missing codec config property".into(),
+                        ))?
+                        .clone(),
                 );
             }
             if grid_item_ids.len() >= tile_count {
@@ -702,8 +740,9 @@ impl Decoder {
         // the 'iref' box.
         grid_item_ids.sort_by_key(|k| self.items.get(k).unwrap().dimg_index);
         let item = self.items.get_mut(&item_id).unwrap();
-        item.properties
-            .push(ItemProperty::CodecConfiguration(first_av1C.unwrap()));
+        item.properties.push(ItemProperty::CodecConfiguration(
+            first_codec_config.unwrap(),
+        ));
         item.grid_item_ids = grid_item_ids;
         Ok(())
     }
@@ -728,6 +767,7 @@ impl Decoder {
         self.codecs = decoder.codecs;
         self.color_track_id = decoder.color_track_id;
         self.parse_state = decoder.parse_state;
+        self.compression_format = decoder.compression_format;
     }
 
     pub fn parse(&mut self) -> AvifResult<()> {
@@ -738,9 +778,6 @@ impl Decoder {
         if self.io.is_none() {
             return Err(AvifError::IoNotSet);
         }
-        if self.settings.enable_decoding_gainmap && !self.settings.enable_parsing_gainmap_metadata {
-            return Err(AvifError::InvalidArgument);
-        }
 
         if self.parse_state == ParseState::None {
             self.reset();
@@ -889,7 +926,7 @@ impl Decoder {
                 }
 
                 // Optional gainmap item
-                if self.settings.enable_parsing_gainmap_metadata && avif_boxes.ftyp.has_tmap() {
+                if avif_boxes.ftyp.has_tmap() {
                     if let Some((tonemap_id, gainmap_id)) =
                         self.find_gainmap_item(item_ids[Category::Color.usize()])?
                     {
@@ -904,7 +941,7 @@ impl Decoder {
                             self.populate_grid_item_ids(gainmap_id, Category::Gainmap)?;
                             self.validate_gainmap_item(gainmap_id, tonemap_id)?;
                             self.gainmap_present = true;
-                            if self.settings.enable_decoding_gainmap {
+                            if self.settings.image_content_to_decode.gainmap() {
                                 item_ids[Category::Gainmap.usize()] = gainmap_id;
                             }
                         }
@@ -973,13 +1010,13 @@ impl Decoder {
                         .unwrap();
                     self.gainmap.image.width = gainmap_item.width;
                     self.gainmap.image.height = gainmap_item.height;
-                    #[allow(non_snake_case)]
-                    let av1C = gainmap_item
-                        .av1C()
+                    let codec_config = gainmap_item
+                        .codec_config()
                         .ok_or(AvifError::BmffParseFailed("".into()))?;
-                    self.gainmap.image.depth = av1C.depth();
-                    self.gainmap.image.yuv_format = av1C.pixel_format();
-                    self.gainmap.image.chroma_sample_position = av1C.chroma_sample_position;
+                    self.gainmap.image.depth = codec_config.depth();
+                    self.gainmap.image.yuv_format = codec_config.pixel_format();
+                    self.gainmap.image.chroma_sample_position =
+                        codec_config.chroma_sample_position();
                 }
 
                 // This borrow has to be in the end of this branch.
@@ -1057,12 +1094,16 @@ impl Decoder {
                 }
             }
 
-            #[allow(non_snake_case)]
-            let av1C = find_property!(color_properties, CodecConfiguration)
+            let codec_config = find_property!(color_properties, CodecConfiguration)
                 .ok_or(AvifError::BmffParseFailed("".into()))?;
-            self.image.depth = av1C.depth();
-            self.image.yuv_format = av1C.pixel_format();
-            self.image.chroma_sample_position = av1C.chroma_sample_position;
+            self.image.depth = codec_config.depth();
+            self.image.yuv_format = codec_config.pixel_format();
+            self.image.chroma_sample_position = codec_config.chroma_sample_position();
+            self.compression_format = if codec_config.is_avif() {
+                CompressionFormat::Avif
+            } else {
+                CompressionFormat::Heic
+            };
 
             if cicp_set {
                 self.parse_state = ParseState::Complete;
@@ -1090,16 +1131,7 @@ impl Decoder {
         )
     }
 
-    #[allow(unreachable_code)]
     fn can_use_single_codec(&self) -> AvifResult<bool> {
-        #[cfg(feature = "android_mediacodec")]
-        {
-            // Android MediaCodec does not support using a single codec instance for images of
-            // varying formats (which could happen when image contains alpha).
-            // TODO: return false for now. But investigate cases where it is possible to use a
-            // single codec instance (it may work for grids).
-            return Ok(false);
-        }
         let total_tile_count = checked_add!(
             checked_add!(self.tiles[0].len(), self.tiles[1].len())?,
             self.tiles[2].len()
@@ -1138,7 +1170,10 @@ impl Decoder {
 
     fn create_codec(&mut self, category: Category, tile_index: usize) -> AvifResult<()> {
         let tile = &self.tiles[category.usize()][tile_index];
-        let mut codec: Codec = self.settings.codec_choice.get_codec()?;
+        let mut codec: Codec = self
+            .settings
+            .codec_choice
+            .get_codec(tile.codec_config.is_avif())?;
         let config = DecoderConfig {
             operating_point: tile.operating_point,
             all_layers: tile.input.all_layers,
@@ -1146,6 +1181,12 @@ impl Decoder {
             height: tile.height,
             depth: self.image.depth,
             max_threads: self.settings.max_threads,
+            max_input_size: tile.max_sample_size(),
+            codec_config: tile.codec_config.clone(),
+            category,
+            android_mediacodec_output_color_format: self
+                .settings
+                .android_mediacodec_output_color_format,
         };
         codec.initialize(&config)?;
         self.codecs.push(codec);
@@ -1156,15 +1197,21 @@ impl Decoder {
         if !self.codecs.is_empty() {
             return Ok(());
         }
-        if matches!(self.source, Source::Tracks) {
-            // In this case, we will use at most two codec instances (one for the color planes and
-            // one for the alpha plane). Gain maps are not supported.
-            self.codecs = create_vec_exact(2)?;
-            self.create_codec(Category::Color, 0)?;
-            self.tiles[Category::Color.usize()][0].codec_index = 0;
-            if !self.tiles[Category::Alpha.usize()].is_empty() {
-                self.create_codec(Category::Alpha, 0)?;
-                self.tiles[Category::Alpha.usize()][0].codec_index = 1;
+        if matches!(self.source, Source::Tracks) || cfg!(feature = "android_mediacodec") {
+            // In this case, there are two possibilities in the following order:
+            //  1) If source is Tracks, then we will use at most two codec instances (one each for
+            //     Color and Alpha). Gainmap will always be empty.
+            //  2) If android_mediacodec is true, then we will use at most three codec instances
+            //     (one for each category).
+            self.codecs = create_vec_exact(3)?;
+            for category in self.settings.image_content_to_decode.categories() {
+                if self.tiles[category.usize()].is_empty() {
+                    continue;
+                }
+                self.create_codec(category, 0)?;
+                for tile in &mut self.tiles[category.usize()] {
+                    tile.codec_index = self.codecs.len() - 1;
+                }
             }
         } else if self.can_use_single_codec()? {
             self.codecs = create_vec_exact(1)?;
@@ -1176,7 +1223,7 @@ impl Decoder {
             }
         } else {
             self.codecs = create_vec_exact(self.tiles.iter().map(|tiles| tiles.len()).sum())?;
-            for category in Category::ALL {
+            for category in self.settings.image_content_to_decode.categories() {
                 for tile_index in 0..self.tiles[category.usize()].len() {
                     self.create_codec(category, tile_index)?;
                     self.tiles[category.usize()][tile_index].codec_index = self.codecs.len() - 1;
@@ -1242,7 +1289,7 @@ impl Decoder {
     }
 
     fn prepare_samples(&mut self, image_index: usize) -> AvifResult<()> {
-        for category in Category::ALL {
+        for category in self.settings.image_content_to_decode.categories() {
             for tile_index in 0..self.tiles[category.usize()].len() {
                 self.prepare_sample(image_index, category, tile_index, None)?;
             }
@@ -1429,15 +1476,21 @@ impl Decoder {
     }
 
     fn decode_tiles(&mut self, image_index: usize) -> AvifResult<()> {
-        for category in Category::ALL {
+        let mut decoded_something = false;
+        for category in self.settings.image_content_to_decode.categories() {
             let previous_decoded_tile_count =
                 self.tile_info[category.usize()].decoded_tile_count as usize;
             let tile_count = self.tiles[category.usize()].len();
             for tile_index in previous_decoded_tile_count..tile_count {
                 self.decode_tile(image_index, category, tile_index)?;
+                decoded_something = true;
             }
         }
-        Ok(())
+        if decoded_something {
+            Ok(())
+        } else {
+            Err(AvifError::NoContent)
+        }
     }
 
     pub fn next_image(&mut self) -> AvifResult<()> {
@@ -1466,8 +1519,8 @@ impl Decoder {
         if !self.parsing_complete() {
             return false;
         }
-        for category in Category::ALL_USIZE {
-            if !self.tile_info[category].is_fully_decoded() {
+        for category in self.settings.image_content_to_decode.categories() {
+            if !self.tile_info[category.usize()].is_fully_decoded() {
                 return false;
             }
         }
@@ -1536,8 +1589,9 @@ impl Decoder {
     // next to retrieve the number of top rows that can be immediately accessed from the luma plane
     // of decoder->image, and alpha if any. The corresponding rows from the chroma planes,
     // if any, can also be accessed (half rounded up if subsampled, same number of rows otherwise).
-    // If a gain map is present, and enable_decoding_gainmap is also on, the gain map's planes can
-    // also be accessed in the same way. The number of available gain map rows is at least:
+    // If a gain map is present, and image_content_to_decode contains ImageContentType::GainMap,
+    // the gain map's planes can also be accessed in the same way.
+    // The number of available gain map rows is at least:
     //   decoder.decoded_row_count() * decoder.gainmap.image.height / decoder.image.height
     // When gain map scaling is needed, callers might choose to use a few less rows depending on how
     // many rows are needed by the scaling algorithm, to avoid the last row(s) changing when more
@@ -1553,7 +1607,7 @@ impl Decoder {
             let first_tile_height = self.tiles[category][0].height;
             let row_count = if category == Category::Gainmap.usize()
                 && self.gainmap_present()
-                && self.settings.enable_decoding_gainmap
+                && self.settings.image_content_to_decode.gainmap()
                 && self.gainmap.image.height != 0
                 && self.gainmap.image.height != self.image.height
             {
diff --git a/src/decoder/tile.rs b/src/decoder/tile.rs
index 777dd01..cc8c47d 100644
--- a/src/decoder/tile.rs
+++ b/src/decoder/tile.rs
@@ -122,6 +122,7 @@ pub struct Tile {
     pub image: Image,
     pub input: DecodeInput,
     pub codec_index: usize,
+    pub codec_config: CodecConfiguration,
 }
 
 impl Tile {
@@ -139,6 +140,10 @@ impl Tile {
             height: item.height,
             operating_point: item.operating_point(),
             image: Image::default(),
+            codec_config: item
+                .codec_config()
+                .ok_or(AvifError::BmffParseFailed("missing av1C property".into()))?
+                .clone(),
             ..Tile::default()
         };
         let mut layer_sizes: [usize; MAX_AV1_LAYER_COUNT] = [0; MAX_AV1_LAYER_COUNT];
@@ -335,4 +340,11 @@ impl Tile {
         }
         Ok(tile)
     }
+
+    pub fn max_sample_size(&self) -> usize {
+        match self.input.samples.iter().max_by_key(|sample| sample.size) {
+            Some(sample) => sample.size,
+            None => 0,
+        }
+    }
 }
diff --git a/src/image.rs b/src/image.rs
index ea9b67c..14dee70 100644
--- a/src/image.rs
+++ b/src/image.rs
@@ -151,22 +151,46 @@ impl Image {
     pub fn width(&self, plane: Plane) -> usize {
         match plane {
             Plane::Y | Plane::A => self.width as usize,
-            Plane::U | Plane::V => match self.yuv_format {
-                PixelFormat::Yuv444 | PixelFormat::AndroidP010 => self.width as usize,
+            Plane::U => match self.yuv_format {
+                PixelFormat::Yuv444
+                | PixelFormat::AndroidP010
+                | PixelFormat::AndroidNv12
+                | PixelFormat::AndroidNv21 => self.width as usize,
                 PixelFormat::Yuv420 | PixelFormat::Yuv422 => (self.width as usize + 1) / 2,
                 PixelFormat::None | PixelFormat::Yuv400 => 0,
             },
+            Plane::V => match self.yuv_format {
+                PixelFormat::Yuv444 => self.width as usize,
+                PixelFormat::Yuv420 | PixelFormat::Yuv422 => (self.width as usize + 1) / 2,
+                PixelFormat::None
+                | PixelFormat::Yuv400
+                | PixelFormat::AndroidP010
+                | PixelFormat::AndroidNv12
+                | PixelFormat::AndroidNv21 => 0,
+            },
         }
     }
 
     pub fn height(&self, plane: Plane) -> usize {
         match plane {
             Plane::Y | Plane::A => self.height as usize,
-            Plane::U | Plane::V => match self.yuv_format {
+            Plane::U => match self.yuv_format {
                 PixelFormat::Yuv444 | PixelFormat::Yuv422 => self.height as usize,
-                PixelFormat::Yuv420 | PixelFormat::AndroidP010 => (self.height as usize + 1) / 2,
+                PixelFormat::Yuv420
+                | PixelFormat::AndroidP010
+                | PixelFormat::AndroidNv12
+                | PixelFormat::AndroidNv21 => (self.height as usize + 1) / 2,
                 PixelFormat::None | PixelFormat::Yuv400 => 0,
             },
+            Plane::V => match self.yuv_format {
+                PixelFormat::Yuv444 | PixelFormat::Yuv422 => self.height as usize,
+                PixelFormat::Yuv420 => (self.height as usize + 1) / 2,
+                PixelFormat::None
+                | PixelFormat::Yuv400
+                | PixelFormat::AndroidP010
+                | PixelFormat::AndroidNv12
+                | PixelFormat::AndroidNv21 => 0,
+            },
         }
     }
 
@@ -247,7 +271,6 @@ impl Image {
                 && (self.planes[plane_index].unwrap_ref().pixel_bit_size() == 0
                     || self.planes[plane_index].unwrap_ref().pixel_bit_size() == pixel_size * 8)
             {
-                // TODO: need to memset to 0 maybe?
                 continue;
             }
             self.planes[plane_index] = Some(if self.depth == 8 {
@@ -285,8 +308,8 @@ impl Image {
         category: Category,
     ) -> AvifResult<()> {
         // This function is used only when |tile| contains pointers and self contains buffers.
-        let row_index = u64::from(tile_index / tile_info.grid.columns);
-        let column_index = u64::from(tile_index % tile_info.grid.columns);
+        let row_index = tile_index / tile_info.grid.columns;
+        let column_index = tile_index % tile_info.grid.columns;
         for plane in category.planes() {
             let plane = *plane;
             let src_plane = tile.plane_data(plane);
@@ -295,50 +318,37 @@ impl Image {
             }
             let src_plane = src_plane.unwrap();
             // If this is the last tile column, clamp to left over width.
-            let src_width_to_copy = if column_index == (tile_info.grid.columns - 1).into() {
-                let width_so_far = u64::from(src_plane.width)
-                    .checked_mul(column_index)
-                    .ok_or(AvifError::BmffParseFailed("".into()))?;
-                u64_from_usize(self.width(plane))?
-                    .checked_sub(width_so_far)
-                    .ok_or(AvifError::BmffParseFailed("".into()))?
+            let src_width_to_copy = if column_index == tile_info.grid.columns - 1 {
+                let width_so_far = checked_mul!(src_plane.width, column_index)?;
+                checked_sub!(self.width(plane), usize_from_u32(width_so_far)?)?
             } else {
-                u64::from(src_plane.width)
+                usize_from_u32(src_plane.width)?
             };
-            let src_width_to_copy = usize_from_u64(src_width_to_copy)?;
 
             // If this is the last tile row, clamp to left over height.
-            let src_height_to_copy = if row_index == (tile_info.grid.rows - 1).into() {
-                let height_so_far = u64::from(src_plane.height)
-                    .checked_mul(row_index)
-                    .ok_or(AvifError::BmffParseFailed("".into()))?;
-                u64_from_usize(self.height(plane))?
-                    .checked_sub(height_so_far)
-                    .ok_or(AvifError::BmffParseFailed("".into()))?
+            let src_height_to_copy = if row_index == tile_info.grid.rows - 1 {
+                let height_so_far = checked_mul!(src_plane.height, row_index)?;
+                checked_sub!(u32_from_usize(self.height(plane))?, height_so_far)?
             } else {
-                u64::from(src_plane.height)
+                src_plane.height
             };
 
-            let dst_y_start = checked_mul!(row_index, u64::from(src_plane.height))?;
-            let dst_x_offset =
-                usize_from_u64(checked_mul!(column_index, u64::from(src_plane.width))?)?;
+            let dst_y_start = checked_mul!(row_index, src_plane.height)?;
+            let dst_x_offset = usize_from_u32(checked_mul!(column_index, src_plane.width)?)?;
             let dst_x_offset_end = checked_add!(dst_x_offset, src_width_to_copy)?;
-            // TODO: src_height_to_copy can just be u32?
             if self.depth == 8 {
                 for y in 0..src_height_to_copy {
-                    let src_row = tile.row(plane, u32_from_u64(y)?)?;
+                    let src_row = tile.row(plane, y)?;
                     let src_slice = &src_row[0..src_width_to_copy];
-                    let dst_row =
-                        self.row_mut(plane, u32_from_u64(checked_add!(dst_y_start, y)?)?)?;
+                    let dst_row = self.row_mut(plane, checked_add!(dst_y_start, y)?)?;
                     let dst_slice = &mut dst_row[dst_x_offset..dst_x_offset_end];
                     dst_slice.copy_from_slice(src_slice);
                 }
             } else {
                 for y in 0..src_height_to_copy {
-                    let src_row = tile.row16(plane, u32_from_u64(y)?)?;
+                    let src_row = tile.row16(plane, y)?;
                     let src_slice = &src_row[0..src_width_to_copy];
-                    let dst_row =
-                        self.row16_mut(plane, u32_from_u64(checked_add!(dst_y_start, y)?)?)?;
+                    let dst_row = self.row16_mut(plane, checked_add!(dst_y_start, y)?)?;
                     let dst_slice = &mut dst_row[dst_x_offset..dst_x_offset_end];
                     dst_slice.copy_from_slice(src_slice);
                 }
diff --git a/src/internal_utils/mod.rs b/src/internal_utils/mod.rs
index 6597e70..125537e 100644
--- a/src/internal_utils/mod.rs
+++ b/src/internal_utils/mod.rs
@@ -23,10 +23,17 @@ use std::ops::Range;
 
 // Some HEIF fractional fields can be negative, hence Fraction and UFraction.
 // The denominator is always unsigned.
+
+/// cbindgen:field-names=[n,d]
 #[derive(Clone, Copy, Debug, Default)]
+#[repr(C)]
 pub struct Fraction(pub i32, pub u32);
+
+/// cbindgen:field-names=[n,d]
 #[derive(Clone, Copy, Debug, Default, PartialEq)]
+#[repr(C)]
 pub struct UFraction(pub u32, pub u32);
+
 // 'clap' fractions do not follow this pattern: both numerators and denominators
 // are used as i32, but they are signalled as u32 according to the specification
 // as of 2024. This may be fixed in later versions of the specification, see
@@ -154,6 +161,8 @@ conversion_function!(isize_from_i32, isize, i32);
 #[cfg(feature = "capi")]
 conversion_function!(isize_from_u32, isize, u32);
 conversion_function!(isize_from_usize, isize, usize);
+#[cfg(feature = "android_mediacodec")]
+conversion_function!(i32_from_usize, i32, usize);
 
 macro_rules! clamp_function {
     ($func:ident, $type:ty) => {
diff --git a/src/internal_utils/stream.rs b/src/internal_utils/stream.rs
index fa3285f..2a0ab29 100644
--- a/src/internal_utils/stream.rs
+++ b/src/internal_utils/stream.rs
@@ -137,6 +137,11 @@ impl IStream<'_> {
         Ok(&self.data[offset_start..offset_start + size])
     }
 
+    pub fn get_immutable_vec(&self, size: usize) -> AvifResult<Vec<u8>> {
+        self.check(size)?;
+        Ok(self.data[self.offset..self.offset + size].to_vec())
+    }
+
     fn get_vec(&mut self, size: usize) -> AvifResult<Vec<u8>> {
         Ok(self.get_slice(size)?.to_vec())
     }
diff --git a/src/lib.rs b/src/lib.rs
index 15e6aa9..94c1ebc 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -57,6 +57,8 @@ pub enum PixelFormat {
     // Android platform. They are intended to be pass-through formats that are used only by the
     // Android MediaCodec wrapper. All internal functions will treat them as opaque.
     AndroidP010 = 5,
+    AndroidNv12 = 6,
+    AndroidNv21 = 7,
 }
 
 impl PixelFormat {
@@ -66,22 +68,26 @@ impl PixelFormat {
 
     pub fn plane_count(&self) -> usize {
         match self {
-            PixelFormat::None | PixelFormat::AndroidP010 => 0,
+            PixelFormat::None
+            | PixelFormat::AndroidP010
+            | PixelFormat::AndroidNv12
+            | PixelFormat::AndroidNv21 => 0,
             PixelFormat::Yuv400 => 1,
             PixelFormat::Yuv420 | PixelFormat::Yuv422 | PixelFormat::Yuv444 => 3,
         }
     }
 
-    pub fn chroma_shift_x(&self) -> u32 {
+    pub fn chroma_shift_x(&self) -> (u32, u32) {
         match self {
-            Self::Yuv422 | Self::Yuv420 => 1,
-            _ => 0,
+            Self::Yuv422 | Self::Yuv420 => (1, 0),
+            Self::AndroidP010 => (1, 1),
+            _ => (0, 0),
         }
     }
 
     pub fn chroma_shift_y(&self) -> u32 {
         match self {
-            Self::Yuv420 => 1,
+            Self::Yuv420 | Self::AndroidP010 | Self::AndroidNv12 | Self::AndroidNv21 => 1,
             _ => 0,
         }
     }
@@ -313,6 +319,28 @@ pub enum AvifError {
 
 pub type AvifResult<T> = Result<T, AvifError>;
 
+#[repr(i32)]
+#[derive(Clone, Copy, Debug, Default)]
+pub enum AndroidMediaCodecOutputColorFormat {
+    // Flexible YUV 420 format used for 8-bit images:
+    // https://developer.android.com/reference/android/media/MediaCodecInfo.CodecCapabilities#COLOR_FormatYUV420Flexible
+    #[default]
+    Yuv420Flexible = 2135033992,
+    // YUV P010 format used for 10-bit images:
+    // https://developer.android.com/reference/android/media/MediaCodecInfo.CodecCapabilities#COLOR_FormatYUVP010
+    P010 = 54,
+}
+
+impl From<i32> for AndroidMediaCodecOutputColorFormat {
+    fn from(value: i32) -> Self {
+        match value {
+            2135033992 => Self::Yuv420Flexible,
+            54 => Self::P010,
+            _ => Self::default(),
+        }
+    }
+}
+
 trait OptionExtension {
     type Value;
 
diff --git a/src/parser/mp4box.rs b/src/parser/mp4box.rs
index 59024be..fa1f2b0 100644
--- a/src/parser/mp4box.rs
+++ b/src/parser/mp4box.rs
@@ -44,7 +44,7 @@ impl BoxHeader {
     }
 }
 
-#[derive(Debug)]
+#[derive(Debug, Default)]
 pub struct FileTypeBox {
     pub major_brand: String,
     // minor_version "is informative only" (section 4.3.1 of ISO/IEC 14496-12)
@@ -63,18 +63,43 @@ impl FileTypeBox {
         self.compatible_brands.iter().any(|x| x.as_str() == brand)
     }
 
+    fn has_brand_any(&self, brands: &[&str]) -> bool {
+        brands.iter().any(|brand| self.has_brand(brand))
+    }
+
     pub fn is_avif(&self) -> bool {
-        self.has_brand("avif") || self.has_brand("avis")
         // "avio" also exists but does not identify the file as AVIF on its own. See
         // https://aomediacodec.github.io/av1-avif/v1.1.0.html#image-and-image-collection-brand
+        if self.has_brand_any(&["avif", "avis"]) {
+            return true;
+        }
+        match (cfg!(feature = "heic"), cfg!(android_soong)) {
+            (false, _) => false,
+            (true, false) => self.has_brand("heic"),
+            (true, true) => {
+                // This is temporary. For the Android Framework, recognize HEIC files only if they
+                // also contain a gainmap.
+                self.has_brand("heic") && self.has_tmap()
+            }
+        }
     }
 
     pub fn needs_meta(&self) -> bool {
-        self.has_brand("avif")
+        self.has_brand_any(&[
+            "avif",
+            #[cfg(feature = "heic")]
+            "heic",
+        ])
     }
 
     pub fn needs_moov(&self) -> bool {
-        self.has_brand("avis")
+        self.has_brand_any(&[
+            "avis",
+            #[cfg(feature = "heic")]
+            "hevc",
+            #[cfg(feature = "heic")]
+            "msf1",
+        ])
     }
 
     pub fn has_tmap(&self) -> bool {
@@ -111,8 +136,8 @@ pub struct PixelInformation {
     pub plane_depths: Vec<u8>,
 }
 
-#[derive(Clone, Copy, Debug, Default, PartialEq)]
-pub struct CodecConfiguration {
+#[derive(Clone, Debug, Default, PartialEq)]
+pub struct Av1CodecConfiguration {
     pub seq_profile: u8,
     pub seq_level_idx0: u8,
     pub seq_tier0: u8,
@@ -122,30 +147,113 @@ pub struct CodecConfiguration {
     pub chroma_subsampling_x: u8,
     pub chroma_subsampling_y: u8,
     pub chroma_sample_position: ChromaSamplePosition,
+    pub raw_data: Vec<u8>,
+}
+
+#[derive(Clone, Debug, Default, PartialEq)]
+pub struct HevcCodecConfiguration {
+    pub bitdepth: u8,
+    pub nal_length_size: u8,
+    pub vps: Vec<u8>,
+    pub sps: Vec<u8>,
+    pub pps: Vec<u8>,
 }
 
 impl CodecConfiguration {
     pub fn depth(&self) -> u8 {
-        match self.twelve_bit {
-            true => 12,
-            false => match self.high_bitdepth {
-                true => 10,
-                false => 8,
+        match self {
+            Self::Av1(config) => match config.twelve_bit {
+                true => 12,
+                false => match config.high_bitdepth {
+                    true => 10,
+                    false => 8,
+                },
             },
+            Self::Hevc(config) => config.bitdepth,
         }
     }
 
     pub fn pixel_format(&self) -> PixelFormat {
-        if self.monochrome {
-            PixelFormat::Yuv400
-        } else if self.chroma_subsampling_x == 1 && self.chroma_subsampling_y == 1 {
-            PixelFormat::Yuv420
-        } else if self.chroma_subsampling_x == 1 {
-            PixelFormat::Yuv422
-        } else {
-            PixelFormat::Yuv444
+        match self {
+            Self::Av1(config) => {
+                if config.monochrome {
+                    PixelFormat::Yuv400
+                } else if config.chroma_subsampling_x == 1 && config.chroma_subsampling_y == 1 {
+                    PixelFormat::Yuv420
+                } else if config.chroma_subsampling_x == 1 {
+                    PixelFormat::Yuv422
+                } else {
+                    PixelFormat::Yuv444
+                }
+            }
+            Self::Hevc(_) => {
+                // It is okay to always return Yuv420 here since that is the only format that
+                // android_mediacodec returns.
+                // TODO: b/370549923 - Identify the correct YUV subsampling type from the codec
+                // configuration data.
+                PixelFormat::Yuv420
+            }
+        }
+    }
+
+    pub fn chroma_sample_position(&self) -> ChromaSamplePosition {
+        match self {
+            Self::Av1(config) => config.chroma_sample_position,
+            Self::Hevc(_) => {
+                // It is okay to always return ChromaSamplePosition::default() here since that is
+                // the only format that android_mediacodec returns.
+                // TODO: b/370549923 - Identify the correct chroma sample position from the codec
+                // configuration data.
+                ChromaSamplePosition::default()
+            }
         }
     }
+
+    pub fn raw_data(&self) -> Vec<u8> {
+        match self {
+            Self::Av1(config) => config.raw_data.clone(),
+            Self::Hevc(config) => {
+                // For HEVC, the codec specific data consists of the following 3 NAL units in
+                // order: VPS, SPS and PPS. Each unit should be preceded by a start code of
+                // "\x00\x00\x00\x01".
+                // https://developer.android.com/reference/android/media/MediaCodec#CSD
+                let mut data: Vec<u8> = Vec::new();
+                for nal_unit in [&config.vps, &config.sps, &config.pps] {
+                    // Start code.
+                    data.extend_from_slice(&[0, 0, 0, 1]);
+                    // Data.
+                    data.extend_from_slice(&nal_unit[..]);
+                }
+                data
+            }
+        }
+    }
+
+    pub fn profile(&self) -> u8 {
+        match self {
+            Self::Av1(config) => config.seq_profile,
+            Self::Hevc(_) => {
+                // TODO: b/370549923 - Identify the correct profile from the codec configuration
+                // data.
+                0
+            }
+        }
+    }
+
+    pub fn nal_length_size(&self) -> u8 {
+        match self {
+            Self::Av1(_) => 0, // Unused. This function is only used for HEVC.
+            Self::Hevc(config) => config.nal_length_size,
+        }
+    }
+
+    pub fn is_avif(&self) -> bool {
+        matches!(self, Self::Av1(_))
+    }
+
+    pub fn is_heic(&self) -> bool {
+        matches!(self, Self::Hevc(_))
+    }
 }
 
 #[derive(Clone, Debug, Default)]
@@ -179,6 +287,18 @@ pub struct ContentLightLevelInformation {
     pub max_pall: u16,
 }
 
+#[derive(Clone, Debug, PartialEq)]
+pub enum CodecConfiguration {
+    Av1(Av1CodecConfiguration),
+    Hevc(HevcCodecConfiguration),
+}
+
+impl Default for CodecConfiguration {
+    fn default() -> Self {
+        Self::Av1(Av1CodecConfiguration::default())
+    }
+}
+
 #[derive(Clone, Debug)]
 pub enum ItemProperty {
     ImageSpatialExtents(ImageSpatialExtents),
@@ -290,8 +410,31 @@ fn parse_header(stream: &mut IStream, top_level: bool) -> AvifResult<BoxHeader>
     })
 }
 
+// Reads a truncated ftyp box. Populates as many brands as it can read.
+fn parse_truncated_ftyp(stream: &mut IStream) -> FileTypeBox {
+    // Section 4.3.2 of ISO/IEC 14496-12.
+    // unsigned int(32) major_brand;
+    let major_brand = match stream.read_string(4) {
+        Ok(major_brand) => major_brand,
+        Err(_) => return FileTypeBox::default(),
+    };
+    let mut compatible_brands: Vec<String> = Vec::new();
+    // unsigned int(32) compatible_brands[];  // to end of the box
+    while stream.has_bytes_left().unwrap_or_default() {
+        match stream.read_string(4) {
+            Ok(brand) => compatible_brands.push(brand),
+            Err(_) => break,
+        }
+    }
+    FileTypeBox {
+        major_brand,
+        compatible_brands,
+    }
+}
+
 fn parse_ftyp(stream: &mut IStream) -> AvifResult<FileTypeBox> {
     // Section 4.3.2 of ISO/IEC 14496-12.
+    // unsigned int(32) major_brand;
     let major_brand = stream.read_string(4)?;
     // unsigned int(4) minor_version;
     stream.skip_u32()?;
@@ -302,6 +445,7 @@ fn parse_ftyp(stream: &mut IStream) -> AvifResult<FileTypeBox> {
         )));
     }
     let mut compatible_brands: Vec<String> = create_vec_exact(stream.bytes_left()? / 4)?;
+    // unsigned int(32) compatible_brands[];  // to end of the box
     while stream.has_bytes_left()? {
         compatible_brands.push(stream.read_string(4)?);
     }
@@ -501,6 +645,7 @@ fn parse_pixi(stream: &mut IStream) -> AvifResult<ItemProperty> {
 
 #[allow(non_snake_case)]
 fn parse_av1C(stream: &mut IStream) -> AvifResult<ItemProperty> {
+    let raw_data = stream.get_immutable_vec(stream.bytes_left()?)?;
     // See https://aomediacodec.github.io/av1-isobmff/v1.2.0.html#av1codecconfigurationbox-syntax.
     let mut bits = stream.sub_bit_stream(4)?;
     // unsigned int (1) marker = 1;
@@ -517,7 +662,7 @@ fn parse_av1C(stream: &mut IStream) -> AvifResult<ItemProperty> {
             "Invalid version ({version}) in av1C"
         )));
     }
-    let av1C = CodecConfiguration {
+    let av1C = Av1CodecConfiguration {
         // unsigned int(3) seq_profile;
         // unsigned int(5) seq_level_idx_0;
         seq_profile: bits.read(3)? as u8,
@@ -536,6 +681,7 @@ fn parse_av1C(stream: &mut IStream) -> AvifResult<ItemProperty> {
         chroma_subsampling_x: bits.read(1)? as u8,
         chroma_subsampling_y: bits.read(1)? as u8,
         chroma_sample_position: bits.read(2)?.into(),
+        raw_data,
     };
 
     // unsigned int(3) reserved = 0;
@@ -573,7 +719,83 @@ fn parse_av1C(stream: &mut IStream) -> AvifResult<ItemProperty> {
 
     // unsigned int(8) configOBUs[];
 
-    Ok(ItemProperty::CodecConfiguration(av1C))
+    Ok(ItemProperty::CodecConfiguration(CodecConfiguration::Av1(
+        av1C,
+    )))
+}
+
+#[allow(non_snake_case)]
+#[cfg(feature = "heic")]
+fn parse_hvcC(stream: &mut IStream) -> AvifResult<ItemProperty> {
+    // unsigned int(8) configurationVersion;
+    let configuration_version = stream.read_u8()?;
+    if configuration_version != 0 && configuration_version != 1 {
+        return Err(AvifError::BmffParseFailed(format!(
+            "Unknown configurationVersion({configuration_version}) in hvcC. Expected 0 or 1."
+        )));
+    }
+    let mut bits = stream.sub_bit_stream(21)?;
+    // unsigned int(2) general_profile_space;
+    // unsigned int(1) general_tier_flag;
+    // unsigned int(5) general_profile_idc;
+    // unsigned int(32) general_profile_compatibility_flags;
+    // unsigned int(48) general_constraint_indicator_flags;
+    // unsigned int(8) general_level_idc;
+    // bit(4) reserved = '1111'b;
+    // unsigned int(12) min_spatial_segmentation_idc;
+    // bit(6) reserved = '111111'b;
+    // unsigned int(2) parallelismType;
+    // bit(6) reserved = '111111'b;
+    // unsigned int(2) chroma_format_idc;
+    // bit(5) reserved = '11111'b;
+    bits.skip(2 + 1 + 5 + 32 + 48 + 8 + 4 + 12 + 6 + 2 + 6 + 2 + 5)?;
+    // unsigned int(3) bit_depth_luma_minus8;
+    let bitdepth = bits.read(3)? as u8 + 8;
+    // bit(5) reserved = '11111'b;
+    // unsigned int(3) bit_depth_chroma_minus8;
+    // unsigned int(16) avgFrameRate;
+    // unsigned int(2) constantFrameRate;
+    // unsigned int(3) numTemporalLayers;
+    // unsigned int(1) temporalIdNested;
+    bits.skip(5 + 3 + 16 + 2 + 3 + 1)?;
+    // unsigned int(2) lengthSizeMinusOne;
+    let nal_length_size = 1 + bits.read(2)? as u8;
+    assert!(bits.remaining_bits()? == 0);
+
+    // unsigned int(8) numOfArrays;
+    let num_of_arrays = stream.read_u8()?;
+    let mut vps: Vec<u8> = Vec::new();
+    let mut sps: Vec<u8> = Vec::new();
+    let mut pps: Vec<u8> = Vec::new();
+    for _i in 0..num_of_arrays {
+        // unsigned int(1) array_completeness;
+        // bit(1) reserved = 0;
+        // unsigned int(6) NAL_unit_type;
+        stream.skip(1)?;
+        // unsigned int(16) numNalus;
+        let num_nalus = stream.read_u16()?;
+        for _j in 0..num_nalus {
+            // unsigned int(16) nalUnitLength;
+            let nal_unit_length = stream.read_u16()?;
+            let nal_unit = stream.get_slice(nal_unit_length as usize)?;
+            let nal_unit_type = (nal_unit[0] >> 1) & 0x3f;
+            match nal_unit_type {
+                32 => vps = nal_unit.to_vec(),
+                33 => sps = nal_unit.to_vec(),
+                34 => pps = nal_unit.to_vec(),
+                _ => {}
+            }
+        }
+    }
+    Ok(ItemProperty::CodecConfiguration(CodecConfiguration::Hevc(
+        HevcCodecConfiguration {
+            bitdepth,
+            nal_length_size,
+            vps,
+            pps,
+            sps,
+        },
+    )))
 }
 
 fn parse_colr(stream: &mut IStream) -> AvifResult<ItemProperty> {
@@ -774,6 +996,8 @@ fn parse_ipco(stream: &mut IStream) -> AvifResult<Vec<ItemProperty>> {
             "lsel" => properties.push(parse_lsel(&mut sub_stream)?),
             "a1lx" => properties.push(parse_a1lx(&mut sub_stream)?),
             "clli" => properties.push(parse_clli(&mut sub_stream)?),
+            #[cfg(feature = "heic")]
+            "hvcC" => properties.push(parse_hvcC(&mut sub_stream)?),
             _ => properties.push(ItemProperty::Unknown(header.box_type)),
         }
     }
@@ -1505,8 +1729,10 @@ fn parse_elst(stream: &mut IStream, track: &mut Track) -> AvifResult<()> {
     //   flags - the following values are defined. The values of flags greater than 1 are reserved
     //     RepeatEdits 1
     if (flags & 1) == 0 {
+        // The only EditList feature that we support is repetition count for animated images. So in
+        // this case, we know that the repetition count is zero and we do not care about the rest
+        // of this box.
         track.is_repeating = false;
-        // TODO: This early return is not part of the spec, investigate
         return Ok(());
     }
     track.is_repeating = true;
@@ -1644,6 +1870,15 @@ pub fn parse(io: &mut GenericIO) -> AvifResult<AvifBoxes> {
         // Read the rest of the box if necessary.
         match header.box_type.as_str() {
             "ftyp" | "meta" | "moov" => {
+                if ftyp.is_none() && header.box_type != "ftyp" {
+                    // Section 6.3.4 of ISO/IEC 14496-12:
+                    //   The FileTypeBox shall occur before any variable-length box. Only a
+                    //   fixed-size box such as a file signature, if required, may precede it.
+                    return Err(AvifError::BmffParseFailed(format!(
+                        "expected ftyp box. found {}.",
+                        header.box_type,
+                    )));
+                }
                 let box_data = match header.size {
                     BoxSize::UntilEndOfStream => io.read(parse_offset, usize::MAX)?,
                     BoxSize::FixedSize(size) => io.read_exact(parse_offset, size)?,
@@ -1657,10 +1892,7 @@ pub fn parse(io: &mut GenericIO) -> AvifResult<AvifBoxes> {
                         }
                     }
                     "meta" => meta = Some(parse_meta(&mut box_stream)?),
-                    "moov" => {
-                        tracks = Some(parse_moov(&mut box_stream)?);
-                        // decoder.image_sequence_track_present = true;
-                    }
+                    "moov" => tracks = Some(parse_moov(&mut box_stream)?),
                     _ => {} // Not reached.
                 }
                 if ftyp.is_some() {
@@ -1690,7 +1922,6 @@ pub fn parse(io: &mut GenericIO) -> AvifResult<AvifBoxes> {
     if (ftyp.needs_meta() && meta.is_none()) || (ftyp.needs_moov() && tracks.is_none()) {
         return Err(AvifError::TruncatedData);
     }
-    // TODO: Enforce 'ftyp' as first box seen, for consistency with peek_compatible_file_type()?
     Ok(AvifBoxes {
         ftyp,
         meta: meta.unwrap_or_default(),
@@ -1707,13 +1938,19 @@ pub fn peek_compatible_file_type(data: &[u8]) -> AvifResult<bool> {
         //   Only a fixed-size box such as a file signature, if required, may precede it.
         return Ok(false);
     }
-    if header.size == BoxSize::UntilEndOfStream {
+    let header_size = match header.size {
+        BoxSize::FixedSize(size) => size,
         // The 'ftyp' box goes on till the end of the file. Either there is no brand requiring
         // anything in the file but a FileTypebox (so not AVIF), or it is invalid.
-        return Ok(false);
-    }
-    let mut header_stream = stream.sub_stream(&header.size)?;
-    let ftyp = parse_ftyp(&mut header_stream)?;
+        BoxSize::UntilEndOfStream => return Ok(false),
+    };
+    let ftyp = if header_size > stream.bytes_left()? {
+        let mut header_stream = stream.sub_stream(&BoxSize::FixedSize(stream.bytes_left()?))?;
+        parse_truncated_ftyp(&mut header_stream)
+    } else {
+        let mut header_stream = stream.sub_stream(&header.size)?;
+        parse_ftyp(&mut header_stream)?
+    };
     Ok(ftyp.is_avif())
 }
 
@@ -1799,12 +2036,14 @@ mod tests {
             0x00, 0x00, 0x00, 0xf2, 0x6d, 0x65, 0x74, 0x61, //
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, //
         ];
-        let min_required_bytes = 32;
+        // Peeking should succeed starting from byte length 12. Since that is the end offset of the
+        // first valid AVIF brand.
+        let min_required_bytes = 12;
         for i in 0..buf.len() {
             let res = mp4box::peek_compatible_file_type(&buf[..i]);
             if i < min_required_bytes {
-                // Not enough bytes.
-                assert!(res.is_err());
+                // Not enough bytes. The return should either be an error or false.
+                assert!(res.is_err() || !res.unwrap());
             } else {
                 assert!(res?);
             }
diff --git a/src/parser/obu.rs b/src/parser/obu.rs
index 602e278..95db355 100644
--- a/src/parser/obu.rs
+++ b/src/parser/obu.rs
@@ -15,7 +15,7 @@
 use crate::image::YuvRange;
 use crate::internal_utils::stream::*;
 use crate::internal_utils::*;
-use crate::parser::mp4box::CodecConfiguration;
+use crate::parser::mp4box::Av1CodecConfiguration;
 use crate::*;
 
 #[derive(Debug)]
@@ -37,7 +37,7 @@ pub struct Av1SequenceHeader {
     pub transfer_characteristics: TransferCharacteristics,
     pub matrix_coefficients: MatrixCoefficients,
     pub yuv_range: YuvRange,
-    config: CodecConfiguration,
+    config: Av1CodecConfiguration,
 }
 
 impl Av1SequenceHeader {
diff --git a/src/reformat/libyuv.rs b/src/reformat/libyuv.rs
index dcb6cfb..aef5343 100644
--- a/src/reformat/libyuv.rs
+++ b/src/reformat/libyuv.rs
@@ -32,14 +32,13 @@ fn find_constants(image: &image::Image) -> Option<(&YuvConstants, &YuvConstants)
     } else {
         image.matrix_coefficients
     };
-    /*
-    // TODO: workaround to allow identity for now.
+    // Android MediaCodec always uses Yuv420. So use Bt601 instead of Identity in that case.
+    #[cfg(feature = "android_mediacodec")]
     let matrix_coefficients = if matrix_coefficients == MatrixCoefficients::Identity {
         MatrixCoefficients::Bt601
     } else {
         matrix_coefficients
     };
-    */
     unsafe {
         match image.yuv_range {
             YuvRange::Full => match matrix_coefficients {
@@ -118,12 +117,16 @@ type YUVAToRGBMatrixHighBitDepth = unsafe extern "C" fn(
     *const u16, c_int, *const u16, c_int, *const u16, c_int, *const u16, c_int, *mut u8, c_int,
     *const YuvConstants, c_int, c_int, c_int) -> c_int;
 #[rustfmt::skip]
-type P010ToAR30Matrix = unsafe extern "C" fn(
+type P010ToRGBMatrix = unsafe extern "C" fn(
     *const u16, c_int, *const u16, c_int, *mut u8, c_int, *const YuvConstants, c_int,
     c_int) -> c_int;
 #[rustfmt::skip]
-type AR30ToAB30 = unsafe extern "C" fn(
+type ARGBToABGR = unsafe extern "C" fn(
     *const u8, c_int, *mut u8, c_int, c_int, c_int) -> c_int;
+#[rustfmt::skip]
+type NVToARGBMatrix = unsafe extern "C" fn(
+    *const u8, c_int, *const u8, c_int, *mut u8, c_int, *const YuvConstants, c_int,
+    c_int) -> c_int;
 
 #[derive(Debug)]
 enum ConversionFunction {
@@ -136,7 +139,8 @@ enum ConversionFunction {
     YUVAToRGBMatrixFilterHighBitDepth(YUVAToRGBMatrixFilterHighBitDepth),
     YUVToRGBMatrixHighBitDepth(YUVToRGBMatrixHighBitDepth),
     YUVAToRGBMatrixHighBitDepth(YUVAToRGBMatrixHighBitDepth),
-    P010ToRGBA1010102Matrix(P010ToAR30Matrix, AR30ToAB30),
+    P010ToRGBMatrix(P010ToRGBMatrix, ARGBToABGR),
+    NVToARGBMatrix(NVToARGBMatrix),
 }
 
 impl ConversionFunction {
@@ -158,8 +162,19 @@ fn find_conversion_function(
     alpha_preferred: bool,
 ) -> Option<ConversionFunction> {
     match (alpha_preferred, yuv_depth, rgb.format, yuv_format) {
-        (_, 10, Format::Rgba1010102, PixelFormat::AndroidP010) => Some(
-            ConversionFunction::P010ToRGBA1010102Matrix(P010ToAR30Matrix, AR30ToAB30),
+        (_, 8, Format::Rgba, PixelFormat::AndroidNv12) => {
+            // What Android considers to be NV12 is actually NV21 in libyuv.
+            Some(ConversionFunction::NVToARGBMatrix(NV21ToARGBMatrix))
+        }
+        (_, 8, Format::Rgba, PixelFormat::AndroidNv21) => {
+            // What Android considers to be NV21 is actually NV12 in libyuv.
+            Some(ConversionFunction::NVToARGBMatrix(NV12ToARGBMatrix))
+        }
+        (_, 16, Format::Rgba1010102, PixelFormat::AndroidP010) => Some(
+            ConversionFunction::P010ToRGBMatrix(P010ToAR30Matrix, AR30ToAB30),
+        ),
+        (_, 16, Format::Rgba, PixelFormat::AndroidP010) => Some(
+            ConversionFunction::P010ToRGBMatrix(P010ToARGBMatrix, ARGBToABGR),
         ),
         (true, 10, Format::Rgba | Format::Bgra, PixelFormat::Yuv422)
             if rgb.chroma_upsampling.bilinear_or_better_filter_allowed() =>
@@ -347,9 +362,7 @@ fn find_conversion_function(
 }
 
 pub fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<bool> {
-    if (rgb.depth != 8 && rgb.depth != 10)
-        || (image.depth != 8 && image.depth != 10 && image.depth != 12)
-    {
+    if (rgb.depth != 8 && rgb.depth != 10) || !image.depth_valid() {
         return Err(AvifError::NotImplemented);
     }
     if rgb.depth == 10
@@ -416,7 +429,7 @@ pub fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<bool
         let mut high_bd_matched = true;
         // Apply one of the high bitdepth functions if possible.
         result = match conversion_function {
-            ConversionFunction::P010ToRGBA1010102Matrix(func1, func2) => {
+            ConversionFunction::P010ToRGBMatrix(func1, func2) => {
                 let result = func1(
                     plane_u16[0],
                     plane_row_bytes[0] / 2,
@@ -429,8 +442,8 @@ pub fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<bool
                     height,
                 );
                 if result == 0 {
-                    // It is okay to use the same pointer as source and destintaion for AR30 to
-                    // AB30 conversion.
+                    // It is okay to use the same pointer as source and destination for this
+                    // conversion.
                     func2(
                         rgb.pixels(),
                         rgb_row_bytes,
@@ -544,6 +557,17 @@ pub fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<bool
                 .unwrap();
         }
         result = match conversion_function {
+            ConversionFunction::NVToARGBMatrix(func) => func(
+                plane_u8[0],
+                plane_row_bytes[0],
+                plane_u8[1],
+                plane_row_bytes[1],
+                rgb.pixels(),
+                rgb_row_bytes,
+                matrix,
+                width,
+                height,
+            ),
             ConversionFunction::YUV400ToRGBMatrix(func) => func(
                 plane_u8[0],
                 plane_row_bytes[0],
diff --git a/src/reformat/rgb.rs b/src/reformat/rgb.rs
index ffb0414..34f8285 100644
--- a/src/reformat/rgb.rs
+++ b/src/reformat/rgb.rs
@@ -233,7 +233,8 @@ impl Image {
     pub fn channel_count(&self) -> u32 {
         match self.format {
             Format::Rgba | Format::Bgra | Format::Argb | Format::Abgr => 4,
-            Format::Rgb | Format::Bgr | Format::Rgb565 => 3,
+            Format::Rgb | Format::Bgr => 3,
+            Format::Rgb565 => 2,
             Format::Rgba1010102 => 0, // This is never used.
         }
     }
@@ -302,6 +303,10 @@ impl Image {
                 return Err(AvifError::NotImplemented);
             }
         }
+        // Android MediaCodec maps all underlying YUV formats to PixelFormat::Yuv420. So do not
+        // perform this validation for Android MediaCodec. The libyuv wrapper will simply use Bt601
+        // coefficients for this color conversion.
+        #[cfg(not(feature = "android_mediacodec"))]
         if image.matrix_coefficients == MatrixCoefficients::Identity
             && !matches!(image.yuv_format, PixelFormat::Yuv444 | PixelFormat::Yuv400)
         {
@@ -332,9 +337,13 @@ impl Image {
                 }
             }
         }
-        if image.yuv_format == PixelFormat::AndroidP010 {
-            // P010 conversion is only supported via libyuv.
-            // TODO: b/362984605 - Handle alpha channel for P010.
+        if matches!(
+            image.yuv_format,
+            PixelFormat::AndroidNv12 | PixelFormat::AndroidNv21
+        ) | matches!(self.format, Format::Rgba1010102)
+        {
+            // These conversions are only supported via libyuv.
+            // TODO: b/362984605 - Handle alpha channel for these formats.
             if converted_with_libyuv {
                 return Ok(());
             } else {
diff --git a/src/reformat/rgb_impl.rs b/src/reformat/rgb_impl.rs
index f4ba168..7077bcc 100644
--- a/src/reformat/rgb_impl.rs
+++ b/src/reformat/rgb_impl.rs
@@ -77,15 +77,23 @@ fn identity_yuv8_to_rgb8_full_range(image: &image::Image, rgb: &mut rgb::Image)
 macro_rules! store_rgb_pixel8 {
     ($dst:ident, $rgb_565: ident, $index: ident, $r: ident, $g: ident, $b: ident, $r_offset: ident,
      $g_offset: ident, $b_offset: ident, $rgb_channel_count: ident, $rgb_max_channel_f: ident) => {
+        let r8 = (0.5 + ($r * $rgb_max_channel_f)) as u8;
+        let g8 = (0.5 + ($g * $rgb_max_channel_f)) as u8;
+        let b8 = (0.5 + ($b * $rgb_max_channel_f)) as u8;
         if $rgb_565 {
-            // TODO: Handle rgb565.
+            // References for RGB565 color conversion:
+            // * https://docs.microsoft.com/en-us/windows/win32/directshow/working-with-16-bit-rgb
+            // * https://chromium.googlesource.com/libyuv/libyuv/+/9892d70c965678381d2a70a1c9002d1cf136ee78/source/row_common.cc#2362
+            let r16 = ((r8 >> 3) as u16) << 11;
+            let g16 = ((g8 >> 2) as u16) << 5;
+            let b16 = (b8 >> 3) as u16;
+            let rgb565 = (r16 | g16 | b16).to_le_bytes();
+            $dst[($index * $rgb_channel_count) + $r_offset] = rgb565[0];
+            $dst[($index * $rgb_channel_count) + $r_offset + 1] = rgb565[1];
         } else {
-            $dst[($index * $rgb_channel_count) + $r_offset] =
-                (0.5 + ($r * $rgb_max_channel_f)) as u8;
-            $dst[($index * $rgb_channel_count) + $g_offset] =
-                (0.5 + ($g * $rgb_max_channel_f)) as u8;
-            $dst[($index * $rgb_channel_count) + $b_offset] =
-                (0.5 + ($b * $rgb_max_channel_f)) as u8;
+            $dst[($index * $rgb_channel_count) + $r_offset] = r8;
+            $dst[($index * $rgb_channel_count) + $g_offset] = g8;
+            $dst[($index * $rgb_channel_count) + $b_offset] = b8;
         }
     };
 }
@@ -108,6 +116,7 @@ fn yuv8_to_rgb8_color(
     let b_offset = rgb.format.b_offset();
     let rgb_channel_count = rgb.channel_count() as usize;
     let rgb_565 = rgb.format == rgb::Format::Rgb565;
+    let chroma_shift = image.yuv_format.chroma_shift_x();
     for j in 0..image.height {
         let uv_j = j >> image.yuv_format.chroma_shift_y();
         let y_row = image.row(Plane::Y, j)?;
@@ -115,7 +124,7 @@ fn yuv8_to_rgb8_color(
         let v_row = image.row(Plane::V, uv_j)?;
         let dst = rgb.row_mut(j)?;
         for i in 0..image.width as usize {
-            let uv_i = i >> image.yuv_format.chroma_shift_x();
+            let uv_i = (i >> chroma_shift.0) << chroma_shift.1;
             let y = table_y[y_row[i] as usize];
             let cb = table_uv[u_row[uv_i] as usize];
             let cr = table_uv[v_row[uv_i] as usize];
@@ -161,14 +170,17 @@ fn yuv16_to_rgb16_color(
     let g_offset = rgb.format.g_offset();
     let b_offset = rgb.format.b_offset();
     let rgb_channel_count = rgb.channel_count() as usize;
+    let chroma_shift = image.yuv_format.chroma_shift_x();
     for j in 0..image.height {
         let uv_j = j >> image.yuv_format.chroma_shift_y();
         let y_row = image.row16(Plane::Y, j)?;
         let u_row = image.row16(Plane::U, uv_j)?;
-        let v_row = image.row16(Plane::V, uv_j)?;
+        // If V plane is missing, then the format is P010. In that case, set V
+        // as U plane but starting at offset 1.
+        let v_row = image.row16(Plane::V, uv_j).unwrap_or(&u_row[1..]);
         let dst = rgb.row16_mut(j)?;
         for i in 0..image.width as usize {
-            let uv_i = i >> image.yuv_format.chroma_shift_x();
+            let uv_i = (i >> chroma_shift.0) << chroma_shift.1;
             let y = table_y[min(y_row[i], yuv_max_channel) as usize];
             let cb = table_uv[min(u_row[uv_i], yuv_max_channel) as usize];
             let cr = table_uv[min(v_row[uv_i], yuv_max_channel) as usize];
@@ -205,14 +217,17 @@ fn yuv16_to_rgb8_color(
     let b_offset = rgb.format.b_offset();
     let rgb_channel_count = rgb.channel_count() as usize;
     let rgb_565 = rgb.format == rgb::Format::Rgb565;
+    let chroma_shift = image.yuv_format.chroma_shift_x();
     for j in 0..image.height {
         let uv_j = j >> image.yuv_format.chroma_shift_y();
         let y_row = image.row16(Plane::Y, j)?;
         let u_row = image.row16(Plane::U, uv_j)?;
-        let v_row = image.row16(Plane::V, uv_j)?;
+        // If V plane is missing, then the format is P010. In that case, set V
+        // as U plane but starting at offset 1.
+        let v_row = image.row16(Plane::V, uv_j).unwrap_or(&u_row[1..]);
         let dst = rgb.row_mut(j)?;
         for i in 0..image.width as usize {
-            let uv_i = i >> image.yuv_format.chroma_shift_x();
+            let uv_i = (i >> chroma_shift.0) << chroma_shift.1;
             let y = table_y[min(y_row[i], yuv_max_channel) as usize];
             let cb = table_uv[min(u_row[uv_i], yuv_max_channel) as usize];
             let cr = table_uv[min(v_row[uv_i], yuv_max_channel) as usize];
@@ -257,6 +272,7 @@ fn yuv8_to_rgb16_color(
     let g_offset = rgb.format.g_offset();
     let b_offset = rgb.format.b_offset();
     let rgb_channel_count = rgb.channel_count() as usize;
+    let chroma_shift = image.yuv_format.chroma_shift_x();
     for j in 0..image.height {
         let uv_j = j >> image.yuv_format.chroma_shift_y();
         let y_row = image.row(Plane::Y, j)?;
@@ -264,7 +280,7 @@ fn yuv8_to_rgb16_color(
         let v_row = image.row(Plane::V, uv_j)?;
         let dst = rgb.row16_mut(j)?;
         for i in 0..image.width as usize {
-            let uv_i = i >> image.yuv_format.chroma_shift_x();
+            let uv_i = (i >> chroma_shift.0) << chroma_shift.1;
             let y = table_y[y_row[i] as usize];
             let cb = table_uv[u_row[uv_i] as usize];
             let cr = table_uv[v_row[uv_i] as usize];
@@ -568,6 +584,7 @@ pub fn yuv_to_rgb_any(
     let yuv_max_channel = image.max_channel();
     let rgb_max_channel = rgb.max_channel();
     let rgb_max_channel_f = rgb.max_channel_f();
+    let chroma_shift = image.yuv_format.chroma_shift_x();
     for j in 0..image.height {
         let uv_j = j >> image.yuv_format.chroma_shift_y();
         let y_row = image.row_generic(Plane::Y, j)?;
@@ -582,7 +599,7 @@ pub fn yuv_to_rgb_any(
             if has_color {
                 let u_row = u_row.unwrap();
                 let v_row = v_row.unwrap();
-                let uv_i = i >> image.yuv_format.chroma_shift_x();
+                let uv_i = (i >> chroma_shift.0) << chroma_shift.1;
                 if image.yuv_format == PixelFormat::Yuv444
                     || matches!(
                         chroma_upsampling,
diff --git a/src/utils/raw.rs b/src/utils/raw.rs
index 8689f1b..18ff05f 100644
--- a/src/utils/raw.rs
+++ b/src/utils/raw.rs
@@ -87,14 +87,28 @@ impl RawWriter {
             }
             let plane_data = plane_data.unwrap();
             for y in 0..plane_data.height {
-                // TODO: Handle row16.
-                let row = if let Ok(row) = image.row(plane, y) {
-                    row
+                if image.depth == 8 {
+                    let row = image.row(plane, y);
+                    if row.is_err() {
+                        return false;
+                    }
+                    let row = &row.unwrap()[..plane_data.width as usize];
+                    if self.file.unwrap_ref().write_all(row).is_err() {
+                        return false;
+                    }
                 } else {
-                    return false;
-                };
-                if self.file.unwrap_ref().write_all(row).is_err() {
-                    return false;
+                    let row = image.row16(plane, y);
+                    if row.is_err() {
+                        return false;
+                    }
+                    let row = &row.unwrap()[..plane_data.width as usize];
+                    let mut row16: Vec<u8> = Vec::new();
+                    for &pixel in row {
+                        row16.extend_from_slice(&pixel.to_le_bytes());
+                    }
+                    if self.file.unwrap_ref().write_all(&row16[..]).is_err() {
+                        return false;
+                    }
                 }
             }
         }
diff --git a/src/utils/y4m.rs b/src/utils/y4m.rs
index c1f6550..7f91c73 100644
--- a/src/utils/y4m.rs
+++ b/src/utils/y4m.rs
@@ -52,7 +52,10 @@ impl Y4MWriter {
 
         let y4m_format = match image.depth {
             8 => match image.yuv_format {
-                PixelFormat::None | PixelFormat::AndroidP010 => "",
+                PixelFormat::None
+                | PixelFormat::AndroidP010
+                | PixelFormat::AndroidNv12
+                | PixelFormat::AndroidNv21 => "",
                 PixelFormat::Yuv444 => {
                     if image.alpha_present {
                         self.write_alpha = true;
@@ -66,14 +69,20 @@ impl Y4MWriter {
                 PixelFormat::Yuv400 => "Cmono XYSCSS=400",
             },
             10 => match image.yuv_format {
-                PixelFormat::None | PixelFormat::AndroidP010 => "",
+                PixelFormat::None
+                | PixelFormat::AndroidP010
+                | PixelFormat::AndroidNv12
+                | PixelFormat::AndroidNv21 => "",
                 PixelFormat::Yuv444 => "C444p10 XYSCSS=444P10",
                 PixelFormat::Yuv422 => "C422p10 XYSCSS=422P10",
                 PixelFormat::Yuv420 => "C420p10 XYSCSS=420P10",
                 PixelFormat::Yuv400 => "Cmono10 XYSCSS=400",
             },
             12 => match image.yuv_format {
-                PixelFormat::None | PixelFormat::AndroidP010 => "",
+                PixelFormat::None
+                | PixelFormat::AndroidP010
+                | PixelFormat::AndroidNv12
+                | PixelFormat::AndroidNv21 => "",
                 PixelFormat::Yuv444 => "C444p12 XYSCSS=444P12",
                 PixelFormat::Yuv422 => "C422p12 XYSCSS=422P12",
                 PixelFormat::Yuv420 => "C420p12 XYSCSS=420P12",
diff --git a/sys/dav1d-sys/Cargo.toml b/sys/dav1d-sys/Cargo.toml
index b28b3ee..a111b8e 100644
--- a/sys/dav1d-sys/Cargo.toml
+++ b/sys/dav1d-sys/Cargo.toml
@@ -6,3 +6,6 @@ edition = "2021"
 [build-dependencies]
 bindgen = "0.69.2"
 pkg-config = "0.3.29"
+
+[lints.rust]
+unexpected_cfgs = { level = "warn", check-cfg = ['cfg(google3)'] }
diff --git a/sys/dav1d-sys/build.rs b/sys/dav1d-sys/build.rs
index c5edcc8..26355a6 100644
--- a/sys/dav1d-sys/build.rs
+++ b/sys/dav1d-sys/build.rs
@@ -77,7 +77,8 @@ fn main() {
 
     // Generate bindings.
     let header_file = PathBuf::from(&project_root).join("wrapper.h");
-    let outfile = PathBuf::from(&project_root).join("dav1d.rs");
+    let outdir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
+    let outfile = PathBuf::from(&outdir).join("dav1d_bindgen.rs");
     let mut bindings = bindgen::Builder::default()
         .header(header_file.into_os_string().into_string().unwrap())
         .clang_args(&include_paths)
@@ -104,8 +105,4 @@ fn main() {
     bindings
         .write_to_file(outfile.as_path())
         .unwrap_or_else(|_| panic!("Couldn't write bindings for dav1d"));
-    println!(
-        "cargo:rustc-env=CRABBYAVIF_DAV1D_BINDINGS_RS={}",
-        outfile.display()
-    );
 }
diff --git a/sys/dav1d-sys/src/lib.rs b/sys/dav1d-sys/src/lib.rs
index c9a0a6d..89ea477 100644
--- a/sys/dav1d-sys/src/lib.rs
+++ b/sys/dav1d-sys/src/lib.rs
@@ -12,12 +12,12 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-#![allow(warnings)]
+#[allow(warnings)]
 pub mod bindings {
-    #[cfg(not(android_soong))]
+    // Blaze does not support the `OUT_DIR` configuration used by Cargo. Instead, it specifies a
+    // complete path to the generated bindings as an environment variable.
+    #[cfg(google3)]
     include!(env!("CRABBYAVIF_DAV1D_BINDINGS_RS"));
-    // Android's soong build system does not support setting environment variables. Set the source
-    // file name directly relative to the OUT_DIR environment variable.
-    #[cfg(android_soong)]
+    #[cfg(not(google3))]
     include!(concat!(env!("OUT_DIR"), "/dav1d_bindgen.rs"));
 }
diff --git a/sys/libgav1-sys/Cargo.toml b/sys/libgav1-sys/Cargo.toml
index 9e31f2d..01c75dc 100644
--- a/sys/libgav1-sys/Cargo.toml
+++ b/sys/libgav1-sys/Cargo.toml
@@ -5,3 +5,6 @@ edition = "2021"
 
 [build-dependencies]
 bindgen = "0.69.2"
+
+[lints.rust]
+unexpected_cfgs = { level = "warn", check-cfg = ['cfg(google3)'] }
diff --git a/sys/libgav1-sys/build.rs b/sys/libgav1-sys/build.rs
index c1ef8c9..8128aac 100644
--- a/sys/libgav1-sys/build.rs
+++ b/sys/libgav1-sys/build.rs
@@ -61,7 +61,8 @@ fn main() {
     // Generate bindings.
     let header_file = PathBuf::from(&abs_library_dir).join(path_buf(&["src", "gav1", "decoder.h"]));
     let version_dir = PathBuf::from(&abs_library_dir).join(path_buf(&["src"]));
-    let outfile = PathBuf::from(&project_root).join(path_buf(&["src", "libgav1.rs"]));
+    let outdir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
+    let outfile = PathBuf::from(&outdir).join("libgav1_bindgen.rs");
     let extra_includes_str = format!("-I{}", version_dir.display());
     let mut bindings = bindgen::Builder::default()
         .header(header_file.into_os_string().into_string().unwrap())
@@ -85,8 +86,4 @@ fn main() {
     bindings
         .write_to_file(outfile.as_path())
         .unwrap_or_else(|_| panic!("Couldn't write bindings for libgav1"));
-    println!(
-        "cargo:rustc-env=CRABBYAVIF_LIBGAV1_BINDINGS_RS={}",
-        outfile.display()
-    );
 }
diff --git a/sys/libgav1-sys/src/lib.rs b/sys/libgav1-sys/src/lib.rs
index 300720e..a4636f9 100644
--- a/sys/libgav1-sys/src/lib.rs
+++ b/sys/libgav1-sys/src/lib.rs
@@ -12,7 +12,12 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+#[allow(warnings)]
 pub mod bindings {
-    #![allow(warnings)]
+    // Blaze does not support the `OUT_DIR` configuration used by Cargo. Instead, it specifies a
+    // complete path to the generated bindings as an environment variable.
+    #[cfg(google3)]
     include!(env!("CRABBYAVIF_LIBGAV1_BINDINGS_RS"));
+    #[cfg(not(google3))]
+    include!(concat!(env!("OUT_DIR"), "/libgav1_bindgen.rs"));
 }
diff --git a/sys/libyuv-sys/Cargo.toml b/sys/libyuv-sys/Cargo.toml
index 14fc7a0..b00a533 100644
--- a/sys/libyuv-sys/Cargo.toml
+++ b/sys/libyuv-sys/Cargo.toml
@@ -6,3 +6,6 @@ edition = "2021"
 [build-dependencies]
 bindgen = "0.69.2"
 pkg-config = "0.3.29"
+
+[lints.rust]
+unexpected_cfgs = { level = "warn", check-cfg = ['cfg(google3)'] }
diff --git a/sys/libyuv-sys/build.rs b/sys/libyuv-sys/build.rs
index 0dccbe2..e3eb501 100644
--- a/sys/libyuv-sys/build.rs
+++ b/sys/libyuv-sys/build.rs
@@ -84,7 +84,8 @@ fn main() {
 
     // Generate bindings.
     let header_file = PathBuf::from(&project_root).join("wrapper.h");
-    let outfile = PathBuf::from(&project_root).join(path_buf(&["src", "libyuv.rs"]));
+    let outdir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
+    let outfile = PathBuf::from(&outdir).join("libyuv_bindgen.rs");
     let mut bindings = bindgen::Builder::default()
         .header(header_file.into_os_string().into_string().unwrap())
         .clang_arg(extra_includes_str)
@@ -95,6 +96,7 @@ fn main() {
         "YuvConstants",
         "FilterMode",
         "ARGBAttenuate",
+        "ARGBToABGR",
         "ARGBUnattenuate",
         "Convert16To8Plane",
         "HalfFloatPlane",
@@ -133,7 +135,10 @@ fn main() {
         "I444AlphaToARGBMatrix",
         "I444ToARGBMatrix",
         "I444ToRGB24Matrix",
+        "NV12ToARGBMatrix",
+        "NV21ToARGBMatrix",
         "P010ToAR30Matrix",
+        "P010ToARGBMatrix",
         "AR30ToAB30",
         "kYuv2020Constants",
         "kYuvF709Constants",
@@ -157,8 +162,4 @@ fn main() {
     bindings
         .write_to_file(outfile.as_path())
         .unwrap_or_else(|_| panic!("Couldn't write bindings for libyuv"));
-    println!(
-        "cargo:rustc-env=CRABBYAVIF_LIBYUV_BINDINGS_RS={}",
-        outfile.display()
-    );
 }
diff --git a/sys/libyuv-sys/src/lib.rs b/sys/libyuv-sys/src/lib.rs
index 6a4827a..40e638f 100644
--- a/sys/libyuv-sys/src/lib.rs
+++ b/sys/libyuv-sys/src/lib.rs
@@ -12,12 +12,12 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-#![allow(warnings)]
+#[allow(warnings)]
 pub mod bindings {
-    #[cfg(not(android_soong))]
+    // Blaze does not support the `OUT_DIR` configuration used by Cargo. Instead, it specifies a
+    // complete path to the generated bindings as an environment variable.
+    #[cfg(google3)]
     include!(env!("CRABBYAVIF_LIBYUV_BINDINGS_RS"));
-    // Android's soong build system does not support setting environment variables. Set the source
-    // file name directly relative to the OUT_DIR environment variable.
-    #[cfg(android_soong)]
+    #[cfg(not(google3))]
     include!(concat!(env!("OUT_DIR"), "/libyuv_bindgen.rs"));
 }
diff --git a/sys/ndk-sys/build.rs b/sys/ndk-sys/build.rs
index f899dba..88710aa 100644
--- a/sys/ndk-sys/build.rs
+++ b/sys/ndk-sys/build.rs
@@ -69,6 +69,7 @@ fn main() {
         "AMediaFormat_delete",
         "AMediaFormat_getInt32",
         "AMediaFormat_new",
+        "AMediaFormat_setBuffer",
         "AMediaFormat_setInt32",
         "AMediaFormat_setString",
     ];
@@ -83,7 +84,9 @@ fn main() {
         "AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED",
         "AMEDIACODEC_INFO_TRY_AGAIN_LATER",
         "AMEDIAFORMAT_KEY_COLOR_FORMAT",
+        "AMEDIAFORMAT_KEY_CSD_0",
         "AMEDIAFORMAT_KEY_HEIGHT",
+        "AMEDIAFORMAT_KEY_MAX_INPUT_SIZE",
         "AMEDIAFORMAT_KEY_MIME",
         "AMEDIAFORMAT_KEY_SLICE_HEIGHT",
         "AMEDIAFORMAT_KEY_STRIDE",
diff --git a/sys/ndk-sys/mediaimage2_wrapper.hpp b/sys/ndk-sys/mediaimage2_wrapper.hpp
new file mode 100644
index 0000000..2ca19e3
--- /dev/null
+++ b/sys/ndk-sys/mediaimage2_wrapper.hpp
@@ -0,0 +1,2 @@
+#include <stdint.h>
+#include <media/hardware/VideoAPI.h>
diff --git a/tests/data/blue.heic b/tests/data/blue.heic
new file mode 100644
index 0000000..982d0db
Binary files /dev/null and b/tests/data/blue.heic differ
diff --git a/tests/data/seine_hdr_gainmap_small_srgb.avif b/tests/data/seine_hdr_gainmap_small_srgb.avif
deleted file mode 100644
index 681edac..0000000
Binary files a/tests/data/seine_hdr_gainmap_small_srgb.avif and /dev/null differ
diff --git a/tests/data/seine_hdr_gainmap_srgb.avif b/tests/data/seine_hdr_gainmap_srgb.avif
deleted file mode 100644
index 6a79b9d..0000000
Binary files a/tests/data/seine_hdr_gainmap_srgb.avif and /dev/null differ
diff --git a/tests/data/seine_sdr_gainmap_big_srgb.avif b/tests/data/seine_sdr_gainmap_big_srgb.avif
deleted file mode 100644
index fad5b61..0000000
Binary files a/tests/data/seine_sdr_gainmap_big_srgb.avif and /dev/null differ
diff --git a/tests/data/seine_sdr_gainmap_srgb.avif b/tests/data/seine_sdr_gainmap_srgb.avif
index b716742..09c4ba2 100644
Binary files a/tests/data/seine_sdr_gainmap_srgb.avif and b/tests/data/seine_sdr_gainmap_srgb.avif differ
diff --git a/tests/decoder_tests.rs b/tests/decoder_tests.rs
index 21aadcf..d533756 100644
--- a/tests/decoder_tests.rs
+++ b/tests/decoder_tests.rs
@@ -13,6 +13,8 @@
 // limitations under the License.
 
 use crabby_avif::decoder::track::RepetitionCount;
+use crabby_avif::decoder::CompressionFormat;
+use crabby_avif::decoder::ImageContentType;
 use crabby_avif::image::*;
 use crabby_avif::reformat::rgb;
 use crabby_avif::*;
@@ -61,6 +63,7 @@ fn animated_image() {
     let mut decoder = get_decoder("colors-animated-8bpc.avif");
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     assert!(!image.alpha_present);
     assert!(image.image_sequence_track_present);
@@ -84,6 +87,7 @@ fn animated_image_with_source_set_to_primary_item() {
     decoder.settings.source = decoder::Source::PrimaryItem;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     assert!(!image.alpha_present);
     // This will be reported as true irrespective of the preferred source.
@@ -108,6 +112,7 @@ fn animated_image_with_alpha_and_metadata() {
     let mut decoder = get_decoder("colors-animated-8bpc-alpha-exif-xmp.avif");
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     assert!(image.alpha_present);
     assert!(image.image_sequence_track_present);
@@ -129,6 +134,7 @@ fn keyframes() {
     let mut decoder = get_decoder("colors-animated-12bpc-keyframes-0-2-3.avif");
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     assert!(image.image_sequence_track_present);
     assert_eq!(decoder.image_count(), 5);
@@ -161,6 +167,7 @@ fn color_grid_alpha_no_grid() {
     let mut decoder = get_decoder("color_grid_alpha_nogrid.avif");
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     assert!(image.alpha_present);
     assert!(!image.image_sequence_track_present);
@@ -190,6 +197,7 @@ fn progressive(filename: &str, layer_count: u32, width: u32, height: u32) {
     decoder.settings.allow_progressive = false;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     assert!(matches!(
         image.progressive_state,
@@ -199,6 +207,7 @@ fn progressive(filename: &str, layer_count: u32, width: u32, height: u32) {
     decoder.settings.allow_progressive = true;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     assert!(matches!(
         image.progressive_state,
@@ -229,6 +238,7 @@ fn decoder_parse_icc_exif_xmp() {
     decoder.settings.ignore_exif = true;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
 
     assert_eq!(image.icc.len(), 596);
@@ -244,6 +254,7 @@ fn decoder_parse_icc_exif_xmp() {
     decoder.settings.ignore_exif = false;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
 
     assert_eq!(image.exif.len(), 1126);
@@ -263,10 +274,10 @@ fn decoder_parse_icc_exif_xmp() {
 #[test]
 fn color_grid_gainmap_different_grid() {
     let mut decoder = get_decoder("color_grid_gainmap_different_grid.avif");
-    decoder.settings.enable_decoding_gainmap = true;
-    decoder.settings.enable_parsing_gainmap_metadata = true;
+    decoder.settings.image_content_to_decode = ImageContentType::All;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     // Color+alpha: 4x3 grid of 128x200 tiles.
     assert_eq!(image.width, 128 * 4);
@@ -284,16 +295,17 @@ fn color_grid_gainmap_different_grid() {
     }
     let res = decoder.next_image();
     assert!(res.is_ok());
+    assert!(decoder.gainmap().image.row_bytes[0] > 0);
 }
 
 // From avifgainmaptest.cc
 #[test]
 fn color_grid_alpha_grid_gainmap_nogrid() {
     let mut decoder = get_decoder("color_grid_alpha_grid_gainmap_nogrid.avif");
-    decoder.settings.enable_decoding_gainmap = true;
-    decoder.settings.enable_parsing_gainmap_metadata = true;
+    decoder.settings.image_content_to_decode = ImageContentType::All;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     // Color+alpha: 4x3 grid of 128x200 tiles.
     assert_eq!(image.width, 128 * 4);
@@ -311,16 +323,17 @@ fn color_grid_alpha_grid_gainmap_nogrid() {
     }
     let res = decoder.next_image();
     assert!(res.is_ok());
+    assert!(decoder.gainmap().image.row_bytes[0] > 0);
 }
 
 // From avifgainmaptest.cc
 #[test]
 fn color_nogrid_alpha_nogrid_gainmap_grid() {
     let mut decoder = get_decoder("color_nogrid_alpha_nogrid_gainmap_grid.avif");
-    decoder.settings.enable_decoding_gainmap = true;
-    decoder.settings.enable_parsing_gainmap_metadata = true;
+    decoder.settings.image_content_to_decode = ImageContentType::All;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     // Color+alpha: single image of size 128x200.
     assert_eq!(image.width, 128);
@@ -338,16 +351,17 @@ fn color_nogrid_alpha_nogrid_gainmap_grid() {
     }
     let res = decoder.next_image();
     assert!(res.is_ok());
+    assert!(decoder.gainmap().image.row_bytes[0] > 0);
 }
 
 // From avifgainmaptest.cc
 #[test]
 fn gainmap_oriented() {
     let mut decoder = get_decoder("gainmap_oriented.avif");
-    decoder.settings.enable_decoding_gainmap = true;
-    decoder.settings.enable_parsing_gainmap_metadata = true;
+    decoder.settings.image_content_to_decode = ImageContentType::All;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     assert_eq!(image.irot_angle, Some(1));
     assert_eq!(image.imir_axis, Some(0));
@@ -363,24 +377,11 @@ fn gainmap_oriented() {
 #[test_case::test_case("unsupported_gainmap_version.avif")]
 #[test_case::test_case("unsupported_gainmap_minimum_version.avif")]
 fn decode_unsupported_version(filename: &str) {
-    // Parse with various enable_decoding_gainmap and
-    // enable_parsing_gainmap_metadata settings.
+    // Parse with various settings.
     let mut decoder = get_decoder(filename);
-    decoder.settings.enable_decoding_gainmap = false;
-    decoder.settings.enable_parsing_gainmap_metadata = false;
-    let res = decoder.parse();
-    assert!(res.is_ok());
-    // Gain map not found since enable_parsing_gainmap_metadata is false.
-    assert!(!decoder.gainmap_present());
-    assert_eq!(decoder.gainmap().image.width, 0);
-    assert_eq!(decoder.gainmap().metadata.base_hdr_headroom.0, 0);
-    assert_eq!(decoder.gainmap().metadata.alternate_hdr_headroom.0, 0);
-
-    decoder = get_decoder(filename);
-    decoder.settings.enable_decoding_gainmap = false;
-    decoder.settings.enable_parsing_gainmap_metadata = true;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     // Gain map marked as not present because the metadata is not supported.
     assert!(!decoder.gainmap_present());
     assert_eq!(decoder.gainmap().image.width, 0);
@@ -388,18 +389,10 @@ fn decode_unsupported_version(filename: &str) {
     assert_eq!(decoder.gainmap().metadata.alternate_hdr_headroom.0, 0);
 
     decoder = get_decoder(filename);
-    decoder.settings.enable_decoding_gainmap = true;
-    decoder.settings.enable_parsing_gainmap_metadata = false;
-    let res = decoder.parse();
-    // Invalid enableDecodingGainMap=true and enable_parsing_gainmap_metadata
-    // combination.
-    assert_eq!(res.err(), Some(AvifError::InvalidArgument));
-
-    decoder = get_decoder(filename);
-    decoder.settings.enable_decoding_gainmap = true;
-    decoder.settings.enable_parsing_gainmap_metadata = true;
+    decoder.settings.image_content_to_decode = ImageContentType::All;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     // Gainmap not found: its metadata is not supported.
     assert!(!decoder.gainmap_present());
     assert_eq!(decoder.gainmap().image.width, 0);
@@ -411,10 +404,9 @@ fn decode_unsupported_version(filename: &str) {
 #[test]
 fn decode_unsupported_writer_version_with_extra_bytes() {
     let mut decoder = get_decoder("unsupported_gainmap_writer_version_with_extra_bytes.avif");
-    decoder.settings.enable_decoding_gainmap = false;
-    decoder.settings.enable_parsing_gainmap_metadata = true;
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     // Decodes successfully: there are extra bytes at the end of the gain map
     // metadata but that's expected as the writer_version field is higher
     // that supported.
@@ -427,14 +419,84 @@ fn decode_unsupported_writer_version_with_extra_bytes() {
 #[test]
 fn decode_supported_writer_version_with_extra_bytes() {
     let mut decoder = get_decoder("supported_gainmap_writer_version_with_extra_bytes.avif");
-    decoder.settings.enable_decoding_gainmap = false;
-    decoder.settings.enable_parsing_gainmap_metadata = true;
     let res = decoder.parse();
     // Fails to decode: there are extra bytes at the end of the gain map metadata
     // that shouldn't be there.
     assert!(matches!(res, Err(AvifError::InvalidToneMappedImage(_))));
 }
 
+// From avifgainmaptest.cc
+#[test]
+fn decode_ignore_gain_map_but_read_metadata() {
+    let mut decoder = get_decoder("seine_sdr_gainmap_srgb.avif");
+
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
+    decoder.image().expect("image was none");
+    // Gain map not decoded.
+    assert!(decoder.gainmap_present());
+    // ... but not decoded because enableDecodingGainMap is false by default.
+    assert_eq!(decoder.gainmap().image.width, 0);
+    assert_eq!(decoder.gainmap().image.row_bytes[0], 0);
+    // Check that the gain map metadata WAS populated.
+    assert_eq!(decoder.gainmap().metadata.alternate_hdr_headroom.0, 13);
+    assert_eq!(decoder.gainmap().metadata.alternate_hdr_headroom.1, 10);
+}
+
+// From avifgainmaptest.cc
+#[test]
+fn decode_ignore_color_and_alpha() {
+    let mut decoder = get_decoder("seine_sdr_gainmap_srgb.avif");
+    decoder.settings.image_content_to_decode = ImageContentType::GainMap;
+
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
+
+    let image = decoder.image().expect("image was none");
+    // Main image metadata is available.
+    assert_eq!(image.width, 400);
+    // The gain map metadata is available.
+    assert!(decoder.gainmap_present());
+    assert_eq!(decoder.gainmap().image.width, 400);
+    assert_eq!(decoder.gainmap().metadata.alternate_hdr_headroom.0, 13);
+
+    if !HAS_DECODER {
+        return;
+    }
+    let res = decoder.next_image();
+    let image = decoder.image().expect("image was none");
+    assert!(res.is_ok());
+    // Main image pixels are not available.
+    assert_eq!(image.row_bytes[0], 0);
+    // Gain map pixels are available.
+    assert!(decoder.gainmap().image.row_bytes[0] > 0);
+}
+
+// From avifgainmaptest.cc
+#[test_case::test_case("paris_icc_exif_xmp.avif")]
+#[test_case::test_case("sofa_grid1x5_420.avif")]
+#[test_case::test_case("color_grid_alpha_nogrid.avif")]
+#[test_case::test_case("seine_sdr_gainmap_srgb.avif")]
+fn decode_ignore_all(filename: &str) {
+    let mut decoder = get_decoder(filename);
+    // Ignore both the main image and the gain map.
+    decoder.settings.image_content_to_decode = ImageContentType::None;
+    // But do read the gain map metadata
+
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
+    let image = decoder.image().expect("image was none");
+    // Main image metadata is available.
+    assert!(image.width > 0);
+    // But trying to access the next image should give an error because both
+    // ignoreColorAndAlpha and enableDecodingGainMap are set.
+    let res = decoder.next_image();
+    assert!(res.is_err());
+}
+
 // From avifcllitest.cc
 #[test_case::test_case("clli_0_0.avif", 0, 0; "clli_0_0")]
 #[test_case::test_case("clli_0_1.avif", 0, 1; "clli_0_1")]
@@ -451,6 +513,7 @@ fn clli(filename: &str, max_cll: u16, max_pall: u16) {
     let mut decoder = get_decoder(&filename_with_prefix);
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     if max_cll == 0 && max_pall == 0 {
         assert!(image.clli.is_none());
@@ -473,6 +536,7 @@ fn raw_io() {
             .expect("Failed to set IO")
     };
     assert!(decoder.parse().is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     assert_eq!(decoder.image_count(), 5);
     if !HAS_DECODER {
         return;
@@ -527,6 +591,7 @@ fn custom_io() {
     });
     decoder.set_io(io);
     assert!(decoder.parse().is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     assert_eq!(decoder.image_count(), 5);
     if !HAS_DECODER {
         return;
@@ -688,6 +753,7 @@ fn nth_image() {
     let mut decoder = get_decoder("colors-animated-8bpc.avif");
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     assert_eq!(decoder.image_count(), 5);
     if !HAS_DECODER {
         return;
@@ -706,6 +772,7 @@ fn color_and_alpha_dimensions_do_not_match() {
     // Parsing should succeed.
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     let image = decoder.image().expect("image was none");
     assert_eq!(image.width, 10);
     assert_eq!(image.height, 10);
@@ -722,6 +789,7 @@ fn rgb_conversion_alpha_premultiply() -> AvifResult<()> {
     let mut decoder = get_decoder("alpha.avif");
     let res = decoder.parse();
     assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     if !HAS_DECODER {
         return Ok(());
     }
@@ -739,6 +807,7 @@ fn rgb_conversion_alpha_premultiply() -> AvifResult<()> {
 fn white_1x1() -> AvifResult<()> {
     let mut decoder = get_decoder("white_1x1.avif");
     assert_eq!(decoder.parse(), Ok(()));
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     if !HAS_DECODER {
         return Ok(());
     }
@@ -770,6 +839,7 @@ fn white_1x1_mdat_size0() -> AvifResult<()> {
     let mut decoder = decoder::Decoder::default();
     decoder.set_io_vec(file_bytes);
     assert_eq!(decoder.parse(), Ok(()));
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     Ok(())
 }
 
@@ -789,6 +859,7 @@ fn white_1x1_meta_size0() -> AvifResult<()> {
     // item extents to be read from the MediaDataBox if the construction_method is 0.
     // Maybe another section or specification enforces that.
     assert_eq!(decoder.parse(), Ok(()));
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     if !HAS_DECODER {
         return Ok(());
     }
@@ -850,3 +921,34 @@ fn dimg_ordering() {
     let row2 = image2.row(Plane::Y, 0).expect("row2 was none");
     assert_ne!(row1, row2);
 }
+
+#[test]
+fn heic_peek() {
+    let file_data = std::fs::read(get_test_file("blue.heic")).expect("could not read file");
+    assert_eq!(
+        decoder::Decoder::peek_compatible_file_type(&file_data),
+        cfg!(feature = "heic")
+    );
+}
+
+#[test]
+fn heic_parsing() {
+    let mut decoder = get_decoder("blue.heic");
+    let res = decoder.parse();
+    if cfg!(feature = "heic") {
+        assert!(res.is_ok());
+        let image = decoder.image().expect("image was none");
+        assert_eq!(image.width, 320);
+        assert_eq!(image.height, 240);
+        assert_eq!(decoder.compression_format(), CompressionFormat::Heic);
+        if cfg!(feature = "android_mediacodec") {
+            // Decoding is available only via android_mediacodec.
+            assert!(!matches!(
+                decoder.next_image(),
+                Err(AvifError::NoCodecAvailable)
+            ));
+        }
+    } else {
+        assert!(res.is_err());
+    }
+}
```

