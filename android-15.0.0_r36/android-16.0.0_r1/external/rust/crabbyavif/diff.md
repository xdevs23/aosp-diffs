```diff
diff --git a/.github/workflows/build-and-run-tests.yml b/.github/workflows/build-and-run-tests.yml
index b6ed7a5..deab89d 100644
--- a/.github/workflows/build-and-run-tests.yml
+++ b/.github/workflows/build-and-run-tests.yml
@@ -34,7 +34,7 @@ jobs:
 
     - name: Cache external dependencies
       id: cache-ext
-      uses: actions/cache@13aacd865c20de90d75de3b17ebe84f7a17d57d2 # v4.0.0
+      uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
       with:
         path: |
           sys
diff --git a/.github/workflows/conformance-tests.yml b/.github/workflows/conformance-tests.yml
index 6fed78b..3747df0 100644
--- a/.github/workflows/conformance-tests.yml
+++ b/.github/workflows/conformance-tests.yml
@@ -31,7 +31,7 @@ jobs:
 
     - name: Cache external dependencies including libavif
       id: cache-ext-with-libavif
-      uses: actions/cache@13aacd865c20de90d75de3b17ebe84f7a17d57d2 # v4.0.0
+      uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
       with:
         path: |
           sys
@@ -95,6 +95,10 @@ jobs:
         token: ${{ github.token }}
         github-binarycache: true
 
+    - name: jpeg, zlib and png (for linux)
+      if: runner.os == 'Linux'
+      run: sudo apt install -y zlib1g libpng-dev libjpeg-dev
+
     - name: Configure libavif (cmake)
       if: steps.cache-ext-with-libavif.outputs.cache-hit != 'true'
       working-directory: ./external/libavif
diff --git a/.gitignore b/.gitignore
index cb180ce..cdb0b5e 100644
--- a/.gitignore
+++ b/.gitignore
@@ -8,6 +8,8 @@
 /external/libavif
 /match_stats.csv
 /out_comparison.txt
+/sys/aom-sys/aom
+/sys/aom-sys/aom.rs
 /sys/dav1d-sys/dav1d
 /sys/dav1d-sys/dav1d.rs
 /sys/libgav1-sys/libgav1
diff --git a/Android.bp b/Android.bp
index d86eff2..4db5ebb 100644
--- a/Android.bp
+++ b/Android.bp
@@ -20,9 +20,9 @@ rust_bindgen {
     ],
     bindgen_flags: [
         "--allowlist-item=android::MediaImage2?",
-        "--no-recursive-allowlist",
-        "--no-layout-tests",
         "--no-doc-comments",
+        "--no-layout-tests",
+        "--no-recursive-allowlist",
     ],
 }
 
@@ -47,6 +47,8 @@ rust_library {
     cfgs: ["android_soong"],
     srcs: [
         "sys/ndk-sys/src/lib.rs",
+        // This comment prevents bpfmt -s from sorting this list as lib.rs
+        // always has to be the first in the source list.
         ":libcrabbyavif_ndk_bindgen",
     ],
     shared_libs: [
@@ -74,11 +76,17 @@ rust_library {
     cfgs: ["android_soong"],
     srcs: [
         "sys/libyuv-sys/src/lib.rs",
+        // This comment prevents bpfmt -s from sorting this list as lib.rs
+        // always has to be the first in the source list.
         ":libcrabbyavif_yuv_bindgen",
     ],
     whole_static_libs: [
         "libyuv",
     ],
+    shared_libs: [
+        "libc++",
+        "libjpeg",
+    ],
 }
 
 rust_ffi_static {
@@ -88,18 +96,22 @@ rust_ffi_static {
     cargo_pkg_version: "0.1.0",
     srcs: [
         "src/lib.rs",
+        // This comment prevents bpfmt -s from sorting this list as lib.rs
+        // always has to be the first in the source list.
         ":libcrabbyavif_mediaimage2_bindgen",
     ],
     cfgs: ["android_soong"],
     edition: "2021",
     features: [
         "android_mediacodec",
-        "libyuv",
         "capi",
         "heic",
+        "libyuv",
     ],
     rustlibs: [
         "liblibyuv_sys",
+        "liblog_rust",
+        "liblogger",
         "libndk_sys",
         "librustutils",
     ],
@@ -108,7 +120,7 @@ rust_ffi_static {
     ],
     include_dirs: ["include"],
     apex_available: [
-        "//apex_available:platform",
         "//apex_available:anyapex",
+        "//apex_available:platform",
     ],
 }
diff --git a/Cargo.toml b/Cargo.toml
index d3d77a4..cdd294c 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -1,4 +1,5 @@
 workspace = { members = [
+  "sys/aom-sys",
   "sys/dav1d-sys",
   "sys/libyuv-sys",
   "sys/libgav1-sys",
@@ -19,6 +20,7 @@ ndk-sys = { version = "0.1.0", path = "sys/ndk-sys", optional = true }
 dav1d-sys = { version = "0.1.0", path = "sys/dav1d-sys", optional = true }
 libgav1-sys = { version = "0.1.0", path = "sys/libgav1-sys", optional = true }
 libyuv-sys = { version = "0.1.0", path = "sys/libyuv-sys", optional = true }
+aom-sys = { version = "0.1.0", path = "sys/aom-sys", optional = true }
 
 [dev-dependencies]
 test-case = "3.3.1"
@@ -26,7 +28,10 @@ seq-macro = "0.3.5"
 tempfile = "3.8.1"
 exitcode = "1.1.2"
 rand = "0.8.5"
-image = "0.25.2"
+clap = { version = "4.5.28", features = ["derive"] }
+clap_derive = { version = "4.5.28" }
+png = "0.17.16"
+image = { version = "0.24.0", features = ["jpeg"] }
 
 [build-dependencies]
 bindgen = "0.69.1"
@@ -40,6 +45,8 @@ libgav1 = ["dep:libgav1-sys"]
 libyuv = ["dep:libyuv-sys"]
 android_mediacodec = ["dep:ndk-sys"]
 heic = []
+disable_cfi = []
+aom = ["dep:aom-sys"]
 
 [package.metadata.capi.header]
 name = "avif"
diff --git a/METADATA b/METADATA
index 5b3ca2e..469cc6a 100644
--- a/METADATA
+++ b/METADATA
@@ -7,15 +7,15 @@ description: "CrabbyAvif is a rust library that is used for AVIF Image Decoding"
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 12
-    day: 6
+    year: 2025
+    month: 3
+    day: 18
   }
   homepage: "https://github.com/webmproject/CrabbyAvif"
   identifier {
     type: "Git"
     value: "https://github.com/webmproject/CrabbyAvif.git"
-    version: "a6987b0a607470dffd02e0d5ea69cae8af552a89"
+    version: "963898a53d056da5ab97193fb3087e208c88dc34"
     primary_source: true
   }
 }
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 0000000..cb50868
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,40 @@
+{
+  "presubmit": [
+    {
+      "name": "CtsGraphicsTestCases",
+      "options": [
+        {
+          "include-filter": "android.graphics.cts.AImageDecoderTest"
+        },
+        {
+          "include-filter": "android.graphics.cts.BitmapFactoryTest"
+        },
+        {
+          "include-filter": "android.graphics.cts.BitmapRegionDecoderTest"
+        },
+        {
+          "include-filter": "android.graphics.cts.ImageDecoderTest"
+        }
+      ]
+    }
+  ],
+  "presubmit-large": [
+    {
+      "name": "CtsMediaMiscTestCases",
+      "options": [
+        {
+          "include-filter": "android.media.misc.cts.ExifInterfaceTest"
+        },
+        {
+          "include-filter": "android.media.misc.cts.HeifWriterTest"
+        },
+        {
+          "include-filter": "android.media.misc.cts.MediaMetadataRetrieverTest"
+        },
+        {
+          "include-filter": "android.media.misc.cts.ThumbnailUtilsTest"
+        }
+      ]
+    }
+  ]
+}
diff --git a/c_api_tests/CMakeLists.txt b/c_api_tests/CMakeLists.txt
index d10cec7..c72702a 100644
--- a/c_api_tests/CMakeLists.txt
+++ b/c_api_tests/CMakeLists.txt
@@ -40,22 +40,9 @@ macro(add_avif_gtest TEST_NAME)
     add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} ${CARGO_ROOT_DIR}/tests/data/)
 endmacro()
 
-add_avif_gtest(avifalphanoispetest)
-add_avif_gtest(avifanimationtest)
-add_avif_gtest(avifcapitest)
-add_avif_gtest(avifclaptest)
-add_avif_gtest(avifcllitest)
-add_avif_gtest(avifdecodetest)
-add_avif_gtest(avifgainmaptest)
-add_avif_gtest(avifimagetest)
-add_avif_gtest(avifincrtest)
-add_avif_gtest(avifiotest)
-add_avif_gtest(avifkeyframetest)
-add_avif_gtest(avifmetadatatest)
-add_avif_gtest(avifprogressivetest)
-add_avif_gtest(avifreformattest)
-add_avif_gtest(avifscaletest)
-add_avif_gtest(aviftest)
+add_avif_gtest(decoder_tests)
+add_avif_gtest(incremental_tests)
+add_avif_gtest(reformat_tests)
 
 # Conformance test.
 add_executable(conformance_tests conformance_tests.cc)
diff --git a/c_api_tests/README.md b/c_api_tests/README.md
deleted file mode 100644
index 9ffe3f5..0000000
--- a/c_api_tests/README.md
+++ /dev/null
@@ -1,16 +0,0 @@
-## C++ tests copied from libavif.
-
-### Copied as is
-
-* avifalphanoispetest.cc
-* avifanimationtest.cc
-* avifdecodetest.cc
-* avifprogressivetest.cc
-* avifclaptest.cc
-
-### Copied with changes
-
-* avifmetadatatest.cc
-  * Remove encoder tests and add more checks to the decoder test.
-* avifgainmaptest.cc
-  * Remove encoder tests.
diff --git a/c_api_tests/avifalphanoispetest.cc b/c_api_tests/avifalphanoispetest.cc
deleted file mode 100644
index c334066..0000000
--- a/c_api_tests/avifalphanoispetest.cc
+++ /dev/null
@@ -1,52 +0,0 @@
-// Copyright 2023 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-TEST(AvifDecodeTest, AlphaNoIspe) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-  // See https://github.com/AOMediaCodec/libavif/pull/745.
-  const char* file_name = "alpha_noispe.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
-                                 (std::string(data_path) + file_name).c_str()),
-            AVIF_RESULT_OK);
-  // By default, loose files are refused. Cast to avoid C4389 Windows warning.
-  EXPECT_EQ(decoder->strictFlags, (avifStrictFlags)AVIF_STRICT_ENABLED);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_BMFF_PARSE_FAILED);
-  // Allow this kind of file specifically.
-  decoder->strictFlags = (avifStrictFlags)AVIF_STRICT_ENABLED &
-                         ~(avifStrictFlags)AVIF_STRICT_ALPHA_ISPE_REQUIRED;
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  EXPECT_EQ(decoder->alphaPresent, AVIF_TRUE);
-  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_NE(decoder->image->alphaPlane, nullptr);
-  EXPECT_GT(decoder->image->alphaRowBytes, 0u);
-}
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifanimationtest.cc b/c_api_tests/avifanimationtest.cc
deleted file mode 100644
index a3e4227..0000000
--- a/c_api_tests/avifanimationtest.cc
+++ /dev/null
@@ -1,93 +0,0 @@
-// Copyright 2023 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-TEST(AvifDecodeTest, AnimatedImage) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-  const char* file_name = "colors-animated-8bpc.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
-                                 (std::string(data_path) + file_name).c_str()),
-            AVIF_RESULT_OK);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
-  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
-  EXPECT_EQ(decoder->imageCount, 5);
-  EXPECT_EQ(decoder->repetitionCount, 0);
-  for (int i = 0; i < 5; ++i) {
-    EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-  }
-}
-
-TEST(AvifDecodeTest, AnimatedImageWithSourceSetToPrimaryItem) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-  const char* file_name = "colors-animated-8bpc.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
-                                 (std::string(data_path) + file_name).c_str()),
-            AVIF_RESULT_OK);
-  ASSERT_EQ(
-      avifDecoderSetSource(decoder.get(), AVIF_DECODER_SOURCE_PRIMARY_ITEM),
-      AVIF_RESULT_OK);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
-  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
-  // imageCount is expected to be 1 because we are using primary item as the
-  // preferred source.
-  EXPECT_EQ(decoder->imageCount, 1);
-  EXPECT_EQ(decoder->repetitionCount, 0);
-  // Get the first (and only) image.
-  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-  // Subsequent calls should not return AVIF_RESULT_OK since there is only one
-  // image in the preferred source.
-  EXPECT_NE(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-}
-
-TEST(AvifDecodeTest, AnimatedImageWithAlphaAndMetadata) {
-  const char* file_name = "colors-animated-8bpc-alpha-exif-xmp.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
-                                 (std::string(data_path) + file_name).c_str()),
-            AVIF_RESULT_OK);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  EXPECT_EQ(decoder->alphaPresent, AVIF_TRUE);
-  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
-  EXPECT_EQ(decoder->imageCount, 5);
-  EXPECT_EQ(decoder->repetitionCount, AVIF_REPETITION_COUNT_INFINITE);
-  EXPECT_EQ(decoder->image->exif.size, 1126);
-  EXPECT_EQ(decoder->image->xmp.size, 3898);
-}
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifcapitest.cc b/c_api_tests/avifcapitest.cc
deleted file mode 100644
index bca57dd..0000000
--- a/c_api_tests/avifcapitest.cc
+++ /dev/null
@@ -1,134 +0,0 @@
-// Copyright 2023 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-std::string get_file_name(const char* file_name) {
-  return std::string(data_path) + file_name;
-}
-
-TEST(AvifDecodeTest, OneShotDecodeFile) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-  const char* file_name = "sofa_grid1x5_420.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  avifImage image;
-  ASSERT_EQ(avifDecoderReadFile(decoder.get(), &image,
-                                get_file_name(file_name).c_str()),
-            AVIF_RESULT_OK);
-  EXPECT_EQ(image.width, 1024);
-  EXPECT_EQ(image.height, 770);
-  EXPECT_EQ(image.depth, 8);
-
-  // Call avifDecoderReadFile with a different file but with the same decoder
-  // instance.
-  file_name = "white_1x1.avif";
-  ASSERT_EQ(avifDecoderReadFile(decoder.get(), &image,
-                                get_file_name(file_name).c_str()),
-            AVIF_RESULT_OK);
-  EXPECT_EQ(image.width, 1);
-  EXPECT_EQ(image.height, 1);
-  EXPECT_EQ(image.depth, 8);
-}
-
-TEST(AvifDecodeTest, OneShotDecodeMemory) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-  const char* file_name = "sofa_grid1x5_420.avif";
-  auto file_data = testutil::read_file(get_file_name(file_name).c_str());
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  avifImage image;
-  ASSERT_EQ(avifDecoderReadMemory(decoder.get(), &image, file_data.data(),
-                                  file_data.size()),
-            AVIF_RESULT_OK);
-  EXPECT_EQ(image.width, 1024);
-  EXPECT_EQ(image.height, 770);
-  EXPECT_EQ(image.depth, 8);
-}
-
-avifResult io_read(struct avifIO* io, uint32_t flags, uint64_t offset,
-                   size_t size, avifROData* out) {
-  avifROData* src = (avifROData*)io->data;
-  if (flags != 0 || offset > src->size) {
-    return AVIF_RESULT_IO_ERROR;
-  }
-  uint64_t available_size = src->size - offset;
-  if (size > available_size) {
-    size = static_cast<size_t>(available_size);
-  }
-  out->data = src->data + offset;
-  out->size = size;
-  return AVIF_RESULT_OK;
-}
-
-TEST(AvifDecodeTest, OneShotDecodeCustomIO) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-  const char* file_name = "sofa_grid1x5_420.avif";
-  auto data = testutil::read_file(get_file_name(file_name).c_str());
-  avifROData ro_data = {.data = data.data(), .size = data.size()};
-  avifIO io = {.destroy = nullptr,
-               .read = io_read,
-               .sizeHint = data.size(),
-               .persistent = false,
-               .data = static_cast<void*>(&ro_data)};
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  avifDecoderSetIO(decoder.get(), &io);
-  avifImage image;
-  ASSERT_EQ(avifDecoderRead(decoder.get(), &image), AVIF_RESULT_OK);
-  EXPECT_EQ(image.width, 1024);
-  EXPECT_EQ(image.height, 770);
-  EXPECT_EQ(image.depth, 8);
-}
-
-TEST(AvifDecodeTest, NthImage) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-  const char* file_name = "colors-animated-8bpc.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
-                                 (std::string(data_path) + file_name).c_str()),
-            AVIF_RESULT_OK);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  EXPECT_EQ(decoder->imageCount, 5);
-  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 3), AVIF_RESULT_OK);
-  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_NE(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 1), AVIF_RESULT_OK);
-  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 4), AVIF_RESULT_OK);
-  EXPECT_NE(avifDecoderNthImage(decoder.get(), 50), AVIF_RESULT_OK);
-  for (int i = 0; i < 5; ++i) {
-  }
-}
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifclaptest.cc b/c_api_tests/avifclaptest.cc
deleted file mode 100644
index 7647170..0000000
--- a/c_api_tests/avifclaptest.cc
+++ /dev/null
@@ -1,156 +0,0 @@
-// Copyright 2023 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace {
-
-struct InvalidClapPropertyParam {
-  uint32_t width;
-  uint32_t height;
-  avifPixelFormat yuv_format;
-  avifCleanApertureBox clap;
-};
-
-constexpr InvalidClapPropertyParam kInvalidClapPropertyTestParams[] = {
-    // Zero or negative denominators.
-    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 0, 132, 1, 0, 1, 0, 1}},
-    {120,
-     160,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {96, static_cast<uint32_t>(-1), 132, 1, 0, 1, 0, 1}},
-    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 1, 132, 0, 0, 1, 0, 1}},
-    {120,
-     160,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {96, 1, 132, static_cast<uint32_t>(-1), 0, 1, 0, 1}},
-    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 1, 132, 1, 0, 0, 0, 1}},
-    {120,
-     160,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {96, 1, 132, 1, 0, static_cast<uint32_t>(-1), 0, 1}},
-    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 1, 132, 1, 0, 1, 0, 0}},
-    {120,
-     160,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {96, 1, 132, 1, 0, 1, 0, static_cast<uint32_t>(-1)}},
-    // Zero or negative clean aperture width or height.
-    {120,
-     160,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {static_cast<uint32_t>(-96), 1, 132, 1, 0, 1, 0, 1}},
-    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {0, 1, 132, 1, 0, 1, 0, 1}},
-    {120,
-     160,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {96, 1, static_cast<uint32_t>(-132), 1, 0, 1, 0, 1}},
-    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 1, 0, 1, 0, 1, 0, 1}},
-    // Clean aperture width or height is not an integer.
-    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 5, 132, 1, 0, 1, 0, 1}},
-    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 1, 132, 5, 0, 1, 0, 1}},
-    // pcX = 103 + (722 - 1)/2 = 463.5
-    // pcY = -308 + (1024 - 1)/2 = 203.5
-    // leftmost = 463.5 - (385 - 1)/2 = 271.5 (not an integer)
-    // topmost = 203.5 - (330 - 1)/2 = 39
-    {722,
-     1024,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {385, 1, 330, 1, 103, 1, static_cast<uint32_t>(-308), 1}},
-    // pcX = -308 + (1024 - 1)/2 = 203.5
-    // pcY = 103 + (722 - 1)/2 = 463.5
-    // leftmost = 203.5 - (330 - 1)/2 = 39
-    // topmost = 463.5 - (385 - 1)/2 = 271.5 (not an integer)
-    {1024,
-     722,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {330, 1, 385, 1, static_cast<uint32_t>(-308), 1, 103, 1}},
-    // pcX = -1/2 + (99 - 1)/2 = 48.5
-    // pcY = -1/2 + (99 - 1)/2 = 48.5
-    // leftmost = 48.5 - (99 - 1)/2 = -0.5 (not an integer)
-    // topmost = 48.5 - (99 - 1)/2 = -0.5 (not an integer)
-    {99,
-     99,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {99, 1, 99, 1, static_cast<uint32_t>(-1), 2, static_cast<uint32_t>(-1),
-      2}},
-};
-
-using InvalidClapPropertyTest =
-    ::testing::TestWithParam<InvalidClapPropertyParam>;
-
-INSTANTIATE_TEST_SUITE_P(Parameterized, InvalidClapPropertyTest,
-                         ::testing::ValuesIn(kInvalidClapPropertyTestParams));
-
-// Negative tests for the avifCropRectConvertCleanApertureBox() function.
-TEST_P(InvalidClapPropertyTest, ValidateClapProperty) {
-  const InvalidClapPropertyParam& param = GetParam();
-  avifCropRect crop_rect;
-  avifDiagnostics diag;
-  EXPECT_FALSE(avifCropRectConvertCleanApertureBox(&crop_rect, &param.clap,
-                                                   param.width, param.height,
-                                                   param.yuv_format, &diag));
-}
-
-struct ValidClapPropertyParam {
-  uint32_t width;
-  uint32_t height;
-  avifPixelFormat yuv_format;
-  avifCleanApertureBox clap;
-
-  avifCropRect expected_crop_rect;
-};
-
-constexpr ValidClapPropertyParam kValidClapPropertyTestParams[] = {
-    // pcX = 0 + (120 - 1)/2 = 59.5
-    // pcY = 0 + (160 - 1)/2 = 79.5
-    // leftmost = 59.5 - (96 - 1)/2 = 12
-    // topmost = 79.5 - (132 - 1)/2 = 14
-    {120,
-     160,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {96, 1, 132, 1, 0, 1, 0, 1},
-     {12, 14, 96, 132}},
-    // pcX = -30 + (120 - 1)/2 = 29.5
-    // pcY = -40 + (160 - 1)/2 = 39.5
-    // leftmost = 29.5 - (60 - 1)/2 = 0
-    // topmost = 39.5 - (80 - 1)/2 = 0
-    {120,
-     160,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {60, 1, 80, 1, static_cast<uint32_t>(-30), 1, static_cast<uint32_t>(-40),
-      1},
-     {0, 0, 60, 80}},
-    // pcX = -1/2 + (100 - 1)/2 = 49
-    // pcY = -1/2 + (100 - 1)/2 = 49
-    // leftmost = 49 - (99 - 1)/2 = 0
-    // topmost = 49 - (99 - 1)/2 = 0
-    {100,
-     100,
-     AVIF_PIXEL_FORMAT_YUV420,
-     {99, 1, 99, 1, static_cast<uint32_t>(-1), 2, static_cast<uint32_t>(-1), 2},
-     {0, 0, 99, 99}},
-};
-
-using ValidClapPropertyTest = ::testing::TestWithParam<ValidClapPropertyParam>;
-
-INSTANTIATE_TEST_SUITE_P(Parameterized, ValidClapPropertyTest,
-                         ::testing::ValuesIn(kValidClapPropertyTestParams));
-
-// Positive tests for the avifCropRectConvertCleanApertureBox() function.
-TEST_P(ValidClapPropertyTest, ValidateClapProperty) {
-  const ValidClapPropertyParam& param = GetParam();
-  avifCropRect crop_rect;
-  avifDiagnostics diag;
-  EXPECT_TRUE(avifCropRectConvertCleanApertureBox(&crop_rect, &param.clap,
-                                                  param.width, param.height,
-                                                  param.yuv_format, &diag))
-      << diag.error;
-  EXPECT_EQ(crop_rect.x, param.expected_crop_rect.x);
-  EXPECT_EQ(crop_rect.y, param.expected_crop_rect.y);
-  EXPECT_EQ(crop_rect.width, param.expected_crop_rect.width);
-  EXPECT_EQ(crop_rect.height, param.expected_crop_rect.height);
-}
-
-}  // namespace
diff --git a/c_api_tests/avifcllitest.cc b/c_api_tests/avifcllitest.cc
deleted file mode 100644
index ac76428..0000000
--- a/c_api_tests/avifcllitest.cc
+++ /dev/null
@@ -1,60 +0,0 @@
-// Copyright 2022 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-TEST(ClliTest, Simple) {
-  struct Params {
-    const char* file_name;
-    uint32_t maxCLL;
-    uint32_t maxPALL;
-  };
-  Params params[9] = {
-    {"clli/clli_0_0.avif", 0, 0},
-    {"clli/clli_0_1.avif", 0, 1},
-    {"clli/clli_0_65535.avif", 0, 65535},
-    {"clli/clli_1_0.avif", 1, 0},
-    {"clli/clli_1_1.avif", 1, 1},
-    {"clli/clli_1_65535.avif", 1, 65535},
-    {"clli/clli_65535_0.avif", 65535, 0},
-    {"clli/clli_65535_1.avif", 65535, 1},
-    {"clli/clli_65535_65535.avif", 65535, 65535},
-  };
-  for (const auto& param : params) {
-    DecoderPtr decoder(avifDecoderCreate());
-    ASSERT_NE(decoder, nullptr);
-    decoder->allowProgressive = true;
-    ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
-                                   (std::string(data_path) + param.file_name).c_str()),
-              AVIF_RESULT_OK);
-    ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-    EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-    avifImage* decoded = decoder->image;
-    ASSERT_NE(decoded, nullptr);
-    ASSERT_EQ(decoded->clli.maxCLL, param.maxCLL);
-    ASSERT_EQ(decoded->clli.maxPALL, param.maxPALL);
-  }
-}
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifdecodetest.cc b/c_api_tests/avifdecodetest.cc
deleted file mode 100644
index 8017e97..0000000
--- a/c_api_tests/avifdecodetest.cc
+++ /dev/null
@@ -1,47 +0,0 @@
-// Copyright 2023 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-TEST(AvifDecodeTest, ColorGridAlphaNoGrid) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-  // Test case from https://github.com/AOMediaCodec/libavif/issues/1203.
-  const char* file_name = "color_grid_alpha_nogrid.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
-                                 (std::string(data_path) + file_name).c_str()),
-            AVIF_RESULT_OK);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  EXPECT_EQ(decoder->alphaPresent, AVIF_TRUE);
-  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_FALSE);
-  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_NE(decoder->image->alphaPlane, nullptr);
-  EXPECT_GT(decoder->image->alphaRowBytes, 0u);
-}
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifgainmaptest.cc b/c_api_tests/avifgainmaptest.cc
deleted file mode 100644
index da14fa1..0000000
--- a/c_api_tests/avifgainmaptest.cc
+++ /dev/null
@@ -1,220 +0,0 @@
-// Copyright 2023 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include <string>
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-TEST(GainMapTest, DecodeGainMapGrid) {
-  const std::string path =
-      std::string(data_path) + "color_grid_gainmap_different_grid.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  decoder->imageContentToDecode |= AVIF_IMAGE_CONTENT_GAIN_MAP;
-
-  avifResult result = avifDecoderSetIOFile(decoder.get(), path.c_str());
-  ASSERT_EQ(result, AVIF_RESULT_OK)
-      << avifResultToString(result) << " " << decoder->diag.error;
-
-  // Just parse the image first.
-  result = avifDecoderParse(decoder.get());
-  ASSERT_EQ(result, AVIF_RESULT_OK)
-      << avifResultToString(result) << " " << decoder->diag.error;
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  avifImage* decoded = decoder->image;
-  ASSERT_NE(decoded, nullptr);
-
-  // Verify that the gain map is present and matches the input.
-  EXPECT_NE(decoder->image->gainMap, nullptr);
-  // Color+alpha: 4x3 grid of 128x200 tiles.
-  EXPECT_EQ(decoded->width, 128u * 4u);
-  EXPECT_EQ(decoded->height, 200u * 3u);
-  EXPECT_EQ(decoded->depth, 10u);
-  ASSERT_NE(decoded->gainMap->image, nullptr);
-  // Gain map: 2x2 grid of 64x80 tiles.
-  EXPECT_EQ(decoded->gainMap->image->width, 64u * 2u);
-  EXPECT_EQ(decoded->gainMap->image->height, 80u * 2u);
-  EXPECT_EQ(decoded->gainMap->image->depth, 8u);
-  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.n, 6u);
-  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.d, 2u);
-
-  // Decode the image.
-  result = avifDecoderNextImage(decoder.get());
-  ASSERT_EQ(result, AVIF_RESULT_OK)
-      << avifResultToString(result) << " " << decoder->diag.error;
-}
-
-TEST(GainMapTest, DecodeOriented) {
-  const std::string path = std::string(data_path) + "gainmap_oriented.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  decoder->imageContentToDecode |= AVIF_IMAGE_CONTENT_GAIN_MAP;
-  ASSERT_EQ(avifDecoderSetIOFile(decoder.get(), path.c_str()), AVIF_RESULT_OK);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-
-  // Verify that the transformative properties were kept.
-  EXPECT_EQ(decoder->image->transformFlags,
-            AVIF_TRANSFORM_IROT | AVIF_TRANSFORM_IMIR);
-  EXPECT_EQ(decoder->image->irot.angle, 1);
-  EXPECT_EQ(decoder->image->imir.axis, 0);
-  EXPECT_EQ(decoder->image->gainMap->image->transformFlags,
-            AVIF_TRANSFORM_NONE);
-}
-
-TEST(GainMapTest, IgnoreGainMapButReadMetadata) {
-  const std::string path =
-      std::string(data_path) + "seine_sdr_gainmap_srgb.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-
-  avifResult result = avifDecoderSetIOFile(decoder.get(), path.c_str());
-  ASSERT_EQ(result, AVIF_RESULT_OK)
-      << avifResultToString(result) << " " << decoder->diag.error;
-  result = avifDecoderParse(decoder.get());
-  ASSERT_EQ(result, AVIF_RESULT_OK)
-      << avifResultToString(result) << " " << decoder->diag.error;
-  avifImage* decoded = decoder->image;
-  ASSERT_NE(decoded, nullptr);
-
-  // Verify that the gain map was detected...
-  EXPECT_NE(decoder->image->gainMap, nullptr);
-  // ... but not decoded because enableDecodingGainMap is false by default.
-  EXPECT_EQ(decoded->gainMap->image, nullptr);
-  // Check that the gain map metadata WAS populated.
-  EXPECT_EQ(decoded->gainMap->alternateHdrHeadroom.n, 13);
-  EXPECT_EQ(decoded->gainMap->alternateHdrHeadroom.d, 10);
-}
-
-TEST(GainMapTest, IgnoreColorAndAlpha) {
-  const std::string path =
-      std::string(data_path) + "seine_sdr_gainmap_srgb.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  decoder->imageContentToDecode = AVIF_IMAGE_CONTENT_GAIN_MAP;
-
-  avifResult result = avifDecoderSetIOFile(decoder.get(), path.c_str());
-  ASSERT_EQ(result, AVIF_RESULT_OK)
-      << avifResultToString(result) << " " << decoder->diag.error;
-  result = avifDecoderParse(decoder.get());
-  ASSERT_EQ(result, AVIF_RESULT_OK)
-      << avifResultToString(result) << " " << decoder->diag.error;
-  result = avifDecoderNextImage(decoder.get());
-  ASSERT_EQ(result, AVIF_RESULT_OK)
-      << avifResultToString(result) << " " << decoder->diag.error;
-  avifImage* decoded = decoder->image;
-  ASSERT_NE(decoded, nullptr);
-
-  // Main image metadata is available.
-  EXPECT_EQ(decoded->width, 400u);
-  EXPECT_EQ(decoded->height, 300u);
-  // But pixels are not.
-  EXPECT_EQ(decoded->yuvRowBytes[0], 0u);
-  EXPECT_EQ(decoded->yuvRowBytes[1], 0u);
-  EXPECT_EQ(decoded->yuvRowBytes[2], 0u);
-  EXPECT_EQ(decoded->alphaRowBytes, 0u);
-  // The gain map was decoded.
-  EXPECT_NE(decoder->image->gainMap, nullptr);
-  ASSERT_NE(decoded->gainMap->image, nullptr);
-  // Including pixels.
-  EXPECT_GT(decoded->gainMap->image->yuvRowBytes[0], 0u);
-}
-
-TEST(GainMapTest, IgnoreAll) {
-  const std::string path =
-      std::string(data_path) + "seine_sdr_gainmap_srgb.avif";
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  decoder->imageContentToDecode = AVIF_IMAGE_CONTENT_NONE;
-
-  avifResult result = avifDecoderSetIOFile(decoder.get(), path.c_str());
-  ASSERT_EQ(result, AVIF_RESULT_OK)
-      << avifResultToString(result) << " " << decoder->diag.error;
-  result = avifDecoderParse(decoder.get());
-  ASSERT_EQ(result, AVIF_RESULT_OK)
-      << avifResultToString(result) << " " << decoder->diag.error;
-  avifImage* decoded = decoder->image;
-  ASSERT_NE(decoded, nullptr);
-
-  EXPECT_NE(decoder->image->gainMap, nullptr);
-  ASSERT_EQ(decoder->image->gainMap->image, nullptr);
-
-  // But trying to access the next image should give an error because both
-  // ignoreColorAndAlpha and enableDecodingGainMap are set.
-  ASSERT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_NO_CONTENT);
-}
-
-// The following two functions use avifDecoderReadFile which is not supported in
-// CAPI yet.
-
-/*
-TEST(GainMapTest, DecodeColorGridGainMapNoGrid) {
-  const std::string path =
-      std::string(data_path) + "color_grid_alpha_grid_gainmap_nogrid.avif";
-  ImagePtr decoded(avifImageCreateEmpty());
-  ASSERT_NE(decoded, nullptr);
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  decoder->enableDecodingGainMap = true;
-  decoder->enableParsingGainMapMetadata = true;
-  ASSERT_EQ(avifDecoderReadFile(decoder.get(), decoded.get(), path.c_str()),
-            AVIF_RESULT_OK);
-
-  // Color+alpha: 4x3 grid of 128x200 tiles.
-  EXPECT_EQ(decoded->width, 128u * 4u);
-  EXPECT_EQ(decoded->height, 200u * 3u);
-  ASSERT_NE(decoded->gainMap, nullptr);
-  ASSERT_NE(decoded->gainMap->image, nullptr);
-  // Gain map: single image of size 64x80.
-  EXPECT_EQ(decoded->gainMap->image->width, 64u);
-  EXPECT_EQ(decoded->gainMap->image->height, 80u);
-  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.n, 6u);
-  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.d, 2u);
-}
-
-TEST(GainMapTest, DecodeColorNoGridGainMapGrid) {
-  const std::string path =
-      std::string(data_path) + "color_nogrid_alpha_nogrid_gainmap_grid.avif";
-  ImagePtr decoded(avifImageCreateEmpty());
-  ASSERT_NE(decoded, nullptr);
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  decoder->enableDecodingGainMap = true;
-  decoder->enableParsingGainMapMetadata = true;
-  ASSERT_EQ(avifDecoderReadFile(decoder.get(), decoded.get(), path.c_str()),
-            AVIF_RESULT_OK);
-
-  // Color+alpha: single image of size 128x200 .
-  EXPECT_EQ(decoded->width, 128u);
-  EXPECT_EQ(decoded->height, 200u);
-  ASSERT_NE(decoded->gainMap, nullptr);
-  ASSERT_NE(decoded->gainMap->image, nullptr);
-  // Gain map: 2x2 grid of 64x80 tiles.
-  EXPECT_EQ(decoded->gainMap->image->width, 64u * 2u);
-  EXPECT_EQ(decoded->gainMap->image->height, 80u * 2u);
-  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.n, 6u);
-  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.d, 2u);
-}
-*/
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifimagetest.cc b/c_api_tests/avifimagetest.cc
deleted file mode 100644
index c947ad3..0000000
--- a/c_api_tests/avifimagetest.cc
+++ /dev/null
@@ -1,83 +0,0 @@
-// Copyright 2024 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include <cstring>
-#include <iostream>
-#include <string>
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-class ImageTest : public testing::TestWithParam<const char*> {};
-
-TEST_P(ImageTest, ImageCopy) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-  const char* file_name = GetParam();
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
-                                 (std::string(data_path) + file_name).c_str()),
-            AVIF_RESULT_OK);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-
-  ImagePtr image2(avifImageCreateEmpty());
-  ASSERT_EQ(avifImageCopy(image2.get(), decoder->image, AVIF_PLANES_ALL),
-            AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->image->width, image2->width);
-  EXPECT_EQ(decoder->image->height, image2->height);
-  EXPECT_EQ(decoder->image->depth, image2->depth);
-  EXPECT_EQ(decoder->image->yuvFormat, image2->yuvFormat);
-  EXPECT_EQ(decoder->image->yuvRange, image2->yuvRange);
-  for (int plane = 0; plane < 3; ++plane) {
-    EXPECT_EQ(decoder->image->yuvPlanes[plane] == nullptr,
-              image2->yuvPlanes[plane] == nullptr);
-    if (decoder->image->yuvPlanes[plane] == nullptr) continue;
-    EXPECT_EQ(decoder->image->yuvRowBytes[plane], image2->yuvRowBytes[plane]);
-    EXPECT_NE(decoder->image->yuvPlanes[plane], image2->yuvPlanes[plane]);
-    const auto plane_height = avifImagePlaneHeight(decoder->image, plane);
-    const auto plane_size = plane_height * decoder->image->yuvRowBytes[plane];
-    EXPECT_EQ(memcmp(decoder->image->yuvPlanes[plane], image2->yuvPlanes[plane],
-                     plane_size),
-              0);
-  }
-  EXPECT_EQ(decoder->image->alphaPlane == nullptr,
-            image2->alphaPlane == nullptr);
-  if (decoder->image->alphaPlane != nullptr) {
-    EXPECT_EQ(decoder->image->alphaRowBytes, image2->alphaRowBytes);
-    EXPECT_NE(decoder->image->alphaPlane, image2->alphaPlane);
-    const auto plane_size =
-        decoder->image->height * decoder->image->alphaRowBytes;
-    EXPECT_EQ(
-        memcmp(decoder->image->alphaPlane, image2->alphaPlane, plane_size), 0);
-  }
-}
-
-INSTANTIATE_TEST_SUITE_P(Some, ImageTest,
-                         testing::ValuesIn({"paris_10bpc.avif", "alpha.avif",
-                                            "colors-animated-8bpc.avif"}));
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifiotest.cc b/c_api_tests/avifiotest.cc
deleted file mode 100644
index f968933..0000000
--- a/c_api_tests/avifiotest.cc
+++ /dev/null
@@ -1,130 +0,0 @@
-// Copyright 2023 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include <iostream>
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-std::string get_file_name() {
-  const char* file_name = "colors-animated-8bpc.avif";
-  return std::string(data_path) + file_name;
-}
-
-TEST(AvifDecodeTest, SetRawIO) {
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  auto data = testutil::read_file(get_file_name().c_str());
-  ASSERT_EQ(avifDecoderSetIOMemory(decoder.get(), data.data(), data.size()),
-            AVIF_RESULT_OK);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
-  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
-  EXPECT_EQ(decoder->imageCount, 5);
-  EXPECT_EQ(decoder->repetitionCount, 0);
-  for (int i = 0; i < 5; ++i) {
-    EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-  }
-}
-
-avifResult io_read(struct avifIO* io, uint32_t flags, uint64_t offset,
-                   size_t size, avifROData* out) {
-  avifROData* src = (avifROData*)io->data;
-  if (flags != 0 || offset > src->size) {
-    return AVIF_RESULT_IO_ERROR;
-  }
-  uint64_t available_size = src->size - offset;
-  if (size > available_size) {
-    size = static_cast<size_t>(available_size);
-  }
-  out->data = src->data + offset;
-  out->size = size;
-  return AVIF_RESULT_OK;
-}
-
-TEST(AvifDecodeTest, SetCustomIO) {
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  auto data = testutil::read_file(get_file_name().c_str());
-  avifROData ro_data = {.data = data.data(), .size = data.size()};
-  avifIO io = {.destroy = nullptr,
-               .read = io_read,
-               .sizeHint = data.size(),
-               .persistent = false,
-               .data = static_cast<void*>(&ro_data)};
-  avifDecoderSetIO(decoder.get(), &io);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
-  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
-  EXPECT_EQ(decoder->imageCount, 5);
-  EXPECT_EQ(decoder->repetitionCount, 0);
-  for (int i = 0; i < 5; ++i) {
-    EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-  }
-}
-
-TEST(AvifDecodeTest, IOMemoryReader) {
-  auto data = testutil::read_file(get_file_name().c_str());
-  avifIO* io = avifIOCreateMemoryReader(data.data(), data.size());
-  ASSERT_NE(io, nullptr);
-  EXPECT_EQ(io->sizeHint, data.size());
-  avifROData ro_data;
-  // Read 10 bytes from the beginning.
-  io->read(io, 0, 0, 10, &ro_data);
-  EXPECT_EQ(ro_data.size, 10);
-  for (int i = 0; i < 10; ++i) {
-    EXPECT_EQ(ro_data.data[i], data[i]);
-  }
-  // Read 10 bytes from the middle.
-  io->read(io, 0, 50, 10, &ro_data);
-  EXPECT_EQ(ro_data.size, 10);
-  for (int i = 0; i < 10; ++i) {
-    EXPECT_EQ(ro_data.data[i], data[i + 50]);
-  }
-  avifIODestroy(io);
-}
-
-TEST(AvifDecodeTest, IOFileReader) {
-  auto data = testutil::read_file(get_file_name().c_str());
-  avifIO* io = avifIOCreateFileReader(get_file_name().c_str());
-  ASSERT_NE(io, nullptr);
-  EXPECT_EQ(io->sizeHint, data.size());
-  avifROData ro_data;
-  // Read 10 bytes from the beginning.
-  io->read(io, 0, 0, 10, &ro_data);
-  EXPECT_EQ(ro_data.size, 10);
-  for (int i = 0; i < 10; ++i) {
-    EXPECT_EQ(ro_data.data[i], data[i]);
-  }
-  // Read 10 bytes from the middle.
-  io->read(io, 0, 50, 10, &ro_data);
-  EXPECT_EQ(ro_data.size, 10);
-  for (int i = 0; i < 10; ++i) {
-    EXPECT_EQ(ro_data.data[i], data[i + 50]);
-  }
-  avifIODestroy(io);
-}
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifkeyframetest.cc b/c_api_tests/avifkeyframetest.cc
deleted file mode 100644
index 9411ccc..0000000
--- a/c_api_tests/avifkeyframetest.cc
+++ /dev/null
@@ -1,66 +0,0 @@
-// Copyright 2024 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include <array>
-#include <string>
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-TEST(KeyframeTest, Decode) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  const std::string file_name = "colors-animated-12bpc-keyframes-0-2-3.avif";
-  ASSERT_EQ(
-      avifDecoderSetIOFile(decoder.get(), (data_path + file_name).c_str()),
-      AVIF_RESULT_OK);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-
-  // The first frame is always a keyframe.
-  EXPECT_TRUE(avifDecoderIsKeyframe(decoder.get(), 0));
-  EXPECT_EQ(avifDecoderNearestKeyframe(decoder.get(), 0), 0);
-
-  // The encoder may choose to use a keyframe here, even without FORCE_KEYFRAME.
-  // It seems not to.
-  EXPECT_FALSE(avifDecoderIsKeyframe(decoder.get(), 1));
-  EXPECT_EQ(avifDecoderNearestKeyframe(decoder.get(), 1), 0);
-
-  EXPECT_TRUE(avifDecoderIsKeyframe(decoder.get(), 2));
-  EXPECT_EQ(avifDecoderNearestKeyframe(decoder.get(), 2), 2);
-
-  // The encoder seems to prefer a keyframe here
-  // (gradient too different from plain color).
-  EXPECT_TRUE(avifDecoderIsKeyframe(decoder.get(), 3));
-  EXPECT_EQ(avifDecoderNearestKeyframe(decoder.get(), 3), 3);
-
-  // This is the same frame as the previous one. It should not be a keyframe.
-  EXPECT_FALSE(avifDecoderIsKeyframe(decoder.get(), 4));
-  EXPECT_EQ(avifDecoderNearestKeyframe(decoder.get(), 4), 3);
-}
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifmetadatatest.cc b/c_api_tests/avifmetadatatest.cc
deleted file mode 100644
index 179bd96..0000000
--- a/c_api_tests/avifmetadatatest.cc
+++ /dev/null
@@ -1,69 +0,0 @@
-// Copyright 2022 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-// A test for https://github.com/AOMediaCodec/libavif/issues/1086 to prevent
-// regression.
-TEST(MetadataTest, DecoderParseICC) {
-  std::string file_path = std::string(data_path) + "paris_icc_exif_xmp.avif";
-  avifDecoder* decoder = avifDecoderCreate();
-  ASSERT_NE(decoder, nullptr);
-  EXPECT_EQ(avifDecoderSetIOFile(decoder, file_path.c_str()), AVIF_RESULT_OK);
-
-  decoder->ignoreXMP = AVIF_TRUE;
-  decoder->ignoreExif = AVIF_TRUE;
-  EXPECT_EQ(avifDecoderParse(decoder), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-
-  ASSERT_GE(decoder->image->icc.size, 4u);
-  EXPECT_EQ(decoder->image->icc.data[0], 0);
-  EXPECT_EQ(decoder->image->icc.data[1], 0);
-  EXPECT_EQ(decoder->image->icc.data[2], 2);
-  EXPECT_EQ(decoder->image->icc.data[3], 84);
-
-  ASSERT_EQ(decoder->image->exif.size, 0u);
-  ASSERT_EQ(decoder->image->xmp.size, 0u);
-
-  decoder->ignoreXMP = AVIF_FALSE;
-  decoder->ignoreExif = AVIF_FALSE;
-  EXPECT_EQ(avifDecoderParse(decoder), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-
-  ASSERT_GE(decoder->image->exif.size, 4u);
-  EXPECT_EQ(decoder->image->exif.data[0], 73);
-  EXPECT_EQ(decoder->image->exif.data[1], 73);
-  EXPECT_EQ(decoder->image->exif.data[2], 42);
-  EXPECT_EQ(decoder->image->exif.data[3], 0);
-
-  ASSERT_GE(decoder->image->xmp.size, 4u);
-  EXPECT_EQ(decoder->image->xmp.data[0], 60);
-  EXPECT_EQ(decoder->image->xmp.data[1], 63);
-  EXPECT_EQ(decoder->image->xmp.data[2], 120);
-  EXPECT_EQ(decoder->image->xmp.data[3], 112);
-
-  avifDecoderDestroy(decoder);
-}
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifprogressivetest.cc b/c_api_tests/avifprogressivetest.cc
deleted file mode 100644
index 577afae..0000000
--- a/c_api_tests/avifprogressivetest.cc
+++ /dev/null
@@ -1,63 +0,0 @@
-// Copyright 2022 Yuan Tong. All rights reserved.
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-TEST(AvifDecodeTest, Progressive) {
-  struct Params {
-    const char* file_name;
-    uint32_t width;
-    uint32_t height;
-    uint32_t layer_count;
-  };
-  Params params[] = {
-    {"progressive/progressive_dimension_change.avif", 256, 256, 2},
-    {"progressive/progressive_layered_grid.avif", 512, 256, 2},
-    {"progressive/progressive_quality_change.avif", 256, 256, 2},
-    {"progressive/progressive_same_layers.avif", 256, 256, 4},
-    {"progressive/tiger_3layer_1res.avif", 1216, 832, 3},
-    {"progressive/tiger_3layer_3res.avif", 1216, 832, 3},
-  };
-  for (const auto& param : params) {
-    DecoderPtr decoder(avifDecoderCreate());
-    ASSERT_NE(decoder, nullptr);
-    decoder->allowProgressive = true;
-    ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
-                                   (std::string(data_path) + param.file_name).c_str()),
-              AVIF_RESULT_OK);
-    ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-    EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-    ASSERT_EQ(decoder->progressiveState, AVIF_PROGRESSIVE_STATE_ACTIVE);
-    ASSERT_EQ(static_cast<uint32_t>(decoder->imageCount), param.layer_count);
-
-    for (uint32_t layer = 0; layer < param.layer_count; ++layer) {
-      ASSERT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-      // libavif scales frame automatically.
-      ASSERT_EQ(decoder->image->width, param.width);
-      ASSERT_EQ(decoder->image->height, param.height);
-    }
-  }
-}
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/avifscaletest.cc b/c_api_tests/avifscaletest.cc
deleted file mode 100644
index e5e2928..0000000
--- a/c_api_tests/avifscaletest.cc
+++ /dev/null
@@ -1,74 +0,0 @@
-// Copyright 2024 Google LLC
-// SPDX-License-Identifier: BSD-2-Clause
-
-#include <cstdint>
-#include <iostream>
-#include <string>
-
-#include "avif/avif.h"
-#include "aviftest_helpers.h"
-#include "gtest/gtest.h"
-
-namespace avif {
-namespace {
-
-// Used to pass the data folder path to the GoogleTest suites.
-const char* data_path = nullptr;
-
-class ScaleTest : public testing::TestWithParam<const char*> {};
-
-TEST_P(ScaleTest, Scaling) {
-  if (!testutil::Av1DecoderAvailable()) {
-    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
-  }
-  const char* file_name = GetParam();
-  DecoderPtr decoder(avifDecoderCreate());
-  ASSERT_NE(decoder, nullptr);
-  ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
-                                 (std::string(data_path) + file_name).c_str()),
-            AVIF_RESULT_OK);
-  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
-  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
-
-  const uint32_t scaled_width =
-      static_cast<uint32_t>(decoder->image->width * 0.8);
-  const uint32_t scaled_height =
-      static_cast<uint32_t>(decoder->image->height * 0.8);
-
-  ASSERT_EQ(
-      avifImageScale(decoder->image, scaled_width, scaled_height, nullptr),
-      AVIF_RESULT_OK);
-  EXPECT_EQ(decoder->image->width, scaled_width);
-  EXPECT_EQ(decoder->image->height, scaled_height);
-
-  // Scaling to a larger dimension is not supported.
-  EXPECT_NE(avifImageScale(decoder->image, decoder->image->width * 2,
-                           decoder->image->height * 0.5, nullptr),
-            AVIF_RESULT_OK);
-  EXPECT_NE(avifImageScale(decoder->image, decoder->image->width * 0.5,
-                           decoder->image->height * 2, nullptr),
-            AVIF_RESULT_OK);
-  EXPECT_NE(avifImageScale(decoder->image, decoder->image->width * 2,
-                           decoder->image->height * 2, nullptr),
-            AVIF_RESULT_OK);
-}
-
-INSTANTIATE_TEST_SUITE_P(Some, ScaleTest,
-                         testing::ValuesIn({"paris_10bpc.avif",
-                                            "paris_icc_exif_xmp.avif"}));
-
-}  // namespace
-}  // namespace avif
-
-int main(int argc, char** argv) {
-  ::testing::InitGoogleTest(&argc, argv);
-  if (argc != 2) {
-    std::cerr << "There must be exactly one argument containing the path to "
-                 "the test data folder"
-              << std::endl;
-    return 1;
-  }
-  avif::data_path = argv[1];
-  return RUN_ALL_TESTS();
-}
diff --git a/c_api_tests/aviftest.cc b/c_api_tests/aviftest.cc
deleted file mode 100644
index 4c7470e..0000000
--- a/c_api_tests/aviftest.cc
+++ /dev/null
@@ -1,359 +0,0 @@
-// Copyright 2020 Joe Drago. All rights reserved.
-// SPDX-License-Identifier: BSD-2-Clause
-
-// #define WIN32_MEMORY_LEAK_DETECTION
-#ifdef WIN32_MEMORY_LEAK_DETECTION
-#define _CRTDBG_MAP_ALLOC
-#include <crtdbg.h>
-#endif
-
-#include "avif/avif.h"
-#include "avif/libavif_compat.h"
-
-#include "aviftest_helpers.h"
-
-#include <inttypes.h>
-#include <stdio.h>
-#include <stdlib.h>
-#include <string.h>
-
-#define AVIF_DATA_EMPTY { NULL, 0 }
-
-#if defined(_WIN32)
-
-#include <windows.h>
-
-typedef struct NextFilenameData
-{
-    int didFirstFile;
-    HANDLE handle;
-    WIN32_FIND_DATA wfd;
-} NextFilenameData;
-
-static const char * nextFilename(const char * parentDir, const char * extension, NextFilenameData * nfd)
-{
-    for (;;) {
-        if (nfd->didFirstFile) {
-            if (FindNextFile(nfd->handle, &nfd->wfd) == 0) {
-                // No more files
-                break;
-            }
-        } else {
-            char filenameBuffer[2048];
-            snprintf(filenameBuffer, sizeof(filenameBuffer), "%s\\*", parentDir);
-            filenameBuffer[sizeof(filenameBuffer) - 1] = 0;
-            nfd->handle = FindFirstFile(filenameBuffer, &nfd->wfd);
-            if (nfd->handle == INVALID_HANDLE_VALUE) {
-                return NULL;
-            }
-            nfd->didFirstFile = 1;
-        }
-
-        // If we get here, we should have a valid wfd
-        const char * dot = strrchr(nfd->wfd.cFileName, '.');
-        if (dot) {
-            ++dot;
-            if (!strcmp(dot, extension)) {
-                return nfd->wfd.cFileName;
-            }
-        }
-    }
-
-    FindClose(nfd->handle);
-    nfd->handle = INVALID_HANDLE_VALUE;
-    nfd->didFirstFile = 0;
-    return NULL;
-}
-
-#else
-#include <dirent.h>
-typedef struct NextFilenameData
-{
-    DIR * dir;
-} NextFilenameData;
-
-static const char * nextFilename(const char * parentDir, const char * extension, NextFilenameData * nfd)
-{
-    if (!nfd->dir) {
-        nfd->dir = opendir(parentDir);
-        if (!nfd->dir) {
-            return NULL;
-        }
-    }
-
-    struct dirent * entry;
-    while ((entry = readdir(nfd->dir)) != NULL) {
-        const char * dot = strrchr(entry->d_name, '.');
-        if (dot) {
-            ++dot;
-            if (!strcmp(dot, extension)) {
-                return entry->d_name;
-            }
-        }
-    }
-
-    closedir(nfd->dir);
-    nfd->dir = NULL;
-    return NULL;
-}
-#endif
-
-typedef struct avifIOMeta {
-    avifROData rodata;
-    size_t availableBytes;
-} avifIOMeta ;
-
-static avifResult avifIOTestReaderRead(struct avifIO * io, uint32_t readFlags, uint64_t offset, size_t size, avifROData * out)
-{
-    //printf("### avifIOTestReaderRead offset %" PRIu64 " size %zu\n", offset, size);
-
-    if (readFlags != 0) {
-        // Unsupported readFlags
-        return AVIF_RESULT_IO_ERROR;
-    }
-
-    avifIOMeta * reader = (avifIOMeta *)io->data;
-
-    // Sanitize/clamp incoming request
-    if (offset > reader->rodata.size) {
-        // The offset is past the end of the buffer.
-        return AVIF_RESULT_IO_ERROR;
-    }
-    if (offset == reader->rodata.size) {
-        // The parser is *exactly* at EOF: return a 0-size pointer to any valid buffer
-        offset = 0;
-        size = 0;
-    }
-    uint64_t availableSize = reader->rodata.size - offset;
-    if (size > availableSize) {
-        size = (size_t)availableSize;
-    }
-
-    if (offset > reader->availableBytes) {
-        return AVIF_RESULT_WAITING_ON_IO;
-    }
-    if (size > (reader->availableBytes - offset)) {
-        return AVIF_RESULT_WAITING_ON_IO;
-    }
-
-    out->data = reader->rodata.data + offset;
-    out->size = size;
-    return AVIF_RESULT_OK;
-}
-
-static void avifIOTestReaderDestroy(struct avifIO * io)
-{
-    avifIOMeta* meta = (avifIOMeta*) io->data;
-    free(meta);
-    free(io);
-}
-
-static avifIO * avifIOCreateTestReader(const uint8_t * data, size_t size)
-{
-    printf("### creating reader of size: %zu\n", size);
-    avifIO * io = reinterpret_cast<avifIO *>(malloc(sizeof(avifIO)));
-    memset(io, 0, sizeof(avifIO));
-    io->destroy = &avifIOTestReaderDestroy;
-    io->read = &avifIOTestReaderRead;
-    io->sizeHint = size;
-    io->persistent = AVIF_TRUE;
-    avifIOMeta * meta = reinterpret_cast<avifIOMeta *>(malloc(sizeof(avifIOMeta)));
-    meta->rodata.data = data;
-    meta->rodata.size = size;
-    meta->availableBytes = 0;
-    io->data = meta;
-    return io;
-}
-
-#define FILENAME_MAX_LENGTH 2047
-
-static int runIOTests(const char * dataDir)
-{
-    printf("AVIF Test Suite: Running IO Tests...\n");
-
-    static const char * ioSuffix = "/io/";
-
-    char ioDir[FILENAME_MAX_LENGTH + 1];
-    size_t dataDirLen = strlen(dataDir);
-    size_t ioSuffixLen = strlen(ioSuffix);
-
-    if ((dataDirLen + ioSuffixLen) > FILENAME_MAX_LENGTH) {
-        printf("Path too long: %s\n", dataDir);
-        return 1;
-    }
-    strcpy(ioDir, dataDir);
-    strcat(ioDir, ioSuffix);
-    size_t ioDirLen = strlen(ioDir);
-
-    int retCode = 0;
-
-    NextFilenameData nfd;
-    memset(&nfd, 0, sizeof(nfd));
-    avifRWData fileBuffer = AVIF_DATA_EMPTY;
-    const char * filename = nextFilename(ioDir, "avif", &nfd);
-    for (; filename != NULL; filename = nextFilename(ioDir, "avif", &nfd)) {
-        char fullFilename[FILENAME_MAX_LENGTH + 1];
-        size_t filenameLen = strlen(filename);
-        if ((ioDirLen + filenameLen) > FILENAME_MAX_LENGTH) {
-            printf("Path too long: %s\n", filename);
-            retCode = 1;
-            break;
-        }
-        strcpy(fullFilename, ioDir);
-        strcat(fullFilename, filename);
-
-        FILE * f = fopen(fullFilename, "rb");
-        if (!f) {
-            printf("Can't open for read: %s\n", filename);
-            retCode = 1;
-            break;
-        }
-        fseek(f, 0, SEEK_END);
-        size_t fileSize = ftell(f);
-        fseek(f, 0, SEEK_SET);
-        if (avifRWDataRealloc(&fileBuffer, fileSize) != AVIF_RESULT_OK) {
-            printf("Out of memory when allocating buffer to read file: %s\n", filename);
-            fclose(f);
-            retCode = 1;
-            break;
-        }
-        if (fread(fileBuffer.data, 1, fileSize, f) != fileSize) {
-            printf("Can't read entire file: %s\n", filename);
-            fclose(f);
-            retCode = 1;
-            break;
-        }
-        fclose(f);
-
-        avifDecoder * decoder = avifDecoderCreate();
-        if (decoder == NULL) {
-            printf("Memory allocation failure\n");
-            retCode = 1;
-            break;
-        }
-        avifIO * io = avifIOCreateTestReader(fileBuffer.data, fileBuffer.size);
-        avifIOMeta * meta = (avifIOMeta*) io->data;
-        avifDecoderSetIO(decoder, (avifIO *)io);
-
-        for (int pass = 0; pass < 4; ++pass) {
-            io->persistent = ((pass % 2) == 0);
-            decoder->ignoreExif = decoder->ignoreXMP = (pass < 2);
-
-            // Slowly pretend to have streamed-in / downloaded more and more bytes
-            avifResult parseResult = AVIF_RESULT_UNKNOWN_ERROR;
-            for (meta->availableBytes = 0; meta->availableBytes <= io->sizeHint; ++meta->availableBytes) {
-                parseResult = avifDecoderParse(decoder);
-                if (parseResult == AVIF_RESULT_WAITING_ON_IO) {
-                    continue;
-                }
-                if (parseResult != AVIF_RESULT_OK) {
-                    retCode = 1;
-                }
-
-                printf("File: [%s @ %zu / %" PRIu64 " bytes, %s, %s] parse returned: (%d) %s\n",
-                       filename,
-                       meta->availableBytes,
-                       io->sizeHint,
-                       io->persistent ? "Persistent" : "NonPersistent",
-                       decoder->ignoreExif ? "IgnoreMetadata" : "Metadata",
-                       parseResult,
-                       avifResultToString(parseResult));
-                break;
-            }
-
-            if (parseResult == AVIF_RESULT_OK) {
-                for (; meta->availableBytes <= io->sizeHint; ++meta->availableBytes) {
-                    avifExtent extent;
-                    avifResult extentResult = avifDecoderNthImageMaxExtent(decoder, 0, &extent);
-                    if (extentResult != AVIF_RESULT_OK) {
-                        retCode = 1;
-
-                        printf("File: [%s @ %zu / %" PRIu64 " bytes, %s, %s] maxExtent returned: %s\n",
-                               filename,
-                               meta->availableBytes,
-                               io->sizeHint,
-                               io->persistent ? "Persistent" : "NonPersistent",
-                               decoder->ignoreExif ? "IgnoreMetadata" : "Metadata",
-                               avifResultToString(extentResult));
-                    } else {
-                        avifResult nextImageResult = avifDecoderNextImage(decoder);
-                        if (nextImageResult == AVIF_RESULT_WAITING_ON_IO) {
-                            continue;
-                        }
-                        if (nextImageResult != AVIF_RESULT_OK) {
-                            retCode = 1;
-                        }
-
-                        printf("File: [%s @ %zu / %" PRIu64 " bytes, %s, %s] nextImage [MaxExtent off %" PRIu64 ", size %zu] returned: (%d) %s\n",
-                               filename,
-                               meta->availableBytes,
-                               io->sizeHint,
-                               io->persistent ? "Persistent" : "NonPersistent",
-                               decoder->ignoreExif ? "IgnoreMetadata" : "Metadata",
-                               extent.offset,
-                               extent.size,
-                               nextImageResult,
-                               avifResultToString(nextImageResult));
-                    }
-                    break;
-                }
-            }
-        }
-
-        avifDecoderDestroy(decoder);
-    }
-
-    avifRWDataFree(&fileBuffer);
-    return retCode;
-}
-
-static void syntax(void)
-{
-    fprintf(stderr, "Syntax: aviftest dataDir\n");
-}
-
-int main(int argc, char * argv[])
-{
-    const char * dataDir = NULL;
-
-#ifdef WIN32_MEMORY_LEAK_DETECTION
-    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
-    // _CrtSetBreakAlloc(2906);
-#endif
-
-    // Parse cmdline
-    for (int i = 1; i < argc; ++i) {
-        char * arg = argv[i];
-        if (!strcmp(arg, "--io-only")) {
-            fprintf(stderr, "WARNING: --io-only is deprecated; ignoring.\n");
-        } else if (dataDir == NULL) {
-            dataDir = arg;
-        } else {
-            fprintf(stderr, "Too many positional arguments: %s\n", arg);
-            syntax();
-            return 1;
-        }
-    }
-
-    // Verify all required args were set
-    if (dataDir == NULL) {
-        fprintf(stderr, "dataDir is required, bailing out.\n");
-        syntax();
-        return 1;
-    }
-
-    setbuf(stdout, NULL);
-
-    char codecVersions[256] = {0};
-    //avifCodecVersions(codecVersions);
-    printf("Codec Versions: %s\n", codecVersions);
-    printf("Test Data Dir : %s\n", dataDir);
-
-    int retCode = runIOTests(dataDir);
-    if (retCode == 0) {
-        printf("AVIF Test Suite: Complete.\n");
-    } else {
-        printf("AVIF Test Suite: Failed.\n");
-    }
-    return retCode;
-}
diff --git a/c_api_tests/conformance_tests.cc b/c_api_tests/conformance_tests.cc
index ebbc939..c079173 100644
--- a/c_api_tests/conformance_tests.cc
+++ b/c_api_tests/conformance_tests.cc
@@ -7,8 +7,8 @@
 #include <string>
 
 #include "avif/avif.h"
-#include "aviftest_helpers.h"
 #include "gtest/gtest.h"
+#include "testutil.h"
 
 namespace avif {
 namespace {
diff --git a/c_api_tests/decoder_tests.cc b/c_api_tests/decoder_tests.cc
new file mode 100644
index 0000000..345c92c
--- /dev/null
+++ b/c_api_tests/decoder_tests.cc
@@ -0,0 +1,907 @@
+// Copyright 2025 Google LLC
+// SPDX-License-Identifier: BSD-2-Clause
+
+#include <algorithm>
+#include <cstddef>
+#include <cstdint>
+#include <cstring>
+#include <iostream>
+#include <numeric>
+#include <string>
+#include <tuple>
+#include <vector>
+
+#include "avif/avif.h"
+#include "gtest/gtest.h"
+#include "testutil.h"
+
+namespace avif {
+namespace {
+
+// Used to pass the data folder path to the GoogleTest suites.
+const char* data_path = nullptr;
+
+std::string GetFilename(const char* file_name) {
+  return std::string(data_path) + file_name;
+}
+
+DecoderPtr CreateDecoder(const char* file_name) {
+  DecoderPtr decoder(avifDecoderCreate());
+  if (decoder == nullptr ||
+      avifDecoderSetIOFile(decoder.get(), GetFilename(file_name).c_str()) !=
+          AVIF_RESULT_OK) {
+    return nullptr;
+  }
+  return decoder;
+}
+
+TEST(DecoderTest, AlphaNoIspe) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  // See https://github.com/AOMediaCodec/libavif/pull/745.
+  auto decoder = CreateDecoder("alpha_noispe.avif");
+  ASSERT_NE(decoder, nullptr);
+  // By default, loose files are refused. Cast to avoid C4389 Windows warning.
+  EXPECT_EQ(decoder->strictFlags, (avifStrictFlags)AVIF_STRICT_ENABLED);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_BMFF_PARSE_FAILED);
+  // Allow this kind of file specifically.
+  decoder->strictFlags = (avifStrictFlags)AVIF_STRICT_ENABLED &
+                         ~(avifStrictFlags)AVIF_STRICT_ALPHA_ISPE_REQUIRED;
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(decoder->alphaPresent, AVIF_TRUE);
+  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_NE(decoder->image->alphaPlane, nullptr);
+  EXPECT_GT(decoder->image->alphaRowBytes, 0u);
+}
+
+TEST(DecoderTest, AlphaPremultiplied) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  auto decoder = CreateDecoder("alpha_premultiplied.avif");
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(decoder->alphaPresent, AVIF_TRUE);
+  ASSERT_NE(decoder->image, nullptr);
+  EXPECT_EQ(decoder->image->alphaPremultiplied, AVIF_TRUE);
+  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_NE(decoder->image->alphaPlane, nullptr);
+  EXPECT_GT(decoder->image->alphaRowBytes, 0u);
+}
+
+TEST(DecoderTest, AnimatedImage) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  auto decoder = CreateDecoder("colors-animated-8bpc.avif");
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
+  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
+  EXPECT_EQ(decoder->imageCount, 5);
+  EXPECT_EQ(decoder->repetitionCount, 0);
+  for (int i = 0; i < 5; ++i) {
+    EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+  }
+}
+
+TEST(DecoderTest, AnimatedImageWithSourceSetToPrimaryItem) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  auto decoder = CreateDecoder("colors-animated-8bpc.avif");
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(
+      avifDecoderSetSource(decoder.get(), AVIF_DECODER_SOURCE_PRIMARY_ITEM),
+      AVIF_RESULT_OK);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
+  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
+  // imageCount is expected to be 1 because we are using primary item as the
+  // preferred source.
+  EXPECT_EQ(decoder->imageCount, 1);
+  EXPECT_EQ(decoder->repetitionCount, 0);
+  // Get the first (and only) image.
+  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+  // Subsequent calls should not return AVIF_RESULT_OK since there is only one
+  // image in the preferred source.
+  EXPECT_NE(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+}
+
+TEST(DecoderTest, AnimatedImageWithAlphaAndMetadata) {
+  auto decoder = CreateDecoder("colors-animated-8bpc-alpha-exif-xmp.avif");
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(decoder->alphaPresent, AVIF_TRUE);
+  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
+  EXPECT_EQ(decoder->imageCount, 5);
+  EXPECT_EQ(decoder->repetitionCount, AVIF_REPETITION_COUNT_INFINITE);
+  EXPECT_EQ(decoder->image->exif.size, 1126);
+  EXPECT_EQ(decoder->image->xmp.size, 3898);
+}
+
+TEST(DecoderTest, OneShotDecodeFile) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  const char* file_name = "sofa_grid1x5_420.avif";
+  DecoderPtr decoder(avifDecoderCreate());
+  ASSERT_NE(decoder, nullptr);
+  avifImage image;
+  ASSERT_EQ(avifDecoderReadFile(decoder.get(), &image,
+                                GetFilename(file_name).c_str()),
+            AVIF_RESULT_OK);
+  EXPECT_EQ(image.width, 1024);
+  EXPECT_EQ(image.height, 770);
+  EXPECT_EQ(image.depth, 8);
+
+  // Call avifDecoderReadFile with a different file but with the same decoder
+  // instance.
+  file_name = "white_1x1.avif";
+  ASSERT_EQ(avifDecoderReadFile(decoder.get(), &image,
+                                GetFilename(file_name).c_str()),
+            AVIF_RESULT_OK);
+  EXPECT_EQ(image.width, 1);
+  EXPECT_EQ(image.height, 1);
+  EXPECT_EQ(image.depth, 8);
+}
+
+TEST(DecoderTest, OneShotDecodeMemory) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  const char* file_name = "sofa_grid1x5_420.avif";
+  auto file_data = testutil::read_file(GetFilename(file_name).c_str());
+  DecoderPtr decoder(avifDecoderCreate());
+  ASSERT_NE(decoder, nullptr);
+  avifImage image;
+  ASSERT_EQ(avifDecoderReadMemory(decoder.get(), &image, file_data.data(),
+                                  file_data.size()),
+            AVIF_RESULT_OK);
+  EXPECT_EQ(image.width, 1024);
+  EXPECT_EQ(image.height, 770);
+  EXPECT_EQ(image.depth, 8);
+}
+
+avifResult io_read(struct avifIO* io, uint32_t flags, uint64_t offset,
+                   size_t size, avifROData* out) {
+  avifROData* src = (avifROData*)io->data;
+  if (flags != 0 || offset > src->size) {
+    return AVIF_RESULT_IO_ERROR;
+  }
+  uint64_t available_size = src->size - offset;
+  if (size > available_size) {
+    size = static_cast<size_t>(available_size);
+  }
+  out->data = src->data + offset;
+  out->size = size;
+  return AVIF_RESULT_OK;
+}
+
+TEST(DecoderTest, OneShotDecodeCustomIO) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  const char* file_name = "sofa_grid1x5_420.avif";
+  auto data = testutil::read_file(GetFilename(file_name).c_str());
+  avifROData ro_data = {.data = data.data(), .size = data.size()};
+  avifIO io = {.destroy = nullptr,
+               .read = io_read,
+               .sizeHint = data.size(),
+               .persistent = false,
+               .data = static_cast<void*>(&ro_data)};
+  DecoderPtr decoder(avifDecoderCreate());
+  ASSERT_NE(decoder, nullptr);
+  avifDecoderSetIO(decoder.get(), &io);
+  avifImage image;
+  ASSERT_EQ(avifDecoderRead(decoder.get(), &image), AVIF_RESULT_OK);
+  EXPECT_EQ(image.width, 1024);
+  EXPECT_EQ(image.height, 770);
+  EXPECT_EQ(image.depth, 8);
+}
+
+TEST(DecoderTest, NthImage) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  auto decoder = CreateDecoder("colors-animated-8bpc.avif");
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(decoder->imageCount, 5);
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 3), AVIF_RESULT_OK);
+  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_NE(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 1), AVIF_RESULT_OK);
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 4), AVIF_RESULT_OK);
+  EXPECT_NE(avifDecoderNthImage(decoder.get(), 50), AVIF_RESULT_OK);
+  for (int i = 0; i < 5; ++i) {
+  }
+}
+
+TEST(DecoderTest, Clli) {
+  struct Params {
+    const char* file_name;
+    uint32_t maxCLL;
+    uint32_t maxPALL;
+  };
+  Params params[9] = {
+      {"clli/clli_0_0.avif", 0, 0},
+      {"clli/clli_0_1.avif", 0, 1},
+      {"clli/clli_0_65535.avif", 0, 65535},
+      {"clli/clli_1_0.avif", 1, 0},
+      {"clli/clli_1_1.avif", 1, 1},
+      {"clli/clli_1_65535.avif", 1, 65535},
+      {"clli/clli_65535_0.avif", 65535, 0},
+      {"clli/clli_65535_1.avif", 65535, 1},
+      {"clli/clli_65535_65535.avif", 65535, 65535},
+  };
+  for (const auto& param : params) {
+    DecoderPtr decoder(avifDecoderCreate());
+    ASSERT_NE(decoder, nullptr);
+    decoder->allowProgressive = true;
+    ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
+                                   GetFilename(param.file_name).c_str()),
+              AVIF_RESULT_OK);
+    ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+    EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+    avifImage* decoded = decoder->image;
+    ASSERT_NE(decoded, nullptr);
+    ASSERT_EQ(decoded->clli.maxCLL, param.maxCLL);
+    ASSERT_EQ(decoded->clli.maxPALL, param.maxPALL);
+  }
+}
+
+TEST(DecoderTest, ColorGridAlphaNoGrid) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  // Test case from https://github.com/AOMediaCodec/libavif/issues/1203.
+  auto decoder = CreateDecoder("color_grid_alpha_nogrid.avif");
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(decoder->alphaPresent, AVIF_TRUE);
+  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_FALSE);
+  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_NE(decoder->image->alphaPlane, nullptr);
+  EXPECT_GT(decoder->image->alphaRowBytes, 0u);
+}
+
+TEST(DecoderTest, GainMapGrid) {
+  auto decoder = CreateDecoder("color_grid_gainmap_different_grid.avif");
+  ASSERT_NE(decoder, nullptr);
+  decoder->imageContentToDecode |= AVIF_IMAGE_CONTENT_GAIN_MAP;
+
+  // Just parse the image first.
+  auto result = avifDecoderParse(decoder.get());
+  ASSERT_EQ(result, AVIF_RESULT_OK)
+      << avifResultToString(result) << " " << decoder->diag.error;
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  avifImage* decoded = decoder->image;
+  ASSERT_NE(decoded, nullptr);
+
+  // Verify that the gain map is present and matches the input.
+  EXPECT_NE(decoder->image->gainMap, nullptr);
+  // Color+alpha: 4x3 grid of 128x200 tiles.
+  EXPECT_EQ(decoded->width, 128u * 4u);
+  EXPECT_EQ(decoded->height, 200u * 3u);
+  EXPECT_EQ(decoded->depth, 10u);
+  ASSERT_NE(decoded->gainMap->image, nullptr);
+  // Gain map: 2x2 grid of 64x80 tiles.
+  EXPECT_EQ(decoded->gainMap->image->width, 64u * 2u);
+  EXPECT_EQ(decoded->gainMap->image->height, 80u * 2u);
+  EXPECT_EQ(decoded->gainMap->image->depth, 8u);
+  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.n, 6u);
+  EXPECT_EQ(decoded->gainMap->baseHdrHeadroom.d, 2u);
+
+  // Decode the image.
+  result = avifDecoderNextImage(decoder.get());
+  ASSERT_EQ(result, AVIF_RESULT_OK)
+      << avifResultToString(result) << " " << decoder->diag.error;
+}
+
+TEST(DecoderTest, GainMapOriented) {
+  auto decoder = CreateDecoder(("gainmap_oriented.avif"));
+  ASSERT_NE(decoder, nullptr);
+  decoder->imageContentToDecode |= AVIF_IMAGE_CONTENT_GAIN_MAP;
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+
+  // Verify that the transformative properties were kept.
+  EXPECT_EQ(decoder->image->transformFlags,
+            AVIF_TRANSFORM_IROT | AVIF_TRANSFORM_IMIR);
+  EXPECT_EQ(decoder->image->irot.angle, 1);
+  EXPECT_EQ(decoder->image->imir.axis, 0);
+  EXPECT_EQ(decoder->image->gainMap->image->transformFlags,
+            AVIF_TRANSFORM_NONE);
+}
+
+TEST(DecoderTest, IgnoreGainMapButReadMetadata) {
+  auto decoder = CreateDecoder(("seine_sdr_gainmap_srgb.avif"));
+  ASSERT_NE(decoder, nullptr);
+  auto result = avifDecoderParse(decoder.get());
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
+TEST(DecoderTest, IgnoreColorAndAlpha) {
+  auto decoder = CreateDecoder(("seine_sdr_gainmap_srgb.avif"));
+  ASSERT_NE(decoder, nullptr);
+  decoder->imageContentToDecode = AVIF_IMAGE_CONTENT_GAIN_MAP;
+  auto result = avifDecoderParse(decoder.get());
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
+TEST(DecoderTest, IgnoreAll) {
+  auto decoder = CreateDecoder(("seine_sdr_gainmap_srgb.avif"));
+  ASSERT_NE(decoder, nullptr);
+  decoder->imageContentToDecode = AVIF_IMAGE_CONTENT_NONE;
+  auto result = avifDecoderParse(decoder.get());
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
+TEST(DecoderTest, KeyFrame) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  auto decoder = CreateDecoder("colors-animated-12bpc-keyframes-0-2-3.avif");
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+
+  // The first frame is always a keyframe.
+  EXPECT_TRUE(avifDecoderIsKeyframe(decoder.get(), 0));
+  EXPECT_EQ(avifDecoderNearestKeyframe(decoder.get(), 0), 0);
+
+  // The encoder may choose to use a keyframe here, even without FORCE_KEYFRAME.
+  // It seems not to.
+  EXPECT_FALSE(avifDecoderIsKeyframe(decoder.get(), 1));
+  EXPECT_EQ(avifDecoderNearestKeyframe(decoder.get(), 1), 0);
+
+  EXPECT_TRUE(avifDecoderIsKeyframe(decoder.get(), 2));
+  EXPECT_EQ(avifDecoderNearestKeyframe(decoder.get(), 2), 2);
+
+  // The encoder seems to prefer a keyframe here
+  // (gradient too different from plain color).
+  EXPECT_TRUE(avifDecoderIsKeyframe(decoder.get(), 3));
+  EXPECT_EQ(avifDecoderNearestKeyframe(decoder.get(), 3), 3);
+
+  // This is the same frame as the previous one. It should not be a keyframe.
+  EXPECT_FALSE(avifDecoderIsKeyframe(decoder.get(), 4));
+  EXPECT_EQ(avifDecoderNearestKeyframe(decoder.get(), 4), 3);
+}
+
+TEST(DecoderTest, Progressive) {
+  struct Params {
+    const char* file_name;
+    uint32_t width;
+    uint32_t height;
+    uint32_t layer_count;
+  };
+  Params params[] = {
+      {"progressive/progressive_dimension_change.avif", 256, 256, 2},
+      {"progressive/progressive_layered_grid.avif", 512, 256, 2},
+      {"progressive/progressive_quality_change.avif", 256, 256, 2},
+      {"progressive/progressive_same_layers.avif", 256, 256, 4},
+      {"progressive/tiger_3layer_1res.avif", 1216, 832, 3},
+      {"progressive/tiger_3layer_3res.avif", 1216, 832, 3},
+  };
+  for (const auto& param : params) {
+    DecoderPtr decoder(avifDecoderCreate());
+    ASSERT_NE(decoder, nullptr);
+    decoder->allowProgressive = true;
+    ASSERT_EQ(avifDecoderSetIOFile(decoder.get(),
+                                   GetFilename(param.file_name).c_str()),
+              AVIF_RESULT_OK);
+    ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+    EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+    ASSERT_EQ(decoder->progressiveState, AVIF_PROGRESSIVE_STATE_ACTIVE);
+    ASSERT_EQ(static_cast<uint32_t>(decoder->imageCount), param.layer_count);
+
+    for (uint32_t layer = 0; layer < param.layer_count; ++layer) {
+      ASSERT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+      // libavif scales frame automatically.
+      ASSERT_EQ(decoder->image->width, param.width);
+      ASSERT_EQ(decoder->image->height, param.height);
+    }
+  }
+}
+
+// A test for https://github.com/AOMediaCodec/libavif/issues/1086 to prevent
+// regression.
+TEST(DecoderTest, ParseICC) {
+  auto decoder = CreateDecoder(("paris_icc_exif_xmp.avif"));
+  ASSERT_NE(decoder, nullptr);
+
+  decoder->ignoreXMP = AVIF_TRUE;
+  decoder->ignoreExif = AVIF_TRUE;
+  EXPECT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+
+  ASSERT_GE(decoder->image->icc.size, 4u);
+  EXPECT_EQ(decoder->image->icc.data[0], 0);
+  EXPECT_EQ(decoder->image->icc.data[1], 0);
+  EXPECT_EQ(decoder->image->icc.data[2], 2);
+  EXPECT_EQ(decoder->image->icc.data[3], 84);
+
+  ASSERT_EQ(decoder->image->exif.size, 0u);
+  ASSERT_EQ(decoder->image->xmp.size, 0u);
+
+  decoder->ignoreXMP = AVIF_FALSE;
+  decoder->ignoreExif = AVIF_FALSE;
+  EXPECT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+
+  ASSERT_GE(decoder->image->exif.size, 4u);
+  EXPECT_EQ(decoder->image->exif.data[0], 73);
+  EXPECT_EQ(decoder->image->exif.data[1], 73);
+  EXPECT_EQ(decoder->image->exif.data[2], 42);
+  EXPECT_EQ(decoder->image->exif.data[3], 0);
+
+  ASSERT_GE(decoder->image->xmp.size, 4u);
+  EXPECT_EQ(decoder->image->xmp.data[0], 60);
+  EXPECT_EQ(decoder->image->xmp.data[1], 63);
+  EXPECT_EQ(decoder->image->xmp.data[2], 120);
+  EXPECT_EQ(decoder->image->xmp.data[3], 112);
+}
+
+bool CompareImages(const avifImage& image1, const avifImage image2) {
+  EXPECT_EQ(image1.width, image2.width);
+  EXPECT_EQ(image1.height, image2.height);
+  EXPECT_EQ(image1.depth, image2.depth);
+  EXPECT_EQ(image1.yuvFormat, image2.yuvFormat);
+  EXPECT_EQ(image1.yuvRange, image2.yuvRange);
+  for (int c = 0; c < 4; ++c) {
+    const uint8_t* row1 = avifImagePlane(&image1, c);
+    const uint8_t* row2 = avifImagePlane(&image2, c);
+    if (!row1 != !row2) {
+      return false;
+    }
+    const uint32_t row_bytes1 = avifImagePlaneRowBytes(&image1, c);
+    const uint32_t row_bytes2 = avifImagePlaneRowBytes(&image2, c);
+    const uint32_t plane_width = avifImagePlaneWidth(&image1, c);
+    const uint32_t plane_height = avifImagePlaneHeight(&image1, c);
+    for (uint32_t y = 0; y < plane_height; ++y) {
+      if (avifImageUsesU16(&image1)) {
+        if (!std::equal(reinterpret_cast<const uint16_t*>(row1),
+                        reinterpret_cast<const uint16_t*>(row1) + plane_width,
+                        reinterpret_cast<const uint16_t*>(row2))) {
+          return false;
+        }
+      } else {
+        if (!std::equal(row1, row1 + plane_width, row2)) {
+          return false;
+        }
+      }
+      row1 += row_bytes1;
+      row2 += row_bytes2;
+    }
+  }
+  return true;
+}
+
+class ImageCopyFileTest : public testing::TestWithParam<const char*> {};
+
+TEST_P(ImageCopyFileTest, ImageCopy) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  auto decoder = CreateDecoder(GetParam());
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+
+  ImagePtr image2(avifImageCreateEmpty());
+  ASSERT_EQ(avifImageCopy(image2.get(), decoder->image, AVIF_PLANES_ALL),
+            AVIF_RESULT_OK);
+  EXPECT_TRUE(CompareImages(*decoder->image, *image2));
+}
+
+INSTANTIATE_TEST_SUITE_P(ImageCopyFileTestInstance, ImageCopyFileTest,
+                         testing::ValuesIn({"paris_10bpc.avif", "alpha.avif",
+                                            "colors-animated-8bpc.avif"}));
+
+class ImageCopyTest : public testing::TestWithParam<
+                          std::tuple<int, avifPixelFormat, avifPlanesFlag>> {};
+
+TEST_P(ImageCopyTest, RightEdgeDoesNotOverreadInLastRow) {
+  const auto depth = std::get<0>(GetParam());
+  const auto pixel_format = std::get<1>(GetParam());
+
+  if ((pixel_format == AVIF_PIXEL_FORMAT_ANDROID_P010 && depth == 8) ||
+      ((pixel_format == AVIF_PIXEL_FORMAT_ANDROID_NV12 ||
+        pixel_format == AVIF_PIXEL_FORMAT_ANDROID_NV21) &&
+       depth != 8)) {
+    GTEST_SKIP() << "This combination of parameters is not valid. Skipping.";
+  }
+
+  constexpr int kWidth = 100;
+  constexpr int kHeight = 100;
+  ImagePtr src(avifImageCreate(kWidth, kHeight, depth, pixel_format));
+
+  const auto planes = std::get<2>(GetParam());
+  ASSERT_EQ(avifImageAllocatePlanes(src.get(), planes), AVIF_RESULT_OK);
+  for (int i = 0; i < 4; ++i) {
+    const int plane_width_bytes =
+        avifImagePlaneWidth(src.get(), i) * ((depth > 8) ? 2 : 1);
+    const int plane_height = avifImagePlaneHeight(src.get(), i);
+    uint8_t* plane = avifImagePlane(src.get(), i);
+    const int row_bytes = avifImagePlaneRowBytes(src.get(), i);
+    for (int y = 0; y < plane_height; ++y) {
+      std::iota(plane, plane + plane_width_bytes, y);
+      plane += row_bytes;
+    }
+  }
+
+  constexpr int kSubsetWidth = 20;
+  constexpr int kSubsetHeight = kHeight;
+
+  // Get a subset of the image near the right edge (last 20 pixel columns). If
+  // the copy implementation is correct, it will copy the exact 20 columns
+  // without over-reading beyond the |width| pixels irrespective of what the
+  // source stride is.
+  ImagePtr subset_image(avifImageCreateEmpty());
+  const avifCropRect rect{
+      .x = 80, .y = 0, .width = kSubsetWidth, .height = kSubsetHeight};
+  auto result = avifImageSetViewRect(subset_image.get(), src.get(), &rect);
+  ASSERT_EQ(result, AVIF_RESULT_OK);
+  auto* image = subset_image.get();
+
+  EXPECT_EQ(image->width, kSubsetWidth);
+  EXPECT_EQ(image->height, kSubsetHeight);
+
+  // Perform a copy of the subset.
+  ImagePtr copied_image(avifImageCreateEmpty());
+  result =
+      avifImageCopy(copied_image.get(), subset_image.get(), AVIF_PLANES_ALL);
+  ASSERT_EQ(result, AVIF_RESULT_OK);
+  EXPECT_TRUE(CompareImages(*subset_image, *copied_image));
+}
+
+INSTANTIATE_TEST_SUITE_P(
+    ImageCopyTestInstance, ImageCopyTest,
+    testing::Combine(testing::ValuesIn({8, 10, 12}),
+                     testing::ValuesIn({AVIF_PIXEL_FORMAT_YUV420,
+                                        AVIF_PIXEL_FORMAT_ANDROID_NV12,
+                                        AVIF_PIXEL_FORMAT_ANDROID_NV21,
+                                        AVIF_PIXEL_FORMAT_ANDROID_P010}),
+                     testing::ValuesIn({AVIF_PLANES_ALL, AVIF_PLANES_YUV})));
+
+TEST(DecoderTest, SetRawIO) {
+  DecoderPtr decoder(avifDecoderCreate());
+  ASSERT_NE(decoder, nullptr);
+  auto data =
+      testutil::read_file(GetFilename("colors-animated-8bpc.avif").c_str());
+  ASSERT_EQ(avifDecoderSetIOMemory(decoder.get(), data.data(), data.size()),
+            AVIF_RESULT_OK);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
+  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
+  EXPECT_EQ(decoder->imageCount, 5);
+  EXPECT_EQ(decoder->repetitionCount, 0);
+  for (int i = 0; i < 5; ++i) {
+    EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+  }
+}
+
+TEST(DecoderTest, SetCustomIO) {
+  DecoderPtr decoder(avifDecoderCreate());
+  ASSERT_NE(decoder, nullptr);
+  auto data =
+      testutil::read_file(GetFilename("colors-animated-8bpc.avif").c_str());
+  avifROData ro_data = {.data = data.data(), .size = data.size()};
+  avifIO io = {.destroy = nullptr,
+               .read = io_read,
+               .sizeHint = data.size(),
+               .persistent = false,
+               .data = static_cast<void*>(&ro_data)};
+  avifDecoderSetIO(decoder.get(), &io);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(decoder->alphaPresent, AVIF_FALSE);
+  EXPECT_EQ(decoder->imageSequenceTrackPresent, AVIF_TRUE);
+  EXPECT_EQ(decoder->imageCount, 5);
+  EXPECT_EQ(decoder->repetitionCount, 0);
+  for (int i = 0; i < 5; ++i) {
+    EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+  }
+}
+
+TEST(DecoderTest, IOMemoryReader) {
+  auto data =
+      testutil::read_file(GetFilename("colors-animated-8bpc.avif").c_str());
+  avifIO* io = avifIOCreateMemoryReader(data.data(), data.size());
+  ASSERT_NE(io, nullptr);
+  EXPECT_EQ(io->sizeHint, data.size());
+  avifROData ro_data;
+  // Read 10 bytes from the beginning.
+  io->read(io, 0, 0, 10, &ro_data);
+  EXPECT_EQ(ro_data.size, 10);
+  for (int i = 0; i < 10; ++i) {
+    EXPECT_EQ(ro_data.data[i], data[i]);
+  }
+  // Read 10 bytes from the middle.
+  io->read(io, 0, 50, 10, &ro_data);
+  EXPECT_EQ(ro_data.size, 10);
+  for (int i = 0; i < 10; ++i) {
+    EXPECT_EQ(ro_data.data[i], data[i + 50]);
+  }
+  avifIODestroy(io);
+}
+
+TEST(DecoderTest, IOFileReader) {
+  const char* file_name = "colors-animated-8bpc.avif";
+  auto data = testutil::read_file(GetFilename(file_name).c_str());
+  avifIO* io = avifIOCreateFileReader(GetFilename(file_name).c_str());
+  ASSERT_NE(io, nullptr);
+  EXPECT_EQ(io->sizeHint, data.size());
+  avifROData ro_data;
+  // Read 10 bytes from the beginning.
+  io->read(io, 0, 0, 10, &ro_data);
+  EXPECT_EQ(ro_data.size, 10);
+  for (int i = 0; i < 10; ++i) {
+    EXPECT_EQ(ro_data.data[i], data[i]);
+  }
+  // Read 10 bytes from the middle.
+  io->read(io, 0, 50, 10, &ro_data);
+  EXPECT_EQ(ro_data.size, 10);
+  for (int i = 0; i < 10; ++i) {
+    EXPECT_EQ(ro_data.data[i], data[i + 50]);
+  }
+  avifIODestroy(io);
+}
+
+class ScaleTest : public testing::TestWithParam<const char*> {};
+
+TEST_P(ScaleTest, Scaling) {
+  if (!testutil::Av1DecoderAvailable()) {
+    GTEST_SKIP() << "AV1 Codec unavailable, skip test.";
+  }
+  auto decoder = CreateDecoder(GetParam());
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+  EXPECT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+
+  const uint32_t scaled_width =
+      static_cast<uint32_t>(decoder->image->width * 0.8);
+  const uint32_t scaled_height =
+      static_cast<uint32_t>(decoder->image->height * 0.8);
+
+  ASSERT_EQ(
+      avifImageScale(decoder->image, scaled_width, scaled_height, nullptr),
+      AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->image->width, scaled_width);
+  EXPECT_EQ(decoder->image->height, scaled_height);
+
+  // Scaling to a larger dimension is not supported.
+  EXPECT_NE(avifImageScale(decoder->image, decoder->image->width * 2,
+                           decoder->image->height * 0.5, nullptr),
+            AVIF_RESULT_OK);
+  EXPECT_NE(avifImageScale(decoder->image, decoder->image->width * 0.5,
+                           decoder->image->height * 2, nullptr),
+            AVIF_RESULT_OK);
+  EXPECT_NE(avifImageScale(decoder->image, decoder->image->width * 2,
+                           decoder->image->height * 2, nullptr),
+            AVIF_RESULT_OK);
+}
+
+INSTANTIATE_TEST_SUITE_P(ScaleTestInstance, ScaleTest,
+                         testing::ValuesIn({"paris_10bpc.avif",
+                                            "paris_icc_exif_xmp.avif"}));
+
+struct InvalidClapPropertyParam {
+  uint32_t width;
+  uint32_t height;
+  avifPixelFormat yuv_format;
+  avifCleanApertureBox clap;
+};
+
+constexpr InvalidClapPropertyParam kInvalidClapPropertyTestParams[] = {
+    // Zero or negative denominators.
+    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 0, 132, 1, 0, 1, 0, 1}},
+    {120,
+     160,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {96, static_cast<uint32_t>(-1), 132, 1, 0, 1, 0, 1}},
+    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 1, 132, 0, 0, 1, 0, 1}},
+    {120,
+     160,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {96, 1, 132, static_cast<uint32_t>(-1), 0, 1, 0, 1}},
+    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 1, 132, 1, 0, 0, 0, 1}},
+    {120,
+     160,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {96, 1, 132, 1, 0, static_cast<uint32_t>(-1), 0, 1}},
+    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 1, 132, 1, 0, 1, 0, 0}},
+    {120,
+     160,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {96, 1, 132, 1, 0, 1, 0, static_cast<uint32_t>(-1)}},
+    // Zero or negative clean aperture width or height.
+    {120,
+     160,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {static_cast<uint32_t>(-96), 1, 132, 1, 0, 1, 0, 1}},
+    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {0, 1, 132, 1, 0, 1, 0, 1}},
+    {120,
+     160,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {96, 1, static_cast<uint32_t>(-132), 1, 0, 1, 0, 1}},
+    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 1, 0, 1, 0, 1, 0, 1}},
+    // Clean aperture width or height is not an integer.
+    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 5, 132, 1, 0, 1, 0, 1}},
+    {120, 160, AVIF_PIXEL_FORMAT_YUV420, {96, 1, 132, 5, 0, 1, 0, 1}},
+    // pcX = 103 + (722 - 1)/2 = 463.5
+    // pcY = -308 + (1024 - 1)/2 = 203.5
+    // leftmost = 463.5 - (385 - 1)/2 = 271.5 (not an integer)
+    // topmost = 203.5 - (330 - 1)/2 = 39
+    {722,
+     1024,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {385, 1, 330, 1, 103, 1, static_cast<uint32_t>(-308), 1}},
+    // pcX = -308 + (1024 - 1)/2 = 203.5
+    // pcY = 103 + (722 - 1)/2 = 463.5
+    // leftmost = 203.5 - (330 - 1)/2 = 39
+    // topmost = 463.5 - (385 - 1)/2 = 271.5 (not an integer)
+    {1024,
+     722,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {330, 1, 385, 1, static_cast<uint32_t>(-308), 1, 103, 1}},
+    // pcX = -1/2 + (99 - 1)/2 = 48.5
+    // pcY = -1/2 + (99 - 1)/2 = 48.5
+    // leftmost = 48.5 - (99 - 1)/2 = -0.5 (not an integer)
+    // topmost = 48.5 - (99 - 1)/2 = -0.5 (not an integer)
+    {99,
+     99,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {99, 1, 99, 1, static_cast<uint32_t>(-1), 2, static_cast<uint32_t>(-1),
+      2}},
+};
+
+using InvalidClapPropertyTest =
+    ::testing::TestWithParam<InvalidClapPropertyParam>;
+
+// Negative tests for the avifCropRectConvertCleanApertureBox() function.
+TEST_P(InvalidClapPropertyTest, ValidateClapProperty) {
+  const InvalidClapPropertyParam& param = GetParam();
+  avifCropRect crop_rect;
+  avifDiagnostics diag;
+  EXPECT_FALSE(avifCropRectConvertCleanApertureBox(&crop_rect, &param.clap,
+                                                   param.width, param.height,
+                                                   param.yuv_format, &diag));
+}
+
+INSTANTIATE_TEST_SUITE_P(Parameterized, InvalidClapPropertyTest,
+                         ::testing::ValuesIn(kInvalidClapPropertyTestParams));
+
+struct ValidClapPropertyParam {
+  uint32_t width;
+  uint32_t height;
+  avifPixelFormat yuv_format;
+  avifCleanApertureBox clap;
+
+  avifCropRect expected_crop_rect;
+};
+
+constexpr ValidClapPropertyParam kValidClapPropertyTestParams[] = {
+    // pcX = 0 + (120 - 1)/2 = 59.5
+    // pcY = 0 + (160 - 1)/2 = 79.5
+    // leftmost = 59.5 - (96 - 1)/2 = 12
+    // topmost = 79.5 - (132 - 1)/2 = 14
+    {120,
+     160,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {96, 1, 132, 1, 0, 1, 0, 1},
+     {12, 14, 96, 132}},
+    // pcX = -30 + (120 - 1)/2 = 29.5
+    // pcY = -40 + (160 - 1)/2 = 39.5
+    // leftmost = 29.5 - (60 - 1)/2 = 0
+    // topmost = 39.5 - (80 - 1)/2 = 0
+    {120,
+     160,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {60, 1, 80, 1, static_cast<uint32_t>(-30), 1, static_cast<uint32_t>(-40),
+      1},
+     {0, 0, 60, 80}},
+    // pcX = -1/2 + (100 - 1)/2 = 49
+    // pcY = -1/2 + (100 - 1)/2 = 49
+    // leftmost = 49 - (99 - 1)/2 = 0
+    // topmost = 49 - (99 - 1)/2 = 0
+    {100,
+     100,
+     AVIF_PIXEL_FORMAT_YUV420,
+     {99, 1, 99, 1, static_cast<uint32_t>(-1), 2, static_cast<uint32_t>(-1), 2},
+     {0, 0, 99, 99}},
+};
+
+using ValidClapPropertyTest = ::testing::TestWithParam<ValidClapPropertyParam>;
+
+// Positive tests for the avifCropRectConvertCleanApertureBox() function.
+TEST_P(ValidClapPropertyTest, ValidateClapProperty) {
+  const ValidClapPropertyParam& param = GetParam();
+  avifCropRect crop_rect;
+  avifDiagnostics diag;
+  EXPECT_TRUE(avifCropRectConvertCleanApertureBox(&crop_rect, &param.clap,
+                                                  param.width, param.height,
+                                                  param.yuv_format, &diag))
+      << diag.error;
+  EXPECT_EQ(crop_rect.x, param.expected_crop_rect.x);
+  EXPECT_EQ(crop_rect.y, param.expected_crop_rect.y);
+  EXPECT_EQ(crop_rect.width, param.expected_crop_rect.width);
+  EXPECT_EQ(crop_rect.height, param.expected_crop_rect.height);
+}
+
+INSTANTIATE_TEST_SUITE_P(Parameterized, ValidClapPropertyTest,
+                         ::testing::ValuesIn(kValidClapPropertyTestParams));
+
+TEST(DecoderTest, ClapIrotImirNonEssential) {
+  // Invalid file with non-essential transformative properties.
+  auto decoder = CreateDecoder("clap_irot_imir_non_essential.avif");
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_BMFF_PARSE_FAILED);
+}
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
diff --git a/c_api_tests/avifincrtest.cc b/c_api_tests/incremental_tests.cc
similarity index 99%
rename from c_api_tests/avifincrtest.cc
rename to c_api_tests/incremental_tests.cc
index 4b74b84..48d6c71 100644
--- a/c_api_tests/avifincrtest.cc
+++ b/c_api_tests/incremental_tests.cc
@@ -6,8 +6,8 @@
 #include <string>
 
 #include "avif/avif.h"
-#include "aviftest_helpers.h"
 #include "gtest/gtest.h"
+#include "testutil.h"
 
 using testing::Bool;
 using testing::Combine;
diff --git a/c_api_tests/avifreformattest.cc b/c_api_tests/reformat_tests.cc
similarity index 98%
rename from c_api_tests/avifreformattest.cc
rename to c_api_tests/reformat_tests.cc
index 7b853ca..60f0d80 100644
--- a/c_api_tests/avifreformattest.cc
+++ b/c_api_tests/reformat_tests.cc
@@ -4,8 +4,8 @@
 #include <vector>
 
 #include "avif/avif.h"
-#include "aviftest_helpers.h"
 #include "gtest/gtest.h"
+#include "testutil.h"
 
 namespace avif {
 namespace {
@@ -52,7 +52,7 @@ constexpr uint8_t kRgb[][kWidth * kHeight * 4] = {
      0xe5, 0x4b, 0x63, 0xff, 0x80, 0x80, 0xc8, 0xff, 0x80, 0x80, 0xc8,
      0xff, 0x80, 0x80, 0xc8, 0xff, 0x80, 0x80, 0xc8, 0xff}};
 
-TEST(AvifDecodeTest, YUVToRGBConversion) {
+TEST(ReformatTest, YUVToRGBConversion) {
   for (int p = 0; p < 3; ++p) {
     ImagePtr image(
         avifImageCreate(kWidth, kHeight, 8, AVIF_PIXEL_FORMAT_YUV444));
diff --git a/c_api_tests/aviftest_helpers.h b/c_api_tests/testutil.h
similarity index 100%
rename from c_api_tests/aviftest_helpers.h
rename to c_api_tests/testutil.h
diff --git a/examples/crabby_decode.rs b/examples/crabby_decode.rs
new file mode 100644
index 0000000..5f2071e
--- /dev/null
+++ b/examples/crabby_decode.rs
@@ -0,0 +1,480 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+use clap::value_parser;
+use clap::Parser;
+
+use crabby_avif::decoder::track::RepetitionCount;
+use crabby_avif::decoder::*;
+use crabby_avif::utils::clap::CropRect;
+use crabby_avif::*;
+
+mod writer;
+
+use writer::jpeg::JpegWriter;
+use writer::png::PngWriter;
+use writer::y4m::Y4MWriter;
+use writer::Writer;
+
+use std::fs::File;
+use std::num::NonZero;
+
+fn depth_parser(s: &str) -> Result<u8, String> {
+    match s.parse::<u8>() {
+        Ok(8) => Ok(8),
+        Ok(16) => Ok(16),
+        _ => Err("Value must be either 8 or 16".into()),
+    }
+}
+
+#[derive(Parser)]
+struct CommandLineArgs {
+    /// Disable strict decoding, which disables strict validation checks and errors
+    #[arg(long, default_value = "false")]
+    no_strict: bool,
+
+    /// Decode all frames and display all image information instead of saving to disk
+    #[arg(short = 'i', long, default_value = "false")]
+    info: bool,
+
+    #[arg(long)]
+    jobs: Option<u32>,
+
+    /// When decoding an image sequence or progressive image, specify which frame index to decode
+    /// (Default: 0)
+    #[arg(long, short = 'I')]
+    index: Option<u32>,
+
+    /// Output depth, either 8 or 16. (PNG only; For y4m/yuv, source depth is retained; JPEG is
+    /// always 8bit)
+    #[arg(long, short = 'd', value_parser = depth_parser)]
+    depth: Option<u8>,
+
+    /// Output quality in 0..100. (JPEG only, default: 90)
+    #[arg(long, short = 'q', value_parser = value_parser!(u8).range(0..=100))]
+    quality: Option<u8>,
+
+    /// Enable progressive AVIF processing. If a progressive image is encountered and --progressive
+    /// is passed, --index will be used to choose which layer to decode (in progressive order).
+    #[arg(long, default_value = "false")]
+    progressive: bool,
+
+    /// Maximum image size (in total pixels) that should be tolerated (0 means unlimited)
+    #[arg(long)]
+    size_limit: Option<u32>,
+
+    /// Maximum image dimension (width or height) that should be tolerated (0 means unlimited)
+    #[arg(long)]
+    dimension_limit: Option<u32>,
+
+    /// If the input file contains embedded Exif metadata, ignore it (no-op if absent)
+    #[arg(long, default_value = "false")]
+    ignore_exif: bool,
+
+    /// If the input file contains embedded XMP metadata, ignore it (no-op if absent)
+    #[arg(long, default_value = "false")]
+    ignore_xmp: bool,
+
+    /// Input AVIF file
+    #[arg(allow_hyphen_values = false)]
+    input_file: String,
+
+    /// Output file
+    #[arg(allow_hyphen_values = false)]
+    output_file: Option<String>,
+}
+
+fn print_data_as_columns(rows: &[(usize, &str, String)]) {
+    let rows: Vec<_> = rows
+        .iter()
+        .filter(|x| !x.1.is_empty())
+        .map(|x| (format!("{} * {}", " ".repeat(x.0 * 4), x.1), x.2.as_str()))
+        .collect();
+
+    // Calculate the maximum width for the first column.
+    let mut max_col1_width = 0;
+    for (col1, _) in &rows {
+        max_col1_width = max_col1_width.max(col1.len());
+    }
+
+    for (col1, col2) in &rows {
+        println!("{col1:<max_col1_width$} : {col2}");
+    }
+}
+
+fn print_vec(data: &[u8]) -> String {
+    if data.is_empty() {
+        format!("Absent")
+    } else {
+        format!("Present ({} bytes)", data.len())
+    }
+}
+
+fn print_image_info(decoder: &Decoder) {
+    let image = decoder.image().unwrap();
+    let mut image_data = vec![
+        (
+            0,
+            "File Format",
+            format!("{:#?}", decoder.compression_format()),
+        ),
+        (0, "Resolution", format!("{}x{}", image.width, image.height)),
+        (0, "Bit Depth", format!("{}", image.depth)),
+        (0, "Format", format!("{:#?}", image.yuv_format)),
+        if image.yuv_format == PixelFormat::Yuv420 {
+            (
+                0,
+                "Chroma Sample Position",
+                format!("{:#?}", image.chroma_sample_position),
+            )
+        } else {
+            (0, "", "".into())
+        },
+        (
+            0,
+            "Alpha",
+            format!(
+                "{}",
+                match (image.alpha_present, image.alpha_premultiplied) {
+                    (true, true) => "Premultiplied",
+                    (true, false) => "Not premultiplied",
+                    (false, _) => "Absent",
+                }
+            ),
+        ),
+        (0, "Range", format!("{:#?}", image.yuv_range)),
+        (
+            0,
+            "Color Primaries",
+            format!("{:#?}", image.color_primaries),
+        ),
+        (
+            0,
+            "Transfer Characteristics",
+            format!("{:#?}", image.transfer_characteristics),
+        ),
+        (
+            0,
+            "Matrix Coefficients",
+            format!("{:#?}", image.matrix_coefficients),
+        ),
+        (0, "ICC Profile", print_vec(&image.icc)),
+        (0, "XMP Metadata", print_vec(&image.xmp)),
+        (0, "Exif Metadata", print_vec(&image.exif)),
+    ];
+    if image.pasp.is_none()
+        && image.clap.is_none()
+        && image.irot_angle.is_none()
+        && image.imir_axis.is_none()
+    {
+        image_data.push((0, "Transformations", format!("None")));
+    } else {
+        image_data.push((0, "Transformations", format!("")));
+        if let Some(pasp) = image.pasp {
+            image_data.push((
+                1,
+                "pasp (Aspect Ratio)",
+                format!("{}/{}", pasp.h_spacing, pasp.v_spacing),
+            ));
+        }
+        if let Some(clap) = image.clap {
+            image_data.push((1, "clap (Clean Aperture)", format!("")));
+            image_data.push((2, "W", format!("{}/{}", clap.width.0, clap.width.1)));
+            image_data.push((2, "H", format!("{}/{}", clap.height.0, clap.height.1)));
+            image_data.push((
+                2,
+                "hOff",
+                format!("{}/{}", clap.horiz_off.0, clap.horiz_off.1),
+            ));
+            image_data.push((
+                2,
+                "vOff",
+                format!("{}/{}", clap.vert_off.0, clap.vert_off.1),
+            ));
+            match CropRect::create_from(&clap, image.width, image.height, image.yuv_format) {
+                Ok(rect) => image_data.extend_from_slice(&[
+                    (2, "Valid, derived crop rect", format!("")),
+                    (3, "X", format!("{}", rect.x)),
+                    (3, "Y", format!("{}", rect.y)),
+                    (3, "W", format!("{}", rect.width)),
+                    (3, "H", format!("{}", rect.height)),
+                ]),
+                Err(_) => image_data.push((2, "Invalid", format!(""))),
+            }
+        }
+        if let Some(angle) = image.irot_angle {
+            image_data.push((1, "irot (Rotation)", format!("{angle}")));
+        }
+        if let Some(axis) = image.imir_axis {
+            image_data.push((1, "imir (Mirror)", format!("{axis}")));
+        }
+    }
+    image_data.push((0, "Progressive", format!("{:#?}", image.progressive_state)));
+    if let Some(clli) = image.clli {
+        image_data.push((0, "CLLI", format!("{}, {}", clli.max_cll, clli.max_pall)));
+    }
+    if decoder.gainmap_present() {
+        let gainmap = decoder.gainmap();
+        let gainmap_image = &gainmap.image;
+        image_data.extend_from_slice(&[
+            (
+                0,
+                "Gainmap",
+                format!(
+                "{}x{} pixels, {} bit, {:#?}, {:#?} Range, Matrix Coeffs. {:#?}, Base Image is {}",
+                gainmap_image.width,
+                gainmap_image.height,
+                gainmap_image.depth,
+                gainmap_image.yuv_format,
+                gainmap_image.yuv_range,
+                gainmap_image.matrix_coefficients,
+                if gainmap.metadata.base_hdr_headroom.0 == 0 { "SDR" } else { "HDR" },
+            ),
+            ),
+            (0, "Alternate image", format!("")),
+            (
+                1,
+                "Color Primaries",
+                format!("{:#?}", gainmap.alt_color_primaries),
+            ),
+            (
+                1,
+                "Transfer Characteristics",
+                format!("{:#?}", gainmap.alt_transfer_characteristics),
+            ),
+            (
+                1,
+                "Matrix Coefficients",
+                format!("{:#?}", gainmap.alt_matrix_coefficients),
+            ),
+            (1, "ICC Profile", print_vec(&gainmap.alt_icc)),
+            (1, "Bit Depth", format!("{}", gainmap.alt_plane_depth)),
+            (1, "Planes", format!("{}", gainmap.alt_plane_count)),
+            if let Some(clli) = gainmap_image.clli {
+                (1, "CLLI", format!("{}, {}", clli.max_cll, clli.max_pall))
+            } else {
+                (1, "", "".into())
+            },
+        ])
+    } else {
+        // TODO: b/394162563 - check if we need to report the present but ignored case.
+        image_data.push((0, "Gainmap", format!("Absent")));
+    }
+    if image.image_sequence_track_present {
+        image_data.push((
+            0,
+            "Repeat Count",
+            match decoder.repetition_count() {
+                RepetitionCount::Finite(x) => format!("{x}"),
+                RepetitionCount::Infinite => format!("Infinite"),
+                RepetitionCount::Unknown => format!("Unknown"),
+            },
+        ));
+    }
+    print_data_as_columns(&image_data);
+}
+
+fn max_threads(jobs: &Option<u32>) -> u32 {
+    match jobs {
+        Some(x) => {
+            if *x == 0 {
+                match std::thread::available_parallelism() {
+                    Ok(value) => value.get() as u32,
+                    Err(_) => 1,
+                }
+            } else {
+                *x
+            }
+        }
+        None => 1,
+    }
+}
+
+fn create_decoder_and_parse(args: &CommandLineArgs) -> AvifResult<Decoder> {
+    let mut settings = Settings {
+        strictness: if args.no_strict { Strictness::None } else { Strictness::All },
+        image_content_to_decode: ImageContentType::All,
+        max_threads: max_threads(&args.jobs),
+        allow_progressive: args.progressive,
+        ignore_exif: args.ignore_exif,
+        ignore_xmp: args.ignore_xmp,
+        ..Settings::default()
+    };
+    // These values cannot be initialized in the list above since we need the default values to be
+    // retain unless they are explicitly specified.
+    if let Some(size_limit) = args.size_limit {
+        settings.image_size_limit = NonZero::new(size_limit);
+    }
+    if let Some(dimension_limit) = args.dimension_limit {
+        settings.image_dimension_limit = NonZero::new(dimension_limit);
+    }
+    let mut decoder = Decoder::default();
+    decoder.settings = settings;
+    decoder
+        .set_io_file(&args.input_file)
+        .or(Err(AvifError::UnknownError(
+            "Cannot open input file".into(),
+        )))?;
+    decoder.parse()?;
+    Ok(decoder)
+}
+
+fn info(args: &CommandLineArgs) -> AvifResult<()> {
+    let mut decoder = create_decoder_and_parse(&args)?;
+    println!("Image decoded: {}", args.input_file);
+    print_image_info(&decoder);
+    println!(
+        " * {} timescales per second, {} seconds ({} timescales), {} frame{}",
+        decoder.timescale(),
+        decoder.duration(),
+        decoder.duration_in_timescales(),
+        decoder.image_count(),
+        if decoder.image_count() == 1 { "" } else { "s" },
+    );
+    if decoder.image_count() > 1 {
+        let image = decoder.image().unwrap();
+        println!(
+            " * {} Frames: ({} expected frames)",
+            if image.image_sequence_track_present {
+                "Image Sequence"
+            } else {
+                "Progressive Image"
+            },
+            decoder.image_count()
+        );
+    } else {
+        println!(" * Frame:");
+    }
+
+    let mut index = 0;
+    loop {
+        match decoder.next_image() {
+            Ok(_) => {
+                println!("     * Decoded frame [{}] [pts {} ({} timescales)] [duration {} ({} timescales)] [{}x{}]",
+                    index,
+                    decoder.image_timing().pts,
+                    decoder.image_timing().pts_in_timescales,
+                    decoder.image_timing().duration,
+                    decoder.image_timing().duration_in_timescales,
+                    decoder.image().unwrap().width,
+                    decoder.image().unwrap().height);
+                index += 1;
+            }
+            Err(AvifError::NoImagesRemaining) => {
+                return Ok(());
+            }
+            Err(err) => {
+                return Err(err);
+            }
+        }
+    }
+}
+
+fn get_extension(filename: &str) -> &str {
+    std::path::Path::new(filename)
+        .extension()
+        .and_then(|s| s.to_str())
+        .unwrap_or("")
+}
+
+fn decode(args: &CommandLineArgs) -> AvifResult<()> {
+    let max_threads = max_threads(&args.jobs);
+    println!(
+        "Decoding with {max_threads} worker thread{}, please wait...",
+        if max_threads == 1 { "" } else { "s" }
+    );
+    let mut decoder = create_decoder_and_parse(&args)?;
+    decoder.nth_image(args.index.unwrap_or(0))?;
+    println!("Image Decoded: {}", args.input_file);
+    println!("Image details:");
+    print_image_info(&decoder);
+
+    let output_filename = &args.output_file.as_ref().unwrap().as_str();
+    let image = decoder.image().unwrap();
+    let extension = get_extension(output_filename);
+    let mut writer: Box<dyn Writer> = match extension {
+        "y4m" | "yuv" => {
+            if !image.icc.is_empty() || !image.exif.is_empty() || !image.xmp.is_empty() {
+                println!("Warning: metadata dropped when saving to {extension}");
+            }
+            Box::new(Y4MWriter::create(extension == "yuv"))
+        }
+        "png" => Box::new(PngWriter { depth: args.depth }),
+        "jpg" | "jpeg" => Box::new(JpegWriter {
+            quality: args.quality,
+        }),
+        _ => {
+            return Err(AvifError::UnknownError(format!(
+                "Unknown output file extension ({extension})"
+            )));
+        }
+    };
+    let mut output_file = File::create(output_filename).or(Err(AvifError::UnknownError(
+        "Could not open output file".into(),
+    )))?;
+    writer.write_frame(&mut output_file, image)?;
+    println!(
+        "Wrote image at index {} to output {}",
+        args.index.unwrap_or(0),
+        output_filename,
+    );
+    Ok(())
+}
+
+fn validate_args(args: &CommandLineArgs) -> AvifResult<()> {
+    if args.info {
+        if args.output_file.is_some()
+            || args.quality.is_some()
+            || args.depth.is_some()
+            || args.index.is_some()
+        {
+            return Err(AvifError::UnknownError(
+                "--info contains unsupported extra arguments".into(),
+            ));
+        }
+    } else {
+        if args.output_file.is_none() {
+            return Err(AvifError::UnknownError("output_file is required".into()));
+        }
+        let output_filename = &args.output_file.as_ref().unwrap().as_str();
+        let extension = get_extension(output_filename);
+        if args.quality.is_some() && extension != "jpg" && extension != "jpeg" {
+            return Err(AvifError::UnknownError(
+                "quality is only supported for jpeg output".into(),
+            ));
+        }
+        if args.depth.is_some() && extension != "png" {
+            return Err(AvifError::UnknownError(
+                "depth is only supported for png output".into(),
+            ));
+        }
+    }
+    Ok(())
+}
+
+fn main() {
+    let args = CommandLineArgs::parse();
+    if let Err(err) = validate_args(&args) {
+        eprintln!("ERROR: {:#?}", err);
+        std::process::exit(1);
+    }
+    let res = if args.info { info(&args) } else { decode(&args) };
+    match res {
+        Ok(_) => std::process::exit(0),
+        Err(err) => {
+            eprintln!("ERROR: {:#?}", err);
+            std::process::exit(1);
+        }
+    }
+}
diff --git a/examples/dec.rs b/examples/dec.rs
deleted file mode 100644
index 5c8f7da..0000000
--- a/examples/dec.rs
+++ /dev/null
@@ -1,135 +0,0 @@
-// Copyright 2024 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-use std::env;
-use std::process::Command;
-
-use crabby_avif::decoder::*;
-
-fn main() {
-    // let data: [u8; 32] = [
-    //     0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x66, 0x00, 0x00, 0x00,
-    //     0x00, 0x61, 0x76, 0x69, 0x66, 0x6d, 0x69, 0x66, 0x31, 0x6d, 0x69, 0x61, 0x66, 0x4d, 0x41,
-    //     0x31, 0x41,
-    // ];
-    // let data: [u8; 32] = [
-    //     0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x67, 0x00, 0x00, 0x00,
-    //     0x00, 0x61, 0x76, 0x69, 0x68, 0x6d, 0x69, 0x66, 0x31, 0x6d, 0x69, 0x61, 0x66, 0x4d, 0x41,
-    //     0x31, 0x41,
-    // ];
-    // let val = Decoder::peek_compatible_file_type(&data);
-    // println!("val: {val}");
-    // return;
-
-    let args: Vec<String> = env::args().collect();
-
-    if args.len() < 3 {
-        println!("Usage: {} <input_avif> <output> [--no-png]", args[0]);
-        std::process::exit(1);
-    }
-    let image_count;
-    {
-        let settings = Settings {
-            strictness: Strictness::None,
-            image_content_to_decode: ImageContentType::All,
-            allow_progressive: true,
-            ..Settings::default()
-        };
-        let mut decoder: Decoder = Default::default();
-        decoder.settings = settings;
-        match decoder.set_io_file(&args[1]) {
-            Ok(_) => {}
-            Err(err) => {
-                println!("failed to set file io: {:#?}", err);
-                std::process::exit(1);
-            }
-        };
-        let res = decoder.parse();
-        if res.is_err() {
-            println!("parse failed! {:#?}", res);
-            std::process::exit(1);
-        }
-        let _image = decoder.image();
-
-        println!("\n^^^ decoder public properties ^^^");
-        println!("image_count: {}", decoder.image_count());
-        println!("timescale: {}", decoder.timescale());
-        println!(
-            "duration_in_timescales: {}",
-            decoder.duration_in_timescales()
-        );
-        println!("duration: {}", decoder.duration());
-        println!("repetition_count: {:#?}", decoder.repetition_count());
-        println!("$$$ end decoder public properties $$$\n");
-
-        image_count = decoder.image_count();
-        //image_count = 1;
-        let mut writer: crabby_avif::utils::y4m::Y4MWriter = Default::default();
-        //let mut writer: crabby_avif::utils::raw::RawWriter = Default::default();
-        writer.filename = Some(args[2].clone());
-        //writer.rgb = true;
-
-        for _i in 0..image_count {
-            let res = decoder.nth_image(0);
-            if res.is_err() {
-                println!("next_image failed! {:#?}", res);
-                std::process::exit(1);
-            }
-            let image = decoder.image().expect("image was none");
-            let ret = writer.write_frame(image);
-            if !ret {
-                println!("error writing y4m file");
-                std::process::exit(1);
-            }
-            println!("timing: {:#?}", decoder.image_timing());
-        }
-        println!("wrote {} frames into {}", image_count, args[2]);
-    }
-    if args.len() == 3 {
-        if image_count <= 1 {
-            let ffmpeg_infile = args[2].to_string();
-            let ffmpeg_outfile = format!("{}.png", args[2]);
-            let ffmpeg = Command::new("ffmpeg")
-                .arg("-i")
-                .arg(ffmpeg_infile)
-                .arg("-frames:v")
-                .arg("1")
-                .arg("-y")
-                .arg(ffmpeg_outfile)
-                .output()
-                .unwrap();
-            if !ffmpeg.status.success() {
-                println!("ffmpeg to convert to png failed");
-                std::process::exit(1);
-            }
-            println!("wrote {}.png", args[2]);
-        } else {
-            let ffmpeg_infile = args[2].to_string();
-            let ffmpeg_outfile = format!("{}.gif", args[2]);
-            let ffmpeg = Command::new("ffmpeg")
-                .arg("-i")
-                .arg(ffmpeg_infile)
-                .arg("-y")
-                .arg(ffmpeg_outfile)
-                .output()
-                .unwrap();
-            if !ffmpeg.status.success() {
-                println!("ffmpeg to convert to gif failed");
-                std::process::exit(1);
-            }
-            println!("wrote {}.gif", args[2]);
-        }
-    }
-    std::process::exit(0);
-}
diff --git a/examples/writer/jpeg.rs b/examples/writer/jpeg.rs
new file mode 100644
index 0000000..9d3fcae
--- /dev/null
+++ b/examples/writer/jpeg.rs
@@ -0,0 +1,50 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+use crabby_avif::image::*;
+use crabby_avif::reformat::rgb;
+use crabby_avif::AvifError;
+use crabby_avif::AvifResult;
+
+use super::Writer;
+
+use image::codecs::jpeg;
+use std::fs::File;
+
+#[derive(Default)]
+pub(crate) struct JpegWriter {
+    pub quality: Option<u8>,
+}
+
+impl Writer for JpegWriter {
+    fn write_frame(&mut self, file: &mut File, image: &Image) -> AvifResult<()> {
+        let mut rgb = rgb::Image::create_from_yuv(image);
+        rgb.depth = 8;
+        rgb.format = rgb::Format::Rgb;
+        rgb.allocate()?;
+        rgb.convert_from_yuv(image)?;
+
+        let rgba_pixels = rgb.pixels.as_ref().unwrap();
+        let mut encoder = jpeg::JpegEncoder::new_with_quality(file, self.quality.unwrap_or(90));
+        encoder
+            .encode(
+                rgba_pixels.slice(0, rgba_pixels.size() as u32)?,
+                image.width,
+                image.height,
+                image::ColorType::Rgb8,
+            )
+            .or(Err(AvifError::UnknownError("Jpeg encoding failed".into())))?;
+        Ok(())
+    }
+}
diff --git a/examples/writer/mod.rs b/examples/writer/mod.rs
new file mode 100644
index 0000000..cb081e4
--- /dev/null
+++ b/examples/writer/mod.rs
@@ -0,0 +1,29 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+// Not all sub-modules are used by all targets. Ignore dead code warnings.
+#![allow(dead_code)]
+
+pub(crate) mod jpeg;
+pub(crate) mod png;
+pub(crate) mod y4m;
+
+use crabby_avif::image::Image;
+use crabby_avif::AvifResult;
+
+use std::fs::File;
+
+pub trait Writer {
+    fn write_frame(&mut self, file: &mut File, image: &Image) -> AvifResult<()>;
+}
diff --git a/examples/writer/png.rs b/examples/writer/png.rs
new file mode 100644
index 0000000..87c3bd6
--- /dev/null
+++ b/examples/writer/png.rs
@@ -0,0 +1,127 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+use crabby_avif::image::*;
+use crabby_avif::reformat::rgb;
+use crabby_avif::AvifError;
+use crabby_avif::AvifResult;
+use crabby_avif::PixelFormat;
+
+use std::fs::File;
+
+use super::Writer;
+
+use png;
+
+#[derive(Default)]
+pub(crate) struct PngWriter {
+    pub depth: Option<u8>,
+}
+
+fn scale_to_8bit(pixel: u16, max_channel: u16) -> u8 {
+    (pixel as u32 * 255 / max_channel as u32) as u8
+}
+
+fn scale_to_16bit(pixel: u16, max_channel: u16) -> u16 {
+    ((pixel as u32 * 65535) / max_channel as u32) as u16
+}
+
+impl Writer for PngWriter {
+    fn write_frame(&mut self, file: &mut File, image: &Image) -> AvifResult<()> {
+        let is_monochrome = image.yuv_format == PixelFormat::Yuv400;
+        let png_color_type = match (is_monochrome, image.alpha_present) {
+            (true, _) => png::ColorType::Grayscale,
+            (_, false) => png::ColorType::Rgb,
+            (_, true) => png::ColorType::Rgba,
+        };
+        let depth = self.depth.unwrap_or(if image.depth == 8 { 8 } else { 16 });
+        let mut rgb = rgb::Image::create_from_yuv(image);
+        if !is_monochrome {
+            rgb.depth = depth;
+            rgb.format = if image.alpha_present { rgb::Format::Rgba } else { rgb::Format::Rgb };
+            rgb.allocate()?;
+            rgb.convert_from_yuv(image)?;
+        }
+
+        let mut encoder = png::Encoder::new(file, image.width, image.height);
+        encoder.set_color(png_color_type);
+        encoder.set_depth(if depth == 8 { png::BitDepth::Eight } else { png::BitDepth::Sixteen });
+        if !image.xmp.is_empty() {
+            if let Ok(text) = String::from_utf8(image.xmp.clone()) {
+                if encoder
+                    .add_itxt_chunk("XML:com.adobe.xmp".to_string(), text)
+                    .is_err()
+                {
+                    eprintln!("Warning: Ignoring XMP data");
+                }
+            } else {
+                eprintln!("Warning: Ignoring XMP data because it is not a valid UTF-8 string");
+            }
+        }
+        let mut writer = encoder.write_header().or(Err(AvifError::UnknownError(
+            "Could not write the PNG header".into(),
+        )))?;
+        let mut rgba_pixel_buffer: Vec<u8> = Vec::new();
+        let rgba_slice = if is_monochrome {
+            for y in 0..image.height {
+                match (image.depth == 8, depth == 8) {
+                    (true, true) => {
+                        let y_row = image.row(Plane::Y, y)?;
+                        rgba_pixel_buffer.extend_from_slice(&y_row[..image.width as usize]);
+                    }
+                    (false, false) => {
+                        let y_row = image.row16(Plane::Y, y)?;
+                        for pixel in &y_row[..image.width as usize] {
+                            let pixel16 = scale_to_16bit(*pixel, image.max_channel());
+                            rgba_pixel_buffer.extend_from_slice(&pixel16.to_be_bytes());
+                        }
+                    }
+                    (true, false) => {
+                        let y_row = image.row(Plane::Y, y)?;
+                        for pixel in &y_row[..image.width as usize] {
+                            let pixel16 = scale_to_16bit(*pixel as u16, image.max_channel());
+                            rgba_pixel_buffer.extend_from_slice(&pixel16.to_be_bytes());
+                        }
+                    }
+                    (false, true) => {
+                        let y_row = image.row16(Plane::Y, y)?;
+                        for pixel in &y_row[..image.width as usize] {
+                            rgba_pixel_buffer.push(scale_to_8bit(*pixel, image.max_channel()));
+                        }
+                    }
+                }
+            }
+            &rgba_pixel_buffer[..]
+        } else if depth == 8 {
+            let rgba_pixels = rgb.pixels.as_ref().unwrap();
+            rgba_pixels.slice(0, rgba_pixels.size() as u32)?
+        } else {
+            let rgba_pixels = rgb.pixels.as_ref().unwrap();
+            let rgba_slice16 = rgba_pixels.slice16(0, rgba_pixels.size() as u32).unwrap();
+            for pixel in rgba_slice16 {
+                rgba_pixel_buffer.extend_from_slice(&pixel.to_be_bytes());
+            }
+            &rgba_pixel_buffer[..]
+        };
+        writer
+            .write_image_data(rgba_slice)
+            .or(Err(AvifError::UnknownError(
+                "Could not write PNG image data".into(),
+            )))?;
+        writer.finish().or(Err(AvifError::UnknownError(
+            "Could not finalize the PNG encoder".into(),
+        )))?;
+        Ok(())
+    }
+}
diff --git a/src/utils/y4m.rs b/examples/writer/y4m.rs
similarity index 68%
rename from src/utils/y4m.rs
rename to examples/writer/y4m.rs
index 7f91c73..e45bfc6 100644
--- a/src/utils/y4m.rs
+++ b/examples/writer/y4m.rs
@@ -12,37 +12,34 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+#[allow(unused_imports)]
 use crate::image::*;
 use crate::*;
+
 use std::fs::File;
 use std::io::prelude::*;
 
+use super::Writer;
+
 #[derive(Default)]
-pub struct Y4MWriter {
-    pub filename: Option<String>,
+pub(crate) struct Y4MWriter {
     header_written: bool,
-    file: Option<File>,
     write_alpha: bool,
+    skip_headers: bool,
 }
 
 impl Y4MWriter {
-    pub fn create(filename: &str) -> Self {
-        Self {
-            filename: Some(filename.to_owned()),
-            ..Self::default()
-        }
-    }
-
-    pub fn create_from_file(file: File) -> Self {
+    #[allow(unused)]
+    pub(crate) fn create(skip_headers: bool) -> Self {
         Self {
-            file: Some(file),
-            ..Self::default()
+            skip_headers,
+            ..Default::default()
         }
     }
 
-    fn write_header(&mut self, image: &Image) -> bool {
+    fn write_header(&mut self, file: &mut File, image: &Image) -> AvifResult<()> {
         if self.header_written {
-            return true;
+            return Ok(());
         }
         self.write_alpha = false;
 
@@ -89,7 +86,7 @@ impl Y4MWriter {
                 PixelFormat::Yuv400 => "Cmono12 XYSCSS=400",
             },
             _ => {
-                return false;
+                return Err(AvifError::NotImplemented);
             }
         };
         let y4m_color_range = if image.yuv_range == YuvRange::Limited {
@@ -101,33 +98,20 @@ impl Y4MWriter {
             "YUV4MPEG2 W{} H{} F25:1 Ip A0:0 {y4m_format} {y4m_color_range}\n",
             image.width, image.height
         );
-        if self.file.is_none() {
-            assert!(self.filename.is_some());
-            let file = File::create(self.filename.unwrap_ref());
-            if file.is_err() {
-                return false;
-            }
-            self.file = Some(file.unwrap());
-        }
-        if self.file.unwrap_ref().write_all(header.as_bytes()).is_err() {
-            return false;
-        }
+        file.write_all(header.as_bytes())
+            .or(Err(AvifError::IoError))?;
         self.header_written = true;
-        true
+        Ok(())
     }
+}
 
-    pub fn write_frame(&mut self, image: &Image) -> bool {
-        if !self.write_header(image) {
-            return false;
-        }
-        let frame_marker = "FRAME\n";
-        if self
-            .file
-            .unwrap_ref()
-            .write_all(frame_marker.as_bytes())
-            .is_err()
-        {
-            return false;
+impl Writer for Y4MWriter {
+    fn write_frame(&mut self, file: &mut File, image: &Image) -> AvifResult<()> {
+        if !self.skip_headers {
+            self.write_header(file, image)?;
+            let frame_marker = "FRAME\n";
+            file.write_all(frame_marker.as_bytes())
+                .or(Err(AvifError::IoError))?;
         }
         let planes: &[Plane] = if self.write_alpha { &ALL_PLANES } else { &YUV_PLANES };
         for plane in planes {
@@ -137,35 +121,23 @@ impl Y4MWriter {
             }
             if image.depth == 8 {
                 for y in 0..image.height(plane) {
-                    let row = if let Ok(row) = image.row(plane, y as u32) {
-                        row
-                    } else {
-                        return false;
-                    };
+                    let row = image.row(plane, y as u32)?;
                     let pixels = &row[..image.width(plane)];
-                    if self.file.unwrap_ref().write_all(pixels).is_err() {
-                        return false;
-                    }
+                    file.write_all(pixels).or(Err(AvifError::IoError))?;
                 }
             } else {
                 for y in 0..image.height(plane) {
-                    let row16 = if let Ok(row16) = image.row16(plane, y as u32) {
-                        row16
-                    } else {
-                        return false;
-                    };
+                    let row16 = image.row16(plane, y as u32)?;
                     let pixels16 = &row16[..image.width(plane)];
                     let mut pixels: Vec<u8> = Vec::new();
                     // y4m is always little endian.
                     for &pixel16 in pixels16 {
                         pixels.extend_from_slice(&pixel16.to_le_bytes());
                     }
-                    if self.file.unwrap_ref().write_all(&pixels[..]).is_err() {
-                        return false;
-                    }
+                    file.write_all(&pixels[..]).or(Err(AvifError::IoError))?;
                 }
             }
         }
-        true
+        Ok(())
     }
 }
diff --git a/include/avif/avif.h b/include/avif/avif.h
index 68237dd..1ae166c 100644
--- a/include/avif/avif.h
+++ b/include/avif/avif.h
@@ -18,14 +18,14 @@ struct avifIO;
 
 namespace crabbyavif {
 
+constexpr static const size_t CRABBY_AVIF_MAX_AV1_LAYER_COUNT = 4;
+
 constexpr static const uint32_t CRABBY_AVIF_DEFAULT_IMAGE_SIZE_LIMIT = (16384 * 16384);
 
 constexpr static const uint32_t CRABBY_AVIF_DEFAULT_IMAGE_DIMENSION_LIMIT = 32768;
 
 constexpr static const uint32_t CRABBY_AVIF_DEFAULT_IMAGE_COUNT_LIMIT = ((12 * 3600) * 60);
 
-constexpr static const size_t CRABBY_AVIF_MAX_AV1_LAYER_COUNT = 4;
-
 constexpr static const int CRABBY_AVIF_TRUE = 1;
 
 constexpr static const int CRABBY_AVIF_FALSE = 0;
diff --git a/src/capi/decoder.rs b/src/capi/decoder.rs
index 114539d..7cdf945 100644
--- a/src/capi/decoder.rs
+++ b/src/capi/decoder.rs
@@ -18,6 +18,7 @@ use super::io::*;
 use super::types::*;
 
 use std::ffi::CStr;
+use std::num::NonZero;
 use std::os::raw::c_char;
 
 use crate::decoder::track::*;
@@ -192,9 +193,9 @@ impl From<&avifDecoder> for Settings {
                 // Silently treat all other choices the same as Auto.
                 _ => CodecChoice::Auto,
             },
-            image_size_limit: decoder.imageSizeLimit,
-            image_dimension_limit: decoder.imageDimensionLimit,
-            image_count_limit: decoder.imageCountLimit,
+            image_size_limit: NonZero::new(decoder.imageSizeLimit),
+            image_dimension_limit: NonZero::new(decoder.imageDimensionLimit),
+            image_count_limit: NonZero::new(decoder.imageCountLimit),
             max_threads: u32::try_from(decoder.maxThreads).unwrap_or(0),
             android_mediacodec_output_color_format: decoder.androidMediaCodecOutputColorFormat,
         }
diff --git a/src/capi/gainmap.rs b/src/capi/gainmap.rs
index 098361b..9b9d1d0 100644
--- a/src/capi/gainmap.rs
+++ b/src/capi/gainmap.rs
@@ -18,8 +18,7 @@ use super::types::*;
 
 use crate::decoder::gainmap::*;
 use crate::image::YuvRange;
-use crate::internal_utils::*;
-use crate::parser::mp4box::*;
+use crate::utils::*;
 use crate::*;
 
 pub type avifContentLightLevelInformationBox = ContentLightLevelInformation;
diff --git a/src/capi/image.rs b/src/capi/image.rs
index 67b2ccc..c3df7b3 100644
--- a/src/capi/image.rs
+++ b/src/capi/image.rs
@@ -18,8 +18,8 @@ use super::types::*;
 
 use crate::image::*;
 use crate::internal_utils::*;
-use crate::parser::mp4box::*;
 use crate::utils::clap::*;
+use crate::utils::*;
 use crate::*;
 
 use std::os::raw::c_int;
@@ -240,6 +240,34 @@ pub unsafe extern "C" fn crabby_avifImageCreate(
     }))
 }
 
+macro_rules! usize_from_u32_or_fail {
+    ($param: expr) => {
+        match usize_from_u32($param) {
+            Ok(value) => value,
+            Err(_) => return avifResult::UnknownError,
+        }
+    };
+}
+
+fn copy_plane_helper(
+    mut src_plane_ptr: *const u8,
+    src_row_bytes: u32,
+    mut dst_plane_ptr: *mut u8,
+    dst_row_bytes: u32,
+    mut width: usize,
+    height: usize,
+    pixel_size: usize,
+) {
+    width *= pixel_size;
+    for _ in 0..height {
+        unsafe {
+            std::ptr::copy_nonoverlapping(src_plane_ptr, dst_plane_ptr, width);
+            src_plane_ptr = src_plane_ptr.offset(src_row_bytes as isize);
+            dst_plane_ptr = dst_plane_ptr.offset(dst_row_bytes as isize);
+        }
+    }
+}
+
 #[no_mangle]
 #[allow(unused)]
 pub unsafe extern "C" fn crabby_avifImageCopy(
@@ -280,38 +308,52 @@ pub unsafe extern "C" fn crabby_avifImageCopy(
     if res != avifResult::Ok {
         return res;
     }
+    let pixel_size: usize = if src.depth > 8 { 2 } else { 1 };
     if (planes & 1) != 0 {
         for plane in 0usize..3 {
             if src.yuvPlanes[plane].is_null() || src.yuvRowBytes[plane] == 0 {
                 continue;
             }
-            let plane_height = unsafe { crabby_avifImagePlaneHeight(srcImage, plane as i32) };
-            let plane_size = match usize_from_u32(src.yuvRowBytes[plane] * plane_height) {
-                Ok(size) => size,
-                Err(_) => return avifResult::UnknownError,
-            };
+            let plane_height = usize_from_u32_or_fail!(unsafe {
+                crabby_avifImagePlaneHeight(srcImage, plane as i32)
+            });
+            let plane_width = usize_from_u32_or_fail!(unsafe {
+                crabby_avifImagePlaneWidth(srcImage, plane as i32)
+            });
+            let alloc_plane_height = round2_usize(plane_height);
+            let alloc_plane_width = round2_usize(plane_width);
+            let plane_size = alloc_plane_width * alloc_plane_height * pixel_size;
             dst.yuvPlanes[plane] = unsafe { crabby_avifAlloc(plane_size) } as *mut _;
-            unsafe {
-                std::ptr::copy_nonoverlapping(
-                    src.yuvPlanes[plane],
-                    dst.yuvPlanes[plane],
-                    plane_size,
-                );
-            }
-            dst.yuvRowBytes[plane] = src.yuvRowBytes[plane];
+            dst.yuvRowBytes[plane] = (pixel_size * alloc_plane_width) as u32;
+            copy_plane_helper(
+                src.yuvPlanes[plane],
+                src.yuvRowBytes[plane],
+                dst.yuvPlanes[plane],
+                dst.yuvRowBytes[plane],
+                plane_width,
+                plane_height,
+                pixel_size,
+            );
             dst.imageOwnsYUVPlanes = AVIF_TRUE;
         }
     }
     if (planes & 2) != 0 && !src.alphaPlane.is_null() && src.alphaRowBytes != 0 {
-        let plane_size = match usize_from_u32(src.alphaRowBytes * src.height) {
-            Ok(size) => size,
-            Err(_) => return avifResult::UnknownError,
-        };
+        let plane_height = usize_from_u32_or_fail!(src.height);
+        let plane_width = usize_from_u32_or_fail!(src.width);
+        let alloc_plane_height = round2_usize(plane_height);
+        let alloc_plane_width = round2_usize(plane_width);
+        let plane_size = alloc_plane_width * alloc_plane_height * pixel_size;
         dst.alphaPlane = unsafe { crabby_avifAlloc(plane_size) } as *mut _;
-        unsafe {
-            std::ptr::copy_nonoverlapping(src.alphaPlane, dst.alphaPlane, plane_size);
-        }
-        dst.alphaRowBytes = src.alphaRowBytes;
+        dst.alphaRowBytes = (pixel_size * alloc_plane_width) as u32;
+        copy_plane_helper(
+            src.alphaPlane,
+            src.alphaRowBytes,
+            dst.alphaPlane,
+            dst.alphaRowBytes,
+            plane_width,
+            plane_height,
+            pixel_size,
+        );
         dst.imageOwnsAlphaPlane = AVIF_TRUE;
     }
     avifResult::Ok
@@ -325,9 +367,11 @@ fn avif_image_allocate_planes_helper(
         return Err(AvifError::InvalidArgument);
     }
     let channel_size = if image.depth == 8 { 1 } else { 2 };
-    let y_row_bytes = usize_from_u32(image.width * channel_size)?;
+    let alloc_width = round2_u32(image.width);
+    let y_row_bytes = usize_from_u32(alloc_width * channel_size)?;
+    let alloc_height = round2_u32(image.height);
     let y_size = y_row_bytes
-        .checked_mul(usize_from_u32(image.height)?)
+        .checked_mul(usize_from_u32(alloc_height)?)
         .ok_or(avifResult::InvalidArgument)?;
     if (planes & 1) != 0 && image.yuvFormat != PixelFormat::None {
         image.imageOwnsYUVPlanes = AVIF_TRUE;
@@ -339,11 +383,17 @@ fn avif_image_allocate_planes_helper(
             let csx0 = image.yuvFormat.chroma_shift_x().0 as u64;
             let csx1 = image.yuvFormat.chroma_shift_x().1 as u64;
             let width = (((image.width as u64) + csx0) >> csx0) << csx1;
+            let alloc_width = round2_u32(u32_from_u64(width)?);
             let csy = image.yuvFormat.chroma_shift_y() as u64;
             let height = ((image.height as u64) + csy) >> csy;
-            let uv_row_bytes = usize_from_u64(width * channel_size as u64)?;
-            let uv_size = usize_from_u64(uv_row_bytes as u64 * height)?;
-            for plane in 1usize..=2 {
+            let alloc_height = round2_u32(u32_from_u64(height)?);
+            let uv_row_bytes = usize_from_u32(alloc_width * channel_size)?;
+            let uv_size = usize_from_u32(uv_row_bytes as u32 * alloc_height)?;
+            let plane_end = match image.yuvFormat {
+                PixelFormat::AndroidP010 | PixelFormat::AndroidNv12 | PixelFormat::AndroidNv21 => 1,
+                _ => 2,
+            };
+            for plane in 1usize..=plane_end {
                 if !image.yuvPlanes[plane].is_null() {
                     continue;
                 }
@@ -462,14 +512,23 @@ pub unsafe extern "C" fn crabby_avifImagePlaneWidth(
     unsafe {
         match channel {
             0 => (*image).width,
-            1 | 2 => {
-                if (*image).yuvFormat.is_monochrome() {
-                    0
-                } else {
-                    let shift_x = (*image).yuvFormat.chroma_shift_x();
-                    (((*image).width + shift_x.0) >> shift_x.0) << shift_x.1
-                }
-            }
+            1 => match (*image).yuvFormat {
+                PixelFormat::Yuv444
+                | PixelFormat::AndroidP010
+                | PixelFormat::AndroidNv12
+                | PixelFormat::AndroidNv21 => (*image).width,
+                PixelFormat::Yuv420 | PixelFormat::Yuv422 => ((*image).width).div_ceil(2),
+                PixelFormat::None | PixelFormat::Yuv400 => 0,
+            },
+            2 => match (*image).yuvFormat {
+                PixelFormat::Yuv444 => (*image).width,
+                PixelFormat::Yuv420 | PixelFormat::Yuv422 => ((*image).width).div_ceil(2),
+                PixelFormat::None
+                | PixelFormat::Yuv400
+                | PixelFormat::AndroidP010
+                | PixelFormat::AndroidNv12
+                | PixelFormat::AndroidNv21 => 0,
+            },
             3 => {
                 if !(*image).alphaPlane.is_null() {
                     (*image).width
diff --git a/src/capi/io.rs b/src/capi/io.rs
index 180ce45..45b2bfd 100644
--- a/src/capi/io.rs
+++ b/src/capi/io.rs
@@ -164,6 +164,7 @@ impl avifIOWrapper {
 }
 
 impl crate::decoder::IO for avifIOWrapper {
+    #[cfg_attr(feature = "disable_cfi", no_sanitize(cfi))]
     fn read(&mut self, offset: u64, size: usize) -> AvifResult<&[u8]> {
         let res = unsafe {
             (self.io.read)(
diff --git a/src/capi/reformat.rs b/src/capi/reformat.rs
index 916e23d..b78b79e 100644
--- a/src/capi/reformat.rs
+++ b/src/capi/reformat.rs
@@ -15,7 +15,6 @@
 use super::image::*;
 use super::types::*;
 
-use crate::decoder::Category;
 use crate::image::*;
 use crate::internal_utils::pixels::*;
 use crate::internal_utils::*;
@@ -194,14 +193,23 @@ fn CopyPlanes(dst: &mut avifImage, src: &Image) -> AvifResult<()> {
                 let src_slice = &src.row(plane, y).unwrap()[..plane_data.width as usize];
                 let dst_slice = unsafe {
                     std::slice::from_raw_parts_mut(
-                        dst_planes[plane.to_usize()]
-                            .offset(isize_from_u32(y * dst_row_bytes[plane.to_usize()])?),
+                        dst_planes[plane.as_usize()]
+                            .offset(isize_from_u32(y * dst_row_bytes[plane.as_usize()])?),
                         usize_from_u32(plane_data.width)?,
                     )
                 };
                 dst_slice.copy_from_slice(src_slice);
             }
         } else {
+            // When scaling a P010 image, the scaling code converts the image into Yuv420 with
+            // an explicit V plane. So if the V plane is missing in |dst|, we will have to allocate
+            // it here. It is safe to do so since it will be free'd with the other plane buffers
+            // when the image object is destroyed.
+            if plane == Plane::V && dst.yuvPlanes[2].is_null() {
+                let plane_size = usize_from_u32(plane_data.width * plane_data.height * 2)?;
+                dst.yuvPlanes[2] = unsafe { crabby_avifAlloc(plane_size) } as *mut _;
+                dst.yuvRowBytes[2] = plane_data.width * 2;
+            }
             let dst_planes = [
                 dst.yuvPlanes[0] as *mut u16,
                 dst.yuvPlanes[1] as *mut u16,
@@ -218,8 +226,8 @@ fn CopyPlanes(dst: &mut avifImage, src: &Image) -> AvifResult<()> {
                 let src_slice = &src.row16(plane, y).unwrap()[..plane_data.width as usize];
                 let dst_slice = unsafe {
                     std::slice::from_raw_parts_mut(
-                        dst_planes[plane.to_usize()]
-                            .offset(isize_from_u32(y * dst_row_bytes[plane.to_usize()])?),
+                        dst_planes[plane.as_usize()]
+                            .offset(isize_from_u32(y * dst_row_bytes[plane.as_usize()])?),
                         usize_from_u32(plane_data.width)?,
                     )
                 };
@@ -260,5 +268,7 @@ pub unsafe extern "C" fn crabby_avifImageScale(
 
     dst_image.width = rust_image.width;
     dst_image.height = rust_image.height;
+    dst_image.depth = rust_image.depth as _;
+    dst_image.yuvFormat = rust_image.yuv_format;
     to_avifResult(&CopyPlanes(dst_image, &rust_image))
 }
diff --git a/src/capi/types.rs b/src/capi/types.rs
index 5a9f81f..658786c 100644
--- a/src/capi/types.rs
+++ b/src/capi/types.rs
@@ -137,7 +137,7 @@ impl From<avifResult> for AvifError {
 }
 
 impl avifResult {
-    pub fn to_usize(&self) -> usize {
+    pub(crate) fn as_usize(&self) -> usize {
         match self {
             Self::Ok => 0,
             Self::UnknownError => 1,
@@ -188,7 +188,7 @@ pub const AVIF_STRICT_ENABLED: u32 =
 pub type avifStrictFlags = u32;
 
 pub const AVIF_IMAGE_CONTENT_NONE: u32 = 0;
-pub const AVIF_IMAGE_CONTENT_COLOR_AND_ALPHA: u32 = 1 << 0 | 1 << 1;
+pub const AVIF_IMAGE_CONTENT_COLOR_AND_ALPHA: u32 = (1 << 0) | (1 << 1);
 pub const AVIF_IMAGE_CONTENT_GAIN_MAP: u32 = 1 << 2;
 pub const AVIF_IMAGE_CONTENT_ALL: u32 =
     AVIF_IMAGE_CONTENT_COLOR_AND_ALPHA | AVIF_IMAGE_CONTENT_GAIN_MAP;
@@ -212,7 +212,7 @@ impl Default for avifDiagnostics {
 }
 
 impl avifDiagnostics {
-    pub fn set_from_result<T>(&mut self, res: &AvifResult<T>) {
+    pub(crate) fn set_from_result<T>(&mut self, res: &AvifResult<T>) {
         match res {
             Ok(_) => self.set_error_empty(),
             Err(AvifError::BmffParseFailed(s))
@@ -241,7 +241,7 @@ impl avifDiagnostics {
         }
     }
 
-    pub fn set_error_empty(&mut self) {
+    pub(crate) fn set_error_empty(&mut self) {
         self.error[0] = 0;
     }
 }
@@ -257,7 +257,7 @@ pub enum avifCodecChoice {
     Avm = 6,
 }
 
-pub fn to_avifBool(val: bool) -> avifBool {
+pub(crate) fn to_avifBool(val: bool) -> avifBool {
     if val {
         AVIF_TRUE
     } else {
@@ -265,7 +265,7 @@ pub fn to_avifBool(val: bool) -> avifBool {
     }
 }
 
-pub fn to_avifResult<T>(res: &AvifResult<T>) -> avifResult {
+pub(crate) fn to_avifResult<T>(res: &AvifResult<T>) -> avifResult {
     match res {
         Ok(_) => avifResult::Ok,
         Err(err) => {
@@ -313,7 +313,7 @@ const RESULT_TO_STRING: &[&str] = &[
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifResultToString(res: avifResult) -> *const c_char {
     unsafe {
-        std::ffi::CStr::from_bytes_with_nul_unchecked(RESULT_TO_STRING[res.to_usize()].as_bytes())
+        std::ffi::CStr::from_bytes_with_nul_unchecked(RESULT_TO_STRING[res.as_usize()].as_bytes())
             .as_ptr() as *const _
     }
 }
diff --git a/src/codecs/android_mediacodec.rs b/src/codecs/android_mediacodec.rs
index 317b6ae..e79302e 100644
--- a/src/codecs/android_mediacodec.rs
+++ b/src/codecs/android_mediacodec.rs
@@ -14,7 +14,8 @@
 
 use crate::codecs::Decoder;
 use crate::codecs::DecoderConfig;
-use crate::decoder::Category;
+use crate::decoder::CodecChoice;
+use crate::decoder::GridImageHelper;
 use crate::image::Image;
 use crate::image::YuvRange;
 use crate::internal_utils::pixels::*;
@@ -31,6 +32,41 @@ use std::ptr;
 #[cfg(android_soong)]
 include!(concat!(env!("OUT_DIR"), "/mediaimage2_bindgen.rs"));
 
+// This sub-module is used by non-soong Android builds. It contains the bindings necessary to
+// infer the YUV format that comes out of MediaCodec. The C struct source is here:
+// https://cs.android.com/android/platform/superproject/main/+/main:frameworks/native/headers/media_plugin/media/hardware/VideoAPI.h;l=60;drc=a68f3a49e36e043b1640fe85010b0005d1bdb875
+#[allow(non_camel_case_types, non_snake_case, unused)]
+#[cfg(not(android_soong))]
+mod android_soong_placeholder {
+    #[repr(C)]
+    #[derive(Clone, Copy)]
+    pub(crate) struct android_MediaImage2_PlaneInfo {
+        pub mOffset: u32,
+        pub mColInc: i32,
+        pub mRowInc: i32,
+        pub mHorizSubsampling: u32,
+        pub mVertSubsampling: u32,
+    }
+
+    #[derive(Clone, Copy)]
+    #[repr(C)]
+    pub(crate) struct android_MediaImage2 {
+        pub mType: u32,
+        pub mNumPlanes: u32,
+        pub mWidth: u32,
+        pub mHeight: u32,
+        pub mBitDepth: u32,
+        pub mBitDepthAllocated: u32,
+        pub mPlane: [android_MediaImage2_PlaneInfo; 4usize],
+    }
+
+    #[allow(non_upper_case_globals)]
+    pub(crate) const android_MediaImage2_Type_MEDIA_IMAGE_TYPE_YUV: u32 = 1;
+}
+
+#[cfg(not(android_soong))]
+use android_soong_placeholder::*;
+
 #[derive(Debug)]
 struct MediaFormat {
     format: *mut AMediaFormat,
@@ -77,6 +113,19 @@ impl PlaneInfo {
 }
 
 impl MediaFormat {
+    // These constants are documented in
+    // https://developer.android.com/reference/android/media/MediaFormat
+    const COLOR_RANGE_LIMITED: i32 = 2;
+
+    const COLOR_STANDARD_BT709: i32 = 1;
+    const COLOR_STANDARD_BT601_PAL: i32 = 2;
+    const COLOR_STANDARD_BT601_NTSC: i32 = 4;
+    const COLOR_STANDARD_BT2020: i32 = 6;
+
+    const COLOR_TRANSFER_LINEAR: i32 = 1;
+    const COLOR_TRANSFER_SDR_VIDEO: i32 = 3;
+    const COLOR_TRANSFER_HLG: i32 = 7;
+
     fn get_i32(&self, key: *const c_char) -> Option<i32> {
         let mut value: i32 = 0;
         match unsafe { AMediaFormat_getInt32(self.format, key, &mut value as *mut _) } {
@@ -118,14 +167,41 @@ impl MediaFormat {
     fn color_range(&self) -> YuvRange {
         // color-range is documented but isn't exposed as a constant in the NDK:
         // https://developer.android.com/reference/android/media/MediaFormat#KEY_COLOR_RANGE
-        let color_range = self.get_i32_from_str("color-range").unwrap_or(2);
-        if color_range == 0 {
+        let color_range = self
+            .get_i32_from_str("color-range")
+            .unwrap_or(Self::COLOR_RANGE_LIMITED);
+        if color_range == Self::COLOR_RANGE_LIMITED {
             YuvRange::Limited
         } else {
             YuvRange::Full
         }
     }
 
+    fn color_primaries(&self) -> ColorPrimaries {
+        // color-standard is documented but isn't exposed as a constant in the NDK:
+        // https://developer.android.com/reference/android/media/MediaFormat#KEY_COLOR_STANDARD
+        let color_standard = self.get_i32_from_str("color-standard").unwrap_or(-1);
+        match color_standard {
+            Self::COLOR_STANDARD_BT709 => ColorPrimaries::Bt709,
+            Self::COLOR_STANDARD_BT2020 => ColorPrimaries::Bt2020,
+            Self::COLOR_STANDARD_BT601_PAL | Self::COLOR_STANDARD_BT601_NTSC => {
+                ColorPrimaries::Bt601
+            }
+            _ => ColorPrimaries::Unspecified,
+        }
+    }
+
+    fn transfer_characteristics(&self) -> TransferCharacteristics {
+        // color-transfer is documented but isn't exposed as a constant in the NDK:
+        // https://developer.android.com/reference/android/media/MediaFormat#KEY_COLOR_TRANSFER
+        match self.get_i32_from_str("color-transfer").unwrap_or(-1) {
+            Self::COLOR_TRANSFER_LINEAR => TransferCharacteristics::Linear,
+            Self::COLOR_TRANSFER_HLG => TransferCharacteristics::Hlg,
+            Self::COLOR_TRANSFER_SDR_VIDEO => TransferCharacteristics::Bt601,
+            _ => TransferCharacteristics::Unspecified,
+        }
+    }
+
     fn guess_plane_info(&self) -> AvifResult<PlaneInfo> {
         let height = self.height()?;
         let slice_height = self.slice_height().unwrap_or(height);
@@ -169,45 +245,40 @@ impl MediaFormat {
     }
 
     fn get_plane_info(&self) -> AvifResult<PlaneInfo> {
-        // When not building for the Android platform, image-data is not available, so simply try to
-        // guess the buffer format based on the available keys in the format.
-        #[cfg(not(android_soong))]
-        return self.guess_plane_info();
-
-        #[cfg(android_soong)]
-        {
-            c_str!(key_str, key_str_tmp, "image-data");
-            let mut data: *mut std::ffi::c_void = ptr::null_mut();
-            let mut size: usize = 0;
-            if !unsafe {
-                AMediaFormat_getBuffer(
-                    self.format,
-                    key_str,
-                    &mut data as *mut _,
-                    &mut size as *mut _,
-                )
-            } {
-                return self.guess_plane_info();
-            }
-            if size != std::mem::size_of::<android_MediaImage2>() {
-                return self.guess_plane_info();
-            }
-            let image_data = unsafe { *(data as *const android_MediaImage2) };
-            if image_data.mType != android_MediaImage2_Type_MEDIA_IMAGE_TYPE_YUV {
-                return self.guess_plane_info();
-            }
-            let planes = unsafe { ptr::read_unaligned(ptr::addr_of!(image_data.mPlane)) };
-            let mut plane_info = PlaneInfo {
-                color_format: self.color_format()?.into(),
-                ..Default::default()
-            };
-            for plane_index in 0usize..3 {
-                plane_info.offset[plane_index] = isize_from_u32(planes[plane_index].mOffset)?;
-                plane_info.row_stride[plane_index] = u32_from_i32(planes[plane_index].mRowInc)?;
-                plane_info.column_stride[plane_index] = u32_from_i32(planes[plane_index].mColInc)?;
-            }
-            return Ok(plane_info);
+        c_str!(key_str, key_str_tmp, "image-data");
+        let mut data: *mut std::ffi::c_void = ptr::null_mut();
+        let mut size: usize = 0;
+        if !unsafe {
+            AMediaFormat_getBuffer(
+                self.format,
+                key_str,
+                &mut data as *mut _,
+                &mut size as *mut _,
+            )
+        } {
+            return self.guess_plane_info();
+        }
+        if size != std::mem::size_of::<android_MediaImage2>() {
+            return self.guess_plane_info();
         }
+        let image_data = unsafe { *(data as *const android_MediaImage2) };
+        if image_data.mType != android_MediaImage2_Type_MEDIA_IMAGE_TYPE_YUV {
+            return self.guess_plane_info();
+        }
+        let planes = unsafe { ptr::read_unaligned(ptr::addr_of!(image_data.mPlane)) };
+        let mut plane_info = PlaneInfo {
+            color_format: self.color_format()?.into(),
+            ..Default::default()
+        };
+        // Clippy suggests using an iterator with an enumerator which does not seem more readable
+        // than using explicit indices.
+        #[allow(clippy::needless_range_loop)]
+        for plane_index in 0usize..3 {
+            plane_info.offset[plane_index] = isize_from_u32(planes[plane_index].mOffset)?;
+            plane_info.row_stride[plane_index] = u32_from_i32(planes[plane_index].mRowInc)?;
+            plane_info.column_stride[plane_index] = u32_from_i32(planes[plane_index].mColInc)?;
+        }
+        Ok(plane_info)
     }
 }
 
@@ -302,20 +373,23 @@ fn get_codec_initializers(config: &DecoderConfig) -> Vec<CodecInitializer> {
 #[derive(Default)]
 pub struct MediaCodec {
     codec: Option<*mut AMediaCodec>,
+    codec_index: usize,
     format: Option<MediaFormat>,
     output_buffer_index: Option<usize>,
     config: Option<DecoderConfig>,
+    codec_initializers: Vec<CodecInitializer>,
 }
 
 impl MediaCodec {
     const AV1_MIME: &str = "video/av01";
     const HEVC_MIME: &str = "video/hevc";
-}
+    const MAX_RETRIES: u32 = 100;
+    const TIMEOUT: u32 = 10000;
 
-impl Decoder for MediaCodec {
-    fn initialize(&mut self, config: &DecoderConfig) -> AvifResult<()> {
-        if self.codec.is_some() {
-            return Ok(()); // Already initialized.
+    fn initialize_impl(&mut self, low_latency: bool) -> AvifResult<()> {
+        let config = self.config.unwrap_ref();
+        if self.codec_index >= self.codec_initializers.len() {
+            return Err(AvifError::NoCodecAvailable);
         }
         let format = unsafe { AMediaFormat_new() };
         if format.is_null() {
@@ -338,15 +412,19 @@ impl Decoder for MediaCodec {
                 format,
                 AMEDIAFORMAT_KEY_COLOR_FORMAT,
                 if config.depth == 8 {
+                    // For 8-bit images, always use Yuv420Flexible.
                     AndroidMediaCodecOutputColorFormat::Yuv420Flexible
                 } else {
-                    AndroidMediaCodecOutputColorFormat::P010
+                    // For all other images, use whatever format is requested.
+                    config.android_mediacodec_output_color_format
                 } as i32,
             );
-            // low-latency is documented but isn't exposed as a constant in the NDK:
-            // https://developer.android.com/reference/android/media/MediaFormat#KEY_LOW_LATENCY
-            c_str!(low_latency, low_latency_tmp, "low-latency");
-            AMediaFormat_setInt32(format, low_latency, 1);
+            if low_latency {
+                // low-latency is documented but isn't exposed as a constant in the NDK:
+                // https://developer.android.com/reference/android/media/MediaFormat#KEY_LOW_LATENCY
+                c_str!(low_latency_str, low_latency_tmp, "low-latency");
+                AMediaFormat_setInt32(format, low_latency_str, 1);
+            }
             AMediaFormat_setInt32(
                 format,
                 AMEDIAFORMAT_KEY_MAX_INPUT_SIZE,
@@ -363,51 +441,151 @@ impl Decoder for MediaCodec {
             }
         }
 
-        let mut codec = ptr::null_mut();
-        for codec_initializer in get_codec_initializers(config) {
-            codec = match codec_initializer {
-                CodecInitializer::ByName(name) => {
-                    c_str!(codec_name, codec_name_tmp, name.as_str());
-                    unsafe { AMediaCodec_createCodecByName(codec_name) }
-                }
-                CodecInitializer::ByMimeType(mime_type) => {
-                    c_str!(codec_mime, codec_mime_tmp, mime_type.as_str());
-                    unsafe { AMediaCodec_createDecoderByType(codec_mime) }
-                }
-            };
-            if codec.is_null() {
-                continue;
-            }
-            let status = unsafe {
-                AMediaCodec_configure(codec, format, ptr::null_mut(), ptr::null_mut(), 0)
-            };
-            if status != media_status_t_AMEDIA_OK {
-                unsafe {
-                    AMediaCodec_delete(codec);
-                }
-                codec = ptr::null_mut();
-                continue;
+        let codec = match &self.codec_initializers[self.codec_index] {
+            CodecInitializer::ByName(name) => {
+                c_str!(codec_name, codec_name_tmp, name.as_str());
+                unsafe { AMediaCodec_createCodecByName(codec_name) }
             }
-            let status = unsafe { AMediaCodec_start(codec) };
-            if status != media_status_t_AMEDIA_OK {
-                unsafe {
-                    AMediaCodec_delete(codec);
-                }
-                codec = ptr::null_mut();
-                continue;
+            CodecInitializer::ByMimeType(mime_type) => {
+                c_str!(codec_mime, codec_mime_tmp, mime_type.as_str());
+                unsafe { AMediaCodec_createDecoderByType(codec_mime) }
             }
-            break;
-        }
+        };
         if codec.is_null() {
             unsafe { AMediaFormat_delete(format) };
             return Err(AvifError::NoCodecAvailable);
         }
+        let status =
+            unsafe { AMediaCodec_configure(codec, format, ptr::null_mut(), ptr::null_mut(), 0) };
+        if status != media_status_t_AMEDIA_OK {
+            unsafe {
+                AMediaCodec_delete(codec);
+                AMediaFormat_delete(format);
+            }
+            return Err(AvifError::NoCodecAvailable);
+        }
+        let status = unsafe { AMediaCodec_start(codec) };
+        if status != media_status_t_AMEDIA_OK {
+            unsafe {
+                AMediaCodec_delete(codec);
+                AMediaFormat_delete(format);
+            }
+            return Err(AvifError::NoCodecAvailable);
+        }
         self.codec = Some(codec);
-        self.config = Some(config.clone());
         Ok(())
     }
 
-    fn get_next_image(
+    fn output_buffer_to_image(
+        &self,
+        buffer: *mut u8,
+        image: &mut Image,
+        category: Category,
+    ) -> AvifResult<()> {
+        if self.format.is_none() {
+            return Err(AvifError::UnknownError("format is none".into()));
+        }
+        let format = self.format.unwrap_ref();
+        image.width = format.width()? as u32;
+        image.height = format.height()? as u32;
+        image.yuv_range = format.color_range();
+        let plane_info = format.get_plane_info()?;
+        image.depth = plane_info.depth();
+        image.yuv_format = plane_info.pixel_format();
+        match category {
+            Category::Alpha => {
+                image.row_bytes[3] = plane_info.row_stride[0];
+                image.planes[3] = Some(Pixels::from_raw_pointer(
+                    unsafe { buffer.offset(plane_info.offset[0]) },
+                    image.depth as u32,
+                    image.height,
+                    image.row_bytes[3],
+                )?);
+            }
+            _ => {
+                image.chroma_sample_position = ChromaSamplePosition::Unknown;
+                image.color_primaries = format.color_primaries();
+                image.transfer_characteristics = format.transfer_characteristics();
+                // MediaCodec does not expose matrix coefficients. Try to infer that based on color
+                // primaries to get the most accurate color conversion possible.
+                image.matrix_coefficients = match image.color_primaries {
+                    ColorPrimaries::Bt601 => MatrixCoefficients::Bt601,
+                    ColorPrimaries::Bt709 => MatrixCoefficients::Bt709,
+                    ColorPrimaries::Bt2020 => MatrixCoefficients::Bt2020Ncl,
+                    _ => MatrixCoefficients::Unspecified,
+                };
+
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
+                        image.depth as u32,
+                        plane_height,
+                        image.row_bytes[i],
+                    )?);
+                }
+            }
+        }
+        Ok(())
+    }
+
+    fn enqueue_payload(&self, input_index: isize, payload: &[u8], flags: u32) -> AvifResult<()> {
+        let codec = self.codec.unwrap();
+        let mut input_buffer_size: usize = 0;
+        let input_buffer = unsafe {
+            AMediaCodec_getInputBuffer(
+                codec,
+                input_index as usize,
+                &mut input_buffer_size as *mut _,
+            )
+        };
+        if input_buffer.is_null() {
+            return Err(AvifError::UnknownError(format!(
+                "input buffer at index {input_index} was null"
+            )));
+        }
+        let hevc_whole_nal_units = self.hevc_whole_nal_units(payload)?;
+        let codec_payload = match &hevc_whole_nal_units {
+            Some(hevc_payload) => hevc_payload,
+            None => payload,
+        };
+        if input_buffer_size < codec_payload.len() {
+            return Err(AvifError::UnknownError(format!(
+                "input buffer (size {input_buffer_size}) was not big enough. required size: {}",
+                codec_payload.len()
+            )));
+        }
+        unsafe {
+            ptr::copy_nonoverlapping(codec_payload.as_ptr(), input_buffer, codec_payload.len());
+
+            if AMediaCodec_queueInputBuffer(
+                codec,
+                usize_from_isize(input_index)?,
+                /*offset=*/ 0,
+                codec_payload.len(),
+                /*pts=*/ 0,
+                flags,
+            ) != media_status_t_AMEDIA_OK
+            {
+                return Err(AvifError::UnknownError("".into()));
+            }
+        }
+        Ok(())
+    }
+
+    fn get_next_image_impl(
         &mut self,
         payload: &[u8],
         _spatial_id: u8,
@@ -415,7 +593,7 @@ impl Decoder for MediaCodec {
         category: Category,
     ) -> AvifResult<()> {
         if self.codec.is_none() {
-            self.initialize(&DecoderConfig::default())?;
+            self.initialize_impl(/*low_latency=*/ true)?;
         }
         let codec = self.codec.unwrap();
         if self.output_buffer_index.is_some() {
@@ -426,49 +604,11 @@ impl Decoder for MediaCodec {
         }
         let mut retry_count = 0;
         unsafe {
-            while retry_count < 100 {
+            while retry_count < Self::MAX_RETRIES {
                 retry_count += 1;
-                let input_index = AMediaCodec_dequeueInputBuffer(codec, 10000);
+                let input_index = AMediaCodec_dequeueInputBuffer(codec, Self::TIMEOUT as _);
                 if input_index >= 0 {
-                    let mut input_buffer_size: usize = 0;
-                    let input_buffer = AMediaCodec_getInputBuffer(
-                        codec,
-                        input_index as usize,
-                        &mut input_buffer_size as *mut _,
-                    );
-                    if input_buffer.is_null() {
-                        return Err(AvifError::UnknownError(format!(
-                            "input buffer at index {input_index} was null"
-                        )));
-                    }
-                    let hevc_whole_nal_units = self.hevc_whole_nal_units(payload)?;
-                    let codec_payload = match &hevc_whole_nal_units {
-                        Some(hevc_payload) => hevc_payload,
-                        None => payload,
-                    };
-                    if input_buffer_size < codec_payload.len() {
-                        return Err(AvifError::UnknownError(format!(
-                        "input buffer (size {input_buffer_size}) was not big enough. required size: {}",
-                        codec_payload.len()
-                    )));
-                    }
-                    ptr::copy_nonoverlapping(
-                        codec_payload.as_ptr(),
-                        input_buffer,
-                        codec_payload.len(),
-                    );
-
-                    if AMediaCodec_queueInputBuffer(
-                        codec,
-                        usize_from_isize(input_index)?,
-                        /*offset=*/ 0,
-                        codec_payload.len(),
-                        /*pts=*/ 0,
-                        /*flags=*/ 0,
-                    ) != media_status_t_AMEDIA_OK
-                    {
-                        return Err(AvifError::UnknownError("".into()));
-                    }
+                    self.enqueue_payload(input_index, payload, 0)?;
                     break;
                 } else if input_index == AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize {
                     continue;
@@ -483,11 +623,14 @@ impl Decoder for MediaCodec {
         let mut buffer_size: usize = 0;
         let mut buffer_info = AMediaCodecBufferInfo::default();
         retry_count = 0;
-        while retry_count < 100 {
+        while retry_count < Self::MAX_RETRIES {
             retry_count += 1;
             unsafe {
-                let output_index =
-                    AMediaCodec_dequeueOutputBuffer(codec, &mut buffer_info as *mut _, 10000);
+                let output_index = AMediaCodec_dequeueOutputBuffer(
+                    codec,
+                    &mut buffer_info as *mut _,
+                    Self::TIMEOUT as _,
+                );
                 if output_index >= 0 {
                     let output_buffer = AMediaCodec_getOutputBuffer(
                         codec,
@@ -523,59 +666,173 @@ impl Decoder for MediaCodec {
                 "did not get buffer from mediacodec".into(),
             ));
         }
-        if self.format.is_none() {
-            return Err(AvifError::UnknownError("format is none".into()));
-        }
-        let buffer = buffer.unwrap();
-        let format = self.format.unwrap_ref();
-        image.width = format.width()? as u32;
-        image.height = format.height()? as u32;
-        image.yuv_range = format.color_range();
-        let plane_info = format.get_plane_info()?;
-        image.depth = plane_info.depth();
-        image.yuv_format = plane_info.pixel_format();
-        match category {
-            Category::Alpha => {
-                // TODO: make sure alpha plane matches previous alpha plane.
-                image.row_bytes[3] = plane_info.row_stride[0];
-                image.planes[3] = Some(Pixels::from_raw_pointer(
-                    unsafe { buffer.offset(plane_info.offset[0]) },
-                    image.depth as u32,
-                    image.height,
-                    image.row_bytes[3],
-                )?);
-            }
-            _ => {
-                image.chroma_sample_position = ChromaSamplePosition::Unknown;
-                image.color_primaries = ColorPrimaries::Unspecified;
-                image.transfer_characteristics = TransferCharacteristics::Unspecified;
-                image.matrix_coefficients = MatrixCoefficients::Unspecified;
+        self.output_buffer_to_image(buffer.unwrap(), image, category)?;
+        Ok(())
+    }
 
-                for i in 0usize..3 {
-                    if i == 2
-                        && matches!(
-                            image.yuv_format,
-                            PixelFormat::AndroidP010
-                                | PixelFormat::AndroidNv12
-                                | PixelFormat::AndroidNv21
-                        )
-                    {
-                        // V plane is not needed for these formats.
+    fn get_next_image_grid_impl(
+        &mut self,
+        payloads: &[Vec<u8>],
+        grid_image_helper: &mut GridImageHelper,
+    ) -> AvifResult<()> {
+        if self.codec.is_none() {
+            self.initialize_impl(/*low_latency=*/ false)?;
+        }
+        let codec = self.codec.unwrap();
+        let mut retry_count = 0;
+        let mut payloads_iter = payloads.iter().peekable();
+        unsafe {
+            while !grid_image_helper.is_grid_complete()? {
+                // Queue as many inputs as we possibly can, then block on dequeuing outputs. After
+                // getting each output, come back and queue the inputs again to keep the decoder as
+                // busy as possible.
+                while payloads_iter.peek().is_some() {
+                    let input_index = AMediaCodec_dequeueInputBuffer(codec, 0);
+                    if input_index < 0 {
+                        if retry_count >= Self::MAX_RETRIES {
+                            return Err(AvifError::UnknownError("max retries exceeded".into()));
+                        }
+                        break;
+                    }
+                    let payload = payloads_iter.next().unwrap();
+                    self.enqueue_payload(
+                        input_index,
+                        payload,
+                        if payloads_iter.peek().is_some() {
+                            0
+                        } else {
+                            AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM as u32
+                        },
+                    )?;
+                }
+                loop {
+                    let mut buffer_info = AMediaCodecBufferInfo::default();
+                    let output_index = AMediaCodec_dequeueOutputBuffer(
+                        codec,
+                        &mut buffer_info as *mut _,
+                        Self::TIMEOUT as _,
+                    );
+                    if output_index == AMEDIACODEC_INFO_OUTPUT_BUFFERS_CHANGED as isize {
+                        continue;
+                    } else if output_index == AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED as isize {
+                        let format = AMediaCodec_getOutputFormat(codec);
+                        if format.is_null() {
+                            return Err(AvifError::UnknownError("output format was null".into()));
+                        }
+                        self.format = Some(MediaFormat { format });
+                        continue;
+                    } else if output_index == AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize {
+                        retry_count += 1;
+                        if retry_count >= Self::MAX_RETRIES {
+                            return Err(AvifError::UnknownError("max retries exceeded".into()));
+                        }
+                        break;
+                    } else if output_index < 0 {
+                        return Err(AvifError::UnknownError("".into()));
+                    } else {
+                        let mut buffer_size: usize = 0;
+                        let output_buffer = AMediaCodec_getOutputBuffer(
+                            codec,
+                            usize_from_isize(output_index)?,
+                            &mut buffer_size as *mut _,
+                        );
+                        if output_buffer.is_null() {
+                            return Err(AvifError::UnknownError("output buffer is null".into()));
+                        }
+                        let mut cell_image = Image::default();
+                        self.output_buffer_to_image(
+                            output_buffer,
+                            &mut cell_image,
+                            grid_image_helper.category,
+                        )?;
+                        grid_image_helper.copy_from_cell_image(&mut cell_image)?;
+                        if !grid_image_helper.is_grid_complete()? {
+                            // The last output buffer will be released when the codec is dropped.
+                            AMediaCodec_releaseOutputBuffer(codec, output_index as _, false);
+                        }
                         break;
                     }
-                    image.row_bytes[i] = plane_info.row_stride[i];
-                    let plane_height = if i == 0 { image.height } else { (image.height + 1) / 2 };
-                    image.planes[i] = Some(Pixels::from_raw_pointer(
-                        unsafe { buffer.offset(plane_info.offset[i]) },
-                        image.depth as u32,
-                        plane_height,
-                        image.row_bytes[i],
-                    )?);
                 }
             }
         }
         Ok(())
     }
+
+    fn drop_impl(&mut self) {
+        if self.codec.is_some() {
+            if self.output_buffer_index.is_some() {
+                unsafe {
+                    AMediaCodec_releaseOutputBuffer(
+                        self.codec.unwrap(),
+                        self.output_buffer_index.unwrap(),
+                        false,
+                    );
+                }
+                self.output_buffer_index = None;
+            }
+            unsafe {
+                AMediaCodec_stop(self.codec.unwrap());
+                AMediaCodec_delete(self.codec.unwrap());
+            }
+            self.codec = None;
+        }
+        self.format = None;
+    }
+}
+
+impl Decoder for MediaCodec {
+    fn codec(&self) -> CodecChoice {
+        CodecChoice::MediaCodec
+    }
+
+    fn initialize(&mut self, config: &DecoderConfig) -> AvifResult<()> {
+        self.codec_initializers = get_codec_initializers(config);
+        self.config = Some(config.clone());
+        // Actual codec initialization will be performed in get_next_image since we may try
+        // multiple codecs.
+        Ok(())
+    }
+
+    fn get_next_image(
+        &mut self,
+        payload: &[u8],
+        spatial_id: u8,
+        image: &mut Image,
+        category: Category,
+    ) -> AvifResult<()> {
+        while self.codec_index < self.codec_initializers.len() {
+            let res = self.get_next_image_impl(payload, spatial_id, image, category);
+            if res.is_ok() {
+                return Ok(());
+            }
+            // Drop the current codec and try the next one.
+            self.drop_impl();
+            self.codec_index += 1;
+        }
+        Err(AvifError::UnknownError(
+            "all the codecs failed to extract an image".into(),
+        ))
+    }
+
+    fn get_next_image_grid(
+        &mut self,
+        payloads: &[Vec<u8>],
+        _spatial_id: u8,
+        grid_image_helper: &mut GridImageHelper,
+    ) -> AvifResult<()> {
+        while self.codec_index < self.codec_initializers.len() {
+            let res = self.get_next_image_grid_impl(payloads, grid_image_helper);
+            if res.is_ok() {
+                return Ok(());
+            }
+            // Drop the current codec and try the next one.
+            self.drop_impl();
+            self.codec_index += 1;
+        }
+        Err(AvifError::UnknownError(
+            "all the codecs failed to extract an image".into(),
+        ))
+    }
 }
 
 impl MediaCodec {
@@ -613,23 +870,6 @@ impl Drop for MediaFormat {
 
 impl Drop for MediaCodec {
     fn drop(&mut self) {
-        if self.codec.is_some() {
-            if self.output_buffer_index.is_some() {
-                unsafe {
-                    AMediaCodec_releaseOutputBuffer(
-                        self.codec.unwrap(),
-                        self.output_buffer_index.unwrap(),
-                        false,
-                    );
-                }
-                self.output_buffer_index = None;
-            }
-            unsafe {
-                AMediaCodec_stop(self.codec.unwrap());
-                AMediaCodec_delete(self.codec.unwrap());
-            }
-            self.codec = None;
-        }
-        self.format = None;
+        self.drop_impl();
     }
 }
diff --git a/src/codecs/dav1d.rs b/src/codecs/dav1d.rs
index 6de8c1b..3db8120 100644
--- a/src/codecs/dav1d.rs
+++ b/src/codecs/dav1d.rs
@@ -14,7 +14,8 @@
 
 use crate::codecs::Decoder;
 use crate::codecs::DecoderConfig;
-use crate::decoder::Category;
+use crate::decoder::CodecChoice;
+use crate::decoder::GridImageHelper;
 use crate::image::Image;
 use crate::image::YuvRange;
 use crate::internal_utils::pixels::*;
@@ -24,10 +25,11 @@ use dav1d_sys::bindings::*;
 
 use std::mem::MaybeUninit;
 
-#[derive(Debug, Default)]
+#[derive(Default)]
 pub struct Dav1d {
     context: Option<*mut Dav1dContext>,
     picture: Option<Dav1dPicture>,
+    config: Option<DecoderConfig>,
 }
 
 unsafe extern "C" fn avif_dav1d_free_callback(
@@ -40,22 +42,34 @@ unsafe extern "C" fn avif_dav1d_free_callback(
 // See https://code.videolan.org/videolan/dav1d/-/blob/9849ede1304da1443cfb4a86f197765081034205/include/dav1d/common.h#L55-59
 const DAV1D_EAGAIN: i32 = if libc::EPERM > 0 { -libc::EAGAIN } else { libc::EAGAIN };
 
-// The type of the fields from dav1d_sys::bindings::* are dependent on the
-// compiler that is used to generate the bindings, version of dav1d, etc.
-// So allow clippy to ignore unnecessary cast warnings.
-#[allow(clippy::unnecessary_cast)]
-impl Decoder for Dav1d {
-    fn initialize(&mut self, config: &DecoderConfig) -> AvifResult<()> {
+impl Dav1d {
+    fn initialize_impl(&mut self, low_latency: bool) -> AvifResult<()> {
         if self.context.is_some() {
             return Ok(());
         }
+        let config = self.config.unwrap_ref();
         let mut settings_uninit: MaybeUninit<Dav1dSettings> = MaybeUninit::uninit();
         unsafe { dav1d_default_settings(settings_uninit.as_mut_ptr()) };
         let mut settings = unsafe { settings_uninit.assume_init() };
-        settings.max_frame_delay = 1;
+        if low_latency {
+            settings.max_frame_delay = 1;
+        }
         settings.n_threads = i32::try_from(config.max_threads).unwrap_or(1);
         settings.operating_point = config.operating_point as i32;
         settings.all_layers = if config.all_layers { 1 } else { 0 };
+        let frame_size_limit = match config.image_size_limit {
+            Some(value) => value.get(),
+            None => 0,
+        };
+        // Set a maximum frame size limit to avoid OOM'ing fuzzers. In 32-bit builds, if
+        // frame_size_limit > 8192 * 8192, dav1d reduces frame_size_limit to 8192 * 8192 and logs
+        // a message, so we set frame_size_limit to at most 8192 * 8192 to avoid the dav1d_log
+        // message.
+        settings.frame_size_limit = if cfg!(target_pointer_width = "32") {
+            std::cmp::min(frame_size_limit, 8192 * 8192)
+        } else {
+            frame_size_limit
+        };
 
         let mut dec = MaybeUninit::uninit();
         let ret = unsafe { dav1d_open(dec.as_mut_ptr(), (&settings) as *const _) };
@@ -65,7 +79,94 @@ impl Decoder for Dav1d {
             )));
         }
         self.context = Some(unsafe { dec.assume_init() });
+        Ok(())
+    }
 
+    fn picture_to_image(
+        &self,
+        dav1d_picture: &Dav1dPicture,
+        image: &mut Image,
+        category: Category,
+    ) -> AvifResult<()> {
+        match category {
+            Category::Alpha => {
+                if image.width > 0
+                    && image.height > 0
+                    && (image.width != (dav1d_picture.p.w as u32)
+                        || image.height != (dav1d_picture.p.h as u32)
+                        || image.depth != (dav1d_picture.p.bpc as u8))
+                {
+                    // Alpha plane does not match the previous alpha plane.
+                    return Err(AvifError::UnknownError("".into()));
+                }
+                image.width = dav1d_picture.p.w as u32;
+                image.height = dav1d_picture.p.h as u32;
+                image.depth = dav1d_picture.p.bpc as u8;
+                image.row_bytes[3] = dav1d_picture.stride[0] as u32;
+                image.planes[3] = Some(Pixels::from_raw_pointer(
+                    dav1d_picture.data[0] as *mut u8,
+                    image.depth as u32,
+                    image.height,
+                    image.row_bytes[3],
+                )?);
+                image.image_owns_planes[3] = false;
+                let seq_hdr = unsafe { &(*dav1d_picture.seq_hdr) };
+                image.yuv_range =
+                    if seq_hdr.color_range == 0 { YuvRange::Limited } else { YuvRange::Full };
+            }
+            _ => {
+                image.width = dav1d_picture.p.w as u32;
+                image.height = dav1d_picture.p.h as u32;
+                image.depth = dav1d_picture.p.bpc as u8;
+
+                image.yuv_format = match dav1d_picture.p.layout {
+                    0 => PixelFormat::Yuv400,
+                    1 => PixelFormat::Yuv420,
+                    2 => PixelFormat::Yuv422,
+                    3 => PixelFormat::Yuv444,
+                    _ => return Err(AvifError::UnknownError("".into())), // not reached.
+                };
+                let seq_hdr = unsafe { &(*dav1d_picture.seq_hdr) };
+                image.yuv_range =
+                    if seq_hdr.color_range == 0 { YuvRange::Limited } else { YuvRange::Full };
+                image.chroma_sample_position = (seq_hdr.chr as u32).into();
+
+                image.color_primaries = (seq_hdr.pri as u16).into();
+                image.transfer_characteristics = (seq_hdr.trc as u16).into();
+                image.matrix_coefficients = (seq_hdr.mtrx as u16).into();
+
+                for plane in 0usize..image.yuv_format.plane_count() {
+                    let stride_index = if plane == 0 { 0 } else { 1 };
+                    image.row_bytes[plane] = dav1d_picture.stride[stride_index] as u32;
+                    image.planes[plane] = Some(Pixels::from_raw_pointer(
+                        dav1d_picture.data[plane] as *mut u8,
+                        image.depth as u32,
+                        image.height,
+                        image.row_bytes[plane],
+                    )?);
+                    image.image_owns_planes[plane] = false;
+                }
+                if image.yuv_format == PixelFormat::Yuv400 {
+                    // Clear left over chroma planes from previous frames.
+                    image.clear_chroma_planes();
+                }
+            }
+        }
+        Ok(())
+    }
+}
+
+// The type of the fields from dav1d_sys::bindings::* are dependent on the
+// compiler that is used to generate the bindings, version of dav1d, etc.
+// So allow clippy to ignore unnecessary cast warnings.
+#[allow(clippy::unnecessary_cast)]
+impl Decoder for Dav1d {
+    fn codec(&self) -> CodecChoice {
+        CodecChoice::Dav1d
+    }
+
+    fn initialize(&mut self, config: &DecoderConfig) -> AvifResult<()> {
+        self.config = Some(config.clone());
         Ok(())
     }
 
@@ -77,7 +178,7 @@ impl Decoder for Dav1d {
         category: Category,
     ) -> AvifResult<()> {
         if self.context.is_none() {
-            self.initialize(&DecoderConfig::default())?;
+            self.initialize_impl(true)?;
         }
         unsafe {
             let mut data: Dav1dData = std::mem::zeroed();
@@ -174,74 +275,18 @@ impl Decoder for Dav1d {
                 return Err(AvifError::UnknownError("".into()));
             }
         }
-
-        let dav1d_picture = self.picture.unwrap_ref();
-        match category {
-            Category::Alpha => {
-                if image.width > 0
-                    && image.height > 0
-                    && (image.width != (dav1d_picture.p.w as u32)
-                        || image.height != (dav1d_picture.p.h as u32)
-                        || image.depth != (dav1d_picture.p.bpc as u8))
-                {
-                    // Alpha plane does not match the previous alpha plane.
-                    return Err(AvifError::UnknownError("".into()));
-                }
-                image.width = dav1d_picture.p.w as u32;
-                image.height = dav1d_picture.p.h as u32;
-                image.depth = dav1d_picture.p.bpc as u8;
-                image.row_bytes[3] = dav1d_picture.stride[0] as u32;
-                image.planes[3] = Some(Pixels::from_raw_pointer(
-                    dav1d_picture.data[0] as *mut u8,
-                    image.depth as u32,
-                    image.height,
-                    image.row_bytes[3],
-                )?);
-                image.image_owns_planes[3] = false;
-                let seq_hdr = unsafe { &(*dav1d_picture.seq_hdr) };
-                image.yuv_range =
-                    if seq_hdr.color_range == 0 { YuvRange::Limited } else { YuvRange::Full };
-            }
-            _ => {
-                image.width = dav1d_picture.p.w as u32;
-                image.height = dav1d_picture.p.h as u32;
-                image.depth = dav1d_picture.p.bpc as u8;
-
-                image.yuv_format = match dav1d_picture.p.layout {
-                    0 => PixelFormat::Yuv400,
-                    1 => PixelFormat::Yuv420,
-                    2 => PixelFormat::Yuv422,
-                    3 => PixelFormat::Yuv444,
-                    _ => return Err(AvifError::UnknownError("".into())), // not reached.
-                };
-                let seq_hdr = unsafe { &(*dav1d_picture.seq_hdr) };
-                image.yuv_range =
-                    if seq_hdr.color_range == 0 { YuvRange::Limited } else { YuvRange::Full };
-                image.chroma_sample_position = (seq_hdr.chr as u32).into();
-
-                image.color_primaries = (seq_hdr.pri as u16).into();
-                image.transfer_characteristics = (seq_hdr.trc as u16).into();
-                image.matrix_coefficients = (seq_hdr.mtrx as u16).into();
-
-                for plane in 0usize..image.yuv_format.plane_count() {
-                    let stride_index = if plane == 0 { 0 } else { 1 };
-                    image.row_bytes[plane] = dav1d_picture.stride[stride_index] as u32;
-                    image.planes[plane] = Some(Pixels::from_raw_pointer(
-                        dav1d_picture.data[plane] as *mut u8,
-                        image.depth as u32,
-                        image.height,
-                        image.row_bytes[plane],
-                    )?);
-                    image.image_owns_planes[plane] = false;
-                }
-                if image.yuv_format == PixelFormat::Yuv400 {
-                    // Clear left over chroma planes from previous frames.
-                    image.clear_chroma_planes();
-                }
-            }
-        }
+        self.picture_to_image(self.picture.unwrap_ref(), image, category)?;
         Ok(())
     }
+
+    fn get_next_image_grid(
+        &mut self,
+        _payloads: &[Vec<u8>],
+        _spatial_id: u8,
+        _grid_image_helper: &mut GridImageHelper,
+    ) -> AvifResult<()> {
+        Err(AvifError::NotImplemented)
+    }
 }
 
 impl Drop for Dav1d {
diff --git a/src/codecs/libgav1.rs b/src/codecs/libgav1.rs
index dc015ab..30acd95 100644
--- a/src/codecs/libgav1.rs
+++ b/src/codecs/libgav1.rs
@@ -14,7 +14,8 @@
 
 use crate::codecs::Decoder;
 use crate::codecs::DecoderConfig;
-use crate::decoder::Category;
+use crate::decoder::CodecChoice;
+use crate::decoder::GridImageHelper;
 use crate::image::Image;
 use crate::image::YuvRange;
 use crate::internal_utils::pixels::*;
@@ -36,6 +37,10 @@ pub struct Libgav1 {
 // unnecessary cast warnings.
 #[allow(clippy::unnecessary_cast)]
 impl Decoder for Libgav1 {
+    fn codec(&self) -> CodecChoice {
+        CodecChoice::Libgav1
+    }
+
     fn initialize(&mut self, config: &DecoderConfig) -> AvifResult<()> {
         if self.decoder.is_some() {
             return Ok(()); // Already initialized.
@@ -188,6 +193,15 @@ impl Decoder for Libgav1 {
         }
         Ok(())
     }
+
+    fn get_next_image_grid(
+        &mut self,
+        _payloads: &[Vec<u8>],
+        _spatial_id: u8,
+        _grid_image_helper: &mut GridImageHelper,
+    ) -> AvifResult<()> {
+        Err(AvifError::NotImplemented)
+    }
 }
 
 impl Drop for Libgav1 {
diff --git a/src/codecs/mod.rs b/src/codecs/mod.rs
index 056cf50..eb42e57 100644
--- a/src/codecs/mod.rs
+++ b/src/codecs/mod.rs
@@ -21,11 +21,15 @@ pub mod libgav1;
 #[cfg(feature = "android_mediacodec")]
 pub mod android_mediacodec;
 
-use crate::decoder::Category;
+use crate::decoder::CodecChoice;
+use crate::decoder::GridImageHelper;
 use crate::image::Image;
 use crate::parser::mp4box::CodecConfiguration;
 use crate::AndroidMediaCodecOutputColorFormat;
 use crate::AvifResult;
+use crate::Category;
+
+use std::num::NonZero;
 
 #[derive(Clone, Default)]
 pub struct DecoderConfig {
@@ -35,6 +39,7 @@ pub struct DecoderConfig {
     pub height: u32,
     pub depth: u8,
     pub max_threads: u32,
+    pub image_size_limit: Option<NonZero<u32>>,
     pub max_input_size: usize,
     pub codec_config: CodecConfiguration,
     pub category: Category,
@@ -42,7 +47,9 @@ pub struct DecoderConfig {
 }
 
 pub trait Decoder {
+    fn codec(&self) -> CodecChoice;
     fn initialize(&mut self, config: &DecoderConfig) -> AvifResult<()>;
+    // Decode a single image and write the output into |image|.
     fn get_next_image(
         &mut self,
         av1_payload: &[u8],
@@ -50,5 +57,12 @@ pub trait Decoder {
         image: &mut Image,
         category: Category,
     ) -> AvifResult<()>;
+    // Decode a list of input images and outputs them into the |grid_image_helper|.
+    fn get_next_image_grid(
+        &mut self,
+        payloads: &[Vec<u8>],
+        spatial_id: u8,
+        grid_image_helper: &mut GridImageHelper,
+    ) -> AvifResult<()>;
     // Destruction must be implemented using Drop.
 }
diff --git a/src/decoder/gainmap.rs b/src/decoder/gainmap.rs
index d1e50f2..7a2ece1 100644
--- a/src/decoder/gainmap.rs
+++ b/src/decoder/gainmap.rs
@@ -14,8 +14,7 @@
 
 use crate::decoder::Image;
 use crate::image::YuvRange;
-use crate::internal_utils::*;
-use crate::parser::mp4box::ContentLightLevelInformation;
+use crate::utils::*;
 use crate::*;
 
 #[derive(Debug, Default)]
@@ -30,6 +29,24 @@ pub struct GainMapMetadata {
     pub use_base_color_space: bool,
 }
 
+impl GainMapMetadata {
+    pub(crate) fn is_valid(&self) -> AvifResult<()> {
+        for i in 0..3 {
+            self.min[i].is_valid()?;
+            self.max[i].is_valid()?;
+            self.gamma[i].is_valid()?;
+            self.base_offset[i].is_valid()?;
+            self.alternate_offset[i].is_valid()?;
+            if self.max[i].as_f64()? < self.min[i].as_f64()? || self.gamma[i].0 == 0 {
+                return Err(AvifError::InvalidArgument);
+            }
+        }
+        self.base_hdr_headroom.is_valid()?;
+        self.alternate_hdr_headroom.is_valid()?;
+        Ok(())
+    }
+}
+
 #[derive(Default)]
 pub struct GainMap {
     pub image: Image,
diff --git a/src/decoder/item.rs b/src/decoder/item.rs
index 3da813e..1f187ee 100644
--- a/src/decoder/item.rs
+++ b/src/decoder/item.rs
@@ -18,6 +18,7 @@ use crate::parser::mp4box::*;
 use crate::*;
 
 use std::collections::BTreeMap;
+use std::num::NonZero;
 
 #[derive(Debug, Default)]
 pub struct Item {
@@ -38,7 +39,10 @@ pub struct Item {
     pub has_unsupported_essential_property: bool,
     pub progressive: bool,
     pub idat: Vec<u8>,
-    pub grid_item_ids: Vec<u32>,
+    // Item ids of source items of a derived image item, in the same order as
+    // they appear in the `dimg` box. E.g. item ids for the cells of a grid
+    // item, or for the layers of an overlay item.
+    pub source_item_ids: Vec<u32>,
     pub data_buffer: Option<Vec<u8>>,
     pub is_made_up: bool, // Placeholder grid alpha item if true.
 }
@@ -53,7 +57,7 @@ macro_rules! find_property {
 }
 
 impl Item {
-    pub fn stream<'a>(&'a mut self, io: &'a mut GenericIO) -> AvifResult<IStream<'a>> {
+    pub(crate) fn stream<'a>(&'a mut self, io: &'a mut GenericIO) -> AvifResult<IStream<'a>> {
         if !self.idat.is_empty() {
             match self.extents.len() {
                 0 => return Err(AvifError::UnknownError("no extent".into())),
@@ -91,71 +95,132 @@ impl Item {
         Ok(IStream::create(io_data))
     }
 
-    pub fn read_and_parse(
-        &mut self,
-        io: &mut GenericIO,
-        grid: &mut Grid,
-        size_limit: u32,
-        dimension_limit: u32,
+    fn validate_derived_image_dimensions(
+        width: u32,
+        height: u32,
+        size_limit: Option<NonZero<u32>>,
+        dimension_limit: Option<NonZero<u32>>,
     ) -> AvifResult<()> {
-        if self.item_type != "grid" {
-            return Ok(());
-        }
-        let mut stream = self.stream(io)?;
-        // unsigned int(8) version = 0;
-        let version = stream.read_u8()?;
-        if version != 0 {
+        if width == 0 || height == 0 || !check_limits(width, height, size_limit, dimension_limit) {
             return Err(AvifError::InvalidImageGrid(
-                "unsupported version for grid".into(),
+                "invalid derived image dimensions".into(),
             ));
         }
-        // unsigned int(8) flags;
-        let flags = stream.read_u8()?;
-        // unsigned int(8) rows_minus_one;
-        grid.rows = stream.read_u8()? as u32 + 1;
-        // unsigned int(8) columns_minus_one;
-        grid.columns = stream.read_u8()? as u32 + 1;
-        if (flags & 1) == 1 {
-            // unsigned int(32) output_width;
-            grid.width = stream.read_u32()?;
-            // unsigned int(32) output_height;
-            grid.height = stream.read_u32()?;
-        } else {
-            // unsigned int(16) output_width;
-            grid.width = stream.read_u16()? as u32;
-            // unsigned int(16) output_height;
-            grid.height = stream.read_u16()? as u32;
-        }
-        if grid.width == 0 || grid.height == 0 {
-            return Err(AvifError::InvalidImageGrid(
-                "invalid dimensions in grid box".into(),
-            ));
-        }
-        if !check_limits(grid.width, grid.height, size_limit, dimension_limit) {
-            return Err(AvifError::InvalidImageGrid(
-                "grid dimensions too large".into(),
-            ));
-        }
-        if stream.has_bytes_left()? {
-            return Err(AvifError::InvalidImageGrid(
-                "found unknown extra bytes in the grid box".into(),
-            ));
+        Ok(())
+    }
+
+    pub(crate) fn read_and_parse(
+        &mut self,
+        io: &mut GenericIO,
+        grid: &mut Grid,
+        overlay: &mut Overlay,
+        size_limit: Option<NonZero<u32>>,
+        dimension_limit: Option<NonZero<u32>>,
+    ) -> AvifResult<()> {
+        if self.is_grid_item() {
+            let mut stream = self.stream(io)?;
+            // unsigned int(8) version = 0;
+            let version = stream.read_u8()?;
+            if version != 0 {
+                return Err(AvifError::InvalidImageGrid(
+                    "unsupported version for grid".into(),
+                ));
+            }
+            // unsigned int(8) flags;
+            let flags = stream.read_u8()?;
+            // unsigned int(8) rows_minus_one;
+            grid.rows = stream.read_u8()? as u32 + 1;
+            // unsigned int(8) columns_minus_one;
+            grid.columns = stream.read_u8()? as u32 + 1;
+            if (flags & 1) == 1 {
+                // unsigned int(32) output_width;
+                grid.width = stream.read_u32()?;
+                // unsigned int(32) output_height;
+                grid.height = stream.read_u32()?;
+            } else {
+                // unsigned int(16) output_width;
+                grid.width = stream.read_u16()? as u32;
+                // unsigned int(16) output_height;
+                grid.height = stream.read_u16()? as u32;
+            }
+            Self::validate_derived_image_dimensions(
+                grid.width,
+                grid.height,
+                size_limit,
+                dimension_limit,
+            )?;
+            if stream.has_bytes_left()? {
+                return Err(AvifError::InvalidImageGrid(
+                    "found unknown extra bytes in the grid box".into(),
+                ));
+            }
+        } else if self.is_overlay_item() {
+            let reference_count = self.source_item_ids.len();
+            let mut stream = self.stream(io)?;
+            // unsigned int(8) version = 0;
+            let version = stream.read_u8()?;
+            if version != 0 {
+                return Err(AvifError::InvalidImageGrid(format!(
+                    "unsupported version {version} for iovl"
+                )));
+            }
+            // unsigned int(8) flags;
+            let flags = stream.read_u8()?;
+            for j in 0..4 {
+                // unsigned int(16) canvas_fill_value;
+                overlay.canvas_fill_value[j] = stream.read_u16()?;
+            }
+            if (flags & 1) == 1 {
+                // unsigned int(32) output_width;
+                overlay.width = stream.read_u32()?;
+                // unsigned int(32) output_height;
+                overlay.height = stream.read_u32()?;
+            } else {
+                // unsigned int(16) output_width;
+                overlay.width = stream.read_u16()? as u32;
+                // unsigned int(16) output_height;
+                overlay.height = stream.read_u16()? as u32;
+            }
+            Self::validate_derived_image_dimensions(
+                overlay.width,
+                overlay.height,
+                size_limit,
+                dimension_limit,
+            )?;
+            for _ in 0..reference_count {
+                if (flags & 1) == 1 {
+                    // unsigned int(32) horizontal_offset;
+                    overlay.horizontal_offsets.push(stream.read_i32()?);
+                    // unsigned int(32) vertical_offset;
+                    overlay.vertical_offsets.push(stream.read_i32()?);
+                } else {
+                    // unsigned int(16) horizontal_offset;
+                    overlay.horizontal_offsets.push(stream.read_i16()? as i32);
+                    // unsigned int(16) vertical_offset;
+                    overlay.vertical_offsets.push(stream.read_i16()? as i32);
+                }
+            }
+            if stream.has_bytes_left()? {
+                return Err(AvifError::InvalidImageGrid(
+                    "found unknown extra bytes in the iovl box".into(),
+                ));
+            }
         }
         Ok(())
     }
 
-    pub fn operating_point(&self) -> u8 {
+    pub(crate) fn operating_point(&self) -> u8 {
         match find_property!(self.properties, OperatingPointSelector) {
             Some(operating_point_selector) => *operating_point_selector,
             _ => 0, // default operating point.
         }
     }
 
-    pub fn harvest_ispe(
+    pub(crate) fn harvest_ispe(
         &mut self,
         alpha_ispe_required: bool,
-        size_limit: u32,
-        dimension_limit: u32,
+        size_limit: Option<NonZero<u32>>,
+        dimension_limit: Option<NonZero<u32>>,
     ) -> AvifResult<()> {
         if self.should_skip() {
             return Ok(());
@@ -199,19 +264,22 @@ impl Item {
         Ok(())
     }
 
-    pub fn validate_properties(&self, items: &Items, pixi_required: bool) -> AvifResult<()> {
+    pub(crate) fn validate_properties(&self, items: &Items, pixi_required: bool) -> AvifResult<()> {
         let codec_config = self
             .codec_config()
             .ok_or(AvifError::BmffParseFailed("missing av1C property".into()))?;
-        if self.item_type == "grid" {
-            for grid_item_id in &self.grid_item_ids {
-                let grid_item = items.get(grid_item_id).unwrap();
-                let grid_codec_config = grid_item.codec_config().ok_or(
-                    AvifError::BmffParseFailed("missing codec config property".into()),
-                )?;
-                if codec_config != grid_codec_config {
+        if self.is_derived_image_item() {
+            for derived_item_id in &self.source_item_ids {
+                let derived_item = items.get(derived_item_id).unwrap();
+                let derived_codec_config =
+                    derived_item
+                        .codec_config()
+                        .ok_or(AvifError::BmffParseFailed(
+                            "missing codec config property".into(),
+                        ))?;
+                if codec_config != derived_codec_config {
                     return Err(AvifError::BmffParseFailed(
-                        "codec config of grid items do not match".into(),
+                        "codec config of derived items do not match".into(),
                     ));
                 }
             }
@@ -235,33 +303,32 @@ impl Item {
         Ok(())
     }
 
-    pub fn codec_config(&self) -> Option<&CodecConfiguration> {
+    pub(crate) fn codec_config(&self) -> Option<&CodecConfiguration> {
         find_property!(self.properties, CodecConfiguration)
     }
 
-    pub fn pixi(&self) -> Option<&PixelInformation> {
+    pub(crate) fn pixi(&self) -> Option<&PixelInformation> {
         find_property!(self.properties, PixelInformation)
     }
 
-    pub fn a1lx(&self) -> Option<&[usize; 3]> {
+    pub(crate) fn a1lx(&self) -> Option<&[usize; 3]> {
         find_property!(self.properties, AV1LayeredImageIndexing)
     }
 
-    pub fn lsel(&self) -> Option<&u16> {
+    pub(crate) fn lsel(&self) -> Option<&u16> {
         find_property!(self.properties, LayerSelector)
     }
 
-    pub fn clli(&self) -> Option<&ContentLightLevelInformation> {
+    pub(crate) fn clli(&self) -> Option<&ContentLightLevelInformation> {
         find_property!(self.properties, ContentLightLevelInformation)
     }
 
-    pub fn is_auxiliary_alpha(&self) -> bool {
-        matches!(find_property!(self.properties, AuxiliaryType),
-                 Some(aux_type) if aux_type == "urn:mpeg:mpegB:cicp:systems:auxiliary:alpha" ||
-                                   aux_type == "urn:mpeg:hevc:2015:auxid:1")
+    pub(crate) fn is_auxiliary_alpha(&self) -> bool {
+        matches!(find_property!(&self.properties, AuxiliaryType),
+                 Some(aux_type) if is_auxiliary_type_alpha(aux_type))
     }
 
-    pub fn is_image_codec_item(&self) -> bool {
+    pub(crate) fn is_image_codec_item(&self) -> bool {
         [
             "av01",
             #[cfg(feature = "heic")]
@@ -270,11 +337,24 @@ impl Item {
         .contains(&self.item_type.as_str())
     }
 
-    pub fn is_image_item(&self) -> bool {
-        self.is_image_codec_item() || self.item_type == "grid"
+    pub(crate) fn is_grid_item(&self) -> bool {
+        self.item_type == "grid"
+    }
+
+    pub(crate) fn is_overlay_item(&self) -> bool {
+        self.item_type == "iovl"
     }
 
-    pub fn should_skip(&self) -> bool {
+    pub(crate) fn is_derived_image_item(&self) -> bool {
+        self.is_grid_item() || self.is_overlay_item() || self.is_tmap()
+    }
+
+    pub(crate) fn is_image_item(&self) -> bool {
+        // Adding || self.is_tmap() here would cause differences with libavif.
+        self.is_image_codec_item() || self.is_grid_item() || self.is_overlay_item()
+    }
+
+    pub(crate) fn should_skip(&self) -> bool {
         // The item has no payload in idat or mdat. It cannot be a coded image item, a
         // non-identity derived image item, or Exif/XMP metadata.
         self.size == 0
@@ -293,19 +373,19 @@ impl Item {
             && self.item_type == *item_type
     }
 
-    pub fn is_exif(&self, color_id: Option<u32>) -> bool {
+    pub(crate) fn is_exif(&self, color_id: Option<u32>) -> bool {
         self.is_metadata("Exif", color_id)
     }
 
-    pub fn is_xmp(&self, color_id: Option<u32>) -> bool {
+    pub(crate) fn is_xmp(&self, color_id: Option<u32>) -> bool {
         self.is_metadata("mime", color_id) && self.content_type == "application/rdf+xml"
     }
 
-    pub fn is_tmap(&self) -> bool {
+    pub(crate) fn is_tmap(&self) -> bool {
         self.is_metadata("tmap", None) && self.thumbnail_for_id == 0
     }
 
-    pub fn max_extent(&self, sample: &DecodeSample) -> AvifResult<Extent> {
+    pub(crate) fn max_extent(&self, sample: &DecodeSample) -> AvifResult<Extent> {
         if !self.idat.is_empty() {
             return Ok(Extent::default());
         }
@@ -372,7 +452,7 @@ fn insert_item_if_not_exists(id: u32, items: &mut Items) {
     );
 }
 
-pub fn construct_items(meta: &MetaBox) -> AvifResult<Items> {
+pub(crate) fn construct_items(meta: &MetaBox) -> AvifResult<Items> {
     let mut items: Items = BTreeMap::new();
     for iinf in &meta.iinf {
         items.insert(
@@ -422,7 +502,12 @@ pub fn construct_items(meta: &MetaBox) -> AvifResult<Items> {
             let property_index: usize = *property_index_ref as usize;
             let essential = *essential_ref;
             if property_index == 0 {
-                // Not associated with any item.
+                if essential {
+                    return Err(AvifError::BmffParseFailed(format!(
+                        "item id {} contains an illegal essential property index 0",
+                        { item.id }
+                    )));
+                }
                 continue;
             }
             // property_index is 1-based.
@@ -440,7 +525,14 @@ pub fn construct_items(meta: &MetaBox) -> AvifResult<Items> {
                     ));
                 }
                 (
-                    ItemProperty::OperatingPointSelector(_) | ItemProperty::LayerSelector(_),
+                    ItemProperty::OperatingPointSelector(_)
+                    | ItemProperty::LayerSelector(_)
+                    // MIAF 2019/Amd. 2:2021: Section 7.3.9:
+                    //   All transformative properties associated with coded and derived images
+                    //   shall be marked as essential.
+                    | ItemProperty::CleanAperture(_)
+                    | ItemProperty::ImageRotation(_)
+                    | ItemProperty::ImageMirror(_),
                     false,
                 ) => {
                     return Err(AvifError::BmffParseFailed(
diff --git a/src/decoder/mod.rs b/src/decoder/mod.rs
index b2e6b77..1beb088 100644
--- a/src/decoder/mod.rs
+++ b/src/decoder/mod.rs
@@ -43,6 +43,7 @@ use crate::*;
 
 use std::cmp::max;
 use std::cmp::min;
+use std::num::NonZero;
 
 pub trait IO {
     fn read(&mut self, offset: u64, max_read_size: usize) -> AvifResult<&[u8]>;
@@ -51,7 +52,7 @@ pub trait IO {
 }
 
 impl dyn IO {
-    pub fn read_exact(&mut self, offset: u64, read_size: usize) -> AvifResult<&[u8]> {
+    pub(crate) fn read_exact(&mut self, offset: u64, read_size: usize) -> AvifResult<&[u8]> {
         let result = self.read(offset, read_size)?;
         if result.len() < read_size {
             Err(AvifError::TruncatedData)
@@ -65,7 +66,7 @@ impl dyn IO {
 pub type GenericIO = Box<dyn IO>;
 pub type Codec = Box<dyn crate::codecs::Decoder>;
 
-#[derive(Debug, Default)]
+#[derive(Debug, Default, PartialEq)]
 pub enum CodecChoice {
     #[default]
     Auto,
@@ -135,7 +136,7 @@ pub enum ImageContentType {
 }
 
 impl ImageContentType {
-    pub fn categories(&self) -> Vec<Category> {
+    pub(crate) fn categories(&self) -> Vec<Category> {
         match self {
             Self::None => vec![],
             Self::ColorAndAlpha => vec![Category::Color, Category::Alpha],
@@ -144,7 +145,7 @@ impl ImageContentType {
         }
     }
 
-    pub fn gainmap(&self) -> bool {
+    pub(crate) fn gainmap(&self) -> bool {
         matches!(self, Self::GainMap | Self::All)
     }
 }
@@ -159,9 +160,9 @@ pub struct Settings {
     pub allow_incremental: bool,
     pub image_content_to_decode: ImageContentType,
     pub codec_choice: CodecChoice,
-    pub image_size_limit: u32,
-    pub image_dimension_limit: u32,
-    pub image_count_limit: u32,
+    pub image_size_limit: Option<NonZero<u32>>,
+    pub image_dimension_limit: Option<NonZero<u32>>,
+    pub image_count_limit: Option<NonZero<u32>>,
     pub max_threads: u32,
     pub android_mediacodec_output_color_format: AndroidMediaCodecOutputColorFormat,
 }
@@ -177,9 +178,9 @@ impl Default for Settings {
             allow_incremental: false,
             image_content_to_decode: ImageContentType::ColorAndAlpha,
             codec_choice: Default::default(),
-            image_size_limit: DEFAULT_IMAGE_SIZE_LIMIT,
-            image_dimension_limit: DEFAULT_IMAGE_DIMENSION_LIMIT,
-            image_count_limit: DEFAULT_IMAGE_COUNT_LIMIT,
+            image_size_limit: NonZero::new(DEFAULT_IMAGE_SIZE_LIMIT),
+            image_dimension_limit: NonZero::new(DEFAULT_IMAGE_DIMENSION_LIMIT),
+            image_count_limit: NonZero::new(DEFAULT_IMAGE_COUNT_LIMIT),
             max_threads: 1,
             android_mediacodec_output_color_format: AndroidMediaCodecOutputColorFormat::default(),
         }
@@ -228,7 +229,7 @@ pub enum Strictness {
 }
 
 impl Strictness {
-    pub fn pixi_required(&self) -> bool {
+    pub(crate) fn pixi_required(&self) -> bool {
         match self {
             Strictness::All => true,
             Strictness::SpecificInclude(flags) => flags
@@ -241,7 +242,7 @@ impl Strictness {
         }
     }
 
-    pub fn alpha_ispe_required(&self) -> bool {
+    pub(crate) fn alpha_ispe_required(&self) -> bool {
         match self {
             Strictness::All => true,
             Strictness::SpecificInclude(flags) => flags
@@ -316,44 +317,56 @@ pub enum CompressionFormat {
     Heic = 1,
 }
 
-#[derive(Clone, Copy, Debug, Default, PartialEq)]
-pub enum Category {
-    #[default]
-    Color,
-    Alpha,
-    Gainmap,
+pub struct GridImageHelper<'a> {
+    grid: &'a Grid,
+    image: &'a mut Image,
+    pub(crate) category: Category,
+    cell_index: usize,
+    codec_config: &'a CodecConfiguration,
+    first_cell_image: Option<Image>,
+    tile_width: u32,
+    tile_height: u32,
 }
 
-impl Category {
-    const COUNT: usize = 3;
-    const ALL: [Category; Category::COUNT] = [Self::Color, Self::Alpha, Self::Gainmap];
-    const ALL_USIZE: [usize; Category::COUNT] = [0, 1, 2];
-
-    pub fn usize(self) -> usize {
-        match self {
-            Category::Color => 0,
-            Category::Alpha => 1,
-            Category::Gainmap => 2,
-        }
+// These functions are not used in all configurations.
+#[allow(unused)]
+impl GridImageHelper<'_> {
+    pub(crate) fn is_grid_complete(&self) -> AvifResult<bool> {
+        Ok(self.cell_index as u32 == checked_mul!(self.grid.rows, self.grid.columns)?)
     }
 
-    pub fn planes(&self) -> &[Plane] {
-        match self {
-            Category::Alpha => &A_PLANE,
-            _ => &YUV_PLANES,
+    pub(crate) fn copy_from_cell_image(&mut self, cell_image: &mut Image) -> AvifResult<()> {
+        if self.is_grid_complete()? {
+            return Ok(());
         }
+        if self.category == Category::Alpha && cell_image.yuv_range == YuvRange::Limited {
+            cell_image.alpha_to_full_range()?;
+        }
+        cell_image.scale(self.tile_width, self.tile_height, self.category)?;
+        if self.cell_index == 0 {
+            validate_grid_image_dimensions(cell_image, self.grid)?;
+            if self.category != Category::Alpha {
+                self.image.width = self.grid.width;
+                self.image.height = self.grid.height;
+                self.image
+                    .copy_properties_from(cell_image, self.codec_config);
+            }
+            self.image.allocate_planes(self.category)?;
+        } else if !cell_image.has_same_properties_and_cicp(self.first_cell_image.unwrap_ref()) {
+            return Err(AvifError::InvalidImageGrid(
+                "grid image contains mismatched tiles".into(),
+            ));
+        }
+        self.image
+            .copy_from_tile(cell_image, self.grid, self.cell_index as u32, self.category)?;
+        if self.cell_index == 0 {
+            self.first_cell_image = Some(cell_image.shallow_clone());
+        }
+        self.cell_index += 1;
+        Ok(())
     }
 }
 
-macro_rules! find_property {
-    ($properties:expr, $property_name:ident) => {
-        $properties.iter().find_map(|p| match p {
-            ItemProperty::$property_name(value) => Some(value.clone()),
-            _ => None,
-        })
-    };
-}
-
 impl Decoder {
     pub fn image_count(&self) -> u32 {
         self.image_count
@@ -426,13 +439,13 @@ impl Decoder {
         }) {
             return Ok(Some(*item.0));
         }
-        if color_item.item_type != "grid" || color_item.grid_item_ids.is_empty() {
+        if !color_item.is_grid_item() || color_item.source_item_ids.is_empty() {
             return Ok(None);
         }
         // If color item is a grid, check if there is an alpha channel which is represented as an
         // auxl item to each color tile item.
-        let mut alpha_item_indices: Vec<u32> = create_vec_exact(color_item.grid_item_ids.len())?;
-        for color_grid_item_id in &color_item.grid_item_ids {
+        let mut alpha_item_indices: Vec<u32> = create_vec_exact(color_item.source_item_ids.len())?;
+        for color_grid_item_id in &color_item.source_item_ids {
             match self
                 .items
                 .iter()
@@ -468,7 +481,7 @@ impl Decoder {
             item_type: String::from("grid"),
             width: color_item.width,
             height: color_item.height,
-            grid_item_ids: alpha_item_indices,
+            source_item_ids: alpha_item_indices,
             properties,
             is_made_up: true,
             ..Item::default()
@@ -604,7 +617,7 @@ impl Decoder {
             .items
             .get(&item_id)
             .ok_or(AvifError::MissingImageItem)?;
-        if item.grid_item_ids.is_empty() {
+        if item.source_item_ids.is_empty() {
             if item.size == 0 {
                 return Err(AvifError::MissingImageItem);
             }
@@ -617,30 +630,30 @@ impl Decoder {
             tile.input.category = category;
             tiles.push(tile);
         } else {
-            if !self.tile_info[category.usize()].is_grid() {
+            if !self.tile_info[category.usize()].is_derived_image() {
                 return Err(AvifError::InvalidImageGrid(
-                    "dimg items were found but image is not grid.".into(),
+                    "dimg items were found but image is not a derived image.".into(),
                 ));
             }
             let mut progressive = true;
-            for grid_item_id in item.grid_item_ids.clone() {
-                let grid_item = self
+            for derived_item_id in item.source_item_ids.clone() {
+                let derived_item = self
                     .items
-                    .get_mut(&grid_item_id)
-                    .ok_or(AvifError::InvalidImageGrid("missing grid item".into()))?;
+                    .get_mut(&derived_item_id)
+                    .ok_or(AvifError::InvalidImageGrid("missing derived item".into()))?;
                 let mut tile = Tile::create_from_item(
-                    grid_item,
+                    derived_item,
                     self.settings.allow_progressive,
                     self.settings.image_count_limit,
                     self.io.unwrap_ref().size_hint(),
                 )?;
                 tile.input.category = category;
                 tiles.push(tile);
-                progressive = progressive && grid_item.progressive;
+                progressive = progressive && derived_item.progressive;
             }
 
             if category == Category::Color && progressive {
-                // Propagate the progressive status to the top-level grid item.
+                // Propagate the progressive status to the top-level item.
                 self.items.get_mut(&item_id).unwrap().progressive = true;
             }
         }
@@ -685,13 +698,16 @@ impl Decoder {
         Ok(())
     }
 
-    fn populate_grid_item_ids(&mut self, item_id: u32, category: Category) -> AvifResult<()> {
-        if self.items.get(&item_id).unwrap().item_type != "grid" {
+    // Populates the source item ids for a derived image item.
+    // These are the ids that are in the item's `dimg` box.
+    fn populate_source_item_ids(&mut self, item_id: u32) -> AvifResult<()> {
+        if !self.items.get(&item_id).unwrap().is_derived_image_item() {
             return Ok(());
         }
-        let tile_count = self.tile_info[category.usize()].grid_tile_count()? as usize;
-        let mut grid_item_ids: Vec<u32> = create_vec_exact(tile_count)?;
+
+        let mut source_item_ids: Vec<u32> = vec![];
         let mut first_codec_config: Option<CodecConfiguration> = None;
+        let mut first_icc: Option<Vec<u8>> = None;
         // Collect all the dimg items.
         for dimg_item_id in self.items.keys() {
             if *dimg_item_id == item_id {
@@ -706,7 +722,7 @@ impl Decoder {
             }
             if !dimg_item.is_image_codec_item() || dimg_item.has_unsupported_essential_property {
                 return Err(AvifError::InvalidImageGrid(
-                    "invalid input item in dimg grid".into(),
+                    "invalid input item in dimg".into(),
                 ));
             }
             if first_codec_config.is_none() {
@@ -721,29 +737,55 @@ impl Decoder {
                         .clone(),
                 );
             }
-            if grid_item_ids.len() >= tile_count {
-                return Err(AvifError::InvalidImageGrid(
-                    "Expected number of tiles not found".into(),
-                ));
+            if dimg_item.is_image_codec_item() && first_icc.is_none() {
+                first_icc = find_icc(&dimg_item.properties)?.cloned();
             }
-            grid_item_ids.push(*dimg_item_id);
+            source_item_ids.push(*dimg_item_id);
         }
-        if grid_item_ids.len() != tile_count {
-            return Err(AvifError::InvalidImageGrid(
-                "Expected number of tiles not found".into(),
-            ));
+        if first_codec_config.is_none() {
+            // No derived images were found.
+            return Ok(());
         }
-        // ISO/IEC 23008-12: The input images are inserted in row-major order,
-        // top-row first, left to right, in the order of SingleItemTypeReferenceBox of type 'dimg'
-        // for this derived image item within the ItemReferenceBox.
-        // Sort the grid items by dimg_index. dimg_index is the order in which the items appear in
-        // the 'iref' box.
-        grid_item_ids.sort_by_key(|k| self.items.get(k).unwrap().dimg_index);
+        // The order of derived item ids matters: sort them by dimg_index, which is the order that
+        // items appear in the 'iref' box.
+        source_item_ids.sort_by_key(|k| self.items.get(k).unwrap().dimg_index);
         let item = self.items.get_mut(&item_id).unwrap();
         item.properties.push(ItemProperty::CodecConfiguration(
             first_codec_config.unwrap(),
         ));
-        item.grid_item_ids = grid_item_ids;
+        if (item.is_grid_item() || item.is_overlay_item())
+            && first_icc.is_some()
+            && find_icc(&item.properties)?.is_none()
+        {
+            // For grid and overlay items, adopt the icc color profile of the first tile if it is
+            // not explicitly specified for the overall grid.
+            item.properties
+                .push(ItemProperty::ColorInformation(ColorInformation::Icc(
+                    first_icc.unwrap().clone(),
+                )));
+        }
+        item.source_item_ids = source_item_ids;
+        Ok(())
+    }
+
+    fn validate_source_item_counts(&self, item_id: u32, tile_info: &TileInfo) -> AvifResult<()> {
+        let item = self.items.get(&item_id).unwrap();
+        if item.is_grid_item() {
+            let tile_count = tile_info.grid_tile_count()? as usize;
+            if item.source_item_ids.len() != tile_count {
+                return Err(AvifError::InvalidImageGrid(
+                    "Expected number of tiles not found".into(),
+                ));
+            }
+        } else if item.is_overlay_item() && item.source_item_ids.is_empty() {
+            return Err(AvifError::BmffParseFailed(
+                "No dimg items found for iovl".into(),
+            ));
+        } else if item.is_tmap() && item.source_item_ids.len() != 2 {
+            return Err(AvifError::InvalidToneMappedImage(
+                "Expected tmap to have 2 dimg items".into(),
+            ));
+        }
         Ok(())
     }
 
@@ -786,10 +828,12 @@ impl Decoder {
             if !self.tracks.is_empty() {
                 self.image.image_sequence_track_present = true;
                 for track in &self.tracks {
-                    if !track.check_limits(
-                        self.settings.image_size_limit,
-                        self.settings.image_dimension_limit,
-                    ) {
+                    if track.is_video_handler()
+                        && !track.check_limits(
+                            self.settings.image_size_limit,
+                            self.settings.image_dimension_limit,
+                        )
+                    {
                         return Err(AvifError::BmffParseFailed(
                             "track dimension too large".into(),
                         ));
@@ -859,7 +903,11 @@ impl Decoder {
                 )?);
                 self.tile_info[Category::Color.usize()].tile_count = 1;
 
-                if let Some(alpha_track) = self.tracks.iter().find(|x| x.is_aux(color_track.id)) {
+                if let Some(alpha_track) = self
+                    .tracks
+                    .iter()
+                    .find(|x| x.is_aux(color_track.id) && x.is_auxiliary_alpha())
+                {
                     self.tiles[Category::Alpha.usize()].push(Tile::create_from_track(
                         alpha_track,
                         self.settings.image_count_limit,
@@ -903,7 +951,6 @@ impl Decoder {
 
                 item_ids[Category::Color.usize()] = color_item_id.ok_or(AvifError::NoContent)?;
                 self.read_and_parse_item(item_ids[Category::Color.usize()], Category::Color)?;
-                self.populate_grid_item_ids(item_ids[Category::Color.usize()], Category::Color)?;
 
                 // Find exif/xmp from meta if any.
                 Self::search_exif_or_xmp_metadata(
@@ -920,7 +967,6 @@ impl Decoder {
                 {
                     if !self.items.get(&alpha_item_id).unwrap().is_made_up {
                         self.read_and_parse_item(alpha_item_id, Category::Alpha)?;
-                        self.populate_grid_item_ids(alpha_item_id, Category::Alpha)?;
                     }
                     item_ids[Category::Alpha.usize()] = alpha_item_id;
                 }
@@ -930,6 +976,8 @@ impl Decoder {
                     if let Some((tonemap_id, gainmap_id)) =
                         self.find_gainmap_item(item_ids[Category::Color.usize()])?
                     {
+                        self.validate_gainmap_item(gainmap_id, tonemap_id)?;
+                        self.read_and_parse_item(gainmap_id, Category::Gainmap)?;
                         let tonemap_item = self
                             .items
                             .get_mut(&tonemap_id)
@@ -937,9 +985,6 @@ impl Decoder {
                         let mut stream = tonemap_item.stream(self.io.unwrap_mut())?;
                         if let Some(metadata) = mp4box::parse_tmap(&mut stream)? {
                             self.gainmap.metadata = metadata;
-                            self.read_and_parse_item(gainmap_id, Category::Gainmap)?;
-                            self.populate_grid_item_ids(gainmap_id, Category::Gainmap)?;
-                            self.validate_gainmap_item(gainmap_id, tonemap_id)?;
                             self.gainmap_present = true;
                             if self.settings.image_content_to_decode.gainmap() {
                                 item_ids[Category::Gainmap.usize()] = gainmap_id;
@@ -991,8 +1036,10 @@ impl Decoder {
                 let color_item = self.items.get(&item_ids[Category::Color.usize()]).unwrap();
                 self.image.width = color_item.width;
                 self.image.height = color_item.height;
-                self.image.alpha_present = item_ids[Category::Alpha.usize()] != 0;
-                // alphapremultiplied.
+                let alpha_item_id = item_ids[Category::Alpha.usize()];
+                self.image.alpha_present = alpha_item_id != 0;
+                self.image.alpha_premultiplied =
+                    alpha_item_id != 0 && color_item.prem_by_id == alpha_item_id;
 
                 if color_item.progressive {
                     self.image.progressive_state = ProgressiveState::Available;
@@ -1123,12 +1170,15 @@ impl Decoder {
         if item_id == 0 {
             return Ok(());
         }
+        self.populate_source_item_ids(item_id)?;
         self.items.get_mut(&item_id).unwrap().read_and_parse(
             self.io.unwrap_mut(),
             &mut self.tile_info[category.usize()].grid,
+            &mut self.tile_info[category.usize()].overlay,
             self.settings.image_size_limit,
             self.settings.image_dimension_limit,
-        )
+        )?;
+        self.validate_source_item_counts(item_id, &self.tile_info[category.usize()])
     }
 
     fn can_use_single_codec(&self) -> AvifResult<bool> {
@@ -1181,6 +1231,7 @@ impl Decoder {
             height: tile.height,
             depth: self.image.depth,
             max_threads: self.settings.max_threads,
+            image_size_limit: self.settings.image_size_limit,
             max_input_size: tile.max_sample_size(),
             codec_config: tile.codec_config.clone(),
             category,
@@ -1297,65 +1348,6 @@ impl Decoder {
         Ok(())
     }
 
-    fn validate_grid_image_dimensions(image: &Image, grid: &Grid) -> AvifResult<()> {
-        if checked_mul!(image.width, grid.columns)? < grid.width
-            || checked_mul!(image.height, grid.rows)? < grid.height
-        {
-            return Err(AvifError::InvalidImageGrid(
-                        "Grid image tiles do not completely cover the image (HEIF (ISO/IEC 23008-12:2017), Section 6.6.2.3.1)".into(),
-                    ));
-        }
-        if checked_mul!(image.width, grid.columns)? < grid.width
-            || checked_mul!(image.height, grid.rows)? < grid.height
-        {
-            return Err(AvifError::InvalidImageGrid(
-                "Grid image tiles do not completely cover the image (HEIF (ISO/IEC 23008-12:2017), \
-                    Section 6.6.2.3.1)"
-                    .into(),
-            ));
-        }
-        if checked_mul!(image.width, grid.columns - 1)? >= grid.width
-            || checked_mul!(image.height, grid.rows - 1)? >= grid.height
-        {
-            return Err(AvifError::InvalidImageGrid(
-                "Grid image tiles in the rightmost column and bottommost row do not overlap the \
-                     reconstructed image grid canvas. See MIAF (ISO/IEC 23000-22:2019), Section \
-                     7.3.11.4.2, Figure 2"
-                    .into(),
-            ));
-        }
-        // ISO/IEC 23000-22:2019, Section 7.3.11.4.2:
-        //   - the tile_width shall be greater than or equal to 64, and should be a multiple of 64
-        //   - the tile_height shall be greater than or equal to 64, and should be a multiple of 64
-        // The "should" part is ignored here.
-        if image.width < 64 || image.height < 64 {
-            return Err(AvifError::InvalidImageGrid(format!(
-                "Grid image tile width ({}) or height ({}) cannot be smaller than 64. See MIAF \
-                     (ISO/IEC 23000-22:2019), Section 7.3.11.4.2",
-                image.width, image.height
-            )));
-        }
-        // ISO/IEC 23000-22:2019, Section 7.3.11.4.2:
-        //   - when the images are in the 4:2:2 chroma sampling format the horizontal tile offsets
-        //     and widths, and the output width, shall be even numbers;
-        //   - when the images are in the 4:2:0 chroma sampling format both the horizontal and
-        //     vertical tile offsets and widths, and the output width and height, shall be even
-        //     numbers.
-        if ((image.yuv_format == PixelFormat::Yuv420 || image.yuv_format == PixelFormat::Yuv422)
-            && (grid.width % 2 != 0 || image.width % 2 != 0))
-            || (image.yuv_format == PixelFormat::Yuv420
-                && (grid.height % 2 != 0 || image.height % 2 != 0))
-        {
-            return Err(AvifError::InvalidImageGrid(format!(
-                "Grid image width ({}) or height ({}) or tile width ({}) or height ({}) shall be \
-                    even if chroma is subsampled in that dimension. See MIAF \
-                    (ISO/IEC 23000-22:2019), Section 7.3.11.4.2",
-                grid.width, grid.height, image.width, image.height
-            )));
-        }
-        Ok(())
-    }
-
     fn decode_tile(
         &mut self,
         image_index: usize,
@@ -1376,7 +1368,23 @@ impl Decoder {
             &self.items.get(&sample.item_id).unwrap().data_buffer
         };
         let data = sample.data(io, item_data_buffer)?;
-        codec.get_next_image(data, sample.spatial_id, &mut tile.image, category)?;
+        let next_image_result =
+            codec.get_next_image(data, sample.spatial_id, &mut tile.image, category);
+        if next_image_result.is_err() {
+            if cfg!(feature = "android_mediacodec")
+                && cfg!(feature = "heic")
+                && tile.codec_config.is_heic()
+                && category == Category::Alpha
+            {
+                // When decoding HEIC on Android, if the alpha channel decoding fails, simply
+                // ignore it and return the rest of the image.
+                checked_incr!(self.tile_info[category.usize()].decoded_tile_count, 1);
+                return Ok(());
+            } else {
+                return next_image_result;
+            }
+        }
+
         checked_incr!(self.tile_info[category.usize()].decoded_tile_count, 1);
 
         if category == Category::Alpha && tile.image.yuv_range == YuvRange::Limited {
@@ -1387,14 +1395,13 @@ impl Decoder {
         if self.tile_info[category.usize()].is_grid() {
             if tile_index == 0 {
                 let grid = &self.tile_info[category.usize()].grid;
-                Self::validate_grid_image_dimensions(&tile.image, grid)?;
+                validate_grid_image_dimensions(&tile.image, grid)?;
                 match category {
                     Category::Color => {
                         self.image.width = grid.width;
                         self.image.height = grid.height;
-                        // Adopt the yuv_format and depth.
-                        self.image.yuv_format = tile.image.yuv_format;
-                        self.image.depth = tile.image.depth;
+                        self.image
+                            .copy_properties_from(&tile.image, &tile.codec_config);
                         self.image.allocate_planes(category)?;
                     }
                     Category::Alpha => {
@@ -1405,13 +1412,70 @@ impl Decoder {
                     Category::Gainmap => {
                         self.gainmap.image.width = grid.width;
                         self.gainmap.image.height = grid.height;
-                        // Adopt the yuv_format and depth.
-                        self.gainmap.image.yuv_format = tile.image.yuv_format;
-                        self.gainmap.image.depth = tile.image.depth;
+                        self.gainmap
+                            .image
+                            .copy_properties_from(&tile.image, &tile.codec_config);
                         self.gainmap.image.allocate_planes(category)?;
                     }
                 }
             }
+            if !tiles_slice1.is_empty()
+                && !tile
+                    .image
+                    .has_same_properties_and_cicp(&tiles_slice1[0].image)
+            {
+                return Err(AvifError::InvalidImageGrid(
+                    "grid image contains mismatched tiles".into(),
+                ));
+            }
+            match category {
+                Category::Gainmap => self.gainmap.image.copy_from_tile(
+                    &tile.image,
+                    &self.tile_info[category.usize()].grid,
+                    tile_index as u32,
+                    category,
+                )?,
+                _ => {
+                    self.image.copy_from_tile(
+                        &tile.image,
+                        &self.tile_info[category.usize()].grid,
+                        tile_index as u32,
+                        category,
+                    )?;
+                }
+            }
+        } else if self.tile_info[category.usize()].is_overlay() {
+            if tile_index == 0 {
+                let overlay = &self.tile_info[category.usize()].overlay;
+                let canvas_fill_values =
+                    self.image.convert_rgba16_to_yuva(overlay.canvas_fill_value);
+                match category {
+                    Category::Color => {
+                        self.image.width = overlay.width;
+                        self.image.height = overlay.height;
+                        self.image
+                            .copy_properties_from(&tile.image, &tile.codec_config);
+                        self.image
+                            .allocate_planes_with_default_values(category, canvas_fill_values)?;
+                    }
+                    Category::Alpha => {
+                        // Alpha is always just one plane and the depth has been validated
+                        // to be the same as the color planes' depth.
+                        self.image
+                            .allocate_planes_with_default_values(category, canvas_fill_values)?;
+                    }
+                    Category::Gainmap => {
+                        self.gainmap.image.width = overlay.width;
+                        self.gainmap.image.height = overlay.height;
+                        self.gainmap
+                            .image
+                            .copy_properties_from(&tile.image, &tile.codec_config);
+                        self.gainmap
+                            .image
+                            .allocate_planes_with_default_values(category, canvas_fill_values)?;
+                    }
+                }
+            }
             if !tiles_slice1.is_empty() {
                 let first_tile_image = &tiles_slice1[0].image;
                 if tile.image.width != first_tile_image.width
@@ -1425,19 +1489,19 @@ impl Decoder {
                     || tile.image.matrix_coefficients != first_tile_image.matrix_coefficients
                 {
                     return Err(AvifError::InvalidImageGrid(
-                        "grid image contains mismatched tiles".into(),
+                        "overlay image contains mismatched tiles".into(),
                     ));
                 }
             }
             match category {
-                Category::Gainmap => self.gainmap.image.copy_from_tile(
+                Category::Gainmap => self.gainmap.image.copy_and_overlay_from_tile(
                     &tile.image,
                     &self.tile_info[category.usize()],
                     tile_index as u32,
                     category,
                 )?,
                 _ => {
-                    self.image.copy_from_tile(
+                    self.image.copy_and_overlay_from_tile(
                         &tile.image,
                         &self.tile_info[category.usize()],
                         tile_index as u32,
@@ -1446,44 +1510,129 @@ impl Decoder {
                 }
             }
         } else {
-            // Non grid path, steal or copy planes from the only tile.
+            // Non grid/overlay path, steal or copy planes from the only tile.
             match category {
                 Category::Color => {
                     self.image.width = tile.image.width;
                     self.image.height = tile.image.height;
-                    self.image.depth = tile.image.depth;
-                    self.image.yuv_format = tile.image.yuv_format;
-                    self.image.steal_or_copy_from(&tile.image, category)?;
+                    self.image
+                        .copy_properties_from(&tile.image, &tile.codec_config);
+                    self.image
+                        .steal_or_copy_planes_from(&tile.image, category)?;
                 }
                 Category::Alpha => {
                     if !self.image.has_same_properties(&tile.image) {
                         return Err(AvifError::DecodeAlphaFailed);
                     }
-                    self.image.steal_or_copy_from(&tile.image, category)?;
+                    self.image
+                        .steal_or_copy_planes_from(&tile.image, category)?;
                 }
                 Category::Gainmap => {
                     self.gainmap.image.width = tile.image.width;
                     self.gainmap.image.height = tile.image.height;
-                    self.gainmap.image.depth = tile.image.depth;
-                    self.gainmap.image.yuv_format = tile.image.yuv_format;
                     self.gainmap
                         .image
-                        .steal_or_copy_from(&tile.image, category)?;
+                        .copy_properties_from(&tile.image, &tile.codec_config);
+                    self.gainmap
+                        .image
+                        .steal_or_copy_planes_from(&tile.image, category)?;
                 }
             }
         }
         Ok(())
     }
 
+    fn decode_grid(&mut self, image_index: usize, category: Category) -> AvifResult<()> {
+        let tile_count = self.tiles[category.usize()].len();
+        if tile_count == 0 {
+            return Ok(());
+        }
+        let previous_decoded_tile_count =
+            self.tile_info[category.usize()].decoded_tile_count as usize;
+        let mut payloads = vec![];
+        for tile_index in previous_decoded_tile_count..tile_count {
+            let tile = &self.tiles[category.usize()][tile_index];
+            let sample = &tile.input.samples[image_index];
+            let item_data_buffer = if sample.item_id == 0 {
+                &None
+            } else {
+                &self.items.get(&sample.item_id).unwrap().data_buffer
+            };
+            let io = &mut self.io.unwrap_mut();
+            let data = sample.data(io, item_data_buffer)?;
+            payloads.push(data.to_vec());
+        }
+        let grid = &self.tile_info[category.usize()].grid;
+        if checked_mul!(grid.rows, grid.columns)? != payloads.len() as u32 {
+            return Err(AvifError::InvalidArgument);
+        }
+        let first_tile = &self.tiles[category.usize()][previous_decoded_tile_count];
+        let mut grid_image_helper = GridImageHelper {
+            grid,
+            image: if category == Category::Gainmap {
+                &mut self.gainmap.image
+            } else {
+                &mut self.image
+            },
+            category,
+            cell_index: 0,
+            codec_config: &first_tile.codec_config,
+            first_cell_image: None,
+            tile_width: first_tile.width,
+            tile_height: first_tile.height,
+        };
+        let codec = &mut self.codecs[first_tile.codec_index];
+        let next_image_result = codec.get_next_image_grid(
+            &payloads,
+            first_tile.input.samples[image_index].spatial_id,
+            &mut grid_image_helper,
+        );
+        if next_image_result.is_err() {
+            if cfg!(feature = "android_mediacodec")
+                && cfg!(feature = "heic")
+                && first_tile.codec_config.is_heic()
+                && category == Category::Alpha
+            {
+                // When decoding HEIC on Android, if the alpha channel decoding fails, simply
+                // ignore it and return the rest of the image.
+            } else {
+                return next_image_result;
+            }
+        }
+        if !grid_image_helper.is_grid_complete()? {
+            return Err(AvifError::UnknownError(
+                "codec did not decode all cells".into(),
+            ));
+        }
+        checked_incr!(
+            self.tile_info[category.usize()].decoded_tile_count,
+            u32_from_usize(payloads.len())?
+        );
+        Ok(())
+    }
+
     fn decode_tiles(&mut self, image_index: usize) -> AvifResult<()> {
         let mut decoded_something = false;
         for category in self.settings.image_content_to_decode.categories() {
-            let previous_decoded_tile_count =
-                self.tile_info[category.usize()].decoded_tile_count as usize;
             let tile_count = self.tiles[category.usize()].len();
-            for tile_index in previous_decoded_tile_count..tile_count {
-                self.decode_tile(image_index, category, tile_index)?;
+            if tile_count == 0 {
+                continue;
+            }
+            let first_tile = &self.tiles[category.usize()][0];
+            let codec = self.codecs[first_tile.codec_index].codec();
+            if codec == CodecChoice::MediaCodec
+                && !self.settings.allow_incremental
+                && self.tile_info[category.usize()].is_grid()
+            {
+                self.decode_grid(image_index, category)?;
                 decoded_something = true;
+            } else {
+                let previous_decoded_tile_count =
+                    self.tile_info[category.usize()].decoded_tile_count as usize;
+                for tile_index in previous_decoded_tile_count..tile_count {
+                    self.decode_tile(image_index, category, tile_index)?;
+                    decoded_something = true;
+                }
             }
         }
         if decoded_something {
@@ -1570,8 +1719,10 @@ impl Decoder {
         if !self.parsing_complete() {
             return Err(AvifError::NoContent);
         }
-        if n > self.settings.image_count_limit {
-            return Err(AvifError::NoImagesRemaining);
+        if let Some(limit) = self.settings.image_count_limit {
+            if n > limit.get() {
+                return Err(AvifError::NoImagesRemaining);
+            }
         }
         if self.color_track_id.is_none() {
             return Ok(self.image_timing);
@@ -1582,6 +1733,9 @@ impl Decoder {
             .iter()
             .find(|x| x.id == color_track_id)
             .ok_or(AvifError::NoContent)?;
+        if color_track.sample_table.is_none() {
+            return Ok(self.image_timing);
+        }
         color_track.image_timing(n)
     }
 
diff --git a/src/decoder/tile.rs b/src/decoder/tile.rs
index cc8c47d..4dd1776 100644
--- a/src/decoder/tile.rs
+++ b/src/decoder/tile.rs
@@ -15,7 +15,7 @@
 use crate::decoder::*;
 use crate::*;
 
-pub const MAX_AV1_LAYER_COUNT: usize = 4;
+use std::num::NonZero;
 
 #[derive(Debug, Default)]
 pub struct DecodeSample {
@@ -27,7 +27,7 @@ pub struct DecodeSample {
 }
 
 impl DecodeSample {
-    pub fn partial_data<'a>(
+    pub(crate) fn partial_data<'a>(
         &'a self,
         io: &'a mut Box<impl decoder::IO + ?Sized>,
         buffer: &'a Option<Vec<u8>>,
@@ -52,7 +52,7 @@ impl DecodeSample {
         }
     }
 
-    pub fn data<'a>(
+    pub(crate) fn data<'a>(
         &'a self,
         io: &'a mut Box<impl decoder::IO + ?Sized>,
         buffer: &'a Option<Vec<u8>>,
@@ -68,27 +68,37 @@ pub struct DecodeInput {
     pub category: Category,
 }
 
-#[derive(Clone, Copy, Debug, Default)]
-pub struct Grid {
-    pub rows: u32,
-    pub columns: u32,
+#[derive(Debug, Default)]
+pub struct Overlay {
+    pub canvas_fill_value: [u16; 4],
     pub width: u32,
     pub height: u32,
+    pub horizontal_offsets: Vec<i32>,
+    pub vertical_offsets: Vec<i32>,
 }
 
 #[derive(Debug, Default)]
-pub struct TileInfo {
+pub(crate) struct TileInfo {
     pub tile_count: u32,
     pub decoded_tile_count: u32,
     pub grid: Grid,
+    pub overlay: Overlay,
 }
 
 impl TileInfo {
-    pub fn is_grid(&self) -> bool {
+    pub(crate) fn is_grid(&self) -> bool {
         self.grid.rows > 0 && self.grid.columns > 0
     }
 
-    pub fn grid_tile_count(&self) -> AvifResult<u32> {
+    pub(crate) fn is_overlay(&self) -> bool {
+        !self.overlay.horizontal_offsets.is_empty() && !self.overlay.vertical_offsets.is_empty()
+    }
+
+    pub(crate) fn is_derived_image(&self) -> bool {
+        self.is_grid() || self.is_overlay()
+    }
+
+    pub(crate) fn grid_tile_count(&self) -> AvifResult<u32> {
         if self.is_grid() {
             checked_mul!(self.grid.rows, self.grid.columns)
         } else {
@@ -96,7 +106,7 @@ impl TileInfo {
         }
     }
 
-    pub fn decoded_row_count(&self, image_height: u32, tile_height: u32) -> u32 {
+    pub(crate) fn decoded_row_count(&self, image_height: u32, tile_height: u32) -> u32 {
         if self.decoded_tile_count == 0 {
             return 0;
         }
@@ -109,7 +119,7 @@ impl TileInfo {
         )
     }
 
-    pub fn is_fully_decoded(&self) -> bool {
+    pub(crate) fn is_fully_decoded(&self) -> bool {
         self.tile_count == self.decoded_tile_count
     }
 }
@@ -126,10 +136,10 @@ pub struct Tile {
 }
 
 impl Tile {
-    pub fn create_from_item(
+    pub(crate) fn create_from_item(
         item: &mut Item,
         allow_progressive: bool,
-        image_count_limit: u32,
+        image_count_limit: Option<NonZero<u32>>,
         size_hint: u64,
     ) -> AvifResult<Tile> {
         if size_hint != 0 && item.size as u64 > size_hint {
@@ -225,10 +235,12 @@ impl Tile {
         } else if item.progressive && allow_progressive {
             // Progressive image. Decode all layers and expose them all to the
             // user.
-            if image_count_limit != 0 && layer_count as u32 > image_count_limit {
-                return Err(AvifError::BmffParseFailed(
-                    "exceeded image_count_limit (progressive)".into(),
-                ));
+            if let Some(limit) = image_count_limit {
+                if layer_count as u32 > limit.get() {
+                    return Err(AvifError::BmffParseFailed(
+                        "exceeded image_count_limit (progressive)".into(),
+                    ));
+                }
             }
             tile.input.all_layers = true;
             let mut offset = 0;
@@ -259,12 +271,18 @@ impl Tile {
         Ok(tile)
     }
 
-    pub fn create_from_track(
+    pub(crate) fn create_from_track(
         track: &Track,
-        mut image_count_limit: u32,
+        image_count_limit: Option<NonZero<u32>>,
         size_hint: u64,
         category: Category,
     ) -> AvifResult<Tile> {
+        let properties = track
+            .get_properties()
+            .ok_or(AvifError::BmffParseFailed("".into()))?;
+        let codec_config = find_property!(properties, CodecConfiguration)
+            .ok_or(AvifError::BmffParseFailed("".into()))?
+            .clone();
         let mut tile = Tile {
             width: track.width,
             height: track.height,
@@ -273,11 +291,13 @@ impl Tile {
                 category,
                 ..DecodeInput::default()
             },
+            codec_config,
             ..Tile::default()
         };
         let sample_table = &track.sample_table.unwrap_ref();
 
-        if image_count_limit != 0 {
+        if let Some(limit) = image_count_limit {
+            let mut limit = limit.get();
             for (chunk_index, _chunk_offset) in sample_table.chunk_offsets.iter().enumerate() {
                 // Figure out how many samples are in this chunk.
                 let sample_count = sample_table.get_sample_count_of_chunk(chunk_index as u32);
@@ -286,12 +306,12 @@ impl Tile {
                         "chunk with 0 samples found".into(),
                     ));
                 }
-                if sample_count > image_count_limit {
+                if sample_count > limit {
                     return Err(AvifError::BmffParseFailed(
                         "exceeded image_count_limit".into(),
                     ));
                 }
-                image_count_limit -= sample_count;
+                limit -= sample_count;
             }
         }
 
@@ -341,7 +361,7 @@ impl Tile {
         Ok(tile)
     }
 
-    pub fn max_sample_size(&self) -> usize {
+    pub(crate) fn max_sample_size(&self) -> usize {
         match self.input.samples.iter().max_by_key(|sample| sample.size) {
             Some(sample) => sample.size,
             None => 0,
diff --git a/src/decoder/track.rs b/src/decoder/track.rs
index 718657a..f4b3eed 100644
--- a/src/decoder/track.rs
+++ b/src/decoder/track.rs
@@ -17,6 +17,8 @@ use crate::parser::mp4box::ItemProperty;
 use crate::parser::mp4box::MetaBox;
 use crate::*;
 
+use std::num::NonZero;
+
 #[derive(Clone, Copy, Debug, PartialEq)]
 pub enum RepetitionCount {
     Unknown,
@@ -45,10 +47,15 @@ pub struct Track {
     pub sample_table: Option<SampleTable>,
     pub elst_seen: bool,
     pub meta: Option<MetaBox>,
+    pub handler_type: String,
 }
 
 impl Track {
-    pub fn check_limits(&self, size_limit: u32, dimension_limit: u32) -> bool {
+    pub(crate) fn check_limits(
+        &self,
+        size_limit: Option<NonZero<u32>>,
+        dimension_limit: Option<NonZero<u32>>,
+    ) -> bool {
         check_limits(self.width, self.height, size_limit, dimension_limit)
     }
 
@@ -59,18 +66,36 @@ impl Track {
             false
         }
     }
-    pub fn is_aux(&self, primary_track_id: u32) -> bool {
+    pub(crate) fn is_video_handler(&self) -> bool {
+        // Handler types known to be associated with video content.
+        self.handler_type == "pict" || self.handler_type == "vide" || self.handler_type == "auxv"
+    }
+    pub(crate) fn is_aux(&self, primary_track_id: u32) -> bool {
+        // Do not check the track's handler_type. It should be "auxv" according to
+        // HEIF (ISO/IEC 23008-12:2022), Section 7.5.3.1, but old versions of libavif used to write
+        // "pict" instead.
         self.has_av1_samples() && self.aux_for_id == Some(primary_track_id)
     }
-    pub fn is_color(&self) -> bool {
+    pub(crate) fn is_color(&self) -> bool {
+        // Do not check the track's handler_type. It should be "pict" according to
+        // HEIF (ISO/IEC 23008-12:2022), Section 7 but some existing files might be using "vide".
         self.has_av1_samples() && self.aux_for_id.is_none()
     }
 
-    pub fn get_properties(&self) -> Option<&Vec<ItemProperty>> {
+    pub(crate) fn is_auxiliary_alpha(&self) -> bool {
+        if let Some(properties) = self.get_properties() {
+            if let Some(aux_type) = &find_property!(properties, AuxiliaryType) {
+                return is_auxiliary_type_alpha(aux_type);
+            }
+        }
+        true // Assume alpha if no type is present
+    }
+
+    pub(crate) fn get_properties(&self) -> Option<&Vec<ItemProperty>> {
         self.sample_table.as_ref()?.get_properties()
     }
 
-    pub fn repetition_count(&self) -> AvifResult<RepetitionCount> {
+    pub(crate) fn repetition_count(&self) -> AvifResult<RepetitionCount> {
         if !self.elst_seen {
             return Ok(RepetitionCount::Unknown);
         }
@@ -104,8 +129,8 @@ impl Track {
         Ok(RepetitionCount::Finite(0))
     }
 
-    pub fn image_timing(&self, image_index: u32) -> AvifResult<ImageTiming> {
-        let sample_table = self.sample_table.as_ref().ok_or(AvifError::NoContent)?;
+    pub(crate) fn image_timing(&self, image_index: u32) -> AvifResult<ImageTiming> {
+        let sample_table = self.sample_table.unwrap_ref();
         let mut image_timing = ImageTiming {
             timescale: self.media_timescale as u64,
             pts_in_timescales: 0,
@@ -152,6 +177,17 @@ pub struct SampleDescription {
     pub properties: Vec<ItemProperty>,
 }
 
+impl SampleDescription {
+    pub(crate) fn is_supported_format(&self) -> bool {
+        [
+            "av01",
+            #[cfg(feature = "heic")]
+            "hvc1",
+        ]
+        .contains(&self.format.as_str())
+    }
+}
+
 #[derive(Debug)]
 pub enum SampleSize {
     FixedSize(u32),
@@ -175,12 +211,14 @@ pub struct SampleTable {
 }
 
 impl SampleTable {
-    pub fn has_av1_sample(&self) -> bool {
-        self.sample_descriptions.iter().any(|x| x.format == "av01")
+    pub(crate) fn has_av1_sample(&self) -> bool {
+        self.sample_descriptions
+            .iter()
+            .any(|x| x.is_supported_format())
     }
 
     // returns the number of samples in the chunk.
-    pub fn get_sample_count_of_chunk(&self, chunk_index: u32) -> u32 {
+    pub(crate) fn get_sample_count_of_chunk(&self, chunk_index: u32) -> u32 {
         for entry in self.sample_to_chunk.iter().rev() {
             if entry.first_chunk <= chunk_index + 1 {
                 return entry.samples_per_chunk;
@@ -189,17 +227,17 @@ impl SampleTable {
         0
     }
 
-    pub fn get_properties(&self) -> Option<&Vec<ItemProperty>> {
+    pub(crate) fn get_properties(&self) -> Option<&Vec<ItemProperty>> {
         Some(
             &self
                 .sample_descriptions
                 .iter()
-                .find(|x| x.format == "av01")?
+                .find(|x| x.is_supported_format())?
                 .properties,
         )
     }
 
-    pub fn sample_size(&self, index: usize) -> AvifResult<usize> {
+    pub(crate) fn sample_size(&self, index: usize) -> AvifResult<usize> {
         usize_from_u32(match &self.sample_size {
             SampleSize::FixedSize(size) => *size,
             SampleSize::Sizes(sizes) => {
@@ -213,7 +251,7 @@ impl SampleTable {
         })
     }
 
-    pub fn image_delta(&self, index: usize) -> AvifResult<u32> {
+    pub(crate) fn image_delta(&self, index: usize) -> AvifResult<u32> {
         let mut max_index: u32 = 0;
         for (i, time_to_sample) in self.time_to_sample.iter().enumerate() {
             checked_incr!(max_index, time_to_sample.sample_count);
diff --git a/src/image.rs b/src/image.rs
index 14dee70..a7edf63 100644
--- a/src/image.rs
+++ b/src/image.rs
@@ -13,11 +13,11 @@
 // limitations under the License.
 
 use crate::decoder::tile::TileInfo;
-use crate::decoder::Category;
 use crate::decoder::ProgressiveState;
 use crate::internal_utils::pixels::*;
 use crate::internal_utils::*;
-use crate::parser::mp4box::*;
+use crate::parser::mp4box::CodecConfiguration;
+use crate::reformat::coeffs::*;
 use crate::utils::clap::CleanAperture;
 use crate::*;
 
@@ -41,7 +41,7 @@ impl From<usize> for Plane {
 }
 
 impl Plane {
-    pub fn to_usize(&self) -> usize {
+    pub(crate) fn as_usize(&self) -> usize {
         match self {
             Plane::Y => 0,
             Plane::U => 1,
@@ -116,7 +116,34 @@ pub enum PlaneRow<'a> {
 }
 
 impl Image {
-    pub fn depth_valid(&self) -> bool {
+    pub(crate) fn shallow_clone(&self) -> Self {
+        Self {
+            width: self.width,
+            height: self.height,
+            depth: self.depth,
+            yuv_format: self.yuv_format,
+            yuv_range: self.yuv_range,
+            chroma_sample_position: self.chroma_sample_position,
+            alpha_present: self.alpha_present,
+            alpha_premultiplied: self.alpha_premultiplied,
+            color_primaries: self.color_primaries,
+            transfer_characteristics: self.transfer_characteristics,
+            matrix_coefficients: self.matrix_coefficients,
+            clli: self.clli,
+            pasp: self.pasp,
+            clap: self.clap,
+            irot_angle: self.irot_angle,
+            imir_axis: self.imir_axis,
+            exif: self.exif.clone(),
+            icc: self.icc.clone(),
+            xmp: self.xmp.clone(),
+            image_sequence_track_present: self.image_sequence_track_present,
+            progressive_state: self.progressive_state,
+            ..Default::default()
+        }
+    }
+
+    pub(crate) fn depth_valid(&self) -> bool {
         matches!(self.depth, 8 | 10 | 12 | 16)
     }
 
@@ -128,12 +155,12 @@ impl Image {
         }
     }
 
-    pub fn max_channel_f(&self) -> f32 {
+    pub(crate) fn max_channel_f(&self) -> f32 {
         self.max_channel() as f32
     }
 
     pub fn has_plane(&self, plane: Plane) -> bool {
-        let plane_index = plane.to_usize();
+        let plane_index = plane.as_usize();
         if self.planes[plane_index].is_none() || self.row_bytes[plane_index] == 0 {
             return false;
         }
@@ -144,10 +171,24 @@ impl Image {
         self.has_plane(Plane::A)
     }
 
-    pub fn has_same_properties(&self, other: &Image) -> bool {
+    pub(crate) fn has_same_properties(&self, other: &Image) -> bool {
         self.width == other.width && self.height == other.height && self.depth == other.depth
     }
 
+    fn has_same_cicp(&self, other: &Image) -> bool {
+        self.depth == other.depth
+            && self.yuv_format == other.yuv_format
+            && self.yuv_range == other.yuv_range
+            && self.chroma_sample_position == other.chroma_sample_position
+            && self.color_primaries == other.color_primaries
+            && self.transfer_characteristics == other.transfer_characteristics
+            && self.matrix_coefficients == other.matrix_coefficients
+    }
+
+    pub(crate) fn has_same_properties_and_cicp(&self, other: &Image) -> bool {
+        self.has_same_properties(other) && self.has_same_cicp(other)
+    }
+
     pub fn width(&self, plane: Plane) -> usize {
         match plane {
             Plane::Y | Plane::A => self.width as usize,
@@ -201,7 +242,7 @@ impl Image {
         Some(PlaneData {
             width: self.width(plane) as u32,
             height: self.height(plane) as u32,
-            row_bytes: self.row_bytes[plane.to_usize()],
+            row_bytes: self.row_bytes[plane.as_usize()],
             pixel_size: if self.depth == 8 { 1 } else { 2 },
         })
     }
@@ -209,7 +250,7 @@ impl Image {
     pub fn row(&self, plane: Plane, row: u32) -> AvifResult<&[u8]> {
         let plane_data = self.plane_data(plane).ok_or(AvifError::NoContent)?;
         let start = checked_mul!(row, plane_data.row_bytes)?;
-        self.planes[plane.to_usize()]
+        self.planes[plane.as_usize()]
             .unwrap_ref()
             .slice(start, plane_data.row_bytes)
     }
@@ -218,7 +259,7 @@ impl Image {
         let plane_data = self.plane_data(plane).ok_or(AvifError::NoContent)?;
         let row_bytes = plane_data.row_bytes;
         let start = checked_mul!(row, row_bytes)?;
-        self.planes[plane.to_usize()]
+        self.planes[plane.as_usize()]
             .unwrap_mut()
             .slice_mut(start, row_bytes)
     }
@@ -227,7 +268,7 @@ impl Image {
         let plane_data = self.plane_data(plane).ok_or(AvifError::NoContent)?;
         let row_bytes = plane_data.row_bytes / 2;
         let start = checked_mul!(row, row_bytes)?;
-        self.planes[plane.to_usize()]
+        self.planes[plane.as_usize()]
             .unwrap_ref()
             .slice16(start, row_bytes)
     }
@@ -236,12 +277,12 @@ impl Image {
         let plane_data = self.plane_data(plane).ok_or(AvifError::NoContent)?;
         let row_bytes = plane_data.row_bytes / 2;
         let start = checked_mul!(row, row_bytes)?;
-        self.planes[plane.to_usize()]
+        self.planes[plane.as_usize()]
             .unwrap_mut()
             .slice16_mut(start, row_bytes)
     }
 
-    pub fn row_generic(&self, plane: Plane, row: u32) -> AvifResult<PlaneRow> {
+    pub(crate) fn row_generic(&self, plane: Plane, row: u32) -> AvifResult<PlaneRow> {
         Ok(if self.depth == 8 {
             PlaneRow::Depth8(self.row(plane, row)?)
         } else {
@@ -249,23 +290,27 @@ impl Image {
         })
     }
 
-    pub fn clear_chroma_planes(&mut self) {
+    #[cfg(any(feature = "dav1d", feature = "libgav1"))]
+    pub(crate) fn clear_chroma_planes(&mut self) {
         for plane in [Plane::U, Plane::V] {
-            let plane = plane.to_usize();
+            let plane = plane.as_usize();
             self.planes[plane] = None;
             self.row_bytes[plane] = 0;
             self.image_owns_planes[plane] = false;
         }
     }
 
-    pub fn allocate_planes(&mut self, category: Category) -> AvifResult<()> {
+    pub(crate) fn allocate_planes_with_default_values(
+        &mut self,
+        category: Category,
+        default_values: [u16; 4],
+    ) -> AvifResult<()> {
         let pixel_size: usize = if self.depth == 8 { 1 } else { 2 };
         for plane in category.planes() {
             let plane = *plane;
-            let plane_index = plane.to_usize();
-            let width = self.width(plane);
-            let plane_size = checked_mul!(width, self.height(plane))?;
-            let default_value = if plane == Plane::A { self.max_channel() } else { 0 };
+            let plane_index = plane.as_usize();
+            let width = round2_usize(self.width(plane));
+            let plane_size = checked_mul!(width, round2_usize(self.height(plane)))?;
             if self.planes[plane_index].is_some()
                 && self.planes[plane_index].unwrap_ref().size() == plane_size
                 && (self.planes[plane_index].unwrap_ref().pixel_bit_size() == 0
@@ -279,37 +324,62 @@ impl Image {
                 Pixels::Buffer16(Vec::new())
             });
             let pixels = self.planes[plane_index].unwrap_mut();
-            pixels.resize(plane_size, default_value)?;
+            pixels.resize(plane_size, default_values[plane_index])?;
             self.row_bytes[plane_index] = u32_from_usize(checked_mul!(width, pixel_size)?)?;
             self.image_owns_planes[plane_index] = true;
         }
         Ok(())
     }
 
+    pub(crate) fn allocate_planes(&mut self, category: Category) -> AvifResult<()> {
+        self.allocate_planes_with_default_values(category, [0, 0, 0, self.max_channel()])
+    }
+
+    pub(crate) fn copy_properties_from(
+        &mut self,
+        image: &Image,
+        codec_config: &CodecConfiguration,
+    ) {
+        self.yuv_format = image.yuv_format;
+        self.depth = image.depth;
+        if cfg!(feature = "heic") && codec_config.is_heic() {
+            // For AVIF, the information in the `colr` box takes precedence over what is reported
+            // by the decoder. For HEIC, we always honor what is reported by the decoder.
+            self.yuv_range = image.yuv_range;
+            self.color_primaries = image.color_primaries;
+            self.transfer_characteristics = image.transfer_characteristics;
+            self.matrix_coefficients = image.matrix_coefficients;
+        }
+    }
+
     // If src contains pointers, this function will simply make a copy of the pointer without
     // copying the actual pixels (stealing). If src contains buffer, this function will clone the
     // buffers (copying).
-    pub fn steal_or_copy_from(&mut self, src: &Image, category: Category) -> AvifResult<()> {
+    pub(crate) fn steal_or_copy_planes_from(
+        &mut self,
+        src: &Image,
+        category: Category,
+    ) -> AvifResult<()> {
         for plane in category.planes() {
-            let plane = plane.to_usize();
+            let plane = plane.as_usize();
             (self.planes[plane], self.row_bytes[plane]) = match &src.planes[plane] {
-                Some(src_plane) => (Some(src_plane.clone()), src.row_bytes[plane]),
+                Some(src_plane) => (Some(src_plane.try_clone()?), src.row_bytes[plane]),
                 None => (None, 0),
             }
         }
         Ok(())
     }
 
-    pub fn copy_from_tile(
+    pub(crate) fn copy_from_tile(
         &mut self,
         tile: &Image,
-        tile_info: &TileInfo,
+        grid: &Grid,
         tile_index: u32,
         category: Category,
     ) -> AvifResult<()> {
         // This function is used only when |tile| contains pointers and self contains buffers.
-        let row_index = tile_index / tile_info.grid.columns;
-        let column_index = tile_index % tile_info.grid.columns;
+        let row_index = tile_index / grid.columns;
+        let column_index = tile_index % grid.columns;
         for plane in category.planes() {
             let plane = *plane;
             let src_plane = tile.plane_data(plane);
@@ -318,7 +388,7 @@ impl Image {
             }
             let src_plane = src_plane.unwrap();
             // If this is the last tile column, clamp to left over width.
-            let src_width_to_copy = if column_index == tile_info.grid.columns - 1 {
+            let src_width_to_copy = if column_index == grid.columns - 1 {
                 let width_so_far = checked_mul!(src_plane.width, column_index)?;
                 checked_sub!(self.width(plane), usize_from_u32(width_so_far)?)?
             } else {
@@ -326,7 +396,7 @@ impl Image {
             };
 
             // If this is the last tile row, clamp to left over height.
-            let src_height_to_copy = if row_index == tile_info.grid.rows - 1 {
+            let src_height_to_copy = if row_index == grid.rows - 1 {
                 let height_so_far = checked_mul!(src_plane.height, row_index)?;
                 checked_sub!(u32_from_usize(self.height(plane))?, height_so_far)?
             } else {
@@ -356,4 +426,133 @@ impl Image {
         }
         Ok(())
     }
+
+    pub(crate) fn copy_and_overlay_from_tile(
+        &mut self,
+        tile: &Image,
+        tile_info: &TileInfo,
+        tile_index: u32,
+        category: Category,
+    ) -> AvifResult<()> {
+        // This function is used only when |tile| contains pointers and self contains buffers.
+        for plane in category.planes() {
+            let plane = *plane;
+            let src_plane = tile.plane_data(plane);
+            let dst_plane = self.plane_data(plane);
+            if src_plane.is_none() || dst_plane.is_none() {
+                continue;
+            }
+            let dst_plane = dst_plane.unwrap();
+            let tile_index = usize_from_u32(tile_index)?;
+
+            let vertical_offset = tile_info.overlay.vertical_offsets[tile_index] as i128;
+            let horizontal_offset = tile_info.overlay.horizontal_offsets[tile_index] as i128;
+            let src_height = tile.height as i128;
+            let src_width = tile.width as i128;
+            let dst_height = dst_plane.height as i128;
+            let dst_width = dst_plane.width as i128;
+
+            if matches!(plane, Plane::Y | Plane::A)
+                && (vertical_offset + src_height < 0
+                    || horizontal_offset + src_width < 0
+                    || vertical_offset >= dst_height
+                    || horizontal_offset >= dst_width)
+            {
+                // Entire tile outside of the canvas. It is sufficient to perform this check only
+                // for Y and A plane since they are never sub-sampled.
+                return Ok(());
+            }
+
+            let mut src_y_start: u32;
+            let mut src_height_to_copy: u32;
+            let mut dst_y_start: u32;
+            if vertical_offset >= 0 {
+                src_y_start = 0;
+                src_height_to_copy = src_height as u32;
+                dst_y_start = vertical_offset as u32;
+            } else {
+                src_y_start = vertical_offset.unsigned_abs() as u32;
+                src_height_to_copy = (src_height - vertical_offset.abs()) as u32;
+                dst_y_start = 0;
+            }
+
+            let mut src_x_start: u32;
+            let mut src_width_to_copy: u32;
+            let mut dst_x_start: u32;
+            if horizontal_offset >= 0 {
+                src_x_start = 0;
+                src_width_to_copy = src_width as u32;
+                dst_x_start = horizontal_offset as u32;
+            } else {
+                src_x_start = horizontal_offset.unsigned_abs() as u32;
+                src_width_to_copy = (src_width - horizontal_offset.abs()) as u32;
+                dst_x_start = 0;
+            }
+
+            // Clamp width to the canvas width.
+            if self.width - dst_x_start < src_width_to_copy {
+                src_width_to_copy = self.width - dst_x_start;
+            }
+
+            // Clamp height to the canvas height.
+            if self.height - dst_y_start < src_height_to_copy {
+                src_height_to_copy = self.height - dst_y_start;
+            }
+
+            // Apply chroma subsampling to the offsets.
+            if plane == Plane::U || plane == Plane::V {
+                src_y_start = tile.yuv_format.apply_chroma_shift_y(src_y_start);
+                src_height_to_copy = tile.yuv_format.apply_chroma_shift_y(src_height_to_copy);
+                dst_y_start = tile.yuv_format.apply_chroma_shift_y(dst_y_start);
+                src_x_start = tile.yuv_format.apply_chroma_shift_x(src_x_start);
+                src_width_to_copy = tile.yuv_format.apply_chroma_shift_x(src_width_to_copy);
+                dst_x_start = tile.yuv_format.apply_chroma_shift_x(dst_x_start);
+            }
+
+            let src_y_range = src_y_start..checked_add!(src_y_start, src_height_to_copy)?;
+            let dst_x_range = usize_from_u32(dst_x_start)?
+                ..usize_from_u32(checked_add!(dst_x_start, src_width_to_copy)?)?;
+            let src_x_range = usize_from_u32(src_x_start)?
+                ..checked_add!(usize_from_u32(src_x_start)?, dst_x_range.len())?;
+            let mut dst_y = dst_y_start;
+            if self.depth == 8 {
+                for src_y in src_y_range {
+                    let src_row = tile.row(plane, src_y)?;
+                    let src_slice = &src_row[src_x_range.clone()];
+                    let dst_row = self.row_mut(plane, dst_y)?;
+                    let dst_slice = &mut dst_row[dst_x_range.clone()];
+                    dst_slice.copy_from_slice(src_slice);
+                    checked_incr!(dst_y, 1);
+                }
+            } else {
+                for src_y in src_y_range {
+                    let src_row = tile.row16(plane, src_y)?;
+                    let src_slice = &src_row[src_x_range.clone()];
+                    let dst_row = self.row16_mut(plane, dst_y)?;
+                    let dst_slice = &mut dst_row[dst_x_range.clone()];
+                    dst_slice.copy_from_slice(src_slice);
+                    checked_incr!(dst_y, 1);
+                }
+            }
+        }
+        Ok(())
+    }
+
+    pub(crate) fn convert_rgba16_to_yuva(&self, rgba: [u16; 4]) -> [u16; 4] {
+        let r = rgba[0] as f32 / 65535.0;
+        let g = rgba[1] as f32 / 65535.0;
+        let b = rgba[2] as f32 / 65535.0;
+        let coeffs = calculate_yuv_coefficients(self.color_primaries, self.matrix_coefficients);
+        let y = coeffs[0] * r + coeffs[1] * g + coeffs[2] * b;
+        let u = (b - y) / (2.0 * (1.0 - coeffs[2]));
+        let v = (r - y) / (2.0 * (1.0 - coeffs[0]));
+        let uv_bias = (1 << (self.depth - 1)) as f32;
+        let max_channel = self.max_channel_f();
+        [
+            (y * max_channel).clamp(0.0, max_channel) as u16,
+            (u * max_channel + uv_bias).clamp(0.0, max_channel) as u16,
+            (v * max_channel + uv_bias).clamp(0.0, max_channel) as u16,
+            ((rgba[3] as f32) / 65535.0 * max_channel).round() as u16,
+        ]
+    }
 }
diff --git a/src/internal_utils/mod.rs b/src/internal_utils/mod.rs
index 125537e..fa18899 100644
--- a/src/internal_utils/mod.rs
+++ b/src/internal_utils/mod.rs
@@ -17,23 +17,12 @@ pub mod pixels;
 pub mod stream;
 
 use crate::parser::mp4box::*;
+use crate::utils::*;
 use crate::*;
 
+use std::num::NonZero;
 use std::ops::Range;
 
-// Some HEIF fractional fields can be negative, hence Fraction and UFraction.
-// The denominator is always unsigned.
-
-/// cbindgen:field-names=[n,d]
-#[derive(Clone, Copy, Debug, Default)]
-#[repr(C)]
-pub struct Fraction(pub i32, pub u32);
-
-/// cbindgen:field-names=[n,d]
-#[derive(Clone, Copy, Debug, Default, PartialEq)]
-#[repr(C)]
-pub struct UFraction(pub u32, pub u32);
-
 // 'clap' fractions do not follow this pattern: both numerators and denominators
 // are used as i32, but they are signalled as u32 according to the specification
 // as of 2024. This may be fixed in later versions of the specification, see
@@ -61,13 +50,13 @@ impl IFraction {
         a as i32
     }
 
-    pub fn simplified(n: i32, d: i32) -> Self {
+    pub(crate) fn simplified(n: i32, d: i32) -> Self {
         let mut fraction = IFraction(n, d);
         fraction.simplify();
         fraction
     }
 
-    pub fn simplify(&mut self) {
+    pub(crate) fn simplify(&mut self) {
         let gcd = Self::gcd(self.0, self.1);
         if gcd > 1 {
             self.0 /= gcd;
@@ -75,16 +64,16 @@ impl IFraction {
         }
     }
 
-    pub fn get_i32(&self) -> i32 {
+    pub(crate) fn get_i32(&self) -> i32 {
         assert!(self.1 != 0);
         self.0 / self.1
     }
 
-    pub fn get_u32(&self) -> AvifResult<u32> {
+    pub(crate) fn get_u32(&self) -> AvifResult<u32> {
         u32_from_i32(self.get_i32())
     }
 
-    pub fn is_integer(&self) -> bool {
+    pub(crate) fn is_integer(&self) -> bool {
         self.0 % self.1 == 0
     }
 
@@ -113,7 +102,7 @@ impl IFraction {
         Ok(())
     }
 
-    pub fn add(&mut self, val: &IFraction) -> AvifResult<()> {
+    pub(crate) fn add(&mut self, val: &IFraction) -> AvifResult<()> {
         let mut val = *val;
         val.simplify();
         self.common_denominator(&mut val)?;
@@ -125,7 +114,7 @@ impl IFraction {
         Ok(())
     }
 
-    pub fn sub(&mut self, val: &IFraction) -> AvifResult<()> {
+    pub(crate) fn sub(&mut self, val: &IFraction) -> AvifResult<()> {
         let mut val = *val;
         val.simplify();
         self.common_denominator(&mut val)?;
@@ -140,7 +129,7 @@ impl IFraction {
 
 macro_rules! conversion_function {
     ($func:ident, $to: ident, $from:ty) => {
-        pub fn $func(value: $from) -> AvifResult<$to> {
+        pub(crate) fn $func(value: $from) -> AvifResult<$to> {
             $to::try_from(value).or(Err(AvifError::BmffParseFailed("".into())))
         }
     };
@@ -158,7 +147,7 @@ conversion_function!(u32_from_i32, u32, i32);
 conversion_function!(i32_from_u32, i32, u32);
 #[cfg(feature = "android_mediacodec")]
 conversion_function!(isize_from_i32, isize, i32);
-#[cfg(feature = "capi")]
+#[cfg(any(feature = "capi", feature = "android_mediacodec"))]
 conversion_function!(isize_from_u32, isize, u32);
 conversion_function!(isize_from_usize, isize, usize);
 #[cfg(feature = "android_mediacodec")]
@@ -166,7 +155,7 @@ conversion_function!(i32_from_usize, i32, usize);
 
 macro_rules! clamp_function {
     ($func:ident, $type:ty) => {
-        pub fn $func(value: $type, low: $type, high: $type) -> $type {
+        pub(crate) fn $func(value: $type, low: $type, high: $type) -> $type {
             if value < low {
                 low
             } else if value > high {
@@ -182,8 +171,33 @@ clamp_function!(clamp_u16, u16);
 clamp_function!(clamp_f32, f32);
 clamp_function!(clamp_i32, i32);
 
+macro_rules! round2_function {
+    ($func:ident, $type:ty) => {
+        pub(crate) fn $func(value: $type) -> $type {
+            if value % 2 == 0 {
+                value
+            } else {
+                value + 1
+            }
+        }
+    };
+}
+
+#[cfg(feature = "capi")]
+round2_function!(round2_u32, u32);
+round2_function!(round2_usize, usize);
+
+macro_rules! find_property {
+    ($properties:expr, $property_name:ident) => {
+        $properties.iter().find_map(|p| match p {
+            ItemProperty::$property_name(value) => Some(value.clone()),
+            _ => None,
+        })
+    };
+}
+
 // Returns the colr nclx property. Returns an error if there are multiple ones.
-pub fn find_nclx(properties: &[ItemProperty]) -> AvifResult<Option<&Nclx>> {
+pub(crate) fn find_nclx(properties: &[ItemProperty]) -> AvifResult<Option<&Nclx>> {
     let mut single_nclx: Option<&Nclx> = None;
     for property in properties {
         if let ItemProperty::ColorInformation(ColorInformation::Nclx(nclx)) = property {
@@ -199,7 +213,7 @@ pub fn find_nclx(properties: &[ItemProperty]) -> AvifResult<Option<&Nclx>> {
 }
 
 // Returns the colr icc property. Returns an error if there are multiple ones.
-pub fn find_icc(properties: &[ItemProperty]) -> AvifResult<Option<&Vec<u8>>> {
+pub(crate) fn find_icc(properties: &[ItemProperty]) -> AvifResult<Option<&Vec<u8>>> {
     let mut single_icc: Option<&Vec<u8>> = None;
     for property in properties {
         if let ItemProperty::ColorInformation(ColorInformation::Icc(icc)) = property {
@@ -212,15 +226,24 @@ pub fn find_icc(properties: &[ItemProperty]) -> AvifResult<Option<&Vec<u8>>> {
     Ok(single_icc)
 }
 
-pub fn check_limits(width: u32, height: u32, size_limit: u32, dimension_limit: u32) -> bool {
+pub(crate) fn check_limits(
+    width: u32,
+    height: u32,
+    size_limit: Option<NonZero<u32>>,
+    dimension_limit: Option<NonZero<u32>>,
+) -> bool {
     if height == 0 {
         return false;
     }
-    if width > size_limit / height {
-        return false;
+    if let Some(limit) = size_limit {
+        if width > limit.get() / height {
+            return false;
+        }
     }
-    if dimension_limit != 0 && (width > dimension_limit || height > dimension_limit) {
-        return false;
+    if let Some(limit) = dimension_limit {
+        if width > limit.get() || height > limit.get() {
+            return false;
+        }
     }
     true
 }
@@ -234,7 +257,7 @@ fn limited_to_full(min: i32, max: i32, full: i32, v: u16) -> u16 {
     ) as u16
 }
 
-pub fn limited_to_full_y(depth: u8, v: u16) -> u16 {
+pub(crate) fn limited_to_full_y(depth: u8, v: u16) -> u16 {
     match depth {
         8 => limited_to_full(16, 235, 255, v),
         10 => limited_to_full(64, 940, 1023, v),
@@ -243,7 +266,7 @@ pub fn limited_to_full_y(depth: u8, v: u16) -> u16 {
     }
 }
 
-pub fn create_vec_exact<T>(size: usize) -> AvifResult<Vec<T>> {
+pub(crate) fn create_vec_exact<T>(size: usize) -> AvifResult<Vec<T>> {
     let mut v = Vec::<T>::new();
     let allocation_size = size
         .checked_mul(std::mem::size_of::<T>())
@@ -264,16 +287,80 @@ pub fn create_vec_exact<T>(size: usize) -> AvifResult<Vec<T>> {
 }
 
 #[cfg(test)]
-pub fn assert_eq_f32_array(a: &[f32], b: &[f32]) {
+pub(crate) fn assert_eq_f32_array(a: &[f32], b: &[f32]) {
     assert_eq!(a.len(), b.len());
     for i in 0..a.len() {
         assert!((a[i] - b[i]).abs() <= std::f32::EPSILON);
     }
 }
 
-pub fn check_slice_range(len: usize, range: &Range<usize>) -> AvifResult<()> {
+pub(crate) fn check_slice_range(len: usize, range: &Range<usize>) -> AvifResult<()> {
     if range.start >= len || range.end > len {
         return Err(AvifError::NoContent);
     }
     Ok(())
 }
+
+pub(crate) fn is_auxiliary_type_alpha(aux_type: &str) -> bool {
+    aux_type == "urn:mpeg:mpegB:cicp:systems:auxiliary:alpha"
+        || aux_type == "urn:mpeg:hevc:2015:auxid:1"
+}
+
+pub(crate) fn validate_grid_image_dimensions(image: &Image, grid: &Grid) -> AvifResult<()> {
+    if checked_mul!(image.width, grid.columns)? < grid.width
+        || checked_mul!(image.height, grid.rows)? < grid.height
+    {
+        return Err(AvifError::InvalidImageGrid(
+                        "Grid image tiles do not completely cover the image (HEIF (ISO/IEC 23008-12:2017), Section 6.6.2.3.1)".into(),
+                    ));
+    }
+    if checked_mul!(image.width, grid.columns)? < grid.width
+        || checked_mul!(image.height, grid.rows)? < grid.height
+    {
+        return Err(AvifError::InvalidImageGrid(
+            "Grid image tiles do not completely cover the image (HEIF (ISO/IEC 23008-12:2017), \
+                    Section 6.6.2.3.1)"
+                .into(),
+        ));
+    }
+    if checked_mul!(image.width, grid.columns - 1)? >= grid.width
+        || checked_mul!(image.height, grid.rows - 1)? >= grid.height
+    {
+        return Err(AvifError::InvalidImageGrid(
+            "Grid image tiles in the rightmost column and bottommost row do not overlap the \
+                     reconstructed image grid canvas. See MIAF (ISO/IEC 23000-22:2019), Section \
+                     7.3.11.4.2, Figure 2"
+                .into(),
+        ));
+    }
+    // ISO/IEC 23000-22:2019, Section 7.3.11.4.2:
+    //   - the tile_width shall be greater than or equal to 64, and should be a multiple of 64
+    //   - the tile_height shall be greater than or equal to 64, and should be a multiple of 64
+    // The "should" part is ignored here.
+    if image.width < 64 || image.height < 64 {
+        return Err(AvifError::InvalidImageGrid(format!(
+            "Grid image tile width ({}) or height ({}) cannot be smaller than 64. See MIAF \
+                     (ISO/IEC 23000-22:2019), Section 7.3.11.4.2",
+            image.width, image.height
+        )));
+    }
+    // ISO/IEC 23000-22:2019, Section 7.3.11.4.2:
+    //   - when the images are in the 4:2:2 chroma sampling format the horizontal tile offsets
+    //     and widths, and the output width, shall be even numbers;
+    //   - when the images are in the 4:2:0 chroma sampling format both the horizontal and
+    //     vertical tile offsets and widths, and the output width and height, shall be even
+    //     numbers.
+    if ((image.yuv_format == PixelFormat::Yuv420 || image.yuv_format == PixelFormat::Yuv422)
+        && (grid.width % 2 != 0 || image.width % 2 != 0))
+        || (image.yuv_format == PixelFormat::Yuv420
+            && (grid.height % 2 != 0 || image.height % 2 != 0))
+    {
+        return Err(AvifError::InvalidImageGrid(format!(
+            "Grid image width ({}) or height ({}) or tile width ({}) or height ({}) shall be \
+                    even if chroma is subsampled in that dimension. See MIAF \
+                    (ISO/IEC 23000-22:2019), Section 7.3.11.4.2",
+            grid.width, grid.height, image.width, image.height
+        )));
+    }
+    Ok(())
+}
diff --git a/src/internal_utils/pixels.rs b/src/internal_utils/pixels.rs
index 59926b9..a0cd289 100644
--- a/src/internal_utils/pixels.rs
+++ b/src/internal_utils/pixels.rs
@@ -74,7 +74,9 @@ impl<T> PointerSlice<T> {
     }
 }
 
-#[derive(Clone, Debug)]
+// This struct must not be derived from the default `Clone` trait as it has to be cloned with error
+// checking using the `try_clone` function.
+#[derive(Debug)]
 pub enum Pixels {
     // Intended for holding data from underlying native libraries. Used for 8-bit images.
     Pointer(PointerSlice<u8>),
@@ -116,7 +118,7 @@ impl Pixels {
         }
     }
 
-    pub fn pixel_bit_size(&self) -> usize {
+    pub(crate) fn pixel_bit_size(&self) -> usize {
         match self {
             Pixels::Pointer(_) => 0,
             Pixels::Pointer16(_) => 0,
@@ -125,7 +127,7 @@ impl Pixels {
         }
     }
 
-    pub fn has_data(&self) -> bool {
+    pub(crate) fn has_data(&self) -> bool {
         match self {
             Pixels::Pointer(ptr) => !ptr.is_empty(),
             Pixels::Pointer16(ptr) => !ptr.is_empty(),
@@ -134,7 +136,7 @@ impl Pixels {
         }
     }
 
-    pub fn resize(&mut self, size: usize, default: u16) -> AvifResult<()> {
+    pub(crate) fn resize(&mut self, size: usize, default: u16) -> AvifResult<()> {
         match self {
             Pixels::Pointer(_) => return Err(AvifError::InvalidArgument),
             Pixels::Pointer16(_) => return Err(AvifError::InvalidArgument),
@@ -154,7 +156,7 @@ impl Pixels {
         Ok(())
     }
 
-    pub fn is_pointer(&self) -> bool {
+    pub(crate) fn is_pointer(&self) -> bool {
         matches!(self, Pixels::Pointer(_) | Pixels::Pointer16(_))
     }
 
@@ -190,11 +192,26 @@ impl Pixels {
         }
     }
 
-    pub fn clone_pointer(&self) -> Option<Pixels> {
+    pub(crate) fn try_clone(&self) -> AvifResult<Pixels> {
         match self {
-            Pixels::Pointer(ptr) => Some(Pixels::Pointer(*ptr)),
-            Pixels::Pointer16(ptr) => Some(Pixels::Pointer16(*ptr)),
-            _ => None,
+            Pixels::Pointer(ptr) => Ok(Pixels::Pointer(*ptr)),
+            Pixels::Pointer16(ptr) => Ok(Pixels::Pointer16(*ptr)),
+            Pixels::Buffer(buffer) => {
+                let mut cloned_buffer: Vec<u8> = vec![];
+                cloned_buffer
+                    .try_reserve_exact(buffer.len())
+                    .or(Err(AvifError::OutOfMemory))?;
+                cloned_buffer.extend_from_slice(buffer);
+                Ok(Pixels::Buffer(cloned_buffer))
+            }
+            Pixels::Buffer16(buffer16) => {
+                let mut cloned_buffer16: Vec<u16> = vec![];
+                cloned_buffer16
+                    .try_reserve_exact(buffer16.len())
+                    .or(Err(AvifError::OutOfMemory))?;
+                cloned_buffer16.extend_from_slice(buffer16);
+                Ok(Pixels::Buffer16(cloned_buffer16))
+            }
         }
     }
 
diff --git a/src/internal_utils/stream.rs b/src/internal_utils/stream.rs
index 2a0ab29..673553f 100644
--- a/src/internal_utils/stream.rs
+++ b/src/internal_utils/stream.rs
@@ -33,7 +33,7 @@ impl IBitStream<'_> {
         Ok((byte >> shift) & 0x01)
     }
 
-    pub fn read(&mut self, n: usize) -> AvifResult<u32> {
+    pub(crate) fn read(&mut self, n: usize) -> AvifResult<u32> {
         assert!(n <= 32);
         let mut value: u32 = 0;
         for _i in 0..n {
@@ -43,12 +43,12 @@ impl IBitStream<'_> {
         Ok(value)
     }
 
-    pub fn read_bool(&mut self) -> AvifResult<bool> {
+    pub(crate) fn read_bool(&mut self) -> AvifResult<bool> {
         let bit = self.read_bit()?;
         Ok(bit == 1)
     }
 
-    pub fn skip(&mut self, n: usize) -> AvifResult<()> {
+    pub(crate) fn skip(&mut self, n: usize) -> AvifResult<()> {
         if checked_add!(self.bit_offset, n)? > checked_mul!(self.data.len(), 8)? {
             return Err(AvifError::BmffParseFailed("Not enough bytes".into()));
         }
@@ -56,7 +56,7 @@ impl IBitStream<'_> {
         Ok(())
     }
 
-    pub fn skip_uvlc(&mut self) -> AvifResult<()> {
+    pub(crate) fn skip_uvlc(&mut self) -> AvifResult<()> {
         // See the section 4.10.3. uvlc() of the AV1 specification.
         let mut leading_zeros = 0u128; // leadingZeros
         while !self.read_bool()? {
@@ -68,7 +68,7 @@ impl IBitStream<'_> {
         Ok(())
     }
 
-    pub fn remaining_bits(&self) -> AvifResult<usize> {
+    pub(crate) fn remaining_bits(&self) -> AvifResult<usize> {
         checked_sub!(checked_mul!(self.data.len(), 8)?, self.bit_offset)
     }
 }
@@ -80,7 +80,7 @@ pub struct IStream<'a> {
 }
 
 impl IStream<'_> {
-    pub fn create(data: &[u8]) -> IStream {
+    pub(crate) fn create(data: &[u8]) -> IStream {
         IStream { data, offset: 0 }
     }
 
@@ -91,7 +91,7 @@ impl IStream<'_> {
         Ok(())
     }
 
-    pub fn sub_stream(&mut self, size: &BoxSize) -> AvifResult<IStream> {
+    pub(crate) fn sub_stream(&mut self, size: &BoxSize) -> AvifResult<IStream> {
         let offset = self.offset;
         checked_incr!(
             self.offset,
@@ -109,7 +109,7 @@ impl IStream<'_> {
         })
     }
 
-    pub fn sub_bit_stream(&mut self, size: usize) -> AvifResult<IBitStream> {
+    pub(crate) fn sub_bit_stream(&mut self, size: usize) -> AvifResult<IBitStream> {
         self.check(size)?;
         let offset = self.offset;
         checked_incr!(self.offset, size);
@@ -119,25 +119,25 @@ impl IStream<'_> {
         })
     }
 
-    pub fn bytes_left(&self) -> AvifResult<usize> {
+    pub(crate) fn bytes_left(&self) -> AvifResult<usize> {
         if self.data.len() < self.offset {
             return Err(AvifError::UnknownError("".into()));
         }
         Ok(self.data.len() - self.offset)
     }
 
-    pub fn has_bytes_left(&self) -> AvifResult<bool> {
+    pub(crate) fn has_bytes_left(&self) -> AvifResult<bool> {
         Ok(self.bytes_left()? > 0)
     }
 
-    pub fn get_slice(&mut self, size: usize) -> AvifResult<&[u8]> {
+    pub(crate) fn get_slice(&mut self, size: usize) -> AvifResult<&[u8]> {
         self.check(size)?;
         let offset_start = self.offset;
         checked_incr!(self.offset, size);
         Ok(&self.data[offset_start..offset_start + size])
     }
 
-    pub fn get_immutable_vec(&self, size: usize) -> AvifResult<Vec<u8>> {
+    pub(crate) fn get_immutable_vec(&self, size: usize) -> AvifResult<Vec<u8>> {
         self.check(size)?;
         Ok(self.data[self.offset..self.offset + size].to_vec())
     }
@@ -146,62 +146,60 @@ impl IStream<'_> {
         Ok(self.get_slice(size)?.to_vec())
     }
 
-    pub fn read_u8(&mut self) -> AvifResult<u8> {
+    pub(crate) fn read_u8(&mut self) -> AvifResult<u8> {
         self.check(1)?;
         let value = self.data[self.offset];
         checked_incr!(self.offset, 1);
         Ok(value)
     }
 
-    pub fn read_u16(&mut self) -> AvifResult<u16> {
+    pub(crate) fn read_u16(&mut self) -> AvifResult<u16> {
         Ok(u16::from_be_bytes(self.get_slice(2)?.try_into().unwrap()))
     }
 
-    pub fn read_u24(&mut self) -> AvifResult<u32> {
+    pub(crate) fn read_u24(&mut self) -> AvifResult<u32> {
         Ok(self.read_uxx(3)? as u32)
     }
 
-    pub fn read_u32(&mut self) -> AvifResult<u32> {
+    pub(crate) fn read_u32(&mut self) -> AvifResult<u32> {
         Ok(u32::from_be_bytes(self.get_slice(4)?.try_into().unwrap()))
     }
 
-    pub fn read_u64(&mut self) -> AvifResult<u64> {
+    pub(crate) fn read_u64(&mut self) -> AvifResult<u64> {
         Ok(u64::from_be_bytes(self.get_slice(8)?.try_into().unwrap()))
     }
 
-    pub fn read_i32(&mut self) -> AvifResult<i32> {
-        // For now this is used only for gainmap fractions where we need
-        // wrapping conversion from u32 to i32.
+    pub(crate) fn read_i32(&mut self) -> AvifResult<i32> {
         Ok(self.read_u32()? as i32)
     }
 
-    pub fn skip_u16(&mut self) -> AvifResult<()> {
-        self.skip(2)
+    pub(crate) fn read_i16(&mut self) -> AvifResult<i16> {
+        Ok(self.read_u16()? as i16)
     }
 
-    pub fn skip_u32(&mut self) -> AvifResult<()> {
+    pub(crate) fn skip_u32(&mut self) -> AvifResult<()> {
         self.skip(4)
     }
 
-    pub fn skip_u64(&mut self) -> AvifResult<()> {
+    pub(crate) fn skip_u64(&mut self) -> AvifResult<()> {
         self.skip(8)
     }
 
-    pub fn read_fraction(&mut self) -> AvifResult<Fraction> {
+    pub(crate) fn read_fraction(&mut self) -> AvifResult<Fraction> {
         Ok(Fraction(self.read_i32()?, self.read_u32()?))
     }
 
-    pub fn read_ufraction(&mut self) -> AvifResult<UFraction> {
+    pub(crate) fn read_ufraction(&mut self) -> AvifResult<UFraction> {
         Ok(UFraction(self.read_u32()?, self.read_u32()?))
     }
 
     // Reads size characters of a non-null-terminated string.
-    pub fn read_string(&mut self, size: usize) -> AvifResult<String> {
+    pub(crate) fn read_string(&mut self, size: usize) -> AvifResult<String> {
         Ok(String::from_utf8(self.get_vec(size)?).unwrap_or("".into()))
     }
 
     // Reads an xx-byte unsigner integer.
-    pub fn read_uxx(&mut self, xx: u8) -> AvifResult<u64> {
+    pub(crate) fn read_uxx(&mut self, xx: u8) -> AvifResult<u64> {
         let n: usize = xx.into();
         if n == 0 {
             return Ok(0);
@@ -216,7 +214,7 @@ impl IStream<'_> {
     }
 
     // Reads a null-terminated string.
-    pub fn read_c_string(&mut self) -> AvifResult<String> {
+    pub(crate) fn read_c_string(&mut self) -> AvifResult<String> {
         self.check(1)?;
         let null_position = self.data[self.offset..]
             .iter()
@@ -227,13 +225,13 @@ impl IStream<'_> {
         Ok(String::from_utf8(self.data[range].to_vec()).unwrap_or("".into()))
     }
 
-    pub fn read_version_and_flags(&mut self) -> AvifResult<(u8, u32)> {
+    pub(crate) fn read_version_and_flags(&mut self) -> AvifResult<(u8, u32)> {
         let version = self.read_u8()?;
         let flags = self.read_u24()?;
         Ok((version, flags))
     }
 
-    pub fn read_and_enforce_version_and_flags(
+    pub(crate) fn read_and_enforce_version_and_flags(
         &mut self,
         enforced_version: u8,
     ) -> AvifResult<(u8, u32)> {
@@ -244,18 +242,18 @@ impl IStream<'_> {
         Ok((version, flags))
     }
 
-    pub fn skip(&mut self, size: usize) -> AvifResult<()> {
+    pub(crate) fn skip(&mut self, size: usize) -> AvifResult<()> {
         self.check(size)?;
         checked_incr!(self.offset, size);
         Ok(())
     }
 
-    pub fn rewind(&mut self, size: usize) -> AvifResult<()> {
+    pub(crate) fn rewind(&mut self, size: usize) -> AvifResult<()> {
         checked_decr!(self.offset, size);
         Ok(())
     }
 
-    pub fn read_uleb128(&mut self) -> AvifResult<u32> {
+    pub(crate) fn read_uleb128(&mut self) -> AvifResult<u32> {
         // See the section 4.10.5. of the AV1 specification.
         let mut value: u64 = 0;
         for i in 0..8 {
diff --git a/src/lib.rs b/src/lib.rs
index 94c1ebc..2aa5d78 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -13,6 +13,10 @@
 // limitations under the License.
 
 #![deny(unsafe_op_in_unsafe_fn)]
+#![cfg_attr(feature = "disable_cfi", feature(no_sanitize))]
+
+#[macro_use]
+mod internal_utils;
 
 pub mod decoder;
 pub mod image;
@@ -25,9 +29,10 @@ pub mod capi;
 /// cbindgen:ignore
 mod codecs;
 
-mod internal_utils;
 mod parser;
 
+use image::*;
+
 // Workaround for https://bugs.chromium.org/p/chromium/issues/detail?id=1516634.
 #[derive(Default)]
 pub struct NonRandomHasherState;
@@ -80,17 +85,26 @@ impl PixelFormat {
     pub fn chroma_shift_x(&self) -> (u32, u32) {
         match self {
             Self::Yuv422 | Self::Yuv420 => (1, 0),
-            Self::AndroidP010 => (1, 1),
+            Self::AndroidP010 | Self::AndroidNv12 => (1, 1),
             _ => (0, 0),
         }
     }
 
+    pub fn apply_chroma_shift_x(&self, value: u32) -> u32 {
+        let chroma_shift = self.chroma_shift_x();
+        (value >> chroma_shift.0) << chroma_shift.1
+    }
+
     pub fn chroma_shift_y(&self) -> u32 {
         match self {
             Self::Yuv420 | Self::AndroidP010 | Self::AndroidNv12 | Self::AndroidNv21 => 1,
             _ => 0,
         }
     }
+
+    pub fn apply_chroma_shift_y(&self, value: u32) -> u32 {
+        value >> self.chroma_shift_y()
+    }
 }
 
 // See https://aomediacodec.github.io/av1-spec/#color-config-semantics
@@ -398,3 +412,66 @@ pub(crate) use checked_decr;
 pub(crate) use checked_incr;
 pub(crate) use checked_mul;
 pub(crate) use checked_sub;
+
+#[derive(Clone, Copy, Debug, Default)]
+pub struct Grid {
+    pub rows: u32,
+    pub columns: u32,
+    pub width: u32,
+    pub height: u32,
+}
+
+#[derive(Clone, Copy, Debug, Default, PartialEq)]
+pub enum Category {
+    #[default]
+    Color,
+    Alpha,
+    Gainmap,
+}
+
+impl Category {
+    const COUNT: usize = 3;
+    const ALL: [Category; Category::COUNT] = [Self::Color, Self::Alpha, Self::Gainmap];
+    const ALL_USIZE: [usize; Category::COUNT] = [0, 1, 2];
+
+    pub(crate) fn usize(self) -> usize {
+        match self {
+            Category::Color => 0,
+            Category::Alpha => 1,
+            Category::Gainmap => 2,
+        }
+    }
+
+    pub fn planes(&self) -> &[Plane] {
+        match self {
+            Category::Alpha => &A_PLANE,
+            _ => &YUV_PLANES,
+        }
+    }
+}
+
+/// cbindgen:rename-all=CamelCase
+#[derive(Clone, Copy, Debug, Default, PartialEq)]
+#[repr(C)]
+pub struct PixelAspectRatio {
+    pub h_spacing: u32,
+    pub v_spacing: u32,
+}
+
+/// cbindgen:field-names=[maxCLL, maxPALL]
+#[repr(C)]
+#[derive(Clone, Copy, Debug, Default, PartialEq)]
+pub struct ContentLightLevelInformation {
+    pub max_cll: u16,
+    pub max_pall: u16,
+}
+
+#[derive(Clone, Debug, Default)]
+pub struct Nclx {
+    pub color_primaries: ColorPrimaries,
+    pub transfer_characteristics: TransferCharacteristics,
+    pub matrix_coefficients: MatrixCoefficients,
+    pub yuv_range: YuvRange,
+}
+
+pub const MAX_AV1_LAYER_COUNT: usize = 4;
diff --git a/src/parser/exif.rs b/src/parser/exif.rs
index be57fc3..e6a54ce 100644
--- a/src/parser/exif.rs
+++ b/src/parser/exif.rs
@@ -33,7 +33,7 @@ fn parse_exif_tiff_header_offset(stream: &mut IStream) -> AvifResult<u32> {
     Err(AvifError::InvalidExifPayload)
 }
 
-pub fn parse(stream: &mut IStream) -> AvifResult<()> {
+pub(crate) fn parse(stream: &mut IStream) -> AvifResult<()> {
     // unsigned int(32) exif_tiff_header_offset;
     let offset = stream.read_u32().or(Err(AvifError::InvalidExifPayload))?;
 
diff --git a/src/parser/mp4box.rs b/src/parser/mp4box.rs
index fa1f2b0..b8c4d4b 100644
--- a/src/parser/mp4box.rs
+++ b/src/parser/mp4box.rs
@@ -67,32 +67,34 @@ impl FileTypeBox {
         brands.iter().any(|brand| self.has_brand(brand))
     }
 
-    pub fn is_avif(&self) -> bool {
+    pub(crate) fn is_avif(&self) -> bool {
         // "avio" also exists but does not identify the file as AVIF on its own. See
         // https://aomediacodec.github.io/av1-avif/v1.1.0.html#image-and-image-collection-brand
-        if self.has_brand_any(&["avif", "avis"]) {
-            return true;
-        }
-        match (cfg!(feature = "heic"), cfg!(android_soong)) {
-            (false, _) => false,
-            (true, false) => self.has_brand("heic"),
-            (true, true) => {
-                // This is temporary. For the Android Framework, recognize HEIC files only if they
-                // also contain a gainmap.
-                self.has_brand("heic") && self.has_tmap()
-            }
-        }
+        self.has_brand_any(&[
+            "avif",
+            "avis",
+            #[cfg(feature = "heic")]
+            "heic",
+            #[cfg(feature = "heic")]
+            "heix",
+            #[cfg(feature = "heic")]
+            "mif1",
+        ])
     }
 
-    pub fn needs_meta(&self) -> bool {
+    pub(crate) fn needs_meta(&self) -> bool {
         self.has_brand_any(&[
             "avif",
             #[cfg(feature = "heic")]
             "heic",
+            #[cfg(feature = "heic")]
+            "heix",
+            #[cfg(feature = "heic")]
+            "mif1",
         ])
     }
 
-    pub fn needs_moov(&self) -> bool {
+    pub(crate) fn needs_moov(&self) -> bool {
         self.has_brand_any(&[
             "avis",
             #[cfg(feature = "heic")]
@@ -102,7 +104,7 @@ impl FileTypeBox {
         ])
     }
 
-    pub fn has_tmap(&self) -> bool {
+    pub(crate) fn has_tmap(&self) -> bool {
         self.has_brand("tmap")
     }
 }
@@ -160,7 +162,7 @@ pub struct HevcCodecConfiguration {
 }
 
 impl CodecConfiguration {
-    pub fn depth(&self) -> u8 {
+    pub(crate) fn depth(&self) -> u8 {
         match self {
             Self::Av1(config) => match config.twelve_bit {
                 true => 12,
@@ -173,7 +175,7 @@ impl CodecConfiguration {
         }
     }
 
-    pub fn pixel_format(&self) -> PixelFormat {
+    pub(crate) fn pixel_format(&self) -> PixelFormat {
         match self {
             Self::Av1(config) => {
                 if config.monochrome {
@@ -196,7 +198,7 @@ impl CodecConfiguration {
         }
     }
 
-    pub fn chroma_sample_position(&self) -> ChromaSamplePosition {
+    pub(crate) fn chroma_sample_position(&self) -> ChromaSamplePosition {
         match self {
             Self::Av1(config) => config.chroma_sample_position,
             Self::Hevc(_) => {
@@ -209,7 +211,8 @@ impl CodecConfiguration {
         }
     }
 
-    pub fn raw_data(&self) -> Vec<u8> {
+    #[cfg(feature = "android_mediacodec")]
+    pub(crate) fn raw_data(&self) -> Vec<u8> {
         match self {
             Self::Av1(config) => config.raw_data.clone(),
             Self::Hevc(config) => {
@@ -240,30 +243,23 @@ impl CodecConfiguration {
         }
     }
 
-    pub fn nal_length_size(&self) -> u8 {
+    #[cfg(feature = "android_mediacodec")]
+    pub(crate) fn nal_length_size(&self) -> u8 {
         match self {
             Self::Av1(_) => 0, // Unused. This function is only used for HEVC.
             Self::Hevc(config) => config.nal_length_size,
         }
     }
 
-    pub fn is_avif(&self) -> bool {
+    pub(crate) fn is_avif(&self) -> bool {
         matches!(self, Self::Av1(_))
     }
 
-    pub fn is_heic(&self) -> bool {
+    pub(crate) fn is_heic(&self) -> bool {
         matches!(self, Self::Hevc(_))
     }
 }
 
-#[derive(Clone, Debug, Default)]
-pub struct Nclx {
-    pub color_primaries: ColorPrimaries,
-    pub transfer_characteristics: TransferCharacteristics,
-    pub matrix_coefficients: MatrixCoefficients,
-    pub yuv_range: YuvRange,
-}
-
 #[derive(Clone, Debug)]
 pub enum ColorInformation {
     Icc(Vec<u8>),
@@ -271,22 +267,6 @@ pub enum ColorInformation {
     Unknown,
 }
 
-/// cbindgen:rename-all=CamelCase
-#[derive(Clone, Copy, Debug, Default, PartialEq)]
-#[repr(C)]
-pub struct PixelAspectRatio {
-    pub h_spacing: u32,
-    pub v_spacing: u32,
-}
-
-/// cbindgen:field-names=[maxCLL, maxPALL]
-#[repr(C)]
-#[derive(Clone, Copy, Debug, Default)]
-pub struct ContentLightLevelInformation {
-    pub max_cll: u16,
-    pub max_pall: u16,
-}
-
 #[derive(Clone, Debug, PartialEq)]
 pub enum CodecConfiguration {
     Av1(Av1CodecConfiguration),
@@ -455,7 +435,7 @@ fn parse_ftyp(stream: &mut IStream) -> AvifResult<FileTypeBox> {
     })
 }
 
-fn parse_hdlr(stream: &mut IStream) -> AvifResult<()> {
+fn parse_hdlr(stream: &mut IStream) -> AvifResult<String> {
     // Section 8.4.3.2 of ISO/IEC 14496-12.
     let (_version, _flags) = stream.read_and_enforce_version_and_flags(0)?;
     // unsigned int(32) pre_defined = 0;
@@ -467,16 +447,6 @@ fn parse_hdlr(stream: &mut IStream) -> AvifResult<()> {
     }
     // unsigned int(32) handler_type;
     let handler_type = stream.read_string(4)?;
-    if handler_type != "pict" {
-        // Section 6.2 of ISO/IEC 23008-12:
-        //   The handler type for the MetaBox shall be 'pict'.
-        // https://aomediacodec.github.io/av1-avif/v1.1.0.html#image-sequences does not apply
-        // because this function is only called for the MetaBox but it would work too:
-        //   The track handler for an AV1 Image Sequence shall be pict.
-        return Err(AvifError::BmffParseFailed(
-            "Box[hdlr] handler_type is not 'pict'".into(),
-        ));
-    }
     // const unsigned int(32)[3] reserved = 0;
     if stream.read_u32()? != 0 || stream.read_u32()? != 0 || stream.read_u32()? != 0 {
         return Err(AvifError::BmffParseFailed(
@@ -488,7 +458,7 @@ fn parse_hdlr(stream: &mut IStream) -> AvifResult<()> {
     //   name gives a human-readable name for the track type (for debugging and inspection
     //   purposes).
     stream.read_c_string()?;
-    Ok(())
+    Ok(handler_type)
 }
 
 fn parse_iloc(stream: &mut IStream) -> AvifResult<ItemLocationBox> {
@@ -976,7 +946,7 @@ fn parse_clli(stream: &mut IStream) -> AvifResult<ItemProperty> {
     Ok(ItemProperty::ContentLightLevelInformation(clli))
 }
 
-fn parse_ipco(stream: &mut IStream) -> AvifResult<Vec<ItemProperty>> {
+fn parse_ipco(stream: &mut IStream, is_track: bool) -> AvifResult<Vec<ItemProperty>> {
     // Section 8.11.14.2 of ISO/IEC 14496-12.
     let mut properties: Vec<ItemProperty> = Vec::new();
     while stream.has_bytes_left()? {
@@ -988,7 +958,8 @@ fn parse_ipco(stream: &mut IStream) -> AvifResult<Vec<ItemProperty>> {
             "av1C" => properties.push(parse_av1C(&mut sub_stream)?),
             "colr" => properties.push(parse_colr(&mut sub_stream)?),
             "pasp" => properties.push(parse_pasp(&mut sub_stream)?),
-            "auxC" => properties.push(parse_auxC(&mut sub_stream)?),
+            "auxC" if !is_track => properties.push(parse_auxC(&mut sub_stream)?),
+            "auxi" if is_track => properties.push(parse_auxC(&mut sub_stream)?),
             "clap" => properties.push(parse_clap(&mut sub_stream)?),
             "irot" => properties.push(parse_irot(&mut sub_stream)?),
             "imir" => properties.push(parse_imir(&mut sub_stream)?),
@@ -1068,7 +1039,7 @@ fn parse_iprp(stream: &mut IStream) -> AvifResult<ItemPropertyBox> {
     // Parse ipco box.
     {
         let mut sub_stream = stream.sub_stream(&header.size)?;
-        iprp.properties = parse_ipco(&mut sub_stream)?;
+        iprp.properties = parse_ipco(&mut sub_stream, /*is_track=*/ false)?;
     }
     // Parse ipma boxes.
     while stream.has_bytes_left()? {
@@ -1236,7 +1207,17 @@ fn parse_meta(stream: &mut IStream) -> AvifResult<MetaBox> {
                 "first box in meta is not hdlr".into(),
             ));
         }
-        parse_hdlr(&mut stream.sub_stream(&header.size)?)?;
+        let handler_type = parse_hdlr(&mut stream.sub_stream(&header.size)?)?;
+        if handler_type != "pict" {
+            // Section 6.2 of ISO/IEC 23008-12:
+            //   The handler type for the MetaBox shall be 'pict'.
+            // https://aomediacodec.github.io/av1-avif/v1.1.0.html#image-sequences does not apply
+            // because this function is only called for the MetaBox but it would work too:
+            //   The track handler for an AV1 Image Sequence shall be pict.
+            return Err(AvifError::BmffParseFailed(
+                "Box[hdlr] handler_type is not 'pict'".into(),
+            ));
+        }
     }
 
     let mut boxes_seen: HashSet<String> = HashSet::with_hasher(NonRandomHasherState);
@@ -1335,11 +1316,6 @@ fn parse_tkhd(stream: &mut IStream, track: &mut Track) -> AvifResult<()> {
     // unsigned int(32) height;
     track.height = stream.read_u32()? >> 16;
 
-    if track.width == 0 || track.height == 0 {
-        return Err(AvifError::BmffParseFailed(
-            "invalid track dimensions".into(),
-        ));
-    }
     Ok(())
 }
 
@@ -1517,7 +1493,7 @@ fn parse_sample_entry(stream: &mut IStream, format: String) -> AvifResult<Sample
     // unsigned int(16) data_reference_index;
     stream.skip(2)?;
 
-    if sample_entry.format == "av01" {
+    if sample_entry.is_supported_format() {
         // https://aomediacodec.github.io/av1-isobmff/v1.2.0.html#av1sampleentry-syntax:
         //   class AV1SampleEntry extends VisualSampleEntry('av01'){
         //     AV1CodecConfigurationBox config;
@@ -1572,7 +1548,10 @@ fn parse_sample_entry(stream: &mut IStream, format: String) -> AvifResult<Sample
         // PixelAspectRatioBox pasp; // optional
 
         // Now read any of 'av1C', 'clap', 'pasp' etc.
-        sample_entry.properties = parse_ipco(&mut stream.sub_stream(&BoxSize::UntilEndOfStream)?)?;
+        sample_entry.properties = parse_ipco(
+            &mut stream.sub_stream(&BoxSize::UntilEndOfStream)?,
+            /*is_track=*/ true,
+        )?;
 
         if !sample_entry
             .properties
@@ -1683,6 +1662,7 @@ fn parse_mdia(stream: &mut IStream, track: &mut Track) -> AvifResult<()> {
         match header.box_type.as_str() {
             "mdhd" => parse_mdhd(&mut sub_stream, track)?,
             "minf" => parse_minf(&mut sub_stream, track)?,
+            "hdlr" => track.handler_type = parse_hdlr(&mut sub_stream)?,
             _ => {}
         }
     }
@@ -1838,7 +1818,13 @@ fn parse_moov(stream: &mut IStream) -> AvifResult<Vec<Track>> {
         let header = parse_header(stream, /*top_level=*/ false)?;
         let mut sub_stream = stream.sub_stream(&header.size)?;
         if header.box_type == "trak" {
-            tracks.push(parse_trak(&mut sub_stream)?);
+            let track = parse_trak(&mut sub_stream)?;
+            if track.is_video_handler() && (track.width == 0 || track.height == 0) {
+                return Err(AvifError::BmffParseFailed(
+                    "invalid track dimensions".into(),
+                ));
+            }
+            tracks.push(track);
         }
     }
     if tracks.is_empty() {
@@ -1849,7 +1835,7 @@ fn parse_moov(stream: &mut IStream) -> AvifResult<Vec<Track>> {
     Ok(tracks)
 }
 
-pub fn parse(io: &mut GenericIO) -> AvifResult<AvifBoxes> {
+pub(crate) fn parse(io: &mut GenericIO) -> AvifResult<AvifBoxes> {
     let mut ftyp: Option<FileTypeBox> = None;
     let mut meta: Option<MetaBox> = None;
     let mut tracks: Option<Vec<Track>> = None;
@@ -1929,7 +1915,7 @@ pub fn parse(io: &mut GenericIO) -> AvifResult<AvifBoxes> {
     })
 }
 
-pub fn peek_compatible_file_type(data: &[u8]) -> AvifResult<bool> {
+pub(crate) fn peek_compatible_file_type(data: &[u8]) -> AvifResult<bool> {
     let mut stream = IStream::create(data);
     let header = parse_header(&mut stream, /*top_level=*/ true)?;
     if header.box_type != "ftyp" {
@@ -1954,7 +1940,7 @@ pub fn peek_compatible_file_type(data: &[u8]) -> AvifResult<bool> {
     Ok(ftyp.is_avif())
 }
 
-pub fn parse_tmap(stream: &mut IStream) -> AvifResult<Option<GainMapMetadata>> {
+pub(crate) fn parse_tmap(stream: &mut IStream) -> AvifResult<Option<GainMapMetadata>> {
     // Experimental, not yet specified.
 
     // unsigned int(8) version = 0;
@@ -2018,6 +2004,7 @@ pub fn parse_tmap(stream: &mut IStream) -> AvifResult<Option<GainMapMetadata>> {
             "invalid trailing bytes in tmap box".into(),
         ));
     }
+    metadata.is_valid()?;
     Ok(Some(metadata))
 }
 
diff --git a/src/parser/obu.rs b/src/parser/obu.rs
index 95db355..1f2fa25 100644
--- a/src/parser/obu.rs
+++ b/src/parser/obu.rs
@@ -295,7 +295,7 @@ impl Av1SequenceHeader {
         Ok(ObuHeader { obu_type, size })
     }
 
-    pub fn parse_from_obus(data: &[u8]) -> AvifResult<Self> {
+    pub(crate) fn parse_from_obus(data: &[u8]) -> AvifResult<Self> {
         let mut stream = IStream::create(data);
 
         while stream.has_bytes_left()? {
diff --git a/src/reformat/alpha.rs b/src/reformat/alpha.rs
index 3c996e4..2dff10e 100644
--- a/src/reformat/alpha.rs
+++ b/src/reformat/alpha.rs
@@ -17,7 +17,6 @@ use super::libyuv;
 
 use super::rgb;
 
-use crate::decoder::Category;
 use crate::image::Plane;
 use crate::internal_utils::*;
 use crate::reformat::rgb::Format;
@@ -41,8 +40,16 @@ fn unpremultiply_u16(pixel: u16, alpha: u16, max_channel_f: f32) -> u16 {
         .min(max_channel_f) as u16
 }
 
+macro_rules! alpha_index_in_rgba_1010102 {
+    ($x:expr) => {{
+        // The index of the alpha pixel depends on the endianness since each pixel is a u32 in this
+        // case. The alpha value is the 2-bit MSB of the pixel at this index.
+        $x * 2 + if cfg!(target_endian = "little") { 1 } else { 0 }
+    }};
+}
+
 impl rgb::Image {
-    pub fn premultiply_alpha(&mut self) -> AvifResult<()> {
+    pub(crate) fn premultiply_alpha(&mut self) -> AvifResult<()> {
         if self.pixels().is_null() || self.row_bytes == 0 {
             return Err(AvifError::ReformatFailed);
         }
@@ -116,7 +123,7 @@ impl rgb::Image {
         Ok(())
     }
 
-    pub fn unpremultiply_alpha(&mut self) -> AvifResult<()> {
+    pub(crate) fn unpremultiply_alpha(&mut self) -> AvifResult<()> {
         if self.pixels().is_null() || self.row_bytes == 0 {
             return Err(AvifError::ReformatFailed);
         }
@@ -190,7 +197,7 @@ impl rgb::Image {
         Ok(())
     }
 
-    pub fn set_opaque(&mut self) -> AvifResult<()> {
+    pub(crate) fn set_opaque(&mut self) -> AvifResult<()> {
         if !self.has_alpha() {
             return Ok(());
         }
@@ -225,7 +232,7 @@ impl rgb::Image {
         clamp_u16(alpha, 0, dst_max_channel)
     }
 
-    pub fn import_alpha_from(&mut self, image: &image::Image) -> AvifResult<()> {
+    pub(crate) fn import_alpha_from(&mut self, image: &image::Image) -> AvifResult<()> {
         if !self.has_alpha()
             || !image.has_alpha()
             || self.width != image.width
@@ -234,6 +241,33 @@ impl rgb::Image {
             return Err(AvifError::InvalidArgument);
         }
         let width = usize_from_u32(self.width)?;
+        if self.format == Format::Rgba1010102 {
+            // Clippy warns about the loops using x as an index for src_row. But it is also used to
+            // compute the index for dst_row. Disable the warnings.
+            #[allow(clippy::needless_range_loop)]
+            if image.depth > 8 {
+                for y in 0..self.height {
+                    let dst_row = self.row16_mut(y)?;
+                    let src_row = image.row16(Plane::A, y)?;
+                    for x in 0..width {
+                        let alpha_pixel = (src_row[x]) >> (image.depth - 2);
+                        let index = alpha_index_in_rgba_1010102!(x);
+                        dst_row[index] = (dst_row[index] & 0x3fff) | (alpha_pixel << 14);
+                    }
+                }
+            } else {
+                for y in 0..self.height {
+                    let dst_row = self.row16_mut(y)?;
+                    let src_row = image.row(Plane::A, y)?;
+                    for x in 0..width {
+                        let alpha_pixel = ((src_row[x]) >> 6) as u16;
+                        let index = alpha_index_in_rgba_1010102!(x);
+                        dst_row[index] = (dst_row[index] & 0x3fff) | (alpha_pixel << 14);
+                    }
+                }
+            }
+            return Ok(());
+        }
         let dst_alpha_offset = self.format.alpha_offset();
         if self.depth == image.depth {
             if self.depth > 8 {
@@ -301,7 +335,7 @@ impl rgb::Image {
 }
 
 impl image::Image {
-    pub fn alpha_to_full_range(&mut self) -> AvifResult<()> {
+    pub(crate) fn alpha_to_full_range(&mut self) -> AvifResult<()> {
         if self.planes[3].is_none() {
             return Ok(());
         }
@@ -317,7 +351,7 @@ impl image::Image {
                     None,
                     None,
                     None,
-                    self.planes[3].unwrap_ref().clone_pointer(),
+                    Some(self.planes[3].unwrap_ref().try_clone()?),
                 ],
                 row_bytes: [0, 0, 0, self.row_bytes[3]],
                 ..image::Image::default()
@@ -577,4 +611,66 @@ mod tests {
         }
         Ok(())
     }
+
+    #[test_matrix(20, 10, 10, [8, 10, 12])]
+    fn reformat_alpha_rgba1010102(
+        width: u32,
+        height: u32,
+        rgb_depth: u8,
+        yuv_depth: u8,
+    ) -> AvifResult<()> {
+        let format = rgb::Format::Rgba1010102;
+        let mut buffer: Vec<u8> = vec![];
+        let mut rgb = rgb_image(
+            width,
+            height,
+            rgb_depth,
+            format,
+            /*use_pointer*/ false,
+            &mut buffer,
+        )?;
+
+        let mut image = image::Image::default();
+        image.width = width;
+        image.height = height;
+        image.depth = yuv_depth;
+        image.allocate_planes(Category::Alpha)?;
+
+        let mut rng = rand::thread_rng();
+        let mut expected_values: Vec<u16> = Vec::new();
+        if yuv_depth == 8 {
+            for y in 0..height {
+                let row = image.row_mut(Plane::A, y)?;
+                for x in 0..width as usize {
+                    let value = rng.gen_range(0..256) as u8;
+                    expected_values.push((value >> 6) as u16);
+                    row[x] = value;
+                }
+            }
+        } else {
+            for y in 0..height {
+                let row = image.row16_mut(Plane::A, y)?;
+                for x in 0..width as usize {
+                    let value = rng.gen_range(0..(1i32 << yuv_depth)) as u16;
+                    expected_values.push(value >> (yuv_depth - 2));
+                    row[x] = value;
+                }
+            }
+        }
+
+        rgb.import_alpha_from(&image)?;
+
+        let mut expected_values = expected_values.into_iter();
+        for y in 0..height {
+            let rgb_row = rgb.row16(y)?;
+            assert_eq!(rgb_row.len(), (width * 2) as usize);
+            for x in 0..width as usize {
+                assert_eq!(
+                    rgb_row[alpha_index_in_rgba_1010102!(x)] >> 14,
+                    expected_values.next().unwrap()
+                );
+            }
+        }
+        Ok(())
+    }
 }
diff --git a/src/reformat/coeffs.rs b/src/reformat/coeffs.rs
index d4bf775..ba2502c 100644
--- a/src/reformat/coeffs.rs
+++ b/src/reformat/coeffs.rs
@@ -19,7 +19,7 @@ fn expand_coeffs(y: f32, v: f32) -> [f32; 3] {
 }
 
 impl ColorPrimaries {
-    pub fn y_coeffs(&self) -> [f32; 3] {
+    pub(crate) fn y_coeffs(&self) -> [f32; 3] {
         // These values come from computations in Section 8 of
         // https://www.itu.int/rec/T-REC-H.273-201612-S
         match self {
@@ -56,7 +56,7 @@ fn calculate_yuv_coefficients_from_cicp(
     }
 }
 
-pub fn calculate_yuv_coefficients(
+pub(crate) fn calculate_yuv_coefficients(
     color_primaries: ColorPrimaries,
     matrix_coefficients: MatrixCoefficients,
 ) -> [f32; 3] {
diff --git a/src/reformat/libyuv.rs b/src/reformat/libyuv.rs
index aef5343..8a1dc8b 100644
--- a/src/reformat/libyuv.rs
+++ b/src/reformat/libyuv.rs
@@ -15,7 +15,6 @@
 use super::rgb;
 use super::rgb::*;
 
-use crate::decoder::Category;
 use crate::image::*;
 use crate::internal_utils::*;
 use crate::*;
@@ -140,6 +139,7 @@ enum ConversionFunction {
     YUVToRGBMatrixHighBitDepth(YUVToRGBMatrixHighBitDepth),
     YUVAToRGBMatrixHighBitDepth(YUVAToRGBMatrixHighBitDepth),
     P010ToRGBMatrix(P010ToRGBMatrix, ARGBToABGR),
+    YUVToAB30Matrix(YUVToRGBMatrixHighBitDepth, ARGBToABGR),
     NVToARGBMatrix(NVToARGBMatrix),
 }
 
@@ -170,9 +170,15 @@ fn find_conversion_function(
             // What Android considers to be NV21 is actually NV12 in libyuv.
             Some(ConversionFunction::NVToARGBMatrix(NV12ToARGBMatrix))
         }
+        (_, 8, Format::Rgb565, PixelFormat::AndroidNv12) => {
+            Some(ConversionFunction::NVToARGBMatrix(NV12ToRGB565Matrix))
+        }
         (_, 16, Format::Rgba1010102, PixelFormat::AndroidP010) => Some(
             ConversionFunction::P010ToRGBMatrix(P010ToAR30Matrix, AR30ToAB30),
         ),
+        (_, 10, Format::Rgba1010102, PixelFormat::Yuv420) => Some(
+            ConversionFunction::YUVToAB30Matrix(I010ToAR30Matrix, AR30ToAB30),
+        ),
         (_, 16, Format::Rgba, PixelFormat::AndroidP010) => Some(
             ConversionFunction::P010ToRGBMatrix(P010ToARGBMatrix, ARGBToABGR),
         ),
@@ -361,12 +367,16 @@ fn find_conversion_function(
     }
 }
 
-pub fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<bool> {
+#[cfg_attr(feature = "disable_cfi", no_sanitize(cfi))]
+pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<bool> {
     if (rgb.depth != 8 && rgb.depth != 10) || !image.depth_valid() {
         return Err(AvifError::NotImplemented);
     }
     if rgb.depth == 10
-        && (image.yuv_format != PixelFormat::AndroidP010 || rgb.format != Format::Rgba1010102)
+        && (!matches!(
+            image.yuv_format,
+            PixelFormat::AndroidP010 | PixelFormat::Yuv420
+        ) || rgb.format != Format::Rgba1010102)
     {
         return Err(AvifError::NotImplemented);
     }
@@ -389,7 +399,7 @@ pub fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<bool
         .iter()
         .map(|x| {
             if image.has_plane(*x) {
-                image.planes[x.to_usize()].unwrap_ref().ptr()
+                image.planes[x.as_usize()].unwrap_ref().ptr()
             } else {
                 std::ptr::null()
             }
@@ -401,7 +411,7 @@ pub fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<bool
         .iter()
         .map(|x| {
             if image.has_plane(*x) {
-                image.planes[x.to_usize()].unwrap_ref().ptr16()
+                image.planes[x.as_usize()].unwrap_ref().ptr16()
             } else {
                 std::ptr::null()
             }
@@ -456,6 +466,35 @@ pub fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<bool
                     result
                 }
             }
+            ConversionFunction::YUVToAB30Matrix(func1, func2) => {
+                let result = func1(
+                    plane_u16[0],
+                    plane_row_bytes[0] / 2,
+                    plane_u16[1],
+                    plane_row_bytes[1] / 2,
+                    plane_u16[2],
+                    plane_row_bytes[2] / 2,
+                    rgb.pixels(),
+                    rgb_row_bytes,
+                    matrix,
+                    width,
+                    height,
+                );
+                if result == 0 {
+                    // It is okay to use the same pointer as source and destination for this
+                    // conversion.
+                    func2(
+                        rgb.pixels(),
+                        rgb_row_bytes,
+                        rgb.pixels(),
+                        rgb_row_bytes,
+                        width,
+                        height,
+                    )
+                } else {
+                    result
+                }
+            }
             ConversionFunction::YUVToRGBMatrixFilterHighBitDepth(func) => func(
                 plane_u16[0],
                 plane_row_bytes[0] / 2,
@@ -535,7 +574,7 @@ pub fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<bool
                 .iter()
                 .map(|x| {
                     if image8.has_plane(*x) {
-                        image8.planes[x.to_usize()].unwrap_ref().ptr()
+                        image8.planes[x.as_usize()].unwrap_ref().ptr()
                     } else {
                         std::ptr::null()
                     }
@@ -673,9 +712,9 @@ fn downshift_to_8bit(
         if pd.width == 0 {
             continue;
         }
-        let source_ptr = image.planes[plane.to_usize()].unwrap_ref().ptr16();
+        let source_ptr = image.planes[plane.as_usize()].unwrap_ref().ptr16();
         let pd8 = image8.plane_data(plane).unwrap();
-        let dst_ptr = image8.planes[plane.to_usize()].unwrap_mut().ptr_mut();
+        let dst_ptr = image8.planes[plane.as_usize()].unwrap_mut().ptr_mut();
         unsafe {
             Convert16To8Plane(
                 source_ptr,
@@ -691,7 +730,7 @@ fn downshift_to_8bit(
     Ok(())
 }
 
-pub fn process_alpha(rgb: &mut rgb::Image, multiply: bool) -> AvifResult<()> {
+pub(crate) fn process_alpha(rgb: &mut rgb::Image, multiply: bool) -> AvifResult<()> {
     if rgb.depth != 8 {
         return Err(AvifError::NotImplemented);
     }
@@ -727,7 +766,7 @@ pub fn process_alpha(rgb: &mut rgb::Image, multiply: bool) -> AvifResult<()> {
     }
 }
 
-pub fn convert_to_half_float(rgb: &mut rgb::Image, scale: f32) -> AvifResult<()> {
+pub(crate) fn convert_to_half_float(rgb: &mut rgb::Image, scale: f32) -> AvifResult<()> {
     let res = unsafe {
         HalfFloatPlane(
             rgb.pixels() as *const u16,
diff --git a/src/reformat/mod.rs b/src/reformat/mod.rs
index 76925e8..9c6c813 100644
--- a/src/reformat/mod.rs
+++ b/src/reformat/mod.rs
@@ -26,20 +26,24 @@ pub mod rgb_impl;
 // without it.
 #[cfg(not(feature = "libyuv"))]
 pub mod libyuv {
-    use crate::decoder::Category;
     use crate::reformat::*;
     use crate::*;
 
-    pub fn yuv_to_rgb(_image: &image::Image, _rgb: &mut rgb::Image) -> AvifResult<bool> {
+    pub(crate) fn yuv_to_rgb(_image: &image::Image, _rgb: &mut rgb::Image) -> AvifResult<bool> {
         Err(AvifError::NotImplemented)
     }
 
-    pub fn convert_to_half_float(_rgb: &mut rgb::Image, _scale: f32) -> AvifResult<()> {
+    pub(crate) fn convert_to_half_float(_rgb: &mut rgb::Image, _scale: f32) -> AvifResult<()> {
         Err(AvifError::NotImplemented)
     }
 
     impl image::Image {
-        pub fn scale(&mut self, width: u32, height: u32, _category: Category) -> AvifResult<()> {
+        pub(crate) fn scale(
+            &mut self,
+            width: u32,
+            height: u32,
+            _category: Category,
+        ) -> AvifResult<()> {
             if self.width == width && self.height == height {
                 return Ok(());
             }
diff --git a/src/reformat/rgb.rs b/src/reformat/rgb.rs
index 34f8285..45417d6 100644
--- a/src/reformat/rgb.rs
+++ b/src/reformat/rgb.rs
@@ -36,7 +36,7 @@ pub enum Format {
 }
 
 impl Format {
-    pub fn offsets(&self) -> [usize; 4] {
+    pub(crate) fn offsets(&self) -> [usize; 4] {
         match self {
             Format::Rgb => [0, 1, 2, 0],
             Format::Rgba => [0, 1, 2, 3],
@@ -64,7 +64,7 @@ impl Format {
         self.offsets()[3]
     }
 
-    pub fn has_alpha(&self) -> bool {
+    pub(crate) fn has_alpha(&self) -> bool {
         !matches!(self, Format::Rgb | Format::Bgr | Format::Rgb565)
     }
 }
@@ -81,12 +81,13 @@ pub enum ChromaUpsampling {
 }
 
 impl ChromaUpsampling {
-    pub fn nearest_neighbor_filter_allowed(&self) -> bool {
-        // TODO: this function has to return different values based on whether libyuv is used.
+    #[cfg(feature = "libyuv")]
+    pub(crate) fn nearest_neighbor_filter_allowed(&self) -> bool {
         !matches!(self, Self::Bilinear | Self::BestQuality)
     }
-    pub fn bilinear_or_better_filter_allowed(&self) -> bool {
-        // TODO: this function has to return different values based on whether libyuv is used.
+
+    #[cfg(feature = "libyuv")]
+    pub(crate) fn bilinear_or_better_filter_allowed(&self) -> bool {
         !matches!(self, Self::Nearest | Self::Fastest)
     }
 }
@@ -126,11 +127,11 @@ pub enum AlphaMultiplyMode {
 }
 
 impl Image {
-    pub fn max_channel(&self) -> u16 {
+    pub(crate) fn max_channel(&self) -> u16 {
         ((1i32 << self.depth) - 1) as u16
     }
 
-    pub fn max_channel_f(&self) -> f32 {
+    pub(crate) fn max_channel_f(&self) -> f32 {
         self.max_channel() as f32
     }
 
@@ -150,7 +151,7 @@ impl Image {
         }
     }
 
-    pub fn pixels(&mut self) -> *mut u8 {
+    pub(crate) fn pixels(&mut self) -> *mut u8 {
         if self.pixels.is_none() {
             return std::ptr::null_mut();
         }
@@ -205,7 +206,7 @@ impl Image {
         Ok(())
     }
 
-    pub fn depth_valid(&self) -> bool {
+    pub(crate) fn depth_valid(&self) -> bool {
         match (self.format, self.is_float, self.depth) {
             (Format::Rgb565, false, 8) => true,
             (Format::Rgb565, _, _) => false,
@@ -222,7 +223,7 @@ impl Image {
         }
     }
 
-    pub fn channel_size(&self) -> u32 {
+    pub(crate) fn channel_size(&self) -> u32 {
         match self.depth {
             8 => 1,
             10 | 12 | 16 => 2,
@@ -230,7 +231,7 @@ impl Image {
         }
     }
 
-    pub fn channel_count(&self) -> u32 {
+    pub(crate) fn channel_count(&self) -> u32 {
         match self.format {
             Format::Rgba | Format::Bgra | Format::Argb | Format::Abgr => 4,
             Format::Rgb | Format::Bgr => 3,
@@ -239,7 +240,7 @@ impl Image {
         }
     }
 
-    pub fn pixel_size(&self) -> u32 {
+    pub(crate) fn pixel_size(&self) -> u32 {
         match self.format {
             Format::Rgba | Format::Bgra | Format::Argb | Format::Abgr => self.channel_size() * 4,
             Format::Rgb | Format::Bgr => self.channel_size() * 3,
@@ -272,7 +273,7 @@ impl Image {
     }
 
     pub fn convert_from_yuv(&mut self, image: &image::Image) -> AvifResult<()> {
-        if !image.has_plane(Plane::Y) || !image.depth_valid() {
+        if !image.has_plane(Plane::Y) || !image.depth_valid() || !self.depth_valid() {
             return Err(AvifError::ReformatFailed);
         }
         if matches!(
@@ -337,14 +338,14 @@ impl Image {
                 }
             }
         }
-        if matches!(
-            image.yuv_format,
-            PixelFormat::AndroidNv12 | PixelFormat::AndroidNv21
-        ) | matches!(self.format, Format::Rgba1010102)
-        {
+        if image.yuv_format == PixelFormat::AndroidNv21 || self.format == Format::Rgba1010102 {
             // These conversions are only supported via libyuv.
-            // TODO: b/362984605 - Handle alpha channel for these formats.
             if converted_with_libyuv {
+                if image.has_alpha() && matches!(self.format, Format::Rgba1010102) {
+                    // If the source image has an alpha channel, scale them to 2 bits and fill it
+                    // into the rgb image. Otherwise, libyuv writes them as opaque by default.
+                    self.import_alpha_from(image)?;
+                }
                 return Ok(());
             } else {
                 return Err(AvifError::NotImplemented);
@@ -460,10 +461,10 @@ impl Image {
 mod tests {
     use super::*;
 
-    use crate::decoder::Category;
     use crate::image::YuvRange;
     use crate::image::ALL_PLANES;
     use crate::image::MAX_PLANE_COUNT;
+    use crate::Category;
 
     use test_case::test_case;
     use test_case::test_matrix;
@@ -577,7 +578,7 @@ mod tests {
         image.allocate_planes(Category::Alpha)?;
         let yuva_planes = &yuv_params.planes;
         for plane in ALL_PLANES {
-            let plane_index = plane.to_usize();
+            let plane_index = plane.as_usize();
             if yuva_planes[plane_index].is_empty() {
                 continue;
             }
diff --git a/src/reformat/rgb_impl.rs b/src/reformat/rgb_impl.rs
index 7077bcc..a3d0257 100644
--- a/src/reformat/rgb_impl.rs
+++ b/src/reformat/rgb_impl.rs
@@ -121,7 +121,9 @@ fn yuv8_to_rgb8_color(
         let uv_j = j >> image.yuv_format.chroma_shift_y();
         let y_row = image.row(Plane::Y, j)?;
         let u_row = image.row(Plane::U, uv_j)?;
-        let v_row = image.row(Plane::V, uv_j)?;
+        // If V plane is missing, then the format is NV12. In that case, set V
+        // as U plane but starting at offset 1.
+        let v_row = image.row(Plane::V, uv_j).unwrap_or(&u_row[1..]);
         let dst = rgb.row_mut(j)?;
         for i in 0..image.width as usize {
             let uv_i = (i >> chroma_shift.0) << chroma_shift.1;
@@ -277,7 +279,9 @@ fn yuv8_to_rgb16_color(
         let uv_j = j >> image.yuv_format.chroma_shift_y();
         let y_row = image.row(Plane::Y, j)?;
         let u_row = image.row(Plane::U, uv_j)?;
-        let v_row = image.row(Plane::V, uv_j)?;
+        // If V plane is missing, then the format is NV12. In that case, set V
+        // as U plane but starting at offset 1.
+        let v_row = image.row(Plane::V, uv_j).unwrap_or(&u_row[1..]);
         let dst = rgb.row16_mut(j)?;
         for i in 0..image.width as usize {
             let uv_i = (i >> chroma_shift.0) << chroma_shift.1;
@@ -428,7 +432,7 @@ fn yuv8_to_rgb16_monochrome(
     Ok(())
 }
 
-pub fn yuv_to_rgb_fast(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<()> {
+pub(crate) fn yuv_to_rgb_fast(image: &image::Image, rgb: &mut rgb::Image) -> AvifResult<()> {
     let mode: Mode = image.into();
     match mode {
         Mode::Identity => {
@@ -561,7 +565,7 @@ fn unorm_value(row: PlaneRow, index: usize, max_channel: u16, table: &[f32]) ->
     table[clamped_pixel(row, index, max_channel) as usize]
 }
 
-pub fn yuv_to_rgb_any(
+pub(crate) fn yuv_to_rgb_any(
     image: &image::Image,
     rgb: &mut rgb::Image,
     alpha_multiply_mode: AlphaMultiplyMode,
@@ -726,7 +730,7 @@ mod tests {
                 yuv_range: YuvRange::Limited,
                 ..Default::default()
             };
-            assert!(yuv.allocate_planes(decoder::Category::Color).is_ok());
+            assert!(yuv.allocate_planes(Category::Color).is_ok());
             for plane in image::YUV_PLANES {
                 let samples = if plane == Plane::Y {
                     &y
diff --git a/src/reformat/scale.rs b/src/reformat/scale.rs
index 026fd79..0a14612 100644
--- a/src/reformat/scale.rs
+++ b/src/reformat/scale.rs
@@ -12,7 +12,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crate::decoder::Category;
 use crate::image::*;
 use crate::internal_utils::*;
 use crate::*;
@@ -20,7 +19,7 @@ use crate::*;
 use libyuv_sys::bindings::*;
 
 impl Image {
-    pub fn scale(&mut self, width: u32, height: u32, category: Category) -> AvifResult<()> {
+    pub(crate) fn scale(&mut self, width: u32, height: u32, category: Category) -> AvifResult<()> {
         if self.width == width && self.height == height {
             return Ok(());
         }
@@ -31,33 +30,80 @@ impl Image {
             Category::Color | Category::Gainmap => &YUV_PLANES,
             Category::Alpha => &A_PLANE,
         };
-        let src = image::Image {
-            width: self.width,
-            height: self.height,
-            depth: self.depth,
-            yuv_format: self.yuv_format,
-            planes: self
-                .planes
-                .as_ref()
-                .iter()
-                .map(
-                    |plane| {
-                        if plane.is_some() {
-                            Some(plane.unwrap_ref().clone())
-                        } else {
-                            None
-                        }
-                    },
-                )
-                .collect::<Vec<_>>()
-                .try_into()
-                .unwrap(),
-            row_bytes: self.row_bytes,
-            ..image::Image::default()
-        };
+        let src =
+            if category != Category::Alpha && self.yuv_format == PixelFormat::AndroidP010 {
+                // P010 images cannot be scaled using ScalePlane_12 since the U and V planes are
+                // interleaved. Convert them into I010 and then scale each plane using
+                // ScalePlane_12.
+                let mut i010 = image::Image {
+                    width: self.width,
+                    height: self.height,
+                    depth: 10,
+                    yuv_format: PixelFormat::Yuv420,
+                    ..image::Image::default()
+                };
+                i010.allocate_planes(Category::Color)?;
+                let src_y_pd = self.plane_data(Plane::Y).unwrap();
+                let src_uv_pd = self.plane_data(Plane::U).unwrap();
+                let src_y = self.planes[Plane::Y.as_usize()].unwrap_ref().ptr16();
+                let src_uv = self.planes[Plane::U.as_usize()].unwrap_ref().ptr16();
+                let dst_y_pd = i010.plane_data(Plane::Y).unwrap();
+                let dst_u_pd = i010.plane_data(Plane::U).unwrap();
+                let dst_v_pd = i010.plane_data(Plane::V).unwrap();
+                let dst_y = i010.planes[Plane::Y.as_usize()].unwrap_mut().ptr16_mut();
+                let dst_u = i010.planes[Plane::U.as_usize()].unwrap_mut().ptr16_mut();
+                let dst_v = i010.planes[Plane::V.as_usize()].unwrap_mut().ptr16_mut();
+                // SAFETY: This function calls into libyuv which is a C++ library. We pass in
+                // pointers and strides to rust slices that are guaranteed to be valid.
+                let ret = unsafe {
+                    P010ToI010(
+                        src_y,
+                        i32_from_u32(src_y_pd.row_bytes / 2)?,
+                        src_uv,
+                        i32_from_u32(src_uv_pd.row_bytes / 2)?,
+                        dst_y,
+                        i32_from_u32(dst_y_pd.row_bytes / 2)?,
+                        dst_u,
+                        i32_from_u32(dst_u_pd.row_bytes / 2)?,
+                        dst_v,
+                        i32_from_u32(dst_v_pd.row_bytes / 2)?,
+                        i32_from_u32(self.width)?,
+                        i32_from_u32(self.height)?,
+                    )
+                };
+                if ret != 0 {
+                    return Err(AvifError::ReformatFailed);
+                }
+                i010
+            } else {
+                image::Image {
+                    width: self.width,
+                    height: self.height,
+                    depth: self.depth,
+                    yuv_format: self.yuv_format,
+                    planes: self
+                        .planes
+                        .as_ref()
+                        .iter()
+                        .map(|plane| {
+                            if plane.is_some() {
+                                plane.unwrap_ref().try_clone().ok()
+                            } else {
+                                None
+                            }
+                        })
+                        .collect::<Vec<_>>()
+                        .try_into()
+                        .unwrap(),
+                    row_bytes: self.row_bytes,
+                    ..image::Image::default()
+                }
+            };
 
         self.width = width;
         self.height = height;
+        self.depth = src.depth;
+        self.yuv_format = src.yuv_format;
         if src.has_plane(Plane::Y) || src.has_plane(Plane::A) {
             if src.width > 16384 || src.height > 16384 {
                 return Err(AvifError::NotImplemented);
@@ -69,6 +115,45 @@ impl Image {
                 self.allocate_planes(Category::Alpha)?;
             }
         }
+
+        if category != Category::Alpha
+            && (self.yuv_format == PixelFormat::AndroidNv12
+                || self.yuv_format == PixelFormat::AndroidNv21)
+        {
+            let src_y_pd = src.plane_data(Plane::Y).unwrap();
+            let src_uv_pd = src.plane_data(Plane::U).unwrap();
+            let src_y = src.planes[Plane::Y.as_usize()].unwrap_ref().ptr();
+            let src_uv = src.planes[Plane::U.as_usize()].unwrap_ref().ptr();
+            let dst_y_pd = self.plane_data(Plane::Y).unwrap();
+            let dst_uv_pd = self.plane_data(Plane::U).unwrap();
+            let dst_y = self.planes[Plane::Y.as_usize()].unwrap_mut().ptr_mut();
+            let dst_uv = self.planes[Plane::U.as_usize()].unwrap_mut().ptr_mut();
+            // SAFETY: This function calls into libyuv which is a C++ library. We pass in pointers
+            // and strides to rust slices that are guaranteed to be valid.
+            let ret = unsafe {
+                NV12Scale(
+                    src_y,
+                    i32_from_u32(src_y_pd.row_bytes)?,
+                    src_uv,
+                    i32_from_u32(src_uv_pd.row_bytes)?,
+                    i32_from_u32(src_y_pd.width)?,
+                    i32_from_u32(src_y_pd.height)?,
+                    dst_y,
+                    i32_from_u32(dst_y_pd.row_bytes)?,
+                    dst_uv,
+                    i32_from_u32(dst_uv_pd.row_bytes)?,
+                    i32_from_u32(dst_y_pd.width)?,
+                    i32_from_u32(dst_y_pd.height)?,
+                    FilterMode_kFilterBox,
+                )
+            };
+            if ret != 0 {
+                return Err(AvifError::ReformatFailed);
+            } else {
+                return Ok(());
+            }
+        }
+
         for plane in planes {
             if !src.has_plane(*plane) || !self.has_plane(*plane) {
                 continue;
@@ -83,8 +168,8 @@ impl Image {
             #[allow(clippy::let_unit_value)]
             let _ret = unsafe {
                 if src.depth > 8 {
-                    let source_ptr = src.planes[plane.to_usize()].unwrap_ref().ptr16();
-                    let dst_ptr = self.planes[plane.to_usize()].unwrap_mut().ptr16_mut();
+                    let source_ptr = src.planes[plane.as_usize()].unwrap_ref().ptr16();
+                    let dst_ptr = self.planes[plane.as_usize()].unwrap_mut().ptr16_mut();
                     ScalePlane_12(
                         source_ptr,
                         i32_from_u32(src_pd.row_bytes / 2)?,
@@ -97,8 +182,8 @@ impl Image {
                         FilterMode_kFilterBox,
                     )
                 } else {
-                    let source_ptr = src.planes[plane.to_usize()].unwrap_ref().ptr();
-                    let dst_ptr = self.planes[plane.to_usize()].unwrap_mut().ptr_mut();
+                    let source_ptr = src.planes[plane.as_usize()].unwrap_ref().ptr();
+                    let dst_ptr = self.planes[plane.as_usize()].unwrap_mut().ptr_mut();
                     ScalePlane(
                         source_ptr,
                         i32_from_u32(src_pd.row_bytes)?,
@@ -144,15 +229,15 @@ mod tests {
             30, 40,
         ];
         for plane in planes {
-            yuv.planes[plane.to_usize()] = Some(if is_pointer_input {
+            yuv.planes[plane.as_usize()] = Some(if is_pointer_input {
                 Pixels::Pointer(unsafe {
                     PointerSlice::create(values.as_mut_ptr(), values.len()).unwrap()
                 })
             } else {
                 Pixels::Buffer(values.to_vec())
             });
-            yuv.row_bytes[plane.to_usize()] = 2;
-            yuv.image_owns_planes[plane.to_usize()] = !is_pointer_input;
+            yuv.row_bytes[plane.as_usize()] = 2;
+            yuv.image_owns_planes[plane.as_usize()] = !is_pointer_input;
         }
         let categories: &[Category] =
             if use_alpha { &[Category::Color, Category::Alpha] } else { &[Category::Color] };
@@ -182,7 +267,7 @@ mod tests {
                     30, 33, 38, 40,
                 ],
             };
-            match &yuv.planes[plane.to_usize()] {
+            match &yuv.planes[plane.as_usize()] {
                 Some(Pixels::Buffer(samples)) => {
                     assert_eq!(*samples, expected_samples)
                 }
diff --git a/src/utils/clap.rs b/src/utils/clap.rs
index c758bca..d2137eb 100644
--- a/src/utils/clap.rs
+++ b/src/utils/clap.rs
@@ -13,7 +13,7 @@
 // limitations under the License.
 
 use crate::internal_utils::*;
-use crate::*;
+use crate::utils::*;
 
 #[derive(Clone, Copy, Debug, PartialEq)]
 pub struct CleanAperture {
diff --git a/src/utils/mod.rs b/src/utils/mod.rs
index 9cef362..f087aa8 100644
--- a/src/utils/mod.rs
+++ b/src/utils/mod.rs
@@ -12,6 +12,42 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+use crate::*;
+
 pub mod clap;
-pub mod raw;
-pub mod y4m;
+
+// Some HEIF fractional fields can be negative, hence Fraction and UFraction.
+// The denominator is always unsigned.
+
+/// cbindgen:field-names=[n,d]
+#[derive(Clone, Copy, Debug, Default)]
+#[repr(C)]
+pub struct Fraction(pub i32, pub u32);
+
+/// cbindgen:field-names=[n,d]
+#[derive(Clone, Copy, Debug, Default, PartialEq)]
+#[repr(C)]
+pub struct UFraction(pub u32, pub u32);
+
+impl Fraction {
+    pub(crate) fn is_valid(&self) -> AvifResult<()> {
+        match self.1 {
+            0 => Err(AvifError::InvalidArgument),
+            _ => Ok(()),
+        }
+    }
+
+    pub(crate) fn as_f64(&self) -> AvifResult<f64> {
+        self.is_valid()?;
+        Ok(self.0 as f64 / self.1 as f64)
+    }
+}
+
+impl UFraction {
+    pub(crate) fn is_valid(&self) -> AvifResult<()> {
+        match self.1 {
+            0 => Err(AvifError::InvalidArgument),
+            _ => Ok(()),
+        }
+    }
+}
diff --git a/src/utils/raw.rs b/src/utils/raw.rs
deleted file mode 100644
index 18ff05f..0000000
--- a/src/utils/raw.rs
+++ /dev/null
@@ -1,117 +0,0 @@
-// Copyright 2024 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-use crate::image::Image;
-use crate::image::ALL_PLANES;
-use crate::reformat::rgb;
-use crate::OptionExtension;
-
-use std::fs::File;
-use std::io::prelude::*;
-
-#[derive(Default)]
-pub struct RawWriter {
-    pub filename: Option<String>,
-    pub rgb: bool,
-    file: Option<File>,
-}
-
-impl RawWriter {
-    pub fn create(filename: &str) -> Self {
-        Self {
-            filename: Some(filename.to_owned()),
-            ..Self::default()
-        }
-    }
-
-    fn write_header(&mut self) -> bool {
-        if self.file.is_none() {
-            assert!(self.filename.is_some());
-            let file = File::create(self.filename.unwrap_ref());
-            if file.is_err() {
-                return false;
-            }
-            self.file = Some(file.unwrap());
-        }
-        true
-    }
-
-    pub fn write_frame(&mut self, image: &Image) -> bool {
-        if !self.write_header() {
-            return false;
-        }
-        if self.rgb {
-            let mut rgb = rgb::Image::create_from_yuv(image);
-            rgb.format = rgb::Format::Rgba;
-            rgb.depth = 16;
-            //rgb.depth = 8;
-            rgb.premultiply_alpha = true;
-            rgb.is_float = true;
-            if rgb.allocate().is_err() || rgb.convert_from_yuv(image).is_err() {
-                return false;
-            }
-            for y in 0..rgb.height {
-                if rgb.depth == 8 {
-                    let row = rgb.row(y).unwrap();
-                    if self.file.unwrap_ref().write_all(row).is_err() {
-                        return false;
-                    }
-                } else {
-                    let row = rgb.row16(y).unwrap();
-                    let mut row16: Vec<u8> = Vec::new();
-                    for &pixel in row {
-                        row16.extend_from_slice(&pixel.to_be_bytes());
-                    }
-                    if self.file.unwrap_ref().write_all(&row16[..]).is_err() {
-                        return false;
-                    }
-                }
-            }
-            return true;
-        }
-        for plane in ALL_PLANES {
-            let plane_data = image.plane_data(plane);
-            if plane_data.is_none() {
-                continue;
-            }
-            let plane_data = plane_data.unwrap();
-            for y in 0..plane_data.height {
-                if image.depth == 8 {
-                    let row = image.row(plane, y);
-                    if row.is_err() {
-                        return false;
-                    }
-                    let row = &row.unwrap()[..plane_data.width as usize];
-                    if self.file.unwrap_ref().write_all(row).is_err() {
-                        return false;
-                    }
-                } else {
-                    let row = image.row16(plane, y);
-                    if row.is_err() {
-                        return false;
-                    }
-                    let row = &row.unwrap()[..plane_data.width as usize];
-                    let mut row16: Vec<u8> = Vec::new();
-                    for &pixel in row {
-                        row16.extend_from_slice(&pixel.to_le_bytes());
-                    }
-                    if self.file.unwrap_ref().write_all(&row16[..]).is_err() {
-                        return false;
-                    }
-                }
-            }
-        }
-        true
-    }
-}
diff --git a/sys/aom-sys/Cargo.toml b/sys/aom-sys/Cargo.toml
new file mode 100644
index 0000000..7bb776d
--- /dev/null
+++ b/sys/aom-sys/Cargo.toml
@@ -0,0 +1,8 @@
+[package]
+name = "aom-sys"
+version = "0.1.0"
+edition = "2021"
+
+[build-dependencies]
+bindgen = "0.69.2"
+pkg-config = "0.3.29"
diff --git a/sys/aom-sys/aom.cmd b/sys/aom-sys/aom.cmd
new file mode 100755
index 0000000..3f3804e
--- /dev/null
+++ b/sys/aom-sys/aom.cmd
@@ -0,0 +1,19 @@
+: # If you want to use a local build of libaom, you must clone the aom repo in this directory first, then set CMake's AVIF_CODEC_AOM to LOCAL options.
+: # The git SHA below is known to work, and will occasionally be updated. Feel free to use a more recent commit.
+
+: # The odd choice of comment style in this file is to try to share this script between *nix and win32.
+
+: # cmake and ninja must be in your PATH.
+
+: # If you're running this on Windows, be sure you've already run this (from your VC2019 install dir):
+: #     "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
+
+git clone -b v3.12.0 --depth 1 https://aomedia.googlesource.com/aom
+
+cd aom
+mkdir build.libavif
+cd build.libavif
+
+cmake -G Ninja -DBUILD_SHARED_LIBS=OFF -DCONFIG_PIC=1 -DCMAKE_BUILD_TYPE=Release -DENABLE_DOCS=0 -DENABLE_EXAMPLES=0 -DENABLE_TESTDATA=0 -DENABLE_TESTS=0 -DENABLE_TOOLS=0 ..
+cd ../..
+ninja -C aom/build.libavif
diff --git a/sys/aom-sys/build.rs b/sys/aom-sys/build.rs
new file mode 100644
index 0000000..4047955
--- /dev/null
+++ b/sys/aom-sys/build.rs
@@ -0,0 +1,97 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+// Build rust library and bindings for libaom.
+
+use std::env;
+use std::path::Path;
+use std::path::PathBuf;
+
+extern crate pkg_config;
+
+fn main() {
+    println!("cargo:rerun-if-changed=build.rs");
+
+    let build_target = std::env::var("TARGET").unwrap();
+    let build_dir = if build_target.contains("android") {
+        if build_target.contains("x86_64") {
+            "build.android/x86_64"
+        } else if build_target.contains("x86") {
+            "build.android/x86"
+        } else if build_target.contains("aarch64") {
+            "build.android/aarch64"
+        } else if build_target.contains("arm") {
+            "build.android/arm"
+        } else {
+            panic!("Unknown target_arch for android. Must be one of x86, x86_64, arm, aarch64.");
+        }
+    } else {
+        "build.libavif"
+    };
+
+    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
+    // Prefer locally built libaom if available.
+    let abs_library_dir = PathBuf::from(&project_root).join("aom");
+    let abs_object_dir = PathBuf::from(&abs_library_dir).join(build_dir);
+    let library_file = PathBuf::from(&abs_object_dir).join("libaom.a");
+    let mut include_paths: Vec<String> = Vec::new();
+    if Path::new(&library_file).exists() {
+        println!("cargo:rustc-link-search={}", abs_object_dir.display());
+        println!("cargo:rustc-link-lib=static=aom");
+        let version_dir = PathBuf::from(&abs_library_dir)
+            .join(build_dir)
+            .join("config");
+        include_paths.push(format!("-I{}", version_dir.display()));
+        let include_dir = PathBuf::from(&abs_library_dir);
+        include_paths.push(format!("-I{}", include_dir.display()));
+    } else {
+        let library = pkg_config::Config::new().probe("aom");
+        if library.is_err() {
+            println!(
+                "aom could not be found with pkg-config. Install the system library or run aom.cmd"
+            );
+        }
+        let library = library.unwrap();
+        for lib in &library.libs {
+            println!("cargo:rustc-link-lib={lib}");
+        }
+        for link_path in &library.link_paths {
+            println!("cargo:rustc-link-search={}", link_path.display());
+        }
+        for include_path in &library.include_paths {
+            include_paths.push(format!("-I{}", include_path.display()));
+        }
+    }
+
+    // Generate bindings.
+    let header_file = PathBuf::from(&project_root).join("wrapper.h");
+    let outfile = PathBuf::from(&project_root).join("aom.rs");
+    let bindings = bindgen::Builder::default()
+        .header(header_file.into_os_string().into_string().unwrap())
+        .clang_args(&include_paths)
+        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
+        .layout_tests(false)
+        .generate_comments(false);
+    // TODO: b/402941742 - Add an allowlist to only generate bindings for necessary items.
+    let bindings = bindings
+        .generate()
+        .unwrap_or_else(|_| panic!("Unable to generate bindings for aom."));
+    bindings
+        .write_to_file(outfile.as_path())
+        .unwrap_or_else(|_| panic!("Couldn't write bindings for aom"));
+    println!(
+        "cargo:rustc-env=CRABBYAVIF_AOM_BINDINGS_RS={}",
+        outfile.display()
+    );
+}
diff --git a/sys/aom-sys/src/lib.rs b/sys/aom-sys/src/lib.rs
new file mode 100644
index 0000000..34191b2
--- /dev/null
+++ b/sys/aom-sys/src/lib.rs
@@ -0,0 +1,18 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#![allow(warnings)]
+pub mod bindings {
+    include!(env!("CRABBYAVIF_AOM_BINDINGS_RS"));
+}
diff --git a/sys/aom-sys/wrapper.h b/sys/aom-sys/wrapper.h
new file mode 100644
index 0000000..4980445
--- /dev/null
+++ b/sys/aom-sys/wrapper.h
@@ -0,0 +1,18 @@
+/*
+ * Copyright 2025 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <aom/aom_encoder.h>
+#include <aom/aomcx.h>
diff --git a/sys/ndk-sys/build.rs b/sys/ndk-sys/build.rs
index 88710aa..3f4f5b5 100644
--- a/sys/ndk-sys/build.rs
+++ b/sys/ndk-sys/build.rs
@@ -67,6 +67,7 @@ fn main() {
         "AMediaCodec_stop",
         "AMediaFormat",
         "AMediaFormat_delete",
+        "AMediaFormat_getBuffer",
         "AMediaFormat_getInt32",
         "AMediaFormat_new",
         "AMediaFormat_setBuffer",
diff --git a/tests/conformance_tests.rs b/tests/conformance_tests.rs
index 596d551..6f9b65a 100644
--- a/tests/conformance_tests.rs
+++ b/tests/conformance_tests.rs
@@ -13,7 +13,6 @@
 // limitations under the License.
 
 use crabby_avif::image::*;
-use crabby_avif::utils::y4m;
 use crabby_avif::*;
 
 use std::env;
@@ -24,6 +23,11 @@ use std::io::Read;
 use std::process::Command;
 use tempfile::NamedTempFile;
 
+#[path = "../examples/writer/mod.rs"]
+mod writer;
+
+use writer::Writer;
+
 // See README.md for instructions on how to set up the dependencies for
 // running the conformance tests.
 
@@ -105,9 +109,11 @@ fn get_tempfile() -> String {
 }
 
 fn write_y4m(image: &Image) -> String {
+    let mut y4m = writer::y4m::Y4MWriter::default();
     let filename = get_tempfile();
-    let mut y4m = y4m::Y4MWriter::create(&filename);
-    assert!(y4m.write_frame(image));
+    let mut file = File::create(&filename).expect("unable to open output file");
+    y4m.write_frame(&mut file, image)
+        .expect("unable to write y4m frame");
     filename
 }
 
diff --git a/tests/data/alpha_premultiplied.avif b/tests/data/alpha_premultiplied.avif
new file mode 100644
index 0000000..4d42519
Binary files /dev/null and b/tests/data/alpha_premultiplied.avif differ
diff --git a/tests/data/clap_irot_imir_non_essential.avif b/tests/data/clap_irot_imir_non_essential.avif
new file mode 100644
index 0000000..bcbe87d
Binary files /dev/null and b/tests/data/clap_irot_imir_non_essential.avif differ
diff --git a/tests/data/colors-animated-8bpc-audio.avif b/tests/data/colors-animated-8bpc-audio.avif
new file mode 100644
index 0000000..93d2cb5
Binary files /dev/null and b/tests/data/colors-animated-8bpc-audio.avif differ
diff --git a/tests/data/colors-animated-8bpc-depth-exif-xmp.avif b/tests/data/colors-animated-8bpc-depth-exif-xmp.avif
new file mode 100644
index 0000000..5ce9bad
Binary files /dev/null and b/tests/data/colors-animated-8bpc-depth-exif-xmp.avif differ
diff --git a/tests/data/overlay_exact_bounds.avif b/tests/data/overlay_exact_bounds.avif
new file mode 100644
index 0000000..7a2f34c
Binary files /dev/null and b/tests/data/overlay_exact_bounds.avif differ
diff --git a/tests/data/overlay_outside_bounds.avif b/tests/data/overlay_outside_bounds.avif
new file mode 100644
index 0000000..67e5a05
Binary files /dev/null and b/tests/data/overlay_outside_bounds.avif differ
diff --git a/tests/data/overlay_with_border.avif b/tests/data/overlay_with_border.avif
new file mode 100644
index 0000000..7e83e9b
Binary files /dev/null and b/tests/data/overlay_with_border.avif differ
diff --git a/tests/data/overlay_yellow_bg.avif b/tests/data/overlay_yellow_bg.avif
new file mode 100644
index 0000000..a6d213b
Binary files /dev/null and b/tests/data/overlay_yellow_bg.avif differ
diff --git a/tests/data/sacre_coeur.png b/tests/data/sacre_coeur.png
index 923d8d9..b3403e8 100644
Binary files a/tests/data/sacre_coeur.png and b/tests/data/sacre_coeur.png differ
diff --git a/tests/decoder_tests.rs b/tests/decoder_tests.rs
index d533756..186ded4 100644
--- a/tests/decoder_tests.rs
+++ b/tests/decoder_tests.rs
@@ -57,10 +57,32 @@ fn alpha_no_ispe() {
     assert!(alpha_plane.unwrap().row_bytes > 0);
 }
 
-// From avifanimationtest.cc
 #[test]
-fn animated_image() {
-    let mut decoder = get_decoder("colors-animated-8bpc.avif");
+fn alpha_premultiplied() {
+    let mut decoder = get_decoder("alpha_premultiplied.avif");
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    let image = decoder.image().expect("image was none");
+    assert!(image.alpha_present);
+    assert!(image.alpha_premultiplied);
+    if !HAS_DECODER {
+        return;
+    }
+    let res = decoder.next_image();
+    assert!(res.is_ok());
+    let image = decoder.image().expect("image was none");
+    assert!(image.alpha_present);
+    assert!(image.alpha_premultiplied);
+    let alpha_plane = image.plane_data(Plane::A);
+    assert!(alpha_plane.is_some());
+    assert!(alpha_plane.unwrap().row_bytes > 0);
+}
+
+// From avifanimationtest.cc
+#[test_case::test_case("colors-animated-8bpc.avif")]
+#[test_case::test_case("colors-animated-8bpc-audio.avif")]
+fn animated_image(filename: &str) {
+    let mut decoder = get_decoder(filename);
     let res = decoder.parse();
     assert!(res.is_ok());
     assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
@@ -81,9 +103,10 @@ fn animated_image() {
 }
 
 // From avifanimationtest.cc
-#[test]
-fn animated_image_with_source_set_to_primary_item() {
-    let mut decoder = get_decoder("colors-animated-8bpc.avif");
+#[test_case::test_case("colors-animated-8bpc.avif")]
+#[test_case::test_case("colors-animated-8bpc-audio.avif")]
+fn animated_image_with_source_set_to_primary_item(filename: &str) {
+    let mut decoder = get_decoder(filename);
     decoder.settings.source = decoder::Source::PrimaryItem;
     let res = decoder.parse();
     assert!(res.is_ok());
@@ -128,6 +151,54 @@ fn animated_image_with_alpha_and_metadata() {
     }
 }
 
+#[test]
+fn animated_image_with_depth_and_metadata() {
+    // Depth map data is not supported and should be ignored.
+    let mut decoder = get_decoder("colors-animated-8bpc-depth-exif-xmp.avif");
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
+    let image = decoder.image().expect("image was none");
+    assert!(!image.alpha_present);
+    assert!(image.image_sequence_track_present);
+    assert_eq!(decoder.image_count(), 5);
+    assert_eq!(decoder.repetition_count(), RepetitionCount::Infinite);
+    assert_eq!(image.exif.len(), 1126);
+    assert_eq!(image.xmp.len(), 3898);
+    if !HAS_DECODER {
+        return;
+    }
+    for _ in 0..5 {
+        assert!(decoder.next_image().is_ok());
+    }
+}
+
+#[test]
+fn animated_image_with_depth_and_metadata_source_set_to_primary_item() {
+    // Depth map data is not supported and should be ignored.
+    let mut decoder = get_decoder("colors-animated-8bpc-depth-exif-xmp.avif");
+    decoder.settings.source = decoder::Source::PrimaryItem;
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
+    let image = decoder.image().expect("image was none");
+    assert!(!image.alpha_present);
+    // This will be reported as true irrespective of the preferred source.
+    assert!(image.image_sequence_track_present);
+    // imageCount is expected to be 1 because we are using primary item as the
+    // preferred source.
+    assert_eq!(decoder.image_count(), 1);
+    assert_eq!(decoder.repetition_count(), RepetitionCount::Finite(0));
+    if !HAS_DECODER {
+        return;
+    }
+    // Get the first (and only) image.
+    assert!(decoder.next_image().is_ok());
+    // Subsequent calls should not return anything since there is only one
+    // image in the preferred source.
+    assert!(decoder.next_image().is_err());
+}
+
 // From avifkeyframetest.cc
 #[test]
 fn keyframes() {
@@ -952,3 +1023,180 @@ fn heic_parsing() {
         assert!(res.is_err());
     }
 }
+
+#[test]
+fn clap_irot_imir_non_essential() {
+    let mut decoder = get_decoder("clap_irot_imir_non_essential.avif");
+    let res = decoder.parse();
+    assert!(res.is_err());
+}
+
+#[derive(Clone)]
+struct ExpectedOverlayImageInfo<'a> {
+    filename: &'a str,
+    width: u32,
+    height: u32,
+    expected_pixels: &'a [(usize, u32, [u8; 4])], // (x, y, [rgba]).
+}
+
+const RED: [u8; 4] = [255, 0, 0, 255];
+const GREEN: [u8; 4] = [0, 255, 0, 255];
+const BLUE: [u8; 4] = [0, 0, 255, 255];
+const BLACK: [u8; 4] = [0, 0, 0, 255];
+const YELLOW: [u8; 4] = [255, 255, 0, 255];
+
+const EXPECTED_OVERLAY_IMAGE_INFOS: [ExpectedOverlayImageInfo; 4] = [
+    ExpectedOverlayImageInfo {
+        // Three 80x60 sub-images with the following offsets:
+        // horizontal_offsets: [0, 40, 80]
+        // vertical_offsets: [0, 40, 80]
+        filename: "overlay_exact_bounds.avif",
+        width: 160,
+        height: 140,
+        expected_pixels: &[
+            // Top left should be red.
+            (0, 0, RED),
+            (10, 10, RED),
+            (20, 20, RED),
+            // Green should be overlaid on top of the red block starting at (40, 40).
+            (40, 40, GREEN),
+            (50, 50, GREEN),
+            (60, 60, GREEN),
+            // Blue should be overlaid on top of the green block starting at (80, 80).
+            (80, 80, BLUE),
+            (90, 90, BLUE),
+            (100, 100, BLUE),
+            // Top right should be background color.
+            (159, 0, BLACK),
+            // Bottom left should be background color.
+            (0, 139, BLACK),
+        ],
+    },
+    ExpectedOverlayImageInfo {
+        // Three 80x60 sub-images with the following offsets:
+        // horizontal_offsets: [20, 60, 100]
+        // vertical_offsets: [20, 60, 100]
+        filename: "overlay_with_border.avif",
+        width: 200,
+        height: 180,
+        expected_pixels: &[
+            // Top left should be background color.
+            (0, 0, BLACK),
+            // Red should be overlaid starting at (20, 20).
+            (20, 20, RED),
+            (30, 30, RED),
+            (40, 40, RED),
+            // Green should be overlaid on top of the red block starting at (60, 60).
+            (60, 60, GREEN),
+            (70, 70, GREEN),
+            (80, 80, GREEN),
+            // Blue should be overlaid on top of the green block starting at (100, 100).
+            (100, 100, BLUE),
+            (110, 110, BLUE),
+            (120, 120, BLUE),
+            // Top right should be background color.
+            (199, 0, BLACK),
+            // Bottom left should be background color.
+            (0, 179, BLACK),
+            // Bottom right should be background color.
+            (199, 179, BLACK),
+        ],
+    },
+    ExpectedOverlayImageInfo {
+        // Two 80x60 sub-images with the following offsets:
+        // horizontal_offsets: [-40, 120]
+        // vertical_offsets: [-40, 100]
+        filename: "overlay_outside_bounds.avif",
+        width: 160,
+        height: 140,
+        expected_pixels: &[
+            // Red overlay is 40x20 in the top left.
+            (0, 0, RED),
+            (15, 15, RED),
+            (39, 19, RED),
+            (40, 20, BLACK),
+            // Blue overlay is 40x40 in the bottom right.
+            (119, 99, BLACK),
+            (120, 100, BLUE),
+            (140, 120, BLUE),
+            (159, 139, BLUE),
+            // Center of the image should be background color.
+            (80, 70, BLACK),
+            // Top right should be background color.
+            (159, 0, BLACK),
+            // Bottom left should be background color.
+            (0, 139, BLACK),
+        ],
+    },
+    ExpectedOverlayImageInfo {
+        // Three 80x60 sub-images with the following offsets:
+        // horizontal_offsets: [0, 40, 80]
+        // vertical_offsets: [0, 40, 80]
+        // canvas background color: yellow.
+        filename: "overlay_yellow_bg.avif",
+        width: 160,
+        height: 140,
+        expected_pixels: &[
+            // Top left should be red.
+            (0, 0, RED),
+            (10, 10, RED),
+            (20, 20, RED),
+            // Green should be overlaid on top of the red block starting at (40, 40).
+            (40, 40, GREEN),
+            (50, 50, GREEN),
+            (60, 60, GREEN),
+            // Blue should be overlaid on top of the green block starting at (80, 80).
+            (80, 80, BLUE),
+            (90, 90, BLUE),
+            (100, 100, BLUE),
+            // Top right should be background color.
+            (159, 0, YELLOW),
+            // Bottom left should be background color.
+            (0, 139, YELLOW),
+        ],
+    },
+];
+
+macro_rules! pixel_eq {
+    ($a:expr, $b:expr) => {
+        assert!((i32::from($a) - i32::from($b)).abs() <= 3);
+    };
+}
+
+#[test_case::test_matrix(0usize..4)]
+fn overlay(index: usize) {
+    let info = &EXPECTED_OVERLAY_IMAGE_INFOS[index];
+    let mut decoder = get_decoder(info.filename);
+    decoder.settings.strictness = decoder::Strictness::None;
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
+    let image = decoder.image().expect("image was none");
+    assert_eq!(image.width, info.width);
+    assert_eq!(image.height, info.height);
+    if !HAS_DECODER {
+        return;
+    }
+    let res = decoder.next_image();
+    assert!(res.is_ok());
+    let image = decoder.image().expect("image was none");
+    assert_eq!(image.width, info.width);
+    assert_eq!(image.height, info.height);
+    let mut rgb = rgb::Image::create_from_yuv(image);
+    rgb.format = rgb::Format::Rgba;
+    assert!(rgb.allocate().is_ok());
+    assert!(rgb.convert_from_yuv(image).is_ok());
+    for expected_pixel in info.expected_pixels {
+        let column = expected_pixel.0;
+        let row = expected_pixel.1;
+        let pixels = rgb.row(row).expect("row was none");
+        let r = pixels[column * 4];
+        let g = pixels[(column * 4) + 1];
+        let b = pixels[(column * 4) + 2];
+        let a = pixels[(column * 4) + 3];
+        pixel_eq!(r, expected_pixel.2[0]);
+        pixel_eq!(g, expected_pixel.2[1]);
+        pixel_eq!(b, expected_pixel.2[2]);
+        pixel_eq!(a, expected_pixel.2[3]);
+    }
+}
diff --git a/tests/iloc_extents_test.rs b/tests/iloc_extents_test.rs
index 2d36fc6..95d18fe 100644
--- a/tests/iloc_extents_test.rs
+++ b/tests/iloc_extents_test.rs
@@ -16,7 +16,6 @@
 mod tests;
 
 use crabby_avif::reformat::rgb::*;
-use image::ImageReader;
 use tests::*;
 
 #[test]
@@ -32,19 +31,16 @@ fn iloc_extents() {
     rgb.format = Format::Rgb;
     assert!(rgb.allocate().is_ok());
     assert!(rgb.convert_from_yuv(decoded).is_ok());
-
-    let source = ImageReader::open(get_test_file("sacre_coeur.png"));
-    let source = source.unwrap().decode().unwrap();
-
+    let source = decode_png("sacre_coeur.png");
     // sacre_coeur_2extents.avif was generated with
     //   avifenc --lossless --ignore-exif --ignore-xmp --ignore-icc sacre_coeur.png
     // so pixels can be compared byte by byte.
     assert_eq!(
-        source.as_bytes(),
+        source,
         rgb.pixels
             .as_ref()
             .unwrap()
-            .slice(0, source.as_bytes().len() as u32)
+            .slice(0, source.len() as u32)
             .unwrap()
     );
 }
diff --git a/tests/lossless_test.rs b/tests/lossless_test.rs
index b9f4d4f..65bf673 100644
--- a/tests/lossless_test.rs
+++ b/tests/lossless_test.rs
@@ -16,7 +16,6 @@
 mod tests;
 
 use crabby_avif::reformat::rgb::*;
-use image::ImageReader;
 use tests::*;
 
 #[test_case::test_case("paris_identity.avif", "paris_icc_exif_xmp.png"; "lossless_identity")]
@@ -34,16 +33,13 @@ fn lossless(avif_file: &str, png_file: &str) {
     rgb.format = Format::Rgb;
     assert!(rgb.allocate().is_ok());
     assert!(rgb.convert_from_yuv(decoded).is_ok());
-
-    let source = ImageReader::open(get_test_file(png_file));
-    let source = source.unwrap().decode().unwrap();
-
+    let source = decode_png(png_file);
     assert_eq!(
-        source.as_bytes(),
+        source,
         rgb.pixels
             .as_ref()
             .unwrap()
-            .slice(0, source.as_bytes().len() as u32)
+            .slice(0, source.len() as u32)
             .unwrap()
     );
 }
diff --git a/tests/mod.rs b/tests/mod.rs
index 34c2d8c..81bd6fd 100644
--- a/tests/mod.rs
+++ b/tests/mod.rs
@@ -12,7 +12,12 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+// Not all functions are used from all test targets. So allow unused functions in this module.
+#![allow(unused)]
+
 use crabby_avif::*;
+use png;
+use std::fs::File;
 
 #[cfg(test)]
 pub fn get_test_file(filename: &str) -> String {
@@ -37,6 +42,17 @@ pub fn get_decoder(filename: &str) -> decoder::Decoder {
     decoder
 }
 
+#[cfg(test)]
+pub fn decode_png(filename: &str) -> Vec<u8> {
+    let decoder = png::Decoder::new(File::open(get_test_file(filename)).unwrap());
+    let mut reader = decoder.read_info().unwrap();
+    // Indexed colors are not supported.
+    assert_ne!(reader.output_color_type().0, png::ColorType::Indexed);
+    let mut pixels = vec![0; reader.output_buffer_size()];
+    let info = reader.next_frame(&mut pixels).unwrap();
+    pixels
+}
+
 #[cfg(test)]
 #[allow(dead_code)]
 pub const HAS_DECODER: bool = if cfg!(any(
```

