```diff
diff --git a/.github/actions/setup-deps/action.yml b/.github/actions/setup-deps/action.yml
new file mode 100644
index 0000000..b58aa5b
--- /dev/null
+++ b/.github/actions/setup-deps/action.yml
@@ -0,0 +1,57 @@
+name: "Set up the dependencies"
+description: "Build all the necessary external dependencies"
+runs:
+  using: "composite"
+  steps:
+  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
+
+  - name: Setup Visual Studio shell
+    if: runner.os == 'Windows'
+    uses: egor-tensin/vs-shell@9a932a62d05192eae18ca370155cf877eecc2202 # v2.1
+
+  - name: Cache external dependencies
+    id: cache-ext
+    uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
+    with:
+      path: |
+        sys
+        external
+      key: ${{ runner.os }}-${{ hashFiles('sys/dav1d-sys/Cargo.toml', 'sys/dav1d-sys/dav1d.cmd', 'sys/dav1d-sys/build.rs', 'sys/libyuv-sys/Cargo.toml', 'sys/libyuv-sys/libyuv.cmd', 'sys/libyuv-sys/build.rs', 'sys/libgav1-sys/Cargo.toml', 'sys/libgav1-sys/libgav1.cmd', 'sys/libgav1-sys/build.rs', 'external/googletest.cmd', 'sys/aom-sys/Cargo.toml', 'sys/aom-sys/aom.cmd', 'sys/aom-sys/build.rs') }}
+
+  - uses: jwlawson/actions-setup-cmake@d06b37b47cfd043ec794ffa3e40e0b6b5858a7ec # v1.14.2
+    if: steps.cache-ext.outputs.cache-hit != 'true'
+  - uses: ilammy/setup-nasm@13cbeb366c45c4379d3478cdcbadd8295feb5028 # v1.5.1
+    if: steps.cache-ext.outputs.cache-hit != 'true'
+  - uses: seanmiddleditch/gha-setup-ninja@8b297075da4cd2a5f1fd21fe011b499edf06e9d2 # v4
+    if: steps.cache-ext.outputs.cache-hit != 'true'
+  - run: pip install meson
+    if: steps.cache-ext.outputs.cache-hit != 'true'
+    shell: bash
+  - name: Build dav1d
+    if: steps.cache-ext.outputs.cache-hit != 'true'
+    working-directory: ./sys/dav1d-sys
+    run: ./dav1d.cmd
+    shell: bash
+  - name: Build libyuv
+    if: steps.cache-ext.outputs.cache-hit != 'true'
+    working-directory: ./sys/libyuv-sys
+    run: ./libyuv.cmd
+    shell: bash
+  - name: Build aom
+    if: steps.cache-ext.outputs.cache-hit != 'true'
+    working-directory: ./sys/aom-sys
+    run: ./aom.cmd
+    shell: bash
+  - name: Build libgav1
+    if: steps.cache-ext.outputs.cache-hit != 'true'
+    working-directory: ./sys/libgav1-sys
+    run: ./libgav1.cmd
+    shell: bash
+  - name: Build GoogleTest
+    if: steps.cache-ext.outputs.cache-hit != 'true' && runner.os != 'Windows'
+    working-directory: ./external
+    run: ./googletest.cmd
+    shell: bash
+  - uses: actions-rs/toolchain@16499b5e05bf2e26879000db0c1d13f7e13fa3af # v1.0.7
+    with:
+      toolchain: stable
diff --git a/.github/workflows/build-and-run-tests.yml b/.github/workflows/build-and-run-tests.yml
index deab89d..5d2d1c5 100644
--- a/.github/workflows/build-and-run-tests.yml
+++ b/.github/workflows/build-and-run-tests.yml
@@ -28,63 +28,20 @@ jobs:
     steps:
     - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
 
-    - name: Setup Visual Studio shell
-      if: runner.os == 'Windows'
-      uses: egor-tensin/vs-shell@9a932a62d05192eae18ca370155cf877eecc2202 # v2.1
-
-    - name: Cache external dependencies
-      id: cache-ext
-      uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
-      with:
-        path: |
-          sys
-          external
-        key: ${{ runner.os }}-${{ hashFiles('sys/dav1d-sys/Cargo.toml', 'sys/dav1d-sys/dav1d.cmd', 'sys/dav1d-sys/build.rs', 'sys/libyuv-sys/Cargo.toml', 'sys/libyuv-sys/libyuv.cmd', 'sys/libyuv-sys/build.rs', 'sys/libgav1-sys/Cargo.toml', 'sys/libgav1-sys/libgav1.cmd', 'sys/libgav1-sys/build.rs', 'external/googletest.cmd') }}
-
-    - uses: jwlawson/actions-setup-cmake@d06b37b47cfd043ec794ffa3e40e0b6b5858a7ec # v1.14.2
-      if: steps.cache-ext.outputs.cache-hit != 'true'
-    - uses: ilammy/setup-nasm@13cbeb366c45c4379d3478cdcbadd8295feb5028 # v1.5.1
-      if: steps.cache-ext.outputs.cache-hit != 'true'
-    - uses: seanmiddleditch/gha-setup-ninja@8b297075da4cd2a5f1fd21fe011b499edf06e9d2 # v4
-      if: steps.cache-ext.outputs.cache-hit != 'true'
-    - run: pip install meson
-      if: steps.cache-ext.outputs.cache-hit != 'true'
-
-    - name: Build dav1d
-      if: steps.cache-ext.outputs.cache-hit != 'true'
-      working-directory: ./sys/dav1d-sys
-      run: ./dav1d.cmd
-    - name: Build libyuv
-      if: steps.cache-ext.outputs.cache-hit != 'true'
-      working-directory: ./sys/libyuv-sys
-      run: ./libyuv.cmd
-
-    - uses: actions-rs/toolchain@16499b5e05bf2e26879000db0c1d13f7e13fa3af # v1.0.7
-      with:
-        toolchain: stable
+    - uses: ./.github/actions/setup-deps
 
     - name: Build and run the Rust tests
       run: cargo test -- --skip test_conformance
 
-    - name: Build GoogleTest
-      if: steps.cache-ext.outputs.cache-hit != 'true' && runner.os != 'Windows'
-      working-directory: ./external
-      run: bash -e googletest.cmd
-
     - name: Build and run the C++ tests
       # TODO: This step fails on macos. So run it on linux only for now.
       if: runner.os == 'Linux'
       run: |
-        cargo build --features capi --release
+        cargo build --features capi,aom --release
         cmake -S c_api_tests -B c_build
         make -C c_build
         ctest --test-dir c_build -E conformance_tests
 
-    - name: Build libgav1
-      if: steps.cache-ext.outputs.cache-hit != 'true'
-      working-directory: ./sys/libgav1-sys
-      run: ./libgav1.cmd
-
     - name: Build and run the Rust tests with libgav1
       run: cargo test --no-default-features --features libgav1,libyuv -- --skip test_conformance
 
@@ -92,10 +49,15 @@ jobs:
       # TODO: This step fails on macos. So run it on linux only for now.
       if: runner.os == 'Linux'
       run: |
-        cargo build --no-default-features --features capi,libgav1,libyuv --release
+        cargo build --no-default-features --features capi,libgav1,libyuv,aom --release
         cmake -S c_api_tests -B c_build_gav1
         make -C c_build_gav1
         ctest --test-dir c_build_gav1 -E conformance_tests
 
     - name: Build and run the heic tests with heic feature enabled
-      run: cargo test --no-default-features --features heic heic
+      run: cargo test --features heic heic
+
+    - name: Build and run all the tests with aom feature enabled
+      # TODO: Enable this for windows.
+      if: runner.os != 'Windows'
+      run: cargo test --features aom -- --skip test_conformance
diff --git a/.github/workflows/c-header-file.yml b/.github/workflows/c-header-file.yml
index 04f0a09..5f4c89b 100644
--- a/.github/workflows/c-header-file.yml
+++ b/.github/workflows/c-header-file.yml
@@ -26,7 +26,7 @@ jobs:
         toolchain: stable
 
     - name: Build the library and generate the C header file
-      run: cargo build --features capi --release --no-default-features
+      run: cargo build --features capi,encoder --release --no-default-features
 
     - name: Ensure that there is no diff in the header file.
       run: git diff --exit-code include/avif/avif.h
diff --git a/.github/workflows/clippy.yml b/.github/workflows/clippy.yml
index 1fc0153..eef83cf 100644
--- a/.github/workflows/clippy.yml
+++ b/.github/workflows/clippy.yml
@@ -20,13 +20,14 @@ jobs:
 
     steps:
     - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
-
-    - uses: actions-rs/toolchain@16499b5e05bf2e26879000db0c1d13f7e13fa3af # v1.0.7
-      with:
-        toolchain: stable
-
-    - name: Run clippy
-      run: cargo clippy --no-default-features -- -Dwarnings
-
-    - name: Run clippy with C API
-      run: cargo clippy --no-default-features --features=capi -- -Dwarnings
+    - uses: ./.github/actions/setup-deps
+    - run: cargo clippy --no-default-features
+    - run: cargo clippy --no-default-features --features=capi
+    - run: cargo clippy
+    - run: cargo clippy --tests
+    - run: cargo clippy --examples
+    - run: cargo clippy --features aom
+    - run: cargo clippy --features aom --tests
+    - run: cargo clippy --features aom --examples
+    - run: cargo clippy --features sample_transform
+    - run: cargo clippy --features sample_transform --tests
diff --git a/.github/workflows/conformance-tests.yml b/.github/workflows/conformance-tests.yml
index 3747df0..cc78ced 100644
--- a/.github/workflows/conformance-tests.yml
+++ b/.github/workflows/conformance-tests.yml
@@ -130,5 +130,5 @@ jobs:
       run: |
         cargo build --features capi --release
         cmake -S c_api_tests -B c_build
-        make -C c_build
+        make -C c_build conformance_tests
         ctest --test-dir c_build -R conformance_tests
diff --git a/Cargo.toml b/Cargo.toml
index cdd294c..fd5710a 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -21,24 +21,23 @@ dav1d-sys = { version = "0.1.0", path = "sys/dav1d-sys", optional = true }
 libgav1-sys = { version = "0.1.0", path = "sys/libgav1-sys", optional = true }
 libyuv-sys = { version = "0.1.0", path = "sys/libyuv-sys", optional = true }
 aom-sys = { version = "0.1.0", path = "sys/aom-sys", optional = true }
+png = { version = "0.17.16", optional = true }
+image = { version = "0.24.0", features = ["jpeg"], optional = true }
 
 [dev-dependencies]
 test-case = "3.3.1"
 seq-macro = "0.3.5"
 tempfile = "3.8.1"
-exitcode = "1.1.2"
 rand = "0.8.5"
 clap = { version = "4.5.28", features = ["derive"] }
 clap_derive = { version = "4.5.28" }
-png = "0.17.16"
-image = { version = "0.24.0", features = ["jpeg"] }
 
 [build-dependencies]
 bindgen = "0.69.1"
 cbindgen = "0.26.0"
 
 [features]
-default = ["dav1d", "libyuv"]
+default = ["dav1d", "libyuv", "png", "jpeg"]
 capi = []
 dav1d = ["dep:libc", "dep:dav1d-sys"]
 libgav1 = ["dep:libgav1-sys"]
@@ -46,7 +45,11 @@ libyuv = ["dep:libyuv-sys"]
 android_mediacodec = ["dep:ndk-sys"]
 heic = []
 disable_cfi = []
-aom = ["dep:aom-sys"]
+aom = ["dep:aom-sys", "encoder"]
+encoder = []
+png = ["dep:png"]
+jpeg = ["dep:image"]
+sample_transform = []
 
 [package.metadata.capi.header]
 name = "avif"
diff --git a/METADATA b/METADATA
index 469cc6a..70cfc30 100644
--- a/METADATA
+++ b/METADATA
@@ -8,14 +8,14 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2025
-    month: 3
-    day: 18
+    month: 5
+    day: 21
   }
   homepage: "https://github.com/webmproject/CrabbyAvif"
   identifier {
     type: "Git"
     value: "https://github.com/webmproject/CrabbyAvif.git"
-    version: "963898a53d056da5ab97193fb3087e208c88dc34"
+    version: "de6dfdcdb290ea75ce39bfeed56263f9f2dce89d"
     primary_source: true
   }
 }
diff --git a/c_api_tests/CMakeLists.txt b/c_api_tests/CMakeLists.txt
index c72702a..e9641a5 100644
--- a/c_api_tests/CMakeLists.txt
+++ b/c_api_tests/CMakeLists.txt
@@ -30,10 +30,17 @@ set(GTEST_MAIN_LIBRARIES "${CARGO_ROOT_DIR}/external/googletest/build/lib/libgte
 set(CRABBY_AVIF_INCLUDE_DIR "${CARGO_ROOT_DIR}/include")
 set(CRABBY_AVIF_LIBRARIES "${CARGO_ROOT_DIR}/target/release/libcrabby_avif.so")
 
+add_library(testutil OBJECT testutil.cc)
+target_include_directories(testutil PRIVATE ${GTEST_INCLUDE_DIR})
+target_include_directories(testutil PRIVATE ${CRABBY_AVIF_INCLUDE_DIR})
+target_link_libraries(testutil PRIVATE ${GTEST_LIBRARIES})
+target_link_libraries(testutil PRIVATE ${CRABBY_AVIF_LIBRARIES})
+
 macro(add_avif_gtest TEST_NAME)
     add_executable(${TEST_NAME} ${TEST_NAME}.cc)
     target_include_directories(${TEST_NAME} PRIVATE ${GTEST_INCLUDE_DIR})
     target_include_directories(${TEST_NAME} PRIVATE ${CRABBY_AVIF_INCLUDE_DIR})
+    target_link_libraries(${TEST_NAME} PRIVATE testutil)
     target_link_libraries(${TEST_NAME} PRIVATE ${GTEST_LIBRARIES})
     target_link_libraries(${TEST_NAME} PRIVATE ${GTEST_MAIN_LIBRARIES})
     target_link_libraries(${TEST_NAME} PRIVATE ${CRABBY_AVIF_LIBRARIES})
@@ -41,6 +48,8 @@ macro(add_avif_gtest TEST_NAME)
 endmacro()
 
 add_avif_gtest(decoder_tests)
+add_avif_gtest(encoder_tests)
+add_avif_gtest(image_tests)
 add_avif_gtest(incremental_tests)
 add_avif_gtest(reformat_tests)
 
diff --git a/c_api_tests/decoder_tests.cc b/c_api_tests/decoder_tests.cc
index 345c92c..1092c76 100644
--- a/c_api_tests/decoder_tests.cc
+++ b/c_api_tests/decoder_tests.cc
@@ -491,6 +491,23 @@ TEST(DecoderTest, ParseICC) {
   EXPECT_EQ(decoder->image->xmp.data[3], 112);
 }
 
+TEST(DecoderTest, ParseExifNonZeroTiffOffset) {
+  auto decoder = CreateDecoder(("paris_exif_non_zero_tiff_offset.avif"));
+  ASSERT_NE(decoder, nullptr);
+
+  EXPECT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->compressionFormat, COMPRESSION_FORMAT_AVIF);
+
+  ASSERT_EQ(decoder->image->exif.size, 1129);
+  EXPECT_EQ(decoder->image->exif.data[0], 0);
+  EXPECT_EQ(decoder->image->exif.data[1], 0);
+  EXPECT_EQ(decoder->image->exif.data[2], 0);
+  EXPECT_EQ(decoder->image->exif.data[3], 73);
+  EXPECT_EQ(decoder->image->exif.data[4], 73);
+  EXPECT_EQ(decoder->image->exif.data[5], 42);
+  EXPECT_EQ(decoder->image->exif.data[6], 0);
+}
+
 bool CompareImages(const avifImage& image1, const avifImage image2) {
   EXPECT_EQ(image1.width, image2.width);
   EXPECT_EQ(image1.height, image2.height);
@@ -738,6 +755,93 @@ INSTANTIATE_TEST_SUITE_P(ScaleTestInstance, ScaleTest,
                          testing::ValuesIn({"paris_10bpc.avif",
                                             "paris_icc_exif_xmp.avif"}));
 
+TEST(ScaleTest, ScaleP010) {
+  const int width = 100;
+  const int height = 50;
+  ImagePtr image(
+      avifImageCreate(width, height, 10, AVIF_PIXEL_FORMAT_ANDROID_P010));
+  ASSERT_EQ(avifImageAllocatePlanes(image.get(), AVIF_PLANES_ALL),
+            AVIF_RESULT_OK);
+
+  const uint32_t scaled_width = static_cast<uint32_t>(width * 0.8);
+  const uint32_t scaled_height = static_cast<uint32_t>(height * 0.6);
+
+  ASSERT_EQ(avifImageScale(image.get(), scaled_width, scaled_height, nullptr),
+            AVIF_RESULT_OK);
+  EXPECT_EQ(image->width, scaled_width);
+  EXPECT_EQ(image->height, scaled_height);
+  EXPECT_EQ(image->depth, 10);
+  // When scaling a P010 image, crabbyavif converts it into an I010 (Yuv420)
+  // image.
+  EXPECT_EQ(image->yuvFormat, AVIF_PIXEL_FORMAT_YUV420);
+  for (int c = 0; c < 3; ++c) {
+    EXPECT_NE(image->yuvPlanes[c], nullptr);
+    EXPECT_GT(image->yuvRowBytes[c], 0);
+  }
+  EXPECT_NE(image->alphaPlane, nullptr);
+  EXPECT_NE(image->alphaRowBytes, 0);
+}
+
+TEST(ScaleTest, ScaleNV12OddDimensions) {
+  const int width = 99;
+  const int height = 49;
+  ImagePtr image(
+      avifImageCreate(width, height, 8, AVIF_PIXEL_FORMAT_ANDROID_NV12));
+  ASSERT_EQ(avifImageAllocatePlanes(image.get(), AVIF_PLANES_ALL),
+            AVIF_RESULT_OK);
+
+  const uint32_t scaled_width = 49;
+  const uint32_t scaled_height = 24;
+
+  ASSERT_EQ(avifImageScale(image.get(), scaled_width, scaled_height, nullptr),
+            AVIF_RESULT_OK);
+  EXPECT_EQ(image->width, scaled_width);
+  EXPECT_EQ(image->height, scaled_height);
+  EXPECT_EQ(image->depth, 8);
+  EXPECT_EQ(image->yuvFormat, AVIF_PIXEL_FORMAT_ANDROID_NV12);
+  for (int c = 0; c < 2; ++c) {
+    EXPECT_NE(image->yuvPlanes[c], nullptr);
+    EXPECT_GT(image->yuvRowBytes[c], 0);
+  }
+  EXPECT_EQ(image->yuvPlanes[2], nullptr);
+  EXPECT_EQ(image->yuvRowBytes[2], 0);
+  EXPECT_NE(image->alphaPlane, nullptr);
+  EXPECT_NE(image->alphaRowBytes, 0);
+}
+
+TEST(ScaleTest, ScaleNV12WithCopyOddDimensions) {
+  const int width = 99;
+  const int height = 49;
+  ImagePtr image(
+      avifImageCreate(width, height, 8, AVIF_PIXEL_FORMAT_ANDROID_NV12));
+  ASSERT_EQ(avifImageAllocatePlanes(image.get(), AVIF_PLANES_ALL),
+            AVIF_RESULT_OK);
+
+  // Create a copy of the image and scale the copy (this mimic's skia's
+  // implementation).
+  ImagePtr image2(avifImageCreateEmpty());
+  ASSERT_EQ(avifImageCopy(image2.get(), image.get(), AVIF_PLANES_ALL),
+            AVIF_RESULT_OK);
+
+  const uint32_t scaled_width = 49;
+  const uint32_t scaled_height = 24;
+
+  ASSERT_EQ(avifImageScale(image2.get(), scaled_width, scaled_height, nullptr),
+            AVIF_RESULT_OK);
+  EXPECT_EQ(image2->width, scaled_width);
+  EXPECT_EQ(image2->height, scaled_height);
+  EXPECT_EQ(image2->depth, 8);
+  EXPECT_EQ(image2->yuvFormat, AVIF_PIXEL_FORMAT_ANDROID_NV12);
+  for (int c = 0; c < 2; ++c) {
+    EXPECT_NE(image->yuvPlanes[c], nullptr);
+    EXPECT_GT(image->yuvRowBytes[c], 0);
+  }
+  EXPECT_EQ(image->yuvPlanes[2], nullptr);
+  EXPECT_EQ(image->yuvRowBytes[2], 0);
+  EXPECT_NE(image->alphaPlane, nullptr);
+  EXPECT_NE(image->alphaRowBytes, 0);
+}
+
 struct InvalidClapPropertyParam {
   uint32_t width;
   uint32_t height;
diff --git a/c_api_tests/encoder_tests.cc b/c_api_tests/encoder_tests.cc
new file mode 100644
index 0000000..65d42f5
--- /dev/null
+++ b/c_api_tests/encoder_tests.cc
@@ -0,0 +1,227 @@
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
+#include <array>
+#include <cstdint>
+#include <iostream>
+#include <tuple>
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
+// ICC color profiles are not checked by crabbyavif so the content does not
+// matter. This is a truncated widespread ICC color profile.
+constexpr std::array<uint8_t, 24> kSampleIcc = {
+    0x00, 0x00, 0x02, 0x0c, 0x6c, 0x63, 0x6d, 0x73, 0x02, 0x10, 0x00, 0x00,
+    0x6d, 0x6e, 0x74, 0x72, 0x52, 0x47, 0x42, 0x20, 0x58, 0x59, 0x5a, 0x20};
+
+// XMP bytes are not checked by crabbyavif so the content does not matter. This
+// is a truncated widespread XMP metadata chunk.
+constexpr std::array<uint8_t, 24> kSampleXmp = {
+    0x3c, 0x3f, 0x78, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x20, 0x62, 0x65,
+    0x67, 0x69, 0x6e, 0x3d, 0x22, 0xef, 0xbb, 0xbf, 0x22, 0x20, 0x69, 0x64};
+
+// Exif bytes are partially checked by crabbyavif. This is a truncated
+// widespread Exif metadata chunk.
+constexpr std::array<uint8_t, 24> kSampleExif = {
+    0xff, 0x1,  0x45, 0x78, 0x69, 0x76, 0x32, 0xff, 0xe1, 0x12, 0x5a, 0x45,
+    0x78, 0x69, 0x66, 0x0,  0x0,  0x49, 0x49, 0x2a, 0x0,  0x8,  0x0,  0x0};
+
+DecoderPtr CreateDecoder(const AvifRwData& encoded) {
+  DecoderPtr decoder(avifDecoderCreate());
+  if (decoder == nullptr ||
+      avifDecoderSetIOMemory(decoder.get(), encoded.data, encoded.size) !=
+          AVIF_RESULT_OK) {
+    return nullptr;
+  }
+  return decoder;
+}
+
+TEST(BasicTest, EncodeDecode) {
+  ImagePtr image = testutil::CreateImage(/*width=*/12, /*height=*/34,
+                                         /*depth=*/8, AVIF_PIXEL_FORMAT_YUV420,
+                                         AVIF_PLANES_ALL, AVIF_RANGE_FULL);
+  ASSERT_NE(image, nullptr);
+  testutil::FillImageGradient(image.get(), /*offset=*/0);
+
+  EncoderPtr encoder(avifEncoderCreate());
+  encoder->quality = 70;
+  encoder->speed = 10;
+  ASSERT_NE(encoder, nullptr);
+  AvifRwData encoded;
+  ASSERT_EQ(avifEncoderWrite(encoder.get(), image.get(), &encoded),
+            AVIF_RESULT_OK);
+
+  auto decoder = CreateDecoder(encoded);
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  ASSERT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->image->width, image->width);
+  EXPECT_EQ(decoder->image->height, image->height);
+  EXPECT_EQ(decoder->image->depth, image->depth);
+  ASSERT_GT(testutil::GetPsnr(*image, *decoder->image, /*ignore_alpha=*/false),
+            40.0);
+}
+
+TEST(TransformTest, ClapIrotImir) {
+  ImagePtr image = testutil::CreateImage(/*width=*/12, /*height=*/34,
+                                         /*depth=*/8, AVIF_PIXEL_FORMAT_YUV444,
+                                         AVIF_PLANES_ALL, AVIF_RANGE_FULL);
+  ASSERT_NE(image, nullptr);
+  testutil::FillImageGradient(image.get(), /*offset=*/0);
+  image->transformFlags |= AVIF_TRANSFORM_CLAP;
+  avifDiagnostics diag{};
+  const avifCropRect rect{/*x=*/4, /*y=*/6, /*width=*/8, /*height=*/10};
+  ASSERT_TRUE(avifCleanApertureBoxConvertCropRect(&image->clap, &rect,
+                                                  image->width, image->height,
+                                                  image->yuvFormat, &diag));
+  image->transformFlags |= AVIF_TRANSFORM_IROT;
+  image->irot.angle = 1;
+  image->transformFlags |= AVIF_TRANSFORM_IMIR;
+  image->imir.axis = 1;
+
+  EncoderPtr encoder(avifEncoderCreate());
+  encoder->speed = 10;
+  ASSERT_NE(encoder, nullptr);
+  AvifRwData encoded;
+  ASSERT_EQ(avifEncoderWrite(encoder.get(), image.get(), &encoded),
+            AVIF_RESULT_OK);
+
+  auto decoder = CreateDecoder(encoded);
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  ASSERT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+
+  EXPECT_EQ(decoder->image->transformFlags, image->transformFlags);
+  EXPECT_EQ(decoder->image->clap.widthN, image->clap.widthN);
+  EXPECT_EQ(decoder->image->clap.widthD, image->clap.widthD);
+  EXPECT_EQ(decoder->image->clap.heightN, image->clap.heightN);
+  EXPECT_EQ(decoder->image->clap.heightD, image->clap.heightD);
+  EXPECT_EQ(decoder->image->clap.horizOffN, image->clap.horizOffN);
+  EXPECT_EQ(decoder->image->clap.horizOffD, image->clap.horizOffD);
+  EXPECT_EQ(decoder->image->clap.vertOffN, image->clap.vertOffN);
+  EXPECT_EQ(decoder->image->clap.vertOffD, image->clap.vertOffD);
+  EXPECT_EQ(decoder->image->irot.angle, image->irot.angle);
+  EXPECT_EQ(decoder->image->imir.axis, image->imir.axis);
+}
+
+TEST(MetadataTest, IccExifXmp) {
+  ImagePtr image = testutil::CreateImage(/*width=*/12, /*height=*/34,
+                                         /*depth=*/8, AVIF_PIXEL_FORMAT_YUV444,
+                                         AVIF_PLANES_ALL, AVIF_RANGE_FULL);
+  ASSERT_NE(image, nullptr);
+  testutil::FillImageGradient(image.get(), /*offset=*/0);
+  ASSERT_EQ(avifRWDataSet(&image->icc, kSampleIcc.data(), kSampleIcc.size()),
+            AVIF_RESULT_OK);
+  ASSERT_EQ(avifRWDataSet(&image->exif, kSampleExif.data(), kSampleExif.size()),
+            AVIF_RESULT_OK);
+  ASSERT_EQ(avifRWDataSet(&image->xmp, kSampleXmp.data(), kSampleXmp.size()),
+            AVIF_RESULT_OK);
+
+  EncoderPtr encoder(avifEncoderCreate());
+  encoder->speed = 10;
+  ASSERT_NE(encoder, nullptr);
+  AvifRwData encoded;
+  ASSERT_EQ(avifEncoderWrite(encoder.get(), image.get(), &encoded),
+            AVIF_RESULT_OK);
+
+  auto decoder = CreateDecoder(encoded);
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  ASSERT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+
+  EXPECT_TRUE(testutil::AreByteSequencesEqual(
+      decoder->image->icc.data, decoder->image->icc.size, image->icc.data,
+      image->icc.size));
+  EXPECT_TRUE(testutil::AreByteSequencesEqual(
+      decoder->image->exif.data, decoder->image->exif.size, image->exif.data,
+      image->exif.size));
+  EXPECT_TRUE(testutil::AreByteSequencesEqual(
+      decoder->image->xmp.data, decoder->image->xmp.size, image->xmp.data,
+      image->xmp.size));
+}
+
+class LosslessRoundTrip
+    : public testing::TestWithParam<
+          std::tuple<avifMatrixCoefficients, avifPixelFormat>> {};
+
+TEST_P(LosslessRoundTrip, RoundTrip) {
+  const auto matrix_coefficients = std::get<0>(GetParam());
+  const auto pixel_format = std::get<1>(GetParam());
+
+  ImagePtr image = testutil::CreateImage(/*width=*/12, /*height=*/34,
+                                         /*depth=*/8, pixel_format,
+                                         AVIF_PLANES_ALL, AVIF_RANGE_FULL);
+  ASSERT_NE(image, nullptr);
+  image->matrixCoefficients = matrix_coefficients;
+  testutil::FillImageGradient(image.get(), /*offset=*/0);
+
+  // Encode.
+  EncoderPtr encoder(avifEncoderCreate());
+  ASSERT_NE(encoder, nullptr);
+  encoder->speed = 10;
+  encoder->quality = 100;
+  AvifRwData encoded;
+  avifResult result = avifEncoderWrite(encoder.get(), image.get(), &encoded);
+
+  if (image->matrixCoefficients == AVIF_MATRIX_COEFFICIENTS_IDENTITY &&
+      image->yuvFormat != AVIF_PIXEL_FORMAT_YUV444) {
+    // The AV1 spec does not allow identity with subsampling.
+    ASSERT_NE(result, AVIF_RESULT_OK);
+    return;
+  }
+  ASSERT_EQ(result, AVIF_RESULT_OK);
+
+  // Decode.
+  auto decoder = CreateDecoder(encoded);
+  ASSERT_NE(decoder, nullptr);
+  ASSERT_EQ(avifDecoderParse(decoder.get()), AVIF_RESULT_OK);
+  ASSERT_EQ(avifDecoderNextImage(decoder.get()), AVIF_RESULT_OK);
+
+  ASSERT_TRUE(testutil::AreImagesEqual(*image, *decoder->image,
+                                       /*ignore_alpha=*/false));
+}
+
+INSTANTIATE_TEST_SUITE_P(
+    LosslessRoundTripTests, LosslessRoundTrip,
+    testing::Combine(testing::Values(AVIF_MATRIX_COEFFICIENTS_IDENTITY,
+                                     AVIF_MATRIX_COEFFICIENTS_YCGCO,
+                                     AVIF_MATRIX_COEFFICIENTS_YCGCO_RE),
+                     testing::Values(AVIF_PIXEL_FORMAT_YUV444,
+                                     AVIF_PIXEL_FORMAT_YUV420,
+                                     AVIF_PIXEL_FORMAT_YUV400)));
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
diff --git a/c_api_tests/image_tests.cc b/c_api_tests/image_tests.cc
new file mode 100644
index 0000000..c404e2b
--- /dev/null
+++ b/c_api_tests/image_tests.cc
@@ -0,0 +1,201 @@
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
+#include <algorithm>
+#include <cstddef>
+#include <cstdint>
+#include <iostream>
+#include <limits>
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
+#if defined(ADDRESS_SANITIZER) || defined(MEMORY_SANITIZER) || \
+    defined(THREAD_SANITIZER) || defined(HWADDRESS_SANITIZER)
+#define CRABBYAVIF_SANITIZER_BUILD
+#endif
+
+// Used to pass the data folder path to the GoogleTest suites.
+const char* data_path = nullptr;
+
+TEST(ImageTest, Create) {
+  ImagePtr image(avifImageCreateEmpty());
+  EXPECT_NE(image, nullptr);
+  image.reset(avifImageCreate(0, 0, 0, AVIF_PIXEL_FORMAT_NONE));
+  EXPECT_NE(image, nullptr);
+  image.reset(avifImageCreate(1, 1, /*depth=*/1, AVIF_PIXEL_FORMAT_NONE));
+  EXPECT_NE(image, nullptr);
+  image.reset(avifImageCreate(64, 64, /*depth=*/8, AVIF_PIXEL_FORMAT_NONE));
+  EXPECT_NE(image, nullptr);
+  image.reset(avifImageCreate(std::numeric_limits<uint32_t>::max(),
+                              std::numeric_limits<uint32_t>::max(),
+                              /*depth=*/16, AVIF_PIXEL_FORMAT_NONE));
+  EXPECT_NE(image, nullptr);
+}
+
+void TestAllocation(uint32_t width, uint32_t height, uint32_t depth,
+                    avifPixelFormat yuv_format, avifPlanesFlags planes,
+                    bool expect_success) {
+  ImagePtr image(avifImageCreateEmpty());
+  ASSERT_NE(image, nullptr);
+  image->width = width;
+  image->height = height;
+  image->depth = depth;
+  image->yuvFormat = yuv_format;
+  auto res = avifImageAllocatePlanes(image.get(), planes);
+  if (expect_success) {
+    ASSERT_EQ(res, AVIF_RESULT_OK);
+    if (yuv_format != AVIF_PIXEL_FORMAT_NONE && (planes & AVIF_PLANES_YUV)) {
+      EXPECT_NE(image->yuvPlanes[AVIF_CHAN_Y], nullptr);
+      if (yuv_format != AVIF_PIXEL_FORMAT_YUV400) {
+        EXPECT_NE(image->yuvPlanes[AVIF_CHAN_U], nullptr);
+        EXPECT_NE(image->yuvPlanes[AVIF_CHAN_V], nullptr);
+      } else {
+        EXPECT_EQ(image->yuvPlanes[AVIF_CHAN_U], nullptr);
+        EXPECT_EQ(image->yuvPlanes[AVIF_CHAN_V], nullptr);
+      }
+    } else {
+      EXPECT_EQ(image->yuvPlanes[AVIF_CHAN_Y], nullptr);
+      EXPECT_EQ(image->yuvPlanes[AVIF_CHAN_U], nullptr);
+      EXPECT_EQ(image->yuvPlanes[AVIF_CHAN_V], nullptr);
+    }
+    if (planes & AVIF_PLANES_A) {
+      EXPECT_NE(image->alphaPlane, nullptr);
+    } else {
+      EXPECT_EQ(image->alphaPlane, nullptr);
+    }
+  } else {
+    ASSERT_NE(res, AVIF_RESULT_OK);
+    EXPECT_EQ(image->yuvPlanes[AVIF_CHAN_Y], nullptr);
+    EXPECT_EQ(image->yuvPlanes[AVIF_CHAN_U], nullptr);
+    EXPECT_EQ(image->yuvPlanes[AVIF_CHAN_V], nullptr);
+    EXPECT_EQ(image->alphaPlane, nullptr);
+  }
+}
+
+class ImageAllocationTest
+    : public testing::TestWithParam<
+          std::tuple<avifPixelFormat, avifPlanesFlag, /*depth=*/int>> {};
+
+TEST_P(ImageAllocationTest, VariousCases) {
+  const auto& param = GetParam();
+  const auto yuv_format = std::get<0>(param);
+  const auto planes = std::get<1>(param);
+  const auto depth = std::get<2>(param);
+  // Minimum valid image dimensions.
+  TestAllocation(1, 1, depth, yuv_format, planes, true);
+#if !defined(CRABBYAVIF_SANITIZER_BUILD)
+  // Maximum valid image dimensions. This allocation is too large for
+  // sanitizers.
+  TestAllocation(CRABBY_AVIF_DEFAULT_IMAGE_DIMENSION_LIMIT,
+                 CRABBY_AVIF_DEFAULT_IMAGE_DIMENSION_LIMIT, depth, yuv_format,
+                 planes, true);
+#endif
+  // Invalid (too large).
+  TestAllocation((1 << 30), 1, depth, yuv_format, planes, false);
+}
+
+INSTANTIATE_TEST_SUITE_P(
+    All, ImageAllocationTest,
+    testing::Combine(
+        testing::Values(AVIF_PIXEL_FORMAT_NONE, AVIF_PIXEL_FORMAT_YUV444,
+                        AVIF_PIXEL_FORMAT_YUV422, AVIF_PIXEL_FORMAT_YUV420,
+                        AVIF_PIXEL_FORMAT_YUV400),
+        testing::Values(AVIF_PLANES_YUV, AVIF_PLANES_A, AVIF_PLANES_ALL),
+        testing::Values(8, 10, 12)));
+
+void TestEncoding(uint32_t width, uint32_t height, uint32_t depth,
+                  avifResult expected_result) {
+  ImagePtr image(avifImageCreateEmpty());
+  ASSERT_NE(image, nullptr);
+  image->width = width;
+  image->height = height;
+  image->depth = depth;
+  image->yuvFormat = AVIF_PIXEL_FORMAT_YUV444;
+
+  // This is a fairly high number of bytes that can safely be allocated in this
+  // test. The goal is to have something to give to libavif but libavif should
+  // return an error before attempting to read all of it, so it does not matter
+  // if there are fewer bytes than the provided image dimensions.
+  static constexpr uint64_t kMaxAlloc = 1073741824;
+  uint32_t row_bytes;
+  size_t num_allocated_bytes;
+  if (static_cast<uint64_t>(image->width) * image->height >
+      kMaxAlloc / (avifImageUsesU16(image.get()) ? 2 : 1)) {
+    row_bytes = 1024;  // Does not matter much.
+    num_allocated_bytes = kMaxAlloc;
+  } else {
+    row_bytes = image->width * (avifImageUsesU16(image.get()) ? 2 : 1);
+    num_allocated_bytes = row_bytes * image->height;
+  }
+
+  // Initialize pixels as 16b values to make sure values are valid for 10
+  // and 12-bit depths. The array will be cast to uint8_t for 8-bit depth.
+  std::vector<uint16_t> pixels(
+      std::max(1lu, num_allocated_bytes / sizeof(uint16_t)), 400);
+  uint8_t* bytes = reinterpret_cast<uint8_t*>(pixels.data());
+  // Avoid avifImageAllocatePlanes() to exercise the checks at encoding.
+  image->imageOwnsYUVPlanes = AVIF_FALSE;
+  image->imageOwnsAlphaPlane = AVIF_FALSE;
+  image->yuvRowBytes[AVIF_CHAN_Y] = row_bytes;
+  image->yuvPlanes[AVIF_CHAN_Y] = bytes;
+  image->yuvRowBytes[AVIF_CHAN_U] = row_bytes;
+  image->yuvPlanes[AVIF_CHAN_U] = bytes;
+  image->yuvRowBytes[AVIF_CHAN_V] = row_bytes;
+  image->yuvPlanes[AVIF_CHAN_V] = bytes;
+  image->alphaRowBytes = row_bytes;
+  image->alphaPlane = bytes;
+
+  // Try to encode.
+  EncoderPtr encoder(avifEncoderCreate());
+  ASSERT_NE(encoder, nullptr);
+  encoder->speed = 10;
+  AvifRwData encoded_avif;
+  ASSERT_EQ(avifEncoderWrite(encoder.get(), image.get(), &encoded_avif),
+            expected_result);
+}
+
+TEST(EncodingTest, VariousCases) {
+  TestEncoding(1, 1, 8, AVIF_RESULT_OK);
+  TestEncoding(101, 102, 8, AVIF_RESULT_OK);
+#if !defined(CRABBYAVIF_SANITIZER_BUILD)
+  // This allocation is too large for sanitizers.
+  TestEncoding(CRABBY_AVIF_DEFAULT_IMAGE_DIMENSION_LIMIT / 2,
+               CRABBY_AVIF_DEFAULT_IMAGE_DIMENSION_LIMIT / 2, 8,
+               AVIF_RESULT_OK);
+#endif
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
diff --git a/c_api_tests/incremental_tests.cc b/c_api_tests/incremental_tests.cc
index 48d6c71..df2ee88 100644
--- a/c_api_tests/incremental_tests.cc
+++ b/c_api_tests/incremental_tests.cc
@@ -268,6 +268,85 @@ TEST(IncrementalTest, Decode) {
             AVIF_RESULT_OK);
 }
 
+TEST(ProgressiveTest, PartialData) {
+  auto file_data = testutil::read_file(
+      get_file_name("progressive/progressive_dimension_change.avif").c_str());
+  avifRWData encoded_avif = {.data = file_data.data(),
+                             .size = file_data.size()};
+  ASSERT_NE(encoded_avif.size, 0u);
+  // Emulate a byte-by-byte stream.
+  PartialData data = {
+      /*available=*/{encoded_avif.data, 0}, /*fullSize=*/encoded_avif.size,
+      /*nonpersistent_bytes=*/nullptr, /*num_nonpersistent_bytes=*/0};
+  avifIO io = {/*destroy=*/nullptr,    PartialRead,
+               /*write=*/nullptr,      encoded_avif.size,
+               /*is_persistent=*/true, &data};
+  DecoderPtr decoder(avifDecoderCreate());
+  ASSERT_NE(decoder, nullptr);
+  avifDecoderSetIO(decoder.get(), &io);
+  decoder->allowProgressive = AVIF_TRUE;
+
+  // Parse.
+  avifResult parse_result = avifDecoderParse(decoder.get());
+  while (parse_result == AVIF_RESULT_WAITING_ON_IO) {
+    if (data.available.size >= data.full_size) {
+      ASSERT_FALSE(true)
+          << "avifDecoderParse() returned WAITING_ON_IO instead of OK";
+    }
+    data.available.size = std::min(data.available.size + 1, data.full_size);
+    parse_result = avifDecoderParse(decoder.get());
+  }
+  EXPECT_EQ(parse_result, AVIF_RESULT_OK);
+
+  EXPECT_EQ(decoder->imageCount, 2);
+  avifExtent extent0;
+  ASSERT_EQ(avifDecoderNthImageMaxExtent(decoder.get(), 0, &extent0),
+            AVIF_RESULT_OK);
+  EXPECT_EQ(extent0.offset, 306);
+  EXPECT_EQ(extent0.size, 2250);
+  avifExtent extent1;
+  ASSERT_EQ(avifDecoderNthImageMaxExtent(decoder.get(), 1, &extent1),
+            AVIF_RESULT_OK);
+  EXPECT_EQ(extent1.offset, 306);
+  EXPECT_EQ(extent1.size, 3813);
+
+  // Getting the first frame now should fail.
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 0), AVIF_RESULT_WAITING_ON_IO);
+  // Set the available size to 1 byte less than the first frame's extent.
+  data.available.size = extent0.offset + extent0.size - 1;
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 0), AVIF_RESULT_WAITING_ON_IO);
+  // Set the available size to exactly the first frame's extent.
+  data.available.size = extent0.offset + extent0.size;
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 0), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->image->width, 256);
+  EXPECT_EQ(decoder->image->height, 256);
+  EXPECT_NE(decoder->image->yuvPlanes[AVIF_CHAN_Y], nullptr);
+  EXPECT_NE(decoder->image->yuvPlanes[AVIF_CHAN_U], nullptr);
+  EXPECT_NE(decoder->image->yuvPlanes[AVIF_CHAN_V], nullptr);
+  // Set the available size to an offset between the first and second frame's
+  // extents.
+  data.available.size = extent0.offset + extent0.size + 100;
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 0), AVIF_RESULT_OK);
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 1), AVIF_RESULT_WAITING_ON_IO);
+  // Set the available size to 1 byte less than the second frame's extent.
+  data.available.size = extent1.offset + extent1.size - 1;
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 0), AVIF_RESULT_OK);
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 1), AVIF_RESULT_WAITING_ON_IO);
+  // Set the available size to exactly the second frame's extent.
+  data.available.size = extent1.offset + extent1.size;
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 1), AVIF_RESULT_OK);
+  EXPECT_EQ(decoder->image->width, 256);
+  EXPECT_EQ(decoder->image->height, 256);
+  EXPECT_NE(decoder->image->yuvPlanes[AVIF_CHAN_Y], nullptr);
+  EXPECT_NE(decoder->image->yuvPlanes[AVIF_CHAN_U], nullptr);
+  EXPECT_NE(decoder->image->yuvPlanes[AVIF_CHAN_V], nullptr);
+  // At this point, we should be able to fetch both the frames in any order.
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 0), AVIF_RESULT_OK);
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 1), AVIF_RESULT_OK);
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 1), AVIF_RESULT_OK);
+  EXPECT_EQ(avifDecoderNthImage(decoder.get(), 0), AVIF_RESULT_OK);
+}
+
 }  // namespace
 }  // namespace avif
 
diff --git a/c_api_tests/testutil.cc b/c_api_tests/testutil.cc
new file mode 100644
index 0000000..095252f
--- /dev/null
+++ b/c_api_tests/testutil.cc
@@ -0,0 +1,280 @@
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
+#include "testutil.h"
+
+#include <algorithm>
+#include <cmath>
+#include <cstddef>
+#include <cstdint>
+#include <cstring>
+#include <fstream>
+#include <ios>
+#include <limits>
+#include <vector>
+
+#include "avif/avif.h"
+#include "avif/libavif_compat.h"
+#include "gtest/gtest.h"
+
+using namespace crabbyavif;
+
+namespace testutil {
+namespace {
+
+template <typename Sample>
+uint64_t SquaredDiffSum(const Sample* samples1, const Sample* samples2,
+                        uint32_t num_samples) {
+  uint64_t sum = 0;
+  for (uint32_t i = 0; i < num_samples; ++i) {
+    const int32_t diff = static_cast<int32_t>(samples1[i]) - samples2[i];
+    sum += diff * diff;
+  }
+  return sum;
+}
+
+}  // namespace
+
+std::vector<uint8_t> read_file(const char* file_name) {
+  std::ifstream file(file_name, std::ios::binary);
+  EXPECT_TRUE(file.is_open());
+  // Get file size.
+  file.seekg(0, std::ios::end);
+  auto size = file.tellg();
+  file.seekg(0, std::ios::beg);
+  std::vector<uint8_t> data(size);
+  file.read(reinterpret_cast<char*>(data.data()), size);
+  file.close();
+  return data;
+}
+
+avif::ImagePtr CreateImage(int width, int height, int depth,
+                           avifPixelFormat yuv_format, avifPlanesFlags planes,
+                           avifRange yuv_range) {
+  avif::ImagePtr image(avifImageCreate(width, height, depth, yuv_format));
+  if (!image) {
+    return nullptr;
+  }
+  image->yuvRange = yuv_range;
+  if (avifImageAllocatePlanes(image.get(), planes) != AVIF_RESULT_OK) {
+    return nullptr;
+  }
+  return image;
+}
+
+void FillImageGradient(avifImage* image, int offset) {
+  for (avifChannelIndex c :
+       {AVIF_CHAN_Y, AVIF_CHAN_U, AVIF_CHAN_V, AVIF_CHAN_A}) {
+    const uint32_t limitedRangeMin =
+        c == AVIF_CHAN_Y ? 16 << (image->depth - 8) : 0;
+    const uint32_t limitedRangeMax = (c == AVIF_CHAN_Y ? 219 : 224)
+                                     << (image->depth - 8);
+
+    const uint32_t plane_width = avifImagePlaneWidth(image, c);
+    // 0 for A if no alpha and 0 for UV if 4:0:0.
+    const uint32_t plane_height = avifImagePlaneHeight(image, c);
+    uint8_t* row = avifImagePlane(image, c);
+    const uint32_t row_bytes = avifImagePlaneRowBytes(image, c);
+    const uint32_t max_xy_sum = plane_width + plane_height - 2;
+    for (uint32_t y = 0; y < plane_height; ++y) {
+      for (uint32_t x = 0; x < plane_width; ++x) {
+        uint32_t value = (x + y + offset) % (max_xy_sum + 1);
+        if (image->yuvRange == AVIF_RANGE_FULL || c == AVIF_CHAN_A) {
+          value =
+              value * ((1u << image->depth) - 1u) / std::max(1u, max_xy_sum);
+        } else {
+          value = limitedRangeMin + value *
+                                        (limitedRangeMax - limitedRangeMin) /
+                                        std::max(1u, max_xy_sum);
+        }
+        if (avifImageUsesU16(image)) {
+          reinterpret_cast<uint16_t*>(row)[x] = static_cast<uint16_t>(value);
+        } else {
+          row[x] = static_cast<uint8_t>(value);
+        }
+      }
+      row += row_bytes;
+    }
+  }
+}
+
+double GetPsnr(const avifImage& image1, const avifImage& image2,
+               bool ignore_alpha) {
+  if (image1.width != image2.width || image1.height != image2.height ||
+      image1.depth != image2.depth || image1.yuvFormat != image2.yuvFormat ||
+      image1.yuvRange != image2.yuvRange) {
+    return -1.0;
+  }
+  uint64_t squared_diff_sum = 0;
+  uint32_t num_samples = 0;
+  const uint32_t max_sample_value = (1 << image1.depth) - 1;
+  for (avifChannelIndex c :
+       {AVIF_CHAN_Y, AVIF_CHAN_U, AVIF_CHAN_V, AVIF_CHAN_A}) {
+    if (ignore_alpha && c == AVIF_CHAN_A) continue;
+
+    const uint32_t plane_width = std::max(avifImagePlaneWidth(&image1, c),
+                                          avifImagePlaneWidth(&image2, c));
+    const uint32_t plane_height = std::max(avifImagePlaneHeight(&image1, c),
+                                           avifImagePlaneHeight(&image2, c));
+    if (plane_width == 0 || plane_height == 0) continue;
+
+    const uint8_t* row1 = avifImagePlane(&image1, c);
+    const uint8_t* row2 = avifImagePlane(&image2, c);
+    if (!row1 != !row2 && c != AVIF_CHAN_A) {
+      return -1.0;
+    }
+    uint32_t row_bytes1 = avifImagePlaneRowBytes(&image1, c);
+    uint32_t row_bytes2 = avifImagePlaneRowBytes(&image2, c);
+
+    // Consider missing alpha planes as samples set to the maximum value.
+    std::vector<uint8_t> opaque_alpha_samples;
+    if (!row1 != !row2) {
+      opaque_alpha_samples.resize(std::max(row_bytes1, row_bytes2));
+      if (avifImageUsesU16(&image1)) {
+        uint16_t* opaque_alpha_samples_16b =
+            reinterpret_cast<uint16_t*>(opaque_alpha_samples.data());
+        std::fill(opaque_alpha_samples_16b,
+                  opaque_alpha_samples_16b + plane_width,
+                  static_cast<int16_t>(max_sample_value));
+      } else {
+        std::fill(opaque_alpha_samples.begin(), opaque_alpha_samples.end(),
+                  uint8_t{255});
+      }
+      if (!row1) {
+        row1 = opaque_alpha_samples.data();
+        row_bytes1 = 0;
+      } else {
+        row2 = opaque_alpha_samples.data();
+        row_bytes2 = 0;
+      }
+    }
+
+    for (uint32_t y = 0; y < plane_height; ++y) {
+      if (avifImageUsesU16(&image1)) {
+        squared_diff_sum += SquaredDiffSum(
+            reinterpret_cast<const uint16_t*>(row1),
+            reinterpret_cast<const uint16_t*>(row2), plane_width);
+      } else {
+        squared_diff_sum += SquaredDiffSum(row1, row2, plane_width);
+      }
+      row1 += row_bytes1;
+      row2 += row_bytes2;
+      num_samples += plane_width;
+    }
+  }
+
+  if (squared_diff_sum == 0) {
+    return 99.0;
+  }
+  const double normalized_error =
+      squared_diff_sum /
+      (static_cast<double>(num_samples) * max_sample_value * max_sample_value);
+  if (normalized_error <= std::numeric_limits<double>::epsilon()) {
+    return 98.99;  // Very small distortion but not lossless.
+  }
+  return std::min(-10 * std::log10(normalized_error), 98.99);
+}
+
+bool AreByteSequencesEqual(const uint8_t* data1, size_t data1_length,
+                           const uint8_t* data2, size_t data2_length) {
+  if (data1_length != data2_length) return false;
+  return data1_length == 0 || std::equal(data1, data1 + data1_length, data2);
+}
+
+bool AreByteSequencesEqual(const avifRWData& data1, const avifRWData& data2) {
+  return AreByteSequencesEqual(data1.data, data1.size, data2.data, data2.size);
+}
+
+bool AreImagesEqual(const avifImage& image1, const avifImage& image2,
+                    bool ignore_alpha) {
+  if (image1.width != image2.width || image1.height != image2.height ||
+      image1.depth != image2.depth || image1.yuvFormat != image2.yuvFormat ||
+      image1.yuvRange != image2.yuvRange) {
+    return false;
+  }
+
+  for (avifChannelIndex c :
+       {AVIF_CHAN_Y, AVIF_CHAN_U, AVIF_CHAN_V, AVIF_CHAN_A}) {
+    if (ignore_alpha && c == AVIF_CHAN_A) continue;
+    const uint8_t* row1 = avifImagePlane(&image1, c);
+    const uint8_t* row2 = avifImagePlane(&image2, c);
+    if (!row1 != !row2) {
+      return false;
+    }
+    if (c == AVIF_CHAN_A && row1 != nullptr &&
+        image1.alphaPremultiplied != image2.alphaPremultiplied) {
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
+
+  if (!AreByteSequencesEqual(image1.icc, image2.icc)) return false;
+
+  if (image1.colorPrimaries != image2.colorPrimaries ||
+      image1.transferCharacteristics != image2.transferCharacteristics ||
+      image1.matrixCoefficients != image2.matrixCoefficients) {
+    return false;
+  }
+
+  if (image1.clli.maxCLL != image2.clli.maxCLL ||
+      image1.clli.maxPALL != image2.clli.maxPALL) {
+    return false;
+  }
+  if (image1.transformFlags != image2.transformFlags ||
+      ((image1.transformFlags & AVIF_TRANSFORM_PASP) &&
+       memcmp(&image1.pasp, &image2.pasp, sizeof(image1.pasp))) ||
+      ((image1.transformFlags & AVIF_TRANSFORM_CLAP) &&
+       memcmp(&image1.clap, &image2.clap, sizeof(image1.clap))) ||
+      ((image1.transformFlags & AVIF_TRANSFORM_IROT) &&
+       memcmp(&image1.irot, &image2.irot, sizeof(image1.irot))) ||
+      ((image1.transformFlags & AVIF_TRANSFORM_IMIR) &&
+       memcmp(&image1.imir, &image2.imir, sizeof(image1.imir)))) {
+    return false;
+  }
+
+  if (!AreByteSequencesEqual(image1.exif, image2.exif)) return false;
+  if (!AreByteSequencesEqual(image1.xmp, image2.xmp)) return false;
+
+  if (!image1.gainMap != !image2.gainMap) return false;
+  if (image1.gainMap != nullptr) {
+    if (!image1.gainMap->image != !image2.gainMap->image) return false;
+    if (image1.gainMap->image != nullptr &&
+        !AreImagesEqual(*image1.gainMap->image, *image2.gainMap->image,
+                        false)) {
+      return false;
+    }
+  }
+  return true;
+}
+
+}  // namespace testutil
diff --git a/c_api_tests/testutil.h b/c_api_tests/testutil.h
index 7b5dc14..cb83662 100644
--- a/c_api_tests/testutil.h
+++ b/c_api_tests/testutil.h
@@ -14,15 +14,13 @@
  * limitations under the License.
  */
 
-#include <fstream>
-#include <iostream>
-#include <iterator>
+#include <cstddef>
+#include <cstdint>
 #include <memory>
 #include <vector>
 
 #include "avif/avif.h"
 #include "avif/libavif_compat.h"
-#include "gtest/gtest.h"
 
 using namespace crabbyavif;
 
@@ -46,33 +44,48 @@ using namespace crabbyavif;
 
 namespace avif {
 
-// Struct to call the destroy functions in a unique_ptr.
+// Use these unique_ptr wrappers/class wrappers for automatic memory management.
 struct UniquePtrDeleter {
   void operator()(avifDecoder* decoder) const { avifDecoderDestroy(decoder); }
-  void operator()(avifImage * image) const { avifImageDestroy(image); }
+  void operator()(avifEncoder* encoder) const { avifEncoderDestroy(encoder); }
+  void operator()(avifImage* image) const { avifImageDestroy(image); }
 };
 
-// Use these unique_ptr to ensure the structs are automatically destroyed.
 using DecoderPtr = std::unique_ptr<avifDecoder, UniquePtrDeleter>;
+using EncoderPtr = std::unique_ptr<avifEncoder, UniquePtrDeleter>;
 using ImagePtr = std::unique_ptr<avifImage, UniquePtrDeleter>;
 
+class AvifRwData : public avifRWData {
+ public:
+  AvifRwData() : avifRWData{nullptr, 0} {}
+  AvifRwData(const AvifRwData&) = delete;
+  AvifRwData(AvifRwData&& other);
+  ~AvifRwData() { avifRWDataFree(this); }
+};
+
 }  // namespace avif
 
 namespace testutil {
 
-bool Av1DecoderAvailable() { return true; }
-
-std::vector<uint8_t> read_file(const char* file_name) {
-  std::ifstream file(file_name, std::ios::binary);
-  EXPECT_TRUE(file.is_open());
-  // Get file size.
-  file.seekg(0, std::ios::end);
-  auto size = file.tellg();
-  file.seekg(0, std::ios::beg);
-  std::vector<uint8_t> data(size);
-  file.read(reinterpret_cast<char*>(data.data()), size);
-  file.close();
-  return data;
-}
+inline bool Av1DecoderAvailable() { return true; }
+
+std::vector<uint8_t> read_file(const char* file_name);
+
+avif::ImagePtr CreateImage(int width, int height, int depth,
+                           avifPixelFormat yuv_format, avifPlanesFlags planes,
+                           avifRange yuv_range);
+
+void FillImageGradient(avifImage* image, int offset);
+
+double GetPsnr(const avifImage& image1, const avifImage& image2,
+               bool ignore_alpha);
+
+bool AreByteSequencesEqual(const uint8_t* data1, size_t data1_length,
+                           const uint8_t* data2, size_t data2_length);
+
+bool AreByteSequencesEqual(const avifRWData& data1, const avifRWData& data2);
+
+bool AreImagesEqual(const avifImage& image1, const avifImage& image2,
+                    bool ignore_alpha);
 
 }  // namespace testutil
diff --git a/cbindgen.toml b/cbindgen.toml
index ea06850..dcebc49 100644
--- a/cbindgen.toml
+++ b/cbindgen.toml
@@ -31,6 +31,7 @@ struct avifIO;
 "MatrixCoefficients" = "avifMatrixCoefficients"
 "PixelFormat" = "avifPixelFormat"
 "ProgressiveState" = "avifProgressiveState"
+"ScalingMode" = "avifScalingMode"
 "Source" = "avifDecoderSource"
 "YuvRange" = "avifRange"
 "TransferCharacteristics" = "avifTransferCharacteristics"
diff --git a/examples/crabby_decode.rs b/examples/crabby_decode.rs
deleted file mode 100644
index 5f2071e..0000000
--- a/examples/crabby_decode.rs
+++ /dev/null
@@ -1,480 +0,0 @@
-// Copyright 2025 Google LLC
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
-use clap::value_parser;
-use clap::Parser;
-
-use crabby_avif::decoder::track::RepetitionCount;
-use crabby_avif::decoder::*;
-use crabby_avif::utils::clap::CropRect;
-use crabby_avif::*;
-
-mod writer;
-
-use writer::jpeg::JpegWriter;
-use writer::png::PngWriter;
-use writer::y4m::Y4MWriter;
-use writer::Writer;
-
-use std::fs::File;
-use std::num::NonZero;
-
-fn depth_parser(s: &str) -> Result<u8, String> {
-    match s.parse::<u8>() {
-        Ok(8) => Ok(8),
-        Ok(16) => Ok(16),
-        _ => Err("Value must be either 8 or 16".into()),
-    }
-}
-
-#[derive(Parser)]
-struct CommandLineArgs {
-    /// Disable strict decoding, which disables strict validation checks and errors
-    #[arg(long, default_value = "false")]
-    no_strict: bool,
-
-    /// Decode all frames and display all image information instead of saving to disk
-    #[arg(short = 'i', long, default_value = "false")]
-    info: bool,
-
-    #[arg(long)]
-    jobs: Option<u32>,
-
-    /// When decoding an image sequence or progressive image, specify which frame index to decode
-    /// (Default: 0)
-    #[arg(long, short = 'I')]
-    index: Option<u32>,
-
-    /// Output depth, either 8 or 16. (PNG only; For y4m/yuv, source depth is retained; JPEG is
-    /// always 8bit)
-    #[arg(long, short = 'd', value_parser = depth_parser)]
-    depth: Option<u8>,
-
-    /// Output quality in 0..100. (JPEG only, default: 90)
-    #[arg(long, short = 'q', value_parser = value_parser!(u8).range(0..=100))]
-    quality: Option<u8>,
-
-    /// Enable progressive AVIF processing. If a progressive image is encountered and --progressive
-    /// is passed, --index will be used to choose which layer to decode (in progressive order).
-    #[arg(long, default_value = "false")]
-    progressive: bool,
-
-    /// Maximum image size (in total pixels) that should be tolerated (0 means unlimited)
-    #[arg(long)]
-    size_limit: Option<u32>,
-
-    /// Maximum image dimension (width or height) that should be tolerated (0 means unlimited)
-    #[arg(long)]
-    dimension_limit: Option<u32>,
-
-    /// If the input file contains embedded Exif metadata, ignore it (no-op if absent)
-    #[arg(long, default_value = "false")]
-    ignore_exif: bool,
-
-    /// If the input file contains embedded XMP metadata, ignore it (no-op if absent)
-    #[arg(long, default_value = "false")]
-    ignore_xmp: bool,
-
-    /// Input AVIF file
-    #[arg(allow_hyphen_values = false)]
-    input_file: String,
-
-    /// Output file
-    #[arg(allow_hyphen_values = false)]
-    output_file: Option<String>,
-}
-
-fn print_data_as_columns(rows: &[(usize, &str, String)]) {
-    let rows: Vec<_> = rows
-        .iter()
-        .filter(|x| !x.1.is_empty())
-        .map(|x| (format!("{} * {}", " ".repeat(x.0 * 4), x.1), x.2.as_str()))
-        .collect();
-
-    // Calculate the maximum width for the first column.
-    let mut max_col1_width = 0;
-    for (col1, _) in &rows {
-        max_col1_width = max_col1_width.max(col1.len());
-    }
-
-    for (col1, col2) in &rows {
-        println!("{col1:<max_col1_width$} : {col2}");
-    }
-}
-
-fn print_vec(data: &[u8]) -> String {
-    if data.is_empty() {
-        format!("Absent")
-    } else {
-        format!("Present ({} bytes)", data.len())
-    }
-}
-
-fn print_image_info(decoder: &Decoder) {
-    let image = decoder.image().unwrap();
-    let mut image_data = vec![
-        (
-            0,
-            "File Format",
-            format!("{:#?}", decoder.compression_format()),
-        ),
-        (0, "Resolution", format!("{}x{}", image.width, image.height)),
-        (0, "Bit Depth", format!("{}", image.depth)),
-        (0, "Format", format!("{:#?}", image.yuv_format)),
-        if image.yuv_format == PixelFormat::Yuv420 {
-            (
-                0,
-                "Chroma Sample Position",
-                format!("{:#?}", image.chroma_sample_position),
-            )
-        } else {
-            (0, "", "".into())
-        },
-        (
-            0,
-            "Alpha",
-            format!(
-                "{}",
-                match (image.alpha_present, image.alpha_premultiplied) {
-                    (true, true) => "Premultiplied",
-                    (true, false) => "Not premultiplied",
-                    (false, _) => "Absent",
-                }
-            ),
-        ),
-        (0, "Range", format!("{:#?}", image.yuv_range)),
-        (
-            0,
-            "Color Primaries",
-            format!("{:#?}", image.color_primaries),
-        ),
-        (
-            0,
-            "Transfer Characteristics",
-            format!("{:#?}", image.transfer_characteristics),
-        ),
-        (
-            0,
-            "Matrix Coefficients",
-            format!("{:#?}", image.matrix_coefficients),
-        ),
-        (0, "ICC Profile", print_vec(&image.icc)),
-        (0, "XMP Metadata", print_vec(&image.xmp)),
-        (0, "Exif Metadata", print_vec(&image.exif)),
-    ];
-    if image.pasp.is_none()
-        && image.clap.is_none()
-        && image.irot_angle.is_none()
-        && image.imir_axis.is_none()
-    {
-        image_data.push((0, "Transformations", format!("None")));
-    } else {
-        image_data.push((0, "Transformations", format!("")));
-        if let Some(pasp) = image.pasp {
-            image_data.push((
-                1,
-                "pasp (Aspect Ratio)",
-                format!("{}/{}", pasp.h_spacing, pasp.v_spacing),
-            ));
-        }
-        if let Some(clap) = image.clap {
-            image_data.push((1, "clap (Clean Aperture)", format!("")));
-            image_data.push((2, "W", format!("{}/{}", clap.width.0, clap.width.1)));
-            image_data.push((2, "H", format!("{}/{}", clap.height.0, clap.height.1)));
-            image_data.push((
-                2,
-                "hOff",
-                format!("{}/{}", clap.horiz_off.0, clap.horiz_off.1),
-            ));
-            image_data.push((
-                2,
-                "vOff",
-                format!("{}/{}", clap.vert_off.0, clap.vert_off.1),
-            ));
-            match CropRect::create_from(&clap, image.width, image.height, image.yuv_format) {
-                Ok(rect) => image_data.extend_from_slice(&[
-                    (2, "Valid, derived crop rect", format!("")),
-                    (3, "X", format!("{}", rect.x)),
-                    (3, "Y", format!("{}", rect.y)),
-                    (3, "W", format!("{}", rect.width)),
-                    (3, "H", format!("{}", rect.height)),
-                ]),
-                Err(_) => image_data.push((2, "Invalid", format!(""))),
-            }
-        }
-        if let Some(angle) = image.irot_angle {
-            image_data.push((1, "irot (Rotation)", format!("{angle}")));
-        }
-        if let Some(axis) = image.imir_axis {
-            image_data.push((1, "imir (Mirror)", format!("{axis}")));
-        }
-    }
-    image_data.push((0, "Progressive", format!("{:#?}", image.progressive_state)));
-    if let Some(clli) = image.clli {
-        image_data.push((0, "CLLI", format!("{}, {}", clli.max_cll, clli.max_pall)));
-    }
-    if decoder.gainmap_present() {
-        let gainmap = decoder.gainmap();
-        let gainmap_image = &gainmap.image;
-        image_data.extend_from_slice(&[
-            (
-                0,
-                "Gainmap",
-                format!(
-                "{}x{} pixels, {} bit, {:#?}, {:#?} Range, Matrix Coeffs. {:#?}, Base Image is {}",
-                gainmap_image.width,
-                gainmap_image.height,
-                gainmap_image.depth,
-                gainmap_image.yuv_format,
-                gainmap_image.yuv_range,
-                gainmap_image.matrix_coefficients,
-                if gainmap.metadata.base_hdr_headroom.0 == 0 { "SDR" } else { "HDR" },
-            ),
-            ),
-            (0, "Alternate image", format!("")),
-            (
-                1,
-                "Color Primaries",
-                format!("{:#?}", gainmap.alt_color_primaries),
-            ),
-            (
-                1,
-                "Transfer Characteristics",
-                format!("{:#?}", gainmap.alt_transfer_characteristics),
-            ),
-            (
-                1,
-                "Matrix Coefficients",
-                format!("{:#?}", gainmap.alt_matrix_coefficients),
-            ),
-            (1, "ICC Profile", print_vec(&gainmap.alt_icc)),
-            (1, "Bit Depth", format!("{}", gainmap.alt_plane_depth)),
-            (1, "Planes", format!("{}", gainmap.alt_plane_count)),
-            if let Some(clli) = gainmap_image.clli {
-                (1, "CLLI", format!("{}, {}", clli.max_cll, clli.max_pall))
-            } else {
-                (1, "", "".into())
-            },
-        ])
-    } else {
-        // TODO: b/394162563 - check if we need to report the present but ignored case.
-        image_data.push((0, "Gainmap", format!("Absent")));
-    }
-    if image.image_sequence_track_present {
-        image_data.push((
-            0,
-            "Repeat Count",
-            match decoder.repetition_count() {
-                RepetitionCount::Finite(x) => format!("{x}"),
-                RepetitionCount::Infinite => format!("Infinite"),
-                RepetitionCount::Unknown => format!("Unknown"),
-            },
-        ));
-    }
-    print_data_as_columns(&image_data);
-}
-
-fn max_threads(jobs: &Option<u32>) -> u32 {
-    match jobs {
-        Some(x) => {
-            if *x == 0 {
-                match std::thread::available_parallelism() {
-                    Ok(value) => value.get() as u32,
-                    Err(_) => 1,
-                }
-            } else {
-                *x
-            }
-        }
-        None => 1,
-    }
-}
-
-fn create_decoder_and_parse(args: &CommandLineArgs) -> AvifResult<Decoder> {
-    let mut settings = Settings {
-        strictness: if args.no_strict { Strictness::None } else { Strictness::All },
-        image_content_to_decode: ImageContentType::All,
-        max_threads: max_threads(&args.jobs),
-        allow_progressive: args.progressive,
-        ignore_exif: args.ignore_exif,
-        ignore_xmp: args.ignore_xmp,
-        ..Settings::default()
-    };
-    // These values cannot be initialized in the list above since we need the default values to be
-    // retain unless they are explicitly specified.
-    if let Some(size_limit) = args.size_limit {
-        settings.image_size_limit = NonZero::new(size_limit);
-    }
-    if let Some(dimension_limit) = args.dimension_limit {
-        settings.image_dimension_limit = NonZero::new(dimension_limit);
-    }
-    let mut decoder = Decoder::default();
-    decoder.settings = settings;
-    decoder
-        .set_io_file(&args.input_file)
-        .or(Err(AvifError::UnknownError(
-            "Cannot open input file".into(),
-        )))?;
-    decoder.parse()?;
-    Ok(decoder)
-}
-
-fn info(args: &CommandLineArgs) -> AvifResult<()> {
-    let mut decoder = create_decoder_and_parse(&args)?;
-    println!("Image decoded: {}", args.input_file);
-    print_image_info(&decoder);
-    println!(
-        " * {} timescales per second, {} seconds ({} timescales), {} frame{}",
-        decoder.timescale(),
-        decoder.duration(),
-        decoder.duration_in_timescales(),
-        decoder.image_count(),
-        if decoder.image_count() == 1 { "" } else { "s" },
-    );
-    if decoder.image_count() > 1 {
-        let image = decoder.image().unwrap();
-        println!(
-            " * {} Frames: ({} expected frames)",
-            if image.image_sequence_track_present {
-                "Image Sequence"
-            } else {
-                "Progressive Image"
-            },
-            decoder.image_count()
-        );
-    } else {
-        println!(" * Frame:");
-    }
-
-    let mut index = 0;
-    loop {
-        match decoder.next_image() {
-            Ok(_) => {
-                println!("     * Decoded frame [{}] [pts {} ({} timescales)] [duration {} ({} timescales)] [{}x{}]",
-                    index,
-                    decoder.image_timing().pts,
-                    decoder.image_timing().pts_in_timescales,
-                    decoder.image_timing().duration,
-                    decoder.image_timing().duration_in_timescales,
-                    decoder.image().unwrap().width,
-                    decoder.image().unwrap().height);
-                index += 1;
-            }
-            Err(AvifError::NoImagesRemaining) => {
-                return Ok(());
-            }
-            Err(err) => {
-                return Err(err);
-            }
-        }
-    }
-}
-
-fn get_extension(filename: &str) -> &str {
-    std::path::Path::new(filename)
-        .extension()
-        .and_then(|s| s.to_str())
-        .unwrap_or("")
-}
-
-fn decode(args: &CommandLineArgs) -> AvifResult<()> {
-    let max_threads = max_threads(&args.jobs);
-    println!(
-        "Decoding with {max_threads} worker thread{}, please wait...",
-        if max_threads == 1 { "" } else { "s" }
-    );
-    let mut decoder = create_decoder_and_parse(&args)?;
-    decoder.nth_image(args.index.unwrap_or(0))?;
-    println!("Image Decoded: {}", args.input_file);
-    println!("Image details:");
-    print_image_info(&decoder);
-
-    let output_filename = &args.output_file.as_ref().unwrap().as_str();
-    let image = decoder.image().unwrap();
-    let extension = get_extension(output_filename);
-    let mut writer: Box<dyn Writer> = match extension {
-        "y4m" | "yuv" => {
-            if !image.icc.is_empty() || !image.exif.is_empty() || !image.xmp.is_empty() {
-                println!("Warning: metadata dropped when saving to {extension}");
-            }
-            Box::new(Y4MWriter::create(extension == "yuv"))
-        }
-        "png" => Box::new(PngWriter { depth: args.depth }),
-        "jpg" | "jpeg" => Box::new(JpegWriter {
-            quality: args.quality,
-        }),
-        _ => {
-            return Err(AvifError::UnknownError(format!(
-                "Unknown output file extension ({extension})"
-            )));
-        }
-    };
-    let mut output_file = File::create(output_filename).or(Err(AvifError::UnknownError(
-        "Could not open output file".into(),
-    )))?;
-    writer.write_frame(&mut output_file, image)?;
-    println!(
-        "Wrote image at index {} to output {}",
-        args.index.unwrap_or(0),
-        output_filename,
-    );
-    Ok(())
-}
-
-fn validate_args(args: &CommandLineArgs) -> AvifResult<()> {
-    if args.info {
-        if args.output_file.is_some()
-            || args.quality.is_some()
-            || args.depth.is_some()
-            || args.index.is_some()
-        {
-            return Err(AvifError::UnknownError(
-                "--info contains unsupported extra arguments".into(),
-            ));
-        }
-    } else {
-        if args.output_file.is_none() {
-            return Err(AvifError::UnknownError("output_file is required".into()));
-        }
-        let output_filename = &args.output_file.as_ref().unwrap().as_str();
-        let extension = get_extension(output_filename);
-        if args.quality.is_some() && extension != "jpg" && extension != "jpeg" {
-            return Err(AvifError::UnknownError(
-                "quality is only supported for jpeg output".into(),
-            ));
-        }
-        if args.depth.is_some() && extension != "png" {
-            return Err(AvifError::UnknownError(
-                "depth is only supported for png output".into(),
-            ));
-        }
-    }
-    Ok(())
-}
-
-fn main() {
-    let args = CommandLineArgs::parse();
-    if let Err(err) = validate_args(&args) {
-        eprintln!("ERROR: {:#?}", err);
-        std::process::exit(1);
-    }
-    let res = if args.info { info(&args) } else { decode(&args) };
-    match res {
-        Ok(_) => std::process::exit(0),
-        Err(err) => {
-            eprintln!("ERROR: {:#?}", err);
-            std::process::exit(1);
-        }
-    }
-}
diff --git a/examples/crabbyavif.rs b/examples/crabbyavif.rs
new file mode 100644
index 0000000..577e8ee
--- /dev/null
+++ b/examples/crabbyavif.rs
@@ -0,0 +1,820 @@
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
+#[cfg(feature = "encoder")]
+use crabby_avif::encoder::*;
+use crabby_avif::utils::clap::CleanAperture;
+use crabby_avif::utils::clap::CropRect;
+use crabby_avif::utils::IFraction;
+use crabby_avif::utils::UFraction;
+use crabby_avif::*;
+
+#[cfg(all(feature = "encoder", feature = "jpeg"))]
+use crabby_avif::utils::reader::jpeg::JpegReader;
+#[cfg(all(feature = "encoder", feature = "png"))]
+use crabby_avif::utils::reader::png::PngReader;
+#[cfg(feature = "encoder")]
+use crabby_avif::utils::reader::y4m::Y4MReader;
+#[cfg(feature = "encoder")]
+use crabby_avif::utils::reader::Config;
+#[cfg(feature = "encoder")]
+use crabby_avif::utils::reader::Reader;
+
+#[cfg(feature = "jpeg")]
+use crabby_avif::utils::writer::jpeg::JpegWriter;
+#[cfg(feature = "png")]
+use crabby_avif::utils::writer::png::PngWriter;
+use crabby_avif::utils::writer::y4m::Y4MWriter;
+use crabby_avif::utils::writer::Writer;
+
+use std::fs::File;
+#[cfg(feature = "encoder")]
+use std::io;
+#[cfg(feature = "encoder")]
+use std::io::Read;
+#[cfg(feature = "encoder")]
+use std::io::Write;
+use std::num::NonZero;
+
+fn depth_parser(s: &str) -> Result<u8, String> {
+    match s.parse::<u8>() {
+        Ok(8) => Ok(8),
+        Ok(10) => Ok(10),
+        Ok(12) => Ok(12),
+        Ok(16) => Ok(16),
+        _ => Err("Value must be one of 8, 10, 12 or 16".into()),
+    }
+}
+
+macro_rules! split_and_check_count {
+    ($parameter: literal, $input:ident, $delimiter:literal, $count:literal, $type:ty) => {{
+        let values: Result<Vec<_>, _> = $input
+            .split($delimiter)
+            .map(|x| x.parse::<$type>())
+            .collect();
+        if values.is_err() {
+            return Err(format!("Invalid {} string", $parameter));
+        }
+        let values = values.unwrap();
+        if values.len() != $count {
+            return Err(format!(
+                "Invalid {} string. Expecting exactly {} values separated with a \"{}\"",
+                $parameter, $count, $delimiter
+            ));
+        }
+        values
+    }};
+}
+
+fn clap_parser(s: &str) -> Result<CleanAperture, String> {
+    let values = split_and_check_count!("clap", s, ",", 8, i32);
+    let values: Vec<_> = values.into_iter().map(|x| x as u32).collect();
+    Ok(CleanAperture {
+        width: UFraction(values[0], values[1]),
+        height: UFraction(values[2], values[3]),
+        horiz_off: UFraction(values[4], values[5]),
+        vert_off: UFraction(values[6], values[7]),
+    })
+}
+
+fn crop_parser(s: &str) -> Result<CropRect, String> {
+    let values = split_and_check_count!("crop", s, ",", 4, u32);
+    Ok(CropRect {
+        x: values[0],
+        y: values[1],
+        width: values[2],
+        height: values[3],
+    })
+}
+
+fn clli_parser(s: &str) -> Result<ContentLightLevelInformation, String> {
+    let values = split_and_check_count!("clli", s, ",", 2, u16);
+    Ok(ContentLightLevelInformation {
+        max_cll: values[0],
+        max_pall: values[1],
+    })
+}
+
+fn pasp_parser(s: &str) -> Result<PixelAspectRatio, String> {
+    let values = split_and_check_count!("pasp", s, ",", 2, u32);
+    Ok(PixelAspectRatio {
+        h_spacing: values[0],
+        v_spacing: values[1],
+    })
+}
+
+fn cicp_parser(s: &str) -> Result<Nclx, String> {
+    let values = split_and_check_count!("cicp", s, "/", 3, u16);
+    Ok(Nclx {
+        color_primaries: values[0].into(),
+        transfer_characteristics: values[1].into(),
+        matrix_coefficients: values[2].into(),
+        ..Default::default()
+    })
+}
+
+fn scaling_mode_parser(s: &str) -> Result<IFraction, String> {
+    let values = split_and_check_count!("scaling_mode", s, "/", 2, i32);
+    Ok(IFraction(values[0], values[1]))
+}
+
+fn yuv_format_parser(s: &str) -> Result<PixelFormat, String> {
+    match s {
+        "420" => Ok(PixelFormat::Yuv420),
+        "422" => Ok(PixelFormat::Yuv422),
+        "444" => Ok(PixelFormat::Yuv444),
+        "400" => Ok(PixelFormat::Yuv400),
+        _ => Err(format!("Invalid yuv format: {s}")),
+    }
+}
+
+#[derive(Parser)]
+struct CommandLineArgs {
+    /// AVIF Decode only: Disable strict decoding, which disables strict validation checks and
+    /// errors
+    #[arg(long, default_value = "false")]
+    no_strict: bool,
+
+    /// AVIF Decode only: Decode all frames and display all image information instead of saving to
+    /// disk
+    #[arg(short = 'i', long, default_value = "false")]
+    info: bool,
+
+    /// Number of threads to use for AVIF encoding/decoding
+    #[arg(long)]
+    jobs: Option<u32>,
+
+    /// AVIF Decode only:  When decoding an image sequence or progressive image, specify which
+    /// frame index to decode (Default: 0)
+    #[arg(long, short = 'I')]
+    index: Option<u32>,
+
+    /// Output depth, either 8 or 16. (AVIF/PNG only; For y4m/yuv, source depth is retained; JPEG
+    /// is always 8bit)
+    #[arg(long, short = 'd', value_parser = depth_parser)]
+    depth: Option<u8>,
+
+    /// Output quality in 0..100. (JPEG/AVIF only, default: 90).
+    #[arg(long, short = 'q', value_parser = value_parser!(u8).range(0..=100))]
+    quality: Option<u8>,
+
+    /// AVIF Encode only: Speed used for encoding.
+    #[arg(long, short = 's', value_parser = value_parser!(u32).range(0..=10))]
+    speed: Option<u32>,
+
+    /// When decoding AVIF: Enable progressive AVIF processing. If a progressive image is
+    /// encountered and --progressive is passed, --index will be used to choose which layer to
+    /// decode (in progressive order).
+    /// When encoding AVIF: Auto set parameters to encode a simple layered image supporting
+    /// progressive rendering from a single input frame.
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
+    /// AVIF Decode only: If the input file contains embedded Exif metadata, ignore it (no-op if absent)
+    #[arg(long, default_value = "false")]
+    ignore_exif: bool,
+
+    /// AVIF Decode only: If the input file contains embedded XMP metadata, ignore it (no-op if absent)
+    #[arg(long, default_value = "false")]
+    ignore_xmp: bool,
+
+    /// AVIF Encode only: Add irot property (rotation), in 0..3. Makes (90 * ANGLE) degree rotation
+    /// anti-clockwise
+    #[arg(long = "irot", value_parser = value_parser!(u8).range(0..=3))]
+    irot_angle: Option<u8>,
+
+    /// AVIF Encode only: Add imir property (mirroring). 0=top-to-bottom, 1=left-to-right
+    #[arg(long = "imir", value_parser = value_parser!(u8).range(0..=1))]
+    imir_axis: Option<u8>,
+
+    /// AVIF Encode only: Add clap property (clean aperture). Width, Height, HOffset, VOffset (in
+    /// numerator/denominator pairs)
+    #[arg(long, value_parser = clap_parser)]
+    clap: Option<CleanAperture>,
+
+    /// AVIF Encode only: Add clap property (clean aperture) calculated from a crop rectangle. X,
+    /// Y, Width, Height
+    #[arg(long, value_parser = crop_parser)]
+    crop: Option<CropRect>,
+
+    /// AVIF Encode only: Add pasp property (aspect ratio). Horizontal spacing, Vertical spacing
+    #[arg(long, value_parser = pasp_parser)]
+    pasp: Option<PixelAspectRatio>,
+
+    /// AVIF Encode only: Add clli property (content light level information). MaxCLL, MaxPALL
+    #[arg(long, value_parser = clli_parser)]
+    clli: Option<ContentLightLevelInformation>,
+
+    /// AVIF Encode only: Set CICP values (nclx colr box) (P/T/M 3 raw numbers, use -r to set range
+    /// flag)
+    #[arg(long, value_parser = cicp_parser)]
+    cicp: Option<Nclx>,
+
+    /// AVIF Encode only: Provide an ICC profile payload to be associated with the primary item
+    #[arg(long)]
+    icc: Option<String>,
+
+    /// AVIF Encode only: Provide an XMP metadata payload to be associated with the primary item
+    #[arg(long)]
+    xmp: Option<String>,
+
+    /// AVIF Encode only: Provide an Exif metadata payload to be associated with the primary item
+    #[arg(long)]
+    exif: Option<String>,
+
+    /// AVIF Encode only: Set frame scaling mode as given fraction
+    #[arg(long, value_parser = scaling_mode_parser)]
+    scaling_mode: Option<IFraction>,
+
+    /// AVIF Encode only: log2 of number of tile rows
+    #[arg(long, value_parser = value_parser!(i32).range(0..=6))]
+    tilerowslog2: Option<i32>,
+
+    /// AVIF Encode only: log2 of number of tile columns
+    #[arg(long, value_parser = value_parser!(i32).range(0..=6))]
+    tilecolslog2: Option<i32>,
+
+    /// AVIF Encode only: Set tile rows and columns automatically. If specified, tilesrowslog2 and
+    /// tilecolslog2 will be ignored
+    #[arg(long, default_value = "false")]
+    autotiling: bool,
+
+    /// AVIF Encode only: Output format, one of 444, 422, 420 or 400. Ignored for y4m. For all
+    /// other cases, auto defaults to 444.
+    #[arg(long = "yuv", value_parser = yuv_format_parser)]
+    yuv_format: Option<PixelFormat>,
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
+        "Absent".to_string()
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
+            match (image.alpha_present, image.alpha_premultiplied) {
+                (true, true) => "Premultiplied".to_string(),
+                (true, false) => "Not premultiplied".to_string(),
+                (false, _) => "Absent".to_string(),
+            },
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
+        image_data.push((0, "Transformations", "None".to_string()));
+    } else {
+        image_data.push((0, "Transformations", "".to_string()));
+        if let Some(pasp) = image.pasp {
+            image_data.push((
+                1,
+                "pasp (Aspect Ratio)",
+                format!("{}/{}", pasp.h_spacing, pasp.v_spacing),
+            ));
+        }
+        if let Some(clap) = image.clap {
+            image_data.push((1, "clap (Clean Aperture)", "".to_string()));
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
+                    (2, "Valid, derived crop rect", "".to_string()),
+                    (3, "X", format!("{}", rect.x)),
+                    (3, "Y", format!("{}", rect.y)),
+                    (3, "W", format!("{}", rect.width)),
+                    (3, "H", format!("{}", rect.height)),
+                ]),
+                Err(_) => image_data.push((2, "Invalid", "".to_string())),
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
+            (0, "Alternate image", "".to_string()),
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
+        image_data.push((0, "Gainmap", "Absent".to_string()));
+    }
+    if image.image_sequence_track_present {
+        image_data.push((
+            0,
+            "Repeat Count",
+            match decoder.repetition_count() {
+                RepetitionCount::Finite(x) => format!("{x}"),
+                RepetitionCount::Infinite => "Infinite".to_string(),
+                RepetitionCount::Unknown => "Unknown".to_string(),
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
+    let mut settings = decoder::Settings {
+        strictness: if args.no_strict { Strictness::None } else { Strictness::All },
+        image_content_to_decode: ImageContentType::All,
+        max_threads: max_threads(&args.jobs),
+        allow_progressive: args.progressive,
+        ignore_exif: args.ignore_exif,
+        ignore_xmp: args.ignore_xmp,
+        ..Default::default()
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
+    let mut decoder = create_decoder_and_parse(args)?;
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
+fn get_extension(filename: &str) -> String {
+    std::path::Path::new(filename)
+        .extension()
+        .and_then(|s| s.to_str())
+        .unwrap_or("")
+        .to_lowercase()
+}
+
+fn decode(args: &CommandLineArgs) -> AvifResult<()> {
+    let max_threads = max_threads(&args.jobs);
+    println!(
+        "Decoding with {max_threads} worker thread{}, please wait...",
+        if max_threads == 1 { "" } else { "s" }
+    );
+    let mut decoder = create_decoder_and_parse(args)?;
+    decoder.nth_image(args.index.unwrap_or(0))?;
+    println!("Image Decoded: {}", args.input_file);
+    println!("Image details:");
+    print_image_info(&decoder);
+
+    let output_filename = &args.output_file.as_ref().unwrap().as_str();
+    let image = decoder.image().unwrap();
+    let extension = get_extension(output_filename);
+    let mut writer: Box<dyn Writer> = match extension.as_str() {
+        "y4m" | "yuv" => {
+            if !image.icc.is_empty() || !image.exif.is_empty() || !image.xmp.is_empty() {
+                println!("Warning: metadata dropped when saving to {extension}");
+            }
+            Box::new(Y4MWriter::create(extension == "yuv"))
+        }
+        #[cfg(feature = "png")]
+        "png" => Box::new(PngWriter { depth: args.depth }),
+        #[cfg(feature = "jpeg")]
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
+#[cfg(feature = "encoder")]
+fn read_file(filepath: &String) -> io::Result<Vec<u8>> {
+    let mut file = File::open(filepath)?;
+    let mut buffer = Vec::new();
+    file.read_to_end(&mut buffer)?;
+    Ok(buffer)
+}
+
+#[cfg(feature = "encoder")]
+fn encode(args: &CommandLineArgs) -> AvifResult<()> {
+    const DEFAULT_ENCODE_QUALITY: u8 = 90;
+    let extension = get_extension(&args.input_file);
+    let mut reader: Box<dyn Reader> = match extension.as_str() {
+        "y4m" => Box::new(Y4MReader::create(&args.input_file)?),
+        #[cfg(feature = "jpeg")]
+        "jpg" | "jpeg" => Box::new(JpegReader::create(&args.input_file)?),
+        #[cfg(feature = "png")]
+        "png" => Box::new(PngReader::create(&args.input_file)?),
+        _ => {
+            return Err(AvifError::UnknownError(format!(
+                "Unknown input file extension ({extension})"
+            )));
+        }
+    };
+    let reader_config = Config {
+        yuv_format: args.yuv_format,
+        depth: args.depth,
+        ..Default::default()
+    };
+    let mut image = reader.read_frame(&reader_config)?;
+    image.irot_angle = args.irot_angle;
+    image.imir_axis = args.imir_axis;
+    if let Some(clap) = args.clap {
+        image.clap = Some(clap);
+    }
+    if let Some(crop) = args.crop {
+        image.clap = Some(CleanAperture::create_from(
+            &crop,
+            image.width,
+            image.height,
+            image.yuv_format,
+        )?);
+    }
+    image.pasp = args.pasp;
+    image.clli = args.clli;
+    if let Some(nclx) = &args.cicp {
+        image.color_primaries = nclx.color_primaries;
+        image.transfer_characteristics = nclx.transfer_characteristics;
+        image.matrix_coefficients = nclx.matrix_coefficients;
+    }
+    if let Some(icc) = &args.icc {
+        image.icc = read_file(icc).expect("failed to read icc file");
+    }
+    if let Some(exif) = &args.exif {
+        image.xmp = read_file(exif).expect("failed to read exif file");
+    }
+    if let Some(xmp) = &args.xmp {
+        image.xmp = read_file(xmp).expect("failed to read xmp file");
+    }
+    let mut settings = encoder::Settings {
+        extra_layer_count: if args.progressive { 1 } else { 0 },
+        speed: args.speed,
+        mutable: MutableSettings {
+            quality: args.quality.unwrap_or(DEFAULT_ENCODE_QUALITY) as i32,
+            tiling_mode: if args.autotiling {
+                TilingMode::Auto
+            } else {
+                TilingMode::Manual(
+                    args.tilerowslog2.unwrap_or(0),
+                    args.tilecolslog2.unwrap_or(0),
+                )
+            },
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+    if let Some(scaling_mode) = args.scaling_mode {
+        settings.mutable.scaling_mode = ScalingMode {
+            horizontal: scaling_mode,
+            vertical: scaling_mode,
+        };
+    }
+    let mut encoder = Encoder::create_with_settings(&settings)?;
+    if reader.has_more_frames() {
+        if args.progressive {
+            println!("Automatic progressive encoding can only have one input image.");
+            return Err(AvifError::InvalidArgument);
+        }
+        loop {
+            // TODO: b/403090413 - Use a proper timestamp here.
+            encoder.add_image_for_sequence(&image, 1000)?;
+            if !reader.has_more_frames() {
+                break;
+            }
+            image = reader.read_frame(&reader_config)?;
+        }
+    } else if args.progressive {
+        // Encode the base layer with very low quality.
+        settings.mutable.quality = 2;
+        encoder.update_settings(&settings.mutable)?;
+        encoder.add_image(&image)?;
+        // Encode the second layer with the requested quality.
+        settings.mutable.quality = args.quality.unwrap_or(DEFAULT_ENCODE_QUALITY) as i32;
+        encoder.update_settings(&settings.mutable)?;
+        encoder.add_image(&image)?;
+    } else {
+        encoder.add_image(&image)?;
+    }
+
+    let encoded_data = encoder.finish()?;
+    let output_file = args.output_file.as_ref().unwrap();
+    let mut file = File::create(output_file).expect("file creation failed");
+    file.write_all(&encoded_data).expect("file writing failed");
+    println!("Write output AVIF: {output_file}");
+    Ok(())
+}
+
+#[cfg(not(feature = "encoder"))]
+fn encode(_args: &CommandLineArgs) -> AvifResult<()> {
+    Err(AvifError::InvalidArgument)
+}
+
+fn can_decode(filename: &str) -> bool {
+    match get_extension(filename).as_str() {
+        "avif" => true,
+        #[cfg(feature = "heic")]
+        "heic" | "heif" => true,
+        _ => false,
+    }
+}
+
+fn can_encode(filename: &str) -> bool {
+    get_extension(filename) == "avif"
+}
+
+fn validate_args(args: &CommandLineArgs) -> AvifResult<()> {
+    if can_decode(&args.input_file) {
+        if args.info {
+            if args.output_file.is_some()
+                || args.quality.is_some()
+                || args.depth.is_some()
+                || args.index.is_some()
+            {
+                return Err(AvifError::UnknownError(
+                    "--info contains unsupported extra arguments".into(),
+                ));
+            }
+        } else {
+            if args.output_file.is_none() {
+                return Err(AvifError::UnknownError("output_file is required".into()));
+            }
+            let output_filename = &args.output_file.as_ref().unwrap().as_str();
+            let extension = get_extension(output_filename);
+            if args.quality.is_some() && extension != "jpg" && extension != "jpeg" {
+                return Err(AvifError::UnknownError(
+                    "quality is only supported for jpeg output".into(),
+                ));
+            }
+            if args.depth.is_some() && extension != "png" {
+                return Err(AvifError::UnknownError(
+                    "depth is only supported for png output".into(),
+                ));
+            }
+        }
+    } else {
+        // TODO: b/403090413 - validate encoding args.
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
+    let res = if can_decode(&args.input_file) {
+        if args.info {
+            info(&args)
+        } else {
+            decode(&args)
+        }
+    } else if let Some(output_file) = &args.output_file {
+        if can_encode(output_file) {
+            encode(&args)
+        } else {
+            eprintln!("Input/output file extensions not supported");
+            std::process::exit(1);
+        }
+    } else {
+        eprintln!(
+            "Input file extension not supported: {}",
+            get_extension(&args.input_file)
+        );
+        std::process::exit(1);
+    };
+    match res {
+        Ok(_) => std::process::exit(0),
+        Err(err) => {
+            eprintln!("ERROR: {:#?}", err);
+            std::process::exit(1);
+        }
+    }
+}
diff --git a/include/avif/avif.h b/include/avif/avif.h
index 1ae166c..768cfc6 100644
--- a/include/avif/avif.h
+++ b/include/avif/avif.h
@@ -76,6 +76,12 @@ constexpr static const uint32_t AVIF_COLOR_PRIMARIES_DCI_P3 = 12;
 
 constexpr static const uint32_t AVIF_TRANSFER_CHARACTERISTICS_SMPTE2084 = 16;
 
+constexpr static const uint32_t AVIF_ADD_IMAGE_FLAG_NONE = 0;
+
+constexpr static const uint32_t AVIF_ADD_IMAGE_FLAG_FORCE_KEYFRAME = (1 << 0);
+
+constexpr static const uint32_t AVIF_ADD_IMAGE_FLAG_SINGLE = (1 << 1);
+
 enum AndroidMediaCodecOutputColorFormat : int32_t {
     ANDROID_MEDIA_CODEC_OUTPUT_COLOR_FORMAT_YUV420_FLEXIBLE = 2135033992,
     ANDROID_MEDIA_CODEC_OUTPUT_COLOR_FORMAT_P010 = 54,
@@ -277,6 +283,8 @@ enum avifResult {
 
 struct Decoder;
 
+struct Encoder;
+
 using avifBool = int;
 
 using avifStrictFlags = uint32_t;
@@ -477,6 +485,38 @@ struct Extent {
 
 using avifExtent = Extent;
 
+struct IFraction {
+    int32_t n;
+    int32_t d;
+};
+
+struct avifScalingMode {
+    IFraction horizontal;
+    IFraction vertical;
+};
+
+struct avifEncoder {
+    avifCodecChoice codecChoice;
+    int32_t maxThreads;
+    int32_t speed;
+    int32_t keyframeInterval;
+    uint64_t timescale;
+    int32_t repetitionCount;
+    uint32_t extraLayerCount;
+    int32_t quality;
+    int32_t qualityAlpha;
+    int32_t tileRowsLog2;
+    int32_t tileColsLog2;
+    avifBool autoTiling;
+    avifScalingMode scalingMode;
+    avifIOStats ioStats;
+    int32_t qualityGainMap;
+    Box<Encoder> rust_encoder;
+    bool rust_encoder_initialized;
+};
+
+using avifAddImageFlags = uint32_t;
+
 using avifPlanesFlags = uint32_t;
 
 struct CropRect {
@@ -566,6 +606,27 @@ avifResult crabby_avifDecoderNthImageMaxExtent(const avifDecoder *decoder,
 
 avifBool crabby_avifPeekCompatibleFileType(const avifROData *input);
 
+avifEncoder *crabby_avifEncoderCreate();
+
+void crabby_avifEncoderDestroy(avifEncoder *encoder);
+
+avifResult crabby_avifEncoderWrite(avifEncoder *encoder,
+                                   const avifImage *image,
+                                   avifRWData *output);
+
+avifResult crabby_avifEncoderAddImage(avifEncoder *encoder,
+                                      const avifImage *image,
+                                      uint64_t durationInTimescales,
+                                      avifAddImageFlags addImageFlags);
+
+avifResult crabby_avifEncoderAddImageGrid(avifEncoder *encoder,
+                                          uint32_t gridCols,
+                                          uint32_t gridRows,
+                                          const avifImage *const *cellImages,
+                                          avifAddImageFlags addImageFlags);
+
+avifResult crabby_avifEncoderFinish(avifEncoder *encoder, avifRWData *output);
+
 avifImage *crabby_avifImageCreateEmpty();
 
 avifImage *crabby_avifImageCreate(uint32_t width,
@@ -639,6 +700,13 @@ avifBool crabby_avifCropRectConvertCleanApertureBox(avifCropRect *cropRect,
                                                     avifPixelFormat yuvFormat,
                                                     avifDiagnostics *_diag);
 
+avifBool crabby_avifCleanApertureBoxConvertCropRect(avifCleanApertureBox *clap,
+                                                    const avifCropRect *cropRect,
+                                                    uint32_t imageW,
+                                                    uint32_t imageH,
+                                                    avifPixelFormat yuvFormat,
+                                                    avifDiagnostics *_diag);
+
 void crabby_avifGetPixelFormatInfo(avifPixelFormat format, avifPixelFormatInfo *info);
 
 void crabby_avifDiagnosticsClearError(avifDiagnostics *diag);
diff --git a/include/avif/libavif_compat.h b/include/avif/libavif_compat.h
index 0d18a13..a414859 100644
--- a/include/avif/libavif_compat.h
+++ b/include/avif/libavif_compat.h
@@ -16,7 +16,10 @@
 
 // Functions.
 #define avifAlloc crabby_avifAlloc
-#define avifCropRectConvertCleanApertureBox crabby_avifCropRectConvertCleanApertureBox
+#define avifCleanApertureBoxConvertCropRect \
+  crabby_avifCleanApertureBoxConvertCropRect
+#define avifCropRectConvertCleanApertureBox \
+  crabby_avifCropRectConvertCleanApertureBox
 #define avifDecoderCreate crabby_avifDecoderCreate
 #define avifDecoderDecodedRowCount crabby_avifDecoderDecodedRowCount
 #define avifDecoderDestroy crabby_avifDecoderDestroy
@@ -35,6 +38,12 @@
 #define avifDecoderSetIOMemory crabby_avifDecoderSetIOMemory
 #define avifDecoderSetSource crabby_avifDecoderSetSource
 #define avifDiagnosticsClearError crabby_avifDiagnosticsClearError
+#define avifEncoderAddImage crabby_avifEncoderAddImage
+#define avifEncoderAddImageGrid crabby_avifEncoderAddImageGrid
+#define avifEncoderCreate crabby_avifEncoderCreate
+#define avifEncoderDestroy crabby_avifEncoderDestroy
+#define avifEncoderFinish crabby_avifEncoderFinish
+#define avifEncoderWrite crabby_avifEncoderWrite
 #define avifFree crabby_avifFree
 #define avifGetPixelFormatInfo crabby_avifGetPixelFormatInfo
 #define avifIOCreateFileReader crabby_avifIOCreateFileReader
@@ -62,7 +71,8 @@
 #define avifRWDataSet crabby_avifRWDataSet
 #define avifResultToString crabby_avifResultToString
 // Constants.
-#define AVIF_DIAGNOSTICS_ERROR_BUFFER_SIZE CRABBY_AVIF_DIAGNOSTICS_ERROR_BUFFER_SIZE
+#define AVIF_DIAGNOSTICS_ERROR_BUFFER_SIZE \
+  CRABBY_AVIF_DIAGNOSTICS_ERROR_BUFFER_SIZE
 #define AVIF_FALSE CRABBY_AVIF_FALSE
 #define AVIF_PLANE_COUNT_YUV CRABBY_AVIF_PLANE_COUNT_YUV
 #define AVIF_REPETITION_COUNT_INFINITE CRABBY_AVIF_REPETITION_COUNT_INFINITE
diff --git a/src/capi/decoder.rs b/src/capi/decoder.rs
index 7cdf945..4bd41e9 100644
--- a/src/capi/decoder.rs
+++ b/src/capi/decoder.rs
@@ -107,6 +107,14 @@ impl Default for avifDecoder {
     }
 }
 
+fn rust_decoder<'a>(decoder: *mut avifDecoder) -> &'a mut Decoder {
+    &mut deref_mut!(decoder).rust_decoder
+}
+
+fn rust_decoder_const<'a>(decoder: *const avifDecoder) -> &'a Decoder {
+    &deref_const!(decoder).rust_decoder
+}
+
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifDecoderCreate() -> *mut avifDecoder {
     Box::into_raw(Box::<avifDecoder>::default())
@@ -114,10 +122,7 @@ pub unsafe extern "C" fn crabby_avifDecoderCreate() -> *mut avifDecoder {
 
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifDecoderSetIO(decoder: *mut avifDecoder, io: *mut avifIO) {
-    unsafe {
-        let rust_decoder = &mut (*decoder).rust_decoder;
-        rust_decoder.set_io(Box::new(avifIOWrapper::create(*io)));
-    }
+    rust_decoder(decoder).set_io(Box::new(avifIOWrapper::create(*deref_const!(io))));
 }
 
 #[no_mangle]
@@ -125,11 +130,8 @@ pub unsafe extern "C" fn crabby_avifDecoderSetIOFile(
     decoder: *mut avifDecoder,
     filename: *const c_char,
 ) -> avifResult {
-    unsafe {
-        let rust_decoder = &mut (*decoder).rust_decoder;
-        let filename = String::from(CStr::from_ptr(filename).to_str().unwrap_or(""));
-        to_avifResult(&rust_decoder.set_io_file(&filename))
-    }
+    let filename = String::from(unsafe { CStr::from_ptr(filename) }.to_str().unwrap_or(""));
+    rust_decoder(decoder).set_io_file(&filename).into()
 }
 
 #[no_mangle]
@@ -138,8 +140,7 @@ pub unsafe extern "C" fn crabby_avifDecoderSetIOMemory(
     data: *const u8,
     size: usize,
 ) -> avifResult {
-    let rust_decoder = unsafe { &mut (*decoder).rust_decoder };
-    to_avifResult(unsafe { &rust_decoder.set_io_raw(data, size) })
+    unsafe { rust_decoder(decoder).set_io_raw(data, size) }.into()
 }
 
 #[no_mangle]
@@ -147,9 +148,7 @@ pub unsafe extern "C" fn crabby_avifDecoderSetSource(
     decoder: *mut avifDecoder,
     source: Source,
 ) -> avifResult {
-    unsafe {
-        (*decoder).requestedSource = source;
-    }
+    deref_mut!(decoder).requestedSource = source;
     avifResult::Ok
 }
 
@@ -239,45 +238,40 @@ fn rust_decoder_to_avifDecoder(src: &Decoder, dst: &mut avifDecoder) {
 
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifDecoderParse(decoder: *mut avifDecoder) -> avifResult {
-    unsafe {
-        let rust_decoder = &mut (*decoder).rust_decoder;
-        rust_decoder.settings = (&(*decoder)).into();
-
-        let res = rust_decoder.parse();
-        (*decoder).diag.set_from_result(&res);
-        if res.is_err() {
-            return to_avifResult(&res);
-        }
-        rust_decoder_to_avifDecoder(rust_decoder, &mut (*decoder));
-        avifResult::Ok
+    let rust_decoder = rust_decoder(decoder);
+    rust_decoder.settings = deref_const!(decoder).into();
+    let res = rust_decoder.parse();
+    deref_mut!(decoder).diag.set_from_result(&res);
+    if res.is_err() {
+        return res.into();
     }
+    rust_decoder_to_avifDecoder(rust_decoder, deref_mut!(decoder));
+    avifResult::Ok
 }
 
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifDecoderNextImage(decoder: *mut avifDecoder) -> avifResult {
-    unsafe {
-        let rust_decoder = &mut (*decoder).rust_decoder;
-        rust_decoder.settings = (&(*decoder)).into();
-
-        let previous_decoded_row_count = rust_decoder.decoded_row_count();
-
-        let res = rust_decoder.next_image();
-        (*decoder).diag.set_from_result(&res);
-        let mut early_return = false;
-        if res.is_err() {
-            early_return = true;
-            if rust_decoder.settings.allow_incremental
-                && matches!(res.as_ref().err().unwrap(), AvifError::WaitingOnIo)
-            {
-                early_return = previous_decoded_row_count == rust_decoder.decoded_row_count();
-            }
-        }
-        if early_return {
-            return to_avifResult(&res);
+    let rust_decoder = rust_decoder(decoder);
+    rust_decoder.settings = deref_const!(decoder).into();
+
+    let previous_decoded_row_count = rust_decoder.decoded_row_count();
+
+    let res = rust_decoder.next_image();
+    deref_mut!(decoder).diag.set_from_result(&res);
+    let mut early_return = false;
+    if res.is_err() {
+        early_return = true;
+        if rust_decoder.settings.allow_incremental
+            && matches!(res.as_ref().err().unwrap(), AvifError::WaitingOnIo)
+        {
+            early_return = previous_decoded_row_count == rust_decoder.decoded_row_count();
         }
-        rust_decoder_to_avifDecoder(rust_decoder, &mut (*decoder));
-        to_avifResult(&res)
     }
+    if early_return {
+        return res.into();
+    }
+    rust_decoder_to_avifDecoder(rust_decoder, deref_mut!(decoder));
+    res.into()
 }
 
 #[no_mangle]
@@ -285,34 +279,32 @@ pub unsafe extern "C" fn crabby_avifDecoderNthImage(
     decoder: *mut avifDecoder,
     frameIndex: u32,
 ) -> avifResult {
-    unsafe {
-        let rust_decoder = &mut (*decoder).rust_decoder;
-        rust_decoder.settings = (&(*decoder)).into();
-
-        let previous_decoded_row_count = rust_decoder.decoded_row_count();
-        let image_index = (rust_decoder.image_index() + 1) as u32;
-
-        let res = rust_decoder.nth_image(frameIndex);
-        (*decoder).diag.set_from_result(&res);
-        let mut early_return = false;
-        if res.is_err() {
-            early_return = true;
-            if rust_decoder.settings.allow_incremental
-                && matches!(res.as_ref().err().unwrap(), AvifError::WaitingOnIo)
-            {
-                if image_index != frameIndex {
-                    early_return = false;
-                } else {
-                    early_return = previous_decoded_row_count == rust_decoder.decoded_row_count();
-                }
+    let rust_decoder = rust_decoder(decoder);
+    rust_decoder.settings = deref_const!(decoder).into();
+
+    let previous_decoded_row_count = rust_decoder.decoded_row_count();
+    let image_index = (rust_decoder.image_index() + 1) as u32;
+
+    let res = rust_decoder.nth_image(frameIndex);
+    deref_mut!(decoder).diag.set_from_result(&res);
+    let mut early_return = false;
+    if res.is_err() {
+        early_return = true;
+        if rust_decoder.settings.allow_incremental
+            && matches!(res.as_ref().err().unwrap(), AvifError::WaitingOnIo)
+        {
+            if image_index != frameIndex {
+                early_return = false;
+            } else {
+                early_return = previous_decoded_row_count == rust_decoder.decoded_row_count();
             }
         }
-        if early_return {
-            return to_avifResult(&res);
-        }
-        rust_decoder_to_avifDecoder(rust_decoder, &mut (*decoder));
-        to_avifResult(&res)
     }
+    if early_return {
+        return res.into();
+    }
+    rust_decoder_to_avifDecoder(rust_decoder, deref_mut!(decoder));
+    res.into()
 }
 
 #[no_mangle]
@@ -321,21 +313,16 @@ pub unsafe extern "C" fn crabby_avifDecoderNthImageTiming(
     frameIndex: u32,
     outTiming: *mut ImageTiming,
 ) -> avifResult {
-    let rust_decoder = unsafe { &(*decoder).rust_decoder };
-    let image_timing = rust_decoder.nth_image_timing(frameIndex);
+    let image_timing = rust_decoder_const(decoder).nth_image_timing(frameIndex);
     if let Ok(timing) = image_timing {
-        unsafe {
-            *outTiming = timing;
-        }
+        *deref_mut!(outTiming) = timing;
     }
-    to_avifResult(&image_timing)
+    image_timing.into()
 }
 
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifDecoderDestroy(decoder: *mut avifDecoder) {
-    unsafe {
-        let _ = Box::from_raw(decoder);
-    }
+    let _ = unsafe { Box::from_raw(decoder) };
 }
 
 #[no_mangle]
@@ -343,22 +330,20 @@ pub unsafe extern "C" fn crabby_avifDecoderRead(
     decoder: *mut avifDecoder,
     image: *mut avifImage,
 ) -> avifResult {
-    unsafe {
-        let rust_decoder = &mut (*decoder).rust_decoder;
-        rust_decoder.settings = (&(*decoder)).into();
+    let rust_decoder = rust_decoder(decoder);
+    rust_decoder.settings = deref_const!(decoder).into();
 
-        let res = rust_decoder.parse();
-        if res.is_err() {
-            return to_avifResult(&res);
-        }
-        let res = rust_decoder.next_image();
-        if res.is_err() {
-            return to_avifResult(&res);
-        }
-        rust_decoder_to_avifDecoder(rust_decoder, &mut (*decoder));
-        *image = (*decoder).image_object.clone();
-        avifResult::Ok
+    let res = rust_decoder.parse();
+    if res.is_err() {
+        return res.into();
+    }
+    let res = rust_decoder.next_image();
+    if res.is_err() {
+        return res.into();
     }
+    rust_decoder_to_avifDecoder(rust_decoder, deref_mut!(decoder));
+    *deref_mut!(image) = deref_mut!(decoder).image_object.clone();
+    avifResult::Ok
 }
 
 #[no_mangle]
@@ -368,13 +353,11 @@ pub unsafe extern "C" fn crabby_avifDecoderReadMemory(
     data: *const u8,
     size: usize,
 ) -> avifResult {
-    unsafe {
-        let res = crabby_avifDecoderSetIOMemory(decoder, data, size);
-        if res != avifResult::Ok {
-            return res;
-        }
-        crabby_avifDecoderRead(decoder, image)
+    let res = unsafe { crabby_avifDecoderSetIOMemory(decoder, data, size) };
+    if res != avifResult::Ok {
+        return res;
     }
+    unsafe { crabby_avifDecoderRead(decoder, image) }
 }
 
 #[no_mangle]
@@ -383,13 +366,11 @@ pub unsafe extern "C" fn crabby_avifDecoderReadFile(
     image: *mut avifImage,
     filename: *const c_char,
 ) -> avifResult {
-    unsafe {
-        let res = crabby_avifDecoderSetIOFile(decoder, filename);
-        if res != avifResult::Ok {
-            return res;
-        }
-        crabby_avifDecoderRead(decoder, image)
+    let res = unsafe { crabby_avifDecoderSetIOFile(decoder, filename) };
+    if res != avifResult::Ok {
+        return res;
     }
+    unsafe { crabby_avifDecoderRead(decoder, image) }
 }
 
 #[no_mangle]
@@ -397,8 +378,7 @@ pub unsafe extern "C" fn crabby_avifDecoderIsKeyframe(
     decoder: *const avifDecoder,
     frameIndex: u32,
 ) -> avifBool {
-    let rust_decoder = unsafe { &(*decoder).rust_decoder };
-    to_avifBool(rust_decoder.is_keyframe(frameIndex))
+    to_avifBool(rust_decoder_const(decoder).is_keyframe(frameIndex))
 }
 
 #[no_mangle]
@@ -406,14 +386,12 @@ pub unsafe extern "C" fn crabby_avifDecoderNearestKeyframe(
     decoder: *const avifDecoder,
     frameIndex: u32,
 ) -> u32 {
-    let rust_decoder = unsafe { &(*decoder).rust_decoder };
-    rust_decoder.nearest_keyframe(frameIndex)
+    rust_decoder_const(decoder).nearest_keyframe(frameIndex)
 }
 
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifDecoderDecodedRowCount(decoder: *const avifDecoder) -> u32 {
-    let rust_decoder = unsafe { &(*decoder).rust_decoder };
-    rust_decoder.decoded_row_count()
+    rust_decoder_const(decoder).decoded_row_count()
 }
 
 #[allow(non_camel_case_types)]
@@ -425,14 +403,11 @@ pub unsafe extern "C" fn crabby_avifDecoderNthImageMaxExtent(
     frameIndex: u32,
     outExtent: *mut avifExtent,
 ) -> avifResult {
-    let rust_decoder = unsafe { &(*decoder).rust_decoder };
-    let res = rust_decoder.nth_image_max_extent(frameIndex);
+    let res = rust_decoder_const(decoder).nth_image_max_extent(frameIndex);
     if res.is_err() {
-        return to_avifResult(&res);
-    }
-    unsafe {
-        *outExtent = res.unwrap();
+        return res.into();
     }
+    *deref_mut!(outExtent) = res.unwrap();
     avifResult::Ok
 }
 
diff --git a/src/capi/encoder.rs b/src/capi/encoder.rs
new file mode 100644
index 0000000..b283f78
--- /dev/null
+++ b/src/capi/encoder.rs
@@ -0,0 +1,142 @@
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
+#![allow(unused)]
+
+use super::gainmap::*;
+use super::image::*;
+use super::io::*;
+use super::types::*;
+
+use std::ffi::CStr;
+use std::num::NonZero;
+use std::os::raw::c_char;
+
+use crate::encoder::*;
+use crate::*;
+
+#[repr(C)]
+#[derive(Default)]
+pub struct avifEncoder {
+    pub codecChoice: avifCodecChoice,
+    pub maxThreads: i32,
+    pub speed: i32,
+    pub keyframeInterval: i32,
+    pub timescale: u64,
+    pub repetitionCount: i32,
+    pub extraLayerCount: u32,
+    pub quality: i32,
+    pub qualityAlpha: i32,
+    pub tileRowsLog2: i32,
+    pub tileColsLog2: i32,
+    pub autoTiling: avifBool,
+    scalingMode: ScalingMode,
+    pub ioStats: crate::decoder::IOStats,
+    pub qualityGainMap: i32,
+    rust_encoder: Box<Encoder>,
+    rust_encoder_initialized: bool,
+}
+
+impl From<&avifEncoder> for Settings {
+    fn from(encoder: &avifEncoder) -> Self {
+        Self {
+            threads: encoder.maxThreads as u32,
+            speed: Some(encoder.speed as u32),
+            keyframe_interval: encoder.keyframeInterval,
+            timescale: encoder.timescale,
+            repetition_count: encoder.repetitionCount,
+            extra_layer_count: encoder.extraLayerCount,
+            mutable: MutableSettings {
+                quality: encoder.quality,
+                // TODO - b/416560730: Convert to proper tiling mode.
+                tiling_mode: TilingMode::Auto,
+                scaling_mode: encoder.scalingMode,
+            },
+        }
+    }
+}
+
+fn rust_encoder<'a>(encoder: *mut avifEncoder) -> &'a mut Encoder {
+    &mut deref_mut!(encoder).rust_encoder
+}
+
+#[no_mangle]
+pub unsafe extern "C" fn crabby_avifEncoderCreate() -> *mut avifEncoder {
+    Box::into_raw(Box::<avifEncoder>::default())
+}
+
+#[no_mangle]
+pub unsafe extern "C" fn crabby_avifEncoderDestroy(encoder: *mut avifEncoder) {
+    let _ = unsafe { Box::from_raw(encoder) };
+}
+
+#[no_mangle]
+pub unsafe extern "C" fn crabby_avifEncoderWrite(
+    encoder: *mut avifEncoder,
+    image: *const avifImage,
+    output: *mut avifRWData,
+) -> avifResult {
+    let res = unsafe { crabby_avifEncoderAddImage(encoder, image, 1, AVIF_ADD_IMAGE_FLAG_SINGLE) };
+    if res != avifResult::Ok {
+        return res;
+    }
+    unsafe { crabby_avifEncoderFinish(encoder, output) }
+}
+
+#[no_mangle]
+pub unsafe extern "C" fn crabby_avifEncoderAddImage(
+    encoder: *mut avifEncoder,
+    image: *const avifImage,
+    durationInTimescales: u64,
+    addImageFlags: avifAddImageFlags,
+) -> avifResult {
+    let encoder_ref = deref_mut!(encoder);
+    if !encoder_ref.rust_encoder_initialized {
+        let settings: Settings = (&*encoder_ref).into();
+        match Encoder::create_with_settings(&settings) {
+            Ok(encoder) => encoder_ref.rust_encoder = Box::new(encoder),
+            Err(err) => return (&err).into(),
+        }
+        encoder_ref.rust_encoder_initialized = true;
+    } else {
+        // TODO - b/416560730: Validate the immutable settings and update the mutable settings for
+        // subsequent frames.
+    }
+    let image: image::Image = deref_const!(image).into();
+    rust_encoder(encoder).add_image(&image).into()
+}
+
+#[no_mangle]
+pub unsafe extern "C" fn crabby_avifEncoderAddImageGrid(
+    encoder: *mut avifEncoder,
+    gridCols: u32,
+    gridRows: u32,
+    cellImages: *const *const avifImage,
+    addImageFlags: avifAddImageFlags,
+) -> avifResult {
+    todo!();
+}
+
+#[no_mangle]
+pub unsafe extern "C" fn crabby_avifEncoderFinish(
+    encoder: *mut avifEncoder,
+    output: *mut avifRWData,
+) -> avifResult {
+    match rust_encoder(encoder).finish() {
+        Ok(encoded_data) => unsafe {
+            crabby_avifRWDataSet(output, encoded_data.as_ptr(), encoded_data.len())
+        },
+        Err(err) => (&err).into(),
+    }
+}
diff --git a/src/capi/gainmap.rs b/src/capi/gainmap.rs
index 9b9d1d0..2fa5e21 100644
--- a/src/capi/gainmap.rs
+++ b/src/capi/gainmap.rs
@@ -16,7 +16,7 @@ use super::image::*;
 use super::io::*;
 use super::types::*;
 
-use crate::decoder::gainmap::*;
+use crate::gainmap::*;
 use crate::image::YuvRange;
 use crate::utils::*;
 use crate::*;
diff --git a/src/capi/image.rs b/src/capi/image.rs
index c3df7b3..00e5c26 100644
--- a/src/capi/image.rs
+++ b/src/capi/image.rs
@@ -19,6 +19,7 @@ use super::types::*;
 use crate::image::*;
 use crate::internal_utils::*;
 use crate::utils::clap::*;
+use crate::utils::pixels::*;
 use crate::utils::*;
 use crate::*;
 
@@ -219,6 +220,111 @@ impl From<&Image> for avifImage {
     }
 }
 
+impl From<&avifImage> for image::Image {
+    fn from(image: &avifImage) -> image::Image {
+        image::Image {
+            width: image.width,
+            height: image.height,
+            depth: image.depth as u8,
+            yuv_format: image.yuvFormat,
+            yuv_range: image.yuvRange,
+            chroma_sample_position: image.yuvChromaSamplePosition,
+            alpha_present: !image.alphaPlane.is_null(),
+            alpha_premultiplied: image.alphaPremultiplied == AVIF_TRUE,
+            planes: [
+                Pixels::from_raw_pointer(
+                    image.yuvPlanes[0],
+                    image.depth,
+                    image.height,
+                    image.yuvRowBytes[0],
+                )
+                .ok(),
+                Pixels::from_raw_pointer(
+                    image.yuvPlanes[1],
+                    image.depth,
+                    image.height,
+                    image.yuvRowBytes[1],
+                )
+                .ok(),
+                Pixels::from_raw_pointer(
+                    image.yuvPlanes[2],
+                    image.depth,
+                    image.height,
+                    image.yuvRowBytes[2],
+                )
+                .ok(),
+                Pixels::from_raw_pointer(
+                    image.alphaPlane,
+                    image.depth,
+                    image.height,
+                    image.alphaRowBytes,
+                )
+                .ok(),
+            ],
+            row_bytes: [
+                image.yuvRowBytes[0],
+                image.yuvRowBytes[1],
+                image.yuvRowBytes[2],
+                image.alphaRowBytes,
+            ],
+            color_primaries: image.colorPrimaries,
+            transfer_characteristics: image.transferCharacteristics,
+            matrix_coefficients: image.matrixCoefficients,
+            clli: image.clli(),
+            pasp: image.pasp(),
+            clap: image.clap(),
+            irot_angle: image.irot_angle(),
+            imir_axis: image.imir_axis(),
+            exif: (&image.exif).into(),
+            icc: (&image.icc).into(),
+            xmp: (&image.xmp).into(),
+            ..Default::default()
+        }
+    }
+}
+
+impl avifImage {
+    fn clli(&self) -> Option<ContentLightLevelInformation> {
+        if self.clli != ContentLightLevelInformation::default() {
+            Some(self.clli)
+        } else {
+            None
+        }
+    }
+
+    fn pasp(&self) -> Option<PixelAspectRatio> {
+        if (self.transformFlags & AVIF_TRANSFORM_PASP) != 0 {
+            Some(self.pasp)
+        } else {
+            None
+        }
+    }
+
+    fn clap(&self) -> Option<CleanAperture> {
+        if (self.transformFlags & AVIF_TRANSFORM_CLAP) != 0 {
+            Some((&self.clap).into())
+        } else {
+            None
+        }
+    }
+
+    fn irot_angle(&self) -> Option<u8> {
+        if (self.transformFlags & AVIF_TRANSFORM_IROT) != 0 {
+            Some(self.irot.angle)
+        } else {
+            None
+        }
+    }
+
+    fn imir_axis(&self) -> Option<u8> {
+        if (self.transformFlags & AVIF_TRANSFORM_IMIR) != 0 {
+            Some(self.imir.axis)
+        } else {
+            None
+        }
+    }
+}
+
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifImageCreateEmpty() -> *mut avifImage {
     Box::into_raw(Box::<avifImage>::default())
@@ -269,7 +375,6 @@ fn copy_plane_helper(
 }
 
 #[no_mangle]
-#[allow(unused)]
 pub unsafe extern "C" fn crabby_avifImageCopy(
     dstImage: *mut avifImage,
     srcImage: *const avifImage,
@@ -278,8 +383,8 @@ pub unsafe extern "C" fn crabby_avifImageCopy(
     unsafe {
         crabby_avifImageFreePlanes(dstImage, avifPlanesFlag::AvifPlanesAll as u32);
     }
-    let dst = unsafe { &mut (*dstImage) };
-    let src = unsafe { &(*srcImage) };
+    let dst = deref_mut!(dstImage);
+    let src = deref_const!(srcImage);
     dst.width = src.width;
     dst.height = src.height;
     dst.depth = src.depth;
@@ -324,6 +429,9 @@ pub unsafe extern "C" fn crabby_avifImageCopy(
             let alloc_plane_width = round2_usize(plane_width);
             let plane_size = alloc_plane_width * alloc_plane_height * pixel_size;
             dst.yuvPlanes[plane] = unsafe { crabby_avifAlloc(plane_size) } as *mut _;
+            if dst.yuvPlanes[plane].is_null() {
+                return avifResult::OutOfMemory;
+            }
             dst.yuvRowBytes[plane] = (pixel_size * alloc_plane_width) as u32;
             copy_plane_helper(
                 src.yuvPlanes[plane],
@@ -344,6 +452,9 @@ pub unsafe extern "C" fn crabby_avifImageCopy(
         let alloc_plane_width = round2_usize(plane_width);
         let plane_size = alloc_plane_width * alloc_plane_height * pixel_size;
         dst.alphaPlane = unsafe { crabby_avifAlloc(plane_size) } as *mut _;
+        if dst.alphaPlane.is_null() {
+            return avifResult::OutOfMemory;
+        }
         dst.alphaRowBytes = (pixel_size * alloc_plane_width) as u32;
         copy_plane_helper(
             src.alphaPlane,
@@ -363,7 +474,11 @@ fn avif_image_allocate_planes_helper(
     image: &mut avifImage,
     planes: avifPlanesFlags,
 ) -> AvifResult<()> {
-    if image.width == 0 || image.height == 0 {
+    if image.width == 0
+        || image.height == 0
+        || image.width > decoder::DEFAULT_IMAGE_DIMENSION_LIMIT
+        || image.height > decoder::DEFAULT_IMAGE_DIMENSION_LIMIT
+    {
         return Err(AvifError::InvalidArgument);
     }
     let channel_size = if image.depth == 8 { 1 } else { 2 };
@@ -378,6 +493,9 @@ fn avif_image_allocate_planes_helper(
         if image.yuvPlanes[0].is_null() {
             image.yuvRowBytes[0] = u32_from_usize(y_row_bytes)?;
             image.yuvPlanes[0] = unsafe { crabby_avifAlloc(y_size) as *mut u8 };
+            if image.yuvPlanes[0].is_null() {
+                return Err(AvifError::OutOfMemory);
+            }
         }
         if !image.yuvFormat.is_monochrome() {
             let csx0 = image.yuvFormat.chroma_shift_x().0 as u64;
@@ -387,8 +505,8 @@ fn avif_image_allocate_planes_helper(
             let csy = image.yuvFormat.chroma_shift_y() as u64;
             let height = ((image.height as u64) + csy) >> csy;
             let alloc_height = round2_u32(u32_from_u64(height)?);
-            let uv_row_bytes = usize_from_u32(alloc_width * channel_size)?;
-            let uv_size = usize_from_u32(uv_row_bytes as u32 * alloc_height)?;
+            let uv_row_bytes = usize_from_u32(checked_mul!(alloc_width, channel_size)?)?;
+            let uv_size = usize_from_u32(checked_mul!(uv_row_bytes as u32, alloc_height)?)?;
             let plane_end = match image.yuvFormat {
                 PixelFormat::AndroidP010 | PixelFormat::AndroidNv12 | PixelFormat::AndroidNv21 => 1,
                 _ => 2,
@@ -399,6 +517,9 @@ fn avif_image_allocate_planes_helper(
                 }
                 image.yuvRowBytes[plane] = u32_from_usize(uv_row_bytes)?;
                 image.yuvPlanes[plane] = unsafe { crabby_avifAlloc(uv_size) as *mut u8 };
+                if image.yuvPlanes[plane].is_null() {
+                    return Err(AvifError::OutOfMemory);
+                }
             }
         }
     }
@@ -406,6 +527,9 @@ fn avif_image_allocate_planes_helper(
         image.imageOwnsAlphaPlane = AVIF_TRUE;
         image.alphaRowBytes = u32_from_usize(y_row_bytes)?;
         image.alphaPlane = unsafe { crabby_avifAlloc(y_size) as *mut u8 };
+        if image.alphaPlane.is_null() {
+            return Err(AvifError::OutOfMemory);
+        }
     }
     Ok(())
 }
@@ -415,8 +539,7 @@ pub unsafe extern "C" fn crabby_avifImageAllocatePlanes(
     image: *mut avifImage,
     planes: avifPlanesFlags,
 ) -> avifResult {
-    let image = unsafe { &mut (*image) };
-    to_avifResult(&avif_image_allocate_planes_helper(image, planes))
+    avif_image_allocate_planes_helper(deref_mut!(image), planes).into()
 }
 
 #[no_mangle]
@@ -424,7 +547,7 @@ pub unsafe extern "C" fn crabby_avifImageFreePlanes(
     image: *mut avifImage,
     planes: avifPlanesFlags,
 ) {
-    let image = unsafe { &mut (*image) };
+    let image = deref_mut!(image);
     if (planes & 1) != 0 {
         for plane in 0usize..3 {
             if image.imageOwnsYUVPlanes == AVIF_TRUE {
@@ -453,21 +576,22 @@ pub unsafe extern "C" fn crabby_avifImageFreePlanes(
 pub unsafe extern "C" fn crabby_avifImageDestroy(image: *mut avifImage) {
     unsafe {
         crabby_avifImageFreePlanes(image, avifPlanesFlag::AvifPlanesAll as u32);
+        crabby_avifRWDataFree(&mut (*image).icc as _);
+        crabby_avifRWDataFree(&mut (*image).exif as _);
+        crabby_avifRWDataFree(&mut (*image).xmp as _);
         let _ = Box::from_raw(image);
     }
 }
 
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifImageUsesU16(image: *const avifImage) -> avifBool {
-    unsafe { to_avifBool(!image.is_null() && (*image).depth > 8) }
+    to_avifBool(!image.is_null() && deref_const!(image).depth > 8)
 }
 
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifImageIsOpaque(image: *const avifImage) -> avifBool {
-    unsafe {
-        // TODO: Check for pixel level opacity as well.
-        to_avifBool(!image.is_null() && !(*image).alphaPlane.is_null())
-    }
+    // TODO: Check for pixel level opacity as well.
+    to_avifBool(!image.is_null() && deref_const!(image).alphaPlane.is_null())
 }
 
 #[no_mangle]
@@ -475,12 +599,10 @@ pub unsafe extern "C" fn crabby_avifImagePlane(image: *const avifImage, channel:
     if image.is_null() {
         return std::ptr::null_mut();
     }
-    unsafe {
-        match channel {
-            0..=2 => (*image).yuvPlanes[channel as usize],
-            3 => (*image).alphaPlane,
-            _ => std::ptr::null_mut(),
-        }
+    match channel {
+        0..=2 => deref_const!(image).yuvPlanes[channel as usize],
+        3 => deref_const!(image).alphaPlane,
+        _ => std::ptr::null_mut(),
     }
 }
 
@@ -492,12 +614,10 @@ pub unsafe extern "C" fn crabby_avifImagePlaneRowBytes(
     if image.is_null() {
         return 0;
     }
-    unsafe {
-        match channel {
-            0..=2 => (*image).yuvRowBytes[channel as usize],
-            3 => (*image).alphaRowBytes,
-            _ => 0,
-        }
+    match channel {
+        0..=2 => deref_const!(image).yuvRowBytes[channel as usize],
+        3 => deref_const!(image).alphaRowBytes,
+        _ => 0,
     }
 }
 
@@ -509,35 +629,34 @@ pub unsafe extern "C" fn crabby_avifImagePlaneWidth(
     if image.is_null() {
         return 0;
     }
-    unsafe {
-        match channel {
-            0 => (*image).width,
-            1 => match (*image).yuvFormat {
-                PixelFormat::Yuv444
-                | PixelFormat::AndroidP010
-                | PixelFormat::AndroidNv12
-                | PixelFormat::AndroidNv21 => (*image).width,
-                PixelFormat::Yuv420 | PixelFormat::Yuv422 => ((*image).width).div_ceil(2),
-                PixelFormat::None | PixelFormat::Yuv400 => 0,
-            },
-            2 => match (*image).yuvFormat {
-                PixelFormat::Yuv444 => (*image).width,
-                PixelFormat::Yuv420 | PixelFormat::Yuv422 => ((*image).width).div_ceil(2),
-                PixelFormat::None
-                | PixelFormat::Yuv400
-                | PixelFormat::AndroidP010
-                | PixelFormat::AndroidNv12
-                | PixelFormat::AndroidNv21 => 0,
-            },
-            3 => {
-                if !(*image).alphaPlane.is_null() {
-                    (*image).width
-                } else {
-                    0
-                }
+    let image = deref_const!(image);
+    match channel {
+        0 => image.width,
+        1 => match image.yuvFormat {
+            PixelFormat::Yuv444
+            | PixelFormat::AndroidP010
+            | PixelFormat::AndroidNv12
+            | PixelFormat::AndroidNv21 => image.width,
+            PixelFormat::Yuv420 | PixelFormat::Yuv422 => image.width.div_ceil(2),
+            PixelFormat::None | PixelFormat::Yuv400 => 0,
+        },
+        2 => match image.yuvFormat {
+            PixelFormat::Yuv444 => image.width,
+            PixelFormat::Yuv420 | PixelFormat::Yuv422 => image.width.div_ceil(2),
+            PixelFormat::None
+            | PixelFormat::Yuv400
+            | PixelFormat::AndroidP010
+            | PixelFormat::AndroidNv12
+            | PixelFormat::AndroidNv21 => 0,
+        },
+        3 => {
+            if !image.alphaPlane.is_null() {
+                image.width
+            } else {
+                0
             }
-            _ => 0,
         }
+        _ => 0,
     }
 }
 
@@ -549,26 +668,25 @@ pub unsafe extern "C" fn crabby_avifImagePlaneHeight(
     if image.is_null() {
         return 0;
     }
-    unsafe {
-        match channel {
-            0 => (*image).height,
-            1 | 2 => {
-                if (*image).yuvFormat.is_monochrome() {
-                    0
-                } else {
-                    let shift_y = (*image).yuvFormat.chroma_shift_y();
-                    ((*image).height + shift_y) >> shift_y
-                }
+    let image = deref_const!(image);
+    match channel {
+        0 => image.height,
+        1 | 2 => {
+            if image.yuvFormat.is_monochrome() {
+                0
+            } else {
+                let shift_y = image.yuvFormat.chroma_shift_y();
+                (image.height + shift_y) >> shift_y
             }
-            3 => {
-                if !(*image).alphaPlane.is_null() {
-                    (*image).height
-                } else {
-                    0
-                }
+        }
+        3 => {
+            if !image.alphaPlane.is_null() {
+                image.height
+            } else {
+                0
             }
-            _ => 0,
         }
+        _ => 0,
     }
 }
 
@@ -578,9 +696,9 @@ pub unsafe extern "C" fn crabby_avifImageSetViewRect(
     srcImage: *const avifImage,
     rect: *const avifCropRect,
 ) -> avifResult {
-    let dst = unsafe { &mut (*dstImage) };
-    let src = unsafe { &(*srcImage) };
-    let rect = unsafe { &(*rect) };
+    let dst = deref_mut!(dstImage);
+    let src = deref_const!(srcImage);
+    let rect = deref_const!(rect);
     if rect.width > src.width
         || rect.height > src.height
         || rect.x > (src.width - rect.width)
diff --git a/src/capi/io.rs b/src/capi/io.rs
index 45b2bfd..5a983fd 100644
--- a/src/capi/io.rs
+++ b/src/capi/io.rs
@@ -64,32 +64,41 @@ impl From<&Vec<u8>> for avifRWData {
     }
 }
 
+impl From<&avifRWData> for Vec<u8> {
+    fn from(data: &avifRWData) -> Vec<u8> {
+        if data.size == 0 {
+            Vec::new()
+        } else {
+            unsafe { std::slice::from_raw_parts(data.data, data.size).to_vec() }
+        }
+    }
+}
+
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifRWDataRealloc(
     raw: *mut avifRWData,
     newSize: usize,
 ) -> avifResult {
-    unsafe {
-        if (*raw).size == newSize {
-            return avifResult::Ok;
-        }
-        // Ok to use size as capacity here since we use reserve_exact.
-        let mut newData: Vec<u8> = Vec::new();
-        if newData.try_reserve_exact(newSize).is_err() {
-            return avifResult::OutOfMemory;
-        }
-        if !(*raw).data.is_null() {
-            let oldData = Box::from_raw(std::slice::from_raw_parts_mut((*raw).data, (*raw).size));
-            let sizeToCopy = std::cmp::min(newSize, oldData.len());
-            newData.extend_from_slice(&oldData[..sizeToCopy]);
-        }
-        newData.resize(newSize, 0);
-        let mut b = newData.into_boxed_slice();
-        (*raw).data = b.as_mut_ptr();
-        std::mem::forget(b);
-        (*raw).size = newSize;
-        avifResult::Ok
+    let raw = deref_mut!(raw);
+    if raw.size == newSize {
+        return avifResult::Ok;
+    }
+    // Ok to use size as capacity here since we use reserve_exact.
+    let mut newData: Vec<u8> = Vec::new();
+    if newData.try_reserve_exact(newSize).is_err() {
+        return avifResult::OutOfMemory;
     }
+    if !raw.data.is_null() {
+        let oldData = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(raw.data, raw.size)) };
+        let sizeToCopy = std::cmp::min(newSize, oldData.len());
+        newData.extend_from_slice(&oldData[..sizeToCopy]);
+    }
+    newData.resize(newSize, 0);
+    let mut b = newData.into_boxed_slice();
+    raw.data = b.as_mut_ptr();
+    std::mem::forget(b);
+    raw.size = newSize;
+    avifResult::Ok
 }
 
 #[no_mangle]
@@ -108,18 +117,17 @@ pub unsafe extern "C" fn crabby_avifRWDataSet(
         } else {
             crabby_avifRWDataFree(raw);
         }
-        avifResult::Ok
     }
+    avifResult::Ok
 }
 
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifRWDataFree(raw: *mut avifRWData) {
-    unsafe {
-        if (*raw).data.is_null() {
-            return;
-        }
-        let _ = Box::from_raw(std::slice::from_raw_parts_mut((*raw).data, (*raw).size));
+    let raw = deref_mut!(raw);
+    if raw.data.is_null() {
+        return;
     }
+    let _ = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(raw.data, raw.size)) };
 }
 
 pub type avifIODestroyFunc = unsafe extern "C" fn(io: *mut avifIO);
@@ -213,25 +221,24 @@ unsafe extern "C" fn cioRead(
     size: usize,
     out: *mut avifROData,
 ) -> avifResult {
-    unsafe {
-        if io.is_null() {
-            return avifResult::IoError;
-        }
-        let cio = (*io).data as *mut avifCIOWrapper;
-        match (*cio).io.read(offset, size) {
-            Ok(data) => {
-                (*cio).buf.clear();
-                if (*cio).buf.try_reserve_exact(data.len()).is_err() {
-                    return avifResult::OutOfMemory;
-                }
-                (*cio).buf.extend_from_slice(data);
+    if io.is_null() {
+        return avifResult::IoError;
+    }
+    let io = deref_mut!(io);
+    let cio = deref_mut!(io.data as *mut avifCIOWrapper);
+    match cio.io.read(offset, size) {
+        Ok(data) => {
+            cio.buf.clear();
+            if cio.buf.try_reserve_exact(data.len()).is_err() {
+                return avifResult::OutOfMemory;
             }
-            Err(_) => return avifResult::IoError,
+            cio.buf.extend_from_slice(data);
         }
-        (*out).data = (*cio).buf.as_ptr();
-        (*out).size = (*cio).buf.len();
-        avifResult::Ok
+        Err(_) => return avifResult::IoError,
     }
+    deref_mut!(out).data = cio.buf.as_ptr();
+    deref_mut!(out).size = cio.buf.len();
+    avifResult::Ok
 }
 
 #[no_mangle]
@@ -267,7 +274,7 @@ pub unsafe extern "C" fn crabby_avifIOCreateMemoryReader(
 
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifIOCreateFileReader(filename: *const c_char) -> *mut avifIO {
-    let filename = unsafe { String::from(CStr::from_ptr(filename).to_str().unwrap_or("")) };
+    let filename = String::from(unsafe { CStr::from_ptr(filename) }.to_str().unwrap_or(""));
     let file_io = match DecoderFileIO::create(&filename) {
         Ok(x) => x,
         Err(_) => return std::ptr::null_mut(),
diff --git a/src/capi/mod.rs b/src/capi/mod.rs
index a9c2f0a..8e1e474 100644
--- a/src/capi/mod.rs
+++ b/src/capi/mod.rs
@@ -20,8 +20,30 @@
 #![allow(dead_code)]
 
 mod decoder;
+#[cfg(feature = "encoder")]
+mod encoder;
 mod gainmap;
 mod image;
 mod io;
 mod reformat;
 mod types;
+
+#[macro_export]
+macro_rules! deref_const {
+    ($ptr:expr) => {{
+        // The extra curly braces here is necessary to make this whole macro into a single
+        // expression.
+        assert!(!$ptr.is_null());
+        unsafe { &*($ptr) }
+    }};
+}
+
+#[macro_export]
+macro_rules! deref_mut {
+    ($ptr:expr) => {{
+        // The extra curly braces here is necessary to make this whole macro into a single
+        // expression.
+        assert!(!$ptr.is_null());
+        unsafe { &mut *($ptr) }
+    }};
+}
diff --git a/src/capi/reformat.rs b/src/capi/reformat.rs
index b78b79e..748e9ef 100644
--- a/src/capi/reformat.rs
+++ b/src/capi/reformat.rs
@@ -16,9 +16,9 @@ use super::image::*;
 use super::types::*;
 
 use crate::image::*;
-use crate::internal_utils::pixels::*;
 use crate::internal_utils::*;
 use crate::reformat::rgb;
+use crate::utils::pixels::*;
 use crate::*;
 
 /// cbindgen:rename-all=CamelCase
@@ -51,7 +51,7 @@ impl From<rgb::Image> for avifRGBImage {
             alpha_premultiplied: rgb.premultiply_alpha,
             is_float: rgb.is_float,
             max_threads: rgb.max_threads,
-            pixels: rgb.pixels(),
+            pixels: rgb.pixels_mut(),
             row_bytes: rgb.row_bytes,
         }
     }
@@ -90,69 +90,13 @@ impl From<&avifRGBImage> for rgb::Image {
     }
 }
 
-impl From<&avifImage> for image::Image {
-    // Only copies fields necessary for reformatting.
-    fn from(image: &avifImage) -> image::Image {
-        image::Image {
-            width: image.width,
-            height: image.height,
-            depth: image.depth as u8,
-            yuv_format: image.yuvFormat,
-            yuv_range: image.yuvRange,
-            alpha_present: !image.alphaPlane.is_null(),
-            alpha_premultiplied: image.alphaPremultiplied == AVIF_TRUE,
-            planes: [
-                Pixels::from_raw_pointer(
-                    image.yuvPlanes[0],
-                    image.depth,
-                    image.height,
-                    image.yuvRowBytes[0],
-                )
-                .ok(),
-                Pixels::from_raw_pointer(
-                    image.yuvPlanes[1],
-                    image.depth,
-                    image.height,
-                    image.yuvRowBytes[1],
-                )
-                .ok(),
-                Pixels::from_raw_pointer(
-                    image.yuvPlanes[2],
-                    image.depth,
-                    image.height,
-                    image.yuvRowBytes[2],
-                )
-                .ok(),
-                Pixels::from_raw_pointer(
-                    image.alphaPlane,
-                    image.depth,
-                    image.height,
-                    image.alphaRowBytes,
-                )
-                .ok(),
-            ],
-            row_bytes: [
-                image.yuvRowBytes[0],
-                image.yuvRowBytes[1],
-                image.yuvRowBytes[2],
-                image.alphaRowBytes,
-            ],
-            color_primaries: image.colorPrimaries,
-            transfer_characteristics: image.transferCharacteristics,
-            matrix_coefficients: image.matrixCoefficients,
-            ..Default::default()
-        }
-    }
-}
-
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifRGBImageSetDefaults(
     rgb: *mut avifRGBImage,
     image: *const avifImage,
 ) {
-    let rgb = unsafe { &mut (*rgb) };
-    let image: image::Image = unsafe { &(*image) }.into();
-    *rgb = rgb::Image::create_from_yuv(&image).into();
+    let image: image::Image = deref_const!(image).into();
+    *deref_mut!(rgb) = rgb::Image::create_from_yuv(&image).into();
 }
 
 #[no_mangle]
@@ -160,14 +104,12 @@ pub unsafe extern "C" fn crabby_avifImageYUVToRGB(
     image: *const avifImage,
     rgb: *mut avifRGBImage,
 ) -> avifResult {
-    unsafe {
-        if (*image).yuvPlanes[0].is_null() {
-            return avifResult::Ok;
-        }
+    if deref_const!(image).yuvPlanes[0].is_null() {
+        return avifResult::Ok;
     }
-    let mut rgb: rgb::Image = unsafe { &(*rgb) }.into();
-    let image: image::Image = unsafe { &(*image) }.into();
-    to_avifResult(&rgb.convert_from_yuv(&image))
+    let mut rgb: rgb::Image = deref_const!(rgb).into();
+    let image: image::Image = deref_const!(image).into();
+    rgb.convert_from_yuv(&image).into()
 }
 
 fn CopyPlanes(dst: &mut avifImage, src: &Image) -> AvifResult<()> {
@@ -208,6 +150,9 @@ fn CopyPlanes(dst: &mut avifImage, src: &Image) -> AvifResult<()> {
             if plane == Plane::V && dst.yuvPlanes[2].is_null() {
                 let plane_size = usize_from_u32(plane_data.width * plane_data.height * 2)?;
                 dst.yuvPlanes[2] = unsafe { crabby_avifAlloc(plane_size) } as *mut _;
+                if dst.yuvPlanes[2].is_null() {
+                    return Err(AvifError::OutOfMemory);
+                }
                 dst.yuvRowBytes[2] = plane_data.width * 2;
             }
             let dst_planes = [
@@ -245,30 +190,33 @@ pub unsafe extern "C" fn crabby_avifImageScale(
     dstHeight: u32,
     _diag: *mut avifDiagnostics,
 ) -> avifResult {
-    // To avoid buffer reallocations, we only support scaling to a smaller size.
-    let dst_image = unsafe { &mut (*image) };
+    let dst_image = deref_mut!(image);
     if dstWidth > dst_image.width || dstHeight > dst_image.height {
+        // To avoid buffer reallocations, we only support scaling to a smaller size.
         return avifResult::NotImplemented;
     }
+    if dstWidth == dst_image.width && dstHeight == dst_image.height {
+        return avifResult::Ok;
+    }
 
-    let mut rust_image: image::Image = unsafe { &(*image) }.into();
+    let mut rust_image: image::Image = deref_const!(image).into();
     let res = rust_image.scale(dstWidth, dstHeight, Category::Color);
     if res.is_err() {
-        return to_avifResult(&res);
+        return res.into();
     }
     // The scale function is designed to work only for one category at a time.
     // Restore the width and height to the original values before scaling the
     // alpha plane.
-    rust_image.width = unsafe { (*image).width };
-    rust_image.height = unsafe { (*image).height };
+    rust_image.width = deref_const!(image).width;
+    rust_image.height = deref_const!(image).height;
     let res = rust_image.scale(dstWidth, dstHeight, Category::Alpha);
     if res.is_err() {
-        return to_avifResult(&res);
+        return res.into();
     }
 
     dst_image.width = rust_image.width;
     dst_image.height = rust_image.height;
     dst_image.depth = rust_image.depth as _;
     dst_image.yuvFormat = rust_image.yuv_format;
-    to_avifResult(&CopyPlanes(dst_image, &rust_image))
+    CopyPlanes(dst_image, &rust_image).into()
 }
diff --git a/src/capi/types.rs b/src/capi/types.rs
index 658786c..5173a2f 100644
--- a/src/capi/types.rs
+++ b/src/capi/types.rs
@@ -97,6 +97,18 @@ impl From<&AvifError> for avifResult {
     }
 }
 
+impl<T> From<AvifResult<T>> for avifResult {
+    fn from(res: AvifResult<T>) -> Self {
+        match res {
+            Ok(_) => avifResult::Ok,
+            Err(err) => {
+                let res: avifResult = (&err).into();
+                res
+            }
+        }
+    }
+}
+
 impl From<avifResult> for AvifError {
     fn from(res: avifResult) -> Self {
         match res {
@@ -247,7 +259,9 @@ impl avifDiagnostics {
 }
 
 #[repr(C)]
+#[derive(Default)]
 pub enum avifCodecChoice {
+    #[default]
     Auto = 0,
     Aom = 1,
     Dav1d = 2,
@@ -265,16 +279,6 @@ pub(crate) fn to_avifBool(val: bool) -> avifBool {
     }
 }
 
-pub(crate) fn to_avifResult<T>(res: &AvifResult<T>) -> avifResult {
-    match res {
-        Ok(_) => avifResult::Ok,
-        Err(err) => {
-            let res: avifResult = err.into();
-            res
-        }
-    }
-}
-
 const RESULT_TO_STRING: &[&str] = &[
     "Ok\0",
     "Unknown Error\0",
@@ -329,8 +333,8 @@ pub unsafe extern "C" fn crabby_avifCropRectConvertCleanApertureBox(
     yuvFormat: PixelFormat,
     _diag: *mut avifDiagnostics,
 ) -> avifBool {
-    let rust_clap: CleanAperture = unsafe { (&(*clap)).into() };
-    let rect = unsafe { &mut (*cropRect) };
+    let rust_clap: CleanAperture = deref_const!(clap).into();
+    let rect = deref_mut!(cropRect);
     *rect = match CropRect::create_from(&rust_clap, imageW, imageH, yuvFormat) {
         Ok(x) => x,
         Err(_) => return AVIF_FALSE,
@@ -338,6 +342,23 @@ pub unsafe extern "C" fn crabby_avifCropRectConvertCleanApertureBox(
     AVIF_TRUE
 }
 
+#[no_mangle]
+pub unsafe extern "C" fn crabby_avifCleanApertureBoxConvertCropRect(
+    clap: *mut avifCleanApertureBox,
+    cropRect: *const avifCropRect,
+    imageW: u32,
+    imageH: u32,
+    yuvFormat: PixelFormat,
+    _diag: *mut avifDiagnostics,
+) -> avifBool {
+    *deref_mut!(clap) =
+        match CleanAperture::create_from(deref_const!(cropRect), imageW, imageH, yuvFormat) {
+            Ok(x) => (&Some(x)).into(),
+            Err(_) => return AVIF_FALSE,
+        };
+    AVIF_TRUE
+}
+
 // Constants and definitions from libavif that are not used in rust.
 
 pub const AVIF_PLANE_COUNT_YUV: usize = 3;
@@ -384,7 +405,7 @@ pub unsafe extern "C" fn crabby_avifGetPixelFormatInfo(
     if info.is_null() {
         return;
     }
-    let info = unsafe { &mut (*info) };
+    let info = deref_mut!(info);
     match format {
         PixelFormat::Yuv444 => {
             info.chromaShiftX = 0;
@@ -415,9 +436,7 @@ pub unsafe extern "C" fn crabby_avifDiagnosticsClearError(diag: *mut avifDiagnos
     if diag.is_null() {
         return;
     }
-    unsafe {
-        (*diag).error[0] = 0;
-    }
+    deref_mut!(diag).error[0] = 0;
 }
 
 #[repr(C)]
@@ -443,7 +462,9 @@ pub const AVIF_TRANSFER_CHARACTERISTICS_SMPTE2084: u32 = 16;
 #[no_mangle]
 pub unsafe extern "C" fn crabby_avifAlloc(size: usize) -> *mut c_void {
     let mut data: Vec<u8> = Vec::new();
-    data.reserve_exact(size);
+    if data.try_reserve_exact(size).is_err() {
+        return std::ptr::null_mut();
+    }
     data.resize(size, 0);
     let mut boxed_slice = data.into_boxed_slice();
     let ptr = boxed_slice.as_mut_ptr();
@@ -457,3 +478,8 @@ pub unsafe extern "C" fn crabby_avifFree(p: *mut c_void) {
         let _ = unsafe { Box::from_raw(p as *mut u8) };
     }
 }
+
+pub const AVIF_ADD_IMAGE_FLAG_NONE: u32 = 0;
+pub const AVIF_ADD_IMAGE_FLAG_FORCE_KEYFRAME: u32 = 1 << 0;
+pub const AVIF_ADD_IMAGE_FLAG_SINGLE: u32 = 1 << 1;
+pub type avifAddImageFlags = u32;
diff --git a/src/codecs/android_mediacodec.rs b/src/codecs/android_mediacodec.rs
index e79302e..0f5d4b7 100644
--- a/src/codecs/android_mediacodec.rs
+++ b/src/codecs/android_mediacodec.rs
@@ -18,9 +18,9 @@ use crate::decoder::CodecChoice;
 use crate::decoder::GridImageHelper;
 use crate::image::Image;
 use crate::image::YuvRange;
-use crate::internal_utils::pixels::*;
 use crate::internal_utils::stream::IStream;
 use crate::internal_utils::*;
+use crate::utils::pixels::*;
 use crate::*;
 
 use ndk_sys::bindings::*;
@@ -439,6 +439,10 @@ impl MediaCodec {
                     codec_specific_data.len(),
                 );
             }
+            // For video codecs, 0 is the highest importance (higher the number lesser the
+            // importance). To make codec for images less important, give it a value more than 0.
+            c_str!(importance, importance_tmp, "importance");
+            AMediaFormat_setInt32(format, importance, 1);
         }
 
         let codec = match &self.codec_initializers[self.codec_index] {
@@ -529,8 +533,15 @@ impl MediaCodec {
                     }
                     image.row_bytes[i] = plane_info.row_stride[i];
                     let plane_height = if i == 0 { image.height } else { (image.height + 1) / 2 };
+                    let offset_index = if i == 1 && image.yuv_format == PixelFormat::AndroidNv21 {
+                        // For Nv21, V plane comes before the U plane, so the UV plane offset
+                        // should point to the V plane.
+                        2
+                    } else {
+                        i
+                    };
                     image.planes[i] = Some(Pixels::from_raw_pointer(
-                        unsafe { buffer.offset(plane_info.offset[i]) },
+                        unsafe { buffer.offset(plane_info.offset[offset_index]) },
                         image.depth as u32,
                         plane_height,
                         image.row_bytes[i],
diff --git a/src/codecs/aom.rs b/src/codecs/aom.rs
new file mode 100644
index 0000000..2276eab
--- /dev/null
+++ b/src/codecs/aom.rs
@@ -0,0 +1,503 @@
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
+#![allow(non_upper_case_globals)]
+
+use crate::codecs::*;
+use crate::encoder::Sample;
+use crate::encoder::ScalingMode;
+use crate::image::Image;
+use crate::image::YuvRange;
+use crate::utils::IFraction;
+use crate::*;
+
+use aom_sys::bindings::*;
+
+use std::cmp;
+use std::mem::MaybeUninit;
+
+#[derive(Default)]
+pub struct Aom {
+    encoder: Option<aom_codec_ctx_t>,
+    aom_config: Option<aom_codec_enc_cfg>,
+    config: Option<EncoderConfig>,
+    current_layer: u32,
+}
+
+fn aom_format(image: &Image, category: Category) -> AvifResult<aom_img_fmt_t> {
+    let format = match category {
+        Category::Alpha => aom_img_fmt_AOM_IMG_FMT_I420,
+        _ => match image.yuv_format {
+            PixelFormat::Yuv420 | PixelFormat::Yuv400 => aom_img_fmt_AOM_IMG_FMT_I420,
+            PixelFormat::Yuv422 => aom_img_fmt_AOM_IMG_FMT_I422,
+            PixelFormat::Yuv444 => aom_img_fmt_AOM_IMG_FMT_I444,
+            _ => return Err(AvifError::InvalidArgument),
+        },
+    };
+    Ok(if image.depth > 8 { format | AOM_IMG_FMT_HIGHBITDEPTH } else { format })
+}
+
+fn aom_bps(format: aom_img_fmt_t) -> i32 {
+    match format {
+        aom_img_fmt_AOM_IMG_FMT_I420 => 12,
+        aom_img_fmt_AOM_IMG_FMT_I422 => 16,
+        aom_img_fmt_AOM_IMG_FMT_I444 => 24,
+        aom_img_fmt_AOM_IMG_FMT_I42016 => 24,
+        aom_img_fmt_AOM_IMG_FMT_I42216 => 32,
+        aom_img_fmt_AOM_IMG_FMT_I44416 => 48,
+        _ => 16,
+    }
+}
+
+fn aom_seq_profile(image: &Image, category: Category) -> AvifResult<u32> {
+    if image.depth == 12 {
+        // 12 bit is always profile 2.
+        return Ok(2);
+    }
+    if category == Category::Alpha {
+        // Alpha is monochrome, so it is always profile 0.
+        return Ok(0);
+    }
+    match image.yuv_format {
+        PixelFormat::Yuv420 | PixelFormat::Yuv400 => Ok(0),
+        PixelFormat::Yuv422 => Ok(2),
+        PixelFormat::Yuv444 => Ok(1),
+        _ => Err(AvifError::InvalidArgument),
+    }
+}
+
+fn get_aom_scaling_mode_1d(mut fraction: IFraction) -> AvifResult<aom_scaling_mode_1d> {
+    fraction.is_valid()?;
+    fraction.simplify();
+    Ok(match fraction {
+        IFraction(1, 1) => aom_scaling_mode_1d_AOME_NORMAL,
+        IFraction(1, 2) => aom_scaling_mode_1d_AOME_ONETWO,
+        IFraction(1, 3) => aom_scaling_mode_1d_AOME_ONETHREE,
+        IFraction(1, 4) => aom_scaling_mode_1d_AOME_ONEFOUR,
+        IFraction(1, 8) => aom_scaling_mode_1d_AOME_ONEEIGHT,
+        IFraction(2, 3) => aom_scaling_mode_1d_AOME_TWOTHREE,
+        IFraction(3, 4) => aom_scaling_mode_1d_AOME_THREEFOUR,
+        IFraction(3, 5) => aom_scaling_mode_1d_AOME_THREEFIVE,
+        IFraction(4, 5) => aom_scaling_mode_1d_AOME_FOURFIVE,
+        _ => return Err(AvifError::NotImplemented),
+    })
+}
+
+fn aom_scaling_mode(scaling_mode: &ScalingMode) -> AvifResult<aom_scaling_mode_t> {
+    Ok(aom_scaling_mode_t {
+        h_scaling_mode: get_aom_scaling_mode_1d(scaling_mode.horizontal)?,
+        v_scaling_mode: get_aom_scaling_mode_1d(scaling_mode.vertical)?,
+    })
+}
+
+macro_rules! codec_control {
+    ($self: expr, $key: expr, $value: expr) => {
+        if unsafe { aom_codec_control($self.encoder.unwrap_mut() as *mut _, $key as _, $value) }
+            != aom_codec_err_t_AOM_CODEC_OK
+        {
+            return Err(AvifError::UnknownError("".into()));
+        }
+    };
+}
+
+impl Encoder for Aom {
+    fn encode_image(
+        &mut self,
+        image: &Image,
+        category: Category,
+        config: &EncoderConfig,
+        output_samples: &mut Vec<Sample>,
+    ) -> AvifResult<()> {
+        if self.encoder.is_none() {
+            let encoder_iface = unsafe { aom_codec_av1_cx() };
+            let aom_usage = if config.is_single_image {
+                AOM_USAGE_ALL_INTRA
+            } else if config.speed.unwrap_or(0) >= 7 {
+                AOM_USAGE_REALTIME
+            } else {
+                AOM_USAGE_GOOD_QUALITY
+            };
+            let mut cfg_uninit: MaybeUninit<aom_codec_enc_cfg> = MaybeUninit::uninit();
+            let err = unsafe {
+                aom_codec_enc_config_default(encoder_iface, cfg_uninit.as_mut_ptr(), aom_usage)
+            };
+            if err != aom_codec_err_t_AOM_CODEC_OK {
+                return Err(AvifError::UnknownError("".into()));
+            }
+            let mut aom_config = unsafe { cfg_uninit.assume_init() };
+            aom_config.rc_end_usage = match aom_usage {
+                AOM_USAGE_REALTIME => aom_rc_mode_AOM_CBR,
+                _ => aom_rc_mode_AOM_Q,
+            };
+            aom_config.g_profile = aom_seq_profile(image, category)?;
+            aom_config.g_bit_depth = image.depth as _;
+            aom_config.g_input_bit_depth = image.depth as _;
+            aom_config.g_w = image.width;
+            aom_config.g_h = image.height;
+
+            if config.is_single_image {
+                aom_config.g_limit = 1;
+                aom_config.g_lag_in_frames = 0;
+                aom_config.kf_mode = aom_kf_mode_AOM_KF_DISABLED;
+                aom_config.kf_max_dist = 0;
+            }
+            if config.disable_lagged_output {
+                aom_config.g_lag_in_frames = 0;
+            }
+            if config.extra_layer_count > 0 {
+                aom_config.g_lag_in_frames = 0;
+                aom_config.g_limit = config.extra_layer_count + 1;
+            }
+            if config.threads > 1 {
+                aom_config.g_threads = cmp::min(config.threads, 64);
+            }
+
+            aom_config.monochrome =
+                (category == Category::Alpha || image.yuv_format == PixelFormat::Yuv400).into();
+            // TODO: Aom options pre init.
+            aom_config.rc_min_quantizer = config.quantizer as u32;
+            aom_config.rc_max_quantizer = config.quantizer as u32;
+
+            let mut encoder_uninit: MaybeUninit<aom_codec_ctx_t> = MaybeUninit::uninit();
+            let err = unsafe {
+                aom_codec_enc_init_ver(
+                    encoder_uninit.as_mut_ptr(),
+                    encoder_iface,
+                    &aom_config as *const _,
+                    if image.depth > 8 { AOM_CODEC_USE_HIGHBITDEPTH } else { 0 } as _,
+                    AOM_ENCODER_ABI_VERSION as _,
+                )
+            };
+            if err != aom_codec_err_t_AOM_CODEC_OK {
+                return Err(AvifError::UnknownError(format!(
+                    "aom_codec_enc_init failed. err: {err}"
+                )));
+            }
+            self.encoder = Some(unsafe { encoder_uninit.assume_init() });
+
+            if aom_config.rc_end_usage == aom_rc_mode_AOM_CQ
+                || aom_config.rc_end_usage == aom_rc_mode_AOM_Q
+            {
+                codec_control!(
+                    self,
+                    aome_enc_control_id_AOME_SET_CQ_LEVEL,
+                    config.quantizer
+                );
+            }
+            if config.quantizer == 0 {
+                codec_control!(self, aome_enc_control_id_AV1E_SET_LOSSLESS, 1);
+            }
+            if config.tile_rows_log2 != 0 {
+                codec_control!(
+                    self,
+                    aome_enc_control_id_AV1E_SET_TILE_ROWS,
+                    config.tile_rows_log2
+                );
+            }
+            if config.tile_columns_log2 != 0 {
+                codec_control!(
+                    self,
+                    aome_enc_control_id_AV1E_SET_TILE_COLUMNS,
+                    config.tile_columns_log2
+                );
+            }
+            if config.extra_layer_count > 0 {
+                codec_control!(
+                    self,
+                    aome_enc_control_id_AOME_SET_NUMBER_SPATIAL_LAYERS,
+                    config.extra_layer_count + 1
+                );
+            }
+            if let Some(speed) = config.speed {
+                codec_control!(
+                    self,
+                    aome_enc_control_id_AOME_SET_CPUUSED,
+                    cmp::min(speed, 9)
+                );
+            }
+            match category {
+                Category::Alpha => {
+                    // AVIF specification, Section 4 "Auxiliary Image Items and Sequences":
+                    //   The color_range field in the Sequence Header OBU shall be set to 1.
+                    codec_control!(
+                        self,
+                        aome_enc_control_id_AV1E_SET_COLOR_RANGE,
+                        aom_color_range_AOM_CR_FULL_RANGE
+                    )
+                    // Keep the default AOM_CSP_UNKNOWN value.
+
+                    // CICP (CP/TC/MC) does not apply to the alpha auxiliary image.
+                    // Keep default Unspecified (2) colour primaries, transfer characteristics,
+                    // and matrix coefficients.
+                }
+                _ => {
+                    // libaom's defaults are AOM_CSP_UNKNOWN and 0 (studio/limited range).
+                    // Call aom_codec_control() only if the values are not the defaults.
+                    // AV1-ISOBMFF specification, Section 2.3.4:
+                    //   The value of full_range_flag in the 'colr' box SHALL match the color_range
+                    //   flag in the Sequence Header OBU.
+                    if image.yuv_range != YuvRange::Limited {
+                        codec_control!(
+                            self,
+                            aome_enc_control_id_AV1E_SET_COLOR_RANGE,
+                            aom_color_range_AOM_CR_FULL_RANGE
+                        );
+                    }
+                    // Section 2.3.4 of AV1-ISOBMFF says 'colr' with 'nclx' should be present and
+                    // shall match CICP values in the Sequence Header OBU, unless the latter has
+                    // 2/2/2 (Unspecified). So set CICP values to 2/2/2 (Unspecified) in the
+                    // Sequence Header OBU for simplicity. libaom's defaults are
+                    // AOM_CICP_CP_UNSPECIFIED, AOM_CICP_TC_UNSPECIFIED, and
+                    // AOM_CICP_MC_UNSPECIFIED. No need to call aom_codec_control().
+                }
+            }
+            if aom_config.g_usage == AOM_USAGE_ALL_INTRA {
+                codec_control!(
+                    self,
+                    aome_enc_control_id_AV1E_SET_SKIP_POSTPROC_FILTERING,
+                    1
+                );
+            }
+            // TODO: Aom options post init.
+            // TODO: tuning?
+            self.aom_config = Some(aom_config);
+            self.config = Some(*config);
+        } else if self.config.unwrap_ref() != config {
+            let aom_config = self.aom_config.unwrap_mut();
+            if aom_config.g_w != image.width || aom_config.g_h != image.height {
+                // Dimension changes aren't allowed.
+                return Err(AvifError::NotImplemented);
+            }
+            let last_config = self.config.unwrap_ref();
+            if last_config.quantizer != config.quantizer {
+                if aom_config.rc_end_usage == aom_rc_mode_AOM_VBR
+                    || aom_config.rc_end_usage == aom_rc_mode_AOM_CBR
+                {
+                    aom_config.rc_min_quantizer = config.quantizer as u32;
+                    aom_config.rc_max_quantizer = config.quantizer as u32;
+                    let err = unsafe {
+                        aom_codec_enc_config_set(
+                            self.encoder.unwrap_mut() as *mut _,
+                            self.aom_config.unwrap_ref() as *const _,
+                        )
+                    };
+                    if err != aom_codec_err_t_AOM_CODEC_OK {
+                        return Err(AvifError::UnknownError(format!(
+                            "aom_codec_enc_config_set failed. err: {err}"
+                        )));
+                    }
+                } else if aom_config.rc_end_usage == aom_rc_mode_AOM_CQ
+                    || aom_config.rc_end_usage == aom_rc_mode_AOM_Q
+                {
+                    codec_control!(
+                        self,
+                        aome_enc_control_id_AOME_SET_CQ_LEVEL,
+                        config.quantizer
+                    );
+                }
+                codec_control!(
+                    self,
+                    aome_enc_control_id_AV1E_SET_LOSSLESS,
+                    if config.quantizer == 0 { 1 } else { 0 }
+                );
+            }
+            if last_config.tile_rows_log2 != config.tile_rows_log2 {
+                codec_control!(
+                    self,
+                    aome_enc_control_id_AV1E_SET_TILE_ROWS,
+                    config.tile_rows_log2
+                );
+            }
+            if last_config.tile_columns_log2 != config.tile_columns_log2 {
+                codec_control!(
+                    self,
+                    aome_enc_control_id_AV1E_SET_TILE_COLUMNS,
+                    config.tile_columns_log2
+                );
+            }
+            self.config = Some(*config);
+        }
+        if self.current_layer > config.extra_layer_count {
+            return Err(AvifError::InvalidArgument);
+        }
+        if config.extra_layer_count > 0 {
+            codec_control!(
+                self,
+                aome_enc_control_id_AOME_SET_SPATIAL_LAYER_ID,
+                self.current_layer
+            );
+        }
+        let scaling_mode = aom_scaling_mode(&self.config.unwrap_ref().scaling_mode)?;
+        if scaling_mode.h_scaling_mode != aom_scaling_mode_1d_AOME_NORMAL
+            || scaling_mode.v_scaling_mode != aom_scaling_mode_1d_AOME_NORMAL
+        {
+            codec_control!(
+                self,
+                aome_enc_control_id_AOME_SET_SCALEMODE,
+                &scaling_mode as *const _
+            );
+        }
+        let mut aom_image: aom_image_t = unsafe { std::mem::zeroed() };
+        aom_image.fmt = aom_format(image, category)?;
+        aom_image.bit_depth = if image.depth > 8 { 16 } else { 8 };
+        aom_image.w = image.width;
+        aom_image.h = image.height;
+        aom_image.d_w = image.width;
+        aom_image.d_h = image.height;
+        aom_image.bps = aom_bps(aom_image.fmt);
+        aom_image.x_chroma_shift = image.yuv_format.chroma_shift_x().0;
+        aom_image.y_chroma_shift = image.yuv_format.chroma_shift_y();
+        match category {
+            Category::Alpha => {
+                aom_image.range = aom_color_range_AOM_CR_FULL_RANGE;
+                aom_image.monochrome = 1;
+                aom_image.x_chroma_shift = 1;
+                aom_image.y_chroma_shift = 1;
+                aom_image.planes[0] = image.planes[3].unwrap_ref().ptr_generic() as *mut _;
+                aom_image.stride[0] = image.row_bytes[3] as i32;
+            }
+            _ => {
+                aom_image.range = image.yuv_range as u32;
+                if image.yuv_format == PixelFormat::Yuv400 {
+                    aom_image.monochrome = 1;
+                    aom_image.x_chroma_shift = 1;
+                    aom_image.y_chroma_shift = 1;
+                    aom_image.planes[0] = image.planes[0].unwrap_ref().ptr_generic() as *mut _;
+                    aom_image.stride[0] = image.row_bytes[0] as i32;
+                } else {
+                    aom_image.monochrome = 0;
+                    for i in 0..=2 {
+                        aom_image.planes[i] = image.planes[i].unwrap_ref().ptr_generic() as *mut _;
+                        aom_image.stride[i] = image.row_bytes[i] as i32;
+                    }
+                }
+            }
+        }
+        aom_image.cp = image.color_primaries as u32;
+        aom_image.tc = image.transfer_characteristics as u32;
+        aom_image.mc = image.matrix_coefficients as u32;
+        // TODO: b/392112497 - force keyframes when necessary.
+        let mut encode_flags = 0i64;
+        if self.current_layer > 0 {
+            encode_flags |= AOM_EFLAG_NO_REF_GF as i64
+                | AOM_EFLAG_NO_REF_ARF as i64
+                | AOM_EFLAG_NO_REF_BWD as i64
+                | AOM_EFLAG_NO_REF_ARF2 as i64
+                | AOM_EFLAG_NO_UPD_GF as i64
+                | AOM_EFLAG_NO_UPD_ARF as i64;
+        }
+        let err = unsafe {
+            aom_codec_encode(
+                self.encoder.unwrap_mut() as *mut _,
+                &aom_image as *const _,
+                0,
+                1,
+                encode_flags,
+            )
+        };
+        if err != aom_codec_err_t_AOM_CODEC_OK {
+            return Err(AvifError::UnknownError(format!("err: {err}")));
+        }
+        let mut iter: aom_codec_iter_t = std::ptr::null_mut();
+        loop {
+            let pkt = unsafe {
+                aom_codec_get_cx_data(self.encoder.unwrap_mut() as *mut _, &mut iter as *mut _)
+            };
+            if pkt.is_null() {
+                break;
+            }
+            let pkt = unsafe { *pkt };
+            if pkt.kind == aom_codec_cx_pkt_kind_AOM_CODEC_CX_FRAME_PKT {
+                unsafe {
+                    let encoded_data = std::slice::from_raw_parts(
+                        pkt.data.frame.buf as *const u8,
+                        pkt.data.frame.sz,
+                    );
+                    let sync = (pkt.data.frame.flags & AOM_FRAME_IS_KEY) != 0;
+                    output_samples.push(Sample::create_from(encoded_data, sync)?);
+                }
+            }
+        }
+        if config.is_single_image
+            || (config.extra_layer_count > 0 && config.extra_layer_count == self.current_layer)
+        {
+            self.finish(output_samples)?;
+            unsafe {
+                aom_codec_destroy(self.encoder.unwrap_mut() as *mut _);
+            }
+            self.encoder = None;
+        }
+        if config.extra_layer_count > 0 {
+            self.current_layer += 1;
+        }
+        Ok(())
+    }
+
+    fn finish(&mut self, output_samples: &mut Vec<crate::encoder::Sample>) -> AvifResult<()> {
+        if self.encoder.is_none() {
+            return Ok(());
+        }
+        loop {
+            // Flush the encoder.
+            let err = unsafe {
+                aom_codec_encode(
+                    self.encoder.unwrap_mut() as *mut _,
+                    std::ptr::null(),
+                    0,
+                    1,
+                    0,
+                )
+            };
+            if err != aom_codec_err_t_AOM_CODEC_OK {
+                return Err(AvifError::UnknownError("".into()));
+            }
+            let mut got_packet = false;
+            let mut iter: aom_codec_iter_t = std::ptr::null_mut();
+            loop {
+                let pkt = unsafe {
+                    aom_codec_get_cx_data(self.encoder.unwrap_mut() as *mut _, &mut iter as *mut _)
+                };
+                if pkt.is_null() {
+                    break;
+                }
+                let pkt = unsafe { *pkt };
+                if pkt.kind == aom_codec_cx_pkt_kind_AOM_CODEC_CX_FRAME_PKT {
+                    got_packet = true;
+                    unsafe {
+                        let encoded_data = std::slice::from_raw_parts(
+                            pkt.data.frame.buf as *const u8,
+                            pkt.data.frame.sz,
+                        );
+                        let sync = (pkt.data.frame.flags & AOM_FRAME_IS_KEY) != 0;
+                        output_samples.push(Sample::create_from(encoded_data, sync)?);
+                    }
+                }
+            }
+            if !got_packet {
+                break;
+            }
+        }
+        Ok(())
+    }
+}
+
+impl Drop for Aom {
+    fn drop(&mut self) {
+        if self.encoder.is_some() {
+            unsafe {
+                aom_codec_destroy(self.encoder.unwrap_mut() as *mut _);
+            }
+        }
+    }
+}
diff --git a/src/codecs/dav1d.rs b/src/codecs/dav1d.rs
index 3db8120..a242e61 100644
--- a/src/codecs/dav1d.rs
+++ b/src/codecs/dav1d.rs
@@ -12,13 +12,18 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+// The type of the fields from dav1d_sys::bindings::* are dependent on the
+// compiler that is used to generate the bindings, version of dav1d, etc.
+// So allow clippy to ignore unnecessary cast warnings.
+#![allow(clippy::unnecessary_cast)]
+
 use crate::codecs::Decoder;
 use crate::codecs::DecoderConfig;
 use crate::decoder::CodecChoice;
 use crate::decoder::GridImageHelper;
 use crate::image::Image;
 use crate::image::YuvRange;
-use crate::internal_utils::pixels::*;
+use crate::utils::pixels::*;
 use crate::*;
 
 use dav1d_sys::bindings::*;
@@ -28,7 +33,7 @@ use std::mem::MaybeUninit;
 #[derive(Default)]
 pub struct Dav1d {
     context: Option<*mut Dav1dContext>,
-    picture: Option<Dav1dPicture>,
+    picture: Option<Dav1dPictureWrapper>,
     config: Option<DecoderConfig>,
 }
 
@@ -42,6 +47,89 @@ unsafe extern "C" fn avif_dav1d_free_callback(
 // See https://code.videolan.org/videolan/dav1d/-/blob/9849ede1304da1443cfb4a86f197765081034205/include/dav1d/common.h#L55-59
 const DAV1D_EAGAIN: i32 = if libc::EPERM > 0 { -libc::EAGAIN } else { libc::EAGAIN };
 
+struct Dav1dPictureWrapper {
+    picture: Dav1dPicture,
+}
+
+impl Default for Dav1dPictureWrapper {
+    fn default() -> Self {
+        Self {
+            picture: unsafe { std::mem::zeroed() },
+        }
+    }
+}
+
+impl Dav1dPictureWrapper {
+    fn mut_ptr(&mut self) -> *mut Dav1dPicture {
+        (&mut self.picture) as *mut _
+    }
+
+    fn get(&self) -> &Dav1dPicture {
+        &self.picture
+    }
+
+    fn use_layer(&self, spatial_id: u8) -> bool {
+        spatial_id == 0xFF || spatial_id == unsafe { (*self.get().frame_hdr).spatial_id as u8 }
+    }
+}
+
+impl Drop for Dav1dPictureWrapper {
+    fn drop(&mut self) {
+        unsafe {
+            dav1d_picture_unref(self.mut_ptr());
+        }
+    }
+}
+
+struct Dav1dDataWrapper {
+    data: Dav1dData,
+}
+
+impl Default for Dav1dDataWrapper {
+    fn default() -> Self {
+        Self {
+            data: unsafe { std::mem::zeroed() },
+        }
+    }
+}
+
+impl Dav1dDataWrapper {
+    fn mut_ptr(&mut self) -> *mut Dav1dData {
+        (&mut self.data) as *mut _
+    }
+
+    fn has_data(&self) -> bool {
+        self.data.sz > 0 && !self.data.data.is_null()
+    }
+
+    fn wrap(&mut self, payload: &[u8]) -> AvifResult<()> {
+        match unsafe {
+            dav1d_data_wrap(
+                self.mut_ptr(),
+                payload.as_ptr(),
+                payload.len(),
+                Some(avif_dav1d_free_callback),
+                /*cookie=*/ std::ptr::null_mut(),
+            )
+        } {
+            0 => Ok(()),
+            res => Err(AvifError::UnknownError(format!(
+                "dav1d_data_wrap returned {res}"
+            ))),
+        }
+    }
+}
+
+impl Drop for Dav1dDataWrapper {
+    fn drop(&mut self) {
+        if self.has_data() {
+            unsafe {
+                dav1d_data_unref(self.mut_ptr());
+            }
+        }
+    }
+}
+
 impl Dav1d {
     fn initialize_impl(&mut self, low_latency: bool) -> AvifResult<()> {
         if self.context.is_some() {
@@ -82,6 +170,14 @@ impl Dav1d {
         Ok(())
     }
 
+    fn drop_impl(&mut self) {
+        self.picture = None;
+        if self.context.is_some() {
+            unsafe { dav1d_close(&mut self.context.unwrap()) };
+        }
+        self.context = None;
+    }
+
     fn picture_to_image(
         &self,
         dav1d_picture: &Dav1dPicture,
@@ -154,12 +250,83 @@ impl Dav1d {
         }
         Ok(())
     }
+
+    fn get_next_image_grid_impl(
+        &mut self,
+        payloads: &[Vec<u8>],
+        spatial_id: u8,
+        grid_image_helper: &mut GridImageHelper,
+    ) -> AvifResult<()> {
+        if self.context.is_none() {
+            self.initialize_impl(false)?;
+        }
+        let mut res;
+        let context = self.context.unwrap();
+        let mut payloads_iter = payloads.iter().peekable();
+        unsafe {
+            let mut data = Dav1dDataWrapper::default();
+            let max_retries = 500;
+            let mut retries = 0;
+            while !grid_image_helper.is_grid_complete()? {
+                if !data.has_data() && payloads_iter.peek().is_some() {
+                    data.wrap(payloads_iter.next().unwrap())?;
+                }
+                if data.has_data() {
+                    res = dav1d_send_data(context, data.mut_ptr());
+                    if res != 0 && res != DAV1D_EAGAIN {
+                        return Err(AvifError::UnknownError(format!(
+                            "dav1d_send_data returned {res}"
+                        )));
+                    }
+                }
+                let mut picture = Dav1dPictureWrapper::default();
+                res = dav1d_get_picture(context, picture.mut_ptr());
+                if res != 0 && res != DAV1D_EAGAIN {
+                    return Err(AvifError::UnknownError(format!(
+                        "dav1d_get_picture returned {res}"
+                    )));
+                } else if res == 0 && picture.use_layer(spatial_id) {
+                    let mut cell_image = Image::default();
+                    self.picture_to_image(
+                        picture.get(),
+                        &mut cell_image,
+                        grid_image_helper.category,
+                    )?;
+                    grid_image_helper.copy_from_cell_image(&mut cell_image)?;
+                    retries = 0;
+                } else {
+                    retries += 1;
+                    if retries > max_retries {
+                        return Err(AvifError::UnknownError(format!(
+                            "dav1d_get_picture never returned a frame after {max_retries} calls"
+                        )));
+                    }
+                }
+            }
+            self.flush()?;
+        }
+        Ok(())
+    }
+
+    fn flush(&mut self) -> AvifResult<()> {
+        unsafe {
+            loop {
+                let mut picture = Dav1dPictureWrapper::default();
+                let res = dav1d_get_picture(self.context.unwrap(), picture.mut_ptr());
+                if res < 0 && res != DAV1D_EAGAIN {
+                    return Err(AvifError::UnknownError(format!(
+                        "error draining buffered frames {res}"
+                    )));
+                }
+                if res != 0 {
+                    break;
+                }
+            }
+        }
+        Ok(())
+    }
 }
 
-// The type of the fields from dav1d_sys::bindings::* are dependent on the
-// compiler that is used to generate the bindings, version of dav1d, etc.
-// So allow clippy to ignore unnecessary cast warnings.
-#[allow(clippy::unnecessary_cast)]
 impl Decoder for Dav1d {
     fn codec(&self) -> CodecChoice {
         CodecChoice::Dav1d
@@ -181,121 +348,65 @@ impl Decoder for Dav1d {
             self.initialize_impl(true)?;
         }
         unsafe {
-            let mut data: Dav1dData = std::mem::zeroed();
-            let res = dav1d_data_wrap(
-                (&mut data) as *mut _,
-                av1_payload.as_ptr(),
-                av1_payload.len(),
-                Some(avif_dav1d_free_callback),
-                /*cookie=*/ std::ptr::null_mut(),
-            );
-            if res != 0 {
-                return Err(AvifError::UnknownError(format!(
-                    "dav1d_data_wrap returned {res}"
-                )));
-            }
-            let mut next_frame: Dav1dPicture = std::mem::zeroed();
-            let got_picture;
+            let mut data = Dav1dDataWrapper::default();
+            data.wrap(av1_payload)?;
+            let next_picture: Option<Dav1dPictureWrapper>;
             loop {
-                if !data.data.is_null() {
-                    let res = dav1d_send_data(self.context.unwrap(), (&mut data) as *mut _);
+                if data.has_data() {
+                    let res = dav1d_send_data(self.context.unwrap(), data.mut_ptr());
                     if res < 0 && res != DAV1D_EAGAIN {
-                        dav1d_data_unref((&mut data) as *mut _);
                         return Err(AvifError::UnknownError(format!(
                             "dav1d_send_data returned {res}"
                         )));
                     }
                 }
 
-                let res = dav1d_get_picture(self.context.unwrap(), (&mut next_frame) as *mut _);
+                let mut picture = Dav1dPictureWrapper::default();
+                let res = dav1d_get_picture(self.context.unwrap(), picture.mut_ptr());
                 if res == DAV1D_EAGAIN {
-                    // send more data.
-                    if !data.data.is_null() {
+                    if data.has_data() {
                         continue;
                     }
                     return Err(AvifError::UnknownError("".into()));
                 } else if res < 0 {
-                    if !data.data.is_null() {
-                        dav1d_data_unref((&mut data) as *mut _);
-                    }
                     return Err(AvifError::UnknownError(format!(
                         "dav1d_send_picture returned {res}"
                     )));
-                } else {
+                } else if picture.use_layer(spatial_id) {
                     // Got a picture.
-                    let frame_spatial_id = (*next_frame.frame_hdr).spatial_id as u8;
-                    if spatial_id != 0xFF && spatial_id != frame_spatial_id {
-                        // layer selection: skip this unwanted layer.
-                        dav1d_picture_unref((&mut next_frame) as *mut _);
-                    } else {
-                        got_picture = true;
-                        break;
-                    }
-                }
-            }
-            if !data.data.is_null() {
-                dav1d_data_unref((&mut data) as *mut _);
-            }
-
-            // Drain all buffered frames in the decoder.
-            //
-            // The sample should have only one frame of the desired layer. If there are more frames
-            // after that frame, we need to discard them so that they won't be mistakenly output
-            // when the decoder is used to decode another sample.
-            let mut buffered_frame: Dav1dPicture = std::mem::zeroed();
-            loop {
-                let res = dav1d_get_picture(self.context.unwrap(), (&mut buffered_frame) as *mut _);
-                if res < 0 {
-                    if res != DAV1D_EAGAIN {
-                        if got_picture {
-                            dav1d_picture_unref((&mut next_frame) as *mut _);
-                        }
-                        return Err(AvifError::UnknownError(format!(
-                            "error draining buffered frames {res}"
-                        )));
-                    }
-                } else {
-                    dav1d_picture_unref((&mut buffered_frame) as *mut _);
-                }
-                if res != 0 {
+                    next_picture = Some(picture);
                     break;
                 }
             }
-
-            if got_picture {
-                // unref previous frame.
-                if self.picture.is_some() {
-                    let mut previous_picture = self.picture.unwrap();
-                    dav1d_picture_unref((&mut previous_picture) as *mut _);
-                }
-                self.picture = Some(next_frame);
+            self.flush()?;
+            if next_picture.is_some() {
+                self.picture = Some(next_picture.unwrap());
             } else if category == Category::Alpha && self.picture.is_some() {
                 // Special case for alpha, re-use last frame.
             } else {
                 return Err(AvifError::UnknownError("".into()));
             }
         }
-        self.picture_to_image(self.picture.unwrap_ref(), image, category)?;
+        self.picture_to_image(self.picture.unwrap_ref().get(), image, category)?;
         Ok(())
     }
 
     fn get_next_image_grid(
         &mut self,
-        _payloads: &[Vec<u8>],
-        _spatial_id: u8,
-        _grid_image_helper: &mut GridImageHelper,
+        payloads: &[Vec<u8>],
+        spatial_id: u8,
+        grid_image_helper: &mut GridImageHelper,
     ) -> AvifResult<()> {
-        Err(AvifError::NotImplemented)
+        let res = self.get_next_image_grid_impl(payloads, spatial_id, grid_image_helper);
+        if res.is_err() {
+            self.drop_impl();
+        }
+        res
     }
 }
 
 impl Drop for Dav1d {
     fn drop(&mut self) {
-        if self.picture.is_some() {
-            unsafe { dav1d_picture_unref(self.picture.unwrap_mut() as *mut _) };
-        }
-        if self.context.is_some() {
-            unsafe { dav1d_close(&mut self.context.unwrap()) };
-        }
+        self.drop_impl();
     }
 }
diff --git a/src/codecs/libgav1.rs b/src/codecs/libgav1.rs
index 30acd95..941d2ac 100644
--- a/src/codecs/libgav1.rs
+++ b/src/codecs/libgav1.rs
@@ -18,7 +18,7 @@ use crate::decoder::CodecChoice;
 use crate::decoder::GridImageHelper;
 use crate::image::Image;
 use crate::image::YuvRange;
-use crate::internal_utils::pixels::*;
+use crate::utils::pixels::*;
 use crate::*;
 
 use libgav1_sys::bindings::*;
diff --git a/src/codecs/mod.rs b/src/codecs/mod.rs
index eb42e57..2094776 100644
--- a/src/codecs/mod.rs
+++ b/src/codecs/mod.rs
@@ -21,6 +21,9 @@ pub mod libgav1;
 #[cfg(feature = "android_mediacodec")]
 pub mod android_mediacodec;
 
+#[cfg(feature = "aom")]
+pub mod aom;
+
 use crate::decoder::CodecChoice;
 use crate::decoder::GridImageHelper;
 use crate::image::Image;
@@ -29,10 +32,15 @@ use crate::AndroidMediaCodecOutputColorFormat;
 use crate::AvifResult;
 use crate::Category;
 
+#[cfg(feature = "encoder")]
+use crate::encoder::*;
+
 use std::num::NonZero;
 
+// Not all fields of this struct are used in all the configurations.
+#[allow(unused)]
 #[derive(Clone, Default)]
-pub struct DecoderConfig {
+pub(crate) struct DecoderConfig {
     pub operating_point: u8,
     pub all_layers: bool,
     pub width: u32,
@@ -46,7 +54,7 @@ pub struct DecoderConfig {
     pub android_mediacodec_output_color_format: AndroidMediaCodecOutputColorFormat,
 }
 
-pub trait Decoder {
+pub(crate) trait Decoder {
     fn codec(&self) -> CodecChoice;
     fn initialize(&mut self, config: &DecoderConfig) -> AvifResult<()>;
     // Decode a single image and write the output into |image|.
@@ -66,3 +74,32 @@ pub trait Decoder {
     ) -> AvifResult<()>;
     // Destruction must be implemented using Drop.
 }
+
+// Not all fields of this struct are used in all the configurations.
+#[allow(unused)]
+#[cfg(feature = "encoder")]
+#[derive(Clone, Copy, Default, PartialEq)]
+pub(crate) struct EncoderConfig {
+    pub tile_rows_log2: i32,
+    pub tile_columns_log2: i32,
+    pub quantizer: i32,
+    pub disable_lagged_output: bool,
+    pub is_single_image: bool,
+    pub speed: Option<u32>,
+    pub extra_layer_count: u32,
+    pub threads: u32,
+    pub scaling_mode: ScalingMode,
+}
+
+#[cfg(feature = "encoder")]
+pub(crate) trait Encoder {
+    fn encode_image(
+        &mut self,
+        image: &Image,
+        category: Category,
+        config: &EncoderConfig,
+        output_samples: &mut Vec<crate::encoder::Sample>,
+    ) -> AvifResult<()>;
+    fn finish(&mut self, output_samples: &mut Vec<crate::encoder::Sample>) -> AvifResult<()>;
+    // Destruction must be implemented using Drop.
+}
diff --git a/src/decoder/gainmap.rs b/src/decoder/gainmap.rs
deleted file mode 100644
index 7a2ece1..0000000
--- a/src/decoder/gainmap.rs
+++ /dev/null
@@ -1,65 +0,0 @@
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
-use crate::decoder::Image;
-use crate::image::YuvRange;
-use crate::utils::*;
-use crate::*;
-
-#[derive(Debug, Default)]
-pub struct GainMapMetadata {
-    pub min: [Fraction; 3],
-    pub max: [Fraction; 3],
-    pub gamma: [UFraction; 3],
-    pub base_offset: [Fraction; 3],
-    pub alternate_offset: [Fraction; 3],
-    pub base_hdr_headroom: UFraction,
-    pub alternate_hdr_headroom: UFraction,
-    pub use_base_color_space: bool,
-}
-
-impl GainMapMetadata {
-    pub(crate) fn is_valid(&self) -> AvifResult<()> {
-        for i in 0..3 {
-            self.min[i].is_valid()?;
-            self.max[i].is_valid()?;
-            self.gamma[i].is_valid()?;
-            self.base_offset[i].is_valid()?;
-            self.alternate_offset[i].is_valid()?;
-            if self.max[i].as_f64()? < self.min[i].as_f64()? || self.gamma[i].0 == 0 {
-                return Err(AvifError::InvalidArgument);
-            }
-        }
-        self.base_hdr_headroom.is_valid()?;
-        self.alternate_hdr_headroom.is_valid()?;
-        Ok(())
-    }
-}
-
-#[derive(Default)]
-pub struct GainMap {
-    pub image: Image,
-    pub metadata: GainMapMetadata,
-
-    pub alt_icc: Vec<u8>,
-    pub alt_color_primaries: ColorPrimaries,
-    pub alt_transfer_characteristics: TransferCharacteristics,
-    pub alt_matrix_coefficients: MatrixCoefficients,
-    pub alt_yuv_range: YuvRange,
-
-    pub alt_plane_count: u8,
-    pub alt_plane_depth: u8,
-
-    pub alt_clli: ContentLightLevelInformation,
-}
diff --git a/src/decoder/item.rs b/src/decoder/item.rs
index 1f187ee..d4668e8 100644
--- a/src/decoder/item.rs
+++ b/src/decoder/item.rs
@@ -112,19 +112,17 @@ impl Item {
     pub(crate) fn read_and_parse(
         &mut self,
         io: &mut GenericIO,
-        grid: &mut Grid,
-        overlay: &mut Overlay,
+        tile_info: &mut TileInfo,
         size_limit: Option<NonZero<u32>>,
         dimension_limit: Option<NonZero<u32>>,
     ) -> AvifResult<()> {
         if self.is_grid_item() {
+            let grid = &mut tile_info.grid;
             let mut stream = self.stream(io)?;
             // unsigned int(8) version = 0;
             let version = stream.read_u8()?;
             if version != 0 {
-                return Err(AvifError::InvalidImageGrid(
-                    "unsupported version for grid".into(),
-                ));
+                return Err(AvifError::NotImplemented);
             }
             // unsigned int(8) flags;
             let flags = stream.read_u8()?;
@@ -155,14 +153,13 @@ impl Item {
                 ));
             }
         } else if self.is_overlay_item() {
+            let overlay = &mut tile_info.overlay;
             let reference_count = self.source_item_ids.len();
             let mut stream = self.stream(io)?;
             // unsigned int(8) version = 0;
             let version = stream.read_u8()?;
             if version != 0 {
-                return Err(AvifError::InvalidImageGrid(format!(
-                    "unsupported version {version} for iovl"
-                )));
+                return Err(AvifError::NotImplemented);
             }
             // unsigned int(8) flags;
             let flags = stream.read_u8()?;
@@ -205,6 +202,12 @@ impl Item {
                     "found unknown extra bytes in the iovl box".into(),
                 ));
             }
+        } else if self.is_tone_mapped_item() {
+            let mut stream = self.stream(io)?;
+            tile_info.gainmap_metadata = mp4box::parse_tmap(&mut stream)?;
+        } else if self.is_sample_transform_item() {
+            let num_inputs = self.source_item_ids.len();
+            tile_info.sample_transform = mp4box::parse_sato(&mut self.stream(io)?, num_inputs)?;
         }
         Ok(())
     }
@@ -270,24 +273,44 @@ impl Item {
             .ok_or(AvifError::BmffParseFailed("missing av1C property".into()))?;
         if self.is_derived_image_item() {
             for derived_item_id in &self.source_item_ids {
-                let derived_item = items.get(derived_item_id).unwrap();
-                let derived_codec_config =
-                    derived_item
+                let source_item = items.get(derived_item_id).unwrap();
+                let source_codec_config =
+                    source_item
                         .codec_config()
                         .ok_or(AvifError::BmffParseFailed(
                             "missing codec config property".into(),
                         ))?;
-                if codec_config != derived_codec_config {
+                // ISO/IEC 23000-22:2019 (MIAF), Section 7.3.11.4.1:
+                // All input image of a grid image item shall use the same coding format, chroma
+                // sampling format, and the same decoder configuration (see 7.3.6.2).
+                // TODO: this is only a requirement for grids, the check for overlays is kept
+                // for now to avoid behavior changes but it should be possible to remove it.
+                if (self.is_grid_item() || self.is_overlay_item())
+                    && codec_config != source_codec_config
+                {
                     return Err(AvifError::BmffParseFailed(
                         "codec config of derived items do not match".into(),
                     ));
                 }
+                if self.is_sample_transform_item()
+                    && (codec_config.pixel_format() != source_codec_config.pixel_format()
+                        || source_item.width != self.width
+                        || source_item.height != self.height)
+                {
+                    return Err(AvifError::BmffParseFailed(
+                            "pixel format or dimensions of input images for sato derived item do not match"
+                                .into(),
+                        ));
+                }
             }
         }
         match self.pixi() {
             Some(pixi) => {
                 for depth in &pixi.plane_depths {
-                    if *depth != codec_config.depth() {
+                    // Check that the depth in pixi matches the codec config.
+                    // For derived image items, the codec config comes from the first source item.
+                    // Sample transform items can have a depth different from their source items.
+                    if *depth != codec_config.depth() && !self.is_sample_transform_item() {
                         return Err(AvifError::BmffParseFailed(
                             "pixi depth does not match codec config depth".into(),
                         ));
@@ -326,6 +349,7 @@ impl Item {
     pub(crate) fn is_auxiliary_alpha(&self) -> bool {
         matches!(find_property!(&self.properties, AuxiliaryType),
                  Some(aux_type) if is_auxiliary_type_alpha(aux_type))
+            && !self.is_sample_transform_item()
     }
 
     pub(crate) fn is_image_codec_item(&self) -> bool {
@@ -345,13 +369,23 @@ impl Item {
         self.item_type == "iovl"
     }
 
+    pub(crate) fn is_tone_mapped_item(&self) -> bool {
+        self.item_type == "tmap"
+    }
+
+    pub(crate) fn is_sample_transform_item(&self) -> bool {
+        cfg!(feature = "sample_transform") && self.item_type == "sato"
+    }
+
     pub(crate) fn is_derived_image_item(&self) -> bool {
-        self.is_grid_item() || self.is_overlay_item() || self.is_tmap()
+        self.is_grid_item()
+            || self.is_overlay_item()
+            || self.is_tone_mapped_item()
+            || self.is_sample_transform_item()
     }
 
     pub(crate) fn is_image_item(&self) -> bool {
-        // Adding || self.is_tmap() here would cause differences with libavif.
-        self.is_image_codec_item() || self.is_grid_item() || self.is_overlay_item()
+        self.is_image_codec_item() || self.is_derived_image_item()
     }
 
     pub(crate) fn should_skip(&self) -> bool {
@@ -381,10 +415,6 @@ impl Item {
         self.is_metadata("mime", color_id) && self.content_type == "application/rdf+xml"
     }
 
-    pub(crate) fn is_tmap(&self) -> bool {
-        self.is_metadata("tmap", None) && self.thumbnail_for_id == 0
-    }
-
     pub(crate) fn max_extent(&self, sample: &DecodeSample) -> AvifResult<Extent> {
         if !self.idat.is_empty() {
             return Ok(Extent::default());
diff --git a/src/decoder/mod.rs b/src/decoder/mod.rs
index 1beb088..7080039 100644
--- a/src/decoder/mod.rs
+++ b/src/decoder/mod.rs
@@ -12,12 +12,12 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-pub mod gainmap;
 pub mod item;
+#[cfg(feature = "sample_transform")]
+pub mod sampletransform;
 pub mod tile;
 pub mod track;
 
-use crate::decoder::gainmap::*;
 use crate::decoder::item::*;
 use crate::decoder::tile::*;
 use crate::decoder::track::*;
@@ -32,6 +32,7 @@ use crate::codecs::libgav1::Libgav1;
 use crate::codecs::android_mediacodec::MediaCodec;
 
 use crate::codecs::DecoderConfig;
+use crate::gainmap::*;
 use crate::image::*;
 use crate::internal_utils::io::*;
 use crate::internal_utils::*;
@@ -64,7 +65,7 @@ impl dyn IO {
 }
 
 pub type GenericIO = Box<dyn IO>;
-pub type Codec = Box<dyn crate::codecs::Decoder>;
+pub(crate) type Codec = Box<dyn crate::codecs::Decoder>;
 
 #[derive(Debug, Default, PartialEq)]
 pub enum CodecChoice {
@@ -136,13 +137,14 @@ pub enum ImageContentType {
 }
 
 impl ImageContentType {
-    pub(crate) fn categories(&self) -> Vec<Category> {
-        match self {
+    pub(crate) fn decoding_items(&self) -> Vec<DecodingItem> {
+        let categories = match self {
             Self::None => vec![],
             Self::ColorAndAlpha => vec![Category::Color, Category::Alpha],
             Self::GainMap => vec![Category::Gainmap],
             Self::All => Category::ALL.to_vec(),
-        }
+        };
+        DecodingItem::all_for_categories(&categories)
     }
 
     pub(crate) fn gainmap(&self) -> bool {
@@ -281,6 +283,68 @@ pub struct IOStats {
     pub alpha_obu_size: usize,
 }
 
+#[derive(Clone, Copy, Debug, PartialEq, Default)]
+pub struct DecodingItem {
+    pub category: Category,
+    // 0 for the main image, 1 to MAX_EXTRA_INPUTS for extra input images.
+    pub item_idx: usize,
+}
+
+impl DecodingItem {
+    const COUNT: usize = 3 + Self::MAX_EXTRA_INPUTS * 2;
+    // Max supported number of inputs for derived image items.
+    const MAX_EXTRA_INPUTS: usize = 3;
+    const ALL: [DecodingItem; Self::COUNT] = [
+        Self::COLOR,
+        Self::color(1),
+        Self::color(2),
+        Self::color(3),
+        Self::ALPHA,
+        Self::alpha(1),
+        Self::alpha(2),
+        Self::alpha(3),
+        Self::GAINMAP,
+    ];
+    const ALL_USIZE: [usize; Self::COUNT] = [0, 1, 2, 3, 4, 5, 6, 7, 8];
+
+    const COLOR: DecodingItem = Self::color(0);
+    const ALPHA: DecodingItem = Self::alpha(0);
+    const GAINMAP: DecodingItem = DecodingItem {
+        category: Category::Gainmap,
+        item_idx: 0,
+    };
+
+    const fn color(item_idx: usize) -> DecodingItem {
+        DecodingItem {
+            category: Category::Color,
+            item_idx,
+        }
+    }
+
+    const fn alpha(item_idx: usize) -> DecodingItem {
+        DecodingItem {
+            category: Category::Alpha,
+            item_idx,
+        }
+    }
+
+    fn all_for_categories(categories: &[Category]) -> Vec<DecodingItem> {
+        Self::ALL
+            .iter()
+            .filter(|x| categories.contains(&x.category))
+            .cloned()
+            .collect()
+    }
+
+    fn usize(self) -> usize {
+        match self.category {
+            Category::Color => self.item_idx,
+            Category::Alpha => 1 + Self::MAX_EXTRA_INPUTS + self.item_idx,
+            Category::Gainmap => (1 + Self::MAX_EXTRA_INPUTS) * 2,
+        }
+    }
+}
+
 #[derive(Default)]
 pub struct Decoder {
     pub settings: Settings,
@@ -294,9 +358,10 @@ pub struct Decoder {
     gainmap: GainMap,
     gainmap_present: bool,
     image: Image,
+    extra_inputs: [Image; DecodingItem::MAX_EXTRA_INPUTS],
     source: Source,
-    tile_info: [TileInfo; Category::COUNT],
-    tiles: [Vec<Tile>; Category::COUNT],
+    tile_info: [TileInfo; DecodingItem::COUNT],
+    tiles: [Vec<Tile>; DecodingItem::COUNT],
     items: Items,
     tracks: Vec<Track>,
     // To replicate the C-API, we need to keep this optional. Otherwise this
@@ -317,11 +382,12 @@ pub enum CompressionFormat {
     Heic = 1,
 }
 
-pub struct GridImageHelper<'a> {
+pub(crate) struct GridImageHelper<'a> {
     grid: &'a Grid,
     image: &'a mut Image,
-    pub(crate) category: Category,
+    pub category: Category,
     cell_index: usize,
+    expected_cell_count: usize,
     codec_config: &'a CodecConfiguration,
     first_cell_image: Option<Image>,
     tile_width: u32,
@@ -332,7 +398,7 @@ pub struct GridImageHelper<'a> {
 #[allow(unused)]
 impl GridImageHelper<'_> {
     pub(crate) fn is_grid_complete(&self) -> AvifResult<bool> {
-        Ok(self.cell_index as u32 == checked_mul!(self.grid.rows, self.grid.columns)?)
+        Ok(self.cell_index == self.expected_cell_count)
     }
 
     pub(crate) fn copy_from_cell_image(&mut self, cell_image: &mut Image) -> AvifResult<()> {
@@ -352,7 +418,9 @@ impl GridImageHelper<'_> {
                     .copy_properties_from(cell_image, self.codec_config);
             }
             self.image.allocate_planes(self.category)?;
-        } else if !cell_image.has_same_properties_and_cicp(self.first_cell_image.unwrap_ref()) {
+        } else if self.first_cell_image.is_some()
+            && !cell_image.has_same_properties_and_cicp(self.first_cell_image.unwrap_ref())
+        {
             return Err(AvifError::InvalidImageGrid(
                 "grid image contains mismatched tiles".into(),
             ));
@@ -486,68 +554,33 @@ impl Decoder {
             is_made_up: true,
             ..Item::default()
         };
-        self.tile_info[Category::Alpha.usize()].grid = self.tile_info[Category::Color.usize()].grid;
+        self.tile_info[DecodingItem::ALPHA.usize()].grid =
+            self.tile_info[DecodingItem::COLOR.usize()].grid;
         self.items.insert(alpha_item_id, alpha_item);
         Ok(Some(alpha_item_id))
     }
 
-    // returns (tone_mapped_image_item_id, gain_map_item_id) if found
-    fn find_tone_mapped_image_item(&self, color_item_id: u32) -> AvifResult<Option<(u32, u32)>> {
-        let tmap_items: Vec<_> = self.items.values().filter(|x| x.is_tmap()).collect();
-        for item in tmap_items {
-            let dimg_items: Vec<_> = self
-                .items
-                .values()
-                .filter(|x| x.dimg_for_id == item.id)
-                .collect();
-            if dimg_items.len() != 2 {
-                return Err(AvifError::InvalidToneMappedImage(
-                    "Expected tmap to have 2 dimg items".into(),
-                ));
-            }
-            let item0 = if dimg_items[0].dimg_index == 0 { dimg_items[0] } else { dimg_items[1] };
-            if item0.id != color_item_id {
-                continue;
-            }
-            let item1 = if dimg_items[0].dimg_index == 0 { dimg_items[1] } else { dimg_items[0] };
-            return Ok(Some((item.id, item1.id)));
-        }
-        Ok(None)
-    }
-
-    // returns (tone_mapped_image_item_id, gain_map_item_id) if found
-    fn find_gainmap_item(&self, color_item_id: u32) -> AvifResult<Option<(u32, u32)>> {
-        if let Some((tonemap_id, gainmap_id)) = self.find_tone_mapped_image_item(color_item_id)? {
-            let gainmap_item = self
-                .items
-                .get(&gainmap_id)
-                .ok_or(AvifError::InvalidToneMappedImage("".into()))?;
-            if gainmap_item.should_skip() {
-                return Err(AvifError::InvalidToneMappedImage("".into()));
-            }
-            Ok(Some((tonemap_id, gainmap_id)))
-        } else {
-            Ok(None)
-        }
-    }
-
-    fn validate_gainmap_item(&mut self, gainmap_id: u32, tonemap_id: u32) -> AvifResult<()> {
+    fn harvest_and_validate_gainmap_properties(
+        &mut self,
+        gainmap_id: u32,
+        tonemap_id: u32,
+        #[allow(unused)] color_item_id: u32, // This parameter is unused in some configurations.
+    ) -> AvifResult<()> {
         let gainmap_item = self
             .items
             .get(&gainmap_id)
             .ok_or(AvifError::InvalidToneMappedImage("".into()))?;
-        // Find and adopt all colr boxes "at most one for a given value of colour type"
-        // (HEIF 6.5.5.1, from Amendment 3). Accept one of each type, and bail out if more than one
-        // of a given type is provided.
+        // ISO/IEC 23008-12:2024/AMD 1:2024(E) (HEIF), Section 6.6.2.4.1:
+        // The gain map input image shall be associated with a 'colr' item property of type 'nclx'
+        // which indicates any transformations that the encoder has done to improve compression.
+        // In this item property, colour_primaries and transfer_characteristics shall be set to 2.
         if let Some(nclx) = find_nclx(&gainmap_item.properties)? {
             self.gainmap.image.color_primaries = nclx.color_primaries;
             self.gainmap.image.transfer_characteristics = nclx.transfer_characteristics;
             self.gainmap.image.matrix_coefficients = nclx.matrix_coefficients;
             self.gainmap.image.yuv_range = nclx.yuv_range;
         }
-        if tonemap_id == 0 {
-            return Ok(());
-        }
+
         // Find and adopt all colr boxes "at most one for a given value of colour type"
         // (HEIF 6.5.5.1, from Amendment 3). Accept one of each type, and bail out if more than one
         // of a given type is provided.
@@ -564,6 +597,7 @@ impl Decoder {
         if let Some(icc) = find_icc(&tonemap_item.properties)? {
             self.gainmap.alt_icc.clone_from(icc);
         }
+
         if let Some(clli) = tonemap_item.clli() {
             self.gainmap.alt_clli = *clli;
         }
@@ -571,15 +605,34 @@ impl Decoder {
             self.gainmap.alt_plane_count = pixi.plane_depths.len() as u8;
             self.gainmap.alt_plane_depth = pixi.plane_depths[0];
         }
-        // HEIC files created by Apple have some of these properties set in the Tonemap item. So do
-        // not perform this validation when HEIC is enabled.
+        // HEIC files created by Apple do not conform to these validation rules so skip them when
+        // HEIC is enabled.
         #[cfg(not(feature = "heic"))]
-        if find_property!(tonemap_item.properties, PixelAspectRatio).is_some()
-            || find_property!(tonemap_item.properties, CleanAperture).is_some()
-            || find_property!(tonemap_item.properties, ImageRotation).is_some()
-            || find_property!(tonemap_item.properties, ImageMirror).is_some()
         {
-            return Err(AvifError::InvalidToneMappedImage("".into()));
+            if let Some(ispe) = find_property!(tonemap_item.properties, ImageSpatialExtents) {
+                let color_item = self
+                    .items
+                    .get(&color_item_id)
+                    .ok_or(AvifError::InvalidToneMappedImage("".into()))?;
+                if ispe.width != color_item.width || ispe.height != color_item.height {
+                    return Err(AvifError::InvalidToneMappedImage(
+                        "Box[tmap] ispe property width/height does not match base image".into(),
+                    ));
+                }
+            } else {
+                return Err(AvifError::InvalidToneMappedImage(
+                    "Box[tmap] missing mandatory ispe property".into(),
+                ));
+            }
+            // HEIC files created by Apple have some of these properties set in the Tonemap item.
+            // So these checks are skipped when HEIC is enabled.
+            if find_property!(tonemap_item.properties, PixelAspectRatio).is_some()
+                || find_property!(tonemap_item.properties, CleanAperture).is_some()
+                || find_property!(tonemap_item.properties, ImageRotation).is_some()
+                || find_property!(tonemap_item.properties, ImageMirror).is_some()
+            {
+                return Err(AvifError::InvalidToneMappedImage("".into()));
+            }
         }
         Ok(())
     }
@@ -611,12 +664,19 @@ impl Decoder {
         Ok(())
     }
 
-    fn generate_tiles(&mut self, item_id: u32, category: Category) -> AvifResult<Vec<Tile>> {
-        let mut tiles: Vec<Tile> = Vec::new();
+    fn generate_tiles(
+        &mut self,
+        item_id: u32,
+        decoding_item: DecodingItem,
+    ) -> AvifResult<Vec<Tile>> {
         let item = self
             .items
             .get(&item_id)
             .ok_or(AvifError::MissingImageItem)?;
+        let mut tiles: Vec<Tile> = Vec::new();
+        if item.is_sample_transform_item() {
+            return Ok(tiles);
+        }
         if item.source_item_ids.is_empty() {
             if item.size == 0 {
                 return Err(AvifError::MissingImageItem);
@@ -627,10 +687,10 @@ impl Decoder {
                 self.settings.image_count_limit,
                 self.io.unwrap_ref().size_hint(),
             )?;
-            tile.input.category = category;
+            tile.input.decoding_item = decoding_item;
             tiles.push(tile);
         } else {
-            if !self.tile_info[category.usize()].is_derived_image() {
+            if !self.tile_info[decoding_item.usize()].is_derived_image() {
                 return Err(AvifError::InvalidImageGrid(
                     "dimg items were found but image is not a derived image.".into(),
                 ));
@@ -647,23 +707,23 @@ impl Decoder {
                     self.settings.image_count_limit,
                     self.io.unwrap_ref().size_hint(),
                 )?;
-                tile.input.category = category;
+                tile.input.decoding_item = decoding_item;
                 tiles.push(tile);
                 progressive = progressive && derived_item.progressive;
             }
 
-            if category == Category::Color && progressive {
+            if decoding_item == DecodingItem::COLOR && progressive {
                 // Propagate the progressive status to the top-level item.
                 self.items.get_mut(&item_id).unwrap().progressive = true;
             }
         }
-        self.tile_info[category.usize()].tile_count = u32_from_usize(tiles.len())?;
+        self.tile_info[decoding_item.usize()].tile_count = u32_from_usize(tiles.len())?;
         Ok(tiles)
     }
 
     fn harvest_cicp_from_sequence_header(&mut self) -> AvifResult<()> {
-        let category = Category::Color;
-        if self.tiles[category.usize()].is_empty() {
+        let decoding_item = DecodingItem::COLOR;
+        if self.tiles[decoding_item.usize()].is_empty() {
             return Ok(());
         }
         let mut search_size = 64;
@@ -671,12 +731,12 @@ impl Decoder {
             let tile_index = 0;
             self.prepare_sample(
                 /*image_index=*/ 0,
-                category,
+                decoding_item,
                 tile_index,
                 Some(search_size),
             )?;
             let io = &mut self.io.unwrap_mut();
-            let sample = &self.tiles[category.usize()][tile_index].input.samples[0];
+            let sample = &self.tiles[decoding_item.usize()][tile_index].input.samples[0];
             let item_data_buffer = if sample.item_id == 0 {
                 &None
             } else {
@@ -708,6 +768,7 @@ impl Decoder {
         let mut source_item_ids: Vec<u32> = vec![];
         let mut first_codec_config: Option<CodecConfiguration> = None;
         let mut first_icc: Option<Vec<u8>> = None;
+        let mut first_nclx: Option<Nclx> = None;
         // Collect all the dimg items.
         for dimg_item_id in self.items.keys() {
             if *dimg_item_id == item_id {
@@ -720,79 +781,166 @@ impl Decoder {
             if dimg_item.dimg_for_id != item_id {
                 continue;
             }
-            if !dimg_item.is_image_codec_item() || dimg_item.has_unsupported_essential_property {
-                return Err(AvifError::InvalidImageGrid(
-                    "invalid input item in dimg".into(),
-                ));
-            }
-            if first_codec_config.is_none() {
-                // Adopt the configuration property of the first tile.
-                // validate_properties() makes sure they are all equal.
-                first_codec_config = Some(
-                    dimg_item
-                        .codec_config()
-                        .ok_or(AvifError::BmffParseFailed(
-                            "missing codec config property".into(),
-                        ))?
-                        .clone(),
-                );
+            if dimg_item.should_skip() {
+                return Err(AvifError::NotImplemented);
             }
-            if dimg_item.is_image_codec_item() && first_icc.is_none() {
-                first_icc = find_icc(&dimg_item.properties)?.cloned();
+            if dimg_item.is_image_codec_item() {
+                if first_codec_config.is_none() {
+                    first_codec_config = Some(
+                        dimg_item
+                            .codec_config()
+                            .ok_or(AvifError::BmffParseFailed(
+                                "missing codec config property".into(),
+                            ))?
+                            .clone(),
+                    );
+                }
+                if first_icc.is_none() {
+                    first_icc = find_icc(&dimg_item.properties)?.cloned();
+                }
+                if first_nclx.is_none() {
+                    first_nclx = find_nclx(&dimg_item.properties)?.cloned();
+                }
             }
             source_item_ids.push(*dimg_item_id);
         }
-        if first_codec_config.is_none() {
-            // No derived images were found.
+        if source_item_ids.is_empty() {
             return Ok(());
         }
         // The order of derived item ids matters: sort them by dimg_index, which is the order that
         // items appear in the 'iref' box.
         source_item_ids.sort_by_key(|k| self.items.get(k).unwrap().dimg_index);
         let item = self.items.get_mut(&item_id).unwrap();
-        item.properties.push(ItemProperty::CodecConfiguration(
-            first_codec_config.unwrap(),
-        ));
-        if (item.is_grid_item() || item.is_overlay_item())
-            && first_icc.is_some()
-            && find_icc(&item.properties)?.is_none()
-        {
-            // For grid and overlay items, adopt the icc color profile of the first tile if it is
-            // not explicitly specified for the overall grid.
+        item.source_item_ids = source_item_ids;
+        if let Some(first_codec_config) = first_codec_config {
+            // Adopt the configuration property of the first tile.
+            // validate_properties() later makes sure they are all equal.
             item.properties
-                .push(ItemProperty::ColorInformation(ColorInformation::Icc(
-                    first_icc.unwrap().clone(),
-                )));
+                .push(ItemProperty::CodecConfiguration(first_codec_config));
+        }
+        if item.is_grid_item() || item.is_overlay_item() {
+            // For grid and overlay items, adopt the icc color profile and the nclx of the first
+            // tile if it is not explicitly specified for the overall grid.
+            if first_icc.is_some() && find_icc(&item.properties)?.is_none() {
+                item.properties
+                    .push(ItemProperty::ColorInformation(ColorInformation::Icc(
+                        first_icc.unwrap(),
+                    )));
+            }
+            if first_nclx.is_some() && find_nclx(&item.properties)?.is_none() {
+                item.properties
+                    .push(ItemProperty::ColorInformation(ColorInformation::Nclx(
+                        first_nclx.unwrap(),
+                    )));
+            }
         }
-        item.source_item_ids = source_item_ids;
         Ok(())
     }
 
-    fn validate_source_item_counts(&self, item_id: u32, tile_info: &TileInfo) -> AvifResult<()> {
+    fn validate_source_items(&self, item_id: u32, tile_info: &TileInfo) -> AvifResult<()> {
         let item = self.items.get(&item_id).unwrap();
+        let source_items: Vec<_> = item
+            .source_item_ids
+            .iter()
+            .map(|id| self.items.get(id).unwrap())
+            .collect();
         if item.is_grid_item() {
             let tile_count = tile_info.grid_tile_count()? as usize;
-            if item.source_item_ids.len() != tile_count {
+            if source_items.len() != tile_count {
                 return Err(AvifError::InvalidImageGrid(
-                    "Expected number of tiles not found".into(),
+                    "expected number of tiles not found".into(),
                 ));
             }
-        } else if item.is_overlay_item() && item.source_item_ids.is_empty() {
-            return Err(AvifError::BmffParseFailed(
-                "No dimg items found for iovl".into(),
-            ));
-        } else if item.is_tmap() && item.source_item_ids.len() != 2 {
-            return Err(AvifError::InvalidToneMappedImage(
-                "Expected tmap to have 2 dimg items".into(),
-            ));
+            if !source_items.iter().all(|item| item.is_image_codec_item()) {
+                return Err(AvifError::InvalidImageGrid("invalid grid items".into()));
+            }
+        } else if item.is_overlay_item() {
+            if source_items.is_empty() {
+                return Err(AvifError::BmffParseFailed(
+                    "no dimg items found for iovl".into(),
+                ));
+            }
+            // MIAF allows overlays of grid but we don't support them.
+            // See ISO/IEC 23000-12:2025, section 7.3.11.1.
+            if source_items.iter().any(|item| item.is_grid_item()) {
+                return Err(AvifError::NotImplemented);
+            }
+            if !source_items.iter().all(|item| item.is_image_codec_item()) {
+                return Err(AvifError::InvalidImageGrid("invalid overlay items".into()));
+            }
+        } else if item.is_tone_mapped_item() {
+            if source_items.len() != 2 {
+                return Err(AvifError::InvalidToneMappedImage(
+                    "expected tmap to have 2 dimg items".into(),
+                ));
+            }
+            if !source_items
+                .iter()
+                .all(|item| item.is_image_codec_item() || item.is_grid_item())
+            {
+                return Err(AvifError::InvalidImageGrid("invalid tmap items".into()));
+            }
+        } else if item.is_sample_transform_item() {
+            if source_items.len() > 32 {
+                return Err(AvifError::InvalidImageGrid(
+                    "expected sato to between 0 and 32 dimg items".into(),
+                ));
+            }
+            if source_items.len() > DecodingItem::MAX_EXTRA_INPUTS {
+                return Err(AvifError::NotImplemented);
+            }
+            if !source_items
+                .iter()
+                .all(|item| item.is_image_codec_item() || item.is_grid_item())
+            {
+                return Err(AvifError::InvalidImageGrid("invalid sato items".into()));
+            }
         }
         Ok(())
     }
 
+    // Finds the best item corresponding to the given item_id using the altr group if present
+    // (finds the first supported alternative in the altr group). Parses the item and returns its
+    // id, which may be different from the passed item_id if an altr group was used.
+    fn find_and_parse_item(
+        &mut self,
+        item_id: u32,
+        decoding_item: DecodingItem,
+        ftyp: &FileTypeBox,
+        meta: &MetaBox,
+    ) -> AvifResult<u32> {
+        let altr_group = meta
+            .grpl
+            .iter()
+            .find(|g| g.grouping_type == "altr" && g.entity_ids.contains(&item_id));
+        let item_ids = match altr_group {
+            Some(altr_group) => &altr_group.entity_ids,
+            None => &vec![item_id],
+        };
+        for item_id in item_ids {
+            if let Some(item) = self.items.get(item_id) {
+                if item.should_skip()
+                    || !item.is_image_item()
+                    || (item.is_tone_mapped_item() && !ftyp.has_tmap())
+                {
+                    continue;
+                }
+                match self.read_and_parse_item(*item_id, decoding_item) {
+                    Ok(()) => return Ok(*item_id),
+                    Err(AvifError::NotImplemented) => continue,
+                    Err(err) => return Err(err),
+                }
+            }
+        }
+        Err(AvifError::NoContent)
+    }
+
     fn reset(&mut self) {
         let decoder = Decoder::default();
         // Reset all fields to default except the following: settings, io, source.
+        /* Do not reset 'settings' */
         self.image_count = decoder.image_count;
+        self.image_index = decoder.image_index;
         self.image_timing = decoder.image_timing;
         self.timescale = decoder.timescale;
         self.duration_in_timescales = decoder.duration_in_timescales;
@@ -801,14 +949,17 @@ impl Decoder {
         self.gainmap = decoder.gainmap;
         self.gainmap_present = decoder.gainmap_present;
         self.image = decoder.image;
+        self.extra_inputs = decoder.extra_inputs;
+        /* Do not reset 'source' */
         self.tile_info = decoder.tile_info;
         self.tiles = decoder.tiles;
-        self.image_index = decoder.image_index;
         self.items = decoder.items;
         self.tracks = decoder.tracks;
+        /* Do not reset 'io' */
         self.codecs = decoder.codecs;
         self.color_track_id = decoder.color_track_id;
         self.parse_state = decoder.parse_state;
+        self.io_stats = decoder.io_stats;
         self.compression_format = decoder.compression_format;
     }
 
@@ -873,6 +1024,7 @@ impl Decoder {
 
             let color_properties: &Vec<ItemProperty>;
             let gainmap_properties: Option<&Vec<ItemProperty>>;
+            let mut is_sample_transform = false;
             if self.source == Source::Tracks {
                 let color_track = self
                     .tracks
@@ -895,33 +1047,35 @@ impl Decoder {
                     .ok_or(AvifError::BmffParseFailed("".into()))?;
                 gainmap_properties = None;
 
-                self.tiles[Category::Color.usize()].push(Tile::create_from_track(
+                self.tiles[DecodingItem::COLOR.usize()].push(Tile::create_from_track(
                     color_track,
                     self.settings.image_count_limit,
                     self.io.unwrap_ref().size_hint(),
-                    Category::Color,
+                    DecodingItem::COLOR,
                 )?);
-                self.tile_info[Category::Color.usize()].tile_count = 1;
+                self.tile_info[DecodingItem::COLOR.usize()].tile_count = 1;
 
                 if let Some(alpha_track) = self
                     .tracks
                     .iter()
                     .find(|x| x.is_aux(color_track.id) && x.is_auxiliary_alpha())
                 {
-                    self.tiles[Category::Alpha.usize()].push(Tile::create_from_track(
+                    self.tiles[DecodingItem::ALPHA.usize()].push(Tile::create_from_track(
                         alpha_track,
                         self.settings.image_count_limit,
                         self.io.unwrap_ref().size_hint(),
-                        Category::Alpha,
+                        DecodingItem::ALPHA,
                     )?);
-                    self.tile_info[Category::Alpha.usize()].tile_count = 1;
+                    self.tile_info[DecodingItem::ALPHA.usize()].tile_count = 1;
                     self.image.alpha_present = true;
                     self.image.alpha_premultiplied = color_track.prem_by_id == Some(alpha_track.id);
                 }
 
                 self.image_index = -1;
-                self.image_count =
-                    self.tiles[Category::Color.usize()][0].input.samples.len() as u32;
+                self.image_count = self.tiles[DecodingItem::COLOR.usize()][0]
+                    .input
+                    .samples
+                    .len() as u32;
                 self.timescale = color_track.media_timescale as u64;
                 self.duration_in_timescales = color_track.media_duration;
                 if self.timescale != 0 {
@@ -936,26 +1090,93 @@ impl Decoder {
                 self.image.height = color_track.height;
             } else {
                 assert_eq!(self.source, Source::PrimaryItem);
-                let mut item_ids: [u32; Category::COUNT] = [0; Category::COUNT];
+                let mut item_ids: [u32; DecodingItem::COUNT] = [0; DecodingItem::COUNT];
 
                 // Mandatory color item (primary item).
-                let color_item_id = self
-                    .items
-                    .iter()
-                    .find(|x| {
-                        !x.1.should_skip()
-                            && x.1.id != 0
-                            && x.1.id == avif_boxes.meta.primary_item_id
-                    })
-                    .map(|it| *it.0);
+                let primary_item_id = self.find_and_parse_item(
+                    avif_boxes.meta.primary_item_id,
+                    DecodingItem::COLOR,
+                    &avif_boxes.ftyp,
+                    &avif_boxes.meta,
+                )?;
+                item_ids[DecodingItem::COLOR.usize()] = primary_item_id;
+
+                let primary_item = self.items.get(&primary_item_id).unwrap();
+                if primary_item.is_tone_mapped_item() {
+                    // validate_source_items() guarantees that tmap has two source item ids.
+                    let base_item_id = primary_item.source_item_ids[0];
+                    let gainmap_id = primary_item.source_item_ids[1];
+
+                    // Set the color item it to the base image and reparse it.
+                    item_ids[DecodingItem::COLOR.usize()] = base_item_id;
+                    self.read_and_parse_item(base_item_id, DecodingItem::COLOR)?;
+
+                    // Parse the gainmap, making sure it's valid.
+                    self.read_and_parse_item(gainmap_id, DecodingItem::GAINMAP)?;
+
+                    self.harvest_and_validate_gainmap_properties(
+                        gainmap_id,
+                        /*tonemap_id=*/ primary_item_id,
+                        item_ids[DecodingItem::COLOR.usize()],
+                    )?;
+                    self.gainmap.metadata = self.tile_info[DecodingItem::COLOR.usize()]
+                        .gainmap_metadata
+                        .clone();
+                    self.gainmap_present = true;
 
-                item_ids[Category::Color.usize()] = color_item_id.ok_or(AvifError::NoContent)?;
-                self.read_and_parse_item(item_ids[Category::Color.usize()], Category::Color)?;
+                    if self.settings.image_content_to_decode.gainmap() {
+                        item_ids[DecodingItem::GAINMAP.usize()] = gainmap_id;
+                    }
+                }
+
+                let mut alpha_present = false;
+                let mut alpha_premultiplied = false;
+
+                let primary_item = self.items.get(&primary_item_id).unwrap();
+                if primary_item.is_sample_transform_item() {
+                    let source_item_ids = primary_item.source_item_ids.clone();
+                    for (idx, item_id) in source_item_ids.iter().enumerate() {
+                        let decoding_item = DecodingItem::color(idx + 1);
+                        item_ids[decoding_item.usize()] = *item_id;
+                        self.read_and_parse_item(*item_id, decoding_item)?;
+                        // Optional alpha auxiliary item
+                        if let Some(alpha_item_id) = self.find_alpha_item(*item_id)? {
+                            let alpha_decoding_item = DecodingItem::alpha(idx + 1);
+                            if !self.items.get(&alpha_item_id).unwrap().is_made_up {
+                                self.read_and_parse_item(alpha_item_id, alpha_decoding_item)?;
+                            }
+                            item_ids[alpha_decoding_item.usize()] = alpha_item_id;
+                            let is_premultiplied =
+                                self.items.get(item_id).unwrap().prem_by_id == alpha_item_id;
+                            if idx > 0 && !alpha_present {
+                                return Err(AvifError::InvalidImageGrid("input images for sato derived image item must either all have alpha or all not have alpha".into()));
+                            }
+                            if alpha_present && alpha_premultiplied != is_premultiplied {
+                                return Err(AvifError::InvalidImageGrid("alpha for sato input images must all have the same premultiplication".into()));
+                            }
+                            alpha_present = true;
+                            alpha_premultiplied = is_premultiplied;
+                        } else if alpha_present {
+                            return Err(AvifError::InvalidImageGrid("input images for sato derived image item must either all have alpha or all not have alpha".into()));
+                        }
+                        let item = self.items.get(item_id).unwrap();
+                        self.extra_inputs[idx].width = item.width;
+                        self.extra_inputs[idx].height = item.height;
+                        let codec_config = item
+                            .codec_config()
+                            .ok_or(AvifError::BmffParseFailed("".into()))?;
+                        self.extra_inputs[idx].depth = codec_config.depth();
+                        self.extra_inputs[idx].yuv_format = codec_config.pixel_format();
+                        self.extra_inputs[idx].chroma_sample_position =
+                            codec_config.chroma_sample_position();
+                    }
+                    is_sample_transform = true;
+                }
 
                 // Find exif/xmp from meta if any.
                 Self::search_exif_or_xmp_metadata(
                     &mut self.items,
-                    Some(item_ids[Category::Color.usize()]),
+                    Some(item_ids[DecodingItem::COLOR.usize()]),
                     &self.settings,
                     self.io.unwrap_mut(),
                     &mut self.image,
@@ -963,34 +1184,19 @@ impl Decoder {
 
                 // Optional alpha auxiliary item
                 if let Some(alpha_item_id) =
-                    self.find_alpha_item(item_ids[Category::Color.usize()])?
+                    self.find_alpha_item(item_ids[DecodingItem::COLOR.usize()])?
                 {
                     if !self.items.get(&alpha_item_id).unwrap().is_made_up {
-                        self.read_and_parse_item(alpha_item_id, Category::Alpha)?;
-                    }
-                    item_ids[Category::Alpha.usize()] = alpha_item_id;
-                }
-
-                // Optional gainmap item
-                if avif_boxes.ftyp.has_tmap() {
-                    if let Some((tonemap_id, gainmap_id)) =
-                        self.find_gainmap_item(item_ids[Category::Color.usize()])?
-                    {
-                        self.validate_gainmap_item(gainmap_id, tonemap_id)?;
-                        self.read_and_parse_item(gainmap_id, Category::Gainmap)?;
-                        let tonemap_item = self
-                            .items
-                            .get_mut(&tonemap_id)
-                            .ok_or(AvifError::InvalidToneMappedImage("".into()))?;
-                        let mut stream = tonemap_item.stream(self.io.unwrap_mut())?;
-                        if let Some(metadata) = mp4box::parse_tmap(&mut stream)? {
-                            self.gainmap.metadata = metadata;
-                            self.gainmap_present = true;
-                            if self.settings.image_content_to_decode.gainmap() {
-                                item_ids[Category::Gainmap.usize()] = gainmap_id;
-                            }
-                        }
+                        self.read_and_parse_item(alpha_item_id, DecodingItem::ALPHA)?;
                     }
+                    item_ids[DecodingItem::ALPHA.usize()] = alpha_item_id;
+                    alpha_present = true;
+                    alpha_premultiplied = self
+                        .items
+                        .get(&item_ids[DecodingItem::COLOR.usize()])
+                        .unwrap()
+                        .prem_by_id
+                        == alpha_item_id
                 }
 
                 self.image_index = -1;
@@ -1002,19 +1208,21 @@ impl Decoder {
                 self.image_timing.duration = 1.0;
                 self.image_timing.duration_in_timescales = 1;
 
-                for category in Category::ALL {
-                    let item_id = item_ids[category.usize()];
+                for decoding_item in DecodingItem::ALL {
+                    let item_id = item_ids[decoding_item.usize()];
                     if item_id == 0 {
                         continue;
                     }
 
                     let item = self.items.get(&item_id).unwrap();
-                    if category == Category::Alpha && item.width == 0 && item.height == 0 {
+                    if decoding_item == DecodingItem::ALPHA && item.width == 0 && item.height == 0 {
                         // NON-STANDARD: Alpha subimage does not have an ispe property; adopt
                         // width/height from color item.
                         assert!(!self.settings.strictness.alpha_ispe_required());
-                        let color_item =
-                            self.items.get(&item_ids[Category::Color.usize()]).unwrap();
+                        let color_item = self
+                            .items
+                            .get(&item_ids[DecodingItem::COLOR.usize()])
+                            .unwrap();
                         let width = color_item.width;
                         let height = color_item.height;
                         let alpha_item = self.items.get_mut(&item_id).unwrap();
@@ -1024,36 +1232,44 @@ impl Decoder {
                         alpha_item.height = height;
                     }
 
-                    self.tiles[category.usize()] = self.generate_tiles(item_id, category)?;
+                    self.tiles[decoding_item.usize()] =
+                        self.generate_tiles(item_id, decoding_item)?;
                     let item = self.items.get(&item_id).unwrap();
                     // Made up alpha item does not contain the pixi property. So do not try to
                     // validate it.
-                    let pixi_required =
-                        self.settings.strictness.pixi_required() && !item.is_made_up;
+                    // Sample transforms can modify the bit depth of an item so it must be
+                    // explicitly signalled.
+                    let pixi_required = self.settings.strictness.pixi_required()
+                        && !item.is_made_up
+                        || item.is_sample_transform_item();
                     item.validate_properties(&self.items, pixi_required)?;
                 }
 
-                let color_item = self.items.get(&item_ids[Category::Color.usize()]).unwrap();
+                let color_item = self
+                    .items
+                    .get(&item_ids[DecodingItem::COLOR.usize()])
+                    .unwrap();
                 self.image.width = color_item.width;
                 self.image.height = color_item.height;
-                let alpha_item_id = item_ids[Category::Alpha.usize()];
-                self.image.alpha_present = alpha_item_id != 0;
-                self.image.alpha_premultiplied =
-                    alpha_item_id != 0 && color_item.prem_by_id == alpha_item_id;
+                self.image.alpha_present = alpha_present;
+                self.image.alpha_premultiplied = alpha_premultiplied;
 
                 if color_item.progressive {
                     self.image.progressive_state = ProgressiveState::Available;
-                    let sample_count = self.tiles[Category::Color.usize()][0].input.samples.len();
+                    let sample_count = self.tiles[DecodingItem::COLOR.usize()][0]
+                        .input
+                        .samples
+                        .len();
                     if sample_count > 1 {
                         self.image.progressive_state = ProgressiveState::Active;
                         self.image_count = sample_count as u32;
                     }
                 }
 
-                if item_ids[Category::Gainmap.usize()] != 0 {
+                if item_ids[DecodingItem::GAINMAP.usize()] != 0 {
                     let gainmap_item = self
                         .items
-                        .get(&item_ids[Category::Gainmap.usize()])
+                        .get(&item_ids[DecodingItem::GAINMAP.usize()])
                         .unwrap();
                     self.gainmap.image.width = gainmap_item.width;
                     self.gainmap.image.height = gainmap_item.height;
@@ -1069,14 +1285,14 @@ impl Decoder {
                 // This borrow has to be in the end of this branch.
                 color_properties = &self
                     .items
-                    .get(&item_ids[Category::Color.usize()])
+                    .get(&item_ids[DecodingItem::COLOR.usize()])
                     .unwrap()
                     .properties;
-                gainmap_properties = if item_ids[Category::Gainmap.usize()] != 0 {
+                gainmap_properties = if item_ids[DecodingItem::GAINMAP.usize()] != 0 {
                     Some(
                         &self
                             .items
-                            .get(&item_ids[Category::Gainmap.usize()])
+                            .get(&item_ids[DecodingItem::GAINMAP.usize()])
                             .unwrap()
                             .properties,
                     )
@@ -1094,14 +1310,19 @@ impl Decoder {
                                 "sample has invalid size.".into(),
                             ));
                         }
-                        match tile.input.category {
-                            Category::Color => {
-                                checked_incr!(self.io_stats.color_obu_size, sample.size)
-                            }
-                            Category::Alpha => {
-                                checked_incr!(self.io_stats.alpha_obu_size, sample.size)
+                        // The item_idx checks is to try to mimic libavif's behavior
+                        // which only takes into account the size of the item whose id
+                        // is in the pitm box.
+                        if tile.input.decoding_item.item_idx <= 1 {
+                            match tile.input.decoding_item.category {
+                                Category::Color => {
+                                    checked_incr!(self.io_stats.color_obu_size, sample.size)
+                                }
+                                Category::Alpha => {
+                                    checked_incr!(self.io_stats.alpha_obu_size, sample.size)
+                                }
+                                _ => {}
                             }
-                            _ => {}
                         }
                     }
                 }
@@ -1144,6 +1365,14 @@ impl Decoder {
             let codec_config = find_property!(color_properties, CodecConfiguration)
                 .ok_or(AvifError::BmffParseFailed("".into()))?;
             self.image.depth = codec_config.depth();
+            // A sample transform item can have a depth different from its input images (which is where
+            // the codec config comes from). The depth from the pixi property should be used instead.
+            if is_sample_transform {
+                if let Some(pixi) = find_property!(color_properties, PixelInformation) {
+                    self.image.depth = pixi.plane_depths[0];
+                }
+            }
+
             self.image.yuv_format = codec_config.pixel_format();
             self.image.chroma_sample_position = codec_config.chroma_sample_position();
             self.compression_format = if codec_config.is_avif() {
@@ -1166,26 +1395,25 @@ impl Decoder {
         Ok(())
     }
 
-    fn read_and_parse_item(&mut self, item_id: u32, category: Category) -> AvifResult<()> {
+    fn read_and_parse_item(&mut self, item_id: u32, decoding_item: DecodingItem) -> AvifResult<()> {
         if item_id == 0 {
             return Ok(());
         }
         self.populate_source_item_ids(item_id)?;
         self.items.get_mut(&item_id).unwrap().read_and_parse(
             self.io.unwrap_mut(),
-            &mut self.tile_info[category.usize()].grid,
-            &mut self.tile_info[category.usize()].overlay,
+            &mut self.tile_info[decoding_item.usize()],
             self.settings.image_size_limit,
             self.settings.image_dimension_limit,
         )?;
-        self.validate_source_item_counts(item_id, &self.tile_info[category.usize()])
+        self.validate_source_items(item_id, &self.tile_info[decoding_item.usize()])
     }
 
     fn can_use_single_codec(&self) -> AvifResult<bool> {
-        let total_tile_count = checked_add!(
-            checked_add!(self.tiles[0].len(), self.tiles[1].len())?,
-            self.tiles[2].len()
-        )?;
+        let mut total_tile_count: usize = 0;
+        for tiles in &self.tiles {
+            total_tile_count = checked_add!(total_tile_count, tiles.len())?;
+        }
         if total_tile_count == 1 {
             return Ok(true);
         }
@@ -1194,11 +1422,11 @@ impl Decoder {
         }
         let mut image_buffers = 0;
         let mut stolen_image_buffers = 0;
-        for category in Category::ALL_USIZE {
-            if self.tile_info[category].tile_count > 0 {
+        for decoding_item in DecodingItem::ALL_USIZE {
+            if self.tile_info[decoding_item].tile_count > 0 {
                 image_buffers += 1;
             }
-            if self.tile_info[category].tile_count == 1 {
+            if self.tile_info[decoding_item].tile_count == 1 {
                 stolen_image_buffers += 1;
             }
         }
@@ -1218,8 +1446,8 @@ impl Decoder {
         Ok(true)
     }
 
-    fn create_codec(&mut self, category: Category, tile_index: usize) -> AvifResult<()> {
-        let tile = &self.tiles[category.usize()][tile_index];
+    fn create_codec(&mut self, decoding_item: DecodingItem, tile_index: usize) -> AvifResult<()> {
+        let tile = &self.tiles[decoding_item.usize()][tile_index];
         let mut codec: Codec = self
             .settings
             .codec_choice
@@ -1234,7 +1462,7 @@ impl Decoder {
             image_size_limit: self.settings.image_size_limit,
             max_input_size: tile.max_sample_size(),
             codec_config: tile.codec_config.clone(),
-            category,
+            category: decoding_item.category,
             android_mediacodec_output_color_format: self
                 .settings
                 .android_mediacodec_output_color_format,
@@ -1255,18 +1483,18 @@ impl Decoder {
             //  2) If android_mediacodec is true, then we will use at most three codec instances
             //     (one for each category).
             self.codecs = create_vec_exact(3)?;
-            for category in self.settings.image_content_to_decode.categories() {
-                if self.tiles[category.usize()].is_empty() {
+            for decoding_item in self.settings.image_content_to_decode.decoding_items() {
+                if self.tiles[decoding_item.usize()].is_empty() {
                     continue;
                 }
-                self.create_codec(category, 0)?;
-                for tile in &mut self.tiles[category.usize()] {
+                self.create_codec(decoding_item, 0)?;
+                for tile in &mut self.tiles[decoding_item.usize()] {
                     tile.codec_index = self.codecs.len() - 1;
                 }
             }
         } else if self.can_use_single_codec()? {
             self.codecs = create_vec_exact(1)?;
-            self.create_codec(Category::Color, 0)?;
+            self.create_codec(DecodingItem::COLOR, 0)?;
             for tiles in &mut self.tiles {
                 for tile in tiles {
                     tile.codec_index = 0;
@@ -1274,10 +1502,11 @@ impl Decoder {
             }
         } else {
             self.codecs = create_vec_exact(self.tiles.iter().map(|tiles| tiles.len()).sum())?;
-            for category in self.settings.image_content_to_decode.categories() {
-                for tile_index in 0..self.tiles[category.usize()].len() {
-                    self.create_codec(category, tile_index)?;
-                    self.tiles[category.usize()][tile_index].codec_index = self.codecs.len() - 1;
+            for decoding_item in self.settings.image_content_to_decode.decoding_items() {
+                for tile_index in 0..self.tiles[decoding_item.usize()].len() {
+                    self.create_codec(decoding_item, tile_index)?;
+                    self.tiles[decoding_item.usize()][tile_index].codec_index =
+                        self.codecs.len() - 1;
                 }
             }
         }
@@ -1287,11 +1516,11 @@ impl Decoder {
     fn prepare_sample(
         &mut self,
         image_index: usize,
-        category: Category,
+        decoding_item: DecodingItem,
         tile_index: usize,
         max_num_bytes: Option<usize>, // Bytes read past that size will be ignored.
     ) -> AvifResult<()> {
-        let tile = &mut self.tiles[category.usize()][tile_index];
+        let tile = &mut self.tiles[decoding_item.usize()][tile_index];
         if tile.input.samples.len() <= image_index {
             return Err(AvifError::NoImagesRemaining);
         }
@@ -1306,7 +1535,9 @@ impl Decoder {
             .get_mut(&sample.item_id)
             .ok_or(AvifError::BmffParseFailed("".into()))?;
         if item.extents.len() == 1 {
-            // Item has only one extent. Nothing to prepare.
+            if !item.idat.is_empty() {
+                item.data_buffer = Some(item.idat.clone());
+            }
             return Ok(());
         }
         if let Some(data) = &item.data_buffer {
@@ -1328,8 +1559,16 @@ impl Decoder {
                 checked_decr!(bytes_to_skip, extent.size);
                 continue;
             }
-            let io = self.io.unwrap_mut();
-            data.extend_from_slice(io.read_exact(extent.offset, extent.size)?);
+            if item.idat.is_empty() {
+                let io = self.io.unwrap_mut();
+                data.extend_from_slice(io.read_exact(extent.offset, extent.size)?);
+            } else {
+                let offset = usize_from_u64(extent.offset)?;
+                let end_offset = checked_add!(offset, extent.size)?;
+                let range = offset..end_offset;
+                check_slice_range(item.idat.len(), &range)?;
+                data.extend_from_slice(&item.idat[range]);
+            }
             if max_num_bytes.is_some_and(|max_num_bytes| data.len() >= max_num_bytes) {
                 return Ok(()); // There are enough merged extents to satisfy max_num_bytes.
             }
@@ -1340,9 +1579,15 @@ impl Decoder {
     }
 
     fn prepare_samples(&mut self, image_index: usize) -> AvifResult<()> {
-        for category in self.settings.image_content_to_decode.categories() {
-            for tile_index in 0..self.tiles[category.usize()].len() {
-                self.prepare_sample(image_index, category, tile_index, None)?;
+        for decoding_item in self.settings.image_content_to_decode.decoding_items() {
+            for tile_index in 0..self.tiles[decoding_item.usize()].len() {
+                match (
+                    self.settings.allow_progressive,
+                    self.prepare_sample(image_index, decoding_item, tile_index, None),
+                ) {
+                    (_, Ok(_)) | (true, Err(AvifError::WaitingOnIo)) => continue,
+                    (_, Err(err)) => return Err(err),
+                }
             }
         }
         Ok(())
@@ -1351,15 +1596,17 @@ impl Decoder {
     fn decode_tile(
         &mut self,
         image_index: usize,
-        category: Category,
+        decoding_item: DecodingItem,
         tile_index: usize,
     ) -> AvifResult<()> {
         // Split the tiles array into two mutable arrays so that we can validate the
         // properties of tiles with index > 0 with that of the first tile.
-        let (tiles_slice1, tiles_slice2) = self.tiles[category.usize()].split_at_mut(tile_index);
+        let (tiles_slice1, tiles_slice2) =
+            self.tiles[decoding_item.usize()].split_at_mut(tile_index);
         let tile = &mut tiles_slice2[0];
         let sample = &tile.input.samples[image_index];
         let io = &mut self.io.unwrap_mut();
+        let category = decoding_item.category;
 
         let codec = &mut self.codecs[tile.codec_index];
         let item_data_buffer = if sample.item_id == 0 {
@@ -1367,7 +1614,16 @@ impl Decoder {
         } else {
             &self.items.get(&sample.item_id).unwrap().data_buffer
         };
-        let data = sample.data(io, item_data_buffer)?;
+        let data = match (
+            self.settings.allow_progressive,
+            sample.data(io, item_data_buffer),
+        ) {
+            (_, Ok(data)) => data,
+            (true, Err(AvifError::TruncatedData) | Err(AvifError::NoContent)) => {
+                return Err(AvifError::WaitingOnIo)
+            }
+            (_, Err(err)) => return Err(err),
+        };
         let next_image_result =
             codec.get_next_image(data, sample.spatial_id, &mut tile.image, category);
         if next_image_result.is_err() {
@@ -1378,44 +1634,41 @@ impl Decoder {
             {
                 // When decoding HEIC on Android, if the alpha channel decoding fails, simply
                 // ignore it and return the rest of the image.
-                checked_incr!(self.tile_info[category.usize()].decoded_tile_count, 1);
+                checked_incr!(self.tile_info[decoding_item.usize()].decoded_tile_count, 1);
                 return Ok(());
             } else {
                 return next_image_result;
             }
         }
 
-        checked_incr!(self.tile_info[category.usize()].decoded_tile_count, 1);
+        checked_incr!(self.tile_info[decoding_item.usize()].decoded_tile_count, 1);
 
         if category == Category::Alpha && tile.image.yuv_range == YuvRange::Limited {
             tile.image.alpha_to_full_range()?;
         }
         tile.image.scale(tile.width, tile.height, category)?;
 
-        if self.tile_info[category.usize()].is_grid() {
+        let dst_image = match category {
+            Category::Color | Category::Alpha if (decoding_item.item_idx == 0) => &mut self.image,
+            Category::Color | Category::Alpha => &mut self.extra_inputs[decoding_item.item_idx - 1],
+            Category::Gainmap => &mut self.gainmap.image,
+        };
+
+        if self.tile_info[decoding_item.usize()].is_grid() {
             if tile_index == 0 {
-                let grid = &self.tile_info[category.usize()].grid;
+                let grid = &self.tile_info[decoding_item.usize()].grid;
                 validate_grid_image_dimensions(&tile.image, grid)?;
                 match category {
-                    Category::Color => {
-                        self.image.width = grid.width;
-                        self.image.height = grid.height;
-                        self.image
-                            .copy_properties_from(&tile.image, &tile.codec_config);
-                        self.image.allocate_planes(category)?;
+                    Category::Color | Category::Gainmap => {
+                        dst_image.width = grid.width;
+                        dst_image.height = grid.height;
+                        dst_image.copy_properties_from(&tile.image, &tile.codec_config);
+                        dst_image.allocate_planes(category)?;
                     }
                     Category::Alpha => {
                         // Alpha is always just one plane and the depth has been validated
                         // to be the same as the color planes' depth.
-                        self.image.allocate_planes(category)?;
-                    }
-                    Category::Gainmap => {
-                        self.gainmap.image.width = grid.width;
-                        self.gainmap.image.height = grid.height;
-                        self.gainmap
-                            .image
-                            .copy_properties_from(&tile.image, &tile.codec_config);
-                        self.gainmap.image.allocate_planes(category)?;
+                        dst_image.allocate_planes(category)?;
                     }
                 }
             }
@@ -1428,50 +1681,30 @@ impl Decoder {
                     "grid image contains mismatched tiles".into(),
                 ));
             }
-            match category {
-                Category::Gainmap => self.gainmap.image.copy_from_tile(
-                    &tile.image,
-                    &self.tile_info[category.usize()].grid,
-                    tile_index as u32,
-                    category,
-                )?,
-                _ => {
-                    self.image.copy_from_tile(
-                        &tile.image,
-                        &self.tile_info[category.usize()].grid,
-                        tile_index as u32,
-                        category,
-                    )?;
-                }
-            }
-        } else if self.tile_info[category.usize()].is_overlay() {
+
+            dst_image.copy_from_tile(
+                &tile.image,
+                &self.tile_info[decoding_item.usize()].grid,
+                tile_index as u32,
+                category,
+            )?;
+        } else if self.tile_info[decoding_item.usize()].is_overlay() {
             if tile_index == 0 {
-                let overlay = &self.tile_info[category.usize()].overlay;
+                let overlay = &self.tile_info[decoding_item.usize()].overlay;
                 let canvas_fill_values =
-                    self.image.convert_rgba16_to_yuva(overlay.canvas_fill_value);
+                    dst_image.convert_rgba16_to_yuva(overlay.canvas_fill_value);
                 match category {
-                    Category::Color => {
-                        self.image.width = overlay.width;
-                        self.image.height = overlay.height;
-                        self.image
-                            .copy_properties_from(&tile.image, &tile.codec_config);
-                        self.image
+                    Category::Color | Category::Gainmap => {
+                        dst_image.width = overlay.width;
+                        dst_image.height = overlay.height;
+                        dst_image.copy_properties_from(&tile.image, &tile.codec_config);
+                        dst_image
                             .allocate_planes_with_default_values(category, canvas_fill_values)?;
                     }
                     Category::Alpha => {
                         // Alpha is always just one plane and the depth has been validated
                         // to be the same as the color planes' depth.
-                        self.image
-                            .allocate_planes_with_default_values(category, canvas_fill_values)?;
-                    }
-                    Category::Gainmap => {
-                        self.gainmap.image.width = overlay.width;
-                        self.gainmap.image.height = overlay.height;
-                        self.gainmap
-                            .image
-                            .copy_properties_from(&tile.image, &tile.codec_config);
-                        self.gainmap
-                            .image
+                        dst_image
                             .allocate_planes_with_default_values(category, canvas_fill_values)?;
                     }
                 }
@@ -1493,65 +1726,43 @@ impl Decoder {
                     ));
                 }
             }
-            match category {
-                Category::Gainmap => self.gainmap.image.copy_and_overlay_from_tile(
-                    &tile.image,
-                    &self.tile_info[category.usize()],
-                    tile_index as u32,
-                    category,
-                )?,
-                _ => {
-                    self.image.copy_and_overlay_from_tile(
-                        &tile.image,
-                        &self.tile_info[category.usize()],
-                        tile_index as u32,
-                        category,
-                    )?;
-                }
-            }
+            dst_image.copy_and_overlay_from_tile(
+                &tile.image,
+                &self.tile_info[decoding_item.usize()],
+                tile_index as u32,
+                category,
+            )?;
         } else {
             // Non grid/overlay path, steal or copy planes from the only tile.
             match category {
-                Category::Color => {
-                    self.image.width = tile.image.width;
-                    self.image.height = tile.image.height;
-                    self.image
-                        .copy_properties_from(&tile.image, &tile.codec_config);
-                    self.image
-                        .steal_or_copy_planes_from(&tile.image, category)?;
+                Category::Color | Category::Gainmap => {
+                    dst_image.width = tile.image.width;
+                    dst_image.height = tile.image.height;
+                    dst_image.copy_properties_from(&tile.image, &tile.codec_config);
+                    dst_image.steal_or_copy_planes_from(&tile.image, category)?;
                 }
                 Category::Alpha => {
-                    if !self.image.has_same_properties(&tile.image) {
+                    if !dst_image.has_same_properties(&tile.image) {
                         return Err(AvifError::DecodeAlphaFailed);
                     }
-                    self.image
-                        .steal_or_copy_planes_from(&tile.image, category)?;
-                }
-                Category::Gainmap => {
-                    self.gainmap.image.width = tile.image.width;
-                    self.gainmap.image.height = tile.image.height;
-                    self.gainmap
-                        .image
-                        .copy_properties_from(&tile.image, &tile.codec_config);
-                    self.gainmap
-                        .image
-                        .steal_or_copy_planes_from(&tile.image, category)?;
+                    dst_image.steal_or_copy_planes_from(&tile.image, category)?;
                 }
             }
         }
         Ok(())
     }
 
-    fn decode_grid(&mut self, image_index: usize, category: Category) -> AvifResult<()> {
-        let tile_count = self.tiles[category.usize()].len();
+    fn decode_grid(&mut self, image_index: usize, decoding_item: DecodingItem) -> AvifResult<()> {
+        let tile_count = self.tiles[decoding_item.usize()].len();
         if tile_count == 0 {
             return Ok(());
         }
         let previous_decoded_tile_count =
-            self.tile_info[category.usize()].decoded_tile_count as usize;
+            self.tile_info[decoding_item.usize()].decoded_tile_count as usize;
         let mut payloads = vec![];
+        let mut pending_read = false;
         for tile_index in previous_decoded_tile_count..tile_count {
-            let tile = &self.tiles[category.usize()][tile_index];
+            let tile = &self.tiles[decoding_item.usize()][tile_index];
             let sample = &tile.input.samples[image_index];
             let item_data_buffer = if sample.item_id == 0 {
                 &None
@@ -1559,14 +1770,35 @@ impl Decoder {
                 &self.items.get(&sample.item_id).unwrap().data_buffer
             };
             let io = &mut self.io.unwrap_mut();
-            let data = sample.data(io, item_data_buffer)?;
+            let data = match sample.data(io, item_data_buffer) {
+                Ok(data) => data,
+                Err(AvifError::WaitingOnIo) => {
+                    if self.settings.allow_incremental {
+                        if payloads.is_empty() {
+                            // No cells have been read. Nothing to decode.
+                            return Err(AvifError::WaitingOnIo);
+                        } else {
+                            // One or more cells have been read. Decode them.
+                            pending_read = true;
+                            break;
+                        }
+                    } else {
+                        return Err(AvifError::WaitingOnIo);
+                    }
+                }
+                Err(err) => return Err(err),
+            };
             payloads.push(data.to_vec());
         }
-        let grid = &self.tile_info[category.usize()].grid;
-        if checked_mul!(grid.rows, grid.columns)? != payloads.len() as u32 {
+        let grid = &self.tile_info[decoding_item.usize()].grid;
+        // If we are not doing incremental decode, all the cells must have been read.
+        if !self.settings.allow_incremental
+            && checked_mul!(grid.rows, grid.columns)? != payloads.len() as u32
+        {
             return Err(AvifError::InvalidArgument);
         }
-        let first_tile = &self.tiles[category.usize()][previous_decoded_tile_count];
+        let first_tile = &self.tiles[decoding_item.usize()][previous_decoded_tile_count];
+        let category = decoding_item.category;
         let mut grid_image_helper = GridImageHelper {
             grid,
             image: if category == Category::Gainmap {
@@ -1575,7 +1807,8 @@ impl Decoder {
                 &mut self.image
             },
             category,
-            cell_index: 0,
+            cell_index: previous_decoded_tile_count,
+            expected_cell_count: previous_decoded_tile_count + payloads.len(),
             codec_config: &first_tile.codec_config,
             first_cell_image: None,
             tile_width: first_tile.width,
@@ -1605,32 +1838,53 @@ impl Decoder {
             ));
         }
         checked_incr!(
-            self.tile_info[category.usize()].decoded_tile_count,
+            self.tile_info[decoding_item.usize()].decoded_tile_count,
             u32_from_usize(payloads.len())?
         );
-        Ok(())
+        if pending_read {
+            Err(AvifError::WaitingOnIo)
+        } else {
+            Ok(())
+        }
+    }
+
+    fn apply_sample_transform(&mut self) -> AvifResult<()> {
+        #[cfg(feature = "sample_transform")]
+        return self.tile_info[DecodingItem::COLOR.usize()]
+            .sample_transform
+            .allocate_planes_and_apply(&self.extra_inputs, &mut self.image);
+        #[cfg(not(feature = "sample_transform"))]
+        return Err(AvifError::NotImplemented);
+    }
+
+    fn can_use_decode_grid(&self, decoding_item: DecodingItem) -> bool {
+        let first_tile = &self.tiles[decoding_item.usize()][0];
+        let codec = self.codecs[first_tile.codec_index].codec();
+        // Has to be a grid.
+        self.tile_info[decoding_item.usize()].is_grid()
+            // Has to be one of the supported codecs.
+            && matches!(codec, CodecChoice::MediaCodec | CodecChoice::Dav1d)
+            // All the tiles must use the same codec instance.
+            && self.tiles[decoding_item.usize()][1..]
+                .iter()
+                .all(|x| x.codec_index == first_tile.codec_index)
     }
 
     fn decode_tiles(&mut self, image_index: usize) -> AvifResult<()> {
         let mut decoded_something = false;
-        for category in self.settings.image_content_to_decode.categories() {
-            let tile_count = self.tiles[category.usize()].len();
+        for decoding_item in self.settings.image_content_to_decode.decoding_items() {
+            let tile_count = self.tiles[decoding_item.usize()].len();
             if tile_count == 0 {
                 continue;
             }
-            let first_tile = &self.tiles[category.usize()][0];
-            let codec = self.codecs[first_tile.codec_index].codec();
-            if codec == CodecChoice::MediaCodec
-                && !self.settings.allow_incremental
-                && self.tile_info[category.usize()].is_grid()
-            {
-                self.decode_grid(image_index, category)?;
+            if self.can_use_decode_grid(decoding_item) {
+                self.decode_grid(image_index, decoding_item)?;
                 decoded_something = true;
             } else {
                 let previous_decoded_tile_count =
-                    self.tile_info[category.usize()].decoded_tile_count as usize;
+                    self.tile_info[decoding_item.usize()].decoded_tile_count as usize;
                 for tile_index in previous_decoded_tile_count..tile_count {
-                    self.decode_tile(image_index, category, tile_index)?;
+                    self.decode_tile(image_index, decoding_item, tile_index)?;
                     decoded_something = true;
                 }
             }
@@ -1650,15 +1904,30 @@ impl Decoder {
             return Err(AvifError::NoContent);
         }
         if self.is_current_frame_fully_decoded() {
-            for category in Category::ALL_USIZE {
-                self.tile_info[category].decoded_tile_count = 0;
+            for decoding_item in DecodingItem::ALL_USIZE {
+                self.tile_info[decoding_item].decoded_tile_count = 0;
             }
         }
 
         let next_image_index = checked_add!(self.image_index, 1)?;
         self.create_codecs()?;
-        self.prepare_samples(next_image_index as usize)?;
+        match (
+            self.settings.allow_progressive,
+            self.prepare_samples(next_image_index as usize),
+        ) {
+            (_, Ok(_)) | (true, Err(AvifError::WaitingOnIo)) => {}
+            (_, Err(err)) => return Err(err),
+        }
         self.decode_tiles(next_image_index as usize)?;
+
+        if !self.tile_info[DecodingItem::COLOR.usize()]
+            .sample_transform
+            .tokens
+            .is_empty()
+        {
+            self.apply_sample_transform()?;
+        }
+
         self.image_index = next_image_index;
         self.image_timing = self.nth_image_timing(self.image_index as u32)?;
         Ok(())
@@ -1668,8 +1937,8 @@ impl Decoder {
         if !self.parsing_complete() {
             return false;
         }
-        for category in self.settings.image_content_to_decode.categories() {
-            if !self.tile_info[category.usize()].is_fully_decoded() {
+        for decoding_item in self.settings.image_content_to_decode.decoding_items() {
+            if !self.tile_info[decoding_item.usize()].is_fully_decoded() {
                 return false;
             }
         }
@@ -1754,21 +2023,22 @@ impl Decoder {
     // returned AvifResult::Ok. Returns 0 in all other cases.
     pub fn decoded_row_count(&self) -> u32 {
         let mut min_row_count = self.image.height;
-        for category in Category::ALL_USIZE {
-            if self.tiles[category].is_empty() {
+        for decoding_item in DecodingItem::ALL {
+            let decoding_item_usize = decoding_item.usize();
+            if self.tiles[decoding_item_usize].is_empty() {
                 continue;
             }
-            let first_tile_height = self.tiles[category][0].height;
-            let row_count = if category == Category::Gainmap.usize()
+            let first_tile_height = self.tiles[decoding_item_usize][0].height;
+            let row_count = if decoding_item.category == Category::Gainmap
                 && self.gainmap_present()
                 && self.settings.image_content_to_decode.gainmap()
                 && self.gainmap.image.height != 0
                 && self.gainmap.image.height != self.image.height
             {
-                if self.tile_info[category].is_fully_decoded() {
+                if self.tile_info[decoding_item_usize].is_fully_decoded() {
                     self.image.height
                 } else {
-                    let gainmap_row_count = self.tile_info[category]
+                    let gainmap_row_count = self.tile_info[decoding_item_usize]
                         .decoded_row_count(self.gainmap.image.height, first_tile_height);
                     // row_count fits for sure in 32 bits because heights do.
                     let row_count = (gainmap_row_count as u64 * self.image.height as u64
@@ -1785,7 +2055,8 @@ impl Decoder {
                     row_count
                 }
             } else {
-                self.tile_info[category].decoded_row_count(self.image.height, first_tile_height)
+                self.tile_info[decoding_item_usize]
+                    .decoded_row_count(self.image.height, first_tile_height)
             };
             min_row_count = std::cmp::min(min_row_count, row_count);
         }
@@ -1798,8 +2069,8 @@ impl Decoder {
         }
         let index = index as usize;
         // All the tiles for the requested index must be a keyframe.
-        for category in Category::ALL_USIZE {
-            for tile in &self.tiles[category] {
+        for decoding_item in DecodingItem::ALL_USIZE {
+            for tile in &self.tiles[decoding_item] {
                 if index >= tile.input.samples.len() || !tile.input.samples[index].sync {
                     return false;
                 }
@@ -1830,8 +2101,8 @@ impl Decoder {
         let start_index = self.nearest_keyframe(index) as usize;
         let end_index = index as usize;
         for current_index in start_index..=end_index {
-            for category in Category::ALL_USIZE {
-                for tile in &self.tiles[category] {
+            for decoding_item in DecodingItem::ALL_USIZE {
+                for tile in &self.tiles[decoding_item] {
                     if current_index >= tile.input.samples.len() {
                         return Err(AvifError::NoImagesRemaining);
                     }
@@ -1884,4 +2155,12 @@ mod tests {
         assert_eq!(e1.offset, expected_offset);
         assert_eq!(e1.size, expected_size);
     }
+
+    #[test]
+    fn decoding_item_usize() {
+        assert_eq!(
+            DecodingItem::ALL.map(|c| c.usize()),
+            DecodingItem::ALL_USIZE
+        );
+    }
 }
diff --git a/src/decoder/sampletransform.rs b/src/decoder/sampletransform.rs
new file mode 100644
index 0000000..a9d560f
--- /dev/null
+++ b/src/decoder/sampletransform.rs
@@ -0,0 +1,756 @@
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
+use crate::decoder::*;
+use crate::*;
+
+impl SampleTransformUnaryOp {
+    fn apply(self, value: i64, bounds: (i64, i64)) -> i64 {
+        let v = match self {
+            SampleTransformUnaryOp::Negation => value.saturating_neg(),
+            SampleTransformUnaryOp::Absolute => value.saturating_abs(),
+            SampleTransformUnaryOp::Not => !value,
+            SampleTransformUnaryOp::BSR => {
+                if value <= 0 {
+                    0
+                } else {
+                    value.ilog2() as i64
+                }
+            }
+        };
+        v.clamp(bounds.0, bounds.1)
+    }
+}
+
+impl SampleTransformBinaryOp {
+    fn apply(self, left: i64, right: i64, bounds: (i64, i64)) -> i64 {
+        let v = match self {
+            SampleTransformBinaryOp::Sum => left.saturating_add(right),
+            SampleTransformBinaryOp::Difference => left.saturating_sub(right),
+            SampleTransformBinaryOp::Product => left.saturating_mul(right),
+            SampleTransformBinaryOp::Quotient => {
+                if right == 0 {
+                    left
+                } else {
+                    left.saturating_div(right)
+                }
+            }
+            SampleTransformBinaryOp::And => left & right,
+            SampleTransformBinaryOp::Or => left | right,
+            SampleTransformBinaryOp::Xor => left ^ right,
+            SampleTransformBinaryOp::Pow => {
+                if left == 0 || left == 1 {
+                    left
+                } else if left == -1 {
+                    if right % 2 == 0 {
+                        1
+                    } else {
+                        -1
+                    }
+                } else if right == 0 {
+                    1
+                } else if right == 1 {
+                    left
+                } else if right < 0 {
+                    // L^R is in ]-1:1[ here, so truncating it always gives 0.
+                    0
+                } else {
+                    left.saturating_pow(right.try_into().unwrap_or(u32::MAX))
+                }
+            }
+            SampleTransformBinaryOp::Min => std::cmp::min(left, right),
+            SampleTransformBinaryOp::Max => std::cmp::max(left, right),
+        };
+        v.clamp(bounds.0, bounds.1)
+    }
+}
+
+enum StackItem {
+    Values(Vec<i64>),
+    Constant(i64),
+    ImageItem(usize),
+}
+
+impl SampleTransformToken {
+    fn apply(
+        &self,
+        stack: &mut Vec<StackItem>,
+        extra_inputs: &[Image],
+        plane: Plane,
+        y: u32,
+        width: usize,
+        bounds: (i64, i64),
+    ) -> AvifResult<()> {
+        let result = match self {
+            SampleTransformToken::Constant(c) => StackItem::Constant(*c),
+            SampleTransformToken::ImageItem(item_idx) => StackItem::ImageItem(*item_idx),
+            SampleTransformToken::UnaryOp(op) => {
+                let value = stack.pop().unwrap();
+                match value {
+                    StackItem::Values(values) => {
+                        StackItem::Values(values.iter().map(|v| op.apply(*v, bounds)).collect())
+                    }
+                    StackItem::Constant(c) => StackItem::Constant(op.apply(c, bounds)),
+                    StackItem::ImageItem(item_idx) => {
+                        if extra_inputs[item_idx].depth == 8 {
+                            let row8 = extra_inputs[item_idx].row_exact(plane, y)?;
+                            StackItem::Values(
+                                row8.iter().map(|v| op.apply(*v as i64, bounds)).collect(),
+                            )
+                        } else {
+                            let row16 = extra_inputs[item_idx].row16_exact(plane, y)?;
+                            StackItem::Values(
+                                row16.iter().map(|v| op.apply(*v as i64, bounds)).collect(),
+                            )
+                        }
+                    }
+                }
+            }
+            SampleTransformToken::BinaryOp(op) => {
+                let right = stack.pop().unwrap();
+                let left = stack.pop().unwrap();
+                match (left, right) {
+                    (StackItem::Values(left), StackItem::Values(right)) => StackItem::Values(
+                        left.iter()
+                            .zip(right.iter())
+                            .map(|(l, r)| op.apply(*l, *r, bounds))
+                            .collect(),
+                    ),
+                    (StackItem::Values(left), StackItem::Constant(right)) => StackItem::Values(
+                        left.iter().map(|l| op.apply(*l, right, bounds)).collect(),
+                    ),
+                    (StackItem::Values(left), StackItem::ImageItem(right_idx)) => {
+                        if extra_inputs[right_idx].depth == 8 {
+                            let row8 = extra_inputs[right_idx].row(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(left[i], row8[i] as i64, bounds))
+                                    .collect(),
+                            )
+                        } else {
+                            let row16 = extra_inputs[right_idx].row16(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(left[i], row16[i] as i64, bounds))
+                                    .collect(),
+                            )
+                        }
+                    }
+                    (StackItem::Constant(left), StackItem::Values(right)) => StackItem::Values(
+                        right.iter().map(|r| op.apply(left, *r, bounds)).collect(),
+                    ),
+                    (StackItem::Constant(left), StackItem::Constant(right)) => {
+                        StackItem::Constant(op.apply(left, right, bounds))
+                    }
+                    (StackItem::Constant(left), StackItem::ImageItem(right_idx)) => {
+                        if extra_inputs[right_idx].depth == 8 {
+                            let row8 = extra_inputs[right_idx].row(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(left, row8[i] as i64, bounds))
+                                    .collect(),
+                            )
+                        } else {
+                            let row16 = extra_inputs[right_idx].row16(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(left, row16[i] as i64, bounds))
+                                    .collect(),
+                            )
+                        }
+                    }
+                    (StackItem::ImageItem(left_idx), StackItem::Values(right)) => {
+                        if extra_inputs[left_idx].depth == 8 {
+                            let row8 = extra_inputs[left_idx].row(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(row8[i] as i64, right[i], bounds))
+                                    .collect(),
+                            )
+                        } else {
+                            let row16 = extra_inputs[left_idx].row16(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(row16[i] as i64, right[i], bounds))
+                                    .collect(),
+                            )
+                        }
+                    }
+                    (StackItem::ImageItem(left_idx), StackItem::Constant(right)) => {
+                        if extra_inputs[left_idx].depth == 8 {
+                            let row8 = extra_inputs[left_idx].row(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(row8[i] as i64, right, bounds))
+                                    .collect(),
+                            )
+                        } else {
+                            let row16 = extra_inputs[left_idx].row16(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(row16[i] as i64, right, bounds))
+                                    .collect(),
+                            )
+                        }
+                    }
+                    (StackItem::ImageItem(left_idx), StackItem::ImageItem(right_idx)) => {
+                        if extra_inputs[left_idx].depth == 8 && extra_inputs[right_idx].depth == 8 {
+                            let left8 = extra_inputs[left_idx].row(plane, y)?;
+                            let right8 = extra_inputs[right_idx].row(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(left8[i] as i64, right8[i] as i64, bounds))
+                                    .collect(),
+                            )
+                        } else if extra_inputs[left_idx].depth == 8
+                            && extra_inputs[right_idx].depth > 8
+                        {
+                            let left8 = extra_inputs[left_idx].row(plane, y)?;
+                            let right16 = extra_inputs[right_idx].row16(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(left8[i] as i64, right16[i] as i64, bounds))
+                                    .collect(),
+                            )
+                        } else if extra_inputs[left_idx].depth > 8
+                            && extra_inputs[right_idx].depth == 8
+                        {
+                            let left16 = extra_inputs[left_idx].row16(plane, y)?;
+                            let right8 = extra_inputs[right_idx].row(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(left16[i] as i64, right8[i] as i64, bounds))
+                                    .collect(),
+                            )
+                        } else {
+                            let left16 = extra_inputs[left_idx].row16(plane, y)?;
+                            let right16 = extra_inputs[right_idx].row16(plane, y)?;
+                            StackItem::Values(
+                                (0..width)
+                                    .map(|i| op.apply(left16[i] as i64, right16[i] as i64, bounds))
+                                    .collect(),
+                            )
+                        }
+                    }
+                }
+            }
+        };
+        stack.push(result);
+        Ok(())
+    }
+}
+
+impl SampleTransform {
+    pub(crate) fn apply(&self, extra_inputs: &[Image], output: &mut Image) -> AvifResult<()> {
+        let max_stack_size = self.tokens.len().div_ceil(2);
+        let mut stack: Vec<StackItem> = create_vec_exact(max_stack_size)?;
+
+        // AVIF specification Draft, 8 January 2025, Section 4.2.3.3.:
+        // The result of any computation underflowing or overflowing the intermediate
+        // bit depth is replaced by -^(2num_bits-1) and 2^(num_bits-1)-1, respectively.
+        // Encoder implementations should not create files leading to potential computation
+        // underflow or overflow. Decoder implementations shall check for computation
+        // underflow or overflow and clamp the results accordingly. Computations with
+        // operands of negative values use the two’s-complement representation.
+        let bounds = match self.bit_depth {
+            8 => (i8::MIN as i64, i8::MAX as i64),
+            16 => (i16::MIN as i64, i16::MAX as i64),
+            32 => (i32::MIN as i64, i32::MAX as i64),
+            64 => (i64::MIN, i64::MAX),
+            _ => unreachable!(),
+        };
+
+        let planes: Vec<Plane> =
+            if output.has_alpha() { ALL_PLANES.to_vec() } else { YUV_PLANES.to_vec() };
+
+        for plane in planes {
+            let width = output.width(plane);
+
+            // Process the image row by row.
+            for y in 0..u32_from_usize(output.height(plane))? {
+                for token in &self.tokens {
+                    token.apply(&mut stack, extra_inputs, plane, y, width, bounds)?;
+                }
+
+                assert!(stack.len() == 1);
+                let result: StackItem = stack.pop().unwrap();
+
+                let mut output_min: u16 = 0;
+                let mut output_max: u16 = output.max_channel();
+                if output.yuv_range == YuvRange::Limited && output.depth >= 8 {
+                    output_min = 16u16 << (output.depth - 8);
+                    output_max = 235u16 << (output.depth - 8);
+                }
+                match result {
+                    StackItem::Values(values) => {
+                        if output.depth == 8 {
+                            let output_row8 = output.row_mut(plane, y)?;
+                            for x in 0..width {
+                                let v = values[x].clamp(output_min as i64, output_max as i64);
+                                output_row8[x] = v as u8;
+                            }
+                        } else {
+                            let output_row16 = output.row16_mut(plane, y)?;
+                            for x in 0..width {
+                                let v = values[x].clamp(output_min as i64, output_max as i64);
+                                output_row16[x] = v as u16;
+                            }
+                        }
+                    }
+                    StackItem::Constant(c) => {
+                        if output.depth == 8 {
+                            let output_row8 = output.row_exact_mut(plane, y)?;
+                            let c8 = c.clamp(output_min as i64, output_max as i64) as u8;
+                            for v in output_row8.iter_mut() {
+                                *v = c8;
+                            }
+                        } else {
+                            let output_row16 = output.row16_exact_mut(plane, y)?;
+                            let c16 = c.clamp(output_min as i64, output_max as i64) as u16;
+                            for v in output_row16.iter_mut() {
+                                *v = c16;
+                            }
+                        }
+                    }
+                    StackItem::ImageItem(item_idx) => {
+                        if output.depth == extra_inputs[item_idx].depth {
+                            if output.depth == 8 {
+                                output
+                                    .row_exact_mut(plane, y)?
+                                    .copy_from_slice(extra_inputs[item_idx].row_exact(plane, y)?);
+                            } else {
+                                output
+                                    .row16_exact_mut(plane, y)?
+                                    .copy_from_slice(extra_inputs[item_idx].row16_exact(plane, y)?);
+                            }
+                        } else if output.depth == 8 && extra_inputs[item_idx].depth > 8 {
+                            let input_row16 = extra_inputs[item_idx].row16(plane, y)?;
+                            let output_row8 = output.row_mut(plane, y)?;
+                            for x in 0..width {
+                                output_row8[x] = input_row16[x].clamp(output_min, output_max) as u8;
+                            }
+                        } else if output.depth > 8 && extra_inputs[item_idx].depth == 8 {
+                            let input_row8 = extra_inputs[item_idx].row(plane, y)?;
+                            let output_row16 = output.row16_mut(plane, y)?;
+                            for x in 0..width {
+                                output_row16[x] = input_row8[x] as u16;
+                            }
+                        } else {
+                            // Both are high bit depth.
+                            let input_row16 = extra_inputs[item_idx].row16(plane, y)?;
+                            let output_row16 = output.row16_mut(plane, y)?;
+                            for x in 0..width {
+                                output_row16[x] = input_row16[x].clamp(output_min, output_max);
+                            }
+                        }
+                    }
+                }
+            }
+        }
+
+        Ok(())
+    }
+
+    fn is_valid(&self) -> AvifResult<()> {
+        let mut stack_size: i32 = 0;
+        for token in &self.tokens {
+            match token {
+                SampleTransformToken::Constant(_) => {
+                    stack_size += 1;
+                }
+                SampleTransformToken::ImageItem(item_idx) => {
+                    if *item_idx >= self.num_inputs {
+                        return Err(AvifError::InvalidImageGrid(
+                            "invalid input image item index".into(),
+                        ));
+                    }
+                    stack_size += 1;
+                }
+                SampleTransformToken::UnaryOp(_) => {
+                    if stack_size < 1 {
+                        return Err(AvifError::InvalidImageGrid(
+                            "invalid stack size for unary operator".into(),
+                        ));
+                    }
+                    // Pop one and push one; the stack size doesn't change.
+                }
+                SampleTransformToken::BinaryOp(_) => {
+                    if stack_size < 2 {
+                        return Err(AvifError::InvalidImageGrid(
+                            "invalid stack size for binary operator".into(),
+                        ));
+                    }
+                    stack_size -= 1; // Pop two and push one.
+                }
+            }
+        }
+        if stack_size != 1 {
+            return Err(AvifError::InvalidImageGrid(
+                "invalid stack size at the end of sample transform".into(),
+            ));
+        }
+        Ok(())
+    }
+
+    pub(crate) fn create_from(
+        bit_depth: u8,
+        num_inputs: usize,
+        tokens: Vec<SampleTransformToken>,
+    ) -> AvifResult<Self> {
+        let sample_transform = SampleTransform {
+            bit_depth,
+            num_inputs,
+            tokens,
+        };
+        sample_transform.is_valid()?;
+        Ok(sample_transform)
+    }
+
+    pub(crate) fn allocate_planes_and_apply(
+        &self,
+        extra_inputs: &[Image],
+        output: &mut Image,
+    ) -> AvifResult<()> {
+        output.allocate_planes(Category::Color)?;
+        if self.num_inputs > 0 && extra_inputs[0].has_alpha() {
+            output.allocate_planes(Category::Alpha)?;
+        }
+        self.apply(extra_inputs, output)
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::image::Image;
+    use crate::image::YuvRange;
+    use crate::utils::pixels::*;
+    use test_case::test_case;
+
+    // Constant
+    #[test_case(8, 8, 16, YuvRange::Full, vec![],
+        vec![SampleTransformToken::Constant(42)], 42)]
+    // Limited range
+    #[test_case(8, 8, 8, YuvRange::Limited, vec![],
+        vec![SampleTransformToken::Constant(5)], 16)]
+    // Image
+    #[test_case(8, 8, 8, YuvRange::Limited, vec![1, 42, 3],
+            vec![SampleTransformToken::ImageItem(1)], 42)]
+    // Shift 8 bit image to 16 bit
+    #[test_case(8, 32, 16, YuvRange::Full, vec![42],
+        vec![SampleTransformToken::ImageItem(0),
+        SampleTransformToken::Constant(256),
+        SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Product)], 10752)]
+    // Shift 12 bit image to 8 bit
+    #[test_case(12, 16, 8, YuvRange::Full, vec![3022],
+            vec![SampleTransformToken::ImageItem(0),
+            SampleTransformToken::Constant(16),
+            SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Quotient)], 188)]
+    // Complex expression
+    #[test_case(8, 8, 8, YuvRange::Limited, vec![],
+        vec![
+                SampleTransformToken::Constant(10),
+                SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Negation),
+                SampleTransformToken::Constant(4),
+                SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Product),
+                SampleTransformToken::Constant(2),
+                SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Difference),
+                SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Negation),
+            ], 42)]
+    // Overflow
+    #[test_case(8, 8, 8, YuvRange::Full, vec![],
+        vec![
+                SampleTransformToken::Constant(100),
+                SampleTransformToken::Constant(100),
+                SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Product),
+                SampleTransformToken::Constant(-10),
+                SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Sum),
+            ], 117)]
+    // BinaryOp(Values, Values)
+    #[test_case(8, 8, 8, YuvRange::Full, vec![42, 10],
+                vec![SampleTransformToken::ImageItem(0), SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Absolute),
+                SampleTransformToken::ImageItem(1), SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Absolute),
+                SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Quotient)], 4)]
+    // BinaryOp(Values, Constant)
+    #[test_case(8, 8, 8, YuvRange::Full, vec![42],
+        vec![SampleTransformToken::ImageItem(0), SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Absolute),
+        SampleTransformToken::Constant(5), SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Difference)], 37)]
+    // BinaryOp(Values, Image)
+    #[test_case(8, 8, 8, YuvRange::Full, vec![42, 10],
+        vec![SampleTransformToken::ImageItem(0), SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Absolute),
+        SampleTransformToken::ImageItem(1),
+        SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Quotient)], 4)]
+    // BinaryOp(Constant, Values)
+    #[test_case(8, 8, 8, YuvRange::Full, vec![3],
+        vec![SampleTransformToken::Constant(100), SampleTransformToken::ImageItem(0), SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Absolute),
+        SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Quotient)], 33)]
+    // BinaryOp(Constant, Constant)
+    #[test_case(8, 8, 8, YuvRange::Full, vec![],
+        vec![SampleTransformToken::Constant(100), SampleTransformToken::Constant(200), SampleTransformToken::BinaryOp(SampleTransformBinaryOp::And)], 64)]
+    // BinaryOp(Constant, Image)
+    #[test_case(8, 8, 8, YuvRange::Full, vec![3],
+        vec![SampleTransformToken::Constant(100), SampleTransformToken::ImageItem(0),
+        SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Quotient)], 33)]
+    // BinaryOp(Image, Values)
+    #[test_case(8, 8, 8, YuvRange::Full, vec![42, 10],
+        vec![SampleTransformToken::ImageItem(0),
+        SampleTransformToken::ImageItem(1), SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Absolute),
+        SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Quotient)], 4)]
+    // BinaryOp(Image, Constant)
+    #[test_case(8, 8, 8, YuvRange::Full, vec![100],
+        vec![        SampleTransformToken::ImageItem(0),
+        SampleTransformToken::Constant(3),
+        SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Quotient)], 33)]
+    // BinaryOp(Image, Image)
+    #[test_case(8, 8, 8, YuvRange::Full, vec![42, 10],
+        vec![SampleTransformToken::ImageItem(0), SampleTransformToken::ImageItem(1),
+        SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Quotient)], 4)]
+    fn test_apply_generic(
+        input_depth: u8,
+        intermediate_depth: u8,
+        output_depth: u8,
+        yuv_range: YuvRange,
+        input_image_values: Vec<u16>,
+        tokens: Vec<SampleTransformToken>,
+        expected_value: i32,
+    ) -> AvifResult<()> {
+        let width = 10;
+        let height = 3;
+        let yuv_format = PixelFormat::Yuv420;
+        let num_inputs = input_image_values.len();
+        let sample_transform =
+            SampleTransform::create_from(intermediate_depth, num_inputs, tokens)?;
+        let mut extra_inputs = create_vec_exact(num_inputs)?;
+        for i in 0..num_inputs {
+            extra_inputs.push(Image {
+                width,
+                height,
+                depth: input_depth,
+                yuv_format,
+                yuv_range,
+                ..Default::default()
+            });
+            extra_inputs[i].allocate_planes(Category::Color)?;
+            if input_depth == 8 {
+                extra_inputs[i].row_mut(Plane::Y, 0)?.copy_from_slice(&vec![
+                    input_image_values[i]
+                        as u8;
+                    width as usize
+                ]);
+            } else {
+                extra_inputs[i]
+                    .row16_mut(Plane::Y, 0)?
+                    .copy_from_slice(&vec![input_image_values[i]; width as usize]);
+            }
+        }
+
+        let mut output = Image {
+            width,
+            height,
+            depth: output_depth,
+            yuv_format,
+            yuv_range,
+            ..Default::default()
+        };
+        output.allocate_planes(Category::Color)?;
+
+        sample_transform.apply(&extra_inputs, &mut output)?;
+
+        if output_depth == 8 {
+            assert_eq!(
+                output.row(Plane::Y, 0)?.first(),
+                Some(&(expected_value as u8))
+            );
+        } else {
+            assert_eq!(
+                output.row16(Plane::Y, 0)?.first(),
+                Some(&(expected_value as u16))
+            );
+        }
+
+        Ok(())
+    }
+
+    #[test]
+    fn test_apply_image_item() -> AvifResult<()> {
+        let sample_transform = SampleTransform::create_from(
+            8,
+            2,
+            vec![
+                SampleTransformToken::ImageItem(0),
+                SampleTransformToken::Constant(2),
+                SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Product),
+                SampleTransformToken::ImageItem(1),
+                SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Sum),
+            ],
+        )?;
+        let width = 2;
+        let height = 1;
+        let mut output = Image {
+            width,
+            height,
+            depth: 8,
+            yuv_format: PixelFormat::Yuv444,
+            yuv_range: YuvRange::Full,
+            ..Default::default()
+        };
+        output.allocate_planes(Category::Color)?;
+        output.allocate_planes(Category::Alpha)?;
+        let mut extra_inputs = Vec::new();
+        let mut input_image = Image {
+            width,
+            height,
+            depth: 8,
+            yuv_format: PixelFormat::Yuv444,
+            yuv_range: YuvRange::Full,
+            ..Default::default()
+        };
+        input_image.allocate_planes(Category::Color)?;
+        input_image.allocate_planes(Category::Alpha)?;
+        input_image.row_mut(Plane::Y, 0)?.copy_from_slice(&[10, 20]);
+        input_image.row_mut(Plane::U, 0)?.copy_from_slice(&[30, 40]);
+        input_image.row_mut(Plane::V, 0)?.copy_from_slice(&[50, 60]);
+        input_image.row_mut(Plane::A, 0)?.copy_from_slice(&[1, 80]);
+        extra_inputs.push(input_image);
+        let mut input_image = Image {
+            width,
+            height,
+            depth: 8,
+            yuv_format: PixelFormat::Yuv444,
+            yuv_range: YuvRange::Full,
+            ..Default::default()
+        };
+        input_image.allocate_planes(Category::Color)?;
+        input_image.allocate_planes(Category::Alpha)?;
+        input_image.row_mut(Plane::Y, 0)?.copy_from_slice(&[1, 2]);
+        input_image.row_mut(Plane::U, 0)?.copy_from_slice(&[3, 4]);
+        input_image.row_mut(Plane::V, 0)?.copy_from_slice(&[5, 6]);
+        input_image.row_mut(Plane::A, 0)?.copy_from_slice(&[7, 8]);
+        extra_inputs.push(input_image);
+
+        sample_transform.apply(&extra_inputs, &mut output)?;
+
+        assert_eq!(output.row(Plane::Y, 0), Ok::<&[u8], _>(&[21, 42]));
+        assert_eq!(output.row(Plane::U, 0), Ok::<&[u8], _>(&[63, 84]));
+        assert_eq!(output.row(Plane::V, 0), Ok::<&[u8], _>(&[105, 126]));
+        // Second value capped at 127 because of "bit_depth: 8" in SampleTransform.
+        assert_eq!(output.row(Plane::A, 0), Ok::<&[u8], _>(&[9, 127]));
+        Ok(())
+    }
+
+    #[test_case(8, 8)]
+    #[test_case(8, 10)]
+    #[test_case(8, 16)]
+    #[test_case(10, 8)]
+    #[test_case(10, 10)]
+    #[test_case(10, 16)]
+    #[test_case(16, 8)]
+    #[test_case(16, 10)]
+    #[test_case(16, 16)]
+    fn test_copy_image(input_bit_depth: u8, output_bit_depth: u8) -> AvifResult<()> {
+        let sample_transform =
+            SampleTransform::create_from(32, 1, vec![SampleTransformToken::ImageItem(0)])?;
+        let width = 2;
+        let height = 1;
+        let mut output = Image {
+            width,
+            height,
+            depth: output_bit_depth,
+            yuv_format: PixelFormat::Yuv444,
+            yuv_range: YuvRange::Full,
+            ..Default::default()
+        };
+        output.allocate_planes(Category::Color)?;
+        output.allocate_planes(Category::Alpha)?;
+        let mut extra_inputs = Vec::new();
+        let mut input_image = Image {
+            width,
+            height,
+            depth: input_bit_depth,
+            yuv_format: PixelFormat::Yuv444,
+            yuv_range: YuvRange::Full,
+            ..Default::default()
+        };
+        if input_bit_depth == 8 {
+            input_image.planes[0] = Some(Pixels::Buffer(vec![10, 20, 99]));
+            input_image.planes[1] = Some(Pixels::Buffer(vec![30, 40, 99]));
+            input_image.planes[2] = Some(Pixels::Buffer(vec![50, 60, 99]));
+            input_image.planes[3] = Some(Pixels::Buffer(vec![1, 80, 99]));
+            input_image.row_bytes = [3; 4];
+        } else {
+            input_image.planes[0] = Some(Pixels::Buffer16(vec![10, 20, 99]));
+            input_image.planes[1] = Some(Pixels::Buffer16(vec![30, 40, 99]));
+            input_image.planes[2] = Some(Pixels::Buffer16(vec![50, 60, 99]));
+            input_image.planes[3] = Some(Pixels::Buffer16(vec![1, 80, 99]));
+            input_image.row_bytes = [6; 4];
+        }
+        input_image.image_owns_planes = [false; 4];
+        extra_inputs.push(input_image);
+
+        sample_transform.apply(&extra_inputs, &mut output)?;
+
+        if output_bit_depth == 8 {
+            assert_eq!(output.row(Plane::Y, 0), Ok::<&[u8], _>(&[10, 20]));
+            assert_eq!(output.row(Plane::U, 0), Ok::<&[u8], _>(&[30, 40]));
+            assert_eq!(output.row(Plane::V, 0), Ok::<&[u8], _>(&[50, 60]));
+            assert_eq!(output.row(Plane::A, 0), Ok::<&[u8], _>(&[1, 80]));
+        } else {
+            assert_eq!(output.row16(Plane::Y, 0), Ok::<&[u16], _>(&[10, 20]));
+            assert_eq!(output.row16(Plane::U, 0), Ok::<&[u16], _>(&[30, 40]));
+            assert_eq!(output.row16(Plane::V, 0), Ok::<&[u16], _>(&[50, 60]));
+            assert_eq!(output.row16(Plane::A, 0), Ok::<&[u16], _>(&[1, 80]));
+        }
+        Ok(())
+    }
+
+    #[test]
+    fn test_pow() {
+        let pow = SampleTransformBinaryOp::Pow;
+        let clamp = (0, 255);
+        assert_eq!(pow.apply(-2, i32::MIN as i64, clamp), 0);
+        assert_eq!(pow.apply(-2, -3, clamp), 0);
+        assert_eq!(pow.apply(-2, -2, clamp), 0);
+        assert_eq!(pow.apply(-2, -1, clamp), 0);
+        assert_eq!(pow.apply(-2, 0, clamp), 1);
+        assert_eq!(pow.apply(-2, 1, clamp), 0); // -2 clamped
+        assert_eq!(pow.apply(-2, 2, clamp), 4);
+        assert_eq!(pow.apply(-2, 3, clamp), 0); // -8 clamped
+        assert_eq!(pow.apply(-2, i32::MAX as i64 - 1, clamp), 255); // i32::MAX as i64 clamped
+        assert_eq!(pow.apply(-2, i32::MAX as i64, clamp), 0); // i32::MIN as i64 clamped
+
+        assert_eq!(pow.apply(-1, i32::MIN as i64, clamp), 1);
+        assert_eq!(pow.apply(-1, -3, clamp), 0); // -1 clamped
+        assert_eq!(pow.apply(-1, -2, clamp), 1);
+        assert_eq!(pow.apply(-1, -1, clamp), 0); // -1 clamped
+        assert_eq!(pow.apply(-1, 0, clamp), 1);
+        assert_eq!(pow.apply(-1, 1, clamp), 0); // -1 clamped
+        assert_eq!(pow.apply(-1, 2, clamp), 1);
+        assert_eq!(pow.apply(-1, 3, clamp), 0); // -1 clamped
+        assert_eq!(pow.apply(-1, i32::MAX as i64 - 1, clamp), 1);
+        assert_eq!(pow.apply(-1, i32::MAX as i64, clamp), 0); // -1 clamped
+
+        for v in [0, 1] {
+            assert_eq!(pow.apply(v, i32::MIN as i64, clamp), v);
+            assert_eq!(pow.apply(v, -2, clamp), v);
+            assert_eq!(pow.apply(v, -1, clamp), v);
+            assert_eq!(pow.apply(v, 0, clamp), v);
+            assert_eq!(pow.apply(v, 1, clamp), v);
+            assert_eq!(pow.apply(v, 2, clamp), v);
+            assert_eq!(pow.apply(v, i32::MAX as i64, clamp), v);
+        }
+
+        assert_eq!(pow.apply(-(1 << 16), 3, clamp), 0); // i32::MIN as i64 clamped
+        assert_eq!(pow.apply(1 << 16, 3, clamp), 255); // i32::MAX as i64 clamped
+    }
+}
diff --git a/src/decoder/tile.rs b/src/decoder/tile.rs
index 4dd1776..c01d930 100644
--- a/src/decoder/tile.rs
+++ b/src/decoder/tile.rs
@@ -65,7 +65,7 @@ impl DecodeSample {
 pub struct DecodeInput {
     pub samples: Vec<DecodeSample>,
     pub all_layers: bool,
-    pub category: Category,
+    pub decoding_item: DecodingItem,
 }
 
 #[derive(Debug, Default)]
@@ -77,12 +77,52 @@ pub struct Overlay {
     pub vertical_offsets: Vec<i32>,
 }
 
+#[derive(Clone, Copy, Debug)]
+pub enum SampleTransformUnaryOp {
+    // Unary operators. L is the operand.
+    Negation, // S = -L
+    Absolute, // S = |L|
+    Not,      // S = ~L
+    BSR,      // S = L<=0 ? 0 : truncate(log2(L)) (Bit Scan Reverse)
+}
+
+#[derive(Clone, Copy, Debug)]
+pub enum SampleTransformBinaryOp {
+    Sum,        // S = L + R
+    Difference, // S = L - R
+    Product,    // S = L * R
+    Quotient,   // S = R==0 ? L : truncate(L / R)
+    And,        // S = L & R
+    Or,         // S = L | R
+    Xor,        // S = L ^ R
+    Pow,        // S = L==0 ? 0 : truncate(pow(L, R))
+    Min,        // S = L<=R ? L : R
+    Max,        // S = L<=R ? R : L
+}
+
+#[derive(Debug)]
+pub enum SampleTransformToken {
+    Constant(i64),
+    ImageItem(usize), // item_idx in source items
+    UnaryOp(SampleTransformUnaryOp),
+    BinaryOp(SampleTransformBinaryOp),
+}
+
+#[derive(Debug, Default)]
+pub struct SampleTransform {
+    pub bit_depth: u8,
+    pub num_inputs: usize, // Number of input images.
+    pub tokens: Vec<SampleTransformToken>,
+}
+
 #[derive(Debug, Default)]
 pub(crate) struct TileInfo {
     pub tile_count: u32,
     pub decoded_tile_count: u32,
     pub grid: Grid,
     pub overlay: Overlay,
+    pub gainmap_metadata: GainMapMetadata,
+    pub sample_transform: SampleTransform,
 }
 
 impl TileInfo {
@@ -94,8 +134,12 @@ impl TileInfo {
         !self.overlay.horizontal_offsets.is_empty() && !self.overlay.vertical_offsets.is_empty()
     }
 
+    pub(crate) fn is_sample_transform(&self) -> bool {
+        !self.sample_transform.tokens.is_empty()
+    }
+
     pub(crate) fn is_derived_image(&self) -> bool {
-        self.is_grid() || self.is_overlay()
+        self.is_grid() || self.is_overlay() || self.is_sample_transform()
     }
 
     pub(crate) fn grid_tile_count(&self) -> AvifResult<u32> {
@@ -275,7 +319,7 @@ impl Tile {
         track: &Track,
         image_count_limit: Option<NonZero<u32>>,
         size_hint: u64,
-        category: Category,
+        decoding_item: DecodingItem,
     ) -> AvifResult<Tile> {
         let properties = track
             .get_properties()
@@ -288,7 +332,7 @@ impl Tile {
             height: track.height,
             operating_point: 0, // No way to set operating point via tracks
             input: DecodeInput {
-                category,
+                decoding_item,
                 ..DecodeInput::default()
             },
             codec_config,
diff --git a/src/encoder/item.rs b/src/encoder/item.rs
new file mode 100644
index 0000000..0f584c6
--- /dev/null
+++ b/src/encoder/item.rs
@@ -0,0 +1,651 @@
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
+use crate::encoder::*;
+use crate::internal_utils::stream::*;
+use crate::utils::clap::CleanAperture;
+use crate::*;
+
+#[derive(Default)]
+pub(crate) struct Item {
+    pub id: u16,
+    pub item_type: String,
+    pub category: Category,
+    pub codec: Option<Codec>,
+    pub samples: Vec<Sample>,
+    pub codec_configuration: CodecConfiguration,
+    pub cell_index: usize,
+    pub hidden_image: bool,
+    pub infe_name: String,
+    pub infe_content_type: String,
+    pub mdat_offset_locations: Vec<usize>,
+    pub iref_to_id: Option<u16>, // If some, then make an iref from this id to iref_to_id.
+    pub iref_type: Option<String>,
+    pub grid: Option<Grid>,
+    pub associations: Vec<(
+        u8,   // 1-based property_index
+        bool, // essential
+    )>,
+    pub extra_layer_count: u32,
+    pub dimg_from_id: Option<u16>, // If some, then make an iref from dimg_from_id to this id.
+    pub metadata_payload: Vec<u8>,
+}
+
+impl fmt::Debug for Item {
+    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
+        write!(
+            f,
+            "Item: {{ id: {}, item_type: {}, has_codec: {} }}",
+            self.id,
+            self.item_type,
+            self.codec.is_some()
+        )
+    }
+}
+
+impl Item {
+    pub(crate) fn has_ipma(&self) -> bool {
+        self.grid.is_some() || self.codec.is_some() || self.is_tmap()
+    }
+
+    pub(crate) fn is_metadata(&self) -> bool {
+        self.item_type != "av01"
+    }
+
+    pub(crate) fn is_tmap(&self) -> bool {
+        self.item_type == "tmap"
+    }
+
+    pub(crate) fn write_ispe(
+        &mut self,
+        stream: &mut OStream,
+        image_metadata: &Image,
+    ) -> AvifResult<()> {
+        stream.start_full_box("ispe", (0, 0))?;
+        let width = match self.grid {
+            Some(grid) => grid.width,
+            None => image_metadata.width,
+        };
+        // unsigned int(32) image_width;
+        stream.write_u32(width)?;
+        let height = match self.grid {
+            Some(grid) => grid.height,
+            None => image_metadata.height,
+        };
+        // unsigned int(32) image_height;
+        stream.write_u32(height)?;
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_pixi(
+        &mut self,
+        stream: &mut OStream,
+        image_metadata: &Image,
+    ) -> AvifResult<()> {
+        stream.start_full_box("pixi", (0, 0))?;
+        let num_channels = if self.category == Category::Alpha {
+            1
+        } else {
+            image_metadata.yuv_format.plane_count() as u8
+        };
+        // unsigned int (8) num_channels;
+        stream.write_u8(num_channels)?;
+        for _ in 0..num_channels {
+            // unsigned int (8) bits_per_channel;
+            stream.write_u8(image_metadata.depth)?;
+        }
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_codec_config(&self, stream: &mut OStream) -> AvifResult<()> {
+        if let CodecConfiguration::Av1(config) = &self.codec_configuration {
+            stream.start_box("av1C")?;
+            // unsigned int (1) marker = 1;
+            stream.write_bits(1, 1)?;
+            // unsigned int (7) version = 1;
+            stream.write_bits(1, 7)?;
+            // unsigned int(3) seq_profile;
+            stream.write_bits(config.seq_profile, 3)?;
+            // unsigned int(5) seq_level_idx_0;
+            stream.write_bits(config.seq_level_idx0, 5)?;
+            // unsigned int(1) seq_tier_0;
+            stream.write_bits(config.seq_tier0, 1)?;
+            // unsigned int(1) high_bitdepth;
+            stream.write_bits(config.high_bitdepth as u8, 1)?;
+            // unsigned int(1) twelve_bit;
+            stream.write_bits(config.twelve_bit as u8, 1)?;
+            // unsigned int(1) monochrome;
+            stream.write_bits(config.monochrome as u8, 1)?;
+            // unsigned int(1) chroma_subsampling_x;
+            stream.write_bits(config.chroma_subsampling_x, 1)?;
+            // unsigned int(1) chroma_subsampling_y;
+            stream.write_bits(config.chroma_subsampling_y, 1)?;
+            // unsigned int(2) chroma_sample_position;
+            stream.write_bits(config.chroma_sample_position as u8, 2)?;
+            // unsigned int (3) reserved = 0;
+            // unsigned int (1) initial_presentation_delay_present;
+            // unsigned int (4) reserved = 0;
+            stream.write_u8(0)?;
+            stream.finish_box()?;
+        }
+        Ok(())
+    }
+
+    #[allow(non_snake_case)]
+    pub(crate) fn write_auxC(&mut self, stream: &mut OStream) -> AvifResult<()> {
+        stream.start_full_box("auxC", (0, 0))?;
+        stream
+            .write_string_with_nul(&String::from("urn:mpeg:mpegB:cicp:systems:auxiliary:alpha"))?;
+        stream.finish_box()
+    }
+
+    fn write_a1lx(&mut self, stream: &mut OStream) -> AvifResult<()> {
+        let layer_sizes: Vec<_> = self.samples[0..self.extra_layer_count as usize]
+            .iter()
+            .map(|x| x.data.len())
+            .collect();
+        let has_large_size = layer_sizes.iter().any(|x| *x > 0xffff);
+        stream.start_box("a1lx")?;
+        // unsigned int(7) reserved = 0;
+        stream.write_bits(0, 7)?;
+        // unsigned int(1) large_size;
+        stream.write_bits(has_large_size as u8, 1)?;
+        // FieldLength = (large_size + 1) * 16;
+        // unsigned int(FieldLength) layer_size[3];
+        for i in 0..3 {
+            let layer_size = *layer_sizes.get(i).unwrap_or(&0);
+            if has_large_size {
+                stream.write_u32(u32_from_usize(layer_size)?)?;
+            } else {
+                stream.write_u16(u16_from_usize(layer_size)?)?;
+            }
+        }
+        stream.finish_box()
+    }
+
+    fn write_nclx(&self, stream: &mut OStream, image_metadata: &Image) -> AvifResult<()> {
+        stream.start_box("colr")?;
+        // unsigned int(32) colour_type;
+        stream.write_str("nclx")?;
+        // unsigned int(16) colour_primaries;
+        stream.write_u16(image_metadata.color_primaries as u16)?;
+        // unsigned int(16) transfer_characteristics;
+        stream.write_u16(image_metadata.transfer_characteristics as u16)?;
+        // unsigned int(16) matrix_coefficients;
+        stream.write_u16(image_metadata.matrix_coefficients as u16)?;
+        // unsigned int(1) full_range_flag;
+        stream.write_bits(
+            if image_metadata.yuv_range == YuvRange::Full { 1 } else { 0 },
+            1,
+        )?;
+        // unsigned int(7) reserved = 0;
+        stream.write_bits(0, 7)?;
+        stream.finish_box()
+    }
+
+    fn write_pasp(&self, stream: &mut OStream, pasp: &PixelAspectRatio) -> AvifResult<()> {
+        stream.start_box("pasp")?;
+        // unsigned int(32) hSpacing;
+        stream.write_u32(pasp.h_spacing)?;
+        // unsigned int(32) vSpacing;
+        stream.write_u32(pasp.v_spacing)?;
+        stream.finish_box()
+    }
+
+    fn write_clli(
+        &self,
+        stream: &mut OStream,
+        clli: &ContentLightLevelInformation,
+    ) -> AvifResult<()> {
+        stream.start_box("clli")?;
+        // unsigned int(16) max_content_light_level
+        stream.write_u16(clli.max_cll)?;
+        // unsigned int(16) max_pic_average_light_level
+        stream.write_u16(clli.max_pall)?;
+        stream.finish_box()
+    }
+
+    fn write_clap(&self, stream: &mut OStream, clap: &CleanAperture) -> AvifResult<()> {
+        stream.start_box("clap")?;
+        // unsigned int(32) cleanApertureWidthN;
+        // unsigned int(32) cleanApertureWidthD;
+        stream.write_ufraction(clap.width)?;
+        // unsigned int(32) cleanApertureHeightN;
+        // unsigned int(32) cleanApertureHeightD;
+        stream.write_ufraction(clap.height)?;
+        // unsigned int(32) horizOffN;
+        // unsigned int(32) horizOffD;
+        stream.write_ufraction(clap.horiz_off)?;
+        // unsigned int(32) vertOffN;
+        // unsigned int(32) vertOffD;
+        stream.write_ufraction(clap.vert_off)?;
+        stream.finish_box()
+    }
+
+    fn write_irot(&self, stream: &mut OStream, angle: u8) -> AvifResult<()> {
+        stream.start_box("irot")?;
+        // unsigned int(6) reserved = 0;
+        stream.write_bits(0, 6)?;
+        // unsigned int(2) angle;
+        stream.write_bits(angle & 0x03, 2)?;
+        stream.finish_box()
+    }
+
+    fn write_imir(&self, stream: &mut OStream, axis: u8) -> AvifResult<()> {
+        stream.start_box("imir")?;
+        // unsigned int(7) reserved = 0;
+        stream.write_bits(0, 7)?;
+        // unsigned int(1) axis;
+        stream.write_bits(axis & 0x01, 1)?;
+        stream.finish_box()
+    }
+
+    fn write_icc(&self, stream: &mut OStream, image_metadata: &Image) -> AvifResult<()> {
+        if image_metadata.icc.is_empty() {
+            return Ok(());
+        }
+        stream.start_box("colr")?;
+        // unsigned int(32) colour_type;
+        stream.write_str("prof")?;
+        stream.write_slice(&image_metadata.icc)?;
+        stream.finish_box()
+    }
+
+    fn write_transformative_properties(
+        &mut self,
+        streams: &mut Vec<OStream>,
+        metadata: &Image,
+    ) -> AvifResult<()> {
+        if let Some(clap) = metadata.clap {
+            streams.push(OStream::default());
+            self.write_clap(streams.last_mut().unwrap(), &clap)?;
+            self.associations
+                .push((u8_from_usize(streams.len())?, true));
+        }
+        if let Some(angle) = metadata.irot_angle {
+            streams.push(OStream::default());
+            self.write_irot(streams.last_mut().unwrap(), angle)?;
+            self.associations
+                .push((u8_from_usize(streams.len())?, true));
+        }
+        if let Some(axis) = metadata.imir_axis {
+            streams.push(OStream::default());
+            self.write_imir(streams.last_mut().unwrap(), axis)?;
+            self.associations
+                .push((u8_from_usize(streams.len())?, true));
+        }
+        Ok(())
+    }
+
+    pub(crate) fn get_property_streams(
+        &mut self,
+        image_metadata: &Image,
+        item_metadata: &Image,
+        streams: &mut Vec<OStream>,
+    ) -> AvifResult<()> {
+        if !self.has_ipma() {
+            return Ok(());
+        }
+
+        streams.push(OStream::default());
+        self.write_ispe(streams.last_mut().unwrap(), item_metadata)?;
+        self.associations
+            .push((u8_from_usize(streams.len())?, false));
+
+        // TODO: check for is_tmap and alt_plane_depth.
+        streams.push(OStream::default());
+        self.write_pixi(streams.last_mut().unwrap(), item_metadata)?;
+        self.associations
+            .push((u8_from_usize(streams.len())?, false));
+
+        if self.codec.is_some() {
+            streams.push(OStream::default());
+            self.write_codec_config(streams.last_mut().unwrap())?;
+            self.associations
+                .push((u8_from_usize(streams.len())?, true));
+        }
+
+        match self.category {
+            Category::Color => {
+                // Color properties.
+                // Note the 'tmap' item when a gain map is present also has category set to
+                // Category::Color.
+                if !item_metadata.icc.is_empty() {
+                    streams.push(OStream::default());
+                    self.write_icc(streams.last_mut().unwrap(), item_metadata)?;
+                    self.associations
+                        .push((u8_from_usize(streams.len())?, false));
+                }
+                streams.push(OStream::default());
+                self.write_nclx(streams.last_mut().unwrap(), item_metadata)?;
+                self.associations
+                    .push((u8_from_usize(streams.len())?, false));
+                if let Some(pasp) = item_metadata.pasp {
+                    streams.push(OStream::default());
+                    self.write_pasp(streams.last_mut().unwrap(), &pasp)?;
+                    self.associations
+                        .push((u8_from_usize(streams.len())?, false));
+                }
+                // HDR properties.
+                if let Some(clli) = item_metadata.clli {
+                    streams.push(OStream::default());
+                    self.write_clli(streams.last_mut().unwrap(), &clli)?;
+                    self.associations
+                        .push((u8_from_usize(streams.len())?, false));
+                }
+                self.write_transformative_properties(streams, item_metadata)?;
+            }
+            Category::Alpha => {
+                streams.push(OStream::default());
+                self.write_auxC(streams.last_mut().unwrap())?;
+                self.associations
+                    .push((u8_from_usize(streams.len())?, false));
+            }
+            Category::Gainmap => {
+                streams.push(OStream::default());
+                self.write_nclx(streams.last_mut().unwrap(), item_metadata)?;
+                self.associations
+                    .push((u8_from_usize(streams.len())?, false));
+                if let Some(pasp) = image_metadata.pasp {
+                    streams.push(OStream::default());
+                    self.write_pasp(streams.last_mut().unwrap(), &pasp)?;
+                    self.associations
+                        .push((u8_from_usize(streams.len())?, false));
+                }
+                if item_metadata.clap.is_some()
+                    || item_metadata.irot_angle.is_some()
+                    || item_metadata.imir_axis.is_some()
+                    || item_metadata.pasp.is_some()
+                {
+                    return Err(AvifError::UnknownError(
+                        "transformative properties must be associated with the base image".into(),
+                    ));
+                }
+                self.write_transformative_properties(streams, image_metadata)?;
+            }
+        }
+        if self.extra_layer_count > 0 {
+            streams.push(OStream::default());
+            self.write_a1lx(streams.last_mut().unwrap())?;
+            self.associations
+                .push((u8_from_usize(streams.len())?, false));
+            // We don't write 'lsel' property since many decoders do not support it and will reject
+            // the image, see https://github.com/AOMediaCodec/libavif/pull/2429
+        }
+        Ok(())
+    }
+
+    pub(crate) fn write_tkhd(
+        &self,
+        stream: &mut OStream,
+        image_metadata: &Image,
+        duration: u64,
+        timestamp: u64,
+    ) -> AvifResult<()> {
+        stream.start_full_box("tkhd", (1, 1))?;
+        // unsigned int(64) creation_time;
+        stream.write_u64(timestamp)?;
+        // unsigned int(64) modification_time;
+        stream.write_u64(timestamp)?;
+        // unsigned int(32) track_ID;
+        stream.write_u32(self.id as u32)?;
+        // const unsigned int(32) reserved = 0;
+        stream.write_u32(0)?;
+        // unsigned int(64) duration;
+        stream.write_u64(duration)?;
+        // const unsigned int(32)[2] reserved = 0;
+        stream.write_u32(0)?;
+        stream.write_u32(0)?;
+        // template int(16) layer = 0;
+        stream.write_u16(0)?;
+        // template int(16) alternate_group = 0;
+        stream.write_u16(0)?;
+        // template int(16) volume = {if track_is_audio 0x0100 else 0};
+        stream.write_u16(0)?;
+        // const unsigned int(16) reserved = 0;
+        stream.write_u16(0)?;
+        // template int(32)[9] matrix
+        stream.write_slice(&mp4box::UNITY_MATRIX)?;
+        // unsigned int(32) width;
+        stream.write_u32(image_metadata.width << 16)?;
+        // unsigned int(32) height;
+        stream.write_u32(image_metadata.height << 16)?;
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_tref(&self, stream: &mut OStream) -> AvifResult<()> {
+        if let Some(iref_to_id) = self.iref_to_id {
+            stream.start_box("tref")?;
+            {
+                stream.start_box(self.iref_type.as_ref().unwrap().as_str())?;
+                stream.write_u32(iref_to_id as u32)?;
+                stream.finish_box()?;
+            }
+            stream.finish_box()?;
+        }
+        Ok(())
+    }
+
+    pub(crate) fn write_vmhd(&self, stream: &mut OStream) -> AvifResult<()> {
+        stream.start_full_box("vmhd", (0, 1))?;
+        // template unsigned int(16) graphicsmode = 0; (copy over the existing image)
+        stream.write_u16(0)?;
+        // template unsigned int(16)[3] opcolor = {0, 0, 0};
+        stream.write_u16(0)?;
+        stream.write_u16(0)?;
+        stream.write_u16(0)?;
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_dinf(&self, stream: &mut OStream) -> AvifResult<()> {
+        stream.start_box("dinf")?;
+        {
+            stream.start_full_box("dref", (0, 0))?;
+            // unsigned int(32) entry_count
+            stream.write_u32(1)?;
+            {
+                // flags:1 means data is in this file
+                stream.start_full_box("url ", (0, 1))?;
+                stream.finish_box()?;
+            }
+            stream.finish_box()?;
+        }
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_ccst(&self, stream: &mut OStream) -> AvifResult<()> {
+        stream.start_full_box("ccst", (0, 0))?;
+        // unsigned int(1) all_ref_pics_intra;
+        stream.write_bits(0, 1)?;
+        // unsigned int(1) intra_pred_used;
+        stream.write_bits(1, 1)?;
+        // unsigned int(4) max_ref_per_pic;
+        stream.write_bits(15, 4)?;
+        // unsigned int(26) reserved;
+        stream.write_bits(0, 2)?;
+        stream.write_u8(0)?;
+        stream.write_u8(0)?;
+        stream.write_u8(0)?;
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_stsd(
+        &self,
+        stream: &mut OStream,
+        image_metadata: &Image,
+    ) -> AvifResult<()> {
+        stream.start_full_box("stsd", (0, 0))?;
+        // unsigned int(32) entry_count;
+        stream.write_u32(1)?;
+        {
+            stream.start_box("av01")?;
+            // const unsigned int(8)[6] reserved = 0;
+            for _ in 0..6 {
+                stream.write_u8(0)?;
+            }
+            // unsigned int(16) data_reference_index;
+            stream.write_u16(1)?;
+            // unsigned int(16) pre_defined = 0;
+            stream.write_u16(0)?;
+            // const unsigned int(16) reserved = 0;
+            stream.write_u16(0)?;
+            // unsigned int(32)[3] pre_defined = 0;
+            stream.write_u32(0)?;
+            stream.write_u32(0)?;
+            stream.write_u32(0)?;
+            // unsigned int(16) width;
+            stream.write_u16(u16_from_u32(image_metadata.width)?)?;
+            // unsigned int(16) height;
+            stream.write_u16(u16_from_u32(image_metadata.height)?)?;
+            // template unsigned int(32) horizresolution
+            stream.write_u32(0x00480000)?;
+            // template unsigned int(32) vertresolution
+            stream.write_u32(0x00480000)?;
+            // const unsigned int(32) reserved = 0;
+            stream.write_u32(0)?;
+            // template unsigned int(16) frame_count = 1;
+            stream.write_u16(1)?;
+            // string[32] compressorname;
+            const COMPRESSOR_NAME: &str = "AOM Coding with CrabbyAvif      ";
+            assert_eq!(COMPRESSOR_NAME.len(), 32);
+            stream.write_str(COMPRESSOR_NAME)?;
+            // template unsigned int(16) depth = 0x0018;
+            stream.write_u16(0x0018)?;
+            // int(16) pre_defined = -1
+            stream.write_u16(0xffff)?;
+
+            self.write_codec_config(stream)?;
+            if self.category == Category::Color {
+                self.write_icc(stream, image_metadata)?;
+                self.write_nclx(stream, image_metadata)?;
+                // TODO: Determine if HDR and transformative properties have to be written here or
+                // not.
+            }
+            self.write_ccst(stream)?;
+
+            stream.finish_box()?;
+        }
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_stts(
+        &self,
+        stream: &mut OStream,
+        duration_in_timescales: &Vec<u64>,
+    ) -> AvifResult<()> {
+        let mut stts: Vec<(u64, u32)> = Vec::new();
+        let mut current_value = None;
+        let mut current_count = 0;
+        for duration in duration_in_timescales {
+            if let Some(current) = current_value {
+                if *duration == current {
+                    current_count += 1;
+                } else {
+                    stts.push((current, current_count));
+                    current_value = Some(*duration);
+                    current_count = 1;
+                }
+            } else {
+                current_value = Some(*duration);
+                current_count = 1;
+            }
+        }
+        if let Some(current) = current_value {
+            stts.push((current, current_count));
+        }
+
+        stream.start_full_box("stts", (0, 0))?;
+        // unsigned int(32) entry_count;
+        stream.write_u32(u32_from_usize(stts.len())?)?;
+        for (sample_delta, sample_count) in stts {
+            // unsigned int(32) sample_count;
+            stream.write_u32(sample_count)?;
+            // unsigned int(32) sample_delta;
+            stream.write_u32(u32_from_u64(sample_delta)?)?;
+        }
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_stsc(&self, stream: &mut OStream) -> AvifResult<()> {
+        stream.start_full_box("stsc", (0, 0))?;
+        // unsigned int(32) entry_count;
+        stream.write_u32(1)?;
+        // unsigned int(32) first_chunk;
+        stream.write_u32(1)?;
+        // unsigned int(32) samples_per_chunk;
+        stream.write_u32(u32_from_usize(self.samples.len())?)?;
+        // unsigned int(32) sample_description_index;
+        stream.write_u32(1)?;
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_stsz(&self, stream: &mut OStream) -> AvifResult<()> {
+        stream.start_full_box("stsz", (0, 0))?;
+        // unsigned int(32) sample_size;
+        stream.write_u32(0)?;
+        // unsigned int(32) sample_count;
+        stream.write_u32(u32_from_usize(self.samples.len())?)?;
+        for sample in &self.samples {
+            // unsigned int(32) entry_size;
+            stream.write_u32(u32_from_usize(sample.data.len())?)?;
+        }
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_stco(&mut self, stream: &mut OStream) -> AvifResult<()> {
+        stream.start_full_box("stco", (0, 0))?;
+        // unsigned int(32) entry_count;
+        stream.write_u32(1)?;
+        // unsigned int(32) chunk_offset;
+        self.mdat_offset_locations.push(stream.offset());
+        stream.write_u32(0)?;
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_stss(&mut self, stream: &mut OStream) -> AvifResult<()> {
+        let sync_samples_count = self.samples.iter().filter(|x| x.sync).count();
+        if sync_samples_count == self.samples.len() {
+            // ISO/IEC 14496-12, Section 8.6.2.1:
+            //   If the SyncSampleBox is not present, every sample is a sync sample.
+            return Ok(());
+        }
+        stream.start_full_box("stss", (0, 0))?;
+        // unsigned int(32) entry_count;
+        stream.write_u32(u32_from_usize(sync_samples_count)?)?;
+        for (index, sample) in self.samples.iter().enumerate() {
+            if !sample.sync {
+                continue;
+            }
+            // unsigned int(32) sample_number;
+            stream.write_u32(u32_from_usize(index + 1)?)?;
+        }
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_stbl(
+        &mut self,
+        stream: &mut OStream,
+        image_metadata: &Image,
+        duration_in_timescales: &Vec<u64>,
+    ) -> AvifResult<()> {
+        stream.start_box("stbl")?;
+        self.write_stsd(stream, image_metadata)?;
+        self.write_stts(stream, duration_in_timescales)?;
+        self.write_stsc(stream)?;
+        self.write_stsz(stream)?;
+        self.write_stco(stream)?;
+        self.write_stss(stream)?;
+        stream.finish_box()
+    }
+}
diff --git a/src/encoder/mod.rs b/src/encoder/mod.rs
new file mode 100644
index 0000000..edefe18
--- /dev/null
+++ b/src/encoder/mod.rs
@@ -0,0 +1,624 @@
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
+pub mod item;
+pub mod mp4box;
+
+use crate::encoder::item::*;
+use crate::encoder::mp4box::*;
+
+use crate::codecs::EncoderConfig;
+use crate::gainmap::GainMap;
+use crate::image::*;
+use crate::internal_utils::stream::IStream;
+use crate::internal_utils::stream::OStream;
+use crate::internal_utils::*;
+use crate::parser::exif;
+use crate::parser::mp4box::*;
+use crate::parser::obu::Av1SequenceHeader;
+use crate::utils::IFraction;
+use crate::*;
+
+#[cfg(feature = "aom")]
+use crate::codecs::aom::Aom;
+
+use std::fmt;
+use std::time::SystemTime;
+use std::time::UNIX_EPOCH;
+
+#[derive(Clone, Copy, Debug, PartialEq)]
+#[repr(C)]
+pub struct ScalingMode {
+    pub horizontal: IFraction,
+    pub vertical: IFraction,
+}
+
+impl Default for ScalingMode {
+    fn default() -> Self {
+        Self {
+            horizontal: IFraction(1, 1),
+            vertical: IFraction(1, 1),
+        }
+    }
+}
+
+#[derive(Clone, Copy, Debug)]
+pub enum TilingMode {
+    Auto,
+    Manual(i32, i32), // tile_rows_log2, tile_columns_log2
+}
+
+impl Default for TilingMode {
+    fn default() -> Self {
+        Self::Manual(0, 0)
+    }
+}
+
+impl TilingMode {
+    fn log2(&self, width: u32, height: u32) -> (i32, i32) {
+        match *self {
+            Self::Auto => {
+                let image_area = width * height;
+                let tiles_log2 =
+                    floor_log2(std::cmp::min(image_area.div_ceil(512 * 512), 8)) as i32;
+                let (dim1, dim2) = if width >= height { (width, height) } else { (height, width) };
+                let diff_log2 = floor_log2(dim1 / dim2) as i32;
+                let diff = std::cmp::max(0, tiles_log2 - diff_log2);
+                let dim2_log2 = diff / 2;
+                let dim1_log2 = tiles_log2 - dim2_log2;
+                if width >= height {
+                    (dim2_log2, dim1_log2)
+                } else {
+                    (dim1_log2, dim2_log2)
+                }
+            }
+            Self::Manual(rows_log2, columns_log2) => (rows_log2, columns_log2),
+        }
+    }
+}
+
+#[derive(Clone, Copy, Debug, Default)]
+pub struct MutableSettings {
+    pub quality: i32,
+    pub tiling_mode: TilingMode,
+    pub scaling_mode: ScalingMode,
+}
+
+#[derive(Clone, Copy, Debug, Default)]
+pub struct Settings {
+    pub threads: u32,
+    pub speed: Option<u32>,
+    pub keyframe_interval: i32,
+    pub timescale: u64,
+    pub repetition_count: i32,
+    pub extra_layer_count: u32,
+    pub mutable: MutableSettings,
+}
+
+impl Settings {
+    pub(crate) fn quantizer(&self) -> i32 {
+        // TODO: account for category here.
+        ((100 - self.mutable.quality) * 63 + 50) / 100
+    }
+}
+
+#[derive(Debug, Default)]
+pub(crate) struct Sample {
+    pub data: Vec<u8>,
+    pub sync: bool,
+}
+
+impl Sample {
+    // This function is not used in all configurations.
+    #[allow(unused)]
+    pub(crate) fn create_from(data: &[u8], sync: bool) -> AvifResult<Self> {
+        let mut copied_data: Vec<u8> = create_vec_exact(data.len())?;
+        copied_data.extend_from_slice(data);
+        Ok(Sample {
+            data: copied_data,
+            sync,
+        })
+    }
+}
+
+pub(crate) type Codec = Box<dyn crate::codecs::Encoder>;
+
+#[derive(Default)]
+#[allow(unused)]
+pub struct Encoder {
+    settings: Settings,
+    items: Vec<Item>,
+    image_metadata: Image,
+    gainmap_image_metadata: Image,
+    alt_image_metadata: Image,
+    quantizer: i32,
+    primary_item_id: u16,
+    alternative_item_ids: Vec<u16>,
+    single_image: bool,
+    alpha_present: bool,
+    image_item_type: String,
+    config_property_name: String,
+    duration_in_timescales: Vec<u64>,
+}
+
+impl Encoder {
+    pub fn create_with_settings(settings: &Settings) -> AvifResult<Self> {
+        if settings.extra_layer_count >= MAX_AV1_LAYER_COUNT as u32 {
+            return Err(AvifError::InvalidArgument);
+        }
+        Ok(Self {
+            settings: *settings,
+            ..Default::default()
+        })
+    }
+
+    pub fn update_settings(&mut self, mutable: &MutableSettings) -> AvifResult<()> {
+        self.settings.mutable = *mutable;
+        Ok(())
+    }
+
+    pub(crate) fn is_sequence(&self) -> bool {
+        self.settings.extra_layer_count == 0 && self.duration_in_timescales.len() > 1
+    }
+
+    fn add_tmap_item(&mut self, gainmap: &GainMap) -> AvifResult<u16> {
+        let item = Item {
+            id: u16_from_usize(self.items.len() + 1)?,
+            item_type: "tmap".into(),
+            infe_name: Category::Gainmap.infe_name(),
+            category: Category::Color,
+            metadata_payload: write_tmap(&gainmap.metadata)?,
+            ..Default::default()
+        };
+        let item_id = item.id;
+        self.items.push(item);
+        Ok(item_id)
+    }
+
+    fn add_items(&mut self, grid: &Grid, category: Category) -> AvifResult<u16> {
+        let cell_count = usize_from_u32(grid.rows * grid.columns)?;
+        let mut top_level_item_id = 0;
+        if cell_count > 1 {
+            let mut stream = OStream::default();
+            write_grid(&mut stream, grid)?;
+            let item = Item {
+                id: u16_from_usize(self.items.len() + 1)?,
+                item_type: "grid".into(),
+                infe_name: category.infe_name(),
+                category,
+                grid: Some(*grid),
+                metadata_payload: stream.data,
+                hidden_image: category == Category::Gainmap,
+                ..Default::default()
+            };
+            top_level_item_id = item.id;
+            self.items.push(item);
+        }
+        for cell_index in 0..cell_count {
+            let item = Item {
+                id: u16_from_usize(self.items.len() + 1)?,
+                item_type: "av01".into(),
+                infe_name: category.infe_name(),
+                cell_index,
+                category,
+                dimg_from_id: if cell_count > 1 { Some(top_level_item_id) } else { None },
+                hidden_image: cell_count > 1,
+                extra_layer_count: self.settings.extra_layer_count,
+                #[cfg(feature = "aom")]
+                codec: Some(Box::<Aom>::default()),
+                ..Default::default()
+            };
+            if cell_count == 1 {
+                top_level_item_id = item.id;
+            }
+            self.items.push(item);
+        }
+        Ok(top_level_item_id)
+    }
+
+    fn add_exif_item(&mut self) -> AvifResult<()> {
+        if self.image_metadata.exif.is_empty() {
+            return Ok(());
+        }
+        let mut stream = IStream::create(&self.image_metadata.exif);
+        let tiff_header_offset = exif::parse_exif_tiff_header_offset(&mut stream)?;
+        let mut metadata_payload: Vec<u8> = create_vec_exact(4 + self.image_metadata.exif.len())?;
+        metadata_payload.extend_from_slice(&tiff_header_offset.to_be_bytes());
+        metadata_payload.extend_from_slice(&self.image_metadata.exif);
+        self.items.push(Item {
+            id: u16_from_usize(self.items.len() + 1)?,
+            item_type: "Exif".into(),
+            infe_name: "Exif".into(),
+            iref_to_id: Some(self.primary_item_id),
+            iref_type: Some("cdsc".into()),
+            metadata_payload,
+            ..Default::default()
+        });
+        Ok(())
+    }
+
+    fn add_xmp_item(&mut self) -> AvifResult<()> {
+        if self.image_metadata.xmp.is_empty() {
+            return Ok(());
+        }
+        self.items.push(Item {
+            id: u16_from_usize(self.items.len() + 1)?,
+            item_type: "mime".into(),
+            infe_name: "XMP".into(),
+            infe_content_type: "application/rdf+xml".into(),
+            iref_to_id: Some(self.primary_item_id),
+            iref_type: Some("cdsc".into()),
+            metadata_payload: self.image_metadata.xmp.clone(),
+            ..Default::default()
+        });
+        Ok(())
+    }
+
+    fn copy_alt_image_metadata(&mut self, gainmap: &GainMap, grid: &Grid) {
+        self.alt_image_metadata.width = grid.width;
+        self.alt_image_metadata.height = grid.height;
+        self.alt_image_metadata.icc = gainmap.alt_icc.clone();
+        self.alt_image_metadata.color_primaries = gainmap.alt_color_primaries;
+        self.alt_image_metadata.transfer_characteristics = gainmap.alt_transfer_characteristics;
+        self.alt_image_metadata.matrix_coefficients = gainmap.alt_matrix_coefficients;
+        self.alt_image_metadata.yuv_range = gainmap.alt_yuv_range;
+        self.alt_image_metadata.depth = if gainmap.alt_plane_depth > 0 {
+            gainmap.alt_plane_depth
+        } else {
+            std::cmp::max(self.image_metadata.depth, gainmap.image.depth)
+        };
+        self.alt_image_metadata.yuv_format = if gainmap.alt_plane_count == 1 {
+            PixelFormat::Yuv400
+        } else {
+            PixelFormat::Yuv444
+        };
+        self.alt_image_metadata.clli = Some(gainmap.alt_clli);
+    }
+
+    fn validate_image_grid(grid: &Grid, images: &[&Image]) -> AvifResult<()> {
+        let first_image = images[0];
+        let last_image = images.last().unwrap();
+        for (index, image) in images.iter().enumerate() {
+            if image.depth != 8 && image.depth != 10 && image.depth != 12 {
+                return Err(AvifError::InvalidArgument);
+            }
+            let expected_width = if grid.is_last_column(index as u32) {
+                first_image.width
+            } else {
+                last_image.width
+            };
+            let expected_height = if grid.is_last_row(index as u32) {
+                first_image.height
+            } else {
+                last_image.height
+            };
+            if image.width != expected_width
+                || image.height != expected_height
+                || !image.has_same_cicp(first_image)
+                || image.has_alpha() != first_image.has_alpha()
+                || image.alpha_premultiplied != first_image.alpha_premultiplied
+            {
+                return Err(AvifError::InvalidImageGrid(
+                    "all cells do not have the same properties".into(),
+                ));
+            }
+            if image.matrix_coefficients == MatrixCoefficients::Identity
+                && image.yuv_format != PixelFormat::Yuv444
+            {
+                return Err(AvifError::InvalidArgument);
+            }
+            if !image.has_plane(Plane::Y) {
+                return Err(AvifError::NoContent);
+            }
+        }
+        if last_image.width > first_image.width || last_image.height > first_image.height {
+            return Err(AvifError::InvalidImageGrid(
+                "last cell was larger than the first cell".into(),
+            ));
+        }
+        if images.len() > 1 {
+            validate_grid_image_dimensions(first_image, grid)?;
+        }
+        Ok(())
+    }
+
+    fn validate_gainmap_grid(grid: &Grid, gainmaps: &[&GainMap]) -> AvifResult<()> {
+        for gainmap in &gainmaps[1..] {
+            if gainmaps[0] != *gainmap {
+                return Err(AvifError::InvalidImageGrid(
+                    "all cells should have the same gain map metadata".into(),
+                ));
+            }
+        }
+        if gainmaps[0].image.color_primaries != ColorPrimaries::Unspecified
+            || gainmaps[0].image.transfer_characteristics != TransferCharacteristics::Unspecified
+        {
+            return Err(AvifError::InvalidArgument);
+        }
+        let gainmap_images: Vec<_> = gainmaps.iter().map(|x| &x.image).collect();
+        Self::validate_image_grid(grid, &gainmap_images)?;
+        // Ensure that the gainmap image does not have alpha. validate_image_grid() ensures that
+        // either all the cell images have alpha or all of them don't. So it is sufficient to check
+        // if the first cell image does not have alpha.
+        if gainmap_images[0].has_alpha() {
+            return Err(AvifError::InvalidArgument);
+        }
+        Ok(())
+    }
+
+    fn add_image_impl(
+        &mut self,
+        grid_columns: u32,
+        grid_rows: u32,
+        cell_images: &[&Image],
+        mut duration: u32,
+        is_single_image: bool,
+        gainmaps: Option<&[&GainMap]>,
+    ) -> AvifResult<()> {
+        let cell_count: usize = usize_from_u32(grid_rows * grid_columns)?;
+        if cell_count == 0 || cell_images.len() != cell_count {
+            return Err(AvifError::InvalidArgument);
+        }
+        if duration == 0 {
+            duration = 1;
+        }
+        if self.items.is_empty() {
+            // TODO: validate clap.
+            let first_image = cell_images[0];
+            let last_image = cell_images.last().unwrap();
+            let grid = Grid {
+                rows: grid_rows,
+                columns: grid_columns,
+                width: (grid_columns - 1) * first_image.width + last_image.width,
+                height: (grid_rows - 1) * first_image.height + last_image.height,
+            };
+            Self::validate_image_grid(&grid, cell_images)?;
+            self.image_metadata = first_image.shallow_clone();
+            if gainmaps.is_some() {
+                self.gainmap_image_metadata = gainmaps.unwrap()[0].image.shallow_clone();
+                self.copy_alt_image_metadata(gainmaps.unwrap()[0], &grid);
+            }
+            let color_item_id = self.add_items(&grid, Category::Color)?;
+            self.primary_item_id = color_item_id;
+            self.alpha_present = first_image.has_plane(Plane::A)
+                && if is_single_image {
+                    // When encoding a single image in which the alpha plane exists but is entirely
+                    // opaque, skip writing an alpha AV1 payload. This does not apply to image
+                    // sequences since subsequent frames may have a non-opaque alpha channel.
+                    !cell_images.iter().all(|image| image.is_opaque())
+                } else {
+                    true
+                };
+
+            if self.alpha_present {
+                let alpha_item_id = self.add_items(&grid, Category::Alpha)?;
+                let alpha_item = &mut self.items[alpha_item_id as usize - 1];
+                alpha_item.iref_type = Some(String::from("auxl"));
+                alpha_item.iref_to_id = Some(color_item_id);
+                if self.image_metadata.alpha_premultiplied {
+                    let color_item = &mut self.items[color_item_id as usize - 1];
+                    color_item.iref_type = Some(String::from("prem"));
+                    color_item.iref_to_id = Some(alpha_item_id);
+                }
+            }
+            if let Some(gainmaps) = gainmaps {
+                if gainmaps.len() != cell_images.len() {
+                    return Err(AvifError::InvalidImageGrid(
+                        "invalid number of gainmap images".into(),
+                    ));
+                }
+                let first_gainmap_image = &gainmaps[0].image;
+                let last_gainmap_image = &gainmaps.last().unwrap().image;
+                let gainmap_grid = Grid {
+                    rows: grid_rows,
+                    columns: grid_columns,
+                    width: (grid_columns - 1) * first_gainmap_image.width
+                        + last_gainmap_image.width,
+                    height: (grid_rows - 1) * first_gainmap_image.height
+                        + last_gainmap_image.height,
+                };
+                Self::validate_gainmap_grid(&gainmap_grid, gainmaps)?;
+                let tonemap_item_id = self.add_tmap_item(gainmaps[0])?;
+                if !self.alternative_item_ids.is_empty() {
+                    return Err(AvifError::UnknownError("".into()));
+                }
+                self.alternative_item_ids.push(tonemap_item_id);
+                self.alternative_item_ids.push(color_item_id);
+                let gainmap_item_id = self.add_items(&gainmap_grid, Category::Gainmap)?;
+                for item_id in [color_item_id, gainmap_item_id] {
+                    self.items[item_id as usize - 1].dimg_from_id = Some(tonemap_item_id);
+                }
+            }
+            self.add_exif_item()?;
+            self.add_xmp_item()?;
+        } else {
+            if gainmaps.is_some() {
+                return Err(AvifError::NotImplemented);
+            }
+            // Another frame in an image sequence, or layer in a layered image.
+            let first_image = cell_images[0];
+            if !first_image.has_same_cicp(&self.image_metadata)
+                || first_image.alpha_premultiplied != self.image_metadata.alpha_premultiplied
+                || first_image.alpha_present != self.image_metadata.alpha_present
+            {
+                return Err(AvifError::InvalidArgument);
+            }
+        }
+
+        let (tile_rows_log2, tile_columns_log2) = self
+            .settings
+            .mutable
+            .tiling_mode
+            .log2(cell_images[0].width, cell_images[0].height);
+        // Encode the AV1 OBUs.
+        for item in &mut self.items {
+            if item.codec.is_none() {
+                continue;
+            }
+            let image = match item.category {
+                Category::Gainmap => &gainmaps.unwrap()[item.cell_index].image,
+                _ => cell_images[item.cell_index],
+            };
+            let first_image = match item.category {
+                Category::Gainmap => &gainmaps.unwrap()[0].image,
+                _ => cell_images[0],
+            };
+            if image.width != first_image.width || image.height != first_image.height {
+                // TODO: pad the image so that the dimensions of all cells are equal.
+            }
+            let encoder_config = EncoderConfig {
+                tile_rows_log2,
+                tile_columns_log2,
+                quantizer: self.settings.quantizer(),
+                disable_lagged_output: self.alpha_present,
+                is_single_image,
+                speed: self.settings.speed,
+                extra_layer_count: self.settings.extra_layer_count,
+                threads: self.settings.threads,
+                scaling_mode: self.settings.mutable.scaling_mode,
+            };
+            item.codec.unwrap_mut().encode_image(
+                image,
+                item.category,
+                &encoder_config,
+                &mut item.samples,
+            )?;
+        }
+        self.duration_in_timescales.push(duration as u64);
+        Ok(())
+    }
+
+    pub fn add_image(&mut self, image: &Image) -> AvifResult<()> {
+        self.add_image_impl(
+            1,
+            1,
+            &[image],
+            0,
+            self.settings.extra_layer_count == 0,
+            None,
+        )
+    }
+
+    pub fn add_image_for_sequence(&mut self, image: &Image, duration: u32) -> AvifResult<()> {
+        // TODO: this and add_image cannot be used on the same instance.
+        self.add_image_impl(1, 1, &[image], duration, false, None)
+    }
+
+    pub fn add_image_grid(
+        &mut self,
+        grid_columns: u32,
+        grid_rows: u32,
+        images: &[&Image],
+    ) -> AvifResult<()> {
+        if grid_columns == 0 || grid_columns > 256 || grid_rows == 0 || grid_rows > 256 {
+            return Err(AvifError::InvalidImageGrid("".into()));
+        }
+        self.add_image_impl(
+            grid_columns,
+            grid_rows,
+            images,
+            0,
+            self.settings.extra_layer_count == 0,
+            None,
+        )
+    }
+
+    pub fn add_image_gainmap(&mut self, image: &Image, gainmap: &GainMap) -> AvifResult<()> {
+        if self.settings.extra_layer_count != 0 {
+            return Err(AvifError::NotImplemented);
+        }
+        self.add_image_impl(1, 1, &[image], 0, true, Some(&[gainmap]))
+    }
+
+    pub fn add_image_gainmap_grid(
+        &mut self,
+        grid_columns: u32,
+        grid_rows: u32,
+        images: &[&Image],
+        gainmaps: &[&GainMap],
+    ) -> AvifResult<()> {
+        if grid_columns == 0 || grid_columns > 256 || grid_rows == 0 || grid_rows > 256 {
+            return Err(AvifError::InvalidImageGrid("".into()));
+        }
+        if self.settings.extra_layer_count != 0 {
+            return Err(AvifError::NotImplemented);
+        }
+        self.add_image_impl(grid_columns, grid_rows, images, 0, true, Some(gainmaps))
+    }
+
+    pub fn finish(&mut self) -> AvifResult<Vec<u8>> {
+        if self.items.is_empty() {
+            return Err(AvifError::NoContent);
+        }
+        self.settings.timescale = 10000;
+        for item in &mut self.items {
+            if item.codec.is_none() {
+                continue;
+            }
+            item.codec.unwrap_mut().finish(&mut item.samples)?;
+            if item.extra_layer_count > 0
+                && item.samples.len() != 1 + item.extra_layer_count as usize
+            {
+                return Err(AvifError::InvalidArgument);
+            }
+            // TODO: check if sample count == duration count.
+
+            if !item.samples.is_empty() {
+                // Harvest codec configuration from sequence header.
+                let sequence_header = Av1SequenceHeader::parse_from_obus(&item.samples[0].data)?;
+                item.codec_configuration = CodecConfiguration::Av1(sequence_header.config);
+            }
+        }
+        let mut stream = OStream::default();
+        self.write_ftyp(&mut stream)?;
+        self.write_meta(&mut stream)?;
+        self.write_moov(&mut stream)?;
+        self.write_mdat(&mut stream)?;
+        Ok(stream.data)
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use test_case::test_case;
+
+    #[test_case(256, 144, 0, 0 ; "144p")]
+    #[test_case(426, 240, 0, 0 ; "240p")]
+    #[test_case(640, 360, 0, 0 ; "360p")]
+    #[test_case(854, 480, 0, 1 ; "480p")]
+    #[test_case(1280, 720, 1, 1 ; "720p")]
+    #[test_case(1920, 1080, 1, 2 ; "1080p")]
+    #[test_case(2560, 1440, 1, 2 ; "2k")]
+    #[test_case(3840, 2160, 1, 2 ; "4k")]
+    #[test_case(7680, 4320, 1, 2 ; "8k")]
+    #[test_case(768, 512, 0, 1 ; "case 1")]
+    #[test_case(16384, 64, 0, 2 ; "case 2")]
+    fn auto_tiling(
+        width: u32,
+        height: u32,
+        expected_tile_rows_log2: i32,
+        expected_tile_columns_log2: i32,
+    ) {
+        let tiling_mode = TilingMode::Auto;
+        assert_eq!(
+            tiling_mode.log2(width, height),
+            (expected_tile_rows_log2, expected_tile_columns_log2)
+        );
+        assert_eq!(
+            tiling_mode.log2(height, width),
+            (expected_tile_columns_log2, expected_tile_rows_log2)
+        );
+    }
+}
diff --git a/src/encoder/mp4box.rs b/src/encoder/mp4box.rs
new file mode 100644
index 0000000..9c05302
--- /dev/null
+++ b/src/encoder/mp4box.rs
@@ -0,0 +1,640 @@
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
+use crate::encoder::*;
+
+use crate::gainmap::GainMapMetadata;
+use crate::internal_utils::stream::OStream;
+use crate::internal_utils::*;
+use crate::*;
+
+pub(crate) const UNITY_MATRIX: [u8; 9 * 4] = [
+    0x00, 0x01, 0x00, 0x00, //
+    0x00, 0x00, 0x00, 0x00, //
+    0x00, 0x00, 0x00, 0x00, //
+    0x00, 0x00, 0x00, 0x00, //
+    0x00, 0x01, 0x00, 0x00, //
+    0x00, 0x00, 0x00, 0x00, //
+    0x00, 0x00, 0x00, 0x00, //
+    0x00, 0x00, 0x00, 0x00, //
+    0x40, 0x00, 0x00, 0x00, //
+];
+
+pub(crate) fn write_hdlr(stream: &mut OStream, handler_type: &str) -> AvifResult<()> {
+    stream.start_full_box("hdlr", (0, 0))?;
+    // unsigned int(32) pre_defined = 0;
+    stream.write_u32(0)?;
+    // unsigned int(32) handler_type;
+    stream.write_str(handler_type)?;
+    // const unsigned int(32)[3] reserved = 0;
+    stream.write_u32(0)?;
+    stream.write_u32(0)?;
+    stream.write_u32(0)?;
+    // string name;
+    stream.write_string_with_nul(&String::from(""))?;
+    stream.finish_box()
+}
+
+pub(crate) fn write_pitm(stream: &mut OStream, item_id: u16) -> AvifResult<()> {
+    stream.start_full_box("pitm", (0, 0))?;
+    //  unsigned int(16) item_ID;
+    stream.write_u16(item_id)?;
+    stream.finish_box()
+}
+
+pub(crate) fn write_grid(stream: &mut OStream, grid: &Grid) -> AvifResult<()> {
+    // ISO/IEC 23008-12 6.6.2.3.2
+    // aligned(8) class ImageGrid {
+    //     unsigned int(8) version = 0;
+    //     unsigned int(8) flags;
+    //     FieldLength = ((flags & 1) + 1) * 16;
+    //     unsigned int(8) rows_minus_one;
+    //     unsigned int(8) columns_minus_one;
+    //     unsigned int(FieldLength) output_width;
+    //     unsigned int(FieldLength) output_height;
+    // }
+    let flags = if grid.width > 65535 || grid.height > 65535 { 1 } else { 0 };
+    // unsigned int(8) version = 0;
+    stream.write_u8(0)?;
+    // unsigned int(8) flags;
+    stream.write_u8(flags)?;
+    // unsigned int(8) rows_minus_one;
+    stream.write_u8(grid.rows as u8 - 1)?;
+    // unsigned int(8) columns_minus_one;
+    stream.write_u8(grid.columns as u8 - 1)?;
+    // unsigned int(FieldLength) output_width;
+    // unsigned int(FieldLength) output_height;
+    if flags == 1 {
+        stream.write_u32(grid.width)?;
+        stream.write_u32(grid.height)?;
+    } else {
+        stream.write_u16(grid.width as u16)?;
+        stream.write_u16(grid.height as u16)?;
+    }
+    Ok(())
+}
+
+pub(crate) fn write_tmap(metadata: &GainMapMetadata) -> AvifResult<Vec<u8>> {
+    let mut stream = OStream::default();
+    // ToneMapImage syntax as per section 6.6.2.4.2 of ISO/IEC 23008-12:2024
+    // amendment "Support for tone map derived image items and other improvements".
+    // unsigned int(8) version = 0;
+    stream.write_u8(0)?;
+    // GainMapMetadata syntax as per clause C.2.2 of ISO 21496-1
+    // unsigned int(16) minimum_version;
+    stream.write_u16(0)?;
+    // unsigned int(16) writer_version;
+    stream.write_u16(0)?;
+    // unsigned int(1) is_multichannel;
+    stream.write_bool(metadata.channel_count() == 3)?;
+    // unsigned int(1) use_base_colour_space;
+    stream.write_bool(metadata.use_base_color_space)?;
+    // unsigned int(6) reserved;
+    stream.write_bits(0, 6)?;
+    // unsigned int(32) base_hdr_headroom_numerator;
+    // unsigned int(32) base_hdr_headroom_denominator;
+    stream.write_ufraction(metadata.base_hdr_headroom)?;
+    // unsigned int(32) alternate_hdr_headroom_numerator;
+    // unsigned int(32) alternate_hdr_headroom_denominator;
+    stream.write_ufraction(metadata.alternate_hdr_headroom)?;
+    for i in 0..metadata.channel_count() as usize {
+        // int(32) gain_map_min_numerator;
+        // unsigned int(32) gain_map_min_denominator
+        stream.write_fraction(metadata.min[i])?;
+        // int(32) gain_map_max_numerator;
+        // unsigned int(32) gain_map_max_denominator;
+        stream.write_fraction(metadata.max[i])?;
+        // unsigned int(32) gamma_numerator;
+        // unsigned int(32) gamma_denominator;
+        stream.write_ufraction(metadata.gamma[i])?;
+        // int(32) base_offset_numerator;
+        // unsigned int(32) base_offset_denominator;
+        stream.write_fraction(metadata.base_offset[i])?;
+        // int(32) alternate_offset_numerator;
+        // unsigned int(32) alternate_offset_denominator;
+        stream.write_fraction(metadata.alternate_offset[i])?;
+    }
+    Ok(stream.data)
+}
+
+impl Encoder {
+    pub(crate) fn write_ftyp(&self, stream: &mut OStream) -> AvifResult<()> {
+        let mut compatible_brands = vec![
+            String::from("avif"),
+            String::from("mif1"),
+            String::from("miaf"),
+        ];
+        // TODO: check if avio brand is necessary.
+        if self.is_sequence() {
+            compatible_brands.extend_from_slice(&[
+                String::from("avis"),
+                String::from("msf1"),
+                String::from("iso8"),
+            ]);
+        }
+        if self.items.iter().any(|x| x.is_tmap()) {
+            compatible_brands.push(String::from("tmap"));
+        }
+        match self.image_metadata.depth {
+            8 | 10 => match self.image_metadata.yuv_format {
+                PixelFormat::Yuv420 => compatible_brands.push(String::from("MA1B")),
+                PixelFormat::Yuv444 => compatible_brands.push(String::from("MA1A")),
+                _ => {}
+            },
+            _ => {}
+        }
+
+        stream.start_box("ftyp")?;
+        // unsigned int(32) major_brand;
+        stream.write_string(&String::from(if self.is_sequence() {
+            "avis"
+        } else {
+            "avif"
+        }))?;
+        // unsigned int(32) minor_version;
+        stream.write_u32(0)?;
+        // unsigned int(32) compatible_brands[];
+        for compatible_brand in &compatible_brands {
+            stream.write_string(compatible_brand)?;
+        }
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_iloc(stream: &mut OStream, items: &mut Vec<&mut Item>) -> AvifResult<()> {
+        stream.start_full_box("iloc", (0, 0))?;
+        // unsigned int(4) offset_size;
+        // unsigned int(4) length_size;
+        stream.write_u8(0x44)?;
+        // unsigned int(4) base_offset_size;
+        // unsigned int(4) reserved;
+        stream.write_u8(0)?;
+        // unsigned int(16) item_count;
+        stream.write_u16(u16_from_usize(items.len())?)?;
+
+        for item in items {
+            // unsigned int(16) item_ID;
+            stream.write_u16(item.id)?;
+            // unsigned int(16) data_reference_index;
+            stream.write_u16(0)?;
+
+            if item.extra_layer_count > 0 {
+                let layer_count = item.extra_layer_count as u16 + 1;
+                // unsigned int(16) extent_count;
+                stream.write_u16(layer_count)?;
+                for i in 0..layer_count as usize {
+                    item.mdat_offset_locations.push(stream.offset());
+                    // unsigned int(offset_size*8) extent_offset;
+                    stream.write_u32(0)?;
+                    // unsigned int(length_size*8) extent_length;
+                    stream.write_u32(u32_from_usize(item.samples[i].data.len())?)?;
+                }
+            } else {
+                // unsigned int(16) extent_count;
+                stream.write_u16(1)?;
+                item.mdat_offset_locations.push(stream.offset());
+                // unsigned int(offset_size*8) extent_offset;
+                stream.write_u32(0)?;
+                let extent_length = if item.samples.is_empty() {
+                    u32_from_usize(item.metadata_payload.len())?
+                } else {
+                    u32_from_usize(item.samples[0].data.len())?
+                };
+                // unsigned int(length_size*8) extent_length;
+                stream.write_u32(extent_length)?;
+            }
+        }
+
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_iinf(stream: &mut OStream, items: &Vec<&mut Item>) -> AvifResult<()> {
+        stream.start_full_box("iinf", (0, 0))?;
+
+        // unsigned int(16) entry_count;
+        stream.write_u16(u16_from_usize(items.len())?)?;
+
+        for item in items {
+            let flags = if item.hidden_image { 1 } else { 0 };
+            stream.start_full_box("infe", (2, flags))?;
+            // unsigned int(16) item_ID;
+            stream.write_u16(item.id)?;
+            // unsigned int(16) item_protection_index;
+            stream.write_u16(0)?;
+            // unsigned int(32) item_type;
+            stream.write_string(&item.item_type)?;
+            // utf8string item_name;
+            stream.write_string_with_nul(&item.infe_name)?;
+            match item.item_type.as_str() {
+                "mime" => {
+                    // utf8string content_type;
+                    stream.write_string_with_nul(&item.infe_content_type)?
+                    // utf8string content_encoding; //optional
+                }
+                "uri " => {
+                    // utf8string item_uri_type;
+                    return Err(AvifError::NotImplemented);
+                }
+                _ => {}
+            }
+            stream.finish_box()?;
+        }
+
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_iref(&self, stream: &mut OStream) -> AvifResult<()> {
+        let mut box_started = false;
+        for item in &self.items {
+            let dimg_item_ids: Vec<_> = self
+                .items
+                .iter()
+                .filter(|dimg_item| dimg_item.dimg_from_id.unwrap_or_default() == item.id)
+                .map(|dimg_item| dimg_item.id)
+                .collect();
+            if !dimg_item_ids.is_empty() {
+                if !box_started {
+                    stream.start_full_box("iref", (0, 0))?;
+                    box_started = true;
+                }
+                stream.start_box("dimg")?;
+                // unsigned int(16) from_item_ID;
+                stream.write_u16(item.id)?;
+                // unsigned int(16) reference_count;
+                stream.write_u16(u16_from_usize(dimg_item_ids.len())?)?;
+                for dimg_item_id in dimg_item_ids {
+                    // unsigned int(16) to_item_ID;
+                    stream.write_u16(dimg_item_id)?;
+                }
+                stream.finish_box()?;
+            }
+            if let Some(iref_to_id) = item.iref_to_id {
+                if !box_started {
+                    stream.start_full_box("iref", (0, 0))?;
+                    box_started = true;
+                }
+                stream.start_box(item.iref_type.as_ref().unwrap().as_str())?;
+                // unsigned int(16) from_item_ID;
+                stream.write_u16(item.id)?;
+                // unsigned int(16) reference_count;
+                stream.write_u16(1)?;
+                // unsigned int(16) to_item_ID;
+                stream.write_u16(iref_to_id)?;
+                stream.finish_box()?;
+            }
+        }
+        if box_started {
+            stream.finish_box()?;
+        }
+        Ok(())
+    }
+
+    pub(crate) fn write_grpl(&mut self, stream: &mut OStream) -> AvifResult<()> {
+        if self.alternative_item_ids.is_empty() {
+            return Ok(());
+        }
+        stream.start_box("grpl")?;
+
+        stream.start_full_box("altr", (0, 0))?;
+        // Section 8.18.3.3 of ISO 14496-12 (ISOBMFF) says:
+        //   group_id is a non-negative integer assigned to the particular grouping that shall not
+        //   be equal to any group_id value of any other EntityToGroupBox, any item_ID value of the
+        //   hierarchy level (file, movie. or track) that contains the GroupsListBox, or any
+        //   track_ID value (when theGroupsListBox is contained in the file level).
+        let group_id = (self.items.iter().map(|item| item.id).max().unwrap_or(0) as u32) + 1;
+        stream.write_u32(group_id)?;
+        stream.write_u32(u32_from_usize(self.alternative_item_ids.len())?)?;
+        for item_id in self.alternative_item_ids.iter() {
+            stream.write_u32((*item_id).into())?;
+        }
+        stream.finish_box()?;
+        // end of altr
+
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_iprp(&mut self, stream: &mut OStream) -> AvifResult<()> {
+        stream.start_box("iprp")?;
+        // ipco
+        stream.start_box("ipco")?;
+        let mut property_streams = Vec::new();
+        for item in &mut self.items {
+            item.get_property_streams(
+                &self.image_metadata,
+                if item.is_tmap() {
+                    &self.alt_image_metadata
+                } else if item.category == Category::Gainmap {
+                    &self.gainmap_image_metadata
+                } else {
+                    &self.image_metadata
+                },
+                &mut property_streams,
+            )?;
+        }
+        // Deduplicate the property streams.
+        let mut property_index_map = Vec::new();
+        let mut last_written_property_index = 0u8;
+        for i in 0..property_streams.len() {
+            let current_data = &property_streams[i].data;
+            match property_streams[0..i]
+                .iter()
+                .position(|x| x.data == *current_data)
+            {
+                Some(property_index) => {
+                    // A duplicate stream was already written. Simply store the index of that
+                    // stream.
+                    property_index_map.push(property_index_map[property_index]);
+                }
+                None => {
+                    // No duplicate streams were found. Write this stream and store its index.
+                    stream.write_slice(current_data)?;
+                    last_written_property_index += 1;
+                    property_index_map.push(last_written_property_index);
+                }
+            }
+        }
+        stream.finish_box()?;
+        // end of ipco
+
+        // ipma
+        stream.start_full_box("ipma", (0, 0))?;
+        let entry_count = u32_from_usize(
+            self.items
+                .iter()
+                .filter(|&item| !item.associations.is_empty())
+                .count(),
+        )?;
+        // unsigned int(32) entry_count;
+        stream.write_u32(entry_count)?;
+        for item in &self.items {
+            if item.associations.is_empty() {
+                continue;
+            }
+            // unsigned int(16) item_ID;
+            stream.write_u16(item.id)?;
+            // unsigned int(8) association_count;
+            stream.write_u8(u8_from_usize(item.associations.len())?)?;
+            for (property_index, essential) in &item.associations {
+                // bit(1) essential;
+                stream.write_bits(*essential as u8, 1)?;
+                // property_index_map is 0-indexed whereas the index stored in item.associations is
+                // 1-indexed.
+                let index = property_index_map[*property_index as usize - 1];
+                if index >= (1 << 7) {
+                    return Err(AvifError::UnknownError("".into()));
+                }
+                // unsigned int(7) property_index;
+                stream.write_bits(index, 7)?;
+            }
+        }
+        stream.finish_box()?;
+        // end of ipma
+
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_mvhd(
+        &mut self,
+        stream: &mut OStream,
+        duration: u64,
+        timestamp: u64,
+    ) -> AvifResult<()> {
+        stream.start_full_box("mvhd", (1, 0))?;
+        // unsigned int(64) creation_time;
+        stream.write_u64(timestamp)?;
+        // unsigned int(64) modification_time;
+        stream.write_u64(timestamp)?;
+        // unsigned int(32) timescale;
+        stream.write_u32(u32_from_u64(self.settings.timescale)?)?;
+        // unsigned int(64) duration;
+        stream.write_u64(duration)?;
+        // template int(32) rate = 0x00010000; // typically 1.0
+        stream.write_u32(0x00010000)?;
+        // template int(16) volume = 0x0100; // typically, full volume
+        stream.write_u16(0x0100)?;
+        // const bit(16) reserved = 0;
+        stream.write_u16(0)?;
+        // const unsigned int(32)[2] reserved = 0;
+        stream.write_u32(0)?;
+        stream.write_u32(0)?;
+        // template int(32)[9] matrix
+        stream.write_slice(&UNITY_MATRIX)?;
+        // bit(32)[6] pre_defined = 0;
+        for _ in 0..6 {
+            stream.write_u32(0)?;
+        }
+        // unsigned int(32) next_track_ID;
+        stream.write_u32(u32_from_usize(self.items.len())?)?;
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_track_meta(&mut self, stream: &mut OStream) -> AvifResult<()> {
+        let mut metadata_items: Vec<_> =
+            self.items.iter_mut().filter(|x| x.is_metadata()).collect();
+        if metadata_items.is_empty() {
+            return Ok(());
+        }
+        stream.start_full_box("meta", (0, 0))?;
+        write_hdlr(stream, "pict")?;
+        Self::write_iloc(stream, &mut metadata_items)?;
+        Self::write_iinf(stream, &metadata_items)?;
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_tracks(
+        &mut self,
+        stream: &mut OStream,
+        duration: u64,
+        timestamp: u64,
+    ) -> AvifResult<()> {
+        for index in 0..self.items.len() {
+            let item = &self.items[index];
+            if item.samples.is_empty() {
+                continue;
+            }
+            stream.start_box("trak")?;
+            item.write_tkhd(stream, &self.image_metadata, duration, timestamp)?;
+            item.write_tref(stream)?;
+            // TODO: write edts box.
+            if item.category == Category::Color {
+                self.write_track_meta(stream)?;
+            }
+            let item = &self.items[index];
+            // mdia
+            {
+                stream.start_box("mdia")?;
+                // mdhd
+                {
+                    stream.start_full_box("mdhd", (1, 0))?;
+                    // unsigned int(64) creation_time;
+                    stream.write_u64(timestamp)?;
+                    // unsigned int(64) modification_time;
+                    stream.write_u64(timestamp)?;
+                    // unsigned int(32) timescale;
+                    stream.write_u32(u32_from_u64(self.settings.timescale)?)?;
+                    // unsigned int(64) duration;
+                    stream.write_u64(duration)?;
+                    // bit(1) pad = 0; unsigned int(5)[3] language; ("und")
+                    stream.write_u16(21956)?;
+                    // unsigned int(16) pre_defined = 0;
+                    stream.write_u16(0)?;
+                    stream.finish_box()?;
+                }
+                write_hdlr(
+                    stream,
+                    if item.category == Category::Alpha { "auxv" } else { "pict" },
+                )?;
+                // minf
+                {
+                    stream.start_box("minf")?;
+                    item.write_vmhd(stream)?;
+                    item.write_dinf(stream)?;
+                    let item_mut = &mut self.items[index];
+                    item_mut.write_stbl(
+                        stream,
+                        &self.image_metadata,
+                        &self.duration_in_timescales,
+                    )?;
+                    stream.finish_box()?;
+                }
+                stream.finish_box()?;
+            }
+            stream.finish_box()?;
+        }
+        Ok(())
+    }
+
+    pub(crate) fn write_mdat(&self, stream: &mut OStream) -> AvifResult<()> {
+        stream.start_box("mdat")?;
+        let mut layered_item_ids = [Vec::new(), Vec::new()];
+        // Use multiple passes to pack the items in the following order:
+        //   * Pass 0: metadata (Exif/XMP/gain map metadata)
+        //   * Pass 1: alpha, gain map image (AV1)
+        //   * Pass 2: all other item data (AV1 color)
+        //
+        // See here for the discussion on alpha coming before color:
+        // https://github.com/AOMediaCodec/libavif/issues/287
+        //
+        // Exif and XMP are packed first as they're required to be fully available by
+        // Decoder::parse() before it returns AVIF_RESULT_OK, unless ignore_xmp and ignore_exif are
+        // enabled.
+        for pass in 0..=2 {
+            for item in &self.items {
+                if pass == 0
+                    && item.item_type != "mime"
+                    && item.item_type != "Exif"
+                    && item.item_type != "tmap"
+                {
+                    continue;
+                }
+                if pass == 1 && !matches!(item.category, Category::Alpha | Category::Gainmap) {
+                    continue;
+                }
+                if pass == 2 && item.category != Category::Color {
+                    continue;
+                }
+                if self.settings.extra_layer_count > 0 && !item.samples.is_empty() {
+                    if item.category == Category::Color {
+                        layered_item_ids[1].push(item.id);
+                    } else if item.category == Category::Alpha {
+                        layered_item_ids[0].push(item.id);
+                    }
+                    continue;
+                }
+
+                let chunk_offset = stream.offset();
+                // TODO: alpha, gainmap, dedupe, etc.
+                if !item.samples.is_empty() {
+                    for sample in &item.samples {
+                        stream.write_slice(&sample.data)?;
+                    }
+                } else if !item.metadata_payload.is_empty() {
+                    stream.write_slice(&item.metadata_payload)?;
+                } else {
+                    // TODO: empty item, ignore or error?
+                }
+                for mdat_offset_location in &item.mdat_offset_locations {
+                    stream.write_u32_at_offset(
+                        u32_from_usize(chunk_offset)?,
+                        *mdat_offset_location,
+                    )?;
+                }
+            }
+        }
+        // TODO: simplify this code.
+        for layered_item_id in &layered_item_ids {
+            if layered_item_id.is_empty() {
+                continue;
+            }
+            let mut layer_index = 0;
+            loop {
+                let mut has_more_samples = false;
+                for item_id in layered_item_id {
+                    let item = &self.items[*item_id as usize - 1];
+
+                    if item.samples.len() <= layer_index {
+                        // Already written all samples for this item.
+                        continue;
+                    } else if item.samples.len() > layer_index + 1 {
+                        has_more_samples = true;
+                    }
+
+                    let chunk_offset = stream.offset();
+                    stream.write_slice(&item.samples[layer_index].data)?;
+                    stream.write_u32_at_offset(
+                        u32_from_usize(chunk_offset)?,
+                        item.mdat_offset_locations[layer_index],
+                    )?;
+                }
+                layer_index += 1;
+                if !has_more_samples {
+                    break;
+                }
+            }
+        }
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_meta(&mut self, stream: &mut OStream) -> AvifResult<()> {
+        stream.start_full_box("meta", (0, 0))?;
+        write_hdlr(stream, "pict")?;
+        write_pitm(stream, self.primary_item_id)?;
+        let mut items_ref: Vec<_> = self.items.iter_mut().collect();
+        Self::write_iloc(stream, &mut items_ref)?;
+        Self::write_iinf(stream, &items_ref)?;
+        self.write_iref(stream)?;
+        self.write_iprp(stream)?;
+        self.write_grpl(stream)?;
+        stream.finish_box()
+    }
+
+    pub(crate) fn write_moov(&mut self, stream: &mut OStream) -> AvifResult<()> {
+        if !self.is_sequence() {
+            return Ok(());
+        }
+        let frames_duration_in_timescales = self
+            .duration_in_timescales
+            .iter()
+            .try_fold(0u64, |acc, &x| acc.checked_add(x))
+            .ok_or(AvifError::UnknownError("".into()))?;
+        let timestamp: u64 = SystemTime::now()
+            .duration_since(UNIX_EPOCH)
+            .unwrap()
+            .as_secs();
+        // TODO: duration_in_timescales should account for loop count.
+        stream.start_box("moov")?;
+        self.write_mvhd(stream, frames_duration_in_timescales, timestamp)?;
+        self.write_tracks(stream, frames_duration_in_timescales, timestamp)?;
+        stream.finish_box()
+    }
+}
diff --git a/src/gainmap.rs b/src/gainmap.rs
new file mode 100644
index 0000000..cce85ff
--- /dev/null
+++ b/src/gainmap.rs
@@ -0,0 +1,145 @@
+// Copyright 2024 Google LLC
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
+use crate::image::YuvRange;
+use crate::utils::*;
+use crate::*;
+
+#[derive(Clone, Debug, Default, PartialEq)]
+pub struct GainMapMetadata {
+    pub min: [Fraction; 3],
+    pub max: [Fraction; 3],
+    pub gamma: [UFraction; 3],
+    pub base_offset: [Fraction; 3],
+    pub alternate_offset: [Fraction; 3],
+    pub base_hdr_headroom: UFraction,
+    pub alternate_hdr_headroom: UFraction,
+    pub use_base_color_space: bool,
+}
+
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
+
+    #[cfg(feature = "encoder")]
+    fn identical_channels(&self) -> bool {
+        self.min[0] == self.min[1]
+            && self.min[0] == self.min[2]
+            && self.max[0] == self.max[1]
+            && self.max[0] == self.max[2]
+            && self.gamma[0] == self.gamma[1]
+            && self.gamma[0] == self.gamma[2]
+            && self.base_offset[0] == self.base_offset[1]
+            && self.base_offset[0] == self.base_offset[2]
+            && self.alternate_offset[0] == self.alternate_offset[1]
+            && self.alternate_offset[0] == self.alternate_offset[2]
+    }
+
+    #[cfg(feature = "encoder")]
+    pub(crate) fn channel_count(&self) -> u8 {
+        if self.identical_channels() {
+            1
+        } else {
+            3
+        }
+    }
+}
+
+#[derive(Default)]
+pub struct GainMap {
+    pub image: Image,
+    pub metadata: GainMapMetadata,
+
+    pub alt_icc: Vec<u8>,
+    pub alt_color_primaries: ColorPrimaries,
+    pub alt_transfer_characteristics: TransferCharacteristics,
+    pub alt_matrix_coefficients: MatrixCoefficients,
+    pub alt_yuv_range: YuvRange,
+
+    pub alt_plane_count: u8,
+    pub alt_plane_depth: u8,
+
+    pub alt_clli: ContentLightLevelInformation,
+}
+
+impl PartialEq for GainMap {
+    fn eq(&self, other: &Self) -> bool {
+        self.metadata == other.metadata
+            && self.alt_icc == other.alt_icc
+            && self.alt_color_primaries == other.alt_color_primaries
+            && self.alt_transfer_characteristics == other.alt_transfer_characteristics
+            && self.alt_matrix_coefficients == other.alt_matrix_coefficients
+            && self.alt_yuv_range == other.alt_yuv_range
+            && self.alt_plane_count == other.alt_plane_count
+            && self.alt_plane_depth == other.alt_plane_depth
+            && self.alt_clli == other.alt_clli
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    #[cfg(feature = "encoder")]
+    use super::*;
+
+    #[test]
+    #[cfg(feature = "encoder")]
+    fn identical_channels() {
+        let mut metadata = GainMapMetadata::default();
+        assert!(metadata.identical_channels());
+        assert_eq!(metadata.channel_count(), 1);
+        for i in 0..3 {
+            metadata = GainMapMetadata::default();
+            metadata.min[i] = Fraction(1, 2);
+            assert!(!metadata.identical_channels());
+            assert_eq!(metadata.channel_count(), 3);
+        }
+        for i in 0..3 {
+            metadata = GainMapMetadata::default();
+            metadata.max[i] = Fraction(1, 2);
+            assert!(!metadata.identical_channels());
+            assert_eq!(metadata.channel_count(), 3);
+        }
+        for i in 0..3 {
+            metadata = GainMapMetadata::default();
+            metadata.gamma[i] = UFraction(1, 2);
+            assert!(!metadata.identical_channels());
+            assert_eq!(metadata.channel_count(), 3);
+        }
+        for i in 0..3 {
+            metadata = GainMapMetadata::default();
+            metadata.base_offset[i] = Fraction(1, 2);
+            assert!(!metadata.identical_channels());
+            assert_eq!(metadata.channel_count(), 3);
+        }
+        for i in 0..3 {
+            metadata = GainMapMetadata::default();
+            metadata.alternate_offset[i] = Fraction(1, 2);
+            assert!(!metadata.identical_channels());
+            assert_eq!(metadata.channel_count(), 3);
+        }
+    }
+}
diff --git a/src/image.rs b/src/image.rs
index a7edf63..88e5216 100644
--- a/src/image.rs
+++ b/src/image.rs
@@ -14,11 +14,11 @@
 
 use crate::decoder::tile::TileInfo;
 use crate::decoder::ProgressiveState;
-use crate::internal_utils::pixels::*;
 use crate::internal_utils::*;
 use crate::parser::mp4box::CodecConfiguration;
 use crate::reformat::coeffs::*;
 use crate::utils::clap::CleanAperture;
+use crate::utils::pixels::*;
 use crate::*;
 
 #[derive(Clone, Copy, Debug, PartialEq)]
@@ -143,8 +143,12 @@ impl Image {
         }
     }
 
+    pub(crate) fn is_supported_depth(depth: u8) -> bool {
+        matches!(depth, 8 | 10 | 12 | 16)
+    }
+
     pub(crate) fn depth_valid(&self) -> bool {
-        matches!(self.depth, 8 | 10 | 12 | 16)
+        Self::is_supported_depth(self.depth)
     }
 
     pub fn max_channel(&self) -> u16 {
@@ -175,7 +179,9 @@ impl Image {
         self.width == other.width && self.height == other.height && self.depth == other.depth
     }
 
-    fn has_same_cicp(&self, other: &Image) -> bool {
+    // TODO: b/392112497 - remove this annotation once encoder feature is enabled by default.
+    #[allow(unused)]
+    pub(crate) fn has_same_cicp(&self, other: &Image) -> bool {
         self.depth == other.depth
             && self.yuv_format == other.yuv_format
             && self.yuv_range == other.yuv_range
@@ -185,7 +191,7 @@ impl Image {
             && self.matrix_coefficients == other.matrix_coefficients
     }
 
-    pub(crate) fn has_same_properties_and_cicp(&self, other: &Image) -> bool {
+    pub fn has_same_properties_and_cicp(&self, other: &Image) -> bool {
         self.has_same_properties(other) && self.has_same_cicp(other)
     }
 
@@ -197,12 +203,12 @@ impl Image {
                 | PixelFormat::AndroidP010
                 | PixelFormat::AndroidNv12
                 | PixelFormat::AndroidNv21 => self.width as usize,
-                PixelFormat::Yuv420 | PixelFormat::Yuv422 => (self.width as usize + 1) / 2,
+                PixelFormat::Yuv420 | PixelFormat::Yuv422 => (self.width as usize).div_ceil(2),
                 PixelFormat::None | PixelFormat::Yuv400 => 0,
             },
             Plane::V => match self.yuv_format {
                 PixelFormat::Yuv444 => self.width as usize,
-                PixelFormat::Yuv420 | PixelFormat::Yuv422 => (self.width as usize + 1) / 2,
+                PixelFormat::Yuv420 | PixelFormat::Yuv422 => (self.width as usize).div_ceil(2),
                 PixelFormat::None
                 | PixelFormat::Yuv400
                 | PixelFormat::AndroidP010
@@ -220,12 +226,12 @@ impl Image {
                 PixelFormat::Yuv420
                 | PixelFormat::AndroidP010
                 | PixelFormat::AndroidNv12
-                | PixelFormat::AndroidNv21 => (self.height as usize + 1) / 2,
+                | PixelFormat::AndroidNv21 => (self.height as usize).div_ceil(2),
                 PixelFormat::None | PixelFormat::Yuv400 => 0,
             },
             Plane::V => match self.yuv_format {
                 PixelFormat::Yuv444 | PixelFormat::Yuv422 => self.height as usize,
-                PixelFormat::Yuv420 => (self.height as usize + 1) / 2,
+                PixelFormat::Yuv420 => (self.height as usize).div_ceil(2),
                 PixelFormat::None
                 | PixelFormat::Yuv400
                 | PixelFormat::AndroidP010
@@ -249,10 +255,17 @@ impl Image {
 
     pub fn row(&self, plane: Plane, row: u32) -> AvifResult<&[u8]> {
         let plane_data = self.plane_data(plane).ok_or(AvifError::NoContent)?;
-        let start = checked_mul!(row, plane_data.row_bytes)?;
+        let row_bytes = plane_data.row_bytes;
+        let start = checked_mul!(row, row_bytes)?;
         self.planes[plane.as_usize()]
             .unwrap_ref()
-            .slice(start, plane_data.row_bytes)
+            .slice(start, row_bytes)
+    }
+
+    // Same as row() but only returns `width` pixels (extra row padding is excluded).
+    pub fn row_exact(&self, plane: Plane, row: u32) -> AvifResult<&[u8]> {
+        let width = self.width(plane);
+        Ok(&self.row(plane, row)?[0..width])
     }
 
     pub fn row_mut(&mut self, plane: Plane, row: u32) -> AvifResult<&mut [u8]> {
@@ -264,6 +277,12 @@ impl Image {
             .slice_mut(start, row_bytes)
     }
 
+    // Same as row_mut() but only returns `width` pixels (extra row padding is excluded).
+    pub fn row_exact_mut(&mut self, plane: Plane, row: u32) -> AvifResult<&mut [u8]> {
+        let width = self.width(plane);
+        Ok(&mut self.row_mut(plane, row)?[0..width])
+    }
+
     pub fn row16(&self, plane: Plane, row: u32) -> AvifResult<&[u16]> {
         let plane_data = self.plane_data(plane).ok_or(AvifError::NoContent)?;
         let row_bytes = plane_data.row_bytes / 2;
@@ -273,6 +292,12 @@ impl Image {
             .slice16(start, row_bytes)
     }
 
+    // Same as row16() but only returns `width` pixels (extra row padding is excluded).
+    pub fn row16_exact(&self, plane: Plane, row: u32) -> AvifResult<&[u16]> {
+        let width = self.width(plane);
+        Ok(&self.row16(plane, row)?[0..width])
+    }
+
     pub fn row16_mut(&mut self, plane: Plane, row: u32) -> AvifResult<&mut [u16]> {
         let plane_data = self.plane_data(plane).ok_or(AvifError::NoContent)?;
         let row_bytes = plane_data.row_bytes / 2;
@@ -282,6 +307,12 @@ impl Image {
             .slice16_mut(start, row_bytes)
     }
 
+    // Same as row16_mut() but only returns `width` pixels (extra row padding is excluded).
+    pub fn row16_exact_mut(&mut self, plane: Plane, row: u32) -> AvifResult<&mut [u16]> {
+        let width = self.width(plane);
+        Ok(&mut self.row16_mut(plane, row)?[0..width])
+    }
+
     pub(crate) fn row_generic(&self, plane: Plane, row: u32) -> AvifResult<PlaneRow> {
         Ok(if self.depth == 8 {
             PlaneRow::Depth8(self.row(plane, row)?)
@@ -290,6 +321,50 @@ impl Image {
         })
     }
 
+    #[cfg(feature = "libyuv")]
+    pub(crate) fn plane_ptrs(&self) -> [*const u8; 4] {
+        ALL_PLANES.map(|x| {
+            if self.has_plane(x) {
+                self.planes[x.as_usize()].unwrap_ref().ptr()
+            } else {
+                std::ptr::null()
+            }
+        })
+    }
+
+    #[cfg(feature = "libyuv")]
+    pub(crate) fn plane_ptrs_mut(&mut self) -> [*mut u8; 4] {
+        ALL_PLANES.map(|x| {
+            if self.has_plane(x) {
+                self.planes[x.as_usize()].unwrap_mut().ptr_mut()
+            } else {
+                std::ptr::null_mut()
+            }
+        })
+    }
+
+    #[cfg(feature = "libyuv")]
+    pub(crate) fn plane16_ptrs(&self) -> [*const u16; 4] {
+        ALL_PLANES.map(|x| {
+            if self.has_plane(x) {
+                self.planes[x.as_usize()].unwrap_ref().ptr16()
+            } else {
+                std::ptr::null()
+            }
+        })
+    }
+
+    #[cfg(feature = "libyuv")]
+    pub(crate) fn plane_row_bytes(&self) -> AvifResult<[i32; 4]> {
+        Ok(ALL_PLANES.map(|x| {
+            if self.has_plane(x) {
+                i32_from_u32(self.plane_data(x).unwrap().row_bytes).unwrap()
+            } else {
+                0
+            }
+        }))
+    }
+
     #[cfg(any(feature = "dav1d", feature = "libgav1"))]
     pub(crate) fn clear_chroma_planes(&mut self) {
         for plane in [Plane::U, Plane::V] {
@@ -331,7 +406,7 @@ impl Image {
         Ok(())
     }
 
-    pub(crate) fn allocate_planes(&mut self, category: Category) -> AvifResult<()> {
+    pub fn allocate_planes(&mut self, category: Category) -> AvifResult<()> {
         self.allocate_planes_with_default_values(category, [0, 0, 0, self.max_channel()])
     }
 
@@ -555,4 +630,27 @@ impl Image {
             ((rgba[3] as f32) / 65535.0 * max_channel).round() as u16,
         ]
     }
+
+    #[cfg(feature = "encoder")]
+    pub(crate) fn is_opaque(&self) -> bool {
+        if let Some(plane_data) = self.plane_data(Plane::A) {
+            let opaque_value = self.max_channel();
+            if self.depth == 8 {
+                for y in 0..plane_data.height {
+                    let row = &self.row(Plane::A, y).unwrap()[..plane_data.width as usize];
+                    if !row.iter().all(|pixel| *pixel == opaque_value as u8) {
+                        return false;
+                    }
+                }
+            } else {
+                for y in 0..plane_data.height {
+                    let row = &self.row16(Plane::A, y).unwrap()[..plane_data.width as usize];
+                    if !row.iter().all(|pixel| *pixel == opaque_value) {
+                        return false;
+                    }
+                }
+            }
+        }
+        true
+    }
 }
diff --git a/src/internal_utils/mod.rs b/src/internal_utils/mod.rs
index fa18899..291e088 100644
--- a/src/internal_utils/mod.rs
+++ b/src/internal_utils/mod.rs
@@ -13,7 +13,6 @@
 // limitations under the License.
 
 pub mod io;
-pub mod pixels;
 pub mod stream;
 
 use crate::parser::mp4box::*;
@@ -23,110 +22,6 @@ use crate::*;
 use std::num::NonZero;
 use std::ops::Range;
 
-// 'clap' fractions do not follow this pattern: both numerators and denominators
-// are used as i32, but they are signalled as u32 according to the specification
-// as of 2024. This may be fixed in later versions of the specification, see
-// https://github.com/AOMediaCodec/libavif/pull/1749#discussion_r1391612932.
-#[derive(Clone, Copy, Debug, Default)]
-pub struct IFraction(pub i32, pub i32);
-
-impl TryFrom<UFraction> for IFraction {
-    type Error = AvifError;
-
-    fn try_from(uf: UFraction) -> AvifResult<IFraction> {
-        Ok(IFraction(uf.0 as i32, i32_from_u32(uf.1)?))
-    }
-}
-
-impl IFraction {
-    fn gcd(a: i32, b: i32) -> i32 {
-        let mut a = if a < 0 { -a as i64 } else { a as i64 };
-        let mut b = if b < 0 { -b as i64 } else { b as i64 };
-        while b != 0 {
-            let r = a % b;
-            a = b;
-            b = r;
-        }
-        a as i32
-    }
-
-    pub(crate) fn simplified(n: i32, d: i32) -> Self {
-        let mut fraction = IFraction(n, d);
-        fraction.simplify();
-        fraction
-    }
-
-    pub(crate) fn simplify(&mut self) {
-        let gcd = Self::gcd(self.0, self.1);
-        if gcd > 1 {
-            self.0 /= gcd;
-            self.1 /= gcd;
-        }
-    }
-
-    pub(crate) fn get_i32(&self) -> i32 {
-        assert!(self.1 != 0);
-        self.0 / self.1
-    }
-
-    pub(crate) fn get_u32(&self) -> AvifResult<u32> {
-        u32_from_i32(self.get_i32())
-    }
-
-    pub(crate) fn is_integer(&self) -> bool {
-        self.0 % self.1 == 0
-    }
-
-    fn common_denominator(&mut self, val: &mut IFraction) -> AvifResult<()> {
-        self.simplify();
-        if self.1 == val.1 {
-            return Ok(());
-        }
-        let self_d = self.1;
-        self.0 = self
-            .0
-            .checked_mul(val.1)
-            .ok_or(AvifError::UnknownError("".into()))?;
-        self.1 = self
-            .1
-            .checked_mul(val.1)
-            .ok_or(AvifError::UnknownError("".into()))?;
-        val.0 = val
-            .0
-            .checked_mul(self_d)
-            .ok_or(AvifError::UnknownError("".into()))?;
-        val.1 = val
-            .1
-            .checked_mul(self_d)
-            .ok_or(AvifError::UnknownError("".into()))?;
-        Ok(())
-    }
-
-    pub(crate) fn add(&mut self, val: &IFraction) -> AvifResult<()> {
-        let mut val = *val;
-        val.simplify();
-        self.common_denominator(&mut val)?;
-        self.0 = self
-            .0
-            .checked_add(val.0)
-            .ok_or(AvifError::UnknownError("".into()))?;
-        self.simplify();
-        Ok(())
-    }
-
-    pub(crate) fn sub(&mut self, val: &IFraction) -> AvifResult<()> {
-        let mut val = *val;
-        val.simplify();
-        self.common_denominator(&mut val)?;
-        self.0 = self
-            .0
-            .checked_sub(val.0)
-            .ok_or(AvifError::UnknownError("".into()))?;
-        self.simplify();
-        Ok(())
-    }
-}
-
 macro_rules! conversion_function {
     ($func:ident, $to: ident, $from:ty) => {
         pub(crate) fn $func(value: $from) -> AvifResult<$to> {
@@ -138,13 +33,21 @@ macro_rules! conversion_function {
 conversion_function!(usize_from_u64, usize, u64);
 conversion_function!(usize_from_u32, usize, u32);
 conversion_function!(usize_from_u16, usize, u16);
+#[cfg(feature = "sample_transform")]
+conversion_function!(usize_from_u8, usize, u8);
 #[cfg(feature = "android_mediacodec")]
 conversion_function!(usize_from_isize, usize, isize);
 conversion_function!(u64_from_usize, u64, usize);
 conversion_function!(u32_from_usize, u32, usize);
+#[cfg(feature = "encoder")]
+conversion_function!(u16_from_usize, u16, usize);
+#[cfg(feature = "encoder")]
+conversion_function!(u8_from_usize, u8, usize);
 conversion_function!(u32_from_u64, u32, u64);
 conversion_function!(u32_from_i32, u32, i32);
 conversion_function!(i32_from_u32, i32, u32);
+#[cfg(feature = "encoder")]
+conversion_function!(u16_from_u32, u16, u32);
 #[cfg(feature = "android_mediacodec")]
 conversion_function!(isize_from_i32, isize, i32);
 #[cfg(any(feature = "capi", feature = "android_mediacodec"))]
@@ -152,6 +55,7 @@ conversion_function!(isize_from_u32, isize, u32);
 conversion_function!(isize_from_usize, isize, usize);
 #[cfg(feature = "android_mediacodec")]
 conversion_function!(i32_from_usize, i32, usize);
+conversion_function!(i32_from_i64, i32, i64);
 
 macro_rules! clamp_function {
     ($func:ident, $type:ty) => {
@@ -174,7 +78,7 @@ clamp_function!(clamp_i32, i32);
 macro_rules! round2_function {
     ($func:ident, $type:ty) => {
         pub(crate) fn $func(value: $type) -> $type {
-            if value % 2 == 0 {
+            if value % 2 == 0 || value == <$type>::MAX {
                 value
             } else {
                 value + 1
@@ -290,7 +194,7 @@ pub(crate) fn create_vec_exact<T>(size: usize) -> AvifResult<Vec<T>> {
 pub(crate) fn assert_eq_f32_array(a: &[f32], b: &[f32]) {
     assert_eq!(a.len(), b.len());
     for i in 0..a.len() {
-        assert!((a[i] - b[i]).abs() <= std::f32::EPSILON);
+        assert!((a[i] - b[i]).abs() <= f32::EPSILON);
     }
 }
 
@@ -350,10 +254,13 @@ pub(crate) fn validate_grid_image_dimensions(image: &Image, grid: &Grid) -> Avif
     //   - when the images are in the 4:2:0 chroma sampling format both the horizontal and
     //     vertical tile offsets and widths, and the output width and height, shall be even
     //     numbers.
-    if ((image.yuv_format == PixelFormat::Yuv420 || image.yuv_format == PixelFormat::Yuv422)
-        && (grid.width % 2 != 0 || image.width % 2 != 0))
-        || (image.yuv_format == PixelFormat::Yuv420
-            && (grid.height % 2 != 0 || image.height % 2 != 0))
+    // Do not perform this validation when HEIC is enabled. There are several HEIC files in the
+    // wild which do not conform to this constraint.
+    if !cfg!(feature = "heic")
+        && (((image.yuv_format == PixelFormat::Yuv420 || image.yuv_format == PixelFormat::Yuv422)
+            && (grid.width % 2 != 0 || image.width % 2 != 0))
+            || (image.yuv_format == PixelFormat::Yuv420
+                && (grid.height % 2 != 0 || image.height % 2 != 0)))
     {
         return Err(AvifError::InvalidImageGrid(format!(
             "Grid image width ({}) or height ({}) or tile width ({}) or height ({}) shall be \
@@ -364,3 +271,71 @@ pub(crate) fn validate_grid_image_dimensions(image: &Image, grid: &Grid) -> Avif
     }
     Ok(())
 }
+
+#[cfg(feature = "encoder")]
+pub(crate) fn floor_log2(n: u32) -> u32 {
+    if n == 0 {
+        0
+    } else {
+        31 - n.leading_zeros()
+    }
+}
+
+#[derive(Clone, Copy, Debug)]
+pub struct PointerSlice<T> {
+    ptr: *mut [T],
+}
+
+impl<T> PointerSlice<T> {
+    /// # Safety
+    /// `ptr` must live at least as long as the struct, and not be accessed other than through this
+    /// struct. It must point to a memory region of at least `size` elements.
+    pub unsafe fn create(ptr: *mut T, size: usize) -> AvifResult<Self> {
+        if ptr.is_null() || size == 0 {
+            return Err(AvifError::NoContent);
+        }
+        // Ensure that size does not exceed isize::MAX.
+        let _ = isize_from_usize(size)?;
+        Ok(Self {
+            ptr: unsafe { std::slice::from_raw_parts_mut(ptr, size) },
+        })
+    }
+
+    fn slice_impl(&self) -> &[T] {
+        // SAFETY: We only construct this with `ptr` which is valid at least as long as this struct
+        // is alive, and ro/mut borrows of the whole struct to access the inner slice, which makes
+        // our access appropriately exclusive.
+        unsafe { &(*self.ptr) }
+    }
+
+    fn slice_impl_mut(&mut self) -> &mut [T] {
+        // SAFETY: We only construct this with `ptr` which is valid at least as long as this struct
+        // is alive, and ro/mut borrows of the whole struct to access the inner slice, which makes
+        // our access appropriately exclusive.
+        unsafe { &mut (*self.ptr) }
+    }
+
+    pub fn slice(&self, range: Range<usize>) -> AvifResult<&[T]> {
+        let data = self.slice_impl();
+        check_slice_range(data.len(), &range)?;
+        Ok(&data[range])
+    }
+
+    pub fn slice_mut(&mut self, range: Range<usize>) -> AvifResult<&mut [T]> {
+        let data = self.slice_impl_mut();
+        check_slice_range(data.len(), &range)?;
+        Ok(&mut data[range])
+    }
+
+    pub fn ptr(&self) -> *const T {
+        self.slice_impl().as_ptr()
+    }
+
+    pub fn ptr_mut(&mut self) -> *mut T {
+        self.slice_impl_mut().as_mut_ptr()
+    }
+
+    pub fn is_empty(&self) -> bool {
+        self.slice_impl().is_empty()
+    }
+}
diff --git a/src/internal_utils/stream.rs b/src/internal_utils/stream.rs
index 673553f..6668564 100644
--- a/src/internal_utils/stream.rs
+++ b/src/internal_utils/stream.rs
@@ -169,14 +169,24 @@ impl IStream<'_> {
         Ok(u64::from_be_bytes(self.get_slice(8)?.try_into().unwrap()))
     }
 
-    pub(crate) fn read_i32(&mut self) -> AvifResult<i32> {
-        Ok(self.read_u32()? as i32)
+    #[cfg(feature = "sample_transform")]
+    pub(crate) fn read_i8(&mut self) -> AvifResult<i8> {
+        Ok(self.read_u8()? as i8)
     }
 
     pub(crate) fn read_i16(&mut self) -> AvifResult<i16> {
         Ok(self.read_u16()? as i16)
     }
 
+    pub(crate) fn read_i32(&mut self) -> AvifResult<i32> {
+        Ok(self.read_u32()? as i32)
+    }
+
+    #[cfg(feature = "sample_transform")]
+    pub(crate) fn read_i64(&mut self) -> AvifResult<i64> {
+        Ok(self.read_u64()? as i64)
+    }
+
     pub(crate) fn skip_u32(&mut self) -> AvifResult<()> {
         self.skip(4)
     }
@@ -278,6 +288,181 @@ impl IStream<'_> {
     }
 }
 
+#[cfg(feature = "encoder")]
+#[derive(Default)]
+pub struct OStream {
+    pub data: Vec<u8>,
+    partial: Option<(u8, u8)>,
+    box_marker_offsets: Vec<usize>,
+}
+
+#[cfg(feature = "encoder")]
+#[allow(dead_code)]
+impl OStream {
+    pub(crate) fn offset(&self) -> usize {
+        assert!(self.partial.is_none());
+        self.data.len()
+    }
+
+    pub(crate) fn try_reserve(&mut self, size: usize) -> AvifResult<()> {
+        self.data.try_reserve(size).or(Err(AvifError::OutOfMemory))
+    }
+
+    pub(crate) fn write_bits(&mut self, value: u8, num_bits: u8) -> AvifResult<()> {
+        if num_bits == 0 || num_bits >= 8 {
+            return Err(AvifError::UnknownError("".into()));
+        }
+        let (bits, offset) = self.partial.unwrap_or((0, 0));
+        if offset + num_bits > 8 {
+            // write_bits cannot overlap multiple bytes.
+            return Err(AvifError::UnknownError("".into()));
+        }
+        let value_at_offset = (value & ((1 << num_bits) - 1)) << (8 - offset - num_bits);
+        let bits = bits | value_at_offset;
+        if offset + num_bits == 8 {
+            self.partial = None;
+            self.write_u8(bits)?;
+        } else {
+            self.partial = Some((bits, offset + num_bits));
+        }
+        Ok(())
+    }
+
+    pub(crate) fn write_bool(&mut self, value: bool) -> AvifResult<()> {
+        self.write_bits(if value { 1 } else { 0 }, 1)
+    }
+
+    pub(crate) fn write_u8(&mut self, value: u8) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        self.try_reserve(1)?;
+        self.data.push(value);
+        Ok(())
+    }
+
+    pub(crate) fn write_u16(&mut self, value: u16) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        self.try_reserve(2)?;
+        self.data.extend_from_slice(&value.to_be_bytes());
+        Ok(())
+    }
+
+    pub(crate) fn write_u24(&mut self, value: u32) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        if value > 0xFFFFFF {
+            return Err(AvifError::InvalidArgument);
+        }
+        self.try_reserve(3)?;
+        self.data.extend_from_slice(&value.to_be_bytes()[1..]);
+        Ok(())
+    }
+
+    pub(crate) fn write_u32(&mut self, value: u32) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        self.try_reserve(4)?;
+        self.data.extend_from_slice(&value.to_be_bytes());
+        Ok(())
+    }
+
+    pub(crate) fn write_u32_at_offset(&mut self, value: u32, offset: usize) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        let range = offset..offset + 4;
+        check_slice_range(self.data.len(), &range)?;
+        self.data[range].copy_from_slice(&value.to_be_bytes());
+        Ok(())
+    }
+
+    pub(crate) fn write_u64(&mut self, value: u64) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        self.try_reserve(8)?;
+        self.data.extend_from_slice(&value.to_be_bytes());
+        Ok(())
+    }
+
+    pub(crate) fn write_str(&mut self, value: &str) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        let bytes = value.as_bytes();
+        self.try_reserve(bytes.len())?;
+        self.data.extend_from_slice(bytes);
+        Ok(())
+    }
+
+    pub(crate) fn write_string(&mut self, value: &String) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        let bytes = value.as_bytes();
+        self.try_reserve(bytes.len())?;
+        self.data.extend_from_slice(bytes);
+        Ok(())
+    }
+
+    pub(crate) fn write_string_with_nul(&mut self, value: &String) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        self.write_string(value)?;
+        self.write_u8(0)?;
+        Ok(())
+    }
+
+    pub(crate) fn write_slice(&mut self, data: &[u8]) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        self.try_reserve(data.len())?;
+        self.data.extend_from_slice(data);
+        Ok(())
+    }
+
+    pub(crate) fn write_ufraction(&mut self, value: UFraction) -> AvifResult<()> {
+        self.write_u32(value.0)?;
+        self.write_u32(value.1)
+    }
+
+    fn write_i32(&mut self, value: i32) -> AvifResult<()> {
+        self.write_u32(value as u32)
+    }
+
+    pub(crate) fn write_fraction(&mut self, value: Fraction) -> AvifResult<()> {
+        self.write_i32(value.0)?;
+        self.write_u32(value.1)
+    }
+
+    fn start_box_impl(
+        &mut self,
+        box_type: &str,
+        version_and_flags: Option<(u8, u32)>,
+    ) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        self.box_marker_offsets.push(self.offset());
+        // 4 bytes for size to be filled out later.
+        self.write_u32(0)?;
+        self.write_str(box_type)?;
+        if let Some((version, flags)) = version_and_flags {
+            self.write_u8(version)?;
+            self.write_u24(flags)?;
+        }
+        Ok(())
+    }
+
+    pub(crate) fn start_box(&mut self, box_type: &str) -> AvifResult<()> {
+        self.start_box_impl(box_type, None)
+    }
+
+    pub(crate) fn start_full_box(
+        &mut self,
+        box_type: &str,
+        version_and_flags: (u8, u32),
+    ) -> AvifResult<()> {
+        self.start_box_impl(box_type, Some(version_and_flags))
+    }
+
+    pub(crate) fn finish_box(&mut self) -> AvifResult<()> {
+        assert!(self.partial.is_none());
+        let offset = self
+            .box_marker_offsets
+            .pop()
+            .ok_or(AvifError::UnknownError("".into()))?;
+        let box_size = u32_from_usize(checked_sub!(self.offset(), offset)?)?;
+        self.write_u32_at_offset(box_size, offset)?;
+        Ok(())
+    }
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
@@ -327,4 +512,121 @@ mod tests {
         ));
         assert_eq!(IStream::create(bytes).read_c_string(), Ok("abcd".into()));
     }
+
+    #[cfg(feature = "encoder")]
+    #[test]
+    fn write_bits() {
+        let mut stream = OStream::default();
+        assert_eq!(stream.write_bits(1, 1), Ok(()));
+        assert_eq!(stream.data.len(), 0);
+        assert_eq!(stream.write_bits(2, 3), Ok(()));
+        assert_eq!(stream.data.len(), 0);
+        assert_eq!(stream.write_bits(1, 4), Ok(()));
+        assert_eq!(stream.data.len(), 1);
+        assert_eq!(stream.write_bits(1, 4), Ok(()));
+        assert_eq!(stream.data.len(), 1);
+        assert_eq!(stream.write_bits(4, 4), Ok(()));
+        assert_eq!(stream.data.len(), 2);
+        assert_eq!(stream.write_u8(0xCC), Ok(()));
+        assert_eq!(stream.data.len(), 3);
+        assert_eq!(stream.data, vec![0xA1, 0x14, 0xCC]);
+        assert!(stream.write_bits(1, 10).is_err());
+
+        // Write 5 bits.
+        assert_eq!(stream.write_bits(5, 5), Ok(()));
+        // Now, trying to write 4 bits should fail since it overlaps more than 1 byte.
+        assert!(stream.write_bits(5, 4).is_err());
+    }
+
+    #[cfg(feature = "encoder")]
+    #[test]
+    fn write_box() {
+        let mut stream = OStream::default();
+        assert!(stream.start_box("ftyp").is_ok());
+        assert!(stream.write_u8(20).is_ok());
+        assert!(stream.start_full_box("abcd", (0, 1)).is_ok());
+        assert!(stream.write_u32(25).is_ok());
+        assert!(stream.finish_box().is_ok());
+        assert!(stream.finish_box().is_ok());
+        assert!(stream.finish_box().is_err());
+    }
+
+    #[cfg(feature = "encoder")]
+    #[test]
+    fn write() {
+        let mut stream = OStream::default();
+
+        let u8value = 10;
+        assert!(stream.write_u8(u8value).is_ok());
+        assert_eq!(stream.offset(), 1);
+        assert_eq!(stream.data[stream.data.len() - 1..], u8value.to_be_bytes());
+
+        let u16value = 1000;
+        assert!(stream.write_u16(u16value).is_ok());
+        assert_eq!(stream.offset(), 3);
+        assert_eq!(stream.data[stream.data.len() - 2..], u16value.to_be_bytes());
+
+        let invalid_u24value = 0xFFFFFF1;
+        assert!(stream.write_u24(invalid_u24value).is_err());
+        let u24value = 12345678;
+        assert!(stream.write_u24(u24value).is_ok());
+        assert_eq!(stream.offset(), 6);
+        assert_eq!(
+            stream.data[stream.data.len() - 3..],
+            u24value.to_be_bytes()[1..]
+        );
+
+        let u32value = 4294901760;
+        assert!(stream.write_u32(u32value).is_ok());
+        assert_eq!(stream.offset(), 10);
+        assert_eq!(stream.data[stream.data.len() - 4..], u32value.to_be_bytes());
+
+        assert!(stream.write_u32_at_offset(u32value, 4).is_ok());
+        assert_eq!(stream.offset(), 10);
+        assert_eq!(stream.data[4..8], u32value.to_be_bytes());
+        assert!(stream.write_u32_at_offset(u32value, 20).is_err()); // invalid offset.
+
+        let u64value = 0xFFFFFFFFFF;
+        assert!(stream.write_u64(u64value).is_ok());
+        assert_eq!(stream.offset(), 18);
+        assert_eq!(stream.data[stream.data.len() - 8..], u64value.to_be_bytes());
+
+        let strvalue = "hello";
+        assert!(stream.write_str(strvalue).is_ok());
+        assert_eq!(stream.offset(), 23);
+        assert_eq!(&stream.data[stream.data.len() - 5..], strvalue.as_bytes());
+
+        let stringvalue = String::from("hello");
+        assert!(stream.write_string(&stringvalue).is_ok());
+        assert_eq!(stream.offset(), 28);
+        assert_eq!(
+            &stream.data[stream.data.len() - 5..],
+            stringvalue.as_bytes()
+        );
+
+        assert!(stream.write_string_with_nul(&stringvalue).is_ok());
+        assert_eq!(stream.offset(), 34);
+        assert_eq!(
+            &stream.data[stream.data.len() - 6..stream.data.len() - 1],
+            stringvalue.as_bytes()
+        );
+        assert_eq!(*stream.data.last().unwrap(), 0);
+
+        let data = [100, 200, 50, 25];
+        assert!(stream.write_slice(&data[..]).is_ok());
+        assert_eq!(stream.offset(), 38);
+        assert_eq!(&stream.data[stream.data.len() - 4..], &data[..]);
+
+        let ufraction = UFraction(10, 20);
+        assert!(stream.write_ufraction(ufraction).is_ok());
+        assert_eq!(stream.offset(), 46);
+        assert_eq!(
+            stream.data[stream.data.len() - 8..stream.data.len() - 4],
+            ufraction.0.to_be_bytes()
+        );
+        assert_eq!(
+            stream.data[stream.data.len() - 4..],
+            ufraction.1.to_be_bytes()
+        );
+    }
 }
diff --git a/src/lib.rs b/src/lib.rs
index 2aa5d78..086c9a7 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -19,6 +19,9 @@
 mod internal_utils;
 
 pub mod decoder;
+#[cfg(feature = "encoder")]
+pub mod encoder;
+pub mod gainmap;
 pub mod image;
 pub mod reformat;
 pub mod utils;
@@ -414,13 +417,24 @@ pub(crate) use checked_mul;
 pub(crate) use checked_sub;
 
 #[derive(Clone, Copy, Debug, Default)]
-pub struct Grid {
+pub(crate) struct Grid {
     pub rows: u32,
     pub columns: u32,
     pub width: u32,
     pub height: u32,
 }
 
+#[cfg(feature = "encoder")]
+impl Grid {
+    pub(crate) fn is_last_column(&self, index: u32) -> bool {
+        (index + 1) % self.columns == 0
+    }
+
+    pub(crate) fn is_last_row(&self, index: u32) -> bool {
+        index >= (self.columns * (self.rows - 1))
+    }
+}
+
 #[derive(Clone, Copy, Debug, Default, PartialEq)]
 pub enum Category {
     #[default]
@@ -432,21 +446,22 @@ pub enum Category {
 impl Category {
     const COUNT: usize = 3;
     const ALL: [Category; Category::COUNT] = [Self::Color, Self::Alpha, Self::Gainmap];
-    const ALL_USIZE: [usize; Category::COUNT] = [0, 1, 2];
 
-    pub(crate) fn usize(self) -> usize {
+    pub fn planes(&self) -> &[Plane] {
         match self {
-            Category::Color => 0,
-            Category::Alpha => 1,
-            Category::Gainmap => 2,
+            Category::Alpha => &A_PLANE,
+            _ => &YUV_PLANES,
         }
     }
 
-    pub fn planes(&self) -> &[Plane] {
+    #[cfg(feature = "encoder")]
+    pub(crate) fn infe_name(&self) -> String {
         match self {
-            Category::Alpha => &A_PLANE,
-            _ => &YUV_PLANES,
+            Self::Color => "Color",
+            Self::Alpha => "Alpha",
+            Self::Gainmap => "GMap",
         }
+        .into()
     }
 }
 
diff --git a/src/parser/exif.rs b/src/parser/exif.rs
index e6a54ce..b51ecb1 100644
--- a/src/parser/exif.rs
+++ b/src/parser/exif.rs
@@ -13,9 +13,10 @@
 // limitations under the License.
 
 use crate::internal_utils::stream::*;
+use crate::parser::mp4box::BoxSize;
 use crate::*;
 
-fn parse_exif_tiff_header_offset(stream: &mut IStream) -> AvifResult<u32> {
+pub(crate) fn parse_exif_tiff_header_offset(stream: &mut IStream) -> AvifResult<u32> {
     const TIFF_HEADER_BE: u32 = 0x4D4D002A; // MM0* (read as a big endian u32)
     const TIFF_HEADER_LE: u32 = 0x49492A00; // II*0 (read as a big endian u32)
     let mut expected_offset: u32 = 0;
@@ -26,8 +27,9 @@ fn parse_exif_tiff_header_offset(stream: &mut IStream) -> AvifResult<u32> {
             stream.rewind(4)?;
             return Ok(expected_offset);
         }
-        checked_decr!(size, 4);
-        checked_incr!(expected_offset, 4);
+        stream.rewind(3)?;
+        checked_decr!(size, 1);
+        checked_incr!(expected_offset, 1);
     }
     // Could not find the TIFF header.
     Err(AvifError::InvalidExifPayload)
@@ -37,9 +39,12 @@ pub(crate) fn parse(stream: &mut IStream) -> AvifResult<()> {
     // unsigned int(32) exif_tiff_header_offset;
     let offset = stream.read_u32().or(Err(AvifError::InvalidExifPayload))?;
 
-    let expected_offset = parse_exif_tiff_header_offset(stream)?;
+    let bytes_left = stream.bytes_left()?;
+    let mut sub_stream = stream.sub_stream(&BoxSize::FixedSize(bytes_left))?;
+    let expected_offset = parse_exif_tiff_header_offset(&mut sub_stream)?;
     if offset != expected_offset {
         return Err(AvifError::InvalidExifPayload);
     }
+    stream.rewind(bytes_left)?;
     Ok(())
 }
diff --git a/src/parser/mp4box.rs b/src/parser/mp4box.rs
index b8c4d4b..d533fcb 100644
--- a/src/parser/mp4box.rs
+++ b/src/parser/mp4box.rs
@@ -12,10 +12,13 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crate::decoder::gainmap::GainMapMetadata;
+use crate::decoder::tile::SampleTransform;
+#[cfg(feature = "sample_transform")]
+use crate::decoder::tile::*;
 use crate::decoder::track::*;
 use crate::decoder::Extent;
 use crate::decoder::GenericIO;
+use crate::gainmap::GainMapMetadata;
 use crate::image::YuvRange;
 use crate::image::MAX_PLANE_COUNT;
 use crate::internal_utils::stream::*;
@@ -155,6 +158,7 @@ pub struct Av1CodecConfiguration {
 #[derive(Clone, Debug, Default, PartialEq)]
 pub struct HevcCodecConfiguration {
     pub bitdepth: u8,
+    pub pixel_format: PixelFormat,
     pub nal_length_size: u8,
     pub vps: Vec<u8>,
     pub sps: Vec<u8>,
@@ -188,13 +192,7 @@ impl CodecConfiguration {
                     PixelFormat::Yuv444
                 }
             }
-            Self::Hevc(_) => {
-                // It is okay to always return Yuv420 here since that is the only format that
-                // android_mediacodec returns.
-                // TODO: b/370549923 - Identify the correct YUV subsampling type from the codec
-                // configuration data.
-                PixelFormat::Yuv420
-            }
+            Self::Hevc(config) => config.pixel_format,
         }
     }
 
@@ -332,6 +330,12 @@ pub struct ItemReference {
     pub index: u32, // 0-based index of the reference within the iref type.
 }
 
+#[derive(Debug)]
+pub struct EntityGroup {
+    pub grouping_type: String,
+    pub entity_ids: Vec<u32>,
+}
+
 #[derive(Debug, Default)]
 pub struct MetaBox {
     pub iinf: Vec<ItemInfo>,
@@ -340,6 +344,7 @@ pub struct MetaBox {
     pub iprp: ItemPropertyBox,
     pub iref: Vec<ItemReference>,
     pub idat: Vec<u8>,
+    pub grpl: Vec<EntityGroup>,
 }
 
 #[derive(Debug)]
@@ -610,6 +615,9 @@ fn parse_pixi(stream: &mut IStream) -> AvifResult<ItemProperty> {
             return Err(AvifError::UnsupportedDepth);
         }
     }
+    if !Image::is_supported_depth(*pixi.plane_depths.last().unwrap()) {
+        return Err(AvifError::UnsupportedDepth);
+    }
     Ok(ItemProperty::PixelInformation(pixi))
 }
 
@@ -716,9 +724,18 @@ fn parse_hvcC(stream: &mut IStream) -> AvifResult<ItemProperty> {
     // bit(6) reserved = '111111'b;
     // unsigned int(2) parallelismType;
     // bit(6) reserved = '111111'b;
+    bits.skip(2 + 1 + 5 + 32 + 48 + 8 + 4 + 12 + 6 + 2 + 6)?;
     // unsigned int(2) chroma_format_idc;
+    let pixel_format = match bits.read(2)? {
+        // Defined in ISO/IEC 23008-2 Section 6.2.
+        0 => PixelFormat::Yuv400,
+        1 => PixelFormat::Yuv420,
+        2 => PixelFormat::Yuv422,
+        // The only other possible value is 3 since we are reading only 2 bits.
+        _ => PixelFormat::Yuv444,
+    };
     // bit(5) reserved = '11111'b;
-    bits.skip(2 + 1 + 5 + 32 + 48 + 8 + 4 + 12 + 6 + 2 + 6 + 2 + 5)?;
+    bits.skip(5)?;
     // unsigned int(3) bit_depth_luma_minus8;
     let bitdepth = bits.read(3)? as u8 + 8;
     // bit(5) reserved = '11111'b;
@@ -760,6 +777,7 @@ fn parse_hvcC(stream: &mut IStream) -> AvifResult<ItemProperty> {
     Ok(ItemProperty::CodecConfiguration(CodecConfiguration::Hevc(
         HevcCodecConfiguration {
             bitdepth,
+            pixel_format,
             nal_length_size,
             vps,
             pps,
@@ -983,10 +1001,6 @@ fn parse_ipma(stream: &mut IStream) -> AvifResult<Vec<ItemPropertyAssociation>>
     let mut ipma: Vec<ItemPropertyAssociation> = create_vec_exact(usize_from_u32(entry_count)?)?;
     for _i in 0..entry_count {
         let mut entry = ItemPropertyAssociation::default();
-        // ISO/IEC 23008-12, First edition, 2017-12, Section 9.3.1:
-        //   Each ItemPropertyAssociation box shall be ordered by increasing item_ID, and there
-        //   shall be at most one association box for each item_ID, in any
-        //   ItemPropertyAssociation box.
         if version < 1 {
             // unsigned int(16) item_ID;
             entry.item_id = stream.read_u16()? as u32;
@@ -1001,6 +1015,10 @@ fn parse_ipma(stream: &mut IStream) -> AvifResult<Vec<ItemPropertyAssociation>>
             )));
         }
         if !ipma.is_empty() {
+            // ISO/IEC 23008-12, First edition, 2017-12, Section 9.3.1:
+            //   Each ItemPropertyAssociation box shall be ordered by increasing item_ID, and there
+            //   shall be at most one association box for each item_ID, in any
+            //   ItemPropertyAssociation box.
             let previous_item_id = ipma.last().unwrap().item_id;
             if entry.item_id <= previous_item_id {
                 return Err(AvifError::BmffParseFailed(
@@ -1109,12 +1127,6 @@ fn parse_infe(stream: &mut IStream) -> AvifResult<ItemInfo> {
 fn parse_iinf(stream: &mut IStream) -> AvifResult<Vec<ItemInfo>> {
     // Section 8.11.6.2 of ISO/IEC 14496-12.
     let (version, _flags) = stream.read_version_and_flags()?;
-    if version > 1 {
-        return Err(AvifError::BmffParseFailed(format!(
-            "Unsupported version {} in iinf box",
-            version
-        )));
-    }
     let entry_count: u32 = if version == 0 {
         // unsigned int(16) entry_count;
         stream.read_u16()? as u32
@@ -1194,6 +1206,27 @@ fn parse_idat(stream: &mut IStream) -> AvifResult<Vec<u8>> {
     Ok(idat)
 }
 
+fn parse_grpl(stream: &mut IStream) -> AvifResult<Vec<EntityGroup>> {
+    let mut grpl: Vec<EntityGroup> = Vec::new();
+    while stream.has_bytes_left()? {
+        let header = parse_header(stream, /*top_level=*/ false)?;
+        let (_version, _flags) = stream.read_version_and_flags()?;
+        // unsigned int(32) group_id;
+        stream.skip_u32()?;
+        let num_entities_in_group = stream.read_u32()?;
+        let mut entity_ids: Vec<u32> = create_vec_exact(usize_from_u32(num_entities_in_group)?)?;
+        for _ in 0..num_entities_in_group {
+            let entity_id = stream.read_u32()?;
+            entity_ids.push(entity_id);
+        }
+        grpl.push(EntityGroup {
+            grouping_type: header.box_type.clone(),
+            entity_ids,
+        })
+    }
+    Ok(grpl)
+}
+
 fn parse_meta(stream: &mut IStream) -> AvifResult<MetaBox> {
     // Section 8.11.1.2 of ISO/IEC 14496-12.
     let (_version, _flags) = stream.read_and_enforce_version_and_flags(0)?;
@@ -1225,7 +1258,7 @@ fn parse_meta(stream: &mut IStream) -> AvifResult<MetaBox> {
     while stream.has_bytes_left()? {
         let header = parse_header(stream, /*top_level=*/ false)?;
         match header.box_type.as_str() {
-            "hdlr" | "iloc" | "pitm" | "iprp" | "iinf" | "iref" | "idat" => {
+            "hdlr" | "iloc" | "pitm" | "iprp" | "iinf" | "iref" | "idat" | "grpl" => {
                 if boxes_seen.contains(&header.box_type) {
                     return Err(AvifError::BmffParseFailed(format!(
                         "duplicate {} box in meta.",
@@ -1244,6 +1277,7 @@ fn parse_meta(stream: &mut IStream) -> AvifResult<MetaBox> {
             "iinf" => meta.iinf = parse_iinf(&mut sub_stream)?,
             "iref" => meta.iref = parse_iref(&mut sub_stream)?,
             "idat" => meta.idat = parse_idat(&mut sub_stream)?,
+            "grpl" => meta.grpl = parse_grpl(&mut sub_stream)?,
             _ => {}
         }
     }
@@ -1940,19 +1974,19 @@ pub(crate) fn peek_compatible_file_type(data: &[u8]) -> AvifResult<bool> {
     Ok(ftyp.is_avif())
 }
 
-pub(crate) fn parse_tmap(stream: &mut IStream) -> AvifResult<Option<GainMapMetadata>> {
+pub(crate) fn parse_tmap(stream: &mut IStream) -> AvifResult<GainMapMetadata> {
     // Experimental, not yet specified.
 
     // unsigned int(8) version = 0;
     let version = stream.read_u8()?;
     if version != 0 {
-        return Ok(None); // Unsupported version.
+        return Err(AvifError::NotImplemented);
     }
     // unsigned int(16) minimum_version;
     let minimum_version = stream.read_u16()?;
     let supported_version = 0;
     if minimum_version > supported_version {
-        return Ok(None); // Unsupported version.
+        return Err(AvifError::NotImplemented);
     }
     // unsigned int(16) writer_version;
     let writer_version = stream.read_u16()?;
@@ -2005,7 +2039,79 @@ pub(crate) fn parse_tmap(stream: &mut IStream) -> AvifResult<Option<GainMapMetad
         ));
     }
     metadata.is_valid()?;
-    Ok(Some(metadata))
+    Ok(metadata)
+}
+
+#[cfg(feature = "sample_transform")]
+pub(crate) fn parse_sato(stream: &mut IStream, num_inputs: usize) -> AvifResult<SampleTransform> {
+    let mut bits = stream.sub_bit_stream(1)?;
+    // unsigned int(2) version = 0;
+    let version = bits.read(2)?;
+    if version != 0 {
+        return Err(AvifError::NotImplemented);
+    }
+    // unsigned int(4) flags;
+    let _reserved = bits.read(4)?;
+    // unsigned int(2) bit_depth; // Enum signaling signed 8, 16, 32 or 64-bit.
+    let bit_depth = 1 << (bits.read(2)? + 3);
+    let bytes = bit_depth / 8;
+
+    // unsigned int(8) token_count;
+    let token_count = stream.read_u8()?;
+    let mut tokens = create_vec_exact(usize_from_u8(token_count)?)?;
+    for _i in 0..token_count {
+        let token = stream.read_u8()?;
+        let sato_token = match token {
+            0 => {
+                let constant = match bytes {
+                    1 => stream.read_i8()? as i64,
+                    2 => stream.read_i16()? as i64,
+                    4 => stream.read_i32()? as i64,
+                    8 => stream.read_i64()?,
+                    _ => unreachable!(),
+                };
+                SampleTransformToken::Constant(constant)
+            }
+            1..=32 => {
+                let source_item_idx = usize_from_u8(token - 1)?;
+                if source_item_idx >= num_inputs {
+                    return Err(AvifError::InvalidImageGrid(
+                        "invalid item reference in sato".into(),
+                    ));
+                }
+                SampleTransformToken::ImageItem(source_item_idx)
+            }
+            64 => SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Negation),
+            65 => SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Absolute),
+            66 => SampleTransformToken::UnaryOp(SampleTransformUnaryOp::Not),
+            67 => SampleTransformToken::UnaryOp(SampleTransformUnaryOp::BSR),
+            128 => SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Sum),
+            129 => SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Difference),
+            130 => SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Product),
+            131 => SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Quotient),
+            132 => SampleTransformToken::BinaryOp(SampleTransformBinaryOp::And),
+            133 => SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Or),
+            134 => SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Xor),
+            135 => SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Pow),
+            136 => SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Min),
+            137 => SampleTransformToken::BinaryOp(SampleTransformBinaryOp::Max),
+            _ => return Err(AvifError::InvalidImageGrid("invalid token in sato".into())),
+        };
+        tokens.push(sato_token);
+    }
+
+    if stream.has_bytes_left()? {
+        return Err(AvifError::InvalidImageGrid(
+            "found unknown extra bytes in the sato box".into(),
+        ));
+    }
+
+    SampleTransform::create_from(bit_depth, num_inputs, tokens)
+}
+
+#[cfg(not(feature = "sample_transform"))]
+pub(crate) fn parse_sato(_stream: &mut IStream, _num_inputs: usize) -> AvifResult<SampleTransform> {
+    Ok(SampleTransform::default())
 }
 
 #[cfg(test)]
diff --git a/src/parser/obu.rs b/src/parser/obu.rs
index 1f2fa25..1c495b9 100644
--- a/src/parser/obu.rs
+++ b/src/parser/obu.rs
@@ -31,13 +31,11 @@ pub struct Av1SequenceHeader {
     max_height: u32,
     bit_depth: u8,
     yuv_format: PixelFormat,
-    #[allow(unused)]
-    chroma_sample_position: ChromaSamplePosition,
     pub color_primaries: ColorPrimaries,
     pub transfer_characteristics: TransferCharacteristics,
     pub matrix_coefficients: MatrixCoefficients,
     pub yuv_range: YuvRange,
-    config: Av1CodecConfiguration,
+    pub config: Av1CodecConfiguration,
 }
 
 impl Av1SequenceHeader {
@@ -251,7 +249,8 @@ impl Av1SequenceHeader {
                 _ => {} // Not reached.
             }
             if self.config.chroma_subsampling_x == 1 && self.config.chroma_subsampling_y == 1 {
-                self.config.chroma_sample_position = bits.read(2)?.into();
+                // chroma_sample_position.
+                bits.skip(2)?;
             }
         }
         // separate_uv_delta_q
diff --git a/src/reformat/alpha.rs b/src/reformat/alpha.rs
index 2dff10e..04ba53c 100644
--- a/src/reformat/alpha.rs
+++ b/src/reformat/alpha.rs
@@ -50,7 +50,7 @@ macro_rules! alpha_index_in_rgba_1010102 {
 
 impl rgb::Image {
     pub(crate) fn premultiply_alpha(&mut self) -> AvifResult<()> {
-        if self.pixels().is_null() || self.row_bytes == 0 {
+        if self.pixels_mut().is_null() || self.row_bytes == 0 {
             return Err(AvifError::ReformatFailed);
         }
         if !self.has_alpha() {
@@ -124,7 +124,7 @@ impl rgb::Image {
     }
 
     pub(crate) fn unpremultiply_alpha(&mut self) -> AvifResult<()> {
-        if self.pixels().is_null() || self.row_bytes == 0 {
+        if self.pixels_mut().is_null() || self.row_bytes == 0 {
             return Err(AvifError::ReformatFailed);
         }
         if !self.has_alpha() {
@@ -391,13 +391,109 @@ impl image::Image {
         }
         Ok(())
     }
+
+    pub(crate) fn import_alpha_from(&mut self, rgb: &rgb::Image) -> AvifResult<()> {
+        if !self.has_plane(Plane::A)
+            || !rgb.has_alpha()
+            || self.width != rgb.width
+            || self.height != rgb.height
+            || rgb.format == rgb::Format::Rgba1010102
+        {
+            return Err(AvifError::InvalidArgument);
+        }
+        let src_alpha_offset = rgb.format.alpha_offset();
+        let width = usize_from_u32(self.width)?;
+        if self.depth == rgb.depth {
+            if self.depth > 8 {
+                for y in 0..self.height {
+                    let dst_row = self.row16_mut(Plane::A, y)?;
+                    let src_row = rgb.row16(y)?;
+                    for x in 0..width {
+                        dst_row[x] = src_row[(x * 4) + src_alpha_offset];
+                    }
+                }
+                return Ok(());
+            }
+            for y in 0..self.height {
+                let dst_row = self.row_mut(Plane::A, y)?;
+                let src_row = rgb.row(y)?;
+                for x in 0..width {
+                    dst_row[x] = src_row[(x * 4) + src_alpha_offset];
+                }
+            }
+            return Ok(());
+        }
+        let max_channel = self.max_channel();
+        if self.depth > 8 {
+            if rgb.depth > 8 {
+                // u16 to u16 depth rescaling.
+                for y in 0..self.height {
+                    let dst_row = self.row16_mut(Plane::A, y)?;
+                    let src_row = rgb.row16(y)?;
+                    for x in 0..width {
+                        dst_row[x] = rgb::Image::rescale_alpha_value(
+                            src_row[(x * 4) + src_alpha_offset],
+                            rgb.max_channel_f(),
+                            max_channel,
+                        );
+                    }
+                }
+                return Ok(());
+            }
+            // u8 to u16 depth rescaling.
+            for y in 0..self.height {
+                let dst_row = self.row16_mut(Plane::A, y)?;
+                let src_row = rgb.row(y)?;
+                for x in 0..width {
+                    dst_row[x] = rgb::Image::rescale_alpha_value(
+                        src_row[(x * 4) + src_alpha_offset] as u16,
+                        rgb.max_channel_f(),
+                        max_channel,
+                    );
+                }
+            }
+            return Ok(());
+        }
+        // u16 to u8 depth rescaling.
+        for y in 0..self.height {
+            let dst_row = self.row_mut(Plane::A, y)?;
+            let src_row = rgb.row16(y)?;
+            for x in 0..width {
+                dst_row[x] = rgb::Image::rescale_alpha_value(
+                    src_row[(x * 4) + src_alpha_offset],
+                    rgb.max_channel_f(),
+                    max_channel,
+                ) as u8;
+            }
+        }
+        Ok(())
+    }
+
+    pub(crate) fn set_opaque(&mut self) -> AvifResult<()> {
+        if let Some(plane_data) = self.plane_data(Plane::A) {
+            let opaque_value = self.max_channel();
+            if self.depth == 8 {
+                for y in 0..plane_data.height {
+                    let row = &mut self.row_mut(Plane::A, y).unwrap()[..plane_data.width as usize];
+                    row.fill(opaque_value as u8);
+                }
+            } else {
+                for y in 0..plane_data.height {
+                    let row =
+                        &mut self.row16_mut(Plane::A, y).unwrap()[..plane_data.width as usize];
+                    row.fill(opaque_value);
+                }
+            }
+        }
+        Ok(())
+    }
 }
 
 #[cfg(test)]
 mod tests {
     use super::*;
 
-    use crate::internal_utils::pixels::*;
+    use crate::utils::pixels::*;
 
     use rand::Rng;
     use test_case::test_matrix;
@@ -443,6 +539,7 @@ mod tests {
         Ok(rgb)
     }
 
+    #[allow(clippy::zero_prefixed_literal)]
     #[test_matrix(20, 10, [8, 10, 12, 16], 0..4, [true, false])]
     fn fill_alpha(
         width: u32,
@@ -519,6 +616,7 @@ mod tests {
         assert_eq!(rgb::Image::rescale_alpha_value(4095, 4095.0, 1023), 1023);
     }
 
+    #[allow(clippy::zero_prefixed_literal)]
     #[test_matrix(20, 10, [8, 10, 12, 16], 0..4, [8, 10, 12], [true, false])]
     fn reformat_alpha(
         width: u32,
@@ -535,10 +633,12 @@ mod tests {
         let mut buffer: Vec<u8> = vec![];
         let mut rgb = rgb_image(width, height, rgb_depth, format, use_pointer, &mut buffer)?;
 
-        let mut image = image::Image::default();
-        image.width = width;
-        image.height = height;
-        image.depth = yuv_depth;
+        let mut image = image::Image {
+            width,
+            height,
+            depth: yuv_depth,
+            ..Default::default()
+        };
         image.allocate_planes(Category::Alpha)?;
 
         let mut rng = rand::thread_rng();
@@ -547,7 +647,7 @@ mod tests {
         if yuv_depth == 8 {
             for y in 0..height {
                 let row = image.row_mut(Plane::A, y)?;
-                for x in 0..width as usize {
+                for pixel in row.iter_mut().take(width as usize) {
                     let value = rng.gen_range(0..256) as u8;
                     if rgb.depth == 8 {
                         expected_values.push(value as u16);
@@ -558,13 +658,13 @@ mod tests {
                             rgb.max_channel(),
                         ));
                     }
-                    row[x] = value;
+                    *pixel = value;
                 }
             }
         } else {
             for y in 0..height {
                 let row = image.row16_mut(Plane::A, y)?;
-                for x in 0..width as usize {
+                for pixel in row.iter_mut().take(width as usize) {
                     let value = rng.gen_range(0..(1i32 << yuv_depth)) as u16;
                     if rgb.depth == yuv_depth {
                         expected_values.push(value);
@@ -575,7 +675,7 @@ mod tests {
                             rgb.max_channel(),
                         ));
                     }
-                    row[x] = value;
+                    *pixel = value;
                 }
             }
         }
@@ -630,10 +730,12 @@ mod tests {
             &mut buffer,
         )?;
 
-        let mut image = image::Image::default();
-        image.width = width;
-        image.height = height;
-        image.depth = yuv_depth;
+        let mut image = image::Image {
+            width,
+            height,
+            depth: yuv_depth,
+            ..Default::default()
+        };
         image.allocate_planes(Category::Alpha)?;
 
         let mut rng = rand::thread_rng();
@@ -641,19 +743,19 @@ mod tests {
         if yuv_depth == 8 {
             for y in 0..height {
                 let row = image.row_mut(Plane::A, y)?;
-                for x in 0..width as usize {
+                for pixel in row.iter_mut().take(width as usize) {
                     let value = rng.gen_range(0..256) as u8;
                     expected_values.push((value >> 6) as u16);
-                    row[x] = value;
+                    *pixel = value;
                 }
             }
         } else {
             for y in 0..height {
                 let row = image.row16_mut(Plane::A, y)?;
-                for x in 0..width as usize {
+                for pixel in row.iter_mut().take(width as usize) {
                     let value = rng.gen_range(0..(1i32 << yuv_depth)) as u16;
                     expected_values.push(value >> (yuv_depth - 2));
-                    row[x] = value;
+                    *pixel = value;
                 }
             }
         }
@@ -673,4 +775,92 @@ mod tests {
         }
         Ok(())
     }
+
+    #[allow(clippy::zero_prefixed_literal)]
+    #[test_matrix(20, 10, [8, 10, 12, 16], 0..4, [8, 10, 12])]
+    fn reformat_alpha_yuv_image(
+        width: u32,
+        height: u32,
+        rgb_depth: u8,
+        format_index: usize,
+        yuv_depth: u8,
+    ) -> AvifResult<()> {
+        let format = ALPHA_RGB_FORMATS[format_index];
+        let mut buffer: Vec<u8> = vec![];
+        let mut rgb = rgb_image(width, height, rgb_depth, format, false, &mut buffer)?;
+
+        let mut image = image::Image {
+            width,
+            height,
+            depth: yuv_depth,
+            ..Default::default()
+        };
+        image.allocate_planes(Category::Alpha)?;
+
+        let mut rng = rand::thread_rng();
+        let mut expected_values: Vec<u16> = Vec::new();
+        let rgb_max_channel_f = rgb.max_channel_f();
+        let rgb_channel_count = rgb.channel_count() as usize;
+        let rgb_pixel_width = width as usize * rgb_channel_count;
+        let rgb_alpha_offset = rgb.format.alpha_offset();
+        if rgb_depth == 8 {
+            for y in 0..height {
+                let row = &mut rgb.row_mut(y)?[..rgb_pixel_width];
+                for pixels in row.chunks_exact_mut(rgb_channel_count) {
+                    let value = rng.gen_range(0..256) as u8;
+                    if yuv_depth == 8 {
+                        expected_values.push(value as u16);
+                    } else {
+                        expected_values.push(rgb::Image::rescale_alpha_value(
+                            value as u16,
+                            rgb_max_channel_f,
+                            image.max_channel(),
+                        ));
+                    }
+                    pixels[rgb_alpha_offset] = value;
+                }
+            }
+        } else {
+            for y in 0..height {
+                let row = &mut rgb.row16_mut(y)?[..rgb_pixel_width];
+                for pixels in row.chunks_exact_mut(rgb_channel_count) {
+                    let value = rng.gen_range(0..(1i32 << yuv_depth)) as u16;
+                    if yuv_depth == rgb_depth {
+                        expected_values.push(value);
+                    } else {
+                        expected_values.push(rgb::Image::rescale_alpha_value(
+                            value as u16,
+                            rgb_max_channel_f,
+                            image.max_channel(),
+                        ));
+                    }
+                    pixels[rgb_alpha_offset] = value;
+                }
+            }
+        }
+
+        image.import_alpha_from(&rgb)?;
+
+        if yuv_depth == 8 {
+            for y in 0..height {
+                let row = image.row(Plane::A, y)?;
+                let start = (y * width) as usize;
+                let expected_values_u8: Vec<u8> = expected_values[start..start + width as usize]
+                    .iter()
+                    .map(|x| *x as u8)
+                    .collect();
+                assert_eq!(expected_values_u8, row[..width as usize]);
+            }
+        } else {
+            for y in 0..height {
+                let row = image.row16(Plane::A, y)?;
+                let start = (y * width) as usize;
+                assert_eq!(
+                    expected_values[start..start + width as usize],
+                    row[..width as usize]
+                );
+            }
+        }
+        Ok(())
+    }
 }
diff --git a/src/reformat/libyuv.rs b/src/reformat/libyuv.rs
index 8a1dc8b..dd12964 100644
--- a/src/reformat/libyuv.rs
+++ b/src/reformat/libyuv.rs
@@ -395,42 +395,9 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
     } else {
         FilterMode_kFilterNone
     };
-    let mut plane_u8: [*const u8; 4] = ALL_PLANES
-        .iter()
-        .map(|x| {
-            if image.has_plane(*x) {
-                image.planes[x.as_usize()].unwrap_ref().ptr()
-            } else {
-                std::ptr::null()
-            }
-        })
-        .collect::<Vec<*const u8>>()
-        .try_into()
-        .unwrap();
-    let plane_u16: [*const u16; 4] = ALL_PLANES
-        .iter()
-        .map(|x| {
-            if image.has_plane(*x) {
-                image.planes[x.as_usize()].unwrap_ref().ptr16()
-            } else {
-                std::ptr::null()
-            }
-        })
-        .collect::<Vec<*const u16>>()
-        .try_into()
-        .unwrap();
-    let mut plane_row_bytes: [i32; 4] = ALL_PLANES
-        .iter()
-        .map(|x| {
-            if image.has_plane(*x) {
-                i32_from_u32(image.plane_data(*x).unwrap().row_bytes).unwrap_or_default()
-            } else {
-                0
-            }
-        })
-        .collect::<Vec<i32>>()
-        .try_into()
-        .unwrap();
+    let mut plane_u8 = image.plane_ptrs();
+    let plane_u16 = image.plane16_ptrs();
+    let mut plane_row_bytes = image.plane_row_bytes()?;
     let rgb_row_bytes = i32_from_u32(rgb.row_bytes)?;
     let width = i32_from_u32(image.width)?;
     let height = i32_from_u32(image.height)?;
@@ -445,7 +412,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                     plane_row_bytes[0] / 2,
                     plane_u16[1],
                     plane_row_bytes[1] / 2,
-                    rgb.pixels(),
+                    rgb.pixels_mut(),
                     rgb_row_bytes,
                     matrix,
                     width,
@@ -455,9 +422,9 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                     // It is okay to use the same pointer as source and destination for this
                     // conversion.
                     func2(
-                        rgb.pixels(),
+                        rgb.pixels_mut(),
                         rgb_row_bytes,
-                        rgb.pixels(),
+                        rgb.pixels_mut(),
                         rgb_row_bytes,
                         width,
                         height,
@@ -474,7 +441,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                     plane_row_bytes[1] / 2,
                     plane_u16[2],
                     plane_row_bytes[2] / 2,
-                    rgb.pixels(),
+                    rgb.pixels_mut(),
                     rgb_row_bytes,
                     matrix,
                     width,
@@ -484,9 +451,9 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                     // It is okay to use the same pointer as source and destination for this
                     // conversion.
                     func2(
-                        rgb.pixels(),
+                        rgb.pixels_mut(),
                         rgb_row_bytes,
-                        rgb.pixels(),
+                        rgb.pixels_mut(),
                         rgb_row_bytes,
                         width,
                         height,
@@ -502,7 +469,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                 plane_row_bytes[u_plane_index] / 2,
                 plane_u16[v_plane_index],
                 plane_row_bytes[v_plane_index] / 2,
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 rgb_row_bytes,
                 matrix,
                 width,
@@ -518,7 +485,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                 plane_row_bytes[v_plane_index] / 2,
                 plane_u16[3],
                 plane_row_bytes[3] / 2,
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 rgb_row_bytes,
                 matrix,
                 width,
@@ -533,7 +500,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                 plane_row_bytes[u_plane_index] / 2,
                 plane_u16[v_plane_index],
                 plane_row_bytes[v_plane_index] / 2,
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 rgb_row_bytes,
                 matrix,
                 width,
@@ -548,7 +515,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                 plane_row_bytes[v_plane_index] / 2,
                 plane_u16[3],
                 plane_row_bytes[3] / 2,
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 rgb_row_bytes,
                 matrix,
                 width,
@@ -570,30 +537,8 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
         let mut image8 = image::Image::default();
         if image.depth > 8 {
             downshift_to_8bit(image, &mut image8, conversion_function.is_yuva())?;
-            plane_u8 = ALL_PLANES
-                .iter()
-                .map(|x| {
-                    if image8.has_plane(*x) {
-                        image8.planes[x.as_usize()].unwrap_ref().ptr()
-                    } else {
-                        std::ptr::null()
-                    }
-                })
-                .collect::<Vec<*const u8>>()
-                .try_into()
-                .unwrap();
-            plane_row_bytes = ALL_PLANES
-                .iter()
-                .map(|x| {
-                    if image8.has_plane(*x) {
-                        i32_from_u32(image8.plane_data(*x).unwrap().row_bytes).unwrap_or_default()
-                    } else {
-                        0
-                    }
-                })
-                .collect::<Vec<i32>>()
-                .try_into()
-                .unwrap();
+            plane_u8 = image8.plane_ptrs();
+            plane_row_bytes = image8.plane_row_bytes()?;
         }
         result = match conversion_function {
             ConversionFunction::NVToARGBMatrix(func) => func(
@@ -601,7 +546,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                 plane_row_bytes[0],
                 plane_u8[1],
                 plane_row_bytes[1],
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 rgb_row_bytes,
                 matrix,
                 width,
@@ -610,7 +555,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
             ConversionFunction::YUV400ToRGBMatrix(func) => func(
                 plane_u8[0],
                 plane_row_bytes[0],
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 rgb_row_bytes,
                 matrix,
                 width,
@@ -623,7 +568,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                 plane_row_bytes[u_plane_index],
                 plane_u8[v_plane_index],
                 plane_row_bytes[v_plane_index],
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 rgb_row_bytes,
                 matrix,
                 width,
@@ -639,7 +584,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                 plane_row_bytes[v_plane_index],
                 plane_u8[3],
                 plane_row_bytes[3],
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 rgb_row_bytes,
                 matrix,
                 width,
@@ -654,7 +599,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                 plane_row_bytes[u_plane_index],
                 plane_u8[v_plane_index],
                 plane_row_bytes[v_plane_index],
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 rgb_row_bytes,
                 matrix,
                 width,
@@ -669,7 +614,7 @@ pub(crate) fn yuv_to_rgb(image: &image::Image, rgb: &mut rgb::Image) -> AvifResu
                 plane_row_bytes[v_plane_index],
                 plane_u8[3],
                 plane_row_bytes[3],
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 rgb_row_bytes,
                 matrix,
                 width,
@@ -741,18 +686,18 @@ pub(crate) fn process_alpha(rgb: &mut rgb::Image, multiply: bool) -> AvifResult<
     let result = unsafe {
         if multiply {
             ARGBAttenuate(
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 i32_from_u32(rgb.row_bytes)?,
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 i32_from_u32(rgb.row_bytes)?,
                 i32_from_u32(rgb.width)?,
                 i32_from_u32(rgb.height)?,
             )
         } else {
             ARGBUnattenuate(
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 i32_from_u32(rgb.row_bytes)?,
-                rgb.pixels(),
+                rgb.pixels_mut(),
                 i32_from_u32(rgb.row_bytes)?,
                 i32_from_u32(rgb.width)?,
                 i32_from_u32(rgb.height)?,
@@ -769,9 +714,9 @@ pub(crate) fn process_alpha(rgb: &mut rgb::Image, multiply: bool) -> AvifResult<
 pub(crate) fn convert_to_half_float(rgb: &mut rgb::Image, scale: f32) -> AvifResult<()> {
     let res = unsafe {
         HalfFloatPlane(
-            rgb.pixels() as *const u16,
+            rgb.pixels_mut() as *const u16,
             i32_from_u32(rgb.row_bytes)?,
-            rgb.pixels() as *mut u16,
+            rgb.pixels_mut() as *mut u16,
             i32_from_u32(rgb.row_bytes)?,
             scale,
             i32_from_u32(rgb.width * rgb.channel_count())?,
@@ -784,3 +729,135 @@ pub(crate) fn convert_to_half_float(rgb: &mut rgb::Image, scale: f32) -> AvifRes
         Err(AvifError::InvalidArgument)
     }
 }
+
+#[rustfmt::skip]
+type RGBToY = unsafe extern "C" fn(*const u8, c_int, *mut u8, c_int, c_int, c_int) -> c_int;
+#[rustfmt::skip]
+type RGBToYUV = unsafe extern "C" fn(
+    *const u8, c_int, *mut u8, c_int, *mut u8, c_int, *mut u8, c_int, c_int, c_int,
+) -> c_int;
+
+#[derive(Debug)]
+enum RGBToYUVConversionFunction {
+    RGBToY(RGBToY),
+    RGBToYUV(RGBToYUV),
+}
+
+fn rgb_to_yuv_conversion_function(
+    rgb: &rgb::Image,
+    image: &mut image::Image,
+) -> AvifResult<RGBToYUVConversionFunction> {
+    if image.depth != 8
+        || rgb.depth != 8
+        || !matches!(
+            image.matrix_coefficients,
+            MatrixCoefficients::Bt470bg | MatrixCoefficients::Bt601
+        )
+    {
+        return Err(AvifError::NotImplemented);
+    }
+    // TODO: b/410088660 - Implement 2-step RGB conversion for functions which aren't directly
+    // available in libyuv.
+    match (image.yuv_format, image.yuv_range, rgb.format) {
+        (PixelFormat::Yuv400, YuvRange::Limited, Format::Bgra) => {
+            Ok(RGBToYUVConversionFunction::RGBToY(ARGBToI400))
+        }
+        (PixelFormat::Yuv400, YuvRange::Full, Format::Rgb) => {
+            Ok(RGBToYUVConversionFunction::RGBToY(RAWToJ400))
+        }
+        (PixelFormat::Yuv400, YuvRange::Full, Format::Rgba) => {
+            Ok(RGBToYUVConversionFunction::RGBToY(ABGRToJ400))
+        }
+        (PixelFormat::Yuv400, YuvRange::Full, Format::Bgr) => {
+            Ok(RGBToYUVConversionFunction::RGBToY(RGB24ToJ400))
+        }
+        (PixelFormat::Yuv400, YuvRange::Full, Format::Bgra) => {
+            Ok(RGBToYUVConversionFunction::RGBToY(ARGBToJ400))
+        }
+        (PixelFormat::Yuv400, YuvRange::Full, Format::Abgr) => {
+            Ok(RGBToYUVConversionFunction::RGBToY(RGBAToJ400))
+        }
+        (PixelFormat::Yuv420, YuvRange::Limited, Format::Rgb) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(RAWToI420))
+        }
+        (PixelFormat::Yuv420, YuvRange::Limited, Format::Rgba) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(ABGRToI420))
+        }
+        (PixelFormat::Yuv420, YuvRange::Limited, Format::Argb) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(BGRAToI420))
+        }
+        (PixelFormat::Yuv420, YuvRange::Limited, Format::Bgr) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(RGB24ToI420))
+        }
+        (PixelFormat::Yuv420, YuvRange::Limited, Format::Bgra) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(ARGBToI420))
+        }
+        (PixelFormat::Yuv420, YuvRange::Limited, Format::Abgr) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(RGBAToI420))
+        }
+        (PixelFormat::Yuv422, YuvRange::Limited, Format::Bgra) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(ARGBToI422))
+        }
+        (PixelFormat::Yuv444, YuvRange::Limited, Format::Bgra) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(ARGBToI444))
+        }
+        (PixelFormat::Yuv420, YuvRange::Full, Format::Rgb) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(RAWToJ420))
+        }
+        (PixelFormat::Yuv420, YuvRange::Full, Format::Rgba) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(ABGRToJ420))
+        }
+        (PixelFormat::Yuv420, YuvRange::Full, Format::Bgr) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(RGB24ToJ420))
+        }
+        (PixelFormat::Yuv420, YuvRange::Full, Format::Bgra) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(ARGBToJ420))
+        }
+        (PixelFormat::Yuv422, YuvRange::Full, Format::Rgba) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(ABGRToJ422))
+        }
+        (PixelFormat::Yuv422, YuvRange::Full, Format::Bgra) => {
+            Ok(RGBToYUVConversionFunction::RGBToYUV(ARGBToJ422))
+        }
+        _ => Err(AvifError::NotImplemented),
+    }
+}
+
+#[cfg_attr(feature = "disable_cfi", no_sanitize(cfi))]
+pub(crate) fn rgb_to_yuv(rgb: &rgb::Image, image: &mut image::Image) -> AvifResult<()> {
+    let conversion_function = rgb_to_yuv_conversion_function(rgb, image)?;
+    let plane_u8 = image.plane_ptrs_mut();
+    let plane_row_bytes = image.plane_row_bytes()?;
+    let width = i32_from_u32(image.width)?;
+    let height = i32_from_u32(image.height)?;
+    let rgb_row_bytes = i32_from_u32(rgb.row_bytes)?;
+    let result = unsafe {
+        match conversion_function {
+            RGBToYUVConversionFunction::RGBToY(func) => func(
+                rgb.pixels(),
+                rgb_row_bytes,
+                plane_u8[0],
+                plane_row_bytes[0],
+                width,
+                height,
+            ),
+            RGBToYUVConversionFunction::RGBToYUV(func) => func(
+                rgb.pixels(),
+                rgb_row_bytes,
+                plane_u8[0],
+                plane_row_bytes[0],
+                plane_u8[1],
+                plane_row_bytes[1],
+                plane_u8[2],
+                plane_row_bytes[2],
+                width,
+                height,
+            ),
+        }
+    };
+    if result == 0 {
+        Ok(())
+    } else {
+        Err(AvifError::ReformatFailed)
+    }
+}
diff --git a/src/reformat/mod.rs b/src/reformat/mod.rs
index 9c6c813..a4b50ac 100644
--- a/src/reformat/mod.rs
+++ b/src/reformat/mod.rs
@@ -33,6 +33,10 @@ pub mod libyuv {
         Err(AvifError::NotImplemented)
     }
 
+    pub(crate) fn rgb_to_yuv(_rgb: &rgb::Image, _image: &mut image::Image) -> AvifResult<bool> {
+        Err(AvifError::NotImplemented)
+    }
+
     pub(crate) fn convert_to_half_float(_rgb: &mut rgb::Image, _scale: f32) -> AvifResult<()> {
         Err(AvifError::NotImplemented)
     }
diff --git a/src/reformat/rgb.rs b/src/reformat/rgb.rs
index 45417d6..98835dc 100644
--- a/src/reformat/rgb.rs
+++ b/src/reformat/rgb.rs
@@ -17,8 +17,8 @@ use super::rgb_impl;
 
 use crate::image::Plane;
 use crate::image::YuvRange;
-use crate::internal_utils::pixels::*;
 use crate::internal_utils::*;
+use crate::utils::pixels::*;
 use crate::*;
 
 #[repr(C)]
@@ -64,7 +64,7 @@ impl Format {
         self.offsets()[3]
     }
 
-    pub(crate) fn has_alpha(&self) -> bool {
+    pub fn has_alpha(&self) -> bool {
         !matches!(self, Format::Rgb | Format::Bgr | Format::Rgb565)
     }
 }
@@ -127,7 +127,7 @@ pub enum AlphaMultiplyMode {
 }
 
 impl Image {
-    pub(crate) fn max_channel(&self) -> u16 {
+    pub fn max_channel(&self) -> u16 {
         ((1i32 << self.depth) - 1) as u16
     }
 
@@ -151,15 +151,19 @@ impl Image {
         }
     }
 
-    pub(crate) fn pixels(&mut self) -> *mut u8 {
-        if self.pixels.is_none() {
-            return std::ptr::null_mut();
+    // This function may not be used in some configurations.
+    #[allow(unused)]
+    pub(crate) fn pixels(&self) -> *const u8 {
+        match &self.pixels {
+            Some(pixels) => pixels.ptr_generic(),
+            None => std::ptr::null(),
         }
-        match self.pixels.unwrap_mut() {
-            Pixels::Pointer(ptr) => ptr.ptr_mut(),
-            Pixels::Pointer16(ptr) => ptr.ptr_mut() as *mut u8,
-            Pixels::Buffer(buffer) => buffer.as_mut_ptr(),
-            Pixels::Buffer16(buffer) => buffer.as_mut_ptr() as *mut u8,
+    }
+
+    pub(crate) fn pixels_mut(&mut self) -> *mut u8 {
+        match &mut self.pixels {
+            Some(pixels) => pixels.ptr_mut_generic(),
+            None => std::ptr::null_mut(),
         }
     }
 
@@ -231,7 +235,7 @@ impl Image {
         }
     }
 
-    pub(crate) fn channel_count(&self) -> u32 {
+    pub fn channel_count(&self) -> u32 {
         match self.format {
             Format::Rgba | Format::Bgra | Format::Argb | Format::Abgr => 4,
             Format::Rgb | Format::Bgr => 3,
@@ -391,6 +395,50 @@ impl Image {
         Ok(())
     }
 
+    pub fn convert_to_yuv(&self, image: &mut image::Image) -> AvifResult<()> {
+        if self.format == Format::Rgb565 || self.is_float {
+            return Err(AvifError::NotImplemented);
+        }
+        image.allocate_planes(Category::Color)?;
+        // TODO: b/410088660 - add a setting to ignore alpha channel.
+        let has_alpha = self.has_alpha();
+        if has_alpha {
+            image.allocate_planes(Category::Alpha)?;
+        }
+        let alpha_multiply_mode =
+            match (has_alpha, self.premultiply_alpha, image.alpha_premultiplied) {
+                (true, false, true) => AlphaMultiplyMode::Multiply,
+                (true, true, false) => AlphaMultiplyMode::UnMultiply,
+                _ => AlphaMultiplyMode::NoOp,
+            };
+        // TODO: b/410088660 - support gray rgb formats.
+        // TODO: b/410088660 - support sharpyuv conversion.
+        let mut conversion_complete = false;
+        if alpha_multiply_mode == AlphaMultiplyMode::NoOp {
+            match libyuv::rgb_to_yuv(self, image) {
+                Ok(_) => {
+                    conversion_complete = true;
+                }
+                Err(err) => {
+                    if err != AvifError::NotImplemented {
+                        return Err(err);
+                    }
+                }
+            }
+        }
+        if !conversion_complete {
+            rgb_impl::rgb_to_yuv(self, image)?;
+        }
+        if image.has_plane(Plane::A) {
+            if has_alpha {
+                image.import_alpha_from(self)?;
+            } else {
+                image.set_opaque()?;
+            }
+        }
+        Ok(())
+    }
+
     pub fn shuffle_channels_to(self, format: Format) -> AvifResult<Image> {
         if self.format == format {
             return Ok(self);
@@ -560,6 +608,7 @@ mod tests {
         },
     ];
 
+    #[allow(clippy::zero_prefixed_literal)]
     #[test_matrix(0usize..5)]
     fn rgb_conversion(rgb_param_index: usize) -> AvifResult<()> {
         let rgb_params = &RGB_PARAMS[rgb_param_index];
@@ -582,10 +631,11 @@ mod tests {
             if yuva_planes[plane_index].is_empty() {
                 continue;
             }
+            let plane_width = image.width(plane);
             for y in 0..image.height(plane) {
                 let row16 = image.row16_mut(plane, y as u32)?;
-                assert_eq!(row16.len(), yuva_planes[plane_index][y].len());
-                let dst = &mut row16[..];
+                let dst = &mut row16[..plane_width];
+                assert_eq!(dst.len(), yuva_planes[plane_index][y].len());
                 dst.copy_from_slice(yuva_planes[plane_index][y]);
             }
         }
@@ -605,7 +655,7 @@ mod tests {
 
         for y in 0..rgb.height as usize {
             let row16 = rgb.row16(y as u32)?;
-            assert_eq!(&row16[..], rgb_params.expected_rgba[y]);
+            assert_eq!(row16, rgb_params.expected_rgba[y]);
         }
         Ok(())
     }
diff --git a/src/reformat/rgb_impl.rs b/src/reformat/rgb_impl.rs
index a3d0257..caaccf7 100644
--- a/src/reformat/rgb_impl.rs
+++ b/src/reformat/rgb_impl.rs
@@ -460,35 +460,44 @@ pub(crate) fn yuv_to_rgb_fast(image: &image::Image, rgb: &mut rgb::Image) -> Avi
     }
 }
 
+fn bias_and_range_y(image: &image::Image) -> (f32, f32) {
+    // Formula specified in ISO/IEC 23091-2.
+    if image.yuv_range == YuvRange::Limited {
+        (
+            (16 << (image.depth - 8)) as f32,
+            (219 << (image.depth - 8)) as f32,
+        )
+    } else {
+        (0.0, image.max_channel_f())
+    }
+}
+
+fn bias_and_range_uv(image: &image::Image) -> (f32, f32) {
+    // Formula specified in ISO/IEC 23091-2.
+    (
+        (1 << (image.depth - 1)) as f32,
+        if image.yuv_range == YuvRange::Limited {
+            (224 << (image.depth - 8)) as f32
+        } else {
+            image.max_channel_f()
+        },
+    )
+}
+
 fn unorm_lookup_tables(
     image: &image::Image,
     mode: Mode,
 ) -> AvifResult<(Vec<f32>, Option<Vec<f32>>)> {
     let count = 1usize << image.depth;
     let mut table_y: Vec<f32> = create_vec_exact(count)?;
-    let bias_y;
-    let range_y;
-    // Formula specified in ISO/IEC 23091-2.
-    if image.yuv_range == YuvRange::Limited {
-        bias_y = (16 << (image.depth - 8)) as f32;
-        range_y = (219 << (image.depth - 8)) as f32;
-    } else {
-        bias_y = 0.0;
-        range_y = image.max_channel_f();
-    }
+    let (bias_y, range_y) = bias_and_range_y(image);
     for cp in 0..count {
         table_y.push(((cp as f32) - bias_y) / range_y);
     }
     if mode == Mode::Identity {
         Ok((table_y, None))
     } else {
-        // Formula specified in ISO/IEC 23091-2.
-        let bias_uv = (1 << (image.depth - 1)) as f32;
-        let range_uv = if image.yuv_range == YuvRange::Limited {
-            (224 << (image.depth - 8)) as f32
-        } else {
-            image.max_channel_f()
-        };
+        let (bias_uv, range_uv) = bias_and_range_uv(image);
         let mut table_uv: Vec<f32> = create_vec_exact(count)?;
         for cp in 0..count {
             table_uv.push(((cp as f32) - bias_uv) / range_uv);
@@ -709,6 +718,216 @@ pub(crate) fn yuv_to_rgb_any(
     Ok(())
 }
 
+#[derive(Debug, Default, Copy, Clone)]
+struct YUVBlock(f32, f32, f32);
+
+pub(crate) fn rgb_to_yuv(rgb: &rgb::Image, image: &mut image::Image) -> AvifResult<()> {
+    let r_offset = rgb.format.r_offset();
+    let g_offset = rgb.format.g_offset();
+    let b_offset = rgb.format.b_offset();
+    let rgb_channel_count = rgb.channel_count() as usize;
+    let rgb_max_channel_f = rgb.max_channel_f();
+    let mode = (image as &image::Image).into();
+    let (bias_y, range_y) = bias_and_range_y(image);
+    let (bias_uv, range_uv) = if mode == Mode::Identity {
+        (bias_y, range_y)
+    } else {
+        bias_and_range_uv(image)
+    };
+    let yuv_max_channel = image.max_channel();
+
+    for outer_j in (0..image.height).step_by(2) {
+        let block_h = if (outer_j + 1) >= image.height { 1 } else { 2 };
+        for outer_i in (0..image.width).step_by(2) {
+            let mut yuv_block: [[YUVBlock; 3]; 3] = Default::default();
+            let block_w = if (outer_i + 1) >= image.width { 1 } else { 2 };
+            for block_j in 0..block_h as usize {
+                #[allow(clippy::needless_range_loop)]
+                for block_i in 0..block_w as usize {
+                    let j = outer_j + block_j as u32;
+                    let i = outer_i as usize + block_i;
+
+                    let rgb_pixel = if rgb.depth == 8 {
+                        let src = rgb.row(j)?;
+                        [
+                            src[(i * rgb_channel_count) + r_offset] as f32 / rgb_max_channel_f,
+                            src[(i * rgb_channel_count) + g_offset] as f32 / rgb_max_channel_f,
+                            src[(i * rgb_channel_count) + b_offset] as f32 / rgb_max_channel_f,
+                        ]
+                    } else {
+                        let src = rgb.row16(j)?;
+                        [
+                            src[(i * rgb_channel_count) + r_offset] as f32 / rgb_max_channel_f,
+                            src[(i * rgb_channel_count) + g_offset] as f32 / rgb_max_channel_f,
+                            src[(i * rgb_channel_count) + b_offset] as f32 / rgb_max_channel_f,
+                        ]
+                    };
+                    // TODO: b/410088660 - handle alpha multiply/unmultiply.
+                    yuv_block[block_i][block_j] = match mode {
+                        Mode::YuvCoefficients(kr, kg, kb) => {
+                            let y = (kr * rgb_pixel[0]) + (kg * rgb_pixel[1]) + (kb * rgb_pixel[2]);
+                            YUVBlock(
+                                y,
+                                (rgb_pixel[2] - y) / (2.0 * (1.0 - kb)),
+                                (rgb_pixel[0] - y) / (2.0 * (1.0 - kr)),
+                            )
+                        }
+                        Mode::Identity => {
+                            // Formulas 41,42,43 from https://www.itu.int/rec/T-REC-H.273-201612-S.
+                            YUVBlock(rgb_pixel[1], rgb_pixel[2], rgb_pixel[0])
+                        }
+                        Mode::YcgcoRe | Mode::YcgcoRo => {
+                            // Formulas 58,59,60,61 from https://www.itu.int/rec/T-REC-H.273-202407-P.
+                            let r = ((rgb_pixel[0] * rgb_max_channel_f)
+                                .clamp(0.0, rgb_max_channel_f)
+                                + 0.5)
+                                .floor() as i32;
+                            let g = ((rgb_pixel[1] * rgb_max_channel_f)
+                                .clamp(0.0, rgb_max_channel_f)
+                                + 0.5)
+                                .floor() as i32;
+                            let b = ((rgb_pixel[2] * rgb_max_channel_f)
+                                .clamp(0.0, rgb_max_channel_f)
+                                + 0.5)
+                                .floor() as i32;
+                            let co = r - b;
+                            let t = b + (co >> 1);
+                            let cg = g - t;
+                            YUVBlock(
+                                (t + (cg >> 1)) as f32 / range_y,
+                                cg as f32 / range_uv,
+                                co as f32 / range_uv,
+                            )
+                        }
+                        Mode::Ycgco => {
+                            // Formulas 44,45,46 from https://www.itu.int/rec/T-REC-H.273-201612-S.
+                            YUVBlock(
+                                0.5 * rgb_pixel[1] + 0.25 * (rgb_pixel[0] + rgb_pixel[2]),
+                                0.5 * rgb_pixel[1] - 0.25 * (rgb_pixel[0] + rgb_pixel[2]),
+                                0.5 * (rgb_pixel[0] - rgb_pixel[2]),
+                            )
+                        }
+                    };
+                    if image.depth == 8 {
+                        let dst_y = image.row_mut(Plane::Y, j)?;
+                        dst_y[i] = to_unorm(
+                            bias_y,
+                            range_y,
+                            yuv_max_channel,
+                            yuv_block[block_i][block_j].0,
+                        ) as u8;
+                        if image.yuv_format == PixelFormat::Yuv444 {
+                            let dst_u = image.row_mut(Plane::U, j)?;
+                            dst_u[i] = to_unorm(
+                                bias_uv,
+                                range_uv,
+                                yuv_max_channel,
+                                yuv_block[block_i][block_j].1,
+                            ) as u8;
+                            let dst_v = image.row_mut(Plane::V, j)?;
+                            dst_v[i] = to_unorm(
+                                bias_uv,
+                                range_uv,
+                                yuv_max_channel,
+                                yuv_block[block_i][block_j].2,
+                            ) as u8;
+                        }
+                    } else {
+                        let dst_y = image.row16_mut(Plane::Y, j)?;
+                        dst_y[i] = to_unorm(
+                            bias_y,
+                            range_y,
+                            yuv_max_channel,
+                            yuv_block[block_i][block_j].0,
+                        );
+                        if image.yuv_format == PixelFormat::Yuv444 {
+                            let dst_u = image.row16_mut(Plane::U, j)?;
+                            dst_u[i] = to_unorm(
+                                bias_uv,
+                                range_uv,
+                                yuv_max_channel,
+                                yuv_block[block_i][block_j].1,
+                            );
+                            let dst_v = image.row16_mut(Plane::V, j)?;
+                            dst_v[i] = to_unorm(
+                                bias_uv,
+                                range_uv,
+                                yuv_max_channel,
+                                yuv_block[block_i][block_j].2,
+                            );
+                        }
+                    }
+                }
+            }
+
+            // Populate subsampled channels with average values of the 2x2 block.
+            match image.yuv_format {
+                PixelFormat::Yuv420 => {
+                    let (avg_u, avg_v) = average_2x2(&yuv_block, block_w * block_h);
+                    let uv_j = outer_j >> 1;
+                    let uv_i = outer_i as usize >> 1;
+                    if image.depth == 8 {
+                        let dst_u = image.row_mut(Plane::U, uv_j)?;
+                        dst_u[uv_i] = to_unorm(bias_uv, range_uv, yuv_max_channel, avg_u) as u8;
+                        let dst_v = image.row_mut(Plane::V, uv_j)?;
+                        dst_v[uv_i] = to_unorm(bias_uv, range_uv, yuv_max_channel, avg_v) as u8;
+                    } else {
+                        let dst_u = image.row16_mut(Plane::U, uv_j)?;
+                        dst_u[uv_i] = to_unorm(bias_uv, range_uv, yuv_max_channel, avg_u);
+                        let dst_v = image.row16_mut(Plane::V, uv_j)?;
+                        dst_v[uv_i] = to_unorm(bias_uv, range_uv, yuv_max_channel, avg_v);
+                    }
+                }
+                PixelFormat::Yuv422 => {
+                    for block_j in 0..block_h {
+                        let (avg_u, avg_v) = average_1x2(&yuv_block, block_j, block_w);
+                        let uv_j = outer_j + block_j;
+                        let uv_i = outer_i as usize >> 1;
+                        if image.depth == 8 {
+                            let dst_u = image.row_mut(Plane::U, uv_j)?;
+                            dst_u[uv_i] = to_unorm(bias_uv, range_uv, yuv_max_channel, avg_u) as u8;
+                            let dst_v = image.row_mut(Plane::V, uv_j)?;
+                            dst_v[uv_i] = to_unorm(bias_uv, range_uv, yuv_max_channel, avg_v) as u8;
+                        } else {
+                            let dst_u = image.row16_mut(Plane::U, uv_j)?;
+                            dst_u[uv_i] = to_unorm(bias_uv, range_uv, yuv_max_channel, avg_u);
+                            let dst_v = image.row16_mut(Plane::V, uv_j)?;
+                            dst_v[uv_i] = to_unorm(bias_uv, range_uv, yuv_max_channel, avg_v);
+                        }
+                    }
+                }
+                _ => {}
+            }
+        }
+    }
+    Ok(())
+}
+
+// TODO - b/410088660: this can be a macro since it's per pixel?
+fn to_unorm(bias_y: f32, range_y: f32, max_channel: u16, v: f32) -> u16 {
+    clamp_i32(
+        (0.5 + (v * range_y + bias_y)).floor() as i32,
+        0,
+        max_channel as i32,
+    ) as u16
+}
+
+fn average_2x2(yuv_block: &[[YUVBlock; 3]; 3], sample_count: u32) -> (f32, f32) {
+    let sum_u: f32 = yuv_block.iter().flatten().map(|pixel| pixel.1).sum();
+    let sum_v: f32 = yuv_block.iter().flatten().map(|pixel| pixel.2).sum();
+    (sum_u / sample_count as f32, sum_v / sample_count as f32)
+}
+
+fn average_1x2(yuv_block: &[[YUVBlock; 3]; 3], block_j: u32, block_w: u32) -> (f32, f32) {
+    let mut sum_u = 0.0;
+    let mut sum_v = 0.0;
+    for row in yuv_block.iter().take(block_w as usize) {
+        sum_u += row[block_j as usize].1;
+        sum_v += row[block_j as usize].2;
+    }
+    (sum_u / block_w as f32, sum_v / block_w as f32)
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
@@ -763,7 +982,7 @@ mod tests {
                 assert_eq!(dst.width, g[y as usize].len() as u32);
                 assert_eq!(dst.width, b[y as usize].len() as u32);
                 for x in 0..dst.width {
-                    let i = (x * dst.pixel_size() + 0) as usize;
+                    let i = (x * dst.pixel_size()) as usize;
                     let pixel = &dst.row(y).unwrap()[i..i + 3];
                     assert_eq!(pixel[0], r[y as usize][x as usize]);
                     assert_eq!(pixel[1], g[y as usize][x as usize]);
diff --git a/src/reformat/scale.rs b/src/reformat/scale.rs
index 0a14612..5608e90 100644
--- a/src/reformat/scale.rs
+++ b/src/reformat/scale.rs
@@ -26,10 +26,7 @@ impl Image {
         if width == 0 || height == 0 {
             return Err(AvifError::InvalidArgument);
         }
-        let planes: &[Plane] = match category {
-            Category::Color | Category::Gainmap => &YUV_PLANES,
-            Category::Alpha => &A_PLANE,
-        };
+        let planes = category.planes();
         let src =
             if category != Category::Alpha && self.yuv_format == PixelFormat::AndroidP010 {
                 // P010 images cannot be scaled using ScalePlane_12 since the U and V planes are
@@ -205,7 +202,7 @@ impl Image {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use crate::internal_utils::pixels::*;
+    use crate::utils::pixels::*;
     use test_case::test_matrix;
 
     #[test_matrix([PixelFormat::Yuv444, PixelFormat::Yuv422, PixelFormat::Yuv420, PixelFormat::Yuv400], [false, true], [false, true])]
@@ -275,4 +272,20 @@ mod tests {
             }
         }
     }
+
+    #[test]
+    fn scale_nv12_odd_dimension() -> AvifResult<()> {
+        let mut image = image::Image {
+            width: 99,
+            height: 49,
+            depth: 8,
+            yuv_format: PixelFormat::AndroidNv12,
+            ..Default::default()
+        };
+        image.allocate_planes(Category::Color)?;
+        assert!(image.scale(49, 24, Category::Color).is_ok());
+        assert_eq!(image.width, 49);
+        assert_eq!(image.height, 24);
+        Ok(())
+    }
 }
diff --git a/src/utils/clap.rs b/src/utils/clap.rs
index d2137eb..0700c86 100644
--- a/src/utils/clap.rs
+++ b/src/utils/clap.rs
@@ -12,7 +12,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crate::internal_utils::*;
 use crate::utils::*;
 
 #[derive(Clone, Copy, Debug, PartialEq)]
@@ -23,7 +22,7 @@ pub struct CleanAperture {
     pub vert_off: UFraction,
 }
 
-#[derive(Clone, Copy, Debug, Default)]
+#[derive(Clone, Copy, Debug, Default, PartialEq)]
 #[repr(C)]
 pub struct CropRect {
     pub x: u32,
@@ -32,6 +31,41 @@ pub struct CropRect {
     pub height: u32,
 }
 
+impl CleanAperture {
+    pub fn create_from(
+        rect: &CropRect,
+        image_width: u32,
+        image_height: u32,
+        pixel_format: PixelFormat,
+    ) -> AvifResult<Self> {
+        if !rect.is_valid(image_width, image_height, pixel_format) {
+            return Err(AvifError::InvalidArgument);
+        }
+        let mut cropped_center_x = IFraction::simplified(i32_from_u32(rect.width)?, 2);
+        let mut cropped_center_y = IFraction::simplified(i32_from_u32(rect.height)?, 2);
+        cropped_center_x.0 = i32_from_i64(checked_add!(
+            cropped_center_x.0 as i64,
+            checked_mul!(rect.x as i64, cropped_center_x.1 as i64)?
+        )?)?;
+        cropped_center_y.0 = i32_from_i64(checked_add!(
+            cropped_center_y.0 as i64,
+            checked_mul!(rect.y as i64, cropped_center_y.1 as i64)?
+        )?)?;
+        let uncropped_center_x = IFraction::simplified(i32_from_u32(image_width)?, 2);
+        let mut horiz_off = cropped_center_x;
+        horiz_off.sub(&uncropped_center_x)?;
+        let uncropped_center_y = IFraction::simplified(i32_from_u32(image_height)?, 2);
+        let mut vert_off = cropped_center_y;
+        vert_off.sub(&uncropped_center_y)?;
+        Ok(Self {
+            width: UFraction(rect.width, 1),
+            height: UFraction(rect.height, 1),
+            horiz_off: UFraction(horiz_off.0 as u32, horiz_off.1 as u32),
+            vert_off: UFraction(vert_off.0 as u32, vert_off.1 as u32),
+        })
+    }
+}
+
 impl CropRect {
     fn is_valid(&self, image_width: u32, image_height: u32, pixel_format: PixelFormat) -> bool {
         let x_plus_width = checked_add!(self.x, self.width);
@@ -175,8 +209,9 @@ mod tests {
         invalid!(99, 99, Yuv420, 99, 1, 99, 1, -1i32 as u32, 2, -1i32 as u32, 2),
     ];
 
+    #[allow(clippy::zero_prefixed_literal)]
     #[test_case::test_matrix(0usize..20)]
-    fn valid_clap_to_rect(index: usize) {
+    fn clap_to_rect(index: usize) {
         let param = &TEST_PARAMS[index];
         let rect = CropRect::create_from(
             &param.clap,
@@ -184,16 +219,28 @@ mod tests {
             param.image_height,
             param.pixel_format,
         );
-        if param.rect.is_some() {
+        if let Some(expected_rect) = param.rect {
             assert!(rect.is_ok());
-            let rect = rect.unwrap();
-            let expected_rect = param.rect.unwrap_ref();
-            assert_eq!(rect.x, expected_rect.x);
-            assert_eq!(rect.y, expected_rect.y);
-            assert_eq!(rect.width, expected_rect.width);
-            assert_eq!(rect.height, expected_rect.height);
+            assert_eq!(rect.unwrap(), expected_rect);
         } else {
             assert!(rect.is_err());
         }
     }
+
+    #[allow(clippy::zero_prefixed_literal)]
+    #[test_case::test_matrix(0usize..20)]
+    fn rect_to_clap(index: usize) {
+        let param = &TEST_PARAMS[index];
+        if param.rect.is_none() {
+            return;
+        }
+        let clap = CleanAperture::create_from(
+            param.rect.unwrap_ref(),
+            param.image_width,
+            param.image_height,
+            param.pixel_format,
+        );
+        assert!(clap.is_ok());
+        assert_eq!(clap.unwrap(), param.clap);
+    }
 }
diff --git a/src/utils/mod.rs b/src/utils/mod.rs
index f087aa8..4c9aba5 100644
--- a/src/utils/mod.rs
+++ b/src/utils/mod.rs
@@ -12,15 +12,19 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+use crate::internal_utils::*;
 use crate::*;
 
 pub mod clap;
+pub mod pixels;
+pub mod reader;
+pub mod writer;
 
 // Some HEIF fractional fields can be negative, hence Fraction and UFraction.
 // The denominator is always unsigned.
 
 /// cbindgen:field-names=[n,d]
-#[derive(Clone, Copy, Debug, Default)]
+#[derive(Clone, Copy, Debug, Default, PartialEq)]
 #[repr(C)]
 pub struct Fraction(pub i32, pub u32);
 
@@ -51,3 +55,118 @@ impl UFraction {
         }
     }
 }
+
+// 'clap' fractions do not follow this pattern: both numerators and denominators
+// are used as i32, but they are signalled as u32 according to the specification
+// as of 2024. This may be fixed in later versions of the specification, see
+// https://github.com/AOMediaCodec/libavif/pull/1749#discussion_r1391612932.
+/// cbindgen:field-names=[n,d]
+#[derive(Clone, Copy, Debug, Default, PartialEq)]
+#[repr(C)]
+pub struct IFraction(pub i32, pub i32);
+
+impl TryFrom<UFraction> for IFraction {
+    type Error = AvifError;
+
+    fn try_from(uf: UFraction) -> AvifResult<IFraction> {
+        Ok(IFraction(uf.0 as i32, i32_from_u32(uf.1)?))
+    }
+}
+
+impl IFraction {
+    // This function is not used in all configurations.
+    #[allow(unused)]
+    pub(crate) fn is_valid(&self) -> AvifResult<()> {
+        match self.1 {
+            0 => Err(AvifError::InvalidArgument),
+            _ => Ok(()),
+        }
+    }
+
+    fn gcd(a: i32, b: i32) -> i32 {
+        let mut a = if a < 0 { -a as i64 } else { a as i64 };
+        let mut b = if b < 0 { -b as i64 } else { b as i64 };
+        while b != 0 {
+            let r = a % b;
+            a = b;
+            b = r;
+        }
+        a as i32
+    }
+
+    pub(crate) fn simplified(n: i32, d: i32) -> Self {
+        let mut fraction = IFraction(n, d);
+        fraction.simplify();
+        fraction
+    }
+
+    pub(crate) fn simplify(&mut self) {
+        let gcd = Self::gcd(self.0, self.1);
+        if gcd > 1 {
+            self.0 /= gcd;
+            self.1 /= gcd;
+        }
+    }
+
+    pub(crate) fn get_i32(&self) -> i32 {
+        assert!(self.1 != 0);
+        self.0 / self.1
+    }
+
+    pub(crate) fn get_u32(&self) -> AvifResult<u32> {
+        u32_from_i32(self.get_i32())
+    }
+
+    pub(crate) fn is_integer(&self) -> bool {
+        self.0 % self.1 == 0
+    }
+
+    fn common_denominator(&mut self, val: &mut IFraction) -> AvifResult<()> {
+        self.simplify();
+        if self.1 == val.1 {
+            return Ok(());
+        }
+        let self_d = self.1;
+        self.0 = self
+            .0
+            .checked_mul(val.1)
+            .ok_or(AvifError::UnknownError("".into()))?;
+        self.1 = self
+            .1
+            .checked_mul(val.1)
+            .ok_or(AvifError::UnknownError("".into()))?;
+        val.0 = val
+            .0
+            .checked_mul(self_d)
+            .ok_or(AvifError::UnknownError("".into()))?;
+        val.1 = val
+            .1
+            .checked_mul(self_d)
+            .ok_or(AvifError::UnknownError("".into()))?;
+        Ok(())
+    }
+
+    pub(crate) fn add(&mut self, val: &IFraction) -> AvifResult<()> {
+        let mut val = *val;
+        val.simplify();
+        self.common_denominator(&mut val)?;
+        self.0 = self
+            .0
+            .checked_add(val.0)
+            .ok_or(AvifError::UnknownError("".into()))?;
+        self.simplify();
+        Ok(())
+    }
+
+    pub(crate) fn sub(&mut self, val: &IFraction) -> AvifResult<()> {
+        let mut val = *val;
+        val.simplify();
+        self.common_denominator(&mut val)?;
+        self.0 = self
+            .0
+            .checked_sub(val.0)
+            .ok_or(AvifError::UnknownError("".into()))?;
+        self.simplify();
+        Ok(())
+    }
+}
diff --git a/src/internal_utils/pixels.rs b/src/utils/pixels.rs
similarity index 77%
rename from src/internal_utils/pixels.rs
rename to src/utils/pixels.rs
index a0cd289..e5002bc 100644
--- a/src/internal_utils/pixels.rs
+++ b/src/utils/pixels.rs
@@ -15,65 +15,6 @@
 use crate::internal_utils::*;
 use crate::*;
 
-#[derive(Clone, Copy, Debug)]
-pub struct PointerSlice<T> {
-    ptr: *mut [T],
-}
-
-impl<T> PointerSlice<T> {
-    /// # Safety
-    /// `ptr` must live at least as long as the struct, and not be accessed other than through this
-    /// struct. It must point to a memory region of at least `size` elements.
-    pub unsafe fn create(ptr: *mut T, size: usize) -> AvifResult<Self> {
-        if ptr.is_null() || size == 0 {
-            return Err(AvifError::NoContent);
-        }
-        // Ensure that size does not exceed isize::MAX.
-        let _ = isize_from_usize(size)?;
-        Ok(Self {
-            ptr: unsafe { std::slice::from_raw_parts_mut(ptr, size) },
-        })
-    }
-
-    fn slice_impl(&self) -> &[T] {
-        // SAFETY: We only construct this with `ptr` which is valid at least as long as this struct
-        // is alive, and ro/mut borrows of the whole struct to access the inner slice, which makes
-        // our access appropriately exclusive.
-        unsafe { &(*self.ptr) }
-    }
-
-    fn slice_impl_mut(&mut self) -> &mut [T] {
-        // SAFETY: We only construct this with `ptr` which is valid at least as long as this struct
-        // is alive, and ro/mut borrows of the whole struct to access the inner slice, which makes
-        // our access appropriately exclusive.
-        unsafe { &mut (*self.ptr) }
-    }
-
-    pub fn slice(&self, range: Range<usize>) -> AvifResult<&[T]> {
-        let data = self.slice_impl();
-        check_slice_range(data.len(), &range)?;
-        Ok(&data[range])
-    }
-
-    pub fn slice_mut(&mut self, range: Range<usize>) -> AvifResult<&mut [T]> {
-        let data = self.slice_impl_mut();
-        check_slice_range(data.len(), &range)?;
-        Ok(&mut data[range])
-    }
-
-    pub fn ptr(&self) -> *const T {
-        self.slice_impl().as_ptr()
-    }
-
-    pub fn ptr_mut(&mut self) -> *mut T {
-        self.slice_impl_mut().as_mut_ptr()
-    }
-
-    pub fn is_empty(&self) -> bool {
-        self.slice_impl().is_empty()
-    }
-}
-
 // This struct must not be derived from the default `Clone` trait as it has to be cloned with error
 // checking using the `try_clone` function.
 #[derive(Debug)]
@@ -90,7 +31,9 @@ pub enum Pixels {
 }
 
 impl Pixels {
-    pub fn from_raw_pointer(
+    // This function may not be used in all configurations.
+    #[allow(unused)]
+    pub(crate) fn from_raw_pointer(
         ptr: *mut u8,
         depth: u32,
         height: u32,
@@ -160,7 +103,9 @@ impl Pixels {
         matches!(self, Pixels::Pointer(_) | Pixels::Pointer16(_))
     }
 
-    pub fn ptr(&self) -> *const u8 {
+    // This function may not be used in all configurations.
+    #[allow(unused)]
+    pub(crate) fn ptr(&self) -> *const u8 {
         match self {
             Pixels::Pointer(ptr) => ptr.ptr(),
             Pixels::Buffer(buffer) => buffer.as_ptr(),
@@ -168,7 +113,9 @@ impl Pixels {
         }
     }
 
-    pub fn ptr16(&self) -> *const u16 {
+    // This function may not be used in all configurations.
+    #[allow(unused)]
+    pub(crate) fn ptr16(&self) -> *const u16 {
         match self {
             Pixels::Pointer16(ptr) => ptr.ptr(),
             Pixels::Buffer16(buffer) => buffer.as_ptr(),
@@ -176,7 +123,9 @@ impl Pixels {
         }
     }
 
-    pub fn ptr_mut(&mut self) -> *mut u8 {
+    // This function may not be used in all configurations.
+    #[allow(unused)]
+    pub(crate) fn ptr_mut(&mut self) -> *mut u8 {
         match self {
             Pixels::Pointer(ptr) => ptr.ptr_mut(),
             Pixels::Buffer(buffer) => buffer.as_mut_ptr(),
@@ -184,7 +133,9 @@ impl Pixels {
         }
     }
 
-    pub fn ptr16_mut(&mut self) -> *mut u16 {
+    // This function may not be used in all configurations.
+    #[allow(unused)]
+    pub(crate) fn ptr16_mut(&mut self) -> *mut u16 {
         match self {
             Pixels::Pointer16(ptr) => ptr.ptr_mut(),
             Pixels::Buffer16(buffer) => buffer.as_mut_ptr(),
@@ -192,6 +143,24 @@ impl Pixels {
         }
     }
 
+    pub(crate) fn ptr_generic(&self) -> *const u8 {
+        match self {
+            Pixels::Pointer(ptr) => ptr.ptr(),
+            Pixels::Pointer16(ptr) => ptr.ptr() as *const u8,
+            Pixels::Buffer(buffer) => buffer.as_ptr(),
+            Pixels::Buffer16(buffer) => buffer.as_ptr() as *const u8,
+        }
+    }
+
+    pub fn ptr_mut_generic(&mut self) -> *mut u8 {
+        match self {
+            Pixels::Pointer(ptr) => ptr.ptr_mut(),
+            Pixels::Pointer16(ptr) => ptr.ptr_mut() as *mut u8,
+            Pixels::Buffer(buffer) => buffer.as_mut_ptr(),
+            Pixels::Buffer16(buffer) => buffer.as_mut_ptr() as *mut u8,
+        }
+    }
+
     pub(crate) fn try_clone(&self) -> AvifResult<Pixels> {
         match self {
             Pixels::Pointer(ptr) => Ok(Pixels::Pointer(*ptr)),
@@ -234,7 +203,7 @@ impl Pixels {
         }
     }
 
-    pub fn slice_mut(&mut self, offset: u32, size: u32) -> AvifResult<&mut [u8]> {
+    pub(crate) fn slice_mut(&mut self, offset: u32, size: u32) -> AvifResult<&mut [u8]> {
         let offset: usize = usize_from_u32(offset)?;
         let size: usize = usize_from_u32(size)?;
         match self {
@@ -272,7 +241,7 @@ impl Pixels {
         }
     }
 
-    pub fn slice16_mut(&mut self, offset: u32, size: u32) -> AvifResult<&mut [u16]> {
+    pub(crate) fn slice16_mut(&mut self, offset: u32, size: u32) -> AvifResult<&mut [u16]> {
         let offset: usize = usize_from_u32(offset)?;
         let size: usize = usize_from_u32(size)?;
         match self {
diff --git a/src/utils/reader/jpeg.rs b/src/utils/reader/jpeg.rs
new file mode 100644
index 0000000..a607dc5
--- /dev/null
+++ b/src/utils/reader/jpeg.rs
@@ -0,0 +1,93 @@
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
+use crate::reformat::*;
+use crate::utils::pixels::Pixels;
+use crate::AvifError;
+use crate::AvifResult;
+use crate::*;
+
+use super::Config;
+use super::Reader;
+
+use std::fs::File;
+use std::io::BufReader;
+
+use ::image::codecs::jpeg;
+use ::image::ColorType;
+use ::image::ImageDecoder;
+
+pub struct JpegReader {
+    filename: String,
+}
+
+impl JpegReader {
+    pub fn create(filename: &str) -> AvifResult<Self> {
+        Ok(Self {
+            filename: filename.into(),
+        })
+    }
+}
+
+impl Reader for JpegReader {
+    fn read_frame(&mut self, config: &Config) -> AvifResult<Image> {
+        let mut reader = BufReader::new(File::open(self.filename.clone()).or(Err(
+            AvifError::UnknownError("error opening input file".into()),
+        ))?);
+        let decoder = jpeg::JpegDecoder::new(&mut reader).or(Err(AvifError::UnknownError(
+            "failed to create jpeg decoder".into(),
+        )))?;
+        let color_type = decoder.color_type();
+        if color_type != ColorType::Rgb8 {
+            return Err(AvifError::UnknownError(format!(
+                "jpeg color type was something other than rgb8: {:#?}",
+                color_type
+            )));
+        }
+        let (width, height) = decoder.dimensions();
+        let total_bytes = decoder.total_bytes() as usize;
+        let mut rgb_bytes = vec![0u8; total_bytes];
+        decoder
+            .read_image(&mut rgb_bytes)
+            .or(Err(AvifError::UnknownError(
+                "failed to read jpeg pixels".into(),
+            )))?;
+        let rgb = rgb::Image {
+            width,
+            height,
+            depth: 8,
+            format: rgb::Format::Rgb,
+            pixels: Some(Pixels::Buffer(rgb_bytes)),
+            row_bytes: width * 3,
+            ..Default::default()
+        };
+        let mut yuv = Image {
+            width,
+            height,
+            depth: config.depth.unwrap_or(8),
+            yuv_format: config.yuv_format.unwrap_or(PixelFormat::Yuv420),
+            yuv_range: YuvRange::Full,
+            matrix_coefficients: config
+                .matrix_coefficients
+                .unwrap_or(MatrixCoefficients::Bt601),
+            ..Default::default()
+        };
+        rgb.convert_to_yuv(&mut yuv)?;
+        Ok(yuv)
+    }
+
+    fn has_more_frames(&mut self) -> bool {
+        false
+    }
+}
diff --git a/src/utils/reader/mod.rs b/src/utils/reader/mod.rs
new file mode 100644
index 0000000..a12b44f
--- /dev/null
+++ b/src/utils/reader/mod.rs
@@ -0,0 +1,39 @@
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
+#[cfg(feature = "jpeg")]
+pub mod jpeg;
+#[cfg(feature = "png")]
+pub mod png;
+pub mod y4m;
+
+use crate::image::Image;
+use crate::AvifResult;
+use crate::MatrixCoefficients;
+use crate::PixelFormat;
+
+#[derive(Default)]
+pub struct Config {
+    pub yuv_format: Option<PixelFormat>,
+    pub depth: Option<u8>,
+    pub matrix_coefficients: Option<MatrixCoefficients>,
+}
+
+pub trait Reader {
+    fn read_frame(&mut self, config: &Config) -> AvifResult<Image>;
+    fn has_more_frames(&mut self) -> bool;
+}
diff --git a/src/utils/reader/png.rs b/src/utils/reader/png.rs
new file mode 100644
index 0000000..9c25f60
--- /dev/null
+++ b/src/utils/reader/png.rs
@@ -0,0 +1,115 @@
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
+use crate::reformat::*;
+use crate::utils::pixels::Pixels;
+use crate::AvifError;
+use crate::AvifResult;
+use crate::*;
+
+use super::Config;
+use super::Reader;
+
+use std::fs::File;
+
+pub struct PngReader {
+    filename: String,
+}
+
+impl PngReader {
+    pub fn create(filename: &str) -> AvifResult<Self> {
+        Ok(Self {
+            filename: filename.into(),
+        })
+    }
+}
+
+impl Reader for PngReader {
+    fn read_frame(&mut self, config: &Config) -> AvifResult<Image> {
+        let file = File::open(self.filename.clone()).or(Err(AvifError::UnknownError(
+            "error opening input file".into(),
+        )))?;
+        let decoder = png::Decoder::new(file);
+        let mut reader = decoder.read_info().or(Err(AvifError::UnknownError(
+            "error reading png info".into(),
+        )))?;
+        let mut decoded_bytes = vec![0u8; reader.output_buffer_size()];
+        let info = reader
+            .next_frame(&mut decoded_bytes)
+            .or(Err(AvifError::UnknownError(
+                "error reading png frame".into(),
+            )))?;
+        let rgb_bytes = &decoded_bytes[..info.buffer_size()];
+        let rgb = rgb::Image {
+            width: info.width,
+            height: info.height,
+            depth: match info.bit_depth {
+                png::BitDepth::Eight => 8,
+                png::BitDepth::Sixteen => 16,
+                _ => {
+                    return Err(AvifError::UnknownError(format!(
+                        "png bit depth is not supported: {:#?}",
+                        info.bit_depth
+                    )))
+                }
+            },
+            format: match info.color_type {
+                png::ColorType::Rgb => rgb::Format::Rgb,
+                png::ColorType::Rgba => rgb::Format::Rgba,
+                _ => {
+                    return Err(AvifError::UnknownError(format!(
+                        "png color type not supported: {:#?}",
+                        info.color_type
+                    )))
+                }
+            },
+            pixels: match info.bit_depth {
+                png::BitDepth::Eight => Some(Pixels::Buffer(rgb_bytes.to_vec())),
+                png::BitDepth::Sixteen => {
+                    let mut rgb_bytes16: Vec<u16> = Vec::new();
+                    for bytes in rgb_bytes.chunks_exact(2) {
+                        rgb_bytes16.push(u16::from_be_bytes([bytes[0], bytes[1]]));
+                    }
+                    Some(Pixels::Buffer16(rgb_bytes16))
+                }
+                _ => {
+                    return Err(AvifError::UnknownError(format!(
+                        "png bit depth is not supported: {:#?}",
+                        info.bit_depth
+                    )))
+                }
+            },
+            row_bytes: info.line_size as u32,
+            ..Default::default()
+        };
+        let mut yuv = Image {
+            width: info.width,
+            height: info.height,
+            depth: config.depth.unwrap_or(std::cmp::min(rgb.depth, 12)),
+            yuv_format: config.yuv_format.unwrap_or(PixelFormat::Yuv420),
+            yuv_range: YuvRange::Full,
+            matrix_coefficients: config
+                .matrix_coefficients
+                .unwrap_or(MatrixCoefficients::Bt601),
+            ..Default::default()
+        };
+        rgb.convert_to_yuv(&mut yuv)?;
+        Ok(yuv)
+    }
+
+    fn has_more_frames(&mut self) -> bool {
+        // TODO: b/403090413 - maybe support APNG?
+        false
+    }
+}
diff --git a/src/utils/reader/y4m.rs b/src/utils/reader/y4m.rs
new file mode 100644
index 0000000..38f3927
--- /dev/null
+++ b/src/utils/reader/y4m.rs
@@ -0,0 +1,267 @@
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
+use crate::image::*;
+use crate::*;
+
+use std::fs::File;
+use std::io::prelude::*;
+
+use super::Config;
+use super::Reader;
+
+use std::io::BufReader;
+use std::io::Read;
+
+#[derive(Debug, Default)]
+pub struct Y4MReader {
+    width: u32,
+    height: u32,
+    depth: u8,
+    has_alpha: bool,
+    format: PixelFormat,
+    range: YuvRange,
+    chroma_sample_position: ChromaSamplePosition,
+    reader: Option<BufReader<File>>,
+}
+
+impl Y4MReader {
+    fn parse_colorspace(&mut self, colorspace: &str) -> AvifResult<()> {
+        (
+            self.depth,
+            self.format,
+            self.chroma_sample_position,
+            self.has_alpha,
+        ) = match colorspace {
+            "420jpeg" => (
+                8,
+                PixelFormat::Yuv420,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "420mpeg2" => (
+                8,
+                PixelFormat::Yuv420,
+                ChromaSamplePosition::Vertical,
+                false,
+            ),
+            "420paldv" => (
+                8,
+                PixelFormat::Yuv420,
+                ChromaSamplePosition::Colocated,
+                false,
+            ),
+            "444p10" => (
+                10,
+                PixelFormat::Yuv444,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "422p10" => (
+                10,
+                PixelFormat::Yuv422,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "420p10" => (
+                10,
+                PixelFormat::Yuv420,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "444p12" => (
+                12,
+                PixelFormat::Yuv444,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "422p12" => (
+                12,
+                PixelFormat::Yuv422,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "420p12" => (
+                12,
+                PixelFormat::Yuv420,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "444" => (
+                8,
+                PixelFormat::Yuv444,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "422" => (
+                8,
+                PixelFormat::Yuv422,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "420" => (
+                8,
+                PixelFormat::Yuv420,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "444alpha" => (
+                8,
+                PixelFormat::Yuv444,
+                ChromaSamplePosition::default(),
+                true,
+            ),
+            "mono" => (
+                8,
+                PixelFormat::Yuv400,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "mono10" => (
+                10,
+                PixelFormat::Yuv400,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            "mono12" => (
+                12,
+                PixelFormat::Yuv400,
+                ChromaSamplePosition::default(),
+                false,
+            ),
+            _ => return Err(AvifError::UnknownError("invalid colorspace string".into())),
+        };
+        Ok(())
+    }
+
+    pub fn create(filename: &str) -> AvifResult<Y4MReader> {
+        let mut reader = BufReader::new(File::open(filename).or(Err(AvifError::UnknownError(
+            "error opening input file".into(),
+        )))?);
+        let mut y4m_line = String::new();
+        let bytes_read = reader
+            .read_line(&mut y4m_line)
+            .or(Err(AvifError::UnknownError(
+                "error reading y4m line".into(),
+            )))?;
+        if bytes_read == 0 {
+            return Err(AvifError::UnknownError("no bytes in y4m line".into()));
+        }
+        y4m_line.pop();
+        let parts: Vec<&str> = y4m_line.split(" ").collect();
+        if parts[0] != "YUV4MPEG2" {
+            return Err(AvifError::UnknownError("Not a Y4M file".into()));
+        }
+        let mut y4m = Y4MReader {
+            range: YuvRange::Limited,
+            ..Default::default()
+        };
+        for part in parts[1..].iter() {
+            match part.get(0..1).unwrap_or("") {
+                "W" => y4m.width = part[1..].parse::<u32>().unwrap_or(0),
+                "H" => y4m.height = part[1..].parse::<u32>().unwrap_or(0),
+                "C" => y4m.parse_colorspace(&part[1..])?,
+                "F" => {
+                    // TODO: Handle frame rate.
+                }
+                "X" => {
+                    if part[1..] == *"COLORRANGE=FULL" {
+                        y4m.range = YuvRange::Full;
+                    }
+                }
+                _ => {}
+            }
+        }
+        if y4m.width == 0 || y4m.height == 0 || y4m.depth == 0 {
+            return Err(AvifError::InvalidArgument);
+        }
+        y4m.reader = Some(reader);
+        Ok(y4m)
+    }
+}
+
+impl Reader for Y4MReader {
+    fn read_frame(&mut self, _config: &Config) -> AvifResult<Image> {
+        const FRAME_MARKER: &str = "FRAME";
+        let mut frame_marker = String::new();
+        let bytes_read = self
+            .reader
+            .as_mut()
+            .unwrap()
+            .read_line(&mut frame_marker)
+            .or(Err(AvifError::UnknownError(
+                "could not read frame marker".into(),
+            )))?;
+        if bytes_read == 0 {
+            return Err(AvifError::UnknownError(
+                "could not read frame marker".into(),
+            ));
+        }
+        frame_marker.pop();
+        if frame_marker != FRAME_MARKER {
+            return Err(AvifError::UnknownError(
+                "could not find frame marker".into(),
+            ));
+        }
+        let mut image = image::Image {
+            width: self.width,
+            height: self.height,
+            depth: self.depth,
+            yuv_format: self.format,
+            yuv_range: self.range,
+            chroma_sample_position: self.chroma_sample_position,
+            ..Default::default()
+        };
+        image.allocate_planes(Category::Color)?;
+        if self.has_alpha {
+            image.allocate_planes(Category::Alpha)?;
+        }
+        let reader = self.reader.as_mut().unwrap();
+        for plane in ALL_PLANES {
+            if !image.has_plane(plane) {
+                continue;
+            }
+            let plane_data = image.plane_data(plane).unwrap();
+            for y in 0..plane_data.height {
+                if self.depth == 8 {
+                    let row = image.row_mut(plane, y)?;
+                    let row_slice = &mut row[..plane_data.width as usize];
+                    reader
+                        .read_exact(row_slice)
+                        .or(Err(AvifError::UnknownError("".into())))?;
+                } else {
+                    let row = image.row16_mut(plane, y)?;
+                    let row_slice = &mut row[..plane_data.width as usize];
+                    let mut pixel_bytes: [u8; 2] = [0, 0];
+                    for pixel in row_slice {
+                        reader
+                            .read_exact(&mut pixel_bytes)
+                            .or(Err(AvifError::UnknownError("".into())))?;
+                        // y4m is always little endian.
+                        *pixel = u16::from_le_bytes(pixel_bytes);
+                    }
+                }
+            }
+        }
+        Ok(image)
+    }
+
+    fn has_more_frames(&mut self) -> bool {
+        let buffer = match self.reader.as_mut().unwrap().fill_buf() {
+            Ok(buffer) => buffer,
+            Err(_) => return false,
+        };
+        !buffer.is_empty()
+    }
+}
diff --git a/examples/writer/jpeg.rs b/src/utils/writer/jpeg.rs
similarity index 90%
rename from examples/writer/jpeg.rs
rename to src/utils/writer/jpeg.rs
index 9d3fcae..95046e8 100644
--- a/examples/writer/jpeg.rs
+++ b/src/utils/writer/jpeg.rs
@@ -12,10 +12,10 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crabby_avif::image::*;
-use crabby_avif::reformat::rgb;
-use crabby_avif::AvifError;
-use crabby_avif::AvifResult;
+use crate::image::*;
+use crate::reformat::rgb;
+use crate::AvifError;
+use crate::AvifResult;
 
 use super::Writer;
 
@@ -23,7 +23,7 @@ use image::codecs::jpeg;
 use std::fs::File;
 
 #[derive(Default)]
-pub(crate) struct JpegWriter {
+pub struct JpegWriter {
     pub quality: Option<u8>,
 }
 
diff --git a/examples/writer/mod.rs b/src/utils/writer/mod.rs
similarity index 85%
rename from examples/writer/mod.rs
rename to src/utils/writer/mod.rs
index cb081e4..0bbce9a 100644
--- a/examples/writer/mod.rs
+++ b/src/utils/writer/mod.rs
@@ -15,12 +15,14 @@
 // Not all sub-modules are used by all targets. Ignore dead code warnings.
 #![allow(dead_code)]
 
-pub(crate) mod jpeg;
-pub(crate) mod png;
-pub(crate) mod y4m;
+#[cfg(feature = "jpeg")]
+pub mod jpeg;
+#[cfg(feature = "png")]
+pub mod png;
+pub mod y4m;
 
-use crabby_avif::image::Image;
-use crabby_avif::AvifResult;
+use crate::image::Image;
+use crate::AvifResult;
 
 use std::fs::File;
 
diff --git a/examples/writer/png.rs b/src/utils/writer/png.rs
similarity index 96%
rename from examples/writer/png.rs
rename to src/utils/writer/png.rs
index 87c3bd6..e3991b8 100644
--- a/examples/writer/png.rs
+++ b/src/utils/writer/png.rs
@@ -12,20 +12,18 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crabby_avif::image::*;
-use crabby_avif::reformat::rgb;
-use crabby_avif::AvifError;
-use crabby_avif::AvifResult;
-use crabby_avif::PixelFormat;
+use crate::image::*;
+use crate::reformat::rgb;
+use crate::AvifError;
+use crate::AvifResult;
+use crate::PixelFormat;
 
 use std::fs::File;
 
 use super::Writer;
 
-use png;
-
 #[derive(Default)]
-pub(crate) struct PngWriter {
+pub struct PngWriter {
     pub depth: Option<u8>,
 }
 
diff --git a/examples/writer/y4m.rs b/src/utils/writer/y4m.rs
similarity index 97%
rename from examples/writer/y4m.rs
rename to src/utils/writer/y4m.rs
index e45bfc6..9286be1 100644
--- a/examples/writer/y4m.rs
+++ b/src/utils/writer/y4m.rs
@@ -12,7 +12,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-#[allow(unused_imports)]
 use crate::image::*;
 use crate::*;
 
@@ -22,15 +21,14 @@ use std::io::prelude::*;
 use super::Writer;
 
 #[derive(Default)]
-pub(crate) struct Y4MWriter {
+pub struct Y4MWriter {
     header_written: bool,
     write_alpha: bool,
     skip_headers: bool,
 }
 
 impl Y4MWriter {
-    #[allow(unused)]
-    pub(crate) fn create(skip_headers: bool) -> Self {
+    pub fn create(skip_headers: bool) -> Self {
         Self {
             skip_headers,
             ..Default::default()
diff --git a/sys/libyuv-sys/build.rs b/sys/libyuv-sys/build.rs
index e3eb501..b8a4a4d 100644
--- a/sys/libyuv-sys/build.rs
+++ b/sys/libyuv-sys/build.rs
@@ -93,53 +93,77 @@ fn main() {
         .layout_tests(false)
         .generate_comments(false);
     let allowlist_items = &[
-        "YuvConstants",
-        "FilterMode",
+        "ABGRToI420",
+        "ABGRToJ400",
+        "ABGRToJ420",
+        "ABGRToJ422",
+        "AR30ToAB30",
         "ARGBAttenuate",
         "ARGBToABGR",
+        "ARGBToI400",
+        "ARGBToI420",
+        "ARGBToI422",
+        "ARGBToI444",
+        "ARGBToJ400",
+        "ARGBToJ420",
+        "ARGBToJ422",
         "ARGBUnattenuate",
+        "BGRAToI420",
         "Convert16To8Plane",
-        "HalfFloatPlane",
-        "ScalePlane_12",
-        "ScalePlane",
+        "FilterMode",
         "FilterMode_kFilterBilinear",
         "FilterMode_kFilterBox",
         "FilterMode_kFilterNone",
-        "I010AlphaToARGBMatrixFilter",
+        "HalfFloatPlane",
         "I010AlphaToARGBMatrix",
-        "I010ToARGBMatrixFilter",
+        "I010AlphaToARGBMatrixFilter",
+        "I010ToAR30Matrix",
         "I010ToARGBMatrix",
+        "I010ToARGBMatrixFilter",
         "I012ToARGBMatrix",
-        "I210AlphaToARGBMatrixFilter",
         "I210AlphaToARGBMatrix",
-        "I210ToARGBMatrixFilter",
+        "I210AlphaToARGBMatrixFilter",
         "I210ToARGBMatrix",
+        "I210ToARGBMatrixFilter",
         "I400ToARGBMatrix",
         "I410AlphaToARGBMatrix",
         "I410ToARGBMatrix",
-        "I420AlphaToARGBMatrixFilter",
         "I420AlphaToARGBMatrix",
-        "I420ToARGBMatrixFilter",
+        "I420AlphaToARGBMatrixFilter",
         "I420ToARGBMatrix",
-        "I420ToRGB24MatrixFilter",
+        "I420ToARGBMatrixFilter",
         "I420ToRGB24Matrix",
+        "I420ToRGB24MatrixFilter",
         "I420ToRGB565Matrix",
         "I420ToRGBAMatrix",
-        "I422AlphaToARGBMatrixFilter",
         "I422AlphaToARGBMatrix",
-        "I422ToARGBMatrixFilter",
+        "I422AlphaToARGBMatrixFilter",
         "I422ToARGBMatrix",
+        "I422ToARGBMatrixFilter",
         "I422ToRGB24MatrixFilter",
         "I422ToRGB565Matrix",
         "I422ToRGBAMatrix",
         "I444AlphaToARGBMatrix",
         "I444ToARGBMatrix",
         "I444ToRGB24Matrix",
+        "NV12Scale",
         "NV12ToARGBMatrix",
+        "NV12ToRGB565Matrix",
         "NV21ToARGBMatrix",
         "P010ToAR30Matrix",
         "P010ToARGBMatrix",
-        "AR30ToAB30",
+        "P010ToI010",
+        "RAWToI420",
+        "RAWToJ400",
+        "RAWToJ420",
+        "RGB24ToI420",
+        "RGB24ToJ400",
+        "RGB24ToJ420",
+        "RGBAToI420",
+        "RGBAToJ400",
+        "ScalePlane",
+        "ScalePlane_12",
+        "YuvConstants",
         "kYuv2020Constants",
         "kYuvF709Constants",
         "kYuvH709Constants",
diff --git a/sys/libyuv-sys/libyuv.cmd b/sys/libyuv-sys/libyuv.cmd
index 0aca6b2..db67e5f 100755
--- a/sys/libyuv-sys/libyuv.cmd
+++ b/sys/libyuv-sys/libyuv.cmd
@@ -17,7 +17,7 @@ cd libyuv
 : # When changing the commit below to a newer version of libyuv, it is best to make sure it is being used by chromium,
 : # because the test suite of chromium provides additional test coverage of libyuv.
 : # It can be looked up at https://source.chromium.org/chromium/chromium/src/+/main:DEPS?q=libyuv.
-git checkout 04821d1e
+git checkout dc47c71b
 
 mkdir build
 cd build
diff --git a/sys/ndk-sys/build.rs b/sys/ndk-sys/build.rs
index 3f4f5b5..0dd61e0 100644
--- a/sys/ndk-sys/build.rs
+++ b/sys/ndk-sys/build.rs
@@ -27,7 +27,17 @@ fn main() {
 
     let build_target = std::env::var("TARGET").unwrap();
     if !build_target.contains("android") {
-        panic!("Not an android target: {build_target}");
+        println!("cargo::warning=Not an android target: {build_target}");
+        // Define CRABBYAVIF_ANDROID_NDK_MEDIA_BINDINGS_RS to avoid src/lib.rs
+        // complaining about either undefined env!() or non-literal string.
+        // Point to an empty file as a no-op.
+        println!(
+            "cargo:rustc-env=CRABBYAVIF_ANDROID_NDK_MEDIA_BINDINGS_RS={}",
+            PathBuf::from(&PathBuf::from(env!("CARGO_MANIFEST_DIR")))
+                .join(path_buf(&["src", "empty.rs"]))
+                .display()
+        );
+        return;
     };
 
     // Generate bindings.
@@ -37,7 +47,7 @@ fn main() {
     let host_tag = "linux-x86_64"; // TODO: Support windows and mac.
     let sysroot = format!(
         "{}/toolchains/llvm/prebuilt/{}/sysroot/",
-        env!("ANDROID_NDK_ROOT"),
+        option_env!("ANDROID_NDK_ROOT").unwrap(),
         host_tag
     );
     let mut bindings = bindgen::Builder::default()
diff --git a/sys/ndk-sys/src/empty.rs b/sys/ndk-sys/src/empty.rs
new file mode 100644
index 0000000..8c45f32
--- /dev/null
+++ b/sys/ndk-sys/src/empty.rs
@@ -0,0 +1,15 @@
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
+// Empty file on purpose. See ../build.rs.
diff --git a/tests/conformance_tests.rs b/tests/conformance_tests.rs
index 6f9b65a..47370af 100644
--- a/tests/conformance_tests.rs
+++ b/tests/conformance_tests.rs
@@ -13,6 +13,8 @@
 // limitations under the License.
 
 use crabby_avif::image::*;
+use crabby_avif::utils::writer::y4m::Y4MWriter;
+use crabby_avif::utils::writer::Writer;
 use crabby_avif::*;
 
 use std::env;
@@ -23,11 +25,6 @@ use std::io::Read;
 use std::process::Command;
 use tempfile::NamedTempFile;
 
-#[path = "../examples/writer/mod.rs"]
-mod writer;
-
-use writer::Writer;
-
 // See README.md for instructions on how to set up the dependencies for
 // running the conformance tests.
 
@@ -109,7 +106,7 @@ fn get_tempfile() -> String {
 }
 
 fn write_y4m(image: &Image) -> String {
-    let mut y4m = writer::y4m::Y4MWriter::default();
+    let mut y4m = Y4MWriter::default();
     let filename = get_tempfile();
     let mut file = File::create(&filename).expect("unable to open output file");
     y4m.write_frame(&mut file, image)
@@ -148,13 +145,14 @@ fn compare_files(file1: &String, file2: &String) -> bool {
     true
 }
 
+#[allow(clippy::zero_prefixed_literal)]
 #[test_case::test_matrix(0usize..172)]
 fn test_conformance(index: usize) {
     let expected_info = &EXPECTED_INFOS[index];
     let filename = get_test_file(expected_info.filename);
     let mut decoder = decoder::Decoder::default();
     decoder.settings.strictness = decoder::Strictness::None;
-    let _ = decoder.set_io_file(&filename).expect("Failed to set IO");
+    decoder.set_io_file(&filename).expect("Failed to set IO");
     let res = decoder.parse();
     assert!(res.is_ok());
     assert_eq!(
@@ -166,7 +164,7 @@ fn test_conformance(index: usize) {
         decoder.io_stats().alpha_obu_size
     );
     let image = decoder.image().expect("image was none");
-    verify_info(expected_info, &image);
+    verify_info(expected_info, image);
     let res = decoder.next_image();
     assert!(res.is_ok());
     let image = decoder.image().expect("image was none");
@@ -174,7 +172,7 @@ fn test_conformance(index: usize) {
     // Link-U 422 files have wrong subsampling in the Avif header(decoded one
     // is right).
     if !filename.contains("Link-U") || !filename.contains("yuv422") {
-        verify_info(expected_info, &image);
+        verify_info(expected_info, image);
     }
 
     // Write y4m.
diff --git a/tests/data/color_grid_alpha_grid_gainmap_nogrid.avif b/tests/data/color_grid_alpha_grid_gainmap_nogrid.avif
index 0dd4265..98c9885 100644
Binary files a/tests/data/color_grid_alpha_grid_gainmap_nogrid.avif and b/tests/data/color_grid_alpha_grid_gainmap_nogrid.avif differ
diff --git a/tests/data/color_grid_gainmap_different_grid.avif b/tests/data/color_grid_gainmap_different_grid.avif
index 17d14da..d7474c0 100644
Binary files a/tests/data/color_grid_gainmap_different_grid.avif and b/tests/data/color_grid_gainmap_different_grid.avif differ
diff --git a/tests/data/draw_points_idat.avif b/tests/data/draw_points_idat.avif
new file mode 100644
index 0000000..877e654
Binary files /dev/null and b/tests/data/draw_points_idat.avif differ
diff --git a/tests/data/draw_points_idat_metasize0.avif b/tests/data/draw_points_idat_metasize0.avif
new file mode 100644
index 0000000..bf78bfd
Binary files /dev/null and b/tests/data/draw_points_idat_metasize0.avif differ
diff --git a/tests/data/draw_points_idat_progressive.avif b/tests/data/draw_points_idat_progressive.avif
new file mode 100644
index 0000000..fe8b23d
Binary files /dev/null and b/tests/data/draw_points_idat_progressive.avif differ
diff --git a/tests/data/draw_points_idat_progressive_metasize0.avif b/tests/data/draw_points_idat_progressive_metasize0.avif
new file mode 100644
index 0000000..2eb8614
Binary files /dev/null and b/tests/data/draw_points_idat_progressive_metasize0.avif differ
diff --git a/tests/data/grid_icc_individual_cells.avif b/tests/data/grid_icc_individual_cells.avif
new file mode 100644
index 0000000..0b1196a
Binary files /dev/null and b/tests/data/grid_icc_individual_cells.avif differ
diff --git a/tests/data/grid_nclx_individual_cells.avif b/tests/data/grid_nclx_individual_cells.avif
new file mode 100644
index 0000000..fed642b
Binary files /dev/null and b/tests/data/grid_nclx_individual_cells.avif differ
diff --git a/tests/data/mismatch_colr_0_0.avif b/tests/data/mismatch_colr_0_0.avif
new file mode 100644
index 0000000..557e2f0
Binary files /dev/null and b/tests/data/mismatch_colr_0_0.avif differ
diff --git a/tests/data/mismatch_colr_0_1.avif b/tests/data/mismatch_colr_0_1.avif
new file mode 100644
index 0000000..3c878fc
Binary files /dev/null and b/tests/data/mismatch_colr_0_1.avif differ
diff --git a/tests/data/mismatch_colr_0_2.avif b/tests/data/mismatch_colr_0_2.avif
new file mode 100644
index 0000000..a02b949
Binary files /dev/null and b/tests/data/mismatch_colr_0_2.avif differ
diff --git a/tests/data/mismatch_colr_1_0.avif b/tests/data/mismatch_colr_1_0.avif
new file mode 100644
index 0000000..3d134a1
Binary files /dev/null and b/tests/data/mismatch_colr_1_0.avif differ
diff --git a/tests/data/mismatch_colr_1_1.avif b/tests/data/mismatch_colr_1_1.avif
new file mode 100644
index 0000000..9f694d4
Binary files /dev/null and b/tests/data/mismatch_colr_1_1.avif differ
diff --git a/tests/data/mismatch_colr_1_2.avif b/tests/data/mismatch_colr_1_2.avif
new file mode 100644
index 0000000..a39f90f
Binary files /dev/null and b/tests/data/mismatch_colr_1_2.avif differ
diff --git a/tests/data/missing_colr_0_0.avif b/tests/data/missing_colr_0_0.avif
new file mode 100644
index 0000000..b2889fd
Binary files /dev/null and b/tests/data/missing_colr_0_0.avif differ
diff --git a/tests/data/missing_colr_0_1.avif b/tests/data/missing_colr_0_1.avif
new file mode 100644
index 0000000..8b7ebc2
Binary files /dev/null and b/tests/data/missing_colr_0_1.avif differ
diff --git a/tests/data/missing_colr_0_2.avif b/tests/data/missing_colr_0_2.avif
new file mode 100644
index 0000000..3e85078
Binary files /dev/null and b/tests/data/missing_colr_0_2.avif differ
diff --git a/tests/data/missing_colr_1_0.avif b/tests/data/missing_colr_1_0.avif
new file mode 100644
index 0000000..844baca
Binary files /dev/null and b/tests/data/missing_colr_1_0.avif differ
diff --git a/tests/data/missing_colr_1_1.avif b/tests/data/missing_colr_1_1.avif
new file mode 100644
index 0000000..9d5e5e7
Binary files /dev/null and b/tests/data/missing_colr_1_1.avif differ
diff --git a/tests/data/missing_colr_1_2.avif b/tests/data/missing_colr_1_2.avif
new file mode 100644
index 0000000..e9d995c
Binary files /dev/null and b/tests/data/missing_colr_1_2.avif differ
diff --git a/tests/data/paris_exif_non_zero_tiff_offset.avif b/tests/data/paris_exif_non_zero_tiff_offset.avif
new file mode 100644
index 0000000..5f1507f
Binary files /dev/null and b/tests/data/paris_exif_non_zero_tiff_offset.avif differ
diff --git a/tests/data/paris_exif_xmp_icc.jpg b/tests/data/paris_exif_xmp_icc.jpg
new file mode 100644
index 0000000..4b40002
Binary files /dev/null and b/tests/data/paris_exif_xmp_icc.jpg differ
diff --git a/tests/data/seine_hdr_gainmap_wrongaltr.avif b/tests/data/seine_hdr_gainmap_wrongaltr.avif
new file mode 100644
index 0000000..b583caa
Binary files /dev/null and b/tests/data/seine_hdr_gainmap_wrongaltr.avif differ
diff --git a/tests/data/seine_sdr_gainmap_notmapbrand.avif b/tests/data/seine_sdr_gainmap_notmapbrand.avif
new file mode 100644
index 0000000..b716742
Binary files /dev/null and b/tests/data/seine_sdr_gainmap_notmapbrand.avif differ
diff --git a/tests/data/tmap_primary_item.avif b/tests/data/tmap_primary_item.avif
new file mode 100644
index 0000000..a6b352e
Binary files /dev/null and b/tests/data/tmap_primary_item.avif differ
diff --git a/tests/data/weld_16bit.png b/tests/data/weld_16bit.png
new file mode 100644
index 0000000..884ca14
Binary files /dev/null and b/tests/data/weld_16bit.png differ
diff --git a/tests/data/weld_sato_12plus4bit.avif b/tests/data/weld_sato_12plus4bit.avif
new file mode 100644
index 0000000..d77728f
Binary files /dev/null and b/tests/data/weld_sato_12plus4bit.avif differ
diff --git a/tests/data/weld_sato_8plus8bit.avif b/tests/data/weld_sato_8plus8bit.avif
new file mode 100644
index 0000000..97d6c6d
Binary files /dev/null and b/tests/data/weld_sato_8plus8bit.avif differ
diff --git a/tests/data/weld_sato_8plus8bit_alpha.avif b/tests/data/weld_sato_8plus8bit_alpha.avif
new file mode 100644
index 0000000..ea57042
Binary files /dev/null and b/tests/data/weld_sato_8plus8bit_alpha.avif differ
diff --git a/tests/decoder_tests.rs b/tests/decoder_tests.rs
index 186ded4..21594fb 100644
--- a/tests/decoder_tests.rs
+++ b/tests/decoder_tests.rs
@@ -19,12 +19,13 @@ use crabby_avif::image::*;
 use crabby_avif::reformat::rgb;
 use crabby_avif::*;
 
-#[path = "./mod.rs"]
-mod tests;
+mod utils;
+use utils::*;
 
 use std::cell::RefCell;
 use std::rc::Rc;
-use tests::*;
+use test_case::test_case;
+use test_case::test_matrix;
 
 // From avifalphanoispetest.cc
 #[test]
@@ -79,8 +80,8 @@ fn alpha_premultiplied() {
 }
 
 // From avifanimationtest.cc
-#[test_case::test_case("colors-animated-8bpc.avif")]
-#[test_case::test_case("colors-animated-8bpc-audio.avif")]
+#[test_case("colors-animated-8bpc.avif")]
+#[test_case("colors-animated-8bpc-audio.avif")]
 fn animated_image(filename: &str) {
     let mut decoder = get_decoder(filename);
     let res = decoder.parse();
@@ -103,8 +104,8 @@ fn animated_image(filename: &str) {
 }
 
 // From avifanimationtest.cc
-#[test_case::test_case("colors-animated-8bpc.avif")]
-#[test_case::test_case("colors-animated-8bpc-audio.avif")]
+#[test_case("colors-animated-8bpc.avif")]
+#[test_case("colors-animated-8bpc-audio.avif")]
 fn animated_image_with_source_set_to_primary_item(filename: &str) {
     let mut decoder = get_decoder(filename);
     decoder.settings.source = decoder::Source::PrimaryItem;
@@ -253,13 +254,38 @@ fn color_grid_alpha_no_grid() {
     assert!(alpha_plane.unwrap().row_bytes > 0);
 }
 
+#[test_case("paris_icc_exif_xmp.avif")]
+#[test_case("sofa_grid1x5_420.avif")]
+#[test_case("color_grid_alpha_nogrid.avif")]
+#[test_case("seine_sdr_gainmap_srgb.avif")]
+fn image_content_to_decode_none(filename: &str) {
+    let mut decoder = get_decoder(filename);
+    decoder.settings.image_content_to_decode = ImageContentType::None;
+    assert!(decoder.parse().is_ok());
+    assert!(decoder.next_image().is_err());
+}
+
+#[test_case("draw_points_idat.avif")]
+#[test_case("draw_points_idat_metasize0.avif")]
+#[test_case("draw_points_idat_progressive.avif")]
+#[test_case("draw_points_idat_progressive_metasize0.avif")]
+fn idat(filename: &str) {
+    let mut decoder = get_decoder(filename);
+    assert!(decoder.parse().is_ok());
+    if !HAS_DECODER {
+        return;
+    }
+    let res = decoder.next_image();
+    assert_eq!(res, Ok(()));
+}
+
 // From avifprogressivetest.cc
-#[test_case::test_case("progressive_dimension_change.avif", 2, 256, 256; "progressive_dimension_change")]
-#[test_case::test_case("progressive_layered_grid.avif", 2, 512, 256; "progressive_layered_grid")]
-#[test_case::test_case("progressive_quality_change.avif", 2, 256, 256; "progressive_quality_change")]
-#[test_case::test_case("progressive_same_layers.avif", 4, 256, 256; "progressive_same_layers")]
-#[test_case::test_case("tiger_3layer_1res.avif", 3, 1216, 832; "tiger_3layer_1res")]
-#[test_case::test_case("tiger_3layer_3res.avif", 3, 1216, 832; "tiger_3layer_3res")]
+#[test_case("progressive_dimension_change.avif", 2, 256, 256; "progressive_dimension_change")]
+#[test_case("progressive_layered_grid.avif", 2, 512, 256; "progressive_layered_grid")]
+#[test_case("progressive_quality_change.avif", 2, 256, 256; "progressive_quality_change")]
+#[test_case("progressive_same_layers.avif", 4, 256, 256; "progressive_same_layers")]
+#[test_case("tiger_3layer_1res.avif", 3, 1216, 832; "tiger_3layer_1res")]
+#[test_case("tiger_3layer_3res.avif", 3, 1216, 832; "tiger_3layer_3res")]
 fn progressive(filename: &str, layer_count: u32, width: u32, height: u32) {
     let mut filename_with_prefix = String::from("progressive/");
     filename_with_prefix.push_str(filename);
@@ -299,6 +325,25 @@ fn progressive(filename: &str, layer_count: u32, width: u32, height: u32) {
     }
 }
 
+#[test]
+fn decoder_parse_exif_non_zero_tiff_offset() {
+    let mut decoder = get_decoder("paris_exif_non_zero_tiff_offset.avif");
+
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
+    let image = decoder.image().expect("image was none");
+
+    assert_eq!(image.exif.len(), 1129);
+    assert_eq!(image.exif[0], 0);
+    assert_eq!(image.exif[1], 0);
+    assert_eq!(image.exif[2], 0);
+    assert_eq!(image.exif[3], 73);
+    assert_eq!(image.exif[4], 73);
+    assert_eq!(image.exif[5], 42);
+    assert_eq!(image.exif[6], 0);
+}
+
 // From avifmetadatatest.cc
 #[test]
 fn decoder_parse_icc_exif_xmp() {
@@ -341,6 +386,34 @@ fn decoder_parse_icc_exif_xmp() {
     assert_eq!(image.xmp[3], 112);
 }
 
+#[test]
+fn decode_gainmap() {
+    let filename = "tmap_primary_item.avif";
+    let mut decoder = get_decoder(filename);
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    // Gain map found but not decoded.
+    assert!(decoder.gainmap_present());
+    assert!(
+        decoder.gainmap().metadata.base_hdr_headroom.0 != 0
+            || decoder.gainmap().metadata.alternate_hdr_headroom.0 != 0
+    );
+    assert_eq!(decoder.gainmap().image.width, 0);
+
+    // Decode again with image_content_to_decode = ImageContentType::All.
+    decoder = get_decoder(filename);
+    decoder.settings.image_content_to_decode = ImageContentType::All;
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    // Gain map found and decoded.
+    assert!(decoder.gainmap_present());
+    assert!(
+        decoder.gainmap().metadata.base_hdr_headroom.0 != 0
+            || decoder.gainmap().metadata.alternate_hdr_headroom.0 != 0
+    );
+    assert_ne!(decoder.gainmap().image.width, 0);
+}
+
 // From avifgainmaptest.cc
 #[test]
 fn color_grid_gainmap_different_grid() {
@@ -441,30 +514,36 @@ fn gainmap_oriented() {
     assert_eq!(decoder.gainmap().image.imir_axis, None);
 }
 
-// The two test files should produce the same results:
-// One has an unsupported 'version' field, the other an unsupported
-// 'minimum_version' field, but the behavior of these two files is the same.
 // From avifgainmaptest.cc
-#[test_case::test_case("unsupported_gainmap_version.avif")]
-#[test_case::test_case("unsupported_gainmap_minimum_version.avif")]
+// Tests files with gain maps that should be ignored by the decoder for various
+// reasons.
+// File with unsupported version field.
+#[test_case("unsupported_gainmap_version.avif")]
+// File with unsupported minimum version field.
+#[test_case("unsupported_gainmap_minimum_version.avif")]
+// Missing 'tmap' brand in ftyp box.
+#[test_case("seine_sdr_gainmap_notmapbrand.avif")]
+// Gain map not present before the base image in 'altr' box.
+#[test_case("seine_hdr_gainmap_wrongaltr.avif")]
 fn decode_unsupported_version(filename: &str) {
     // Parse with various settings.
     let mut decoder = get_decoder(filename);
     let res = decoder.parse();
     assert!(res.is_ok());
     assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
-    // Gain map marked as not present because the metadata is not supported.
+    // Gain map marked as not present.
     assert!(!decoder.gainmap_present());
     assert_eq!(decoder.gainmap().image.width, 0);
     assert_eq!(decoder.gainmap().metadata.base_hdr_headroom.0, 0);
     assert_eq!(decoder.gainmap().metadata.alternate_hdr_headroom.0, 0);
 
+    // Decode again with image_content_to_decode = ImageContentType::All.
     decoder = get_decoder(filename);
     decoder.settings.image_content_to_decode = ImageContentType::All;
     let res = decoder.parse();
     assert!(res.is_ok());
     assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
-    // Gainmap not found: its metadata is not supported.
+    // Gain map marked as not present.
     assert!(!decoder.gainmap_present());
     assert_eq!(decoder.gainmap().image.width, 0);
     assert_eq!(decoder.gainmap().metadata.base_hdr_headroom.0, 0);
@@ -546,10 +625,10 @@ fn decode_ignore_color_and_alpha() {
 }
 
 // From avifgainmaptest.cc
-#[test_case::test_case("paris_icc_exif_xmp.avif")]
-#[test_case::test_case("sofa_grid1x5_420.avif")]
-#[test_case::test_case("color_grid_alpha_nogrid.avif")]
-#[test_case::test_case("seine_sdr_gainmap_srgb.avif")]
+#[test_case("paris_icc_exif_xmp.avif")]
+#[test_case("sofa_grid1x5_420.avif")]
+#[test_case("color_grid_alpha_nogrid.avif")]
+#[test_case("seine_sdr_gainmap_srgb.avif")]
 fn decode_ignore_all(filename: &str) {
     let mut decoder = get_decoder(filename);
     // Ignore both the main image and the gain map.
@@ -569,15 +648,15 @@ fn decode_ignore_all(filename: &str) {
 }
 
 // From avifcllitest.cc
-#[test_case::test_case("clli_0_0.avif", 0, 0; "clli_0_0")]
-#[test_case::test_case("clli_0_1.avif", 0, 1; "clli_0_1")]
-#[test_case::test_case("clli_0_65535.avif", 0, 65535; "clli_0_65535")]
-#[test_case::test_case("clli_1_0.avif", 1, 0; "clli_1_0")]
-#[test_case::test_case("clli_1_1.avif", 1, 1; "clli_1_1")]
-#[test_case::test_case("clli_1_65535.avif", 1, 65535; "clli_1_65535")]
-#[test_case::test_case("clli_65535_0.avif", 65535, 0; "clli_65535_0")]
-#[test_case::test_case("clli_65535_1.avif", 65535, 1; "clli_65535_1")]
-#[test_case::test_case("clli_65535_65535.avif", 65535, 65535; "clli_65535_65535")]
+#[test_case("clli_0_0.avif", 0, 0; "clli_0_0")]
+#[test_case("clli_0_1.avif", 0, 1; "clli_0_1")]
+#[test_case("clli_0_65535.avif", 0, 65535; "clli_0_65535")]
+#[test_case("clli_1_0.avif", 1, 0; "clli_1_0")]
+#[test_case("clli_1_1.avif", 1, 1; "clli_1_1")]
+#[test_case("clli_1_65535.avif", 1, 65535; "clli_1_65535")]
+#[test_case("clli_65535_0.avif", 65535, 0; "clli_65535_0")]
+#[test_case("clli_65535_1.avif", 65535, 1; "clli_65535_1")]
+#[test_case("clli_65535_65535.avif", 65535, 65535; "clli_65535_65535")]
 fn clli(filename: &str, max_cll: u16, max_pall: u16) {
     let mut filename_with_prefix = String::from("clli/");
     filename_with_prefix.push_str(filename);
@@ -601,11 +680,11 @@ fn raw_io() {
     let data =
         std::fs::read(get_test_file("colors-animated-8bpc.avif")).expect("Unable to read file");
     let mut decoder = decoder::Decoder::default();
-    let _ = unsafe {
+    unsafe {
         decoder
             .set_io_raw(data.as_ptr(), data.len())
-            .expect("Failed to set IO")
-    };
+            .expect("Failed to set IO");
+    }
     assert!(decoder.parse().is_ok());
     assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
     assert_eq!(decoder.image_count(), 5);
@@ -678,7 +757,7 @@ fn expected_min_decoded_row_count(
     cell_columns: u32,
     available_size: usize,
     size: usize,
-    grid_cell_offsets: &Vec<usize>,
+    grid_cell_offsets: &[usize],
 ) -> u32 {
     if available_size >= size {
         return height;
@@ -709,7 +788,7 @@ fn expected_min_decoded_row_count_computation() {
         expected_min_decoded_row_count(770, cell_height, 1, 1000, 30000, &grid_cell_offsets)
     );
     assert_eq!(
-        1 * cell_height,
+        cell_height,
         expected_min_decoded_row_count(770, cell_height, 1, 4000, 30000, &grid_cell_offsets)
     );
     assert_eq!(
@@ -721,7 +800,7 @@ fn expected_min_decoded_row_count_computation() {
         expected_min_decoded_row_count(770, cell_height, 1, 17846, 30000, &grid_cell_offsets)
     );
     assert_eq!(
-        1 * cell_height,
+        cell_height,
         expected_min_decoded_row_count(462, cell_height, 2, 17846, 30000, &grid_cell_offsets)
     );
     assert_eq!(
@@ -729,7 +808,7 @@ fn expected_min_decoded_row_count_computation() {
         expected_min_decoded_row_count(462, cell_height, 2, 23000, 30000, &grid_cell_offsets)
     );
     assert_eq!(
-        1 * cell_height,
+        cell_height,
         expected_min_decoded_row_count(308, cell_height, 3, 23000, 30000, &grid_cell_offsets)
     );
     assert_eq!(
@@ -770,8 +849,7 @@ fn incremental_decode() {
         {
             let mut available_size = available_size_rc.borrow_mut();
             if *available_size >= len {
-                println!("parse returned waiting on io after full file.");
-                assert!(false);
+                panic!("parse returned waiting on io after full file.");
             }
             *available_size = std::cmp::min(*available_size + step, len);
         }
@@ -794,8 +872,7 @@ fn incremental_decode() {
         {
             let mut available_size = available_size_rc.borrow_mut();
             if *available_size >= len {
-                println!("next_image returned waiting on io after full file.");
-                assert!(false);
+                panic!("next_image returned waiting on io after full file.");
             }
             let decoded_row_count = decoder.decoded_row_count();
             assert!(decoded_row_count >= previous_decoded_row_count);
@@ -819,6 +896,89 @@ fn incremental_decode() {
     // TODO: check if incremental and non incremental produces same output.
 }
 
+#[test]
+fn progressive_partial_data() -> AvifResult<()> {
+    let data = std::fs::read(get_test_file(
+        "progressive/progressive_dimension_change.avif",
+    ))
+    .expect("Unable to read file");
+    let len = data.len();
+    let available_size_rc = Rc::new(RefCell::new(0usize));
+    let mut decoder = decoder::Decoder::default();
+    decoder.settings.allow_progressive = true;
+    let io = Box::new(CustomIO {
+        available_size_rc: available_size_rc.clone(),
+        data,
+    });
+    decoder.set_io(io);
+
+    // Parse.
+    let mut parse_result = decoder.parse();
+    while parse_result.is_err()
+        && matches!(parse_result.as_ref().err().unwrap(), AvifError::WaitingOnIo)
+    {
+        {
+            let mut available_size = available_size_rc.borrow_mut();
+            if *available_size >= len {
+                panic!("parse returned waiting on io after full file.");
+            }
+            *available_size = std::cmp::min(*available_size + 1, len);
+        }
+        parse_result = decoder.parse();
+    }
+    assert!(parse_result.is_ok());
+    if !HAS_DECODER {
+        return Ok(());
+    }
+
+    assert_eq!(decoder.image_count(), 2);
+    let extent0 = decoder.nth_image_max_extent(0)?;
+    assert_eq!(extent0.offset, 306);
+    assert_eq!(extent0.size, 2250);
+    let extent1 = decoder.nth_image_max_extent(1)?;
+    assert_eq!(extent1.offset, 306);
+    assert_eq!(extent1.size, 3813);
+
+    // Getting the first frame now should fail.
+    assert_eq!(decoder.nth_image(0), Err(AvifError::WaitingOnIo));
+    // Set the available size to 1 byte less than the first frame's extent.
+    *available_size_rc.borrow_mut() = extent0.offset as usize + extent0.size - 1;
+    assert_eq!(decoder.nth_image(0), Err(AvifError::WaitingOnIo));
+    // Set the available size to exactly the first frame's extent.
+    *available_size_rc.borrow_mut() = extent0.offset as usize + extent0.size;
+    assert!(decoder.nth_image(0).is_ok());
+    let image = decoder.image().expect("unable to get image");
+    assert_eq!(image.width, 256);
+    assert_eq!(image.height, 256);
+    assert!(image.has_plane(Plane::Y));
+    assert!(image.has_plane(Plane::U));
+    assert!(image.has_plane(Plane::V));
+    // Set the available size to an offset between the first and second frame's extents.
+    *available_size_rc.borrow_mut() = extent0.offset as usize + extent0.size + 100;
+    assert!(decoder.nth_image(0).is_ok());
+    assert_eq!(decoder.nth_image(1), Err(AvifError::WaitingOnIo));
+    // Set the available size to 1 byte less than the second frame's extent.
+    *available_size_rc.borrow_mut() = extent1.offset as usize + extent1.size - 1;
+    assert!(decoder.nth_image(0).is_ok());
+    assert_eq!(decoder.nth_image(1), Err(AvifError::WaitingOnIo));
+    // Set the available size to 1 byte less than the second frame's extent.
+    *available_size_rc.borrow_mut() = extent1.offset as usize + extent1.size;
+    assert!(decoder.nth_image(1).is_ok());
+    let image = decoder.image().expect("unable to get image");
+    assert_eq!(image.width, 256);
+    assert_eq!(image.height, 256);
+    assert!(image.has_plane(Plane::Y));
+    assert!(image.has_plane(Plane::U));
+    assert!(image.has_plane(Plane::V));
+    // At this point, we should be able to fetch both the frames in any order.
+    assert!(decoder.nth_image(0).is_ok());
+    assert!(decoder.nth_image(1).is_ok());
+    assert!(decoder.nth_image(1).is_ok());
+    assert!(decoder.nth_image(0).is_ok());
+
+    Ok(())
+}
+
 #[test]
 fn nth_image() {
     let mut decoder = get_decoder("colors-animated-8bpc.avif");
@@ -953,6 +1113,21 @@ fn white_1x1_ftyp_size0() -> AvifResult<()> {
     Ok(())
 }
 
+#[test]
+fn white_1x1_unknown_top_level_box_size0() -> AvifResult<()> {
+    // Edit the file to insert an unknown top level box with size 0 after ftyp (invalid).
+    let mut file_bytes = std::fs::read(get_test_file("white_1x1.avif")).unwrap();
+    // Insert a top level box after ftyp (box type and size all 0s).
+    for _ in 0..8 {
+        file_bytes.insert(32, 0);
+    }
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(file_bytes);
+    assert!(decoder.parse().is_err());
+    Ok(())
+}
+
 #[test]
 fn dimg_repetition() {
     let mut decoder = get_decoder("sofa_grid1x5_420_dimg_repeat.avif");
@@ -993,6 +1168,27 @@ fn dimg_ordering() {
     assert_ne!(row1, row2);
 }
 
+#[test]
+fn grid_image_icc_associated_with_individual_cells() {
+    let mut decoder = get_decoder("grid_icc_individual_cells.avif");
+    assert!(decoder.parse().is_ok());
+    let image = decoder.image().expect("image was none");
+    assert!(!image.icc.is_empty());
+}
+
+#[test]
+fn grid_image_nclx_associated_with_individual_cells() {
+    let mut decoder = get_decoder("grid_nclx_individual_cells.avif");
+    assert!(decoder.parse().is_ok());
+    let image = decoder.image().expect("image was none");
+    assert_eq!(image.color_primaries, ColorPrimaries::Bt470bg);
+    assert_eq!(
+        image.transfer_characteristics,
+        TransferCharacteristics::Bt470bg
+    );
+    assert_eq!(image.matrix_coefficients, MatrixCoefficients::Bt470bg);
+}
+
 #[test]
 fn heic_peek() {
     let file_data = std::fs::read(get_test_file("blue.heic")).expect("could not read file");
@@ -1163,7 +1359,8 @@ macro_rules! pixel_eq {
     };
 }
 
-#[test_case::test_matrix(0usize..4)]
+#[allow(clippy::zero_prefixed_literal)]
+#[test_matrix(0usize..4)]
 fn overlay(index: usize) {
     let info = &EXPECTED_OVERLAY_IMAGE_INFOS[index];
     let mut decoder = get_decoder(info.filename);
@@ -1200,3 +1397,44 @@ fn overlay(index: usize) {
         pixel_eq!(a, expected_pixel.2[3]);
     }
 }
+
+#[test_case("mismatch_colr_0_0.avif", YuvRange::Limited ; "mismatch case 0")]
+#[test_case("mismatch_colr_0_1.avif", YuvRange::Limited ; "mismatch case 1")]
+#[test_case("mismatch_colr_0_2.avif", YuvRange::Limited ; "mismatch case 2")]
+#[test_case("mismatch_colr_1_0.avif", YuvRange::Full ; "mismatch case 3")]
+#[test_case("mismatch_colr_1_1.avif", YuvRange::Full ; "mismatch case 4")]
+#[test_case("mismatch_colr_1_2.avif", YuvRange::Full ; "mismatch case 5")]
+#[test_case("missing_colr_0_0.avif", YuvRange::Limited ; "missing colr case 0")]
+#[test_case("missing_colr_0_1.avif", YuvRange::Limited ; "missing colr case 1")]
+#[test_case("missing_colr_0_2.avif", YuvRange::Limited ; "missing colr case 2")]
+#[test_case("missing_colr_1_0.avif", YuvRange::Full ; "missing colr case 3")]
+#[test_case("missing_colr_1_1.avif", YuvRange::Full ; "missing colr case 4")]
+#[test_case("missing_colr_1_2.avif", YuvRange::Full ; "missing colr case 5")]
+fn yuv_range(filename: &str, expected_yuv_range: YuvRange) {
+    let mut decoder = get_decoder(filename);
+    let res = decoder.parse();
+    assert!(res.is_ok());
+    let image = decoder.image().expect("image was none");
+    assert_eq!(image.yuv_range, expected_yuv_range);
+}
+
+#[test_case("weld_sato_8plus8bit.avif", false)]
+#[test_case("weld_sato_8plus8bit_alpha.avif", true)]
+#[test_case("weld_sato_12plus4bit.avif", false)]
+fn sato_16bit(filename: &str, has_alpha: bool) {
+    let mut decoder = get_decoder(filename);
+    assert!(decoder.parse().is_ok());
+    assert_eq!(has_alpha, decoder.image().unwrap().alpha_present);
+    if !HAS_DECODER {
+        return;
+    }
+    let res = decoder.next_image();
+    assert_eq!(res, Ok(()));
+    assert_eq!(has_alpha, decoder.image().unwrap().has_alpha());
+    if cfg!(feature = "sample_transform") {
+        assert_eq!(16, decoder.image().unwrap().depth);
+        // TODO: compare with reference weld_16bit.png
+    } else {
+        assert!(decoder.image().unwrap().depth < 16);
+    }
+}
diff --git a/tests/encoder_tests.rs b/tests/encoder_tests.rs
new file mode 100644
index 0000000..35a18cf
--- /dev/null
+++ b/tests/encoder_tests.rs
@@ -0,0 +1,857 @@
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
+#![cfg(feature = "encoder")]
+
+use crabby_avif::decoder::CompressionFormat;
+use crabby_avif::decoder::ImageContentType;
+use crabby_avif::decoder::ProgressiveState;
+use crabby_avif::encoder::*;
+use crabby_avif::gainmap::*;
+use crabby_avif::image::*;
+use crabby_avif::utils::*;
+use crabby_avif::*;
+
+mod utils;
+use utils::*;
+
+use test_case::test_matrix;
+
+#[test_matrix(
+    [100, 121],
+    [200, 107],
+    [8, 10, 12],
+    [PixelFormat::Yuv420, PixelFormat::Yuv422, PixelFormat::Yuv444, PixelFormat::Yuv400],
+    [YuvRange::Limited, YuvRange::Full],
+    [false, true],
+    [TilingMode::Manual(0, 0), TilingMode::Manual(1, 0)]
+)]
+fn encode_decode(
+    width: u32,
+    height: u32,
+    depth: u8,
+    yuv_format: PixelFormat,
+    yuv_range: YuvRange,
+    alpha: bool,
+    tiling_mode: TilingMode,
+) -> AvifResult<()> {
+    if !HAS_ENCODER {
+        return Ok(());
+    }
+    let input_image = generate_gradient_image(width, height, depth, yuv_format, yuv_range, alpha)?;
+    let settings = encoder::Settings {
+        speed: Some(10),
+        mutable: encoder::MutableSettings {
+            quality: 90,
+            tiling_mode,
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    encoder.add_image(&input_image)?;
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    assert!(decoder.parse().is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
+    assert_eq!(decoder.image_count(), 1);
+
+    let image = decoder.image().expect("image was none");
+    assert_eq!(image.alpha_present, alpha);
+    assert!(!image.image_sequence_track_present);
+    assert_eq!(image.width, width);
+    assert_eq!(image.height, height);
+    assert_eq!(image.depth, depth);
+    assert_eq!(image.yuv_format, yuv_format);
+    assert_eq!(image.yuv_range, yuv_range);
+    assert_eq!(image.pasp, input_image.pasp);
+    assert_eq!(image.clli, input_image.clli);
+    // TODO: test for other properties.
+
+    if !HAS_DECODER {
+        return Ok(());
+    }
+    assert!(decoder.next_image().is_ok());
+    let image = decoder.image().expect("image was none");
+    assert!(psnr(image, &input_image)? >= 50.0);
+    Ok(())
+}
+
+#[test_matrix(
+    [100, 121],
+    [200, 107],
+    [8, 10, 12],
+    [PixelFormat::Yuv420, PixelFormat::Yuv422, PixelFormat::Yuv444, PixelFormat::Yuv400],
+    [YuvRange::Limited, YuvRange::Full],
+    [false, true]
+)]
+fn encode_decode_sequence(
+    width: u32,
+    height: u32,
+    depth: u8,
+    yuv_format: PixelFormat,
+    yuv_range: YuvRange,
+    alpha: bool,
+) -> AvifResult<()> {
+    if !HAS_ENCODER {
+        return Ok(());
+    }
+    let mut input_images = Vec::new();
+    let frame_count = 10;
+    for _ in 0..frame_count {
+        input_images.push(generate_gradient_image(
+            width, height, depth, yuv_format, yuv_range, alpha,
+        )?);
+    }
+    let images: Vec<&Image> = input_images.iter().collect();
+    let settings = encoder::Settings {
+        speed: Some(6),
+        timescale: 10000,
+        mutable: encoder::MutableSettings {
+            quality: 50,
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    for image in images {
+        encoder.add_image_for_sequence(image, 1000)?;
+    }
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    assert!(decoder.parse().is_ok());
+    assert_eq!(decoder.compression_format(), CompressionFormat::Avif);
+    assert_eq!(decoder.image_count(), 10);
+
+    let image = decoder.image().expect("image was none");
+    assert_eq!(image.alpha_present, alpha);
+    assert!(image.image_sequence_track_present);
+    assert_eq!(image.width, width);
+    assert_eq!(image.height, height);
+    assert_eq!(image.depth, depth);
+    assert_eq!(image.yuv_format, yuv_format);
+    assert_eq!(image.yuv_range, yuv_range);
+
+    if !HAS_DECODER {
+        return Ok(());
+    }
+    for _ in 0..frame_count {
+        assert!(decoder.next_image().is_ok());
+    }
+    Ok(())
+}
+
+#[test_matrix([0, 1, 65535], [0, 1, 65535])]
+fn clli(max_cll: u16, max_pall: u16) -> AvifResult<()> {
+    if !HAS_ENCODER || !HAS_DECODER {
+        return Ok(());
+    }
+    let mut image = generate_gradient_image(8, 8, 8, PixelFormat::Yuv444, YuvRange::Full, false)?;
+    image.clli = Some(ContentLightLevelInformation { max_cll, max_pall });
+
+    let settings = encoder::Settings {
+        speed: Some(10),
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    encoder.add_image(&image)?;
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    assert!(decoder.parse().is_ok());
+    let decoded_image = decoder.image().unwrap();
+    assert_eq!(decoded_image.clli, image.clli);
+
+    Ok(())
+}
+
+fn test_progressive_decode(
+    edata: Vec<u8>,
+    width: u32,
+    height: u32,
+    extra_layer_count: u32,
+) -> AvifResult<()> {
+    let mut decoder = decoder::Decoder::default();
+    decoder.settings.allow_progressive = true;
+    decoder.set_io_vec(edata);
+    assert!(decoder.parse().is_ok());
+    let image = decoder.image().expect("image was none");
+    assert!(matches!(image.progressive_state, ProgressiveState::Active));
+    assert_eq!(decoder.image_count(), extra_layer_count + 1);
+    assert_eq!(image.width, width);
+    assert_eq!(image.height, height);
+    if !HAS_DECODER {
+        return Ok(());
+    }
+    for _ in 0..extra_layer_count + 1 {
+        let res = decoder.next_image();
+        assert!(res.is_ok());
+        let image = decoder.image().expect("image was none");
+        assert_eq!(image.width, width);
+        assert_eq!(image.height, height);
+    }
+    Ok(())
+}
+
+#[test_matrix([true, false])]
+fn progressive_quality_change(use_grid: bool) -> AvifResult<()> {
+    if !HAS_ENCODER {
+        return Ok(());
+    }
+    let image = generate_gradient_image(256, 256, 8, PixelFormat::Yuv444, YuvRange::Full, false)?;
+    let mut settings = encoder::Settings {
+        speed: Some(10),
+        extra_layer_count: 1,
+        mutable: encoder::MutableSettings {
+            quality: 2,
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    let images = [&image, &image];
+    if use_grid {
+        encoder.add_image_grid(2, 1, &images)?;
+    } else {
+        encoder.add_image(&image)?;
+    }
+    settings.mutable.quality = 90;
+    encoder.update_settings(&settings.mutable)?;
+    if use_grid {
+        encoder.add_image_grid(2, 1, &images)?;
+    } else {
+        encoder.add_image(&image)?;
+    }
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+    test_progressive_decode(
+        edata,
+        if use_grid { 512 } else { 256 },
+        256,
+        settings.extra_layer_count,
+    )?;
+    Ok(())
+}
+
+#[test_matrix([IFraction(1,2), IFraction(2, 6), IFraction(4, 32)], [true, false])]
+fn progressive_dimension_change(scaling_fraction: IFraction, use_grid: bool) -> AvifResult<()> {
+    if !HAS_ENCODER {
+        return Ok(());
+    }
+    let image = generate_gradient_image(256, 256, 8, PixelFormat::Yuv444, YuvRange::Full, false)?;
+    let mut settings = encoder::Settings {
+        speed: Some(10),
+        extra_layer_count: 1,
+        mutable: encoder::MutableSettings {
+            quality: 100,
+            scaling_mode: ScalingMode {
+                horizontal: scaling_fraction,
+                vertical: scaling_fraction,
+            },
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    let images = [&image, &image];
+    if use_grid {
+        encoder.add_image_grid(2, 1, &images)?;
+    } else {
+        encoder.add_image(&image)?;
+    }
+    settings.mutable.scaling_mode = ScalingMode::default();
+    encoder.update_settings(&settings.mutable)?;
+    if use_grid {
+        encoder.add_image_grid(2, 1, &images)?;
+    } else {
+        encoder.add_image(&image)?;
+    }
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+    test_progressive_decode(
+        edata,
+        if use_grid { 512 } else { 256 },
+        256,
+        settings.extra_layer_count,
+    )?;
+    Ok(())
+}
+
+#[test]
+fn progressive_same_layers() -> AvifResult<()> {
+    if !HAS_ENCODER {
+        return Ok(());
+    }
+    let image = generate_gradient_image(256, 256, 8, PixelFormat::Yuv444, YuvRange::Full, false)?;
+    let settings = encoder::Settings {
+        extra_layer_count: 3,
+        speed: Some(10),
+        mutable: encoder::MutableSettings {
+            quality: 50,
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    for _ in 0..4 {
+        encoder.add_image(&image)?;
+    }
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+    test_progressive_decode(edata, 256, 256, settings.extra_layer_count)?;
+    Ok(())
+}
+
+#[test]
+fn progressive_incorrect_number_of_layers() -> AvifResult<()> {
+    if !HAS_ENCODER {
+        return Ok(());
+    }
+    let image = generate_gradient_image(256, 256, 8, PixelFormat::Yuv444, YuvRange::Full, false)?;
+    let settings = encoder::Settings {
+        speed: Some(10),
+        extra_layer_count: 1,
+        mutable: encoder::MutableSettings {
+            quality: 50,
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+
+    // Too many layers.
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    assert!(encoder.add_image(&image).is_ok());
+    assert!(encoder.add_image(&image).is_ok());
+    assert!(encoder.add_image(&image).is_err());
+
+    // Too few layers.
+    encoder = encoder::Encoder::create_with_settings(&settings)?;
+    assert!(encoder.add_image(&image).is_ok());
+    assert!(encoder.finish().is_err());
+    Ok(())
+}
+
+fn gainmap_metadata(base_is_hdr: bool) -> GainMapMetadata {
+    let mut metadata = GainMapMetadata {
+        use_base_color_space: true,
+        base_hdr_headroom: if base_is_hdr { UFraction(6, 2) } else { UFraction(0, 1) },
+        alternate_hdr_headroom: if base_is_hdr { UFraction(0, 1) } else { UFraction(6, 2) },
+        ..Default::default()
+    };
+    for c in 0..3u32 {
+        metadata.base_offset[c as usize] = Fraction(c as i32 * 10, 1000);
+        metadata.alternate_offset[c as usize] = Fraction(c as i32 * 20, 1000);
+        metadata.gamma[c as usize] = UFraction(1, c + 1);
+        metadata.min[c as usize] = Fraction(-1, c + 1);
+        metadata.max[c as usize] = Fraction(c as i32 + 11, c + 1);
+    }
+    metadata
+}
+
+fn generate_gainmap_image(base_is_hdr: bool) -> AvifResult<(Image, GainMap)> {
+    let mut image = generate_gradient_image(12, 34, 10, PixelFormat::Yuv420, YuvRange::Full, true)?;
+    image.transfer_characteristics = if base_is_hdr {
+        TransferCharacteristics::Pq
+    } else {
+        TransferCharacteristics::Srgb
+    };
+    let mut gainmap = GainMap {
+        image: generate_gradient_image(6, 17, 8, PixelFormat::Yuv420, YuvRange::Full, false)?,
+        metadata: gainmap_metadata(base_is_hdr),
+        ..Default::default()
+    };
+    gainmap.alt_plane_count = 3;
+    gainmap.alt_matrix_coefficients = MatrixCoefficients::Smpte2085;
+    let clli = ContentLightLevelInformation {
+        max_cll: 10,
+        max_pall: 5,
+    };
+    if base_is_hdr {
+        image.clli = Some(clli);
+        gainmap.alt_plane_depth = 8;
+        gainmap.alt_color_primaries = ColorPrimaries::Bt601;
+        gainmap.alt_transfer_characteristics = TransferCharacteristics::Srgb;
+    } else {
+        gainmap.alt_clli = clli;
+        gainmap.alt_plane_depth = 10;
+        gainmap.alt_color_primaries = ColorPrimaries::Bt2020;
+        gainmap.alt_transfer_characteristics = TransferCharacteristics::Pq;
+    }
+    Ok((image, gainmap))
+}
+
+#[test]
+fn gainmap_base_image_sdr() -> AvifResult<()> {
+    let (image, gainmap) = generate_gainmap_image(false)?;
+    let settings = encoder::Settings {
+        speed: Some(10),
+        mutable: encoder::MutableSettings {
+            quality: 80,
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    encoder.add_image_gainmap(&image, &gainmap)?;
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    decoder.settings.image_content_to_decode = ImageContentType::All;
+    assert!(decoder.parse().is_ok());
+    assert!(decoder.image().unwrap().alpha_present);
+    assert!(decoder.gainmap_present());
+    let decoded_gainmap = decoder.gainmap();
+    assert_eq!(
+        decoded_gainmap.image.matrix_coefficients,
+        gainmap.image.matrix_coefficients
+    );
+    assert_eq!(decoded_gainmap.alt_clli, gainmap.alt_clli);
+    assert_eq!(decoded_gainmap.alt_plane_depth, 10);
+    assert_eq!(decoded_gainmap.alt_plane_count, 3);
+    assert_eq!(decoded_gainmap.alt_color_primaries, ColorPrimaries::Bt2020);
+    assert_eq!(
+        decoded_gainmap.alt_transfer_characteristics,
+        TransferCharacteristics::Pq
+    );
+    assert_eq!(
+        decoded_gainmap.alt_matrix_coefficients,
+        MatrixCoefficients::Smpte2085
+    );
+    assert_eq!(decoded_gainmap.image.width, gainmap.image.width);
+    assert_eq!(decoded_gainmap.image.height, gainmap.image.height);
+    assert_eq!(decoded_gainmap.image.depth, gainmap.image.depth);
+    assert_eq!(decoded_gainmap.metadata, gainmap.metadata);
+    assert!(decoder.next_image().is_ok());
+    let decoded_image = decoder.image().expect("failed to get image");
+    assert!(decoded_image.has_plane(Plane::A));
+    assert!(psnr(&image, decoded_image)? >= 40.0);
+    let decoded_gainmap = decoder.gainmap();
+    assert!(psnr(&gainmap.image, &decoded_gainmap.image)? >= 40.0);
+    Ok(())
+}
+
+#[test]
+fn gainmap_base_image_hdr() -> AvifResult<()> {
+    let (image, gainmap) = generate_gainmap_image(true)?;
+    let settings = encoder::Settings {
+        speed: Some(10),
+        mutable: encoder::MutableSettings {
+            quality: 80,
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    encoder.add_image_gainmap(&image, &gainmap)?;
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    decoder.settings.image_content_to_decode = ImageContentType::All;
+    assert!(decoder.parse().is_ok());
+    assert!(decoder.gainmap_present());
+    let decoded_gainmap = decoder.gainmap();
+    let decoded_image = decoder.image().expect("failed to get decoded image");
+    assert_eq!(
+        decoded_gainmap.image.matrix_coefficients,
+        gainmap.image.matrix_coefficients
+    );
+    assert_eq!(decoded_image.clli, image.clli);
+    assert_eq!(
+        decoded_gainmap.alt_clli,
+        ContentLightLevelInformation::default()
+    );
+    assert_eq!(decoded_gainmap.alt_plane_depth, 8);
+    assert_eq!(decoded_gainmap.alt_plane_count, 3);
+    assert_eq!(decoded_gainmap.alt_color_primaries, ColorPrimaries::Bt601);
+    assert_eq!(
+        decoded_gainmap.alt_transfer_characteristics,
+        TransferCharacteristics::Srgb
+    );
+    assert_eq!(
+        decoded_gainmap.alt_matrix_coefficients,
+        MatrixCoefficients::Smpte2085
+    );
+    assert_eq!(decoded_gainmap.image.width, gainmap.image.width);
+    assert_eq!(decoded_gainmap.image.height, gainmap.image.height);
+    assert_eq!(decoded_gainmap.image.depth, gainmap.image.depth);
+    assert_eq!(decoded_gainmap.metadata, gainmap.metadata);
+    assert!(decoder.next_image().is_ok());
+    let decoded_image = decoder.image().expect("failed to get image");
+    assert!(psnr(&image, decoded_image)? >= 40.0);
+    let decoded_gainmap = decoder.gainmap();
+    assert!(psnr(&gainmap.image, &decoded_gainmap.image)? >= 40.0);
+    Ok(())
+}
+
+#[test]
+fn gainmap_oriented() -> AvifResult<()> {
+    let (mut image, gainmap) = generate_gainmap_image(false)?;
+    image.irot_angle = Some(1);
+    image.imir_axis = Some(0);
+    let settings = encoder::Settings {
+        speed: Some(10),
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    encoder.add_image_gainmap(&image, &gainmap)?;
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    decoder.settings.image_content_to_decode = ImageContentType::All;
+    assert!(decoder.parse().is_ok());
+    assert!(decoder.gainmap_present());
+    let decoded_image = decoder.image().expect("failed to get decoded image");
+    assert_eq!(decoded_image.irot_angle, image.irot_angle);
+    assert_eq!(decoded_image.imir_axis, image.imir_axis);
+    let decoded_gainmap = decoder.gainmap();
+    assert!(decoded_gainmap.image.irot_angle.is_none());
+    assert!(decoded_gainmap.image.imir_axis.is_none());
+    Ok(())
+}
+
+#[test]
+fn gainmap_image_alpha_invalid() -> AvifResult<()> {
+    let (image, mut gainmap) = generate_gainmap_image(false)?;
+    // Invalid: gainmap.image must not have alpha plane.
+    gainmap.image = generate_gradient_image(6, 17, 8, PixelFormat::Yuv420, YuvRange::Full, true)?;
+    let settings = encoder::Settings {
+        speed: Some(10),
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    assert!(encoder.add_image_gainmap(&image, &gainmap).is_err());
+    Ok(())
+}
+
+#[test_matrix([0, 1, 2])]
+fn gainmap_oriented_invalid(transformation_index: u8) -> AvifResult<()> {
+    let (image, mut gainmap) = generate_gainmap_image(false)?;
+    // Gainmap image should not have a transformative property. Expect a failure.
+    match transformation_index {
+        0 => gainmap.image.irot_angle = Some(1),
+        1 => gainmap.image.imir_axis = Some(0),
+        2 => gainmap.image.pasp = Some(PixelAspectRatio::default()),
+        _ => {} // not reached.
+    }
+    let settings = encoder::Settings {
+        speed: Some(10),
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    encoder.add_image_gainmap(&image, &gainmap)?;
+    assert!(encoder.finish().is_err());
+    Ok(())
+}
+
+#[test]
+fn gainmap_all_channels_identical() -> AvifResult<()> {
+    let (image, mut gainmap) = generate_gainmap_image(true)?;
+    for c in 0..3 {
+        gainmap.metadata.base_offset[c] = Fraction(1, 2);
+        gainmap.metadata.alternate_offset[c] = Fraction(3, 4);
+        gainmap.metadata.gamma[c] = UFraction(5, 6);
+        gainmap.metadata.min[c] = Fraction(7, 8);
+        gainmap.metadata.max[c] = Fraction(9, 10);
+    }
+    let settings = encoder::Settings {
+        speed: Some(10),
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    encoder.add_image_gainmap(&image, &gainmap)?;
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    decoder.settings.image_content_to_decode = ImageContentType::All;
+    assert!(decoder.parse().is_ok());
+    assert!(decoder.gainmap_present());
+    let decoded_gainmap = decoder.gainmap();
+    assert_eq!(decoded_gainmap.metadata, gainmap.metadata);
+    Ok(())
+}
+
+#[test]
+fn gainmap_grid() -> AvifResult<()> {
+    let grid_columns = 2;
+    let grid_rows = 2;
+    let cell_width = 128;
+    let cell_height = 200;
+    let mut cells = Vec::new();
+    for _ in 0..grid_rows * grid_columns {
+        let mut image = generate_gradient_image(
+            cell_width,
+            cell_height,
+            10,
+            PixelFormat::Yuv444,
+            YuvRange::Full,
+            false,
+        )?;
+        image.transfer_characteristics = TransferCharacteristics::Pq;
+        let gainmap = GainMap {
+            image: generate_gradient_image(
+                cell_width / 2,
+                cell_height / 2,
+                8,
+                PixelFormat::Yuv420,
+                YuvRange::Full,
+                false,
+            )?,
+            metadata: gainmap_metadata(true),
+            ..Default::default()
+        };
+        cells.push((image, gainmap));
+    }
+    let mut images = Vec::new();
+    let mut gainmaps = Vec::new();
+    for cell in &cells {
+        images.push(&cell.0);
+        gainmaps.push(&cell.1);
+    }
+
+    let settings = encoder::Settings {
+        speed: Some(10),
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    encoder.add_image_gainmap_grid(grid_columns, grid_rows, &images, &gainmaps)?;
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    decoder.settings.image_content_to_decode = ImageContentType::All;
+    assert!(decoder.parse().is_ok());
+    assert!(decoder.gainmap_present());
+    assert!(decoder.next_image().is_ok());
+    Ok(())
+}
+
+#[test_matrix([0, 1, 2, 3, 4])]
+fn invalid_grid(test_case_index: u8) -> AvifResult<()> {
+    let grid_columns = 2;
+    let grid_rows = 2;
+    let cell_width = 128;
+    let cell_height = 200;
+    let mut cells = Vec::new();
+    for _ in 0..grid_rows * grid_columns {
+        let mut image = generate_gradient_image(
+            cell_width,
+            cell_height,
+            10,
+            PixelFormat::Yuv444,
+            YuvRange::Full,
+            false,
+        )?;
+        image.transfer_characteristics = TransferCharacteristics::Pq;
+        let gainmap = GainMap {
+            image: generate_gradient_image(
+                cell_width / 2,
+                cell_height / 2,
+                8,
+                PixelFormat::Yuv420,
+                YuvRange::Full,
+                false,
+            )?,
+            metadata: gainmap_metadata(true),
+            ..Default::default()
+        };
+        cells.push((image, gainmap));
+    }
+
+    let settings = encoder::Settings {
+        speed: Some(10),
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+
+    match test_case_index {
+        0 => {
+            // Invalid: one gainmap cell has the wrong size.
+            cells[1].1.image.height = 90;
+        }
+        1 => {
+            // Invalid: one gainmap cell has a different depth.
+            cells[1].1.image.depth = 12;
+        }
+        2 => {
+            // Invalid: one gainmap cell has different gainmap metadata.
+            cells[1].1.metadata.gamma[0] = UFraction(42, 1);
+        }
+        3 => {
+            // Invalid: one image cell has the wrong size.
+            cells[1].0.height = 90;
+        }
+        4 => {
+            // Invalid: one gainmap cell has a different depth.
+            cells[1].0.depth = 12;
+        }
+        _ => unreachable!(),
+    }
+    let images: Vec<_> = cells.iter().map(|x| &x.0).collect();
+    let gainmaps: Vec<_> = cells.iter().map(|x| &x.1).collect();
+    assert!(encoder
+        .add_image_gainmap_grid(grid_columns, grid_rows, &images, &gainmaps)
+        .is_err());
+    Ok(())
+}
+
+#[test_matrix([8, 10, 12], [false, true])]
+fn opaque_alpha(depth: u8, is_sequence: bool) -> AvifResult<()> {
+    if !HAS_ENCODER {
+        return Ok(());
+    }
+    let width = 2;
+    let height = 2;
+    let mut input_image = generate_gradient_image(
+        width,
+        height,
+        depth,
+        PixelFormat::Yuv420,
+        YuvRange::Full,
+        /*alpha=*/ true,
+    )?;
+    let opaque_value = input_image.max_channel();
+    fill_plane(&mut input_image, Plane::A, opaque_value)?;
+    let settings = encoder::Settings {
+        speed: Some(10),
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    if is_sequence {
+        for i in 0..2 {
+            encoder.add_image_for_sequence(&input_image, i)?;
+        }
+    } else {
+        encoder.add_image(&input_image)?;
+    }
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    assert!(decoder.parse().is_ok());
+    let image = decoder.image().expect("image was none");
+
+    if is_sequence {
+        assert_eq!(decoder.image_count(), 2);
+        assert!(image.alpha_present);
+        if !HAS_DECODER {
+            return Ok(());
+        }
+        for _ in 0..2 {
+            let res = decoder.next_image();
+            assert!(res.is_ok());
+            let image = decoder.image().expect("image was none");
+            assert!(image.alpha_present);
+            let alpha_plane = image.plane_data(Plane::A);
+            assert!(alpha_plane.is_some());
+            assert!(alpha_plane.unwrap().row_bytes > 0);
+        }
+    } else {
+        assert_eq!(decoder.image_count(), 1);
+        assert!(!image.alpha_present);
+        if !HAS_DECODER {
+            return Ok(());
+        }
+        let res = decoder.next_image();
+        assert!(res.is_ok());
+        let image = decoder.image().expect("image was none");
+        assert!(!image.alpha_present);
+        assert!(image.plane_data(Plane::A).is_none());
+    }
+    Ok(())
+}
+
+#[test_matrix([8, 10, 12], [true, false])]
+fn opaque_alpha_grid(depth: u8, all_cells_opaque: bool) -> AvifResult<()> {
+    if !HAS_ENCODER {
+        return Ok(());
+    }
+    let width = 100;
+    let height = 100;
+    let mut image1 = generate_gradient_image(
+        width,
+        height,
+        depth,
+        PixelFormat::Yuv420,
+        YuvRange::Full,
+        /*alpha=*/ true,
+    )?;
+    let mut image2 = generate_gradient_image(
+        width,
+        height,
+        depth,
+        PixelFormat::Yuv420,
+        YuvRange::Full,
+        /*alpha=*/ true,
+    )?;
+    let opaque_value = image1.max_channel();
+    fill_plane(&mut image1, Plane::A, opaque_value)?;
+    fill_plane(&mut image2, Plane::A, opaque_value)?;
+    if !all_cells_opaque {
+        // Set some alpha pixels as not opaque in one of the cells.
+        if depth == 8 {
+            image2.row_mut(Plane::A, 0)?[0] = 10;
+        } else {
+            image2.row16_mut(Plane::A, 0)?[0] = 10;
+        }
+    }
+    let settings = encoder::Settings {
+        speed: Some(10),
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    encoder.add_image_grid(1, 2, &[&image1, &image2])?;
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    assert!(decoder.parse().is_ok());
+    let image = decoder.image().expect("image was none");
+    assert_eq!(decoder.image_count(), 1);
+    assert_eq!(image.alpha_present, !all_cells_opaque);
+    if !HAS_DECODER {
+        return Ok(());
+    }
+    let res = decoder.next_image();
+    assert!(res.is_ok());
+    let image = decoder.image().expect("image was none");
+    if all_cells_opaque {
+        assert!(!image.alpha_present);
+        assert!(image.plane_data(Plane::A).is_none());
+    } else {
+        assert!(image.alpha_present);
+        let alpha_plane = image.plane_data(Plane::A);
+        assert!(alpha_plane.is_some());
+        assert!(alpha_plane.unwrap().row_bytes > 0);
+    }
+    Ok(())
+}
diff --git a/tests/iloc_extents_test.rs b/tests/iloc_extents_test.rs
index 95d18fe..dfa9f3d 100644
--- a/tests/iloc_extents_test.rs
+++ b/tests/iloc_extents_test.rs
@@ -12,11 +12,10 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-#[path = "./mod.rs"]
-mod tests;
+mod utils;
 
 use crabby_avif::reformat::rgb::*;
-use tests::*;
+use utils::*;
 
 #[test]
 fn iloc_extents() {
@@ -31,18 +30,21 @@ fn iloc_extents() {
     rgb.format = Format::Rgb;
     assert!(rgb.allocate().is_ok());
     assert!(rgb.convert_from_yuv(decoded).is_ok());
-    let source = decode_png("sacre_coeur.png");
-    // sacre_coeur_2extents.avif was generated with
-    //   avifenc --lossless --ignore-exif --ignore-xmp --ignore-icc sacre_coeur.png
-    // so pixels can be compared byte by byte.
-    assert_eq!(
-        source,
-        rgb.pixels
-            .as_ref()
-            .unwrap()
-            .slice(0, source.len() as u32)
-            .unwrap()
-    );
+    #[cfg(feature = "png")]
+    {
+        let source = decode_png("sacre_coeur.png");
+        // sacre_coeur_2extents.avif was generated with
+        //   avifenc --lossless --ignore-exif --ignore-xmp --ignore-icc sacre_coeur.png
+        // so pixels can be compared byte by byte.
+        assert_eq!(
+            source,
+            rgb.pixels
+                .as_ref()
+                .unwrap()
+                .slice(0, source.len() as u32)
+                .unwrap()
+        );
+    }
 }
 
 #[test]
diff --git a/tests/lossless_test.rs b/tests/lossless_test.rs
index 65bf673..50dacca 100644
--- a/tests/lossless_test.rs
+++ b/tests/lossless_test.rs
@@ -12,14 +12,29 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-#[path = "./mod.rs"]
-mod tests;
+#![cfg(feature = "png")]
+
+mod utils;
+use utils::*;
 
 use crabby_avif::reformat::rgb::*;
-use tests::*;
+#[cfg(all(feature = "jpeg", feature = "encoder"))]
+use crabby_avif::utils::reader::jpeg::JpegReader;
+#[cfg(feature = "encoder")]
+use crabby_avif::utils::reader::png::PngReader;
+#[cfg(feature = "encoder")]
+use crabby_avif::utils::reader::Config;
+#[cfg(feature = "encoder")]
+use crabby_avif::utils::reader::Reader;
+#[cfg(feature = "encoder")]
+use crabby_avif::*;
+
+use test_case::test_case;
+#[cfg(feature = "encoder")]
+use test_case::test_matrix;
 
-#[test_case::test_case("paris_identity.avif", "paris_icc_exif_xmp.png"; "lossless_identity")]
-#[test_case::test_case("paris_ycgco_re.avif", "paris_icc_exif_xmp.png"; "lossless_ycgco_re")]
+#[test_case("paris_identity.avif", "paris_icc_exif_xmp.png"; "lossless_identity")]
+#[test_case("paris_ycgco_re.avif", "paris_icc_exif_xmp.png"; "lossless_ycgco_re")]
 fn lossless(avif_file: &str, png_file: &str) {
     let mut decoder = get_decoder(avif_file);
     assert!(decoder.parse().is_ok());
@@ -43,3 +58,67 @@ fn lossless(avif_file: &str, png_file: &str) {
             .unwrap()
     );
 }
+
+#[test_matrix(
+    ["paris_icc_exif_xmp.png", "paris_exif_xmp_icc.jpg"],
+    [MatrixCoefficients::Identity, MatrixCoefficients::Ycgco, MatrixCoefficients::YcgcoRe],
+    [PixelFormat::Yuv444, PixelFormat::Yuv420]
+)]
+#[cfg(feature = "encoder")]
+fn lossless_roundtrip(
+    input_file: &str,
+    matrix_coefficients: MatrixCoefficients,
+    yuv_format: PixelFormat,
+) -> AvifResult<()> {
+    if !HAS_ENCODER {
+        return Ok(());
+    }
+    if input_file.ends_with("jpg") && !cfg!(feature = "jpeg") {
+        return Ok(());
+    }
+    if matrix_coefficients == MatrixCoefficients::Identity && yuv_format != PixelFormat::Yuv444 {
+        // The AV1 spec does not allow identity with subsampling.
+        return Ok(());
+    }
+    let input_file_abs = get_test_file(input_file);
+    let mut reader: Box<dyn Reader> = if input_file.ends_with("png") {
+        Box::new(PngReader::create(&input_file_abs)?)
+    } else {
+        #[cfg(feature = "jpeg")]
+        {
+            Box::new(JpegReader::create(&input_file_abs)?)
+        }
+        #[cfg(not(feature = "jpeg"))]
+        unreachable!();
+    };
+    let image = reader.read_frame(&Config {
+        yuv_format: Some(yuv_format),
+        matrix_coefficients: Some(matrix_coefficients),
+        ..Default::default()
+    })?;
+
+    let settings = encoder::Settings {
+        speed: Some(10),
+        mutable: encoder::MutableSettings {
+            quality: 100,
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+    let mut encoder = encoder::Encoder::create_with_settings(&settings)?;
+    encoder.add_image(&image)?;
+    let edata = encoder.finish()?;
+    assert!(!edata.is_empty());
+
+    if !HAS_DECODER {
+        return Ok(());
+    }
+
+    let mut decoder = decoder::Decoder::default();
+    decoder.set_io_vec(edata);
+    assert!(decoder.parse().is_ok());
+    assert!(decoder.next_image().is_ok());
+    let decoded_image = decoder.image().expect("image was none");
+    are_images_equal(&image, decoded_image)?;
+    Ok(())
+}
diff --git a/tests/mod.rs b/tests/mod.rs
deleted file mode 100644
index 81bd6fd..0000000
--- a/tests/mod.rs
+++ /dev/null
@@ -1,66 +0,0 @@
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
-// Not all functions are used from all test targets. So allow unused functions in this module.
-#![allow(unused)]
-
-use crabby_avif::*;
-use png;
-use std::fs::File;
-
-#[cfg(test)]
-pub fn get_test_file(filename: &str) -> String {
-    let base_path = if cfg!(google3) {
-        format!(
-            "{}/google3/third_party/crabbyavif/",
-            std::env::var("TEST_SRCDIR").expect("TEST_SRCDIR is not defined")
-        )
-    } else {
-        "".to_string()
-    };
-    String::from(format!("{base_path}tests/data/{filename}"))
-}
-
-#[cfg(test)]
-pub fn get_decoder(filename: &str) -> decoder::Decoder {
-    let abs_filename = get_test_file(filename);
-    let mut decoder = decoder::Decoder::default();
-    let _ = decoder
-        .set_io_file(&abs_filename)
-        .expect("Failed to set IO");
-    decoder
-}
-
-#[cfg(test)]
-pub fn decode_png(filename: &str) -> Vec<u8> {
-    let decoder = png::Decoder::new(File::open(get_test_file(filename)).unwrap());
-    let mut reader = decoder.read_info().unwrap();
-    // Indexed colors are not supported.
-    assert_ne!(reader.output_color_type().0, png::ColorType::Indexed);
-    let mut pixels = vec![0; reader.output_buffer_size()];
-    let info = reader.next_frame(&mut pixels).unwrap();
-    pixels
-}
-
-#[cfg(test)]
-#[allow(dead_code)]
-pub const HAS_DECODER: bool = if cfg!(any(
-    feature = "dav1d",
-    feature = "libgav1",
-    feature = "android_mediacodec"
-)) {
-    true
-} else {
-    false
-};
diff --git a/tests/rgb_tests.rs b/tests/rgb_tests.rs
new file mode 100644
index 0000000..24f49f0
--- /dev/null
+++ b/tests/rgb_tests.rs
@@ -0,0 +1,456 @@
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
+use crabby_avif::reformat::rgb::ChromaDownsampling;
+use crabby_avif::*;
+
+use test_case::test_matrix;
+
+#[derive(Default)]
+struct RgbToYuvParam {
+    rgb_depth: u8,
+    yuv_depth: u8,
+    rgb_format: rgb::Format,
+    yuv_format: PixelFormat,
+    yuv_range: YuvRange,
+    matrix_coefficients: MatrixCoefficients,
+    #[allow(unused)]
+    chroma_downsampling: ChromaDownsampling,
+    add_noise: bool,
+    rgb_step: u32,
+    max_average_abs_diff: f64,
+    min_psnr: f64,
+}
+
+fn fill_rgb_image_channel(
+    rgb: &mut rgb::Image,
+    channel_offset: usize,
+    value: u16,
+) -> AvifResult<()> {
+    let channel_count = rgb.channel_count() as usize;
+    let pixel_width = channel_count * rgb.width as usize;
+    assert!(channel_offset < channel_count);
+    for y in 0..rgb.height {
+        if rgb.depth == 8 {
+            let row = &mut rgb.row_mut(y)?[..pixel_width];
+            for pixels in row.chunks_exact_mut(channel_count) {
+                pixels[channel_offset] = value as u8;
+            }
+        } else {
+            let row = &mut rgb.row16_mut(y)?[..pixel_width];
+            for pixels in row.chunks_exact_mut(channel_count) {
+                pixels[channel_offset] = value;
+            }
+        }
+    }
+    Ok(())
+}
+
+fn add_noise(rgb: &mut rgb::Image, channel_offset: usize, noise: &[u16]) -> AvifResult<()> {
+    let channel_count = rgb.channel_count() as usize;
+    let pixel_width = channel_count * rgb.width as usize;
+    assert!(channel_offset < channel_count);
+    let mut noise_values = std::iter::repeat(noise).flat_map(|x| x.iter());
+    for y in 0..rgb.height {
+        if rgb.depth == 8 {
+            let row = &mut rgb.row_mut(y)?[..pixel_width];
+            for pixels in row.chunks_exact_mut(channel_count) {
+                pixels[channel_offset] += *noise_values.next().unwrap() as u8;
+            }
+        } else {
+            let row = &mut rgb.row16_mut(y)?[..pixel_width];
+            for pixels in row.chunks_exact_mut(channel_count) {
+                pixels[channel_offset] += noise_values.next().unwrap();
+            }
+        }
+    }
+    Ok(())
+}
+
+fn compute_diff_sum(
+    rgb1: &rgb::Image,
+    rgb2: &rgb::Image,
+    abs_diff_sum: &mut i64,
+    sq_diff_sum: &mut i64,
+    max_abs_diff: &mut i64,
+) -> AvifResult<()> {
+    assert_eq!(rgb1.depth, rgb2.depth);
+    assert!(rgb1.format == rgb2.format);
+    let pixel_width = (rgb1.width * rgb1.channel_count()) as usize;
+    for y in 0..rgb1.height {
+        if rgb1.depth == 8 {
+            let row1 = &rgb1.row(y)?[..pixel_width];
+            let row2 = &rgb2.row(y)?[..pixel_width];
+            for x in 0..pixel_width {
+                let diff = row2[x] as i64 - row1[x] as i64;
+                *abs_diff_sum += diff.abs();
+                *sq_diff_sum += diff * diff;
+                *max_abs_diff = std::cmp::max(*max_abs_diff, diff.abs());
+            }
+        } else {
+            let row1 = &rgb1.row16(y)?[..pixel_width];
+            let row2 = &rgb2.row16(y)?[..pixel_width];
+            for x in 0..pixel_width {
+                let diff = row2[x] as i64 - row1[x] as i64;
+                *abs_diff_sum += diff.abs();
+                *sq_diff_sum += diff * diff;
+                *max_abs_diff = std::cmp::max(*max_abs_diff, diff.abs());
+            }
+        }
+    }
+    Ok(())
+}
+
+fn psnr(sq_diff_sum: f64, num_diffs: f64, max_abs_diff: f64) -> f64 {
+    if sq_diff_sum == 0.0 {
+        return 99.0;
+    }
+    let distortion = sq_diff_sum / (num_diffs * max_abs_diff * max_abs_diff);
+    if distortion > 0.0 {
+        (-10.0 * distortion.log10()).min(98.9)
+    } else {
+        98.9
+    }
+}
+
+// Random permutation of 16 values.
+const RED_NOISE: [u16; 16] = [7, 14, 11, 5, 4, 6, 8, 15, 2, 9, 13, 3, 12, 1, 10, 0];
+// Random permutation of 16 values that is somewhat close to RED_NOISE.
+const GREEN_NOISE: [u16; 16] = [3, 2, 12, 15, 14, 10, 7, 13, 5, 1, 9, 0, 8, 4, 11, 6];
+// Random permutation of 16 values that is somewhat close to GREEN_NOISE.
+const BLUE_NOISE: [u16; 16] = [0, 8, 14, 9, 13, 12, 2, 7, 3, 1, 11, 10, 6, 15, 5, 4];
+
+fn rgb_to_yuv_whole_range(p: &RgbToYuvParam) -> AvifResult<()> {
+    let width = 4;
+    let height = 4;
+    let mut image = image::Image {
+        width,
+        height,
+        depth: p.yuv_depth,
+        yuv_format: p.yuv_format,
+        yuv_range: p.yuv_range,
+        matrix_coefficients: p.matrix_coefficients,
+        ..Default::default()
+    };
+    image.allocate_planes(Category::Color)?;
+    if p.rgb_format.has_alpha() {
+        image.allocate_planes(Category::Alpha)?;
+    }
+    let mut src_rgb = rgb::Image {
+        width,
+        height,
+        depth: p.rgb_depth,
+        format: p.rgb_format,
+        ..Default::default()
+    };
+    src_rgb.allocate()?;
+    let mut dst_rgb = rgb::Image {
+        width,
+        height,
+        depth: p.rgb_depth,
+        format: p.rgb_format,
+        ..Default::default()
+    };
+    dst_rgb.allocate()?;
+    let rgb_max_channel = src_rgb.max_channel();
+    if p.rgb_format.has_alpha() {
+        fill_rgb_image_channel(&mut src_rgb, p.rgb_format.alpha_offset(), rgb_max_channel)?;
+    }
+    let mut abs_diff_sum = 0i64;
+    let mut sq_diff_sum = 0i64;
+    let mut max_abs_diff = 0i64;
+    let mut num_diffs = 0i64;
+    let max_value = (rgb_max_channel - if p.add_noise { 15 } else { 0 }) as u32;
+    let rgb_step = p.rgb_step;
+    for r in (0..max_value + rgb_step).step_by(rgb_step as usize) {
+        let value = std::cmp::min(r, max_value) as u16;
+        fill_rgb_image_channel(&mut src_rgb, p.rgb_format.r_offset(), value)?;
+        if p.add_noise {
+            add_noise(&mut src_rgb, p.rgb_format.r_offset(), &RED_NOISE)?;
+        }
+        if p.yuv_format == PixelFormat::Yuv400 {
+            fill_rgb_image_channel(&mut src_rgb, p.rgb_format.g_offset(), value)?;
+            fill_rgb_image_channel(&mut src_rgb, p.rgb_format.b_offset(), value)?;
+            if p.add_noise {
+                add_noise(&mut src_rgb, p.rgb_format.g_offset(), &GREEN_NOISE)?;
+                add_noise(&mut src_rgb, p.rgb_format.b_offset(), &BLUE_NOISE)?;
+            }
+            src_rgb.convert_to_yuv(&mut image)?;
+            dst_rgb.convert_from_yuv(&image)?;
+            compute_diff_sum(
+                &src_rgb,
+                &dst_rgb,
+                &mut abs_diff_sum,
+                &mut sq_diff_sum,
+                &mut max_abs_diff,
+            )?;
+            num_diffs += (src_rgb.width * src_rgb.height * 3) as i64;
+        } else {
+            for g in (0..max_value + rgb_step).step_by(rgb_step as usize) {
+                let value = std::cmp::min(g, max_value) as u16;
+                fill_rgb_image_channel(&mut src_rgb, p.rgb_format.g_offset(), value)?;
+                if p.add_noise {
+                    add_noise(&mut src_rgb, p.rgb_format.g_offset(), &GREEN_NOISE)?;
+                }
+                for b in (0..max_value + rgb_step).step_by(rgb_step as usize) {
+                    let value = std::cmp::min(b, max_value) as u16;
+                    fill_rgb_image_channel(&mut src_rgb, p.rgb_format.b_offset(), value)?;
+                    if p.add_noise {
+                        add_noise(&mut src_rgb, p.rgb_format.b_offset(), &BLUE_NOISE)?;
+                    }
+                    src_rgb.convert_to_yuv(&mut image)?;
+                    dst_rgb.convert_from_yuv(&image)?;
+                    compute_diff_sum(
+                        &src_rgb,
+                        &dst_rgb,
+                        &mut abs_diff_sum,
+                        &mut sq_diff_sum,
+                        &mut max_abs_diff,
+                    )?;
+                    num_diffs += (src_rgb.width * src_rgb.height * 3) as i64;
+                }
+            }
+        }
+    }
+    let average_abs_diff = abs_diff_sum as f64 / num_diffs as f64;
+    let psnr = psnr(sq_diff_sum as f64, num_diffs as f64, rgb_max_channel as f64);
+    assert!(average_abs_diff <= p.max_average_abs_diff);
+    assert!(psnr >= p.min_psnr);
+    Ok(())
+}
+
+#[test_matrix(
+    [8, 10, 12, 16],
+    [8, 10, 12, 16],
+    [
+        rgb::Format::Rgb, rgb::Format::Rgba, rgb::Format::Argb,
+        rgb::Format::Bgr, rgb::Format::Bgra, rgb::Format::Abgr,
+    ],
+    [PixelFormat::Yuv420, PixelFormat::Yuv422, PixelFormat::Yuv444, PixelFormat::Yuv400],
+    [YuvRange::Full, YuvRange::Limited],
+    [
+        ChromaDownsampling::Automatic,
+        ChromaDownsampling::Fastest,
+        ChromaDownsampling::BestQuality,
+        ChromaDownsampling::Average,
+    ],
+    [MatrixCoefficients::Bt601]
+)]
+fn exhaustive_settings(
+    rgb_depth: u8,
+    yuv_depth: u8,
+    rgb_format: rgb::Format,
+    yuv_format: PixelFormat,
+    yuv_range: YuvRange,
+    chroma_downsampling: ChromaDownsampling,
+    matrix_coefficients: MatrixCoefficients,
+) -> AvifResult<()> {
+    rgb_to_yuv_whole_range(&RgbToYuvParam {
+        rgb_depth,
+        yuv_depth,
+        rgb_format,
+        yuv_format,
+        yuv_range,
+        matrix_coefficients,
+        chroma_downsampling,
+        add_noise: true,
+        // Only try the minimum and maximum values.
+        rgb_step: (1 << rgb_depth) - 1,
+        // Barely check the results, just for coverage.
+        max_average_abs_diff: ((1 << rgb_depth) - 1) as f64,
+        min_psnr: 5.0,
+    })
+}
+
+#[test_matrix(
+    [8, 10, 12, 16],
+    [8, 10, 12, 16],
+    [PixelFormat::Yuv420, PixelFormat::Yuv422, PixelFormat::Yuv444, PixelFormat::Yuv400],
+    [YuvRange::Full, YuvRange::Limited],
+    [ChromaDownsampling::Fastest, ChromaDownsampling::Automatic],
+    [
+        MatrixCoefficients::Bt709,
+        MatrixCoefficients::Unspecified,
+        MatrixCoefficients::Fcc,
+        MatrixCoefficients::Bt470bg,
+        MatrixCoefficients::Bt601,
+        MatrixCoefficients::Smpte240,
+        MatrixCoefficients::Bt2020Ncl,
+        MatrixCoefficients::ChromaDerivedNcl,
+        MatrixCoefficients::Ycgco,
+        MatrixCoefficients::YcgcoRe,
+        MatrixCoefficients::YcgcoRo,
+    ]
+)]
+fn all_matrix_coefficients(
+    rgb_depth: u8,
+    yuv_depth: u8,
+    yuv_format: PixelFormat,
+    yuv_range: YuvRange,
+    chroma_downsampling: ChromaDownsampling,
+    matrix_coefficients: MatrixCoefficients,
+) -> AvifResult<()> {
+    if (matches!(
+        matrix_coefficients,
+        MatrixCoefficients::Ycgco | MatrixCoefficients::YcgcoRe | MatrixCoefficients::YcgcoRo
+    ) && yuv_range == YuvRange::Limited)
+        || (matrix_coefficients == MatrixCoefficients::YcgcoRe && yuv_depth - 2 != rgb_depth)
+        || (matrix_coefficients == MatrixCoefficients::YcgcoRo && yuv_depth - 1 != rgb_depth)
+    {
+        // These combinations are not supported.
+        return Ok(());
+    }
+    rgb_to_yuv_whole_range(&RgbToYuvParam {
+        rgb_depth,
+        yuv_depth,
+        rgb_format: rgb::Format::Rgba,
+        yuv_format,
+        yuv_range,
+        matrix_coefficients,
+        chroma_downsampling,
+        add_noise: true,
+        // Only try the minimum and maximum values.
+        rgb_step: (1 << rgb_depth) - 1,
+        // Barely check the results, just for coverage.
+        max_average_abs_diff: ((1 << rgb_depth) - 1) as f64,
+        min_psnr: 5.0,
+    })
+}
+
+#[test]
+fn default_8bit_png_to_avif() -> AvifResult<()> {
+    rgb_to_yuv_whole_range(&RgbToYuvParam {
+        rgb_depth: 8,
+        yuv_depth: 8,
+        rgb_format: rgb::Format::Rgba,
+        yuv_format: PixelFormat::Yuv420,
+        yuv_range: YuvRange::Full,
+        matrix_coefficients: MatrixCoefficients::Bt601,
+        chroma_downsampling: ChromaDownsampling::Automatic,
+        add_noise: true,
+        rgb_step: 3,
+        max_average_abs_diff: 2.88,
+        min_psnr: 36.0,
+    })
+}
+
+#[test_matrix(
+    [(8, 31), (10, 101), (12, 401), (16, 6421)],
+    [8, 10, 12, 16]
+)]
+fn identity(rgb_depth_and_step: (u8, u32), yuv_depth: u8) -> AvifResult<()> {
+    let rgb_depth = rgb_depth_and_step.0;
+    if yuv_depth < rgb_depth {
+        return Ok(());
+    }
+    let rgb_step = rgb_depth_and_step.1;
+    rgb_to_yuv_whole_range(&RgbToYuvParam {
+        rgb_depth,
+        yuv_depth,
+        rgb_format: rgb::Format::Rgba,
+        yuv_format: PixelFormat::Yuv444,
+        yuv_range: YuvRange::Full,
+        matrix_coefficients: MatrixCoefficients::Identity,
+        chroma_downsampling: ChromaDownsampling::Automatic,
+        add_noise: true,
+        rgb_step,
+        max_average_abs_diff: 0.0,
+        min_psnr: 99.0,
+    })
+}
+
+#[test_matrix([8, 10, 12, 16])]
+fn monochrome_lossless(depth: u8) -> AvifResult<()> {
+    rgb_to_yuv_whole_range(&RgbToYuvParam {
+        rgb_depth: depth,
+        yuv_depth: depth,
+        rgb_format: rgb::Format::Rgba,
+        yuv_format: PixelFormat::Yuv400,
+        yuv_range: YuvRange::Full,
+        matrix_coefficients: MatrixCoefficients::Bt601,
+        chroma_downsampling: ChromaDownsampling::Automatic,
+        add_noise: false,
+        rgb_step: if depth == 16 {
+            // For depth == 16, running through all the values is too slow, so use a higher step.
+            401
+        } else {
+            1
+        },
+        max_average_abs_diff: 0.0,
+        min_psnr: 99.0,
+    })
+}
+
+#[test]
+fn ycgco() -> AvifResult<()> {
+    rgb_to_yuv_whole_range(&RgbToYuvParam {
+        rgb_depth: 8,
+        yuv_depth: 10,
+        rgb_format: rgb::Format::Rgba,
+        yuv_format: PixelFormat::Yuv444,
+        yuv_range: YuvRange::Full,
+        matrix_coefficients: MatrixCoefficients::YcgcoRe,
+        chroma_downsampling: ChromaDownsampling::Automatic,
+        add_noise: true,
+        rgb_step: 101,
+        max_average_abs_diff: 0.0,
+        min_psnr: 99.0,
+    })
+}
+
+#[test_matrix([PixelFormat::Yuv420, PixelFormat::Yuv422, PixelFormat::Yuv444])]
+fn any_subsampling_8bit(yuv_format: PixelFormat) -> AvifResult<()> {
+    rgb_to_yuv_whole_range(&RgbToYuvParam {
+        rgb_depth: 8,
+        yuv_depth: 8,
+        rgb_format: rgb::Format::Rgba,
+        yuv_format,
+        yuv_range: YuvRange::Full,
+        matrix_coefficients: MatrixCoefficients::Bt601,
+        chroma_downsampling: ChromaDownsampling::Automatic,
+        add_noise: false,
+        rgb_step: 17,
+        max_average_abs_diff: 0.84,
+        min_psnr: 45.0,
+    })
+}
+
+#[test_matrix(
+    [rgb::Format::Rgba, rgb::Format::Bgr],
+    [PixelFormat::Yuv420, PixelFormat::Yuv422, PixelFormat::Yuv444],
+    [(8, 61, 2.96, 36.0), (10, 211, 2.83, 47.0), (12, 809, 2.82, 52.0), (16, 16001, 2.82, 80.0)],
+    [true, false]
+)]
+fn all_same_bitdepths(
+    rgb_format: rgb::Format,
+    yuv_format: PixelFormat,
+    params: (u8, u32, f64, f64),
+    add_noise: bool,
+) -> AvifResult<()> {
+    rgb_to_yuv_whole_range(&RgbToYuvParam {
+        rgb_depth: params.0,
+        yuv_depth: params.0,
+        rgb_format,
+        yuv_format,
+        yuv_range: YuvRange::Limited,
+        matrix_coefficients: MatrixCoefficients::Bt601,
+        chroma_downsampling: ChromaDownsampling::Automatic,
+        add_noise,
+        rgb_step: params.1,
+        max_average_abs_diff: params.2,
+        min_psnr: params.3,
+    })
+}
diff --git a/tests/utils/mod.rs b/tests/utils/mod.rs
new file mode 100644
index 0000000..c034f9b
--- /dev/null
+++ b/tests/utils/mod.rs
@@ -0,0 +1,228 @@
+// Copyright 2024 Google LLC
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
+// Not all functions are used from all test targets. So allow unused functions in this module.
+#![allow(unused)]
+
+use crabby_avif::image::*;
+use crabby_avif::*;
+use std::fs::File;
+
+pub fn get_test_file(filename: &str) -> String {
+    let base_path = if cfg!(google3) {
+        format!(
+            "{}/google3/third_party/crabbyavif/",
+            std::env::var("TEST_SRCDIR").expect("TEST_SRCDIR is not defined")
+        )
+    } else {
+        "".to_string()
+    };
+    format!("{base_path}tests/data/{filename}")
+}
+
+pub fn get_decoder(filename: &str) -> decoder::Decoder {
+    let abs_filename = get_test_file(filename);
+    let mut decoder = decoder::Decoder::default();
+    decoder
+        .set_io_file(&abs_filename)
+        .expect("Failed to set IO");
+    decoder
+}
+
+#[cfg(feature = "png")]
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
+fn full_to_limited_pixel(min: i32, max: i32, full: i32, v: u16) -> u16 {
+    let v = v as i32;
+    let v = (((v * (max - min)) + (full / 2)) / full) + min;
+    if v < min {
+        min as u16
+    } else if v > max {
+        max as u16
+    } else {
+        v as u16
+    }
+}
+
+fn full_to_limited(v: u16, plane: Plane, depth: u8) -> u16 {
+    match (plane, depth) {
+        (Plane::Y, 8) => full_to_limited_pixel(16, 235, 255, v),
+        (Plane::Y, 10) => full_to_limited_pixel(64, 940, 1023, v),
+        (Plane::Y, 12) => full_to_limited_pixel(256, 3760, 4095, v),
+        (Plane::U | Plane::V, 8) => full_to_limited_pixel(16, 240, 255, v),
+        (Plane::U | Plane::V, 10) => full_to_limited_pixel(64, 960, 1023, v),
+        (Plane::U | Plane::V, 12) => full_to_limited_pixel(256, 3840, 4095, v),
+        _ => unreachable!(""),
+    }
+}
+
+pub fn generate_gradient_image(
+    width: u32,
+    height: u32,
+    depth: u8,
+    yuv_format: PixelFormat,
+    yuv_range: YuvRange,
+    alpha: bool,
+) -> AvifResult<Image> {
+    let mut image = image::Image {
+        width,
+        height,
+        depth,
+        yuv_format,
+        yuv_range,
+        ..Default::default()
+    };
+    image.allocate_planes(Category::Color)?;
+    if alpha {
+        image.allocate_planes(Category::Alpha)?;
+        image.alpha_present = true;
+    }
+    for plane in ALL_PLANES {
+        if !image.has_plane(plane) {
+            continue;
+        }
+        let plane_data = image.plane_data(plane).unwrap();
+        let max_xy_sum = plane_data.width + plane_data.height - 2;
+        for y in 0..plane_data.height {
+            if image.depth == 8 {
+                let row = image.row_mut(plane, y)?;
+                for x in 0..plane_data.width {
+                    let value = (x + y) % (max_xy_sum + 1);
+                    row[x as usize] = (value * 255 / std::cmp::max(1, max_xy_sum)) as u8;
+                    if yuv_range == YuvRange::Limited && plane != Plane::A {
+                        row[x as usize] =
+                            full_to_limited(row[x as usize] as u16, plane, depth) as u8;
+                    }
+                }
+            } else {
+                let max_channel = image.max_channel() as u32;
+                let row = image.row16_mut(plane, y)?;
+                for x in 0..plane_data.width {
+                    let value = (x + y) % (max_xy_sum + 1);
+                    row[x as usize] = (value * max_channel / std::cmp::max(1, max_xy_sum)) as u16;
+                    if yuv_range == YuvRange::Limited && plane != Plane::A {
+                        row[x as usize] = full_to_limited(row[x as usize], plane, depth);
+                    }
+                }
+            }
+        }
+    }
+    Ok(image)
+}
+
+pub fn are_images_equal(image1: &Image, image2: &Image) -> AvifResult<()> {
+    assert!(image1.has_same_properties_and_cicp(image2));
+    for plane in image::ALL_PLANES {
+        assert_eq!(image1.has_plane(plane), image2.has_plane(plane));
+        if !image1.has_plane(plane) {
+            continue;
+        }
+        let width = image1.width(plane);
+        let height = image1.height(plane);
+        for y in 0..height as u32 {
+            if image1.depth > 8 {
+                assert_eq!(
+                    image1.row16(plane, y)?[..width],
+                    image2.row16(plane, y)?[..width]
+                );
+            } else {
+                assert_eq!(
+                    image1.row(plane, y)?[..width],
+                    image2.row(plane, y)?[..width]
+                );
+            }
+        }
+    }
+    Ok(())
+}
+
+fn squared_diff_sum(pixel1: u16, pixel2: u16) -> u64 {
+    let diff = pixel1 as i32 - pixel2 as i32;
+    (diff * diff) as u64
+}
+
+pub fn psnr(image1: &Image, image2: &Image) -> AvifResult<f64> {
+    assert!(image1.has_same_properties_and_cicp(image2));
+    let mut diff_sum = 0u64;
+    let mut num_samples = 0;
+    for plane in image::ALL_PLANES {
+        assert_eq!(image1.has_plane(plane), image2.has_plane(plane));
+        if !image1.has_plane(plane) {
+            continue;
+        }
+        let width = image1.width(plane);
+        let height = image1.height(plane);
+        if width == 0 || height == 0 {
+            continue;
+        }
+        for y in 0..height as u32 {
+            if image1.depth > 8 {
+                let row1 = image1.row16(plane, y)?;
+                let row2 = image2.row16(plane, y)?;
+                for x in 0..width {
+                    diff_sum += squared_diff_sum(row1[x], row2[x]);
+                }
+            } else {
+                let row1 = image1.row(plane, y)?;
+                let row2 = image2.row(plane, y)?;
+                for x in 0..width {
+                    diff_sum += squared_diff_sum(row1[x] as u16, row2[x] as u16);
+                }
+            }
+            num_samples += width;
+        }
+    }
+    if diff_sum == 0 {
+        return Ok(99.0);
+    }
+    let max_channel_f = image1.max_channel() as f64;
+    let normalized_error = diff_sum as f64 / (num_samples as f64 * max_channel_f * max_channel_f);
+    if normalized_error <= f64::EPSILON {
+        Ok(98.99)
+    } else {
+        Ok((-10.0 * normalized_error.log10()).min(98.99))
+    }
+}
+
+pub fn fill_plane(image: &mut Image, plane: Plane, value: u16) -> AvifResult<()> {
+    let plane_data = image.plane_data(plane).ok_or(AvifError::NoContent)?;
+    for y in 0..plane_data.height {
+        if image.depth == 8 {
+            for pixel in &mut image.row_mut(Plane::A, y)?[..plane_data.width as usize] {
+                *pixel = value as u8;
+            }
+        } else {
+            for pixel in &mut image.row16_mut(Plane::A, y)?[..plane_data.width as usize] {
+                *pixel = value;
+            }
+        }
+    }
+    Ok(())
+}
+
+pub const HAS_DECODER: bool = cfg!(any(
+    feature = "dav1d",
+    feature = "libgav1",
+    feature = "android_mediacodec"
+));
+
+pub const HAS_ENCODER: bool = cfg!(feature = "aom");
diff --git a/tests/y4m_tests.rs b/tests/y4m_tests.rs
new file mode 100644
index 0000000..78370ef
--- /dev/null
+++ b/tests/y4m_tests.rs
@@ -0,0 +1,72 @@
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
+use crabby_avif::utils::reader::y4m::Y4MReader;
+use crabby_avif::utils::reader::Config;
+use crabby_avif::utils::reader::Reader;
+use crabby_avif::utils::writer::y4m::Y4MWriter;
+use crabby_avif::utils::writer::Writer;
+use crabby_avif::*;
+
+mod utils;
+use utils::*;
+
+use std::fs::File;
+use tempfile::NamedTempFile;
+use test_case::test_matrix;
+
+fn get_tempfile() -> String {
+    let file = NamedTempFile::new().expect("unable to open tempfile");
+    let path = file.into_temp_path();
+    let filename = String::from(path.to_str().unwrap());
+    let _ = path.close();
+    filename
+}
+
+#[test_matrix(
+    [100, 121],
+    [200, 107],
+    [8, 10, 12],
+    [PixelFormat::Yuv420, PixelFormat::Yuv422, PixelFormat::Yuv444, PixelFormat::Yuv400],
+    [YuvRange::Limited, YuvRange::Full],
+    [false, true]
+)]
+fn roundtrip(
+    width: u32,
+    height: u32,
+    depth: u8,
+    yuv_format: PixelFormat,
+    yuv_range: YuvRange,
+    alpha: bool,
+) -> AvifResult<()> {
+    if alpha && (depth != 8 || yuv_format != PixelFormat::Yuv444) {
+        // alpha in y4m is supported only for 8-bit 444 images.
+        return Ok(());
+    }
+    let image1 = generate_gradient_image(width, height, depth, yuv_format, yuv_range, alpha)?;
+    let output_filename = get_tempfile();
+    // Write the image.
+    {
+        let mut writer = Y4MWriter::create(false);
+        let mut output_file =
+            File::create(output_filename.clone()).expect("output file creation failed");
+        writer.write_frame(&mut output_file, &image1)?;
+    }
+    // Read the image.
+    let mut reader = Y4MReader::create(&output_filename)?;
+    let image2 = reader.read_frame(&Config::default())?;
+    are_images_equal(&image1, &image2)?;
+    Ok(())
+}
```

