```diff
diff --git a/.github/workflows/cmake_mac.yml b/.github/workflows/cmake_mac.yml
index 75b9f3e..b9c953c 100644
--- a/.github/workflows/cmake_mac.yml
+++ b/.github/workflows/cmake_mac.yml
@@ -62,7 +62,13 @@ jobs:
       uses: jwlawson/actions-setup-cmake@v2
 
     - name: Install dependencies on macOS
-      run: brew install pkg-config jpeg-turbo
+      run: |
+        if ! command -v pkg-config &> /dev/null; then
+          brew install pkg-config
+        fi
+        if ! brew list jpeg-turbo &> /dev/null; then
+          brew install jpeg-turbo
+        fi
 
     - name: Configure CMake
       shell: bash
diff --git a/Android.bp b/Android.bp
index 194fc1c..09ee9d5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -40,7 +40,8 @@ cc_library {
         "lib/include",
     ],
     local_include_dirs: ["lib/include"],
-    cflags: ["-DUHDR_ENABLE_INTRINSICS"],
+    cflags: ["-DUHDR_ENABLE_INTRINSICS",
+        "-DUHDR_WRITE_XMP",],
     srcs: [
         "lib/src/icc.cpp",
         "lib/src/jpegr.cpp",
diff --git a/CMakeLists.txt b/CMakeLists.txt
index c518d85..69a249b 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -23,7 +23,7 @@ if(POLICY CMP0091)
 endif()
 
 set(UHDR_MAJOR_VERSION 1)
-set(UHDR_MINOR_VERSION 3)
+set(UHDR_MINOR_VERSION 4)
 set(UHDR_PATCH_VERSION 0)
 project(libuhdr
         VERSION ${UHDR_MAJOR_VERSION}.${UHDR_MINOR_VERSION}.${UHDR_PATCH_VERSION}
@@ -124,6 +124,12 @@ option_if_not_defined(UHDR_ENABLE_INTRINSICS "Build with SIMD acceleration " TRU
 option_if_not_defined(UHDR_ENABLE_GLES "Build with GPU acceleration " FALSE)
 option_if_not_defined(UHDR_ENABLE_WERROR "Build with -Werror" FALSE)
 
+# These options effect only encoding process.
+# Decoding continues to support both iso and xmp irrespective of this configuration.
+# Also, if both packets are present iso is prioritized over xmp.
+option_if_not_defined(UHDR_WRITE_XMP "Write gainmap metadata in XMP packet" FALSE)
+option_if_not_defined(UHDR_WRITE_ISO "Write gainmap metadata in ISO 21496_1 packet" TRUE)
+
 # pre-requisites
 if(UHDR_BUILD_TESTS AND EMSCRIPTEN)
   message(FATAL_ERROR "Building tests not supported for wasm targets")
@@ -199,6 +205,12 @@ endif()
 if(UHDR_ENABLE_INTRINSICS)
   add_compile_options(-DUHDR_ENABLE_INTRINSICS)
 endif()
+if(UHDR_WRITE_XMP)
+  add_compile_options(-DUHDR_WRITE_XMP)
+endif()
+if(UHDR_WRITE_ISO)
+  add_compile_options(-DUHDR_WRITE_ISO)
+endif()
 
 include(CheckCXXCompilerFlag)
 function(CheckCompilerOption opt res)
@@ -568,7 +580,11 @@ file(GLOB UHDR_BM_SRCS_LIST "${BENCHMARK_DIR}/*.cpp")
 file(GLOB IMAGE_IO_SRCS_LIST "${THIRD_PARTY_DIR}/image_io/src/**/*.cc")
 
 set(PRIVATE_INCLUDE_DIR ${SOURCE_DIR}/include/ ${JPEG_INCLUDE_DIRS})
-set(COMMON_LIBS_LIST ${JPEG_LIBRARIES} Threads::Threads)
+set(PRIVATE_LINK_LIBS ${JPEG_LIBRARIES} Threads::Threads)
+if(UHDR_ENABLE_GLES)
+  list(APPEND PRIVATE_INCLUDE_DIR ${EGL_INCLUDE_DIRS} ${OPENGLES3_INCLUDE_DIRS})
+  list(APPEND PRIVATE_LINK_LIBS ${EGL_LIBRARIES} ${OPENGLES3_LIBRARIES})
+endif()
 
 ###########################################################
 # Targets
@@ -600,10 +616,7 @@ target_include_directories(${UHDR_CORE_LIB_NAME} PUBLIC ${EXPORT_INCLUDE_DIR})
 if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
   target_link_libraries(${UHDR_CORE_LIB_NAME} PUBLIC ${log-lib})
 endif()
-if(UHDR_ENABLE_GLES)
-  target_link_libraries(${UHDR_CORE_LIB_NAME} PRIVATE ${EGL_LIBRARIES} ${OPENGLES3_LIBRARIES})
-endif()
-target_link_libraries(${UHDR_CORE_LIB_NAME} PRIVATE ${COMMON_LIBS_LIST} ${IMAGEIO_TARGET_NAME})
+target_link_libraries(${UHDR_CORE_LIB_NAME} PRIVATE ${PRIVATE_LINK_LIBS} ${IMAGEIO_TARGET_NAME})
 
 if(UHDR_BUILD_EXAMPLES)
   set(UHDR_SAMPLE_APP ultrahdr_app)
@@ -664,7 +677,7 @@ if(UHDR_BUILD_BENCHMARK)
   target_link_libraries(ultrahdr_bm ${UHDR_CORE_LIB_NAME} ${BENCHMARK_LIBRARIES})
 
   set(RES_FILE "${TESTS_DIR}/data/UltrahdrBenchmarkTestRes-1.2.zip")
-  set(RES_FILE_MD5SUM "31fc352444f95bc1ab4b9d6e397de6c1")
+  set(RES_FILE_MD5SUM "14eac767ef7252051cc5658c4ad776d9")
   set(GET_RES_FILE TRUE)
   if(EXISTS ${RES_FILE})
     file(MD5 ${RES_FILE} CURR_MD5_SUM)
@@ -738,13 +751,10 @@ set(UHDR_TARGET_NAME uhdr)
 add_library(${UHDR_TARGET_NAME})
 add_dependencies(${UHDR_TARGET_NAME} ${UHDR_CORE_LIB_NAME})
 target_compile_options(${UHDR_TARGET_NAME} PRIVATE ${UHDR_WERROR_FLAGS})
-if(UHDR_ENABLE_GLES)
-  target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${EGL_LIBRARIES} ${OPENGLES3_LIBRARIES})
-endif()
 if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
   target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${log-lib})
 endif()
-target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${JPEG_LIBRARIES})
+target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${PRIVATE_LINK_LIBS})
 set_target_properties(${UHDR_TARGET_NAME}
                       PROPERTIES PUBLIC_HEADER ultrahdr_api.h)
 if(BUILD_SHARED_LIBS)
@@ -761,13 +771,10 @@ if(BUILD_SHARED_LIBS)
   add_library(${UHDR_TARGET_NAME_STATIC} STATIC)
   add_dependencies(${UHDR_TARGET_NAME_STATIC} ${UHDR_CORE_LIB_NAME})
   target_compile_options(${UHDR_TARGET_NAME_STATIC} PRIVATE ${UHDR_WERROR_FLAGS})
-  if(UHDR_ENABLE_GLES)
-    target_link_libraries(${UHDR_TARGET_NAME_STATIC} PRIVATE ${EGL_LIBRARIES} ${OPENGLES3_LIBRARIES})
-  endif()
   if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
     target_link_libraries(${UHDR_TARGET_NAME_STATIC} PRIVATE ${log-lib})
   endif()
-  target_link_libraries(${UHDR_TARGET_NAME_STATIC} PRIVATE ${JPEG_LIBRARIES})
+  target_link_libraries(${UHDR_TARGET_NAME_STATIC} PRIVATE ${PRIVATE_LINK_LIBS})
   combine_static_libs(${UHDR_CORE_LIB_NAME} ${UHDR_TARGET_NAME_STATIC})
   if(NOT MSVC)
     set_target_properties(${UHDR_TARGET_NAME_STATIC}
diff --git a/METADATA b/METADATA
index e6c20d4..ce82cb3 100644
--- a/METADATA
+++ b/METADATA
@@ -7,13 +7,13 @@ description: "Android fork of the libultrahdr library."
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 11
-    day: 21
+    year: 2025
+    month: 1
+    day: 10
   }
   identifier {
     type: "Git"
     value: "https://github.com/google/libultrahdr.git"
-    version: "285824d15db48ef11a556455ae0927c50e325d8b"
+    version: "d52a0d13814ca399fc8a07e23de1d2c63f0e8404"
   }
 }
diff --git a/docs/building.md b/docs/building.md
index bb2a3cf..46d4a18 100644
--- a/docs/building.md
+++ b/docs/building.md
@@ -64,6 +64,8 @@ Following is a list of available options:
 | `UHDR_ENABLE_GLES` | OFF | Build with GPU acceleration. |
 | `UHDR_ENABLE_WERROR` | OFF | Enable -Werror when building. |
 | `UHDR_MAX_DIMENSION` | 8192 | Maximum dimension supported by the library. The library defaults to handling images upto resolution 8192x8192. For different resolution needs use this option. For example, `-DUHDR_MAX_DIMENSION=4096`. |
+| `UHDR_WRITE_XMP` | OFF | Enable writing gainmap metadata in XMP packet. <ul><li> Current implementation of XMP format supports writing only single channel gainmap metadata. To support encoding multi channel gainmap metadata, XMP format encoding is disabled by default. If enabled, metadata of all channels of gainmap image is merged into one and signalled. </li></ul> |
+| `UHDR_WRITE_ISO` | ON | Enable writing gainmap metadata in ISO 21496-1 format. |
 | `UHDR_SANITIZE_OPTIONS` | OFF | Build library with sanitize options. Values set to this parameter are passed to directly to compilation option `-fsanitize`. For example, `-DUHDR_SANITIZE_OPTIONS=address,undefined` adds `-fsanitize=address,undefined` to the list of compilation options. CMake configuration errors are raised if the compiler does not support these flags. This is useful during fuzz testing. <ul><li> As `-fsanitize` is an instrumentation option, dependencies are also built from source instead of using pre-builts. This is done by forcing `UHDR_BUILD_DEPS` to **ON** internally. </li></ul> |
 | `UHDR_BUILD_PACKAGING` | OFF | Build distribution packages using CPack. |
 | | | |
diff --git a/examples/metadata.cfg b/examples/metadata.cfg
index baf8f2f..bfbc50e 100644
--- a/examples/metadata.cfg
+++ b/examples/metadata.cfg
@@ -1,7 +1,8 @@
---maxContentBoost 6.0
---minContentBoost 1.0
---gamma 1.0
---offsetSdr 0.0
---offsetHdr 0.0
+--maxContentBoost 6.0 6.0 6.0
+--minContentBoost 1.0 1.0 1.0
+--gamma 1.0 1.0 1.0
+--offsetSdr 0.0 0.0 0.0
+--offsetHdr 0.0 0.0 0.0
 --hdrCapacityMin 1.0
---hdrCapacityMax 6.0
+--hdrCapacityMax 49.2611
+--useBaseColorSpace 1
diff --git a/examples/ultrahdr_app.cpp b/examples/ultrahdr_app.cpp
index e963f81..3f03205 100644
--- a/examples/ultrahdr_app.cpp
+++ b/examples/ultrahdr_app.cpp
@@ -563,19 +563,21 @@ bool UltraHdrAppInput::fillGainMapCompressedImageHandle() {
 
 void parse_argument(uhdr_gainmap_metadata* metadata, char* argument, float* value) {
   if (!strcmp(argument, "maxContentBoost"))
-    metadata->max_content_boost = *value;
+    std::copy(value, value + 3, metadata->max_content_boost);
   else if (!strcmp(argument, "minContentBoost"))
-    metadata->min_content_boost = *value;
+    std::copy(value, value + 3, metadata->min_content_boost);
   else if (!strcmp(argument, "gamma"))
-    metadata->gamma = *value;
+    std::copy(value, value + 3, metadata->gamma);
   else if (!strcmp(argument, "offsetSdr"))
-    metadata->offset_sdr = *value;
+    std::copy(value, value + 3, metadata->offset_sdr);
   else if (!strcmp(argument, "offsetHdr"))
-    metadata->offset_hdr = *value;
+    std::copy(value, value + 3, metadata->offset_hdr);
   else if (!strcmp(argument, "hdrCapacityMin"))
     metadata->hdr_capacity_min = *value;
   else if (!strcmp(argument, "hdrCapacityMax"))
     metadata->hdr_capacity_max = *value;
+  else if (!strcmp(argument, "useBaseColorSpace"))
+    metadata->use_base_cg = *value;
   else
     std::cout << " Ignoring argument " << argument << std::endl;
 }
@@ -587,11 +589,14 @@ bool UltraHdrAppInput::fillGainMapMetadataDescriptor() {
   }
   std::string line;
   char argument[128];
-  float value;
+  float value[3];
   while (std::getline(file, line)) {
-    if (sscanf(line.c_str(), "--%s %f", argument, &value) == 2) {
-      parse_argument(&mGainMapMetadata, argument, &value);
-    }
+    int count = sscanf(line.c_str(), "--%s %f %f %f", argument, &value[0], &value[1], &value[2]);
+    if (count == 2) value[1] = value[2] = value[0];
+    if (count == 2 || count == 4)
+      parse_argument(&mGainMapMetadata, argument, value);
+    else
+      std::cout << " Ignoring line " << line << std::endl;
   }
   file.close();
   return true;
@@ -612,13 +617,37 @@ bool UltraHdrAppInput::writeGainMapMetadataToFile(uhdr_gainmap_metadata_t* metad
   if (!file.is_open()) {
     return false;
   }
-  file << "--maxContentBoost " << metadata->max_content_boost << std::endl;
-  file << "--minContentBoost " << metadata->min_content_boost << std::endl;
-  file << "--gamma " << metadata->gamma << std::endl;
-  file << "--offsetSdr " << metadata->offset_sdr << std::endl;
-  file << "--offsetHdr " << metadata->offset_hdr << std::endl;
+  bool allChannelsIdentical = metadata->max_content_boost[0] == metadata->max_content_boost[1] &&
+                              metadata->max_content_boost[0] == metadata->max_content_boost[2] &&
+                              metadata->min_content_boost[0] == metadata->min_content_boost[1] &&
+                              metadata->min_content_boost[0] == metadata->min_content_boost[2] &&
+                              metadata->gamma[0] == metadata->gamma[1] &&
+                              metadata->gamma[0] == metadata->gamma[2] &&
+                              metadata->offset_sdr[0] == metadata->offset_sdr[1] &&
+                              metadata->offset_sdr[0] == metadata->offset_sdr[2] &&
+                              metadata->offset_hdr[0] == metadata->offset_hdr[1] &&
+                              metadata->offset_hdr[0] == metadata->offset_hdr[2];
+  if (allChannelsIdentical) {
+    file << "--maxContentBoost " << metadata->max_content_boost[0] << std::endl;
+    file << "--minContentBoost " << metadata->min_content_boost[0] << std::endl;
+    file << "--gamma " << metadata->gamma[0] << std::endl;
+    file << "--offsetSdr " << metadata->offset_sdr[0] << std::endl;
+    file << "--offsetHdr " << metadata->offset_hdr[0] << std::endl;
+  } else {
+    file << "--maxContentBoost " << metadata->max_content_boost[0] << " "
+         << metadata->max_content_boost[1] << " " << metadata->max_content_boost[2] << std::endl;
+    file << "--minContentBoost " << metadata->min_content_boost[0] << " "
+         << metadata->min_content_boost[1] << " " << metadata->min_content_boost[2] << std::endl;
+    file << "--gamma " << metadata->gamma[0] << " " << metadata->gamma[1] << " "
+         << metadata->gamma[2] << std::endl;
+    file << "--offsetSdr " << metadata->offset_sdr[0] << " " << metadata->offset_sdr[1] << " "
+         << metadata->offset_sdr[2] << std::endl;
+    file << "--offsetHdr " << metadata->offset_hdr[0] << " " << metadata->offset_hdr[1] << " "
+         << metadata->offset_hdr[2] << std::endl;
+  }
   file << "--hdrCapacityMin " << metadata->hdr_capacity_min << std::endl;
   file << "--hdrCapacityMax " << metadata->hdr_capacity_max << std::endl;
+  file << "--useBaseColorSpace " << metadata->use_base_cg << std::endl;
   file.close();
   return true;
 }
diff --git a/fuzzer/ultrahdr_enc_fuzzer.cpp b/fuzzer/ultrahdr_enc_fuzzer.cpp
index cf8b889..914343d 100644
--- a/fuzzer/ultrahdr_enc_fuzzer.cpp
+++ b/fuzzer/ultrahdr_enc_fuzzer.cpp
@@ -39,7 +39,7 @@ constexpr int kTfMax = UHDR_CT_SRGB;
 
 class UltraHdrEncFuzzer {
  public:
-  UltraHdrEncFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {};
+  UltraHdrEncFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
   void process();
   template <typename T>
   void fillBuffer(T* data, int width, int height, int stride);
@@ -69,9 +69,11 @@ void UltraHdrEncFuzzer::fillBuffer(T* data, int width, int height, int stride) {
 
 void UltraHdrEncFuzzer::process() {
   if (mFdp.remaining_bytes()) {
-    struct uhdr_raw_image hdrImg{};
-    struct uhdr_raw_image sdrImg{};
-    struct uhdr_raw_image gainmapImg{};
+    struct uhdr_raw_image hdrImg {};
+    struct uhdr_raw_image sdrImg {};
+    struct uhdr_raw_image gainmapImg {};
+
+    float maxBoost[3], minBoost[3], gamma[3], offsetSdr[3], offsetHdr[3];
 
     // which encode api to select
     int muxSwitch = mFdp.ConsumeIntegralInRange<int8_t>(0, 4);
@@ -129,14 +131,31 @@ void UltraHdrEncFuzzer::process() {
     // encoding speed preset
     auto enc_preset = mFdp.ConsumeBool() ? UHDR_USAGE_REALTIME : UHDR_USAGE_BEST_QUALITY;
 
+    bool are_all_channels_identical = mFdp.ConsumeBool();
+
     // gainmap metadata
-    auto minBoost = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
-    auto maxBoost = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
-    auto gamma = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 5);
-    auto offsetSdr = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
-    auto offsetHdr = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
+    if (are_all_channels_identical) {
+      minBoost[0] = minBoost[1] = minBoost[2] =
+          mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
+      maxBoost[0] = maxBoost[1] = maxBoost[2] =
+          mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
+      gamma[0] = gamma[1] = gamma[2] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 5);
+      offsetSdr[0] = offsetSdr[1] = offsetSdr[2] =
+          mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
+      offsetHdr[0] = offsetHdr[1] = offsetHdr[2] =
+          mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
+    } else {
+      for (int i = 0; i < 3; i++) {
+        minBoost[i] = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
+        maxBoost[i] = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
+        gamma[i] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 5);
+        offsetSdr[i] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
+        offsetHdr[i] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
+      }
+    }
     auto minCapacity = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
     auto maxCapacity = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
+    auto useBaseCg = mFdp.ConsumeBool();
 
     // target display peak brightness
     auto targetDispPeakBrightness = mFdp.ConsumeFloatingPointInRange<float>(100.0f, 10500.0f);
@@ -193,10 +212,14 @@ void UltraHdrEncFuzzer::process() {
     ALOGV("base image quality %d ", (int)base_quality);
     ALOGV("encoding preset %d ", (int)enc_preset);
     ALOGV(
-        "gainmap metadata: min content boost %f, max content boost %f, gamma %f, offset sdr %f, "
-        "offset hdr %f, hdr min capacity %f, hdr max capacity %f",
-        (float)minBoost, (float)maxBoost, (float)gamma, (float)offsetSdr, (float)offsetHdr,
-        (float)minCapacity, (float)maxCapacity);
+        "gainmap metadata: min content boost %f %f %f, max content boost %f %f %f, gamma %f %f %f, "
+        "offset sdr %f %f %f, offset hdr %f %f %f, hdr min capacity %f, hdr max capacity %f, "
+        "useBaseCg %d",
+        (float)minBoost[0], (float)minBoost[1], (float)minBoost[2], (float)maxBoost[0],
+        (float)maxBoost[1], (float)maxBoost[2], (float)gamma[0], (float)gamma[1], (float)gamma[2],
+        (float)offsetSdr[0], (float)offsetSdr[1], offsetSdr[2], (float)offsetHdr[0],
+        (float)offsetHdr[1], (float)offsetHdr[2], (float)minCapacity, (float)maxCapacity,
+        (int)useBaseCg);
     ALOGV("hdr intent luma stride %d, chroma stride %d", yHdrStride, uvHdrStride);
     ALOGV("sdr intent luma stride %d, chroma stride %d", ySdrStride, uvSdrStride);
     if (applyMirror) ALOGV("added mirror effect, direction %d", (int)direction);
@@ -361,8 +384,8 @@ void UltraHdrEncFuzzer::process() {
     ON_ERR(uhdr_enc_set_exif_data(enc_handle, &exif))
     ON_ERR(uhdr_enc_set_using_multi_channel_gainmap(enc_handle, multi_channel_gainmap))
     ON_ERR(uhdr_enc_set_gainmap_scale_factor(enc_handle, gm_scale_factor))
-    ON_ERR(uhdr_enc_set_gainmap_gamma(enc_handle, gamma))
-    ON_ERR(uhdr_enc_set_min_max_content_boost(enc_handle, minBoost, maxBoost))
+    ON_ERR(uhdr_enc_set_gainmap_gamma(enc_handle, gamma[0]))
+    ON_ERR(uhdr_enc_set_min_max_content_boost(enc_handle, minBoost[0], maxBoost[0]))
     ON_ERR(uhdr_enc_set_target_display_peak_brightness(enc_handle, targetDispPeakBrightness))
     ON_ERR(uhdr_enc_set_preset(enc_handle, enc_preset))
     ON_ERR(uhdr_enable_gpu_acceleration(enc_handle, 1))
@@ -392,13 +415,14 @@ void UltraHdrEncFuzzer::process() {
               UHDR_CODEC_OK) {
             struct uhdr_compressed_image jpegGainMap = gainMapEncoder.getCompressedImage();
             uhdr_gainmap_metadata metadata;
-            metadata.max_content_boost = maxBoost;
-            metadata.min_content_boost = minBoost;
-            metadata.gamma = gamma;
-            metadata.offset_sdr = offsetSdr;
-            metadata.offset_hdr = offsetHdr;
+            std::copy(maxBoost, maxBoost + 3, metadata.max_content_boost);
+            std::copy(minBoost, minBoost + 3, metadata.min_content_boost);
+            std::copy(gamma, gamma + 3, metadata.gamma);
+            std::copy(offsetSdr, offsetSdr + 3, metadata.offset_sdr);
+            std::copy(offsetHdr, offsetHdr + 3, metadata.offset_hdr);
             metadata.hdr_capacity_min = minCapacity;
             metadata.hdr_capacity_max = maxCapacity;
+            metadata.use_base_cg = useBaseCg;
             ON_ERR(uhdr_enc_set_compressed_image(enc_handle, &jpegImg, UHDR_BASE_IMG))
             ON_ERR(uhdr_enc_set_gainmap_image(enc_handle, &jpegGainMap, &metadata))
             status = uhdr_encode(enc_handle);
diff --git a/fuzzer/ultrahdr_legacy_fuzzer.cpp b/fuzzer/ultrahdr_legacy_fuzzer.cpp
index 2b78340..9a5f992 100644
--- a/fuzzer/ultrahdr_legacy_fuzzer.cpp
+++ b/fuzzer/ultrahdr_legacy_fuzzer.cpp
@@ -233,7 +233,7 @@ void UltraHdrEncFuzzer::process() {
 
     // dest
     // 2 * p010 size as input data is random, DCT compression might not behave as expected
-    jpegImgR.maxLength = std::max(8 * 1024 /* min size 8kb */, width * height * 3 * 2);
+    jpegImgR.maxLength = std::max(64 * 1024 /* min size 8kb */, width * height * 3 * 2);
     auto jpegImgRaw = std::make_unique<uint8_t[]>(jpegImgR.maxLength);
     jpegImgR.data = jpegImgRaw.get();
 // #define DUMP_PARAM
diff --git a/java/UltraHdrApp.java b/java/UltraHdrApp.java
index 2b90dab..83f6b3b 100644
--- a/java/UltraHdrApp.java
+++ b/java/UltraHdrApp.java
@@ -27,6 +27,7 @@ import java.io.FileOutputStream;
 import java.io.IOException;
 import java.nio.ByteBuffer;
 import java.nio.ByteOrder;
+import java.util.Arrays;
 
 import com.google.media.codecs.ultrahdr.UltraHDRDecoder;
 import com.google.media.codecs.ultrahdr.UltraHDREncoder;
@@ -278,30 +279,44 @@ public class UltraHdrApp {
             String line;
             while ((line = reader.readLine()) != null) {
                 String[] parts = line.split("\\s+");
-                if (parts.length == 2 && parts[0].startsWith("--")) {
+                if (parts.length >= 2 && parts[0].startsWith("--")) {
                     String option = parts[0].substring(2); // remove the "--" prefix
-                    float value = Float.parseFloat(parts[1]);
+                    float[] values = new float[3];
+                    int count = Math.min(parts.length - 1, 3);
+                    if (count != 1 && count != 3) {
+                        System.err.println("ignoring line: " + line);
+                        continue;
+                    }
+                    for (int i = 0; i < count; i++) {
+                        values[i] = Float.parseFloat(parts[i + 1]);
+                    }
+                    if (count == 1) {
+                        values[1] = values[2] = values[0];
+                    }
                     switch (option) {
                         case "maxContentBoost":
-                            mMetadata.maxContentBoost = value;
+                            System.arraycopy(values, 0, mMetadata.maxContentBoost, 0, 3);
                             break;
                         case "minContentBoost":
-                            mMetadata.minContentBoost = value;
+                            System.arraycopy(values, 0, mMetadata.minContentBoost, 0, 3);
                             break;
                         case "gamma":
-                            mMetadata.gamma = value;
+                            System.arraycopy(values, 0, mMetadata.gamma, 0, 3);
                             break;
                         case "offsetSdr":
-                            mMetadata.offsetSdr = value;
+                            System.arraycopy(values, 0, mMetadata.offsetSdr, 0, 3);
                             break;
                         case "offsetHdr":
-                            mMetadata.offsetHdr = value;
+                            System.arraycopy(values, 0, mMetadata.offsetHdr, 0, 3);
                             break;
                         case "hdrCapacityMin":
-                            mMetadata.hdrCapacityMin = value;
+                            mMetadata.hdrCapacityMin = values[0];
                             break;
                         case "hdrCapacityMax":
-                            mMetadata.hdrCapacityMax = value;
+                            mMetadata.hdrCapacityMax = values[0];
+                            break;
+                        case "useBaseColorSpace":
+                            mMetadata.useBaseColorSpace = values[0] != 0.0f;
                             break;
                         default:
                             System.err.println("ignoring option: " + option);
@@ -316,13 +331,40 @@ public class UltraHdrApp {
 
     public void writeGainMapMetadataToFile(GainMapMetadata metadata) throws IOException {
         try (BufferedWriter writer = new BufferedWriter(new FileWriter(mGainMapMetadaCfgFile))) {
-            writer.write("--maxContentBoost " + metadata.maxContentBoost + "\n");
-            writer.write("--minContentBoost " + metadata.minContentBoost + "\n");
-            writer.write("--gamma " + metadata.gamma + "\n");
-            writer.write("--offsetSdr " + metadata.offsetSdr + "\n");
-            writer.write("--offsetHdr " + metadata.offsetHdr + "\n");
+            boolean allChannelsIdentical =
+                    metadata.maxContentBoost[0] == metadata.maxContentBoost[1]
+                            && metadata.maxContentBoost[0] == metadata.maxContentBoost[2]
+                            && metadata.minContentBoost[0] == metadata.minContentBoost[1]
+                            && metadata.minContentBoost[0] == metadata.minContentBoost[2]
+                            && metadata.gamma[0] == metadata.gamma[1]
+                            && metadata.gamma[0] == metadata.gamma[2]
+                            && metadata.offsetSdr[0] == metadata.offsetSdr[1]
+                            && metadata.offsetSdr[0] == metadata.offsetSdr[2]
+                            && metadata.offsetHdr[0] == metadata.offsetHdr[1]
+                            && metadata.offsetHdr[0] == metadata.offsetHdr[2];
+            if (allChannelsIdentical) {
+                writer.write("--maxContentBoost " + metadata.maxContentBoost[0] + "\n");
+                writer.write("--minContentBoost " + metadata.minContentBoost[0] + "\n");
+                writer.write("--gamma " + metadata.gamma[0] + "\n");
+                writer.write("--offsetSdr " + metadata.offsetSdr[0] + "\n");
+                writer.write("--offsetHdr " + metadata.offsetHdr[0] + "\n");
+            } else {
+                writer.write("--maxContentBoost " + metadata.maxContentBoost[0] + " "
+                        + metadata.maxContentBoost[1] + " " + metadata.maxContentBoost[2] + "\n");
+                writer.write("--minContentBoost " + metadata.minContentBoost[0] + " "
+                        + metadata.minContentBoost[1] + " " + metadata.minContentBoost[2] + "\n");
+                writer.write("--gamma " + metadata.gamma[0] + " " + metadata.gamma[1] + " "
+                        + metadata.gamma[2] + "\n");
+                writer.write(
+                        "--offsetSdr " + metadata.offsetSdr[0] + " " + metadata.offsetSdr[1] + " "
+                                + metadata.offsetSdr[2] + "\n");
+                writer.write(
+                        "--offsetHdr " + metadata.offsetHdr[0] + " " + metadata.offsetHdr[1] + " "
+                                + metadata.offsetHdr[2] + "\n");
+            }
             writer.write("--hdrCapacityMin " + metadata.hdrCapacityMin + "\n");
             writer.write("--hdrCapacityMax " + metadata.hdrCapacityMax + "\n");
+            writer.write("--useBaseColorSpace " + (metadata.useBaseColorSpace ? "1" : "0") + "\n");
         }
     }
 
@@ -396,7 +438,8 @@ public class UltraHdrApp {
                 handle.setGainMapImageInfo(mGainMapCompressedImageData,
                         mGainMapCompressedImageData.length, mMetadata.maxContentBoost,
                         mMetadata.minContentBoost, mMetadata.gamma, mMetadata.offsetSdr,
-                        mMetadata.offsetHdr, mMetadata.hdrCapacityMin, mMetadata.hdrCapacityMax);
+                        mMetadata.offsetHdr, mMetadata.hdrCapacityMin, mMetadata.hdrCapacityMax,
+                        mMetadata.useBaseColorSpace);
             }
             if (mExifFile != null) {
                 fillExifMemoryBlock();
diff --git a/java/com/google/media/codecs/ultrahdr/UltraHDRDecoder.java b/java/com/google/media/codecs/ultrahdr/UltraHDRDecoder.java
index f383cdc..dcae4e7 100644
--- a/java/com/google/media/codecs/ultrahdr/UltraHDRDecoder.java
+++ b/java/com/google/media/codecs/ultrahdr/UltraHDRDecoder.java
@@ -28,6 +28,7 @@ import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_UNSPE
 import java.io.IOException;
 import java.nio.ByteBuffer;
 import java.nio.ByteOrder;
+import java.util.Arrays;
 
 /**
  * Ultra HDR decoding utility class.
@@ -38,33 +39,37 @@ public class UltraHDRDecoder implements AutoCloseable {
      * GainMap Metadata Descriptor
      */
     public static class GainMapMetadata {
-        public float maxContentBoost;
-        public float minContentBoost;
-        public float gamma;
-        public float offsetSdr;
-        public float offsetHdr;
+        public float[] maxContentBoost = new float[3];
+        public float[] minContentBoost = new float[3];
+        public float[] gamma = new float[3];
+        public float[] offsetSdr = new float[3];
+        public float[] offsetHdr = new float[3];
         public float hdrCapacityMin;
         public float hdrCapacityMax;
+        public boolean useBaseColorSpace;
 
         public GainMapMetadata() {
-            this.maxContentBoost = 1.0f;
-            this.minContentBoost = 1.0f;
-            this.gamma = 1.0f;
-            this.offsetSdr = 0.0f;
-            this.offsetHdr = 0.0f;
+            Arrays.fill(this.maxContentBoost, 1.0f);
+            Arrays.fill(this.minContentBoost, 1.0f);
+            Arrays.fill(this.gamma, 1.0f);
+            Arrays.fill(this.offsetSdr, 0.0f);
+            Arrays.fill(this.offsetHdr, 0.0f);
             this.hdrCapacityMin = 1.0f;
             this.hdrCapacityMax = 1.0f;
+            this.useBaseColorSpace = true;
         }
 
-        public GainMapMetadata(float maxContentBoost, float minContentBoost, float gamma,
-                float offsetSdr, float offsetHdr, float hdrCapacityMin, float hdrCapacityMax) {
-            this.maxContentBoost = maxContentBoost;
-            this.minContentBoost = minContentBoost;
-            this.gamma = gamma;
-            this.offsetSdr = offsetSdr;
-            this.offsetHdr = offsetHdr;
+        public GainMapMetadata(float[] maxContentBoost, float[] minContentBoost, float[] gamma,
+                float[] offsetSdr, float[] offsetHdr, float hdrCapacityMin, float hdrCapacityMax,
+                boolean useBaseColorSpace) {
+            System.arraycopy(maxContentBoost, 0, this.maxContentBoost, 0, 3);
+            System.arraycopy(minContentBoost, 0, this.minContentBoost, 0, 3);
+            System.arraycopy(gamma, 0, this.gamma, 0, 3);
+            System.arraycopy(offsetSdr, 0, this.offsetSdr, 0, 3);
+            System.arraycopy(offsetHdr, 0, this.offsetHdr, 0, 3);
             this.hdrCapacityMin = hdrCapacityMin;
             this.hdrCapacityMax = hdrCapacityMax;
+            this.useBaseColorSpace = useBaseColorSpace;
         }
     }
 
@@ -383,7 +388,7 @@ public class UltraHDRDecoder implements AutoCloseable {
     public GainMapMetadata getGainmapMetadata() throws IOException {
         getGainmapMetadataNative();
         return new GainMapMetadata(maxContentBoost, minContentBoost, gamma, offsetSdr,
-                offsetHdr, hdrCapacityMin, hdrCapacityMax);
+                offsetHdr, hdrCapacityMin, hdrCapacityMax, useBaseColorSpace);
     }
 
     /**
@@ -474,13 +479,14 @@ public class UltraHDRDecoder implements AutoCloseable {
     }
 
     private void resetState() {
-        maxContentBoost = 1.0f;
-        minContentBoost = 1.0f;
-        gamma = 1.0f;
-        offsetSdr = 0.0f;
-        offsetHdr = 0.0f;
+        Arrays.fill(maxContentBoost, 1.0f);
+        Arrays.fill(minContentBoost, 1.0f);
+        Arrays.fill(gamma, 1.0f);
+        Arrays.fill(offsetSdr, 0.0f);
+        Arrays.fill(offsetHdr, 0.0f);
         hdrCapacityMin = 1.0f;
         hdrCapacityMax = 1.0f;
+        useBaseColorSpace = true;
 
         decodedDataNativeOrder = null;
         decodedDataInt32 = null;
@@ -554,13 +560,14 @@ public class UltraHDRDecoder implements AutoCloseable {
     /**
      * gainmap metadata fields. Filled by {@link UltraHDRDecoder#getGainmapMetadataNative()}
      */
-    private float maxContentBoost;
-    private float minContentBoost;
-    private float gamma;
-    private float offsetSdr;
-    private float offsetHdr;
+    private float[] maxContentBoost = new float[3];
+    private float[] minContentBoost = new float[3];
+    private float[] gamma = new float[3];
+    private float[] offsetSdr = new float[3];
+    private float[] offsetHdr = new float[3];
     private float hdrCapacityMin;
     private float hdrCapacityMax;
+    private boolean useBaseColorSpace;
 
     /**
      * decoded image fields. Filled by {@link UltraHDRDecoder#getDecodedImageNative()}
diff --git a/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java b/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java
index bc3427d..ac77886 100644
--- a/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java
+++ b/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java
@@ -315,9 +315,10 @@ public class UltraHDREncoder implements AutoCloseable {
      *                     or current encoder instance is not suitable for configuration
      *                     exception is thrown
      */
-    public void setGainMapImageInfo(byte[] data, int size, float maxContentBoost,
-            float minContentBoost, float gainmapGamma, float offsetSdr, float offsetHdr,
-            float hdrCapacityMin, float hdrCapacityMax) throws IOException {
+    public void setGainMapImageInfo(byte[] data, int size, float[] maxContentBoost,
+            float[] minContentBoost, float[] gainmapGamma, float[] offsetSdr, float[] offsetHdr,
+            float hdrCapacityMin, float hdrCapacityMax, boolean useBaseColorSpace)
+            throws IOException {
         if (data == null) {
             throw new IOException("received null for image data handle");
         }
@@ -325,7 +326,7 @@ public class UltraHDREncoder implements AutoCloseable {
             throw new IOException("received invalid compressed image size, size is <= 0");
         }
         setGainMapImageInfoNative(data, size, maxContentBoost, minContentBoost, gainmapGamma,
-                offsetSdr, offsetHdr, hdrCapacityMin, hdrCapacityMax);
+                offsetSdr, offsetHdr, hdrCapacityMin, hdrCapacityMax, useBaseColorSpace);
     }
 
     /**
@@ -530,9 +531,10 @@ public class UltraHDREncoder implements AutoCloseable {
     private native void setCompressedImageNative(byte[] data, int size, int colorGamut,
             int colorTransfer, int range, int intent) throws IOException;
 
-    private native void setGainMapImageInfoNative(byte[] data, int size, float maxContentBoost,
-            float minContentBoost, float gainmapGamma, float offsetSdr, float offsetHdr,
-            float hdrCapacityMin, float hdrCapacityMax) throws IOException;
+    private native void setGainMapImageInfoNative(byte[] data, int size, float[] maxContentBoost,
+            float[] minContentBoost, float[] gainmapGamma, float[] offsetSdr, float[] offsetHdr,
+            float hdrCapacityMin, float hdrCapacityMax, boolean useBaseColorSpace)
+            throws IOException;
 
     private native void setExifDataNative(byte[] data, int size) throws IOException;
 
diff --git a/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h b/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h
index 985b6ae..271aa93 100644
--- a/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h
+++ b/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h
@@ -76,10 +76,10 @@ JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_set
 /*
  * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
  * Method:    setGainMapImageInfoNative
- * Signature: ([BIFFFFFFF)V
+ * Signature: ([BI[F[F[F[F[FFFZ)V
  */
 JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapImageInfoNative
-  (JNIEnv *, jobject, jbyteArray, jint, jfloat, jfloat, jfloat, jfloat, jfloat, jfloat, jfloat);
+  (JNIEnv *, jobject, jbyteArray, jint, jfloatArray, jfloatArray, jfloatArray, jfloatArray, jfloatArray, jfloat, jfloat, jboolean);
 
 /*
  * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
diff --git a/java/jni/ultrahdr-jni.cpp b/java/jni/ultrahdr-jni.cpp
index 0fa8f4b..e105b52 100644
--- a/java/jni/ultrahdr-jni.cpp
+++ b/java/jni/ultrahdr-jni.cpp
@@ -233,9 +233,10 @@ Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setCompressedImageNative(
 
 extern "C" JNIEXPORT void JNICALL
 Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapImageInfoNative(
-    JNIEnv *env, jobject thiz, jbyteArray data, jint size, jfloat max_content_boost,
-    jfloat min_content_boost, jfloat gainmap_gamma, jfloat offset_sdr, jfloat offset_hdr,
-    jfloat hdr_capacity_min, jfloat hdr_capacity_max) {
+    JNIEnv *env, jobject thiz, jbyteArray data, jint size, jfloatArray max_content_boost,
+    jfloatArray min_content_boost, jfloatArray gainmap_gamma, jfloatArray offset_sdr,
+    jfloatArray offset_hdr, jfloat hdr_capacity_min, jfloat hdr_capacity_max,
+    jboolean use_base_color_space) {
   GET_HANDLE()
   RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
   jsize length = env->GetArrayLength(data);
@@ -248,9 +249,23 @@ Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapImageInfoNative(
                               UHDR_CG_UNSPECIFIED,
                               UHDR_CT_UNSPECIFIED,
                               UHDR_CR_UNSPECIFIED};
-  uhdr_gainmap_metadata_t metadata{max_content_boost, min_content_boost, gainmap_gamma,
-                                   offset_sdr,        offset_hdr,        hdr_capacity_min,
-                                   hdr_capacity_max};
+
+#define GET_FLOAT_ARRAY(env, srcArray, dstArray)                                   \
+  {                                                                                \
+    RET_IF_TRUE(srcArray == nullptr, "java/io/IOException", "received nullptr");   \
+    jsize length = env->GetArrayLength(srcArray);                                  \
+    RET_IF_TRUE(length != 3, "java/io/IOException", "array must have 3 elements"); \
+    env->GetFloatArrayRegion(srcArray, 0, 3, dstArray);                            \
+  }
+  uhdr_gainmap_metadata_t metadata{};
+  GET_FLOAT_ARRAY(env, max_content_boost, metadata.max_content_boost)
+  GET_FLOAT_ARRAY(env, min_content_boost, metadata.min_content_boost)
+  GET_FLOAT_ARRAY(env, gainmap_gamma, metadata.gamma)
+  GET_FLOAT_ARRAY(env, offset_sdr, metadata.offset_sdr)
+  GET_FLOAT_ARRAY(env, offset_hdr, metadata.offset_hdr)
+  metadata.hdr_capacity_min = hdr_capacity_min;
+  metadata.hdr_capacity_max = hdr_capacity_max;
+  metadata.use_base_cg = use_base_color_space;
   auto status = uhdr_enc_set_gainmap_image((uhdr_codec_private_t *)handle, &img, &metadata);
   env->ReleaseByteArrayElements(data, body, 0);
   RET_IF_TRUE(
@@ -624,6 +639,19 @@ Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainmapMetadataNative(J
       uhdr_dec_get_gainmap_metadata((uhdr_codec_private_t *)handle);
   RET_IF_TRUE(gainmap_metadata == nullptr, "java/io/IOException",
               "uhdr_dec_probe() is not yet called or it has returned with error")
+#define SET_FLOAT_ARRAY_FIELD(name, valArray)                         \
+  {                                                                   \
+    jfieldID fID = env->GetFieldID(clazz, name, "[F");                \
+    RET_IF_TRUE(fID == nullptr, "java/io/IOException",                \
+                "GetFieldID for field " #name " returned with error") \
+    jfloatArray array = env->NewFloatArray(3);                        \
+    RET_IF_TRUE(array == nullptr, "java/io/IOException",              \
+                "Failed to allocate float array for field " #name)    \
+    env->SetFloatArrayRegion(array, 0, 3, (const jfloat *)valArray);  \
+    env->SetObjectField(thiz, fID, array);                            \
+    env->DeleteLocalRef(array);                                       \
+  }
+
 #define SET_FLOAT_FIELD(name, val)                                    \
   {                                                                   \
     jfieldID fID = env->GetFieldID(clazz, name, "F");                 \
@@ -631,13 +659,21 @@ Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainmapMetadataNative(J
                 "GetFieldID for field " #name " returned with error") \
     env->SetFloatField(thiz, fID, (jfloat)val);                       \
   }
-  SET_FLOAT_FIELD("maxContentBoost", gainmap_metadata->max_content_boost)
-  SET_FLOAT_FIELD("minContentBoost", gainmap_metadata->min_content_boost)
-  SET_FLOAT_FIELD("gamma", gainmap_metadata->gamma)
-  SET_FLOAT_FIELD("offsetSdr", gainmap_metadata->offset_sdr)
-  SET_FLOAT_FIELD("offsetHdr", gainmap_metadata->offset_hdr)
+  SET_FLOAT_ARRAY_FIELD("maxContentBoost", gainmap_metadata->max_content_boost)
+  SET_FLOAT_ARRAY_FIELD("minContentBoost", gainmap_metadata->min_content_boost)
+  SET_FLOAT_ARRAY_FIELD("gamma", gainmap_metadata->gamma)
+  SET_FLOAT_ARRAY_FIELD("offsetSdr", gainmap_metadata->offset_sdr)
+  SET_FLOAT_ARRAY_FIELD("offsetHdr", gainmap_metadata->offset_hdr)
   SET_FLOAT_FIELD("hdrCapacityMin", gainmap_metadata->hdr_capacity_min)
   SET_FLOAT_FIELD("hdrCapacityMax", gainmap_metadata->hdr_capacity_max)
+#define SET_BOOLEAN_FIELD(name, val)                                  \
+  {                                                                   \
+    jfieldID fID = env->GetFieldID(clazz, name, "Z");                 \
+    RET_IF_TRUE(fID == nullptr, "java/io/IOException",                \
+                "GetFieldID for field " #name " returned with error") \
+    env->SetBooleanField(thiz, fID, (jboolean)val);                   \
+  }
+  SET_BOOLEAN_FIELD("useBaseColorSpace", gainmap_metadata->use_base_cg)
 }
 
 extern "C" JNIEXPORT void JNICALL
diff --git a/java/metadata.cfg b/java/metadata.cfg
index baf8f2f..bfbc50e 100644
--- a/java/metadata.cfg
+++ b/java/metadata.cfg
@@ -1,7 +1,8 @@
---maxContentBoost 6.0
---minContentBoost 1.0
---gamma 1.0
---offsetSdr 0.0
---offsetHdr 0.0
+--maxContentBoost 6.0 6.0 6.0
+--minContentBoost 1.0 1.0 1.0
+--gamma 1.0 1.0 1.0
+--offsetSdr 0.0 0.0 0.0
+--offsetHdr 0.0 0.0 0.0
 --hdrCapacityMin 1.0
---hdrCapacityMax 6.0
+--hdrCapacityMax 49.2611
+--useBaseColorSpace 1
diff --git a/lib/include/ultrahdr/gainmapmath.h b/lib/include/ultrahdr/gainmapmath.h
index d604ad2..b51a977 100644
--- a/lib/include/ultrahdr/gainmapmath.h
+++ b/lib/include/ultrahdr/gainmapmath.h
@@ -398,6 +398,13 @@ void putYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel);
 // Color space conversions
 
 // color gamut conversion (rgb) functions
+extern const std::array<float, 9> kBt709ToP3;
+extern const std::array<float, 9> kBt709ToBt2100;
+extern const std::array<float, 9> kP3ToBt709;
+extern const std::array<float, 9> kP3ToBt2100;
+extern const std::array<float, 9> kBt2100ToBt709;
+extern const std::array<float, 9> kBt2100ToP3;
+
 inline Color identityConversion(Color e) { return e; }
 Color bt709ToP3(Color e);
 Color bt709ToBt2100(Color e);
@@ -449,48 +456,57 @@ constexpr int32_t kGainFactorPrecision = 10;
 constexpr int32_t kGainFactorNumEntries = 1 << kGainFactorPrecision;
 
 struct GainLUT {
-  GainLUT(uhdr_gainmap_metadata_ext_t* metadata) {
-    this->mGammaInv = 1.0f / metadata->gamma;
-    for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
-      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
-      float logBoost = log2(metadata->min_content_boost) * (1.0f - value) +
-                       log2(metadata->max_content_boost) * value;
-      mGainTable[idx] = exp2(logBoost);
+  GainLUT(uhdr_gainmap_metadata_ext_t* metadata, float gainmapWeight) {
+    bool isSingleChannel = metadata->are_all_channels_identical();
+    for (int i = 0; i < (isSingleChannel ? 1 : 3); i++) {
+      mGainTable[i] = memory[i] = new float[kGainFactorNumEntries];
+      this->mGammaInv[i] = 1.0f / metadata->gamma[i];
+      for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
+        float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
+        float logBoost = log2(metadata->min_content_boost[i]) * (1.0f - value) +
+                         log2(metadata->max_content_boost[i]) * value;
+        mGainTable[i][idx] = exp2(logBoost * gainmapWeight);
+      }
+    }
+    if (isSingleChannel) {
+      memory[1] = memory[2] = nullptr;
+      mGammaInv[1] = mGammaInv[2] = mGammaInv[0];
+      mGainTable[1] = mGainTable[2] = mGainTable[0];
     }
   }
 
-  GainLUT(uhdr_gainmap_metadata_ext_t* metadata, float gainmapWeight) {
-    this->mGammaInv = 1.0f / metadata->gamma;
-    for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
-      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
-      float logBoost = log2(metadata->min_content_boost) * (1.0f - value) +
-                       log2(metadata->max_content_boost) * value;
-      mGainTable[idx] = exp2(logBoost * gainmapWeight);
+  GainLUT(uhdr_gainmap_metadata_ext_t* metadata) : GainLUT(metadata, 1.0f) {}
+
+  ~GainLUT() {
+    for (int i = 0; i < 3; i++) {
+      if (memory[i]) {
+        delete[] memory[i];
+        memory[i] = nullptr;
+      }
     }
   }
 
-  ~GainLUT() {}
-
-  float getGainFactor(float gain) {
-    if (mGammaInv != 1.0f) gain = pow(gain, mGammaInv);
+  float getGainFactor(float gain, int index) {
+    if (mGammaInv[index] != 1.0f) gain = pow(gain, mGammaInv[index]);
     int32_t idx = static_cast<int32_t>(gain * (kGainFactorNumEntries - 1) + 0.5);
     // TODO() : Remove once conversion modules have appropriate clamping in place
     idx = CLIP3(idx, 0, kGainFactorNumEntries - 1);
-    return mGainTable[idx];
+    return mGainTable[index][idx];
   }
 
  private:
-  float mGainTable[kGainFactorNumEntries];
-  float mGammaInv;
+  float* memory[3]{};
+  float* mGainTable[3]{};
+  float mGammaInv[3]{};
 };
 
 /*
  * Calculate the 8-bit unsigned integer gain value for the given SDR and HDR
  * luminances in linear space and gainmap metadata fields.
  */
-uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata);
+uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata, int index);
 uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata,
-                   float log2MinContentBoost, float log2MaxContentBoost);
+                   float log2MinContentBoost, float log2MaxContentBoost, int index);
 float computeGain(float sdr, float hdr);
 uint8_t affineMapGain(float gainlog2, float mingainlog2, float maxgainlog2, float gamma);
 
@@ -536,6 +552,14 @@ PutPixelFn putPixelFn(uhdr_img_fmt_t format);
 
 ////////////////////////////////////////////////////////////////////////////////
 // common utils
+static const float kHdrOffset = 1e-7f;
+static const float kSdrOffset = 1e-7f;
+
+static inline float clipNegatives(float value) { return (value < 0.0f) ? 0.0f : value; }
+
+static inline Color clipNegatives(Color e) {
+  return {{{clipNegatives(e.r), clipNegatives(e.g), clipNegatives(e.b)}}};
+}
 
 // maximum limit of normalized pixel value in float representation
 static const float kMaxPixelFloat = 1.0f;
diff --git a/lib/include/ultrahdr/icc.h b/lib/include/ultrahdr/icc.h
index 9f71e30..5e88346 100644
--- a/lib/include/ultrahdr/icc.h
+++ b/lib/include/ultrahdr/icc.h
@@ -103,6 +103,10 @@ static constexpr size_t kICCTagTableEntrySize = 12;
 // bytes for a single XYZ number type (4 bytes per coordinate).
 static constexpr size_t kColorantTagSize = 20;
 
+// size should be 12; 4 bytes for type descriptor, 4 bytes reserved, one
+// byte each for primaries, transfer, matrix, range.
+static constexpr size_t kCicpTagSize = 12;
+
 static constexpr uint32_t kDisplay_Profile = SetFourByteTag('m', 'n', 't', 'r');
 static constexpr uint32_t kRGB_ColorSpace = SetFourByteTag('R', 'G', 'B', ' ');
 static constexpr uint32_t kXYZ_PCSSpace = SetFourByteTag('X', 'Y', 'Z', ' ');
@@ -149,10 +153,12 @@ static constexpr Matrix3x3 kRec2020 = {{
     {-0.00193139f, 0.0299794f, 0.797162f},
 }};
 
+static constexpr uint32_t kCICPPrimariesUnSpecified = 2;
 static constexpr uint32_t kCICPPrimariesSRGB = 1;
 static constexpr uint32_t kCICPPrimariesP3 = 12;
 static constexpr uint32_t kCICPPrimariesRec2020 = 9;
 
+static constexpr uint32_t kCICPTrfnUnSpecified = 2;
 static constexpr uint32_t kCICPTrfnSRGB = 1;
 static constexpr uint32_t kCICPTrfnLinear = 8;
 static constexpr uint32_t kCICPTrfnPQ = 16;
diff --git a/lib/include/ultrahdr/ultrahdrcommon.h b/lib/include/ultrahdr/ultrahdrcommon.h
index 67a3d06..4823844 100644
--- a/lib/include/ultrahdr/ultrahdrcommon.h
+++ b/lib/include/ultrahdr/ultrahdrcommon.h
@@ -204,17 +204,28 @@ typedef struct uhdr_effect_desc uhdr_effect_desc_t;
 typedef struct uhdr_gainmap_metadata_ext : uhdr_gainmap_metadata {
   uhdr_gainmap_metadata_ext() {}
 
-  uhdr_gainmap_metadata_ext(std::string ver) { version = ver; }
-
-  uhdr_gainmap_metadata_ext(uhdr_gainmap_metadata& metadata, std::string ver) {
-    max_content_boost = metadata.max_content_boost;
-    min_content_boost = metadata.min_content_boost;
-    gamma = metadata.gamma;
-    offset_sdr = metadata.offset_sdr;
-    offset_hdr = metadata.offset_hdr;
+  uhdr_gainmap_metadata_ext(std::string ver) : version(ver) {}
+
+  uhdr_gainmap_metadata_ext(uhdr_gainmap_metadata& metadata, std::string ver)
+      : uhdr_gainmap_metadata_ext(ver) {
+    std::copy(metadata.max_content_boost, metadata.max_content_boost + 3, max_content_boost);
+    std::copy(metadata.min_content_boost, metadata.min_content_boost + 3, min_content_boost);
+    std::copy(metadata.gamma, metadata.gamma + 3, gamma);
+    std::copy(metadata.offset_sdr, metadata.offset_sdr + 3, offset_sdr);
+    std::copy(metadata.offset_hdr, metadata.offset_hdr + 3, offset_hdr);
     hdr_capacity_min = metadata.hdr_capacity_min;
     hdr_capacity_max = metadata.hdr_capacity_max;
-    version = ver;
+    use_base_cg = metadata.use_base_cg;
+  }
+
+  bool are_all_channels_identical() const {
+    return max_content_boost[0] == max_content_boost[1] &&
+           max_content_boost[0] == max_content_boost[2] &&
+           min_content_boost[0] == min_content_boost[1] &&
+           min_content_boost[0] == min_content_boost[2] && gamma[0] == gamma[1] &&
+           gamma[0] == gamma[2] && offset_sdr[0] == offset_sdr[1] &&
+           offset_sdr[0] == offset_sdr[2] && offset_hdr[0] == offset_hdr[1] &&
+           offset_hdr[0] == offset_hdr[2];
   }
 
   std::string version;         /**< Ultra HDR format version */
diff --git a/lib/src/gainmapmath.cpp b/lib/src/gainmapmath.cpp
index fa56c3e..b14be0e 100644
--- a/lib/src/gainmapmath.cpp
+++ b/lib/src/gainmapmath.cpp
@@ -89,7 +89,7 @@ void ShepardsIDW::fillShepardsIDW(float* weights, int incR, int incB) {
 // sRGB transformations
 
 // See IEC 61966-2-1/Amd 1:2003, Equation F.7.
-static const float kSrgbR = 0.2126f, kSrgbG = 0.7152f, kSrgbB = 0.0722f;
+static const float kSrgbR = 0.212639f, kSrgbG = 0.715169f, kSrgbB = 0.072192f;
 
 float srgbLuminance(Color e) { return kSrgbR * e.r + kSrgbG * e.g + kSrgbB * e.b; }
 
@@ -97,7 +97,7 @@ float srgbLuminance(Color e) { return kSrgbR * e.r + kSrgbG * e.g + kSrgbB * e.b
 // Uses the same coefficients for deriving luma signal as
 // IEC 61966-2-1/Amd 1:2003 states for luminance, so we reuse the luminance
 // function above.
-static const float kSrgbCb = 1.8556f, kSrgbCr = 1.5748f;
+static const float kSrgbCb = (2 * (1 - kSrgbB)), kSrgbCr = (2 * (1 - kSrgbR));
 
 Color srgbRgbToYuv(Color e_gamma) {
   float y_gamma = srgbLuminance(e_gamma);
@@ -121,7 +121,7 @@ float srgbInvOetf(float e_gamma) {
   if (e_gamma <= 0.04045f) {
     return e_gamma / 12.92f;
   } else {
-    return pow((e_gamma + 0.055f) / 1.055f, 2.4);
+    return pow((e_gamma + 0.055f) / 1.055f, 2.4f);
   }
 }
 
@@ -129,7 +129,6 @@ Color srgbInvOetf(Color e_gamma) {
   return {{{srgbInvOetf(e_gamma.r), srgbInvOetf(e_gamma.g), srgbInvOetf(e_gamma.b)}}};
 }
 
-// See IEC 61966-2-1, Equations F.5 and F.6.
 float srgbInvOetfLUT(float e_gamma) {
   int32_t value = static_cast<int32_t>(e_gamma * (kSrgbInvOETFNumEntries - 1) + 0.5);
   // TODO() : Remove once conversion modules have appropriate clamping in place
@@ -142,15 +141,16 @@ Color srgbInvOetfLUT(Color e_gamma) {
   return {{{srgbInvOetfLUT(e_gamma.r), srgbInvOetfLUT(e_gamma.g), srgbInvOetfLUT(e_gamma.b)}}};
 }
 
+// See IEC 61966-2-1/Amd 1:2003, Equations F.10 and F.11.
 float srgbOetf(float e) {
-  constexpr float kThreshold = 0.0031308;
-  constexpr float kLowSlope = 12.92;
-  constexpr float kHighOffset = 0.055;
-  constexpr float kPowerExponent = 1.0 / 2.4;
+  constexpr float kThreshold = 0.0031308f;
+  constexpr float kLowSlope = 12.92f;
+  constexpr float kHighOffset = 0.055f;
+  constexpr float kPowerExponent = 1.0f / 2.4f;
   if (e <= kThreshold) {
     return kLowSlope * e;
   }
-  return (1.0 + kHighOffset) * std::pow(e, kPowerExponent) - kHighOffset;
+  return (1.0f + kHighOffset) * std::pow(e, kPowerExponent) - kHighOffset;
 }
 
 Color srgbOetf(Color e) { return {{{srgbOetf(e.r), srgbOetf(e.g), srgbOetf(e.b)}}}; }
@@ -158,8 +158,8 @@ Color srgbOetf(Color e) { return {{{srgbOetf(e.r), srgbOetf(e.g), srgbOetf(e.b)}
 ////////////////////////////////////////////////////////////////////////////////
 // Display-P3 transformations
 
-// See SMPTE EG 432-1, Equation 7-8.
-static const float kP3R = 0.20949f, kP3G = 0.72160f, kP3B = 0.06891f;
+// See SMPTE EG 432-1, Equation G-7.
+static const float kP3R = 0.2289746f, kP3G = 0.6917385f, kP3B = 0.0792869f;
 
 float p3Luminance(Color e) { return kP3R * e.r + kP3G * e.g + kP3B * e.b; }
 
@@ -190,14 +190,14 @@ Color p3YuvToRgb(Color e_gamma) {
 // BT.2100 transformations - according to ITU-R BT.2100-2
 
 // See ITU-R BT.2100-2, Table 5, HLG Reference OOTF
-static const float kBt2100R = 0.2627f, kBt2100G = 0.6780f, kBt2100B = 0.0593f;
+static const float kBt2100R = 0.2627f, kBt2100G = 0.677998f, kBt2100B = 0.059302f;
 
 float bt2100Luminance(Color e) { return kBt2100R * e.r + kBt2100G * e.g + kBt2100B * e.b; }
 
 // See ITU-R BT.2100-2, Table 6, Derivation of colour difference signals.
 // BT.2100 uses the same coefficients for calculating luma signal and luminance,
 // so we reuse the luminance function here.
-static const float kBt2100Cb = 1.8814f, kBt2100Cr = 1.4746f;
+static const float kBt2100Cb = (2 * (1 - kBt2100B)), kBt2100Cr = (2 * (1 - kBt2100R));
 
 Color bt2100RgbToYuv(Color e_gamma) {
   float y_gamma = bt2100Luminance(e_gamma);
@@ -239,7 +239,7 @@ Color bt2100YuvToRgb(Color e_gamma) {
 }
 
 // See ITU-R BT.2100-2, Table 5, HLG Reference OETF.
-static const float kHlgA = 0.17883277f, kHlgB = 0.28466892f, kHlgC = 0.55991073;
+static const float kHlgA = 0.17883277f, kHlgB = 0.28466892f, kHlgC = 0.55991073f;
 
 float hlgOetf(float e) {
   if (e <= 1.0f / 12.0f) {
@@ -286,9 +286,11 @@ Color hlgInvOetfLUT(Color e_gamma) {
   return {{{hlgInvOetfLUT(e_gamma.r), hlgInvOetfLUT(e_gamma.g), hlgInvOetfLUT(e_gamma.b)}}};
 }
 
-// 1.2f + 0.42 * log(kHlgMaxNits / 1000)
+// See ITU-R BT.2100-2, Table 5, Note 5f
+// Gamma = 1.2 + 0.42 * log(kHlgMaxNits / 1000)
 static const float kOotfGamma = 1.2f;
 
+// See ITU-R BT.2100-2, Table 5, HLG Reference OOTF
 Color hlgOotf(Color e, LuminanceFn luminance) {
   float y = luminance(e);
   return e * std::pow(y, kOotfGamma - 1.0f);
@@ -298,6 +300,7 @@ Color hlgOotfApprox(Color e, [[maybe_unused]] LuminanceFn luminance) {
   return {{{std::pow(e.r, kOotfGamma), std::pow(e.g, kOotfGamma), std::pow(e.b, kOotfGamma)}}};
 }
 
+// See ITU-R BT.2100-2, Table 5, Note 5i
 Color hlgInverseOotf(Color e, LuminanceFn luminance) {
   float y = luminance(e);
   return e * std::pow(y, (1.0f / kOotfGamma) - 1.0f);
@@ -600,42 +603,34 @@ void putYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel) {
 
 ////////////////////////////////////////////////////////////////////////////////
 // Color space conversions
-
-Color bt709ToP3(Color e) {
-  return {{{0.82254f * e.r + 0.17755f * e.g + 0.00006f * e.b,
-            0.03312f * e.r + 0.96684f * e.g + -0.00001f * e.b,
-            0.01706f * e.r + 0.07240f * e.g + 0.91049f * e.b}}};
-}
-
-Color bt709ToBt2100(Color e) {
-  return {{{0.62740f * e.r + 0.32930f * e.g + 0.04332f * e.b,
-            0.06904f * e.r + 0.91958f * e.g + 0.01138f * e.b,
-            0.01636f * e.r + 0.08799f * e.g + 0.89555f * e.b}}};
-}
-
-Color p3ToBt709(Color e) {
-  return {{{1.22482f * e.r + -0.22490f * e.g + -0.00007f * e.b,
-            -0.04196f * e.r + 1.04199f * e.g + 0.00001f * e.b,
-            -0.01961f * e.r + -0.07865f * e.g + 1.09831f * e.b}}};
-}
-
-Color p3ToBt2100(Color e) {
-  return {{{0.75378f * e.r + 0.19862f * e.g + 0.04754f * e.b,
-            0.04576f * e.r + 0.94177f * e.g + 0.01250f * e.b,
-            -0.00121f * e.r + 0.01757f * e.g + 0.98359f * e.b}}};
-}
-
-Color bt2100ToBt709(Color e) {
-  return {{{1.66045f * e.r + -0.58764f * e.g + -0.07286f * e.b,
-            -0.12445f * e.r + 1.13282f * e.g + -0.00837f * e.b,
-            -0.01811f * e.r + -0.10057f * e.g + 1.11878f * e.b}}};
-}
-
-Color bt2100ToP3(Color e) {
-  return {{{1.34369f * e.r + -0.28223f * e.g + -0.06135f * e.b,
-            -0.06533f * e.r + 1.07580f * e.g + -0.01051f * e.b,
-            0.00283f * e.r + -0.01957f * e.g + 1.01679f * e.b}}};
-}
+// Sample, See,
+// https://registry.khronos.org/DataFormat/specs/1.3/dataformat.1.3.html#_bt_709_bt_2020_primary_conversion_example
+
+const std::array<float, 9> kBt709ToP3 = {0.822462f,  0.177537f, 0.000001f, 0.033194f, 0.966807f,
+                                         -0.000001f, 0.017083f, 0.072398f, 0.91052f};
+const std::array<float, 9> kBt709ToBt2100 = {0.627404f, 0.329282f, 0.043314f, 0.069097f, 0.919541f,
+                                             0.011362f, 0.016392f, 0.088013f, 0.895595f};
+const std::array<float, 9> kP3ToBt709 = {1.22494f, -0.22494f,  0.0f,       -0.042057f, 1.042057f,
+                                         0.0f,     -0.019638f, -0.078636f, 1.098274f};
+const std::array<float, 9> kP3ToBt2100 = {0.753833f, 0.198597f, 0.04757f,  0.045744f, 0.941777f,
+                                          0.012479f, -0.00121f, 0.017601f, 0.983608f};
+const std::array<float, 9> kBt2100ToBt709 = {1.660491f,  -0.587641f, -0.07285f,
+                                             -0.124551f, 1.1329f,    -0.008349f,
+                                             -0.018151f, -0.100579f, 1.11873f};
+const std::array<float, 9> kBt2100ToP3 = {1.343578f, -0.282179f, -0.061399f, -0.065298f, 1.075788f,
+                                          -0.01049f, 0.002822f,  -0.019598f, 1.016777f};
+
+Color ConvertGamut(Color e, const std::array<float, 9>& coeffs) {
+  return {{{coeffs[0] * e.r + coeffs[1] * e.g + coeffs[2] * e.b,
+            coeffs[3] * e.r + coeffs[4] * e.g + coeffs[5] * e.b,
+            coeffs[6] * e.r + coeffs[7] * e.g + coeffs[8] * e.b}}};
+}
+Color bt709ToP3(Color e) { return ConvertGamut(e, kBt709ToP3); }
+Color bt709ToBt2100(Color e) { return ConvertGamut(e, kBt709ToBt2100); }
+Color p3ToBt709(Color e) { return ConvertGamut(e, kP3ToBt709); }
+Color p3ToBt2100(Color e) { return ConvertGamut(e, kP3ToBt2100); }
+Color bt2100ToBt709(Color e) { return ConvertGamut(e, kBt2100ToBt709); }
+Color bt2100ToP3(Color e) { return ConvertGamut(e, kBt2100ToP3); }
 
 // All of these conversions are derived from the respective input YUV->RGB conversion followed by
 // the RGB->YUV for the receiving encoding. They are consistent with the RGB<->YUV functions in
@@ -761,33 +756,35 @@ void transformYuv444(uhdr_raw_image_t* image, const std::array<float, 9>& coeffs
 ////////////////////////////////////////////////////////////////////////////////
 // Gain map calculations
 
-uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata) {
-  return encodeGain(y_sdr, y_hdr, metadata, log2(metadata->min_content_boost),
-                    log2(metadata->max_content_boost));
+uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata, int index) {
+  return encodeGain(y_sdr, y_hdr, metadata, log2(metadata->min_content_boost[index]),
+                    log2(metadata->max_content_boost[index]), index);
 }
 
 uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata,
-                   float log2MinContentBoost, float log2MaxContentBoost) {
+                   float log2MinContentBoost, float log2MaxContentBoost, int index) {
   float gain = 1.0f;
   if (y_sdr > 0.0f) {
     gain = y_hdr / y_sdr;
   }
 
-  if (gain < metadata->min_content_boost) gain = metadata->min_content_boost;
-  if (gain > metadata->max_content_boost) gain = metadata->max_content_boost;
+  if (gain < metadata->min_content_boost[index]) gain = metadata->min_content_boost[index];
+  if (gain > metadata->max_content_boost[index]) gain = metadata->max_content_boost[index];
   float gain_normalized =
       (log2(gain) - log2MinContentBoost) / (log2MaxContentBoost - log2MinContentBoost);
-  float gain_normalized_gamma = powf(gain_normalized, metadata->gamma);
+  float gain_normalized_gamma = powf(gain_normalized, metadata->gamma[index]);
   return static_cast<uint8_t>(gain_normalized_gamma * 255.0f);
 }
 
 float computeGain(float sdr, float hdr) {
-  if (sdr == 0.0f) return 0.0f;  // for sdr black return no gain
-  if (hdr == 0.0f) {  // for hdr black, return a gain large enough to attenuate the sdr pel
-    float offset = (1.0f / 64);
-    return log2(offset / (offset + sdr));
+  float gain = log2((hdr + kHdrOffset) / (sdr + kSdrOffset));
+  if (sdr < 2.f / 255.0f) {
+    // If sdr is zero and hdr is non zero, it can result in very large gain values. In compression -
+    // decompression process, if the same sdr pixel increases to 1, the hdr recovered pixel will
+    // blow out. Dont allow dark pixels to signal large gains.
+    gain = (std::min)(gain, 2.3f);
   }
-  return log2(hdr / sdr);
+  return gain;
 }
 
 uint8_t affineMapGain(float gainlog2, float mingainlog2, float maxgainlog2, float gamma) {
@@ -798,73 +795,69 @@ uint8_t affineMapGain(float gainlog2, float mingainlog2, float maxgainlog2, floa
 }
 
 Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata) {
-  if (metadata->gamma != 1.0f) gain = pow(gain, 1.0f / metadata->gamma);
-  float logBoost =
-      log2(metadata->min_content_boost) * (1.0f - gain) + log2(metadata->max_content_boost) * gain;
+  if (metadata->gamma[0] != 1.0f) gain = pow(gain, 1.0f / metadata->gamma[0]);
+  float logBoost = log2(metadata->min_content_boost[0]) * (1.0f - gain) +
+                   log2(metadata->max_content_boost[0]) * gain;
   float gainFactor = exp2(logBoost);
-  return ((e + metadata->offset_sdr) * gainFactor) - metadata->offset_hdr;
+  return ((e + metadata->offset_sdr[0]) * gainFactor) - metadata->offset_hdr[0];
 }
 
 Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata, float gainmapWeight) {
-  if (metadata->gamma != 1.0f) gain = pow(gain, 1.0f / metadata->gamma);
-  float logBoost =
-      log2(metadata->min_content_boost) * (1.0f - gain) + log2(metadata->max_content_boost) * gain;
+  if (metadata->gamma[0] != 1.0f) gain = pow(gain, 1.0f / metadata->gamma[0]);
+  float logBoost = log2(metadata->min_content_boost[0]) * (1.0f - gain) +
+                   log2(metadata->max_content_boost[0]) * gain;
   float gainFactor = exp2(logBoost * gainmapWeight);
-  return ((e + metadata->offset_sdr) * gainFactor) - metadata->offset_hdr;
+  return ((e + metadata->offset_sdr[0]) * gainFactor) - metadata->offset_hdr[0];
 }
 
 Color applyGainLUT(Color e, float gain, GainLUT& gainLUT, uhdr_gainmap_metadata_ext_t* metadata) {
-  float gainFactor = gainLUT.getGainFactor(gain);
-  return ((e + metadata->offset_sdr) * gainFactor) - metadata->offset_hdr;
+  float gainFactor = gainLUT.getGainFactor(gain, 0);
+  return ((e + metadata->offset_sdr[0]) * gainFactor) - metadata->offset_hdr[0];
 }
 
 Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata) {
-  if (metadata->gamma != 1.0f) {
-    gain.r = pow(gain.r, 1.0f / metadata->gamma);
-    gain.g = pow(gain.g, 1.0f / metadata->gamma);
-    gain.b = pow(gain.b, 1.0f / metadata->gamma);
-  }
-  float logBoostR = log2(metadata->min_content_boost) * (1.0f - gain.r) +
-                    log2(metadata->max_content_boost) * gain.r;
-  float logBoostG = log2(metadata->min_content_boost) * (1.0f - gain.g) +
-                    log2(metadata->max_content_boost) * gain.g;
-  float logBoostB = log2(metadata->min_content_boost) * (1.0f - gain.b) +
-                    log2(metadata->max_content_boost) * gain.b;
+  if (metadata->gamma[0] != 1.0f) gain.r = pow(gain.r, 1.0f / metadata->gamma[0]);
+  if (metadata->gamma[1] != 1.0f) gain.g = pow(gain.g, 1.0f / metadata->gamma[1]);
+  if (metadata->gamma[2] != 1.0f) gain.b = pow(gain.b, 1.0f / metadata->gamma[2]);
+  float logBoostR = log2(metadata->min_content_boost[0]) * (1.0f - gain.r) +
+                    log2(metadata->max_content_boost[0]) * gain.r;
+  float logBoostG = log2(metadata->min_content_boost[1]) * (1.0f - gain.g) +
+                    log2(metadata->max_content_boost[1]) * gain.g;
+  float logBoostB = log2(metadata->min_content_boost[2]) * (1.0f - gain.b) +
+                    log2(metadata->max_content_boost[2]) * gain.b;
   float gainFactorR = exp2(logBoostR);
   float gainFactorG = exp2(logBoostG);
   float gainFactorB = exp2(logBoostB);
-  return {{{((e.r + metadata->offset_sdr) * gainFactorR) - metadata->offset_hdr,
-            ((e.g + metadata->offset_sdr) * gainFactorG) - metadata->offset_hdr,
-            ((e.b + metadata->offset_sdr) * gainFactorB) - metadata->offset_hdr}}};
+  return {{{((e.r + metadata->offset_sdr[0]) * gainFactorR) - metadata->offset_hdr[0],
+            ((e.g + metadata->offset_sdr[1]) * gainFactorG) - metadata->offset_hdr[1],
+            ((e.b + metadata->offset_sdr[2]) * gainFactorB) - metadata->offset_hdr[2]}}};
 }
 
 Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata, float gainmapWeight) {
-  if (metadata->gamma != 1.0f) {
-    gain.r = pow(gain.r, 1.0f / metadata->gamma);
-    gain.g = pow(gain.g, 1.0f / metadata->gamma);
-    gain.b = pow(gain.b, 1.0f / metadata->gamma);
-  }
-  float logBoostR = log2(metadata->min_content_boost) * (1.0f - gain.r) +
-                    log2(metadata->max_content_boost) * gain.r;
-  float logBoostG = log2(metadata->min_content_boost) * (1.0f - gain.g) +
-                    log2(metadata->max_content_boost) * gain.g;
-  float logBoostB = log2(metadata->min_content_boost) * (1.0f - gain.b) +
-                    log2(metadata->max_content_boost) * gain.b;
+  if (metadata->gamma[0] != 1.0f) gain.r = pow(gain.r, 1.0f / metadata->gamma[0]);
+  if (metadata->gamma[1] != 1.0f) gain.g = pow(gain.g, 1.0f / metadata->gamma[1]);
+  if (metadata->gamma[2] != 1.0f) gain.b = pow(gain.b, 1.0f / metadata->gamma[2]);
+  float logBoostR = log2(metadata->min_content_boost[0]) * (1.0f - gain.r) +
+                    log2(metadata->max_content_boost[0]) * gain.r;
+  float logBoostG = log2(metadata->min_content_boost[1]) * (1.0f - gain.g) +
+                    log2(metadata->max_content_boost[1]) * gain.g;
+  float logBoostB = log2(metadata->min_content_boost[2]) * (1.0f - gain.b) +
+                    log2(metadata->max_content_boost[2]) * gain.b;
   float gainFactorR = exp2(logBoostR * gainmapWeight);
   float gainFactorG = exp2(logBoostG * gainmapWeight);
   float gainFactorB = exp2(logBoostB * gainmapWeight);
-  return {{{((e.r + metadata->offset_sdr) * gainFactorR) - metadata->offset_hdr,
-            ((e.g + metadata->offset_sdr) * gainFactorG) - metadata->offset_hdr,
-            ((e.b + metadata->offset_sdr) * gainFactorB) - metadata->offset_hdr}}};
+  return {{{((e.r + metadata->offset_sdr[0]) * gainFactorR) - metadata->offset_hdr[0],
+            ((e.g + metadata->offset_sdr[1]) * gainFactorG) - metadata->offset_hdr[1],
+            ((e.b + metadata->offset_sdr[2]) * gainFactorB) - metadata->offset_hdr[2]}}};
 }
 
 Color applyGainLUT(Color e, Color gain, GainLUT& gainLUT, uhdr_gainmap_metadata_ext_t* metadata) {
-  float gainFactorR = gainLUT.getGainFactor(gain.r);
-  float gainFactorG = gainLUT.getGainFactor(gain.g);
-  float gainFactorB = gainLUT.getGainFactor(gain.b);
-  return {{{((e.r + metadata->offset_sdr) * gainFactorR) - metadata->offset_hdr,
-            ((e.g + metadata->offset_sdr) * gainFactorG) - metadata->offset_hdr,
-            ((e.b + metadata->offset_sdr) * gainFactorB) - metadata->offset_hdr}}};
+  float gainFactorR = gainLUT.getGainFactor(gain.r, 0);
+  float gainFactorG = gainLUT.getGainFactor(gain.g, 1);
+  float gainFactorB = gainLUT.getGainFactor(gain.b, 2);
+  return {{{((e.r + metadata->offset_sdr[0]) * gainFactorR) - metadata->offset_hdr[0],
+            ((e.g + metadata->offset_sdr[1]) * gainFactorG) - metadata->offset_hdr[1],
+            ((e.b + metadata->offset_sdr[2]) * gainFactorB) - metadata->offset_hdr[2]}}};
 }
 
 // TODO: do we need something more clever for filtering either the map or images
diff --git a/lib/src/gainmapmetadata.cpp b/lib/src/gainmapmetadata.cpp
index 6979c82..3699a96 100644
--- a/lib/src/gainmapmetadata.cpp
+++ b/lib/src/gainmapmetadata.cpp
@@ -324,17 +324,6 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(
     UHDR_CHECK_NON_ZERO(from->alternateOffsetD[i], "alternateOffset denominator");
   }
 
-  // TODO: extend uhdr_gainmap_metadata_ext_t to cover multi-channel
-  if (!from->allChannelsIdentical()) {
-    uhdr_error_info_t status;
-    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "current implementation does not handle images with gainmap metadata different "
-             "across r/g/b channels");
-    return status;
-  }
-
   // jpeg supports only 8 bits per component, applying gainmap in inverse direction is unexpected
   if (from->backwardDirection) {
     uhdr_error_info_t status;
@@ -344,27 +333,20 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(
     return status;
   }
 
-  // TODO: parse gainmap image icc and use it for color conversion during applygainmap
-  if (!from->useBaseColorSpace) {
-    uhdr_error_info_t status;
-    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "current implementation requires gainmap application space to match base color space");
-    return status;
-  }
-
   to->version = kJpegrVersion;
-  to->max_content_boost = exp2((float)from->gainMapMaxN[0] / from->gainMapMaxD[0]);
-  to->min_content_boost = exp2((float)from->gainMapMinN[0] / from->gainMapMinD[0]);
+  for (int i = 0; i < 3; i++) {
+    to->max_content_boost[i] = exp2((float)from->gainMapMaxN[i] / from->gainMapMaxD[i]);
+    to->min_content_boost[i] = exp2((float)from->gainMapMinN[i] / from->gainMapMinD[i]);
 
-  to->gamma = (float)from->gainMapGammaN[0] / from->gainMapGammaD[0];
+    to->gamma[i] = (float)from->gainMapGammaN[i] / from->gainMapGammaD[i];
 
-  // BaseRenditionIsHDR is false
-  to->offset_sdr = (float)from->baseOffsetN[0] / from->baseOffsetD[0];
-  to->offset_hdr = (float)from->alternateOffsetN[0] / from->alternateOffsetD[0];
+    // BaseRenditionIsHDR is false
+    to->offset_sdr[i] = (float)from->baseOffsetN[i] / from->baseOffsetD[i];
+    to->offset_hdr[i] = (float)from->alternateOffsetN[i] / from->alternateOffsetD[i];
+  }
   to->hdr_capacity_max = exp2((float)from->alternateHdrHeadroomN / from->alternateHdrHeadroomD);
   to->hdr_capacity_min = exp2((float)from->baseHdrHeadroomN / from->baseHdrHeadroomD);
+  to->use_base_cg = from->useBaseColorSpace;
 
   return g_no_error;
 }
@@ -381,7 +363,7 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(
   }
 
   to->backwardDirection = false;
-  to->useBaseColorSpace = true;
+  to->useBaseColorSpace = from->use_base_cg;
 
 #define CONVERT_FLT_TO_UNSIGNED_FRACTION(flt, numerator, denominator)                          \
   if (!floatToUnsignedFraction(flt, numerator, denominator)) {                                 \
@@ -405,28 +387,38 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(
     return status;                                                                             \
   }
 
-  CONVERT_FLT_TO_SIGNED_FRACTION(log2(from->max_content_boost), &to->gainMapMaxN[0],
-                                 &to->gainMapMaxD[0])
-  to->gainMapMaxN[2] = to->gainMapMaxN[1] = to->gainMapMaxN[0];
-  to->gainMapMaxD[2] = to->gainMapMaxD[1] = to->gainMapMaxD[0];
+  bool isSingleChannel = from->are_all_channels_identical();
+  for (int i = 0; i < (isSingleChannel ? 1 : 3); i++) {
+    CONVERT_FLT_TO_SIGNED_FRACTION(log2(from->max_content_boost[i]), &to->gainMapMaxN[i],
+                                   &to->gainMapMaxD[i])
+
+    CONVERT_FLT_TO_SIGNED_FRACTION(log2(from->min_content_boost[i]), &to->gainMapMinN[i],
+                                   &to->gainMapMinD[i]);
 
-  CONVERT_FLT_TO_SIGNED_FRACTION(log2(from->min_content_boost), &to->gainMapMinN[0],
-                                 &to->gainMapMinD[0]);
-  to->gainMapMinN[2] = to->gainMapMinN[1] = to->gainMapMinN[0];
-  to->gainMapMinD[2] = to->gainMapMinD[1] = to->gainMapMinD[0];
+    CONVERT_FLT_TO_UNSIGNED_FRACTION(from->gamma[i], &to->gainMapGammaN[i], &to->gainMapGammaD[i]);
 
-  CONVERT_FLT_TO_UNSIGNED_FRACTION(from->gamma, &to->gainMapGammaN[0], &to->gainMapGammaD[0]);
-  to->gainMapGammaN[2] = to->gainMapGammaN[1] = to->gainMapGammaN[0];
-  to->gainMapGammaD[2] = to->gainMapGammaD[1] = to->gainMapGammaD[0];
+    CONVERT_FLT_TO_SIGNED_FRACTION(from->offset_sdr[i], &to->baseOffsetN[i], &to->baseOffsetD[i]);
 
-  CONVERT_FLT_TO_SIGNED_FRACTION(from->offset_sdr, &to->baseOffsetN[0], &to->baseOffsetD[0]);
-  to->baseOffsetN[2] = to->baseOffsetN[1] = to->baseOffsetN[0];
-  to->baseOffsetD[2] = to->baseOffsetD[1] = to->baseOffsetD[0];
+    CONVERT_FLT_TO_SIGNED_FRACTION(from->offset_hdr[i], &to->alternateOffsetN[i],
+                                   &to->alternateOffsetD[i]);
+  }
 
-  CONVERT_FLT_TO_SIGNED_FRACTION(from->offset_hdr, &to->alternateOffsetN[0],
-                                 &to->alternateOffsetD[0]);
-  to->alternateOffsetN[2] = to->alternateOffsetN[1] = to->alternateOffsetN[0];
-  to->alternateOffsetD[2] = to->alternateOffsetD[1] = to->alternateOffsetD[0];
+  if (isSingleChannel) {
+    to->gainMapMaxN[2] = to->gainMapMaxN[1] = to->gainMapMaxN[0];
+    to->gainMapMaxD[2] = to->gainMapMaxD[1] = to->gainMapMaxD[0];
+
+    to->gainMapMinN[2] = to->gainMapMinN[1] = to->gainMapMinN[0];
+    to->gainMapMinD[2] = to->gainMapMinD[1] = to->gainMapMinD[0];
+
+    to->gainMapGammaN[2] = to->gainMapGammaN[1] = to->gainMapGammaN[0];
+    to->gainMapGammaD[2] = to->gainMapGammaD[1] = to->gainMapGammaD[0];
+
+    to->baseOffsetN[2] = to->baseOffsetN[1] = to->baseOffsetN[0];
+    to->baseOffsetD[2] = to->baseOffsetD[1] = to->baseOffsetD[0];
+
+    to->alternateOffsetN[2] = to->alternateOffsetN[1] = to->alternateOffsetN[0];
+    to->alternateOffsetD[2] = to->alternateOffsetD[1] = to->alternateOffsetD[0];
+  }
 
   CONVERT_FLT_TO_UNSIGNED_FRACTION(log2(from->hdr_capacity_min), &to->baseHdrHeadroomN,
                                    &to->baseHdrHeadroomD);
diff --git a/lib/src/gpu/applygainmap_gl.cpp b/lib/src/gpu/applygainmap_gl.cpp
index 100d5fd..f5eba87 100644
--- a/lib/src/gpu/applygainmap_gl.cpp
+++ b/lib/src/gpu/applygainmap_gl.cpp
@@ -132,32 +132,28 @@ static const std::string getGainMapSampleMultiChannel = R"__SHADER__(
 )__SHADER__";
 
 static const std::string applyGainMapShader = R"__SHADER__(
-  uniform float gamma;
-  uniform float logMinBoost;
-  uniform float logMaxBoost;
+  uniform float gamma[3];
+  uniform float logMinBoost[3];
+  uniform float logMaxBoost[3];
   uniform float weight;
-  uniform float offsetSdr;
-  uniform float offsetHdr;
+  uniform float offsetSdr[3];
+  uniform float offsetHdr[3];
   uniform float normalize;
 
-  float applyGainMapSample(const float channel, float gain) {
-    gain = pow(gain, 1.0f / gamma);
-    float logBoost = logMinBoost * (1.0f - gain) + logMaxBoost * gain;
+  float applyGainMapSample(const float channel, float gain, int idx) {
+    gain = pow(gain, 1.0f / gamma[idx]);
+    float logBoost = logMinBoost[idx] * (1.0f - gain) + logMaxBoost[idx] * gain;
     logBoost = exp2(logBoost * weight);
-    return ((channel + offsetSdr) * logBoost - offsetHdr) / normalize;
+    return ((channel + offsetSdr[idx]) * logBoost - offsetHdr[idx]) / normalize;
   }
 
   vec3 applyGain(const vec3 color, const vec3 gain) {
-    return vec3(applyGainMapSample(color.r, gain.r),
-            applyGainMapSample(color.g, gain.g),
-            applyGainMapSample(color.b, gain.b));
+    return vec3(applyGainMapSample(color.r, gain.r, 0),
+            applyGainMapSample(color.g, gain.g, 1),
+            applyGainMapSample(color.b, gain.b, 2));
   }
 )__SHADER__";
 
-static const std::string linearOETFShader = R"__SHADER__(
-  vec3 OETF(const vec3 linear) { return linear; }
-)__SHADER__";
-
 static const std::string hlgOETFShader = R"__SHADER__(
   float OETF(const float linear) {
     const float kHlgA = 0.17883277;
@@ -195,12 +191,60 @@ static const std::string hlgInverseOOTFShader = R"__SHADER__(
   }
 )__SHADER__";
 
-static const std::string IdentityInverseOOTFShader = R"__SHADER__(
-  vec3 InverseOOTF(const vec3 linear) { return linear; }
-)__SHADER__";
+template <typename... Args>
+std::string StringFormat(const std::string& format, Args... args) {
+  auto size = std::snprintf(nullptr, 0, format.c_str(), args...);
+  if (size < 0) return std::string();
+  std::vector<char> buffer(size + 1);  // Add 1 for terminating null byte
+  std::snprintf(buffer.data(), buffer.size(), format.c_str(), args...);
+  return std::string(buffer.data(), size);  // Exclude the terminating null byte
+}
+
+std::string getClampPixelFloatShader(uhdr_color_transfer_t output_ct) {
+  return StringFormat(
+      "  vec3 clampPixelFloat(const vec3 color) {\n"
+      "    return clamp(color, 0.0, %f);\n"
+      "  }\n",
+      output_ct == UHDR_CT_LINEAR ? kMaxPixelFloatHdrLinear : kMaxPixelFloat);
+}
+
+std::string getGamutConversionShader(uhdr_color_gamut_t src_cg, uhdr_color_gamut_t dst_cg) {
+  const float* coeffs = nullptr;
+  if (dst_cg == UHDR_CG_BT_709) {
+    if (src_cg == UHDR_CG_DISPLAY_P3) {
+      coeffs = kP3ToBt709.data();
+    } else if (src_cg == UHDR_CG_BT_2100) {
+      coeffs = kBt2100ToBt709.data();
+    }
+  } else if (dst_cg == UHDR_CG_DISPLAY_P3) {
+    if (src_cg == UHDR_CG_BT_709) {
+      coeffs = kBt709ToP3.data();
+    }
+    if (src_cg == UHDR_CG_BT_2100) {
+      coeffs = kBt2100ToP3.data();
+    }
+  } else if (dst_cg == UHDR_CG_BT_2100) {
+    if (src_cg == UHDR_CG_BT_709) {
+      coeffs = kBt709ToBt2100.data();
+    } else if (src_cg == UHDR_CG_DISPLAY_P3) {
+      coeffs = kP3ToBt2100.data();
+    }
+  }
+  return StringFormat(
+      "  vec3 gamutConversion(const vec3 color) {\n"
+      "    const mat3 transform = mat3(\n"
+      "      %f, %f, %f,\n"
+      "      %f, %f, %f,\n"
+      "      %f, %f, %f);\n"
+      "    return transform * color;\n"
+      "  }\n",
+      coeffs[0], coeffs[3], coeffs[6], coeffs[1], coeffs[4], coeffs[7], coeffs[2], coeffs[5],
+      coeffs[8]);
+}
 
 std::string getApplyGainMapFragmentShader(uhdr_img_fmt sdr_fmt, uhdr_img_fmt gm_fmt,
-                                          uhdr_color_transfer output_ct) {
+                                          uhdr_color_transfer output_ct, uhdr_color_gamut_t sdr_cg,
+                                          uhdr_color_gamut_t hdr_cg, bool use_base_cg) {
   std::string shader_code = R"__SHADER__(#version 300 es
     precision highp float;
     precision highp int;
@@ -221,27 +265,49 @@ std::string getApplyGainMapFragmentShader(uhdr_img_fmt sdr_fmt, uhdr_img_fmt gm_
   shader_code.append(gm_fmt == UHDR_IMG_FMT_8bppYCbCr400 ? getGainMapSampleSingleChannel
                                                          : getGainMapSampleMultiChannel);
   shader_code.append(applyGainMapShader);
-  if (output_ct == UHDR_CT_LINEAR) {
-    shader_code.append(IdentityInverseOOTFShader);
-    shader_code.append(linearOETFShader);
-  } else if (output_ct == UHDR_CT_HLG) {
+  if (sdr_cg != hdr_cg) shader_code.append(getGamutConversionShader(sdr_cg, hdr_cg));
+  shader_code.append(getClampPixelFloatShader(output_ct));
+  if (output_ct == UHDR_CT_HLG) {
     shader_code.append(hlgInverseOOTFShader);
     shader_code.append(hlgOETFShader);
   } else if (output_ct == UHDR_CT_PQ) {
-    shader_code.append(IdentityInverseOOTFShader);
     shader_code.append(pqOETFShader);
   }
-
   shader_code.append(R"__SHADER__(
     void main() {
       vec3 yuv_gamma_sdr = getYUVPixel();
       vec3 rgb_gamma_sdr = p3YuvToRgb(yuv_gamma_sdr);
       vec3 rgb_sdr = sRGBEOTF(rgb_gamma_sdr);
+  )__SHADER__");
+  if (sdr_cg != hdr_cg && !use_base_cg) {
+    shader_code.append(R"__SHADER__(
+      rgb_sdr = gamutConversion(rgb_sdr);
+    )__SHADER__");
+  }
+  shader_code.append(R"__SHADER__(
       vec3 gain = sampleMap(gainMapTexture);
       vec3 rgb_hdr = applyGain(rgb_sdr, gain);
+  )__SHADER__");
+  if (sdr_cg != hdr_cg && use_base_cg) {
+    shader_code.append(R"__SHADER__(
+      rgb_hdr = gamutConversion(rgb_hdr);
+    )__SHADER__");
+  }
+  shader_code.append(R"__SHADER__(
+      rgb_hdr = clampPixelFloat(rgb_hdr);
+  )__SHADER__");
+  if (output_ct == UHDR_CT_HLG) {
+    shader_code.append(R"__SHADER__(
       rgb_hdr = InverseOOTF(rgb_hdr);
-      vec3 rgb_gamma_hdr = OETF(rgb_hdr);
-      FragColor = vec4(rgb_gamma_hdr, 1.0);
+      rgb_hdr = OETF(rgb_hdr);
+    )__SHADER__");
+  } else if (output_ct == UHDR_CT_PQ) {
+    shader_code.append(R"__SHADER__(
+      rgb_hdr = OETF(rgb_hdr);
+    )__SHADER__");
+  }
+  shader_code.append(R"__SHADER__(
+      FragColor = vec4(rgb_hdr, 1.0);
     }
   )__SHADER__");
   return shader_code;
@@ -279,9 +345,10 @@ bool isBufferDataContiguous(uhdr_raw_image_t* img) {
 uhdr_error_info_t applyGainMapGLES(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
                                    uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                    uhdr_color_transfer_t output_ct, float display_boost,
-                                   uhdr_raw_image_t* dest, uhdr_opengl_ctxt_t* opengl_ctxt) {
-  GLuint shaderProgram = 0;   // shader program
-  GLuint yuvTexture = 0;      // sdr intent texture
+                                   uhdr_color_gamut_t sdr_cg, uhdr_color_gamut_t hdr_cg,
+                                   uhdr_opengl_ctxt_t* opengl_ctxt) {
+  GLuint shaderProgram = 0;  // shader program
+  GLuint yuvTexture = 0;     // sdr intent texture
   GLuint frameBuffer = 0;
 
 #define RET_IF_ERR()                                           \
@@ -294,7 +361,9 @@ uhdr_error_info_t applyGainMapGLES(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_
 
   shaderProgram = opengl_ctxt->create_shader_program(
       vertex_shader.c_str(),
-      getApplyGainMapFragmentShader(sdr_intent->fmt, gainmap_img->fmt, output_ct).c_str());
+      getApplyGainMapFragmentShader(sdr_intent->fmt, gainmap_img->fmt, output_ct, sdr_cg, hdr_cg,
+                                    gainmap_metadata->use_base_cg)
+          .c_str());
   RET_IF_ERR()
 
   yuvTexture = opengl_ctxt->create_texture(sdr_intent->fmt, sdr_intent->w, sdr_intent->h,
@@ -325,11 +394,17 @@ uhdr_error_info_t applyGainMapGLES(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_
 
   glUniform1i(pWidthLocation, sdr_intent->w);
   glUniform1i(pHeightLocation, sdr_intent->h);
-  glUniform1f(gammaLocation, gainmap_metadata->gamma);
-  glUniform1f(logMinBoostLocation, log2(gainmap_metadata->min_content_boost));
-  glUniform1f(logMaxBoostLocation, log2(gainmap_metadata->max_content_boost));
-  glUniform1f(offsetSdrLocation, gainmap_metadata->offset_sdr);
-  glUniform1f(offsetHdrLocation, gainmap_metadata->offset_hdr);
+  glUniform1fv(gammaLocation, 3, gainmap_metadata->gamma);
+  float logMinBoostValues[3] = {static_cast<float>(log2(gainmap_metadata->min_content_boost[0])),
+                                static_cast<float>(log2(gainmap_metadata->min_content_boost[1])),
+                                static_cast<float>(log2(gainmap_metadata->min_content_boost[2]))};
+  float logMaxBoostValues[3] = {static_cast<float>(log2(gainmap_metadata->max_content_boost[0])),
+                                static_cast<float>(log2(gainmap_metadata->max_content_boost[1])),
+                                static_cast<float>(log2(gainmap_metadata->max_content_boost[2]))};
+  glUniform1fv(logMinBoostLocation, 3, logMinBoostValues);
+  glUniform1fv(logMaxBoostLocation, 3, logMaxBoostValues);
+  glUniform1fv(offsetSdrLocation, 3, gainmap_metadata->offset_sdr);
+  glUniform1fv(offsetHdrLocation, 3, gainmap_metadata->offset_hdr);
   float gainmap_weight;
   if (display_boost != gainmap_metadata->hdr_capacity_max) {
     gainmap_weight =
@@ -342,8 +417,10 @@ uhdr_error_info_t applyGainMapGLES(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_
   }
   glUniform1f(weightLocation, gainmap_weight);
   float normalize = 1.0f;
-  if (output_ct == UHDR_CT_HLG) normalize = kHlgMaxNits / kSdrWhiteNits;
-  else if (output_ct == UHDR_CT_PQ) normalize = kPqMaxNits / kSdrWhiteNits;
+  if (output_ct == UHDR_CT_HLG)
+    normalize = kHlgMaxNits / kSdrWhiteNits;
+  else if (output_ct == UHDR_CT_PQ)
+    normalize = kPqMaxNits / kSdrWhiteNits;
   glUniform1f(normalizeLocation, normalize);
 
   glActiveTexture(GL_TEXTURE0);
@@ -364,8 +441,6 @@ uhdr_error_info_t applyGainMapGLES(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_
   opengl_ctxt->check_gl_errors("reading gles output");
   RET_IF_ERR()
 
-  dest->cg = sdr_intent->cg;
-
   if (frameBuffer) glDeleteFramebuffers(1, &frameBuffer);
   if (yuvTexture) glDeleteTextures(1, &yuvTexture);
   if (shaderProgram) glDeleteProgram(shaderProgram);
diff --git a/lib/src/icc.cpp b/lib/src/icc.cpp
index b4fd11c..05ef18d 100644
--- a/lib/src/icc.cpp
+++ b/lib/src/icc.cpp
@@ -273,8 +273,7 @@ float IccHelper::compute_tone_map_gain(const uhdr_color_transfer_t tf, float L)
 
 std::shared_ptr<DataStruct> IccHelper::write_cicp_tag(uint32_t color_primaries,
                                                       uint32_t transfer_characteristics) {
-  int total_length = 12;  // 4 + 4 + 1 + 1 + 1 + 1
-  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);
+  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(kCicpTagSize);
   dataStruct->write32(Endian_SwapBE32(kTAG_cicp));  // Type signature
   dataStruct->write32(0);                           // Reserved
   dataStruct->write8(color_primaries);              // Color primaries
@@ -416,7 +415,6 @@ std::shared_ptr<DataStruct> IccHelper::writeIccProfile(uhdr_color_transfer_t tf,
 
   // Compute profile description tag
   std::string desc = get_desc_string(tf, gamut);
-
   tags.emplace_back(kTAG_desc, write_text_tag(desc.c_str()));
 
   Matrix3x3 toXYZD50;
@@ -466,26 +464,32 @@ std::shared_ptr<DataStruct> IccHelper::writeIccProfile(uhdr_color_transfer_t tf,
                         write_trc_tag(kTrcTableSize, reinterpret_cast<uint8_t*>(trc_table.data())));
       tags.emplace_back(kTAG_bTRC,
                         write_trc_tag(kTrcTableSize, reinterpret_cast<uint8_t*>(trc_table.data())));
-    } else {
+    } else if (tf == UHDR_CT_SRGB) {
       tags.emplace_back(kTAG_rTRC, write_trc_tag(kSRGB_TransFun));
       tags.emplace_back(kTAG_gTRC, write_trc_tag(kSRGB_TransFun));
       tags.emplace_back(kTAG_bTRC, write_trc_tag(kSRGB_TransFun));
+    } else if (tf == UHDR_CT_LINEAR) {
+      tags.emplace_back(kTAG_rTRC, write_trc_tag(kLinear_TransFun));
+      tags.emplace_back(kTAG_gTRC, write_trc_tag(kLinear_TransFun));
+      tags.emplace_back(kTAG_bTRC, write_trc_tag(kLinear_TransFun));
     }
   }
 
-  // Compute CICP.
-  if (tf == UHDR_CT_HLG || tf == UHDR_CT_PQ) {
+  // Compute CICP - for hdr images icc profile shall contain cicp.
+  if (tf == UHDR_CT_HLG || tf == UHDR_CT_PQ || tf == UHDR_CT_LINEAR) {
     // The CICP tag is present in ICC 4.4, so update the header's version.
     header.version = Endian_SwapBE32(0x04400000);
 
-    uint32_t color_primaries = 0;
+    uint32_t color_primaries = kCICPPrimariesUnSpecified;
     if (gamut == UHDR_CG_BT_709) {
       color_primaries = kCICPPrimariesSRGB;
     } else if (gamut == UHDR_CG_DISPLAY_P3) {
       color_primaries = kCICPPrimariesP3;
+    } else if (gamut == UHDR_CG_BT_2100) {
+      color_primaries = kCICPPrimariesRec2020;
     }
 
-    uint32_t transfer_characteristics = 0;
+    uint32_t transfer_characteristics = kCICPTrfnUnSpecified;
     if (tf == UHDR_CT_SRGB) {
       transfer_characteristics = kCICPTrfnSRGB;
     } else if (tf == UHDR_CT_LINEAR) {
@@ -602,7 +606,7 @@ std::shared_ptr<DataStruct> IccHelper::writeIccProfile(uhdr_color_transfer_t tf,
 
 bool IccHelper::tagsEqualToMatrix(const Matrix3x3& matrix, const uint8_t* red_tag,
                                   const uint8_t* green_tag, const uint8_t* blue_tag) {
-  const float tolerance = 0.001;
+  const float tolerance = 0.001f;
   Fixed r_x_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(red_tag))[2]);
   Fixed r_y_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(red_tag))[3]);
   Fixed r_z_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(red_tag))[4]);
@@ -670,6 +674,7 @@ uhdr_color_gamut_t IccHelper::readIccColorGamut(void* icc_data, size_t icc_size)
   // of ICC data and therefore a tag offset of zero would never be valid.
   size_t red_primary_offset = 0, green_primary_offset = 0, blue_primary_offset = 0;
   size_t red_primary_size = 0, green_primary_size = 0, blue_primary_size = 0;
+  size_t cicp_size = 0, cicp_offset = 0;
   for (size_t tag_idx = 0; tag_idx < Endian_SwapBE32(header->tag_count); ++tag_idx) {
     if (icc_size < kICCIdentifierSize + sizeof(ICCHeader) + ((tag_idx + 1) * kTagTableEntrySize)) {
       ALOGE(
@@ -692,6 +697,27 @@ uhdr_color_gamut_t IccHelper::readIccColorGamut(void* icc_data, size_t icc_size)
     } else if (blue_primary_offset == 0 && *tag_entry_start == Endian_SwapBE32(kTAG_bXYZ)) {
       blue_primary_offset = Endian_SwapBE32(*(tag_entry_start + 1));
       blue_primary_size = Endian_SwapBE32(*(tag_entry_start + 2));
+    } else if (cicp_offset == 0 && *tag_entry_start == Endian_SwapBE32(kTAG_cicp)) {
+      cicp_offset = Endian_SwapBE32(*(tag_entry_start + 1));
+      cicp_size = Endian_SwapBE32(*(tag_entry_start + 2));
+    }
+  }
+
+  if (cicp_offset != 0 && cicp_size == kCicpTagSize &&
+      kICCIdentifierSize + cicp_offset + cicp_size <= icc_size) {
+    uint8_t* cicp = icc_bytes + cicp_offset;
+    uint8_t primaries = cicp[8];
+    uhdr_color_gamut_t gamut = UHDR_CG_UNSPECIFIED;
+    if (primaries == kCICPPrimariesSRGB) {
+      gamut = UHDR_CG_BT_709;
+    } else if (primaries == kCICPPrimariesP3) {
+      gamut = UHDR_CG_DISPLAY_P3;
+    } else if (primaries == kCICPPrimariesRec2020) {
+      gamut = UHDR_CG_BT_2100;
+    }
+    if (gamut != UHDR_CG_UNSPECIFIED) {
+      if (aligned_block) ::operator delete[](aligned_block, std::align_val_t(alignment_needs));
+      return gamut;
     }
   }
 
diff --git a/lib/src/jpegr.cpp b/lib/src/jpegr.cpp
index 1f83b34..8ce700f 100644
--- a/lib/src/jpegr.cpp
+++ b/lib/src/jpegr.cpp
@@ -49,12 +49,21 @@ namespace ultrahdr {
 uhdr_error_info_t applyGainMapGLES(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
                                    uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                    uhdr_color_transfer_t output_ct, float display_boost,
-                                   uhdr_raw_image_t* dest, uhdr_opengl_ctxt_t* opengl_ctxt);
+                                   uhdr_color_gamut_t sdr_cg, uhdr_color_gamut_t hdr_cg,
+                                   uhdr_opengl_ctxt_t* opengl_ctxt);
 #endif
 
 // Gain map metadata
+#ifdef UHDR_WRITE_XMP
 static const bool kWriteXmpMetadata = true;
+#else
+static const bool kWriteXmpMetadata = false;
+#endif
+#ifdef UHDR_WRITE_ISO
+static const bool kWriteIso21496_1Metadata = true;
+#else
 static const bool kWriteIso21496_1Metadata = false;
+#endif
 
 static const string kXmpNameSpace = "http://ns.adobe.com/xap/1.0/";
 static const string kIsoNameSpace = "urn:iso:std:iso:ts:21496:-1";
@@ -385,6 +394,22 @@ uhdr_error_info_t JpegR::encodeJPEGR(uhdr_compressed_image_t* base_img_compresse
   JpegDecoderHelper decoder;
   UHDR_ERR_CHECK(decoder.parseImage(base_img_compressed->data, base_img_compressed->data_sz));
 
+  if (!metadata->use_base_cg) {
+    JpegDecoderHelper gainmap_decoder;
+    UHDR_ERR_CHECK(
+        gainmap_decoder.parseImage(gainmap_img_compressed->data, gainmap_img_compressed->data_sz));
+    if (!(gainmap_decoder.getICCSize() > 0)) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "For gainmap application space to be alternate image space, gainmap image is "
+               "expected to contain alternate image color space in the form of ICC. The ICC marker "
+               "in gainmap jpeg is missing.");
+      return status;
+    }
+  }
+
   // Add ICC if not already present.
   if (decoder.getICCSize() > 0) {
     UHDR_ERR_CHECK(appendGainMap(base_img_compressed, gainmap_img_compressed, /* exif */ nullptr,
@@ -494,6 +519,11 @@ uhdr_error_info_t JpegR::convertYuv(uhdr_raw_image_t* image, uhdr_color_gamut_t
 
 uhdr_error_info_t JpegR::compressGainMap(uhdr_raw_image_t* gainmap_img,
                                          JpegEncoderHelper* jpeg_enc_obj) {
+  if (!kWriteXmpMetadata) {
+    std::shared_ptr<DataStruct> icc = IccHelper::writeIccProfile(gainmap_img->ct, gainmap_img->cg);
+    return jpeg_enc_obj->compressImage(gainmap_img, mMapCompressQuality, icc->getData(),
+                                       icc->getLength());
+  }
   return jpeg_enc_obj->compressImage(gainmap_img, mMapCompressQuality, nullptr, 0);
 }
 
@@ -530,16 +560,6 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     return status;
   }
 
-  /*if (mUseMultiChannelGainMap) {
-    if (!kWriteIso21496_1Metadata || kWriteXmpMetadata) {
-      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
-      status.has_detail = 1;
-      snprintf(status.detail, sizeof status.detail,
-               "Multi-channel gain map is only supported for ISO 21496-1 metadata");
-      return status;
-    }
-  }*/
-
   ColorTransformFn hdrInvOetf = getInverseOetfFn(hdr_intent->ct);
   if (hdrInvOetf == nullptr) {
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
@@ -581,15 +601,40 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     return status;
   }
 
-  ColorTransformFn hdrGamutConversionFn = getGamutConversionFn(sdr_intent->cg, hdr_intent->cg);
-  if (hdrGamutConversionFn == nullptr) {
-    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "No implementation available for gamut conversion from %d to %d", hdr_intent->cg,
-             sdr_intent->cg);
-    return status;
+  ColorTransformFn hdrGamutConversionFn;
+  ColorTransformFn sdrGamutConversionFn;
+  bool use_sdr_cg = true;
+  if (sdr_intent->cg != hdr_intent->cg) {
+    use_sdr_cg = kWriteXmpMetadata ||
+                 !(hdr_intent->cg == UHDR_CG_BT_2100 ||
+                   (hdr_intent->cg == UHDR_CG_DISPLAY_P3 && sdr_intent->cg != UHDR_CG_BT_2100));
+    if (use_sdr_cg) {
+      hdrGamutConversionFn = getGamutConversionFn(sdr_intent->cg, hdr_intent->cg);
+      if (hdrGamutConversionFn == nullptr) {
+        status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "No implementation available for gamut conversion from %d to %d", hdr_intent->cg,
+                 sdr_intent->cg);
+        return status;
+      }
+      sdrGamutConversionFn = identityConversion;
+    } else {
+      hdrGamutConversionFn = identityConversion;
+      sdrGamutConversionFn = getGamutConversionFn(hdr_intent->cg, sdr_intent->cg);
+      if (sdrGamutConversionFn == nullptr) {
+        status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "No implementation available for gamut conversion from %d to %d", sdr_intent->cg,
+                 hdr_intent->cg);
+        return status;
+      }
+    }
+  } else {
+    hdrGamutConversionFn = sdrGamutConversionFn = identityConversion;
   }
+  gainmap_metadata->use_base_cg = use_sdr_cg;
 
   ColorTransformFn sdrYuvToRgbFn = getYuvToRgbFn(sdr_intent->cg);
   if (sdrYuvToRgbFn == nullptr) {
@@ -659,29 +704,36 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     map_height = image_height / mMapDimensionScaleFactor;
   }
 
+  // NOTE: Even though gainmap image raw descriptor is being initialized with hdr intent's color
+  // aspects, one should not associate gainmap image to this color profile. gain map image gamut
+  // space can be hdr intent's or sdr intent's space (a decision made during gainmap generation).
+  // Its color transfer is dependent on the gainmap encoding gamma. The reason to initialize with
+  // hdr color aspects is compressGainMap method will use this to write hdr intent color profile in
+  // the bitstream.
   gainmap_img = std::make_unique<uhdr_raw_image_ext_t>(
       mUseMultiChannelGainMap ? UHDR_IMG_FMT_24bppRGB888 : UHDR_IMG_FMT_8bppYCbCr400,
-      UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, map_width, map_height, 64);
+      hdr_intent->cg, hdr_intent->ct, hdr_intent->range, map_width, map_height, 64);
   uhdr_raw_image_ext_t* dest = gainmap_img.get();
 
   auto generateGainMapOnePass = [this, sdr_intent, hdr_intent, gainmap_metadata, dest, map_height,
                                  hdrInvOetf, hdrLuminanceFn, hdrOotfFn, hdrGamutConversionFn,
-                                 luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn, sdr_sample_pixel_fn,
-                                 hdr_sample_pixel_fn, hdr_white_nits, use_luminance]() -> void {
-    gainmap_metadata->max_content_boost = hdr_white_nits / kSdrWhiteNits;
-    gainmap_metadata->min_content_boost = 1.0f;
-    gainmap_metadata->gamma = mGamma;
-    gainmap_metadata->offset_sdr = 0.0f;
-    gainmap_metadata->offset_hdr = 0.0f;
+                                 sdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn,
+                                 sdr_sample_pixel_fn, hdr_sample_pixel_fn, hdr_white_nits,
+                                 use_luminance]() -> void {
+    std::fill_n(gainmap_metadata->max_content_boost, 3, hdr_white_nits / kSdrWhiteNits);
+    std::fill_n(gainmap_metadata->min_content_boost, 3, 1.0f);
+    std::fill_n(gainmap_metadata->gamma, 3, mGamma);
+    std::fill_n(gainmap_metadata->offset_sdr, 3, 0.0f);
+    std::fill_n(gainmap_metadata->offset_hdr, 3, 0.0f);
     gainmap_metadata->hdr_capacity_min = 1.0f;
     if (this->mTargetDispPeakBrightness != -1.0f) {
       gainmap_metadata->hdr_capacity_max = this->mTargetDispPeakBrightness / kSdrWhiteNits;
     } else {
-      gainmap_metadata->hdr_capacity_max = gainmap_metadata->max_content_boost;
+      gainmap_metadata->hdr_capacity_max = gainmap_metadata->max_content_boost[0];
     }
 
-    float log2MinBoost = log2(gainmap_metadata->min_content_boost);
-    float log2MaxBoost = log2(gainmap_metadata->max_content_boost);
+    float log2MinBoost = log2(gainmap_metadata->min_content_boost[0]);
+    float log2MaxBoost = log2(gainmap_metadata->max_content_boost[0]);
 
     const int threads = (std::min)(GetCPUCoreCount(), 4u);
     const int jobSizeInRows = 1;
@@ -689,17 +741,14 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     JobQueue jobQueue;
     std::function<void()> generateMap =
         [this, sdr_intent, hdr_intent, gainmap_metadata, dest, hdrInvOetf, hdrLuminanceFn,
-         hdrOotfFn, hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn,
-         sdr_sample_pixel_fn, hdr_sample_pixel_fn, hdr_white_nits, log2MinBoost, log2MaxBoost,
-         use_luminance, &jobQueue]() -> void {
+         hdrOotfFn, hdrGamutConversionFn, sdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn,
+         hdrYuvToRgbFn, sdr_sample_pixel_fn, hdr_sample_pixel_fn, hdr_white_nits, log2MinBoost,
+         log2MaxBoost, use_luminance, &jobQueue]() -> void {
       unsigned int rowStart, rowEnd;
       const bool isHdrIntentRgb = isPixelFormatRgb(hdr_intent->fmt);
       const bool isSdrIntentRgb = isPixelFormatRgb(sdr_intent->fmt);
       const float hdrSampleToNitsFactor =
           hdr_intent->ct == UHDR_CT_LINEAR ? kSdrWhiteNits : hdr_white_nits;
-      ColorTransformFn clampPixel = hdr_intent->ct == UHDR_CT_LINEAR
-                                        ? static_cast<ColorTransformFn>(clampPixelFloatLinear)
-                                        : static_cast<ColorTransformFn>(clampPixelFloat);
       while (jobQueue.dequeueJob(rowStart, rowEnd)) {
         for (size_t y = rowStart; y < rowEnd; ++y) {
           for (size_t x = 0; x < dest->w; ++x) {
@@ -718,6 +767,8 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
 #else
             Color sdr_rgb = srgbInvOetf(sdr_rgb_gamma);
 #endif
+            sdr_rgb = sdrGamutConversionFn(sdr_rgb);
+            sdr_rgb = clipNegatives(sdr_rgb);
 
             Color hdr_rgb_gamma;
 
@@ -730,7 +781,7 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
             Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
             hdr_rgb = hdrOotfFn(hdr_rgb, hdrLuminanceFn);
             hdr_rgb = hdrGamutConversionFn(hdr_rgb);
-            hdr_rgb = clampPixel(hdr_rgb);
+            hdr_rgb = clipNegatives(hdr_rgb);
 
             if (mUseMultiChannelGainMap) {
               Color sdr_rgb_nits = sdr_rgb * kSdrWhiteNits;
@@ -738,13 +789,13 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
               size_t pixel_idx = (x + y * dest->stride[UHDR_PLANE_PACKED]) * 3;
 
               reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] = encodeGain(
-                  sdr_rgb_nits.r, hdr_rgb_nits.r, gainmap_metadata, log2MinBoost, log2MaxBoost);
+                  sdr_rgb_nits.r, hdr_rgb_nits.r, gainmap_metadata, log2MinBoost, log2MaxBoost, 0);
               reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx + 1] =
                   encodeGain(sdr_rgb_nits.g, hdr_rgb_nits.g, gainmap_metadata, log2MinBoost,
-                             log2MaxBoost);
+                             log2MaxBoost, 1);
               reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx + 2] =
                   encodeGain(sdr_rgb_nits.b, hdr_rgb_nits.b, gainmap_metadata, log2MinBoost,
-                             log2MaxBoost);
+                             log2MaxBoost, 2);
             } else {
               float sdr_y_nits;
               float hdr_y_nits;
@@ -758,8 +809,8 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
 
               size_t pixel_idx = x + y * dest->stride[UHDR_PLANE_Y];
 
-              reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_Y])[pixel_idx] =
-                  encodeGain(sdr_y_nits, hdr_y_nits, gainmap_metadata, log2MinBoost, log2MaxBoost);
+              reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_Y])[pixel_idx] = encodeGain(
+                  sdr_y_nits, hdr_y_nits, gainmap_metadata, log2MinBoost, log2MaxBoost, 0);
             }
           }
         }
@@ -782,10 +833,11 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
   };
 
-  auto generateGainMapTwoPass =
-      [this, sdr_intent, hdr_intent, gainmap_metadata, dest, map_width, map_height, hdrInvOetf,
-       hdrLuminanceFn, hdrOotfFn, hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn,
-       sdr_sample_pixel_fn, hdr_sample_pixel_fn, hdr_white_nits, use_luminance]() -> void {
+  auto generateGainMapTwoPass = [this, sdr_intent, hdr_intent, gainmap_metadata, dest, map_width,
+                                 map_height, hdrInvOetf, hdrLuminanceFn, hdrOotfFn,
+                                 hdrGamutConversionFn, sdrGamutConversionFn, luminanceFn,
+                                 sdrYuvToRgbFn, hdrYuvToRgbFn, sdr_sample_pixel_fn,
+                                 hdr_sample_pixel_fn, hdr_white_nits, use_luminance]() -> void {
     uhdr_memory_block_t gainmap_mem((size_t)map_width * map_height * sizeof(float) *
                                     (mUseMultiChannelGainMap ? 3 : 1));
     float* gainmap_data = reinterpret_cast<float*>(gainmap_mem.m_buffer.get());
@@ -799,17 +851,14 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     JobQueue jobQueue;
     std::function<void()> generateMap =
         [this, sdr_intent, hdr_intent, gainmap_data, map_width, hdrInvOetf, hdrLuminanceFn,
-         hdrOotfFn, hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn,
-         sdr_sample_pixel_fn, hdr_sample_pixel_fn, hdr_white_nits, use_luminance, &gainmap_min,
-         &gainmap_max, &gainmap_minmax, &jobQueue]() -> void {
+         hdrOotfFn, hdrGamutConversionFn, sdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn,
+         hdrYuvToRgbFn, sdr_sample_pixel_fn, hdr_sample_pixel_fn, hdr_white_nits, use_luminance,
+         &gainmap_min, &gainmap_max, &gainmap_minmax, &jobQueue]() -> void {
       unsigned int rowStart, rowEnd;
       const bool isHdrIntentRgb = isPixelFormatRgb(hdr_intent->fmt);
       const bool isSdrIntentRgb = isPixelFormatRgb(sdr_intent->fmt);
       const float hdrSampleToNitsFactor =
           hdr_intent->ct == UHDR_CT_LINEAR ? kSdrWhiteNits : hdr_white_nits;
-      ColorTransformFn clampPixel = hdr_intent->ct == UHDR_CT_LINEAR
-                                        ? static_cast<ColorTransformFn>(clampPixelFloatLinear)
-                                        : static_cast<ColorTransformFn>(clampPixelFloat);
       float gainmap_min_th[3] = {127.0f, 127.0f, 127.0f};
       float gainmap_max_th[3] = {-128.0f, -128.0f, -128.0f};
 
@@ -831,6 +880,8 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
 #else
             Color sdr_rgb = srgbInvOetf(sdr_rgb_gamma);
 #endif
+            sdr_rgb = sdrGamutConversionFn(sdr_rgb);
+            sdr_rgb = clipNegatives(sdr_rgb);
 
             Color hdr_rgb_gamma;
 
@@ -843,7 +894,7 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
             Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
             hdr_rgb = hdrOotfFn(hdr_rgb, hdrLuminanceFn);
             hdr_rgb = hdrGamutConversionFn(hdr_rgb);
-            hdr_rgb = clampPixel(hdr_rgb);
+            hdr_rgb = clipNegatives(hdr_rgb);
 
             if (mUseMultiChannelGainMap) {
               Color sdr_rgb_nits = sdr_rgb * kSdrWhiteNits;
@@ -901,30 +952,40 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     generateMap();
     std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
 
-    float min_content_boost_log2 = gainmap_min[0];
-    float max_content_boost_log2 = gainmap_max[0];
-    for (int index = 1; index < (mUseMultiChannelGainMap ? 3 : 1); index++) {
-      min_content_boost_log2 = (std::min)(gainmap_min[index], min_content_boost_log2);
-      max_content_boost_log2 = (std::max)(gainmap_max[index], max_content_boost_log2);
-    }
-    // -13.0 emphirically is a small enough gain factor that is capable of representing hdr
-    // black from any sdr luminance. Allowing further excursion might not offer any benefit and on
-    // the downside can cause bigger error during affine map and inverse map.
-    min_content_boost_log2 = (std::max)(-13.0f, min_content_boost_log2);
-    if (this->mMaxContentBoost != FLT_MAX) {
-      float suggestion = log2(this->mMaxContentBoost);
-      max_content_boost_log2 = (std::min)(max_content_boost_log2, suggestion);
-    }
-    if (this->mMinContentBoost != FLT_MIN) {
-      float suggestion = log2(this->mMinContentBoost);
-      min_content_boost_log2 = (std::max)(min_content_boost_log2, suggestion);
+    // xmp metadata current implementation does not support writing multichannel metadata
+    // so merge them in to one
+    if (kWriteXmpMetadata) {
+      float min_content_boost_log2 = gainmap_min[0];
+      float max_content_boost_log2 = gainmap_max[0];
+      for (int index = 1; index < (mUseMultiChannelGainMap ? 3 : 1); index++) {
+        min_content_boost_log2 = (std::min)(gainmap_min[index], min_content_boost_log2);
+        max_content_boost_log2 = (std::max)(gainmap_max[index], max_content_boost_log2);
+      }
+      std::fill_n(gainmap_min, 3, min_content_boost_log2);
+      std::fill_n(gainmap_max, 3, max_content_boost_log2);
     }
-    if (fabs(max_content_boost_log2 - min_content_boost_log2) < FLT_EPSILON) {
-      max_content_boost_log2 += 0.1;  // to avoid div by zero during affine transform
+
+    for (int index = 0; index < (mUseMultiChannelGainMap ? 3 : 1); index++) {
+      // gain coefficient range [-14.3, 15.6] is capable of representing hdr pels from sdr pels.
+      // Allowing further excursion might not offer any benefit and on the downside can cause bigger
+      // error during affine map and inverse affine map.
+      gainmap_min[index] = (std::clamp)(gainmap_min[index], -14.3f, 15.6f);
+      gainmap_max[index] = (std::clamp)(gainmap_max[index], -14.3f, 15.6f);
+      if (this->mMaxContentBoost != FLT_MAX) {
+        float suggestion = log2(this->mMaxContentBoost);
+        gainmap_max[index] = (std::min)(gainmap_max[index], suggestion);
+      }
+      if (this->mMinContentBoost != FLT_MIN) {
+        float suggestion = log2(this->mMinContentBoost);
+        gainmap_min[index] = (std::max)(gainmap_min[index], suggestion);
+      }
+      if (fabs(gainmap_max[index] - gainmap_min[index]) < FLT_EPSILON) {
+        gainmap_max[index] += 0.1f;  // to avoid div by zero during affine transform
+      }
     }
 
-    std::function<void()> encodeMap = [this, gainmap_data, map_width, dest, min_content_boost_log2,
-                                       max_content_boost_log2, &jobQueue]() -> void {
+    std::function<void()> encodeMap = [this, gainmap_data, map_width, dest, gainmap_min,
+                                       gainmap_max, &jobQueue]() -> void {
       unsigned int rowStart, rowEnd;
 
       while (jobQueue.dequeueJob(rowStart, rowEnd)) {
@@ -934,8 +995,8 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
             size_t src_pixel_idx = j * map_width * 3;
             for (size_t i = 0; i < map_width * 3; i++) {
               reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[dst_pixel_idx + i] =
-                  affineMapGain(gainmap_data[src_pixel_idx + i], min_content_boost_log2,
-                                max_content_boost_log2, this->mGamma);
+                  affineMapGain(gainmap_data[src_pixel_idx + i], gainmap_min[i % 3],
+                                gainmap_max[i % 3], this->mGamma);
             }
           }
         } else {
@@ -944,8 +1005,8 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
             size_t src_pixel_idx = j * map_width;
             for (size_t i = 0; i < map_width; i++) {
               reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_Y])[dst_pixel_idx + i] =
-                  affineMapGain(gainmap_data[src_pixel_idx + i], min_content_boost_log2,
-                                max_content_boost_log2, this->mGamma);
+                  affineMapGain(gainmap_data[src_pixel_idx + i], gainmap_min[0], gainmap_max[0],
+                                this->mGamma);
             }
           }
         }
@@ -966,11 +1027,18 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     encodeMap();
     std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
 
-    gainmap_metadata->max_content_boost = exp2(max_content_boost_log2);
-    gainmap_metadata->min_content_boost = exp2(min_content_boost_log2);
-    gainmap_metadata->gamma = this->mGamma;
-    gainmap_metadata->offset_sdr = 0.0f;
-    gainmap_metadata->offset_hdr = 0.0f;
+    if (mUseMultiChannelGainMap) {
+      for (int i = 0; i < 3; i++) {
+        gainmap_metadata->max_content_boost[i] = exp2(gainmap_max[i]);
+        gainmap_metadata->min_content_boost[i] = exp2(gainmap_min[i]);
+      }
+    } else {
+      std::fill_n(gainmap_metadata->max_content_boost, 3, exp2(gainmap_max[0]));
+      std::fill_n(gainmap_metadata->min_content_boost, 3, exp2(gainmap_min[0]));
+    }
+    std::fill_n(gainmap_metadata->gamma, 3, this->mGamma);
+    std::fill_n(gainmap_metadata->offset_sdr, 3, kSdrOffset);
+    std::fill_n(gainmap_metadata->offset_hdr, 3, kHdrOffset);
     gainmap_metadata->hdr_capacity_min = 1.0f;
     if (this->mTargetDispPeakBrightness != -1.0f) {
       gainmap_metadata->hdr_capacity_max = this->mTargetDispPeakBrightness / kSdrWhiteNits;
@@ -1038,6 +1106,25 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
                                        uhdr_mem_block_t* pExif, void* pIcc, size_t icc_size,
                                        uhdr_gainmap_metadata_ext_t* metadata,
                                        uhdr_compressed_image_t* dest) {
+  if (kWriteXmpMetadata && !metadata->use_base_cg) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(
+        status.detail, sizeof status.detail,
+        "setting gainmap application space as alternate image space in xmp mode is not supported");
+    return status;
+  }
+
+  if (kWriteXmpMetadata && !metadata->are_all_channels_identical()) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "signalling multichannel gainmap metadata in xmp mode is not supported");
+    return status;
+  }
+
   const size_t xmpNameSpaceLength = kXmpNameSpace.size() + 1;  // need to count the null terminator
   const size_t isoNameSpaceLength = kIsoNameSpace.size() + 1;  // need to count the null terminator
 
@@ -1073,12 +1160,12 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
     iso_secondary_length = 2 + isoNameSpaceLength + iso_secondary_data.size();
   }
 
-  size_t secondary_image_size = 2 /* 2 bytes length of APP1 sign */ + gainmap_compressed->data_sz;
+  size_t secondary_image_size = gainmap_compressed->data_sz;
   if (kWriteXmpMetadata) {
-    secondary_image_size += xmp_secondary_length;
+    secondary_image_size += 2 /* 2 bytes length of APP1 sign */ + xmp_secondary_length;
   }
   if (kWriteIso21496_1Metadata) {
-    secondary_image_size += iso_secondary_length;
+    secondary_image_size += 2 /* 2 bytes length of APP2 sign */ + iso_secondary_length;
   }
 
   // Check if EXIF package presents in the JPEG input.
@@ -1323,6 +1410,8 @@ uhdr_error_info_t JpegR::decodeJPEGR(uhdr_compressed_image_t* uhdr_compressed_im
     if (gainmap_img != nullptr) {
       UHDR_ERR_CHECK(copy_raw_image(&gainmap, gainmap_img));
     }
+    gainmap.cg =
+        IccHelper::readIccColorGamut(jpeg_dec_obj_gm.getICCPtr(), jpeg_dec_obj_gm.getICCSize());
   }
 
   uhdr_gainmap_metadata_ext_t uhdr_metadata;
@@ -1332,13 +1421,18 @@ uhdr_error_info_t JpegR::decodeJPEGR(uhdr_compressed_image_t* uhdr_compressed_im
                                         static_cast<uint8_t*>(jpeg_dec_obj_gm.getXMPPtr()),
                                         jpeg_dec_obj_gm.getXMPSize(), &uhdr_metadata))
     if (gainmap_metadata != nullptr) {
-      gainmap_metadata->min_content_boost = uhdr_metadata.min_content_boost;
-      gainmap_metadata->max_content_boost = uhdr_metadata.max_content_boost;
-      gainmap_metadata->gamma = uhdr_metadata.gamma;
-      gainmap_metadata->offset_sdr = uhdr_metadata.offset_sdr;
-      gainmap_metadata->offset_hdr = uhdr_metadata.offset_hdr;
+      std::copy(uhdr_metadata.min_content_boost, uhdr_metadata.min_content_boost + 3,
+                gainmap_metadata->min_content_boost);
+      std::copy(uhdr_metadata.max_content_boost, uhdr_metadata.max_content_boost + 3,
+                gainmap_metadata->max_content_boost);
+      std::copy(uhdr_metadata.gamma, uhdr_metadata.gamma + 3, gainmap_metadata->gamma);
+      std::copy(uhdr_metadata.offset_sdr, uhdr_metadata.offset_sdr + 3,
+                gainmap_metadata->offset_sdr);
+      std::copy(uhdr_metadata.offset_hdr, uhdr_metadata.offset_hdr + 3,
+                gainmap_metadata->offset_hdr);
       gainmap_metadata->hdr_capacity_min = uhdr_metadata.hdr_capacity_min;
       gainmap_metadata->hdr_capacity_max = uhdr_metadata.hdr_capacity_max;
+      gainmap_metadata->use_base_cg = uhdr_metadata.use_base_cg;
     }
   }
 
@@ -1398,6 +1492,23 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
     return status;
   }
 
+  uhdr_color_gamut_t sdr_cg =
+      sdr_intent->cg == UHDR_CG_UNSPECIFIED ? UHDR_CG_BT_709 : sdr_intent->cg;
+  uhdr_color_gamut_t hdr_cg = gainmap_img->cg == UHDR_CG_UNSPECIFIED ? sdr_cg : gainmap_img->cg;
+  dest->cg = hdr_cg;
+  ColorTransformFn hdrGamutConversionFn =
+      gainmap_metadata->use_base_cg ? getGamutConversionFn(hdr_cg, sdr_cg) : identityConversion;
+  ColorTransformFn sdrGamutConversionFn =
+      gainmap_metadata->use_base_cg ? identityConversion : getGamutConversionFn(hdr_cg, sdr_cg);
+  if (hdrGamutConversionFn == nullptr || sdrGamutConversionFn == nullptr) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for converting from gamut %d to %d", sdr_cg, hdr_cg);
+    return status;
+  }
+
 #ifdef UHDR_ENABLE_GLES
   if (mUhdrGLESCtxt != nullptr) {
     if (((sdr_intent->fmt == UHDR_IMG_FMT_12bppYCbCr420 && sdr_intent->w % 2 == 0 &&
@@ -1411,7 +1522,7 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
       float display_boost = (std::min)(max_display_boost, gainmap_metadata->hdr_capacity_max);
 
       return applyGainMapGLES(sdr_intent, gainmap_img, gainmap_metadata, output_ct, display_boost,
-                              dest, static_cast<uhdr_opengl_ctxt_t*>(mUhdrGLESCtxt));
+                              sdr_cg, hdr_cg, static_cast<uhdr_opengl_ctxt_t*>(mUhdrGLESCtxt));
     }
   }
 #endif
@@ -1422,7 +1533,7 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
     float gainmap_aspect_ratio = (float)gainmap_img->w / gainmap_img->h;
     float delta_aspect_ratio = fabs(primary_aspect_ratio - gainmap_aspect_ratio);
     // Allow 1% delta
-    const float delta_tolerance = 0.01;
+    const float delta_tolerance = 0.01f;
     if (delta_aspect_ratio / primary_aspect_ratio > delta_tolerance) {
       resized_gainmap = resize_image(gainmap_img, sdr_intent->w, sdr_intent->h);
       if (resized_gainmap == nullptr) {
@@ -1441,7 +1552,6 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
   float map_scale_factor = (float)sdr_intent->w / gainmap_img->w;
   int map_scale_factor_rnd = (std::max)(1, (int)std::roundf(map_scale_factor));
 
-  dest->cg = sdr_intent->cg;
   // Table will only be used when map scale factor is integer.
   ShepardsIDW idwTable(map_scale_factor_rnd);
   float display_boost = (std::min)(max_display_boost, gainmap_metadata->hdr_capacity_max);
@@ -1470,7 +1580,8 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
 
   JobQueue jobQueue;
   std::function<void()> applyRecMap = [sdr_intent, gainmap_img, dest, &jobQueue, &idwTable,
-                                       output_ct, &gainLUT, gainmap_metadata,
+                                       output_ct, &gainLUT, gainmap_metadata, hdrGamutConversionFn,
+                                       sdrGamutConversionFn,
 #if !USE_APPLY_GAIN_LUT
                                        gainmap_weight,
 #endif
@@ -1490,6 +1601,7 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
 #else
           Color rgb_sdr = srgbInvOetf(rgb_gamma_sdr);
 #endif
+          rgb_sdr = sdrGamutConversionFn(rgb_sdr);
           Color rgb_hdr;
           if (gainmap_img->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
             float gain;
@@ -1527,6 +1639,8 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
 
           switch (output_ct) {
             case UHDR_CT_LINEAR: {
+              rgb_hdr = hdrGamutConversionFn(rgb_hdr);
+              rgb_hdr = clampPixelFloatLinear(rgb_hdr);
               uint64_t rgba_f16 = colorToRgbaF16(rgb_hdr);
               reinterpret_cast<uint64_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] = rgba_f16;
               break;
@@ -1538,6 +1652,8 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
               ColorTransformFn hdrOetf = hlgOetf;
 #endif
               rgb_hdr = rgb_hdr * kSdrWhiteNits / kHlgMaxNits;
+              rgb_hdr = hdrGamutConversionFn(rgb_hdr);
+              rgb_hdr = clampPixelFloat(rgb_hdr);
               rgb_hdr = hlgInverseOotfApprox(rgb_hdr);
               Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
               uint32_t rgba_1010102 = colorToRgba1010102(rgb_gamma_hdr);
@@ -1552,6 +1668,8 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
               ColorTransformFn hdrOetf = pqOetf;
 #endif
               rgb_hdr = rgb_hdr * kSdrWhiteNits / kPqMaxNits;
+              rgb_hdr = hdrGamutConversionFn(rgb_hdr);
+              rgb_hdr = clampPixelFloat(rgb_hdr);
               Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
               uint32_t rgba_1010102 = colorToRgba1010102(rgb_gamma_hdr);
               reinterpret_cast<uint32_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
@@ -1697,8 +1815,8 @@ uhdr_error_info_t JpegR::parseJpegInfo(uhdr_compressed_image_t* jpeg_image, j_in
 }
 
 static float ReinhardMap(float y_hdr, float headroom) {
-  float out = 1.0 + y_hdr / (headroom * headroom);
-  out /= 1.0 + y_hdr;
+  float out = 1.0f + y_hdr / (headroom * headroom);
+  out /= 1.0f + y_hdr;
   return out * y_hdr;
 }
 
@@ -2466,15 +2584,15 @@ status_t JpegR::encodeJPEGR(jr_compressed_ptr yuv420jpg_image_ptr,
   output.ct = UHDR_CT_UNSPECIFIED;
   output.range = UHDR_CR_UNSPECIFIED;
 
-  uhdr_gainmap_metadata_ext_t meta;
-  meta.version = metadata->version;
+  uhdr_gainmap_metadata_ext_t meta(metadata->version);
   meta.hdr_capacity_max = metadata->hdrCapacityMax;
   meta.hdr_capacity_min = metadata->hdrCapacityMin;
-  meta.gamma = metadata->gamma;
-  meta.offset_sdr = metadata->offsetSdr;
-  meta.offset_hdr = metadata->offsetHdr;
-  meta.max_content_boost = metadata->maxContentBoost;
-  meta.min_content_boost = metadata->minContentBoost;
+  std::fill_n(meta.gamma, 3, metadata->gamma);
+  std::fill_n(meta.offset_sdr, 3, metadata->offsetSdr);
+  std::fill_n(meta.offset_hdr, 3, metadata->offsetHdr);
+  std::fill_n(meta.max_content_boost, 3, metadata->maxContentBoost);
+  std::fill_n(meta.min_content_boost, 3, metadata->minContentBoost);
+  meta.use_base_cg = true;
 
   auto result = encodeJPEGR(&input, &gainmap, &meta, &output);
   if (result.error_code == UHDR_CODEC_OK) {
@@ -2628,14 +2746,15 @@ status_t JpegR::decodeJPEGR(jr_compressed_ptr jpegr_image_ptr, jr_uncompressed_p
       gainmap_image_ptr->chroma_data = nullptr;
     }
     if (metadata) {
+      if (!meta.are_all_channels_identical()) return ERROR_JPEGR_METADATA_ERROR;
       metadata->version = meta.version;
       metadata->hdrCapacityMax = meta.hdr_capacity_max;
       metadata->hdrCapacityMin = meta.hdr_capacity_min;
-      metadata->gamma = meta.gamma;
-      metadata->offsetSdr = meta.offset_sdr;
-      metadata->offsetHdr = meta.offset_hdr;
-      metadata->maxContentBoost = meta.max_content_boost;
-      metadata->minContentBoost = meta.min_content_boost;
+      metadata->gamma = meta.gamma[0];
+      metadata->offsetSdr = meta.offset_sdr[0];
+      metadata->offsetHdr = meta.offset_hdr[0];
+      metadata->maxContentBoost = meta.max_content_boost[0];
+      metadata->minContentBoost = meta.min_content_boost[0];
     }
   }
 
diff --git a/lib/src/jpegrutils.cpp b/lib/src/jpegrutils.cpp
index 463a359..4a00590 100644
--- a/lib/src/jpegrutils.cpp
+++ b/lib/src/jpegrutils.cpp
@@ -532,7 +532,7 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size,
              kMapVersion.c_str());
     return status;
   }
-  if (!handler.getMaxContentBoost(&metadata->max_content_boost, &present) || !present) {
+  if (!handler.getMaxContentBoost(&metadata->max_content_boost[0], &present) || !present) {
     uhdr_error_info_t status;
     status.error_code = UHDR_CODEC_ERROR;
     status.has_detail = 1;
@@ -548,7 +548,7 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size,
              kMapHDRCapacityMax.c_str());
     return status;
   }
-  if (!handler.getMinContentBoost(&metadata->min_content_boost, &present)) {
+  if (!handler.getMinContentBoost(&metadata->min_content_boost[0], &present)) {
     if (present) {
       uhdr_error_info_t status;
       status.error_code = UHDR_CODEC_ERROR;
@@ -557,9 +557,9 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size,
                kMapGainMapMin.c_str());
       return status;
     }
-    metadata->min_content_boost = 1.0f;
+    metadata->min_content_boost[0] = 1.0f;
   }
-  if (!handler.getGamma(&metadata->gamma, &present)) {
+  if (!handler.getGamma(&metadata->gamma[0], &present)) {
     if (present) {
       uhdr_error_info_t status;
       status.error_code = UHDR_CODEC_ERROR;
@@ -568,9 +568,9 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size,
                kMapGamma.c_str());
       return status;
     }
-    metadata->gamma = 1.0f;
+    metadata->gamma[0] = 1.0f;
   }
-  if (!handler.getOffsetSdr(&metadata->offset_sdr, &present)) {
+  if (!handler.getOffsetSdr(&metadata->offset_sdr[0], &present)) {
     if (present) {
       uhdr_error_info_t status;
       status.error_code = UHDR_CODEC_ERROR;
@@ -579,9 +579,9 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size,
                kMapOffsetSdr.c_str());
       return status;
     }
-    metadata->offset_sdr = 1.0f / 64.0f;
+    metadata->offset_sdr[0] = 1.0f / 64.0f;
   }
-  if (!handler.getOffsetHdr(&metadata->offset_hdr, &present)) {
+  if (!handler.getOffsetHdr(&metadata->offset_hdr[0], &present)) {
     if (present) {
       uhdr_error_info_t status;
       status.error_code = UHDR_CODEC_ERROR;
@@ -590,7 +590,7 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size,
                kMapOffsetHdr.c_str());
       return status;
     }
-    metadata->offset_hdr = 1.0f / 64.0f;
+    metadata->offset_hdr[0] = 1.0f / 64.0f;
   }
   if (!handler.getHdrCapacityMin(&metadata->hdr_capacity_min, &present)) {
     if (present) {
@@ -623,6 +623,12 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size,
     snprintf(status.detail, sizeof status.detail, "hdr intent as base rendition is not supported");
     return status;
   }
+  metadata->use_base_cg = true;
+  std::fill_n(metadata->min_content_boost + 1, 2, metadata->min_content_boost[0]);
+  std::fill_n(metadata->max_content_boost + 1, 2, metadata->max_content_boost[0]);
+  std::fill_n(metadata->gamma + 1, 2, metadata->gamma[0]);
+  std::fill_n(metadata->offset_hdr + 1, 2, metadata->offset_hdr[0]);
+  std::fill_n(metadata->offset_sdr + 1, 2, metadata->offset_sdr[0]);
 
   return g_no_error;
 }
@@ -679,11 +685,11 @@ string generateXmpForSecondaryImage(uhdr_gainmap_metadata_ext_t& metadata) {
   writer.StartWritingElement("rdf:Description");
   writer.WriteXmlns(kGainMapPrefix, kGainMapUri);
   writer.WriteAttributeNameAndValue(kMapVersion, metadata.version);
-  writer.WriteAttributeNameAndValue(kMapGainMapMin, log2(metadata.min_content_boost));
-  writer.WriteAttributeNameAndValue(kMapGainMapMax, log2(metadata.max_content_boost));
-  writer.WriteAttributeNameAndValue(kMapGamma, metadata.gamma);
-  writer.WriteAttributeNameAndValue(kMapOffsetSdr, metadata.offset_sdr);
-  writer.WriteAttributeNameAndValue(kMapOffsetHdr, metadata.offset_hdr);
+  writer.WriteAttributeNameAndValue(kMapGainMapMin, log2(metadata.min_content_boost[0]));
+  writer.WriteAttributeNameAndValue(kMapGainMapMax, log2(metadata.max_content_boost[0]));
+  writer.WriteAttributeNameAndValue(kMapGamma, metadata.gamma[0]);
+  writer.WriteAttributeNameAndValue(kMapOffsetSdr, metadata.offset_sdr[0]);
+  writer.WriteAttributeNameAndValue(kMapOffsetHdr, metadata.offset_hdr[0]);
   writer.WriteAttributeNameAndValue(kMapHDRCapacityMin, log2(metadata.hdr_capacity_min));
   writer.WriteAttributeNameAndValue(kMapHDRCapacityMax, log2(metadata.hdr_capacity_max));
   writer.WriteAttributeNameAndValue(kMapBaseRenditionIsHDR, "False");
diff --git a/lib/src/ultrahdr_api.cpp b/lib/src/ultrahdr_api.cpp
index 95264fd..f9d1182 100644
--- a/lib/src/ultrahdr_api.cpp
+++ b/lib/src/ultrahdr_api.cpp
@@ -428,58 +428,68 @@ uhdr_error_info_t uhdr_validate_gainmap_metadata_descriptor(uhdr_gainmap_metadat
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
              "received nullptr for gainmap metadata descriptor");
-  } else if (!std::isfinite(metadata->min_content_boost) ||
-             !std::isfinite(metadata->max_content_boost) || !std::isfinite(metadata->offset_sdr) ||
-             !std::isfinite(metadata->offset_hdr) || !std::isfinite(metadata->hdr_capacity_min) ||
-             !std::isfinite(metadata->hdr_capacity_max) || !std::isfinite(metadata->gamma)) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "Field(s) of gainmap metadata descriptor are either NaN or infinite. min content "
-             "boost %f, max content boost %f, offset sdr %f, offset hdr %f, hdr capacity min %f, "
-             "hdr capacity max %f, gamma %f",
-             metadata->min_content_boost, metadata->max_content_boost, metadata->offset_sdr,
-             metadata->offset_hdr, metadata->hdr_capacity_min, metadata->hdr_capacity_max,
-             metadata->gamma);
-  } else if (metadata->max_content_boost < metadata->min_content_boost) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for content boost max %f, expects to be >= content boost min %f",
-             metadata->max_content_boost, metadata->min_content_boost);
-  } else if (metadata->min_content_boost <= 0.0f) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for min boost %f, expects > 0.0f", metadata->min_content_boost);
-    return status;
-  } else if (metadata->gamma <= 0.0f) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail, "received bad value for gamma %f, expects > 0.0f",
-             metadata->gamma);
-  } else if (metadata->offset_sdr < 0.0f) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for offset sdr %f, expects to be >= 0.0f", metadata->offset_sdr);
-  } else if (metadata->offset_hdr < 0.0f) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for offset hdr %f, expects to be >= 0.0f", metadata->offset_hdr);
-  } else if (metadata->hdr_capacity_max <= metadata->hdr_capacity_min) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for hdr capacity max %f, expects to be > hdr capacity min %f",
-             metadata->hdr_capacity_max, metadata->hdr_capacity_min);
-  } else if (metadata->hdr_capacity_min < 1.0f) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for hdr capacity min %f, expects to be >= 1.0f",
-             metadata->hdr_capacity_min);
+  } else {
+    for (int i = 0; i < 3; i++) {
+      if (!std::isfinite(metadata->min_content_boost[i]) ||
+          !std::isfinite(metadata->max_content_boost[i]) ||
+          !std::isfinite(metadata->offset_sdr[i]) || !std::isfinite(metadata->offset_hdr[i]) ||
+          !std::isfinite(metadata->hdr_capacity_min) ||
+          !std::isfinite(metadata->hdr_capacity_max) || !std::isfinite(metadata->gamma[i])) {
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        status.has_detail = 1;
+        snprintf(
+            status.detail, sizeof status.detail,
+            "Field(s) of gainmap metadata descriptor are either NaN or infinite. min content "
+            "boost %f, max content boost %f, offset sdr %f, offset hdr %f, hdr capacity min %f, "
+            "hdr capacity max %f, gamma %f",
+            metadata->min_content_boost[i], metadata->max_content_boost[i], metadata->offset_sdr[i],
+            metadata->offset_hdr[i], metadata->hdr_capacity_min, metadata->hdr_capacity_max,
+            metadata->gamma[i]);
+      } else if (metadata->max_content_boost[i] < metadata->min_content_boost[i]) {
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        status.has_detail = 1;
+        snprintf(
+            status.detail, sizeof status.detail,
+            "received bad value for content boost max %f, expects to be >= content boost min %f",
+            metadata->max_content_boost[i], metadata->min_content_boost[i]);
+      } else if (metadata->min_content_boost[i] <= 0.0f) {
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "received bad value for min boost %f, expects > 0.0f",
+                 metadata->min_content_boost[i]);
+        return status;
+      } else if (metadata->gamma[i] <= 0.0f) {
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "received bad value for gamma %f, expects > 0.0f", metadata->gamma[i]);
+      } else if (metadata->offset_sdr[i] < 0.0f) {
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "received bad value for offset sdr %f, expects to be >= 0.0f",
+                 metadata->offset_sdr[i]);
+      } else if (metadata->offset_hdr[i] < 0.0f) {
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "received bad value for offset hdr %f, expects to be >= 0.0f",
+                 metadata->offset_hdr[i]);
+      } else if (metadata->hdr_capacity_max <= metadata->hdr_capacity_min) {
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "received bad value for hdr capacity max %f, expects to be > hdr capacity min %f",
+                 metadata->hdr_capacity_max, metadata->hdr_capacity_min);
+      } else if (metadata->hdr_capacity_min < 1.0f) {
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "received bad value for hdr capacity min %f, expects to be >= 1.0f",
+                 metadata->hdr_capacity_min);
+      }
+    }
   }
   return status;
 }
@@ -1248,7 +1258,7 @@ uhdr_error_info_t uhdr_encode(uhdr_codec_private_t* enc) {
       auto& gainmap_entry = handle->m_compressed_images.find(UHDR_GAIN_MAP_IMG)->second;
 
       size_t size =
-          (std::max)(((size_t)8 * 1024), 2 * (base_entry->data_sz + gainmap_entry->data_sz));
+          (std::max)(((size_t)64 * 1024), 2 * (base_entry->data_sz + gainmap_entry->data_sz));
       handle->m_compressed_output_buffer = std::make_unique<ultrahdr::uhdr_compressed_image_ext_t>(
           UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, size);
 
@@ -1260,7 +1270,7 @@ uhdr_error_info_t uhdr_encode(uhdr_codec_private_t* enc) {
     } else if (handle->m_raw_images.find(UHDR_HDR_IMG) != handle->m_raw_images.end()) {
       auto& hdr_raw_entry = handle->m_raw_images.find(UHDR_HDR_IMG)->second;
 
-      size_t size = (std::max)((8u * 1024), hdr_raw_entry->w * hdr_raw_entry->h * 3 * 2);
+      size_t size = (std::max)((64u * 1024), hdr_raw_entry->w * hdr_raw_entry->h * 3 * 2);
       handle->m_compressed_output_buffer = std::make_unique<ultrahdr::uhdr_compressed_image_ext_t>(
           UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, size);
 
@@ -1572,13 +1582,16 @@ uhdr_error_info_t uhdr_dec_probe(uhdr_codec_private_t* dec) {
                                         gainmap_image.xmpData.data(), gainmap_image.xmpData.size(),
                                         &metadata);
     if (status.error_code != UHDR_CODEC_OK) return status;
-    handle->m_metadata.max_content_boost = metadata.max_content_boost;
-    handle->m_metadata.min_content_boost = metadata.min_content_boost;
-    handle->m_metadata.gamma = metadata.gamma;
-    handle->m_metadata.offset_sdr = metadata.offset_sdr;
-    handle->m_metadata.offset_hdr = metadata.offset_hdr;
+    std::copy(metadata.max_content_boost, metadata.max_content_boost + 3,
+              handle->m_metadata.max_content_boost);
+    std::copy(metadata.min_content_boost, metadata.min_content_boost + 3,
+              handle->m_metadata.min_content_boost);
+    std::copy(metadata.gamma, metadata.gamma + 3, handle->m_metadata.gamma);
+    std::copy(metadata.offset_sdr, metadata.offset_sdr + 3, handle->m_metadata.offset_sdr);
+    std::copy(metadata.offset_hdr, metadata.offset_hdr + 3, handle->m_metadata.offset_hdr);
     handle->m_metadata.hdr_capacity_min = metadata.hdr_capacity_min;
     handle->m_metadata.hdr_capacity_max = metadata.hdr_capacity_max;
+    handle->m_metadata.use_base_cg = metadata.use_base_cg;
 
     handle->m_img_wd = primary_image.width;
     handle->m_img_ht = primary_image.height;
diff --git a/tests/gainmapmath_test.cpp b/tests/gainmapmath_test.cpp
index 91d942a..7da1000 100644
--- a/tests/gainmapmath_test.cpp
+++ b/tests/gainmapmath_test.cpp
@@ -540,9 +540,9 @@ TEST_F(GainMapMathTest, ColorDivideFloat) {
 TEST_F(GainMapMathTest, SrgbLuminance) {
   EXPECT_FLOAT_EQ(srgbLuminance(RgbBlack()), 0.0f);
   EXPECT_FLOAT_EQ(srgbLuminance(RgbWhite()), 1.0f);
-  EXPECT_FLOAT_EQ(srgbLuminance(RgbRed()), 0.2126f);
-  EXPECT_FLOAT_EQ(srgbLuminance(RgbGreen()), 0.7152f);
-  EXPECT_FLOAT_EQ(srgbLuminance(RgbBlue()), 0.0722f);
+  EXPECT_FLOAT_EQ(srgbLuminance(RgbRed()), 0.212639f);
+  EXPECT_FLOAT_EQ(srgbLuminance(RgbGreen()), 0.715169f);
+  EXPECT_FLOAT_EQ(srgbLuminance(RgbBlue()), 0.072192f);
 }
 
 TEST_F(GainMapMathTest, SrgbYuvToRgb) {
@@ -607,9 +607,9 @@ TEST_F(GainMapMathTest, SrgbTransferFunction) {
 TEST_F(GainMapMathTest, P3Luminance) {
   EXPECT_FLOAT_EQ(p3Luminance(RgbBlack()), 0.0f);
   EXPECT_FLOAT_EQ(p3Luminance(RgbWhite()), 1.0f);
-  EXPECT_FLOAT_EQ(p3Luminance(RgbRed()), 0.20949f);
-  EXPECT_FLOAT_EQ(p3Luminance(RgbGreen()), 0.72160f);
-  EXPECT_FLOAT_EQ(p3Luminance(RgbBlue()), 0.06891f);
+  EXPECT_FLOAT_EQ(p3Luminance(RgbRed()), 0.2289746f);
+  EXPECT_FLOAT_EQ(p3Luminance(RgbGreen()), 0.6917385f);
+  EXPECT_FLOAT_EQ(p3Luminance(RgbBlue()), 0.0792869f);
 }
 
 TEST_F(GainMapMathTest, P3YuvToRgb) {
@@ -666,8 +666,8 @@ TEST_F(GainMapMathTest, Bt2100Luminance) {
   EXPECT_FLOAT_EQ(bt2100Luminance(RgbBlack()), 0.0f);
   EXPECT_FLOAT_EQ(bt2100Luminance(RgbWhite()), 1.0f);
   EXPECT_FLOAT_EQ(bt2100Luminance(RgbRed()), 0.2627f);
-  EXPECT_FLOAT_EQ(bt2100Luminance(RgbGreen()), 0.6780f);
-  EXPECT_FLOAT_EQ(bt2100Luminance(RgbBlue()), 0.0593f);
+  EXPECT_FLOAT_EQ(bt2100Luminance(RgbGreen()), 0.677998f);
+  EXPECT_FLOAT_EQ(bt2100Luminance(RgbBlue()), 0.059302f);
 }
 
 TEST_F(GainMapMathTest, Bt2100YuvToRgb) {
@@ -1127,13 +1127,16 @@ TEST_F(GainMapMathTest, srgbInvOetfLUT) {
 
 TEST_F(GainMapMathTest, applyGainLUT) {
   for (float boost = 1.5; boost <= 12; boost++) {
-    uhdr_gainmap_metadata_ext_t metadata;
-
-    metadata.min_content_boost = 1.0f / boost;
-    metadata.max_content_boost = boost;
-    metadata.gamma = 1.0f;
-    metadata.hdr_capacity_max = metadata.max_content_boost;
-    metadata.hdr_capacity_min = metadata.min_content_boost;
+    uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
+
+    std::fill_n(metadata.min_content_boost, 3, 1.0f / boost);
+    std::fill_n(metadata.max_content_boost, 3, boost);
+    std::fill_n(metadata.gamma, 3, 1.0f);
+    std::fill_n(metadata.offset_sdr, 3, 0.0f);
+    std::fill_n(metadata.offset_hdr, 3, 0.0f);
+    metadata.hdr_capacity_max = metadata.max_content_boost[0];
+    metadata.hdr_capacity_min = metadata.min_content_boost[0];
+    metadata.use_base_cg = true;
     GainLUT gainLUT(&metadata);
     float weight = (log2(boost) - log2(metadata.hdr_capacity_min)) /
                    (log2(metadata.hdr_capacity_max) - log2(metadata.hdr_capacity_min));
@@ -1165,13 +1168,16 @@ TEST_F(GainMapMathTest, applyGainLUT) {
   }
 
   for (float boost = 1.5; boost <= 12; boost++) {
-    uhdr_gainmap_metadata_ext_t metadata;
-
-    metadata.min_content_boost = 1.0f;
-    metadata.max_content_boost = boost;
-    metadata.gamma = 1.0f;
-    metadata.hdr_capacity_max = metadata.max_content_boost;
-    metadata.hdr_capacity_min = metadata.min_content_boost;
+    uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
+
+    std::fill_n(metadata.min_content_boost, 3, 1.0f / boost);
+    std::fill_n(metadata.max_content_boost, 3, boost);
+    std::fill_n(metadata.gamma, 3, 1.0f);
+    std::fill_n(metadata.offset_sdr, 3, 0.0f);
+    std::fill_n(metadata.offset_hdr, 3, 0.0f);
+    metadata.hdr_capacity_max = metadata.max_content_boost[0];
+    metadata.hdr_capacity_min = metadata.min_content_boost[0];
+    metadata.use_base_cg = true;
     GainLUT gainLUT(&metadata);
     float weight = (log2(boost) - log2(metadata.hdr_capacity_min)) /
                    (log2(metadata.hdr_capacity_max) - log2(metadata.hdr_capacity_min));
@@ -1203,13 +1209,16 @@ TEST_F(GainMapMathTest, applyGainLUT) {
   }
 
   for (float boost = 1.5; boost <= 12; boost++) {
-    uhdr_gainmap_metadata_ext_t metadata;
-
-    metadata.min_content_boost = 1.0f / powf(boost, 1.0f / 3.0f);
-    metadata.max_content_boost = boost;
-    metadata.gamma = 1.0f;
-    metadata.hdr_capacity_max = metadata.max_content_boost;
-    metadata.hdr_capacity_min = metadata.min_content_boost;
+    uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
+
+    std::fill_n(metadata.min_content_boost, 3, 1.0f / powf(boost, 1.0f / 3.0f));
+    std::fill_n(metadata.max_content_boost, 3, boost);
+    std::fill_n(metadata.gamma, 3, 1.0f);
+    std::fill_n(metadata.offset_sdr, 3, 0.0f);
+    std::fill_n(metadata.offset_hdr, 3, 0.0f);
+    metadata.hdr_capacity_max = metadata.max_content_boost[0];
+    metadata.hdr_capacity_min = metadata.min_content_boost[0];
+    metadata.use_base_cg = true;
     GainLUT gainLUT(&metadata);
     float weight = (log2(boost) - log2(metadata.hdr_capacity_min)) /
                    (log2(metadata.hdr_capacity_max) - log2(metadata.hdr_capacity_min));
@@ -1276,7 +1285,7 @@ TEST_F(GainMapMathTest, EncodeGain) {
   float max_boost = log2(4.0f);
   float gamma = 1.0f;
 
-  EXPECT_EQ(affineMapGain(computeGain(0.0f, 1.0f), min_boost, max_boost, 1.0f), 128);
+  EXPECT_EQ(affineMapGain(computeGain(0.0f, 1.0f), min_boost, max_boost, 1.0f), 255);
   EXPECT_EQ(affineMapGain(computeGain(1.0f, 0.0f), min_boost, max_boost, 1.0f), 0);
   EXPECT_EQ(affineMapGain(computeGain(0.5f, 0.0f), min_boost, max_boost, 1.0f), 0);
   EXPECT_EQ(affineMapGain(computeGain(1.0f, 1.0), min_boost, max_boost, 1.0f), 128);
@@ -1322,21 +1331,22 @@ TEST_F(GainMapMathTest, EncodeGain) {
   EXPECT_EQ(affineMapGain(computeGain(1.0f, 1.0f), min_boost, max_boost, 1.0f), 64);
   EXPECT_EQ(affineMapGain(computeGain(1.0f, 8.0f), min_boost, max_boost, 1.0f), 255);
   EXPECT_EQ(affineMapGain(computeGain(1.0f, 4.0f), min_boost, max_boost, 1.0f), 191);
-  EXPECT_EQ(affineMapGain(computeGain(1.0f, 2.0f), min_boost, max_boost, 1.0f), 128);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 2.0f), min_boost, max_boost, 1.0f), 127);
   EXPECT_EQ(affineMapGain(computeGain(1.0f, 0.7071f), min_boost, max_boost, 1.0f), 32);
   EXPECT_EQ(affineMapGain(computeGain(1.0f, 0.5f), min_boost, max_boost, 1.0f), 0);
 }
 
 TEST_F(GainMapMathTest, ApplyGain) {
-  uhdr_gainmap_metadata_ext_t metadata;
+  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
 
-  metadata.min_content_boost = 1.0f / 4.0f;
-  metadata.max_content_boost = 4.0f;
-  metadata.hdr_capacity_max = metadata.max_content_boost;
-  metadata.hdr_capacity_min = metadata.min_content_boost;
-  metadata.offset_sdr = 0.0f;
-  metadata.offset_hdr = 0.0f;
-  metadata.gamma = 1.0f;
+  std::fill_n(metadata.min_content_boost, 3, 1.0f / 4.0f);
+  std::fill_n(metadata.max_content_boost, 3, 4.0f);
+  std::fill_n(metadata.offset_sdr, 3, 0.0f);
+  std::fill_n(metadata.offset_hdr, 3, 0.0f);
+  std::fill_n(metadata.gamma, 3, 1.0f);
+  metadata.hdr_capacity_max = metadata.max_content_boost[0];
+  metadata.hdr_capacity_min = metadata.min_content_boost[0];
+  metadata.use_base_cg = true;
 
   EXPECT_RGB_NEAR(applyGain(RgbBlack(), 0.0f, &metadata), RgbBlack());
   EXPECT_RGB_NEAR(applyGain(RgbBlack(), 0.5f, &metadata), RgbBlack());
@@ -1348,10 +1358,10 @@ TEST_F(GainMapMathTest, ApplyGain) {
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.75f, &metadata), RgbWhite() * 2.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 4.0f);
 
-  metadata.max_content_boost = 2.0f;
-  metadata.min_content_boost = 1.0f / 2.0f;
-  metadata.hdr_capacity_max = metadata.max_content_boost;
-  metadata.hdr_capacity_min = metadata.min_content_boost;
+  std::fill_n(metadata.max_content_boost, 3, 2.0f);
+  std::fill_n(metadata.min_content_boost, 3, 1.0f / 2.0f);
+  metadata.hdr_capacity_max = metadata.max_content_boost[0];
+  metadata.hdr_capacity_min = metadata.min_content_boost[0];
 
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite() / 2.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.25f, &metadata), RgbWhite() / 1.41421f);
@@ -1359,10 +1369,10 @@ TEST_F(GainMapMathTest, ApplyGain) {
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.75f, &metadata), RgbWhite() * 1.41421f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 2.0f);
 
-  metadata.max_content_boost = 8.0f;
-  metadata.min_content_boost = 1.0f / 8.0f;
-  metadata.hdr_capacity_max = metadata.max_content_boost;
-  metadata.hdr_capacity_min = metadata.min_content_boost;
+  std::fill_n(metadata.max_content_boost, 3, 8.0f);
+  std::fill_n(metadata.min_content_boost, 3, 1.0f / 8.0f);
+  metadata.hdr_capacity_max = metadata.max_content_boost[0];
+  metadata.hdr_capacity_min = metadata.min_content_boost[0];
 
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite() / 8.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.25f, &metadata), RgbWhite() / 2.82843f);
@@ -1370,20 +1380,20 @@ TEST_F(GainMapMathTest, ApplyGain) {
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.75f, &metadata), RgbWhite() * 2.82843f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
 
-  metadata.max_content_boost = 8.0f;
-  metadata.min_content_boost = 1.0f;
-  metadata.hdr_capacity_max = metadata.max_content_boost;
-  metadata.hdr_capacity_min = metadata.min_content_boost;
+  std::fill_n(metadata.max_content_boost, 3, 8.0f);
+  std::fill_n(metadata.min_content_boost, 3, 1.0f);
+  metadata.hdr_capacity_max = metadata.max_content_boost[0];
+  metadata.hdr_capacity_min = metadata.min_content_boost[0];
 
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite());
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f / 3.0f, &metadata), RgbWhite() * 2.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 2.0f / 3.0f, &metadata), RgbWhite() * 4.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
 
-  metadata.max_content_boost = 8.0f;
-  metadata.min_content_boost = 0.5f;
-  metadata.hdr_capacity_max = metadata.max_content_boost;
-  metadata.hdr_capacity_min = metadata.min_content_boost;
+  std::fill_n(metadata.max_content_boost, 3, 8.0f);
+  std::fill_n(metadata.min_content_boost, 3, 0.5f);
+  metadata.hdr_capacity_max = metadata.max_content_boost[0];
+  metadata.hdr_capacity_min = metadata.min_content_boost[0];
 
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite() / 2.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.25f, &metadata), RgbWhite());
@@ -1392,10 +1402,10 @@ TEST_F(GainMapMathTest, ApplyGain) {
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
 
   Color e = {{{0.0f, 0.5f, 1.0f}}};
-  metadata.max_content_boost = 4.0f;
-  metadata.min_content_boost = 1.0f / 4.0f;
-  metadata.hdr_capacity_max = metadata.max_content_boost;
-  metadata.hdr_capacity_min = metadata.min_content_boost;
+  std::fill_n(metadata.max_content_boost, 3, 4.0f);
+  std::fill_n(metadata.min_content_boost, 3, 1.0f / 4.0f);
+  metadata.hdr_capacity_max = metadata.max_content_boost[0];
+  metadata.hdr_capacity_min = metadata.min_content_boost[0];
 
   EXPECT_RGB_NEAR(applyGain(e, 0.0f, &metadata), e / 4.0f);
   EXPECT_RGB_NEAR(applyGain(e, 0.25f, &metadata), e / 2.0f);
@@ -1623,13 +1633,13 @@ TEST_F(GainMapMathTest, GenerateMapLuminancePq) {
 }
 
 TEST_F(GainMapMathTest, ApplyMap) {
-  uhdr_gainmap_metadata_ext_t metadata;
+  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
 
-  metadata.min_content_boost = 1.0f / 8.0f;
-  metadata.max_content_boost = 8.0f;
-  metadata.offset_sdr = 0.0f;
-  metadata.offset_hdr = 0.0f;
-  metadata.gamma = 1.0f;
+  std::fill_n(metadata.min_content_boost, 3, 1.0f / 8.0f);
+  std::fill_n(metadata.max_content_boost, 3, 8.0f);
+  std::fill_n(metadata.offset_sdr, 3, 0.0f);
+  std::fill_n(metadata.offset_hdr, 3, 0.0f);
+  std::fill_n(metadata.gamma, 3, 1.0f);
 
   EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
   EXPECT_RGB_EQ(Recover(YuvBlack(), 1.0f, &metadata), RgbBlack());
@@ -1661,16 +1671,16 @@ TEST_F(GainMapMathTest, ApplyMap) {
   EXPECT_RGB_CLOSE(Recover(SrgbYuvGreen(), 0.0f, &metadata), RgbGreen() / 8.0f);
   EXPECT_RGB_CLOSE(Recover(SrgbYuvBlue(), 0.0f, &metadata), RgbBlue() / 8.0f);
 
-  metadata.max_content_boost = 8.0f;
-  metadata.min_content_boost = 1.0f;
+  metadata.max_content_boost[0] = 8.0f;
+  metadata.min_content_boost[0] = 1.0f;
 
   EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
   EXPECT_RGB_EQ(Recover(YuvWhite(), 2.0f / 3.0f, &metadata), RgbWhite() * 4.0f);
   EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f / 3.0f, &metadata), RgbWhite() * 2.0f);
   EXPECT_RGB_EQ(Recover(YuvWhite(), 0.0f, &metadata), RgbWhite());
 
-  metadata.max_content_boost = 8.0f;
-  metadata.min_content_boost = 0.5f;
+  metadata.max_content_boost[0] = 8.0f;
+  metadata.min_content_boost[0] = 0.5f;
 
   EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
   EXPECT_RGB_EQ(Recover(YuvWhite(), 0.75, &metadata), RgbWhite() * 4.0f);
diff --git a/tests/gainmapmetadata_test.cpp b/tests/gainmapmetadata_test.cpp
index 18eb68e..f80e052 100644
--- a/tests/gainmapmetadata_test.cpp
+++ b/tests/gainmapmetadata_test.cpp
@@ -43,13 +43,16 @@ const std::string kIso = "urn:iso:std:iso:ts:21496:-1";
 
 TEST_F(GainMapMetadataTest, encodeMetadataThenDecode) {
   uhdr_gainmap_metadata_ext_t expected("1.0");
-  expected.max_content_boost = 100.5f;
-  expected.min_content_boost = 1.5f;
-  expected.gamma = 1.0f;
-  expected.offset_sdr = 0.0625f;
-  expected.offset_hdr = 0.0625f;
+  for (int i = 0; i < 3; i++) {
+    expected.max_content_boost[i] = 100.5f + i;
+    expected.min_content_boost[i] = 1.5f + i * 0.1f;
+    expected.gamma[i] = 1.0f + i * 0.01f;
+    expected.offset_sdr[i] = 0.0625f + i * 0.025f;
+    expected.offset_hdr[i] = 0.0625f + i * 0.025f;
+  }
   expected.hdr_capacity_min = 1.0f;
   expected.hdr_capacity_max = 10000.0f / 203.0f;
+  expected.use_base_cg = false;
 
   uhdr_gainmap_metadata_frac metadata;
   EXPECT_EQ(
@@ -71,19 +74,25 @@ TEST_F(GainMapMetadataTest, encodeMetadataThenDecode) {
                 .error_code,
             UHDR_CODEC_OK);
 
-  EXPECT_FLOAT_EQ(expected.max_content_boost, decodedUHdrMetadata.max_content_boost);
-  EXPECT_FLOAT_EQ(expected.min_content_boost, decodedUHdrMetadata.min_content_boost);
-  EXPECT_FLOAT_EQ(expected.gamma, decodedUHdrMetadata.gamma);
-  EXPECT_FLOAT_EQ(expected.offset_sdr, decodedUHdrMetadata.offset_sdr);
-  EXPECT_FLOAT_EQ(expected.offset_hdr, decodedUHdrMetadata.offset_hdr);
+  for (int i = 0; i < 3; i++) {
+    EXPECT_FLOAT_EQ(expected.max_content_boost[i], decodedUHdrMetadata.max_content_boost[i]);
+    EXPECT_FLOAT_EQ(expected.min_content_boost[i], decodedUHdrMetadata.min_content_boost[i]);
+    EXPECT_FLOAT_EQ(expected.gamma[i], decodedUHdrMetadata.gamma[i]);
+    EXPECT_FLOAT_EQ(expected.offset_sdr[i], decodedUHdrMetadata.offset_sdr[i]);
+    EXPECT_FLOAT_EQ(expected.offset_hdr[i], decodedUHdrMetadata.offset_hdr[i]);
+  }
   EXPECT_FLOAT_EQ(expected.hdr_capacity_min, decodedUHdrMetadata.hdr_capacity_min);
   EXPECT_FLOAT_EQ(expected.hdr_capacity_max, decodedUHdrMetadata.hdr_capacity_max);
+  EXPECT_EQ(expected.use_base_cg, decodedUHdrMetadata.use_base_cg);
 
   data.clear();
-  expected.min_content_boost = 0.000578369f;
-  expected.offset_sdr = -0.0625f;
-  expected.offset_hdr = -0.0625f;
+  for (int i = 0; i < 3; i++) {
+    expected.min_content_boost[i] = 0.000578369f + i * 0.001f;
+    expected.offset_sdr[i] = -0.0625f + i * 0.001f;
+    expected.offset_hdr[i] = -0.0625f + i * 0.001f;
+  }
   expected.hdr_capacity_max = 1000.0f / 203.0f;
+  expected.use_base_cg = true;
 
   EXPECT_EQ(
       uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(&expected, &metadata).error_code,
@@ -97,13 +106,16 @@ TEST_F(GainMapMetadataTest, encodeMetadataThenDecode) {
                 .error_code,
             UHDR_CODEC_OK);
 
-  EXPECT_FLOAT_EQ(expected.max_content_boost, decodedUHdrMetadata.max_content_boost);
-  EXPECT_FLOAT_EQ(expected.min_content_boost, decodedUHdrMetadata.min_content_boost);
-  EXPECT_FLOAT_EQ(expected.gamma, decodedUHdrMetadata.gamma);
-  EXPECT_FLOAT_EQ(expected.offset_sdr, decodedUHdrMetadata.offset_sdr);
-  EXPECT_FLOAT_EQ(expected.offset_hdr, decodedUHdrMetadata.offset_hdr);
+  for (int i = 0; i < 3; i++) {
+    EXPECT_FLOAT_EQ(expected.max_content_boost[i], decodedUHdrMetadata.max_content_boost[i]);
+    EXPECT_FLOAT_EQ(expected.min_content_boost[i], decodedUHdrMetadata.min_content_boost[i]);
+    EXPECT_FLOAT_EQ(expected.gamma[i], decodedUHdrMetadata.gamma[i]);
+    EXPECT_FLOAT_EQ(expected.offset_sdr[i], decodedUHdrMetadata.offset_sdr[i]);
+    EXPECT_FLOAT_EQ(expected.offset_hdr[i], decodedUHdrMetadata.offset_hdr[i]);
+  }
   EXPECT_FLOAT_EQ(expected.hdr_capacity_min, decodedUHdrMetadata.hdr_capacity_min);
   EXPECT_FLOAT_EQ(expected.hdr_capacity_max, decodedUHdrMetadata.hdr_capacity_max);
+  EXPECT_EQ(expected.use_base_cg, decodedUHdrMetadata.use_base_cg);
 }
 
 }  // namespace ultrahdr
diff --git a/tests/jpegr_test.cpp b/tests/jpegr_test.cpp
index 82db6bf..2cf5265 100644
--- a/tests/jpegr_test.cpp
+++ b/tests/jpegr_test.cpp
@@ -1401,15 +1401,16 @@ TEST(JpegRTest, DecodeAPIWithInvalidArgs) {
 }
 
 TEST(JpegRTest, writeXmpThenRead) {
-  uhdr_gainmap_metadata_ext_t metadata_expected;
-  metadata_expected.version = "1.0";
-  metadata_expected.max_content_boost = 1.25f;
-  metadata_expected.min_content_boost = 0.75f;
-  metadata_expected.gamma = 1.0f;
-  metadata_expected.offset_sdr = 0.0f;
-  metadata_expected.offset_hdr = 0.0f;
+  uhdr_gainmap_metadata_ext_t metadata_expected("1.0");
+  std::fill_n(metadata_expected.max_content_boost, 3, 1.25f);
+  std::fill_n(metadata_expected.min_content_boost, 3, 0.75f);
+  std::fill_n(metadata_expected.gamma, 3, 1.0f);
+  std::fill_n(metadata_expected.offset_sdr, 3, 0.0f);
+  std::fill_n(metadata_expected.offset_hdr, 3, 0.0f);
   metadata_expected.hdr_capacity_min = 1.0f;
-  metadata_expected.hdr_capacity_max = metadata_expected.max_content_boost;
+  metadata_expected.hdr_capacity_max = metadata_expected.max_content_boost[0];
+  metadata_expected.use_base_cg = true;
+
   const std::string nameSpace = "http://ns.adobe.com/xap/1.0/\0";
   const size_t nameSpaceLength = nameSpace.size() + 1;  // need to count the null terminator
 
@@ -1425,13 +1426,14 @@ TEST(JpegRTest, writeXmpThenRead) {
   uhdr_gainmap_metadata_ext_t metadata_read;
   EXPECT_EQ(getMetadataFromXMP(xmpData.data(), xmpData.size(), &metadata_read).error_code,
             UHDR_CODEC_OK);
-  EXPECT_FLOAT_EQ(metadata_expected.max_content_boost, metadata_read.max_content_boost);
-  EXPECT_FLOAT_EQ(metadata_expected.min_content_boost, metadata_read.min_content_boost);
-  EXPECT_FLOAT_EQ(metadata_expected.gamma, metadata_read.gamma);
-  EXPECT_FLOAT_EQ(metadata_expected.offset_sdr, metadata_read.offset_sdr);
-  EXPECT_FLOAT_EQ(metadata_expected.offset_hdr, metadata_read.offset_hdr);
+  EXPECT_FLOAT_EQ(metadata_expected.max_content_boost[0], metadata_read.max_content_boost[0]);
+  EXPECT_FLOAT_EQ(metadata_expected.min_content_boost[0], metadata_read.min_content_boost[0]);
+  EXPECT_FLOAT_EQ(metadata_expected.gamma[0], metadata_read.gamma[0]);
+  EXPECT_FLOAT_EQ(metadata_expected.offset_sdr[0], metadata_read.offset_sdr[0]);
+  EXPECT_FLOAT_EQ(metadata_expected.offset_hdr[0], metadata_read.offset_hdr[0]);
   EXPECT_FLOAT_EQ(metadata_expected.hdr_capacity_min, metadata_read.hdr_capacity_min);
   EXPECT_FLOAT_EQ(metadata_expected.hdr_capacity_max, metadata_read.hdr_capacity_max);
+  EXPECT_TRUE(metadata_read.use_base_cg);
 }
 
 class JpegRAPIEncodeAndDecodeTest
diff --git a/ultrahdr_api.h b/ultrahdr_api.h
index 6a6edec..43b8373 100644
--- a/ultrahdr_api.h
+++ b/ultrahdr_api.h
@@ -72,11 +72,13 @@
  *                                               existing API which warrants a major version update.
  *                                               But indicated as a minor update.
  *   1.3.0           1.3.0                       Some bug fixes, introduced new API.
+ *   1.4.0           1.4.0                       quality improvements, bug fixes, added new features
+ *                                               and api update.
  */
 
 // This needs to be kept in sync with version in CMakeLists.txt
 #define UHDR_LIB_VER_MAJOR 1
-#define UHDR_LIB_VER_MINOR 3
+#define UHDR_LIB_VER_MINOR 4
 #define UHDR_LIB_VER_PATCH 0
 
 #define UHDR_LIB_VERSION \
@@ -253,21 +255,22 @@ typedef struct uhdr_mem_block {
 
 /**\brief Gain map metadata. */
 typedef struct uhdr_gainmap_metadata {
-  float max_content_boost; /**< Value to control how much brighter an image can get, when shown on
+  float max_content_boost[3]; /**< Value to control how much brighter an image can get, when shown
+                              on an HDR display, relative to the SDR rendition. This is constant for
+                              a given image. Value MUST be in linear scale. */
+  float min_content_boost[3]; /**< Value to control how much darker an image can get, when shown on
                               an HDR display, relative to the SDR rendition. This is constant for a
                               given image. Value MUST be in linear scale. */
-  float min_content_boost; /**< Value to control how much darker an image can get, when shown on
-                              an HDR display, relative to the SDR rendition. This is constant for a
-                              given image. Value MUST be in linear scale. */
-  float gamma;             /**< Encoding Gamma of the gainmap image. */
-  float offset_sdr; /**< The offset to apply to the SDR pixel values during gainmap generation and
-                       application. */
-  float offset_hdr; /**< The offset to apply to the HDR pixel values during gainmap generation and
-                       application. */
-  float hdr_capacity_min;  /**< Minimum display boost value for which the map is applied completely.
-                              Value MUST be in linear scale. */
-  float hdr_capacity_max;  /**< Maximum display boost value for which the map is applied completely.
-                              Value MUST be in linear scale. */
+  float gamma[3];             /**< Encoding Gamma of the gainmap image. */
+  float offset_sdr[3];    /**< The offset to apply to the SDR pixel values during gainmap generation
+                          and application. */
+  float offset_hdr[3];    /**< The offset to apply to the HDR pixel values during gainmap generation
+                          and application. */
+  float hdr_capacity_min; /**< Minimum display boost value for which the map is applied completely.
+                             Value MUST be in linear scale. */
+  float hdr_capacity_max; /**< Maximum display boost value for which the map is applied completely.
+                             Value MUST be in linear scale. */
+  int use_base_cg;         /**< Is gainmap application space same as base image color space */
 } uhdr_gainmap_metadata_t; /**< alias for struct uhdr_gainmap_metadata */
 
 /**\brief ultrahdr codec context opaque descriptor */
```

