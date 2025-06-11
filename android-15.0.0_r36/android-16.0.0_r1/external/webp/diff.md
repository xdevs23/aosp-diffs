```diff
diff --git a/.gitignore b/.gitignore
index 6d6f03c4..cf448223 100644
--- a/.gitignore
+++ b/.gitignore
@@ -52,5 +52,6 @@ tests/fuzzer/animdecoder_fuzzer
 tests/fuzzer/animencoder_fuzzer
 tests/fuzzer/demux_api_fuzzer
 tests/fuzzer/enc_dec_fuzzer
+tests/fuzzer/huffman_fuzzer
 tests/fuzzer/mux_demux_api_fuzzer
 tests/fuzzer/simple_api_fuzzer
diff --git a/AUTHORS b/AUTHORS
index 4cbe9766..6772bcd1 100644
--- a/AUTHORS
+++ b/AUTHORS
@@ -11,11 +11,13 @@ Contributors:
 - Christopher Degawa (ccom at randomderp dot com)
 - Clement Courbet (courbet at google dot com)
 - Djordje Pesut (djordje dot pesut at imgtec dot com)
+- Frank (1433351828 at qq dot com)
 - Frank Barchard (fbarchard at google dot com)
 - Hui Su (huisu at google dot com)
 - H. Vetinari (h dot vetinari at gmx dot com)
 - Ilya Kurdyukov (jpegqs at gmail dot com)
 - Ingvar Stepanyan (rreverser at google dot com)
+- Istvan Stefan (Istvan dot Stefan at arm dot com)
 - James Zern (jzern at google dot com)
 - Jan Engelhardt (jengelh at medozas dot de)
 - Jehan (jehan at girinstud dot io)
@@ -62,6 +64,7 @@ Contributors:
 - Vincent Rabaud (vrabaud at google dot com)
 - Vlad Tsyrklevich (vtsyrklevich at chromium dot org)
 - Wan-Teh Chang (wtc at google dot com)
+- wrv (wrv at utexas dot edu)
 - Yang Zhang (yang dot zhang at arm dot com)
 - Yannis Guyon (yguyon at google dot com)
 - Zhi An Ng (zhin at chromium dot org)
diff --git a/Android.bp b/Android.bp
index 9ecd22d6..e0389cc2 100644
--- a/Android.bp
+++ b/Android.bp
@@ -249,102 +249,3 @@ cc_library_static {
         },
     },
 }
-
-cc_defaults {
-    name: "libwebp_fuzzer_defaults",
-    host_supported: true,
-    native_coverage: true,
-
-    local_include_dirs: [
-        ".",
-        "src",
-    ],
-
-    fuzz_config: {
-        cc: fuzz_email_cc,
-        componentid: bug_component_id,
-    },
-
-    corpus: ["fuzz_seed_corpus/*"],
-}
-
-cc_fuzz {
-    name: "libwebp_advanced_api_fuzzer",
-    defaults: ["libwebp_fuzzer_defaults"],
-
-    srcs: [
-        "tests/fuzzer/advanced_api_fuzzer.c",
-    ],
-
-    static_libs: [
-        "libwebp-decode",
-    ],
-}
-
-cc_fuzz {
-    name: "libwebp_animation_api_fuzzer",
-    defaults: ["libwebp_fuzzer_defaults"],
-
-    srcs: [
-        "tests/fuzzer/animation_api_fuzzer.c",
-    ],
-
-    static_libs: [
-        "libwebp-decode",
-    ],
-}
-
-cc_fuzz {
-    name: "libwebp_animencoder_fuzzer",
-    defaults: ["libwebp_fuzzer_defaults"],
-
-    srcs: [
-        "tests/fuzzer/animencoder_fuzzer.cc",
-    ],
-
-    static_libs: [
-        "libwebp-decode",
-        "libwebp-encode",
-    ],
-}
-
-cc_fuzz {
-    name: "libwebp_enc_dec_fuzzer",
-    defaults: ["libwebp_fuzzer_defaults"],
-
-    srcs: [
-        "tests/fuzzer/enc_dec_fuzzer.cc",
-    ],
-
-    static_libs: [
-        "libwebp-decode",
-        "libwebp-encode",
-    ],
-}
-
-cc_fuzz {
-    name: "libwebp_mux_demux_api_fuzzer",
-    defaults: ["libwebp_fuzzer_defaults"],
-
-    srcs: [
-        "tests/fuzzer/mux_demux_api_fuzzer.c",
-    ],
-
-    static_libs: [
-        "libwebp-decode",
-        "libwebp-encode",
-    ],
-}
-
-cc_fuzz {
-    name: "libwebp_simple_api_fuzzer",
-    defaults: ["libwebp_fuzzer_defaults"],
-
-    srcs: [
-        "tests/fuzzer/simple_api_fuzzer.c",
-    ],
-
-    static_libs: [
-        "libwebp-decode",
-    ],
-}
diff --git a/CMakeLists.txt b/CMakeLists.txt
index b785a8e6..d7e8963f 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -45,6 +45,7 @@ option(WEBP_BUILD_LIBWEBPMUX "Build the libwebpmux library." ON)
 option(WEBP_BUILD_WEBPMUX "Build the webpmux command line tool." ON)
 option(WEBP_BUILD_EXTRAS "Build extras." ON)
 option(WEBP_BUILD_WEBP_JS "Emscripten build of webp.js." OFF)
+option(WEBP_BUILD_FUZZTEST "Build the fuzztest tests." OFF)
 option(WEBP_USE_THREAD "Enable threading support" ON)
 option(WEBP_NEAR_LOSSLESS "Enable near-lossless encoding" ON)
 option(WEBP_ENABLE_SWAP_16BIT_CSP "Enable byte swap for 16 bit colorspaces."
@@ -375,9 +376,11 @@ if(XCODE)
 endif()
 target_link_libraries(webpdecoder ${WEBP_DEP_LIBRARIES})
 target_include_directories(
-  webpdecoder PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}
-  INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
-            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
+  webpdecoder
+  PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}
+  INTERFACE
+    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR};${CMAKE_CURRENT_BINARY_DIR}>"
+    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
 set_target_properties(
   webpdecoder
   PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/src/webp/decode.h;\
@@ -479,6 +482,7 @@ if(WEBP_BUILD_ANIM_UTILS
    OR WEBP_BUILD_CWEBP
    OR WEBP_BUILD_DWEBP
    OR WEBP_BUILD_EXTRAS
+   OR WEBP_BUILD_FUZZTEST
    OR WEBP_BUILD_GIF2WEBP
    OR WEBP_BUILD_IMG2WEBP
    OR WEBP_BUILD_VWEBP
@@ -563,7 +567,8 @@ if(WEBP_BUILD_GIF2WEBP)
   add_executable(gif2webp ${GIF2WEBP_SRCS})
   target_link_libraries(gif2webp exampleutil imageioutil webp libwebpmux
                         ${WEBP_DEP_GIF_LIBRARIES})
-  target_include_directories(gif2webp PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/src)
+  target_include_directories(gif2webp PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/src
+                                              ${CMAKE_CURRENT_SOURCE_DIR})
   install(TARGETS gif2webp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
 endif()
 
@@ -771,6 +776,10 @@ if(WEBP_BUILD_ANIM_UTILS)
   target_include_directories(anim_dump PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/src)
 endif()
 
+if(WEBP_BUILD_FUZZTEST)
+  add_subdirectory(tests/fuzzer)
+endif()
+
 # Install the different headers and libraries.
 install(
   TARGETS ${INSTALLED_LIBRARIES}
diff --git a/ChangeLog b/ChangeLog
index e0d920ef..4b07e231 100644
--- a/ChangeLog
+++ b/ChangeLog
@@ -1,3 +1,141 @@
+c3d85ce4 update NEWS
+ad14e811 tests/fuzzer/*: add missing <string_view> include
+74cd026e fuzz_utils.cc: fix build error w/WEBP_REDUCE_SIZE
+a027aa93 mux_demux_api_fuzzer.cc: fix -Wshadow warning
+25e17c68 update ChangeLog (tag: v1.5.0-rc1)
+aa2684fc update NEWS
+36923846 bump version to 1.5.0
+ceea8ff6 update AUTHORS
+e4f7a9f0 img2webp: add a warning for unused options
+1b4c967f Merge "Properly check the data size against the end of the RIFF chunk" into main
+9e5ecfaf Properly check the data size against the end of the RIFF chunk
+da0d9c7d examples: exit w/failure w/no args
+fcff86c7 {gif,img}2webp: sync -m help w/cwebp
+b76c4a84 man/img2webp.1: sync -m text w/cwebp.1 & gif2webp.1
+30633519 muxread: fix reading of buffers > riff size
+4c85d860 yuv.h: update RGB<->YUV coefficients in comment
+0ab789e0 Merge changes I6dfedfd5,I2376e2dc into main
+03236450 {ios,xcframework}build.sh: fix compilation w/Xcode 16
+61e2cfda rework AddVectorEq_SSE2
+7bda3deb rework AddVector_SSE2
+2ddaaf0a Fix variable names in SharpYuvComputeConversionMatrix
+a3ba6f19 Makefile.vc: fix gif2webp link error
+f999d94f gif2webp: add -sharp_yuv/-near_lossless
+dfdcb7f9 Merge "lossless.h: fix function declaration mismatches" into main (tag: webp-rfc9649)
+78ed6839 fix overread in Intra4Preds_NEON
+d516a68e lossless.h: fix function declaration mismatches
+87406904 Merge "Improve documentation of SharpYuvConversionMatrix." into main
+fdb229ea Merge changes I07a7e36a,Ib29980f7,I2316122d,I2356e314,I32b53dd3, ... into main
+0c3cd9cc Improve documentation of SharpYuvConversionMatrix.
+169dfbf9 disable Intra4Preds_NEON
+2dd5eb98 dsp/yuv*: use WEBP_RESTRICT qualifier
+23bbafbe dsp/upsampling*: use WEBP_RESTRICT qualifier
+35915b38 dsp/rescaler*: use WEBP_RESTRICT qualifier
+a32b436b dsp/lossless*: use WEBP_RESTRICT qualifier
+04d4b4f3 dsp/filters*: use WEBP_RESTRICT qualifier
+b1cb37e6 dsp/enc*: use WEBP_RESTRICT qualifier
+201894ef dsp/dec*: use WEBP_RESTRICT qualifier
+02eac8a7 dsp/cost*: use WEBP_RESTRICT qualifier
+84b118c9 Merge "webp-container-spec: normalize notes & unknown chunk link" into main
+052cf42f webp-container-spec: normalize notes & unknown chunk link
+220ee529 Search for best predictor transform bits
+78619478 Try to reduce the sampling for the entropy image
+14f09ab7 webp-container-spec: reorder chunk size - N text
+a78c5356 Remove a useless malloc for entropy image
+bc491763 Merge "Refactor predictor finding" into main
+34f92238 man/{cwebp,img2webp}.1: rm 'if needed' from -sharp_yuv
+367ca938 Refactor predictor finding
+a582b53b webp-lossless-bitstream-spec: clarify some text
+0fd25d84 Merge "anim_encode.c: fix function ref in comment" into main
+f8882913 anim_encode.c: fix function ref in comment
+40e4ca60 specs_generation.md: update kramdown command line
+57883c78 img2webp: add -exact/-noexact per-frame options
+1c8eba97 img2webp,cosmetics: add missing '.' spacers to help
+2e81017c Convert predictor_enc.c to fixed point
+94de6c7f Merge "Fix fuzztest link errors w/-DBUILD_SHARED_LIBS=1" into main
+51d9832a Fix fuzztest link errors w/-DBUILD_SHARED_LIBS=1
+7bcb36b8 Merge "Fix static overflow warning." into main
+8e0cc14c Fix static overflow warning.
+cea68462 README.md: add security report note
+615e5874 Merge "make VP8LPredictor[01]_C() static" into main
+233e86b9 Merge changes Ie43dc5ef,I94cd8bab into main
+1a29fd2f make VP8LPredictor[01]_C() static
+dd9d3770 Do*Filter_*: remove row & num_rows parameters
+ab451a49 Do*Filter_C: remove dead 'inverse' code paths
+f9a480f7 {TrueMotion,TM16}_NEON: remove zero extension
+04834aca Merge changes I25c30a9e,I0a192fc6,I4cf89575 into main
+39a602af webp-lossless-bitstream-spec: normalize predictor transform ref
+f28c837d Merge "webp-container-spec: align anim pseudocode w/prose" into main
+74be8e22 Fix implicit conversion issues
+0c01db7c Merge "Increase the transform bits if possible." into main
+f2d6dc1e Increase the transform bits if possible.
+caa19e5b update link to issue tracker
+c9dd9bd4 webp-container-spec: align anim pseudocode w/prose
+8a7c8dc6 WASM: Enable VP8L_USE_FAST_LOAD
+f0c53cd9 WASM: don't use USE_GENERIC_TREE
+eef903d0 WASM: Enable 64-bit BITS caching
+6296cc8d iterator_enc: make VP8IteratorReset() static
+fbd93896 histogram_enc: make VP8LGetHistogramSize static
+cc7ff545 cost_enc: make VP8CalculateLevelCosts[] static
+4e2828ba vp8l_dec: make VP8LClear() static
+d742b24a Intra16Preds_NEON: fix truemotion saturation
+c7bb4cb5 Intra4Preds_NEON: fix truemotion saturation
+952a989b Merge "Remove TODO now that log is using fixed point." into main
+dde11574 Remove TODO now that log is using fixed point.
+a1ca153d Fix hidden myerr in my_error_exit
+3bd94202 Merge changes Iff6e47ed,I24c67cd5,Id781e761 into main
+d27d246e Merge "Convert VP8LFastSLog2 to fixed point" into main
+4838611f Disable msg_code use in fuzzing mode
+314a142a Use QuantizeBlock_NEON for VP8EncQuantizeBlockWHT on Arm
+3bfb05e3 Add AArch64 Neon implementation of Intra16Preds
+baa93808 Add AArch64 Neon implementation of Intra4Preds
+41a5e582 Fix errors when compiling code as C++
+fb444b69 Convert VP8LFastSLog2 to fixed point
+c1c89f51 Fix WEBP_NODISCARD comment and C++ version
+66408c2c Switch the histogram_enc.h API to fixed point
+ac1e410d Remove leftover tiff dep
+b78d3957 Disable TIFF on fuzztest.
+cff21a7d Do not build statically on oss-fuzz.
+6853a8e5 Merge "Move more internal fuzzers to public." into main
+9bc09db4 Merge "Convert VP8LFastLog2 to fixed point" into main
+0a9f1c19 Convert VP8LFastLog2 to fixed point
+db0cb9c2 Move more internal fuzzers to public.
+ff2b5b15 Merge "advanced_api_fuzzer.cc: use crop dims in OOM check" into main
+c4af79d0 Put 0 at the end of a palette and do not store it.
+0ec80aef Delete last references to delta palettization
+96d79f84 advanced_api_fuzzer.cc: use crop dims in OOM check
+c35c7e02 Fix huffman fuzzer to not leak.
+f2fe8dec Bump fuzztest dependency.
+9ce982fd Fix fuzz tests to work on oss-fuzz
+3ba8af1a Do not escape quotes anymore in build.sh
+ea0e121b Allow centipede to be used as a fuzzing engine.
+27731afd make VP8I4ModeOffsets & VP8MakeIntra4Preds static
+ddd6245e oss-fuzz/build.sh: use heredoc for script creation
+50074930 oss-fuzz/build.sh,cosmetics: fix indent
+20e92f7d Limit the possible fuzz engines.
+4f200de5 Switch public fuzz tests to fuzztest.
+64186bb3 Add huffman_fuzzer to .gitignore
+0905f61c Move build script from oss-fuzz repo to here.
+e8678758 Fix link to Javascript documentation
+5e5b8f0c Fix SSE2 Transform_AC3 function name
+45129ee0 Revert "Check all the rows."
+ee26766a Check all the rows.
+7ec51c59 Increase the transform bits if possible.
+3cd16fd3 Revert "Increase the transform bits if possible."
+971a03d8 Increase the transform bits if possible.
+1bf198a2 Allow transform_bits to be different during encoding.
+1e462ca8 Define MAX_TRANSFORM_BITS according to the specification.
+64d1ec23 Use (MIN/NUM)_(TRANSFORM/HUFFMAN)_BITS where appropriate
+a90160e1 Refactor histograms in predictors.
+a7aa7525 Fix some function declarations
+68ff4e1e Merge "jpegdec: add a hint for EOF/READ errors" into main
+79e7968a jpegdec: add a hint for EOF/READ errors
+d33455cd man/*: s/BUGS/REPORTING BUGS/
+a67ff735 normalize example exit status
+edc28909 upsampling_{neon,sse41}: fix int sanitizer warning
+3cada4ce ImgIoUtilReadFile: check ftell() return
+dc950585 Merge tag 'v1.4.0'
+845d5476 update ChangeLog (tag: v1.4.0, origin/1.4.0)
 8a6a55bb update NEWS
 cf7c5a5d provide a way to opt-out/override WEBP_NODISCARD
 cc34288a update ChangeLog (tag: v1.4.0-rc1)
diff --git a/METADATA b/METADATA
index 05991759..bdde04bf 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/webp
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "webp"
 description: "Android fork of the libwebp library."
@@ -8,12 +8,12 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 4
-    day: 16
+    month: 12
+    day: 20
   }
   identifier {
     type: "Git"
     value: "https://chromium.googlesource.com/webm/libwebp"
-    version: "v1.4.0"
+    version: "v1.5.0"
   }
 }
diff --git a/Makefile.vc b/Makefile.vc
index 84e9a5dd..c2cdcc0d 100644
--- a/Makefile.vc
+++ b/Makefile.vc
@@ -393,7 +393,7 @@ $(DIRBIN)\dwebp.exe: $(IMAGEIO_UTIL_OBJS)
 $(DIRBIN)\dwebp.exe: $(LIBWEBPDEMUX)
 $(DIRBIN)\gif2webp.exe: $(DIROBJ)\examples\gif2webp.obj $(EX_GIF_DEC_OBJS)
 $(DIRBIN)\gif2webp.exe: $(EX_UTIL_OBJS) $(IMAGEIO_UTIL_OBJS) $(LIBWEBPMUX)
-$(DIRBIN)\gif2webp.exe: $(LIBWEBP)
+$(DIRBIN)\gif2webp.exe: $(LIBWEBP) $(LIBSHARPYUV)
 $(DIRBIN)\vwebp.exe: $(DIROBJ)\examples\vwebp.obj $(EX_UTIL_OBJS)
 $(DIRBIN)\vwebp.exe: $(IMAGEIO_UTIL_OBJS) $(LIBWEBPDEMUX) $(LIBWEBP)
 $(DIRBIN)\vwebp_sdl.exe: $(DIROBJ)\extras\vwebp_sdl.obj
diff --git a/NEWS b/NEWS
index 8e40d8ea..7ad3df03 100644
--- a/NEWS
+++ b/NEWS
@@ -1,3 +1,25 @@
+- 12/19/2024 version 1.5.0
+  This is a binary compatible release.
+  API changes:
+    - `cross_color_transform_bits` added to WebPAuxStats
+  * minor lossless encoder speed and compression improvements
+  * lossless encoding does not use floats anymore
+  * additional Arm optimizations for lossy & lossless + general code generation
+    improvements
+  * improvements to WASM performance (#643)
+  * improvements and corrections in webp-container-spec.txt and
+    webp-lossless-bitstream-spec.txt (#646, #355607636)
+  * further security related hardening and increased fuzzing coverage w/fuzztest
+    (oss-fuzz: #382816119, #70112, #70102, #69873, #69825, #69508, #69208)
+  * miscellaneous warning, bug & build fixes (#499, #562, #381372617,
+    #381109771, #42340561, #375011696, #372109644, chromium: #334120888)
+  Tool updates:
+    * gif2webp: add -sharp_yuv & -near_lossless
+    * img2webp: add -exact & -noexact
+    * exit codes normalized; running an example program with no
+      arguments will output its help and exit with an error (#42340557,
+      #381372617)
+
 - 4/12/2024: version 1.4.0
   This is a binary compatible release.
   * API changes:
diff --git a/OWNERS b/OWNERS
index be4e3c0a..bf9c8f0d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -5,3 +5,4 @@ djsollen@google.com
 pascal.massimino@gmail.com
 # skal@google.com
 # libwebp-{en,de}code is used by external/{skia,skqp}
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.android b/README.android
index 1945b89e..1a604f54 100644
--- a/README.android
+++ b/README.android
@@ -1,5 +1,5 @@
 URL: https://chromium.googlesource.com/webm/libwebp
-Version: v1.4.0
+Version: v1.5.0
 License: Google BSD like
 
 Local modifications:
diff --git a/README.md b/README.md
index ffffa538..8ae1ab79 100644
--- a/README.md
+++ b/README.md
@@ -7,7 +7,7 @@
       \__\__/\____/\_____/__/ ____  ___
             / _/ /    \    \ /  _ \/ _/
            /  \_/   / /   \ \   __/  \__
-           \____/____/\_____/_____/____/v1.4.0
+           \____/____/\_____/_____/____/v1.5.0
 ```
 
 WebP codec is a library to encode and decode images in WebP format. This package
@@ -42,7 +42,8 @@ See the [APIs documentation](doc/api.md), and API usage examples in the
 
 ## Bugs
 
-Please report all bugs to the issue tracker: https://bugs.chromium.org/p/webp
+Please report all bugs to the [issue tracker](https://issues.webmproject.org).
+For security reports, select 'Security report' from the Template dropdown.
 
 Patches welcome! See [how to contribute](CONTRIBUTING.md).
 
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 00000000..16f26b59
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,30 @@
+{
+  "presubmit": [
+    {
+      "name": "CtsGraphicsTestCases",
+      "options": [
+        {
+          "include-filter": "android.graphics.cts.AImageDecoderTest"
+        },
+        {
+          "include-filter": "android.graphics.cts.Bitmap_CompressFormatTest"
+        },
+        {
+          "include-filter": "android.graphics.cts.BitmapFactoryTest"
+        },
+        {
+          "include-filter": "android.graphics.cts.BitmapRegionDecoderTest"
+        },
+        {
+          "include-filter": "android.graphics.cts.BitmapTest"
+        },
+        {
+          "include-filter": "android.graphics.cts.ImageDecoderTest"
+        },
+        {
+          "include-filter": "android.graphics.drawable.cts.AnimatedImageDrawableTest"
+        }
+      ]
+    }
+  ]
+}
diff --git a/configure.ac b/configure.ac
index af7ac0ea..1617614f 100644
--- a/configure.ac
+++ b/configure.ac
@@ -1,5 +1,5 @@
-AC_INIT([libwebp], [1.4.0],
-        [https://bugs.chromium.org/p/webp],,
+AC_INIT([libwebp], [1.5.0],
+        [https://issues.webmproject.org],,
         [https://developers.google.com/speed/webp])
 AC_CANONICAL_HOST
 AC_PREREQ([2.60])
diff --git a/doc/building.md b/doc/building.md
index d870e34e..17df670f 100644
--- a/doc/building.md
+++ b/doc/building.md
@@ -228,4 +228,4 @@ generated code, but is untested.
 ## Javascript decoder
 
 Libwebp can be compiled into a JavaScript decoder using Emscripten and CMake.
-See the [corresponding documentation](../README.md)
+See the [corresponding documentation](../webp_js/README.md)
diff --git a/doc/specs_generation.md b/doc/specs_generation.md
index 0380d664..f9722698 100644
--- a/doc/specs_generation.md
+++ b/doc/specs_generation.md
@@ -17,10 +17,11 @@ rubygems will install automatically. The following will apply inline CSS
 styling; an external stylesheet is not needed.
 
 ```shell
-$ kramdown doc/webp-lossless-bitstream-spec.txt --template \
-  doc/template.html --coderay-css style --coderay-line-numbers ' ' \
-  --coderay-default-lang c > \
-  doc/output/webp-lossless-bitstream-spec.html
+$ kramdown doc/webp-lossless-bitstream-spec.txt \
+  --template doc/template.html \
+  -x syntax-coderay --syntax-highlighter coderay \
+  --syntax-highlighter-opts "{default_lang: c, line_numbers: , css: style}" \
+  > doc/output/webp-lossless-bitstream-spec.html
 ```
 
 Optimally, use kramdown 0.13.7 or newer if syntax highlighting desired.
diff --git a/doc/tools.md b/doc/tools.md
index bf492746..78506b9d 100644
--- a/doc/tools.md
+++ b/doc/tools.md
@@ -321,10 +321,13 @@ Per-frame options (only used for subsequent images input):
 
 ```
 -d <int> ............. frame duration in ms (default: 100)
--lossless  ........... use lossless mode (default)
--lossy ... ........... use lossy mode
+-lossless ............ use lossless mode (default)
+-lossy ............... use lossy mode
 -q <float> ........... quality
--m <int> ............. method to use
+-m <int> ............. compression method (0=fast, 6=slowest), default=4
+-exact, -noexact ..... preserve or alter RGB values in transparent area
+                       (default: -noexact, may cause artifacts
+                                 with lossy animations)
 ```
 
 example: `img2webp -loop 2 in0.png -lossy in1.jpg -d 80 in2.tiff -o out.webp`
@@ -351,8 +354,12 @@ Options:
 -lossy ................. encode image using lossy compression
 -mixed ................. for each frame in the image, pick lossy
                          or lossless compression heuristically
+-near_lossless <int> ... use near-lossless image preprocessing
+                         (0..100=off), default=100
+-sharp_yuv ............. use sharper (and slower) RGB->YUV conversion
+                         (lossy only)
 -q <float> ............. quality factor (0:small..100:big)
--m <int> ............... compression method (0=fast, 6=slowest)
+-m <int> ............... compression method (0=fast, 6=slowest), default=4
 -min_size .............. minimize output size (default:off)
                          lossless compression by default; can be
                          combined with -q, -m, -lossy or -mixed
diff --git a/doc/webp-container-spec.txt b/doc/webp-container-spec.txt
index c64bfd40..da951b7d 100644
--- a/doc/webp-container-spec.txt
+++ b/doc/webp-container-spec.txt
@@ -131,7 +131,7 @@ Chunk Payload: _Chunk Size_ bytes
 : The data payload. If _Chunk Size_ is odd, a single padding byte -- which MUST
   be `0` to conform with RIFF -- is added.
 
-**Note:** RIFF has a convention that all-uppercase chunk FourCCs are standard
+**Note**: RIFF has a convention that all-uppercase chunk FourCCs are standard
 chunks that apply to any RIFF file format, while FourCCs specific to a file
 format are all lowercase. WebP does not follow this convention.
 
@@ -220,7 +220,7 @@ use another conversion method, but visual results may differ among decoders.
 Simple File Format (Lossless)
 -----------------------------
 
-**Note:** Older readers may not support files using the lossless format.
+**Note**: Older readers may not support files using the lossless format.
 
 This layout SHOULD be used if the image requires _lossless_ encoding (with an
 optional transparency channel) and does not require advanced features provided
@@ -262,7 +262,7 @@ and height of the canvas.
 Extended File Format
 --------------------
 
-**Note:** Older readers may not support files using the extended format.
+**Note**: Older readers may not support files using the extended format.
 
 An extended format file consists of:
 
@@ -290,12 +290,12 @@ up of:
 For an _animated image_, the _image data_ consists of multiple frames. More
 details about frames can be found in the [Animation](#animation) section.
 
-All chunks necessary for reconstruction and color correction, that is 'VP8X',
-'ICCP', 'ANIM', 'ANMF', 'ALPH', 'VP8 ' and 'VP8L', MUST appear in the order
+All chunks necessary for reconstruction and color correction, that is, 'VP8X',
+'ICCP', 'ANIM', 'ANMF', 'ALPH', 'VP8 ', and 'VP8L', MUST appear in the order
 described earlier. Readers SHOULD fail when chunks necessary for reconstruction
 and color correction are out of order.
 
-[Metadata](#metadata) and [unknown](#unknown-chunks) chunks MAY appear out of
+[Metadata](#metadata) and [unknown chunks](#unknown-chunks) MAY appear out of
 order.
 
 **Rationale:** The chunks necessary for reconstruction should appear first in
@@ -401,7 +401,7 @@ Background Color: 32 bits (_uint32_)
   around the frames, as well as the transparent pixels of the first frame.
   The background color is also used when the Disposal method is `1`.
 
-**Note**:
+**Notes**:
 
   * The background color MAY contain a non-opaque alpha value, even if the
     _Alpha_ flag in the ['VP8X' Chunk](#extended_header) is unset.
@@ -525,7 +525,7 @@ Disposal method (D): 1 bit
     not present, standard RGB (sRGB) is to be assumed. (Note that sRGB also
     needs to be linearized due to a gamma of ~2.2.)
 
-Frame Data: _Chunk Size_ - `16` bytes
+Frame Data: _Chunk Size_ bytes - `16`
 
 : Consists of:
 
@@ -616,7 +616,7 @@ Compression method (C): 2 bits
     * `0`: No compression.
     * `1`: Compressed using the WebP lossless format.
 
-Alpha bitstream: _Chunk Size_ - `1` bytes
+Alpha bitstream: _Chunk Size_ bytes - `1`
 
 : Encoded alpha bitstream.
 
@@ -781,7 +781,8 @@ _VP8X.field_ means the field in the 'VP8X' Chunk with the same description.
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 VP8X.flags.hasAnimation MUST be TRUE
 canvas ← new image of size VP8X.canvasWidth x VP8X.canvasHeight with
-         background color ANIM.background_color.
+         background color ANIM.background_color or
+         application-defined color.
 loop_count ← ANIM.loopCount
 dispose_method ← Dispose to background color
 if loop_count == 0:
@@ -809,6 +810,7 @@ for loop = 0..loop_count - 1
         bitstream subchunks not found in 'Frame Data' earlier MUST
           be TRUE
         frame_params.bitstream = bitstream_data
+    apply dispose_method.
     render frame with frame_params.alpha and frame_params.bitstream
       on canvas with top-left corner at (frame_params.frameX,
       frame_params.frameY), using Blending method
diff --git a/doc/webp-lossless-bitstream-spec.txt b/doc/webp-lossless-bitstream-spec.txt
index f4db09a7..d4836d1c 100644
--- a/doc/webp-lossless-bitstream-spec.txt
+++ b/doc/webp-lossless-bitstream-spec.txt
@@ -351,7 +351,7 @@ int ClampAddSubtractHalf(int a, int b) {
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 There are special handling rules for some border pixels. If there is a
-prediction transform, regardless of the mode \[0..13\] for these pixels, the
+predictor transform, regardless of the mode \[0..13\] for these pixels, the
 predicted value for the left-topmost pixel of the image is 0xff000000, all
 pixels on the top row are L-pixel, and all pixels on the leftmost column are
 T-pixel.
@@ -436,8 +436,8 @@ should be interpreted as an 8-bit two's complement number (that is: uint8 range
 
 The multiplication is to be done using more precision (with at least 16-bit
 precision). The sign extension property of the shift operation does not matter
-here; only the lowest 8 bits are used from the result, and there the sign
-extension shifting and unsigned shifting are consistent with each other.
+here; only the lowest 8 bits are used from the result, and in these bits, the
+sign extension shifting and unsigned shifting are consistent with each other.
 
 Now, we describe the contents of color transform data so that decoding can apply
 the inverse color transform and recover the original red and blue values. The
@@ -613,8 +613,8 @@ We use image data in five different roles:
   1. Color transform image: Created by `ColorTransformElement` values
      (defined in ["Color Transform"](#color-transform)) for different blocks of
      the image.
-  1. Color indexing image: An array of size `color_table_size` (up to 256 ARGB
-     values) storing the metadata for the color indexing transform (see
+  1. Color indexing image: An array of the size of `color_table_size` (up to
+     256 ARGB values) that stores metadata for the color indexing transform (see
      ["Color Indexing Transform"](#color-indexing-transform)).
 
 ### 5.2 Encoding of Image Data
diff --git a/examples/Makefile.am b/examples/Makefile.am
index bbf0bac9..b8c669c6 100644
--- a/examples/Makefile.am
+++ b/examples/Makefile.am
@@ -67,7 +67,7 @@ dwebp_LDADD += ../src/libwebp.la
 dwebp_LDADD +=$(PNG_LIBS) $(JPEG_LIBS)
 
 gif2webp_SOURCES = gif2webp.c gifdec.c gifdec.h
-gif2webp_CPPFLAGS = $(AM_CPPFLAGS) $(GIF_INCLUDES)
+gif2webp_CPPFLAGS = $(AM_CPPFLAGS) $(GIF_INCLUDES) -I$(top_srcdir)
 gif2webp_LDADD  =
 gif2webp_LDADD += libexample_util.la
 gif2webp_LDADD += ../imageio/libimageio_util.la
diff --git a/examples/anim_diff.c b/examples/anim_diff.c
index 7ffabc8f..0bfaa7c1 100644
--- a/examples/anim_diff.c
+++ b/examples/anim_diff.c
@@ -16,7 +16,7 @@
 #include <assert.h>
 #include <limits.h>
 #include <stdio.h>
-#include <stdlib.h>  // for 'strtod'.
+#include <stdlib.h>
 #include <string.h>  // for 'strcmp'.
 
 #include "./anim_util.h"
@@ -206,8 +206,9 @@ static void Help(void) {
   printf("  -version ............ print version number and exit\n");
 }
 
+// Returns 0 on success, 1 if animation files differ, and 2 for any error.
 int main(int argc, const char* argv[]) {
-  int return_code = -1;
+  int return_code = 2;
   int dump_frames = 0;
   const char* dump_folder = NULL;
   double min_psnr = 0.;
@@ -269,18 +270,18 @@ int main(int argc, const char* argv[]) {
     }
     if (parse_error) {
       Help();
-      FREE_WARGV_AND_RETURN(-1);
+      FREE_WARGV_AND_RETURN(return_code);
     }
   }
   if (argc < 3) {
     Help();
-    FREE_WARGV_AND_RETURN(-1);
+    FREE_WARGV_AND_RETURN(return_code);
   }
 
 
   if (!got_input2) {
     Help();
-    FREE_WARGV_AND_RETURN(-1);
+    FREE_WARGV_AND_RETURN(return_code);
   }
 
   if (dump_frames) {
@@ -293,7 +294,7 @@ int main(int argc, const char* argv[]) {
     if (!ReadAnimatedImage(files[i], &images[i], dump_frames, dump_folder)) {
       WFPRINTF(stderr, "Error decoding file: %s\n Aborting.\n",
                (const W_CHAR*)files[i]);
-      return_code = -2;
+      return_code = 2;
       goto End;
     } else {
       MinimizeAnimationFrames(&images[i], max_diff);
@@ -304,7 +305,7 @@ int main(int argc, const char* argv[]) {
                                 premultiply, min_psnr)) {
     WFPRINTF(stderr, "\nFiles %s and %s differ.\n", (const W_CHAR*)files[0],
              (const W_CHAR*)files[1]);
-    return_code = -3;
+    return_code = 1;
   } else {
     WPRINTF("\nFiles %s and %s are identical.\n", (const W_CHAR*)files[0],
             (const W_CHAR*)files[1]);
diff --git a/examples/anim_dump.c b/examples/anim_dump.c
index 269cbaba..fa702dd2 100644
--- a/examples/anim_dump.c
+++ b/examples/anim_dump.c
@@ -12,6 +12,7 @@
 // Author: Skal (pascal.massimino@gmail.com)
 
 #include <stdio.h>
+#include <stdlib.h>
 #include <string.h>  // for 'strcmp'.
 
 #include "./anim_util.h"
@@ -35,6 +36,7 @@ static void Help(void) {
   printf("  -version ............ print version number and exit\n");
 }
 
+// Returns EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 int main(int argc, const char* argv[]) {
   int error = 0;
   const W_CHAR* dump_folder = TO_W_CHAR(".");
@@ -47,7 +49,7 @@ int main(int argc, const char* argv[]) {
 
   if (argc < 2) {
     Help();
-    FREE_WARGV_AND_RETURN(-1);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
 
   for (c = 1; !error && c < argc; ++c) {
@@ -73,7 +75,7 @@ int main(int argc, const char* argv[]) {
       suffix = TO_W_CHAR("pam");
     } else if (!strcmp(argv[c], "-h") || !strcmp(argv[c], "-help")) {
       Help();
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-version")) {
       int dec_version, demux_version;
       GetAnimatedImageVersions(&dec_version, &demux_version);
@@ -82,7 +84,7 @@ int main(int argc, const char* argv[]) {
              (dec_version >> 0) & 0xff,
              (demux_version >> 16) & 0xff, (demux_version >> 8) & 0xff,
              (demux_version >> 0) & 0xff);
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else {
       uint32_t i;
       AnimatedImage image;
@@ -121,5 +123,5 @@ int main(int argc, const char* argv[]) {
       ClearAnimatedImage(&image);
     }
   }
-  FREE_WARGV_AND_RETURN(error ? 1 : 0);
+  FREE_WARGV_AND_RETURN(error ? EXIT_FAILURE : EXIT_SUCCESS);
 }
diff --git a/examples/cwebp.c b/examples/cwebp.c
index cab70054..716a1117 100644
--- a/examples/cwebp.c
+++ b/examples/cwebp.c
@@ -178,8 +178,14 @@ static void PrintFullLosslessInfo(const WebPAuxStats* const stats,
     if (stats->lossless_features & 8) fprintf(stderr, " PALETTE");
     fprintf(stderr, "\n");
   }
-  fprintf(stderr, "  * Precision Bits: histogram=%d transform=%d cache=%d\n",
-          stats->histogram_bits, stats->transform_bits, stats->cache_bits);
+  fprintf(stderr, "  * Precision Bits: histogram=%d", stats->histogram_bits);
+  if (stats->lossless_features & 1) {
+    fprintf(stderr, " prediction=%d", stats->transform_bits);
+  }
+  if (stats->lossless_features & 2) {
+    fprintf(stderr, " cross-color=%d", stats->cross_color_transform_bits);
+  }
+  fprintf(stderr, " cache=%d\n", stats->cache_bits);
   if (stats->palette_size > 0) {
     fprintf(stderr, "  * Palette size:   %d\n", stats->palette_size);
   }
@@ -651,8 +657,9 @@ static const char* const kErrorMessages[VP8_ENC_ERROR_LAST] = {
 
 //------------------------------------------------------------------------------
 
+// Returns EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 int main(int argc, const char* argv[]) {
-  int return_value = -1;
+  int return_value = EXIT_FAILURE;
   const char* in_file = NULL, *out_file = NULL, *dump_file = NULL;
   FILE* out = NULL;
   int c;
@@ -686,22 +693,22 @@ int main(int argc, const char* argv[]) {
       !WebPPictureInit(&original_picture) ||
       !WebPConfigInit(&config)) {
     fprintf(stderr, "Error! Version mismatch!\n");
-    FREE_WARGV_AND_RETURN(-1);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
 
   if (argc == 1) {
     HelpShort();
-    FREE_WARGV_AND_RETURN(0);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
 
   for (c = 1; c < argc; ++c) {
     int parse_error = 0;
     if (!strcmp(argv[c], "-h") || !strcmp(argv[c], "-help")) {
       HelpShort();
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-H") || !strcmp(argv[c], "-longhelp")) {
       HelpLong();
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-o") && c + 1 < argc) {
       out_file = (const char*)GET_WARGV(argv, ++c);
     } else if (!strcmp(argv[c], "-d") && c + 1 < argc) {
@@ -842,7 +849,7 @@ int main(int argc, const char* argv[]) {
       printf("libsharpyuv: %d.%d.%d\n",
              (sharpyuv_version >> 24) & 0xff, (sharpyuv_version >> 16) & 0xffff,
              sharpyuv_version & 0xff);
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-progress")) {
       show_progress = 1;
     } else if (!strcmp(argv[c], "-quiet")) {
@@ -904,7 +911,7 @@ int main(int argc, const char* argv[]) {
         if (i == kNumTokens) {
           fprintf(stderr, "Error! Unknown metadata type '%.*s'\n",
                   (int)(token - start), start);
-          FREE_WARGV_AND_RETURN(-1);
+          FREE_WARGV_AND_RETURN(EXIT_FAILURE);
         }
         start = token + 1;
       }
@@ -923,14 +930,14 @@ int main(int argc, const char* argv[]) {
     } else if (argv[c][0] == '-') {
       fprintf(stderr, "Error! Unknown option '%s'\n", argv[c]);
       HelpLong();
-      FREE_WARGV_AND_RETURN(-1);
+      FREE_WARGV_AND_RETURN(EXIT_FAILURE);
     } else {
       in_file = (const char*)GET_WARGV(argv, c);
     }
 
     if (parse_error) {
       HelpLong();
-      FREE_WARGV_AND_RETURN(-1);
+      FREE_WARGV_AND_RETURN(EXIT_FAILURE);
     }
   }
   if (in_file == NULL) {
@@ -1231,7 +1238,7 @@ int main(int argc, const char* argv[]) {
       PrintMetadataInfo(&metadata, metadata_written);
     }
   }
-  return_value = 0;
+  return_value = EXIT_SUCCESS;
 
  Error:
   WebPMemoryWriterClear(&memory_writer);
diff --git a/examples/dwebp.c b/examples/dwebp.c
index 652de6a6..9dc3c6b6 100644
--- a/examples/dwebp.c
+++ b/examples/dwebp.c
@@ -177,6 +177,7 @@ static uint8_t* AllocateExternalBuffer(WebPDecoderConfig* config,
   return external_buffer;
 }
 
+// Returns EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 int main(int argc, const char* argv[]) {
   int ok = 0;
   const char* in_file = NULL;
@@ -197,14 +198,14 @@ int main(int argc, const char* argv[]) {
 
   if (!WebPInitDecoderConfig(&config)) {
     fprintf(stderr, "Library version mismatch!\n");
-    FREE_WARGV_AND_RETURN(-1);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
 
   for (c = 1; c < argc; ++c) {
     int parse_error = 0;
     if (!strcmp(argv[c], "-h") || !strcmp(argv[c], "-help")) {
       Help();
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-o") && c < argc - 1) {
       out_file = (const char*)GET_WARGV(argv, ++c);
     } else if (!strcmp(argv[c], "-alpha")) {
@@ -227,7 +228,7 @@ int main(int argc, const char* argv[]) {
       const int version = WebPGetDecoderVersion();
       printf("%d.%d.%d\n",
              (version >> 16) & 0xff, (version >> 8) & 0xff, version & 0xff);
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-pgm")) {
       format = PGM;
     } else if (!strcmp(argv[c], "-yuv")) {
@@ -293,21 +294,21 @@ int main(int argc, const char* argv[]) {
     } else if (argv[c][0] == '-') {
       fprintf(stderr, "Unknown option '%s'\n", argv[c]);
       Help();
-      FREE_WARGV_AND_RETURN(-1);
+      FREE_WARGV_AND_RETURN(EXIT_FAILURE);
     } else {
       in_file = (const char*)GET_WARGV(argv, c);
     }
 
     if (parse_error) {
       Help();
-      FREE_WARGV_AND_RETURN(-1);
+      FREE_WARGV_AND_RETURN(EXIT_FAILURE);
     }
   }
 
   if (in_file == NULL) {
     fprintf(stderr, "missing input file!!\n");
     Help();
-    FREE_WARGV_AND_RETURN(-1);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
 
   if (quiet) verbose = 0;
@@ -316,7 +317,7 @@ int main(int argc, const char* argv[]) {
     VP8StatusCode status = VP8_STATUS_OK;
     size_t data_size = 0;
     if (!LoadWebP(in_file, &data, &data_size, bitstream)) {
-      FREE_WARGV_AND_RETURN(-1);
+      FREE_WARGV_AND_RETURN(EXIT_FAILURE);
     }
 
     switch (format) {
@@ -415,7 +416,7 @@ int main(int argc, const char* argv[]) {
   WebPFreeDecBuffer(output_buffer);
   WebPFree((void*)external_buffer);
   WebPFree((void*)data);
-  FREE_WARGV_AND_RETURN(ok ? 0 : -1);
+  FREE_WARGV_AND_RETURN(ok ? EXIT_SUCCESS : EXIT_FAILURE);
 }
 
 //------------------------------------------------------------------------------
diff --git a/examples/gif2webp.c b/examples/gif2webp.c
index cc9b25d9..2b297428 100644
--- a/examples/gif2webp.c
+++ b/examples/gif2webp.c
@@ -28,6 +28,7 @@
 #endif
 
 #include <gif_lib.h>
+#include "sharpyuv/sharpyuv.h"
 #include "webp/encode.h"
 #include "webp/mux.h"
 #include "../examples/example_util.h"
@@ -70,8 +71,14 @@ static void Help(void) {
   printf("  -lossy ................. encode image using lossy compression\n");
   printf("  -mixed ................. for each frame in the image, pick lossy\n"
          "                           or lossless compression heuristically\n");
+  printf("  -near_lossless <int> ... use near-lossless image preprocessing\n"
+         "                           (0..100=off), default=100\n");
+  printf("  -sharp_yuv ............. use sharper (and slower) RGB->YUV "
+                                    "conversion\n"
+         "                           (lossy only)\n");
   printf("  -q <float> ............. quality factor (0:small..100:big)\n");
-  printf("  -m <int> ............... compression method (0=fast, 6=slowest)\n");
+  printf("  -m <int> ............... compression method (0=fast, 6=slowest), "
+         "default=4\n");
   printf("  -min_size .............. minimize output size (default:off)\n"
          "                           lossless compression by default; can be\n"
          "                           combined with -q, -m, -lossy or -mixed\n"
@@ -96,6 +103,7 @@ static void Help(void) {
 
 //------------------------------------------------------------------------------
 
+// Returns EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 int main(int argc, const char* argv[]) {
   int verbose = 0;
   int gif_error = GIF_ERROR;
@@ -140,7 +148,7 @@ int main(int argc, const char* argv[]) {
       !WebPPictureInit(&frame) || !WebPPictureInit(&curr_canvas) ||
       !WebPPictureInit(&prev_canvas)) {
     fprintf(stderr, "Error! Version mismatch!\n");
-    FREE_WARGV_AND_RETURN(-1);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
   config.lossless = 1;  // Use lossless compression by default.
 
@@ -150,14 +158,14 @@ int main(int argc, const char* argv[]) {
 
   if (argc == 1) {
     Help();
-    FREE_WARGV_AND_RETURN(0);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
 
   for (c = 1; c < argc; ++c) {
     int parse_error = 0;
     if (!strcmp(argv[c], "-h") || !strcmp(argv[c], "-help")) {
       Help();
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-o") && c < argc - 1) {
       out_file = GET_WARGV(argv, ++c);
     } else if (!strcmp(argv[c], "-lossy")) {
@@ -165,6 +173,10 @@ int main(int argc, const char* argv[]) {
     } else if (!strcmp(argv[c], "-mixed")) {
       enc_options.allow_mixed = 1;
       config.lossless = 0;
+    } else if (!strcmp(argv[c], "-near_lossless") && c < argc - 1) {
+      config.near_lossless = ExUtilGetInt(argv[++c], 0, &parse_error);
+    } else if (!strcmp(argv[c], "-sharp_yuv")) {
+      config.use_sharp_yuv = 1;
     } else if (!strcmp(argv[c], "-loop_compatibility")) {
       loop_compatibility = 1;
     } else if (!strcmp(argv[c], "-q") && c < argc - 1) {
@@ -216,7 +228,7 @@ int main(int argc, const char* argv[]) {
           fprintf(stderr, "Error! Unknown metadata type '%.*s'\n",
                   (int)(token - start), start);
           Help();
-          FREE_WARGV_AND_RETURN(-1);
+          FREE_WARGV_AND_RETURN(EXIT_FAILURE);
         }
         start = token + 1;
       }
@@ -225,11 +237,14 @@ int main(int argc, const char* argv[]) {
     } else if (!strcmp(argv[c], "-version")) {
       const int enc_version = WebPGetEncoderVersion();
       const int mux_version = WebPGetMuxVersion();
+      const int sharpyuv_version = SharpYuvGetVersion();
       printf("WebP Encoder version: %d.%d.%d\nWebP Mux version: %d.%d.%d\n",
              (enc_version >> 16) & 0xff, (enc_version >> 8) & 0xff,
              enc_version & 0xff, (mux_version >> 16) & 0xff,
              (mux_version >> 8) & 0xff, mux_version & 0xff);
-      FREE_WARGV_AND_RETURN(0);
+      printf("libsharpyuv: %d.%d.%d\n", (sharpyuv_version >> 24) & 0xff,
+             (sharpyuv_version >> 16) & 0xffff, sharpyuv_version & 0xff);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-quiet")) {
       quiet = 1;
       enc_options.verbose = 0;
@@ -242,14 +257,14 @@ int main(int argc, const char* argv[]) {
     } else if (argv[c][0] == '-') {
       fprintf(stderr, "Error! Unknown option '%s'\n", argv[c]);
       Help();
-      FREE_WARGV_AND_RETURN(-1);
+      FREE_WARGV_AND_RETURN(EXIT_FAILURE);
     } else {
       in_file = GET_WARGV(argv, c);
     }
 
     if (parse_error) {
       Help();
-      FREE_WARGV_AND_RETURN(-1);
+      FREE_WARGV_AND_RETURN(EXIT_FAILURE);
     }
   }
 
@@ -593,7 +608,7 @@ int main(int argc, const char* argv[]) {
 #endif
   }
 
-  FREE_WARGV_AND_RETURN(!ok);
+  FREE_WARGV_AND_RETURN(ok ? EXIT_SUCCESS : EXIT_FAILURE);
 }
 
 #else  // !WEBP_HAVE_GIF
@@ -601,7 +616,7 @@ int main(int argc, const char* argv[]) {
 int main(int argc, const char* argv[]) {
   fprintf(stderr, "GIF support not enabled in %s.\n", argv[0]);
   (void)argc;
-  return 0;
+  return EXIT_FAILURE;
 }
 
 #endif
diff --git a/examples/img2webp.c b/examples/img2webp.c
index 3735030c..97d2669e 100644
--- a/examples/img2webp.c
+++ b/examples/img2webp.c
@@ -59,10 +59,15 @@ static void Help(void) {
 
   printf("Per-frame options (only used for subsequent images input):\n");
   printf(" -d <int> ............. frame duration in ms (default: 100)\n");
-  printf(" -lossless  ........... use lossless mode (default)\n");
-  printf(" -lossy ... ........... use lossy mode\n");
+  printf(" -lossless ............ use lossless mode (default)\n");
+  printf(" -lossy ............... use lossy mode\n");
   printf(" -q <float> ........... quality\n");
-  printf(" -m <int> ............. method to use\n");
+  printf(" -m <int> ............. compression method (0=fast, 6=slowest), "
+         "default=4\n");
+  printf(" -exact, -noexact ..... preserve or alter RGB values in transparent "
+                                  "area\n"
+         "                        (default: -noexact, may cause artifacts\n"
+         "                                  with lossy animations)\n");
 
   printf("\n");
   printf("example: img2webp -loop 2 in0.png -lossy in1.jpg\n"
@@ -130,6 +135,7 @@ static int SetLoopCount(int loop_count, WebPData* const webp_data) {
 
 //------------------------------------------------------------------------------
 
+// Returns EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 int main(int argc, const char* argv[]) {
   const char* output = NULL;
   WebPAnimEncoder* enc = NULL;
@@ -145,13 +151,14 @@ int main(int argc, const char* argv[]) {
   WebPData webp_data;
   int c;
   int have_input = 0;
+  int last_input_index = 0;
   CommandLineArguments cmd_args;
   int ok;
 
   INIT_WARGV(argc, argv);
 
   ok = ExUtilInitCommandLineArguments(argc - 1, argv + 1, &cmd_args);
-  if (!ok) FREE_WARGV_AND_RETURN(1);
+  if (!ok) FREE_WARGV_AND_RETURN(EXIT_FAILURE);
 
   argc = cmd_args.argc_;
   argv = cmd_args.argv_;
@@ -199,7 +206,7 @@ int main(int argc, const char* argv[]) {
         verbose = 1;
       } else if (!strcmp(argv[c], "-h") || !strcmp(argv[c], "-help")) {
         Help();
-        FREE_WARGV_AND_RETURN(0);
+        FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
       } else if (!strcmp(argv[c], "-version")) {
         const int enc_version = WebPGetEncoderVersion();
         const int mux_version = WebPGetMuxVersion();
@@ -223,6 +230,8 @@ int main(int argc, const char* argv[]) {
   }
   if (!have_input) {
     fprintf(stderr, "No input file(s) for generating animation!\n");
+    ok = 0;
+    Help();
     goto End;
   }
 
@@ -247,6 +256,10 @@ int main(int argc, const char* argv[]) {
           fprintf(stderr, "Invalid negative duration (%d)\n", duration);
           parse_error = 1;
         }
+      } else if (!strcmp(argv[c], "-exact")) {
+        config.exact = 1;
+      } else if (!strcmp(argv[c], "-noexact")) {
+        config.exact = 0;
       } else {
         parse_error = 1;   // shouldn't be here.
         fprintf(stderr, "Unknown option [%s]\n", argv[c]);
@@ -267,6 +280,7 @@ int main(int argc, const char* argv[]) {
     // read next input image
     pic.use_argb = 1;
     ok = ReadImage((const char*)GET_WARGV_SHIFTED(argv, c), &pic);
+    last_input_index = c;
     if (!ok) goto End;
 
     if (enc == NULL) {
@@ -305,6 +319,13 @@ int main(int argc, const char* argv[]) {
     ++pic_num;
   }
 
+  for (c = last_input_index + 1; c < argc; ++c) {
+    if (argv[c] != NULL) {
+      fprintf(stderr, "Warning: unused option [%s]!"
+                      " Frame options go before the input frame.\n", argv[c]);
+    }
+  }
+
   // add a last fake frame to signal the last duration
   ok = ok && WebPAnimEncoderAdd(enc, NULL, timestamp_ms, NULL);
   ok = ok && WebPAnimEncoderAssemble(enc, &webp_data);
@@ -335,5 +356,5 @@ int main(int argc, const char* argv[]) {
   }
   WebPDataClear(&webp_data);
   ExUtilDeleteCommandLineArguments(&cmd_args);
-  FREE_WARGV_AND_RETURN(ok ? 0 : 1);
+  FREE_WARGV_AND_RETURN(ok ? EXIT_SUCCESS : EXIT_FAILURE);
 }
diff --git a/examples/vwebp.c b/examples/vwebp.c
index fa5fadb1..89e8d8c1 100644
--- a/examples/vwebp.c
+++ b/examples/vwebp.c
@@ -506,7 +506,7 @@ int main(int argc, char* argv[]) {
 
   if (!WebPInitDecoderConfig(config)) {
     fprintf(stderr, "Library version mismatch!\n");
-    FREE_WARGV_AND_RETURN(-1);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
   config->options.dithering_strength = 50;
   config->options.alpha_dithering_strength = 100;
@@ -518,7 +518,7 @@ int main(int argc, char* argv[]) {
     int parse_error = 0;
     if (!strcmp(argv[c], "-h") || !strcmp(argv[c], "-help")) {
       Help();
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-noicc")) {
       kParams.use_color_profile = 0;
     } else if (!strcmp(argv[c], "-nofancy")) {
@@ -541,7 +541,7 @@ int main(int argc, char* argv[]) {
              (dec_version >> 16) & 0xff, (dec_version >> 8) & 0xff,
              dec_version & 0xff, (dmux_version >> 16) & 0xff,
              (dmux_version >> 8) & 0xff, dmux_version & 0xff);
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-mt")) {
       config->options.use_threads = 1;
     } else if (!strcmp(argv[c], "--")) {
@@ -553,7 +553,7 @@ int main(int argc, char* argv[]) {
     } else if (argv[c][0] == '-') {
       printf("Unknown option '%s'\n", argv[c]);
       Help();
-      FREE_WARGV_AND_RETURN(-1);
+      FREE_WARGV_AND_RETURN(EXIT_FAILURE);
     } else {
       kParams.file_name = (const char*)GET_WARGV(argv, c);
       file_name_argv_index = c;
@@ -561,14 +561,14 @@ int main(int argc, char* argv[]) {
 
     if (parse_error) {
       Help();
-      FREE_WARGV_AND_RETURN(-1);
+      FREE_WARGV_AND_RETURN(EXIT_FAILURE);
     }
   }
 
   if (kParams.file_name == NULL) {
     printf("missing input file!!\n");
     Help();
-    FREE_WARGV_AND_RETURN(0);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
 
   if (!ImgIoUtilReadFile(kParams.file_name,
@@ -643,11 +643,11 @@ int main(int argc, char* argv[]) {
 
   // Should only be reached when using FREEGLUT:
   ClearParams();
-  FREE_WARGV_AND_RETURN(0);
+  FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
 
  Error:
   ClearParams();
-  FREE_WARGV_AND_RETURN(-1);
+  FREE_WARGV_AND_RETURN(EXIT_FAILURE);
 }
 
 #else   // !WEBP_HAVE_GL
@@ -655,7 +655,7 @@ int main(int argc, char* argv[]) {
 int main(int argc, const char* argv[]) {
   fprintf(stderr, "OpenGL support not enabled in %s.\n", argv[0]);
   (void)argc;
-  return 0;
+  return EXIT_FAILURE;
 }
 
 #endif
diff --git a/examples/webpinfo.c b/examples/webpinfo.c
index 1d2278ee..ba8f1e12 100644
--- a/examples/webpinfo.c
+++ b/examples/webpinfo.c
@@ -14,6 +14,7 @@
 
 #include <assert.h>
 #include <stdio.h>
+#include <stdlib.h>
 
 #ifdef HAVE_CONFIG_H
 #include "webp/config.h"
@@ -1120,6 +1121,7 @@ static void Help(void) {
          "  -bitstream_info .... Parse bitstream header.\n");
 }
 
+// Returns EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 int main(int argc, const char* argv[]) {
   int c, quiet = 0, show_diag = 0, show_summary = 0;
   int parse_bitstream = 0;
@@ -1130,7 +1132,7 @@ int main(int argc, const char* argv[]) {
 
   if (argc == 1) {
     Help();
-    FREE_WARGV_AND_RETURN(WEBP_INFO_OK);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
 
   // Parse command-line input.
@@ -1138,7 +1140,7 @@ int main(int argc, const char* argv[]) {
     if (!strcmp(argv[c], "-h") || !strcmp(argv[c], "-help") ||
         !strcmp(argv[c], "-H") || !strcmp(argv[c], "-longhelp")) {
       Help();
-      FREE_WARGV_AND_RETURN(WEBP_INFO_OK);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else if (!strcmp(argv[c], "-quiet")) {
       quiet = 1;
     } else if (!strcmp(argv[c], "-diag")) {
@@ -1151,7 +1153,7 @@ int main(int argc, const char* argv[]) {
       const int version = WebPGetDecoderVersion();
       printf("WebP Decoder version: %d.%d.%d\n",
              (version >> 16) & 0xff, (version >> 8) & 0xff, version & 0xff);
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else {  // Assume the remaining are all input files.
       break;
     }
@@ -1159,7 +1161,7 @@ int main(int argc, const char* argv[]) {
 
   if (c == argc) {
     Help();
-    FREE_WARGV_AND_RETURN(WEBP_INFO_INVALID_COMMAND);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
 
   // Process input files one by one.
@@ -1182,5 +1184,6 @@ int main(int argc, const char* argv[]) {
     webp_info_status = AnalyzeWebP(&webp_info, &webp_data);
     WebPDataClear(&webp_data);
   }
-  FREE_WARGV_AND_RETURN(webp_info_status);
+  FREE_WARGV_AND_RETURN((webp_info_status == WEBP_INFO_OK) ? EXIT_SUCCESS
+                                                           : EXIT_FAILURE);
 }
diff --git a/examples/webpmux.c b/examples/webpmux.c
index 9bf45103..49d72641 100644
--- a/examples/webpmux.c
+++ b/examples/webpmux.c
@@ -59,6 +59,7 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
+
 #include "webp/decode.h"
 #include "webp/mux.h"
 #include "../examples/example_util.h"
@@ -1225,6 +1226,7 @@ static int Process(const Config* config) {
 //------------------------------------------------------------------------------
 // Main.
 
+// Returns EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 int main(int argc, const char* argv[]) {
   Config config;
   int ok;
@@ -1238,7 +1240,7 @@ int main(int argc, const char* argv[]) {
     PrintHelp();
   }
   DeleteConfig(&config);
-  FREE_WARGV_AND_RETURN(!ok);
+  FREE_WARGV_AND_RETURN(ok ? EXIT_SUCCESS : EXIT_FAILURE);
 }
 
 //------------------------------------------------------------------------------
diff --git a/extras/extras.c b/extras/extras.c
index 3a3d254e..c458c695 100644
--- a/extras/extras.c
+++ b/extras/extras.c
@@ -24,7 +24,7 @@
 #include "webp/types.h"
 
 #define XTRA_MAJ_VERSION 1
-#define XTRA_MIN_VERSION 4
+#define XTRA_MIN_VERSION 5
 #define XTRA_REV_VERSION 0
 
 //------------------------------------------------------------------------------
diff --git a/extras/get_disto.c b/extras/get_disto.c
index 3aa345bb..7b9c202b 100644
--- a/extras/get_disto.c
+++ b/extras/get_disto.c
@@ -227,10 +227,11 @@ static void Help(void) {
           WebPGetEnabledInputFileFormats());
 }
 
+// Returns EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 int main(int argc, const char* argv[]) {
   WebPPicture pic1, pic2;
   size_t size1 = 0, size2 = 0;
-  int ret = 1;
+  int ret = EXIT_FAILURE;
   float disto[5];
   int type = 0;
   int c;
@@ -246,7 +247,7 @@ int main(int argc, const char* argv[]) {
 
   if (!WebPPictureInit(&pic1) || !WebPPictureInit(&pic2)) {
     fprintf(stderr, "Can't init pictures\n");
-    FREE_WARGV_AND_RETURN(1);
+    FREE_WARGV_AND_RETURN(EXIT_FAILURE);
   }
 
   for (c = 1; c < argc; ++c) {
@@ -262,7 +263,7 @@ int main(int argc, const char* argv[]) {
       use_gray = 1;
     } else if (!strcmp(argv[c], "-h")) {
       help = 1;
-      ret = 0;
+      ret = EXIT_SUCCESS;
     } else if (!strcmp(argv[c], "-o")) {
       if (++c == argc) {
         fprintf(stderr, "missing file name after %s option.\n", argv[c - 1]);
@@ -337,7 +338,8 @@ int main(int argc, const char* argv[]) {
       fprintf(stderr, "Error during lossless encoding.\n");
       goto End;
     }
-    ret = ImgIoUtilWriteFile(output, data, data_size) ? 0 : 1;
+    ret = ImgIoUtilWriteFile(output, data, data_size) ? EXIT_SUCCESS
+                                                      : EXIT_FAILURE;
     WebPFree(data);
     if (ret) goto End;
 #else
@@ -345,9 +347,10 @@ int main(int argc, const char* argv[]) {
     (void)data_size;
     fprintf(stderr, "Cannot save the difference map. Please recompile "
                     "without the WEBP_REDUCE_CSP flag.\n");
+    goto End;
 #endif  // WEBP_REDUCE_CSP
   }
-  ret = 0;
+  ret = EXIT_SUCCESS;
 
  End:
   WebPPictureFree(&pic1);
diff --git a/extras/vwebp_sdl.c b/extras/vwebp_sdl.c
index acf48909..1906bf39 100644
--- a/extras/vwebp_sdl.c
+++ b/extras/vwebp_sdl.c
@@ -15,6 +15,7 @@
 // Author: James Zern (jzern@google.com)
 
 #include <stdio.h>
+#include <stdlib.h>
 
 #ifdef HAVE_CONFIG_H
 #include "webp/config.h"
@@ -49,19 +50,26 @@ static void ProcessEvents(void) {
   }
 }
 
+// Returns EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 int main(int argc, char* argv[]) {
   int c;
   int ok = 0;
 
   INIT_WARGV(argc, argv);
 
+  if (argc == 1) {
+    fprintf(stderr, "Usage: %s [-h] image.webp [more_files.webp...]\n",
+            argv[0]);
+    goto Error;
+  }
+
   for (c = 1; c < argc; ++c) {
     const char* file = NULL;
     const uint8_t* webp = NULL;
     size_t webp_size = 0;
     if (!strcmp(argv[c], "-h")) {
       printf("Usage: %s [-h] image.webp [more_files.webp...]\n", argv[0]);
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else {
       file = (const char*)GET_WARGV(argv, c);
     }
@@ -87,7 +95,7 @@ int main(int argc, char* argv[]) {
 
  Error:
   SDL_Quit();
-  FREE_WARGV_AND_RETURN(ok ? 0 : 1);
+  FREE_WARGV_AND_RETURN(ok ? EXIT_SUCCESS : EXIT_FAILURE);
 }
 
 #else  // !WEBP_HAVE_SDL
diff --git a/extras/webp_quality.c b/extras/webp_quality.c
index 0a3b25f1..52bd663b 100644
--- a/extras/webp_quality.c
+++ b/extras/webp_quality.c
@@ -15,6 +15,7 @@
 #include "imageio/imageio_util.h"
 #include "../examples/unicode.h"
 
+// Returns EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 int main(int argc, const char* argv[]) {
   int c;
   int quiet = 0;
@@ -27,7 +28,7 @@ int main(int argc, const char* argv[]) {
       quiet = 1;
     } else if (!strcmp(argv[c], "-help") || !strcmp(argv[c], "-h")) {
       printf("webp_quality [-h][-quiet] webp_files...\n");
-      FREE_WARGV_AND_RETURN(0);
+      FREE_WARGV_AND_RETURN(EXIT_SUCCESS);
     } else {
       const char* const filename = (const char*)GET_WARGV(argv, c);
       const uint8_t* data = NULL;
@@ -50,5 +51,5 @@ int main(int argc, const char* argv[]) {
       free((void*)data);
     }
   }
-  FREE_WARGV_AND_RETURN(ok ? 0 : 1);
+  FREE_WARGV_AND_RETURN(ok ? EXIT_SUCCESS : EXIT_FAILURE);
 }
diff --git a/imageio/imageio_util.c b/imageio/imageio_util.c
index df37137e..4ae4e03c 100644
--- a/imageio/imageio_util.c
+++ b/imageio/imageio_util.c
@@ -89,6 +89,11 @@ int ImgIoUtilReadFile(const char* const file_name,
   }
   fseek(in, 0, SEEK_END);
   file_size = ftell(in);
+  if (file_size == (size_t)-1) {
+    fclose(in);
+    WFPRINTF(stderr, "error getting size of '%s'\n", (const W_CHAR*)file_name);
+    return 0;
+  }
   fseek(in, 0, SEEK_SET);
   // we allocate one extra byte for the \0 terminator
   file_data = (uint8_t*)WebPMalloc(file_size + 1);
diff --git a/imageio/jpegdec.c b/imageio/jpegdec.c
index 74a4c09c..7bce1206 100644
--- a/imageio/jpegdec.c
+++ b/imageio/jpegdec.c
@@ -206,8 +206,18 @@ struct my_error_mgr {
 
 static void my_error_exit(j_common_ptr dinfo) {
   struct my_error_mgr* myerr = (struct my_error_mgr*)dinfo->err;
+  // The following code is disabled in fuzzing mode because:
+  // - the logs can be flooded due to invalid JPEG files
+  // - msg_code is wrongfully seen as uninitialized by msan when the libjpeg
+  //   dependency is not built with sanitizers enabled
+#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
+  const int msg_code = myerr->pub.msg_code;
   fprintf(stderr, "libjpeg error: ");
   dinfo->err->output_message(dinfo);
+  if (msg_code == JERR_INPUT_EOF || msg_code == JERR_FILE_READ) {
+    fprintf(stderr, "`jpegtran -copy all` MAY be able to process this file.\n");
+  }
+#endif
   longjmp(myerr->setjmp_buffer, 1);
 }
 
diff --git a/iosbuild.sh b/iosbuild.sh
index d0fb5572..859aa348 100755
--- a/iosbuild.sh
+++ b/iosbuild.sh
@@ -53,7 +53,7 @@ DEMUXLIBLIST=''
 if [[ -z "${SDK}" ]]; then
   echo "iOS SDK not available"
   exit 1
-elif [[ ${SDK%%.*} -gt 8 ]]; then
+elif [[ ${SDK%%.*} -gt 8 && "${XCODE%%.*}" -lt 16 ]]; then
   EXTRA_CFLAGS="-fembed-bitcode"
 elif [[ ${SDK%%.*} -le 6 ]]; then
   echo "You need iOS SDK version 6.0 or above"
diff --git a/man/cwebp.1 b/man/cwebp.1
index f8d88143..b4bf4f9d 100644
--- a/man/cwebp.1
+++ b/man/cwebp.1
@@ -1,5 +1,5 @@
 .\"                                      Hey, EMACS: -*- nroff -*-
-.TH CWEBP 1 "March 26, 2024"
+.TH CWEBP 1 "September 17, 2024"
 .SH NAME
 cwebp \- compress an image file to a WebP file
 .SH SYNOPSIS
@@ -180,8 +180,8 @@ Disable strong filtering (if filtering is being used thanks to the
 \fB\-f\fP option) and use simple filtering instead.
 .TP
 .B \-sharp_yuv
-Use more accurate and sharper RGB->YUV conversion if needed. Note that this
-process is slower than the default 'fast' RGB->YUV conversion.
+Use more accurate and sharper RGB->YUV conversion. Note that this process is
+slower than the default 'fast' RGB->YUV conversion.
 .TP
 .BI \-sns " int
 Specify the amplitude of the spatial noise shaping. Spatial noise shaping
@@ -299,12 +299,12 @@ Note: each input format may not support all combinations.
 .B \-noasm
 Disable all assembly optimizations.
 
-.SH BUGS
-Please report all bugs to the issue tracker:
-https://bugs.chromium.org/p/webp
-.br
-Patches welcome! See this page to get started:
-https://www.webmproject.org/code/contribute/submitting\-patches/
+.SH EXIT STATUS
+If there were no problems during execution, \fBcwebp\fP exits with the value of
+the C constant \fBEXIT_SUCCESS\fP. This is usually zero.
+.PP
+If an error occurs, \fBcwebp\fP exits with the value of the C constant
+\fBEXIT_FAILURE\fP. This is usually one.
 
 .SH EXAMPLES
 cwebp \-q 50 -lossless picture.png \-o picture_lossless.webp
@@ -324,6 +324,13 @@ https://chromium.googlesource.com/webm/libwebp
 This manual page was written by Pascal Massimino <pascal.massimino@gmail.com>,
 for the Debian project (and may be used by others).
 
+.SH REPORTING BUGS
+Please report all bugs to the issue tracker:
+https://issues.webmproject.org
+.br
+Patches welcome! See this page to get started:
+https://www.webmproject.org/code/contribute/submitting\-patches/
+
 .SH SEE ALSO
 .BR dwebp (1),
 .BR gif2webp (1)
diff --git a/man/dwebp.1 b/man/dwebp.1
index e718aba7..dafe0dd3 100644
--- a/man/dwebp.1
+++ b/man/dwebp.1
@@ -1,5 +1,5 @@
 .\"                                      Hey, EMACS: -*- nroff -*-
-.TH DWEBP 1 "November 17, 2021"
+.TH DWEBP 1 "July 18, 2024"
 .SH NAME
 dwebp \- decompress a WebP file to an image file
 .SH SYNOPSIS
@@ -108,12 +108,12 @@ Print extra information (decoding time in particular).
 .B \-noasm
 Disable all assembly optimizations.
 
-.SH BUGS
-Please report all bugs to the issue tracker:
-https://bugs.chromium.org/p/webp
-.br
-Patches welcome! See this page to get started:
-https://www.webmproject.org/code/contribute/submitting\-patches/
+.SH EXIT STATUS
+If there were no problems during execution, \fBdwebp\fP exits with the value of
+the C constant \fBEXIT_SUCCESS\fP. This is usually zero.
+.PP
+If an error occurs, \fBdwebp\fP exits with the value of the C constant
+\fBEXIT_FAILURE\fP. This is usually one.
 
 .SH EXAMPLES
 dwebp picture.webp \-o output.png
@@ -133,6 +133,13 @@ https://chromium.googlesource.com/webm/libwebp
 This manual page was written by Pascal Massimino <pascal.massimino@gmail.com>,
 for the Debian project (and may be used by others).
 
+.SH REPORTING BUGS
+Please report all bugs to the issue tracker:
+https://issues.webmproject.org
+.br
+Patches welcome! See this page to get started:
+https://www.webmproject.org/code/contribute/submitting\-patches/
+
 .SH SEE ALSO
 .BR cwebp (1),
 .BR gif2webp (1),
diff --git a/man/gif2webp.1 b/man/gif2webp.1
index 3bf43bcc..2b0e7e1f 100644
--- a/man/gif2webp.1
+++ b/man/gif2webp.1
@@ -1,5 +1,5 @@
 .\"                                      Hey, EMACS: -*- nroff -*-
-.TH GIF2WEBP 1 "November 17, 2021"
+.TH GIF2WEBP 1 "November 4, 2024"
 .SH NAME
 gif2webp \- Convert a GIF image to WebP
 .SH SYNOPSIS
@@ -39,6 +39,18 @@ Encode the image using lossy compression.
 Mixed compression mode: optimize compression of the image by picking either
 lossy or lossless compression for each frame heuristically.
 .TP
+.BI \-near_lossless " int
+Specify the level of near\-lossless image preprocessing. This option adjusts
+pixel values to help compressibility, but has minimal impact on the visual
+quality. It triggers lossless compression mode automatically. The range is 0
+(maximum preprocessing) to 100 (no preprocessing, the default). The typical
+value is around 60. Note that lossy with \fB\-q 100\fP can at times yield
+better results.
+.TP
+.B \-sharp_yuv
+Use more accurate and sharper RGB->YUV conversion. Note that this process is
+slower than the default 'fast' RGB->YUV conversion.
+.TP
 .BI \-q " float
 Specify the compression factor for RGB channels between 0 and 100. The default
 is 75.
@@ -126,12 +138,12 @@ Print extra information.
 .B \-quiet
 Do not print anything.
 
-.SH BUGS
-Please report all bugs to the issue tracker:
-https://bugs.chromium.org/p/webp
-.br
-Patches welcome! See this page to get started:
-https://www.webmproject.org/code/contribute/submitting\-patches/
+.SH EXIT STATUS
+If there were no problems during execution, \fBgif2webp\fP exits with the value
+of the C constant \fBEXIT_SUCCESS\fP. This is usually zero.
+.PP
+If an error occurs, \fBgif2webp\fP exits with the value of the C constant
+\fBEXIT_FAILURE\fP. This is usually one.
 
 .SH EXAMPLES
 gif2webp picture.gif \-o picture.webp
@@ -155,6 +167,13 @@ https://chromium.googlesource.com/webm/libwebp
 This manual page was written by Urvang Joshi <urvang@google.com>, for the
 Debian project (and may be used by others).
 
+.SH REPORTING BUGS
+Please report all bugs to the issue tracker:
+https://issues.webmproject.org
+.br
+Patches welcome! See this page to get started:
+https://www.webmproject.org/code/contribute/submitting\-patches/
+
 .SH SEE ALSO
 .BR cwebp (1),
 .BR dwebp (1),
diff --git a/man/img2webp.1 b/man/img2webp.1
index fc493e12..202d8772 100644
--- a/man/img2webp.1
+++ b/man/img2webp.1
@@ -1,5 +1,5 @@
 .\"                                      Hey, EMACS: -*- nroff -*-
-.TH IMG2WEBP 1 "March 17, 2023"
+.TH IMG2WEBP 1 "November 26, 2024"
 .SH NAME
 img2webp \- create animated WebP file from a sequence of input images.
 .SH SYNOPSIS
@@ -53,8 +53,8 @@ value is around 60. Note that lossy with \fB\-q 100\fP can at times yield
 better results.
 .TP
 .B \-sharp_yuv
-Use more accurate and sharper RGB->YUV conversion if needed. Note that this
-process is slower than the default 'fast' RGB->YUV conversion.
+Use more accurate and sharper RGB->YUV conversion. Note that this process is
+slower than the default 'fast' RGB->YUV conversion.
 .TP
 .BI \-loop " int
 Specifies the number of times the animation should loop. Using '0'
@@ -88,18 +88,27 @@ Specify the compression factor between 0 and 100. The default is 75.
 Specify the compression method to use. This parameter controls the
 trade off between encoding speed and the compressed file size and quality.
 Possible values range from 0 to 6. Default value is 4.
+When higher values are used, the encoder will spend more time inspecting
+additional encoding possibilities and decide on the quality gain.
+Lower value can result in faster processing time at the expense of
+larger file size and lower compression quality.
+.TP
+.B \-exact, \-noexact
+Preserve or alter RGB values in transparent area. The default is
+\fB-noexact\fP, to help compressibility. Note \fB\-noexact\fP may cause
+artifacts in frames compressed with \fB\-lossy\fP.
+
+.SH EXIT STATUS
+If there were no problems during execution, \fBimg2webp\fP exits with the value
+of the C constant \fBEXIT_SUCCESS\fP. This is usually zero.
+.PP
+If an error occurs, \fBimg2webp\fP exits with the value of the C constant
+\fBEXIT_FAILURE\fP. This is usually one.
 
 .SH EXAMPLE
 img2webp -loop 2 in0.png -lossy in1.jpg -d 80 in2.tiff -o out.webp
 .br
 
-.SH BUGS
-Please report all bugs to the issue tracker:
-https://bugs.chromium.org/p/webp
-.br
-Patches welcome! See this page to get started:
-https://www.webmproject.org/code/contribute/submitting\-patches/
-
 .SH AUTHORS
 \fBimg2webp\fP is a part of libwebp and was written by the WebP team.
 .br
@@ -109,6 +118,13 @@ https://chromium.googlesource.com/webm/libwebp
 This manual page was written by Pascal Massimino <pascal.massimino@gmail.com>,
 for the Debian project (and may be used by others).
 
+.SH REPORTING BUGS
+Please report all bugs to the issue tracker:
+https://issues.webmproject.org
+.br
+Patches welcome! See this page to get started:
+https://www.webmproject.org/code/contribute/submitting\-patches/
+
 .SH SEE ALSO
 .BR webpmux (1),
 .BR gif2webp (1)
diff --git a/man/vwebp.1 b/man/vwebp.1
index fa48db6d..36a02c54 100644
--- a/man/vwebp.1
+++ b/man/vwebp.1
@@ -1,5 +1,5 @@
 .\"                                      Hey, EMACS: -*- nroff -*-
-.TH VWEBP 1 "November 17, 2021"
+.TH VWEBP 1 "July 18, 2024"
 .SH NAME
 vwebp \- decompress a WebP file and display it in a window
 .SH SYNOPSIS
@@ -72,12 +72,12 @@ Disable blending and disposal process, for debugging purposes.
 .B 'q' / 'Q' / ESC
 Quit.
 
-.SH BUGS
-Please report all bugs to the issue tracker:
-https://bugs.chromium.org/p/webp
-.br
-Patches welcome! See this page to get started:
-https://www.webmproject.org/code/contribute/submitting\-patches/
+.SH EXIT STATUS
+If there were no problems during execution, \fBvwebp\fP exits with the value of
+the C constant \fBEXIT_SUCCESS\fP. This is usually zero.
+.PP
+If an error occurs, \fBvwebp\fP exits with the value of the C constant
+\fBEXIT_FAILURE\fP. This is usually one.
 
 .SH EXAMPLES
 vwebp picture.webp
@@ -94,6 +94,13 @@ https://chromium.googlesource.com/webm/libwebp
 .PP
 This manual page was written for the Debian project (and may be used by others).
 
+.SH REPORTING BUGS
+Please report all bugs to the issue tracker:
+https://issues.webmproject.org
+.br
+Patches welcome! See this page to get started:
+https://www.webmproject.org/code/contribute/submitting\-patches/
+
 .SH SEE ALSO
 .BR dwebp (1)
 .br
diff --git a/man/webpinfo.1 b/man/webpinfo.1
index 35d6d92f..10aff9de 100644
--- a/man/webpinfo.1
+++ b/man/webpinfo.1
@@ -1,5 +1,5 @@
 .\"                                      Hey, EMACS: -*- nroff -*-
-.TH WEBPINFO 1 "November 17, 2021"
+.TH WEBPINFO 1 "July 18, 2024"
 .SH NAME
 webpinfo \- print out the chunk level structure of WebP files
 along with basic integrity checks.
@@ -47,12 +47,12 @@ Detailed usage instructions.
 Input files in WebP format. Input files must come last, following
 options (if any). There can be multiple input files.
 
-.SH BUGS
-Please report all bugs to the issue tracker:
-https://bugs.chromium.org/p/webp
-.br
-Patches welcome! See this page to get started:
-https://www.webmproject.org/code/contribute/submitting\-patches/
+.SH EXIT STATUS
+If there were no problems during execution, \fBwebpinfo\fP exits with the value
+of the C constant \fBEXIT_SUCCESS\fP. This is usually zero.
+.PP
+If an error occurs, \fBwebpinfo\fP exits with the value of the C constant
+\fBEXIT_FAILURE\fP. This is usually one.
 
 .SH EXAMPLES
 .br
@@ -73,6 +73,13 @@ https://chromium.googlesource.com/webm/libwebp
 This manual page was written by Hui Su <huisu@google.com>,
 for the Debian project (and may be used by others).
 
+.SH REPORTING BUGS
+Please report all bugs to the issue tracker:
+https://issues.webmproject.org
+.br
+Patches welcome! See this page to get started:
+https://www.webmproject.org/code/contribute/submitting\-patches/
+
 .SH SEE ALSO
 .BR webpmux (1)
 .br
diff --git a/man/webpmux.1 b/man/webpmux.1
index 07e87389..21b572d1 100644
--- a/man/webpmux.1
+++ b/man/webpmux.1
@@ -1,5 +1,5 @@
 .\"                                      Hey, EMACS: -*- nroff -*-
-.TH WEBPMUX 1 "November 17, 2021"
+.TH WEBPMUX 1 "July 18, 2024"
 .SH NAME
 webpmux \- create animated WebP files from non\-animated WebP images, extract
 frames from animated WebP images, and manage XMP/EXIF metadata and ICC profile.
@@ -186,12 +186,12 @@ Output file in WebP format.
 .TP
 The nature of EXIF, XMP and ICC data is not checked and is assumed to be valid.
 
-.SH BUGS
-Please report all bugs to the issue tracker:
-https://bugs.chromium.org/p/webp
-.br
-Patches welcome! See this page to get started:
-https://www.webmproject.org/code/contribute/submitting\-patches/
+.SH EXIT STATUS
+If there were no problems during execution, \fBwebpmux\fP exits with the value
+of the C constant \fBEXIT_SUCCESS\fP. This is usually zero.
+.PP
+If an error occurs, \fBwebpmux\fP exits with the value of the C constant
+\fBEXIT_FAILURE\fP. This is usually one.
 
 .SH EXAMPLES
 .P
@@ -262,6 +262,13 @@ https://chromium.googlesource.com/webm/libwebp
 This manual page was written by Vikas Arora <vikaas.arora@gmail.com>,
 for the Debian project (and may be used by others).
 
+.SH REPORTING BUGS
+Please report all bugs to the issue tracker:
+https://issues.webmproject.org
+.br
+Patches welcome! See this page to get started:
+https://www.webmproject.org/code/contribute/submitting\-patches/
+
 .SH SEE ALSO
 .BR cwebp (1),
 .BR dwebp (1),
diff --git a/sharpyuv/Makefile.am b/sharpyuv/Makefile.am
index 1a94d467..bd5b22dc 100644
--- a/sharpyuv/Makefile.am
+++ b/sharpyuv/Makefile.am
@@ -33,7 +33,7 @@ libsharpyuv_la_SOURCES += sharpyuv_gamma.c sharpyuv_gamma.h
 libsharpyuv_la_SOURCES += sharpyuv.c sharpyuv.h
 
 libsharpyuv_la_CPPFLAGS = $(AM_CPPFLAGS)
-libsharpyuv_la_LDFLAGS = -no-undefined -version-info 1:0:1 -lm
+libsharpyuv_la_LDFLAGS = -no-undefined -version-info 1:1:1 -lm
 libsharpyuv_la_LIBADD =
 libsharpyuv_la_LIBADD += libsharpyuv_sse2.la
 libsharpyuv_la_LIBADD += libsharpyuv_neon.la
diff --git a/sharpyuv/libsharpyuv.rc b/sharpyuv/libsharpyuv.rc
index e0027aa4..93fd1b8c 100644
--- a/sharpyuv/libsharpyuv.rc
+++ b/sharpyuv/libsharpyuv.rc
@@ -6,8 +6,8 @@
 LANGUAGE LANG_ENGLISH, SUBLANG_ENGLISH_US
 
 VS_VERSION_INFO VERSIONINFO
- FILEVERSION 0,0,4,0
- PRODUCTVERSION 0,0,4,0
+ FILEVERSION 0,0,4,1
+ PRODUCTVERSION 0,0,4,1
  FILEFLAGSMASK 0x3fL
 #ifdef _DEBUG
  FILEFLAGS 0x1L
@@ -24,12 +24,12 @@ BEGIN
         BEGIN
             VALUE "CompanyName", "Google, Inc."
             VALUE "FileDescription", "libsharpyuv DLL"
-            VALUE "FileVersion", "0.4.0"
+            VALUE "FileVersion", "0.4.1"
             VALUE "InternalName", "libsharpyuv.dll"
             VALUE "LegalCopyright", "Copyright (C) 2024"
             VALUE "OriginalFilename", "libsharpyuv.dll"
             VALUE "ProductName", "SharpYuv Library"
-            VALUE "ProductVersion", "0.4.0"
+            VALUE "ProductVersion", "0.4.1"
         END
     END
     BLOCK "VarFileInfo"
diff --git a/sharpyuv/sharpyuv.c b/sharpyuv/sharpyuv.c
index 7cbf668f..14013ebe 100644
--- a/sharpyuv/sharpyuv.c
+++ b/sharpyuv/sharpyuv.c
@@ -565,10 +565,11 @@ int SharpYuvConvertWithOptions(const void* r_ptr, const void* g_ptr,
   scaled_matrix.rgb_to_u[3] = Shift(yuv_matrix->rgb_to_u[3], sfix);
   scaled_matrix.rgb_to_v[3] = Shift(yuv_matrix->rgb_to_v[3], sfix);
 
-  return DoSharpArgbToYuv(r_ptr, g_ptr, b_ptr, rgb_step, rgb_stride,
-                          rgb_bit_depth, y_ptr, y_stride, u_ptr, u_stride,
-                          v_ptr, v_stride, yuv_bit_depth, width, height,
-                          &scaled_matrix, transfer_type);
+  return DoSharpArgbToYuv(
+      (const uint8_t*)r_ptr, (const uint8_t*)g_ptr, (const uint8_t*)b_ptr,
+      rgb_step, rgb_stride, rgb_bit_depth, (uint8_t*)y_ptr, y_stride,
+      (uint8_t*)u_ptr, u_stride, (uint8_t*)v_ptr, v_stride, yuv_bit_depth,
+      width, height, &scaled_matrix, transfer_type);
 }
 
 //------------------------------------------------------------------------------
diff --git a/sharpyuv/sharpyuv.h b/sharpyuv/sharpyuv.h
index fe958915..0317fd49 100644
--- a/sharpyuv/sharpyuv.h
+++ b/sharpyuv/sharpyuv.h
@@ -52,7 +52,7 @@ extern "C" {
 // SharpYUV API version following the convention from semver.org
 #define SHARPYUV_VERSION_MAJOR 0
 #define SHARPYUV_VERSION_MINOR 4
-#define SHARPYUV_VERSION_PATCH 0
+#define SHARPYUV_VERSION_PATCH 1
 // Version as a uint32_t. The major number is the high 8 bits.
 // The minor number is the middle 8 bits. The patch number is the low 16 bits.
 #define SHARPYUV_MAKE_VERSION(MAJOR, MINOR, PATCH) \
@@ -66,10 +66,17 @@ extern "C" {
 SHARPYUV_EXTERN int SharpYuvGetVersion(void);
 
 // RGB to YUV conversion matrix, in 16 bit fixed point.
-// y = rgb_to_y[0] * r + rgb_to_y[1] * g + rgb_to_y[2] * b + rgb_to_y[3]
-// u = rgb_to_u[0] * r + rgb_to_u[1] * g + rgb_to_u[2] * b + rgb_to_u[3]
-// v = rgb_to_v[0] * r + rgb_to_v[1] * g + rgb_to_v[2] * b + rgb_to_v[3]
-// Then y, u and v values are divided by 1<<16 and rounded.
+// y_ = rgb_to_y[0] * r + rgb_to_y[1] * g + rgb_to_y[2] * b + rgb_to_y[3]
+// u_ = rgb_to_u[0] * r + rgb_to_u[1] * g + rgb_to_u[2] * b + rgb_to_u[3]
+// v_ = rgb_to_v[0] * r + rgb_to_v[1] * g + rgb_to_v[2] * b + rgb_to_v[3]
+// Then the values are divided by 1<<16 and rounded.
+// y = (y_ + (1 << 15)) >> 16
+// u = (u_ + (1 << 15)) >> 16
+// v = (v_ + (1 << 15)) >> 16
+//
+// Typically, the offset values rgb_to_y[3], rgb_to_u[3] and rgb_to_v[3] depend
+// on the input's bit depth, e.g., rgb_to_u[3] = 1 << (rgb_bit_depth - 1 + 16).
+// See also sharpyuv_csp.h to get a predefined matrix or generate a matrix.
 typedef struct {
   int rgb_to_y[4];
   int rgb_to_u[4];
@@ -127,6 +134,8 @@ typedef enum SharpYuvTransferFunctionType {
 //     adjacent pixels on the y, u and v channels. If yuv_bit_depth > 8, they
 //     should be multiples of 2.
 // width, height: width and height of the image in pixels
+// yuv_matrix: RGB to YUV conversion matrix. The matrix values typically
+//     depend on the input's rgb_bit_depth.
 // This function calls SharpYuvConvertWithOptions with a default transfer
 // function of kSharpYuvTransferFunctionSrgb.
 SHARPYUV_EXTERN int SharpYuvConvert(const void* r_ptr, const void* g_ptr,
diff --git a/sharpyuv/sharpyuv_csp.c b/sharpyuv/sharpyuv_csp.c
index 0ad22be9..ae03523e 100644
--- a/sharpyuv/sharpyuv_csp.c
+++ b/sharpyuv/sharpyuv_csp.c
@@ -22,16 +22,16 @@ void SharpYuvComputeConversionMatrix(const SharpYuvColorSpace* yuv_color_space,
   const float kr = yuv_color_space->kr;
   const float kb = yuv_color_space->kb;
   const float kg = 1.0f - kr - kb;
-  const float cr = 0.5f / (1.0f - kb);
-  const float cb = 0.5f / (1.0f - kr);
+  const float cb = 0.5f / (1.0f - kb);
+  const float cr = 0.5f / (1.0f - kr);
 
   const int shift = yuv_color_space->bit_depth - 8;
 
   const float denom = (float)((1 << yuv_color_space->bit_depth) - 1);
   float scale_y = 1.0f;
   float add_y = 0.0f;
-  float scale_u = cr;
-  float scale_v = cb;
+  float scale_u = cb;
+  float scale_v = cr;
   float add_uv = (float)(128 << shift);
   assert(yuv_color_space->bit_depth >= 8);
 
@@ -59,31 +59,35 @@ void SharpYuvComputeConversionMatrix(const SharpYuvColorSpace* yuv_color_space,
 }
 
 // Matrices are in YUV_FIX fixed point precision.
-// WebP's matrix, similar but not identical to kRec601LimitedMatrix.
+// WebP's matrix, similar but not identical to kRec601LimitedMatrix
+// Derived using the following formulas:
+// Y = 0.2569 * R + 0.5044 * G + 0.0979 * B + 16
+// U = -0.1483 * R - 0.2911 * G + 0.4394 * B + 128
+// V = 0.4394 * R - 0.3679 * G - 0.0715 * B + 128
 static const SharpYuvConversionMatrix kWebpMatrix = {
   {16839, 33059, 6420, 16 << 16},
   {-9719, -19081, 28800, 128 << 16},
   {28800, -24116, -4684, 128 << 16},
 };
-// Kr=0.2990f Kb=0.1140f bits=8 range=kSharpYuvRangeLimited
+// Kr=0.2990f Kb=0.1140f bit_depth=8 range=kSharpYuvRangeLimited
 static const SharpYuvConversionMatrix kRec601LimitedMatrix = {
   {16829, 33039, 6416, 16 << 16},
   {-9714, -19071, 28784, 128 << 16},
   {28784, -24103, -4681, 128 << 16},
 };
-// Kr=0.2990f Kb=0.1140f bits=8 range=kSharpYuvRangeFull
+// Kr=0.2990f Kb=0.1140f bit_depth=8 range=kSharpYuvRangeFull
 static const SharpYuvConversionMatrix kRec601FullMatrix = {
   {19595, 38470, 7471, 0},
   {-11058, -21710, 32768, 128 << 16},
   {32768, -27439, -5329, 128 << 16},
 };
-// Kr=0.2126f Kb=0.0722f bits=8 range=kSharpYuvRangeLimited
+// Kr=0.2126f Kb=0.0722f bit_depth=8 range=kSharpYuvRangeLimited
 static const SharpYuvConversionMatrix kRec709LimitedMatrix = {
   {11966, 40254, 4064, 16 << 16},
   {-6596, -22189, 28784, 128 << 16},
   {28784, -26145, -2639, 128 << 16},
 };
-// Kr=0.2126f Kb=0.0722f bits=8 range=kSharpYuvRangeFull
+// Kr=0.2126f Kb=0.0722f bit_depth=8 range=kSharpYuvRangeFull
 static const SharpYuvConversionMatrix kRec709FullMatrix = {
   {13933, 46871, 4732, 0},
   {-7509, -25259, 32768, 128 << 16},
diff --git a/sharpyuv/sharpyuv_csp.h b/sharpyuv/sharpyuv_csp.h
index 3214e3ac..efc01053 100644
--- a/sharpyuv/sharpyuv_csp.h
+++ b/sharpyuv/sharpyuv_csp.h
@@ -41,10 +41,15 @@ SHARPYUV_EXTERN void SharpYuvComputeConversionMatrix(
 
 // Enums for precomputed conversion matrices.
 typedef enum {
+  // WebP's matrix, similar but not identical to kSharpYuvMatrixRec601Limited
   kSharpYuvMatrixWebp = 0,
+  // Kr=0.2990f Kb=0.1140f bit_depth=8 range=kSharpYuvRangeLimited
   kSharpYuvMatrixRec601Limited,
+  // Kr=0.2990f Kb=0.1140f bit_depth=8 range=kSharpYuvRangeFull
   kSharpYuvMatrixRec601Full,
+  // Kr=0.2126f Kb=0.0722f bit_depth=8 range=kSharpYuvRangeLimited
   kSharpYuvMatrixRec709Limited,
+  // Kr=0.2126f Kb=0.0722f bit_depth=8 range=kSharpYuvRangeFull
   kSharpYuvMatrixRec709Full,
   kSharpYuvMatrixNum
 } SharpYuvMatrixType;
diff --git a/src/Makefile.am b/src/Makefile.am
index 1dafadd1..b4473450 100644
--- a/src/Makefile.am
+++ b/src/Makefile.am
@@ -36,7 +36,7 @@ libwebp_la_LIBADD += utils/libwebputils.la
 # other than the ones listed on the command line, i.e., after linking, it will
 # not have unresolved symbols. Some platforms (Windows among them) require all
 # symbols in shared libraries to be resolved at library creation.
-libwebp_la_LDFLAGS = -no-undefined -version-info 8:9:1
+libwebp_la_LDFLAGS = -no-undefined -version-info 8:10:1
 libwebpincludedir = $(includedir)/webp
 pkgconfig_DATA = libwebp.pc
 
@@ -48,7 +48,7 @@ if BUILD_LIBWEBPDECODER
   libwebpdecoder_la_LIBADD += dsp/libwebpdspdecode.la
   libwebpdecoder_la_LIBADD += utils/libwebputilsdecode.la
 
-  libwebpdecoder_la_LDFLAGS = -no-undefined -version-info 4:9:1
+  libwebpdecoder_la_LDFLAGS = -no-undefined -version-info 4:10:1
   pkgconfig_DATA += libwebpdecoder.pc
 endif
 
diff --git a/src/dec/tree_dec.c b/src/dec/tree_dec.c
index 24346059..8093e78b 100644
--- a/src/dec/tree_dec.c
+++ b/src/dec/tree_dec.c
@@ -16,7 +16,8 @@
 #include "src/utils/bit_reader_inl_utils.h"
 
 #if !defined(USE_GENERIC_TREE)
-#if !defined(__arm__) && !defined(_M_ARM) && !WEBP_AARCH64
+#if !defined(__arm__) && !defined(_M_ARM) && !WEBP_AARCH64 && \
+    !defined(__wasm__)
 // using a table is ~1-2% slower on ARM. Prefer the coded-tree approach then.
 #define USE_GENERIC_TREE 1   // ALTERNATE_CODE
 #else
diff --git a/src/dec/vp8i_dec.h b/src/dec/vp8i_dec.h
index cb21d475..c07319e9 100644
--- a/src/dec/vp8i_dec.h
+++ b/src/dec/vp8i_dec.h
@@ -32,7 +32,7 @@ extern "C" {
 
 // version numbers
 #define DEC_MAJ_VERSION 1
-#define DEC_MIN_VERSION 4
+#define DEC_MIN_VERSION 5
 #define DEC_REV_VERSION 0
 
 // YUV-cache parameters. Cache is 32-bytes wide (= one cacheline).
diff --git a/src/dec/vp8l_dec.c b/src/dec/vp8l_dec.c
index 11c00ea9..d60f5892 100644
--- a/src/dec/vp8l_dec.c
+++ b/src/dec/vp8l_dec.c
@@ -20,10 +20,9 @@
 #include "src/dsp/dsp.h"
 #include "src/dsp/lossless.h"
 #include "src/dsp/lossless_common.h"
-#include "src/dsp/yuv.h"
-#include "src/utils/endian_inl_utils.h"
 #include "src/utils/huffman_utils.h"
 #include "src/utils/utils.h"
+#include "src/webp/format_constants.h"
 
 #define NUM_ARGB_CACHE_ROWS          16
 
@@ -381,7 +380,8 @@ static int ReadHuffmanCodes(VP8LDecoder* const dec, int xsize, int ysize,
 
   if (allow_recursion && VP8LReadBits(br, 1)) {
     // use meta Huffman codes.
-    const int huffman_precision = VP8LReadBits(br, 3) + 2;
+    const int huffman_precision =
+        MIN_HUFFMAN_BITS + VP8LReadBits(br, NUM_HUFFMAN_BITS);
     const int huffman_xsize = VP8LSubSampleSize(xsize, huffman_precision);
     const int huffman_ysize = VP8LSubSampleSize(ysize, huffman_precision);
     const int huffman_pixs = huffman_xsize * huffman_ysize;
@@ -1351,7 +1351,8 @@ static int ReadTransform(int* const xsize, int const* ysize,
   switch (type) {
     case PREDICTOR_TRANSFORM:
     case CROSS_COLOR_TRANSFORM:
-      transform->bits_ = VP8LReadBits(br, 3) + 2;
+      transform->bits_ =
+          MIN_TRANSFORM_BITS + VP8LReadBits(br, NUM_TRANSFORM_BITS);
       ok = DecodeImageStream(VP8LSubSampleSize(transform->xsize_,
                                                transform->bits_),
                              VP8LSubSampleSize(transform->ysize_,
@@ -1416,7 +1417,9 @@ VP8LDecoder* VP8LNew(void) {
   return dec;
 }
 
-void VP8LClear(VP8LDecoder* const dec) {
+// Resets the decoder in its initial state, reclaiming memory.
+// Preserves the dec->status_ value.
+static void VP8LClear(VP8LDecoder* const dec) {
   int i;
   if (dec == NULL) return;
   ClearMetadata(&dec->hdr_);
diff --git a/src/dec/vp8li_dec.h b/src/dec/vp8li_dec.h
index 9a13bcc9..6f95b357 100644
--- a/src/dec/vp8li_dec.h
+++ b/src/dec/vp8li_dec.h
@@ -121,10 +121,6 @@ WEBP_NODISCARD int VP8LDecodeHeader(VP8LDecoder* const dec, VP8Io* const io);
 // this function. Returns false in case of error, with updated dec->status_.
 WEBP_NODISCARD int VP8LDecodeImage(VP8LDecoder* const dec);
 
-// Resets the decoder in its initial state, reclaiming memory.
-// Preserves the dec->status_ value.
-void VP8LClear(VP8LDecoder* const dec);
-
 // Clears and deallocate a lossless decoder instance.
 void VP8LDelete(VP8LDecoder* const dec);
 
diff --git a/src/demux/Makefile.am b/src/demux/Makefile.am
index 9ecff146..30ecd0e7 100644
--- a/src/demux/Makefile.am
+++ b/src/demux/Makefile.am
@@ -13,6 +13,6 @@ noinst_HEADERS =
 noinst_HEADERS += ../webp/format_constants.h
 
 libwebpdemux_la_LIBADD = ../libwebp.la
-libwebpdemux_la_LDFLAGS = -no-undefined -version-info 2:15:0
+libwebpdemux_la_LDFLAGS = -no-undefined -version-info 2:16:0
 libwebpdemuxincludedir = $(includedir)/webp
 pkgconfig_DATA = libwebpdemux.pc
diff --git a/src/demux/demux.c b/src/demux/demux.c
index d01c6a74..37d35c6d 100644
--- a/src/demux/demux.c
+++ b/src/demux/demux.c
@@ -24,7 +24,7 @@
 #include "src/webp/format_constants.h"
 
 #define DMUX_MAJ_VERSION 1
-#define DMUX_MIN_VERSION 4
+#define DMUX_MIN_VERSION 5
 #define DMUX_REV_VERSION 0
 
 typedef struct {
diff --git a/src/demux/libwebpdemux.rc b/src/demux/libwebpdemux.rc
index bc57c408..f01ad2ac 100644
--- a/src/demux/libwebpdemux.rc
+++ b/src/demux/libwebpdemux.rc
@@ -6,8 +6,8 @@
 LANGUAGE LANG_ENGLISH, SUBLANG_ENGLISH_US
 
 VS_VERSION_INFO VERSIONINFO
- FILEVERSION 1,0,4,0
- PRODUCTVERSION 1,0,4,0
+ FILEVERSION 1,0,5,0
+ PRODUCTVERSION 1,0,5,0
  FILEFLAGSMASK 0x3fL
 #ifdef _DEBUG
  FILEFLAGS 0x1L
@@ -24,12 +24,12 @@ BEGIN
         BEGIN
             VALUE "CompanyName", "Google, Inc."
             VALUE "FileDescription", "libwebpdemux DLL"
-            VALUE "FileVersion", "1.4.0"
+            VALUE "FileVersion", "1.5.0"
             VALUE "InternalName", "libwebpdemux.dll"
             VALUE "LegalCopyright", "Copyright (C) 2024"
             VALUE "OriginalFilename", "libwebpdemux.dll"
             VALUE "ProductName", "WebP Image Demuxer"
-            VALUE "ProductVersion", "1.4.0"
+            VALUE "ProductVersion", "1.5.0"
         END
     END
     BLOCK "VarFileInfo"
diff --git a/src/dsp/cost.c b/src/dsp/cost.c
index 73d21401..609f9264 100644
--- a/src/dsp/cost.c
+++ b/src/dsp/cost.c
@@ -354,8 +354,8 @@ static int GetResidualCost_C(int ctx0, const VP8Residual* const res) {
   return cost;
 }
 
-static void SetResidualCoeffs_C(const int16_t* const coeffs,
-                                VP8Residual* const res) {
+static void SetResidualCoeffs_C(const int16_t* WEBP_RESTRICT const coeffs,
+                                VP8Residual* WEBP_RESTRICT const res) {
   int n;
   res->last = -1;
   assert(res->first == 0 || coeffs[0] == 0);
diff --git a/src/dsp/cost_mips32.c b/src/dsp/cost_mips32.c
index 0500f88c..54586576 100644
--- a/src/dsp/cost_mips32.c
+++ b/src/dsp/cost_mips32.c
@@ -96,8 +96,8 @@ static int GetResidualCost_MIPS32(int ctx0, const VP8Residual* const res) {
   return cost;
 }
 
-static void SetResidualCoeffs_MIPS32(const int16_t* const coeffs,
-                                     VP8Residual* const res) {
+static void SetResidualCoeffs_MIPS32(const int16_t* WEBP_RESTRICT const coeffs,
+                                     VP8Residual* WEBP_RESTRICT const res) {
   const int16_t* p_coeffs = (int16_t*)coeffs;
   int temp0, temp1, temp2, n, n1;
   assert(res->first == 0 || coeffs[0] == 0);
diff --git a/src/dsp/cost_neon.c b/src/dsp/cost_neon.c
index 6582669c..e1bf3657 100644
--- a/src/dsp/cost_neon.c
+++ b/src/dsp/cost_neon.c
@@ -19,8 +19,8 @@
 static const uint8_t position[16] = { 1, 2,  3,  4,  5,  6,  7,  8,
                                       9, 10, 11, 12, 13, 14, 15, 16 };
 
-static void SetResidualCoeffs_NEON(const int16_t* const coeffs,
-                                   VP8Residual* const res) {
+static void SetResidualCoeffs_NEON(const int16_t* WEBP_RESTRICT const coeffs,
+                                   VP8Residual* WEBP_RESTRICT const res) {
   const int16x8_t minus_one = vdupq_n_s16(-1);
   const int16x8_t coeffs_0 = vld1q_s16(coeffs);
   const int16x8_t coeffs_1 = vld1q_s16(coeffs + 8);
diff --git a/src/dsp/cost_sse2.c b/src/dsp/cost_sse2.c
index 487a0799..a869b48d 100644
--- a/src/dsp/cost_sse2.c
+++ b/src/dsp/cost_sse2.c
@@ -22,8 +22,8 @@
 
 //------------------------------------------------------------------------------
 
-static void SetResidualCoeffs_SSE2(const int16_t* const coeffs,
-                                   VP8Residual* const res) {
+static void SetResidualCoeffs_SSE2(const int16_t* WEBP_RESTRICT const coeffs,
+                                   VP8Residual* WEBP_RESTRICT const res) {
   const __m128i c0 = _mm_loadu_si128((const __m128i*)(coeffs + 0));
   const __m128i c1 = _mm_loadu_si128((const __m128i*)(coeffs + 8));
   // Use SSE2 to compare 16 values with a single instruction.
diff --git a/src/dsp/dec.c b/src/dsp/dec.c
index 451d649d..dc1a7625 100644
--- a/src/dsp/dec.c
+++ b/src/dsp/dec.c
@@ -38,7 +38,8 @@ static WEBP_INLINE uint8_t clip_8b(int v) {
 } while (0)
 
 #if !WEBP_NEON_OMIT_C_CODE
-static void TransformOne_C(const int16_t* in, uint8_t* dst) {
+static void TransformOne_C(const int16_t* WEBP_RESTRICT in,
+                           uint8_t* WEBP_RESTRICT dst) {
   int C[4 * 4], *tmp;
   int i;
   tmp = C;
@@ -82,7 +83,8 @@ static void TransformOne_C(const int16_t* in, uint8_t* dst) {
 }
 
 // Simplified transform when only in[0], in[1] and in[4] are non-zero
-static void TransformAC3_C(const int16_t* in, uint8_t* dst) {
+static void TransformAC3_C(const int16_t* WEBP_RESTRICT in,
+                           uint8_t* WEBP_RESTRICT dst) {
   const int a = in[0] + 4;
   const int c4 = WEBP_TRANSFORM_AC3_MUL2(in[4]);
   const int d4 = WEBP_TRANSFORM_AC3_MUL1(in[4]);
@@ -95,7 +97,8 @@ static void TransformAC3_C(const int16_t* in, uint8_t* dst) {
 }
 #undef STORE2
 
-static void TransformTwo_C(const int16_t* in, uint8_t* dst, int do_two) {
+static void TransformTwo_C(const int16_t* WEBP_RESTRICT in,
+                           uint8_t* WEBP_RESTRICT dst, int do_two) {
   TransformOne_C(in, dst);
   if (do_two) {
     TransformOne_C(in + 16, dst + 4);
@@ -103,13 +106,15 @@ static void TransformTwo_C(const int16_t* in, uint8_t* dst, int do_two) {
 }
 #endif  // !WEBP_NEON_OMIT_C_CODE
 
-static void TransformUV_C(const int16_t* in, uint8_t* dst) {
+static void TransformUV_C(const int16_t* WEBP_RESTRICT in,
+                          uint8_t* WEBP_RESTRICT dst) {
   VP8Transform(in + 0 * 16, dst, 1);
   VP8Transform(in + 2 * 16, dst + 4 * BPS, 1);
 }
 
 #if !WEBP_NEON_OMIT_C_CODE
-static void TransformDC_C(const int16_t* in, uint8_t* dst) {
+static void TransformDC_C(const int16_t* WEBP_RESTRICT in,
+                          uint8_t* WEBP_RESTRICT dst) {
   const int DC = in[0] + 4;
   int i, j;
   for (j = 0; j < 4; ++j) {
@@ -120,7 +125,8 @@ static void TransformDC_C(const int16_t* in, uint8_t* dst) {
 }
 #endif  // !WEBP_NEON_OMIT_C_CODE
 
-static void TransformDCUV_C(const int16_t* in, uint8_t* dst) {
+static void TransformDCUV_C(const int16_t* WEBP_RESTRICT in,
+                            uint8_t* WEBP_RESTRICT dst) {
   if (in[0 * 16]) VP8TransformDC(in + 0 * 16, dst);
   if (in[1 * 16]) VP8TransformDC(in + 1 * 16, dst + 4);
   if (in[2 * 16]) VP8TransformDC(in + 2 * 16, dst + 4 * BPS);
@@ -133,7 +139,8 @@ static void TransformDCUV_C(const int16_t* in, uint8_t* dst) {
 // Paragraph 14.3
 
 #if !WEBP_NEON_OMIT_C_CODE
-static void TransformWHT_C(const int16_t* in, int16_t* out) {
+static void TransformWHT_C(const int16_t* WEBP_RESTRICT in,
+                           int16_t* WEBP_RESTRICT out) {
   int tmp[16];
   int i;
   for (i = 0; i < 4; ++i) {
@@ -161,7 +168,7 @@ static void TransformWHT_C(const int16_t* in, int16_t* out) {
 }
 #endif  // !WEBP_NEON_OMIT_C_CODE
 
-void (*VP8TransformWHT)(const int16_t* in, int16_t* out);
+VP8WHT VP8TransformWHT;
 
 //------------------------------------------------------------------------------
 // Intra predictions
@@ -661,32 +668,32 @@ static void HFilter16i_C(uint8_t* p, int stride,
 
 #if !WEBP_NEON_OMIT_C_CODE
 // 8-pixels wide variant, for chroma filtering
-static void VFilter8_C(uint8_t* u, uint8_t* v, int stride,
-                       int thresh, int ithresh, int hev_thresh) {
+static void VFilter8_C(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                       int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop26_C(u, stride, 1, 8, thresh, ithresh, hev_thresh);
   FilterLoop26_C(v, stride, 1, 8, thresh, ithresh, hev_thresh);
 }
 #endif  // !WEBP_NEON_OMIT_C_CODE
 
 #if !WEBP_NEON_OMIT_C_CODE || WEBP_NEON_WORK_AROUND_GCC
-static void HFilter8_C(uint8_t* u, uint8_t* v, int stride,
-                       int thresh, int ithresh, int hev_thresh) {
+static void HFilter8_C(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                       int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop26_C(u, 1, stride, 8, thresh, ithresh, hev_thresh);
   FilterLoop26_C(v, 1, stride, 8, thresh, ithresh, hev_thresh);
 }
 #endif  // !WEBP_NEON_OMIT_C_CODE || WEBP_NEON_WORK_AROUND_GCC
 
 #if !WEBP_NEON_OMIT_C_CODE
-static void VFilter8i_C(uint8_t* u, uint8_t* v, int stride,
-                        int thresh, int ithresh, int hev_thresh) {
+static void VFilter8i_C(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                        int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop24_C(u + 4 * stride, stride, 1, 8, thresh, ithresh, hev_thresh);
   FilterLoop24_C(v + 4 * stride, stride, 1, 8, thresh, ithresh, hev_thresh);
 }
 #endif  // !WEBP_NEON_OMIT_C_CODE
 
 #if !WEBP_NEON_OMIT_C_CODE || WEBP_NEON_WORK_AROUND_GCC
-static void HFilter8i_C(uint8_t* u, uint8_t* v, int stride,
-                        int thresh, int ithresh, int hev_thresh) {
+static void HFilter8i_C(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                        int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop24_C(u + 4, 1, stride, 8, thresh, ithresh, hev_thresh);
   FilterLoop24_C(v + 4, 1, stride, 8, thresh, ithresh, hev_thresh);
 }
@@ -694,8 +701,8 @@ static void HFilter8i_C(uint8_t* u, uint8_t* v, int stride,
 
 //------------------------------------------------------------------------------
 
-static void DitherCombine8x8_C(const uint8_t* dither, uint8_t* dst,
-                               int dst_stride) {
+static void DitherCombine8x8_C(const uint8_t* WEBP_RESTRICT dither,
+                               uint8_t* WEBP_RESTRICT dst, int dst_stride) {
   int i, j;
   for (j = 0; j < 8; ++j) {
     for (i = 0; i < 8; ++i) {
@@ -730,8 +737,8 @@ VP8SimpleFilterFunc VP8SimpleHFilter16;
 VP8SimpleFilterFunc VP8SimpleVFilter16i;
 VP8SimpleFilterFunc VP8SimpleHFilter16i;
 
-void (*VP8DitherCombine8x8)(const uint8_t* dither, uint8_t* dst,
-                            int dst_stride);
+void (*VP8DitherCombine8x8)(const uint8_t* WEBP_RESTRICT dither,
+                            uint8_t* WEBP_RESTRICT dst, int dst_stride);
 
 extern VP8CPUInfo VP8GetCPUInfo;
 extern void VP8DspInitSSE2(void);
diff --git a/src/dsp/dec_mips32.c b/src/dsp/dec_mips32.c
index f0e7de4a..89fe9009 100644
--- a/src/dsp/dec_mips32.c
+++ b/src/dsp/dec_mips32.c
@@ -133,26 +133,26 @@ static void HFilter16(uint8_t* p, int stride,
 }
 
 // 8-pixels wide variant, for chroma filtering
-static void VFilter8(uint8_t* u, uint8_t* v, int stride,
-                     int thresh, int ithresh, int hev_thresh) {
+static void VFilter8(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                     int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop26(u, stride, 1, 8, thresh, ithresh, hev_thresh);
   FilterLoop26(v, stride, 1, 8, thresh, ithresh, hev_thresh);
 }
 
-static void HFilter8(uint8_t* u, uint8_t* v, int stride,
-                     int thresh, int ithresh, int hev_thresh) {
+static void HFilter8(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                     int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop26(u, 1, stride, 8, thresh, ithresh, hev_thresh);
   FilterLoop26(v, 1, stride, 8, thresh, ithresh, hev_thresh);
 }
 
-static void VFilter8i(uint8_t* u, uint8_t* v, int stride,
-                      int thresh, int ithresh, int hev_thresh) {
+static void VFilter8i(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                      int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop24(u + 4 * stride, stride, 1, 8, thresh, ithresh, hev_thresh);
   FilterLoop24(v + 4 * stride, stride, 1, 8, thresh, ithresh, hev_thresh);
 }
 
-static void HFilter8i(uint8_t* u, uint8_t* v, int stride,
-                      int thresh, int ithresh, int hev_thresh) {
+static void HFilter8i(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                      int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop24(u + 4, 1, stride, 8, thresh, ithresh, hev_thresh);
   FilterLoop24(v + 4, 1, stride, 8, thresh, ithresh, hev_thresh);
 }
@@ -215,7 +215,8 @@ static void SimpleHFilter16i(uint8_t* p, int stride, int thresh) {
   }
 }
 
-static void TransformOne(const int16_t* in, uint8_t* dst) {
+static void TransformOne(const int16_t* WEBP_RESTRICT in,
+                         uint8_t* WEBP_RESTRICT dst) {
   int temp0, temp1, temp2, temp3, temp4;
   int temp5, temp6, temp7, temp8, temp9;
   int temp10, temp11, temp12, temp13, temp14;
@@ -532,7 +533,8 @@ static void TransformOne(const int16_t* in, uint8_t* dst) {
   );
 }
 
-static void TransformTwo(const int16_t* in, uint8_t* dst, int do_two) {
+static void TransformTwo(const int16_t* WEBP_RESTRICT in,
+                         uint8_t* WEBP_RESTRICT dst, int do_two) {
   TransformOne(in, dst);
   if (do_two) {
     TransformOne(in + 16, dst + 4);
diff --git a/src/dsp/dec_mips_dsp_r2.c b/src/dsp/dec_mips_dsp_r2.c
index 0ba706a2..03b5f122 100644
--- a/src/dsp/dec_mips_dsp_r2.c
+++ b/src/dsp/dec_mips_dsp_r2.c
@@ -21,7 +21,8 @@
 static const int kC1 = WEBP_TRANSFORM_AC3_C1;
 static const int kC2 = WEBP_TRANSFORM_AC3_C2;
 
-static void TransformDC(const int16_t* in, uint8_t* dst) {
+static void TransformDC(const int16_t* WEBP_RESTRICT in,
+                        uint8_t* WEBP_RESTRICT dst) {
   int temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8, temp9, temp10;
 
   __asm__ volatile (
@@ -45,7 +46,8 @@ static void TransformDC(const int16_t* in, uint8_t* dst) {
   );
 }
 
-static void TransformAC3(const int16_t* in, uint8_t* dst) {
+static void TransformAC3(const int16_t* WEBP_RESTRICT in,
+                         uint8_t* WEBP_RESTRICT dst) {
   const int a = in[0] + 4;
   int c4 = WEBP_TRANSFORM_AC3_MUL2(in[4]);
   const int d4 = WEBP_TRANSFORM_AC3_MUL1(in[4]);
@@ -81,7 +83,8 @@ static void TransformAC3(const int16_t* in, uint8_t* dst) {
   );
 }
 
-static void TransformOne(const int16_t* in, uint8_t* dst) {
+static void TransformOne(const int16_t* WEBP_RESTRICT in,
+                         uint8_t* WEBP_RESTRICT dst) {
   int temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8, temp9;
   int temp10, temp11, temp12, temp13, temp14, temp15, temp16, temp17, temp18;
 
@@ -148,7 +151,8 @@ static void TransformOne(const int16_t* in, uint8_t* dst) {
   );
 }
 
-static void TransformTwo(const int16_t* in, uint8_t* dst, int do_two) {
+static void TransformTwo(const int16_t* WEBP_RESTRICT in,
+                         uint8_t* WEBP_RESTRICT dst, int do_two) {
   TransformOne(in, dst);
   if (do_two) {
     TransformOne(in + 16, dst + 4);
@@ -434,14 +438,14 @@ static void HFilter16(uint8_t* p, int stride,
 }
 
 // 8-pixels wide variant, for chroma filtering
-static void VFilter8(uint8_t* u, uint8_t* v, int stride,
-                     int thresh, int ithresh, int hev_thresh) {
+static void VFilter8(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                     int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop26(u, stride, 1, 8, thresh, ithresh, hev_thresh);
   FilterLoop26(v, stride, 1, 8, thresh, ithresh, hev_thresh);
 }
 
-static void HFilter8(uint8_t* u, uint8_t* v, int stride,
-                     int thresh, int ithresh, int hev_thresh) {
+static void HFilter8(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                     int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop26(u, 1, stride, 8, thresh, ithresh, hev_thresh);
   FilterLoop26(v, 1, stride, 8, thresh, ithresh, hev_thresh);
 }
@@ -465,14 +469,14 @@ static void HFilter16i(uint8_t* p, int stride,
   }
 }
 
-static void VFilter8i(uint8_t* u, uint8_t* v, int stride,
-                      int thresh, int ithresh, int hev_thresh) {
+static void VFilter8i(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                      int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop24(u + 4 * stride, stride, 1, 8, thresh, ithresh, hev_thresh);
   FilterLoop24(v + 4 * stride, stride, 1, 8, thresh, ithresh, hev_thresh);
 }
 
-static void HFilter8i(uint8_t* u, uint8_t* v, int stride,
-                      int thresh, int ithresh, int hev_thresh) {
+static void HFilter8i(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                      int stride, int thresh, int ithresh, int hev_thresh) {
   FilterLoop24(u + 4, 1, stride, 8, thresh, ithresh, hev_thresh);
   FilterLoop24(v + 4, 1, stride, 8, thresh, ithresh, hev_thresh);
 }
diff --git a/src/dsp/dec_msa.c b/src/dsp/dec_msa.c
index 58d17301..422b3632 100644
--- a/src/dsp/dec_msa.c
+++ b/src/dsp/dec_msa.c
@@ -38,7 +38,8 @@
   BUTTERFLY_4(a1_m, b1_m, c1_m, d1_m, out0, out1, out2, out3);   \
 }
 
-static void TransformOne(const int16_t* in, uint8_t* dst) {
+static void TransformOne(const int16_t* WEBP_RESTRICT in,
+                         uint8_t* WEBP_RESTRICT dst) {
   v8i16 input0, input1;
   v4i32 in0, in1, in2, in3, hz0, hz1, hz2, hz3, vt0, vt1, vt2, vt3;
   v4i32 res0, res1, res2, res3;
@@ -65,14 +66,16 @@ static void TransformOne(const int16_t* in, uint8_t* dst) {
   ST4x4_UB(res0, res0, 3, 2, 1, 0, dst, BPS);
 }
 
-static void TransformTwo(const int16_t* in, uint8_t* dst, int do_two) {
+static void TransformTwo(const int16_t* WEBP_RESTRICT in,
+                         uint8_t* WEBP_RESTRICT dst, int do_two) {
   TransformOne(in, dst);
   if (do_two) {
     TransformOne(in + 16, dst + 4);
   }
 }
 
-static void TransformWHT(const int16_t* in, int16_t* out) {
+static void TransformWHT(const int16_t* WEBP_RESTRICT in,
+                         int16_t* WEBP_RESTRICT out) {
   v8i16 input0, input1;
   const v8i16 mask0 = { 0, 1, 2, 3, 8, 9, 10, 11 };
   const v8i16 mask1 = { 4, 5, 6, 7, 12, 13, 14, 15 };
@@ -114,13 +117,15 @@ static void TransformWHT(const int16_t* in, int16_t* out) {
   out[240] = __msa_copy_s_h(out1, 7);
 }
 
-static void TransformDC(const int16_t* in, uint8_t* dst) {
+static void TransformDC(const int16_t* WEBP_RESTRICT in,
+                        uint8_t* WEBP_RESTRICT dst) {
   const int DC = (in[0] + 4) >> 3;
   const v8i16 tmp0 = __msa_fill_h(DC);
   ADDBLK_ST4x4_UB(tmp0, tmp0, tmp0, tmp0, dst, BPS);
 }
 
-static void TransformAC3(const int16_t* in, uint8_t* dst) {
+static void TransformAC3(const int16_t* WEBP_RESTRICT in,
+                         uint8_t* WEBP_RESTRICT dst) {
   const int a = in[0] + 4;
   const int c4 = WEBP_TRANSFORM_AC3_MUL2(in[4]);
   const int d4 = WEBP_TRANSFORM_AC3_MUL1(in[4]);
@@ -475,8 +480,8 @@ static void HFilter16i(uint8_t* src_y, int stride,
 }
 
 // 8-pixels wide variants, for chroma filtering
-static void VFilter8(uint8_t* src_u, uint8_t* src_v, int stride,
-                     int b_limit_in, int limit_in, int thresh_in) {
+static void VFilter8(uint8_t* WEBP_RESTRICT src_u, uint8_t* WEBP_RESTRICT src_v,
+                     int stride, int b_limit_in, int limit_in, int thresh_in) {
   uint8_t* ptmp_src_u = src_u - 4 * stride;
   uint8_t* ptmp_src_v = src_v - 4 * stride;
   uint64_t p2_d, p1_d, p0_d, q0_d, q1_d, q2_d;
@@ -520,8 +525,8 @@ static void VFilter8(uint8_t* src_u, uint8_t* src_v, int stride,
   SD(q2_d, ptmp_src_v);
 }
 
-static void HFilter8(uint8_t* src_u, uint8_t* src_v, int stride,
-                     int b_limit_in, int limit_in, int thresh_in) {
+static void HFilter8(uint8_t* WEBP_RESTRICT src_u, uint8_t* WEBP_RESTRICT src_v,
+                     int stride, int b_limit_in, int limit_in, int thresh_in) {
   uint8_t* ptmp_src_u = src_u - 4;
   uint8_t* ptmp_src_v = src_v - 4;
   v16u8 p3, p2, p1, p0, q3, q2, q1, q0, mask, hev;
@@ -556,7 +561,8 @@ static void HFilter8(uint8_t* src_u, uint8_t* src_v, int stride,
   ST6x4_UB(tmp7, 0, tmp5, 4, ptmp_src_v, stride);
 }
 
-static void VFilter8i(uint8_t* src_u, uint8_t* src_v, int stride,
+static void VFilter8i(uint8_t* WEBP_RESTRICT src_u,
+                      uint8_t* WEBP_RESTRICT src_v, int stride,
                       int b_limit_in, int limit_in, int thresh_in) {
   uint64_t p1_d, p0_d, q0_d, q1_d;
   v16u8 p3, p2, p1, p0, q3, q2, q1, q0, mask, hev;
@@ -587,7 +593,8 @@ static void VFilter8i(uint8_t* src_u, uint8_t* src_v, int stride,
   SD4(q1_d, q0_d, p0_d, p1_d, src_v, -stride);
 }
 
-static void HFilter8i(uint8_t* src_u, uint8_t* src_v, int stride,
+static void HFilter8i(uint8_t* WEBP_RESTRICT src_u,
+                      uint8_t* WEBP_RESTRICT src_v, int stride,
                       int b_limit_in, int limit_in, int thresh_in) {
   v16u8 p3, p2, p1, p0, q3, q2, q1, q0, mask, hev;
   v16u8 row0, row1, row2, row3, row4, row5, row6, row7, row8;
diff --git a/src/dsp/dec_neon.c b/src/dsp/dec_neon.c
index 83b3a1f9..f150692a 100644
--- a/src/dsp/dec_neon.c
+++ b/src/dsp/dec_neon.c
@@ -916,8 +916,8 @@ static void HFilter16i_NEON(uint8_t* p, int stride,
 #endif  // !WORK_AROUND_GCC
 
 // 8-pixels wide variant, for chroma filtering
-static void VFilter8_NEON(uint8_t* u, uint8_t* v, int stride,
-                          int thresh, int ithresh, int hev_thresh) {
+static void VFilter8_NEON(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                          int stride, int thresh, int ithresh, int hev_thresh) {
   uint8x16_t p3, p2, p1, p0, q0, q1, q2, q3;
   Load8x8x2_NEON(u, v, stride, &p3, &p2, &p1, &p0, &q0, &q1, &q2, &q3);
   {
@@ -932,7 +932,8 @@ static void VFilter8_NEON(uint8_t* u, uint8_t* v, int stride,
     Store8x2x2_NEON(oq1, oq2, u + 2 * stride, v + 2 * stride, stride);
   }
 }
-static void VFilter8i_NEON(uint8_t* u, uint8_t* v, int stride,
+static void VFilter8i_NEON(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                           int stride,
                            int thresh, int ithresh, int hev_thresh) {
   uint8x16_t p3, p2, p1, p0, q0, q1, q2, q3;
   u += 4 * stride;
@@ -949,8 +950,8 @@ static void VFilter8i_NEON(uint8_t* u, uint8_t* v, int stride,
 }
 
 #if !defined(WORK_AROUND_GCC)
-static void HFilter8_NEON(uint8_t* u, uint8_t* v, int stride,
-                          int thresh, int ithresh, int hev_thresh) {
+static void HFilter8_NEON(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                          int stride, int thresh, int ithresh, int hev_thresh) {
   uint8x16_t p3, p2, p1, p0, q0, q1, q2, q3;
   Load8x8x2T_NEON(u, v, stride, &p3, &p2, &p1, &p0, &q0, &q1, &q2, &q3);
   {
@@ -964,7 +965,8 @@ static void HFilter8_NEON(uint8_t* u, uint8_t* v, int stride,
   }
 }
 
-static void HFilter8i_NEON(uint8_t* u, uint8_t* v, int stride,
+static void HFilter8i_NEON(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                           int stride,
                            int thresh, int ithresh, int hev_thresh) {
   uint8x16_t p3, p2, p1, p0, q0, q1, q2, q3;
   u += 4;
@@ -1041,7 +1043,8 @@ static WEBP_INLINE void TransformPass_NEON(int16x8x2_t* const rows) {
   Transpose8x2_NEON(E0, E1, rows);
 }
 
-static void TransformOne_NEON(const int16_t* in, uint8_t* dst) {
+static void TransformOne_NEON(const int16_t* WEBP_RESTRICT in,
+                              uint8_t* WEBP_RESTRICT dst) {
   int16x8x2_t rows;
   INIT_VECTOR2(rows, vld1q_s16(in + 0), vld1q_s16(in + 8));
   TransformPass_NEON(&rows);
@@ -1051,7 +1054,8 @@ static void TransformOne_NEON(const int16_t* in, uint8_t* dst) {
 
 #else
 
-static void TransformOne_NEON(const int16_t* in, uint8_t* dst) {
+static void TransformOne_NEON(const int16_t* WEBP_RESTRICT in,
+                              uint8_t* WEBP_RESTRICT dst) {
   const int kBPS = BPS;
   // kC1, kC2. Padded because vld1.16 loads 8 bytes
   const int16_t constants[4] = { kC1, kC2, 0, 0 };
@@ -1184,14 +1188,16 @@ static void TransformOne_NEON(const int16_t* in, uint8_t* dst) {
 
 #endif    // WEBP_USE_INTRINSICS
 
-static void TransformTwo_NEON(const int16_t* in, uint8_t* dst, int do_two) {
+static void TransformTwo_NEON(const int16_t* WEBP_RESTRICT in,
+                              uint8_t* WEBP_RESTRICT dst, int do_two) {
   TransformOne_NEON(in, dst);
   if (do_two) {
     TransformOne_NEON(in + 16, dst + 4);
   }
 }
 
-static void TransformDC_NEON(const int16_t* in, uint8_t* dst) {
+static void TransformDC_NEON(const int16_t* WEBP_RESTRICT in,
+                             uint8_t* WEBP_RESTRICT dst) {
   const int16x8_t DC = vdupq_n_s16(in[0]);
   Add4x4_NEON(DC, DC, dst);
 }
@@ -1205,7 +1211,8 @@ static void TransformDC_NEON(const int16_t* in, uint8_t* dst) {
   *dst = vgetq_lane_s32(rows.val[3], col); (dst) += 16; \
 } while (0)
 
-static void TransformWHT_NEON(const int16_t* in, int16_t* out) {
+static void TransformWHT_NEON(const int16_t* WEBP_RESTRICT in,
+                              int16_t* WEBP_RESTRICT out) {
   int32x4x4_t tmp;
 
   {
@@ -1256,7 +1263,8 @@ static void TransformWHT_NEON(const int16_t* in, int16_t* out) {
 
 //------------------------------------------------------------------------------
 
-static void TransformAC3_NEON(const int16_t* in, uint8_t* dst) {
+static void TransformAC3_NEON(const int16_t* WEBP_RESTRICT in,
+                              uint8_t* WEBP_RESTRICT dst) {
   const int16x4_t A = vld1_dup_s16(in);
   const int16x4_t c4 = vdup_n_s16(WEBP_TRANSFORM_AC3_MUL2(in[4]));
   const int16x4_t d4 = vdup_n_s16(WEBP_TRANSFORM_AC3_MUL1(in[4]));
@@ -1300,18 +1308,19 @@ static void DC4_NEON(uint8_t* dst) {    // DC
 static WEBP_INLINE void TrueMotion_NEON(uint8_t* dst, int size) {
   const uint8x8_t TL = vld1_dup_u8(dst - BPS - 1);  // top-left pixel 'A[-1]'
   const uint8x8_t T = vld1_u8(dst - BPS);  // top row 'A[0..3]'
-  const int16x8_t d = vreinterpretq_s16_u16(vsubl_u8(T, TL));  // A[c] - A[-1]
+  const uint16x8_t d = vsubl_u8(T, TL);  // A[c] - A[-1]
   int y;
   for (y = 0; y < size; y += 4) {
     // left edge
-    const int16x8_t L0 = ConvertU8ToS16_NEON(vld1_dup_u8(dst + 0 * BPS - 1));
-    const int16x8_t L1 = ConvertU8ToS16_NEON(vld1_dup_u8(dst + 1 * BPS - 1));
-    const int16x8_t L2 = ConvertU8ToS16_NEON(vld1_dup_u8(dst + 2 * BPS - 1));
-    const int16x8_t L3 = ConvertU8ToS16_NEON(vld1_dup_u8(dst + 3 * BPS - 1));
-    const int16x8_t r0 = vaddq_s16(L0, d);  // L[r] + A[c] - A[-1]
-    const int16x8_t r1 = vaddq_s16(L1, d);
-    const int16x8_t r2 = vaddq_s16(L2, d);
-    const int16x8_t r3 = vaddq_s16(L3, d);
+    const uint8x8_t L0 = vld1_dup_u8(dst + 0 * BPS - 1);
+    const uint8x8_t L1 = vld1_dup_u8(dst + 1 * BPS - 1);
+    const uint8x8_t L2 = vld1_dup_u8(dst + 2 * BPS - 1);
+    const uint8x8_t L3 = vld1_dup_u8(dst + 3 * BPS - 1);
+    // L[r] + A[c] - A[-1]
+    const int16x8_t r0 = vreinterpretq_s16_u16(vaddw_u8(d, L0));
+    const int16x8_t r1 = vreinterpretq_s16_u16(vaddw_u8(d, L1));
+    const int16x8_t r2 = vreinterpretq_s16_u16(vaddw_u8(d, L2));
+    const int16x8_t r3 = vreinterpretq_s16_u16(vaddw_u8(d, L3));
     // Saturate and store the result.
     const uint32x2_t r0_u32 = vreinterpret_u32_u8(vqmovun_s16(r0));
     const uint32x2_t r1_u32 = vreinterpret_u32_u8(vqmovun_s16(r1));
@@ -1572,23 +1581,24 @@ static void TM16_NEON(uint8_t* dst) {
   const uint8x8_t TL = vld1_dup_u8(dst - BPS - 1);  // top-left pixel 'A[-1]'
   const uint8x16_t T = vld1q_u8(dst - BPS);  // top row 'A[0..15]'
   // A[c] - A[-1]
-  const int16x8_t d_lo = vreinterpretq_s16_u16(vsubl_u8(vget_low_u8(T), TL));
-  const int16x8_t d_hi = vreinterpretq_s16_u16(vsubl_u8(vget_high_u8(T), TL));
+  const uint16x8_t d_lo = vsubl_u8(vget_low_u8(T), TL);
+  const uint16x8_t d_hi = vsubl_u8(vget_high_u8(T), TL);
   int y;
   for (y = 0; y < 16; y += 4) {
     // left edge
-    const int16x8_t L0 = ConvertU8ToS16_NEON(vld1_dup_u8(dst + 0 * BPS - 1));
-    const int16x8_t L1 = ConvertU8ToS16_NEON(vld1_dup_u8(dst + 1 * BPS - 1));
-    const int16x8_t L2 = ConvertU8ToS16_NEON(vld1_dup_u8(dst + 2 * BPS - 1));
-    const int16x8_t L3 = ConvertU8ToS16_NEON(vld1_dup_u8(dst + 3 * BPS - 1));
-    const int16x8_t r0_lo = vaddq_s16(L0, d_lo);  // L[r] + A[c] - A[-1]
-    const int16x8_t r1_lo = vaddq_s16(L1, d_lo);
-    const int16x8_t r2_lo = vaddq_s16(L2, d_lo);
-    const int16x8_t r3_lo = vaddq_s16(L3, d_lo);
-    const int16x8_t r0_hi = vaddq_s16(L0, d_hi);
-    const int16x8_t r1_hi = vaddq_s16(L1, d_hi);
-    const int16x8_t r2_hi = vaddq_s16(L2, d_hi);
-    const int16x8_t r3_hi = vaddq_s16(L3, d_hi);
+    const uint8x8_t L0 = vld1_dup_u8(dst + 0 * BPS - 1);
+    const uint8x8_t L1 = vld1_dup_u8(dst + 1 * BPS - 1);
+    const uint8x8_t L2 = vld1_dup_u8(dst + 2 * BPS - 1);
+    const uint8x8_t L3 = vld1_dup_u8(dst + 3 * BPS - 1);
+    // L[r] + A[c] - A[-1]
+    const int16x8_t r0_lo = vreinterpretq_s16_u16(vaddw_u8(d_lo, L0));
+    const int16x8_t r1_lo = vreinterpretq_s16_u16(vaddw_u8(d_lo, L1));
+    const int16x8_t r2_lo = vreinterpretq_s16_u16(vaddw_u8(d_lo, L2));
+    const int16x8_t r3_lo = vreinterpretq_s16_u16(vaddw_u8(d_lo, L3));
+    const int16x8_t r0_hi = vreinterpretq_s16_u16(vaddw_u8(d_hi, L0));
+    const int16x8_t r1_hi = vreinterpretq_s16_u16(vaddw_u8(d_hi, L1));
+    const int16x8_t r2_hi = vreinterpretq_s16_u16(vaddw_u8(d_hi, L2));
+    const int16x8_t r3_hi = vreinterpretq_s16_u16(vaddw_u8(d_hi, L3));
     // Saturate and store the result.
     const uint8x16_t row0 = vcombine_u8(vqmovun_s16(r0_lo), vqmovun_s16(r0_hi));
     const uint8x16_t row1 = vcombine_u8(vqmovun_s16(r1_lo), vqmovun_s16(r1_hi));
diff --git a/src/dsp/dec_sse2.c b/src/dsp/dec_sse2.c
index ff3a2855..b0faada8 100644
--- a/src/dsp/dec_sse2.c
+++ b/src/dsp/dec_sse2.c
@@ -30,7 +30,8 @@
 //------------------------------------------------------------------------------
 // Transforms (Paragraph 14.4)
 
-static void Transform_SSE2(const int16_t* in, uint8_t* dst, int do_two) {
+static void Transform_SSE2(const int16_t* WEBP_RESTRICT in,
+                           uint8_t* WEBP_RESTRICT dst, int do_two) {
   // This implementation makes use of 16-bit fixed point versions of two
   // multiply constants:
   //    K1 = sqrt(2) * cos (pi/8) ~= 85627 / 2^16
@@ -197,7 +198,8 @@ static void Transform_SSE2(const int16_t* in, uint8_t* dst, int do_two) {
 
 #if (USE_TRANSFORM_AC3 == 1)
 
-static void TransformAC3(const int16_t* in, uint8_t* dst) {
+static void TransformAC3_SSE2(const int16_t* WEBP_RESTRICT in,
+                              uint8_t* WEBP_RESTRICT dst) {
   const __m128i A = _mm_set1_epi16(in[0] + 4);
   const __m128i c4 = _mm_set1_epi16(WEBP_TRANSFORM_AC3_MUL2(in[4]));
   const __m128i d4 = _mm_set1_epi16(WEBP_TRANSFORM_AC3_MUL1(in[4]));
@@ -792,8 +794,8 @@ static void HFilter16i_SSE2(uint8_t* p, int stride,
 }
 
 // 8-pixels wide variant, for chroma filtering
-static void VFilter8_SSE2(uint8_t* u, uint8_t* v, int stride,
-                          int thresh, int ithresh, int hev_thresh) {
+static void VFilter8_SSE2(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                          int stride, int thresh, int ithresh, int hev_thresh) {
   __m128i mask;
   __m128i t1, p2, p1, p0, q0, q1, q2;
 
@@ -817,8 +819,8 @@ static void VFilter8_SSE2(uint8_t* u, uint8_t* v, int stride,
   STOREUV(q2, u, v, 2 * stride);
 }
 
-static void HFilter8_SSE2(uint8_t* u, uint8_t* v, int stride,
-                          int thresh, int ithresh, int hev_thresh) {
+static void HFilter8_SSE2(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                          int stride, int thresh, int ithresh, int hev_thresh) {
   __m128i mask;
   __m128i p3, p2, p1, p0, q0, q1, q2, q3;
 
@@ -837,7 +839,8 @@ static void HFilter8_SSE2(uint8_t* u, uint8_t* v, int stride,
   Store16x4_SSE2(&q0, &q1, &q2, &q3, u, v, stride);
 }
 
-static void VFilter8i_SSE2(uint8_t* u, uint8_t* v, int stride,
+static void VFilter8i_SSE2(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                           int stride,
                            int thresh, int ithresh, int hev_thresh) {
   __m128i mask;
   __m128i t1, t2, p1, p0, q0, q1;
@@ -863,7 +866,8 @@ static void VFilter8i_SSE2(uint8_t* u, uint8_t* v, int stride,
   STOREUV(q1, u, v, 1 * stride);
 }
 
-static void HFilter8i_SSE2(uint8_t* u, uint8_t* v, int stride,
+static void HFilter8i_SSE2(uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                           int stride,
                            int thresh, int ithresh, int hev_thresh) {
   __m128i mask;
   __m128i t1, t2, p1, p0, q0, q1;
diff --git a/src/dsp/dsp.h b/src/dsp/dsp.h
index 23bc2965..1b37ef4b 100644
--- a/src/dsp/dsp.h
+++ b/src/dsp/dsp.h
@@ -60,53 +60,66 @@ extern "C" {
 // Transforms
 // VP8Idct: Does one of two inverse transforms. If do_two is set, the transforms
 //          will be done for (ref, in, dst) and (ref + 4, in + 16, dst + 4).
-typedef void (*VP8Idct)(const uint8_t* ref, const int16_t* in, uint8_t* dst,
-                        int do_two);
-typedef void (*VP8Fdct)(const uint8_t* src, const uint8_t* ref, int16_t* out);
-typedef void (*VP8WHT)(const int16_t* in, int16_t* out);
+typedef void (*VP8Idct)(const uint8_t* WEBP_RESTRICT ref,
+                        const int16_t* WEBP_RESTRICT in,
+                        uint8_t* WEBP_RESTRICT dst, int do_two);
+typedef void (*VP8Fdct)(const uint8_t* WEBP_RESTRICT src,
+                        const uint8_t* WEBP_RESTRICT ref,
+                        int16_t* WEBP_RESTRICT out);
+typedef void (*VP8WHT)(const int16_t* WEBP_RESTRICT in,
+                       int16_t* WEBP_RESTRICT out);
 extern VP8Idct VP8ITransform;
 extern VP8Fdct VP8FTransform;
 extern VP8Fdct VP8FTransform2;   // performs two transforms at a time
 extern VP8WHT VP8FTransformWHT;
 // Predictions
 // *dst is the destination block. *top and *left can be NULL.
-typedef void (*VP8IntraPreds)(uint8_t* dst, const uint8_t* left,
-                              const uint8_t* top);
-typedef void (*VP8Intra4Preds)(uint8_t* dst, const uint8_t* top);
+typedef void (*VP8IntraPreds)(uint8_t* WEBP_RESTRICT dst,
+                              const uint8_t* WEBP_RESTRICT left,
+                              const uint8_t* WEBP_RESTRICT top);
+typedef void (*VP8Intra4Preds)(uint8_t* WEBP_RESTRICT dst,
+                               const uint8_t* WEBP_RESTRICT top);
 extern VP8Intra4Preds VP8EncPredLuma4;
 extern VP8IntraPreds VP8EncPredLuma16;
 extern VP8IntraPreds VP8EncPredChroma8;
 
-typedef int (*VP8Metric)(const uint8_t* pix, const uint8_t* ref);
+typedef int (*VP8Metric)(const uint8_t* WEBP_RESTRICT pix,
+                         const uint8_t* WEBP_RESTRICT ref);
 extern VP8Metric VP8SSE16x16, VP8SSE16x8, VP8SSE8x8, VP8SSE4x4;
-typedef int (*VP8WMetric)(const uint8_t* pix, const uint8_t* ref,
-                          const uint16_t* const weights);
+typedef int (*VP8WMetric)(const uint8_t* WEBP_RESTRICT pix,
+                          const uint8_t* WEBP_RESTRICT ref,
+                          const uint16_t* WEBP_RESTRICT const weights);
 // The weights for VP8TDisto4x4 and VP8TDisto16x16 contain a row-major
 // 4 by 4 symmetric matrix.
 extern VP8WMetric VP8TDisto4x4, VP8TDisto16x16;
 
 // Compute the average (DC) of four 4x4 blocks.
 // Each sub-4x4 block #i sum is stored in dc[i].
-typedef void (*VP8MeanMetric)(const uint8_t* ref, uint32_t dc[4]);
+typedef void (*VP8MeanMetric)(const uint8_t* WEBP_RESTRICT ref,
+                              uint32_t dc[4]);
 extern VP8MeanMetric VP8Mean16x4;
 
-typedef void (*VP8BlockCopy)(const uint8_t* src, uint8_t* dst);
+typedef void (*VP8BlockCopy)(const uint8_t* WEBP_RESTRICT src,
+                             uint8_t* WEBP_RESTRICT dst);
 extern VP8BlockCopy VP8Copy4x4;
 extern VP8BlockCopy VP8Copy16x8;
 // Quantization
 struct VP8Matrix;   // forward declaration
-typedef int (*VP8QuantizeBlock)(int16_t in[16], int16_t out[16],
-                                const struct VP8Matrix* const mtx);
+typedef int (*VP8QuantizeBlock)(
+    int16_t in[16], int16_t out[16],
+    const struct VP8Matrix* WEBP_RESTRICT const mtx);
 // Same as VP8QuantizeBlock, but quantizes two consecutive blocks.
-typedef int (*VP8Quantize2Blocks)(int16_t in[32], int16_t out[32],
-                                  const struct VP8Matrix* const mtx);
+typedef int (*VP8Quantize2Blocks)(
+    int16_t in[32], int16_t out[32],
+    const struct VP8Matrix* WEBP_RESTRICT const mtx);
 
 extern VP8QuantizeBlock VP8EncQuantizeBlock;
 extern VP8Quantize2Blocks VP8EncQuantize2Blocks;
 
 // specific to 2nd transform:
-typedef int (*VP8QuantizeBlockWHT)(int16_t in[16], int16_t out[16],
-                                   const struct VP8Matrix* const mtx);
+typedef int (*VP8QuantizeBlockWHT)(
+    int16_t in[16], int16_t out[16],
+    const struct VP8Matrix* WEBP_RESTRICT const mtx);
 extern VP8QuantizeBlockWHT VP8EncQuantizeBlockWHT;
 
 extern const int VP8DspScan[16 + 4 + 4];
@@ -118,9 +131,10 @@ typedef struct {
   int max_value;
   int last_non_zero;
 } VP8Histogram;
-typedef void (*VP8CHisto)(const uint8_t* ref, const uint8_t* pred,
+typedef void (*VP8CHisto)(const uint8_t* WEBP_RESTRICT ref,
+                          const uint8_t* WEBP_RESTRICT pred,
                           int start_block, int end_block,
-                          VP8Histogram* const histo);
+                          VP8Histogram* WEBP_RESTRICT const histo);
 extern VP8CHisto VP8CollectHistogram;
 // General-purpose util function to help VP8CollectHistogram().
 void VP8SetHistogramData(const int distribution[MAX_COEFF_THRESH + 1],
@@ -138,8 +152,9 @@ extern const uint16_t VP8LevelFixedCosts[2047 /*MAX_LEVEL*/ + 1];
 extern const uint8_t VP8EncBands[16 + 1];
 
 struct VP8Residual;
-typedef void (*VP8SetResidualCoeffsFunc)(const int16_t* const coeffs,
-                                         struct VP8Residual* const res);
+typedef void (*VP8SetResidualCoeffsFunc)(
+    const int16_t* WEBP_RESTRICT const coeffs,
+    struct VP8Residual* WEBP_RESTRICT const res);
 extern VP8SetResidualCoeffsFunc VP8SetResidualCoeffs;
 
 // Cost calculation function.
@@ -193,9 +208,11 @@ void VP8SSIMDspInit(void);
 //------------------------------------------------------------------------------
 // Decoding
 
-typedef void (*VP8DecIdct)(const int16_t* coeffs, uint8_t* dst);
+typedef void (*VP8DecIdct)(const int16_t* WEBP_RESTRICT coeffs,
+                           uint8_t* WEBP_RESTRICT dst);
 // when doing two transforms, coeffs is actually int16_t[2][16].
-typedef void (*VP8DecIdct2)(const int16_t* coeffs, uint8_t* dst, int do_two);
+typedef void (*VP8DecIdct2)(const int16_t* WEBP_RESTRICT coeffs,
+                            uint8_t* WEBP_RESTRICT dst, int do_two);
 extern VP8DecIdct2 VP8Transform;
 extern VP8DecIdct VP8TransformAC3;
 extern VP8DecIdct VP8TransformUV;
@@ -233,7 +250,8 @@ extern VP8SimpleFilterFunc VP8SimpleHFilter16i;
 // regular filter (on both macroblock edges and inner edges)
 typedef void (*VP8LumaFilterFunc)(uint8_t* luma, int stride,
                                   int thresh, int ithresh, int hev_t);
-typedef void (*VP8ChromaFilterFunc)(uint8_t* u, uint8_t* v, int stride,
+typedef void (*VP8ChromaFilterFunc)(uint8_t* WEBP_RESTRICT u,
+                                    uint8_t* WEBP_RESTRICT v, int stride,
                                     int thresh, int ithresh, int hev_t);
 // on outer edge
 extern VP8LumaFilterFunc VP8VFilter16;
@@ -253,8 +271,8 @@ extern VP8ChromaFilterFunc VP8HFilter8i;
 #define VP8_DITHER_DESCALE_ROUNDER (1 << (VP8_DITHER_DESCALE - 1))
 #define VP8_DITHER_AMP_BITS 7
 #define VP8_DITHER_AMP_CENTER (1 << VP8_DITHER_AMP_BITS)
-extern void (*VP8DitherCombine8x8)(const uint8_t* dither, uint8_t* dst,
-                                   int dst_stride);
+extern void (*VP8DitherCombine8x8)(const uint8_t* WEBP_RESTRICT dither,
+                                   uint8_t* WEBP_RESTRICT dst, int dst_stride);
 
 // must be called before anything using the above
 void VP8DspInit(void);
@@ -267,10 +285,10 @@ void VP8DspInit(void);
 // Convert a pair of y/u/v lines together to the output rgb/a colorspace.
 // bottom_y can be NULL if only one line of output is needed (at top/bottom).
 typedef void (*WebPUpsampleLinePairFunc)(
-    const uint8_t* top_y, const uint8_t* bottom_y,
-    const uint8_t* top_u, const uint8_t* top_v,
-    const uint8_t* cur_u, const uint8_t* cur_v,
-    uint8_t* top_dst, uint8_t* bottom_dst, int len);
+    const uint8_t* WEBP_RESTRICT top_y, const uint8_t* WEBP_RESTRICT bottom_y,
+    const uint8_t* WEBP_RESTRICT top_u, const uint8_t* WEBP_RESTRICT top_v,
+    const uint8_t* WEBP_RESTRICT cur_u, const uint8_t* WEBP_RESTRICT cur_v,
+    uint8_t* WEBP_RESTRICT top_dst, uint8_t* WEBP_RESTRICT bottom_dst, int len);
 
 #ifdef FANCY_UPSAMPLING
 
@@ -280,13 +298,15 @@ extern WebPUpsampleLinePairFunc WebPUpsamplers[/* MODE_LAST */];
 #endif    // FANCY_UPSAMPLING
 
 // Per-row point-sampling methods.
-typedef void (*WebPSamplerRowFunc)(const uint8_t* y,
-                                   const uint8_t* u, const uint8_t* v,
-                                   uint8_t* dst, int len);
+typedef void (*WebPSamplerRowFunc)(const uint8_t* WEBP_RESTRICT y,
+                                   const uint8_t* WEBP_RESTRICT u,
+                                   const uint8_t* WEBP_RESTRICT v,
+                                   uint8_t* WEBP_RESTRICT dst, int len);
 // Generic function to apply 'WebPSamplerRowFunc' to the whole plane:
-void WebPSamplerProcessPlane(const uint8_t* y, int y_stride,
-                             const uint8_t* u, const uint8_t* v, int uv_stride,
-                             uint8_t* dst, int dst_stride,
+void WebPSamplerProcessPlane(const uint8_t* WEBP_RESTRICT y, int y_stride,
+                             const uint8_t* WEBP_RESTRICT u,
+                             const uint8_t* WEBP_RESTRICT v, int uv_stride,
+                             uint8_t* WEBP_RESTRICT dst, int dst_stride,
                              int width, int height, WebPSamplerRowFunc func);
 
 // Sampling functions to convert rows of YUV to RGB(A)
@@ -298,9 +318,10 @@ extern WebPSamplerRowFunc WebPSamplers[/* MODE_LAST */];
 WebPUpsampleLinePairFunc WebPGetLinePairConverter(int alpha_is_last);
 
 // YUV444->RGB converters
-typedef void (*WebPYUV444Converter)(const uint8_t* y,
-                                    const uint8_t* u, const uint8_t* v,
-                                    uint8_t* dst, int len);
+typedef void (*WebPYUV444Converter)(const uint8_t* WEBP_RESTRICT y,
+                                    const uint8_t* WEBP_RESTRICT u,
+                                    const uint8_t* WEBP_RESTRICT v,
+                                    uint8_t* WEBP_RESTRICT dst, int len);
 
 extern WebPYUV444Converter WebPYUV444Converters[/* MODE_LAST */];
 
@@ -316,26 +337,35 @@ void WebPInitYUV444Converters(void);
 // ARGB -> YUV converters
 
 // Convert ARGB samples to luma Y.
-extern void (*WebPConvertARGBToY)(const uint32_t* argb, uint8_t* y, int width);
+extern void (*WebPConvertARGBToY)(const uint32_t* WEBP_RESTRICT argb,
+                                  uint8_t* WEBP_RESTRICT y, int width);
 // Convert ARGB samples to U/V with downsampling. do_store should be '1' for
 // even lines and '0' for odd ones. 'src_width' is the original width, not
 // the U/V one.
-extern void (*WebPConvertARGBToUV)(const uint32_t* argb, uint8_t* u, uint8_t* v,
+extern void (*WebPConvertARGBToUV)(const uint32_t* WEBP_RESTRICT argb,
+                                   uint8_t* WEBP_RESTRICT u,
+                                   uint8_t* WEBP_RESTRICT v,
                                    int src_width, int do_store);
 
 // Convert a row of accumulated (four-values) of rgba32 toward U/V
-extern void (*WebPConvertRGBA32ToUV)(const uint16_t* rgb,
-                                     uint8_t* u, uint8_t* v, int width);
+extern void (*WebPConvertRGBA32ToUV)(const uint16_t* WEBP_RESTRICT rgb,
+                                     uint8_t* WEBP_RESTRICT u,
+                                     uint8_t* WEBP_RESTRICT v, int width);
 
 // Convert RGB or BGR to Y
-extern void (*WebPConvertRGB24ToY)(const uint8_t* rgb, uint8_t* y, int width);
-extern void (*WebPConvertBGR24ToY)(const uint8_t* bgr, uint8_t* y, int width);
+extern void (*WebPConvertRGB24ToY)(const uint8_t* WEBP_RESTRICT rgb,
+                                   uint8_t* WEBP_RESTRICT y, int width);
+extern void (*WebPConvertBGR24ToY)(const uint8_t* WEBP_RESTRICT bgr,
+                                   uint8_t* WEBP_RESTRICT y, int width);
 
 // used for plain-C fallback.
-extern void WebPConvertARGBToUV_C(const uint32_t* argb, uint8_t* u, uint8_t* v,
+extern void WebPConvertARGBToUV_C(const uint32_t* WEBP_RESTRICT argb,
+                                  uint8_t* WEBP_RESTRICT u,
+                                  uint8_t* WEBP_RESTRICT v,
                                   int src_width, int do_store);
-extern void WebPConvertRGBA32ToUV_C(const uint16_t* rgb,
-                                    uint8_t* u, uint8_t* v, int width);
+extern void WebPConvertRGBA32ToUV_C(const uint16_t* WEBP_RESTRICT rgb,
+                                    uint8_t* WEBP_RESTRICT u,
+                                    uint8_t* WEBP_RESTRICT v, int width);
 
 // Must be called before using the above.
 void WebPInitConvertARGBToYUV(void);
@@ -348,8 +378,9 @@ struct WebPRescaler;
 // Import a row of data and save its contribution in the rescaler.
 // 'channel' denotes the channel number to be imported. 'Expand' corresponds to
 // the wrk->x_expand case. Otherwise, 'Shrink' is to be used.
-typedef void (*WebPRescalerImportRowFunc)(struct WebPRescaler* const wrk,
-                                          const uint8_t* src);
+typedef void (*WebPRescalerImportRowFunc)(
+    struct WebPRescaler* WEBP_RESTRICT const wrk,
+    const uint8_t* WEBP_RESTRICT src);
 
 extern WebPRescalerImportRowFunc WebPRescalerImportRowExpand;
 extern WebPRescalerImportRowFunc WebPRescalerImportRowShrink;
@@ -362,16 +393,19 @@ extern WebPRescalerExportRowFunc WebPRescalerExportRowExpand;
 extern WebPRescalerExportRowFunc WebPRescalerExportRowShrink;
 
 // Plain-C implementation, as fall-back.
-extern void WebPRescalerImportRowExpand_C(struct WebPRescaler* const wrk,
-                                          const uint8_t* src);
-extern void WebPRescalerImportRowShrink_C(struct WebPRescaler* const wrk,
-                                          const uint8_t* src);
+extern void WebPRescalerImportRowExpand_C(
+    struct WebPRescaler* WEBP_RESTRICT const wrk,
+    const uint8_t* WEBP_RESTRICT src);
+extern void WebPRescalerImportRowShrink_C(
+    struct WebPRescaler* WEBP_RESTRICT const wrk,
+    const uint8_t* WEBP_RESTRICT src);
 extern void WebPRescalerExportRowExpand_C(struct WebPRescaler* const wrk);
 extern void WebPRescalerExportRowShrink_C(struct WebPRescaler* const wrk);
 
 // Main entry calls:
-extern void WebPRescalerImportRow(struct WebPRescaler* const wrk,
-                                  const uint8_t* src);
+extern void WebPRescalerImportRow(
+    struct WebPRescaler* WEBP_RESTRICT const wrk,
+    const uint8_t* WEBP_RESTRICT src);
 // Export one row (starting at x_out position) from rescaler.
 extern void WebPRescalerExportRow(struct WebPRescaler* const wrk);
 
@@ -480,8 +514,9 @@ typedef enum {     // Filter types.
   WEBP_FILTER_FAST
 } WEBP_FILTER_TYPE;
 
-typedef void (*WebPFilterFunc)(const uint8_t* in, int width, int height,
-                               int stride, uint8_t* out);
+typedef void (*WebPFilterFunc)(const uint8_t* WEBP_RESTRICT in,
+                               int width, int height, int stride,
+                               uint8_t* WEBP_RESTRICT out);
 // In-place un-filtering.
 // Warning! 'prev_line' pointer can be equal to 'cur_line' or 'preds'.
 typedef void (*WebPUnfilterFunc)(const uint8_t* prev_line, const uint8_t* preds,
diff --git a/src/dsp/enc.c b/src/dsp/enc.c
index 395ad05b..4bef1bab 100644
--- a/src/dsp/enc.c
+++ b/src/dsp/enc.c
@@ -59,9 +59,10 @@ void VP8SetHistogramData(const int distribution[MAX_COEFF_THRESH + 1],
 }
 
 #if !WEBP_NEON_OMIT_C_CODE
-static void CollectHistogram_C(const uint8_t* ref, const uint8_t* pred,
+static void CollectHistogram_C(const uint8_t* WEBP_RESTRICT ref,
+                               const uint8_t* WEBP_RESTRICT pred,
                                int start_block, int end_block,
-                               VP8Histogram* const histo) {
+                               VP8Histogram* WEBP_RESTRICT const histo) {
   int j;
   int distribution[MAX_COEFF_THRESH + 1] = { 0 };
   for (j = start_block; j < end_block; ++j) {
@@ -109,8 +110,9 @@ static WEBP_TSAN_IGNORE_FUNCTION void InitTables(void) {
 #define STORE(x, y, v) \
   dst[(x) + (y) * BPS] = clip_8b(ref[(x) + (y) * BPS] + ((v) >> 3))
 
-static WEBP_INLINE void ITransformOne(const uint8_t* ref, const int16_t* in,
-                                      uint8_t* dst) {
+static WEBP_INLINE void ITransformOne(const uint8_t* WEBP_RESTRICT ref,
+                                      const int16_t* WEBP_RESTRICT in,
+                                      uint8_t* WEBP_RESTRICT dst) {
   int C[4 * 4], *tmp;
   int i;
   tmp = C;
@@ -146,7 +148,9 @@ static WEBP_INLINE void ITransformOne(const uint8_t* ref, const int16_t* in,
   }
 }
 
-static void ITransform_C(const uint8_t* ref, const int16_t* in, uint8_t* dst,
+static void ITransform_C(const uint8_t* WEBP_RESTRICT ref,
+                         const int16_t* WEBP_RESTRICT in,
+                         uint8_t* WEBP_RESTRICT dst,
                          int do_two) {
   ITransformOne(ref, in, dst);
   if (do_two) {
@@ -154,7 +158,9 @@ static void ITransform_C(const uint8_t* ref, const int16_t* in, uint8_t* dst,
   }
 }
 
-static void FTransform_C(const uint8_t* src, const uint8_t* ref, int16_t* out) {
+static void FTransform_C(const uint8_t* WEBP_RESTRICT src,
+                         const uint8_t* WEBP_RESTRICT ref,
+                         int16_t* WEBP_RESTRICT out) {
   int i;
   int tmp[16];
   for (i = 0; i < 4; ++i, src += BPS, ref += BPS) {
@@ -184,14 +190,16 @@ static void FTransform_C(const uint8_t* src, const uint8_t* ref, int16_t* out) {
 }
 #endif  // !WEBP_NEON_OMIT_C_CODE
 
-static void FTransform2_C(const uint8_t* src, const uint8_t* ref,
-                          int16_t* out) {
+static void FTransform2_C(const uint8_t* WEBP_RESTRICT src,
+                          const uint8_t* WEBP_RESTRICT ref,
+                          int16_t* WEBP_RESTRICT out) {
   VP8FTransform(src, ref, out);
   VP8FTransform(src + 4, ref + 4, out + 16);
 }
 
 #if !WEBP_NEON_OMIT_C_CODE
-static void FTransformWHT_C(const int16_t* in, int16_t* out) {
+static void FTransformWHT_C(const int16_t* WEBP_RESTRICT in,
+                            int16_t* WEBP_RESTRICT out) {
   // input is 12b signed
   int32_t tmp[16];
   int i;
@@ -234,8 +242,9 @@ static WEBP_INLINE void Fill(uint8_t* dst, int value, int size) {
   }
 }
 
-static WEBP_INLINE void VerticalPred(uint8_t* dst,
-                                     const uint8_t* top, int size) {
+static WEBP_INLINE void VerticalPred(uint8_t* WEBP_RESTRICT dst,
+                                     const uint8_t* WEBP_RESTRICT top,
+                                     int size) {
   int j;
   if (top != NULL) {
     for (j = 0; j < size; ++j) memcpy(dst + j * BPS, top, size);
@@ -244,8 +253,9 @@ static WEBP_INLINE void VerticalPred(uint8_t* dst,
   }
 }
 
-static WEBP_INLINE void HorizontalPred(uint8_t* dst,
-                                       const uint8_t* left, int size) {
+static WEBP_INLINE void HorizontalPred(uint8_t* WEBP_RESTRICT dst,
+                                       const uint8_t* WEBP_RESTRICT left,
+                                       int size) {
   if (left != NULL) {
     int j;
     for (j = 0; j < size; ++j) {
@@ -256,8 +266,9 @@ static WEBP_INLINE void HorizontalPred(uint8_t* dst,
   }
 }
 
-static WEBP_INLINE void TrueMotion(uint8_t* dst, const uint8_t* left,
-                                   const uint8_t* top, int size) {
+static WEBP_INLINE void TrueMotion(uint8_t* WEBP_RESTRICT dst,
+                                   const uint8_t* WEBP_RESTRICT left,
+                                   const uint8_t* WEBP_RESTRICT top, int size) {
   int y;
   if (left != NULL) {
     if (top != NULL) {
@@ -286,8 +297,9 @@ static WEBP_INLINE void TrueMotion(uint8_t* dst, const uint8_t* left,
   }
 }
 
-static WEBP_INLINE void DCMode(uint8_t* dst, const uint8_t* left,
-                               const uint8_t* top,
+static WEBP_INLINE void DCMode(uint8_t* WEBP_RESTRICT dst,
+                               const uint8_t* WEBP_RESTRICT left,
+                               const uint8_t* WEBP_RESTRICT top,
                                int size, int round, int shift) {
   int DC = 0;
   int j;
@@ -312,8 +324,9 @@ static WEBP_INLINE void DCMode(uint8_t* dst, const uint8_t* left,
 //------------------------------------------------------------------------------
 // Chroma 8x8 prediction (paragraph 12.2)
 
-static void IntraChromaPreds_C(uint8_t* dst, const uint8_t* left,
-                               const uint8_t* top) {
+static void IntraChromaPreds_C(uint8_t* WEBP_RESTRICT dst,
+                               const uint8_t* WEBP_RESTRICT left,
+                               const uint8_t* WEBP_RESTRICT top) {
   // U block
   DCMode(C8DC8 + dst, left, top, 8, 8, 4);
   VerticalPred(C8VE8 + dst, top, 8);
@@ -332,22 +345,28 @@ static void IntraChromaPreds_C(uint8_t* dst, const uint8_t* left,
 //------------------------------------------------------------------------------
 // luma 16x16 prediction (paragraph 12.3)
 
-static void Intra16Preds_C(uint8_t* dst,
-                           const uint8_t* left, const uint8_t* top) {
+#if !WEBP_NEON_OMIT_C_CODE || !WEBP_AARCH64
+static void Intra16Preds_C(uint8_t* WEBP_RESTRICT dst,
+                           const uint8_t* WEBP_RESTRICT left,
+                           const uint8_t* WEBP_RESTRICT top) {
   DCMode(I16DC16 + dst, left, top, 16, 16, 5);
   VerticalPred(I16VE16 + dst, top, 16);
   HorizontalPred(I16HE16 + dst, left, 16);
   TrueMotion(I16TM16 + dst, left, top, 16);
 }
+#endif  // !WEBP_NEON_OMIT_C_CODE || !WEBP_AARCH64
 
 //------------------------------------------------------------------------------
 // luma 4x4 prediction
 
+#if !WEBP_NEON_OMIT_C_CODE || !WEBP_AARCH64 || BPS != 32
+
 #define DST(x, y) dst[(x) + (y) * BPS]
 #define AVG3(a, b, c) ((uint8_t)(((a) + 2 * (b) + (c) + 2) >> 2))
 #define AVG2(a, b) (((a) + (b) + 1) >> 1)
 
-static void VE4(uint8_t* dst, const uint8_t* top) {    // vertical
+// vertical
+static void VE4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   const uint8_t vals[4] = {
     AVG3(top[-1], top[0], top[1]),
     AVG3(top[ 0], top[1], top[2]),
@@ -360,7 +379,8 @@ static void VE4(uint8_t* dst, const uint8_t* top) {    // vertical
   }
 }
 
-static void HE4(uint8_t* dst, const uint8_t* top) {    // horizontal
+// horizontal
+static void HE4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   const int X = top[-1];
   const int I = top[-2];
   const int J = top[-3];
@@ -372,14 +392,14 @@ static void HE4(uint8_t* dst, const uint8_t* top) {    // horizontal
   WebPUint32ToMem(dst + 3 * BPS, 0x01010101U * AVG3(K, L, L));
 }
 
-static void DC4(uint8_t* dst, const uint8_t* top) {
+static void DC4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   uint32_t dc = 4;
   int i;
   for (i = 0; i < 4; ++i) dc += top[i] + top[-5 + i];
   Fill(dst, dc >> 3, 4);
 }
 
-static void RD4(uint8_t* dst, const uint8_t* top) {
+static void RD4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   const int X = top[-1];
   const int I = top[-2];
   const int J = top[-3];
@@ -398,7 +418,7 @@ static void RD4(uint8_t* dst, const uint8_t* top) {
   DST(3, 0)                                     = AVG3(D, C, B);
 }
 
-static void LD4(uint8_t* dst, const uint8_t* top) {
+static void LD4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   const int A = top[0];
   const int B = top[1];
   const int C = top[2];
@@ -416,7 +436,7 @@ static void LD4(uint8_t* dst, const uint8_t* top) {
   DST(3, 3)                                     = AVG3(G, H, H);
 }
 
-static void VR4(uint8_t* dst, const uint8_t* top) {
+static void VR4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   const int X = top[-1];
   const int I = top[-2];
   const int J = top[-3];
@@ -438,7 +458,7 @@ static void VR4(uint8_t* dst, const uint8_t* top) {
   DST(3, 1) =             AVG3(B, C, D);
 }
 
-static void VL4(uint8_t* dst, const uint8_t* top) {
+static void VL4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   const int A = top[0];
   const int B = top[1];
   const int C = top[2];
@@ -460,7 +480,7 @@ static void VL4(uint8_t* dst, const uint8_t* top) {
               DST(3, 3) = AVG3(F, G, H);
 }
 
-static void HU4(uint8_t* dst, const uint8_t* top) {
+static void HU4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   const int I = top[-2];
   const int J = top[-3];
   const int K = top[-4];
@@ -475,7 +495,7 @@ static void HU4(uint8_t* dst, const uint8_t* top) {
   DST(0, 3) = DST(1, 3) = DST(2, 3) = DST(3, 3) = L;
 }
 
-static void HD4(uint8_t* dst, const uint8_t* top) {
+static void HD4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   const int X = top[-1];
   const int I = top[-2];
   const int J = top[-3];
@@ -498,7 +518,7 @@ static void HD4(uint8_t* dst, const uint8_t* top) {
   DST(1, 3)             = AVG3(L, K, J);
 }
 
-static void TM4(uint8_t* dst, const uint8_t* top) {
+static void TM4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int x, y;
   const uint8_t* const clip = clip1 + 255 - top[-1];
   for (y = 0; y < 4; ++y) {
@@ -516,7 +536,8 @@ static void TM4(uint8_t* dst, const uint8_t* top) {
 
 // Left samples are top[-5 .. -2], top_left is top[-1], top are
 // located at top[0..3], and top right is top[4..7]
-static void Intra4Preds_C(uint8_t* dst, const uint8_t* top) {
+static void Intra4Preds_C(uint8_t* WEBP_RESTRICT dst,
+                          const uint8_t* WEBP_RESTRICT top) {
   DC4(I4DC4 + dst, top);
   TM4(I4TM4 + dst, top);
   VE4(I4VE4 + dst, top);
@@ -529,11 +550,14 @@ static void Intra4Preds_C(uint8_t* dst, const uint8_t* top) {
   HU4(I4HU4 + dst, top);
 }
 
+#endif  // !WEBP_NEON_OMIT_C_CODE || !WEBP_AARCH64 || BPS != 32
+
 //------------------------------------------------------------------------------
 // Metric
 
 #if !WEBP_NEON_OMIT_C_CODE
-static WEBP_INLINE int GetSSE(const uint8_t* a, const uint8_t* b,
+static WEBP_INLINE int GetSSE(const uint8_t* WEBP_RESTRICT a,
+                              const uint8_t* WEBP_RESTRICT b,
                               int w, int h) {
   int count = 0;
   int y, x;
@@ -548,21 +572,25 @@ static WEBP_INLINE int GetSSE(const uint8_t* a, const uint8_t* b,
   return count;
 }
 
-static int SSE16x16_C(const uint8_t* a, const uint8_t* b) {
+static int SSE16x16_C(const uint8_t* WEBP_RESTRICT a,
+                      const uint8_t* WEBP_RESTRICT b) {
   return GetSSE(a, b, 16, 16);
 }
-static int SSE16x8_C(const uint8_t* a, const uint8_t* b) {
+static int SSE16x8_C(const uint8_t* WEBP_RESTRICT a,
+                     const uint8_t* WEBP_RESTRICT b) {
   return GetSSE(a, b, 16, 8);
 }
-static int SSE8x8_C(const uint8_t* a, const uint8_t* b) {
+static int SSE8x8_C(const uint8_t* WEBP_RESTRICT a,
+                    const uint8_t* WEBP_RESTRICT b) {
   return GetSSE(a, b, 8, 8);
 }
-static int SSE4x4_C(const uint8_t* a, const uint8_t* b) {
+static int SSE4x4_C(const uint8_t* WEBP_RESTRICT a,
+                    const uint8_t* WEBP_RESTRICT b) {
   return GetSSE(a, b, 4, 4);
 }
 #endif  // !WEBP_NEON_OMIT_C_CODE
 
-static void Mean16x4_C(const uint8_t* ref, uint32_t dc[4]) {
+static void Mean16x4_C(const uint8_t* WEBP_RESTRICT ref, uint32_t dc[4]) {
   int k, x, y;
   for (k = 0; k < 4; ++k) {
     uint32_t avg = 0;
@@ -586,7 +614,8 @@ static void Mean16x4_C(const uint8_t* ref, uint32_t dc[4]) {
 // Hadamard transform
 // Returns the weighted sum of the absolute value of transformed coefficients.
 // w[] contains a row-major 4 by 4 symmetric matrix.
-static int TTransform(const uint8_t* in, const uint16_t* w) {
+static int TTransform(const uint8_t* WEBP_RESTRICT in,
+                      const uint16_t* WEBP_RESTRICT w) {
   int sum = 0;
   int tmp[16];
   int i;
@@ -620,15 +649,17 @@ static int TTransform(const uint8_t* in, const uint16_t* w) {
   return sum;
 }
 
-static int Disto4x4_C(const uint8_t* const a, const uint8_t* const b,
-                      const uint16_t* const w) {
+static int Disto4x4_C(const uint8_t* WEBP_RESTRICT const a,
+                      const uint8_t* WEBP_RESTRICT const b,
+                      const uint16_t* WEBP_RESTRICT const w) {
   const int sum1 = TTransform(a, w);
   const int sum2 = TTransform(b, w);
   return abs(sum2 - sum1) >> 5;
 }
 
-static int Disto16x16_C(const uint8_t* const a, const uint8_t* const b,
-                        const uint16_t* const w) {
+static int Disto16x16_C(const uint8_t* WEBP_RESTRICT const a,
+                        const uint8_t* WEBP_RESTRICT const b,
+                        const uint16_t* WEBP_RESTRICT const w) {
   int D = 0;
   int x, y;
   for (y = 0; y < 16 * BPS; y += 4 * BPS) {
@@ -644,13 +675,14 @@ static int Disto16x16_C(const uint8_t* const a, const uint8_t* const b,
 // Quantization
 //
 
+#if !WEBP_NEON_OMIT_C_CODE || WEBP_NEON_WORK_AROUND_GCC
 static const uint8_t kZigzag[16] = {
   0, 1, 4, 8, 5, 2, 3, 6, 9, 12, 13, 10, 7, 11, 14, 15
 };
 
 // Simple quantization
 static int QuantizeBlock_C(int16_t in[16], int16_t out[16],
-                           const VP8Matrix* const mtx) {
+                           const VP8Matrix* WEBP_RESTRICT const mtx) {
   int last = -1;
   int n;
   for (n = 0; n < 16; ++n) {
@@ -675,9 +707,8 @@ static int QuantizeBlock_C(int16_t in[16], int16_t out[16],
   return (last >= 0);
 }
 
-#if !WEBP_NEON_OMIT_C_CODE || WEBP_NEON_WORK_AROUND_GCC
 static int Quantize2Blocks_C(int16_t in[32], int16_t out[32],
-                             const VP8Matrix* const mtx) {
+                             const VP8Matrix* WEBP_RESTRICT const mtx) {
   int nz;
   nz  = VP8EncQuantizeBlock(in + 0 * 16, out + 0 * 16, mtx) << 0;
   nz |= VP8EncQuantizeBlock(in + 1 * 16, out + 1 * 16, mtx) << 1;
@@ -688,7 +719,8 @@ static int Quantize2Blocks_C(int16_t in[32], int16_t out[32],
 //------------------------------------------------------------------------------
 // Block copy
 
-static WEBP_INLINE void Copy(const uint8_t* src, uint8_t* dst, int w, int h) {
+static WEBP_INLINE void Copy(const uint8_t* WEBP_RESTRICT src,
+                             uint8_t* WEBP_RESTRICT dst, int w, int h) {
   int y;
   for (y = 0; y < h; ++y) {
     memcpy(dst, src, w);
@@ -697,11 +729,13 @@ static WEBP_INLINE void Copy(const uint8_t* src, uint8_t* dst, int w, int h) {
   }
 }
 
-static void Copy4x4_C(const uint8_t* src, uint8_t* dst) {
+static void Copy4x4_C(const uint8_t* WEBP_RESTRICT src,
+                      uint8_t* WEBP_RESTRICT dst) {
   Copy(src, dst, 4, 4);
 }
 
-static void Copy16x8_C(const uint8_t* src, uint8_t* dst) {
+static void Copy16x8_C(const uint8_t* WEBP_RESTRICT src,
+                       uint8_t* WEBP_RESTRICT dst) {
   Copy(src, dst, 16, 8);
 }
 
@@ -760,14 +794,19 @@ WEBP_DSP_INIT_FUNC(VP8EncDspInit) {
 #if !WEBP_NEON_OMIT_C_CODE || WEBP_NEON_WORK_AROUND_GCC
   VP8EncQuantizeBlock = QuantizeBlock_C;
   VP8EncQuantize2Blocks = Quantize2Blocks_C;
+  VP8EncQuantizeBlockWHT = QuantizeBlock_C;
 #endif
 
-  VP8FTransform2 = FTransform2_C;
+#if !WEBP_NEON_OMIT_C_CODE || !WEBP_AARCH64 || BPS != 32
   VP8EncPredLuma4 = Intra4Preds_C;
+#endif
+#if !WEBP_NEON_OMIT_C_CODE || !WEBP_AARCH64
   VP8EncPredLuma16 = Intra16Preds_C;
+#endif
+
+  VP8FTransform2 = FTransform2_C;
   VP8EncPredChroma8 = IntraChromaPreds_C;
   VP8Mean16x4 = Mean16x4_C;
-  VP8EncQuantizeBlockWHT = QuantizeBlock_C;
   VP8Copy4x4 = Copy4x4_C;
   VP8Copy16x8 = Copy16x8_C;
 
diff --git a/src/dsp/enc_mips32.c b/src/dsp/enc_mips32.c
index 50518a5f..6cd8c93d 100644
--- a/src/dsp/enc_mips32.c
+++ b/src/dsp/enc_mips32.c
@@ -109,9 +109,9 @@ static const int kC2 = WEBP_TRANSFORM_AC3_C2;
   "sb      %[" #TEMP12 "],   3+" XSTR(BPS) "*" #A "(%[temp16]) \n\t"
 
 // Does one or two inverse transforms.
-static WEBP_INLINE void ITransformOne_MIPS32(const uint8_t* ref,
-                                             const int16_t* in,
-                                             uint8_t* dst) {
+static WEBP_INLINE void ITransformOne_MIPS32(const uint8_t* WEBP_RESTRICT ref,
+                                             const int16_t* WEBP_RESTRICT in,
+                                             uint8_t* WEBP_RESTRICT dst) {
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6;
   int temp7, temp8, temp9, temp10, temp11, temp12, temp13;
   int temp14, temp15, temp16, temp17, temp18, temp19, temp20;
@@ -141,8 +141,9 @@ static WEBP_INLINE void ITransformOne_MIPS32(const uint8_t* ref,
   );
 }
 
-static void ITransform_MIPS32(const uint8_t* ref, const int16_t* in,
-                              uint8_t* dst, int do_two) {
+static void ITransform_MIPS32(const uint8_t* WEBP_RESTRICT ref,
+                              const int16_t* WEBP_RESTRICT in,
+                              uint8_t* WEBP_RESTRICT dst, int do_two) {
   ITransformOne_MIPS32(ref, in, dst);
   if (do_two) {
     ITransformOne_MIPS32(ref + 4, in + 16, dst + 4);
@@ -236,7 +237,7 @@ static int QuantizeBlock_MIPS32(int16_t in[16], int16_t out[16],
 }
 
 static int Quantize2Blocks_MIPS32(int16_t in[32], int16_t out[32],
-                                  const VP8Matrix* const mtx) {
+                                  const VP8Matrix* WEBP_RESTRICT const mtx) {
   int nz;
   nz  = QuantizeBlock_MIPS32(in + 0 * 16, out + 0 * 16, mtx) << 0;
   nz |= QuantizeBlock_MIPS32(in + 1 * 16, out + 1 * 16, mtx) << 1;
@@ -358,8 +359,9 @@ static int Quantize2Blocks_MIPS32(int16_t in[32], int16_t out[32],
   "msub   %[temp6],  %[temp0]                \n\t"                \
   "msub   %[temp7],  %[temp1]                \n\t"
 
-static int Disto4x4_MIPS32(const uint8_t* const a, const uint8_t* const b,
-                           const uint16_t* const w) {
+static int Disto4x4_MIPS32(const uint8_t* WEBP_RESTRICT const a,
+                           const uint8_t* WEBP_RESTRICT const b,
+                           const uint16_t* WEBP_RESTRICT const w) {
   int tmp[32];
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8;
 
@@ -393,8 +395,9 @@ static int Disto4x4_MIPS32(const uint8_t* const a, const uint8_t* const b,
 #undef VERTICAL_PASS
 #undef HORIZONTAL_PASS
 
-static int Disto16x16_MIPS32(const uint8_t* const a, const uint8_t* const b,
-                             const uint16_t* const w) {
+static int Disto16x16_MIPS32(const uint8_t* WEBP_RESTRICT const a,
+                             const uint8_t* WEBP_RESTRICT const b,
+                             const uint16_t* WEBP_RESTRICT const w) {
   int D = 0;
   int x, y;
   for (y = 0; y < 16 * BPS; y += 4 * BPS) {
@@ -475,8 +478,9 @@ static int Disto16x16_MIPS32(const uint8_t* const a, const uint8_t* const b,
   "sh     %[" #TEMP8 "],  " #D "(%[temp20])              \n\t"    \
   "sh     %[" #TEMP12 "], " #B "(%[temp20])              \n\t"
 
-static void FTransform_MIPS32(const uint8_t* src, const uint8_t* ref,
-                              int16_t* out) {
+static void FTransform_MIPS32(const uint8_t* WEBP_RESTRICT src,
+                              const uint8_t* WEBP_RESTRICT ref,
+                              int16_t* WEBP_RESTRICT out) {
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8;
   int temp9, temp10, temp11, temp12, temp13, temp14, temp15, temp16;
   int temp17, temp18, temp19, temp20;
@@ -537,7 +541,8 @@ static void FTransform_MIPS32(const uint8_t* src, const uint8_t* ref,
   GET_SSE_INNER(C, C + 1, C + 2, C + 3)   \
   GET_SSE_INNER(D, D + 1, D + 2, D + 3)
 
-static int SSE16x16_MIPS32(const uint8_t* a, const uint8_t* b) {
+static int SSE16x16_MIPS32(const uint8_t* WEBP_RESTRICT a,
+                           const uint8_t* WEBP_RESTRICT b) {
   int count;
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;
 
@@ -571,7 +576,8 @@ static int SSE16x16_MIPS32(const uint8_t* a, const uint8_t* b) {
   return count;
 }
 
-static int SSE16x8_MIPS32(const uint8_t* a, const uint8_t* b) {
+static int SSE16x8_MIPS32(const uint8_t* WEBP_RESTRICT a,
+                          const uint8_t* WEBP_RESTRICT b) {
   int count;
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;
 
@@ -597,7 +603,8 @@ static int SSE16x8_MIPS32(const uint8_t* a, const uint8_t* b) {
   return count;
 }
 
-static int SSE8x8_MIPS32(const uint8_t* a, const uint8_t* b) {
+static int SSE8x8_MIPS32(const uint8_t* WEBP_RESTRICT a,
+                         const uint8_t* WEBP_RESTRICT b) {
   int count;
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;
 
@@ -619,7 +626,8 @@ static int SSE8x8_MIPS32(const uint8_t* a, const uint8_t* b) {
   return count;
 }
 
-static int SSE4x4_MIPS32(const uint8_t* a, const uint8_t* b) {
+static int SSE4x4_MIPS32(const uint8_t* WEBP_RESTRICT a,
+                         const uint8_t* WEBP_RESTRICT b) {
   int count;
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;
 
diff --git a/src/dsp/enc_mips_dsp_r2.c b/src/dsp/enc_mips_dsp_r2.c
index e1431f3b..4d808960 100644
--- a/src/dsp/enc_mips_dsp_r2.c
+++ b/src/dsp/enc_mips_dsp_r2.c
@@ -141,8 +141,9 @@ static const int kC2 = WEBP_TRANSFORM_AC3_C2;
   "sh              %[" #TEMP8 "],   " #D "(%[temp20])               \n\t"      \
   "sh              %[" #TEMP12 "],  " #B "(%[temp20])               \n\t"
 
-static void FTransform_MIPSdspR2(const uint8_t* src, const uint8_t* ref,
-                                 int16_t* out) {
+static void FTransform_MIPSdspR2(const uint8_t* WEBP_RESTRICT src,
+                                 const uint8_t* WEBP_RESTRICT ref,
+                                 int16_t* WEBP_RESTRICT out) {
   const int c2217 = 2217;
   const int c5352 = 5352;
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8;
@@ -171,8 +172,9 @@ static void FTransform_MIPSdspR2(const uint8_t* src, const uint8_t* ref,
 #undef VERTICAL_PASS
 #undef HORIZONTAL_PASS
 
-static WEBP_INLINE void ITransformOne(const uint8_t* ref, const int16_t* in,
-                                      uint8_t* dst) {
+static WEBP_INLINE void ITransformOne(const uint8_t* WEBP_RESTRICT ref,
+                                      const int16_t* WEBP_RESTRICT in,
+                                      uint8_t* WEBP_RESTRICT dst) {
   int temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8, temp9;
   int temp10, temp11, temp12, temp13, temp14, temp15, temp16, temp17, temp18;
 
@@ -239,16 +241,18 @@ static WEBP_INLINE void ITransformOne(const uint8_t* ref, const int16_t* in,
   );
 }
 
-static void ITransform_MIPSdspR2(const uint8_t* ref, const int16_t* in,
-                                 uint8_t* dst, int do_two) {
+static void ITransform_MIPSdspR2(const uint8_t* WEBP_RESTRICT ref,
+                                 const int16_t* WEBP_RESTRICT in,
+                                 uint8_t* WEBP_RESTRICT dst, int do_two) {
   ITransformOne(ref, in, dst);
   if (do_two) {
     ITransformOne(ref + 4, in + 16, dst + 4);
   }
 }
 
-static int Disto4x4_MIPSdspR2(const uint8_t* const a, const uint8_t* const b,
-                              const uint16_t* const w) {
+static int Disto4x4_MIPSdspR2(const uint8_t* WEBP_RESTRICT const a,
+                              const uint8_t* WEBP_RESTRICT const b,
+                              const uint16_t* WEBP_RESTRICT const w) {
   int temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8, temp9;
   int temp10, temp11, temp12, temp13, temp14, temp15, temp16, temp17;
 
@@ -314,9 +318,9 @@ static int Disto4x4_MIPSdspR2(const uint8_t* const a, const uint8_t* const b,
   return abs(temp3 - temp17) >> 5;
 }
 
-static int Disto16x16_MIPSdspR2(const uint8_t* const a,
-                                const uint8_t* const b,
-                                const uint16_t* const w) {
+static int Disto16x16_MIPSdspR2(const uint8_t* WEBP_RESTRICT const a,
+                                const uint8_t* WEBP_RESTRICT const b,
+                                const uint16_t* WEBP_RESTRICT const w) {
   int D = 0;
   int x, y;
   for (y = 0; y < 16 * BPS; y += 4 * BPS) {
@@ -367,8 +371,8 @@ static int Disto16x16_MIPSdspR2(const uint8_t* const a,
 } while (0)
 
 #define VERTICAL_PRED(DST, TOP, SIZE)                                          \
-static WEBP_INLINE void VerticalPred##SIZE(uint8_t* (DST),                     \
-                                           const uint8_t* (TOP)) {             \
+static WEBP_INLINE void VerticalPred##SIZE(                                    \
+    uint8_t* WEBP_RESTRICT (DST), const uint8_t* WEBP_RESTRICT (TOP)) {        \
   int j;                                                                       \
   if ((TOP)) {                                                                 \
     for (j = 0; j < (SIZE); ++j) memcpy((DST) + j * BPS, (TOP), (SIZE));       \
@@ -383,8 +387,8 @@ VERTICAL_PRED(dst, top, 16)
 #undef VERTICAL_PRED
 
 #define HORIZONTAL_PRED(DST, LEFT, SIZE)                                       \
-static WEBP_INLINE void HorizontalPred##SIZE(uint8_t* (DST),                   \
-                                             const uint8_t* (LEFT)) {          \
+static WEBP_INLINE void HorizontalPred##SIZE(                                  \
+    uint8_t* WEBP_RESTRICT (DST), const uint8_t* WEBP_RESTRICT (LEFT)) {       \
   if (LEFT) {                                                                  \
     int j;                                                                     \
     for (j = 0; j < (SIZE); ++j) {                                             \
@@ -451,8 +455,9 @@ HORIZONTAL_PRED(dst, left, 16)
 } while (0)
 
 #define TRUE_MOTION(DST, LEFT, TOP, SIZE)                                      \
-static WEBP_INLINE void TrueMotion##SIZE(uint8_t* (DST), const uint8_t* (LEFT),\
-                                         const uint8_t* (TOP)) {               \
+static WEBP_INLINE void TrueMotion##SIZE(uint8_t* WEBP_RESTRICT (DST),         \
+                                         const uint8_t* WEBP_RESTRICT (LEFT),  \
+                                         const uint8_t* WEBP_RESTRICT (TOP)) { \
   if ((LEFT) != NULL) {                                                        \
     if ((TOP) != NULL) {                                                       \
       CLIP_TO_DST((DST), (LEFT), (TOP), (SIZE));                               \
@@ -480,8 +485,9 @@ TRUE_MOTION(dst, left, top, 16)
 #undef CLIP_8B_TO_DST
 #undef CLIPPING
 
-static WEBP_INLINE void DCMode16(uint8_t* dst, const uint8_t* left,
-                                 const uint8_t* top) {
+static WEBP_INLINE void DCMode16(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT left,
+                                 const uint8_t* WEBP_RESTRICT top) {
   int DC, DC1;
   int temp0, temp1, temp2, temp3;
 
@@ -543,8 +549,9 @@ static WEBP_INLINE void DCMode16(uint8_t* dst, const uint8_t* left,
   FILL_8_OR_16(dst, DC, 16);
 }
 
-static WEBP_INLINE void DCMode8(uint8_t* dst, const uint8_t* left,
-                                const uint8_t* top) {
+static WEBP_INLINE void DCMode8(uint8_t* WEBP_RESTRICT dst,
+                                const uint8_t* WEBP_RESTRICT left,
+                                const uint8_t* WEBP_RESTRICT top) {
   int DC, DC1;
   int temp0, temp1, temp2, temp3;
 
@@ -588,7 +595,7 @@ static WEBP_INLINE void DCMode8(uint8_t* dst, const uint8_t* left,
   FILL_8_OR_16(dst, DC, 8);
 }
 
-static void DC4(uint8_t* dst, const uint8_t* top) {
+static void DC4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int temp0, temp1;
   __asm__ volatile(
     "ulw          %[temp0],   0(%[top])               \n\t"
@@ -609,7 +616,7 @@ static void DC4(uint8_t* dst, const uint8_t* top) {
   );
 }
 
-static void TM4(uint8_t* dst, const uint8_t* top) {
+static void TM4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int a10, a32, temp0, temp1, temp2, temp3, temp4, temp5;
   const int c35 = 0xff00ff;
   __asm__ volatile (
@@ -664,7 +671,7 @@ static void TM4(uint8_t* dst, const uint8_t* top) {
   );
 }
 
-static void VE4(uint8_t* dst, const uint8_t* top) {
+static void VE4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6;
   __asm__ volatile(
     "ulw             %[temp0],   -1(%[top])              \n\t"
@@ -695,7 +702,7 @@ static void VE4(uint8_t* dst, const uint8_t* top) {
   );
 }
 
-static void HE4(uint8_t* dst, const uint8_t* top) {
+static void HE4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6;
   __asm__ volatile(
     "ulw             %[temp0],   -4(%[top])              \n\t"
@@ -731,7 +738,7 @@ static void HE4(uint8_t* dst, const uint8_t* top) {
   );
 }
 
-static void RD4(uint8_t* dst, const uint8_t* top) {
+static void RD4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int temp0, temp1, temp2, temp3, temp4, temp5;
   int temp6, temp7, temp8, temp9, temp10, temp11;
   __asm__ volatile(
@@ -780,7 +787,7 @@ static void RD4(uint8_t* dst, const uint8_t* top) {
   );
 }
 
-static void VR4(uint8_t* dst, const uint8_t* top) {
+static void VR4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int temp0, temp1, temp2, temp3, temp4;
   int temp5, temp6, temp7, temp8, temp9;
   __asm__ volatile (
@@ -830,7 +837,7 @@ static void VR4(uint8_t* dst, const uint8_t* top) {
   );
 }
 
-static void LD4(uint8_t* dst, const uint8_t* top) {
+static void LD4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int temp0, temp1, temp2, temp3, temp4, temp5;
   int temp6, temp7, temp8, temp9, temp10, temp11;
   __asm__ volatile(
@@ -877,7 +884,7 @@ static void LD4(uint8_t* dst, const uint8_t* top) {
   );
 }
 
-static void VL4(uint8_t* dst, const uint8_t* top) {
+static void VL4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int temp0, temp1, temp2, temp3, temp4;
   int temp5, temp6, temp7, temp8, temp9;
   __asm__ volatile (
@@ -926,7 +933,7 @@ static void VL4(uint8_t* dst, const uint8_t* top) {
   );
 }
 
-static void HD4(uint8_t* dst, const uint8_t* top) {
+static void HD4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int temp0, temp1, temp2, temp3, temp4;
   int temp5, temp6, temp7, temp8, temp9;
   __asm__ volatile (
@@ -974,7 +981,7 @@ static void HD4(uint8_t* dst, const uint8_t* top) {
   );
 }
 
-static void HU4(uint8_t* dst, const uint8_t* top) {
+static void HU4(uint8_t* WEBP_RESTRICT dst, const uint8_t* WEBP_RESTRICT top) {
   int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;
   __asm__ volatile (
     "ulw             %[temp0],   -5(%[top])              \n\t"
@@ -1013,8 +1020,9 @@ static void HU4(uint8_t* dst, const uint8_t* top) {
 //------------------------------------------------------------------------------
 // Chroma 8x8 prediction (paragraph 12.2)
 
-static void IntraChromaPreds_MIPSdspR2(uint8_t* dst, const uint8_t* left,
-                                       const uint8_t* top) {
+static void IntraChromaPreds_MIPSdspR2(uint8_t* WEBP_RESTRICT dst,
+                                       const uint8_t* WEBP_RESTRICT left,
+                                       const uint8_t* WEBP_RESTRICT top) {
   // U block
   DCMode8(C8DC8 + dst, left, top);
   VerticalPred8(C8VE8 + dst, top);
@@ -1033,8 +1041,9 @@ static void IntraChromaPreds_MIPSdspR2(uint8_t* dst, const uint8_t* left,
 //------------------------------------------------------------------------------
 // luma 16x16 prediction (paragraph 12.3)
 
-static void Intra16Preds_MIPSdspR2(uint8_t* dst,
-                                   const uint8_t* left, const uint8_t* top) {
+static void Intra16Preds_MIPSdspR2(uint8_t* WEBP_RESTRICT dst,
+                                   const uint8_t* WEBP_RESTRICT left,
+                                   const uint8_t* WEBP_RESTRICT top) {
   DCMode16(I16DC16 + dst, left, top);
   VerticalPred16(I16VE16 + dst, top);
   HorizontalPred16(I16HE16 + dst, left);
@@ -1043,7 +1052,8 @@ static void Intra16Preds_MIPSdspR2(uint8_t* dst,
 
 // Left samples are top[-5 .. -2], top_left is top[-1], top are
 // located at top[0..3], and top right is top[4..7]
-static void Intra4Preds_MIPSdspR2(uint8_t* dst, const uint8_t* top) {
+static void Intra4Preds_MIPSdspR2(uint8_t* WEBP_RESTRICT dst,
+                                  const uint8_t* WEBP_RESTRICT top) {
   DC4(I4DC4 + dst, top);
   TM4(I4TM4 + dst, top);
   VE4(I4VE4 + dst, top);
@@ -1079,7 +1089,8 @@ static void Intra4Preds_MIPSdspR2(uint8_t* dst, const uint8_t* top) {
   GET_SSE_INNER(C)                        \
   GET_SSE_INNER(D)
 
-static int SSE16x16_MIPSdspR2(const uint8_t* a, const uint8_t* b) {
+static int SSE16x16_MIPSdspR2(const uint8_t* WEBP_RESTRICT a,
+                              const uint8_t* WEBP_RESTRICT b) {
   int count;
   int temp0, temp1, temp2, temp3;
   __asm__ volatile (
@@ -1109,7 +1120,8 @@ static int SSE16x16_MIPSdspR2(const uint8_t* a, const uint8_t* b) {
   return count;
 }
 
-static int SSE16x8_MIPSdspR2(const uint8_t* a, const uint8_t* b) {
+static int SSE16x8_MIPSdspR2(const uint8_t* WEBP_RESTRICT a,
+                             const uint8_t* WEBP_RESTRICT b) {
   int count;
   int temp0, temp1, temp2, temp3;
   __asm__ volatile (
@@ -1131,7 +1143,8 @@ static int SSE16x8_MIPSdspR2(const uint8_t* a, const uint8_t* b) {
   return count;
 }
 
-static int SSE8x8_MIPSdspR2(const uint8_t* a, const uint8_t* b) {
+static int SSE8x8_MIPSdspR2(const uint8_t* WEBP_RESTRICT a,
+                            const uint8_t* WEBP_RESTRICT b) {
   int count;
   int temp0, temp1, temp2, temp3;
   __asm__ volatile (
@@ -1149,7 +1162,8 @@ static int SSE8x8_MIPSdspR2(const uint8_t* a, const uint8_t* b) {
   return count;
 }
 
-static int SSE4x4_MIPSdspR2(const uint8_t* a, const uint8_t* b) {
+static int SSE4x4_MIPSdspR2(const uint8_t* WEBP_RESTRICT a,
+                            const uint8_t* WEBP_RESTRICT b) {
   int count;
   int temp0, temp1, temp2, temp3;
   __asm__ volatile (
@@ -1273,7 +1287,7 @@ static int SSE4x4_MIPSdspR2(const uint8_t* a, const uint8_t* b) {
 "3:                                                          \n\t"
 
 static int QuantizeBlock_MIPSdspR2(int16_t in[16], int16_t out[16],
-                                   const VP8Matrix* const mtx) {
+                                   const VP8Matrix* WEBP_RESTRICT const mtx) {
   int temp0, temp1, temp2, temp3, temp4, temp5,temp6;
   int sign, coeff, level;
   int max_level = MAX_LEVEL;
@@ -1314,7 +1328,7 @@ static int QuantizeBlock_MIPSdspR2(int16_t in[16], int16_t out[16],
 }
 
 static int Quantize2Blocks_MIPSdspR2(int16_t in[32], int16_t out[32],
-                                     const VP8Matrix* const mtx) {
+                                     const VP8Matrix* WEBP_RESTRICT const mtx) {
   int nz;
   nz  = QuantizeBlock_MIPSdspR2(in + 0 * 16, out + 0 * 16, mtx) << 0;
   nz |= QuantizeBlock_MIPSdspR2(in + 1 * 16, out + 1 * 16, mtx) << 1;
@@ -1360,7 +1374,8 @@ static int Quantize2Blocks_MIPSdspR2(int16_t in[32], int16_t out[32],
   "usw             %[" #TEMP4 "],  " #C "(%[out])                 \n\t"        \
   "usw             %[" #TEMP6 "],  " #D "(%[out])                 \n\t"
 
-static void FTransformWHT_MIPSdspR2(const int16_t* in, int16_t* out) {
+static void FTransformWHT_MIPSdspR2(const int16_t* WEBP_RESTRICT in,
+                                    int16_t* WEBP_RESTRICT out) {
   int temp0, temp1, temp2, temp3, temp4;
   int temp5, temp6, temp7, temp8, temp9;
 
diff --git a/src/dsp/enc_msa.c b/src/dsp/enc_msa.c
index 6f85add4..31ecb942 100644
--- a/src/dsp/enc_msa.c
+++ b/src/dsp/enc_msa.c
@@ -41,8 +41,9 @@
   BUTTERFLY_4(a1_m, b1_m, c1_m, d1_m, out0, out1, out2, out3);      \
 } while (0)
 
-static WEBP_INLINE void ITransformOne(const uint8_t* ref, const int16_t* in,
-                                      uint8_t* dst) {
+static WEBP_INLINE void ITransformOne(const uint8_t* WEBP_RESTRICT ref,
+                                      const int16_t* WEBP_RESTRICT in,
+                                      uint8_t* WEBP_RESTRICT dst) {
   v8i16 input0, input1;
   v4i32 in0, in1, in2, in3, hz0, hz1, hz2, hz3, vt0, vt1, vt2, vt3;
   v4i32 res0, res1, res2, res3;
@@ -69,16 +70,18 @@ static WEBP_INLINE void ITransformOne(const uint8_t* ref, const int16_t* in,
   ST4x4_UB(res0, res0, 3, 2, 1, 0, dst, BPS);
 }
 
-static void ITransform_MSA(const uint8_t* ref, const int16_t* in, uint8_t* dst,
-                           int do_two) {
+static void ITransform_MSA(const uint8_t* WEBP_RESTRICT ref,
+                           const int16_t* WEBP_RESTRICT in,
+                           uint8_t* WEBP_RESTRICT dst, int do_two) {
   ITransformOne(ref, in, dst);
   if (do_two) {
     ITransformOne(ref + 4, in + 16, dst + 4);
   }
 }
 
-static void FTransform_MSA(const uint8_t* src, const uint8_t* ref,
-                           int16_t* out) {
+static void FTransform_MSA(const uint8_t* WEBP_RESTRICT src,
+                           const uint8_t* WEBP_RESTRICT ref,
+                           int16_t* WEBP_RESTRICT out) {
   uint64_t out0, out1, out2, out3;
   uint32_t in0, in1, in2, in3;
   v4i32 tmp0, tmp1, tmp2, tmp3, tmp4, tmp5;
@@ -131,7 +134,8 @@ static void FTransform_MSA(const uint8_t* src, const uint8_t* ref,
   SD4(out0, out1, out2, out3, out, 8);
 }
 
-static void FTransformWHT_MSA(const int16_t* in, int16_t* out) {
+static void FTransformWHT_MSA(const int16_t* WEBP_RESTRICT in,
+                              int16_t* WEBP_RESTRICT out) {
   v8i16 in0 = { 0 };
   v8i16 in1 = { 0 };
   v8i16 tmp0, tmp1, tmp2, tmp3;
@@ -168,7 +172,8 @@ static void FTransformWHT_MSA(const int16_t* in, int16_t* out) {
   ST_SH2(out0, out1, out, 8);
 }
 
-static int TTransform_MSA(const uint8_t* in, const uint16_t* w) {
+static int TTransform_MSA(const uint8_t* WEBP_RESTRICT in,
+                          const uint16_t* WEBP_RESTRICT w) {
   int sum;
   uint32_t in0_m, in1_m, in2_m, in3_m;
   v16i8 src0 = { 0 };
@@ -200,15 +205,17 @@ static int TTransform_MSA(const uint8_t* in, const uint16_t* w) {
   return sum;
 }
 
-static int Disto4x4_MSA(const uint8_t* const a, const uint8_t* const b,
-                        const uint16_t* const w) {
+static int Disto4x4_MSA(const uint8_t* WEBP_RESTRICT const a,
+                        const uint8_t* WEBP_RESTRICT const b,
+                        const uint16_t* WEBP_RESTRICT const w) {
   const int sum1 = TTransform_MSA(a, w);
   const int sum2 = TTransform_MSA(b, w);
   return abs(sum2 - sum1) >> 5;
 }
 
-static int Disto16x16_MSA(const uint8_t* const a, const uint8_t* const b,
-                          const uint16_t* const w) {
+static int Disto16x16_MSA(const uint8_t* WEBP_RESTRICT const a,
+                          const uint8_t* WEBP_RESTRICT const b,
+                          const uint16_t* WEBP_RESTRICT const w) {
   int D = 0;
   int x, y;
   for (y = 0; y < 16 * BPS; y += 4 * BPS) {
@@ -259,7 +266,9 @@ static void CollectHistogram_MSA(const uint8_t* ref, const uint8_t* pred,
 #define AVG3(a, b, c) (((a) + 2 * (b) + (c) + 2) >> 2)
 #define AVG2(a, b) (((a) + (b) + 1) >> 1)
 
-static WEBP_INLINE void VE4(uint8_t* dst, const uint8_t* top) {    // vertical
+// vertical
+static WEBP_INLINE void VE4(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   const v16u8 A1 = { 0 };
   const uint64_t val_m = LD(top - 1);
   const v16u8 A = (v16u8)__msa_insert_d((v2i64)A1, 0, val_m);
@@ -272,7 +281,9 @@ static WEBP_INLINE void VE4(uint8_t* dst, const uint8_t* top) {    // vertical
   SW4(out, out, out, out, dst, BPS);
 }
 
-static WEBP_INLINE void HE4(uint8_t* dst, const uint8_t* top) {    // horizontal
+// horizontal
+static WEBP_INLINE void HE4(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   const int X = top[-1];
   const int I = top[-2];
   const int J = top[-3];
@@ -284,7 +295,8 @@ static WEBP_INLINE void HE4(uint8_t* dst, const uint8_t* top) {    // horizontal
   WebPUint32ToMem(dst + 3 * BPS, 0x01010101U * AVG3(K, L, L));
 }
 
-static WEBP_INLINE void DC4(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void DC4(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   uint32_t dc = 4;
   int i;
   for (i = 0; i < 4; ++i) dc += top[i] + top[-5 + i];
@@ -293,7 +305,8 @@ static WEBP_INLINE void DC4(uint8_t* dst, const uint8_t* top) {
   SW4(dc, dc, dc, dc, dst, BPS);
 }
 
-static WEBP_INLINE void RD4(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void RD4(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   const v16u8 A2 = { 0 };
   const uint64_t val_m = LD(top - 5);
   const v16u8 A1 = (v16u8)__msa_insert_d((v2i64)A2, 0, val_m);
@@ -313,7 +326,8 @@ static WEBP_INLINE void RD4(uint8_t* dst, const uint8_t* top) {
   SW4(val3, val2, val1, val0, dst, BPS);
 }
 
-static WEBP_INLINE void LD4(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void LD4(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   const v16u8 A1 = { 0 };
   const uint64_t val_m = LD(top);
   const v16u8 A = (v16u8)__msa_insert_d((v2i64)A1, 0, val_m);
@@ -333,7 +347,8 @@ static WEBP_INLINE void LD4(uint8_t* dst, const uint8_t* top) {
   SW4(val0, val1, val2, val3, dst, BPS);
 }
 
-static WEBP_INLINE void VR4(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void VR4(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   const int X = top[-1];
   const int I = top[-2];
   const int J = top[-3];
@@ -354,7 +369,8 @@ static WEBP_INLINE void VR4(uint8_t* dst, const uint8_t* top) {
   DST(3, 1) =             AVG3(B, C, D);
 }
 
-static WEBP_INLINE void VL4(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void VL4(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   const int A = top[0];
   const int B = top[1];
   const int C = top[2];
@@ -375,7 +391,8 @@ static WEBP_INLINE void VL4(uint8_t* dst, const uint8_t* top) {
               DST(3, 3) = AVG3(F, G, H);
 }
 
-static WEBP_INLINE void HU4(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void HU4(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   const int I = top[-2];
   const int J = top[-3];
   const int K = top[-4];
@@ -390,7 +407,8 @@ static WEBP_INLINE void HU4(uint8_t* dst, const uint8_t* top) {
   DST(0, 3) = DST(1, 3) = DST(2, 3) = DST(3, 3) = L;
 }
 
-static WEBP_INLINE void HD4(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void HD4(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   const int X = top[-1];
   const int I = top[-2];
   const int J = top[-3];
@@ -411,7 +429,8 @@ static WEBP_INLINE void HD4(uint8_t* dst, const uint8_t* top) {
   DST(1, 3)             = AVG3(L, K, J);
 }
 
-static WEBP_INLINE void TM4(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void TM4(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   const v16i8 zero = { 0 };
   const v8i16 TL = (v8i16)__msa_fill_h(top[-1]);
   const v8i16 L0 = (v8i16)__msa_fill_h(top[-2]);
@@ -431,7 +450,8 @@ static WEBP_INLINE void TM4(uint8_t* dst, const uint8_t* top) {
 #undef AVG3
 #undef AVG2
 
-static void Intra4Preds_MSA(uint8_t* dst, const uint8_t* top) {
+static void Intra4Preds_MSA(uint8_t* WEBP_RESTRICT dst,
+                            const uint8_t* WEBP_RESTRICT top) {
   DC4(I4DC4 + dst, top);
   TM4(I4TM4 + dst, top);
   VE4(I4VE4 + dst, top);
@@ -451,7 +471,8 @@ static void Intra4Preds_MSA(uint8_t* dst, const uint8_t* top) {
     ST_UB8(out, out, out, out, out, out, out, out, dst + 8 * BPS, BPS);  \
 } while (0)
 
-static WEBP_INLINE void VerticalPred16x16(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void VerticalPred16x16(uint8_t* WEBP_RESTRICT dst,
+                                          const uint8_t* WEBP_RESTRICT top) {
   if (top != NULL) {
     const v16u8 out = LD_UB(top);
     STORE16x16(out, dst);
@@ -461,8 +482,8 @@ static WEBP_INLINE void VerticalPred16x16(uint8_t* dst, const uint8_t* top) {
   }
 }
 
-static WEBP_INLINE void HorizontalPred16x16(uint8_t* dst,
-                                            const uint8_t* left) {
+static WEBP_INLINE void HorizontalPred16x16(uint8_t* WEBP_RESTRICT dst,
+                                            const uint8_t* WEBP_RESTRICT left) {
   if (left != NULL) {
     int j;
     for (j = 0; j < 16; j += 4) {
@@ -480,8 +501,9 @@ static WEBP_INLINE void HorizontalPred16x16(uint8_t* dst,
   }
 }
 
-static WEBP_INLINE void TrueMotion16x16(uint8_t* dst, const uint8_t* left,
-                                        const uint8_t* top) {
+static WEBP_INLINE void TrueMotion16x16(uint8_t* WEBP_RESTRICT dst,
+                                        const uint8_t* WEBP_RESTRICT left,
+                                        const uint8_t* WEBP_RESTRICT top) {
   if (left != NULL) {
     if (top != NULL) {
       int j;
@@ -519,8 +541,9 @@ static WEBP_INLINE void TrueMotion16x16(uint8_t* dst, const uint8_t* left,
   }
 }
 
-static WEBP_INLINE void DCMode16x16(uint8_t* dst, const uint8_t* left,
-                                    const uint8_t* top) {
+static WEBP_INLINE void DCMode16x16(uint8_t* WEBP_RESTRICT dst,
+                                    const uint8_t* WEBP_RESTRICT left,
+                                    const uint8_t* WEBP_RESTRICT top) {
   int DC;
   v16u8 out;
   if (top != NULL && left != NULL) {
@@ -548,8 +571,9 @@ static WEBP_INLINE void DCMode16x16(uint8_t* dst, const uint8_t* left,
   STORE16x16(out, dst);
 }
 
-static void Intra16Preds_MSA(uint8_t* dst,
-                             const uint8_t* left, const uint8_t* top) {
+static void Intra16Preds_MSA(uint8_t* WEBP_RESTRICT dst,
+                             const uint8_t* WEBP_RESTRICT left,
+                             const uint8_t* WEBP_RESTRICT top) {
   DCMode16x16(I16DC16 + dst, left, top);
   VerticalPred16x16(I16VE16 + dst, top);
   HorizontalPred16x16(I16HE16 + dst, left);
@@ -574,7 +598,8 @@ static void Intra16Preds_MSA(uint8_t* dst,
   SD4(out, out, out, out, dst + 4 * BPS, BPS);  \
 } while (0)
 
-static WEBP_INLINE void VerticalPred8x8(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void VerticalPred8x8(uint8_t* WEBP_RESTRICT dst,
+                                        const uint8_t* WEBP_RESTRICT top) {
   if (top != NULL) {
     const uint64_t out = LD(top);
     STORE8x8(out, dst);
@@ -584,7 +609,8 @@ static WEBP_INLINE void VerticalPred8x8(uint8_t* dst, const uint8_t* top) {
   }
 }
 
-static WEBP_INLINE void HorizontalPred8x8(uint8_t* dst, const uint8_t* left) {
+static WEBP_INLINE void HorizontalPred8x8(uint8_t* WEBP_RESTRICT dst,
+                                          const uint8_t* WEBP_RESTRICT left) {
   if (left != NULL) {
     int j;
     for (j = 0; j < 8; j += 4) {
@@ -606,8 +632,9 @@ static WEBP_INLINE void HorizontalPred8x8(uint8_t* dst, const uint8_t* left) {
   }
 }
 
-static WEBP_INLINE void TrueMotion8x8(uint8_t* dst, const uint8_t* left,
-                                      const uint8_t* top) {
+static WEBP_INLINE void TrueMotion8x8(uint8_t* WEBP_RESTRICT dst,
+                                      const uint8_t* WEBP_RESTRICT left,
+                                      const uint8_t* WEBP_RESTRICT top) {
   if (left != NULL) {
     if (top != NULL) {
       int j;
@@ -646,8 +673,9 @@ static WEBP_INLINE void TrueMotion8x8(uint8_t* dst, const uint8_t* left,
   }
 }
 
-static WEBP_INLINE void DCMode8x8(uint8_t* dst, const uint8_t* left,
-                                  const uint8_t* top) {
+static WEBP_INLINE void DCMode8x8(uint8_t* WEBP_RESTRICT dst,
+                                  const uint8_t* WEBP_RESTRICT left,
+                                  const uint8_t* WEBP_RESTRICT top) {
   uint64_t out;
   v16u8 src = { 0 };
   if (top != NULL && left != NULL) {
@@ -670,8 +698,9 @@ static WEBP_INLINE void DCMode8x8(uint8_t* dst, const uint8_t* left,
   STORE8x8(out, dst);
 }
 
-static void IntraChromaPreds_MSA(uint8_t* dst, const uint8_t* left,
-                                 const uint8_t* top) {
+static void IntraChromaPreds_MSA(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT left,
+                                 const uint8_t* WEBP_RESTRICT top) {
   // U block
   DCMode8x8(C8DC8 + dst, left, top);
   VerticalPred8x8(C8VE8 + dst, top);
@@ -712,7 +741,8 @@ static void IntraChromaPreds_MSA(uint8_t* dst, const uint8_t* left,
   DPADD_SH2_SW(tmp2, tmp3, tmp2, tmp3, out2, out3);                         \
 } while (0)
 
-static int SSE16x16_MSA(const uint8_t* a, const uint8_t* b) {
+static int SSE16x16_MSA(const uint8_t* WEBP_RESTRICT a,
+                        const uint8_t* WEBP_RESTRICT b) {
   uint32_t sum;
   v16u8 src0, src1, src2, src3, src4, src5, src6, src7;
   v16u8 ref0, ref1, ref2, ref3, ref4, ref5, ref6, ref7;
@@ -739,7 +769,8 @@ static int SSE16x16_MSA(const uint8_t* a, const uint8_t* b) {
   return sum;
 }
 
-static int SSE16x8_MSA(const uint8_t* a, const uint8_t* b) {
+static int SSE16x8_MSA(const uint8_t* WEBP_RESTRICT a,
+                       const uint8_t* WEBP_RESTRICT b) {
   uint32_t sum;
   v16u8 src0, src1, src2, src3, src4, src5, src6, src7;
   v16u8 ref0, ref1, ref2, ref3, ref4, ref5, ref6, ref7;
@@ -758,7 +789,8 @@ static int SSE16x8_MSA(const uint8_t* a, const uint8_t* b) {
   return sum;
 }
 
-static int SSE8x8_MSA(const uint8_t* a, const uint8_t* b) {
+static int SSE8x8_MSA(const uint8_t* WEBP_RESTRICT a,
+                      const uint8_t* WEBP_RESTRICT b) {
   uint32_t sum;
   v16u8 src0, src1, src2, src3, src4, src5, src6, src7;
   v16u8 ref0, ref1, ref2, ref3, ref4, ref5, ref6, ref7;
@@ -778,7 +810,8 @@ static int SSE8x8_MSA(const uint8_t* a, const uint8_t* b) {
   return sum;
 }
 
-static int SSE4x4_MSA(const uint8_t* a, const uint8_t* b) {
+static int SSE4x4_MSA(const uint8_t* WEBP_RESTRICT a,
+                      const uint8_t* WEBP_RESTRICT b) {
   uint32_t sum = 0;
   uint32_t src0, src1, src2, src3, ref0, ref1, ref2, ref3;
   v16u8 src = { 0 }, ref = { 0 }, tmp0, tmp1;
@@ -801,7 +834,7 @@ static int SSE4x4_MSA(const uint8_t* a, const uint8_t* b) {
 // Quantization
 
 static int QuantizeBlock_MSA(int16_t in[16], int16_t out[16],
-                             const VP8Matrix* const mtx) {
+                             const VP8Matrix* WEBP_RESTRICT const mtx) {
   int sum;
   v8i16 in0, in1, sh0, sh1, out0, out1;
   v8i16 tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, sign0, sign1;
@@ -854,7 +887,7 @@ static int QuantizeBlock_MSA(int16_t in[16], int16_t out[16],
 }
 
 static int Quantize2Blocks_MSA(int16_t in[32], int16_t out[32],
-                               const VP8Matrix* const mtx) {
+                               const VP8Matrix* WEBP_RESTRICT const mtx) {
   int nz;
   nz  = VP8EncQuantizeBlock(in + 0 * 16, out + 0 * 16, mtx) << 0;
   nz |= VP8EncQuantizeBlock(in + 1 * 16, out + 1 * 16, mtx) << 1;
diff --git a/src/dsp/enc_neon.c b/src/dsp/enc_neon.c
index 6f641c9a..b373245d 100644
--- a/src/dsp/enc_neon.c
+++ b/src/dsp/enc_neon.c
@@ -60,8 +60,8 @@ static WEBP_INLINE void SaturateAndStore4x4_NEON(uint8_t* const dst,
 
 static WEBP_INLINE void Add4x4_NEON(const int16x8_t row01,
                                     const int16x8_t row23,
-                                    const uint8_t* const ref,
-                                    uint8_t* const dst) {
+                                    const uint8_t* WEBP_RESTRICT const ref,
+                                    uint8_t* WEBP_RESTRICT const dst) {
   uint32x2_t dst01 = vdup_n_u32(0);
   uint32x2_t dst23 = vdup_n_u32(0);
 
@@ -120,8 +120,9 @@ static WEBP_INLINE void TransformPass_NEON(int16x8x2_t* const rows) {
   Transpose8x2_NEON(E0, E1, rows);
 }
 
-static void ITransformOne_NEON(const uint8_t* ref,
-                               const int16_t* in, uint8_t* dst) {
+static void ITransformOne_NEON(const uint8_t* WEBP_RESTRICT ref,
+                               const int16_t* WEBP_RESTRICT in,
+                               uint8_t* WEBP_RESTRICT dst) {
   int16x8x2_t rows;
   INIT_VECTOR2(rows, vld1q_s16(in + 0), vld1q_s16(in + 8));
   TransformPass_NEON(&rows);
@@ -131,8 +132,9 @@ static void ITransformOne_NEON(const uint8_t* ref,
 
 #else
 
-static void ITransformOne_NEON(const uint8_t* ref,
-                               const int16_t* in, uint8_t* dst) {
+static void ITransformOne_NEON(const uint8_t* WEBP_RESTRICT ref,
+                               const int16_t* WEBP_RESTRICT in,
+                               uint8_t* WEBP_RESTRICT dst) {
   const int kBPS = BPS;
   const int16_t kC1C2[] = { kC1, kC2, 0, 0 };
 
@@ -247,8 +249,9 @@ static void ITransformOne_NEON(const uint8_t* ref,
 
 #endif    // WEBP_USE_INTRINSICS
 
-static void ITransform_NEON(const uint8_t* ref,
-                            const int16_t* in, uint8_t* dst, int do_two) {
+static void ITransform_NEON(const uint8_t* WEBP_RESTRICT ref,
+                            const int16_t* WEBP_RESTRICT in,
+                            uint8_t* WEBP_RESTRICT dst, int do_two) {
   ITransformOne_NEON(ref, in, dst);
   if (do_two) {
     ITransformOne_NEON(ref + 4, in + 16, dst + 4);
@@ -294,8 +297,9 @@ static WEBP_INLINE int16x8_t DiffU8ToS16_NEON(const uint8x8_t a,
   return vreinterpretq_s16_u16(vsubl_u8(a, b));
 }
 
-static void FTransform_NEON(const uint8_t* src, const uint8_t* ref,
-                            int16_t* out) {
+static void FTransform_NEON(const uint8_t* WEBP_RESTRICT src,
+                            const uint8_t* WEBP_RESTRICT ref,
+                            int16_t* WEBP_RESTRICT out) {
   int16x8_t d0d1, d3d2;   // working 4x4 int16 variables
   {
     const uint8x16_t S0 = Load4x4_NEON(src);
@@ -364,8 +368,9 @@ static const int32_t kCoeff32[] = {
   51000, 51000, 51000, 51000
 };
 
-static void FTransform_NEON(const uint8_t* src, const uint8_t* ref,
-                            int16_t* out) {
+static void FTransform_NEON(const uint8_t* WEBP_RESTRICT src,
+                            const uint8_t* WEBP_RESTRICT ref,
+                            int16_t* WEBP_RESTRICT out) {
   const int kBPS = BPS;
   const uint8_t* src_ptr = src;
   const uint8_t* ref_ptr = ref;
@@ -484,7 +489,8 @@ static void FTransform_NEON(const uint8_t* src, const uint8_t* ref,
   src += stride;                                    \
 } while (0)
 
-static void FTransformWHT_NEON(const int16_t* src, int16_t* out) {
+static void FTransformWHT_NEON(const int16_t* WEBP_RESTRICT src,
+                               int16_t* WEBP_RESTRICT out) {
   const int stride = 16;
   const int16x4_t zero = vdup_n_s16(0);
   int32x4x4_t tmp0;
@@ -659,8 +665,9 @@ static WEBP_INLINE int32x2_t DistoSum_NEON(const int16x8x4_t q4_in,
 // Hadamard transform
 // Returns the weighted sum of the absolute value of transformed coefficients.
 // w[] contains a row-major 4 by 4 symmetric matrix.
-static int Disto4x4_NEON(const uint8_t* const a, const uint8_t* const b,
-                         const uint16_t* const w) {
+static int Disto4x4_NEON(const uint8_t* WEBP_RESTRICT const a,
+                         const uint8_t* WEBP_RESTRICT const b,
+                         const uint16_t* WEBP_RESTRICT const w) {
   uint32x2_t d_in_ab_0123 = vdup_n_u32(0);
   uint32x2_t d_in_ab_4567 = vdup_n_u32(0);
   uint32x2_t d_in_ab_89ab = vdup_n_u32(0);
@@ -701,8 +708,9 @@ static int Disto4x4_NEON(const uint8_t* const a, const uint8_t* const b,
 }
 #undef LOAD_LANE_32b
 
-static int Disto16x16_NEON(const uint8_t* const a, const uint8_t* const b,
-                           const uint16_t* const w) {
+static int Disto16x16_NEON(const uint8_t* WEBP_RESTRICT const a,
+                           const uint8_t* WEBP_RESTRICT const b,
+                           const uint16_t* WEBP_RESTRICT const w) {
   int D = 0;
   int x, y;
   for (y = 0; y < 16 * BPS; y += 4 * BPS) {
@@ -715,9 +723,10 @@ static int Disto16x16_NEON(const uint8_t* const a, const uint8_t* const b,
 
 //------------------------------------------------------------------------------
 
-static void CollectHistogram_NEON(const uint8_t* ref, const uint8_t* pred,
+static void CollectHistogram_NEON(const uint8_t* WEBP_RESTRICT ref,
+                                  const uint8_t* WEBP_RESTRICT pred,
                                   int start_block, int end_block,
-                                  VP8Histogram* const histo) {
+                                  VP8Histogram* WEBP_RESTRICT const histo) {
   const uint16x8_t max_coeff_thresh = vdupq_n_u16(MAX_COEFF_THRESH);
   int j;
   int distribution[MAX_COEFF_THRESH + 1] = { 0 };
@@ -747,9 +756,9 @@ static void CollectHistogram_NEON(const uint8_t* ref, const uint8_t* pred,
 
 //------------------------------------------------------------------------------
 
-static WEBP_INLINE void AccumulateSSE16_NEON(const uint8_t* const a,
-                                             const uint8_t* const b,
-                                             uint32x4_t* const sum) {
+static WEBP_INLINE void AccumulateSSE16_NEON(
+    const uint8_t* WEBP_RESTRICT const a, const uint8_t* WEBP_RESTRICT const b,
+    uint32x4_t* const sum) {
   const uint8x16_t a0 = vld1q_u8(a);
   const uint8x16_t b0 = vld1q_u8(b);
   const uint8x16_t abs_diff = vabdq_u8(a0, b0);
@@ -775,7 +784,8 @@ static int SumToInt_NEON(uint32x4_t sum) {
 #endif
 }
 
-static int SSE16x16_NEON(const uint8_t* a, const uint8_t* b) {
+static int SSE16x16_NEON(const uint8_t* WEBP_RESTRICT a,
+                         const uint8_t* WEBP_RESTRICT b) {
   uint32x4_t sum = vdupq_n_u32(0);
   int y;
   for (y = 0; y < 16; ++y) {
@@ -784,7 +794,8 @@ static int SSE16x16_NEON(const uint8_t* a, const uint8_t* b) {
   return SumToInt_NEON(sum);
 }
 
-static int SSE16x8_NEON(const uint8_t* a, const uint8_t* b) {
+static int SSE16x8_NEON(const uint8_t* WEBP_RESTRICT a,
+                        const uint8_t* WEBP_RESTRICT b) {
   uint32x4_t sum = vdupq_n_u32(0);
   int y;
   for (y = 0; y < 8; ++y) {
@@ -793,7 +804,8 @@ static int SSE16x8_NEON(const uint8_t* a, const uint8_t* b) {
   return SumToInt_NEON(sum);
 }
 
-static int SSE8x8_NEON(const uint8_t* a, const uint8_t* b) {
+static int SSE8x8_NEON(const uint8_t* WEBP_RESTRICT a,
+                       const uint8_t* WEBP_RESTRICT b) {
   uint32x4_t sum = vdupq_n_u32(0);
   int y;
   for (y = 0; y < 8; ++y) {
@@ -806,7 +818,8 @@ static int SSE8x8_NEON(const uint8_t* a, const uint8_t* b) {
   return SumToInt_NEON(sum);
 }
 
-static int SSE4x4_NEON(const uint8_t* a, const uint8_t* b) {
+static int SSE4x4_NEON(const uint8_t* WEBP_RESTRICT a,
+                       const uint8_t* WEBP_RESTRICT b) {
   const uint8x16_t a0 = Load4x4_NEON(a);
   const uint8x16_t b0 = Load4x4_NEON(b);
   const uint8x16_t abs_diff = vabdq_u8(a0, b0);
@@ -825,8 +838,9 @@ static int SSE4x4_NEON(const uint8_t* a, const uint8_t* b) {
 // Compilation with gcc-4.6.x is problematic for now.
 #if !defined(WORK_AROUND_GCC)
 
-static int16x8_t Quantize_NEON(int16_t* const in,
-                               const VP8Matrix* const mtx, int offset) {
+static int16x8_t Quantize_NEON(int16_t* WEBP_RESTRICT const in,
+                               const VP8Matrix* WEBP_RESTRICT const mtx,
+                               int offset) {
   const uint16x8_t sharp = vld1q_u16(&mtx->sharpen_[offset]);
   const uint16x8_t q = vld1q_u16(&mtx->q_[offset]);
   const uint16x8_t iq = vld1q_u16(&mtx->iq_[offset]);
@@ -860,7 +874,7 @@ static const uint8_t kShuffles[4][8] = {
 };
 
 static int QuantizeBlock_NEON(int16_t in[16], int16_t out[16],
-                              const VP8Matrix* const mtx) {
+                              const VP8Matrix* WEBP_RESTRICT const mtx) {
   const int16x8_t out0 = Quantize_NEON(in, mtx, 0);
   const int16x8_t out1 = Quantize_NEON(in, mtx, 8);
   uint8x8x4_t shuffles;
@@ -902,7 +916,7 @@ static int QuantizeBlock_NEON(int16_t in[16], int16_t out[16],
 }
 
 static int Quantize2Blocks_NEON(int16_t in[32], int16_t out[32],
-                                const VP8Matrix* const mtx) {
+                                const VP8Matrix* WEBP_RESTRICT const mtx) {
   int nz;
   nz  = QuantizeBlock_NEON(in + 0 * 16, out + 0 * 16, mtx) << 0;
   nz |= QuantizeBlock_NEON(in + 1 * 16, out + 1 * 16, mtx) << 1;
@@ -911,6 +925,271 @@ static int Quantize2Blocks_NEON(int16_t in[32], int16_t out[32],
 
 #endif   // !WORK_AROUND_GCC
 
+#if WEBP_AARCH64
+
+#if BPS == 32
+#define DC4_VE4_HE4_TM4_NEON(dst, tbl, res, lane)                              \
+  do {                                                                         \
+    uint8x16_t r;                                                              \
+    r = vqtbl2q_u8(qcombined, tbl);                                            \
+    r = vreinterpretq_u8_u32(                                                  \
+        vsetq_lane_u32(vget_lane_u32(vreinterpret_u32_u8(res), lane),          \
+                       vreinterpretq_u32_u8(r), 1));                           \
+    vst1q_u8(dst, r);                                                          \
+  } while (0)
+
+#define RD4_VR4_LD4_VL4_NEON(dst, tbl)                                         \
+  do {                                                                         \
+    uint8x16_t r;                                                              \
+    r = vqtbl2q_u8(qcombined, tbl);                                            \
+    vst1q_u8(dst, r);                                                          \
+  } while (0)
+
+static void Intra4Preds_NEON(uint8_t* WEBP_RESTRICT dst,
+                             const uint8_t* WEBP_RESTRICT top) {
+  // 0   1   2   3   4   5   6   7   8   9  10  11  12  13
+  //     L   K   J   I   X   A   B   C   D   E   F   G   H
+  //    -5  -4  -3  -2  -1   0   1   2   3   4   5   6   7
+  static const uint8_t kLookupTbl1[64] = {
+    0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 12, 12,
+    3,  3,  3,  3,  2,  2,  2,  2,  1,  1,  1,  1,  0,  0,  0,  0,
+    4, 20, 21, 22,  3, 18,  2, 17,  3, 19,  4, 20,  2, 17,  1, 16,
+    2, 18,  3, 19,  1, 16, 31, 31,  1, 17,  2, 18, 31, 31, 31, 31
+  };
+
+  static const uint8_t kLookupTbl2[64] = {
+    20, 21, 22, 23,  5,  6,  7,  8, 22, 23, 24, 25,  6,  7,  8,  9,
+    19, 20, 21, 22, 20, 21, 22, 23, 23, 24, 25, 26, 22, 23, 24, 25,
+    18, 19, 20, 21, 19,  5,  6,  7, 24, 25, 26, 27,  7,  8,  9, 26,
+    17, 18, 19, 20, 18, 20, 21, 22, 25, 26, 27, 28, 23, 24, 25, 27
+  };
+
+  static const uint8_t kLookupTbl3[64] = {
+    30, 30, 30, 30,  0,  0,  0,  0, 21, 22, 23, 24, 19, 19, 19, 19,
+    30, 30, 30, 30,  0,  0,  0,  0, 21, 22, 23, 24, 18, 18, 18, 18,
+    30, 30, 30, 30,  0,  0,  0,  0, 21, 22, 23, 24, 17, 17, 17, 17,
+    30, 30, 30, 30,  0,  0,  0,  0, 21, 22, 23, 24, 16, 16, 16, 16
+  };
+
+  const uint8x16x4_t lookup_avgs1 = vld1q_u8_x4(kLookupTbl1);
+  const uint8x16x4_t lookup_avgs2 = vld1q_u8_x4(kLookupTbl2);
+  const uint8x16x4_t lookup_avgs3 = vld1q_u8_x4(kLookupTbl3);
+
+  const uint8x16_t preload = vld1q_u8(top - 5);
+  uint8x16x2_t qcombined;
+  uint8x16_t result0, result1;
+
+  uint8x16_t a = vqtbl1q_u8(preload, lookup_avgs1.val[0]);
+  uint8x16_t b = preload;
+  uint8x16_t c = vextq_u8(a, a, 2);
+
+  uint8x16_t avg3_all = vrhaddq_u8(vhaddq_u8(a, c), b);
+  uint8x16_t avg2_all = vrhaddq_u8(a, b);
+
+  uint8x8_t preload_x8, sub_a, sub_c;
+  uint8_t result_u8;
+  uint8x8_t res_lo, res_hi;
+  uint8x16_t full_b;
+  uint16x8_t sub, sum_lo, sum_hi;
+
+  preload_x8 = vget_low_u8(c);
+  preload_x8 = vset_lane_u8(vgetq_lane_u8(preload, 0), preload_x8, 3);
+
+  result_u8 = (vaddlv_u8(preload_x8) + 4) >> 3;
+
+  avg3_all = vsetq_lane_u8(vgetq_lane_u8(preload, 0), avg3_all, 15);
+  avg3_all = vsetq_lane_u8(result_u8, avg3_all, 14);
+
+  qcombined.val[0] = avg2_all;
+  qcombined.val[1] = avg3_all;
+
+  sub_a = vdup_laneq_u8(preload, 4);
+
+  // preload = {a,b,c,d,...} => full_b = {d,d,d,d,c,c,c,c,b,b,b,b,a,a,a,a}
+  full_b = vqtbl1q_u8(preload, lookup_avgs1.val[1]);
+  // preload = {a,b,c,d,...} => sub_c = {a,b,c,d,a,b,c,d,a,b,c,d,a,b,c,d}
+  sub_c = vreinterpret_u8_u32(vdup_n_u32(
+      vgetq_lane_u32(vreinterpretq_u32_u8(vextq_u8(preload, preload, 5)), 0)));
+
+  sub = vsubl_u8(sub_c, sub_a);
+  sum_lo = vaddw_u8(sub, vget_low_u8(full_b));
+  res_lo = vqmovun_s16(vreinterpretq_s16_u16(sum_lo));
+
+  sum_hi = vaddw_u8(sub, vget_high_u8(full_b));
+  res_hi = vqmovun_s16(vreinterpretq_s16_u16(sum_hi));
+
+  // DC4, VE4, HE4, TM4
+  DC4_VE4_HE4_TM4_NEON(dst + I4DC4 + BPS * 0, lookup_avgs3.val[0], res_lo, 0);
+  DC4_VE4_HE4_TM4_NEON(dst + I4DC4 + BPS * 1, lookup_avgs3.val[1], res_lo, 1);
+  DC4_VE4_HE4_TM4_NEON(dst + I4DC4 + BPS * 2, lookup_avgs3.val[2], res_hi, 0);
+  DC4_VE4_HE4_TM4_NEON(dst + I4DC4 + BPS * 3, lookup_avgs3.val[3], res_hi, 1);
+
+  // RD4, VR4, LD4, VL4
+  RD4_VR4_LD4_VL4_NEON(dst + I4RD4 + BPS * 0, lookup_avgs2.val[0]);
+  RD4_VR4_LD4_VL4_NEON(dst + I4RD4 + BPS * 1, lookup_avgs2.val[1]);
+  RD4_VR4_LD4_VL4_NEON(dst + I4RD4 + BPS * 2, lookup_avgs2.val[2]);
+  RD4_VR4_LD4_VL4_NEON(dst + I4RD4 + BPS * 3, lookup_avgs2.val[3]);
+
+  // HD4, HU4
+  result0 = vqtbl2q_u8(qcombined, lookup_avgs1.val[2]);
+  result1 = vqtbl2q_u8(qcombined, lookup_avgs1.val[3]);
+
+  vst1_u8(dst + I4HD4 + BPS * 0, vget_low_u8(result0));
+  vst1_u8(dst + I4HD4 + BPS * 1, vget_high_u8(result0));
+  vst1_u8(dst + I4HD4 + BPS * 2, vget_low_u8(result1));
+  vst1_u8(dst + I4HD4 + BPS * 3, vget_high_u8(result1));
+}
+#endif  // BPS == 32
+
+static WEBP_INLINE void Fill_NEON(uint8_t* dst, const uint8_t value) {
+  uint8x16_t a = vdupq_n_u8(value);
+  int i;
+  for (i = 0; i < 16; i++) {
+    vst1q_u8(dst + BPS * i, a);
+  }
+}
+
+static WEBP_INLINE void Fill16_NEON(uint8_t* dst, const uint8_t* src) {
+  uint8x16_t a = vld1q_u8(src);
+  int i;
+  for (i = 0; i < 16; i++) {
+    vst1q_u8(dst + BPS * i, a);
+  }
+}
+
+static WEBP_INLINE void HorizontalPred16_NEON(uint8_t* dst,
+                                              const uint8_t* left) {
+  uint8x16_t a;
+
+  if (left == NULL) {
+    Fill_NEON(dst, 129);
+    return;
+  }
+
+  a = vld1q_u8(left + 0);
+  vst1q_u8(dst + BPS * 0, vdupq_laneq_u8(a, 0));
+  vst1q_u8(dst + BPS * 1, vdupq_laneq_u8(a, 1));
+  vst1q_u8(dst + BPS * 2, vdupq_laneq_u8(a, 2));
+  vst1q_u8(dst + BPS * 3, vdupq_laneq_u8(a, 3));
+  vst1q_u8(dst + BPS * 4, vdupq_laneq_u8(a, 4));
+  vst1q_u8(dst + BPS * 5, vdupq_laneq_u8(a, 5));
+  vst1q_u8(dst + BPS * 6, vdupq_laneq_u8(a, 6));
+  vst1q_u8(dst + BPS * 7, vdupq_laneq_u8(a, 7));
+  vst1q_u8(dst + BPS * 8, vdupq_laneq_u8(a, 8));
+  vst1q_u8(dst + BPS * 9, vdupq_laneq_u8(a, 9));
+  vst1q_u8(dst + BPS * 10, vdupq_laneq_u8(a, 10));
+  vst1q_u8(dst + BPS * 11, vdupq_laneq_u8(a, 11));
+  vst1q_u8(dst + BPS * 12, vdupq_laneq_u8(a, 12));
+  vst1q_u8(dst + BPS * 13, vdupq_laneq_u8(a, 13));
+  vst1q_u8(dst + BPS * 14, vdupq_laneq_u8(a, 14));
+  vst1q_u8(dst + BPS * 15, vdupq_laneq_u8(a, 15));
+}
+
+static WEBP_INLINE void VerticalPred16_NEON(uint8_t* dst, const uint8_t* top) {
+  if (top != NULL) {
+    Fill16_NEON(dst, top);
+  } else {
+    Fill_NEON(dst, 127);
+  }
+}
+
+static WEBP_INLINE void DCMode_NEON(uint8_t* dst, const uint8_t* left,
+                                    const uint8_t* top) {
+  uint8_t s;
+
+  if (top != NULL) {
+    uint16_t dc;
+    dc = vaddlvq_u8(vld1q_u8(top));
+    if (left != NULL) {
+      // top and left present.
+      dc += vaddlvq_u8(vld1q_u8(left));
+      s = vqrshrnh_n_u16(dc, 5);
+    } else {
+      // top but no left.
+      s = vqrshrnh_n_u16(dc, 4);
+    }
+  } else {
+    if (left != NULL) {
+      uint16_t dc;
+      // left but no top.
+      dc = vaddlvq_u8(vld1q_u8(left));
+      s = vqrshrnh_n_u16(dc, 4);
+    } else {
+      // No top, no left, nothing.
+      s = 0x80;
+    }
+  }
+  Fill_NEON(dst, s);
+}
+
+static WEBP_INLINE void TrueMotionHelper_NEON(uint8_t* dst,
+                                              const uint8x8_t outer,
+                                              const uint8x8x2_t inner,
+                                              const uint16x8_t a, int i,
+                                              const int n) {
+  uint8x8_t d1, d2;
+  uint16x8_t r1, r2;
+
+  r1 = vaddl_u8(outer, inner.val[0]);
+  r1 = vqsubq_u16(r1, a);
+  d1 = vqmovun_s16(vreinterpretq_s16_u16(r1));
+  r2 = vaddl_u8(outer, inner.val[1]);
+  r2 = vqsubq_u16(r2, a);
+  d2 = vqmovun_s16(vreinterpretq_s16_u16(r2));
+  vst1_u8(dst + BPS * (i * 4 + n), d1);
+  vst1_u8(dst + BPS * (i * 4 + n) + 8, d2);
+}
+
+static WEBP_INLINE void TrueMotion_NEON(uint8_t* dst, const uint8_t* left,
+                                        const uint8_t* top) {
+  int i;
+  uint16x8_t a;
+  uint8x8x2_t inner;
+
+  if (left == NULL) {
+    // True motion without left samples (hence: with default 129 value) is
+    // equivalent to VE prediction where you just copy the top samples.
+    // Note that if top samples are not available, the default value is then
+    // 129, and not 127 as in the VerticalPred case.
+    if (top != NULL) {
+      VerticalPred16_NEON(dst, top);
+    } else {
+      Fill_NEON(dst, 129);
+    }
+    return;
+  }
+
+  // left is not NULL.
+  if (top == NULL) {
+    HorizontalPred16_NEON(dst, left);
+    return;
+  }
+
+  // Neither left nor top are NULL.
+  a = vdupq_n_u16(left[-1]);
+  inner = vld1_u8_x2(top);
+
+  for (i = 0; i < 4; i++) {
+    const uint8x8x4_t outer = vld4_dup_u8(&left[i * 4]);
+
+    TrueMotionHelper_NEON(dst, outer.val[0], inner, a, i, 0);
+    TrueMotionHelper_NEON(dst, outer.val[1], inner, a, i, 1);
+    TrueMotionHelper_NEON(dst, outer.val[2], inner, a, i, 2);
+    TrueMotionHelper_NEON(dst, outer.val[3], inner, a, i, 3);
+  }
+}
+
+static void Intra16Preds_NEON(uint8_t* WEBP_RESTRICT dst,
+                              const uint8_t* WEBP_RESTRICT left,
+                              const uint8_t* WEBP_RESTRICT top) {
+  DCMode_NEON(I16DC16 + dst, left, top);
+  VerticalPred16_NEON(I16VE16 + dst, top);
+  HorizontalPred16_NEON(I16HE16 + dst, left);
+  TrueMotion_NEON(I16TM16 + dst, left, top);
+}
+
+#endif // WEBP_AARCH64
+
 //------------------------------------------------------------------------------
 // Entry point
 
@@ -931,9 +1210,17 @@ WEBP_TSAN_IGNORE_FUNCTION void VP8EncDspInitNEON(void) {
   VP8SSE8x8 = SSE8x8_NEON;
   VP8SSE4x4 = SSE4x4_NEON;
 
+#if WEBP_AARCH64
+#if BPS == 32
+  VP8EncPredLuma4 = Intra4Preds_NEON;
+#endif
+  VP8EncPredLuma16 = Intra16Preds_NEON;
+#endif
+
 #if !defined(WORK_AROUND_GCC)
   VP8EncQuantizeBlock = QuantizeBlock_NEON;
   VP8EncQuantize2Blocks = Quantize2Blocks_NEON;
+  VP8EncQuantizeBlockWHT = QuantizeBlock_NEON;
 #endif
 }
 
diff --git a/src/dsp/enc_sse2.c b/src/dsp/enc_sse2.c
index 010624a2..588a6292 100644
--- a/src/dsp/enc_sse2.c
+++ b/src/dsp/enc_sse2.c
@@ -26,8 +26,9 @@
 // Transforms (Paragraph 14.4)
 
 // Does one inverse transform.
-static void ITransform_One_SSE2(const uint8_t* ref, const int16_t* in,
-                                uint8_t* dst) {
+static void ITransform_One_SSE2(const uint8_t* WEBP_RESTRICT ref,
+                                const int16_t* WEBP_RESTRICT in,
+                                uint8_t* WEBP_RESTRICT dst) {
   // This implementation makes use of 16-bit fixed point versions of two
   // multiply constants:
   //    K1 = sqrt(2) * cos (pi/8) ~= 85627 / 2^16
@@ -177,8 +178,9 @@ static void ITransform_One_SSE2(const uint8_t* ref, const int16_t* in,
 }
 
 // Does two inverse transforms.
-static void ITransform_Two_SSE2(const uint8_t* ref, const int16_t* in,
-                                uint8_t* dst) {
+static void ITransform_Two_SSE2(const uint8_t* WEBP_RESTRICT ref,
+                                const int16_t* WEBP_RESTRICT in,
+                                uint8_t* WEBP_RESTRICT dst) {
   // This implementation makes use of 16-bit fixed point versions of two
   // multiply constants:
   //    K1 = sqrt(2) * cos (pi/8) ~= 85627 / 2^16
@@ -316,7 +318,9 @@ static void ITransform_Two_SSE2(const uint8_t* ref, const int16_t* in,
 }
 
 // Does one or two inverse transforms.
-static void ITransform_SSE2(const uint8_t* ref, const int16_t* in, uint8_t* dst,
+static void ITransform_SSE2(const uint8_t* WEBP_RESTRICT ref,
+                            const int16_t* WEBP_RESTRICT in,
+                            uint8_t* WEBP_RESTRICT dst,
                             int do_two) {
   if (do_two) {
     ITransform_Two_SSE2(ref, in, dst);
@@ -373,7 +377,7 @@ static void FTransformPass1_SSE2(const __m128i* const in01,
 
 static void FTransformPass2_SSE2(const __m128i* const v01,
                                  const __m128i* const v32,
-                                 int16_t* out) {
+                                 int16_t* WEBP_RESTRICT out) {
   const __m128i zero = _mm_setzero_si128();
   const __m128i seven = _mm_set1_epi16(7);
   const __m128i k5352_2217 = _mm_set_epi16(5352,  2217, 5352,  2217,
@@ -424,8 +428,9 @@ static void FTransformPass2_SSE2(const __m128i* const v01,
   _mm_storeu_si128((__m128i*)&out[8], d2_f3);
 }
 
-static void FTransform_SSE2(const uint8_t* src, const uint8_t* ref,
-                            int16_t* out) {
+static void FTransform_SSE2(const uint8_t* WEBP_RESTRICT src,
+                            const uint8_t* WEBP_RESTRICT ref,
+                            int16_t* WEBP_RESTRICT out) {
   const __m128i zero = _mm_setzero_si128();
   // Load src.
   const __m128i src0 = _mm_loadl_epi64((const __m128i*)&src[0 * BPS]);
@@ -468,8 +473,9 @@ static void FTransform_SSE2(const uint8_t* src, const uint8_t* ref,
   FTransformPass2_SSE2(&v01, &v32, out);
 }
 
-static void FTransform2_SSE2(const uint8_t* src, const uint8_t* ref,
-                             int16_t* out) {
+static void FTransform2_SSE2(const uint8_t* WEBP_RESTRICT src,
+                             const uint8_t* WEBP_RESTRICT ref,
+                             int16_t* WEBP_RESTRICT out) {
   const __m128i zero = _mm_setzero_si128();
 
   // Load src and convert to 16b.
@@ -517,7 +523,8 @@ static void FTransform2_SSE2(const uint8_t* src, const uint8_t* ref,
   FTransformPass2_SSE2(&v01h, &v32h, out + 16);
 }
 
-static void FTransformWHTRow_SSE2(const int16_t* const in, __m128i* const out) {
+static void FTransformWHTRow_SSE2(const int16_t* WEBP_RESTRICT const in,
+                                  __m128i* const out) {
   const __m128i kMult = _mm_set_epi16(-1, 1, -1, 1, 1, 1, 1, 1);
   const __m128i src0 = _mm_loadl_epi64((__m128i*)&in[0 * 16]);
   const __m128i src1 = _mm_loadl_epi64((__m128i*)&in[1 * 16]);
@@ -533,7 +540,8 @@ static void FTransformWHTRow_SSE2(const int16_t* const in, __m128i* const out) {
   *out = _mm_madd_epi16(D, kMult);
 }
 
-static void FTransformWHT_SSE2(const int16_t* in, int16_t* out) {
+static void FTransformWHT_SSE2(const int16_t* WEBP_RESTRICT in,
+                               int16_t* WEBP_RESTRICT out) {
   // Input is 12b signed.
   __m128i row0, row1, row2, row3;
   // Rows are 14b signed.
@@ -566,9 +574,10 @@ static void FTransformWHT_SSE2(const int16_t* in, int16_t* out) {
 // Compute susceptibility based on DCT-coeff histograms:
 // the higher, the "easier" the macroblock is to compress.
 
-static void CollectHistogram_SSE2(const uint8_t* ref, const uint8_t* pred,
+static void CollectHistogram_SSE2(const uint8_t* WEBP_RESTRICT ref,
+                                  const uint8_t* WEBP_RESTRICT pred,
                                   int start_block, int end_block,
-                                  VP8Histogram* const histo) {
+                                  VP8Histogram* WEBP_RESTRICT const histo) {
   const __m128i zero = _mm_setzero_si128();
   const __m128i max_coeff_thresh = _mm_set1_epi16(MAX_COEFF_THRESH);
   int j;
@@ -640,7 +649,8 @@ static WEBP_INLINE void Fill_SSE2(uint8_t* dst, int value, int size) {
   }
 }
 
-static WEBP_INLINE void VE8uv_SSE2(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void VE8uv_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                   const uint8_t* WEBP_RESTRICT top) {
   int j;
   const __m128i top_values = _mm_loadl_epi64((const __m128i*)top);
   for (j = 0; j < 8; ++j) {
@@ -648,7 +658,8 @@ static WEBP_INLINE void VE8uv_SSE2(uint8_t* dst, const uint8_t* top) {
   }
 }
 
-static WEBP_INLINE void VE16_SSE2(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void VE16_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                  const uint8_t* WEBP_RESTRICT top) {
   const __m128i top_values = _mm_load_si128((const __m128i*)top);
   int j;
   for (j = 0; j < 16; ++j) {
@@ -656,8 +667,9 @@ static WEBP_INLINE void VE16_SSE2(uint8_t* dst, const uint8_t* top) {
   }
 }
 
-static WEBP_INLINE void VerticalPred_SSE2(uint8_t* dst,
-                                          const uint8_t* top, int size) {
+static WEBP_INLINE void VerticalPred_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                          const uint8_t* WEBP_RESTRICT top,
+                                          int size) {
   if (top != NULL) {
     if (size == 8) {
       VE8uv_SSE2(dst, top);
@@ -669,7 +681,8 @@ static WEBP_INLINE void VerticalPred_SSE2(uint8_t* dst,
   }
 }
 
-static WEBP_INLINE void HE8uv_SSE2(uint8_t* dst, const uint8_t* left) {
+static WEBP_INLINE void HE8uv_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                   const uint8_t* WEBP_RESTRICT left) {
   int j;
   for (j = 0; j < 8; ++j) {
     const __m128i values = _mm_set1_epi8((char)left[j]);
@@ -678,7 +691,8 @@ static WEBP_INLINE void HE8uv_SSE2(uint8_t* dst, const uint8_t* left) {
   }
 }
 
-static WEBP_INLINE void HE16_SSE2(uint8_t* dst, const uint8_t* left) {
+static WEBP_INLINE void HE16_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                  const uint8_t* WEBP_RESTRICT left) {
   int j;
   for (j = 0; j < 16; ++j) {
     const __m128i values = _mm_set1_epi8((char)left[j]);
@@ -687,8 +701,9 @@ static WEBP_INLINE void HE16_SSE2(uint8_t* dst, const uint8_t* left) {
   }
 }
 
-static WEBP_INLINE void HorizontalPred_SSE2(uint8_t* dst,
-                                            const uint8_t* left, int size) {
+static WEBP_INLINE void HorizontalPred_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                            const uint8_t* WEBP_RESTRICT left,
+                                            int size) {
   if (left != NULL) {
     if (size == 8) {
       HE8uv_SSE2(dst, left);
@@ -700,8 +715,9 @@ static WEBP_INLINE void HorizontalPred_SSE2(uint8_t* dst,
   }
 }
 
-static WEBP_INLINE void TM_SSE2(uint8_t* dst, const uint8_t* left,
-                                const uint8_t* top, int size) {
+static WEBP_INLINE void TM_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                const uint8_t* WEBP_RESTRICT left,
+                                const uint8_t* WEBP_RESTRICT top, int size) {
   const __m128i zero = _mm_setzero_si128();
   int y;
   if (size == 8) {
@@ -728,8 +744,10 @@ static WEBP_INLINE void TM_SSE2(uint8_t* dst, const uint8_t* left,
   }
 }
 
-static WEBP_INLINE void TrueMotion_SSE2(uint8_t* dst, const uint8_t* left,
-                                        const uint8_t* top, int size) {
+static WEBP_INLINE void TrueMotion_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                        const uint8_t* WEBP_RESTRICT left,
+                                        const uint8_t* WEBP_RESTRICT top,
+                                        int size) {
   if (left != NULL) {
     if (top != NULL) {
       TM_SSE2(dst, left, top, size);
@@ -749,8 +767,9 @@ static WEBP_INLINE void TrueMotion_SSE2(uint8_t* dst, const uint8_t* left,
   }
 }
 
-static WEBP_INLINE void DC8uv_SSE2(uint8_t* dst, const uint8_t* left,
-                                   const uint8_t* top) {
+static WEBP_INLINE void DC8uv_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                   const uint8_t* WEBP_RESTRICT left,
+                                   const uint8_t* WEBP_RESTRICT top) {
   const __m128i top_values = _mm_loadl_epi64((const __m128i*)top);
   const __m128i left_values = _mm_loadl_epi64((const __m128i*)left);
   const __m128i combined = _mm_unpacklo_epi64(top_values, left_values);
@@ -758,7 +777,8 @@ static WEBP_INLINE void DC8uv_SSE2(uint8_t* dst, const uint8_t* left,
   Put8x8uv_SSE2(DC >> 4, dst);
 }
 
-static WEBP_INLINE void DC8uvNoLeft_SSE2(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void DC8uvNoLeft_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                         const uint8_t* WEBP_RESTRICT top) {
   const __m128i zero = _mm_setzero_si128();
   const __m128i top_values = _mm_loadl_epi64((const __m128i*)top);
   const __m128i sum = _mm_sad_epu8(top_values, zero);
@@ -766,7 +786,8 @@ static WEBP_INLINE void DC8uvNoLeft_SSE2(uint8_t* dst, const uint8_t* top) {
   Put8x8uv_SSE2(DC >> 3, dst);
 }
 
-static WEBP_INLINE void DC8uvNoTop_SSE2(uint8_t* dst, const uint8_t* left) {
+static WEBP_INLINE void DC8uvNoTop_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                        const uint8_t* WEBP_RESTRICT left) {
   // 'left' is contiguous so we can reuse the top summation.
   DC8uvNoLeft_SSE2(dst, left);
 }
@@ -775,8 +796,9 @@ static WEBP_INLINE void DC8uvNoTopLeft_SSE2(uint8_t* dst) {
   Put8x8uv_SSE2(0x80, dst);
 }
 
-static WEBP_INLINE void DC8uvMode_SSE2(uint8_t* dst, const uint8_t* left,
-                                       const uint8_t* top) {
+static WEBP_INLINE void DC8uvMode_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                       const uint8_t* WEBP_RESTRICT left,
+                                       const uint8_t* WEBP_RESTRICT top) {
   if (top != NULL) {
     if (left != NULL) {  // top and left present
       DC8uv_SSE2(dst, left, top);
@@ -790,8 +812,9 @@ static WEBP_INLINE void DC8uvMode_SSE2(uint8_t* dst, const uint8_t* left,
   }
 }
 
-static WEBP_INLINE void DC16_SSE2(uint8_t* dst, const uint8_t* left,
-                                  const uint8_t* top) {
+static WEBP_INLINE void DC16_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                  const uint8_t* WEBP_RESTRICT left,
+                                  const uint8_t* WEBP_RESTRICT top) {
   const __m128i top_row = _mm_load_si128((const __m128i*)top);
   const __m128i left_row = _mm_load_si128((const __m128i*)left);
   const int DC =
@@ -799,13 +822,15 @@ static WEBP_INLINE void DC16_SSE2(uint8_t* dst, const uint8_t* left,
   Put16_SSE2(DC >> 5, dst);
 }
 
-static WEBP_INLINE void DC16NoLeft_SSE2(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void DC16NoLeft_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                        const uint8_t* WEBP_RESTRICT top) {
   const __m128i top_row = _mm_load_si128((const __m128i*)top);
   const int DC = VP8HorizontalAdd8b(&top_row) + 8;
   Put16_SSE2(DC >> 4, dst);
 }
 
-static WEBP_INLINE void DC16NoTop_SSE2(uint8_t* dst, const uint8_t* left) {
+static WEBP_INLINE void DC16NoTop_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                       const uint8_t* WEBP_RESTRICT left) {
   // 'left' is contiguous so we can reuse the top summation.
   DC16NoLeft_SSE2(dst, left);
 }
@@ -814,8 +839,9 @@ static WEBP_INLINE void DC16NoTopLeft_SSE2(uint8_t* dst) {
   Put16_SSE2(0x80, dst);
 }
 
-static WEBP_INLINE void DC16Mode_SSE2(uint8_t* dst, const uint8_t* left,
-                                      const uint8_t* top) {
+static WEBP_INLINE void DC16Mode_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                      const uint8_t* WEBP_RESTRICT left,
+                                      const uint8_t* WEBP_RESTRICT top) {
   if (top != NULL) {
     if (left != NULL) {  // top and left present
       DC16_SSE2(dst, left, top);
@@ -844,8 +870,9 @@ static WEBP_INLINE void DC16Mode_SSE2(uint8_t* dst, const uint8_t* left,
 //   where: AC = (a + b + 1) >> 1,   BC = (b + c + 1) >> 1
 //   and ab = a ^ b, bc = b ^ c, lsb = (AC^BC)&1
 
-static WEBP_INLINE void VE4_SSE2(uint8_t* dst,
-                                 const uint8_t* top) {  // vertical
+// vertical
+static WEBP_INLINE void VE4_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT top) {
   const __m128i one = _mm_set1_epi8(1);
   const __m128i ABCDEFGH = _mm_loadl_epi64((__m128i*)(top - 1));
   const __m128i BCDEFGH0 = _mm_srli_si128(ABCDEFGH, 1);
@@ -861,8 +888,9 @@ static WEBP_INLINE void VE4_SSE2(uint8_t* dst,
   }
 }
 
-static WEBP_INLINE void HE4_SSE2(uint8_t* dst,
-                                 const uint8_t* top) {  // horizontal
+// horizontal
+static WEBP_INLINE void HE4_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT top) {
   const int X = top[-1];
   const int I = top[-2];
   const int J = top[-3];
@@ -874,15 +902,17 @@ static WEBP_INLINE void HE4_SSE2(uint8_t* dst,
   WebPUint32ToMem(dst + 3 * BPS, 0x01010101U * AVG3(K, L, L));
 }
 
-static WEBP_INLINE void DC4_SSE2(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void DC4_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT top) {
   uint32_t dc = 4;
   int i;
   for (i = 0; i < 4; ++i) dc += top[i] + top[-5 + i];
   Fill_SSE2(dst, dc >> 3, 4);
 }
 
-static WEBP_INLINE void LD4_SSE2(uint8_t* dst,
-                                 const uint8_t* top) {  // Down-Left
+// Down-Left
+static WEBP_INLINE void LD4_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT top) {
   const __m128i one = _mm_set1_epi8(1);
   const __m128i ABCDEFGH = _mm_loadl_epi64((const __m128i*)top);
   const __m128i BCDEFGH0 = _mm_srli_si128(ABCDEFGH, 1);
@@ -898,8 +928,9 @@ static WEBP_INLINE void LD4_SSE2(uint8_t* dst,
   WebPInt32ToMem(dst + 3 * BPS, _mm_cvtsi128_si32(_mm_srli_si128(abcdefg, 3)));
 }
 
-static WEBP_INLINE void VR4_SSE2(uint8_t* dst,
-                                 const uint8_t* top) {  // Vertical-Right
+// Vertical-Right
+static WEBP_INLINE void VR4_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT top) {
   const __m128i one = _mm_set1_epi8(1);
   const int I = top[-2];
   const int J = top[-3];
@@ -924,8 +955,9 @@ static WEBP_INLINE void VR4_SSE2(uint8_t* dst,
   DST(0, 3) = AVG3(K, J, I);
 }
 
-static WEBP_INLINE void VL4_SSE2(uint8_t* dst,
-                                 const uint8_t* top) {  // Vertical-Left
+// Vertical-Left
+static WEBP_INLINE void VL4_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT top) {
   const __m128i one = _mm_set1_epi8(1);
   const __m128i ABCDEFGH = _mm_loadl_epi64((const __m128i*)top);
   const __m128i BCDEFGH_ = _mm_srli_si128(ABCDEFGH, 1);
@@ -951,8 +983,9 @@ static WEBP_INLINE void VL4_SSE2(uint8_t* dst,
   DST(3, 3) = (extra_out >> 8) & 0xff;
 }
 
-static WEBP_INLINE void RD4_SSE2(uint8_t* dst,
-                                 const uint8_t* top) {  // Down-right
+// Down-right
+static WEBP_INLINE void RD4_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT top) {
   const __m128i one = _mm_set1_epi8(1);
   const __m128i LKJIXABC = _mm_loadl_epi64((const __m128i*)(top - 5));
   const __m128i LKJIXABCD = _mm_insert_epi16(LKJIXABC, top[3], 4);
@@ -968,7 +1001,8 @@ static WEBP_INLINE void RD4_SSE2(uint8_t* dst,
   WebPInt32ToMem(dst + 0 * BPS, _mm_cvtsi128_si32(_mm_srli_si128(abcdefg, 3)));
 }
 
-static WEBP_INLINE void HU4_SSE2(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void HU4_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT top) {
   const int I = top[-2];
   const int J = top[-3];
   const int K = top[-4];
@@ -983,7 +1017,8 @@ static WEBP_INLINE void HU4_SSE2(uint8_t* dst, const uint8_t* top) {
   DST(0, 3) = DST(1, 3) = DST(2, 3) = DST(3, 3) = L;
 }
 
-static WEBP_INLINE void HD4_SSE2(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void HD4_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT top) {
   const int X = top[-1];
   const int I = top[-2];
   const int J = top[-3];
@@ -1006,7 +1041,8 @@ static WEBP_INLINE void HD4_SSE2(uint8_t* dst, const uint8_t* top) {
   DST(1, 3)             = AVG3(L, K, J);
 }
 
-static WEBP_INLINE void TM4_SSE2(uint8_t* dst, const uint8_t* top) {
+static WEBP_INLINE void TM4_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                 const uint8_t* WEBP_RESTRICT top) {
   const __m128i zero = _mm_setzero_si128();
   const __m128i top_values = _mm_cvtsi32_si128(WebPMemToInt32(top));
   const __m128i top_base = _mm_unpacklo_epi8(top_values, zero);
@@ -1028,7 +1064,8 @@ static WEBP_INLINE void TM4_SSE2(uint8_t* dst, const uint8_t* top) {
 
 // Left samples are top[-5 .. -2], top_left is top[-1], top are
 // located at top[0..3], and top right is top[4..7]
-static void Intra4Preds_SSE2(uint8_t* dst, const uint8_t* top) {
+static void Intra4Preds_SSE2(uint8_t* WEBP_RESTRICT dst,
+                             const uint8_t* WEBP_RESTRICT top) {
   DC4_SSE2(I4DC4 + dst, top);
   TM4_SSE2(I4TM4 + dst, top);
   VE4_SSE2(I4VE4 + dst, top);
@@ -1044,8 +1081,9 @@ static void Intra4Preds_SSE2(uint8_t* dst, const uint8_t* top) {
 //------------------------------------------------------------------------------
 // Chroma 8x8 prediction (paragraph 12.2)
 
-static void IntraChromaPreds_SSE2(uint8_t* dst, const uint8_t* left,
-                                  const uint8_t* top) {
+static void IntraChromaPreds_SSE2(uint8_t* WEBP_RESTRICT dst,
+                                  const uint8_t* WEBP_RESTRICT left,
+                                  const uint8_t* WEBP_RESTRICT top) {
   // U block
   DC8uvMode_SSE2(C8DC8 + dst, left, top);
   VerticalPred_SSE2(C8VE8 + dst, top, 8);
@@ -1064,8 +1102,9 @@ static void IntraChromaPreds_SSE2(uint8_t* dst, const uint8_t* left,
 //------------------------------------------------------------------------------
 // luma 16x16 prediction (paragraph 12.3)
 
-static void Intra16Preds_SSE2(uint8_t* dst,
-                              const uint8_t* left, const uint8_t* top) {
+static void Intra16Preds_SSE2(uint8_t* WEBP_RESTRICT dst,
+                              const uint8_t* WEBP_RESTRICT left,
+                              const uint8_t* WEBP_RESTRICT top) {
   DC16Mode_SSE2(I16DC16 + dst, left, top);
   VerticalPred_SSE2(I16VE16 + dst, top, 16);
   HorizontalPred_SSE2(I16HE16 + dst, left, 16);
@@ -1092,7 +1131,8 @@ static WEBP_INLINE void SubtractAndAccumulate_SSE2(const __m128i a,
   *sum = _mm_add_epi32(sum1, sum2);
 }
 
-static WEBP_INLINE int SSE_16xN_SSE2(const uint8_t* a, const uint8_t* b,
+static WEBP_INLINE int SSE_16xN_SSE2(const uint8_t* WEBP_RESTRICT a,
+                                     const uint8_t* WEBP_RESTRICT b,
                                      int num_pairs) {
   __m128i sum = _mm_setzero_si128();
   int32_t tmp[4];
@@ -1114,18 +1154,21 @@ static WEBP_INLINE int SSE_16xN_SSE2(const uint8_t* a, const uint8_t* b,
   return (tmp[3] + tmp[2] + tmp[1] + tmp[0]);
 }
 
-static int SSE16x16_SSE2(const uint8_t* a, const uint8_t* b) {
+static int SSE16x16_SSE2(const uint8_t* WEBP_RESTRICT a,
+                         const uint8_t* WEBP_RESTRICT b) {
   return SSE_16xN_SSE2(a, b, 8);
 }
 
-static int SSE16x8_SSE2(const uint8_t* a, const uint8_t* b) {
+static int SSE16x8_SSE2(const uint8_t* WEBP_RESTRICT a,
+                        const uint8_t* WEBP_RESTRICT b) {
   return SSE_16xN_SSE2(a, b, 4);
 }
 
 #define LOAD_8x16b(ptr) \
   _mm_unpacklo_epi8(_mm_loadl_epi64((const __m128i*)(ptr)), zero)
 
-static int SSE8x8_SSE2(const uint8_t* a, const uint8_t* b) {
+static int SSE8x8_SSE2(const uint8_t* WEBP_RESTRICT a,
+                       const uint8_t* WEBP_RESTRICT b) {
   const __m128i zero = _mm_setzero_si128();
   int num_pairs = 4;
   __m128i sum = zero;
@@ -1152,7 +1195,8 @@ static int SSE8x8_SSE2(const uint8_t* a, const uint8_t* b) {
 }
 #undef LOAD_8x16b
 
-static int SSE4x4_SSE2(const uint8_t* a, const uint8_t* b) {
+static int SSE4x4_SSE2(const uint8_t* WEBP_RESTRICT a,
+                       const uint8_t* WEBP_RESTRICT b) {
   const __m128i zero = _mm_setzero_si128();
 
   // Load values. Note that we read 8 pixels instead of 4,
@@ -1189,7 +1233,7 @@ static int SSE4x4_SSE2(const uint8_t* a, const uint8_t* b) {
 
 //------------------------------------------------------------------------------
 
-static void Mean16x4_SSE2(const uint8_t* ref, uint32_t dc[4]) {
+static void Mean16x4_SSE2(const uint8_t* WEBP_RESTRICT ref, uint32_t dc[4]) {
   const __m128i mask = _mm_set1_epi16(0x00ff);
   const __m128i a0 = _mm_loadu_si128((const __m128i*)&ref[BPS * 0]);
   const __m128i a1 = _mm_loadu_si128((const __m128i*)&ref[BPS * 1]);
@@ -1227,8 +1271,9 @@ static void Mean16x4_SSE2(const uint8_t* ref, uint32_t dc[4]) {
 // Hadamard transform
 // Returns the weighted sum of the absolute value of transformed coefficients.
 // w[] contains a row-major 4 by 4 symmetric matrix.
-static int TTransform_SSE2(const uint8_t* inA, const uint8_t* inB,
-                           const uint16_t* const w) {
+static int TTransform_SSE2(const uint8_t* WEBP_RESTRICT inA,
+                           const uint8_t* WEBP_RESTRICT inB,
+                           const uint16_t* WEBP_RESTRICT const w) {
   int32_t sum[4];
   __m128i tmp_0, tmp_1, tmp_2, tmp_3;
   const __m128i zero = _mm_setzero_si128();
@@ -1328,14 +1373,16 @@ static int TTransform_SSE2(const uint8_t* inA, const uint8_t* inB,
   return sum[0] + sum[1] + sum[2] + sum[3];
 }
 
-static int Disto4x4_SSE2(const uint8_t* const a, const uint8_t* const b,
-                         const uint16_t* const w) {
+static int Disto4x4_SSE2(const uint8_t* WEBP_RESTRICT const a,
+                         const uint8_t* WEBP_RESTRICT const b,
+                         const uint16_t* WEBP_RESTRICT const w) {
   const int diff_sum = TTransform_SSE2(a, b, w);
   return abs(diff_sum) >> 5;
 }
 
-static int Disto16x16_SSE2(const uint8_t* const a, const uint8_t* const b,
-                           const uint16_t* const w) {
+static int Disto16x16_SSE2(const uint8_t* WEBP_RESTRICT const a,
+                           const uint8_t* WEBP_RESTRICT const b,
+                           const uint16_t* WEBP_RESTRICT const w) {
   int D = 0;
   int x, y;
   for (y = 0; y < 16 * BPS; y += 4 * BPS) {
@@ -1350,9 +1397,10 @@ static int Disto16x16_SSE2(const uint8_t* const a, const uint8_t* const b,
 // Quantization
 //
 
-static WEBP_INLINE int DoQuantizeBlock_SSE2(int16_t in[16], int16_t out[16],
-                                            const uint16_t* const sharpen,
-                                            const VP8Matrix* const mtx) {
+static WEBP_INLINE int DoQuantizeBlock_SSE2(
+    int16_t in[16], int16_t out[16],
+    const uint16_t* WEBP_RESTRICT const sharpen,
+    const VP8Matrix* WEBP_RESTRICT const mtx) {
   const __m128i max_coeff_2047 = _mm_set1_epi16(MAX_LEVEL);
   const __m128i zero = _mm_setzero_si128();
   __m128i coeff0, coeff8;
@@ -1463,17 +1511,17 @@ static WEBP_INLINE int DoQuantizeBlock_SSE2(int16_t in[16], int16_t out[16],
 }
 
 static int QuantizeBlock_SSE2(int16_t in[16], int16_t out[16],
-                              const VP8Matrix* const mtx) {
+                              const VP8Matrix* WEBP_RESTRICT const mtx) {
   return DoQuantizeBlock_SSE2(in, out, &mtx->sharpen_[0], mtx);
 }
 
 static int QuantizeBlockWHT_SSE2(int16_t in[16], int16_t out[16],
-                                 const VP8Matrix* const mtx) {
+                                 const VP8Matrix* WEBP_RESTRICT const mtx) {
   return DoQuantizeBlock_SSE2(in, out, NULL, mtx);
 }
 
 static int Quantize2Blocks_SSE2(int16_t in[32], int16_t out[32],
-                                const VP8Matrix* const mtx) {
+                                const VP8Matrix* WEBP_RESTRICT const mtx) {
   int nz;
   const uint16_t* const sharpen = &mtx->sharpen_[0];
   nz  = DoQuantizeBlock_SSE2(in + 0 * 16, out + 0 * 16, sharpen, mtx) << 0;
diff --git a/src/dsp/enc_sse41.c b/src/dsp/enc_sse41.c
index 924035a6..613c44cf 100644
--- a/src/dsp/enc_sse41.c
+++ b/src/dsp/enc_sse41.c
@@ -23,9 +23,10 @@
 //------------------------------------------------------------------------------
 // Compute susceptibility based on DCT-coeff histograms.
 
-static void CollectHistogram_SSE41(const uint8_t* ref, const uint8_t* pred,
+static void CollectHistogram_SSE41(const uint8_t* WEBP_RESTRICT ref,
+                                   const uint8_t* WEBP_RESTRICT pred,
                                    int start_block, int end_block,
-                                   VP8Histogram* const histo) {
+                                   VP8Histogram* WEBP_RESTRICT const histo) {
   const __m128i max_coeff_thresh = _mm_set1_epi16(MAX_COEFF_THRESH);
   int j;
   int distribution[MAX_COEFF_THRESH + 1] = { 0 };
@@ -168,14 +169,16 @@ static int TTransform_SSE41(const uint8_t* inA, const uint8_t* inB,
   return sum[0] + sum[1] + sum[2] + sum[3];
 }
 
-static int Disto4x4_SSE41(const uint8_t* const a, const uint8_t* const b,
-                          const uint16_t* const w) {
+static int Disto4x4_SSE41(const uint8_t* WEBP_RESTRICT const a,
+                          const uint8_t* WEBP_RESTRICT const b,
+                          const uint16_t* WEBP_RESTRICT const w) {
   const int diff_sum = TTransform_SSE41(a, b, w);
   return abs(diff_sum) >> 5;
 }
 
-static int Disto16x16_SSE41(const uint8_t* const a, const uint8_t* const b,
-                            const uint16_t* const w) {
+static int Disto16x16_SSE41(const uint8_t* WEBP_RESTRICT const a,
+                            const uint8_t* WEBP_RESTRICT const b,
+                            const uint16_t* WEBP_RESTRICT const w) {
   int D = 0;
   int x, y;
   for (y = 0; y < 16 * BPS; y += 4 * BPS) {
@@ -301,17 +304,17 @@ static WEBP_INLINE int DoQuantizeBlock_SSE41(int16_t in[16], int16_t out[16],
 #undef PSHUFB_CST
 
 static int QuantizeBlock_SSE41(int16_t in[16], int16_t out[16],
-                               const VP8Matrix* const mtx) {
+                               const VP8Matrix* WEBP_RESTRICT const mtx) {
   return DoQuantizeBlock_SSE41(in, out, &mtx->sharpen_[0], mtx);
 }
 
 static int QuantizeBlockWHT_SSE41(int16_t in[16], int16_t out[16],
-                                  const VP8Matrix* const mtx) {
+                                  const VP8Matrix* WEBP_RESTRICT const mtx) {
   return DoQuantizeBlock_SSE41(in, out, NULL, mtx);
 }
 
 static int Quantize2Blocks_SSE41(int16_t in[32], int16_t out[32],
-                                 const VP8Matrix* const mtx) {
+                                 const VP8Matrix* WEBP_RESTRICT const mtx) {
   int nz;
   const uint16_t* const sharpen = &mtx->sharpen_[0];
   nz  = DoQuantizeBlock_SSE41(in + 0 * 16, out + 0 * 16, sharpen, mtx) << 0;
diff --git a/src/dsp/filters.c b/src/dsp/filters.c
index c9232ff1..f5e1e5f9 100644
--- a/src/dsp/filters.c
+++ b/src/dsp/filters.c
@@ -23,55 +23,42 @@
   do {                                                                         \
     assert((in) != NULL);                                                      \
     assert((out) != NULL);                                                     \
+    assert((in) != (out));                                                     \
     assert(width > 0);                                                         \
     assert(height > 0);                                                        \
     assert(stride >= width);                                                   \
-    assert(row >= 0 && num_rows > 0 && row + num_rows <= height);              \
-    (void)height;  /* Silence unused warning. */                               \
   } while (0)
 
 #if !WEBP_NEON_OMIT_C_CODE
-static WEBP_INLINE void PredictLine_C(const uint8_t* src, const uint8_t* pred,
-                                      uint8_t* dst, int length, int inverse) {
+static WEBP_INLINE void PredictLine_C(const uint8_t* WEBP_RESTRICT src,
+                                      const uint8_t* WEBP_RESTRICT pred,
+                                      uint8_t* WEBP_RESTRICT dst, int length) {
   int i;
-  if (inverse) {
-    for (i = 0; i < length; ++i) dst[i] = (uint8_t)(src[i] + pred[i]);
-  } else {
-    for (i = 0; i < length; ++i) dst[i] = (uint8_t)(src[i] - pred[i]);
-  }
+  for (i = 0; i < length; ++i) dst[i] = (uint8_t)(src[i] - pred[i]);
 }
 
 //------------------------------------------------------------------------------
 // Horizontal filter.
 
-static WEBP_INLINE void DoHorizontalFilter_C(const uint8_t* in,
+static WEBP_INLINE void DoHorizontalFilter_C(const uint8_t* WEBP_RESTRICT in,
                                              int width, int height, int stride,
-                                             int row, int num_rows,
-                                             int inverse, uint8_t* out) {
-  const uint8_t* preds;
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+                                             uint8_t* WEBP_RESTRICT out) {
+  const uint8_t* preds = in;
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
-  preds = inverse ? out : in;
-
-  if (row == 0) {
-    // Leftmost pixel is the same as input for topmost scanline.
-    out[0] = in[0];
-    PredictLine_C(in + 1, preds, out + 1, width - 1, inverse);
-    row = 1;
-    preds += stride;
-    in += stride;
-    out += stride;
-  }
+
+  // Leftmost pixel is the same as input for topmost scanline.
+  out[0] = in[0];
+  PredictLine_C(in + 1, preds, out + 1, width - 1);
+  preds += stride;
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
-  while (row < last_row) {
+  for (row = 1; row < height; ++row) {
     // Leftmost pixel is predicted from above.
-    PredictLine_C(in, preds - stride, out, 1, inverse);
-    PredictLine_C(in + 1, preds, out + 1, width - 1, inverse);
-    ++row;
+    PredictLine_C(in, preds - stride, out, 1);
+    PredictLine_C(in + 1, preds, out + 1, width - 1);
     preds += stride;
     in += stride;
     out += stride;
@@ -81,35 +68,23 @@ static WEBP_INLINE void DoHorizontalFilter_C(const uint8_t* in,
 //------------------------------------------------------------------------------
 // Vertical filter.
 
-static WEBP_INLINE void DoVerticalFilter_C(const uint8_t* in,
+static WEBP_INLINE void DoVerticalFilter_C(const uint8_t* WEBP_RESTRICT in,
                                            int width, int height, int stride,
-                                           int row, int num_rows,
-                                           int inverse, uint8_t* out) {
-  const uint8_t* preds;
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+                                           uint8_t* WEBP_RESTRICT out) {
+  const uint8_t* preds = in;
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
-  preds = inverse ? out : in;
-
-  if (row == 0) {
-    // Very first top-left pixel is copied.
-    out[0] = in[0];
-    // Rest of top scan-line is left-predicted.
-    PredictLine_C(in + 1, preds, out + 1, width - 1, inverse);
-    row = 1;
-    in += stride;
-    out += stride;
-  } else {
-    // We are starting from in-between. Make sure 'preds' points to prev row.
-    preds -= stride;
-  }
+
+  // Very first top-left pixel is copied.
+  out[0] = in[0];
+  // Rest of top scan-line is left-predicted.
+  PredictLine_C(in + 1, preds, out + 1, width - 1);
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
-  while (row < last_row) {
-    PredictLine_C(in, preds, out, width, inverse);
-    ++row;
+  for (row = 1; row < height; ++row) {
+    PredictLine_C(in, preds, out, width);
     preds += stride;
     in += stride;
     out += stride;
@@ -126,40 +101,31 @@ static WEBP_INLINE int GradientPredictor_C(uint8_t a, uint8_t b, uint8_t c) {
 }
 
 #if !WEBP_NEON_OMIT_C_CODE
-static WEBP_INLINE void DoGradientFilter_C(const uint8_t* in,
+static WEBP_INLINE void DoGradientFilter_C(const uint8_t* WEBP_RESTRICT in,
                                            int width, int height, int stride,
-                                           int row, int num_rows,
-                                           int inverse, uint8_t* out) {
-  const uint8_t* preds;
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+                                           uint8_t* WEBP_RESTRICT out) {
+  const uint8_t* preds = in;
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
-  preds = inverse ? out : in;
 
   // left prediction for top scan-line
-  if (row == 0) {
-    out[0] = in[0];
-    PredictLine_C(in + 1, preds, out + 1, width - 1, inverse);
-    row = 1;
-    preds += stride;
-    in += stride;
-    out += stride;
-  }
+  out[0] = in[0];
+  PredictLine_C(in + 1, preds, out + 1, width - 1);
+  preds += stride;
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
-  while (row < last_row) {
+  for (row = 1; row < height; ++row) {
     int w;
     // leftmost pixel: predict from above.
-    PredictLine_C(in, preds - stride, out, 1, inverse);
+    PredictLine_C(in, preds - stride, out, 1);
     for (w = 1; w < width; ++w) {
       const int pred = GradientPredictor_C(preds[w - 1],
                                            preds[w - stride],
                                            preds[w - stride - 1]);
-      out[w] = (uint8_t)(in[w] + (inverse ? pred : -pred));
+      out[w] = (uint8_t)(in[w] - pred);
     }
-    ++row;
     preds += stride;
     in += stride;
     out += stride;
@@ -172,20 +138,22 @@ static WEBP_INLINE void DoGradientFilter_C(const uint8_t* in,
 //------------------------------------------------------------------------------
 
 #if !WEBP_NEON_OMIT_C_CODE
-static void HorizontalFilter_C(const uint8_t* data, int width, int height,
-                               int stride, uint8_t* filtered_data) {
-  DoHorizontalFilter_C(data, width, height, stride, 0, height, 0,
-                       filtered_data);
+static void HorizontalFilter_C(const uint8_t* WEBP_RESTRICT data,
+                               int width, int height, int stride,
+                               uint8_t* WEBP_RESTRICT filtered_data) {
+  DoHorizontalFilter_C(data, width, height, stride, filtered_data);
 }
 
-static void VerticalFilter_C(const uint8_t* data, int width, int height,
-                             int stride, uint8_t* filtered_data) {
-  DoVerticalFilter_C(data, width, height, stride, 0, height, 0, filtered_data);
+static void VerticalFilter_C(const uint8_t* WEBP_RESTRICT data,
+                             int width, int height, int stride,
+                             uint8_t* WEBP_RESTRICT filtered_data) {
+  DoVerticalFilter_C(data, width, height, stride, filtered_data);
 }
 
-static void GradientFilter_C(const uint8_t* data, int width, int height,
-                             int stride, uint8_t* filtered_data) {
-  DoGradientFilter_C(data, width, height, stride, 0, height, 0, filtered_data);
+static void GradientFilter_C(const uint8_t* WEBP_RESTRICT data,
+                             int width, int height, int stride,
+                             uint8_t* WEBP_RESTRICT filtered_data) {
+  DoGradientFilter_C(data, width, height, stride, filtered_data);
 }
 #endif  // !WEBP_NEON_OMIT_C_CODE
 
diff --git a/src/dsp/filters_mips_dsp_r2.c b/src/dsp/filters_mips_dsp_r2.c
index eca866f5..c62bb872 100644
--- a/src/dsp/filters_mips_dsp_r2.c
+++ b/src/dsp/filters_mips_dsp_r2.c
@@ -26,13 +26,12 @@
 
 #define DCHECK(in, out)                                                        \
   do {                                                                         \
-    assert(in != NULL);                                                        \
-    assert(out != NULL);                                                       \
+    assert((in) != NULL);                                                      \
+    assert((out) != NULL);                                                     \
+    assert((in) != (out));                                                     \
     assert(width > 0);                                                         \
     assert(height > 0);                                                        \
     assert(stride >= width);                                                   \
-    assert(row >= 0 && num_rows > 0 && row + num_rows <= height);              \
-    (void)height;  /* Silence unused warning. */                               \
   } while (0)
 
 #define DO_PREDICT_LINE(SRC, DST, LENGTH, INVERSE) do {                        \
@@ -103,7 +102,8 @@
     );                                                                         \
   } while (0)
 
-static WEBP_INLINE void PredictLine_MIPSdspR2(const uint8_t* src, uint8_t* dst,
+static WEBP_INLINE void PredictLine_MIPSdspR2(const uint8_t* WEBP_RESTRICT src,
+                                              uint8_t* WEBP_RESTRICT dst,
                                               int length) {
   DO_PREDICT_LINE(src, dst, length, 0);
 }
@@ -184,99 +184,75 @@ static WEBP_INLINE void PredictLine_MIPSdspR2(const uint8_t* src, uint8_t* dst,
 // Horizontal filter.
 
 #define FILTER_LINE_BY_LINE do {                                               \
-    while (row < last_row) {                                                   \
+    for (row = 1; row < height; ++row) {                                       \
       PREDICT_LINE_ONE_PASS(in, preds - stride, out);                          \
       DO_PREDICT_LINE(in + 1, out + 1, width - 1, 0);                          \
-      ++row;                                                                   \
       preds += stride;                                                         \
       in += stride;                                                            \
       out += stride;                                                           \
     }                                                                          \
   } while (0)
 
-static WEBP_INLINE void DoHorizontalFilter_MIPSdspR2(const uint8_t* in,
-                                                     int width, int height,
-                                                     int stride,
-                                                     int row, int num_rows,
-                                                     uint8_t* out) {
-  const uint8_t* preds;
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+static WEBP_INLINE void DoHorizontalFilter_MIPSdspR2(
+    const uint8_t* WEBP_RESTRICT in, int width, int height, int stride,
+    uint8_t* WEBP_RESTRICT out) {
+  const uint8_t* preds = in;
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
-  preds = in;
-
-  if (row == 0) {
-    // Leftmost pixel is the same as input for topmost scanline.
-    out[0] = in[0];
-    PredictLine_MIPSdspR2(in + 1, out + 1, width - 1);
-    row = 1;
-    preds += stride;
-    in += stride;
-    out += stride;
-  }
+
+  // Leftmost pixel is the same as input for topmost scanline.
+  out[0] = in[0];
+  PredictLine_MIPSdspR2(in + 1, out + 1, width - 1);
+  preds += stride;
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
   FILTER_LINE_BY_LINE;
 }
 #undef FILTER_LINE_BY_LINE
 
-static void HorizontalFilter_MIPSdspR2(const uint8_t* data,
-                                       int width, int height,
-                                       int stride, uint8_t* filtered_data) {
-  DoHorizontalFilter_MIPSdspR2(data, width, height, stride, 0, height,
-                               filtered_data);
+static void HorizontalFilter_MIPSdspR2(const uint8_t* WEBP_RESTRICT data,
+                                       int width, int height, int stride,
+                                       uint8_t* WEBP_RESTRICT filtered_data) {
+  DoHorizontalFilter_MIPSdspR2(data, width, height, stride, filtered_data);
 }
 
 //------------------------------------------------------------------------------
 // Vertical filter.
 
 #define FILTER_LINE_BY_LINE do {                                               \
-    while (row < last_row) {                                                   \
+    for (row = 1; row < height; ++row) {                                       \
       DO_PREDICT_LINE_VERTICAL(in, preds, out, width, 0);                      \
-      ++row;                                                                   \
       preds += stride;                                                         \
       in += stride;                                                            \
       out += stride;                                                           \
     }                                                                          \
   } while (0)
 
-static WEBP_INLINE void DoVerticalFilter_MIPSdspR2(const uint8_t* in,
-                                                   int width, int height,
-                                                   int stride,
-                                                   int row, int num_rows,
-                                                   uint8_t* out) {
-  const uint8_t* preds;
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+static WEBP_INLINE void DoVerticalFilter_MIPSdspR2(
+    const uint8_t* WEBP_RESTRICT in, int width, int height, int stride,
+    uint8_t* WEBP_RESTRICT out) {
+  const uint8_t* preds = in;
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
-  preds = in;
-
-  if (row == 0) {
-    // Very first top-left pixel is copied.
-    out[0] = in[0];
-    // Rest of top scan-line is left-predicted.
-    PredictLine_MIPSdspR2(in + 1, out + 1, width - 1);
-    row = 1;
-    in += stride;
-    out += stride;
-  } else {
-    // We are starting from in-between. Make sure 'preds' points to prev row.
-    preds -= stride;
-  }
+
+  // Very first top-left pixel is copied.
+  out[0] = in[0];
+  // Rest of top scan-line is left-predicted.
+  PredictLine_MIPSdspR2(in + 1, out + 1, width - 1);
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
   FILTER_LINE_BY_LINE;
 }
 #undef FILTER_LINE_BY_LINE
 
-static void VerticalFilter_MIPSdspR2(const uint8_t* data, int width, int height,
-                                     int stride, uint8_t* filtered_data) {
-  DoVerticalFilter_MIPSdspR2(data, width, height, stride, 0, height,
-                             filtered_data);
+static void VerticalFilter_MIPSdspR2(const uint8_t* WEBP_RESTRICT data,
+                                     int width, int height, int stride,
+                                     uint8_t* WEBP_RESTRICT filtered_data) {
+  DoVerticalFilter_MIPSdspR2(data, width, height, stride, filtered_data);
 }
 
 //------------------------------------------------------------------------------
@@ -297,7 +273,7 @@ static int GradientPredictor_MIPSdspR2(uint8_t a, uint8_t b, uint8_t c) {
 }
 
 #define FILTER_LINE_BY_LINE(PREDS, OPERATION) do {                             \
-    while (row < last_row) {                                                   \
+    for (row = 1; row < height; ++row) {                                       \
       int w;                                                                   \
       PREDICT_LINE_ONE_PASS(in, PREDS - stride, out);                          \
       for (w = 1; w < width; ++w) {                                            \
@@ -306,42 +282,34 @@ static int GradientPredictor_MIPSdspR2(uint8_t a, uint8_t b, uint8_t c) {
                                                      PREDS[w - stride - 1]);   \
         out[w] = in[w] OPERATION pred;                                         \
       }                                                                        \
-      ++row;                                                                   \
       in += stride;                                                            \
       out += stride;                                                           \
     }                                                                          \
   } while (0)
 
-static void DoGradientFilter_MIPSdspR2(const uint8_t* in,
+static void DoGradientFilter_MIPSdspR2(const uint8_t* WEBP_RESTRICT in,
                                        int width, int height, int stride,
-                                       int row, int num_rows, uint8_t* out) {
-  const uint8_t* preds;
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+                                       uint8_t* WEBP_RESTRICT out) {
+  const uint8_t* preds = in;
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
-  preds = in;
 
   // left prediction for top scan-line
-  if (row == 0) {
-    out[0] = in[0];
-    PredictLine_MIPSdspR2(in + 1, out + 1, width - 1);
-    row = 1;
-    preds += stride;
-    in += stride;
-    out += stride;
-  }
+  out[0] = in[0];
+  PredictLine_MIPSdspR2(in + 1, out + 1, width - 1);
+  preds += stride;
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
   FILTER_LINE_BY_LINE(in, -);
 }
 #undef FILTER_LINE_BY_LINE
 
-static void GradientFilter_MIPSdspR2(const uint8_t* data, int width, int height,
-                                     int stride, uint8_t* filtered_data) {
-  DoGradientFilter_MIPSdspR2(data, width, height, stride, 0, height,
-                             filtered_data);
+static void GradientFilter_MIPSdspR2(const uint8_t* WEBP_RESTRICT data,
+                                     int width, int height, int stride,
+                                     uint8_t* WEBP_RESTRICT filtered_data) {
+  DoGradientFilter_MIPSdspR2(data, width, height, stride, filtered_data);
 }
 
 //------------------------------------------------------------------------------
diff --git a/src/dsp/filters_msa.c b/src/dsp/filters_msa.c
index 33a1b20b..ae3d3699 100644
--- a/src/dsp/filters_msa.c
+++ b/src/dsp/filters_msa.c
@@ -21,7 +21,8 @@
 
 static WEBP_INLINE void PredictLineInverse0(const uint8_t* src,
                                             const uint8_t* pred,
-                                            uint8_t* dst, int length) {
+                                            uint8_t* WEBP_RESTRICT dst,
+                                            int length) {
   v16u8 src0, pred0, dst0;
   assert(length >= 0);
   while (length >= 32) {
@@ -58,8 +59,9 @@ static WEBP_INLINE void PredictLineInverse0(const uint8_t* src,
 
 #define DCHECK(in, out)        \
   do {                         \
-    assert(in != NULL);        \
-    assert(out != NULL);       \
+    assert((in) != NULL);      \
+    assert((out) != NULL);     \
+    assert((in) != (out));     \
     assert(width > 0);         \
     assert(height > 0);        \
     assert(stride >= width);   \
@@ -68,8 +70,9 @@ static WEBP_INLINE void PredictLineInverse0(const uint8_t* src,
 //------------------------------------------------------------------------------
 // Horrizontal filter
 
-static void HorizontalFilter_MSA(const uint8_t* data, int width, int height,
-                                 int stride, uint8_t* filtered_data) {
+static void HorizontalFilter_MSA(const uint8_t* WEBP_RESTRICT data,
+                                 int width, int height, int stride,
+                                 uint8_t* WEBP_RESTRICT filtered_data) {
   const uint8_t* preds = data;
   const uint8_t* in = data;
   uint8_t* out = filtered_data;
@@ -99,8 +102,8 @@ static void HorizontalFilter_MSA(const uint8_t* data, int width, int height,
 
 static WEBP_INLINE void PredictLineGradient(const uint8_t* pinput,
                                             const uint8_t* ppred,
-                                            uint8_t* poutput, int stride,
-                                            int size) {
+                                            uint8_t* WEBP_RESTRICT poutput,
+                                            int stride, int size) {
   int w;
   const v16i8 zero = { 0 };
   while (size >= 16) {
@@ -131,8 +134,9 @@ static WEBP_INLINE void PredictLineGradient(const uint8_t* pinput,
 }
 
 
-static void GradientFilter_MSA(const uint8_t* data, int width, int height,
-                               int stride, uint8_t* filtered_data) {
+static void GradientFilter_MSA(const uint8_t* WEBP_RESTRICT data,
+                               int width, int height, int stride,
+                               uint8_t* WEBP_RESTRICT filtered_data) {
   const uint8_t* in = data;
   const uint8_t* preds = data;
   uint8_t* out = filtered_data;
@@ -159,8 +163,9 @@ static void GradientFilter_MSA(const uint8_t* data, int width, int height,
 //------------------------------------------------------------------------------
 // Vertical filter
 
-static void VerticalFilter_MSA(const uint8_t* data, int width, int height,
-                               int stride, uint8_t* filtered_data) {
+static void VerticalFilter_MSA(const uint8_t* WEBP_RESTRICT data,
+                               int width, int height, int stride,
+                               uint8_t* WEBP_RESTRICT filtered_data) {
   const uint8_t* in = data;
   const uint8_t* preds = data;
   uint8_t* out = filtered_data;
diff --git a/src/dsp/filters_neon.c b/src/dsp/filters_neon.c
index b49e515a..4df10172 100644
--- a/src/dsp/filters_neon.c
+++ b/src/dsp/filters_neon.c
@@ -23,13 +23,12 @@
 
 #define DCHECK(in, out)                                                        \
   do {                                                                         \
-    assert(in != NULL);                                                        \
-    assert(out != NULL);                                                       \
+    assert((in) != NULL);                                                      \
+    assert((out) != NULL);                                                     \
+    assert((in) != (out));                                                     \
     assert(width > 0);                                                         \
     assert(height > 0);                                                        \
     assert(stride >= width);                                                   \
-    assert(row >= 0 && num_rows > 0 && row + num_rows <= height);              \
-    (void)height;  /* Silence unused warning. */                               \
   } while (0)
 
 // load eight u8 and widen to s16
@@ -46,7 +45,7 @@
 #define ROTATE_RIGHT_N(A, N)   vext_u8((A), (A), (8 - (N)) % 8)
 
 static void PredictLine_NEON(const uint8_t* src, const uint8_t* pred,
-                             uint8_t* dst, int length) {
+                             uint8_t* WEBP_RESTRICT dst, int length) {
   int i;
   assert(length >= 0);
   for (i = 0; i + 16 <= length; i += 16) {
@@ -59,86 +58,70 @@ static void PredictLine_NEON(const uint8_t* src, const uint8_t* pred,
 }
 
 // Special case for left-based prediction (when preds==dst-1 or preds==src-1).
-static void PredictLineLeft_NEON(const uint8_t* src, uint8_t* dst, int length) {
+static void PredictLineLeft_NEON(const uint8_t* WEBP_RESTRICT src,
+                                 uint8_t* WEBP_RESTRICT dst, int length) {
   PredictLine_NEON(src, src - 1, dst, length);
 }
 
 //------------------------------------------------------------------------------
 // Horizontal filter.
 
-static WEBP_INLINE void DoHorizontalFilter_NEON(const uint8_t* in,
-                                                int width, int height,
-                                                int stride,
-                                                int row, int num_rows,
-                                                uint8_t* out) {
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+static WEBP_INLINE void DoHorizontalFilter_NEON(
+    const uint8_t* WEBP_RESTRICT in, int width, int height, int stride,
+    uint8_t* WEBP_RESTRICT out) {
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
 
-  if (row == 0) {
-    // Leftmost pixel is the same as input for topmost scanline.
-    out[0] = in[0];
-    PredictLineLeft_NEON(in + 1, out + 1, width - 1);
-    row = 1;
-    in += stride;
-    out += stride;
-  }
+  // Leftmost pixel is the same as input for topmost scanline.
+  out[0] = in[0];
+  PredictLineLeft_NEON(in + 1, out + 1, width - 1);
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
-  while (row < last_row) {
+  for (row = 1; row < height; ++row) {
     // Leftmost pixel is predicted from above.
     out[0] = in[0] - in[-stride];
     PredictLineLeft_NEON(in + 1, out + 1, width - 1);
-    ++row;
     in += stride;
     out += stride;
   }
 }
 
-static void HorizontalFilter_NEON(const uint8_t* data, int width, int height,
-                                  int stride, uint8_t* filtered_data) {
-  DoHorizontalFilter_NEON(data, width, height, stride, 0, height,
-                          filtered_data);
+static void HorizontalFilter_NEON(const uint8_t* WEBP_RESTRICT data,
+                                  int width, int height, int stride,
+                                  uint8_t* WEBP_RESTRICT filtered_data) {
+  DoHorizontalFilter_NEON(data, width, height, stride, filtered_data);
 }
 
 //------------------------------------------------------------------------------
 // Vertical filter.
 
-static WEBP_INLINE void DoVerticalFilter_NEON(const uint8_t* in,
+static WEBP_INLINE void DoVerticalFilter_NEON(const uint8_t* WEBP_RESTRICT in,
                                               int width, int height, int stride,
-                                              int row, int num_rows,
-                                              uint8_t* out) {
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+                                              uint8_t* WEBP_RESTRICT out) {
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
 
-  if (row == 0) {
-    // Very first top-left pixel is copied.
-    out[0] = in[0];
-    // Rest of top scan-line is left-predicted.
-    PredictLineLeft_NEON(in + 1, out + 1, width - 1);
-    row = 1;
-    in += stride;
-    out += stride;
-  }
+  // Very first top-left pixel is copied.
+  out[0] = in[0];
+  // Rest of top scan-line is left-predicted.
+  PredictLineLeft_NEON(in + 1, out + 1, width - 1);
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
-  while (row < last_row) {
+  for (row = 1; row < height; ++row) {
     PredictLine_NEON(in, in - stride, out, width);
-    ++row;
     in += stride;
     out += stride;
   }
 }
 
-static void VerticalFilter_NEON(const uint8_t* data, int width, int height,
-                                int stride, uint8_t* filtered_data) {
-  DoVerticalFilter_NEON(data, width, height, stride, 0, height,
-                        filtered_data);
+static void VerticalFilter_NEON(const uint8_t* WEBP_RESTRICT data,
+                                int width, int height, int stride,
+                                uint8_t* WEBP_RESTRICT filtered_data) {
+  DoVerticalFilter_NEON(data, width, height, stride, filtered_data);
 }
 
 //------------------------------------------------------------------------------
@@ -151,7 +134,8 @@ static WEBP_INLINE int GradientPredictor_C(uint8_t a, uint8_t b, uint8_t c) {
 
 static void GradientPredictDirect_NEON(const uint8_t* const row,
                                        const uint8_t* const top,
-                                       uint8_t* const out, int length) {
+                                       uint8_t* WEBP_RESTRICT const out,
+                                       int length) {
   int i;
   for (i = 0; i + 8 <= length; i += 8) {
     const uint8x8_t A = vld1_u8(&row[i - 1]);
@@ -167,40 +151,31 @@ static void GradientPredictDirect_NEON(const uint8_t* const row,
   }
 }
 
-static WEBP_INLINE void DoGradientFilter_NEON(const uint8_t* in,
-                                              int width, int height,
-                                              int stride,
-                                              int row, int num_rows,
-                                              uint8_t* out) {
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+static WEBP_INLINE void DoGradientFilter_NEON(const uint8_t* WEBP_RESTRICT in,
+                                              int width, int height, int stride,
+                                              uint8_t* WEBP_RESTRICT out) {
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
 
   // left prediction for top scan-line
-  if (row == 0) {
-    out[0] = in[0];
-    PredictLineLeft_NEON(in + 1, out + 1, width - 1);
-    row = 1;
-    in += stride;
-    out += stride;
-  }
+  out[0] = in[0];
+  PredictLineLeft_NEON(in + 1, out + 1, width - 1);
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
-  while (row < last_row) {
+  for (row = 1; row < height; ++row) {
     out[0] = in[0] - in[-stride];
     GradientPredictDirect_NEON(in + 1, in + 1 - stride, out + 1, width - 1);
-    ++row;
     in += stride;
     out += stride;
   }
 }
 
-static void GradientFilter_NEON(const uint8_t* data, int width, int height,
-                                int stride, uint8_t* filtered_data) {
-  DoGradientFilter_NEON(data, width, height, stride, 0, height,
-                        filtered_data);
+static void GradientFilter_NEON(const uint8_t* WEBP_RESTRICT data,
+                                int width, int height, int stride,
+                                uint8_t* WEBP_RESTRICT filtered_data) {
+  DoGradientFilter_NEON(data, width, height, stride, filtered_data);
 }
 
 #undef DCHECK
diff --git a/src/dsp/filters_sse2.c b/src/dsp/filters_sse2.c
index bb4b5d58..d2ba7894 100644
--- a/src/dsp/filters_sse2.c
+++ b/src/dsp/filters_sse2.c
@@ -27,15 +27,15 @@
   do {                                                                         \
     assert((in) != NULL);                                                      \
     assert((out) != NULL);                                                     \
+    assert((in) != (out));                                                     \
     assert(width > 0);                                                         \
     assert(height > 0);                                                        \
     assert(stride >= width);                                                   \
-    assert(row >= 0 && num_rows > 0 && row + num_rows <= height);              \
-    (void)height;  /* Silence unused warning. */                               \
   } while (0)
 
-static void PredictLineTop_SSE2(const uint8_t* src, const uint8_t* pred,
-                                uint8_t* dst, int length) {
+static void PredictLineTop_SSE2(const uint8_t* WEBP_RESTRICT src,
+                                const uint8_t* WEBP_RESTRICT pred,
+                                uint8_t* WEBP_RESTRICT dst, int length) {
   int i;
   const int max_pos = length & ~31;
   assert(length >= 0);
@@ -53,7 +53,8 @@ static void PredictLineTop_SSE2(const uint8_t* src, const uint8_t* pred,
 }
 
 // Special case for left-based prediction (when preds==dst-1 or preds==src-1).
-static void PredictLineLeft_SSE2(const uint8_t* src, uint8_t* dst, int length) {
+static void PredictLineLeft_SSE2(const uint8_t* WEBP_RESTRICT src,
+                                 uint8_t* WEBP_RESTRICT dst, int length) {
   int i;
   const int max_pos = length & ~31;
   assert(length >= 0);
@@ -73,32 +74,23 @@ static void PredictLineLeft_SSE2(const uint8_t* src, uint8_t* dst, int length) {
 //------------------------------------------------------------------------------
 // Horizontal filter.
 
-static WEBP_INLINE void DoHorizontalFilter_SSE2(const uint8_t* in,
-                                                int width, int height,
-                                                int stride,
-                                                int row, int num_rows,
-                                                uint8_t* out) {
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+static WEBP_INLINE void DoHorizontalFilter_SSE2(
+    const uint8_t* WEBP_RESTRICT in, int width, int height, int stride,
+    uint8_t* WEBP_RESTRICT out) {
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
 
-  if (row == 0) {
-    // Leftmost pixel is the same as input for topmost scanline.
-    out[0] = in[0];
-    PredictLineLeft_SSE2(in + 1, out + 1, width - 1);
-    row = 1;
-    in += stride;
-    out += stride;
-  }
+  // Leftmost pixel is the same as input for topmost scanline.
+  out[0] = in[0];
+  PredictLineLeft_SSE2(in + 1, out + 1, width - 1);
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
-  while (row < last_row) {
+  for (row = 1; row < height; ++row) {
     // Leftmost pixel is predicted from above.
     out[0] = in[0] - in[-stride];
     PredictLineLeft_SSE2(in + 1, out + 1, width - 1);
-    ++row;
     in += stride;
     out += stride;
   }
@@ -107,30 +99,22 @@ static WEBP_INLINE void DoHorizontalFilter_SSE2(const uint8_t* in,
 //------------------------------------------------------------------------------
 // Vertical filter.
 
-static WEBP_INLINE void DoVerticalFilter_SSE2(const uint8_t* in,
+static WEBP_INLINE void DoVerticalFilter_SSE2(const uint8_t* WEBP_RESTRICT in,
                                               int width, int height, int stride,
-                                              int row, int num_rows,
-                                              uint8_t* out) {
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+                                              uint8_t* WEBP_RESTRICT out) {
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
 
-  if (row == 0) {
-    // Very first top-left pixel is copied.
-    out[0] = in[0];
-    // Rest of top scan-line is left-predicted.
-    PredictLineLeft_SSE2(in + 1, out + 1, width - 1);
-    row = 1;
-    in += stride;
-    out += stride;
-  }
+  // Very first top-left pixel is copied.
+  out[0] = in[0];
+  // Rest of top scan-line is left-predicted.
+  PredictLineLeft_SSE2(in + 1, out + 1, width - 1);
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
-  while (row < last_row) {
+  for (row = 1; row < height; ++row) {
     PredictLineTop_SSE2(in, in - stride, out, width);
-    ++row;
     in += stride;
     out += stride;
   }
@@ -146,7 +130,8 @@ static WEBP_INLINE int GradientPredictor_SSE2(uint8_t a, uint8_t b, uint8_t c) {
 
 static void GradientPredictDirect_SSE2(const uint8_t* const row,
                                        const uint8_t* const top,
-                                       uint8_t* const out, int length) {
+                                       uint8_t* WEBP_RESTRICT const out,
+                                       int length) {
   const int max_pos = length & ~7;
   int i;
   const __m128i zero = _mm_setzero_si128();
@@ -170,30 +155,22 @@ static void GradientPredictDirect_SSE2(const uint8_t* const row,
   }
 }
 
-static WEBP_INLINE void DoGradientFilter_SSE2(const uint8_t* in,
+static WEBP_INLINE void DoGradientFilter_SSE2(const uint8_t* WEBP_RESTRICT in,
                                               int width, int height, int stride,
-                                              int row, int num_rows,
-                                              uint8_t* out) {
-  const size_t start_offset = row * stride;
-  const int last_row = row + num_rows;
+                                              uint8_t* WEBP_RESTRICT out) {
+  int row;
   DCHECK(in, out);
-  in += start_offset;
-  out += start_offset;
 
   // left prediction for top scan-line
-  if (row == 0) {
-    out[0] = in[0];
-    PredictLineLeft_SSE2(in + 1, out + 1, width - 1);
-    row = 1;
-    in += stride;
-    out += stride;
-  }
+  out[0] = in[0];
+  PredictLineLeft_SSE2(in + 1, out + 1, width - 1);
+  in += stride;
+  out += stride;
 
   // Filter line-by-line.
-  while (row < last_row) {
+  for (row = 1; row < height; ++row) {
     out[0] = (uint8_t)(in[0] - in[-stride]);
     GradientPredictDirect_SSE2(in + 1, in + 1 - stride, out + 1, width - 1);
-    ++row;
     in += stride;
     out += stride;
   }
@@ -203,20 +180,22 @@ static WEBP_INLINE void DoGradientFilter_SSE2(const uint8_t* in,
 
 //------------------------------------------------------------------------------
 
-static void HorizontalFilter_SSE2(const uint8_t* data, int width, int height,
-                                  int stride, uint8_t* filtered_data) {
-  DoHorizontalFilter_SSE2(data, width, height, stride, 0, height,
-                          filtered_data);
+static void HorizontalFilter_SSE2(const uint8_t* WEBP_RESTRICT data,
+                                  int width, int height, int stride,
+                                  uint8_t* WEBP_RESTRICT filtered_data) {
+  DoHorizontalFilter_SSE2(data, width, height, stride, filtered_data);
 }
 
-static void VerticalFilter_SSE2(const uint8_t* data, int width, int height,
-                                int stride, uint8_t* filtered_data) {
-  DoVerticalFilter_SSE2(data, width, height, stride, 0, height, filtered_data);
+static void VerticalFilter_SSE2(const uint8_t* WEBP_RESTRICT data,
+                                int width, int height, int stride,
+                                uint8_t* WEBP_RESTRICT filtered_data) {
+  DoVerticalFilter_SSE2(data, width, height, stride, filtered_data);
 }
 
-static void GradientFilter_SSE2(const uint8_t* data, int width, int height,
-                                int stride, uint8_t* filtered_data) {
-  DoGradientFilter_SSE2(data, width, height, stride, 0, height, filtered_data);
+static void GradientFilter_SSE2(const uint8_t* WEBP_RESTRICT data,
+                                int width, int height, int stride,
+                                uint8_t* WEBP_RESTRICT filtered_data) {
+  DoGradientFilter_SSE2(data, width, height, stride, filtered_data);
 }
 
 //------------------------------------------------------------------------------
diff --git a/src/dsp/lossless.c b/src/dsp/lossless.c
index 9f812094..a02443f1 100644
--- a/src/dsp/lossless.c
+++ b/src/dsp/lossless.c
@@ -107,14 +107,14 @@ static WEBP_INLINE uint32_t Select(uint32_t a, uint32_t b, uint32_t c) {
 //------------------------------------------------------------------------------
 // Predictors
 
-uint32_t VP8LPredictor0_C(const uint32_t* const left,
-                          const uint32_t* const top) {
+static uint32_t VP8LPredictor0_C(const uint32_t* const left,
+                                 const uint32_t* const top) {
   (void)top;
   (void)left;
   return ARGB_BLACK;
 }
-uint32_t VP8LPredictor1_C(const uint32_t* const left,
-                          const uint32_t* const top) {
+static uint32_t VP8LPredictor1_C(const uint32_t* const left,
+                                 const uint32_t* const top) {
   (void)top;
   return *left;
 }
@@ -182,13 +182,13 @@ uint32_t VP8LPredictor13_C(const uint32_t* const left,
 }
 
 static void PredictorAdd0_C(const uint32_t* in, const uint32_t* upper,
-                            int num_pixels, uint32_t* out) {
+                            int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int x;
   (void)upper;
   for (x = 0; x < num_pixels; ++x) out[x] = VP8LAddPixels(in[x], ARGB_BLACK);
 }
 static void PredictorAdd1_C(const uint32_t* in, const uint32_t* upper,
-                            int num_pixels, uint32_t* out) {
+                            int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   uint32_t left = out[-1];
   (void)upper;
@@ -441,8 +441,8 @@ static int is_big_endian(void) {
   return (tmp.b[0] != 1);
 }
 
-void VP8LConvertBGRAToRGB_C(const uint32_t* src,
-                            int num_pixels, uint8_t* dst) {
+void VP8LConvertBGRAToRGB_C(const uint32_t* WEBP_RESTRICT src,
+                            int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const src_end = src + num_pixels;
   while (src < src_end) {
     const uint32_t argb = *src++;
@@ -452,8 +452,8 @@ void VP8LConvertBGRAToRGB_C(const uint32_t* src,
   }
 }
 
-void VP8LConvertBGRAToRGBA_C(const uint32_t* src,
-                             int num_pixels, uint8_t* dst) {
+void VP8LConvertBGRAToRGBA_C(const uint32_t* WEBP_RESTRICT src,
+                             int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const src_end = src + num_pixels;
   while (src < src_end) {
     const uint32_t argb = *src++;
@@ -464,8 +464,8 @@ void VP8LConvertBGRAToRGBA_C(const uint32_t* src,
   }
 }
 
-void VP8LConvertBGRAToRGBA4444_C(const uint32_t* src,
-                                 int num_pixels, uint8_t* dst) {
+void VP8LConvertBGRAToRGBA4444_C(const uint32_t* WEBP_RESTRICT src,
+                                 int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const src_end = src + num_pixels;
   while (src < src_end) {
     const uint32_t argb = *src++;
@@ -481,8 +481,8 @@ void VP8LConvertBGRAToRGBA4444_C(const uint32_t* src,
   }
 }
 
-void VP8LConvertBGRAToRGB565_C(const uint32_t* src,
-                               int num_pixels, uint8_t* dst) {
+void VP8LConvertBGRAToRGB565_C(const uint32_t* WEBP_RESTRICT src,
+                               int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const src_end = src + num_pixels;
   while (src < src_end) {
     const uint32_t argb = *src++;
@@ -498,8 +498,8 @@ void VP8LConvertBGRAToRGB565_C(const uint32_t* src,
   }
 }
 
-void VP8LConvertBGRAToBGR_C(const uint32_t* src,
-                            int num_pixels, uint8_t* dst) {
+void VP8LConvertBGRAToBGR_C(const uint32_t* WEBP_RESTRICT src,
+                            int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const src_end = src + num_pixels;
   while (src < src_end) {
     const uint32_t argb = *src++;
@@ -509,8 +509,8 @@ void VP8LConvertBGRAToBGR_C(const uint32_t* src,
   }
 }
 
-static void CopyOrSwap(const uint32_t* src, int num_pixels, uint8_t* dst,
-                       int swap_on_big_endian) {
+static void CopyOrSwap(const uint32_t* WEBP_RESTRICT src, int num_pixels,
+                       uint8_t* WEBP_RESTRICT dst, int swap_on_big_endian) {
   if (is_big_endian() == swap_on_big_endian) {
     const uint32_t* const src_end = src + num_pixels;
     while (src < src_end) {
diff --git a/src/dsp/lossless.h b/src/dsp/lossless.h
index 0bf10a1a..bbc1b8d3 100644
--- a/src/dsp/lossless.h
+++ b/src/dsp/lossless.h
@@ -18,6 +18,7 @@
 #include "src/webp/types.h"
 #include "src/webp/decode.h"
 
+#include "src/dsp/dsp.h"
 #include "src/enc/histogram_enc.h"
 #include "src/utils/utils.h"
 
@@ -32,10 +33,6 @@ typedef uint32_t (*VP8LPredictorFunc)(const uint32_t* const left,
                                       const uint32_t* const top);
 extern VP8LPredictorFunc VP8LPredictors[16];
 
-uint32_t VP8LPredictor0_C(const uint32_t* const left,
-                          const uint32_t* const top);
-uint32_t VP8LPredictor1_C(const uint32_t* const left,
-                          const uint32_t* const top);
 uint32_t VP8LPredictor2_C(const uint32_t* const left,
                           const uint32_t* const top);
 uint32_t VP8LPredictor3_C(const uint32_t* const left,
@@ -64,7 +61,7 @@ uint32_t VP8LPredictor13_C(const uint32_t* const left,
 // These Add/Sub function expects upper[-1] and out[-1] to be readable.
 typedef void (*VP8LPredictorAddSubFunc)(const uint32_t* in,
                                         const uint32_t* upper, int num_pixels,
-                                        uint32_t* out);
+                                        uint32_t* WEBP_RESTRICT out);
 extern VP8LPredictorAddSubFunc VP8LPredictorsAdd[16];
 extern VP8LPredictorAddSubFunc VP8LPredictorsAdd_C[16];
 
@@ -95,8 +92,8 @@ void VP8LInverseTransform(const struct VP8LTransform* const transform,
                           const uint32_t* const in, uint32_t* const out);
 
 // Color space conversion.
-typedef void (*VP8LConvertFunc)(const uint32_t* src, int num_pixels,
-                                uint8_t* dst);
+typedef void (*VP8LConvertFunc)(const uint32_t* WEBP_RESTRICT src,
+                                int num_pixels, uint8_t* WEBP_RESTRICT dst);
 extern VP8LConvertFunc VP8LConvertBGRAToRGB;
 extern VP8LConvertFunc VP8LConvertBGRAToRGBA;
 extern VP8LConvertFunc VP8LConvertBGRAToRGBA4444;
@@ -131,13 +128,16 @@ void VP8LTransformColorInverse_C(const VP8LMultipliers* const m,
                                  const uint32_t* src, int num_pixels,
                                  uint32_t* dst);
 
-void VP8LConvertBGRAToRGB_C(const uint32_t* src, int num_pixels, uint8_t* dst);
-void VP8LConvertBGRAToRGBA_C(const uint32_t* src, int num_pixels, uint8_t* dst);
-void VP8LConvertBGRAToRGBA4444_C(const uint32_t* src,
-                                 int num_pixels, uint8_t* dst);
-void VP8LConvertBGRAToRGB565_C(const uint32_t* src,
-                               int num_pixels, uint8_t* dst);
-void VP8LConvertBGRAToBGR_C(const uint32_t* src, int num_pixels, uint8_t* dst);
+void VP8LConvertBGRAToRGB_C(const uint32_t* WEBP_RESTRICT src, int num_pixels,
+                            uint8_t* WEBP_RESTRICT dst);
+void VP8LConvertBGRAToRGBA_C(const uint32_t* WEBP_RESTRICT src, int num_pixels,
+                             uint8_t* WEBP_RESTRICT dst);
+void VP8LConvertBGRAToRGBA4444_C(const uint32_t* WEBP_RESTRICT src,
+                                 int num_pixels, uint8_t* WEBP_RESTRICT dst);
+void VP8LConvertBGRAToRGB565_C(const uint32_t* WEBP_RESTRICT src,
+                               int num_pixels, uint8_t* WEBP_RESTRICT dst);
+void VP8LConvertBGRAToBGR_C(const uint32_t* WEBP_RESTRICT src, int num_pixels,
+                            uint8_t* WEBP_RESTRICT dst);
 void VP8LAddGreenToBlueAndRed_C(const uint32_t* src, int num_pixels,
                                 uint32_t* dst);
 
@@ -149,32 +149,35 @@ void VP8LDspInit(void);
 
 typedef void (*VP8LProcessEncBlueAndRedFunc)(uint32_t* dst, int num_pixels);
 extern VP8LProcessEncBlueAndRedFunc VP8LSubtractGreenFromBlueAndRed;
-typedef void (*VP8LTransformColorFunc)(const VP8LMultipliers* const m,
-                                       uint32_t* dst, int num_pixels);
+typedef void (*VP8LTransformColorFunc)(
+    const VP8LMultipliers* WEBP_RESTRICT const m, uint32_t* WEBP_RESTRICT dst,
+    int num_pixels);
 extern VP8LTransformColorFunc VP8LTransformColor;
 typedef void (*VP8LCollectColorBlueTransformsFunc)(
-    const uint32_t* argb, int stride,
+    const uint32_t* WEBP_RESTRICT argb, int stride,
     int tile_width, int tile_height,
-    int green_to_blue, int red_to_blue, int histo[]);
+    int green_to_blue, int red_to_blue, uint32_t histo[]);
 extern VP8LCollectColorBlueTransformsFunc VP8LCollectColorBlueTransforms;
 
 typedef void (*VP8LCollectColorRedTransformsFunc)(
-    const uint32_t* argb, int stride,
+    const uint32_t* WEBP_RESTRICT argb, int stride,
     int tile_width, int tile_height,
-    int green_to_red, int histo[]);
+    int green_to_red, uint32_t histo[]);
 extern VP8LCollectColorRedTransformsFunc VP8LCollectColorRedTransforms;
 
 // Expose some C-only fallback functions
-void VP8LTransformColor_C(const VP8LMultipliers* const m,
-                          uint32_t* data, int num_pixels);
+void VP8LTransformColor_C(const VP8LMultipliers* WEBP_RESTRICT const m,
+                          uint32_t* WEBP_RESTRICT data, int num_pixels);
 void VP8LSubtractGreenFromBlueAndRed_C(uint32_t* argb_data, int num_pixels);
-void VP8LCollectColorRedTransforms_C(const uint32_t* argb, int stride,
+void VP8LCollectColorRedTransforms_C(const uint32_t* WEBP_RESTRICT argb,
+                                     int stride,
                                      int tile_width, int tile_height,
-                                     int green_to_red, int histo[]);
-void VP8LCollectColorBlueTransforms_C(const uint32_t* argb, int stride,
+                                     int green_to_red, uint32_t histo[]);
+void VP8LCollectColorBlueTransforms_C(const uint32_t* WEBP_RESTRICT argb,
+                                      int stride,
                                       int tile_width, int tile_height,
                                       int green_to_blue, int red_to_blue,
-                                      int histo[]);
+                                      uint32_t histo[]);
 
 extern VP8LPredictorAddSubFunc VP8LPredictorsSub[16];
 extern VP8LPredictorAddSubFunc VP8LPredictorsSub_C[16];
@@ -183,14 +186,17 @@ extern VP8LPredictorAddSubFunc VP8LPredictorsSub_C[16];
 // Huffman-cost related functions.
 
 typedef uint32_t (*VP8LCostFunc)(const uint32_t* population, int length);
-typedef uint32_t (*VP8LCostCombinedFunc)(const uint32_t* X, const uint32_t* Y,
+typedef uint32_t (*VP8LCostCombinedFunc)(const uint32_t* WEBP_RESTRICT X,
+                                         const uint32_t* WEBP_RESTRICT Y,
                                          int length);
-typedef float (*VP8LCombinedShannonEntropyFunc)(const int X[256],
-                                                const int Y[256]);
+typedef uint64_t (*VP8LCombinedShannonEntropyFunc)(const uint32_t X[256],
+                                                   const uint32_t Y[256]);
+typedef uint64_t (*VP8LShannonEntropyFunc)(const uint32_t* X, int length);
 
 extern VP8LCostFunc VP8LExtraCost;
 extern VP8LCostCombinedFunc VP8LExtraCostCombined;
 extern VP8LCombinedShannonEntropyFunc VP8LCombinedShannonEntropy;
+extern VP8LShannonEntropyFunc VP8LShannonEntropy;
 
 typedef struct {        // small struct to hold counters
   int counts[2];        // index: 0=zero streak, 1=non-zero streak
@@ -198,7 +204,7 @@ typedef struct {        // small struct to hold counters
 } VP8LStreaks;
 
 typedef struct {            // small struct to hold bit entropy results
-  float entropy;            // entropy
+  uint64_t entropy;         // entropy
   uint32_t sum;             // sum of the population
   int nonzeros;             // number of non-zero elements in the population
   uint32_t max_val;         // maximum value in the population
@@ -212,26 +218,30 @@ void VP8LBitEntropyInit(VP8LBitEntropy* const entropy);
 // codec specific heuristics.
 typedef void (*VP8LGetCombinedEntropyUnrefinedFunc)(
     const uint32_t X[], const uint32_t Y[], int length,
-    VP8LBitEntropy* const bit_entropy, VP8LStreaks* const stats);
+    VP8LBitEntropy* WEBP_RESTRICT const bit_entropy,
+    VP8LStreaks* WEBP_RESTRICT const stats);
 extern VP8LGetCombinedEntropyUnrefinedFunc VP8LGetCombinedEntropyUnrefined;
 
 // Get the entropy for the distribution 'X'.
-typedef void (*VP8LGetEntropyUnrefinedFunc)(const uint32_t X[], int length,
-                                            VP8LBitEntropy* const bit_entropy,
-                                            VP8LStreaks* const stats);
+typedef void (*VP8LGetEntropyUnrefinedFunc)(
+    const uint32_t X[], int length,
+    VP8LBitEntropy* WEBP_RESTRICT const bit_entropy,
+    VP8LStreaks* WEBP_RESTRICT const stats);
 extern VP8LGetEntropyUnrefinedFunc VP8LGetEntropyUnrefined;
 
-void VP8LBitsEntropyUnrefined(const uint32_t* const array, int n,
-                              VP8LBitEntropy* const entropy);
+void VP8LBitsEntropyUnrefined(const uint32_t* WEBP_RESTRICT const array, int n,
+                              VP8LBitEntropy* WEBP_RESTRICT const entropy);
 
-typedef void (*VP8LAddVectorFunc)(const uint32_t* a, const uint32_t* b,
-                                  uint32_t* out, int size);
+typedef void (*VP8LAddVectorFunc)(const uint32_t* WEBP_RESTRICT a,
+                                  const uint32_t* WEBP_RESTRICT b,
+                                  uint32_t* WEBP_RESTRICT out, int size);
 extern VP8LAddVectorFunc VP8LAddVector;
-typedef void (*VP8LAddVectorEqFunc)(const uint32_t* a, uint32_t* out, int size);
+typedef void (*VP8LAddVectorEqFunc)(const uint32_t* WEBP_RESTRICT a,
+                                    uint32_t* WEBP_RESTRICT out, int size);
 extern VP8LAddVectorEqFunc VP8LAddVectorEq;
-void VP8LHistogramAdd(const VP8LHistogram* const a,
-                      const VP8LHistogram* const b,
-                      VP8LHistogram* const out);
+void VP8LHistogramAdd(const VP8LHistogram* WEBP_RESTRICT const a,
+                      const VP8LHistogram* WEBP_RESTRICT const b,
+                      VP8LHistogram* WEBP_RESTRICT const out);
 
 // -----------------------------------------------------------------------------
 // PrefixEncode()
@@ -241,11 +251,12 @@ typedef int (*VP8LVectorMismatchFunc)(const uint32_t* const array1,
 // Returns the first index where array1 and array2 are different.
 extern VP8LVectorMismatchFunc VP8LVectorMismatch;
 
-typedef void (*VP8LBundleColorMapFunc)(const uint8_t* const row, int width,
-                                       int xbits, uint32_t* dst);
+typedef void (*VP8LBundleColorMapFunc)(const uint8_t* WEBP_RESTRICT const row,
+                                       int width, int xbits,
+                                       uint32_t* WEBP_RESTRICT dst);
 extern VP8LBundleColorMapFunc VP8LBundleColorMap;
-void VP8LBundleColorMap_C(const uint8_t* const row, int width, int xbits,
-                          uint32_t* dst);
+void VP8LBundleColorMap_C(const uint8_t* WEBP_RESTRICT const row,
+                          int width, int xbits, uint32_t* WEBP_RESTRICT dst);
 
 // Must be called before calling any of the above methods.
 void VP8LEncDspInit(void);
diff --git a/src/dsp/lossless_common.h b/src/dsp/lossless_common.h
index d6139b2b..66eadf1f 100644
--- a/src/dsp/lossless_common.h
+++ b/src/dsp/lossless_common.h
@@ -73,23 +73,44 @@ static WEBP_INLINE int VP8LNearLosslessBits(int near_lossless_quality) {
 // Keeping a high threshold for now.
 #define APPROX_LOG_WITH_CORRECTION_MAX  65536
 #define APPROX_LOG_MAX                   4096
+// VP8LFastLog2 and VP8LFastSLog2 are used on elements from image histograms.
+// The histogram values cannot exceed the maximum number of pixels, which
+// is (1 << 14) * (1 << 14). Therefore S * log(S) < (1 << 33).
+// No more than 32 bits of precision should be chosen.
+// To match the original float implementation, 23 bits of precision are used.
+#define LOG_2_PRECISION_BITS 23
 #define LOG_2_RECIPROCAL 1.44269504088896338700465094007086
+// LOG_2_RECIPROCAL * (1 << LOG_2_PRECISION_BITS)
+#define LOG_2_RECIPROCAL_FIXED_DOUBLE 12102203.161561485379934310913085937500
+#define LOG_2_RECIPROCAL_FIXED ((uint64_t)12102203)
 #define LOG_LOOKUP_IDX_MAX 256
-extern const float kLog2Table[LOG_LOOKUP_IDX_MAX];
-extern const float kSLog2Table[LOG_LOOKUP_IDX_MAX];
-typedef float (*VP8LFastLog2SlowFunc)(uint32_t v);
+extern const uint32_t kLog2Table[LOG_LOOKUP_IDX_MAX];
+extern const uint64_t kSLog2Table[LOG_LOOKUP_IDX_MAX];
+typedef uint32_t (*VP8LFastLog2SlowFunc)(uint32_t v);
+typedef uint64_t (*VP8LFastSLog2SlowFunc)(uint32_t v);
 
 extern VP8LFastLog2SlowFunc VP8LFastLog2Slow;
-extern VP8LFastLog2SlowFunc VP8LFastSLog2Slow;
+extern VP8LFastSLog2SlowFunc VP8LFastSLog2Slow;
 
-static WEBP_INLINE float VP8LFastLog2(uint32_t v) {
+static WEBP_INLINE uint32_t VP8LFastLog2(uint32_t v) {
   return (v < LOG_LOOKUP_IDX_MAX) ? kLog2Table[v] : VP8LFastLog2Slow(v);
 }
 // Fast calculation of v * log2(v) for integer input.
-static WEBP_INLINE float VP8LFastSLog2(uint32_t v) {
+static WEBP_INLINE uint64_t VP8LFastSLog2(uint32_t v) {
   return (v < LOG_LOOKUP_IDX_MAX) ? kSLog2Table[v] : VP8LFastSLog2Slow(v);
 }
 
+static WEBP_INLINE uint64_t RightShiftRound(uint64_t v, uint32_t shift) {
+  return (v + (1ull << shift >> 1)) >> shift;
+}
+
+static WEBP_INLINE int64_t DivRound(int64_t a, int64_t b) {
+  return ((a < 0) == (b < 0)) ? ((a + b / 2) / b) : ((a - b / 2) / b);
+}
+
+#define WEBP_INT64_MAX ((int64_t)((1ull << 63) - 1))
+#define WEBP_UINT64_MAX (~0ull)
+
 // -----------------------------------------------------------------------------
 // PrefixEncode()
 
@@ -173,15 +194,15 @@ uint32_t VP8LSubPixels(uint32_t a, uint32_t b) {
 
 // The predictor is added to the output pixel (which
 // is therefore considered as a residual) to get the final prediction.
-#define GENERATE_PREDICTOR_ADD(PREDICTOR, PREDICTOR_ADD)             \
-static void PREDICTOR_ADD(const uint32_t* in, const uint32_t* upper, \
-                          int num_pixels, uint32_t* out) {           \
-  int x;                                                             \
-  assert(upper != NULL);                                             \
-  for (x = 0; x < num_pixels; ++x) {                                 \
-    const uint32_t pred = (PREDICTOR)(&out[x - 1], upper + x);       \
-    out[x] = VP8LAddPixels(in[x], pred);                             \
-  }                                                                  \
+#define GENERATE_PREDICTOR_ADD(PREDICTOR, PREDICTOR_ADD)                 \
+static void PREDICTOR_ADD(const uint32_t* in, const uint32_t* upper,     \
+                          int num_pixels, uint32_t* WEBP_RESTRICT out) { \
+  int x;                                                                 \
+  assert(upper != NULL);                                                 \
+  for (x = 0; x < num_pixels; ++x) {                                     \
+    const uint32_t pred = (PREDICTOR)(&out[x - 1], upper + x);           \
+    out[x] = VP8LAddPixels(in[x], pred);                                 \
+  }                                                                      \
 }
 
 #ifdef __cplusplus
diff --git a/src/dsp/lossless_enc.c b/src/dsp/lossless_enc.c
index 997d56c2..7e621a71 100644
--- a/src/dsp/lossless_enc.c
+++ b/src/dsp/lossless_enc.c
@@ -24,203 +24,123 @@
 #include "src/dsp/lossless_common.h"
 #include "src/dsp/yuv.h"
 
-// lookup table for small values of log2(int)
-const float kLog2Table[LOG_LOOKUP_IDX_MAX] = {
-  0.0000000000000000f, 0.0000000000000000f,
-  1.0000000000000000f, 1.5849625007211560f,
-  2.0000000000000000f, 2.3219280948873621f,
-  2.5849625007211560f, 2.8073549220576041f,
-  3.0000000000000000f, 3.1699250014423121f,
-  3.3219280948873621f, 3.4594316186372973f,
-  3.5849625007211560f, 3.7004397181410921f,
-  3.8073549220576041f, 3.9068905956085187f,
-  4.0000000000000000f, 4.0874628412503390f,
-  4.1699250014423121f, 4.2479275134435852f,
-  4.3219280948873626f, 4.3923174227787606f,
-  4.4594316186372973f, 4.5235619560570130f,
-  4.5849625007211560f, 4.6438561897747243f,
-  4.7004397181410917f, 4.7548875021634682f,
-  4.8073549220576037f, 4.8579809951275718f,
-  4.9068905956085187f, 4.9541963103868749f,
-  5.0000000000000000f, 5.0443941193584533f,
-  5.0874628412503390f, 5.1292830169449663f,
-  5.1699250014423121f, 5.2094533656289501f,
-  5.2479275134435852f, 5.2854022188622487f,
-  5.3219280948873626f, 5.3575520046180837f,
-  5.3923174227787606f, 5.4262647547020979f,
-  5.4594316186372973f, 5.4918530963296747f,
-  5.5235619560570130f, 5.5545888516776376f,
-  5.5849625007211560f, 5.6147098441152083f,
-  5.6438561897747243f, 5.6724253419714951f,
-  5.7004397181410917f, 5.7279204545631987f,
-  5.7548875021634682f, 5.7813597135246599f,
-  5.8073549220576037f, 5.8328900141647412f,
-  5.8579809951275718f, 5.8826430493618415f,
-  5.9068905956085187f, 5.9307373375628866f,
-  5.9541963103868749f, 5.9772799234999167f,
-  6.0000000000000000f, 6.0223678130284543f,
-  6.0443941193584533f, 6.0660891904577720f,
-  6.0874628412503390f, 6.1085244567781691f,
-  6.1292830169449663f, 6.1497471195046822f,
-  6.1699250014423121f, 6.1898245588800175f,
-  6.2094533656289501f, 6.2288186904958804f,
-  6.2479275134435852f, 6.2667865406949010f,
-  6.2854022188622487f, 6.3037807481771030f,
-  6.3219280948873626f, 6.3398500028846243f,
-  6.3575520046180837f, 6.3750394313469245f,
-  6.3923174227787606f, 6.4093909361377017f,
-  6.4262647547020979f, 6.4429434958487279f,
-  6.4594316186372973f, 6.4757334309663976f,
-  6.4918530963296747f, 6.5077946401986963f,
-  6.5235619560570130f, 6.5391588111080309f,
-  6.5545888516776376f, 6.5698556083309478f,
-  6.5849625007211560f, 6.5999128421871278f,
-  6.6147098441152083f, 6.6293566200796094f,
-  6.6438561897747243f, 6.6582114827517946f,
-  6.6724253419714951f, 6.6865005271832185f,
-  6.7004397181410917f, 6.7142455176661224f,
-  6.7279204545631987f, 6.7414669864011464f,
-  6.7548875021634682f, 6.7681843247769259f,
-  6.7813597135246599f, 6.7944158663501061f,
-  6.8073549220576037f, 6.8201789624151878f,
-  6.8328900141647412f, 6.8454900509443747f,
-  6.8579809951275718f, 6.8703647195834047f,
-  6.8826430493618415f, 6.8948177633079437f,
-  6.9068905956085187f, 6.9188632372745946f,
-  6.9307373375628866f, 6.9425145053392398f,
-  6.9541963103868749f, 6.9657842846620869f,
-  6.9772799234999167f, 6.9886846867721654f,
-  7.0000000000000000f, 7.0112272554232539f,
-  7.0223678130284543f, 7.0334230015374501f,
-  7.0443941193584533f, 7.0552824355011898f,
-  7.0660891904577720f, 7.0768155970508308f,
-  7.0874628412503390f, 7.0980320829605263f,
-  7.1085244567781691f, 7.1189410727235076f,
-  7.1292830169449663f, 7.1395513523987936f,
-  7.1497471195046822f, 7.1598713367783890f,
-  7.1699250014423121f, 7.1799090900149344f,
-  7.1898245588800175f, 7.1996723448363644f,
-  7.2094533656289501f, 7.2191685204621611f,
-  7.2288186904958804f, 7.2384047393250785f,
-  7.2479275134435852f, 7.2573878426926521f,
-  7.2667865406949010f, 7.2761244052742375f,
-  7.2854022188622487f, 7.2946207488916270f,
-  7.3037807481771030f, 7.3128829552843557f,
-  7.3219280948873626f, 7.3309168781146167f,
-  7.3398500028846243f, 7.3487281542310771f,
-  7.3575520046180837f, 7.3663222142458160f,
-  7.3750394313469245f, 7.3837042924740519f,
-  7.3923174227787606f, 7.4008794362821843f,
-  7.4093909361377017f, 7.4178525148858982f,
-  7.4262647547020979f, 7.4346282276367245f,
-  7.4429434958487279f, 7.4512111118323289f,
-  7.4594316186372973f, 7.4676055500829976f,
-  7.4757334309663976f, 7.4838157772642563f,
-  7.4918530963296747f, 7.4998458870832056f,
-  7.5077946401986963f, 7.5156998382840427f,
-  7.5235619560570130f, 7.5313814605163118f,
-  7.5391588111080309f, 7.5468944598876364f,
-  7.5545888516776376f, 7.5622424242210728f,
-  7.5698556083309478f, 7.5774288280357486f,
-  7.5849625007211560f, 7.5924570372680806f,
-  7.5999128421871278f, 7.6073303137496104f,
-  7.6147098441152083f, 7.6220518194563764f,
-  7.6293566200796094f, 7.6366246205436487f,
-  7.6438561897747243f, 7.6510516911789281f,
-  7.6582114827517946f, 7.6653359171851764f,
-  7.6724253419714951f, 7.6794800995054464f,
-  7.6865005271832185f, 7.6934869574993252f,
-  7.7004397181410917f, 7.7073591320808825f,
-  7.7142455176661224f, 7.7210991887071855f,
-  7.7279204545631987f, 7.7347096202258383f,
-  7.7414669864011464f, 7.7481928495894605f,
-  7.7548875021634682f, 7.7615512324444795f,
-  7.7681843247769259f, 7.7747870596011736f,
-  7.7813597135246599f, 7.7879025593914317f,
-  7.7944158663501061f, 7.8008998999203047f,
-  7.8073549220576037f, 7.8137811912170374f,
-  7.8201789624151878f, 7.8265484872909150f,
-  7.8328900141647412f, 7.8392037880969436f,
-  7.8454900509443747f, 7.8517490414160571f,
-  7.8579809951275718f, 7.8641861446542797f,
-  7.8703647195834047f, 7.8765169465649993f,
-  7.8826430493618415f, 7.8887432488982591f,
-  7.8948177633079437f, 7.9008668079807486f,
-  7.9068905956085187f, 7.9128893362299619f,
-  7.9188632372745946f, 7.9248125036057812f,
-  7.9307373375628866f, 7.9366379390025709f,
-  7.9425145053392398f, 7.9483672315846778f,
-  7.9541963103868749f, 7.9600019320680805f,
-  7.9657842846620869f, 7.9715435539507719f,
-  7.9772799234999167f, 7.9829935746943103f,
-  7.9886846867721654f, 7.9943534368588577f
+// lookup table for small values of log2(int) * (1 << LOG_2_PRECISION_BITS).
+// Obtained in Python with:
+// a = [ str(round((1<<23)*math.log2(i))) if i else "0" for i in range(256)]
+// print(',\n'.join(['  '+','.join(v)
+//       for v in batched([i.rjust(9) for i in a],7)]))
+const uint32_t kLog2Table[LOG_LOOKUP_IDX_MAX] = {
+         0,        0,  8388608, 13295629, 16777216, 19477745, 21684237,
+  23549800, 25165824, 26591258, 27866353, 29019816, 30072845, 31041538,
+  31938408, 32773374, 33554432, 34288123, 34979866, 35634199, 36254961,
+  36845429, 37408424, 37946388, 38461453, 38955489, 39430146, 39886887,
+  40327016, 40751698, 41161982, 41558811, 41943040, 42315445, 42676731,
+  43027545, 43368474, 43700062, 44022807, 44337167, 44643569, 44942404,
+  45234037, 45518808, 45797032, 46069003, 46334996, 46595268, 46850061,
+  47099600, 47344097, 47583753, 47818754, 48049279, 48275495, 48497560,
+  48715624, 48929828, 49140306, 49347187, 49550590, 49750631, 49947419,
+  50141058, 50331648, 50519283, 50704053, 50886044, 51065339, 51242017,
+  51416153, 51587818, 51757082, 51924012, 52088670, 52251118, 52411415,
+  52569616, 52725775, 52879946, 53032177, 53182516, 53331012, 53477707,
+  53622645, 53765868, 53907416, 54047327, 54185640, 54322389, 54457611,
+  54591338, 54723604, 54854440, 54983876, 55111943, 55238669, 55364082,
+  55488208, 55611074, 55732705, 55853126, 55972361, 56090432, 56207362,
+  56323174, 56437887, 56551524, 56664103, 56775645, 56886168, 56995691,
+  57104232, 57211808, 57318436, 57424133, 57528914, 57632796, 57735795,
+  57837923, 57939198, 58039632, 58139239, 58238033, 58336027, 58433234,
+  58529666, 58625336, 58720256, 58814437, 58907891, 59000628, 59092661,
+  59183999, 59274652, 59364632, 59453947, 59542609, 59630625, 59718006,
+  59804761, 59890898, 59976426, 60061354, 60145690, 60229443, 60312620,
+  60395229, 60477278, 60558775, 60639726, 60720140, 60800023, 60879382,
+  60958224, 61036555, 61114383, 61191714, 61268554, 61344908, 61420785,
+  61496188, 61571124, 61645600, 61719620, 61793189, 61866315, 61939001,
+  62011253, 62083076, 62154476, 62225457, 62296024, 62366182, 62435935,
+  62505289, 62574248, 62642816, 62710997, 62778797, 62846219, 62913267,
+  62979946, 63046260, 63112212, 63177807, 63243048, 63307939, 63372484,
+  63436687, 63500551, 63564080, 63627277, 63690146, 63752690, 63814912,
+  63876816, 63938405, 63999682, 64060650, 64121313, 64181673, 64241734,
+  64301498, 64360969, 64420148, 64479040, 64537646, 64595970, 64654014,
+  64711782, 64769274, 64826495, 64883447, 64940132, 64996553, 65052711,
+  65108611, 65164253, 65219641, 65274776, 65329662, 65384299, 65438691,
+  65492840, 65546747, 65600416, 65653847, 65707044, 65760008, 65812741,
+  65865245, 65917522, 65969575, 66021404, 66073013, 66124403, 66175575,
+  66226531, 66277275, 66327806, 66378127, 66428240, 66478146, 66527847,
+  66577345, 66626641, 66675737, 66724635, 66773336, 66821842, 66870154,
+  66918274, 66966204, 67013944, 67061497
 };
 
-const float kSLog2Table[LOG_LOOKUP_IDX_MAX] = {
-  0.00000000f,    0.00000000f,  2.00000000f,   4.75488750f,
-  8.00000000f,   11.60964047f,  15.50977500f,  19.65148445f,
-  24.00000000f,  28.52932501f,  33.21928095f,  38.05374781f,
-  43.01955001f,  48.10571634f,  53.30296891f,  58.60335893f,
-  64.00000000f,  69.48686830f,  75.05865003f,  80.71062276f,
-  86.43856190f,  92.23866588f,  98.10749561f,  104.04192499f,
-  110.03910002f, 116.09640474f, 122.21143267f, 128.38196256f,
-  134.60593782f, 140.88144886f, 147.20671787f, 153.58008562f,
-  160.00000000f, 166.46500594f, 172.97373660f, 179.52490559f,
-  186.11730005f, 192.74977453f, 199.42124551f, 206.13068654f,
-  212.87712380f, 219.65963219f, 226.47733176f, 233.32938445f,
-  240.21499122f, 247.13338933f, 254.08384998f, 261.06567603f,
-  268.07820003f, 275.12078236f, 282.19280949f, 289.29369244f,
-  296.42286534f, 303.57978409f, 310.76392512f, 317.97478424f,
-  325.21187564f, 332.47473081f, 339.76289772f, 347.07593991f,
-  354.41343574f, 361.77497759f, 369.16017124f, 376.56863518f,
-  384.00000000f, 391.45390785f, 398.93001188f, 406.42797576f,
-  413.94747321f, 421.48818752f, 429.04981119f, 436.63204548f,
-  444.23460010f, 451.85719280f, 459.49954906f, 467.16140179f,
-  474.84249102f, 482.54256363f, 490.26137307f, 497.99867911f,
-  505.75424759f, 513.52785023f, 521.31926438f, 529.12827280f,
-  536.95466351f, 544.79822957f, 552.65876890f, 560.53608414f,
-  568.42998244f, 576.34027536f, 584.26677867f, 592.20931226f,
-  600.16769996f, 608.14176943f, 616.13135206f, 624.13628279f,
-  632.15640007f, 640.19154569f, 648.24156472f, 656.30630539f,
-  664.38561898f, 672.47935976f, 680.58738488f, 688.70955430f,
-  696.84573069f, 704.99577935f, 713.15956818f, 721.33696754f,
-  729.52785023f, 737.73209140f, 745.94956849f, 754.18016116f,
-  762.42375127f, 770.68022275f, 778.94946161f, 787.23135586f,
-  795.52579543f, 803.83267219f, 812.15187982f, 820.48331383f,
-  828.82687147f, 837.18245171f, 845.54995518f, 853.92928416f,
-  862.32034249f, 870.72303558f, 879.13727036f, 887.56295522f,
-  896.00000000f, 904.44831595f, 912.90781569f, 921.37841320f,
-  929.86002376f, 938.35256392f, 946.85595152f, 955.37010560f,
-  963.89494641f, 972.43039537f, 980.97637504f, 989.53280911f,
-  998.09962237f, 1006.67674069f, 1015.26409097f, 1023.86160116f,
-  1032.46920021f, 1041.08681805f, 1049.71438560f, 1058.35183469f,
-  1066.99909811f, 1075.65610955f, 1084.32280357f, 1092.99911564f,
-  1101.68498204f, 1110.38033993f, 1119.08512727f, 1127.79928282f,
-  1136.52274614f, 1145.25545758f, 1153.99735821f, 1162.74838989f,
-  1171.50849518f, 1180.27761738f, 1189.05570047f, 1197.84268914f,
-  1206.63852876f, 1215.44316535f, 1224.25654560f, 1233.07861684f,
-  1241.90932703f, 1250.74862473f, 1259.59645914f, 1268.45278005f,
-  1277.31753781f, 1286.19068338f, 1295.07216828f, 1303.96194457f,
-  1312.85996488f, 1321.76618236f, 1330.68055071f, 1339.60302413f,
-  1348.53355734f, 1357.47210556f, 1366.41862452f, 1375.37307041f,
-  1384.33539991f, 1393.30557020f, 1402.28353887f, 1411.26926400f,
-  1420.26270412f, 1429.26381818f, 1438.27256558f, 1447.28890615f,
-  1456.31280014f, 1465.34420819f, 1474.38309138f, 1483.42941118f,
-  1492.48312945f, 1501.54420843f, 1510.61261078f, 1519.68829949f,
-  1528.77123795f, 1537.86138993f, 1546.95871952f, 1556.06319119f,
-  1565.17476976f, 1574.29342040f, 1583.41910860f, 1592.55180020f,
-  1601.69146137f, 1610.83805860f, 1619.99155871f, 1629.15192882f,
-  1638.31913637f, 1647.49314911f, 1656.67393509f, 1665.86146266f,
-  1675.05570047f, 1684.25661744f, 1693.46418280f, 1702.67836605f,
-  1711.89913698f, 1721.12646563f, 1730.36032233f, 1739.60067768f,
-  1748.84750254f, 1758.10076802f, 1767.36044551f, 1776.62650662f,
-  1785.89892323f, 1795.17766747f, 1804.46271172f, 1813.75402857f,
-  1823.05159087f, 1832.35537170f, 1841.66534438f, 1850.98148244f,
-  1860.30375965f, 1869.63214999f, 1878.96662767f, 1888.30716711f,
-  1897.65374295f, 1907.00633003f, 1916.36490342f, 1925.72943838f,
-  1935.09991037f, 1944.47629506f, 1953.85856831f, 1963.24670620f,
-  1972.64068498f, 1982.04048108f, 1991.44607117f, 2000.85743204f,
-  2010.27454072f, 2019.69737440f, 2029.12591044f, 2038.56012640f
+// lookup table for small values of int*log2(int) * (1 << LOG_2_PRECISION_BITS).
+// Obtained in Python with:
+// a=[ "%d"%i if i<(1<<32) else "%dull"%i
+//     for i in [ round((1<<LOG_2_PRECISION_BITS)*math.log2(i)*i) if i
+//     else 0 for i in range(256)]]
+// print(',\n '.join([','.join(v) for v in batched([i.rjust(15)
+//                      for i in a],4)]))
+const uint64_t kSLog2Table[LOG_LOOKUP_IDX_MAX] = {
+               0,              0,       16777216,       39886887,
+        67108864,       97388723,      130105423,      164848600,
+       201326592,      239321324,      278663526,      319217973,
+       360874141,      403539997,      447137711,      491600606,
+       536870912,      582898099,      629637592,      677049776,
+       725099212,      773754010,      822985323,      872766924,
+       923074875,      973887230,     1025183802,     1076945958,
+      1129156447,     1181799249,     1234859451,     1288323135,
+      1342177280,     1396409681,     1451008871,     1505964059,
+      1561265072,     1616902301,     1672866655,     1729149526,
+      1785742744,     1842638548,     1899829557,     1957308741,
+      2015069397,     2073105127,     2131409817,  2189977618ull,
+   2248802933ull,  2307880396ull,  2367204859ull,  2426771383ull,
+   2486575220ull,  2546611805ull,  2606876748ull,  2667365819ull,
+   2728074942ull,  2789000187ull,  2850137762ull,  2911484006ull,
+   2973035382ull,  3034788471ull,  3096739966ull,  3158886666ull,
+   3221225472ull,  3283753383ull,  3346467489ull,  3409364969ull,
+   3472443085ull,  3535699182ull,  3599130679ull,  3662735070ull,
+   3726509920ull,  3790452862ull,  3854561593ull,  3918833872ull,
+   3983267519ull,  4047860410ull,  4112610476ull,  4177515704ull,
+   4242574127ull,  4307783833ull,  4373142952ull,  4438649662ull,
+   4504302186ull,  4570098787ull,  4636037770ull,  4702117480ull,
+   4768336298ull,  4834692645ull,  4901184974ull,  4967811774ull,
+   5034571569ull,  5101462912ull,  5168484389ull,  5235634615ull,
+   5302912235ull,  5370315922ull,  5437844376ull,  5505496324ull,
+   5573270518ull,  5641165737ull,  5709180782ull,  5777314477ull,
+   5845565671ull,  5913933235ull,  5982416059ull,  6051013057ull,
+   6119723161ull,  6188545324ull,  6257478518ull,  6326521733ull,
+   6395673979ull,  6464934282ull,  6534301685ull,  6603775250ull,
+   6673354052ull,  6743037185ull,  6812823756ull,  6882712890ull,
+   6952703725ull,  7022795412ull,  7092987118ull,  7163278025ull,
+   7233667324ull,  7304154222ull,  7374737939ull,  7445417707ull,
+   7516192768ull,  7587062379ull,  7658025806ull,  7729082328ull,
+   7800231234ull,  7871471825ull,  7942803410ull,  8014225311ull,
+   8085736859ull,  8157337394ull,  8229026267ull,  8300802839ull,
+   8372666477ull,  8444616560ull,  8516652476ull,  8588773618ull,
+   8660979393ull,  8733269211ull,  8805642493ull,  8878098667ull,
+   8950637170ull,  9023257446ull,  9095958945ull,  9168741125ull,
+   9241603454ull,  9314545403ull,  9387566451ull,  9460666086ull,
+   9533843800ull,  9607099093ull,  9680431471ull,  9753840445ull,
+   9827325535ull,  9900886263ull,  9974522161ull, 10048232765ull,
+  10122017615ull, 10195876260ull, 10269808253ull, 10343813150ull,
+  10417890516ull, 10492039919ull, 10566260934ull, 10640553138ull,
+  10714916116ull, 10789349456ull, 10863852751ull, 10938425600ull,
+  11013067604ull, 11087778372ull, 11162557513ull, 11237404645ull,
+  11312319387ull, 11387301364ull, 11462350205ull, 11537465541ull,
+  11612647010ull, 11687894253ull, 11763206912ull, 11838584638ull,
+  11914027082ull, 11989533899ull, 12065104750ull, 12140739296ull,
+  12216437206ull, 12292198148ull, 12368021795ull, 12443907826ull,
+  12519855920ull, 12595865759ull, 12671937032ull, 12748069427ull,
+  12824262637ull, 12900516358ull, 12976830290ull, 13053204134ull,
+  13129637595ull, 13206130381ull, 13282682202ull, 13359292772ull,
+  13435961806ull, 13512689025ull, 13589474149ull, 13666316903ull,
+  13743217014ull, 13820174211ull, 13897188225ull, 13974258793ull,
+  14051385649ull, 14128568535ull, 14205807192ull, 14283101363ull,
+  14360450796ull, 14437855239ull, 14515314443ull, 14592828162ull,
+  14670396151ull, 14748018167ull, 14825693972ull, 14903423326ull,
+  14981205995ull, 15059041743ull, 15136930339ull, 15214871554ull,
+  15292865160ull, 15370910930ull, 15449008641ull, 15527158071ull,
+  15605359001ull, 15683611210ull, 15761914485ull, 15840268608ull,
+  15918673369ull, 15997128556ull, 16075633960ull, 16154189373ull,
+  16232794589ull, 16311449405ull, 16390153617ull, 16468907026ull,
+  16547709431ull, 16626560636ull, 16705460444ull, 16784408661ull,
+  16863405094ull, 16942449552ull, 17021541845ull, 17100681785ull
 };
 
 const VP8LPrefixCode kPrefixEncodeCode[PREFIX_LOOKUP_IDX_MAX] = {
@@ -326,23 +246,19 @@ const uint8_t kPrefixEncodeExtraBitsValue[PREFIX_LOOKUP_IDX_MAX] = {
   112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126
 };
 
-static float FastSLog2Slow_C(uint32_t v) {
+static uint64_t FastSLog2Slow_C(uint32_t v) {
   assert(v >= LOG_LOOKUP_IDX_MAX);
   if (v < APPROX_LOG_WITH_CORRECTION_MAX) {
+    const uint64_t orig_v = v;
+    uint64_t correction;
 #if !defined(WEBP_HAVE_SLOW_CLZ_CTZ)
     // use clz if available
-    const int log_cnt = BitsLog2Floor(v) - 7;
+    const uint64_t log_cnt = BitsLog2Floor(v) - 7;
     const uint32_t y = 1 << log_cnt;
-    int correction = 0;
-    const float v_f = (float)v;
-    const uint32_t orig_v = v;
     v >>= log_cnt;
 #else
-    int log_cnt = 0;
+    uint64_t log_cnt = 0;
     uint32_t y = 1;
-    int correction = 0;
-    const float v_f = (float)v;
-    const uint32_t orig_v = v;
     do {
       ++log_cnt;
       v = v >> 1;
@@ -354,45 +270,43 @@ static float FastSLog2Slow_C(uint32_t v) {
     // log2(Xf) = log2(floor(Xf)) + log2(1 + (v % y) / v)
     // The correction factor: log(1 + d) ~ d; for very small d values, so
     // log2(1 + (v % y) / v) ~ LOG_2_RECIPROCAL * (v % y)/v
-    // LOG_2_RECIPROCAL ~ 23/16
-    correction = (23 * (orig_v & (y - 1))) >> 4;
-    return v_f * (kLog2Table[v] + log_cnt) + correction;
+    correction = LOG_2_RECIPROCAL_FIXED * (orig_v & (y - 1));
+    return orig_v * (kLog2Table[v] + (log_cnt << LOG_2_PRECISION_BITS)) +
+           correction;
   } else {
-    return (float)(LOG_2_RECIPROCAL * v * log((double)v));
+    return (uint64_t)(LOG_2_RECIPROCAL_FIXED_DOUBLE * v * log((double)v) + .5);
   }
 }
 
-static float FastLog2Slow_C(uint32_t v) {
+static uint32_t FastLog2Slow_C(uint32_t v) {
   assert(v >= LOG_LOOKUP_IDX_MAX);
   if (v < APPROX_LOG_WITH_CORRECTION_MAX) {
+    const uint32_t orig_v = v;
+    uint32_t log_2;
 #if !defined(WEBP_HAVE_SLOW_CLZ_CTZ)
     // use clz if available
-    const int log_cnt = BitsLog2Floor(v) - 7;
+    const uint32_t log_cnt = BitsLog2Floor(v) - 7;
     const uint32_t y = 1 << log_cnt;
-    const uint32_t orig_v = v;
-    double log_2;
     v >>= log_cnt;
 #else
-    int log_cnt = 0;
+    uint32_t log_cnt = 0;
     uint32_t y = 1;
-    const uint32_t orig_v = v;
-    double log_2;
     do {
       ++log_cnt;
       v = v >> 1;
       y = y << 1;
     } while (v >= LOG_LOOKUP_IDX_MAX);
 #endif
-    log_2 = kLog2Table[v] + log_cnt;
+    log_2 = kLog2Table[v] + (log_cnt << LOG_2_PRECISION_BITS);
     if (orig_v >= APPROX_LOG_MAX) {
       // Since the division is still expensive, add this correction factor only
       // for large values of 'v'.
-      const int correction = (23 * (orig_v & (y - 1))) >> 4;
-      log_2 += (double)correction / orig_v;
+      const uint64_t correction = LOG_2_RECIPROCAL_FIXED * (orig_v & (y - 1));
+      log_2 += (uint32_t)DivRound(correction, orig_v);
     }
-    return (float)log_2;
+    return log_2;
   } else {
-    return (float)(LOG_2_RECIPROCAL * log((double)v));
+    return (uint32_t)(LOG_2_RECIPROCAL_FIXED_DOUBLE * log((double)v) + .5);
   }
 }
 
@@ -400,37 +314,53 @@ static float FastLog2Slow_C(uint32_t v) {
 // Methods to calculate Entropy (Shannon).
 
 // Compute the combined Shanon's entropy for distribution {X} and {X+Y}
-static float CombinedShannonEntropy_C(const int X[256], const int Y[256]) {
+static uint64_t CombinedShannonEntropy_C(const uint32_t X[256],
+                                         const uint32_t Y[256]) {
   int i;
-  float retval = 0.f;
-  int sumX = 0, sumXY = 0;
+  uint64_t retval = 0;
+  uint32_t sumX = 0, sumXY = 0;
   for (i = 0; i < 256; ++i) {
-    const int x = X[i];
+    const uint32_t x = X[i];
     if (x != 0) {
-      const int xy = x + Y[i];
+      const uint32_t xy = x + Y[i];
       sumX += x;
-      retval -= VP8LFastSLog2(x);
+      retval += VP8LFastSLog2(x);
       sumXY += xy;
-      retval -= VP8LFastSLog2(xy);
+      retval += VP8LFastSLog2(xy);
     } else if (Y[i] != 0) {
       sumXY += Y[i];
-      retval -= VP8LFastSLog2(Y[i]);
+      retval += VP8LFastSLog2(Y[i]);
+    }
+  }
+  retval = VP8LFastSLog2(sumX) + VP8LFastSLog2(sumXY) - retval;
+  return retval;
+}
+
+static uint64_t ShannonEntropy_C(const uint32_t* X, int n) {
+  int i;
+  uint64_t retval = 0;
+  uint32_t sumX = 0;
+  for (i = 0; i < n; ++i) {
+    const int x = X[i];
+    if (x != 0) {
+      sumX += x;
+      retval += VP8LFastSLog2(x);
     }
   }
-  retval += VP8LFastSLog2(sumX) + VP8LFastSLog2(sumXY);
+  retval = VP8LFastSLog2(sumX) - retval;
   return retval;
 }
 
 void VP8LBitEntropyInit(VP8LBitEntropy* const entropy) {
-  entropy->entropy = 0.;
+  entropy->entropy = 0;
   entropy->sum = 0;
   entropy->nonzeros = 0;
   entropy->max_val = 0;
   entropy->nonzero_code = VP8L_NON_TRIVIAL_SYM;
 }
 
-void VP8LBitsEntropyUnrefined(const uint32_t* const array, int n,
-                              VP8LBitEntropy* const entropy) {
+void VP8LBitsEntropyUnrefined(const uint32_t* WEBP_RESTRICT const array, int n,
+                              VP8LBitEntropy* WEBP_RESTRICT const entropy) {
   int i;
 
   VP8LBitEntropyInit(entropy);
@@ -440,18 +370,20 @@ void VP8LBitsEntropyUnrefined(const uint32_t* const array, int n,
       entropy->sum += array[i];
       entropy->nonzero_code = i;
       ++entropy->nonzeros;
-      entropy->entropy -= VP8LFastSLog2(array[i]);
+      entropy->entropy += VP8LFastSLog2(array[i]);
       if (entropy->max_val < array[i]) {
         entropy->max_val = array[i];
       }
     }
   }
-  entropy->entropy += VP8LFastSLog2(entropy->sum);
+  entropy->entropy = VP8LFastSLog2(entropy->sum) - entropy->entropy;
 }
 
 static WEBP_INLINE void GetEntropyUnrefinedHelper(
-    uint32_t val, int i, uint32_t* const val_prev, int* const i_prev,
-    VP8LBitEntropy* const bit_entropy, VP8LStreaks* const stats) {
+    uint32_t val, int i, uint32_t* WEBP_RESTRICT const val_prev,
+    int* WEBP_RESTRICT const i_prev,
+    VP8LBitEntropy* WEBP_RESTRICT const bit_entropy,
+    VP8LStreaks* WEBP_RESTRICT const stats) {
   const int streak = i - *i_prev;
 
   // Gather info for the bit entropy.
@@ -459,7 +391,7 @@ static WEBP_INLINE void GetEntropyUnrefinedHelper(
     bit_entropy->sum += (*val_prev) * streak;
     bit_entropy->nonzeros += streak;
     bit_entropy->nonzero_code = *i_prev;
-    bit_entropy->entropy -= VP8LFastSLog2(*val_prev) * streak;
+    bit_entropy->entropy += VP8LFastSLog2(*val_prev) * streak;
     if (bit_entropy->max_val < *val_prev) {
       bit_entropy->max_val = *val_prev;
     }
@@ -473,9 +405,10 @@ static WEBP_INLINE void GetEntropyUnrefinedHelper(
   *i_prev = i;
 }
 
-static void GetEntropyUnrefined_C(const uint32_t X[], int length,
-                                  VP8LBitEntropy* const bit_entropy,
-                                  VP8LStreaks* const stats) {
+static void GetEntropyUnrefined_C(
+    const uint32_t X[], int length,
+    VP8LBitEntropy* WEBP_RESTRICT const bit_entropy,
+    VP8LStreaks* WEBP_RESTRICT const stats) {
   int i;
   int i_prev = 0;
   uint32_t x_prev = X[0];
@@ -491,14 +424,13 @@ static void GetEntropyUnrefined_C(const uint32_t X[], int length,
   }
   GetEntropyUnrefinedHelper(0, i, &x_prev, &i_prev, bit_entropy, stats);
 
-  bit_entropy->entropy += VP8LFastSLog2(bit_entropy->sum);
+  bit_entropy->entropy = VP8LFastSLog2(bit_entropy->sum) - bit_entropy->entropy;
 }
 
-static void GetCombinedEntropyUnrefined_C(const uint32_t X[],
-                                          const uint32_t Y[],
-                                          int length,
-                                          VP8LBitEntropy* const bit_entropy,
-                                          VP8LStreaks* const stats) {
+static void GetCombinedEntropyUnrefined_C(
+    const uint32_t X[], const uint32_t Y[], int length,
+    VP8LBitEntropy* WEBP_RESTRICT const bit_entropy,
+    VP8LStreaks* WEBP_RESTRICT const stats) {
   int i = 1;
   int i_prev = 0;
   uint32_t xy_prev = X[0] + Y[0];
@@ -514,7 +446,7 @@ static void GetCombinedEntropyUnrefined_C(const uint32_t X[],
   }
   GetEntropyUnrefinedHelper(0, i, &xy_prev, &i_prev, bit_entropy, stats);
 
-  bit_entropy->entropy += VP8LFastSLog2(bit_entropy->sum);
+  bit_entropy->entropy = VP8LFastSLog2(bit_entropy->sum) - bit_entropy->entropy;
 }
 
 //------------------------------------------------------------------------------
@@ -538,8 +470,8 @@ static WEBP_INLINE int8_t U32ToS8(uint32_t v) {
   return (int8_t)(v & 0xff);
 }
 
-void VP8LTransformColor_C(const VP8LMultipliers* const m, uint32_t* data,
-                          int num_pixels) {
+void VP8LTransformColor_C(const VP8LMultipliers* WEBP_RESTRICT const m,
+                          uint32_t* WEBP_RESTRICT data, int num_pixels) {
   int i;
   for (i = 0; i < num_pixels; ++i) {
     const uint32_t argb = data[i];
@@ -575,9 +507,10 @@ static WEBP_INLINE uint8_t TransformColorBlue(uint8_t green_to_blue,
   return (new_blue & 0xff);
 }
 
-void VP8LCollectColorRedTransforms_C(const uint32_t* argb, int stride,
+void VP8LCollectColorRedTransforms_C(const uint32_t* WEBP_RESTRICT argb,
+                                     int stride,
                                      int tile_width, int tile_height,
-                                     int green_to_red, int histo[]) {
+                                     int green_to_red, uint32_t histo[]) {
   while (tile_height-- > 0) {
     int x;
     for (x = 0; x < tile_width; ++x) {
@@ -587,10 +520,11 @@ void VP8LCollectColorRedTransforms_C(const uint32_t* argb, int stride,
   }
 }
 
-void VP8LCollectColorBlueTransforms_C(const uint32_t* argb, int stride,
+void VP8LCollectColorBlueTransforms_C(const uint32_t* WEBP_RESTRICT argb,
+                                      int stride,
                                       int tile_width, int tile_height,
                                       int green_to_blue, int red_to_blue,
-                                      int histo[]) {
+                                      uint32_t histo[]) {
   while (tile_height-- > 0) {
     int x;
     for (x = 0; x < tile_width; ++x) {
@@ -614,8 +548,8 @@ static int VectorMismatch_C(const uint32_t* const array1,
 }
 
 // Bundles multiple (1, 2, 4 or 8) pixels into a single pixel.
-void VP8LBundleColorMap_C(const uint8_t* const row, int width, int xbits,
-                          uint32_t* dst) {
+void VP8LBundleColorMap_C(const uint8_t* WEBP_RESTRICT const row,
+                          int width, int xbits, uint32_t* WEBP_RESTRICT dst) {
   int x;
   if (xbits > 0) {
     const int bit_depth = 1 << (3 - xbits);
@@ -646,7 +580,8 @@ static uint32_t ExtraCost_C(const uint32_t* population, int length) {
   return cost;
 }
 
-static uint32_t ExtraCostCombined_C(const uint32_t* X, const uint32_t* Y,
+static uint32_t ExtraCostCombined_C(const uint32_t* WEBP_RESTRICT X,
+                                    const uint32_t* WEBP_RESTRICT Y,
                                     int length) {
   int i;
   uint32_t cost = X[4] + Y[4] + X[5] + Y[5];
@@ -661,13 +596,15 @@ static uint32_t ExtraCostCombined_C(const uint32_t* X, const uint32_t* Y,
 
 //------------------------------------------------------------------------------
 
-static void AddVector_C(const uint32_t* a, const uint32_t* b, uint32_t* out,
-                        int size) {
+static void AddVector_C(const uint32_t* WEBP_RESTRICT a,
+                        const uint32_t* WEBP_RESTRICT b,
+                        uint32_t* WEBP_RESTRICT out, int size) {
   int i;
   for (i = 0; i < size; ++i) out[i] = a[i] + b[i];
 }
 
-static void AddVectorEq_C(const uint32_t* a, uint32_t* out, int size) {
+static void AddVectorEq_C(const uint32_t* WEBP_RESTRICT a,
+                          uint32_t* WEBP_RESTRICT out, int size) {
   int i;
   for (i = 0; i < size; ++i) out[i] += a[i];
 }
@@ -696,8 +633,9 @@ static void AddVectorEq_C(const uint32_t* a, uint32_t* out, int size) {
   }                                                                            \
 } while (0)
 
-void VP8LHistogramAdd(const VP8LHistogram* const a,
-                      const VP8LHistogram* const b, VP8LHistogram* const out) {
+void VP8LHistogramAdd(const VP8LHistogram* WEBP_RESTRICT const a,
+                      const VP8LHistogram* WEBP_RESTRICT const b,
+                      VP8LHistogram* WEBP_RESTRICT const out) {
   int i;
   const int literal_size = VP8LHistogramNumCodes(a->palette_code_bits_);
   assert(a->palette_code_bits_ == b->palette_code_bits_);
@@ -727,14 +665,14 @@ void VP8LHistogramAdd(const VP8LHistogram* const a,
 // Image transforms.
 
 static void PredictorSub0_C(const uint32_t* in, const uint32_t* upper,
-                            int num_pixels, uint32_t* out) {
+                            int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   for (i = 0; i < num_pixels; ++i) out[i] = VP8LSubPixels(in[i], ARGB_BLACK);
   (void)upper;
 }
 
 static void PredictorSub1_C(const uint32_t* in, const uint32_t* upper,
-                            int num_pixels, uint32_t* out) {
+                            int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   for (i = 0; i < num_pixels; ++i) out[i] = VP8LSubPixels(in[i], in[i - 1]);
   (void)upper;
@@ -745,7 +683,8 @@ static void PredictorSub1_C(const uint32_t* in, const uint32_t* upper,
 #define GENERATE_PREDICTOR_SUB(PREDICTOR_I)                                \
 static void PredictorSub##PREDICTOR_I##_C(const uint32_t* in,              \
                                           const uint32_t* upper,           \
-                                          int num_pixels, uint32_t* out) { \
+                                          int num_pixels,                  \
+                                          uint32_t* WEBP_RESTRICT out) {   \
   int x;                                                                   \
   assert(upper != NULL);                                                   \
   for (x = 0; x < num_pixels; ++x) {                                       \
@@ -778,11 +717,12 @@ VP8LCollectColorBlueTransformsFunc VP8LCollectColorBlueTransforms;
 VP8LCollectColorRedTransformsFunc VP8LCollectColorRedTransforms;
 
 VP8LFastLog2SlowFunc VP8LFastLog2Slow;
-VP8LFastLog2SlowFunc VP8LFastSLog2Slow;
+VP8LFastSLog2SlowFunc VP8LFastSLog2Slow;
 
 VP8LCostFunc VP8LExtraCost;
 VP8LCostCombinedFunc VP8LExtraCostCombined;
 VP8LCombinedShannonEntropyFunc VP8LCombinedShannonEntropy;
+VP8LShannonEntropyFunc VP8LShannonEntropy;
 
 VP8LGetEntropyUnrefinedFunc VP8LGetEntropyUnrefined;
 VP8LGetCombinedEntropyUnrefinedFunc VP8LGetCombinedEntropyUnrefined;
@@ -822,6 +762,7 @@ WEBP_DSP_INIT_FUNC(VP8LEncDspInit) {
   VP8LExtraCost = ExtraCost_C;
   VP8LExtraCostCombined = ExtraCostCombined_C;
   VP8LCombinedShannonEntropy = CombinedShannonEntropy_C;
+  VP8LShannonEntropy = ShannonEntropy_C;
 
   VP8LGetEntropyUnrefined = GetEntropyUnrefined_C;
   VP8LGetCombinedEntropyUnrefined = GetCombinedEntropyUnrefined_C;
@@ -911,6 +852,7 @@ WEBP_DSP_INIT_FUNC(VP8LEncDspInit) {
   assert(VP8LExtraCost != NULL);
   assert(VP8LExtraCostCombined != NULL);
   assert(VP8LCombinedShannonEntropy != NULL);
+  assert(VP8LShannonEntropy != NULL);
   assert(VP8LGetEntropyUnrefined != NULL);
   assert(VP8LGetCombinedEntropyUnrefined != NULL);
   assert(VP8LAddVector != NULL);
diff --git a/src/dsp/lossless_enc_mips32.c b/src/dsp/lossless_enc_mips32.c
index e10f12da..8e9d7358 100644
--- a/src/dsp/lossless_enc_mips32.c
+++ b/src/dsp/lossless_enc_mips32.c
@@ -23,12 +23,12 @@
 #include <stdlib.h>
 #include <string.h>
 
-static float FastSLog2Slow_MIPS32(uint32_t v) {
+static uint64_t FastSLog2Slow_MIPS32(uint32_t v) {
   assert(v >= LOG_LOOKUP_IDX_MAX);
   if (v < APPROX_LOG_WITH_CORRECTION_MAX) {
-    uint32_t log_cnt, y, correction;
+    uint32_t log_cnt, y;
+    uint64_t correction;
     const int c24 = 24;
-    const float v_f = (float)v;
     uint32_t temp;
 
     // Xf = 256 = 2^8
@@ -49,22 +49,23 @@ static float FastSLog2Slow_MIPS32(uint32_t v) {
     // log2(Xf) = log2(floor(Xf)) + log2(1 + (v % y) / v)
     // The correction factor: log(1 + d) ~ d; for very small d values, so
     // log2(1 + (v % y) / v) ~ LOG_2_RECIPROCAL * (v % y)/v
-    // LOG_2_RECIPROCAL ~ 23/16
 
     // (v % y) = (v % 2^log_cnt) = v & (2^log_cnt - 1)
-    correction = (23 * (v & (y - 1))) >> 4;
-    return v_f * (kLog2Table[temp] + log_cnt) + correction;
+    correction = LOG_2_RECIPROCAL_FIXED * (v & (y - 1));
+    return (uint64_t)v * (kLog2Table[temp] +
+                          ((uint64_t)log_cnt << LOG_2_PRECISION_BITS)) +
+           correction;
   } else {
-    return (float)(LOG_2_RECIPROCAL * v * log((double)v));
+    return (uint64_t)(LOG_2_RECIPROCAL_FIXED_DOUBLE * v * log((double)v) + .5);
   }
 }
 
-static float FastLog2Slow_MIPS32(uint32_t v) {
+static uint32_t FastLog2Slow_MIPS32(uint32_t v) {
   assert(v >= LOG_LOOKUP_IDX_MAX);
   if (v < APPROX_LOG_WITH_CORRECTION_MAX) {
     uint32_t log_cnt, y;
     const int c24 = 24;
-    double log_2;
+    uint32_t log_2;
     uint32_t temp;
 
     __asm__ volatile(
@@ -78,17 +79,16 @@ static float FastLog2Slow_MIPS32(uint32_t v) {
       : [c24]"r"(c24), [v]"r"(v)
     );
 
-    log_2 = kLog2Table[temp] + log_cnt;
+    log_2 = kLog2Table[temp] + (log_cnt << LOG_2_PRECISION_BITS);
     if (v >= APPROX_LOG_MAX) {
       // Since the division is still expensive, add this correction factor only
       // for large values of 'v'.
-
-      const uint32_t correction = (23 * (v & (y - 1))) >> 4;
-      log_2 += (double)correction / v;
+      const uint64_t correction = LOG_2_RECIPROCAL_FIXED * (v & (y - 1));
+      log_2 += (uint32_t)DivRound(correction, v);
     }
-    return (float)log_2;
+    return log_2;
   } else {
-    return (float)(LOG_2_RECIPROCAL * log((double)v));
+    return (uint32_t)(LOG_2_RECIPROCAL_FIXED_DOUBLE * log((double)v) + .5);
   }
 }
 
@@ -149,8 +149,9 @@ static uint32_t ExtraCost_MIPS32(const uint32_t* const population, int length) {
 //     pY += 2;
 //   }
 //   return cost;
-static uint32_t ExtraCostCombined_MIPS32(const uint32_t* const X,
-                                         const uint32_t* const Y, int length) {
+static uint32_t ExtraCostCombined_MIPS32(const uint32_t* WEBP_RESTRICT const X,
+                                         const uint32_t* WEBP_RESTRICT const Y,
+                                         int length) {
   int i, temp0, temp1, temp2, temp3;
   const uint32_t* pX = &X[4];
   const uint32_t* pY = &Y[4];
@@ -215,8 +216,10 @@ static uint32_t ExtraCostCombined_MIPS32(const uint32_t* const X,
 
 // Returns the various RLE counts
 static WEBP_INLINE void GetEntropyUnrefinedHelper(
-    uint32_t val, int i, uint32_t* const val_prev, int* const i_prev,
-    VP8LBitEntropy* const bit_entropy, VP8LStreaks* const stats) {
+    uint32_t val, int i, uint32_t* WEBP_RESTRICT const val_prev,
+    int* WEBP_RESTRICT const i_prev,
+    VP8LBitEntropy* WEBP_RESTRICT const bit_entropy,
+    VP8LStreaks* WEBP_RESTRICT const stats) {
   int* const pstreaks = &stats->streaks[0][0];
   int* const pcnts = &stats->counts[0];
   int temp0, temp1, temp2, temp3;
@@ -227,7 +230,7 @@ static WEBP_INLINE void GetEntropyUnrefinedHelper(
     bit_entropy->sum += (*val_prev) * streak;
     bit_entropy->nonzeros += streak;
     bit_entropy->nonzero_code = *i_prev;
-    bit_entropy->entropy -= VP8LFastSLog2(*val_prev) * streak;
+    bit_entropy->entropy += VP8LFastSLog2(*val_prev) * streak;
     if (bit_entropy->max_val < *val_prev) {
       bit_entropy->max_val = *val_prev;
     }
@@ -241,9 +244,10 @@ static WEBP_INLINE void GetEntropyUnrefinedHelper(
   *i_prev = i;
 }
 
-static void GetEntropyUnrefined_MIPS32(const uint32_t X[], int length,
-                                       VP8LBitEntropy* const bit_entropy,
-                                       VP8LStreaks* const stats) {
+static void GetEntropyUnrefined_MIPS32(
+    const uint32_t X[], int length,
+    VP8LBitEntropy* WEBP_RESTRICT const bit_entropy,
+    VP8LStreaks* WEBP_RESTRICT const stats) {
   int i;
   int i_prev = 0;
   uint32_t x_prev = X[0];
@@ -259,14 +263,13 @@ static void GetEntropyUnrefined_MIPS32(const uint32_t X[], int length,
   }
   GetEntropyUnrefinedHelper(0, i, &x_prev, &i_prev, bit_entropy, stats);
 
-  bit_entropy->entropy += VP8LFastSLog2(bit_entropy->sum);
+  bit_entropy->entropy = VP8LFastSLog2(bit_entropy->sum) - bit_entropy->entropy;
 }
 
-static void GetCombinedEntropyUnrefined_MIPS32(const uint32_t X[],
-                                               const uint32_t Y[],
-                                               int length,
-                                               VP8LBitEntropy* const entropy,
-                                               VP8LStreaks* const stats) {
+static void GetCombinedEntropyUnrefined_MIPS32(
+    const uint32_t X[], const uint32_t Y[], int length,
+    VP8LBitEntropy* WEBP_RESTRICT const entropy,
+    VP8LStreaks* WEBP_RESTRICT const stats) {
   int i = 1;
   int i_prev = 0;
   uint32_t xy_prev = X[0] + Y[0];
@@ -282,7 +285,7 @@ static void GetCombinedEntropyUnrefined_MIPS32(const uint32_t X[],
   }
   GetEntropyUnrefinedHelper(0, i, &xy_prev, &i_prev, entropy, stats);
 
-  entropy->entropy += VP8LFastSLog2(entropy->sum);
+  entropy->entropy = VP8LFastSLog2(entropy->sum) - entropy->entropy;
 }
 
 #define ASM_START                                       \
@@ -344,8 +347,9 @@ static void GetCombinedEntropyUnrefined_MIPS32(const uint32_t X[],
     ASM_END_COMMON_0                                    \
     ASM_END_COMMON_1
 
-static void AddVector_MIPS32(const uint32_t* pa, const uint32_t* pb,
-                             uint32_t* pout, int size) {
+static void AddVector_MIPS32(const uint32_t* WEBP_RESTRICT pa,
+                             const uint32_t* WEBP_RESTRICT pb,
+                             uint32_t* WEBP_RESTRICT pout, int size) {
   uint32_t temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;
   const int end = ((size) / 4) * 4;
   const uint32_t* const LoopEnd = pa + end;
@@ -356,7 +360,8 @@ static void AddVector_MIPS32(const uint32_t* pa, const uint32_t* pb,
   for (i = 0; i < size - end; ++i) pout[i] = pa[i] + pb[i];
 }
 
-static void AddVectorEq_MIPS32(const uint32_t* pa, uint32_t* pout, int size) {
+static void AddVectorEq_MIPS32(const uint32_t* WEBP_RESTRICT pa,
+                               uint32_t* WEBP_RESTRICT pout, int size) {
   uint32_t temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;
   const int end = ((size) / 4) * 4;
   const uint32_t* const LoopEnd = pa + end;
diff --git a/src/dsp/lossless_enc_mips_dsp_r2.c b/src/dsp/lossless_enc_mips_dsp_r2.c
index 5855e6ae..e10b8f7e 100644
--- a/src/dsp/lossless_enc_mips_dsp_r2.c
+++ b/src/dsp/lossless_enc_mips_dsp_r2.c
@@ -78,8 +78,9 @@ static WEBP_INLINE uint32_t ColorTransformDelta(int8_t color_pred,
   return (uint32_t)((int)(color_pred) * color) >> 5;
 }
 
-static void TransformColor_MIPSdspR2(const VP8LMultipliers* const m,
-                                     uint32_t* data, int num_pixels) {
+static void TransformColor_MIPSdspR2(
+    const VP8LMultipliers* WEBP_RESTRICT const m, uint32_t* WEBP_RESTRICT data,
+    int num_pixels) {
   int temp0, temp1, temp2, temp3, temp4, temp5;
   uint32_t argb, argb1, new_red, new_red1;
   const uint32_t G_to_R = m->green_to_red_;
@@ -171,13 +172,10 @@ static WEBP_INLINE uint8_t TransformColorBlue(uint8_t green_to_blue,
   return (new_blue & 0xff);
 }
 
-static void CollectColorBlueTransforms_MIPSdspR2(const uint32_t* argb,
-                                                 int stride,
-                                                 int tile_width,
-                                                 int tile_height,
-                                                 int green_to_blue,
-                                                 int red_to_blue,
-                                                 int histo[]) {
+static void CollectColorBlueTransforms_MIPSdspR2(
+    const uint32_t* WEBP_RESTRICT argb, int stride,
+    int tile_width, int tile_height,
+    int green_to_blue, int red_to_blue, uint32_t histo[]) {
   const int rtb = (red_to_blue << 16) | (red_to_blue & 0xffff);
   const int gtb = (green_to_blue << 16) | (green_to_blue & 0xffff);
   const uint32_t mask = 0xff00ffu;
@@ -225,12 +223,9 @@ static WEBP_INLINE uint8_t TransformColorRed(uint8_t green_to_red,
   return (new_red & 0xff);
 }
 
-static void CollectColorRedTransforms_MIPSdspR2(const uint32_t* argb,
-                                                int stride,
-                                                int tile_width,
-                                                int tile_height,
-                                                int green_to_red,
-                                                int histo[]) {
+static void CollectColorRedTransforms_MIPSdspR2(
+    const uint32_t* WEBP_RESTRICT argb, int stride,
+    int tile_width, int tile_height, int green_to_red, uint32_t histo[]) {
   const int gtr = (green_to_red << 16) | (green_to_red & 0xffff);
   while (tile_height-- > 0) {
     int x;
diff --git a/src/dsp/lossless_enc_msa.c b/src/dsp/lossless_enc_msa.c
index 600dddfb..6d835ab7 100644
--- a/src/dsp/lossless_enc_msa.c
+++ b/src/dsp/lossless_enc_msa.c
@@ -48,8 +48,8 @@
   dst = VSHF_UB(src, t0, mask1);                                \
 } while (0)
 
-static void TransformColor_MSA(const VP8LMultipliers* const m, uint32_t* data,
-                               int num_pixels) {
+static void TransformColor_MSA(const VP8LMultipliers* WEBP_RESTRICT const m,
+                               uint32_t* WEBP_RESTRICT data, int num_pixels) {
   v16u8 src0, dst0;
   const v16i8 g2br = (v16i8)__msa_fill_w(m->green_to_blue_ |
                                          (m->green_to_red_ << 16));
diff --git a/src/dsp/lossless_enc_neon.c b/src/dsp/lossless_enc_neon.c
index e32c7961..838204a7 100644
--- a/src/dsp/lossless_enc_neon.c
+++ b/src/dsp/lossless_enc_neon.c
@@ -72,8 +72,9 @@ static void SubtractGreenFromBlueAndRed_NEON(uint32_t* argb_data,
 //------------------------------------------------------------------------------
 // Color Transform
 
-static void TransformColor_NEON(const VP8LMultipliers* const m,
-                                uint32_t* argb_data, int num_pixels) {
+static void TransformColor_NEON(const VP8LMultipliers* WEBP_RESTRICT const m,
+                                uint32_t* WEBP_RESTRICT argb_data,
+                                int num_pixels) {
   // sign-extended multiplying constants, pre-shifted by 6.
 #define CST(X)  (((int16_t)(m->X << 8)) >> 6)
   const int16_t rb[8] = {
diff --git a/src/dsp/lossless_enc_sse2.c b/src/dsp/lossless_enc_sse2.c
index 66cbaab7..b2fa6480 100644
--- a/src/dsp/lossless_enc_sse2.c
+++ b/src/dsp/lossless_enc_sse2.c
@@ -49,8 +49,9 @@ static void SubtractGreenFromBlueAndRed_SSE2(uint32_t* argb_data,
 #define MK_CST_16(HI, LO) \
   _mm_set1_epi32((int)(((uint32_t)(HI) << 16) | ((LO) & 0xffff)))
 
-static void TransformColor_SSE2(const VP8LMultipliers* const m,
-                                uint32_t* argb_data, int num_pixels) {
+static void TransformColor_SSE2(const VP8LMultipliers* WEBP_RESTRICT const m,
+                                uint32_t* WEBP_RESTRICT argb_data,
+                                int num_pixels) {
   const __m128i mults_rb = MK_CST_16(CST_5b(m->green_to_red_),
                                      CST_5b(m->green_to_blue_));
   const __m128i mults_b2 = MK_CST_16(CST_5b(m->red_to_blue_), 0);
@@ -79,10 +80,11 @@ static void TransformColor_SSE2(const VP8LMultipliers* const m,
 
 //------------------------------------------------------------------------------
 #define SPAN 8
-static void CollectColorBlueTransforms_SSE2(const uint32_t* argb, int stride,
+static void CollectColorBlueTransforms_SSE2(const uint32_t* WEBP_RESTRICT argb,
+                                            int stride,
                                             int tile_width, int tile_height,
                                             int green_to_blue, int red_to_blue,
-                                            int histo[]) {
+                                            uint32_t histo[]) {
   const __m128i mults_r = MK_CST_16(CST_5b(red_to_blue), 0);
   const __m128i mults_g = MK_CST_16(0, CST_5b(green_to_blue));
   const __m128i mask_g = _mm_set1_epi32(0x00ff00);  // green mask
@@ -126,9 +128,10 @@ static void CollectColorBlueTransforms_SSE2(const uint32_t* argb, int stride,
   }
 }
 
-static void CollectColorRedTransforms_SSE2(const uint32_t* argb, int stride,
+static void CollectColorRedTransforms_SSE2(const uint32_t* WEBP_RESTRICT argb,
+                                           int stride,
                                            int tile_width, int tile_height,
-                                           int green_to_red, int histo[]) {
+                                           int green_to_red, uint32_t histo[]) {
   const __m128i mults_g = MK_CST_16(0, CST_5b(green_to_red));
   const __m128i mask_g = _mm_set1_epi32(0x00ff00);  // green mask
   const __m128i mask = _mm_set1_epi32(0xff);
@@ -172,75 +175,113 @@ static void CollectColorRedTransforms_SSE2(const uint32_t* argb, int stride,
 
 // Note we are adding uint32_t's as *signed* int32's (using _mm_add_epi32). But
 // that's ok since the histogram values are less than 1<<28 (max picture size).
-#define LINE_SIZE 16    // 8 or 16
-static void AddVector_SSE2(const uint32_t* a, const uint32_t* b, uint32_t* out,
-                           int size) {
-  int i;
-  for (i = 0; i + LINE_SIZE <= size; i += LINE_SIZE) {
+static void AddVector_SSE2(const uint32_t* WEBP_RESTRICT a,
+                           const uint32_t* WEBP_RESTRICT b,
+                           uint32_t* WEBP_RESTRICT out, int size) {
+  int i = 0;
+  int aligned_size = size & ~15;
+  // Size is, at minimum, NUM_DISTANCE_CODES (40) and may be as large as
+  // NUM_LITERAL_CODES (256) + NUM_LENGTH_CODES (24) + (0 or a non-zero power of
+  // 2). See the usage in VP8LHistogramAdd().
+  assert(size >= 16);
+  assert(size % 2 == 0);
+
+  do {
     const __m128i a0 = _mm_loadu_si128((const __m128i*)&a[i +  0]);
     const __m128i a1 = _mm_loadu_si128((const __m128i*)&a[i +  4]);
-#if (LINE_SIZE == 16)
     const __m128i a2 = _mm_loadu_si128((const __m128i*)&a[i +  8]);
     const __m128i a3 = _mm_loadu_si128((const __m128i*)&a[i + 12]);
-#endif
     const __m128i b0 = _mm_loadu_si128((const __m128i*)&b[i +  0]);
     const __m128i b1 = _mm_loadu_si128((const __m128i*)&b[i +  4]);
-#if (LINE_SIZE == 16)
     const __m128i b2 = _mm_loadu_si128((const __m128i*)&b[i +  8]);
     const __m128i b3 = _mm_loadu_si128((const __m128i*)&b[i + 12]);
-#endif
     _mm_storeu_si128((__m128i*)&out[i +  0], _mm_add_epi32(a0, b0));
     _mm_storeu_si128((__m128i*)&out[i +  4], _mm_add_epi32(a1, b1));
-#if (LINE_SIZE == 16)
     _mm_storeu_si128((__m128i*)&out[i +  8], _mm_add_epi32(a2, b2));
     _mm_storeu_si128((__m128i*)&out[i + 12], _mm_add_epi32(a3, b3));
-#endif
+    i += 16;
+  } while (i != aligned_size);
+
+  if ((size & 8) != 0) {
+    const __m128i a0 = _mm_loadu_si128((const __m128i*)&a[i + 0]);
+    const __m128i a1 = _mm_loadu_si128((const __m128i*)&a[i + 4]);
+    const __m128i b0 = _mm_loadu_si128((const __m128i*)&b[i + 0]);
+    const __m128i b1 = _mm_loadu_si128((const __m128i*)&b[i + 4]);
+    _mm_storeu_si128((__m128i*)&out[i + 0], _mm_add_epi32(a0, b0));
+    _mm_storeu_si128((__m128i*)&out[i + 4], _mm_add_epi32(a1, b1));
+    i += 8;
   }
-  for (; i < size; ++i) {
-    out[i] = a[i] + b[i];
+
+  size &= 7;
+  if (size == 4) {
+    const __m128i a0 = _mm_loadu_si128((const __m128i*)&a[i]);
+    const __m128i b0 = _mm_loadu_si128((const __m128i*)&b[i]);
+    _mm_storeu_si128((__m128i*)&out[i], _mm_add_epi32(a0, b0));
+  } else if (size == 2) {
+    const __m128i a0 = _mm_loadl_epi64((const __m128i*)&a[i]);
+    const __m128i b0 = _mm_loadl_epi64((const __m128i*)&b[i]);
+    _mm_storel_epi64((__m128i*)&out[i], _mm_add_epi32(a0, b0));
   }
 }
 
-static void AddVectorEq_SSE2(const uint32_t* a, uint32_t* out, int size) {
-  int i;
-  for (i = 0; i + LINE_SIZE <= size; i += LINE_SIZE) {
+static void AddVectorEq_SSE2(const uint32_t* WEBP_RESTRICT a,
+                             uint32_t* WEBP_RESTRICT out, int size) {
+  int i = 0;
+  int aligned_size = size & ~15;
+  // Size is, at minimum, NUM_DISTANCE_CODES (40) and may be as large as
+  // NUM_LITERAL_CODES (256) + NUM_LENGTH_CODES (24) + (0 or a non-zero power of
+  // 2). See the usage in VP8LHistogramAdd().
+  assert(size >= 16);
+  assert(size % 2 == 0);
+
+  do {
     const __m128i a0 = _mm_loadu_si128((const __m128i*)&a[i +  0]);
     const __m128i a1 = _mm_loadu_si128((const __m128i*)&a[i +  4]);
-#if (LINE_SIZE == 16)
     const __m128i a2 = _mm_loadu_si128((const __m128i*)&a[i +  8]);
     const __m128i a3 = _mm_loadu_si128((const __m128i*)&a[i + 12]);
-#endif
     const __m128i b0 = _mm_loadu_si128((const __m128i*)&out[i +  0]);
     const __m128i b1 = _mm_loadu_si128((const __m128i*)&out[i +  4]);
-#if (LINE_SIZE == 16)
     const __m128i b2 = _mm_loadu_si128((const __m128i*)&out[i +  8]);
     const __m128i b3 = _mm_loadu_si128((const __m128i*)&out[i + 12]);
-#endif
     _mm_storeu_si128((__m128i*)&out[i +  0], _mm_add_epi32(a0, b0));
     _mm_storeu_si128((__m128i*)&out[i +  4], _mm_add_epi32(a1, b1));
-#if (LINE_SIZE == 16)
     _mm_storeu_si128((__m128i*)&out[i +  8], _mm_add_epi32(a2, b2));
     _mm_storeu_si128((__m128i*)&out[i + 12], _mm_add_epi32(a3, b3));
-#endif
+    i += 16;
+  } while (i != aligned_size);
+
+  if ((size & 8) != 0) {
+    const __m128i a0 = _mm_loadu_si128((const __m128i*)&a[i + 0]);
+    const __m128i a1 = _mm_loadu_si128((const __m128i*)&a[i + 4]);
+    const __m128i b0 = _mm_loadu_si128((const __m128i*)&out[i + 0]);
+    const __m128i b1 = _mm_loadu_si128((const __m128i*)&out[i + 4]);
+    _mm_storeu_si128((__m128i*)&out[i + 0], _mm_add_epi32(a0, b0));
+    _mm_storeu_si128((__m128i*)&out[i + 4], _mm_add_epi32(a1, b1));
+    i += 8;
   }
-  for (; i < size; ++i) {
-    out[i] += a[i];
+
+  size &= 7;
+  if (size == 4) {
+    const __m128i a0 = _mm_loadu_si128((const __m128i*)&a[i]);
+    const __m128i b0 = _mm_loadu_si128((const __m128i*)&out[i]);
+    _mm_storeu_si128((__m128i*)&out[i], _mm_add_epi32(a0, b0));
+  } else if (size == 2) {
+    const __m128i a0 = _mm_loadl_epi64((const __m128i*)&a[i]);
+    const __m128i b0 = _mm_loadl_epi64((const __m128i*)&out[i]);
+    _mm_storel_epi64((__m128i*)&out[i], _mm_add_epi32(a0, b0));
   }
 }
-#undef LINE_SIZE
 
 //------------------------------------------------------------------------------
 // Entropy
 
-// TODO(https://crbug.com/webp/499): this function produces different results
-// from the C code due to use of double/float resulting in output differences
-// when compared to -noasm.
-#if !(defined(WEBP_HAVE_SLOW_CLZ_CTZ) || defined(__i386__) || defined(_M_IX86))
+#if !defined(WEBP_HAVE_SLOW_CLZ_CTZ)
 
-static float CombinedShannonEntropy_SSE2(const int X[256], const int Y[256]) {
+static uint64_t CombinedShannonEntropy_SSE2(const uint32_t X[256],
+                                            const uint32_t Y[256]) {
   int i;
-  float retval = 0.f;
-  int sumX = 0, sumXY = 0;
+  uint64_t retval = 0;
+  uint32_t sumX = 0, sumXY = 0;
   const __m128i zero = _mm_setzero_si128();
 
   for (i = 0; i < 256; i += 16) {
@@ -260,19 +301,19 @@ static float CombinedShannonEntropy_SSE2(const int X[256], const int Y[256]) {
     int32_t my = _mm_movemask_epi8(_mm_cmpgt_epi8(y4, zero)) | mx;
     while (my) {
       const int32_t j = BitsCtz(my);
-      int xy;
+      uint32_t xy;
       if ((mx >> j) & 1) {
         const int x = X[i + j];
         sumXY += x;
-        retval -= VP8LFastSLog2(x);
+        retval += VP8LFastSLog2(x);
       }
       xy = X[i + j] + Y[i + j];
       sumX += xy;
-      retval -= VP8LFastSLog2(xy);
+      retval += VP8LFastSLog2(xy);
       my &= my - 1;
     }
   }
-  retval += VP8LFastSLog2(sumX) + VP8LFastSLog2(sumXY);
+  retval = VP8LFastSLog2(sumX) + VP8LFastSLog2(sumXY) - retval;
   return retval;
 }
 
@@ -335,8 +376,9 @@ static int VectorMismatch_SSE2(const uint32_t* const array1,
 }
 
 // Bundles multiple (1, 2, 4 or 8) pixels into a single pixel.
-static void BundleColorMap_SSE2(const uint8_t* const row, int width, int xbits,
-                                uint32_t* dst) {
+static void BundleColorMap_SSE2(const uint8_t* WEBP_RESTRICT const row,
+                                int width, int xbits,
+                                uint32_t* WEBP_RESTRICT dst) {
   int x;
   assert(xbits >= 0);
   assert(xbits <= 3);
@@ -425,7 +467,7 @@ static WEBP_INLINE void Average2_m128i(const __m128i* const a0,
 
 // Predictor0: ARGB_BLACK.
 static void PredictorSub0_SSE2(const uint32_t* in, const uint32_t* upper,
-                               int num_pixels, uint32_t* out) {
+                               int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   const __m128i black = _mm_set1_epi32((int)ARGB_BLACK);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -442,7 +484,8 @@ static void PredictorSub0_SSE2(const uint32_t* in, const uint32_t* upper,
 #define GENERATE_PREDICTOR_1(X, IN)                                         \
   static void PredictorSub##X##_SSE2(const uint32_t* const in,              \
                                      const uint32_t* const upper,           \
-                                     int num_pixels, uint32_t* const out) { \
+                                     int num_pixels,                        \
+                                     uint32_t* WEBP_RESTRICT const out) {   \
     int i;                                                                  \
     for (i = 0; i + 4 <= num_pixels; i += 4) {                              \
       const __m128i src = _mm_loadu_si128((const __m128i*)&in[i]);          \
@@ -464,7 +507,7 @@ GENERATE_PREDICTOR_1(4, upper[i - 1])    // Predictor4: TL
 
 // Predictor5: avg2(avg2(L, TR), T)
 static void PredictorSub5_SSE2(const uint32_t* in, const uint32_t* upper,
-                               int num_pixels, uint32_t* out) {
+                               int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   for (i = 0; i + 4 <= num_pixels; i += 4) {
     const __m128i L = _mm_loadu_si128((const __m128i*)&in[i - 1]);
@@ -484,7 +527,8 @@ static void PredictorSub5_SSE2(const uint32_t* in, const uint32_t* upper,
 
 #define GENERATE_PREDICTOR_2(X, A, B)                                         \
 static void PredictorSub##X##_SSE2(const uint32_t* in, const uint32_t* upper, \
-                                   int num_pixels, uint32_t* out) {           \
+                                   int num_pixels,                            \
+                                   uint32_t* WEBP_RESTRICT out) {             \
   int i;                                                                      \
   for (i = 0; i + 4 <= num_pixels; i += 4) {                                  \
     const __m128i tA = _mm_loadu_si128((const __m128i*)&(A));                 \
@@ -508,7 +552,7 @@ GENERATE_PREDICTOR_2(9, upper[i], upper[i + 1])    // Predictor9: average(T, TR)
 
 // Predictor10: avg(avg(L,TL), avg(T, TR)).
 static void PredictorSub10_SSE2(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   for (i = 0; i + 4 <= num_pixels; i += 4) {
     const __m128i L = _mm_loadu_si128((const __m128i*)&in[i - 1]);
@@ -543,7 +587,7 @@ static void GetSumAbsDiff32_SSE2(const __m128i* const A, const __m128i* const B,
 }
 
 static void PredictorSub11_SSE2(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   for (i = 0; i + 4 <= num_pixels; i += 4) {
     const __m128i L = _mm_loadu_si128((const __m128i*)&in[i - 1]);
@@ -569,7 +613,7 @@ static void PredictorSub11_SSE2(const uint32_t* in, const uint32_t* upper,
 
 // Predictor12: ClampedSubSubtractFull.
 static void PredictorSub12_SSE2(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   const __m128i zero = _mm_setzero_si128();
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -598,7 +642,7 @@ static void PredictorSub12_SSE2(const uint32_t* in, const uint32_t* upper,
 
 // Predictors13: ClampedAddSubtractHalf
 static void PredictorSub13_SSE2(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   const __m128i zero = _mm_setzero_si128();
   for (i = 0; i + 2 <= num_pixels; i += 2) {
diff --git a/src/dsp/lossless_enc_sse41.c b/src/dsp/lossless_enc_sse41.c
index 7ab83c26..87ed056f 100644
--- a/src/dsp/lossless_enc_sse41.c
+++ b/src/dsp/lossless_enc_sse41.c
@@ -44,8 +44,9 @@ static uint32_t ExtraCost_SSE41(const uint32_t* const a, int length) {
   return HorizontalSum_SSE41(cost);
 }
 
-static uint32_t ExtraCostCombined_SSE41(const uint32_t* const a,
-                                        const uint32_t* const b, int length) {
+static uint32_t ExtraCostCombined_SSE41(const uint32_t* WEBP_RESTRICT const a,
+                                        const uint32_t* WEBP_RESTRICT const b,
+                                        int length) {
   int i;
   __m128i cost = _mm_add_epi32(_mm_set_epi32(2 * a[7], 2 * a[6], a[5], a[4]),
                                _mm_set_epi32(2 * b[7], 2 * b[6], b[5], b[4]));
@@ -95,10 +96,11 @@ static void SubtractGreenFromBlueAndRed_SSE41(uint32_t* argb_data,
 #define MK_CST_16(HI, LO) \
   _mm_set1_epi32((int)(((uint32_t)(HI) << 16) | ((LO) & 0xffff)))
 
-static void CollectColorBlueTransforms_SSE41(const uint32_t* argb, int stride,
+static void CollectColorBlueTransforms_SSE41(const uint32_t* WEBP_RESTRICT argb,
+                                             int stride,
                                              int tile_width, int tile_height,
                                              int green_to_blue, int red_to_blue,
-                                             int histo[]) {
+                                             uint32_t histo[]) {
   const __m128i mult =
       MK_CST_16(CST_5b(red_to_blue) + 256,CST_5b(green_to_blue));
   const __m128i perm =
@@ -141,10 +143,11 @@ static void CollectColorBlueTransforms_SSE41(const uint32_t* argb, int stride,
   }
 }
 
-static void CollectColorRedTransforms_SSE41(const uint32_t* argb, int stride,
+static void CollectColorRedTransforms_SSE41(const uint32_t* WEBP_RESTRICT argb,
+                                            int stride,
                                             int tile_width, int tile_height,
-                                            int green_to_red, int histo[]) {
-
+                                            int green_to_red,
+                                            uint32_t histo[]) {
   const __m128i mult = MK_CST_16(0, CST_5b(green_to_red));
   const __m128i mask_g = _mm_set1_epi32(0x0000ff00);
   if (tile_width >= 4) {
diff --git a/src/dsp/lossless_neon.c b/src/dsp/lossless_neon.c
index e9960db3..93f41cef 100644
--- a/src/dsp/lossless_neon.c
+++ b/src/dsp/lossless_neon.c
@@ -26,8 +26,8 @@
 #if !defined(WORK_AROUND_GCC)
 // gcc 4.6.0 had some trouble (NDK-r9) with this code. We only use it for
 // gcc-4.8.x at least.
-static void ConvertBGRAToRGBA_NEON(const uint32_t* src,
-                                   int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToRGBA_NEON(const uint32_t* WEBP_RESTRICT src,
+                                   int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const end = src + (num_pixels & ~15);
   for (; src < end; src += 16) {
     uint8x16x4_t pixel = vld4q_u8((uint8_t*)src);
@@ -41,8 +41,8 @@ static void ConvertBGRAToRGBA_NEON(const uint32_t* src,
   VP8LConvertBGRAToRGBA_C(src, num_pixels & 15, dst);  // left-overs
 }
 
-static void ConvertBGRAToBGR_NEON(const uint32_t* src,
-                                  int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToBGR_NEON(const uint32_t* WEBP_RESTRICT src,
+                                  int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const end = src + (num_pixels & ~15);
   for (; src < end; src += 16) {
     const uint8x16x4_t pixel = vld4q_u8((uint8_t*)src);
@@ -53,8 +53,8 @@ static void ConvertBGRAToBGR_NEON(const uint32_t* src,
   VP8LConvertBGRAToBGR_C(src, num_pixels & 15, dst);  // left-overs
 }
 
-static void ConvertBGRAToRGB_NEON(const uint32_t* src,
-                                  int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToRGB_NEON(const uint32_t* WEBP_RESTRICT src,
+                                  int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const end = src + (num_pixels & ~15);
   for (; src < end; src += 16) {
     const uint8x16x4_t pixel = vld4q_u8((uint8_t*)src);
@@ -71,8 +71,8 @@ static void ConvertBGRAToRGB_NEON(const uint32_t* src,
 
 static const uint8_t kRGBAShuffle[8] = { 2, 1, 0, 3, 6, 5, 4, 7 };
 
-static void ConvertBGRAToRGBA_NEON(const uint32_t* src,
-                                   int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToRGBA_NEON(const uint32_t* WEBP_RESTRICT src,
+                                   int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const end = src + (num_pixels & ~1);
   const uint8x8_t shuffle = vld1_u8(kRGBAShuffle);
   for (; src < end; src += 2) {
@@ -89,8 +89,8 @@ static const uint8_t kBGRShuffle[3][8] = {
   { 21, 22, 24, 25, 26, 28, 29, 30 }
 };
 
-static void ConvertBGRAToBGR_NEON(const uint32_t* src,
-                                  int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToBGR_NEON(const uint32_t* WEBP_RESTRICT src,
+                                  int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const end = src + (num_pixels & ~7);
   const uint8x8_t shuffle0 = vld1_u8(kBGRShuffle[0]);
   const uint8x8_t shuffle1 = vld1_u8(kBGRShuffle[1]);
@@ -116,8 +116,8 @@ static const uint8_t kRGBShuffle[3][8] = {
   { 21, 20, 26, 25, 24, 30, 29, 28 }
 };
 
-static void ConvertBGRAToRGB_NEON(const uint32_t* src,
-                                  int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToRGB_NEON(const uint32_t* WEBP_RESTRICT src,
+                                  int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const uint32_t* const end = src + (num_pixels & ~7);
   const uint8x8_t shuffle0 = vld1_u8(kRGBShuffle[0]);
   const uint8x8_t shuffle1 = vld1_u8(kRGBShuffle[1]);
@@ -209,7 +209,7 @@ static uint32_t Predictor13_NEON(const uint32_t* const left,
 
 // Predictor0: ARGB_BLACK.
 static void PredictorAdd0_NEON(const uint32_t* in, const uint32_t* upper,
-                               int num_pixels, uint32_t* out) {
+                               int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   const uint8x16_t black = vreinterpretq_u8_u32(vdupq_n_u32(ARGB_BLACK));
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -222,7 +222,7 @@ static void PredictorAdd0_NEON(const uint32_t* in, const uint32_t* upper,
 
 // Predictor1: left.
 static void PredictorAdd1_NEON(const uint32_t* in, const uint32_t* upper,
-                               int num_pixels, uint32_t* out) {
+                               int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   const uint8x16_t zero = LOADQ_U32_AS_U8(0);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -248,7 +248,7 @@ static void PredictorAdd1_NEON(const uint32_t* in, const uint32_t* upper,
 #define GENERATE_PREDICTOR_1(X, IN)                                       \
 static void PredictorAdd##X##_NEON(const uint32_t* in,                    \
                                    const uint32_t* upper, int num_pixels, \
-                                   uint32_t* out) {                       \
+                                   uint32_t* WEBP_RESTRICT out) {         \
   int i;                                                                  \
   for (i = 0; i + 4 <= num_pixels; i += 4) {                              \
     const uint8x16_t src = LOADQ_U32P_AS_U8(&in[i]);                      \
@@ -276,7 +276,7 @@ GENERATE_PREDICTOR_1(4, upper[i - 1])
 } while (0)
 
 static void PredictorAdd5_NEON(const uint32_t* in, const uint32_t* upper,
-                               int num_pixels, uint32_t* out) {
+                               int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   uint8x16_t L = LOADQ_U32_AS_U8(out[-1]);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -301,7 +301,7 @@ static void PredictorAdd5_NEON(const uint32_t* in, const uint32_t* upper,
 
 // Predictor6: average(left, TL)
 static void PredictorAdd6_NEON(const uint32_t* in, const uint32_t* upper,
-                               int num_pixels, uint32_t* out) {
+                               int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   uint8x16_t L = LOADQ_U32_AS_U8(out[-1]);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -317,7 +317,7 @@ static void PredictorAdd6_NEON(const uint32_t* in, const uint32_t* upper,
 
 // Predictor7: average(left, T)
 static void PredictorAdd7_NEON(const uint32_t* in, const uint32_t* upper,
-                               int num_pixels, uint32_t* out) {
+                               int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   uint8x16_t L = LOADQ_U32_AS_U8(out[-1]);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -335,7 +335,7 @@ static void PredictorAdd7_NEON(const uint32_t* in, const uint32_t* upper,
 #define GENERATE_PREDICTOR_2(X, IN)                                       \
 static void PredictorAdd##X##_NEON(const uint32_t* in,                    \
                                    const uint32_t* upper, int num_pixels, \
-                                   uint32_t* out) {                       \
+                                   uint32_t* WEBP_RESTRICT out) {         \
   int i;                                                                  \
   for (i = 0; i + 4 <= num_pixels; i += 4) {                              \
     const uint8x16_t src = LOADQ_U32P_AS_U8(&in[i]);                      \
@@ -363,7 +363,7 @@ GENERATE_PREDICTOR_2(9, upper[i + 1])
 } while (0)
 
 static void PredictorAdd10_NEON(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   uint8x16_t L = LOADQ_U32_AS_U8(out[-1]);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -394,7 +394,7 @@ static void PredictorAdd10_NEON(const uint32_t* in, const uint32_t* upper,
 } while (0)
 
 static void PredictorAdd11_NEON(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   uint8x16_t L = LOADQ_U32_AS_U8(out[-1]);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -427,7 +427,7 @@ static void PredictorAdd11_NEON(const uint32_t* in, const uint32_t* upper,
 } while (0)
 
 static void PredictorAdd12_NEON(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   uint16x8_t L = vmovl_u8(LOAD_U32_AS_U8(out[-1]));
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -468,7 +468,7 @@ static void PredictorAdd12_NEON(const uint32_t* in, const uint32_t* upper,
 } while (0)
 
 static void PredictorAdd13_NEON(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   uint8x16_t L = LOADQ_U32_AS_U8(out[-1]);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
diff --git a/src/dsp/lossless_sse2.c b/src/dsp/lossless_sse2.c
index 4b6a532c..5b68d1cf 100644
--- a/src/dsp/lossless_sse2.c
+++ b/src/dsp/lossless_sse2.c
@@ -186,7 +186,7 @@ static uint32_t Predictor13_SSE2(const uint32_t* const left,
 
 // Predictor0: ARGB_BLACK.
 static void PredictorAdd0_SSE2(const uint32_t* in, const uint32_t* upper,
-                               int num_pixels, uint32_t* out) {
+                               int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   const __m128i black = _mm_set1_epi32((int)ARGB_BLACK);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -202,7 +202,7 @@ static void PredictorAdd0_SSE2(const uint32_t* in, const uint32_t* upper,
 
 // Predictor1: left.
 static void PredictorAdd1_SSE2(const uint32_t* in, const uint32_t* upper,
-                               int num_pixels, uint32_t* out) {
+                               int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   __m128i prev = _mm_set1_epi32((int)out[-1]);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -230,7 +230,8 @@ static void PredictorAdd1_SSE2(const uint32_t* in, const uint32_t* upper,
 // per 8 bit channel.
 #define GENERATE_PREDICTOR_1(X, IN)                                           \
 static void PredictorAdd##X##_SSE2(const uint32_t* in, const uint32_t* upper, \
-                                  int num_pixels, uint32_t* out) {            \
+                                   int num_pixels,                            \
+                                   uint32_t* WEBP_RESTRICT out) {             \
   int i;                                                                      \
   for (i = 0; i + 4 <= num_pixels; i += 4) {                                  \
     const __m128i src = _mm_loadu_si128((const __m128i*)&in[i]);              \
@@ -259,7 +260,8 @@ GENERATE_PREDICTOR_ADD(Predictor7_SSE2, PredictorAdd7_SSE2)
 
 #define GENERATE_PREDICTOR_2(X, IN)                                           \
 static void PredictorAdd##X##_SSE2(const uint32_t* in, const uint32_t* upper, \
-                                   int num_pixels, uint32_t* out) {           \
+                                   int num_pixels,                            \
+                                   uint32_t* WEBP_RESTRICT out) {             \
   int i;                                                                      \
   for (i = 0; i + 4 <= num_pixels; i += 4) {                                  \
     const __m128i Tother = _mm_loadu_si128((const __m128i*)&(IN));            \
@@ -297,7 +299,7 @@ GENERATE_PREDICTOR_2(9, upper[i + 1])
 } while (0)
 
 static void PredictorAdd10_SSE2(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   __m128i L = _mm_cvtsi32_si128((int)out[-1]);
   for (i = 0; i + 4 <= num_pixels; i += 4) {
@@ -344,7 +346,7 @@ static void PredictorAdd10_SSE2(const uint32_t* in, const uint32_t* upper,
 } while (0)
 
 static void PredictorAdd11_SSE2(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   __m128i pa;
   __m128i L = _mm_cvtsi32_si128((int)out[-1]);
@@ -395,7 +397,7 @@ static void PredictorAdd11_SSE2(const uint32_t* in, const uint32_t* upper,
 } while (0)
 
 static void PredictorAdd12_SSE2(const uint32_t* in, const uint32_t* upper,
-                                int num_pixels, uint32_t* out) {
+                                int num_pixels, uint32_t* WEBP_RESTRICT out) {
   int i;
   const __m128i zero = _mm_setzero_si128();
   const __m128i L8 = _mm_cvtsi32_si128((int)out[-1]);
@@ -490,8 +492,8 @@ static void TransformColorInverse_SSE2(const VP8LMultipliers* const m,
 //------------------------------------------------------------------------------
 // Color-space conversion functions
 
-static void ConvertBGRAToRGB_SSE2(const uint32_t* src, int num_pixels,
-                                  uint8_t* dst) {
+static void ConvertBGRAToRGB_SSE2(const uint32_t* WEBP_RESTRICT src,
+                                  int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const __m128i* in = (const __m128i*)src;
   __m128i* out = (__m128i*)dst;
 
@@ -526,8 +528,8 @@ static void ConvertBGRAToRGB_SSE2(const uint32_t* src, int num_pixels,
   }
 }
 
-static void ConvertBGRAToRGBA_SSE2(const uint32_t* src,
-                                   int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToRGBA_SSE2(const uint32_t* WEBP_RESTRICT src,
+                                   int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const __m128i red_blue_mask = _mm_set1_epi32(0x00ff00ff);
   const __m128i* in = (const __m128i*)src;
   __m128i* out = (__m128i*)dst;
@@ -554,8 +556,9 @@ static void ConvertBGRAToRGBA_SSE2(const uint32_t* src,
   }
 }
 
-static void ConvertBGRAToRGBA4444_SSE2(const uint32_t* src,
-                                       int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToRGBA4444_SSE2(const uint32_t* WEBP_RESTRICT src,
+                                       int num_pixels,
+                                       uint8_t* WEBP_RESTRICT dst) {
   const __m128i mask_0x0f = _mm_set1_epi8(0x0f);
   const __m128i mask_0xf0 = _mm_set1_epi8((char)0xf0);
   const __m128i* in = (const __m128i*)src;
@@ -590,8 +593,9 @@ static void ConvertBGRAToRGBA4444_SSE2(const uint32_t* src,
   }
 }
 
-static void ConvertBGRAToRGB565_SSE2(const uint32_t* src,
-                                     int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToRGB565_SSE2(const uint32_t* WEBP_RESTRICT src,
+                                     int num_pixels,
+                                     uint8_t* WEBP_RESTRICT dst) {
   const __m128i mask_0xe0 = _mm_set1_epi8((char)0xe0);
   const __m128i mask_0xf8 = _mm_set1_epi8((char)0xf8);
   const __m128i mask_0x07 = _mm_set1_epi8(0x07);
@@ -631,8 +635,8 @@ static void ConvertBGRAToRGB565_SSE2(const uint32_t* src,
   }
 }
 
-static void ConvertBGRAToBGR_SSE2(const uint32_t* src,
-                                  int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToBGR_SSE2(const uint32_t* WEBP_RESTRICT src,
+                                  int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const __m128i mask_l = _mm_set_epi32(0, 0x00ffffff, 0, 0x00ffffff);
   const __m128i mask_h = _mm_set_epi32(0x00ffffff, 0, 0x00ffffff, 0);
   const __m128i* in = (const __m128i*)src;
diff --git a/src/dsp/lossless_sse41.c b/src/dsp/lossless_sse41.c
index bb7ce761..a2d19144 100644
--- a/src/dsp/lossless_sse41.c
+++ b/src/dsp/lossless_sse41.c
@@ -77,8 +77,8 @@ static void TransformColorInverse_SSE41(const VP8LMultipliers* const m,
   }                                                   \
 } while (0)
 
-static void ConvertBGRAToRGB_SSE41(const uint32_t* src, int num_pixels,
-                                   uint8_t* dst) {
+static void ConvertBGRAToRGB_SSE41(const uint32_t* WEBP_RESTRICT src,
+                                   int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const __m128i* in = (const __m128i*)src;
   __m128i* out = (__m128i*)dst;
   const __m128i perm0 = _mm_setr_epi8(2, 1, 0, 6, 5, 4, 10, 9,
@@ -95,8 +95,8 @@ static void ConvertBGRAToRGB_SSE41(const uint32_t* src, int num_pixels,
   }
 }
 
-static void ConvertBGRAToBGR_SSE41(const uint32_t* src,
-                                   int num_pixels, uint8_t* dst) {
+static void ConvertBGRAToBGR_SSE41(const uint32_t* WEBP_RESTRICT src,
+                                   int num_pixels, uint8_t* WEBP_RESTRICT dst) {
   const __m128i* in = (const __m128i*)src;
   __m128i* out = (__m128i*)dst;
   const __m128i perm0 = _mm_setr_epi8(0, 1, 2, 4, 5, 6, 8, 9, 10,
diff --git a/src/dsp/rescaler.c b/src/dsp/rescaler.c
index 325d8be1..a96ca669 100644
--- a/src/dsp/rescaler.c
+++ b/src/dsp/rescaler.c
@@ -26,8 +26,8 @@
 //------------------------------------------------------------------------------
 // Row import
 
-void WebPRescalerImportRowExpand_C(WebPRescaler* const wrk,
-                                   const uint8_t* src) {
+void WebPRescalerImportRowExpand_C(WebPRescaler* WEBP_RESTRICT const wrk,
+                                   const uint8_t* WEBP_RESTRICT src) {
   const int x_stride = wrk->num_channels;
   const int x_out_max = wrk->dst_width * wrk->num_channels;
   int channel;
@@ -59,8 +59,8 @@ void WebPRescalerImportRowExpand_C(WebPRescaler* const wrk,
   }
 }
 
-void WebPRescalerImportRowShrink_C(WebPRescaler* const wrk,
-                                   const uint8_t* src) {
+void WebPRescalerImportRowShrink_C(WebPRescaler* WEBP_RESTRICT const wrk,
+                                   const uint8_t* WEBP_RESTRICT src) {
   const int x_stride = wrk->num_channels;
   const int x_out_max = wrk->dst_width * wrk->num_channels;
   int channel;
@@ -158,7 +158,8 @@ void WebPRescalerExportRowShrink_C(WebPRescaler* const wrk) {
 //------------------------------------------------------------------------------
 // Main entry calls
 
-void WebPRescalerImportRow(WebPRescaler* const wrk, const uint8_t* src) {
+void WebPRescalerImportRow(WebPRescaler* WEBP_RESTRICT const wrk,
+                           const uint8_t* WEBP_RESTRICT src) {
   assert(!WebPRescalerInputDone(wrk));
   if (!wrk->x_expand) {
     WebPRescalerImportRowShrink(wrk, src);
diff --git a/src/dsp/rescaler_mips32.c b/src/dsp/rescaler_mips32.c
index 61f63c61..b5168caa 100644
--- a/src/dsp/rescaler_mips32.c
+++ b/src/dsp/rescaler_mips32.c
@@ -21,8 +21,8 @@
 //------------------------------------------------------------------------------
 // Row import
 
-static void ImportRowShrink_MIPS32(WebPRescaler* const wrk,
-                                   const uint8_t* src) {
+static void ImportRowShrink_MIPS32(WebPRescaler* WEBP_RESTRICT const wrk,
+                                   const uint8_t* WEBP_RESTRICT src) {
   const int x_stride = wrk->num_channels;
   const int x_out_max = wrk->dst_width * wrk->num_channels;
   const int fx_scale = wrk->fx_scale;
@@ -81,8 +81,8 @@ static void ImportRowShrink_MIPS32(WebPRescaler* const wrk,
   }
 }
 
-static void ImportRowExpand_MIPS32(WebPRescaler* const wrk,
-                                   const uint8_t* src) {
+static void ImportRowExpand_MIPS32(WebPRescaler* WEBP_RESTRICT const wrk,
+                                   const uint8_t* WEBP_RESTRICT src) {
   const int x_stride = wrk->num_channels;
   const int x_out_max = wrk->dst_width * wrk->num_channels;
   const int x_add = wrk->x_add;
diff --git a/src/dsp/rescaler_msa.c b/src/dsp/rescaler_msa.c
index 256dbdd4..954d0fdf 100644
--- a/src/dsp/rescaler_msa.c
+++ b/src/dsp/rescaler_msa.c
@@ -114,9 +114,9 @@
   dst = __msa_copy_s_w((v4i32)t0, 0);                             \
 } while (0)
 
-static WEBP_INLINE void ExportRowExpand_0(const uint32_t* frow, uint8_t* dst,
-                                          int length,
-                                          WebPRescaler* const wrk) {
+static WEBP_INLINE void ExportRowExpand_0(
+    const uint32_t* WEBP_RESTRICT frow, uint8_t* WEBP_RESTRICT dst, int length,
+    WebPRescaler* WEBP_RESTRICT const wrk) {
   const v4u32 scale = (v4u32)__msa_fill_w(wrk->fy_scale);
   const v4u32 shift = (v4u32)__msa_fill_w(WEBP_RESCALER_RFIX);
   const v4i32 zero = { 0 };
@@ -171,9 +171,10 @@ static WEBP_INLINE void ExportRowExpand_0(const uint32_t* frow, uint8_t* dst,
   }
 }
 
-static WEBP_INLINE void ExportRowExpand_1(const uint32_t* frow, uint32_t* irow,
-                                          uint8_t* dst, int length,
-                                          WebPRescaler* const wrk) {
+static WEBP_INLINE void ExportRowExpand_1(
+    const uint32_t* WEBP_RESTRICT frow, uint32_t* WEBP_RESTRICT irow,
+    uint8_t* WEBP_RESTRICT dst, int length,
+    WebPRescaler* WEBP_RESTRICT const wrk) {
   const uint32_t B = WEBP_RESCALER_FRAC(-wrk->y_accum, wrk->y_sub);
   const uint32_t A = (uint32_t)(WEBP_RESCALER_ONE - B);
   const v4i32 B1 = __msa_fill_w(B);
@@ -262,10 +263,10 @@ static void RescalerExportRowExpand_MIPSdspR2(WebPRescaler* const wrk) {
 }
 
 #if 0  // disabled for now. TODO(skal): make match the C-code
-static WEBP_INLINE void ExportRowShrink_0(const uint32_t* frow, uint32_t* irow,
-                                          uint8_t* dst, int length,
-                                          const uint32_t yscale,
-                                          WebPRescaler* const wrk) {
+static WEBP_INLINE void ExportRowShrink_0(
+    const uint32_t* WEBP_RESTRICT frow, uint32_t* WEBP_RESTRICT irow,
+    uint8_t* WEBP_RESTRICT dst, int length, const uint32_t yscale,
+    WebPRescaler* WEBP_RESTRICT const wrk) {
   const v4u32 y_scale = (v4u32)__msa_fill_w(yscale);
   const v4u32 fxyscale = (v4u32)__msa_fill_w(wrk->fxy_scale);
   const v4u32 shiftval = (v4u32)__msa_fill_w(WEBP_RESCALER_RFIX);
@@ -348,9 +349,9 @@ static WEBP_INLINE void ExportRowShrink_0(const uint32_t* frow, uint32_t* irow,
   }
 }
 
-static WEBP_INLINE void ExportRowShrink_1(uint32_t* irow, uint8_t* dst,
-                                          int length,
-                                          WebPRescaler* const wrk) {
+static WEBP_INLINE void ExportRowShrink_1(
+    uint32_t* WEBP_RESTRICT irow, uint8_t* WEBP_RESTRICT dst, int length,
+    WebPRescaler* WEBP_RESTRICT const wrk) {
   const v4u32 scale = (v4u32)__msa_fill_w(wrk->fxy_scale);
   const v4u32 shift = (v4u32)__msa_fill_w(WEBP_RESCALER_RFIX);
   const v4i32 zero = { 0 };
diff --git a/src/dsp/rescaler_neon.c b/src/dsp/rescaler_neon.c
index 957a92db..ab4ddc00 100644
--- a/src/dsp/rescaler_neon.c
+++ b/src/dsp/rescaler_neon.c
@@ -45,8 +45,8 @@
 #error "MULT_FIX/WEBP_RESCALER_RFIX need some more work"
 #endif
 
-static uint32x4_t Interpolate_NEON(const rescaler_t* const frow,
-                                   const rescaler_t* const irow,
+static uint32x4_t Interpolate_NEON(const rescaler_t* WEBP_RESTRICT const frow,
+                                   const rescaler_t* WEBP_RESTRICT const irow,
                                    uint32_t A, uint32_t B) {
   LOAD_32x4(frow, A0);
   LOAD_32x4(irow, B0);
diff --git a/src/dsp/rescaler_sse2.c b/src/dsp/rescaler_sse2.c
index 3f18e94e..e898e2ac 100644
--- a/src/dsp/rescaler_sse2.c
+++ b/src/dsp/rescaler_sse2.c
@@ -43,8 +43,8 @@ static void LoadEightPixels_SSE2(const uint8_t* const src, __m128i* out) {
   *out = _mm_unpacklo_epi8(A, zero);
 }
 
-static void RescalerImportRowExpand_SSE2(WebPRescaler* const wrk,
-                                         const uint8_t* src) {
+static void RescalerImportRowExpand_SSE2(WebPRescaler* WEBP_RESTRICT const wrk,
+                                         const uint8_t* WEBP_RESTRICT src) {
   rescaler_t* frow = wrk->frow;
   const rescaler_t* const frow_end = frow + wrk->dst_width * wrk->num_channels;
   const int x_add = wrk->x_add;
@@ -109,8 +109,8 @@ static void RescalerImportRowExpand_SSE2(WebPRescaler* const wrk,
   assert(accum == 0);
 }
 
-static void RescalerImportRowShrink_SSE2(WebPRescaler* const wrk,
-                                         const uint8_t* src) {
+static void RescalerImportRowShrink_SSE2(WebPRescaler* WEBP_RESTRICT const wrk,
+                                         const uint8_t* WEBP_RESTRICT src) {
   const int x_sub = wrk->x_sub;
   int accum = 0;
   const __m128i zero = _mm_setzero_si128();
@@ -168,12 +168,10 @@ static void RescalerImportRowShrink_SSE2(WebPRescaler* const wrk,
 // Row export
 
 // load *src as epi64, multiply by mult and store result in [out0 ... out3]
-static WEBP_INLINE void LoadDispatchAndMult_SSE2(const rescaler_t* const src,
-                                                 const __m128i* const mult,
-                                                 __m128i* const out0,
-                                                 __m128i* const out1,
-                                                 __m128i* const out2,
-                                                 __m128i* const out3) {
+static WEBP_INLINE void LoadDispatchAndMult_SSE2(
+    const rescaler_t* WEBP_RESTRICT const src, const __m128i* const mult,
+    __m128i* const out0, __m128i* const out1, __m128i* const out2,
+    __m128i* const out3) {
   const __m128i A0 = _mm_loadu_si128((const __m128i*)(src + 0));
   const __m128i A1 = _mm_loadu_si128((const __m128i*)(src + 4));
   const __m128i A2 = _mm_srli_epi64(A0, 32);
diff --git a/src/dsp/upsampling.c b/src/dsp/upsampling.c
index 983b9c42..5953fe48 100644
--- a/src/dsp/upsampling.c
+++ b/src/dsp/upsampling.c
@@ -35,10 +35,14 @@ WebPUpsampleLinePairFunc WebPUpsamplers[MODE_LAST];
 #define LOAD_UV(u, v) ((u) | ((v) << 16))
 
 #define UPSAMPLE_FUNC(FUNC_NAME, FUNC, XSTEP)                                  \
-static void FUNC_NAME(const uint8_t* top_y, const uint8_t* bottom_y,           \
-                      const uint8_t* top_u, const uint8_t* top_v,              \
-                      const uint8_t* cur_u, const uint8_t* cur_v,              \
-                      uint8_t* top_dst, uint8_t* bottom_dst, int len) {        \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT top_y,                      \
+                      const uint8_t* WEBP_RESTRICT bottom_y,                   \
+                      const uint8_t* WEBP_RESTRICT top_u,                      \
+                      const uint8_t* WEBP_RESTRICT top_v,                      \
+                      const uint8_t* WEBP_RESTRICT cur_u,                      \
+                      const uint8_t* WEBP_RESTRICT cur_v,                      \
+                      uint8_t* WEBP_RESTRICT top_dst,                          \
+                      uint8_t* WEBP_RESTRICT bottom_dst, int len) {            \
   int x;                                                                       \
   const int last_pixel_pair = (len - 1) >> 1;                                  \
   uint32_t tl_uv = LOAD_UV(top_u[0], top_v[0]);   /* top-left sample */        \
@@ -136,10 +140,14 @@ static void EmptyUpsampleFunc(const uint8_t* top_y, const uint8_t* bottom_y,
 
 #if !defined(FANCY_UPSAMPLING)
 #define DUAL_SAMPLE_FUNC(FUNC_NAME, FUNC)                                      \
-static void FUNC_NAME(const uint8_t* top_y, const uint8_t* bot_y,              \
-                      const uint8_t* top_u, const uint8_t* top_v,              \
-                      const uint8_t* bot_u, const uint8_t* bot_v,              \
-                      uint8_t* top_dst, uint8_t* bot_dst, int len) {           \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT top_y,                      \
+                      const uint8_t* WEBP_RESTRICT bot_y,                      \
+                      const uint8_t* WEBP_RESTRICT top_u,                      \
+                      const uint8_t* WEBP_RESTRICT top_v,                      \
+                      const uint8_t* WEBP_RESTRICT bot_u,                      \
+                      const uint8_t* WEBP_RESTRICT bot_v,                      \
+                      uint8_t* WEBP_RESTRICT top_dst,                          \
+                      uint8_t* WEBP_RESTRICT bot_dst, int len) {               \
   const int half_len = len >> 1;                                               \
   int x;                                                                       \
   assert(top_dst != NULL);                                                     \
@@ -178,10 +186,14 @@ WebPUpsampleLinePairFunc WebPGetLinePairConverter(int alpha_is_last) {
 // YUV444 converter
 
 #define YUV444_FUNC(FUNC_NAME, FUNC, XSTEP)                                    \
-extern void FUNC_NAME(const uint8_t* y, const uint8_t* u, const uint8_t* v,    \
-                      uint8_t* dst, int len);                                  \
-void FUNC_NAME(const uint8_t* y, const uint8_t* u, const uint8_t* v,           \
-               uint8_t* dst, int len) {                                        \
+extern void FUNC_NAME(const uint8_t* WEBP_RESTRICT y,                          \
+                      const uint8_t* WEBP_RESTRICT u,                          \
+                      const uint8_t* WEBP_RESTRICT v,                          \
+                      uint8_t* WEBP_RESTRICT dst, int len);                    \
+void FUNC_NAME(const uint8_t* WEBP_RESTRICT y,                                 \
+               const uint8_t* WEBP_RESTRICT u,                                 \
+               const uint8_t* WEBP_RESTRICT v,                                 \
+               uint8_t* WEBP_RESTRICT dst, int len) {                          \
   int i;                                                                       \
   for (i = 0; i < len; ++i) FUNC(y[i], u[i], v[i], &dst[i * (XSTEP)]);         \
 }
diff --git a/src/dsp/upsampling_mips_dsp_r2.c b/src/dsp/upsampling_mips_dsp_r2.c
index 10d499d7..cbe8e71d 100644
--- a/src/dsp/upsampling_mips_dsp_r2.c
+++ b/src/dsp/upsampling_mips_dsp_r2.c
@@ -143,10 +143,14 @@ static WEBP_INLINE void YuvToRgba(uint8_t y, uint8_t u, uint8_t v,
 #define LOAD_UV(u, v) ((u) | ((v) << 16))
 
 #define UPSAMPLE_FUNC(FUNC_NAME, FUNC, XSTEP)                                  \
-static void FUNC_NAME(const uint8_t* top_y, const uint8_t* bottom_y,           \
-                      const uint8_t* top_u, const uint8_t* top_v,              \
-                      const uint8_t* cur_u, const uint8_t* cur_v,              \
-                      uint8_t* top_dst, uint8_t* bottom_dst, int len) {        \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT top_y,                      \
+                      const uint8_t* WEBP_RESTRICT bottom_y,                   \
+                      const uint8_t* WEBP_RESTRICT top_u,                      \
+                      const uint8_t* WEBP_RESTRICT top_v,                      \
+                      const uint8_t* WEBP_RESTRICT cur_u,                      \
+                      const uint8_t* WEBP_RESTRICT cur_v,                      \
+                      uint8_t* WEBP_RESTRICT top_dst,                          \
+                      uint8_t* WEBP_RESTRICT bottom_dst, int len) {            \
   int x;                                                                       \
   const int last_pixel_pair = (len - 1) >> 1;                                  \
   uint32_t tl_uv = LOAD_UV(top_u[0], top_v[0]);   /* top-left sample */        \
@@ -241,8 +245,10 @@ WEBP_TSAN_IGNORE_FUNCTION void WebPInitUpsamplersMIPSdspR2(void) {
 // YUV444 converter
 
 #define YUV444_FUNC(FUNC_NAME, FUNC, XSTEP)                                    \
-static void FUNC_NAME(const uint8_t* y, const uint8_t* u, const uint8_t* v,    \
-                      uint8_t* dst, int len) {                                 \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT y,                          \
+                      const uint8_t* WEBP_RESTRICT u,                          \
+                      const uint8_t* WEBP_RESTRICT v,                          \
+                      uint8_t* WEBP_RESTRICT dst, int len) {                   \
   int i;                                                                       \
   for (i = 0; i < len; ++i) FUNC(y[i], u[i], v[i], &dst[i * XSTEP]);           \
 }
diff --git a/src/dsp/upsampling_msa.c b/src/dsp/upsampling_msa.c
index f2e03e85..72a526bc 100644
--- a/src/dsp/upsampling_msa.c
+++ b/src/dsp/upsampling_msa.c
@@ -320,8 +320,10 @@ static void YuvToRgba(uint8_t y, uint8_t u, uint8_t v, uint8_t* const rgba) {
 }
 
 #if !defined(WEBP_REDUCE_CSP)
-static void YuvToRgbLine(const uint8_t* y, const uint8_t* u,
-                         const uint8_t* v, uint8_t* dst, int length) {
+static void YuvToRgbLine(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst, int length) {
   v16u8 R, G, B;
   while (length >= 16) {
     CALC_RGB16(y, u, v, R, G, B);
@@ -347,8 +349,10 @@ static void YuvToRgbLine(const uint8_t* y, const uint8_t* u,
   }
 }
 
-static void YuvToBgrLine(const uint8_t* y, const uint8_t* u,
-                         const uint8_t* v, uint8_t* dst, int length) {
+static void YuvToBgrLine(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst, int length) {
   v16u8 R, G, B;
   while (length >= 16) {
     CALC_RGB16(y, u, v, R, G, B);
@@ -375,8 +379,10 @@ static void YuvToBgrLine(const uint8_t* y, const uint8_t* u,
 }
 #endif  // WEBP_REDUCE_CSP
 
-static void YuvToRgbaLine(const uint8_t* y, const uint8_t* u,
-                          const uint8_t* v, uint8_t* dst, int length) {
+static void YuvToRgbaLine(const uint8_t* WEBP_RESTRICT y,
+                          const uint8_t* WEBP_RESTRICT u,
+                          const uint8_t* WEBP_RESTRICT v,
+                          uint8_t* WEBP_RESTRICT dst, int length) {
   v16u8 R, G, B;
   const v16u8 A = (v16u8)__msa_ldi_b(ALPHAVAL);
   while (length >= 16) {
@@ -403,8 +409,10 @@ static void YuvToRgbaLine(const uint8_t* y, const uint8_t* u,
   }
 }
 
-static void YuvToBgraLine(const uint8_t* y, const uint8_t* u,
-                          const uint8_t* v, uint8_t* dst, int length) {
+static void YuvToBgraLine(const uint8_t* WEBP_RESTRICT y,
+                          const uint8_t* WEBP_RESTRICT u,
+                          const uint8_t* WEBP_RESTRICT v,
+                          uint8_t* WEBP_RESTRICT dst, int length) {
   v16u8 R, G, B;
   const v16u8 A = (v16u8)__msa_ldi_b(ALPHAVAL);
   while (length >= 16) {
@@ -432,8 +440,10 @@ static void YuvToBgraLine(const uint8_t* y, const uint8_t* u,
 }
 
 #if !defined(WEBP_REDUCE_CSP)
-static void YuvToArgbLine(const uint8_t* y, const uint8_t* u,
-                          const uint8_t* v, uint8_t* dst, int length) {
+static void YuvToArgbLine(const uint8_t* WEBP_RESTRICT y,
+                          const uint8_t* WEBP_RESTRICT u,
+                          const uint8_t* WEBP_RESTRICT v,
+                          uint8_t* WEBP_RESTRICT dst, int length) {
   v16u8 R, G, B;
   const v16u8 A = (v16u8)__msa_ldi_b(ALPHAVAL);
   while (length >= 16) {
@@ -460,8 +470,10 @@ static void YuvToArgbLine(const uint8_t* y, const uint8_t* u,
   }
 }
 
-static void YuvToRgba4444Line(const uint8_t* y, const uint8_t* u,
-                              const uint8_t* v, uint8_t* dst, int length) {
+static void YuvToRgba4444Line(const uint8_t* WEBP_RESTRICT y,
+                              const uint8_t* WEBP_RESTRICT u,
+                              const uint8_t* WEBP_RESTRICT v,
+                              uint8_t* WEBP_RESTRICT dst, int length) {
   v16u8 R, G, B, RG, BA, tmp0, tmp1;
   while (length >= 16) {
 #if (WEBP_SWAP_16BIT_CSP == 1)
@@ -496,8 +508,10 @@ static void YuvToRgba4444Line(const uint8_t* y, const uint8_t* u,
   }
 }
 
-static void YuvToRgb565Line(const uint8_t* y, const uint8_t* u,
-                            const uint8_t* v, uint8_t* dst, int length) {
+static void YuvToRgb565Line(const uint8_t* WEBP_RESTRICT y,
+                            const uint8_t* WEBP_RESTRICT u,
+                            const uint8_t* WEBP_RESTRICT v,
+                            uint8_t* WEBP_RESTRICT dst, int length) {
   v16u8 R, G, B, RG, GB, tmp0, tmp1;
   while (length >= 16) {
 #if (WEBP_SWAP_16BIT_CSP == 1)
@@ -564,11 +578,14 @@ static void YuvToRgb565Line(const uint8_t* y, const uint8_t* u,
 } while (0)
 
 #define UPSAMPLE_FUNC(FUNC_NAME, FUNC, XSTEP)                            \
-static void FUNC_NAME(const uint8_t* top_y, const uint8_t* bot_y,        \
-                      const uint8_t* top_u, const uint8_t* top_v,        \
-                      const uint8_t* cur_u, const uint8_t* cur_v,        \
-                      uint8_t* top_dst, uint8_t* bot_dst, int len)       \
-{                                                                        \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT top_y,                \
+                      const uint8_t* WEBP_RESTRICT bot_y,                \
+                      const uint8_t* WEBP_RESTRICT top_u,                \
+                      const uint8_t* WEBP_RESTRICT top_v,                \
+                      const uint8_t* WEBP_RESTRICT cur_u,                \
+                      const uint8_t* WEBP_RESTRICT cur_v,                \
+                      uint8_t* WEBP_RESTRICT top_dst,                    \
+                      uint8_t* WEBP_RESTRICT bot_dst, int len) {         \
   int size = (len - 1) >> 1;                                             \
   uint8_t temp_u[64];                                                    \
   uint8_t temp_v[64];                                                    \
diff --git a/src/dsp/upsampling_neon.c b/src/dsp/upsampling_neon.c
index bbc000ca..2bd3e931 100644
--- a/src/dsp/upsampling_neon.c
+++ b/src/dsp/upsampling_neon.c
@@ -58,8 +58,9 @@
 } while (0)
 
 // Turn the macro into a function for reducing code-size when non-critical
-static void Upsample16Pixels_NEON(const uint8_t* r1, const uint8_t* r2,
-                                  uint8_t* out) {
+static void Upsample16Pixels_NEON(const uint8_t* WEBP_RESTRICT const r1,
+                                  const uint8_t* WEBP_RESTRICT const r2,
+                                  uint8_t* WEBP_RESTRICT const out) {
   UPSAMPLE_16PIXELS(r1, r2, out);
 }
 
@@ -189,57 +190,61 @@ static const int16_t kCoeffs1[4] = { 19077, 26149, 6419, 13320 };
   }                                                                     \
 }
 
-#define NEON_UPSAMPLE_FUNC(FUNC_NAME, FMT, XSTEP)                       \
-static void FUNC_NAME(const uint8_t* top_y, const uint8_t* bottom_y,    \
-                      const uint8_t* top_u, const uint8_t* top_v,       \
-                      const uint8_t* cur_u, const uint8_t* cur_v,       \
-                      uint8_t* top_dst, uint8_t* bottom_dst, int len) { \
-  int block;                                                            \
-  /* 16 byte aligned array to cache reconstructed u and v */            \
-  uint8_t uv_buf[2 * 32 + 15];                                          \
-  uint8_t* const r_uv = (uint8_t*)((uintptr_t)(uv_buf + 15) & ~15);     \
-  const int uv_len = (len + 1) >> 1;                                    \
-  /* 9 pixels must be read-able for each block */                       \
-  const int num_blocks = (uv_len - 1) >> 3;                             \
-  const int leftover = uv_len - num_blocks * 8;                         \
-  const int last_pos = 1 + 16 * num_blocks;                             \
-                                                                        \
-  const int u_diag = ((top_u[0] + cur_u[0]) >> 1) + 1;                  \
-  const int v_diag = ((top_v[0] + cur_v[0]) >> 1) + 1;                  \
-                                                                        \
-  const int16x4_t coeff1 = vld1_s16(kCoeffs1);                          \
-  const int16x8_t R_Rounder = vdupq_n_s16(-14234);                      \
-  const int16x8_t G_Rounder = vdupq_n_s16(8708);                        \
-  const int16x8_t B_Rounder = vdupq_n_s16(-17685);                      \
-                                                                        \
-  /* Treat the first pixel in regular way */                            \
-  assert(top_y != NULL);                                                \
-  {                                                                     \
-    const int u0 = (top_u[0] + u_diag) >> 1;                            \
-    const int v0 = (top_v[0] + v_diag) >> 1;                            \
-    VP8YuvTo ## FMT(top_y[0], u0, v0, top_dst);                         \
-  }                                                                     \
-  if (bottom_y != NULL) {                                               \
-    const int u0 = (cur_u[0] + u_diag) >> 1;                            \
-    const int v0 = (cur_v[0] + v_diag) >> 1;                            \
-    VP8YuvTo ## FMT(bottom_y[0], u0, v0, bottom_dst);                   \
-  }                                                                     \
-                                                                        \
-  for (block = 0; block < num_blocks; ++block) {                        \
-    UPSAMPLE_16PIXELS(top_u, cur_u, r_uv);                              \
-    UPSAMPLE_16PIXELS(top_v, cur_v, r_uv + 16);                         \
-    CONVERT2RGB_8(FMT, XSTEP, top_y, bottom_y, r_uv,                    \
-                  top_dst, bottom_dst, 16 * block + 1, 16);             \
-    top_u += 8;                                                         \
-    cur_u += 8;                                                         \
-    top_v += 8;                                                         \
-    cur_v += 8;                                                         \
-  }                                                                     \
-                                                                        \
-  UPSAMPLE_LAST_BLOCK(top_u, cur_u, leftover, r_uv);                    \
-  UPSAMPLE_LAST_BLOCK(top_v, cur_v, leftover, r_uv + 16);               \
-  CONVERT2RGB_1(VP8YuvTo ## FMT, XSTEP, top_y, bottom_y, r_uv,          \
-                top_dst, bottom_dst, last_pos, len - last_pos);         \
+#define NEON_UPSAMPLE_FUNC(FUNC_NAME, FMT, XSTEP)                              \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT top_y,                      \
+                      const uint8_t* WEBP_RESTRICT bottom_y,                   \
+                      const uint8_t* WEBP_RESTRICT top_u,                      \
+                      const uint8_t* WEBP_RESTRICT top_v,                      \
+                      const uint8_t* WEBP_RESTRICT cur_u,                      \
+                      const uint8_t* WEBP_RESTRICT cur_v,                      \
+                      uint8_t* WEBP_RESTRICT top_dst,                          \
+                      uint8_t* WEBP_RESTRICT bottom_dst, int len) {            \
+  int block;                                                                   \
+  /* 16 byte aligned array to cache reconstructed u and v */                   \
+  uint8_t uv_buf[2 * 32 + 15];                                                 \
+  uint8_t* const r_uv = (uint8_t*)((uintptr_t)(uv_buf + 15) & ~(uintptr_t)15); \
+  const int uv_len = (len + 1) >> 1;                                           \
+  /* 9 pixels must be read-able for each block */                              \
+  const int num_blocks = (uv_len - 1) >> 3;                                    \
+  const int leftover = uv_len - num_blocks * 8;                                \
+  const int last_pos = 1 + 16 * num_blocks;                                    \
+                                                                               \
+  const int u_diag = ((top_u[0] + cur_u[0]) >> 1) + 1;                         \
+  const int v_diag = ((top_v[0] + cur_v[0]) >> 1) + 1;                         \
+                                                                               \
+  const int16x4_t coeff1 = vld1_s16(kCoeffs1);                                 \
+  const int16x8_t R_Rounder = vdupq_n_s16(-14234);                             \
+  const int16x8_t G_Rounder = vdupq_n_s16(8708);                               \
+  const int16x8_t B_Rounder = vdupq_n_s16(-17685);                             \
+                                                                               \
+  /* Treat the first pixel in regular way */                                   \
+  assert(top_y != NULL);                                                       \
+  {                                                                            \
+    const int u0 = (top_u[0] + u_diag) >> 1;                                   \
+    const int v0 = (top_v[0] + v_diag) >> 1;                                   \
+    VP8YuvTo ## FMT(top_y[0], u0, v0, top_dst);                                \
+  }                                                                            \
+  if (bottom_y != NULL) {                                                      \
+    const int u0 = (cur_u[0] + u_diag) >> 1;                                   \
+    const int v0 = (cur_v[0] + v_diag) >> 1;                                   \
+    VP8YuvTo ## FMT(bottom_y[0], u0, v0, bottom_dst);                          \
+  }                                                                            \
+                                                                               \
+  for (block = 0; block < num_blocks; ++block) {                               \
+    UPSAMPLE_16PIXELS(top_u, cur_u, r_uv);                                     \
+    UPSAMPLE_16PIXELS(top_v, cur_v, r_uv + 16);                                \
+    CONVERT2RGB_8(FMT, XSTEP, top_y, bottom_y, r_uv,                           \
+                  top_dst, bottom_dst, 16 * block + 1, 16);                    \
+    top_u += 8;                                                                \
+    cur_u += 8;                                                                \
+    top_v += 8;                                                                \
+    cur_v += 8;                                                                \
+  }                                                                            \
+                                                                               \
+  UPSAMPLE_LAST_BLOCK(top_u, cur_u, leftover, r_uv);                           \
+  UPSAMPLE_LAST_BLOCK(top_v, cur_v, leftover, r_uv + 16);                      \
+  CONVERT2RGB_1(VP8YuvTo ## FMT, XSTEP, top_y, bottom_y, r_uv,                 \
+                top_dst, bottom_dst, last_pos, len - last_pos);                \
 }
 
 // NEON variants of the fancy upsampler.
diff --git a/src/dsp/upsampling_sse2.c b/src/dsp/upsampling_sse2.c
index 77b4f722..36226fb1 100644
--- a/src/dsp/upsampling_sse2.c
+++ b/src/dsp/upsampling_sse2.c
@@ -88,8 +88,9 @@
 } while (0)
 
 // Turn the macro into a function for reducing code-size when non-critical
-static void Upsample32Pixels_SSE2(const uint8_t r1[], const uint8_t r2[],
-                                  uint8_t* const out) {
+static void Upsample32Pixels_SSE2(const uint8_t* WEBP_RESTRICT const r1,
+                                  const uint8_t* WEBP_RESTRICT const r2,
+                                  uint8_t* WEBP_RESTRICT const out) {
   UPSAMPLE_32PIXELS(r1, r2, out);
 }
 
@@ -114,10 +115,14 @@ static void Upsample32Pixels_SSE2(const uint8_t r1[], const uint8_t r2[],
 } while (0)
 
 #define SSE2_UPSAMPLE_FUNC(FUNC_NAME, FUNC, XSTEP)                             \
-static void FUNC_NAME(const uint8_t* top_y, const uint8_t* bottom_y,           \
-                      const uint8_t* top_u, const uint8_t* top_v,              \
-                      const uint8_t* cur_u, const uint8_t* cur_v,              \
-                      uint8_t* top_dst, uint8_t* bottom_dst, int len) {        \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT top_y,                      \
+                      const uint8_t* WEBP_RESTRICT bottom_y,                   \
+                      const uint8_t* WEBP_RESTRICT top_u,                      \
+                      const uint8_t* WEBP_RESTRICT top_v,                      \
+                      const uint8_t* WEBP_RESTRICT cur_u,                      \
+                      const uint8_t* WEBP_RESTRICT cur_v,                      \
+                      uint8_t* WEBP_RESTRICT top_dst,                          \
+                      uint8_t* WEBP_RESTRICT bottom_dst, int len) {            \
   int uv_pos, pos;                                                             \
   /* 16byte-aligned array to cache reconstructed u and v */                    \
   uint8_t uv_buf[14 * 32 + 15] = { 0 };                                        \
@@ -215,10 +220,14 @@ extern WebPYUV444Converter WebPYUV444Converters[/* MODE_LAST */];
 extern void WebPInitYUV444ConvertersSSE2(void);
 
 #define YUV444_FUNC(FUNC_NAME, CALL, CALL_C, XSTEP)                            \
-extern void CALL_C(const uint8_t* y, const uint8_t* u, const uint8_t* v,       \
-                   uint8_t* dst, int len);                                     \
-static void FUNC_NAME(const uint8_t* y, const uint8_t* u, const uint8_t* v,    \
-                      uint8_t* dst, int len) {                                 \
+extern void CALL_C(const uint8_t* WEBP_RESTRICT y,                             \
+                   const uint8_t* WEBP_RESTRICT u,                             \
+                   const uint8_t* WEBP_RESTRICT v,                             \
+                   uint8_t* WEBP_RESTRICT dst, int len);                       \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT y,                          \
+                      const uint8_t* WEBP_RESTRICT u,                          \
+                      const uint8_t* WEBP_RESTRICT v,                          \
+                      uint8_t* WEBP_RESTRICT dst, int len) {                   \
   int i;                                                                       \
   const int max_len = len & ~31;                                               \
   for (i = 0; i < max_len; i += 32) {                                          \
diff --git a/src/dsp/upsampling_sse41.c b/src/dsp/upsampling_sse41.c
index e38c88d5..823633c4 100644
--- a/src/dsp/upsampling_sse41.c
+++ b/src/dsp/upsampling_sse41.c
@@ -90,8 +90,9 @@
 } while (0)
 
 // Turn the macro into a function for reducing code-size when non-critical
-static void Upsample32Pixels_SSE41(const uint8_t r1[], const uint8_t r2[],
-                                  uint8_t* const out) {
+static void Upsample32Pixels_SSE41(const uint8_t* WEBP_RESTRICT const r1,
+                                   const uint8_t* WEBP_RESTRICT const r2,
+                                   uint8_t* WEBP_RESTRICT const out) {
   UPSAMPLE_32PIXELS(r1, r2, out);
 }
 
@@ -116,14 +117,18 @@ static void Upsample32Pixels_SSE41(const uint8_t r1[], const uint8_t r2[],
 } while (0)
 
 #define SSE4_UPSAMPLE_FUNC(FUNC_NAME, FUNC, XSTEP)                             \
-static void FUNC_NAME(const uint8_t* top_y, const uint8_t* bottom_y,           \
-                      const uint8_t* top_u, const uint8_t* top_v,              \
-                      const uint8_t* cur_u, const uint8_t* cur_v,              \
-                      uint8_t* top_dst, uint8_t* bottom_dst, int len) {        \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT top_y,                      \
+                      const uint8_t* WEBP_RESTRICT bottom_y,                   \
+                      const uint8_t* WEBP_RESTRICT top_u,                      \
+                      const uint8_t* WEBP_RESTRICT top_v,                      \
+                      const uint8_t* WEBP_RESTRICT cur_u,                      \
+                      const uint8_t* WEBP_RESTRICT cur_v,                      \
+                      uint8_t* WEBP_RESTRICT top_dst,                          \
+                      uint8_t* WEBP_RESTRICT bottom_dst, int len) {            \
   int uv_pos, pos;                                                             \
   /* 16byte-aligned array to cache reconstructed u and v */                    \
   uint8_t uv_buf[14 * 32 + 15] = { 0 };                                        \
-  uint8_t* const r_u = (uint8_t*)((uintptr_t)(uv_buf + 15) & ~15);             \
+  uint8_t* const r_u = (uint8_t*)((uintptr_t)(uv_buf + 15) & ~(uintptr_t)15);  \
   uint8_t* const r_v = r_u + 32;                                               \
                                                                                \
   assert(top_y != NULL);                                                       \
@@ -202,10 +207,14 @@ extern WebPYUV444Converter WebPYUV444Converters[/* MODE_LAST */];
 extern void WebPInitYUV444ConvertersSSE41(void);
 
 #define YUV444_FUNC(FUNC_NAME, CALL, CALL_C, XSTEP)                            \
-extern void CALL_C(const uint8_t* y, const uint8_t* u, const uint8_t* v,       \
-                   uint8_t* dst, int len);                                     \
-static void FUNC_NAME(const uint8_t* y, const uint8_t* u, const uint8_t* v,    \
-                      uint8_t* dst, int len) {                                 \
+extern void CALL_C(const uint8_t* WEBP_RESTRICT y,                             \
+                   const uint8_t* WEBP_RESTRICT u,                             \
+                   const uint8_t* WEBP_RESTRICT v,                             \
+                   uint8_t* WEBP_RESTRICT dst, int len);                       \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT y,                          \
+                      const uint8_t* WEBP_RESTRICT u,                          \
+                      const uint8_t* WEBP_RESTRICT v,                          \
+                      uint8_t* WEBP_RESTRICT dst, int len) {                   \
   int i;                                                                       \
   const int max_len = len & ~31;                                               \
   for (i = 0; i < max_len; i += 32) {                                          \
diff --git a/src/dsp/yuv.c b/src/dsp/yuv.c
index 8a04b85d..c1320f28 100644
--- a/src/dsp/yuv.c
+++ b/src/dsp/yuv.c
@@ -20,9 +20,10 @@
 // Plain-C version
 
 #define ROW_FUNC(FUNC_NAME, FUNC, XSTEP)                                       \
-static void FUNC_NAME(const uint8_t* y,                                        \
-                      const uint8_t* u, const uint8_t* v,                      \
-                      uint8_t* dst, int len) {                                 \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT y,                          \
+                      const uint8_t* WEBP_RESTRICT u,                          \
+                      const uint8_t* WEBP_RESTRICT v,                          \
+                      uint8_t* WEBP_RESTRICT dst, int len) {                   \
   const uint8_t* const end = dst + (len & ~1) * (XSTEP);                       \
   while (dst != end) {                                                         \
     FUNC(y[0], u[0], v[0], dst);                                               \
@@ -49,9 +50,10 @@ ROW_FUNC(YuvToRgb565Row,   VP8YuvToRgb565, 2)
 #undef ROW_FUNC
 
 // Main call for processing a plane with a WebPSamplerRowFunc function:
-void WebPSamplerProcessPlane(const uint8_t* y, int y_stride,
-                             const uint8_t* u, const uint8_t* v, int uv_stride,
-                             uint8_t* dst, int dst_stride,
+void WebPSamplerProcessPlane(const uint8_t* WEBP_RESTRICT y, int y_stride,
+                             const uint8_t* WEBP_RESTRICT u,
+                             const uint8_t* WEBP_RESTRICT v, int uv_stride,
+                             uint8_t* WEBP_RESTRICT dst, int dst_stride,
                              int width, int height, WebPSamplerRowFunc func) {
   int j;
   for (j = 0; j < height; ++j) {
@@ -117,7 +119,8 @@ WEBP_DSP_INIT_FUNC(WebPInitSamplers) {
 //-----------------------------------------------------------------------------
 // ARGB -> YUV converters
 
-static void ConvertARGBToY_C(const uint32_t* argb, uint8_t* y, int width) {
+static void ConvertARGBToY_C(const uint32_t* WEBP_RESTRICT argb,
+                             uint8_t* WEBP_RESTRICT y, int width) {
   int i;
   for (i = 0; i < width; ++i) {
     const uint32_t p = argb[i];
@@ -126,7 +129,8 @@ static void ConvertARGBToY_C(const uint32_t* argb, uint8_t* y, int width) {
   }
 }
 
-void WebPConvertARGBToUV_C(const uint32_t* argb, uint8_t* u, uint8_t* v,
+void WebPConvertARGBToUV_C(const uint32_t* WEBP_RESTRICT argb,
+                           uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
                            int src_width, int do_store) {
   // No rounding. Last pixel is dealt with separately.
   const int uv_width = src_width >> 1;
@@ -169,22 +173,25 @@ void WebPConvertARGBToUV_C(const uint32_t* argb, uint8_t* u, uint8_t* v,
 
 //-----------------------------------------------------------------------------
 
-static void ConvertRGB24ToY_C(const uint8_t* rgb, uint8_t* y, int width) {
+static void ConvertRGB24ToY_C(const uint8_t* WEBP_RESTRICT rgb,
+                              uint8_t* WEBP_RESTRICT y, int width) {
   int i;
   for (i = 0; i < width; ++i, rgb += 3) {
     y[i] = VP8RGBToY(rgb[0], rgb[1], rgb[2], YUV_HALF);
   }
 }
 
-static void ConvertBGR24ToY_C(const uint8_t* bgr, uint8_t* y, int width) {
+static void ConvertBGR24ToY_C(const uint8_t* WEBP_RESTRICT bgr,
+                              uint8_t* WEBP_RESTRICT y, int width) {
   int i;
   for (i = 0; i < width; ++i, bgr += 3) {
     y[i] = VP8RGBToY(bgr[2], bgr[1], bgr[0], YUV_HALF);
   }
 }
 
-void WebPConvertRGBA32ToUV_C(const uint16_t* rgb,
-                             uint8_t* u, uint8_t* v, int width) {
+void WebPConvertRGBA32ToUV_C(const uint16_t* WEBP_RESTRICT rgb,
+                             uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
+                             int width) {
   int i;
   for (i = 0; i < width; i += 1, rgb += 4) {
     const int r = rgb[0], g = rgb[1], b = rgb[2];
@@ -195,13 +202,18 @@ void WebPConvertRGBA32ToUV_C(const uint16_t* rgb,
 
 //-----------------------------------------------------------------------------
 
-void (*WebPConvertRGB24ToY)(const uint8_t* rgb, uint8_t* y, int width);
-void (*WebPConvertBGR24ToY)(const uint8_t* bgr, uint8_t* y, int width);
-void (*WebPConvertRGBA32ToUV)(const uint16_t* rgb,
-                              uint8_t* u, uint8_t* v, int width);
+void (*WebPConvertRGB24ToY)(const uint8_t* WEBP_RESTRICT rgb,
+                            uint8_t* WEBP_RESTRICT y, int width);
+void (*WebPConvertBGR24ToY)(const uint8_t* WEBP_RESTRICT bgr,
+                            uint8_t* WEBP_RESTRICT y, int width);
+void (*WebPConvertRGBA32ToUV)(const uint16_t* WEBP_RESTRICT rgb,
+                              uint8_t* WEBP_RESTRICT u,
+                              uint8_t* WEBP_RESTRICT v, int width);
 
-void (*WebPConvertARGBToY)(const uint32_t* argb, uint8_t* y, int width);
-void (*WebPConvertARGBToUV)(const uint32_t* argb, uint8_t* u, uint8_t* v,
+void (*WebPConvertARGBToY)(const uint32_t* WEBP_RESTRICT argb,
+                           uint8_t* WEBP_RESTRICT y, int width);
+void (*WebPConvertARGBToUV)(const uint32_t* WEBP_RESTRICT argb,
+                            uint8_t* WEBP_RESTRICT u, uint8_t* WEBP_RESTRICT v,
                             int src_width, int do_store);
 
 extern void WebPInitConvertARGBToYUVSSE2(void);
diff --git a/src/dsp/yuv.h b/src/dsp/yuv.h
index 66a397d1..59b871ae 100644
--- a/src/dsp/yuv.h
+++ b/src/dsp/yuv.h
@@ -11,15 +11,15 @@
 //
 // The exact naming is Y'CbCr, following the ITU-R BT.601 standard.
 // More information at: https://en.wikipedia.org/wiki/YCbCr
-// Y = 0.2569 * R + 0.5044 * G + 0.0979 * B + 16
-// U = -0.1483 * R - 0.2911 * G + 0.4394 * B + 128
-// V = 0.4394 * R - 0.3679 * G - 0.0715 * B + 128
+// Y = 0.2568 * R + 0.5041 * G + 0.0979 * B + 16
+// U = -0.1482 * R - 0.2910 * G + 0.4392 * B + 128
+// V = 0.4392 * R - 0.3678 * G - 0.0714 * B + 128
 // We use 16bit fixed point operations for RGB->YUV conversion (YUV_FIX).
 //
 // For the Y'CbCr to RGB conversion, the BT.601 specification reads:
 //   R = 1.164 * (Y-16) + 1.596 * (V-128)
-//   G = 1.164 * (Y-16) - 0.813 * (V-128) - 0.391 * (U-128)
-//   B = 1.164 * (Y-16)                   + 2.018 * (U-128)
+//   G = 1.164 * (Y-16) - 0.813 * (V-128) - 0.392 * (U-128)
+//   B = 1.164 * (Y-16)                   + 2.017 * (U-128)
 // where Y is in the [16,235] range, and U/V in the [16,240] range.
 //
 // The fixed-point implementation used here is:
@@ -149,20 +149,34 @@ static WEBP_INLINE void VP8YuvToRgba(uint8_t y, uint8_t u, uint8_t v,
 #if defined(WEBP_USE_SSE2)
 
 // Process 32 pixels and store the result (16b, 24b or 32b per pixel) in *dst.
-void VP8YuvToRgba32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                         uint8_t* dst);
-void VP8YuvToRgb32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                        uint8_t* dst);
-void VP8YuvToBgra32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                         uint8_t* dst);
-void VP8YuvToBgr32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                        uint8_t* dst);
-void VP8YuvToArgb32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                         uint8_t* dst);
-void VP8YuvToRgba444432_SSE2(const uint8_t* y, const uint8_t* u,
-                             const uint8_t* v, uint8_t* dst);
-void VP8YuvToRgb56532_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                           uint8_t* dst);
+void VP8YuvToRgba32_SSE2(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst);
+void VP8YuvToRgb32_SSE2(const uint8_t* WEBP_RESTRICT y,
+                        const uint8_t* WEBP_RESTRICT u,
+                        const uint8_t* WEBP_RESTRICT v,
+                        uint8_t* WEBP_RESTRICT dst);
+void VP8YuvToBgra32_SSE2(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst);
+void VP8YuvToBgr32_SSE2(const uint8_t* WEBP_RESTRICT y,
+                        const uint8_t* WEBP_RESTRICT u,
+                        const uint8_t* WEBP_RESTRICT v,
+                        uint8_t* WEBP_RESTRICT dst);
+void VP8YuvToArgb32_SSE2(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst);
+void VP8YuvToRgba444432_SSE2(const uint8_t* WEBP_RESTRICT y,
+                             const uint8_t* WEBP_RESTRICT u,
+                             const uint8_t* WEBP_RESTRICT v,
+                             uint8_t* WEBP_RESTRICT dst);
+void VP8YuvToRgb56532_SSE2(const uint8_t* WEBP_RESTRICT y,
+                           const uint8_t* WEBP_RESTRICT u,
+                           const uint8_t* WEBP_RESTRICT v,
+                           uint8_t* WEBP_RESTRICT dst);
 
 #endif    // WEBP_USE_SSE2
 
@@ -172,10 +186,14 @@ void VP8YuvToRgb56532_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
 #if defined(WEBP_USE_SSE41)
 
 // Process 32 pixels and store the result (16b, 24b or 32b per pixel) in *dst.
-void VP8YuvToRgb32_SSE41(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                         uint8_t* dst);
-void VP8YuvToBgr32_SSE41(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                         uint8_t* dst);
+void VP8YuvToRgb32_SSE41(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst);
+void VP8YuvToBgr32_SSE41(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst);
 
 #endif    // WEBP_USE_SSE41
 
diff --git a/src/dsp/yuv_mips32.c b/src/dsp/yuv_mips32.c
index 9d0a8878..1f634858 100644
--- a/src/dsp/yuv_mips32.c
+++ b/src/dsp/yuv_mips32.c
@@ -22,9 +22,10 @@
 // simple point-sampling
 
 #define ROW_FUNC(FUNC_NAME, XSTEP, R, G, B, A)                                 \
-static void FUNC_NAME(const uint8_t* y,                                        \
-                      const uint8_t* u, const uint8_t* v,                      \
-                      uint8_t* dst, int len) {                                 \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT y,                          \
+                      const uint8_t* WEBP_RESTRICT u,                          \
+                      const uint8_t* WEBP_RESTRICT v,                          \
+                      uint8_t* WEBP_RESTRICT dst, int len) {                   \
   int i, r, g, b;                                                              \
   int temp0, temp1, temp2, temp3, temp4;                                       \
   for (i = 0; i < (len >> 1); i++) {                                           \
diff --git a/src/dsp/yuv_mips_dsp_r2.c b/src/dsp/yuv_mips_dsp_r2.c
index cc8afcc7..816340fe 100644
--- a/src/dsp/yuv_mips_dsp_r2.c
+++ b/src/dsp/yuv_mips_dsp_r2.c
@@ -69,9 +69,10 @@
   : "memory", "hi", "lo"                                                       \
 
 #define ROW_FUNC(FUNC_NAME, XSTEP, R, G, B, A)                                 \
-static void FUNC_NAME(const uint8_t* y,                                        \
-                      const uint8_t* u, const uint8_t* v,                      \
-                      uint8_t* dst, int len) {                                 \
+static void FUNC_NAME(const uint8_t* WEBP_RESTRICT y,                          \
+                      const uint8_t* WEBP_RESTRICT u,                          \
+                      const uint8_t* WEBP_RESTRICT v,                          \
+                      uint8_t* WEBP_RESTRICT dst, int len) {                   \
   int i;                                                                       \
   uint32_t temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;             \
   const int t_con_1 = 26149;                                                   \
diff --git a/src/dsp/yuv_neon.c b/src/dsp/yuv_neon.c
index ff77b009..b1b7c604 100644
--- a/src/dsp/yuv_neon.c
+++ b/src/dsp/yuv_neon.c
@@ -46,7 +46,8 @@ static uint8x8_t ConvertRGBToY_NEON(const uint8x8_t R,
   return vqmovn_u16(Y2);
 }
 
-static void ConvertRGB24ToY_NEON(const uint8_t* rgb, uint8_t* y, int width) {
+static void ConvertRGB24ToY_NEON(const uint8_t* WEBP_RESTRICT rgb,
+                                 uint8_t* WEBP_RESTRICT y, int width) {
   int i;
   for (i = 0; i + 8 <= width; i += 8, rgb += 3 * 8) {
     const uint8x8x3_t RGB = vld3_u8(rgb);
@@ -58,7 +59,8 @@ static void ConvertRGB24ToY_NEON(const uint8_t* rgb, uint8_t* y, int width) {
   }
 }
 
-static void ConvertBGR24ToY_NEON(const uint8_t* bgr, uint8_t* y, int width) {
+static void ConvertBGR24ToY_NEON(const uint8_t* WEBP_RESTRICT bgr,
+                                 uint8_t* WEBP_RESTRICT y, int width) {
   int i;
   for (i = 0; i + 8 <= width; i += 8, bgr += 3 * 8) {
     const uint8x8x3_t BGR = vld3_u8(bgr);
@@ -70,7 +72,8 @@ static void ConvertBGR24ToY_NEON(const uint8_t* bgr, uint8_t* y, int width) {
   }
 }
 
-static void ConvertARGBToY_NEON(const uint32_t* argb, uint8_t* y, int width) {
+static void ConvertARGBToY_NEON(const uint32_t* WEBP_RESTRICT argb,
+                                uint8_t* WEBP_RESTRICT y, int width) {
   int i;
   for (i = 0; i + 8 <= width; i += 8) {
     const uint8x8x4_t RGB = vld4_u8((const uint8_t*)&argb[i]);
@@ -114,8 +117,9 @@ static void ConvertARGBToY_NEON(const uint32_t* argb, uint8_t* y, int width) {
   MULTIPLY_16b(28800, -24116, -4684, 128 << SHIFT, V_DST);       \
 } while (0)
 
-static void ConvertRGBA32ToUV_NEON(const uint16_t* rgb,
-                                   uint8_t* u, uint8_t* v, int width) {
+static void ConvertRGBA32ToUV_NEON(const uint16_t* WEBP_RESTRICT rgb,
+                                   uint8_t* WEBP_RESTRICT u,
+                                   uint8_t* WEBP_RESTRICT v, int width) {
   int i;
   for (i = 0; i + 8 <= width; i += 8, rgb += 4 * 8) {
     const uint16x8x4_t RGB = vld4q_u16((const uint16_t*)rgb);
@@ -131,7 +135,9 @@ static void ConvertRGBA32ToUV_NEON(const uint16_t* rgb,
   }
 }
 
-static void ConvertARGBToUV_NEON(const uint32_t* argb, uint8_t* u, uint8_t* v,
+static void ConvertARGBToUV_NEON(const uint32_t* WEBP_RESTRICT argb,
+                                 uint8_t* WEBP_RESTRICT u,
+                                 uint8_t* WEBP_RESTRICT v,
                                  int src_width, int do_store) {
   int i;
   for (i = 0; i + 16 <= src_width; i += 16, u += 8, v += 8) {
diff --git a/src/dsp/yuv_sse2.c b/src/dsp/yuv_sse2.c
index 01a48f9a..a96b4522 100644
--- a/src/dsp/yuv_sse2.c
+++ b/src/dsp/yuv_sse2.c
@@ -82,9 +82,9 @@ static WEBP_INLINE __m128i Load_UV_HI_8_SSE2(const uint8_t* src) {
 }
 
 // Convert 32 samples of YUV444 to R/G/B
-static void YUV444ToRGB_SSE2(const uint8_t* const y,
-                             const uint8_t* const u,
-                             const uint8_t* const v,
+static void YUV444ToRGB_SSE2(const uint8_t* WEBP_RESTRICT const y,
+                             const uint8_t* WEBP_RESTRICT const u,
+                             const uint8_t* WEBP_RESTRICT const v,
                              __m128i* const R, __m128i* const G,
                              __m128i* const B) {
   const __m128i Y0 = Load_HI_16_SSE2(y), U0 = Load_HI_16_SSE2(u),
@@ -93,9 +93,9 @@ static void YUV444ToRGB_SSE2(const uint8_t* const y,
 }
 
 // Convert 32 samples of YUV420 to R/G/B
-static void YUV420ToRGB_SSE2(const uint8_t* const y,
-                             const uint8_t* const u,
-                             const uint8_t* const v,
+static void YUV420ToRGB_SSE2(const uint8_t* WEBP_RESTRICT const y,
+                             const uint8_t* WEBP_RESTRICT const u,
+                             const uint8_t* WEBP_RESTRICT const v,
                              __m128i* const R, __m128i* const G,
                              __m128i* const B) {
   const __m128i Y0 = Load_HI_16_SSE2(y), U0 = Load_UV_HI_8_SSE2(u),
@@ -108,7 +108,7 @@ static WEBP_INLINE void PackAndStore4_SSE2(const __m128i* const R,
                                            const __m128i* const G,
                                            const __m128i* const B,
                                            const __m128i* const A,
-                                           uint8_t* const dst) {
+                                           uint8_t* WEBP_RESTRICT const dst) {
   const __m128i rb = _mm_packus_epi16(*R, *B);
   const __m128i ga = _mm_packus_epi16(*G, *A);
   const __m128i rg = _mm_unpacklo_epi8(rb, ga);
@@ -120,11 +120,9 @@ static WEBP_INLINE void PackAndStore4_SSE2(const __m128i* const R,
 }
 
 // Pack R/G/B/A results into 16b output.
-static WEBP_INLINE void PackAndStore4444_SSE2(const __m128i* const R,
-                                              const __m128i* const G,
-                                              const __m128i* const B,
-                                              const __m128i* const A,
-                                              uint8_t* const dst) {
+static WEBP_INLINE void PackAndStore4444_SSE2(
+     const __m128i* const R, const __m128i* const G, const __m128i* const B,
+     const __m128i* const A, uint8_t* WEBP_RESTRICT const dst) {
 #if (WEBP_SWAP_16BIT_CSP == 0)
   const __m128i rg0 = _mm_packus_epi16(*R, *G);
   const __m128i ba0 = _mm_packus_epi16(*B, *A);
@@ -145,7 +143,7 @@ static WEBP_INLINE void PackAndStore4444_SSE2(const __m128i* const R,
 static WEBP_INLINE void PackAndStore565_SSE2(const __m128i* const R,
                                              const __m128i* const G,
                                              const __m128i* const B,
-                                             uint8_t* const dst) {
+                                             uint8_t* WEBP_RESTRICT const dst) {
   const __m128i r0 = _mm_packus_epi16(*R, *R);
   const __m128i g0 = _mm_packus_epi16(*G, *G);
   const __m128i b0 = _mm_packus_epi16(*B, *B);
@@ -170,7 +168,7 @@ static WEBP_INLINE void PackAndStore565_SSE2(const __m128i* const R,
 static WEBP_INLINE void PlanarTo24b_SSE2(__m128i* const in0, __m128i* const in1,
                                          __m128i* const in2, __m128i* const in3,
                                          __m128i* const in4, __m128i* const in5,
-                                         uint8_t* const rgb) {
+                                         uint8_t* WEBP_RESTRICT const rgb) {
   // The input is 6 registers of sixteen 8b but for the sake of explanation,
   // let's take 6 registers of four 8b values.
   // To pack, we will keep taking one every two 8b integer and move it
@@ -193,8 +191,10 @@ static WEBP_INLINE void PlanarTo24b_SSE2(__m128i* const in0, __m128i* const in1,
   _mm_storeu_si128((__m128i*)(rgb + 80), *in5);
 }
 
-void VP8YuvToRgba32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                         uint8_t* dst) {
+void VP8YuvToRgba32_SSE2(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst) {
   const __m128i kAlpha = _mm_set1_epi16(255);
   int n;
   for (n = 0; n < 32; n += 8, dst += 32) {
@@ -204,8 +204,10 @@ void VP8YuvToRgba32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
   }
 }
 
-void VP8YuvToBgra32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                         uint8_t* dst) {
+void VP8YuvToBgra32_SSE2(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst) {
   const __m128i kAlpha = _mm_set1_epi16(255);
   int n;
   for (n = 0; n < 32; n += 8, dst += 32) {
@@ -215,8 +217,10 @@ void VP8YuvToBgra32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
   }
 }
 
-void VP8YuvToArgb32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                         uint8_t* dst) {
+void VP8YuvToArgb32_SSE2(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst) {
   const __m128i kAlpha = _mm_set1_epi16(255);
   int n;
   for (n = 0; n < 32; n += 8, dst += 32) {
@@ -226,8 +230,10 @@ void VP8YuvToArgb32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
   }
 }
 
-void VP8YuvToRgba444432_SSE2(const uint8_t* y, const uint8_t* u,
-                             const uint8_t* v, uint8_t* dst) {
+void VP8YuvToRgba444432_SSE2(const uint8_t* WEBP_RESTRICT y,
+                             const uint8_t* WEBP_RESTRICT u,
+                             const uint8_t* WEBP_RESTRICT v,
+                             uint8_t* WEBP_RESTRICT dst) {
   const __m128i kAlpha = _mm_set1_epi16(255);
   int n;
   for (n = 0; n < 32; n += 8, dst += 16) {
@@ -237,8 +243,10 @@ void VP8YuvToRgba444432_SSE2(const uint8_t* y, const uint8_t* u,
   }
 }
 
-void VP8YuvToRgb56532_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                           uint8_t* dst) {
+void VP8YuvToRgb56532_SSE2(const uint8_t* WEBP_RESTRICT y,
+                           const uint8_t* WEBP_RESTRICT u,
+                           const uint8_t* WEBP_RESTRICT v,
+                           uint8_t* WEBP_RESTRICT dst) {
   int n;
   for (n = 0; n < 32; n += 8, dst += 16) {
     __m128i R, G, B;
@@ -247,8 +255,10 @@ void VP8YuvToRgb56532_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
   }
 }
 
-void VP8YuvToRgb32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                        uint8_t* dst) {
+void VP8YuvToRgb32_SSE2(const uint8_t* WEBP_RESTRICT y,
+                        const uint8_t* WEBP_RESTRICT u,
+                        const uint8_t* WEBP_RESTRICT v,
+                        uint8_t* WEBP_RESTRICT dst) {
   __m128i R0, R1, R2, R3, G0, G1, G2, G3, B0, B1, B2, B3;
   __m128i rgb0, rgb1, rgb2, rgb3, rgb4, rgb5;
 
@@ -269,8 +279,10 @@ void VP8YuvToRgb32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
   PlanarTo24b_SSE2(&rgb0, &rgb1, &rgb2, &rgb3, &rgb4, &rgb5, dst);
 }
 
-void VP8YuvToBgr32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                        uint8_t* dst) {
+void VP8YuvToBgr32_SSE2(const uint8_t* WEBP_RESTRICT y,
+                        const uint8_t* WEBP_RESTRICT u,
+                        const uint8_t* WEBP_RESTRICT v,
+                        uint8_t* WEBP_RESTRICT dst) {
   __m128i R0, R1, R2, R3, G0, G1, G2, G3, B0, B1, B2, B3;
   __m128i bgr0, bgr1, bgr2, bgr3, bgr4, bgr5;
 
@@ -294,9 +306,10 @@ void VP8YuvToBgr32_SSE2(const uint8_t* y, const uint8_t* u, const uint8_t* v,
 //-----------------------------------------------------------------------------
 // Arbitrary-length row conversion functions
 
-static void YuvToRgbaRow_SSE2(const uint8_t* y,
-                              const uint8_t* u, const uint8_t* v,
-                              uint8_t* dst, int len) {
+static void YuvToRgbaRow_SSE2(const uint8_t* WEBP_RESTRICT y,
+                              const uint8_t* WEBP_RESTRICT u,
+                              const uint8_t* WEBP_RESTRICT v,
+                              uint8_t* WEBP_RESTRICT dst, int len) {
   const __m128i kAlpha = _mm_set1_epi16(255);
   int n;
   for (n = 0; n + 8 <= len; n += 8, dst += 32) {
@@ -316,9 +329,10 @@ static void YuvToRgbaRow_SSE2(const uint8_t* y,
   }
 }
 
-static void YuvToBgraRow_SSE2(const uint8_t* y,
-                              const uint8_t* u, const uint8_t* v,
-                              uint8_t* dst, int len) {
+static void YuvToBgraRow_SSE2(const uint8_t* WEBP_RESTRICT y,
+                              const uint8_t* WEBP_RESTRICT u,
+                              const uint8_t* WEBP_RESTRICT v,
+                              uint8_t* WEBP_RESTRICT dst, int len) {
   const __m128i kAlpha = _mm_set1_epi16(255);
   int n;
   for (n = 0; n + 8 <= len; n += 8, dst += 32) {
@@ -338,9 +352,10 @@ static void YuvToBgraRow_SSE2(const uint8_t* y,
   }
 }
 
-static void YuvToArgbRow_SSE2(const uint8_t* y,
-                              const uint8_t* u, const uint8_t* v,
-                              uint8_t* dst, int len) {
+static void YuvToArgbRow_SSE2(const uint8_t* WEBP_RESTRICT y,
+                              const uint8_t* WEBP_RESTRICT u,
+                              const uint8_t* WEBP_RESTRICT v,
+                              uint8_t* WEBP_RESTRICT dst, int len) {
   const __m128i kAlpha = _mm_set1_epi16(255);
   int n;
   for (n = 0; n + 8 <= len; n += 8, dst += 32) {
@@ -360,9 +375,10 @@ static void YuvToArgbRow_SSE2(const uint8_t* y,
   }
 }
 
-static void YuvToRgbRow_SSE2(const uint8_t* y,
-                             const uint8_t* u, const uint8_t* v,
-                             uint8_t* dst, int len) {
+static void YuvToRgbRow_SSE2(const uint8_t* WEBP_RESTRICT y,
+                             const uint8_t* WEBP_RESTRICT u,
+                             const uint8_t* WEBP_RESTRICT v,
+                             uint8_t* WEBP_RESTRICT dst, int len) {
   int n;
   for (n = 0; n + 32 <= len; n += 32, dst += 32 * 3) {
     __m128i R0, R1, R2, R3, G0, G1, G2, G3, B0, B1, B2, B3;
@@ -397,9 +413,10 @@ static void YuvToRgbRow_SSE2(const uint8_t* y,
   }
 }
 
-static void YuvToBgrRow_SSE2(const uint8_t* y,
-                             const uint8_t* u, const uint8_t* v,
-                             uint8_t* dst, int len) {
+static void YuvToBgrRow_SSE2(const uint8_t* WEBP_RESTRICT y,
+                             const uint8_t* WEBP_RESTRICT u,
+                             const uint8_t* WEBP_RESTRICT v,
+                             uint8_t* WEBP_RESTRICT dst, int len) {
   int n;
   for (n = 0; n + 32 <= len; n += 32, dst += 32 * 3) {
     __m128i R0, R1, R2, R3, G0, G1, G2, G3, B0, B1, B2, B3;
@@ -471,7 +488,7 @@ static WEBP_INLINE void RGB24PackedToPlanarHelper_SSE2(
 // rrrr... rrrr... gggg... gggg... bbbb... bbbb....
 // Similar to PlanarTo24bHelper(), but in reverse order.
 static WEBP_INLINE void RGB24PackedToPlanar_SSE2(
-    const uint8_t* const rgb, __m128i* const out /*out[6]*/) {
+    const uint8_t* WEBP_RESTRICT const rgb, __m128i* const out /*out[6]*/) {
   __m128i tmp[6];
   tmp[0] = _mm_loadu_si128((const __m128i*)(rgb +  0));
   tmp[1] = _mm_loadu_si128((const __m128i*)(rgb + 16));
@@ -488,8 +505,8 @@ static WEBP_INLINE void RGB24PackedToPlanar_SSE2(
 }
 
 // Convert 8 packed ARGB to r[], g[], b[]
-static WEBP_INLINE void RGB32PackedToPlanar_SSE2(const uint32_t* const argb,
-                                                 __m128i* const rgb /*in[6]*/) {
+static WEBP_INLINE void RGB32PackedToPlanar_SSE2(
+    const uint32_t* WEBP_RESTRICT const argb, __m128i* const rgb /*in[6]*/) {
   const __m128i zero = _mm_setzero_si128();
   __m128i a0 = LOAD_16(argb + 0);
   __m128i a1 = LOAD_16(argb + 4);
@@ -562,7 +579,8 @@ static WEBP_INLINE void ConvertRGBToUV_SSE2(const __m128i* const R,
 #undef MK_CST_16
 #undef TRANSFORM
 
-static void ConvertRGB24ToY_SSE2(const uint8_t* rgb, uint8_t* y, int width) {
+static void ConvertRGB24ToY_SSE2(const uint8_t* WEBP_RESTRICT rgb,
+                                 uint8_t* WEBP_RESTRICT y, int width) {
   const int max_width = width & ~31;
   int i;
   for (i = 0; i < max_width; rgb += 3 * 16 * 2) {
@@ -596,7 +614,8 @@ static void ConvertRGB24ToY_SSE2(const uint8_t* rgb, uint8_t* y, int width) {
   }
 }
 
-static void ConvertBGR24ToY_SSE2(const uint8_t* bgr, uint8_t* y, int width) {
+static void ConvertBGR24ToY_SSE2(const uint8_t* WEBP_RESTRICT bgr,
+                                 uint8_t* WEBP_RESTRICT y, int width) {
   const int max_width = width & ~31;
   int i;
   for (i = 0; i < max_width; bgr += 3 * 16 * 2) {
@@ -630,7 +649,8 @@ static void ConvertBGR24ToY_SSE2(const uint8_t* bgr, uint8_t* y, int width) {
   }
 }
 
-static void ConvertARGBToY_SSE2(const uint32_t* argb, uint8_t* y, int width) {
+static void ConvertARGBToY_SSE2(const uint32_t* WEBP_RESTRICT argb,
+                                uint8_t* WEBP_RESTRICT y, int width) {
   const int max_width = width & ~15;
   int i;
   for (i = 0; i < max_width; i += 16) {
@@ -658,8 +678,9 @@ static void HorizontalAddPack_SSE2(const __m128i* const A,
   *out = _mm_packs_epi32(C, D);
 }
 
-static void ConvertARGBToUV_SSE2(const uint32_t* argb,
-                                 uint8_t* u, uint8_t* v,
+static void ConvertARGBToUV_SSE2(const uint32_t* WEBP_RESTRICT argb,
+                                 uint8_t* WEBP_RESTRICT u,
+                                 uint8_t* WEBP_RESTRICT v,
                                  int src_width, int do_store) {
   const int max_width = src_width & ~31;
   int i;
@@ -695,7 +716,7 @@ static void ConvertARGBToUV_SSE2(const uint32_t* argb,
 
 // Convert 16 packed ARGB 16b-values to r[], g[], b[]
 static WEBP_INLINE void RGBA32PackedToPlanar_16b_SSE2(
-    const uint16_t* const rgbx,
+    const uint16_t* WEBP_RESTRICT const rgbx,
     __m128i* const r, __m128i* const g, __m128i* const b) {
   const __m128i in0 = LOAD_16(rgbx +  0);  // r0 | g0 | b0 |x| r1 | g1 | b1 |x
   const __m128i in1 = LOAD_16(rgbx +  8);  // r2 | g2 | b2 |x| r3 | g3 | b3 |x
@@ -715,8 +736,9 @@ static WEBP_INLINE void RGBA32PackedToPlanar_16b_SSE2(
   *b = _mm_unpacklo_epi64(B1, B3);
 }
 
-static void ConvertRGBA32ToUV_SSE2(const uint16_t* rgb,
-                                   uint8_t* u, uint8_t* v, int width) {
+static void ConvertRGBA32ToUV_SSE2(const uint16_t* WEBP_RESTRICT rgb,
+                                   uint8_t* WEBP_RESTRICT u,
+                                   uint8_t* WEBP_RESTRICT v, int width) {
   const int max_width = width & ~15;
   const uint16_t* const last_rgb = rgb + 4 * max_width;
   while (rgb < last_rgb) {
diff --git a/src/dsp/yuv_sse41.c b/src/dsp/yuv_sse41.c
index f79b802e..071e4908 100644
--- a/src/dsp/yuv_sse41.c
+++ b/src/dsp/yuv_sse41.c
@@ -82,9 +82,9 @@ static WEBP_INLINE __m128i Load_UV_HI_8_SSE41(const uint8_t* src) {
 }
 
 // Convert 32 samples of YUV444 to R/G/B
-static void YUV444ToRGB_SSE41(const uint8_t* const y,
-                              const uint8_t* const u,
-                              const uint8_t* const v,
+static void YUV444ToRGB_SSE41(const uint8_t* WEBP_RESTRICT const y,
+                              const uint8_t* WEBP_RESTRICT const u,
+                              const uint8_t* WEBP_RESTRICT const v,
                               __m128i* const R, __m128i* const G,
                               __m128i* const B) {
   const __m128i Y0 = Load_HI_16_SSE41(y), U0 = Load_HI_16_SSE41(u),
@@ -93,9 +93,9 @@ static void YUV444ToRGB_SSE41(const uint8_t* const y,
 }
 
 // Convert 32 samples of YUV420 to R/G/B
-static void YUV420ToRGB_SSE41(const uint8_t* const y,
-                              const uint8_t* const u,
-                              const uint8_t* const v,
+static void YUV420ToRGB_SSE41(const uint8_t* WEBP_RESTRICT const y,
+                              const uint8_t* WEBP_RESTRICT const u,
+                              const uint8_t* WEBP_RESTRICT const v,
                               __m128i* const R, __m128i* const G,
                               __m128i* const B) {
   const __m128i Y0 = Load_HI_16_SSE41(y), U0 = Load_UV_HI_8_SSE41(u),
@@ -109,7 +109,7 @@ static void YUV420ToRGB_SSE41(const uint8_t* const y,
 static WEBP_INLINE void PlanarTo24b_SSE41(
     __m128i* const in0, __m128i* const in1, __m128i* const in2,
     __m128i* const in3, __m128i* const in4, __m128i* const in5,
-    uint8_t* const rgb) {
+    uint8_t* WEBP_RESTRICT const rgb) {
   // The input is 6 registers of sixteen 8b but for the sake of explanation,
   // let's take 6 registers of four 8b values.
   // To pack, we will keep taking one every two 8b integer and move it
@@ -132,8 +132,10 @@ static WEBP_INLINE void PlanarTo24b_SSE41(
   _mm_storeu_si128((__m128i*)(rgb + 80), *in5);
 }
 
-void VP8YuvToRgb32_SSE41(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                         uint8_t* dst) {
+void VP8YuvToRgb32_SSE41(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst) {
   __m128i R0, R1, R2, R3, G0, G1, G2, G3, B0, B1, B2, B3;
   __m128i rgb0, rgb1, rgb2, rgb3, rgb4, rgb5;
 
@@ -154,8 +156,10 @@ void VP8YuvToRgb32_SSE41(const uint8_t* y, const uint8_t* u, const uint8_t* v,
   PlanarTo24b_SSE41(&rgb0, &rgb1, &rgb2, &rgb3, &rgb4, &rgb5, dst);
 }
 
-void VP8YuvToBgr32_SSE41(const uint8_t* y, const uint8_t* u, const uint8_t* v,
-                         uint8_t* dst) {
+void VP8YuvToBgr32_SSE41(const uint8_t* WEBP_RESTRICT y,
+                         const uint8_t* WEBP_RESTRICT u,
+                         const uint8_t* WEBP_RESTRICT v,
+                         uint8_t* WEBP_RESTRICT dst) {
   __m128i R0, R1, R2, R3, G0, G1, G2, G3, B0, B1, B2, B3;
   __m128i bgr0, bgr1, bgr2, bgr3, bgr4, bgr5;
 
@@ -179,9 +183,10 @@ void VP8YuvToBgr32_SSE41(const uint8_t* y, const uint8_t* u, const uint8_t* v,
 //-----------------------------------------------------------------------------
 // Arbitrary-length row conversion functions
 
-static void YuvToRgbRow_SSE41(const uint8_t* y,
-                              const uint8_t* u, const uint8_t* v,
-                              uint8_t* dst, int len) {
+static void YuvToRgbRow_SSE41(const uint8_t* WEBP_RESTRICT y,
+                              const uint8_t* WEBP_RESTRICT u,
+                              const uint8_t* WEBP_RESTRICT v,
+                              uint8_t* WEBP_RESTRICT dst, int len) {
   int n;
   for (n = 0; n + 32 <= len; n += 32, dst += 32 * 3) {
     __m128i R0, R1, R2, R3, G0, G1, G2, G3, B0, B1, B2, B3;
@@ -216,9 +221,10 @@ static void YuvToRgbRow_SSE41(const uint8_t* y,
   }
 }
 
-static void YuvToBgrRow_SSE41(const uint8_t* y,
-                              const uint8_t* u, const uint8_t* v,
-                              uint8_t* dst, int len) {
+static void YuvToBgrRow_SSE41(const uint8_t* WEBP_RESTRICT y,
+                              const uint8_t* WEBP_RESTRICT u,
+                              const uint8_t* WEBP_RESTRICT v,
+                              uint8_t* WEBP_RESTRICT dst, int len) {
   int n;
   for (n = 0; n + 32 <= len; n += 32, dst += 32 * 3) {
     __m128i R0, R1, R2, R3, G0, G1, G2, G3, B0, B1, B2, B3;
@@ -290,7 +296,7 @@ WEBP_TSAN_IGNORE_FUNCTION void WebPInitSamplersSSE41(void) {
 // rrrr... rrrr... gggg... gggg... bbbb... bbbb....
 // Similar to PlanarTo24bHelper(), but in reverse order.
 static WEBP_INLINE void RGB24PackedToPlanar_SSE41(
-    const uint8_t* const rgb, __m128i* const out /*out[6]*/) {
+    const uint8_t* WEBP_RESTRICT const rgb, __m128i* const out /*out[6]*/) {
   const __m128i A0 = _mm_loadu_si128((const __m128i*)(rgb +  0));
   const __m128i A1 = _mm_loadu_si128((const __m128i*)(rgb + 16));
   const __m128i A2 = _mm_loadu_si128((const __m128i*)(rgb + 32));
@@ -334,7 +340,7 @@ static WEBP_INLINE void RGB24PackedToPlanar_SSE41(
 
 // Convert 8 packed ARGB to r[], g[], b[]
 static WEBP_INLINE void RGB32PackedToPlanar_SSE41(
-    const uint32_t* const argb, __m128i* const rgb /*in[6]*/) {
+    const uint32_t* WEBP_RESTRICT const argb, __m128i* const rgb /*in[6]*/) {
   const __m128i zero = _mm_setzero_si128();
   __m128i a0 = LOAD_16(argb + 0);
   __m128i a1 = LOAD_16(argb + 4);
@@ -407,7 +413,8 @@ static WEBP_INLINE void ConvertRGBToUV_SSE41(const __m128i* const R,
 #undef MK_CST_16
 #undef TRANSFORM
 
-static void ConvertRGB24ToY_SSE41(const uint8_t* rgb, uint8_t* y, int width) {
+static void ConvertRGB24ToY_SSE41(const uint8_t* WEBP_RESTRICT rgb,
+                                  uint8_t* WEBP_RESTRICT y, int width) {
   const int max_width = width & ~31;
   int i;
   for (i = 0; i < max_width; rgb += 3 * 16 * 2) {
@@ -441,7 +448,8 @@ static void ConvertRGB24ToY_SSE41(const uint8_t* rgb, uint8_t* y, int width) {
   }
 }
 
-static void ConvertBGR24ToY_SSE41(const uint8_t* bgr, uint8_t* y, int width) {
+static void ConvertBGR24ToY_SSE41(const uint8_t* WEBP_RESTRICT bgr,
+                                  uint8_t* WEBP_RESTRICT y, int width) {
   const int max_width = width & ~31;
   int i;
   for (i = 0; i < max_width; bgr += 3 * 16 * 2) {
@@ -475,7 +483,8 @@ static void ConvertBGR24ToY_SSE41(const uint8_t* bgr, uint8_t* y, int width) {
   }
 }
 
-static void ConvertARGBToY_SSE41(const uint32_t* argb, uint8_t* y, int width) {
+static void ConvertARGBToY_SSE41(const uint32_t* WEBP_RESTRICT argb,
+                                 uint8_t* WEBP_RESTRICT y, int width) {
   const int max_width = width & ~15;
   int i;
   for (i = 0; i < max_width; i += 16) {
@@ -503,8 +512,9 @@ static void HorizontalAddPack_SSE41(const __m128i* const A,
   *out = _mm_packs_epi32(C, D);
 }
 
-static void ConvertARGBToUV_SSE41(const uint32_t* argb,
-                                  uint8_t* u, uint8_t* v,
+static void ConvertARGBToUV_SSE41(const uint32_t* WEBP_RESTRICT argb,
+                                  uint8_t* WEBP_RESTRICT u,
+                                  uint8_t* WEBP_RESTRICT v,
                                   int src_width, int do_store) {
   const int max_width = src_width & ~31;
   int i;
@@ -540,7 +550,7 @@ static void ConvertARGBToUV_SSE41(const uint32_t* argb,
 
 // Convert 16 packed ARGB 16b-values to r[], g[], b[]
 static WEBP_INLINE void RGBA32PackedToPlanar_16b_SSE41(
-    const uint16_t* const rgbx,
+    const uint16_t* WEBP_RESTRICT const rgbx,
     __m128i* const r, __m128i* const g, __m128i* const b) {
   const __m128i in0 = LOAD_16(rgbx +  0);  // r0 | g0 | b0 |x| r1 | g1 | b1 |x
   const __m128i in1 = LOAD_16(rgbx +  8);  // r2 | g2 | b2 |x| r3 | g3 | b3 |x
@@ -570,8 +580,9 @@ static WEBP_INLINE void RGBA32PackedToPlanar_16b_SSE41(
   *b = _mm_unpackhi_epi64(B1, B3);
 }
 
-static void ConvertRGBA32ToUV_SSE41(const uint16_t* rgb,
-                                    uint8_t* u, uint8_t* v, int width) {
+static void ConvertRGBA32ToUV_SSE41(const uint16_t* WEBP_RESTRICT rgb,
+                                    uint8_t* WEBP_RESTRICT u,
+                                    uint8_t* WEBP_RESTRICT v, int width) {
   const int max_width = width & ~15;
   const uint16_t* const last_rgb = rgb + 4 * max_width;
   while (rgb < last_rgb) {
diff --git a/src/enc/alpha_enc.c b/src/enc/alpha_enc.c
index c11a261c..03570944 100644
--- a/src/enc/alpha_enc.c
+++ b/src/enc/alpha_enc.c
@@ -276,6 +276,7 @@ static int ApplyFiltersAndEncode(const uint8_t* alpha, int width, int height,
       stats->lossless_features = best.stats.lossless_features;
       stats->histogram_bits = best.stats.histogram_bits;
       stats->transform_bits = best.stats.transform_bits;
+      stats->cross_color_transform_bits = best.stats.cross_color_transform_bits;
       stats->cache_bits = best.stats.cache_bits;
       stats->palette_size = best.stats.palette_size;
       stats->lossless_size = best.stats.lossless_size;
diff --git a/src/enc/backward_references_cost_enc.c b/src/enc/backward_references_cost_enc.c
index 6968ef3c..e097b509 100644
--- a/src/enc/backward_references_cost_enc.c
+++ b/src/enc/backward_references_cost_enc.c
@@ -15,7 +15,7 @@
 //
 
 #include <assert.h>
-#include <float.h>
+#include <string.h>
 
 #include "src/dsp/lossless_common.h"
 #include "src/enc/backward_references_enc.h"
@@ -31,15 +31,15 @@ extern void VP8LBackwardRefsCursorAdd(VP8LBackwardRefs* const refs,
                                       const PixOrCopy v);
 
 typedef struct {
-  float alpha_[VALUES_IN_BYTE];
-  float red_[VALUES_IN_BYTE];
-  float blue_[VALUES_IN_BYTE];
-  float distance_[NUM_DISTANCE_CODES];
-  float* literal_;
+  uint32_t alpha_[VALUES_IN_BYTE];
+  uint32_t red_[VALUES_IN_BYTE];
+  uint32_t blue_[VALUES_IN_BYTE];
+  uint32_t distance_[NUM_DISTANCE_CODES];
+  uint32_t* literal_;
 } CostModel;
 
 static void ConvertPopulationCountTableToBitEstimates(
-    int num_symbols, const uint32_t population_counts[], float output[]) {
+    int num_symbols, const uint32_t population_counts[], uint32_t output[]) {
   uint32_t sum = 0;
   int nonzeros = 0;
   int i;
@@ -52,7 +52,7 @@ static void ConvertPopulationCountTableToBitEstimates(
   if (nonzeros <= 1) {
     memset(output, 0, num_symbols * sizeof(*output));
   } else {
-    const float logsum = VP8LFastLog2(sum);
+    const uint32_t logsum = VP8LFastLog2(sum);
     for (i = 0; i < num_symbols; ++i) {
       output[i] = logsum - VP8LFastLog2(population_counts[i]);
     }
@@ -93,47 +93,47 @@ static int CostModelBuild(CostModel* const m, int xsize, int cache_bits,
   return ok;
 }
 
-static WEBP_INLINE float GetLiteralCost(const CostModel* const m, uint32_t v) {
-  return m->alpha_[v >> 24] +
-         m->red_[(v >> 16) & 0xff] +
-         m->literal_[(v >> 8) & 0xff] +
-         m->blue_[v & 0xff];
+static WEBP_INLINE int64_t GetLiteralCost(const CostModel* const m,
+                                          uint32_t v) {
+  return (int64_t)m->alpha_[v >> 24] + m->red_[(v >> 16) & 0xff] +
+         m->literal_[(v >> 8) & 0xff] + m->blue_[v & 0xff];
 }
 
-static WEBP_INLINE float GetCacheCost(const CostModel* const m, uint32_t idx) {
+static WEBP_INLINE int64_t GetCacheCost(const CostModel* const m,
+                                        uint32_t idx) {
   const int literal_idx = VALUES_IN_BYTE + NUM_LENGTH_CODES + idx;
-  return m->literal_[literal_idx];
+  return (int64_t)m->literal_[literal_idx];
 }
 
-static WEBP_INLINE float GetLengthCost(const CostModel* const m,
-                                       uint32_t length) {
+static WEBP_INLINE int64_t GetLengthCost(const CostModel* const m,
+                                         uint32_t length) {
   int code, extra_bits;
   VP8LPrefixEncodeBits(length, &code, &extra_bits);
-  return m->literal_[VALUES_IN_BYTE + code] + extra_bits;
+  return (int64_t)m->literal_[VALUES_IN_BYTE + code] +
+         ((int64_t)extra_bits << LOG_2_PRECISION_BITS);
 }
 
-static WEBP_INLINE float GetDistanceCost(const CostModel* const m,
-                                         uint32_t distance) {
+static WEBP_INLINE int64_t GetDistanceCost(const CostModel* const m,
+                                           uint32_t distance) {
   int code, extra_bits;
   VP8LPrefixEncodeBits(distance, &code, &extra_bits);
-  return m->distance_[code] + extra_bits;
+  return (int64_t)m->distance_[code] +
+         ((int64_t)extra_bits << LOG_2_PRECISION_BITS);
 }
 
 static WEBP_INLINE void AddSingleLiteralWithCostModel(
     const uint32_t* const argb, VP8LColorCache* const hashers,
     const CostModel* const cost_model, int idx, int use_color_cache,
-    float prev_cost, float* const cost, uint16_t* const dist_array) {
-  float cost_val = prev_cost;
+    int64_t prev_cost, int64_t* const cost, uint16_t* const dist_array) {
+  int64_t cost_val = prev_cost;
   const uint32_t color = argb[idx];
   const int ix = use_color_cache ? VP8LColorCacheContains(hashers, color) : -1;
   if (ix >= 0) {
     // use_color_cache is true and hashers contains color
-    const float mul0 = 0.68f;
-    cost_val += GetCacheCost(cost_model, ix) * mul0;
+    cost_val += DivRound(GetCacheCost(cost_model, ix) * 68, 100);
   } else {
-    const float mul1 = 0.82f;
     if (use_color_cache) VP8LColorCacheInsert(hashers, color);
-    cost_val += GetLiteralCost(cost_model, color) * mul1;
+    cost_val += DivRound(GetLiteralCost(cost_model, color) * 82, 100);
   }
   if (cost[idx] > cost_val) {
     cost[idx] = cost_val;
@@ -163,7 +163,7 @@ static WEBP_INLINE void AddSingleLiteralWithCostModel(
 // therefore no overlapping intervals.
 typedef struct CostInterval CostInterval;
 struct CostInterval {
-  float cost_;
+  int64_t cost_;
   int start_;
   int end_;
   int index_;
@@ -173,7 +173,7 @@ struct CostInterval {
 
 // The GetLengthCost(cost_model, k) are cached in a CostCacheInterval.
 typedef struct {
-  float cost_;
+  int64_t cost_;
   int start_;
   int end_;       // Exclusive.
 } CostCacheInterval;
@@ -188,8 +188,9 @@ typedef struct {
   int count_;  // The number of stored intervals.
   CostCacheInterval* cache_intervals_;
   size_t cache_intervals_size_;
-  float cost_cache_[MAX_LENGTH];  // Contains the GetLengthCost(cost_model, k).
-  float* costs_;
+  // Contains the GetLengthCost(cost_model, k).
+  int64_t cost_cache_[MAX_LENGTH];
+  int64_t* costs_;
   uint16_t* dist_array_;
   // Most of the time, we only need few intervals -> use a free-list, to avoid
   // fragmentation with small allocs in most common cases.
@@ -298,7 +299,7 @@ static int CostManagerInit(CostManager* const manager,
     cur->end_ = 1;
     cur->cost_ = manager->cost_cache_[0];
     for (i = 1; i < cost_cache_size; ++i) {
-      const float cost_val = manager->cost_cache_[i];
+      const int64_t cost_val = manager->cost_cache_[i];
       if (cost_val != cur->cost_) {
         ++cur;
         // Initialize an interval.
@@ -311,13 +312,15 @@ static int CostManagerInit(CostManager* const manager,
            manager->cache_intervals_size_);
   }
 
-  manager->costs_ = (float*)WebPSafeMalloc(pix_count, sizeof(*manager->costs_));
+  manager->costs_ =
+      (int64_t*)WebPSafeMalloc(pix_count, sizeof(*manager->costs_));
   if (manager->costs_ == NULL) {
     CostManagerClear(manager);
     return 0;
   }
-  // Set the initial costs_ high for every pixel as we will keep the minimum.
-  for (i = 0; i < pix_count; ++i) manager->costs_[i] = FLT_MAX;
+  // Set the initial costs_ to INT64_MAX for every pixel as we will keep the
+  // minimum.
+  for (i = 0; i < pix_count; ++i) manager->costs_[i] = WEBP_INT64_MAX;
 
   return 1;
 }
@@ -325,7 +328,7 @@ static int CostManagerInit(CostManager* const manager,
 // Given the cost and the position that define an interval, update the cost at
 // pixel 'i' if it is smaller than the previously computed value.
 static WEBP_INLINE void UpdateCost(CostManager* const manager, int i,
-                                   int position, float cost) {
+                                   int position, int64_t cost) {
   const int k = i - position;
   assert(k >= 0 && k < MAX_LENGTH);
 
@@ -339,7 +342,7 @@ static WEBP_INLINE void UpdateCost(CostManager* const manager, int i,
 // all the pixels between 'start' and 'end' excluded.
 static WEBP_INLINE void UpdateCostPerInterval(CostManager* const manager,
                                               int start, int end, int position,
-                                              float cost) {
+                                              int64_t cost) {
   int i;
   for (i = start; i < end; ++i) UpdateCost(manager, i, position, cost);
 }
@@ -424,7 +427,7 @@ static WEBP_INLINE void PositionOrphanInterval(CostManager* const manager,
 // interval_in as a hint. The intervals are sorted by start_ value.
 static WEBP_INLINE void InsertInterval(CostManager* const manager,
                                        CostInterval* const interval_in,
-                                       float cost, int position, int start,
+                                       int64_t cost, int position, int start,
                                        int end) {
   CostInterval* interval_new;
 
@@ -463,7 +466,7 @@ static WEBP_INLINE void InsertInterval(CostManager* const manager,
 // If handling the interval or one of its subintervals becomes to heavy, its
 // contribution is added to the costs right away.
 static WEBP_INLINE void PushInterval(CostManager* const manager,
-                                     float distance_cost, int position,
+                                     int64_t distance_cost, int position,
                                      int len) {
   size_t i;
   CostInterval* interval = manager->head_;
@@ -478,7 +481,7 @@ static WEBP_INLINE void PushInterval(CostManager* const manager,
     int j;
     for (j = position; j < position + len; ++j) {
       const int k = j - position;
-      float cost_tmp;
+      int64_t cost_tmp;
       assert(k >= 0 && k < MAX_LENGTH);
       cost_tmp = distance_cost + manager->cost_cache_[k];
 
@@ -498,7 +501,7 @@ static WEBP_INLINE void PushInterval(CostManager* const manager,
     const int end = position + (cost_cache_intervals[i].end_ > len
                                  ? len
                                  : cost_cache_intervals[i].end_);
-    const float cost = distance_cost + cost_cache_intervals[i].cost_;
+    const int64_t cost = distance_cost + cost_cache_intervals[i].cost_;
 
     for (; interval != NULL && interval->start_ < end;
          interval = interval_next) {
@@ -576,7 +579,7 @@ static int BackwardReferencesHashChainDistanceOnly(
   const int pix_count = xsize * ysize;
   const int use_color_cache = (cache_bits > 0);
   const size_t literal_array_size =
-      sizeof(float) * (VP8LHistogramNumCodes(cache_bits));
+      sizeof(*((CostModel*)NULL)->literal_) * VP8LHistogramNumCodes(cache_bits);
   const size_t cost_model_size = sizeof(CostModel) + literal_array_size;
   CostModel* const cost_model =
       (CostModel*)WebPSafeCalloc(1ULL, cost_model_size);
@@ -584,13 +587,13 @@ static int BackwardReferencesHashChainDistanceOnly(
   CostManager* cost_manager =
       (CostManager*)WebPSafeCalloc(1ULL, sizeof(*cost_manager));
   int offset_prev = -1, len_prev = -1;
-  float offset_cost = -1.f;
+  int64_t offset_cost = -1;
   int first_offset_is_constant = -1;  // initialized with 'impossible' value
   int reach = 0;
 
   if (cost_model == NULL || cost_manager == NULL) goto Error;
 
-  cost_model->literal_ = (float*)(cost_model + 1);
+  cost_model->literal_ = (uint32_t*)(cost_model + 1);
   if (use_color_cache) {
     cc_init = VP8LColorCacheInit(&hashers, cache_bits);
     if (!cc_init) goto Error;
@@ -608,11 +611,12 @@ static int BackwardReferencesHashChainDistanceOnly(
   // non-processed locations from this point.
   dist_array[0] = 0;
   // Add first pixel as literal.
-  AddSingleLiteralWithCostModel(argb, &hashers, cost_model, 0, use_color_cache,
-                                0.f, cost_manager->costs_, dist_array);
+  AddSingleLiteralWithCostModel(argb, &hashers, cost_model, /*idx=*/0,
+                                use_color_cache, /*prev_cost=*/0,
+                                cost_manager->costs_, dist_array);
 
   for (i = 1; i < pix_count; ++i) {
-    const float prev_cost = cost_manager->costs_[i - 1];
+    const int64_t prev_cost = cost_manager->costs_[i - 1];
     int offset, len;
     VP8LHashChainFindCopy(hash_chain, i, &offset, &len);
 
diff --git a/src/enc/backward_references_enc.c b/src/enc/backward_references_enc.c
index dc98bf17..0f1d83da 100644
--- a/src/enc/backward_references_enc.c
+++ b/src/enc/backward_references_enc.c
@@ -13,8 +13,6 @@
 #include "src/enc/backward_references_enc.h"
 
 #include <assert.h>
-#include <float.h>
-#include <math.h>
 
 #include "src/dsp/dsp.h"
 #include "src/dsp/lossless.h"
@@ -27,8 +25,6 @@
 
 #define MIN_BLOCK_SIZE 256  // minimum block size for backward references
 
-#define MAX_ENTROPY    (1e30f)
-
 // 1M window (4M bytes) minus 120 special codes for short distances.
 #define WINDOW_SIZE ((1 << WINDOW_SIZE_BITS) - 120)
 
@@ -758,7 +754,7 @@ static int CalculateBestCacheSize(const uint32_t* argb, int quality,
                                   int* const best_cache_bits) {
   int i;
   const int cache_bits_max = (quality <= 25) ? 0 : *best_cache_bits;
-  float entropy_min = MAX_ENTROPY;
+  uint64_t entropy_min = WEBP_UINT64_MAX;
   int cc_init[MAX_COLOR_CACHE_BITS + 1] = { 0 };
   VP8LColorCache hashers[MAX_COLOR_CACHE_BITS + 1];
   VP8LRefsCursor c = VP8LRefsCursorInit(refs);
@@ -843,7 +839,7 @@ static int CalculateBestCacheSize(const uint32_t* argb, int quality,
   }
 
   for (i = 0; i <= cache_bits_max; ++i) {
-    const float entropy = VP8LHistogramEstimateBits(histos[i]);
+    const uint64_t entropy = VP8LHistogramEstimateBits(histos[i]);
     if (i == 0 || entropy < entropy_min) {
       entropy_min = entropy;
       *best_cache_bits = i;
@@ -920,7 +916,7 @@ static int GetBackwardReferences(int width, int height,
   int i, lz77_type;
   // Index 0 is for a color cache, index 1 for no cache (if needed).
   int lz77_types_best[2] = {0, 0};
-  float bit_costs_best[2] = {FLT_MAX, FLT_MAX};
+  uint64_t bit_costs_best[2] = {WEBP_UINT64_MAX, WEBP_UINT64_MAX};
   VP8LHashChain hash_chain_box;
   VP8LBackwardRefs* const refs_tmp = &refs[do_no_cache ? 2 : 1];
   int status = 0;
@@ -932,7 +928,7 @@ static int GetBackwardReferences(int width, int height,
   for (lz77_type = 1; lz77_types_to_try;
        lz77_types_to_try &= ~lz77_type, lz77_type <<= 1) {
     int res = 0;
-    float bit_cost = 0.f;
+    uint64_t bit_cost = 0u;
     if ((lz77_types_to_try & lz77_type) == 0) continue;
     switch (lz77_type) {
       case kLZ77RLE:
@@ -1006,7 +1002,7 @@ static int GetBackwardReferences(int width, int height,
       const VP8LHashChain* const hash_chain_tmp =
           (lz77_types_best[i] == kLZ77Standard) ? hash_chain : &hash_chain_box;
       const int cache_bits = (i == 1) ? 0 : *cache_bits_best;
-      float bit_cost_trace;
+      uint64_t bit_cost_trace;
       if (!VP8LBackwardReferencesTraceBackwards(width, height, argb, cache_bits,
                                                 hash_chain_tmp, &refs[i],
                                                 refs_tmp)) {
diff --git a/src/enc/config_enc.c b/src/enc/config_enc.c
index 3518b414..ac478484 100644
--- a/src/enc/config_enc.c
+++ b/src/enc/config_enc.c
@@ -55,7 +55,6 @@ int WebPConfigInitInternal(WebPConfig* config,
   config->thread_level = 0;
   config->low_memory = 0;
   config->near_lossless = 100;
-  config->use_delta_palette = 0;
   config->use_sharp_yuv = 0;
 
   // TODO(skal): tune.
@@ -125,9 +124,6 @@ int WebPValidateConfig(const WebPConfig* config) {
   if (config->thread_level < 0 || config->thread_level > 1) return 0;
   if (config->low_memory < 0 || config->low_memory > 1) return 0;
   if (config->exact < 0 || config->exact > 1) return 0;
-  if (config->use_delta_palette < 0 || config->use_delta_palette > 1) {
-    return 0;
-  }
   if (config->use_sharp_yuv < 0 || config->use_sharp_yuv > 1) return 0;
 
   return 1;
diff --git a/src/enc/cost_enc.c b/src/enc/cost_enc.c
index 48fd9bc3..f0bba6ef 100644
--- a/src/enc/cost_enc.c
+++ b/src/enc/cost_enc.c
@@ -19,7 +19,7 @@
 // For each given level, the following table gives the pattern of contexts to
 // use for coding it (in [][0]) as well as the bit value to use for each
 // context (in [][1]).
-const uint16_t VP8LevelCodes[MAX_VARIABLE_LEVEL][2] = {
+static const uint16_t VP8LevelCodes[MAX_VARIABLE_LEVEL][2] = {
                   {0x001, 0x000}, {0x007, 0x001}, {0x00f, 0x005},
   {0x00f, 0x00d}, {0x033, 0x003}, {0x033, 0x003}, {0x033, 0x023},
   {0x033, 0x023}, {0x033, 0x023}, {0x033, 0x023}, {0x0d3, 0x013},
diff --git a/src/enc/cost_enc.h b/src/enc/cost_enc.h
index a4b177b3..a3524f9f 100644
--- a/src/enc/cost_enc.h
+++ b/src/enc/cost_enc.h
@@ -61,7 +61,6 @@ static WEBP_INLINE int VP8BitCost(int bit, uint8_t proba) {
 }
 
 // Level cost calculations
-extern const uint16_t VP8LevelCodes[MAX_VARIABLE_LEVEL][2];
 void VP8CalculateLevelCosts(VP8EncProba* const proba);
 static WEBP_INLINE int VP8LevelCost(const uint16_t* const table, int level) {
   return VP8LevelFixedCosts[level]
diff --git a/src/enc/histogram_enc.c b/src/enc/histogram_enc.c
index 3ca67b3a..e210549b 100644
--- a/src/enc/histogram_enc.c
+++ b/src/enc/histogram_enc.c
@@ -13,8 +13,7 @@
 #include "src/webp/config.h"
 #endif
 
-#include <float.h>
-#include <math.h>
+#include <string.h>
 
 #include "src/dsp/lossless.h"
 #include "src/dsp/lossless_common.h"
@@ -23,8 +22,6 @@
 #include "src/enc/vp8i_enc.h"
 #include "src/utils/utils.h"
 
-#define MAX_BIT_COST FLT_MAX
-
 // Number of partitions for the three dominant (literal, red and blue) symbol
 // costs.
 #define NUM_PARTITIONS 4
@@ -33,10 +30,18 @@
 // Maximum number of histograms allowed in greedy combining algorithm.
 #define MAX_HISTO_GREEDY 100
 
+// Return the size of the histogram for a given cache_bits.
+static int GetHistogramSize(int cache_bits) {
+  const int literal_size = VP8LHistogramNumCodes(cache_bits);
+  const size_t total_size = sizeof(VP8LHistogram) + sizeof(int) * literal_size;
+  assert(total_size <= (size_t)0x7fffffff);
+  return (int)total_size;
+}
+
 static void HistogramClear(VP8LHistogram* const p) {
   uint32_t* const literal = p->literal_;
   const int cache_bits = p->palette_code_bits_;
-  const int histo_size = VP8LGetHistogramSize(cache_bits);
+  const int histo_size = GetHistogramSize(cache_bits);
   memset(p, 0, histo_size);
   p->palette_code_bits_ = cache_bits;
   p->literal_ = literal;
@@ -54,20 +59,13 @@ static void HistogramCopy(const VP8LHistogram* const src,
   uint32_t* const dst_literal = dst->literal_;
   const int dst_cache_bits = dst->palette_code_bits_;
   const int literal_size = VP8LHistogramNumCodes(dst_cache_bits);
-  const int histo_size = VP8LGetHistogramSize(dst_cache_bits);
+  const int histo_size = GetHistogramSize(dst_cache_bits);
   assert(src->palette_code_bits_ == dst_cache_bits);
   memcpy(dst, src, histo_size);
   dst->literal_ = dst_literal;
   memcpy(dst->literal_, src->literal_, literal_size * sizeof(*dst->literal_));
 }
 
-int VP8LGetHistogramSize(int cache_bits) {
-  const int literal_size = VP8LHistogramNumCodes(cache_bits);
-  const size_t total_size = sizeof(VP8LHistogram) + sizeof(int) * literal_size;
-  assert(total_size <= (size_t)0x7fffffff);
-  return (int)total_size;
-}
-
 void VP8LFreeHistogram(VP8LHistogram* const histo) {
   WebPSafeFree(histo);
 }
@@ -102,17 +100,17 @@ void VP8LHistogramInit(VP8LHistogram* const p, int palette_code_bits,
     HistogramClear(p);
   } else {
     p->trivial_symbol_ = 0;
-    p->bit_cost_ = 0.;
-    p->literal_cost_ = 0.;
-    p->red_cost_ = 0.;
-    p->blue_cost_ = 0.;
+    p->bit_cost_ = 0;
+    p->literal_cost_ = 0;
+    p->red_cost_ = 0;
+    p->blue_cost_ = 0;
     memset(p->is_used_, 0, sizeof(p->is_used_));
   }
 }
 
 VP8LHistogram* VP8LAllocateHistogram(int cache_bits) {
   VP8LHistogram* histo = NULL;
-  const int total_size = VP8LGetHistogramSize(cache_bits);
+  const int total_size = GetHistogramSize(cache_bits);
   uint8_t* const memory = (uint8_t*)WebPSafeMalloc(total_size, sizeof(*memory));
   if (memory == NULL) return NULL;
   histo = (VP8LHistogram*)memory;
@@ -126,7 +124,7 @@ VP8LHistogram* VP8LAllocateHistogram(int cache_bits) {
 static void HistogramSetResetPointers(VP8LHistogramSet* const set,
                                       int cache_bits) {
   int i;
-  const int histo_size = VP8LGetHistogramSize(cache_bits);
+  const int histo_size = GetHistogramSize(cache_bits);
   uint8_t* memory = (uint8_t*) (set->histograms);
   memory += set->max_size * sizeof(*set->histograms);
   for (i = 0; i < set->max_size; ++i) {
@@ -140,7 +138,7 @@ static void HistogramSetResetPointers(VP8LHistogramSet* const set,
 
 // Returns the total size of the VP8LHistogramSet.
 static size_t HistogramSetTotalSize(int size, int cache_bits) {
-  const int histo_size = VP8LGetHistogramSize(cache_bits);
+  const int histo_size = GetHistogramSize(cache_bits);
   return (sizeof(VP8LHistogramSet) + size * (sizeof(VP8LHistogram*) +
           histo_size + WEBP_ALIGN_CST));
 }
@@ -230,8 +228,8 @@ void VP8LHistogramAddSinglePixOrCopy(VP8LHistogram* const histo,
 // -----------------------------------------------------------------------------
 // Entropy-related functions.
 
-static WEBP_INLINE float BitsEntropyRefine(const VP8LBitEntropy* entropy) {
-  float mix;
+static WEBP_INLINE uint64_t BitsEntropyRefine(const VP8LBitEntropy* entropy) {
+  uint64_t mix;
   if (entropy->nonzeros < 5) {
     if (entropy->nonzeros <= 1) {
       return 0;
@@ -240,67 +238,72 @@ static WEBP_INLINE float BitsEntropyRefine(const VP8LBitEntropy* entropy) {
     // Let's mix in a bit of entropy to favor good clustering when
     // distributions of these are combined.
     if (entropy->nonzeros == 2) {
-      return 0.99f * entropy->sum + 0.01f * entropy->entropy;
+      return DivRound(99 * ((uint64_t)entropy->sum << LOG_2_PRECISION_BITS) +
+                          entropy->entropy,
+                      100);
     }
     // No matter what the entropy says, we cannot be better than min_limit
     // with Huffman coding. I am mixing a bit of entropy into the
     // min_limit since it produces much better (~0.5 %) compression results
     // perhaps because of better entropy clustering.
     if (entropy->nonzeros == 3) {
-      mix = 0.95f;
+      mix = 950;
     } else {
-      mix = 0.7f;  // nonzeros == 4.
+      mix = 700;  // nonzeros == 4.
     }
   } else {
-    mix = 0.627f;
+    mix = 627;
   }
 
   {
-    float min_limit = 2.f * entropy->sum - entropy->max_val;
-    min_limit = mix * min_limit + (1.f - mix) * entropy->entropy;
+    uint64_t min_limit = (uint64_t)(2 * entropy->sum - entropy->max_val)
+                         << LOG_2_PRECISION_BITS;
+    min_limit =
+        DivRound(mix * min_limit + (1000 - mix) * entropy->entropy, 1000);
     return (entropy->entropy < min_limit) ? min_limit : entropy->entropy;
   }
 }
 
-float VP8LBitsEntropy(const uint32_t* const array, int n) {
+uint64_t VP8LBitsEntropy(const uint32_t* const array, int n) {
   VP8LBitEntropy entropy;
   VP8LBitsEntropyUnrefined(array, n, &entropy);
 
   return BitsEntropyRefine(&entropy);
 }
 
-static float InitialHuffmanCost(void) {
+static uint64_t InitialHuffmanCost(void) {
   // Small bias because Huffman code length is typically not stored in
   // full length.
-  static const int kHuffmanCodeOfHuffmanCodeSize = CODE_LENGTH_CODES * 3;
-  static const float kSmallBias = 9.1f;
-  return kHuffmanCodeOfHuffmanCodeSize - kSmallBias;
+  static const uint64_t kHuffmanCodeOfHuffmanCodeSize = CODE_LENGTH_CODES * 3;
+  // Subtract a bias of 9.1.
+  return (kHuffmanCodeOfHuffmanCodeSize << LOG_2_PRECISION_BITS) -
+         DivRound(91ll << LOG_2_PRECISION_BITS, 10);
 }
 
 // Finalize the Huffman cost based on streak numbers and length type (<3 or >=3)
-static float FinalHuffmanCost(const VP8LStreaks* const stats) {
-  // The constants in this function are experimental and got rounded from
+static uint64_t FinalHuffmanCost(const VP8LStreaks* const stats) {
+  // The constants in this function are empirical and got rounded from
   // their original values in 1/8 when switched to 1/1024.
-  float retval = InitialHuffmanCost();
+  uint64_t retval = InitialHuffmanCost();
   // Second coefficient: Many zeros in the histogram are covered efficiently
   // by a run-length encode. Originally 2/8.
-  retval += stats->counts[0] * 1.5625f + 0.234375f * stats->streaks[0][1];
+  uint32_t retval_extra = stats->counts[0] * 1600 + 240 * stats->streaks[0][1];
   // Second coefficient: Constant values are encoded less efficiently, but still
   // RLE'ed. Originally 6/8.
-  retval += stats->counts[1] * 2.578125f + 0.703125f * stats->streaks[1][1];
+  retval_extra += stats->counts[1] * 2640 + 720 * stats->streaks[1][1];
   // 0s are usually encoded more efficiently than non-0s.
   // Originally 15/8.
-  retval += 1.796875f * stats->streaks[0][0];
+  retval_extra += 1840 * stats->streaks[0][0];
   // Originally 26/8.
-  retval += 3.28125f * stats->streaks[1][0];
-  return retval;
+  retval_extra += 3360 * stats->streaks[1][0];
+  return retval + ((uint64_t)retval_extra << (LOG_2_PRECISION_BITS - 10));
 }
 
 // Get the symbol entropy for the distribution 'population'.
 // Set 'trivial_sym', if there's only one symbol present in the distribution.
-static float PopulationCost(const uint32_t* const population, int length,
-                            uint32_t* const trivial_sym,
-                            uint8_t* const is_used) {
+static uint64_t PopulationCost(const uint32_t* const population, int length,
+                               uint32_t* const trivial_sym,
+                               uint8_t* const is_used) {
   VP8LBitEntropy bit_entropy;
   VP8LStreaks stats;
   VP8LGetEntropyUnrefined(population, length, &bit_entropy, &stats);
@@ -316,10 +319,11 @@ static float PopulationCost(const uint32_t* const population, int length,
 
 // trivial_at_end is 1 if the two histograms only have one element that is
 // non-zero: both the zero-th one, or both the last one.
-static WEBP_INLINE float GetCombinedEntropy(const uint32_t* const X,
-                                            const uint32_t* const Y, int length,
-                                            int is_X_used, int is_Y_used,
-                                            int trivial_at_end) {
+static WEBP_INLINE uint64_t GetCombinedEntropy(const uint32_t* const X,
+                                               const uint32_t* const Y,
+                                               int length, int is_X_used,
+                                               int is_Y_used,
+                                               int trivial_at_end) {
   VP8LStreaks stats;
   if (trivial_at_end) {
     // This configuration is due to palettization that transforms an indexed
@@ -357,7 +361,7 @@ static WEBP_INLINE float GetCombinedEntropy(const uint32_t* const X,
 }
 
 // Estimates the Entropy + Huffman + other block overhead size cost.
-float VP8LHistogramEstimateBits(VP8LHistogram* const p) {
+uint64_t VP8LHistogramEstimateBits(VP8LHistogram* const p) {
   return PopulationCost(p->literal_,
                         VP8LHistogramNumCodes(p->palette_code_bits_), NULL,
                         &p->is_used_[0]) +
@@ -366,27 +370,42 @@ float VP8LHistogramEstimateBits(VP8LHistogram* const p) {
          PopulationCost(p->alpha_, NUM_LITERAL_CODES, NULL, &p->is_used_[3]) +
          PopulationCost(p->distance_, NUM_DISTANCE_CODES, NULL,
                         &p->is_used_[4]) +
-         (float)VP8LExtraCost(p->literal_ + NUM_LITERAL_CODES,
-                              NUM_LENGTH_CODES) +
-         (float)VP8LExtraCost(p->distance_, NUM_DISTANCE_CODES);
+         ((uint64_t)(VP8LExtraCost(p->literal_ + NUM_LITERAL_CODES,
+                                   NUM_LENGTH_CODES) +
+                     VP8LExtraCost(p->distance_, NUM_DISTANCE_CODES))
+          << LOG_2_PRECISION_BITS);
 }
 
 // -----------------------------------------------------------------------------
 // Various histogram combine/cost-eval functions
 
-static int GetCombinedHistogramEntropy(const VP8LHistogram* const a,
-                                       const VP8LHistogram* const b,
-                                       float cost_threshold, float* cost) {
+// Set a + b in b, saturating at WEBP_INT64_MAX.
+static WEBP_INLINE void SaturateAdd(uint64_t a, int64_t* b) {
+  if (*b < 0 || (int64_t)a <= WEBP_INT64_MAX - *b) {
+    *b += (int64_t)a;
+  } else {
+    *b = WEBP_INT64_MAX;
+  }
+}
+
+// Returns 1 if the cost of the combined histogram is less than the threshold.
+// Otherwise returns 0 and the cost is invalid due to early bail-out.
+WEBP_NODISCARD static int GetCombinedHistogramEntropy(
+    const VP8LHistogram* const a, const VP8LHistogram* const b,
+    int64_t cost_threshold_in, uint64_t* cost) {
   const int palette_code_bits = a->palette_code_bits_;
   int trivial_at_end = 0;
+  const uint64_t cost_threshold = (uint64_t)cost_threshold_in;
   assert(a->palette_code_bits_ == b->palette_code_bits_);
-  *cost += GetCombinedEntropy(a->literal_, b->literal_,
-                              VP8LHistogramNumCodes(palette_code_bits),
-                              a->is_used_[0], b->is_used_[0], 0);
-  *cost += (float)VP8LExtraCostCombined(a->literal_ + NUM_LITERAL_CODES,
-                                        b->literal_ + NUM_LITERAL_CODES,
-                                        NUM_LENGTH_CODES);
-  if (*cost > cost_threshold) return 0;
+  if (cost_threshold_in <= 0) return 0;
+  *cost = GetCombinedEntropy(a->literal_, b->literal_,
+                             VP8LHistogramNumCodes(palette_code_bits),
+                             a->is_used_[0], b->is_used_[0], 0);
+  *cost += (uint64_t)VP8LExtraCostCombined(a->literal_ + NUM_LITERAL_CODES,
+                                           b->literal_ + NUM_LITERAL_CODES,
+                                           NUM_LENGTH_CODES)
+           << LOG_2_PRECISION_BITS;
+  if (*cost >= cost_threshold) return 0;
 
   if (a->trivial_symbol_ != VP8L_NON_TRIVIAL_SYM &&
       a->trivial_symbol_ == b->trivial_symbol_) {
@@ -401,27 +420,24 @@ static int GetCombinedHistogramEntropy(const VP8LHistogram* const a,
     }
   }
 
-  *cost +=
-      GetCombinedEntropy(a->red_, b->red_, NUM_LITERAL_CODES, a->is_used_[1],
-                         b->is_used_[1], trivial_at_end);
-  if (*cost > cost_threshold) return 0;
+  *cost += GetCombinedEntropy(a->red_, b->red_, NUM_LITERAL_CODES,
+                              a->is_used_[1], b->is_used_[1], trivial_at_end);
+  if (*cost >= cost_threshold) return 0;
 
-  *cost +=
-      GetCombinedEntropy(a->blue_, b->blue_, NUM_LITERAL_CODES, a->is_used_[2],
-                         b->is_used_[2], trivial_at_end);
-  if (*cost > cost_threshold) return 0;
+  *cost += GetCombinedEntropy(a->blue_, b->blue_, NUM_LITERAL_CODES,
+                              a->is_used_[2], b->is_used_[2], trivial_at_end);
+  if (*cost >= cost_threshold) return 0;
 
-  *cost +=
-      GetCombinedEntropy(a->alpha_, b->alpha_, NUM_LITERAL_CODES,
-                         a->is_used_[3], b->is_used_[3], trivial_at_end);
-  if (*cost > cost_threshold) return 0;
+  *cost += GetCombinedEntropy(a->alpha_, b->alpha_, NUM_LITERAL_CODES,
+                              a->is_used_[3], b->is_used_[3], trivial_at_end);
+  if (*cost >= cost_threshold) return 0;
 
-  *cost +=
-      GetCombinedEntropy(a->distance_, b->distance_, NUM_DISTANCE_CODES,
-                         a->is_used_[4], b->is_used_[4], 0);
-  *cost += (float)VP8LExtraCostCombined(a->distance_, b->distance_,
-                                        NUM_DISTANCE_CODES);
-  if (*cost > cost_threshold) return 0;
+  *cost += GetCombinedEntropy(a->distance_, b->distance_, NUM_DISTANCE_CODES,
+                              a->is_used_[4], b->is_used_[4], 0);
+  *cost += (uint64_t)VP8LExtraCostCombined(a->distance_, b->distance_,
+                                           NUM_DISTANCE_CODES)
+           << LOG_2_PRECISION_BITS;
+  if (*cost >= cost_threshold) return 0;
 
   return 1;
 }
@@ -441,33 +457,39 @@ static WEBP_INLINE void HistogramAdd(const VP8LHistogram* const a,
 // Since the previous score passed is 'cost_threshold', we only need to compare
 // the partial cost against 'cost_threshold + C(a) + C(b)' to possibly bail-out
 // early.
-static float HistogramAddEval(const VP8LHistogram* const a,
-                              const VP8LHistogram* const b,
-                              VP8LHistogram* const out, float cost_threshold) {
-  float cost = 0;
-  const float sum_cost = a->bit_cost_ + b->bit_cost_;
-  cost_threshold += sum_cost;
-
-  if (GetCombinedHistogramEntropy(a, b, cost_threshold, &cost)) {
-    HistogramAdd(a, b, out);
-    out->bit_cost_ = cost;
-    out->palette_code_bits_ = a->palette_code_bits_;
-  }
-
-  return cost - sum_cost;
+// Returns 1 if the cost is less than the threshold.
+// Otherwise returns 0 and the cost is invalid due to early bail-out.
+WEBP_NODISCARD static int HistogramAddEval(const VP8LHistogram* const a,
+                                           const VP8LHistogram* const b,
+                                           VP8LHistogram* const out,
+                                           int64_t cost_threshold) {
+  uint64_t cost;
+  const uint64_t sum_cost = a->bit_cost_ + b->bit_cost_;
+  SaturateAdd(sum_cost, &cost_threshold);
+  if (!GetCombinedHistogramEntropy(a, b, cost_threshold, &cost)) return 0;
+
+  HistogramAdd(a, b, out);
+  out->bit_cost_ = cost;
+  out->palette_code_bits_ = a->palette_code_bits_;
+  return 1;
 }
 
 // Same as HistogramAddEval(), except that the resulting histogram
 // is not stored. Only the cost C(a+b) - C(a) is evaluated. We omit
 // the term C(b) which is constant over all the evaluations.
-static float HistogramAddThresh(const VP8LHistogram* const a,
-                                const VP8LHistogram* const b,
-                                float cost_threshold) {
-  float cost;
+// Returns 1 if the cost is less than the threshold.
+// Otherwise returns 0 and the cost is invalid due to early bail-out.
+WEBP_NODISCARD static int HistogramAddThresh(const VP8LHistogram* const a,
+                                             const VP8LHistogram* const b,
+                                             int64_t cost_threshold,
+                                             int64_t* cost_out) {
+  uint64_t cost;
   assert(a != NULL && b != NULL);
-  cost = -a->bit_cost_;
-  GetCombinedHistogramEntropy(a, b, cost_threshold, &cost);
-  return cost;
+  SaturateAdd(a->bit_cost_, &cost_threshold);
+  if (!GetCombinedHistogramEntropy(a, b, cost_threshold, &cost)) return 0;
+
+  *cost_out = (int64_t)cost - (int64_t)a->bit_cost_;
+  return 1;
 }
 
 // -----------------------------------------------------------------------------
@@ -475,21 +497,21 @@ static float HistogramAddThresh(const VP8LHistogram* const a,
 // The structure to keep track of cost range for the three dominant entropy
 // symbols.
 typedef struct {
-  float literal_max_;
-  float literal_min_;
-  float red_max_;
-  float red_min_;
-  float blue_max_;
-  float blue_min_;
+  uint64_t literal_max_;
+  uint64_t literal_min_;
+  uint64_t red_max_;
+  uint64_t red_min_;
+  uint64_t blue_max_;
+  uint64_t blue_min_;
 } DominantCostRange;
 
 static void DominantCostRangeInit(DominantCostRange* const c) {
-  c->literal_max_ = 0.;
-  c->literal_min_ = MAX_BIT_COST;
-  c->red_max_ = 0.;
-  c->red_min_ = MAX_BIT_COST;
-  c->blue_max_ = 0.;
-  c->blue_min_ = MAX_BIT_COST;
+  c->literal_max_ = 0;
+  c->literal_min_ = WEBP_UINT64_MAX;
+  c->red_max_ = 0;
+  c->red_min_ = WEBP_UINT64_MAX;
+  c->blue_max_ = 0;
+  c->blue_min_ = WEBP_UINT64_MAX;
 }
 
 static void UpdateDominantCostRange(
@@ -504,15 +526,18 @@ static void UpdateDominantCostRange(
 
 static void UpdateHistogramCost(VP8LHistogram* const h) {
   uint32_t alpha_sym, red_sym, blue_sym;
-  const float alpha_cost =
+  const uint64_t alpha_cost =
       PopulationCost(h->alpha_, NUM_LITERAL_CODES, &alpha_sym, &h->is_used_[3]);
-  const float distance_cost =
+  const uint64_t distance_cost =
       PopulationCost(h->distance_, NUM_DISTANCE_CODES, NULL, &h->is_used_[4]) +
-      (float)VP8LExtraCost(h->distance_, NUM_DISTANCE_CODES);
+      ((uint64_t)VP8LExtraCost(h->distance_, NUM_DISTANCE_CODES)
+       << LOG_2_PRECISION_BITS);
   const int num_codes = VP8LHistogramNumCodes(h->palette_code_bits_);
   h->literal_cost_ =
       PopulationCost(h->literal_, num_codes, NULL, &h->is_used_[0]) +
-      (float)VP8LExtraCost(h->literal_ + NUM_LITERAL_CODES, NUM_LENGTH_CODES);
+      ((uint64_t)VP8LExtraCost(h->literal_ + NUM_LITERAL_CODES,
+                               NUM_LENGTH_CODES)
+       << LOG_2_PRECISION_BITS);
   h->red_cost_ =
       PopulationCost(h->red_, NUM_LITERAL_CODES, &red_sym, &h->is_used_[1]);
   h->blue_cost_ =
@@ -527,10 +552,10 @@ static void UpdateHistogramCost(VP8LHistogram* const h) {
   }
 }
 
-static int GetBinIdForEntropy(float min, float max, float val) {
-  const float range = max - min;
-  if (range > 0.) {
-    const float delta = val - min;
+static int GetBinIdForEntropy(uint64_t min, uint64_t max, uint64_t val) {
+  const uint64_t range = max - min;
+  if (range > 0) {
+    const uint64_t delta = val - min;
     return (int)((NUM_PARTITIONS - 1e-6) * delta / range);
   } else {
     return 0;
@@ -576,11 +601,11 @@ static void HistogramBuild(
 }
 
 // Copies the histograms and computes its bit_cost.
-static const uint16_t kInvalidHistogramSymbol = (uint16_t)(-1);
+static const uint32_t kInvalidHistogramSymbol = (uint32_t)(-1);
 static void HistogramCopyAndAnalyze(VP8LHistogramSet* const orig_histo,
                                     VP8LHistogramSet* const image_histo,
                                     int* const num_used,
-                                    uint16_t* const histogram_symbols) {
+                                    uint32_t* const histogram_symbols) {
   int i, cluster_id;
   int num_used_orig = *num_used;
   VP8LHistogram** const orig_histograms = orig_histo->histograms;
@@ -639,11 +664,12 @@ static void HistogramAnalyzeEntropyBin(VP8LHistogramSet* const image_histo,
 
 // Merges some histograms with same bin_id together if it's advantageous.
 // Sets the remaining histograms to NULL.
+// 'combine_cost_factor' has to be divided by 100.
 static void HistogramCombineEntropyBin(
     VP8LHistogramSet* const image_histo, int* num_used,
-    const uint16_t* const clusters, uint16_t* const cluster_mappings,
+    const uint32_t* const clusters, uint16_t* const cluster_mappings,
     VP8LHistogram* cur_combo, const uint16_t* const bin_map, int num_bins,
-    float combine_cost_factor, int low_effort) {
+    int32_t combine_cost_factor, int low_effort) {
   VP8LHistogram** const histograms = image_histo->histograms;
   int idx;
   struct {
@@ -673,11 +699,11 @@ static void HistogramCombineEntropyBin(
       cluster_mappings[clusters[idx]] = clusters[first];
     } else {
       // try to merge #idx into #first (both share the same bin_id)
-      const float bit_cost = histograms[idx]->bit_cost_;
-      const float bit_cost_thresh = -bit_cost * combine_cost_factor;
-      const float curr_cost_diff = HistogramAddEval(
-          histograms[first], histograms[idx], cur_combo, bit_cost_thresh);
-      if (curr_cost_diff < bit_cost_thresh) {
+      const uint64_t bit_cost = histograms[idx]->bit_cost_;
+      const int64_t bit_cost_thresh =
+          -DivRound((int64_t)bit_cost * combine_cost_factor, 100);
+      if (HistogramAddEval(histograms[first], histograms[idx], cur_combo,
+                           bit_cost_thresh)) {
         // Try to merge two histograms only if the combo is a trivial one or
         // the two candidate histograms are already non-trivial.
         // For some images, 'try_combine' turns out to be false for a lot of
@@ -724,8 +750,8 @@ static uint32_t MyRand(uint32_t* const seed) {
 typedef struct {
   int idx1;
   int idx2;
-  float cost_diff;
-  float cost_combo;
+  int64_t cost_diff;
+  uint64_t cost_combo;
 } HistogramPair;
 
 typedef struct {
@@ -765,7 +791,7 @@ static void HistoQueuePopPair(HistoQueue* const histo_queue,
 // Check whether a pair in the queue should be updated as head or not.
 static void HistoQueueUpdateHead(HistoQueue* const histo_queue,
                                  HistogramPair* const pair) {
-  assert(pair->cost_diff < 0.);
+  assert(pair->cost_diff < 0);
   assert(pair >= histo_queue->queue &&
          pair < (histo_queue->queue + histo_queue->size));
   assert(histo_queue->size > 0);
@@ -778,29 +804,35 @@ static void HistoQueueUpdateHead(HistoQueue* const histo_queue,
 }
 
 // Update the cost diff and combo of a pair of histograms. This needs to be
-// called when the the histograms have been merged with a third one.
-static void HistoQueueUpdatePair(const VP8LHistogram* const h1,
-                                 const VP8LHistogram* const h2, float threshold,
-                                 HistogramPair* const pair) {
-  const float sum_cost = h1->bit_cost_ + h2->bit_cost_;
-  pair->cost_combo = 0.;
-  GetCombinedHistogramEntropy(h1, h2, sum_cost + threshold, &pair->cost_combo);
-  pair->cost_diff = pair->cost_combo - sum_cost;
+// called when the histograms have been merged with a third one.
+// Returns 1 if the cost diff is less than the threshold.
+// Otherwise returns 0 and the cost is invalid due to early bail-out.
+WEBP_NODISCARD static int HistoQueueUpdatePair(const VP8LHistogram* const h1,
+                                               const VP8LHistogram* const h2,
+                                               int64_t cost_threshold,
+                                               HistogramPair* const pair) {
+  const int64_t sum_cost = h1->bit_cost_ + h2->bit_cost_;
+  SaturateAdd(sum_cost, &cost_threshold);
+  if (!GetCombinedHistogramEntropy(h1, h2, cost_threshold, &pair->cost_combo)) {
+    return 0;
+  }
+  pair->cost_diff = (int64_t)pair->cost_combo - sum_cost;
+  return 1;
 }
 
 // Create a pair from indices "idx1" and "idx2" provided its cost
 // is inferior to "threshold", a negative entropy.
-// It returns the cost of the pair, or 0. if it superior to threshold.
-static float HistoQueuePush(HistoQueue* const histo_queue,
-                            VP8LHistogram** const histograms, int idx1,
-                            int idx2, float threshold) {
+// It returns the cost of the pair, or 0 if it superior to threshold.
+static int64_t HistoQueuePush(HistoQueue* const histo_queue,
+                              VP8LHistogram** const histograms, int idx1,
+                              int idx2, int64_t threshold) {
   const VP8LHistogram* h1;
   const VP8LHistogram* h2;
   HistogramPair pair;
 
   // Stop here if the queue is full.
-  if (histo_queue->size == histo_queue->max_size) return 0.;
-  assert(threshold <= 0.);
+  if (histo_queue->size == histo_queue->max_size) return 0;
+  assert(threshold <= 0);
   if (idx1 > idx2) {
     const int tmp = idx2;
     idx2 = idx1;
@@ -811,10 +843,8 @@ static float HistoQueuePush(HistoQueue* const histo_queue,
   h1 = histograms[idx1];
   h2 = histograms[idx2];
 
-  HistoQueueUpdatePair(h1, h2, threshold, &pair);
-
   // Do not even consider the pair if it does not improve the entropy.
-  if (pair.cost_diff >= threshold) return 0.;
+  if (!HistoQueueUpdatePair(h1, h2, threshold, &pair)) return 0;
 
   histo_queue->queue[histo_queue->size++] = pair;
   HistoQueueUpdateHead(histo_queue, &histo_queue->queue[histo_queue->size - 1]);
@@ -851,7 +881,7 @@ static int HistogramCombineGreedy(VP8LHistogramSet* const image_histo,
     for (j = i + 1; j < image_histo_size; ++j) {
       // Initialize queue.
       if (image_histo->histograms[j] == NULL) continue;
-      HistoQueuePush(&histo_queue, histograms, i, j, 0.);
+      HistoQueuePush(&histo_queue, histograms, i, j, 0);
     }
   }
 
@@ -879,7 +909,7 @@ static int HistogramCombineGreedy(VP8LHistogramSet* const image_histo,
     // Push new pairs formed with combined histogram to the queue.
     for (i = 0; i < image_histo->size; ++i) {
       if (i == idx1 || image_histo->histograms[i] == NULL) continue;
-      HistoQueuePush(&histo_queue, image_histo->histograms, idx1, i, 0.);
+      HistoQueuePush(&histo_queue, image_histo->histograms, idx1, i, 0);
     }
   }
 
@@ -937,8 +967,8 @@ static int HistogramCombineStochastic(VP8LHistogramSet* const image_histo,
            ++tries_with_no_success < num_tries_no_success;
        ++iter) {
     int* mapping_index;
-    float best_cost =
-        (histo_queue.size == 0) ? 0.f : histo_queue.queue[0].cost_diff;
+    int64_t best_cost =
+        (histo_queue.size == 0) ? 0 : histo_queue.queue[0].cost_diff;
     int best_idx1 = -1, best_idx2 = 1;
     const uint32_t rand_range = (*num_used - 1) * (*num_used);
     // (*num_used) / 2 was chosen empirically. Less means faster but worse
@@ -947,7 +977,7 @@ static int HistogramCombineStochastic(VP8LHistogramSet* const image_histo,
 
     // Pick random samples.
     for (j = 0; *num_used >= 2 && j < num_tries; ++j) {
-      float curr_cost;
+      int64_t curr_cost;
       // Choose two different histograms at random and try to combine them.
       const uint32_t tmp = MyRand(&seed) % rand_range;
       uint32_t idx1 = tmp / (*num_used - 1);
@@ -1012,8 +1042,8 @@ static int HistogramCombineStochastic(VP8LHistogramSet* const image_histo,
       }
       if (do_eval) {
         // Re-evaluate the cost of an updated pair.
-        HistoQueueUpdatePair(histograms[p->idx1], histograms[p->idx2], 0., p);
-        if (p->cost_diff >= 0.) {
+        if (!HistoQueueUpdatePair(histograms[p->idx1], histograms[p->idx2], 0,
+                                  p)) {
           HistoQueuePopPair(&histo_queue, p);
           continue;
         }
@@ -1040,7 +1070,7 @@ static int HistogramCombineStochastic(VP8LHistogramSet* const image_histo,
 // Note: we assume that out[]->bit_cost_ is already up-to-date.
 static void HistogramRemap(const VP8LHistogramSet* const in,
                            VP8LHistogramSet* const out,
-                           uint16_t* const symbols) {
+                           uint32_t* const symbols) {
   int i;
   VP8LHistogram** const in_histo = in->histograms;
   VP8LHistogram** const out_histo = out->histograms;
@@ -1049,7 +1079,7 @@ static void HistogramRemap(const VP8LHistogramSet* const in,
   if (out_size > 1) {
     for (i = 0; i < in_size; ++i) {
       int best_out = 0;
-      float best_bits = MAX_BIT_COST;
+      int64_t best_bits = WEBP_INT64_MAX;
       int k;
       if (in_histo[i] == NULL) {
         // Arbitrarily set to the previous value if unused to help future LZ77.
@@ -1057,9 +1087,9 @@ static void HistogramRemap(const VP8LHistogramSet* const in,
         continue;
       }
       for (k = 0; k < out_size; ++k) {
-        float cur_bits;
-        cur_bits = HistogramAddThresh(out_histo[k], in_histo[i], best_bits);
-        if (k == 0 || cur_bits < best_bits) {
+        int64_t cur_bits;
+        if (HistogramAddThresh(out_histo[k], in_histo[i], best_bits,
+                               &cur_bits)) {
           best_bits = cur_bits;
           best_out = k;
         }
@@ -1085,13 +1115,13 @@ static void HistogramRemap(const VP8LHistogramSet* const in,
   }
 }
 
-static float GetCombineCostFactor(int histo_size, int quality) {
-  float combine_cost_factor = 0.16f;
+static int32_t GetCombineCostFactor(int histo_size, int quality) {
+  int32_t combine_cost_factor = 16;
   if (quality < 90) {
-    if (histo_size > 256) combine_cost_factor /= 2.f;
-    if (histo_size > 512) combine_cost_factor /= 2.f;
-    if (histo_size > 1024) combine_cost_factor /= 2.f;
-    if (quality <= 50) combine_cost_factor /= 2.f;
+    if (histo_size > 256) combine_cost_factor /= 2;
+    if (histo_size > 512) combine_cost_factor /= 2;
+    if (histo_size > 1024) combine_cost_factor /= 2;
+    if (quality <= 50) combine_cost_factor /= 2;
   }
   return combine_cost_factor;
 }
@@ -1101,10 +1131,10 @@ static float GetCombineCostFactor(int histo_size, int quality) {
 // assign the smallest possible clusters values.
 static void OptimizeHistogramSymbols(const VP8LHistogramSet* const set,
                                      uint16_t* const cluster_mappings,
-                                     int num_clusters,
+                                     uint32_t num_clusters,
                                      uint16_t* const cluster_mappings_tmp,
-                                     uint16_t* const symbols) {
-  int i, cluster_max;
+                                     uint32_t* const symbols) {
+  uint32_t i, cluster_max;
   int do_continue = 1;
   // First, assign the lowest cluster to each pixel.
   while (do_continue) {
@@ -1128,7 +1158,7 @@ static void OptimizeHistogramSymbols(const VP8LHistogramSet* const set,
          set->max_size * sizeof(*cluster_mappings_tmp));
   assert(cluster_mappings[0] == 0);
   // Re-map the ids.
-  for (i = 0; i < set->max_size; ++i) {
+  for (i = 0; i < (uint32_t)set->max_size; ++i) {
     int cluster;
     if (symbols[i] == kInvalidHistogramSymbol) continue;
     cluster = cluster_mappings[symbols[i]];
@@ -1142,7 +1172,7 @@ static void OptimizeHistogramSymbols(const VP8LHistogramSet* const set,
 
   // Make sure all cluster values are used.
   cluster_max = 0;
-  for (i = 0; i < set->max_size; ++i) {
+  for (i = 0; i < (uint32_t)set->max_size; ++i) {
     if (symbols[i] == kInvalidHistogramSymbol) continue;
     if (symbols[i] <= cluster_max) continue;
     ++cluster_max;
@@ -1165,7 +1195,7 @@ int VP8LGetHistoImageSymbols(int xsize, int ysize,
                              int low_effort, int histogram_bits, int cache_bits,
                              VP8LHistogramSet* const image_histo,
                              VP8LHistogram* const tmp_histo,
-                             uint16_t* const histogram_symbols,
+                             uint32_t* const histogram_symbols,
                              const WebPPicture* const pic, int percent_range,
                              int* const percent) {
   const int histo_xsize =
@@ -1181,7 +1211,7 @@ int VP8LGetHistoImageSymbols(int xsize, int ysize,
   const int entropy_combine_num_bins = low_effort ? NUM_PARTITIONS : BIN_SIZE;
   int entropy_combine;
   uint16_t* const map_tmp =
-      WebPSafeMalloc(2 * image_histo_raw_size, sizeof(*map_tmp));
+      (uint16_t*)WebPSafeMalloc(2 * image_histo_raw_size, sizeof(*map_tmp));
   uint16_t* const cluster_mappings = map_tmp + image_histo_raw_size;
   int num_used = image_histo_raw_size;
   if (orig_histo == NULL || map_tmp == NULL) {
@@ -1201,7 +1231,7 @@ int VP8LGetHistoImageSymbols(int xsize, int ysize,
 
   if (entropy_combine) {
     uint16_t* const bin_map = map_tmp;
-    const float combine_cost_factor =
+    const int32_t combine_cost_factor =
         GetCombineCostFactor(image_histo_raw_size, quality);
     const uint32_t num_clusters = num_used;
 
@@ -1217,9 +1247,10 @@ int VP8LGetHistoImageSymbols(int xsize, int ysize,
   // Don't combine the histograms using stochastic and greedy heuristics for
   // low-effort compression mode.
   if (!low_effort || !entropy_combine) {
-    const float x = quality / 100.f;
     // cubic ramp between 1 and MAX_HISTO_GREEDY:
-    const int threshold_size = (int)(1 + (x * x * x) * (MAX_HISTO_GREEDY - 1));
+    const int threshold_size =
+        (int)(1 + DivRound(quality * quality * quality * (MAX_HISTO_GREEDY - 1),
+                           100 * 100 * 100));
     int do_greedy;
     if (!HistogramCombineStochastic(image_histo, &num_used, threshold_size,
                                     &do_greedy)) {
diff --git a/src/enc/histogram_enc.h b/src/enc/histogram_enc.h
index 4c0bb974..772eac78 100644
--- a/src/enc/histogram_enc.h
+++ b/src/enc/histogram_enc.h
@@ -40,10 +40,10 @@ typedef struct {
   int palette_code_bits_;
   uint32_t trivial_symbol_;  // True, if histograms for Red, Blue & Alpha
                              // literal symbols are single valued.
-  float bit_cost_;           // cached value of bit cost.
-  float literal_cost_;       // Cached values of dominant entropy costs:
-  float red_cost_;           // literal, red & blue.
-  float blue_cost_;
+  uint64_t bit_cost_;        // cached value of bit cost.
+  uint64_t literal_cost_;    // Cached values of dominant entropy costs:
+  uint64_t red_cost_;        // literal, red & blue.
+  uint64_t blue_cost_;
   uint8_t is_used_[5];       // 5 for literal, red, blue, alpha, distance
 } VP8LHistogram;
 
@@ -64,9 +64,6 @@ void VP8LHistogramCreate(VP8LHistogram* const p,
                          const VP8LBackwardRefs* const refs,
                          int palette_code_bits);
 
-// Return the size of the histogram for a given cache_bits.
-int VP8LGetHistogramSize(int cache_bits);
-
 // Set the palette_code_bits and reset the stats.
 // If init_arrays is true, the arrays are also filled with 0's.
 void VP8LHistogramInit(VP8LHistogram* const p, int palette_code_bits,
@@ -112,16 +109,16 @@ int VP8LGetHistoImageSymbols(int xsize, int ysize,
                              int low_effort, int histogram_bits, int cache_bits,
                              VP8LHistogramSet* const image_histo,
                              VP8LHistogram* const tmp_histo,
-                             uint16_t* const histogram_symbols,
+                             uint32_t* const histogram_symbols,
                              const WebPPicture* const pic, int percent_range,
                              int* const percent);
 
 // Returns the entropy for the symbols in the input array.
-float VP8LBitsEntropy(const uint32_t* const array, int n);
+uint64_t VP8LBitsEntropy(const uint32_t* const array, int n);
 
 // Estimate how many bits the combined entropy of literals and distance
 // approximately maps to.
-float VP8LHistogramEstimateBits(VP8LHistogram* const p);
+uint64_t VP8LHistogramEstimateBits(VP8LHistogram* const p);
 
 #ifdef __cplusplus
 }
diff --git a/src/enc/iterator_enc.c b/src/enc/iterator_enc.c
index 29f91d83..eb83a327 100644
--- a/src/enc/iterator_enc.c
+++ b/src/enc/iterator_enc.c
@@ -13,6 +13,7 @@
 
 #include <string.h>
 
+#include "src/dsp/cpu.h"
 #include "src/enc/vp8i_enc.h"
 
 //------------------------------------------------------------------------------
@@ -54,7 +55,8 @@ void VP8IteratorSetRow(VP8EncIterator* const it, int y) {
   InitLeft(it);
 }
 
-void VP8IteratorReset(VP8EncIterator* const it) {
+// restart a scan
+static void VP8IteratorReset(VP8EncIterator* const it) {
   VP8Encoder* const enc = it->enc_;
   VP8IteratorSetRow(it, 0);
   VP8IteratorSetCountDown(it, enc->mb_w_ * enc->mb_h_);  // default
@@ -424,6 +426,15 @@ void VP8IteratorStartI4(VP8EncIterator* const it) {
       it->i4_boundary_[17 + i] = it->i4_boundary_[17 + 15];
     }
   }
+#if WEBP_AARCH64 && BPS == 32 && defined(WEBP_MSAN)
+  // Intra4Preds_NEON() reads 3 uninitialized bytes from i4_boundary_ when top
+  // is positioned at offset 29 (VP8TopLeftI4[3]). The values are not used
+  // meaningfully, but due to limitations in MemorySanitizer related to
+  // modeling of tbl instructions, a warning will be issued. This can be
+  // removed if MSan is updated to support the instructions. See
+  // https://issues.webmproject.org/372109644.
+  memset(it->i4_boundary_ + sizeof(it->i4_boundary_) - 3, 0xaa, 3);
+#endif
   VP8IteratorNzToBytes(it);  // import the non-zero context
 }
 
diff --git a/src/enc/predictor_enc.c b/src/enc/predictor_enc.c
index b3d44b59..a4eb1e44 100644
--- a/src/enc/predictor_enc.c
+++ b/src/enc/predictor_enc.c
@@ -14,53 +14,75 @@
 //          Urvang Joshi (urvang@google.com)
 //          Vincent Rabaud (vrabaud@google.com)
 
+#include <assert.h>
+#include <stdlib.h>
+#include <string.h>
+
 #include "src/dsp/lossless.h"
 #include "src/dsp/lossless_common.h"
 #include "src/enc/vp8i_enc.h"
 #include "src/enc/vp8li_enc.h"
+#include "src/utils/utils.h"
+#include "src/webp/encode.h"
+#include "src/webp/format_constants.h"
+#include "src/webp/types.h"
 
-#define MAX_DIFF_COST (1e30f)
-
-static const float kSpatialPredictorBias = 15.f;
+#define HISTO_SIZE (4 * 256)
+static const int64_t kSpatialPredictorBias = 15ll << LOG_2_PRECISION_BITS;
 static const int kPredLowEffort = 11;
 static const uint32_t kMaskAlpha = 0xff000000;
+static const int kNumPredModes = 14;
 
 // Mostly used to reduce code size + readability
 static WEBP_INLINE int GetMin(int a, int b) { return (a > b) ? b : a; }
+static WEBP_INLINE int GetMax(int a, int b) { return (a < b) ? b : a; }
 
 //------------------------------------------------------------------------------
 // Methods to calculate Entropy (Shannon).
 
-static float PredictionCostSpatial(const int counts[256], int weight_0,
-                                   float exp_val) {
+// Compute a bias for prediction entropy using a global heuristic to favor
+// values closer to 0. Hence the final negative sign.
+// 'exp_val' has a scaling factor of 1/100.
+static int64_t PredictionCostBias(const uint32_t counts[256], uint64_t weight_0,
+                                  uint64_t exp_val) {
   const int significant_symbols = 256 >> 4;
-  const float exp_decay_factor = 0.6f;
-  float bits = (float)weight_0 * counts[0];
+  const uint64_t exp_decay_factor = 6;  // has a scaling factor of 1/10
+  uint64_t bits = (weight_0 * counts[0]) << LOG_2_PRECISION_BITS;
   int i;
+  exp_val <<= LOG_2_PRECISION_BITS;
   for (i = 1; i < significant_symbols; ++i) {
-    bits += exp_val * (counts[i] + counts[256 - i]);
-    exp_val *= exp_decay_factor;
+    bits += DivRound(exp_val * (counts[i] + counts[256 - i]), 100);
+    exp_val = DivRound(exp_decay_factor * exp_val, 10);
   }
-  return (float)(-0.1 * bits);
+  return -DivRound((int64_t)bits, 10);
 }
 
-static float PredictionCostSpatialHistogram(const int accumulated[4][256],
-                                            const int tile[4][256]) {
+static int64_t PredictionCostSpatialHistogram(
+    const uint32_t accumulated[HISTO_SIZE], const uint32_t tile[HISTO_SIZE],
+    int mode, int left_mode, int above_mode) {
   int i;
-  float retval = 0.f;
+  int64_t retval = 0;
   for (i = 0; i < 4; ++i) {
-    const float kExpValue = 0.94f;
-    retval += PredictionCostSpatial(tile[i], 1, kExpValue);
-    retval += VP8LCombinedShannonEntropy(tile[i], accumulated[i]);
+    const uint64_t kExpValue = 94;
+    retval += PredictionCostBias(&tile[i * 256], 1, kExpValue);
+    // Compute the new cost if 'tile' is added to 'accumulate' but also add the
+    // cost of the current histogram to guide the spatial predictor selection.
+    // Basically, favor low entropy, locally and globally.
+    retval += (int64_t)VP8LCombinedShannonEntropy(&tile[i * 256],
+                                                  &accumulated[i * 256]);
   }
-  return (float)retval;
+  // Favor keeping the areas locally similar.
+  if (mode == left_mode) retval -= kSpatialPredictorBias;
+  if (mode == above_mode) retval -= kSpatialPredictorBias;
+  return retval;
 }
 
-static WEBP_INLINE void UpdateHisto(int histo_argb[4][256], uint32_t argb) {
-  ++histo_argb[0][argb >> 24];
-  ++histo_argb[1][(argb >> 16) & 0xff];
-  ++histo_argb[2][(argb >> 8) & 0xff];
-  ++histo_argb[3][argb & 0xff];
+static WEBP_INLINE void UpdateHisto(uint32_t histo_argb[HISTO_SIZE],
+                                    uint32_t argb) {
+  ++histo_argb[0 * 256 + (argb >> 24)];
+  ++histo_argb[1 * 256 + ((argb >> 16) & 0xff)];
+  ++histo_argb[2 * 256 + ((argb >> 8) & 0xff)];
+  ++histo_argb[3 * 256 + (argb & 0xff)];
 }
 
 //------------------------------------------------------------------------------
@@ -91,8 +113,6 @@ static WEBP_INLINE void PredictBatch(int mode, int x_start, int y,
 }
 
 #if (WEBP_NEAR_LOSSLESS == 1)
-static WEBP_INLINE int GetMax(int a, int b) { return (a < b) ? b : a; }
-
 static int MaxDiffBetweenPixels(uint32_t p1, uint32_t p2) {
   const int diff_a = abs((int)(p1 >> 24) - (int)(p2 >> 24));
   const int diff_r = abs((int)((p1 >> 16) & 0xff) - (int)((p2 >> 16) & 0xff));
@@ -291,23 +311,80 @@ static WEBP_INLINE void GetResidual(
   }
 }
 
-// Returns best predictor and updates the accumulated histogram.
+// Accessors to residual histograms.
+static WEBP_INLINE uint32_t* GetHistoArgb(uint32_t* const all_histos,
+                                          int subsampling_index, int mode) {
+  return &all_histos[(subsampling_index * kNumPredModes + mode) * HISTO_SIZE];
+}
+
+static WEBP_INLINE const uint32_t* GetHistoArgbConst(
+    const uint32_t* const all_histos, int subsampling_index, int mode) {
+  return &all_histos[subsampling_index * kNumPredModes * HISTO_SIZE +
+                     mode * HISTO_SIZE];
+}
+
+// Accessors to accumulated residual histogram.
+static WEBP_INLINE uint32_t* GetAccumulatedHisto(uint32_t* all_accumulated,
+                                                 int subsampling_index) {
+  return &all_accumulated[subsampling_index * HISTO_SIZE];
+}
+
+// Find and store the best predictor for a tile at subsampling
+// 'subsampling_index'.
+static void GetBestPredictorForTile(const uint32_t* const all_argb,
+                                    int subsampling_index, int tile_x,
+                                    int tile_y, int tiles_per_row,
+                                    uint32_t* all_accumulated_argb,
+                                    uint32_t** const all_modes,
+                                    uint32_t* const all_pred_histos) {
+  uint32_t* const accumulated_argb =
+      GetAccumulatedHisto(all_accumulated_argb, subsampling_index);
+  uint32_t* const modes = all_modes[subsampling_index];
+  uint32_t* const pred_histos =
+      &all_pred_histos[subsampling_index * kNumPredModes];
+  // Prediction modes of the left and above neighbor tiles.
+  const int left_mode =
+      (tile_x > 0) ? (modes[tile_y * tiles_per_row + tile_x - 1] >> 8) & 0xff
+                   : 0xff;
+  const int above_mode =
+      (tile_y > 0) ? (modes[(tile_y - 1) * tiles_per_row + tile_x] >> 8) & 0xff
+                   : 0xff;
+  int mode;
+  int64_t best_diff = WEBP_INT64_MAX;
+  uint32_t best_mode = 0;
+  const uint32_t* best_histo =
+      GetHistoArgbConst(all_argb, /*subsampling_index=*/0, best_mode);
+  for (mode = 0; mode < kNumPredModes; ++mode) {
+    const uint32_t* const histo_argb =
+        GetHistoArgbConst(all_argb, subsampling_index, mode);
+    const int64_t cur_diff = PredictionCostSpatialHistogram(
+        accumulated_argb, histo_argb, mode, left_mode, above_mode);
+
+    if (cur_diff < best_diff) {
+      best_histo = histo_argb;
+      best_diff = cur_diff;
+      best_mode = mode;
+    }
+  }
+  // Update the accumulated histogram.
+  VP8LAddVectorEq(best_histo, accumulated_argb, HISTO_SIZE);
+  modes[tile_y * tiles_per_row + tile_x] = ARGB_BLACK | (best_mode << 8);
+  ++pred_histos[best_mode];
+}
+
+// Computes the residuals for the different predictors.
 // If max_quantization > 1, assumes that near lossless processing will be
 // applied, quantizing residuals to multiples of quantization levels up to
 // max_quantization (the actual quantization level depends on smoothness near
 // the given pixel).
-static int GetBestPredictorForTile(int width, int height,
-                                   int tile_x, int tile_y, int bits,
-                                   int accumulated[4][256],
-                                   uint32_t* const argb_scratch,
-                                   const uint32_t* const argb,
-                                   int max_quantization,
-                                   int exact, int used_subtract_green,
-                                   const uint32_t* const modes) {
-  const int kNumPredModes = 14;
-  const int start_x = tile_x << bits;
-  const int start_y = tile_y << bits;
-  const int tile_size = 1 << bits;
+static void ComputeResidualsForTile(
+    int width, int height, int tile_x, int tile_y, int min_bits,
+    uint32_t update_up_to_index, uint32_t* const all_argb,
+    uint32_t* const argb_scratch, const uint32_t* const argb,
+    int max_quantization, int exact, int used_subtract_green) {
+  const int start_x = tile_x << min_bits;
+  const int start_y = tile_y << min_bits;
+  const int tile_size = 1 << min_bits;
   const int max_y = GetMin(tile_size, height - start_y);
   const int max_x = GetMin(tile_size, width - start_x);
   // Whether there exist columns just outside the tile.
@@ -318,35 +395,20 @@ static int GetBestPredictorForTile(int width, int height,
 #if (WEBP_NEAR_LOSSLESS == 1)
   const int context_width = max_x + have_left + (max_x < width - start_x);
 #endif
-  const int tiles_per_row = VP8LSubSampleSize(width, bits);
-  // Prediction modes of the left and above neighbor tiles.
-  const int left_mode = (tile_x > 0) ?
-      (modes[tile_y * tiles_per_row + tile_x - 1] >> 8) & 0xff : 0xff;
-  const int above_mode = (tile_y > 0) ?
-      (modes[(tile_y - 1) * tiles_per_row + tile_x] >> 8) & 0xff : 0xff;
   // The width of upper_row and current_row is one pixel larger than image width
   // to allow the top right pixel to point to the leftmost pixel of the next row
   // when at the right edge.
   uint32_t* upper_row = argb_scratch;
   uint32_t* current_row = upper_row + width + 1;
   uint8_t* const max_diffs = (uint8_t*)(current_row + width + 1);
-  float best_diff = MAX_DIFF_COST;
-  int best_mode = 0;
   int mode;
-  int histo_stack_1[4][256];
-  int histo_stack_2[4][256];
   // Need pointers to be able to swap arrays.
-  int (*histo_argb)[256] = histo_stack_1;
-  int (*best_histo)[256] = histo_stack_2;
-  int i, j;
   uint32_t residuals[1 << MAX_TRANSFORM_BITS];
-  assert(bits <= MAX_TRANSFORM_BITS);
   assert(max_x <= (1 << MAX_TRANSFORM_BITS));
-
   for (mode = 0; mode < kNumPredModes; ++mode) {
-    float cur_diff;
     int relative_y;
-    memset(histo_argb, 0, sizeof(histo_stack_1));
+    uint32_t* const histo_argb =
+        GetHistoArgb(all_argb, /*subsampling_index=*/0, mode);
     if (start_y > 0) {
       // Read the row above the tile which will become the first upper_row.
       // Include a pixel to the left if it exists; include a pixel to the right
@@ -382,41 +444,31 @@ static int GetBestPredictorForTile(int width, int height,
       for (relative_x = 0; relative_x < max_x; ++relative_x) {
         UpdateHisto(histo_argb, residuals[relative_x]);
       }
-    }
-    cur_diff = PredictionCostSpatialHistogram(
-        (const int (*)[256])accumulated, (const int (*)[256])histo_argb);
-    // Favor keeping the areas locally similar.
-    if (mode == left_mode) cur_diff -= kSpatialPredictorBias;
-    if (mode == above_mode) cur_diff -= kSpatialPredictorBias;
-
-    if (cur_diff < best_diff) {
-      int (*tmp)[256] = histo_argb;
-      histo_argb = best_histo;
-      best_histo = tmp;
-      best_diff = cur_diff;
-      best_mode = mode;
-    }
-  }
-
-  for (i = 0; i < 4; i++) {
-    for (j = 0; j < 256; j++) {
-      accumulated[i][j] += best_histo[i][j];
+      if (update_up_to_index > 0) {
+        uint32_t subsampling_index;
+        for (subsampling_index = 1; subsampling_index <= update_up_to_index;
+             ++subsampling_index) {
+          uint32_t* const super_histo =
+              GetHistoArgb(all_argb, subsampling_index, mode);
+          for (relative_x = 0; relative_x < max_x; ++relative_x) {
+            UpdateHisto(super_histo, residuals[relative_x]);
+          }
+        }
+      }
     }
   }
-
-  return best_mode;
 }
 
 // Converts pixels of the image to residuals with respect to predictions.
 // If max_quantization > 1, applies near lossless processing, quantizing
 // residuals to multiples of quantization levels up to max_quantization
 // (the actual quantization level depends on smoothness near the given pixel).
-static void CopyImageWithPrediction(int width, int height,
-                                    int bits, uint32_t* const modes,
+static void CopyImageWithPrediction(int width, int height, int bits,
+                                    const uint32_t* const modes,
                                     uint32_t* const argb_scratch,
-                                    uint32_t* const argb,
-                                    int low_effort, int max_quantization,
-                                    int exact, int used_subtract_green) {
+                                    uint32_t* const argb, int low_effort,
+                                    int max_quantization, int exact,
+                                    int used_subtract_green) {
   const int tiles_per_row = VP8LSubSampleSize(width, bits);
   // The width of upper_row and current_row is one pixel larger than image width
   // to allow the top right pixel to point to the leftmost pixel of the next row
@@ -469,47 +521,307 @@ static void CopyImageWithPrediction(int width, int height,
   }
 }
 
+// Checks whether 'image' can be subsampled by finding the biggest power of 2
+// squares (defined by 'best_bits') of uniform value it is made out of.
+void VP8LOptimizeSampling(uint32_t* const image, int full_width,
+                          int full_height, int bits, int max_bits,
+                          int* best_bits_out) {
+  int width = VP8LSubSampleSize(full_width, bits);
+  int height = VP8LSubSampleSize(full_height, bits);
+  int old_width, x, y, square_size;
+  int best_bits = bits;
+  *best_bits_out = bits;
+  // Check rows first.
+  while (best_bits < max_bits) {
+    const int new_square_size = 1 << (best_bits + 1 - bits);
+    int is_good = 1;
+    square_size = 1 << (best_bits - bits);
+    for (y = 0; y + square_size < height; y += new_square_size) {
+      // Check the first lines of consecutive line groups.
+      if (memcmp(&image[y * width], &image[(y + square_size) * width],
+                 width * sizeof(*image)) != 0) {
+        is_good = 0;
+        break;
+      }
+    }
+    if (is_good) {
+      ++best_bits;
+    } else {
+      break;
+    }
+  }
+  if (best_bits == bits) return;
+
+  // Check columns.
+  while (best_bits > bits) {
+    int is_good = 1;
+    square_size = 1 << (best_bits - bits);
+    for (y = 0; is_good && y < height; ++y) {
+      for (x = 0; is_good && x < width; x += square_size) {
+        int i;
+        for (i = x + 1; i < GetMin(x + square_size, width); ++i) {
+          if (image[y * width + i] != image[y * width + x]) {
+            is_good = 0;
+            break;
+          }
+        }
+      }
+    }
+    if (is_good) {
+      break;
+    }
+    --best_bits;
+  }
+  if (best_bits == bits) return;
+
+  // Subsample the image.
+  old_width = width;
+  square_size = 1 << (best_bits - bits);
+  width = VP8LSubSampleSize(full_width, best_bits);
+  height = VP8LSubSampleSize(full_height, best_bits);
+  for (y = 0; y < height; ++y) {
+    for (x = 0; x < width; ++x) {
+      image[y * width + x] = image[square_size * (y * old_width + x)];
+    }
+  }
+  *best_bits_out = best_bits;
+}
+
+// Computes the best predictor image.
+// Finds the best predictors per tile. Once done, finds the best predictor image
+// sampling.
+// best_bits is set to 0 in case of error.
+// The following requires some glossary:
+// - a tile is a square of side 2^min_bits pixels.
+// - a super-tile of a tile is a square of side 2^bits pixels with bits in
+// [min_bits+1, max_bits].
+// - the max-tile of a tile is the square of 2^max_bits pixels containing it.
+//   If this max-tile crosses the border of an image, it is cropped.
+// - tile, super-tiles and max_tile are aligned on powers of 2 in the original
+//   image.
+// - coordinates for tile, super-tile, max-tile are respectively named
+//   tile_x, super_tile_x, max_tile_x at their bit scale.
+// - in the max-tile, a tile has local coordinates (local_tile_x, local_tile_y).
+// The tiles are processed in the following zigzag order to complete the
+// super-tiles as soon as possible:
+//   1  2|  5  6
+//   3  4|  7  8
+// --------------
+//   9 10| 13 14
+//  11 12| 15 16
+// When computing the residuals for a tile, the histogram of the above
+// super-tile is updated. If this super-tile is finished, its histogram is used
+// to update the histogram of the next super-tile and so on up to the max-tile.
+static void GetBestPredictorsAndSubSampling(
+    int width, int height, const int min_bits, const int max_bits,
+    uint32_t* const argb_scratch, const uint32_t* const argb,
+    int max_quantization, int exact, int used_subtract_green,
+    const WebPPicture* const pic, int percent_range, int* const percent,
+    uint32_t** const all_modes, int* best_bits, uint32_t** best_mode) {
+  const uint32_t tiles_per_row = VP8LSubSampleSize(width, min_bits);
+  const uint32_t tiles_per_col = VP8LSubSampleSize(height, min_bits);
+  int64_t best_cost;
+  uint32_t subsampling_index;
+  const uint32_t max_subsampling_index = max_bits - min_bits;
+  // Compute the needed memory size for residual histograms, accumulated
+  // residual histograms and predictor histograms.
+  const int num_argb = (max_subsampling_index + 1) * kNumPredModes * HISTO_SIZE;
+  const int num_accumulated_rgb = (max_subsampling_index + 1) * HISTO_SIZE;
+  const int num_predictors = (max_subsampling_index + 1) * kNumPredModes;
+  uint32_t* const raw_data = (uint32_t*)WebPSafeCalloc(
+      num_argb + num_accumulated_rgb + num_predictors, sizeof(uint32_t));
+  uint32_t* const all_argb = raw_data;
+  uint32_t* const all_accumulated_argb = all_argb + num_argb;
+  uint32_t* const all_pred_histos = all_accumulated_argb + num_accumulated_rgb;
+  const int max_tile_size = 1 << max_subsampling_index;  // in tile size
+  int percent_start = *percent;
+  // When using the residuals of a tile for its super-tiles, you can either:
+  // - use each residual to update the histogram of the super-tile, with a cost
+  //   of 4 * (1<<n)^2 increment operations (4 for the number of channels, and
+  //   (1<<n)^2 for the number of pixels in the tile)
+  // - use the histogram of the tile to update the histogram of the super-tile,
+  //   with a cost of HISTO_SIZE (1024)
+  // The first method is therefore faster until n==4. 'update_up_to_index'
+  // defines the maximum subsampling_index for which the residuals should be
+  // individually added to the super-tile histogram.
+  const uint32_t update_up_to_index =
+      GetMax(GetMin(4, max_bits), min_bits) - min_bits;
+  // Coordinates in the max-tile in tile units.
+  uint32_t local_tile_x = 0, local_tile_y = 0;
+  uint32_t max_tile_x = 0, max_tile_y = 0;
+  uint32_t tile_x = 0, tile_y = 0;
+
+  *best_bits = 0;
+  *best_mode = NULL;
+  if (raw_data == NULL) return;
+
+  while (tile_y < tiles_per_col) {
+    ComputeResidualsForTile(width, height, tile_x, tile_y, min_bits,
+                            update_up_to_index, all_argb, argb_scratch, argb,
+                            max_quantization, exact, used_subtract_green);
+
+    // Update all the super-tiles that are complete.
+    subsampling_index = 0;
+    while (1) {
+      const uint32_t super_tile_x = tile_x >> subsampling_index;
+      const uint32_t super_tile_y = tile_y >> subsampling_index;
+      const uint32_t super_tiles_per_row =
+          VP8LSubSampleSize(width, min_bits + subsampling_index);
+      GetBestPredictorForTile(all_argb, subsampling_index, super_tile_x,
+                              super_tile_y, super_tiles_per_row,
+                              all_accumulated_argb, all_modes, all_pred_histos);
+      if (subsampling_index == max_subsampling_index) break;
+
+      // Update the following super-tile histogram if it has not been updated
+      // yet.
+      ++subsampling_index;
+      if (subsampling_index > update_up_to_index &&
+          subsampling_index <= max_subsampling_index) {
+        VP8LAddVectorEq(
+            GetHistoArgbConst(all_argb, subsampling_index - 1, /*mode=*/0),
+            GetHistoArgb(all_argb, subsampling_index, /*mode=*/0),
+            HISTO_SIZE * kNumPredModes);
+      }
+      // Check whether the super-tile is not complete (if the smallest tile
+      // is not at the end of a line/column or at the beginning of a super-tile
+      // of size (1 << subsampling_index)).
+      if (!((tile_x == (tiles_per_row - 1) ||
+             (local_tile_x + 1) % (1 << subsampling_index) == 0) &&
+            (tile_y == (tiles_per_col - 1) ||
+             (local_tile_y + 1) % (1 << subsampling_index) == 0))) {
+        --subsampling_index;
+        // subsampling_index now is the index of the last finished super-tile.
+        break;
+      }
+    }
+    // Reset all the histograms belonging to finished tiles.
+    memset(all_argb, 0,
+           HISTO_SIZE * kNumPredModes * (subsampling_index + 1) *
+               sizeof(*all_argb));
+
+    if (subsampling_index == max_subsampling_index) {
+      // If a new max-tile is started.
+      if (tile_x == (tiles_per_row - 1)) {
+        max_tile_x = 0;
+        ++max_tile_y;
+      } else {
+        ++max_tile_x;
+      }
+      local_tile_x = 0;
+      local_tile_y = 0;
+    } else {
+      // Proceed with the Z traversal.
+      uint32_t coord_x = local_tile_x >> subsampling_index;
+      uint32_t coord_y = local_tile_y >> subsampling_index;
+      if (tile_x == (tiles_per_row - 1) && coord_x % 2 == 0) {
+        ++coord_y;
+      } else {
+        if (coord_x % 2 == 0) {
+          ++coord_x;
+        } else {
+          // Z traversal.
+          ++coord_y;
+          --coord_x;
+        }
+      }
+      local_tile_x = coord_x << subsampling_index;
+      local_tile_y = coord_y << subsampling_index;
+    }
+    tile_x = max_tile_x * max_tile_size + local_tile_x;
+    tile_y = max_tile_y * max_tile_size + local_tile_y;
+
+    if (tile_x == 0 &&
+        !WebPReportProgress(
+            pic, percent_start + percent_range * tile_y / tiles_per_col,
+            percent)) {
+      WebPSafeFree(raw_data);
+      return;
+    }
+  }
+
+  // Figure out the best sampling.
+  best_cost = WEBP_INT64_MAX;
+  for (subsampling_index = 0; subsampling_index <= max_subsampling_index;
+       ++subsampling_index) {
+    int plane;
+    const uint32_t* const accumulated =
+        GetAccumulatedHisto(all_accumulated_argb, subsampling_index);
+    int64_t cost = VP8LShannonEntropy(
+        &all_pred_histos[subsampling_index * kNumPredModes], kNumPredModes);
+    for (plane = 0; plane < 4; ++plane) {
+      cost += VP8LShannonEntropy(&accumulated[plane * 256], 256);
+    }
+    if (cost < best_cost) {
+      best_cost = cost;
+      *best_bits = min_bits + subsampling_index;
+      *best_mode = all_modes[subsampling_index];
+    }
+  }
+
+  WebPSafeFree(raw_data);
+
+  VP8LOptimizeSampling(*best_mode, width, height, *best_bits,
+                       MAX_TRANSFORM_BITS, best_bits);
+}
+
 // Finds the best predictor for each tile, and converts the image to residuals
 // with respect to predictions. If near_lossless_quality < 100, applies
 // near lossless processing, shaving off more bits of residuals for lower
 // qualities.
-int VP8LResidualImage(int width, int height, int bits, int low_effort,
-                      uint32_t* const argb, uint32_t* const argb_scratch,
-                      uint32_t* const image, int near_lossless_quality,
-                      int exact, int used_subtract_green,
-                      const WebPPicture* const pic, int percent_range,
-                      int* const percent) {
-  const int tiles_per_row = VP8LSubSampleSize(width, bits);
-  const int tiles_per_col = VP8LSubSampleSize(height, bits);
+int VP8LResidualImage(int width, int height, int min_bits, int max_bits,
+                      int low_effort, uint32_t* const argb,
+                      uint32_t* const argb_scratch, uint32_t* const image,
+                      int near_lossless_quality, int exact,
+                      int used_subtract_green, const WebPPicture* const pic,
+                      int percent_range, int* const percent,
+                      int* const best_bits) {
   int percent_start = *percent;
-  int tile_y;
-  int histo[4][256];
   const int max_quantization = 1 << VP8LNearLosslessBits(near_lossless_quality);
   if (low_effort) {
+    const int tiles_per_row = VP8LSubSampleSize(width, max_bits);
+    const int tiles_per_col = VP8LSubSampleSize(height, max_bits);
     int i;
     for (i = 0; i < tiles_per_row * tiles_per_col; ++i) {
       image[i] = ARGB_BLACK | (kPredLowEffort << 8);
     }
+    *best_bits = max_bits;
   } else {
-    memset(histo, 0, sizeof(histo));
-    for (tile_y = 0; tile_y < tiles_per_col; ++tile_y) {
-      int tile_x;
-      for (tile_x = 0; tile_x < tiles_per_row; ++tile_x) {
-        const int pred = GetBestPredictorForTile(
-            width, height, tile_x, tile_y, bits, histo, argb_scratch, argb,
-            max_quantization, exact, used_subtract_green, image);
-        image[tile_y * tiles_per_row + tile_x] = ARGB_BLACK | (pred << 8);
-      }
-
-      if (!WebPReportProgress(
-              pic, percent_start + percent_range * tile_y / tiles_per_col,
-              percent)) {
-        return 0;
-      }
+    // Allocate data to try all samplings from min_bits to max_bits.
+    int bits;
+    uint32_t sum_num_pixels = 0u;
+    uint32_t *modes_raw, *best_mode;
+    uint32_t* modes[MAX_TRANSFORM_BITS + 1];
+    uint32_t num_pixels[MAX_TRANSFORM_BITS + 1];
+    for (bits = min_bits; bits <= max_bits; ++bits) {
+      const int tiles_per_row = VP8LSubSampleSize(width, bits);
+      const int tiles_per_col = VP8LSubSampleSize(height, bits);
+      num_pixels[bits] = tiles_per_row * tiles_per_col;
+      sum_num_pixels += num_pixels[bits];
     }
+    modes_raw = (uint32_t*)WebPSafeMalloc(sum_num_pixels, sizeof(*modes_raw));
+    if (modes_raw == NULL) return 0;
+    // Have modes point to the right global memory modes_raw.
+    modes[min_bits] = modes_raw;
+    for (bits = min_bits + 1; bits <= max_bits; ++bits) {
+      modes[bits] = modes[bits - 1] + num_pixels[bits - 1];
+    }
+    // Find the best sampling.
+    GetBestPredictorsAndSubSampling(
+        width, height, min_bits, max_bits, argb_scratch, argb, max_quantization,
+        exact, used_subtract_green, pic, percent_range, percent,
+        &modes[min_bits], best_bits, &best_mode);
+    if (*best_bits == 0) {
+      WebPSafeFree(modes_raw);
+      return 0;
+    }
+    // Keep the best predictor image.
+    memcpy(image, best_mode,
+           VP8LSubSampleSize(width, *best_bits) *
+               VP8LSubSampleSize(height, *best_bits) * sizeof(*image));
+    WebPSafeFree(modes_raw);
   }
 
-  CopyImageWithPrediction(width, height, bits, image, argb_scratch, argb,
+  CopyImageWithPrediction(width, height, *best_bits, image, argb_scratch, argb,
                           low_effort, max_quantization, exact,
                           used_subtract_green);
   return WebPReportProgress(pic, percent_start + percent_range, percent);
@@ -539,48 +851,51 @@ static WEBP_INLINE uint32_t MultipliersToColorCode(
          m->green_to_red_;
 }
 
-static float PredictionCostCrossColor(const int accumulated[256],
-                                      const int counts[256]) {
+static int64_t PredictionCostCrossColor(const uint32_t accumulated[256],
+                                        const uint32_t counts[256]) {
   // Favor low entropy, locally and globally.
   // Favor small absolute values for PredictionCostSpatial
-  static const float kExpValue = 2.4f;
-  return VP8LCombinedShannonEntropy(counts, accumulated) +
-         PredictionCostSpatial(counts, 3, kExpValue);
+  static const uint64_t kExpValue = 240;
+  return (int64_t)VP8LCombinedShannonEntropy(counts, accumulated) +
+         PredictionCostBias(counts, 3, kExpValue);
 }
 
-static float GetPredictionCostCrossColorRed(
+static int64_t GetPredictionCostCrossColorRed(
     const uint32_t* argb, int stride, int tile_width, int tile_height,
     VP8LMultipliers prev_x, VP8LMultipliers prev_y, int green_to_red,
-    const int accumulated_red_histo[256]) {
-  int histo[256] = { 0 };
-  float cur_diff;
+    const uint32_t accumulated_red_histo[256]) {
+  uint32_t histo[256] = { 0 };
+  int64_t cur_diff;
 
   VP8LCollectColorRedTransforms(argb, stride, tile_width, tile_height,
                                 green_to_red, histo);
 
   cur_diff = PredictionCostCrossColor(accumulated_red_histo, histo);
   if ((uint8_t)green_to_red == prev_x.green_to_red_) {
-    cur_diff -= 3;  // favor keeping the areas locally similar
+    // favor keeping the areas locally similar
+    cur_diff -= 3ll << LOG_2_PRECISION_BITS;
   }
   if ((uint8_t)green_to_red == prev_y.green_to_red_) {
-    cur_diff -= 3;  // favor keeping the areas locally similar
+    // favor keeping the areas locally similar
+    cur_diff -= 3ll << LOG_2_PRECISION_BITS;
   }
   if (green_to_red == 0) {
-    cur_diff -= 3;
+    cur_diff -= 3ll << LOG_2_PRECISION_BITS;
   }
   return cur_diff;
 }
 
-static void GetBestGreenToRed(
-    const uint32_t* argb, int stride, int tile_width, int tile_height,
-    VP8LMultipliers prev_x, VP8LMultipliers prev_y, int quality,
-    const int accumulated_red_histo[256], VP8LMultipliers* const best_tx) {
+static void GetBestGreenToRed(const uint32_t* argb, int stride, int tile_width,
+                              int tile_height, VP8LMultipliers prev_x,
+                              VP8LMultipliers prev_y, int quality,
+                              const uint32_t accumulated_red_histo[256],
+                              VP8LMultipliers* const best_tx) {
   const int kMaxIters = 4 + ((7 * quality) >> 8);  // in range [4..6]
   int green_to_red_best = 0;
   int iter, offset;
-  float best_diff = GetPredictionCostCrossColorRed(
-      argb, stride, tile_width, tile_height, prev_x, prev_y,
-      green_to_red_best, accumulated_red_histo);
+  int64_t best_diff = GetPredictionCostCrossColorRed(
+      argb, stride, tile_width, tile_height, prev_x, prev_y, green_to_red_best,
+      accumulated_red_histo);
   for (iter = 0; iter < kMaxIters; ++iter) {
     // ColorTransformDelta is a 3.5 bit fixed point, so 32 is equal to
     // one in color computation. Having initial delta here as 1 is sufficient
@@ -589,7 +904,7 @@ static void GetBestGreenToRed(
     // Try a negative and a positive delta from the best known value.
     for (offset = -delta; offset <= delta; offset += 2 * delta) {
       const int green_to_red_cur = offset + green_to_red_best;
-      const float cur_diff = GetPredictionCostCrossColorRed(
+      const int64_t cur_diff = GetPredictionCostCrossColorRed(
           argb, stride, tile_width, tile_height, prev_x, prev_y,
           green_to_red_cur, accumulated_red_histo);
       if (cur_diff < best_diff) {
@@ -601,45 +916,50 @@ static void GetBestGreenToRed(
   best_tx->green_to_red_ = (green_to_red_best & 0xff);
 }
 
-static float GetPredictionCostCrossColorBlue(
+static int64_t GetPredictionCostCrossColorBlue(
     const uint32_t* argb, int stride, int tile_width, int tile_height,
-    VP8LMultipliers prev_x, VP8LMultipliers prev_y,
-    int green_to_blue, int red_to_blue, const int accumulated_blue_histo[256]) {
-  int histo[256] = { 0 };
-  float cur_diff;
+    VP8LMultipliers prev_x, VP8LMultipliers prev_y, int green_to_blue,
+    int red_to_blue, const uint32_t accumulated_blue_histo[256]) {
+  uint32_t histo[256] = { 0 };
+  int64_t cur_diff;
 
   VP8LCollectColorBlueTransforms(argb, stride, tile_width, tile_height,
                                  green_to_blue, red_to_blue, histo);
 
   cur_diff = PredictionCostCrossColor(accumulated_blue_histo, histo);
   if ((uint8_t)green_to_blue == prev_x.green_to_blue_) {
-    cur_diff -= 3;  // favor keeping the areas locally similar
+    // favor keeping the areas locally similar
+    cur_diff -= 3ll << LOG_2_PRECISION_BITS;
   }
   if ((uint8_t)green_to_blue == prev_y.green_to_blue_) {
-    cur_diff -= 3;  // favor keeping the areas locally similar
+    // favor keeping the areas locally similar
+    cur_diff -= 3ll << LOG_2_PRECISION_BITS;
   }
   if ((uint8_t)red_to_blue == prev_x.red_to_blue_) {
-    cur_diff -= 3;  // favor keeping the areas locally similar
+    // favor keeping the areas locally similar
+    cur_diff -= 3ll << LOG_2_PRECISION_BITS;
   }
   if ((uint8_t)red_to_blue == prev_y.red_to_blue_) {
-    cur_diff -= 3;  // favor keeping the areas locally similar
+    // favor keeping the areas locally similar
+    cur_diff -= 3ll << LOG_2_PRECISION_BITS;
   }
   if (green_to_blue == 0) {
-    cur_diff -= 3;
+    cur_diff -= 3ll << LOG_2_PRECISION_BITS;
   }
   if (red_to_blue == 0) {
-    cur_diff -= 3;
+    cur_diff -= 3ll << LOG_2_PRECISION_BITS;
   }
   return cur_diff;
 }
 
 #define kGreenRedToBlueNumAxis 8
 #define kGreenRedToBlueMaxIters 7
-static void GetBestGreenRedToBlue(
-    const uint32_t* argb, int stride, int tile_width, int tile_height,
-    VP8LMultipliers prev_x, VP8LMultipliers prev_y, int quality,
-    const int accumulated_blue_histo[256],
-    VP8LMultipliers* const best_tx) {
+static void GetBestGreenRedToBlue(const uint32_t* argb, int stride,
+                                  int tile_width, int tile_height,
+                                  VP8LMultipliers prev_x,
+                                  VP8LMultipliers prev_y, int quality,
+                                  const uint32_t accumulated_blue_histo[256],
+                                  VP8LMultipliers* const best_tx) {
   const int8_t offset[kGreenRedToBlueNumAxis][2] =
       {{0, -1}, {0, 1}, {-1, 0}, {1, 0}, {-1, -1}, {-1, 1}, {1, -1}, {1, 1}};
   const int8_t delta_lut[kGreenRedToBlueMaxIters] = { 16, 16, 8, 4, 2, 2, 2 };
@@ -649,9 +969,9 @@ static void GetBestGreenRedToBlue(
   int red_to_blue_best = 0;
   int iter;
   // Initial value at origin:
-  float best_diff = GetPredictionCostCrossColorBlue(
-      argb, stride, tile_width, tile_height, prev_x, prev_y,
-      green_to_blue_best, red_to_blue_best, accumulated_blue_histo);
+  int64_t best_diff = GetPredictionCostCrossColorBlue(
+      argb, stride, tile_width, tile_height, prev_x, prev_y, green_to_blue_best,
+      red_to_blue_best, accumulated_blue_histo);
   for (iter = 0; iter < iters; ++iter) {
     const int delta = delta_lut[iter];
     int axis;
@@ -659,7 +979,7 @@ static void GetBestGreenRedToBlue(
       const int green_to_blue_cur =
           offset[axis][0] * delta + green_to_blue_best;
       const int red_to_blue_cur = offset[axis][1] * delta + red_to_blue_best;
-      const float cur_diff = GetPredictionCostCrossColorBlue(
+      const int64_t cur_diff = GetPredictionCostCrossColorBlue(
           argb, stride, tile_width, tile_height, prev_x, prev_y,
           green_to_blue_cur, red_to_blue_cur, accumulated_blue_histo);
       if (cur_diff < best_diff) {
@@ -684,13 +1004,10 @@ static void GetBestGreenRedToBlue(
 #undef kGreenRedToBlueNumAxis
 
 static VP8LMultipliers GetBestColorTransformForTile(
-    int tile_x, int tile_y, int bits,
-    VP8LMultipliers prev_x,
-    VP8LMultipliers prev_y,
-    int quality, int xsize, int ysize,
-    const int accumulated_red_histo[256],
-    const int accumulated_blue_histo[256],
-    const uint32_t* const argb) {
+    int tile_x, int tile_y, int bits, VP8LMultipliers prev_x,
+    VP8LMultipliers prev_y, int quality, int xsize, int ysize,
+    const uint32_t accumulated_red_histo[256],
+    const uint32_t accumulated_blue_histo[256], const uint32_t* const argb) {
   const int max_tile_size = 1 << bits;
   const int tile_y_offset = tile_y * max_tile_size;
   const int tile_x_offset = tile_x * max_tile_size;
@@ -728,13 +1045,13 @@ static void CopyTileWithColorTransform(int xsize, int ysize,
 int VP8LColorSpaceTransform(int width, int height, int bits, int quality,
                             uint32_t* const argb, uint32_t* image,
                             const WebPPicture* const pic, int percent_range,
-                            int* const percent) {
+                            int* const percent, int* const best_bits) {
   const int max_tile_size = 1 << bits;
   const int tile_xsize = VP8LSubSampleSize(width, bits);
   const int tile_ysize = VP8LSubSampleSize(height, bits);
   int percent_start = *percent;
-  int accumulated_red_histo[256] = { 0 };
-  int accumulated_blue_histo[256] = { 0 };
+  uint32_t accumulated_red_histo[256] = { 0 };
+  uint32_t accumulated_blue_histo[256] = { 0 };
   int tile_x, tile_y;
   VP8LMultipliers prev_x, prev_y;
   MultipliersClear(&prev_y);
@@ -788,5 +1105,7 @@ int VP8LColorSpaceTransform(int width, int height, int bits, int quality,
       return 0;
     }
   }
+  VP8LOptimizeSampling(image, width, height, bits, MAX_TRANSFORM_BITS,
+                       best_bits);
   return 1;
 }
diff --git a/src/enc/quant_enc.c b/src/enc/quant_enc.c
index 6d8202d2..d1c60620 100644
--- a/src/enc/quant_enc.c
+++ b/src/enc/quant_enc.c
@@ -462,7 +462,7 @@ const uint16_t VP8I16ModeOffsets[4] = { I16DC16, I16TM16, I16VE16, I16HE16 };
 const uint16_t VP8UVModeOffsets[4] = { C8DC8, C8TM8, C8VE8, C8HE8 };
 
 // Must be indexed using {B_DC_PRED -> B_HU_PRED} as index
-const uint16_t VP8I4ModeOffsets[NUM_BMODES] = {
+static const uint16_t VP8I4ModeOffsets[NUM_BMODES] = {
   I4DC4, I4TM4, I4VE4, I4HE4, I4RD4, I4VR4, I4LD4, I4VL4, I4HD4, I4HU4
 };
 
@@ -478,7 +478,9 @@ void VP8MakeChroma8Preds(const VP8EncIterator* const it) {
   VP8EncPredChroma8(it->yuv_p_, left, top);
 }
 
-void VP8MakeIntra4Preds(const VP8EncIterator* const it) {
+// Form all the ten Intra4x4 predictions in the yuv_p_ cache
+// for the 4x4 block it->i4_
+static void MakeIntra4Preds(const VP8EncIterator* const it) {
   VP8EncPredLuma4(it->yuv_p_, it->i4_top_);
 }
 
@@ -1099,7 +1101,7 @@ static int PickBestIntra4(VP8EncIterator* WEBP_RESTRICT const it,
     uint8_t* tmp_dst = it->yuv_p_ + I4TMP;    // scratch buffer.
 
     InitScore(&rd_i4);
-    VP8MakeIntra4Preds(it);
+    MakeIntra4Preds(it);
     for (mode = 0; mode < NUM_BMODES; ++mode) {
       VP8ModeScore rd_tmp;
       int16_t tmp_levels[16];
@@ -1234,7 +1236,7 @@ static void SimpleQuantize(VP8EncIterator* WEBP_RESTRICT const it,
           it->preds_[(it->i4_ & 3) + (it->i4_ >> 2) * enc->preds_w_];
       const uint8_t* const src = it->yuv_in_ + Y_OFF_ENC + VP8Scan[it->i4_];
       uint8_t* const dst = it->yuv_out_ + Y_OFF_ENC + VP8Scan[it->i4_];
-      VP8MakeIntra4Preds(it);
+      MakeIntra4Preds(it);
       nz |= ReconstructIntra4(it, rd->y_ac_levels[it->i4_],
                               src, dst, mode) << it->i4_;
     } while (VP8IteratorRotateI4(it, it->yuv_out_ + Y_OFF_ENC));
@@ -1302,7 +1304,7 @@ static void RefineUsingDistortion(VP8EncIterator* WEBP_RESTRICT const it,
       const uint8_t* const src = it->yuv_in_ + Y_OFF_ENC + VP8Scan[it->i4_];
       const uint16_t* const mode_costs = GetCostModeI4(it, rd->modes_i4);
 
-      VP8MakeIntra4Preds(it);
+      MakeIntra4Preds(it);
       for (mode = 0; mode < NUM_BMODES; ++mode) {
         const uint8_t* const ref = it->yuv_p_ + VP8I4ModeOffsets[mode];
         const score_t score = VP8SSE4x4(src, ref) * RD_DISTO_MULT
diff --git a/src/enc/vp8i_enc.h b/src/enc/vp8i_enc.h
index 00ff1be7..9d32bdab 100644
--- a/src/enc/vp8i_enc.h
+++ b/src/enc/vp8i_enc.h
@@ -16,6 +16,7 @@
 
 #include <string.h>     // for memcpy()
 #include "src/dec/common_dec.h"
+#include "src/dsp/cpu.h"
 #include "src/dsp/dsp.h"
 #include "src/utils/bit_writer_utils.h"
 #include "src/utils/thread_utils.h"
@@ -31,7 +32,7 @@ extern "C" {
 
 // version numbers
 #define ENC_MAJ_VERSION 1
-#define ENC_MIN_VERSION 4
+#define ENC_MIN_VERSION 5
 #define ENC_REV_VERSION 0
 
 enum { MAX_LF_LEVELS = 64,       // Maximum loop filter level
@@ -78,7 +79,6 @@ typedef enum {   // Rate-distortion optimization levels
 extern const uint16_t VP8Scan[16];
 extern const uint16_t VP8UVModeOffsets[4];
 extern const uint16_t VP8I16ModeOffsets[4];
-extern const uint16_t VP8I4ModeOffsets[NUM_BMODES];
 
 // Layout of prediction blocks
 // intra 16x16
@@ -234,7 +234,11 @@ typedef struct {
   VP8BitWriter* bw_;               // current bit-writer
   uint8_t*      preds_;            // intra mode predictors (4x4 blocks)
   uint32_t*     nz_;               // non-zero pattern
+#if WEBP_AARCH64 && BPS == 32
+  uint8_t       i4_boundary_[40];  // 32+8 boundary samples needed by intra4x4
+#else
   uint8_t       i4_boundary_[37];  // 32+5 boundary samples needed by intra4x4
+#endif
   uint8_t*      i4_top_;           // pointer to the current top boundary sample
   int           i4_;               // current intra4x4 mode being tested
   int           top_nz_[9];        // top-non-zero context.
@@ -267,8 +271,6 @@ typedef struct {
   // in iterator.c
 // must be called first
 void VP8IteratorInit(VP8Encoder* const enc, VP8EncIterator* const it);
-// restart a scan
-void VP8IteratorReset(VP8EncIterator* const it);
 // reset iterator position to row 'y'
 void VP8IteratorSetRow(VP8EncIterator* const it, int y);
 // set count down (=number of iterations to go)
@@ -444,9 +446,6 @@ extern const uint8_t VP8Cat6[];
 void VP8MakeLuma16Preds(const VP8EncIterator* const it);
 // Form all the four Chroma8x8 predictions in the yuv_p_ cache
 void VP8MakeChroma8Preds(const VP8EncIterator* const it);
-// Form all the ten Intra4x4 predictions in the yuv_p_ cache
-// for the 4x4 block it->i4_
-void VP8MakeIntra4Preds(const VP8EncIterator* const it);
 // Rate calculation
 int VP8GetCostLuma16(VP8EncIterator* const it, const VP8ModeScore* const rd);
 int VP8GetCostLuma4(VP8EncIterator* const it, const int16_t levels[16]);
diff --git a/src/enc/vp8l_enc.c b/src/enc/vp8l_enc.c
index 40eafa41..ad03b5a6 100644
--- a/src/enc/vp8l_enc.c
+++ b/src/enc/vp8l_enc.c
@@ -30,6 +30,10 @@
 
 // Maximum number of histogram images (sub-blocks).
 #define MAX_HUFF_IMAGE_SIZE       2600
+#define MAX_HUFFMAN_BITS (MIN_HUFFMAN_BITS + (1 << NUM_HUFFMAN_BITS) - 1)
+// Empirical value for which it becomes too computationally expensive to
+// compute the best predictor image.
+#define MAX_PREDICTOR_IMAGE_SIZE (1 << 14)
 
 // -----------------------------------------------------------------------------
 // Palette
@@ -140,8 +144,8 @@ static int AnalyzeEntropy(const uint32_t* argb,
       curr_row += argb_stride;
     }
     {
-      float entropy_comp[kHistoTotal];
-      float entropy[kNumEntropyIx];
+      uint64_t entropy_comp[kHistoTotal];
+      uint64_t entropy[kNumEntropyIx];
       int k;
       int last_mode_to_analyze = use_palette ? kPalette : kSpatialSubGreen;
       int j;
@@ -179,19 +183,19 @@ static int AnalyzeEntropy(const uint32_t* argb,
       // When including transforms, there is an overhead in bits from
       // storing them. This overhead is small but matters for small images.
       // For spatial, there are 14 transformations.
-      entropy[kSpatial] += VP8LSubSampleSize(width, transform_bits) *
+      entropy[kSpatial] += (uint64_t)VP8LSubSampleSize(width, transform_bits) *
                            VP8LSubSampleSize(height, transform_bits) *
                            VP8LFastLog2(14);
       // For color transforms: 24 as only 3 channels are considered in a
       // ColorTransformElement.
-      entropy[kSpatialSubGreen] += VP8LSubSampleSize(width, transform_bits) *
-                                   VP8LSubSampleSize(height, transform_bits) *
-                                   VP8LFastLog2(24);
+      entropy[kSpatialSubGreen] +=
+          (uint64_t)VP8LSubSampleSize(width, transform_bits) *
+          VP8LSubSampleSize(height, transform_bits) * VP8LFastLog2(24);
       // For palettes, add the cost of storing the palette.
       // We empirically estimate the cost of a compressed entry as 8 bits.
       // The palette is differential-coded when compressed hence a much
       // lower cost than sizeof(uint32_t)*8.
-      entropy[kPalette] += palette_size * 8;
+      entropy[kPalette] += (palette_size * 8ull) << LOG_2_PRECISION_BITS;
 
       *min_entropy_ix = kDirect;
       for (k = kDirect + 1; k <= last_mode_to_analyze; ++k) {
@@ -231,17 +235,33 @@ static int AnalyzeEntropy(const uint32_t* argb,
   }
 }
 
+// Clamp histogram and transform bits.
+static int ClampBits(int width, int height, int bits, int min_bits,
+                     int max_bits, int image_size_max) {
+  int image_size;
+  bits = (bits < min_bits) ? min_bits : (bits > max_bits) ? max_bits : bits;
+  image_size = VP8LSubSampleSize(width, bits) * VP8LSubSampleSize(height, bits);
+  while (bits < max_bits && image_size > image_size_max) {
+    ++bits;
+    image_size =
+        VP8LSubSampleSize(width, bits) * VP8LSubSampleSize(height, bits);
+  }
+  // In case the bits reduce the image too much, choose the smallest value
+  // setting the histogram image size to 1.
+  while (bits > min_bits && image_size == 1) {
+    image_size = VP8LSubSampleSize(width, bits - 1) *
+                 VP8LSubSampleSize(height, bits - 1);
+    if (image_size != 1) break;
+    --bits;
+  }
+  return bits;
+}
+
 static int GetHistoBits(int method, int use_palette, int width, int height) {
   // Make tile size a function of encoding method (Range: 0 to 6).
-  int histo_bits = (use_palette ? 9 : 7) - method;
-  while (1) {
-    const int huff_image_size = VP8LSubSampleSize(width, histo_bits) *
-                                VP8LSubSampleSize(height, histo_bits);
-    if (huff_image_size <= MAX_HUFF_IMAGE_SIZE) break;
-    ++histo_bits;
-  }
-  return (histo_bits < MIN_HUFFMAN_BITS) ? MIN_HUFFMAN_BITS :
-         (histo_bits > MAX_HUFFMAN_BITS) ? MAX_HUFFMAN_BITS : histo_bits;
+  const int histo_bits = (use_palette ? 9 : 7) - method;
+  return ClampBits(width, height, histo_bits, MIN_HUFFMAN_BITS,
+                   MAX_HUFFMAN_BITS, MAX_HUFF_IMAGE_SIZE);
 }
 
 static int GetTransformBits(int method, int histo_bits) {
@@ -280,7 +300,7 @@ static int EncoderAnalyze(VP8LEncoder* const enc,
   const int method = config->method;
   const int low_effort = (config->method == 0);
   int i;
-  int use_palette;
+  int use_palette, transform_bits;
   int n_lz77s;
   // If set to 0, analyze the cache with the computed cache value. If 1, also
   // analyze with no-cache.
@@ -297,7 +317,9 @@ static int EncoderAnalyze(VP8LEncoder* const enc,
   // Empirical bit sizes.
   enc->histo_bits_ = GetHistoBits(method, use_palette,
                                   pic->width, pic->height);
-  enc->transform_bits_ = GetTransformBits(method, enc->histo_bits_);
+  transform_bits = GetTransformBits(method, enc->histo_bits_);
+  enc->predictor_transform_bits_ = transform_bits;
+  enc->cross_color_transform_bits_ = transform_bits;
 
   if (low_effort) {
     // AnalyzeEntropy is somewhat slow.
@@ -311,8 +333,8 @@ static int EncoderAnalyze(VP8LEncoder* const enc,
     // Try out multiple LZ77 on images with few colors.
     n_lz77s = (enc->palette_size_ > 0 && enc->palette_size_ <= 16) ? 2 : 1;
     if (!AnalyzeEntropy(pic->argb, width, height, pic->argb_stride, use_palette,
-                        enc->palette_size_, enc->transform_bits_,
-                        &min_entropy_ix, red_and_blue_always_zero)) {
+                        enc->palette_size_, transform_bits, &min_entropy_ix,
+                        red_and_blue_always_zero)) {
       return 0;
     }
     if (method == 6 && config->quality == 100) {
@@ -661,11 +683,12 @@ static WEBP_INLINE void WriteHuffmanCodeWithExtraBits(
   VP8LPutBits(bw, (bits << depth) | symbol, depth + n_bits);
 }
 
-static int StoreImageToBitMask(
-    VP8LBitWriter* const bw, int width, int histo_bits,
-    const VP8LBackwardRefs* const refs,
-    const uint16_t* histogram_symbols,
-    const HuffmanTreeCode* const huffman_codes, const WebPPicture* const pic) {
+static int StoreImageToBitMask(VP8LBitWriter* const bw, int width,
+                               int histo_bits,
+                               const VP8LBackwardRefs* const refs,
+                               const uint32_t* histogram_symbols,
+                               const HuffmanTreeCode* const huffman_codes,
+                               const WebPPicture* const pic) {
   const int histo_xsize = histo_bits ? VP8LSubSampleSize(width, histo_bits) : 1;
   const int tile_mask = (histo_bits == 0) ? 0 : -(1 << histo_bits);
   // x and y trace the position in the image.
@@ -673,7 +696,7 @@ static int StoreImageToBitMask(
   int y = 0;
   int tile_x = x & tile_mask;
   int tile_y = y & tile_mask;
-  int histogram_ix = histogram_symbols[0];
+  int histogram_ix = (histogram_symbols[0] >> 8) & 0xffff;
   const HuffmanTreeCode* codes = huffman_codes + 5 * histogram_ix;
   VP8LRefsCursor c = VP8LRefsCursorInit(refs);
   while (VP8LRefsCursorOk(&c)) {
@@ -681,8 +704,10 @@ static int StoreImageToBitMask(
     if ((tile_x != (x & tile_mask)) || (tile_y != (y & tile_mask))) {
       tile_x = x & tile_mask;
       tile_y = y & tile_mask;
-      histogram_ix = histogram_symbols[(y >> histo_bits) * histo_xsize +
-                                       (x >> histo_bits)];
+      histogram_ix = (histogram_symbols[(y >> histo_bits) * histo_xsize +
+                                        (x >> histo_bits)] >>
+                      8) &
+                     0xffff;
       codes = huffman_codes + 5 * histogram_ix;
     }
     if (PixOrCopyIsLiteral(v)) {
@@ -738,7 +763,7 @@ static int EncodeImageNoHuffman(VP8LBitWriter* const bw,
   VP8LBackwardRefs* refs;
   HuffmanTreeToken* tokens = NULL;
   HuffmanTreeCode huffman_codes[5] = {{0, NULL, NULL}};
-  const uint16_t histogram_symbols[1] = {0};  // only one tree, one symbol
+  const uint32_t histogram_symbols[1] = {0};  // only one tree, one symbol
   int cache_bits = 0;
   VP8LHistogramSet* histogram_image = NULL;
   HuffmanTree* const huff_tree = (HuffmanTree*)WebPSafeMalloc(
@@ -821,32 +846,32 @@ static int EncodeImageInternal(
     VP8LBitWriter* const bw, const uint32_t* const argb,
     VP8LHashChain* const hash_chain, VP8LBackwardRefs refs_array[4], int width,
     int height, int quality, int low_effort, const CrunchConfig* const config,
-    int* cache_bits, int histogram_bits, size_t init_byte_position,
+    int* cache_bits, int histogram_bits_in, size_t init_byte_position,
     int* const hdr_size, int* const data_size, const WebPPicture* const pic,
     int percent_range, int* const percent) {
   const uint32_t histogram_image_xysize =
-      VP8LSubSampleSize(width, histogram_bits) *
-      VP8LSubSampleSize(height, histogram_bits);
+      VP8LSubSampleSize(width, histogram_bits_in) *
+      VP8LSubSampleSize(height, histogram_bits_in);
   int remaining_percent = percent_range;
   int percent_start = *percent;
   VP8LHistogramSet* histogram_image = NULL;
   VP8LHistogram* tmp_histo = NULL;
-  int histogram_image_size = 0;
+  uint32_t i, histogram_image_size = 0;
   size_t bit_array_size = 0;
   HuffmanTree* const huff_tree = (HuffmanTree*)WebPSafeMalloc(
       3ULL * CODE_LENGTH_CODES, sizeof(*huff_tree));
   HuffmanTreeToken* tokens = NULL;
   HuffmanTreeCode* huffman_codes = NULL;
-  uint16_t* const histogram_symbols = (uint16_t*)WebPSafeMalloc(
-      histogram_image_xysize, sizeof(*histogram_symbols));
+  uint32_t* const histogram_argb = (uint32_t*)WebPSafeMalloc(
+      histogram_image_xysize, sizeof(*histogram_argb));
   int sub_configs_idx;
   int cache_bits_init, write_histogram_image;
   VP8LBitWriter bw_init = *bw, bw_best;
   int hdr_size_tmp;
   VP8LHashChain hash_chain_histogram;  // histogram image hash chain
   size_t bw_size_best = ~(size_t)0;
-  assert(histogram_bits >= MIN_HUFFMAN_BITS);
-  assert(histogram_bits <= MAX_HUFFMAN_BITS);
+  assert(histogram_bits_in >= MIN_HUFFMAN_BITS);
+  assert(histogram_bits_in <= MAX_HUFFMAN_BITS);
   assert(hdr_size != NULL);
   assert(data_size != NULL);
 
@@ -857,7 +882,7 @@ static int EncodeImageInternal(
   }
 
   // Make sure we can allocate the different objects.
-  if (huff_tree == NULL || histogram_symbols == NULL ||
+  if (huff_tree == NULL || histogram_argb == NULL ||
       !VP8LHashChainInit(&hash_chain_histogram, histogram_image_xysize)) {
     WebPEncodingSetError(pic, VP8_ENC_ERROR_OUT_OF_MEMORY);
     goto Error;
@@ -899,6 +924,7 @@ static int EncodeImageInternal(
 
     for (i_cache = 0; i_cache < (sub_config->do_no_cache_ ? 2 : 1); ++i_cache) {
       const int cache_bits_tmp = (i_cache == 0) ? cache_bits_best : 0;
+      int histogram_bits = histogram_bits_in;
       // Speed-up: no need to study the no-cache case if it was already studied
       // in i_cache == 0.
       if (i_cache == 1 && cache_bits_best == 0) break;
@@ -920,7 +946,7 @@ static int EncodeImageInternal(
       if (!VP8LGetHistoImageSymbols(
               width, height, &refs_array[i_cache], quality, low_effort,
               histogram_bits, cache_bits_tmp, histogram_image, tmp_histo,
-              histogram_symbols, pic, i_percent_range, percent)) {
+              histogram_argb, pic, i_percent_range, percent)) {
         goto Error;
       }
       // Create Huffman bit lengths and codes for each histogram image.
@@ -953,26 +979,19 @@ static int EncodeImageInternal(
       }
 
       // Huffman image + meta huffman.
+      histogram_image_size = 0;
+      for (i = 0; i < histogram_image_xysize; ++i) {
+        if (histogram_argb[i] >= histogram_image_size) {
+          histogram_image_size = histogram_argb[i] + 1;
+        }
+        histogram_argb[i] <<= 8;
+      }
+
       write_histogram_image = (histogram_image_size > 1);
       VP8LPutBits(bw, write_histogram_image, 1);
       if (write_histogram_image) {
-        uint32_t* const histogram_argb = (uint32_t*)WebPSafeMalloc(
-            histogram_image_xysize, sizeof(*histogram_argb));
-        int max_index = 0;
-        uint32_t i;
-        if (histogram_argb == NULL) {
-          WebPEncodingSetError(pic, VP8_ENC_ERROR_OUT_OF_MEMORY);
-          goto Error;
-        }
-        for (i = 0; i < histogram_image_xysize; ++i) {
-          const int symbol_index = histogram_symbols[i] & 0xffff;
-          histogram_argb[i] = (symbol_index << 8);
-          if (symbol_index >= max_index) {
-            max_index = symbol_index + 1;
-          }
-        }
-        histogram_image_size = max_index;
-
+        VP8LOptimizeSampling(histogram_argb, width, height, histogram_bits_in,
+                             MAX_HUFFMAN_BITS, &histogram_bits);
         VP8LPutBits(bw, histogram_bits - 2, 3);
         i_percent_range = i_remaining_percent / 2;
         i_remaining_percent -= i_percent_range;
@@ -981,15 +1000,12 @@ static int EncodeImageInternal(
                 VP8LSubSampleSize(width, histogram_bits),
                 VP8LSubSampleSize(height, histogram_bits), quality, low_effort,
                 pic, i_percent_range, percent)) {
-          WebPSafeFree(histogram_argb);
           goto Error;
         }
-        WebPSafeFree(histogram_argb);
       }
 
       // Store Huffman codes.
       {
-        int i;
         int max_tokens = 0;
         // Find maximum number of symbols for the huffman tree-set.
         for (i = 0; i < 5 * histogram_image_size; ++i) {
@@ -1012,7 +1028,7 @@ static int EncodeImageInternal(
       // Store actual literals.
       hdr_size_tmp = (int)(VP8LBitWriterNumBytes(bw) - init_byte_position);
       if (!StoreImageToBitMask(bw, width, histogram_bits, &refs_array[i_cache],
-                               histogram_symbols, huffman_codes, pic)) {
+                               histogram_argb, huffman_codes, pic)) {
         goto Error;
       }
       // Keep track of the smallest image so far.
@@ -1049,7 +1065,7 @@ static int EncodeImageInternal(
     WebPSafeFree(huffman_codes->codes);
     WebPSafeFree(huffman_codes);
   }
-  WebPSafeFree(histogram_symbols);
+  WebPSafeFree(histogram_argb);
   VP8LBitWriterWipeOut(&bw_best);
   return (pic->error_code == VP8_ENC_OK);
 }
@@ -1064,54 +1080,60 @@ static void ApplySubtractGreen(VP8LEncoder* const enc, int width, int height,
   VP8LSubtractGreenFromBlueAndRed(enc->argb_, width * height);
 }
 
-static int ApplyPredictFilter(const VP8LEncoder* const enc, int width,
-                              int height, int quality, int low_effort,
+static int ApplyPredictFilter(VP8LEncoder* const enc, int width, int height,
+                              int quality, int low_effort,
                               int used_subtract_green, VP8LBitWriter* const bw,
                               int percent_range, int* const percent) {
-  const int pred_bits = enc->transform_bits_;
-  const int transform_width = VP8LSubSampleSize(width, pred_bits);
-  const int transform_height = VP8LSubSampleSize(height, pred_bits);
-  // we disable near-lossless quantization if palette is used.
+  int best_bits;
   const int near_lossless_strength =
       enc->use_palette_ ? 100 : enc->config_->near_lossless;
-
-  if (!VP8LResidualImage(
-          width, height, pred_bits, low_effort, enc->argb_, enc->argb_scratch_,
-          enc->transform_data_, near_lossless_strength, enc->config_->exact,
-          used_subtract_green, enc->pic_, percent_range / 2, percent)) {
+  const int max_bits = ClampBits(width, height, enc->predictor_transform_bits_,
+                                 MIN_TRANSFORM_BITS, MAX_TRANSFORM_BITS,
+                                 MAX_PREDICTOR_IMAGE_SIZE);
+  const int min_bits = ClampBits(
+      width, height,
+      max_bits - 2 * (enc->config_->method > 4 ? enc->config_->method - 4 : 0),
+      MIN_TRANSFORM_BITS, MAX_TRANSFORM_BITS, MAX_PREDICTOR_IMAGE_SIZE);
+
+  if (!VP8LResidualImage(width, height, min_bits, max_bits, low_effort,
+                         enc->argb_, enc->argb_scratch_, enc->transform_data_,
+                         near_lossless_strength, enc->config_->exact,
+                         used_subtract_green, enc->pic_, percent_range / 2,
+                         percent, &best_bits)) {
     return 0;
   }
   VP8LPutBits(bw, TRANSFORM_PRESENT, 1);
   VP8LPutBits(bw, PREDICTOR_TRANSFORM, 2);
-  assert(pred_bits >= 2);
-  VP8LPutBits(bw, pred_bits - 2, 3);
+  assert(best_bits >= MIN_TRANSFORM_BITS && best_bits <= MAX_TRANSFORM_BITS);
+  VP8LPutBits(bw, best_bits - MIN_TRANSFORM_BITS, NUM_TRANSFORM_BITS);
+  enc->predictor_transform_bits_ = best_bits;
   return EncodeImageNoHuffman(
-      bw, enc->transform_data_, (VP8LHashChain*)&enc->hash_chain_,
-      (VP8LBackwardRefs*)&enc->refs_[0], transform_width, transform_height,
+      bw, enc->transform_data_, &enc->hash_chain_, &enc->refs_[0],
+      VP8LSubSampleSize(width, best_bits), VP8LSubSampleSize(height, best_bits),
       quality, low_effort, enc->pic_, percent_range - percent_range / 2,
       percent);
 }
 
-static int ApplyCrossColorFilter(const VP8LEncoder* const enc, int width,
-                                 int height, int quality, int low_effort,
+static int ApplyCrossColorFilter(VP8LEncoder* const enc, int width, int height,
+                                 int quality, int low_effort,
                                  VP8LBitWriter* const bw, int percent_range,
                                  int* const percent) {
-  const int ccolor_transform_bits = enc->transform_bits_;
-  const int transform_width = VP8LSubSampleSize(width, ccolor_transform_bits);
-  const int transform_height = VP8LSubSampleSize(height, ccolor_transform_bits);
+  const int min_bits = enc->cross_color_transform_bits_;
+  int best_bits;
 
-  if (!VP8LColorSpaceTransform(width, height, ccolor_transform_bits, quality,
-                               enc->argb_, enc->transform_data_, enc->pic_,
-                               percent_range / 2, percent)) {
+  if (!VP8LColorSpaceTransform(width, height, min_bits, quality, enc->argb_,
+                               enc->transform_data_, enc->pic_,
+                               percent_range / 2, percent, &best_bits)) {
     return 0;
   }
   VP8LPutBits(bw, TRANSFORM_PRESENT, 1);
   VP8LPutBits(bw, CROSS_COLOR_TRANSFORM, 2);
-  assert(ccolor_transform_bits >= 2);
-  VP8LPutBits(bw, ccolor_transform_bits - 2, 3);
+  assert(best_bits >= MIN_TRANSFORM_BITS && best_bits <= MAX_TRANSFORM_BITS);
+  VP8LPutBits(bw, best_bits - MIN_TRANSFORM_BITS, NUM_TRANSFORM_BITS);
+  enc->cross_color_transform_bits_ = best_bits;
   return EncodeImageNoHuffman(
-      bw, enc->transform_data_, (VP8LHashChain*)&enc->hash_chain_,
-      (VP8LBackwardRefs*)&enc->refs_[0], transform_width, transform_height,
+      bw, enc->transform_data_, &enc->hash_chain_, &enc->refs_[0],
+      VP8LSubSampleSize(width, best_bits), VP8LSubSampleSize(height, best_bits),
       quality, low_effort, enc->pic_, percent_range - percent_range / 2,
       percent);
 }
@@ -1199,8 +1221,8 @@ static int AllocateTransformBuffer(VP8LEncoder* const enc, int width,
                         : 0;
   const uint64_t transform_data_size =
       (enc->use_predict_ || enc->use_cross_color_)
-          ? (uint64_t)VP8LSubSampleSize(width, enc->transform_bits_) *
-                VP8LSubSampleSize(height, enc->transform_bits_)
+          ? (uint64_t)VP8LSubSampleSize(width, MIN_TRANSFORM_BITS) *
+                VP8LSubSampleSize(height, MIN_TRANSFORM_BITS)
           : 0;
   const uint64_t max_alignment_in_words =
       (WEBP_ALIGN_CST + sizeof(uint32_t) - 1) / sizeof(uint32_t);
@@ -1374,13 +1396,11 @@ static int ApplyPalette(const uint32_t* src, uint32_t src_stride, uint32_t* dst,
 #undef APPLY_PALETTE_GREEDY_MAX
 
 // Note: Expects "enc->palette_" to be set properly.
-static int MapImageFromPalette(VP8LEncoder* const enc, int in_place) {
+static int MapImageFromPalette(VP8LEncoder* const enc) {
   const WebPPicture* const pic = enc->pic_;
   const int width = pic->width;
   const int height = pic->height;
   const uint32_t* const palette = enc->palette_;
-  const uint32_t* src = in_place ? enc->argb_ : pic->argb;
-  const int src_stride = in_place ? enc->current_width_ : pic->argb_stride;
   const int palette_size = enc->palette_size_;
   int xbits;
 
@@ -1395,9 +1415,9 @@ static int MapImageFromPalette(VP8LEncoder* const enc, int in_place) {
   if (!AllocateTransformBuffer(enc, VP8LSubSampleSize(width, xbits), height)) {
     return 0;
   }
-  if (!ApplyPalette(src, src_stride,
-                     enc->argb_, enc->current_width_,
-                     palette, palette_size, width, height, xbits, pic)) {
+  if (!ApplyPalette(pic->argb, pic->argb_stride, enc->argb_,
+                    enc->current_width_, palette, palette_size, width, height,
+                    xbits, pic)) {
     return 0;
   }
   enc->argb_content_ = kEncoderPalette;
@@ -1405,24 +1425,31 @@ static int MapImageFromPalette(VP8LEncoder* const enc, int in_place) {
 }
 
 // Save palette_[] to bitstream.
-static WebPEncodingError EncodePalette(VP8LBitWriter* const bw, int low_effort,
-                                       VP8LEncoder* const enc,
-                                       int percent_range, int* const percent) {
+static int EncodePalette(VP8LBitWriter* const bw, int low_effort,
+                         VP8LEncoder* const enc, int percent_range,
+                         int* const percent) {
   int i;
   uint32_t tmp_palette[MAX_PALETTE_SIZE];
   const int palette_size = enc->palette_size_;
   const uint32_t* const palette = enc->palette_;
+  // If the last element is 0, do not store it and count on automatic palette
+  // 0-filling. This can only happen if there is no pixel packing, hence if
+  // there are strictly more than 16 colors (after 0 is removed).
+  const uint32_t encoded_palette_size =
+      (enc->palette_[palette_size - 1] == 0 && palette_size > 17)
+          ? palette_size - 1
+          : palette_size;
   VP8LPutBits(bw, TRANSFORM_PRESENT, 1);
   VP8LPutBits(bw, COLOR_INDEXING_TRANSFORM, 2);
   assert(palette_size >= 1 && palette_size <= MAX_PALETTE_SIZE);
-  VP8LPutBits(bw, palette_size - 1, 8);
-  for (i = palette_size - 1; i >= 1; --i) {
+  VP8LPutBits(bw, encoded_palette_size - 1, 8);
+  for (i = encoded_palette_size - 1; i >= 1; --i) {
     tmp_palette[i] = VP8LSubPixels(palette[i], palette[i - 1]);
   }
   tmp_palette[0] = palette[0];
-  return EncodeImageNoHuffman(bw, tmp_palette, &enc->hash_chain_,
-                              &enc->refs_[0], palette_size, 1, /*quality=*/20,
-                              low_effort, enc->pic_, percent_range, percent);
+  return EncodeImageNoHuffman(
+      bw, tmp_palette, &enc->hash_chain_, &enc->refs_[0], encoded_palette_size,
+      1, /*quality=*/20, low_effort, enc->pic_, percent_range, percent);
 }
 
 // -----------------------------------------------------------------------------
@@ -1493,7 +1520,6 @@ static int EncodeStreamHook(void* input, void* data2) {
 #endif
   int hdr_size = 0;
   int data_size = 0;
-  int use_delta_palette = 0;
   int idx;
   size_t best_size = ~(size_t)0;
   VP8LBitWriter bw_init = *bw, bw_best;
@@ -1558,45 +1584,43 @@ static int EncodeStreamHook(void* input, void* data2) {
         goto Error;
       }
       remaining_percent -= percent_range;
-      if (!MapImageFromPalette(enc, use_delta_palette)) goto Error;
+      if (!MapImageFromPalette(enc)) goto Error;
       // If using a color cache, do not have it bigger than the number of
       // colors.
       if (enc->palette_size_ < (1 << MAX_COLOR_CACHE_BITS)) {
         enc->cache_bits_ = BitsLog2Floor(enc->palette_size_) + 1;
       }
     }
-    if (!use_delta_palette) {
-      // In case image is not packed.
-      if (enc->argb_content_ != kEncoderNearLossless &&
-          enc->argb_content_ != kEncoderPalette) {
-        if (!MakeInputImageCopy(enc)) goto Error;
-      }
+    // In case image is not packed.
+    if (enc->argb_content_ != kEncoderNearLossless &&
+        enc->argb_content_ != kEncoderPalette) {
+      if (!MakeInputImageCopy(enc)) goto Error;
+    }
 
-      // -----------------------------------------------------------------------
-      // Apply transforms and write transform data.
+    // -------------------------------------------------------------------------
+    // Apply transforms and write transform data.
 
-      if (enc->use_subtract_green_) {
-        ApplySubtractGreen(enc, enc->current_width_, height, bw);
-      }
+    if (enc->use_subtract_green_) {
+      ApplySubtractGreen(enc, enc->current_width_, height, bw);
+    }
 
-      if (enc->use_predict_) {
-        percent_range = remaining_percent / 3;
-        if (!ApplyPredictFilter(enc, enc->current_width_, height, quality,
-                                low_effort, enc->use_subtract_green_, bw,
-                                percent_range, &percent)) {
-          goto Error;
-        }
-        remaining_percent -= percent_range;
+    if (enc->use_predict_) {
+      percent_range = remaining_percent / 3;
+      if (!ApplyPredictFilter(enc, enc->current_width_, height, quality,
+                              low_effort, enc->use_subtract_green_, bw,
+                              percent_range, &percent)) {
+        goto Error;
       }
+      remaining_percent -= percent_range;
+    }
 
-      if (enc->use_cross_color_) {
-        percent_range = remaining_percent / 2;
-        if (!ApplyCrossColorFilter(enc, enc->current_width_, height, quality,
-                                   low_effort, bw, percent_range, &percent)) {
-          goto Error;
-        }
-        remaining_percent -= percent_range;
+    if (enc->use_cross_color_) {
+      percent_range = remaining_percent / 2;
+      if (!ApplyCrossColorFilter(enc, enc->current_width_, height, quality,
+                                 low_effort, bw, percent_range, &percent)) {
+        goto Error;
       }
+      remaining_percent -= percent_range;
     }
 
     VP8LPutBits(bw, !TRANSFORM_PRESENT, 1);  // No more transforms.
@@ -1625,7 +1649,8 @@ static int EncodeStreamHook(void* input, void* data2) {
         if (enc->use_subtract_green_) stats->lossless_features |= 4;
         if (enc->use_palette_) stats->lossless_features |= 8;
         stats->histogram_bits = enc->histo_bits_;
-        stats->transform_bits = enc->transform_bits_;
+        stats->transform_bits = enc->predictor_transform_bits_;
+        stats->cross_color_transform_bits = enc->cross_color_transform_bits_;
         stats->cache_bits = enc->cache_bits_;
         stats->palette_size = enc->palette_size_;
         stats->lossless_size = (int)(best_size - byte_position);
@@ -1735,7 +1760,10 @@ int VP8LEncodeStream(const WebPConfig* const config,
         }
         // Copy the values that were computed for the main encoder.
         enc_side->histo_bits_ = enc_main->histo_bits_;
-        enc_side->transform_bits_ = enc_main->transform_bits_;
+        enc_side->predictor_transform_bits_ =
+            enc_main->predictor_transform_bits_;
+        enc_side->cross_color_transform_bits_ =
+            enc_main->cross_color_transform_bits_;
         enc_side->palette_size_ = enc_main->palette_size_;
         memcpy(enc_side->palette_, enc_main->palette_,
                sizeof(enc_main->palette_));
diff --git a/src/enc/vp8li_enc.h b/src/enc/vp8li_enc.h
index c5b60dcb..1ba7d428 100644
--- a/src/enc/vp8li_enc.h
+++ b/src/enc/vp8li_enc.h
@@ -34,7 +34,7 @@ extern "C" {
 #endif
 
 // maximum value of transform_bits_ in VP8LEncoder.
-#define MAX_TRANSFORM_BITS 6
+#define MAX_TRANSFORM_BITS (MIN_TRANSFORM_BITS + (1 << NUM_TRANSFORM_BITS) - 1)
 
 typedef enum {
   kEncoderNone = 0,
@@ -59,7 +59,8 @@ typedef struct {
 
   // Encoding parameters derived from quality parameter.
   int histo_bits_;
-  int transform_bits_;    // <= MAX_TRANSFORM_BITS.
+  int predictor_transform_bits_;    // <= MAX_TRANSFORM_BITS
+  int cross_color_transform_bits_;  // <= MAX_TRANSFORM_BITS
   int cache_bits_;        // If equal to 0, don't use color cache.
 
   // Encoding parameters derived from image characteristics.
@@ -104,16 +105,21 @@ int VP8ApplyNearLossless(const WebPPicture* const picture, int quality,
 
 // pic and percent are for progress.
 // Returns false in case of error (stored in pic->error_code).
-int VP8LResidualImage(int width, int height, int bits, int low_effort,
-                      uint32_t* const argb, uint32_t* const argb_scratch,
-                      uint32_t* const image, int near_lossless, int exact,
-                      int used_subtract_green, const WebPPicture* const pic,
-                      int percent_range, int* const percent);
+int VP8LResidualImage(int width, int height, int min_bits, int max_bits,
+                      int low_effort, uint32_t* const argb,
+                      uint32_t* const argb_scratch, uint32_t* const image,
+                      int near_lossless, int exact, int used_subtract_green,
+                      const WebPPicture* const pic, int percent_range,
+                      int* const percent, int* const best_bits);
 
 int VP8LColorSpaceTransform(int width, int height, int bits, int quality,
                             uint32_t* const argb, uint32_t* image,
                             const WebPPicture* const pic, int percent_range,
-                            int* const percent);
+                            int* const percent, int* const best_bits);
+
+void VP8LOptimizeSampling(uint32_t* const image, int full_width,
+                          int full_height, int bits, int max_bits,
+                          int* best_bits_out);
 
 //------------------------------------------------------------------------------
 
diff --git a/src/libwebp.rc b/src/libwebp.rc
index d51536f5..92fd893a 100644
--- a/src/libwebp.rc
+++ b/src/libwebp.rc
@@ -6,8 +6,8 @@
 LANGUAGE LANG_ENGLISH, SUBLANG_ENGLISH_US
 
 VS_VERSION_INFO VERSIONINFO
- FILEVERSION 1,0,4,0
- PRODUCTVERSION 1,0,4,0
+ FILEVERSION 1,0,5,0
+ PRODUCTVERSION 1,0,5,0
  FILEFLAGSMASK 0x3fL
 #ifdef _DEBUG
  FILEFLAGS 0x1L
@@ -24,12 +24,12 @@ BEGIN
         BEGIN
             VALUE "CompanyName", "Google, Inc."
             VALUE "FileDescription", "libwebp DLL"
-            VALUE "FileVersion", "1.4.0"
+            VALUE "FileVersion", "1.5.0"
             VALUE "InternalName", "libwebp.dll"
             VALUE "LegalCopyright", "Copyright (C) 2024"
             VALUE "OriginalFilename", "libwebp.dll"
             VALUE "ProductName", "WebP Image Codec"
-            VALUE "ProductVersion", "1.4.0"
+            VALUE "ProductVersion", "1.5.0"
         END
     END
     BLOCK "VarFileInfo"
diff --git a/src/libwebpdecoder.rc b/src/libwebpdecoder.rc
index 3891488c..8e6e4c71 100644
--- a/src/libwebpdecoder.rc
+++ b/src/libwebpdecoder.rc
@@ -6,8 +6,8 @@
 LANGUAGE LANG_ENGLISH, SUBLANG_ENGLISH_US
 
 VS_VERSION_INFO VERSIONINFO
- FILEVERSION 1,0,4,0
- PRODUCTVERSION 1,0,4,0
+ FILEVERSION 1,0,5,0
+ PRODUCTVERSION 1,0,5,0
  FILEFLAGSMASK 0x3fL
 #ifdef _DEBUG
  FILEFLAGS 0x1L
@@ -24,12 +24,12 @@ BEGIN
         BEGIN
             VALUE "CompanyName", "Google, Inc."
             VALUE "FileDescription", "libwebpdecoder DLL"
-            VALUE "FileVersion", "1.4.0"
+            VALUE "FileVersion", "1.5.0"
             VALUE "InternalName", "libwebpdecoder.dll"
             VALUE "LegalCopyright", "Copyright (C) 2024"
             VALUE "OriginalFilename", "libwebpdecoder.dll"
             VALUE "ProductName", "WebP Image Decoder"
-            VALUE "ProductVersion", "1.4.0"
+            VALUE "ProductVersion", "1.5.0"
         END
     END
     BLOCK "VarFileInfo"
diff --git a/src/mux/Makefile.am b/src/mux/Makefile.am
index 18bc90e9..0512b649 100644
--- a/src/mux/Makefile.am
+++ b/src/mux/Makefile.am
@@ -17,6 +17,6 @@ noinst_HEADERS =
 noinst_HEADERS += ../webp/format_constants.h
 
 libwebpmux_la_LIBADD = ../libwebp.la
-libwebpmux_la_LDFLAGS = -no-undefined -version-info 4:0:1 -lm
+libwebpmux_la_LDFLAGS = -no-undefined -version-info 4:1:1 -lm
 libwebpmuxincludedir = $(includedir)/webp
 pkgconfig_DATA = libwebpmux.pc
diff --git a/src/mux/anim_encode.c b/src/mux/anim_encode.c
index 31bd0457..deeb414a 100644
--- a/src/mux/anim_encode.c
+++ b/src/mux/anim_encode.c
@@ -191,7 +191,8 @@ int WebPAnimEncoderOptionsInitInternal(WebPAnimEncoderOptions* enc_options,
   return 1;
 }
 
-// This starting value is more fit to WebPCleanupTransparentAreaLossless().
+// This value is used to match a later call to WebPReplaceTransparentPixels(),
+// making it a no-op for lossless (see WebPEncode()).
 #define TRANSPARENT_COLOR   0x00000000
 
 static void ClearRectangle(WebPPicture* const picture,
diff --git a/src/mux/libwebpmux.rc b/src/mux/libwebpmux.rc
index 1b20fac1..60be5efc 100644
--- a/src/mux/libwebpmux.rc
+++ b/src/mux/libwebpmux.rc
@@ -6,8 +6,8 @@
 LANGUAGE LANG_ENGLISH, SUBLANG_ENGLISH_US
 
 VS_VERSION_INFO VERSIONINFO
- FILEVERSION 1,0,4,0
- PRODUCTVERSION 1,0,4,0
+ FILEVERSION 1,0,5,0
+ PRODUCTVERSION 1,0,5,0
  FILEFLAGSMASK 0x3fL
 #ifdef _DEBUG
  FILEFLAGS 0x1L
@@ -24,12 +24,12 @@ BEGIN
         BEGIN
             VALUE "CompanyName", "Google, Inc."
             VALUE "FileDescription", "libwebpmux DLL"
-            VALUE "FileVersion", "1.4.0"
+            VALUE "FileVersion", "1.5.0"
             VALUE "InternalName", "libwebpmux.dll"
             VALUE "LegalCopyright", "Copyright (C) 2024"
             VALUE "OriginalFilename", "libwebpmux.dll"
             VALUE "ProductName", "WebP Image Muxer"
-            VALUE "ProductVersion", "1.4.0"
+            VALUE "ProductVersion", "1.5.0"
         END
     END
     BLOCK "VarFileInfo"
diff --git a/src/mux/muxi.h b/src/mux/muxi.h
index 74ae3fac..3c542f93 100644
--- a/src/mux/muxi.h
+++ b/src/mux/muxi.h
@@ -28,7 +28,7 @@ extern "C" {
 // Defines and constants.
 
 #define MUX_MAJ_VERSION 1
-#define MUX_MIN_VERSION 4
+#define MUX_MIN_VERSION 5
 #define MUX_REV_VERSION 0
 
 // Chunk object.
diff --git a/src/mux/muxread.c b/src/mux/muxread.c
index afd3542e..aa406c1a 100644
--- a/src/mux/muxread.c
+++ b/src/mux/muxread.c
@@ -223,11 +223,13 @@ WebPMux* WebPMuxCreateInternal(const WebPData* bitstream, int copy_data,
   // Note this padding is historical and differs from demux.c which does not
   // pad the file size.
   riff_size = SizeWithPadding(riff_size);
-  if (riff_size < CHUNK_HEADER_SIZE) goto Err;
+  // Make sure the whole RIFF header is available.
+  if (riff_size < RIFF_HEADER_SIZE) goto Err;
   if (riff_size > size) goto Err;
-  // There's no point in reading past the end of the RIFF chunk.
-  if (size > riff_size + CHUNK_HEADER_SIZE) {
-    size = riff_size + CHUNK_HEADER_SIZE;
+  // There's no point in reading past the end of the RIFF chunk. Note riff_size
+  // includes CHUNK_HEADER_SIZE after SizeWithPadding().
+  if (size > riff_size) {
+    size = riff_size;
   }
 
   end = data + size;
diff --git a/src/utils/bit_reader_utils.c b/src/utils/bit_reader_utils.c
index a26557aa..2707420f 100644
--- a/src/utils/bit_reader_utils.c
+++ b/src/utils/bit_reader_utils.c
@@ -124,7 +124,8 @@ int32_t VP8GetSignedValue(VP8BitReader* const br, int bits,
 
 #if defined(__arm__) || defined(_M_ARM) || WEBP_AARCH64 || \
     defined(__i386__) || defined(_M_IX86) || \
-    defined(__x86_64__) || defined(_M_X64)
+    defined(__x86_64__) || defined(_M_X64) || \
+    defined(__wasm__)
 #define VP8L_USE_FAST_LOAD
 #endif
 
diff --git a/src/utils/bit_reader_utils.h b/src/utils/bit_reader_utils.h
index 25ff31e5..b41a7881 100644
--- a/src/utils/bit_reader_utils.h
+++ b/src/utils/bit_reader_utils.h
@@ -69,6 +69,8 @@ extern "C" {
 #define BITS 56
 #elif defined(__mips__)                        // MIPS
 #define BITS 24
+#elif defined(__wasm__)                        // WASM
+#define BITS 56
 #else                                          // reasonable default
 #define BITS 24
 #endif
diff --git a/src/utils/palette.c b/src/utils/palette.c
index 515da210..8ae0a5cd 100644
--- a/src/utils/palette.c
+++ b/src/utils/palette.c
@@ -191,6 +191,12 @@ static void PaletteSortMinimizeDeltas(const uint32_t* const palette_sorted,
   // Find greedily always the closest color of the predicted color to minimize
   // deltas in the palette. This reduces storage needs since the
   // palette is stored with delta encoding.
+  if (num_colors > 17) {
+    if (palette[0] == 0) {
+      --num_colors;
+      SwapColor(&palette[num_colors], &palette[0]);
+    }
+  }
   for (i = 0; i < num_colors; ++i) {
     int best_ix = i;
     uint32_t best_score = ~0U;
@@ -384,8 +390,13 @@ int PaletteSort(PaletteSorting method, const struct WebPPicture* const pic,
                 uint32_t* const palette) {
   switch (method) {
     case kSortedDefault:
-      // Nothing to do, we have already sorted the palette.
-      memcpy(palette, palette_sorted, num_colors * sizeof(*palette));
+      if (palette_sorted[0] == 0 && num_colors > 17) {
+        memcpy(palette, palette_sorted + 1,
+               (num_colors - 1) * sizeof(*palette_sorted));
+        palette[num_colors - 1] = 0;
+      } else {
+        memcpy(palette, palette_sorted, num_colors * sizeof(*palette));
+      }
       return 1;
     case kMinimizeDelta:
       PaletteSortMinimizeDeltas(palette_sorted, num_colors, palette);
diff --git a/src/utils/palette.h b/src/utils/palette.h
index 34479e46..417c61fa 100644
--- a/src/utils/palette.h
+++ b/src/utils/palette.h
@@ -53,6 +53,8 @@ int GetColorPalette(const struct WebPPicture* const pic,
 // Sorts the palette according to the criterion defined by 'method'.
 // 'palette_sorted' is the input palette sorted lexicographically, as done in
 // PrepareMapToPalette. Returns 0 on memory allocation error.
+// For kSortedDefault and kMinimizeDelta methods, 0 (if present) is set as the
+// last element to optimize later storage.
 int PaletteSort(PaletteSorting method, const struct WebPPicture* const pic,
                 const uint32_t* const palette_sorted, uint32_t num_colors,
                 uint32_t* const palette);
diff --git a/src/webp/encode.h b/src/webp/encode.h
index f3d59297..8b59351e 100644
--- a/src/webp/encode.h
+++ b/src/webp/encode.h
@@ -20,7 +20,7 @@
 extern "C" {
 #endif
 
-#define WEBP_ENCODER_ABI_VERSION 0x020f    // MAJOR(8b) + MINOR(8b)
+#define WEBP_ENCODER_ABI_VERSION 0x0210  // MAJOR(8b) + MINOR(8b)
 
 // Note: forward declaring enumerations is not allowed in (strict) C and C++,
 // the types are left here for reference.
@@ -145,7 +145,7 @@ struct WebPConfig {
                           // RGB information for better compression. The default
                           // value is 0.
 
-  int use_delta_palette;  // reserved for future lossless feature
+  int use_delta_palette;  // reserved
   int use_sharp_yuv;      // if needed, use sharp (and slow) RGB->YUV conversion
 
   int qmin;               // minimum permissible quality factor
@@ -224,14 +224,15 @@ struct WebPAuxStats {
   uint32_t lossless_features;  // bit0:predictor bit1:cross-color transform
                                // bit2:subtract-green bit3:color indexing
   int histogram_bits;          // number of precision bits of histogram
-  int transform_bits;          // precision bits for transform
+  int transform_bits;          // precision bits for predictor transform
   int cache_bits;              // number of bits for color cache lookup
   int palette_size;            // number of color in palette, if used
   int lossless_size;           // final lossless size
   int lossless_hdr_size;       // lossless header (transform, huffman etc) size
   int lossless_data_size;      // lossless image data size
+  int cross_color_transform_bits;  // precision bits for cross-color transform
 
-  uint32_t pad[2];        // padding for later use
+  uint32_t pad[1];  // padding for later use
 };
 
 // Signature for output function. Should return true if writing was successful.
diff --git a/src/webp/format_constants.h b/src/webp/format_constants.h
index 999035c5..9b007c8a 100644
--- a/src/webp/format_constants.h
+++ b/src/webp/format_constants.h
@@ -46,7 +46,12 @@
 #define CODE_LENGTH_CODES            19
 
 #define MIN_HUFFMAN_BITS             2  // min number of Huffman bits
-#define MAX_HUFFMAN_BITS             9  // max number of Huffman bits
+#define NUM_HUFFMAN_BITS             3
+
+// the maximum number of bits defining a transform is
+// MIN_TRANSFORM_BITS + (1 << NUM_TRANSFORM_BITS) - 1
+#define MIN_TRANSFORM_BITS           2
+#define NUM_TRANSFORM_BITS           3
 
 #define TRANSFORM_PRESENT            1  // The bit to be written when next data
                                         // to be read is a transform.
diff --git a/src/webp/types.h b/src/webp/types.h
index 9c17edec..a0363f1c 100644
--- a/src/webp/types.h
+++ b/src/webp/types.h
@@ -38,11 +38,11 @@ typedef long long int int64_t;
 
 #ifndef WEBP_NODISCARD
 #if defined(WEBP_ENABLE_NODISCARD) && WEBP_ENABLE_NODISCARD
-#if (defined(__cplusplus) && __cplusplus >= 201700L) || \
+#if (defined(__cplusplus) && __cplusplus >= 201703L) || \
     (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L)
 #define WEBP_NODISCARD [[nodiscard]]
 #else
-// gcc's __has_attribute does not work for enums.
+// gcc's __attribute__((warn_unused_result)) does not work for enums.
 #if defined(__clang__) && defined(__has_attribute)
 #if __has_attribute(warn_unused_result)
 #define WEBP_NODISCARD __attribute__((warn_unused_result))
diff --git a/tests/README.md b/tests/README.md
index 91daba26..60180c95 100644
--- a/tests/README.md
+++ b/tests/README.md
@@ -11,8 +11,9 @@ https://chromium.googlesource.com/webm/libwebp-test-data
 Follow the [build instructions](../doc/building.md) for libwebp, optionally
 adding build flags for various sanitizers (e.g., -fsanitize=address).
 
-`fuzzer/makefile.unix` can then be used to compile the fuzzer targets:
+`-DWEBP_BUILD_FUZZTEST=ON` can then be used to compile the fuzzer targets:
 
 ```shell
-$ make -C fuzzer -f makefile.unix
+$ cmake -B ./build -S . -DWEBP_BUILD_FUZZTEST=ON
+$ make -C build
 ```
diff --git a/tests/fuzzer/CMakeLists.txt b/tests/fuzzer/CMakeLists.txt
new file mode 100644
index 00000000..10bacb1c
--- /dev/null
+++ b/tests/fuzzer/CMakeLists.txt
@@ -0,0 +1,69 @@
+#  Copyright (c) 2024 Google LLC
+#
+#  Use of this source code is governed by a BSD-style license
+#  that can be found in the LICENSE file in the root of the source
+#  tree. An additional intellectual property rights grant can be found
+#  in the file PATENTS.  All contributing project authors may
+#  be found in the AUTHORS file in the root of the source tree.
+
+# Adds a fuzztest from file TEST_NAME.cc located in the gtest folder. Extra
+# arguments are considered as extra source files.
+
+if(CMAKE_VERSION VERSION_LESS "3.19.0")
+  return()
+endif()
+
+macro(add_webp_fuzztest TEST_NAME)
+  add_executable(${TEST_NAME} ${TEST_NAME}.cc)
+  # FuzzTest bundles GoogleTest so no need to link to gtest libraries.
+  target_link_libraries(${TEST_NAME} PRIVATE fuzz_utils webp ${ARGN})
+  target_include_directories(${TEST_NAME} PRIVATE ${CMAKE_BINARY_DIR}/src)
+  link_fuzztest(${TEST_NAME})
+  add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
+  set_property(
+    TEST ${TEST_NAME}
+    PROPERTY ENVIRONMENT "TEST_DATA_DIRS=${CMAKE_CURRENT_SOURCE_DIR}/data/")
+endmacro()
+
+enable_language(CXX)
+set(CMAKE_CXX_STANDARD 17)
+set(CMAKE_CXX_STANDARD_REQUIRED ON)
+
+include(FetchContent)
+
+set(FETCHCONTENT_QUIET FALSE)
+set(fuzztest_SOURCE_DIR ${CMAKE_BINARY_DIR}/_deps/fuzztest-src)
+FetchContent_Declare(
+  fuzztest
+  GIT_REPOSITORY https://github.com/google/fuzztest.git
+  GIT_TAG 078ea0871cc96d3a69bad406577f176a4fa14ae9
+  GIT_PROGRESS TRUE
+  PATCH_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/patch.sh)
+
+FetchContent_MakeAvailable(fuzztest)
+
+fuzztest_setup_fuzzing_flags()
+
+add_library(fuzz_utils fuzz_utils.h fuzz_utils.cc img_alpha.h img_grid.h
+                       img_peak.h)
+target_link_libraries(fuzz_utils PUBLIC webpdecoder)
+link_fuzztest(fuzz_utils)
+
+add_webp_fuzztest(advanced_api_fuzzer webpdecode webpdspdecode webputilsdecode)
+add_webp_fuzztest(dec_fuzzer)
+add_webp_fuzztest(enc_dec_fuzzer)
+add_webp_fuzztest(enc_fuzzer imagedec)
+add_webp_fuzztest(huffman_fuzzer webpdecode webpdspdecode webputilsdecode)
+add_webp_fuzztest(imageio_fuzzer imagedec)
+add_webp_fuzztest(simple_api_fuzzer)
+
+if(WEBP_BUILD_LIBWEBPMUX)
+  add_webp_fuzztest(animation_api_fuzzer webpdemux)
+  add_webp_fuzztest(animdecoder_fuzzer imageioutil webpdemux)
+  add_webp_fuzztest(animencoder_fuzzer libwebpmux)
+  add_webp_fuzztest(mux_demux_api_fuzzer libwebpmux webpdemux)
+endif()
+
+if(WEBP_BUILD_WEBPINFO)
+  add_webp_fuzztest(webp_info_fuzzer imageioutil)
+endif()
diff --git a/tests/fuzzer/advanced_api_fuzzer.c b/tests/fuzzer/advanced_api_fuzzer.cc
similarity index 59%
rename from tests/fuzzer/advanced_api_fuzzer.c
rename to tests/fuzzer/advanced_api_fuzzer.cc
index 22c689bb..a4f8045a 100644
--- a/tests/fuzzer/advanced_api_fuzzer.c
+++ b/tests/fuzzer/advanced_api_fuzzer.cc
@@ -14,54 +14,60 @@
 //
 ////////////////////////////////////////////////////////////////////////////////
 
-#include <stdint.h>
-#include <string.h>
+#include <algorithm>
+#include <cstddef>
+#include <cstdint>
+#include <string_view>
 
 #include "./fuzz_utils.h"
+#include "src/dec/webpi_dec.h"
 #include "src/utils/rescaler_utils.h"
 #include "src/webp/decode.h"
 
-int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
+namespace {
+
+void AdvancedApiTest(std::string_view blob, uint8_t factor_u8, bool flip,
+                     bool bypass_filtering, bool no_fancy_upsampling,
+                     bool use_threads, bool use_cropping, bool use_scaling,
+                     bool use_dithering, int colorspace, bool incremental) {
   WebPDecoderConfig config;
-  if (!WebPInitDecoderConfig(&config)) return 0;
-  if (WebPGetFeatures(data, size, &config.input) != VP8_STATUS_OK) return 0;
-  if ((size_t)config.input.width * config.input.height > kFuzzPxLimit) return 0;
+  if (!WebPInitDecoderConfig(&config)) return;
+  const uint8_t* const data = reinterpret_cast<const uint8_t*>(blob.data());
+  const size_t size = blob.size();
+  if (WebPGetFeatures(data, size, &config.input) != VP8_STATUS_OK) return;
+  if ((size_t)config.input.width * config.input.height >
+      fuzz_utils::kFuzzPxLimit) {
+    return;
+  }
 
   // Using two independent criteria ensures that all combinations of options
   // can reach each path at the decoding stage, with meaningful differences.
 
-  const uint8_t value = FuzzHash(data, size);
-  const float factor = value / 255.f;  // 0-1
+  const uint8_t value = fuzz_utils::FuzzHash(data, size);
+  const float factor = factor_u8 / 255.f;  // 0-1
 
-  config.options.flip = value & 1;
-  config.options.bypass_filtering = value & 2;
-  config.options.no_fancy_upsampling = value & 4;
-  config.options.use_threads = value & 8;
-  if (size & 1) {
+  config.options.flip = flip;
+  config.options.bypass_filtering = bypass_filtering;
+  config.options.no_fancy_upsampling = no_fancy_upsampling;
+  config.options.use_threads = use_threads;
+  if (use_cropping) {
     config.options.use_cropping = 1;
     config.options.crop_width = (int)(config.input.width * (1 - factor));
     config.options.crop_height = (int)(config.input.height * (1 - factor));
     config.options.crop_left = config.input.width - config.options.crop_width;
     config.options.crop_top = config.input.height - config.options.crop_height;
   }
-  if (size & 2) {
+  if (use_dithering) {
     int strength = (int)(factor * 100);
     config.options.dithering_strength = strength;
     config.options.alpha_dithering_strength = 100 - strength;
   }
-  if (size & 4) {
+  if (use_scaling) {
     config.options.use_scaling = 1;
     config.options.scaled_width = (int)(config.input.width * factor * 2);
     config.options.scaled_height = (int)(config.input.height * factor * 2);
   }
-
-#if defined(WEBP_REDUCE_CSP)
-  config.output.colorspace = (value & 1)
-                                 ? ((value & 2) ? MODE_RGBA : MODE_BGRA)
-                                 : ((value & 2) ? MODE_rgbA : MODE_bgrA);
-#else
-  config.output.colorspace = (WEBP_CSP_MODE)(value % MODE_LAST);
-#endif  // WEBP_REDUCE_CSP
+  config.output.colorspace = static_cast<WEBP_CSP_MODE>(colorspace);
 
   for (int i = 0; i < 2; ++i) {
     if (i == 1) {
@@ -75,12 +81,25 @@ int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
 
       // Skip easily avoidable out-of-memory fuzzing errors.
       if (config.options.use_scaling) {
+        int input_width = config.input.width;
+        int input_height = config.input.height;
+        if (config.options.use_cropping) {
+          const int cw = config.options.crop_width;
+          const int ch = config.options.crop_height;
+          const int x = config.options.crop_left & ~1;
+          const int y = config.options.crop_top & ~1;
+          if (WebPCheckCropDimensions(input_width, input_height, x, y, cw,
+                                      ch)) {
+            input_width = cw;
+            input_height = ch;
+          }
+        }
+
         int scaled_width = config.options.scaled_width;
         int scaled_height = config.options.scaled_height;
-        if (WebPRescalerGetScaledDimensions(config.input.width,
-                                            config.input.height, &scaled_width,
-                                            &scaled_height)) {
-          size_t fuzz_px_limit = kFuzzPxLimit;
+        if (WebPRescalerGetScaledDimensions(input_width, input_height,
+                                            &scaled_width, &scaled_height)) {
+          size_t fuzz_px_limit = fuzz_utils::kFuzzPxLimit;
           if (scaled_width != config.input.width ||
               scaled_height != config.input.height) {
             // Using the WebPRescalerImport internally can significantly slow
@@ -92,18 +111,18 @@ int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
           // very wide input image to a very tall canvas can be as slow as
           // decoding a huge number of pixels. Avoid timeouts due to these.
           const uint64_t max_num_operations =
-              (uint64_t)Max(scaled_width, config.input.width) *
-              Max(scaled_height, config.input.height);
+              (uint64_t)std::max(scaled_width, config.input.width) *
+              std::max(scaled_height, config.input.height);
           if (max_num_operations > fuzz_px_limit) {
             break;
           }
         }
       }
     }
-    if (size % 3) {
+    if (incremental) {
       // Decodes incrementally in chunks of increasing size.
       WebPIDecoder* idec = WebPIDecode(NULL, 0, &config);
-      if (!idec) return 0;
+      if (!idec) return;
       VP8StatusCode status;
       if (size & 8) {
         size_t available_size = value + 1;
@@ -135,5 +154,28 @@ int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
 
     WebPFreeDecBuffer(&config.output);
   }
-  return 0;
 }
+
+}  // namespace
+
+FUZZ_TEST(AdvancedApi, AdvancedApiTest)
+    .WithDomains(
+        fuzztest::String()
+            .WithMaxSize(fuzz_utils::kMaxWebPFileSize + 1),
+        /*factor_u8=*/fuzztest::Arbitrary<uint8_t>(),
+        /*flip=*/fuzztest::Arbitrary<bool>(),
+        /*bypass_filtering=*/fuzztest::Arbitrary<bool>(),
+        /*no_fancy_upsampling=*/fuzztest::Arbitrary<bool>(),
+        /*use_threads=*/fuzztest::Arbitrary<bool>(),
+        /*use_cropping=*/fuzztest::Arbitrary<bool>(),
+        /*use_scaling=*/fuzztest::Arbitrary<bool>(),
+        /*use_dithering=*/fuzztest::Arbitrary<bool>(),
+#if defined(WEBP_REDUCE_CSP)
+        fuzztest::ElementOf<int>({static_cast<int>(MODE_RGBA),
+                                  static_cast<int>(MODE_BGRA),
+                                  static_cast<int>(MODE_rgbA),
+                                  static_cast<int>(MODE_bgrA)}),
+#else
+        fuzztest::InRange<int>(0, static_cast<int>(MODE_LAST) - 1),
+#endif
+        /*incremental=*/fuzztest::Arbitrary<bool>());
diff --git a/tests/fuzzer/animation_api_fuzzer.c b/tests/fuzzer/animation_api_fuzzer.cc
similarity index 60%
rename from tests/fuzzer/animation_api_fuzzer.c
rename to tests/fuzzer/animation_api_fuzzer.cc
index 187ed24e..efe0e1db 100644
--- a/tests/fuzzer/animation_api_fuzzer.c
+++ b/tests/fuzzer/animation_api_fuzzer.cc
@@ -14,37 +14,46 @@
 //
 ////////////////////////////////////////////////////////////////////////////////
 
+#include <cstddef>
+#include <cstdint>
+#include <string_view>
+
 #include "./fuzz_utils.h"
 #include "src/webp/decode.h"
 #include "src/webp/demux.h"
 #include "src/webp/mux_types.h"
 
-int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
+namespace {
+
+void AnimationApiTest(std::string_view blob, bool use_threads,
+                      WEBP_CSP_MODE color_mode) {
+  const size_t size = blob.size();
   WebPData webp_data;
   WebPDataInit(&webp_data);
   webp_data.size = size;
-  webp_data.bytes = data;
+  webp_data.bytes = reinterpret_cast<const uint8_t*>(blob.data());
 
   // WebPAnimDecoderNew uses WebPDemux internally to calloc canvas size.
   WebPDemuxer* const demux = WebPDemux(&webp_data);
-  if (!demux) return 0;
+  if (!demux) return;
   const uint32_t cw = WebPDemuxGetI(demux, WEBP_FF_CANVAS_WIDTH);
   const uint32_t ch = WebPDemuxGetI(demux, WEBP_FF_CANVAS_HEIGHT);
-  if ((size_t)cw * ch > kFuzzPxLimit) {
+  if ((size_t)cw * ch > fuzz_utils::kFuzzPxLimit) {
     WebPDemuxDelete(demux);
-    return 0;
+    return;
   }
 
   // In addition to canvas size, check each frame separately.
   WebPIterator iter;
-  for (int i = 0; i < kFuzzFrameLimit; i++) {
+  for (int i = 0; i < fuzz_utils::kFuzzFrameLimit; i++) {
     if (!WebPDemuxGetFrame(demux, i + 1, &iter)) break;
     int w, h;
     if (WebPGetInfo(iter.fragment.bytes, iter.fragment.size, &w, &h)) {
-      if ((size_t)w * h > kFuzzPxLimit) {  // image size of the frame payload
+      if ((size_t)w * h >
+          fuzz_utils::kFuzzPxLimit) {  // image size of the frame payload
         WebPDemuxReleaseIterator(&iter);
         WebPDemuxDelete(demux);
-        return 0;
+        return;
       }
     }
   }
@@ -53,26 +62,30 @@ int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
   WebPDemuxDelete(demux);
 
   WebPAnimDecoderOptions dec_options;
-  if (!WebPAnimDecoderOptionsInit(&dec_options)) return 0;
+  if (!WebPAnimDecoderOptionsInit(&dec_options)) return;
 
-  dec_options.use_threads = size & 1;
-  // Animations only support 4 (of 12) modes.
-  dec_options.color_mode = (WEBP_CSP_MODE)(size % MODE_LAST);
-  if (dec_options.color_mode != MODE_BGRA &&
-      dec_options.color_mode != MODE_rgbA &&
-      dec_options.color_mode != MODE_bgrA) {
-    dec_options.color_mode = MODE_RGBA;
-  }
+  dec_options.use_threads = use_threads;
+  dec_options.color_mode = color_mode;
 
   WebPAnimDecoder* dec = WebPAnimDecoderNew(&webp_data, &dec_options);
-  if (!dec) return 0;
+  if (!dec) return;
 
-  for (int i = 0; i < kFuzzFrameLimit; i++) {
+  for (int i = 0; i < fuzz_utils::kFuzzFrameLimit; i++) {
     uint8_t* buf;
     int timestamp;
     if (!WebPAnimDecoderGetNext(dec, &buf, &timestamp)) break;
   }
 
   WebPAnimDecoderDelete(dec);
-  return 0;
 }
+
+}  // namespace
+
+FUZZ_TEST(AnimationApi, AnimationApiTest)
+    .WithDomains(
+        fuzztest::String()
+            .WithMaxSize(fuzz_utils::kMaxWebPFileSize + 1),
+        /*use_threads=*/fuzztest::Arbitrary<bool>(),
+        // Animations only support 4 (out of 12) modes.
+        fuzztest::ElementOf<WEBP_CSP_MODE>({MODE_RGBA, MODE_BGRA, MODE_rgbA,
+                                            MODE_bgrA}));
diff --git a/tests/fuzzer/animdecoder_fuzzer.cc b/tests/fuzzer/animdecoder_fuzzer.cc
index c3ea4758..9826a644 100644
--- a/tests/fuzzer/animdecoder_fuzzer.cc
+++ b/tests/fuzzer/animdecoder_fuzzer.cc
@@ -16,13 +16,20 @@
 
 #include <cstddef>
 #include <cstdint>
+#include <string_view>
 
+#include "./fuzz_utils.h"
 #include "imageio/imageio_util.h"
 #include "src/webp/decode.h"
 #include "src/webp/demux.h"
 #include "src/webp/mux_types.h"
 
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+namespace {
+
+void AnimDecoderTest(std::string_view blob) {
+  const uint8_t* const data = reinterpret_cast<const uint8_t*>(blob.data());
+  const size_t size = blob.size();
+
   // WebPAnimDecoderGetInfo() is too late to check the canvas size as
   // WebPAnimDecoderNew() will handle the allocations.
   const size_t kMaxNumBytes = 2684354560;  // RSS (resident set size) limit.
@@ -34,14 +41,14 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
                                              features.height) ||
         static_cast<size_t>(features.width) * features.height >
             kMaxNumPixelsSafe) {
-      return 0;
+      return;
     }
   }
 
   // decode everything as an animation
   WebPData webp_data = {data, size};
   WebPAnimDecoder* const dec = WebPAnimDecoderNew(&webp_data, nullptr);
-  if (dec == nullptr) return 0;
+  if (dec == nullptr) return;
 
   WebPAnimInfo info;
   if (!WebPAnimDecoderGetInfo(dec, &info)) goto End;
@@ -57,5 +64,11 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
   }
 End:
   WebPAnimDecoderDelete(dec);
-  return 0;
 }
+
+}  // namespace
+
+FUZZ_TEST(AnimDecoder, AnimDecoderTest)
+    .WithDomains(
+        fuzztest::String()
+            .WithMaxSize(fuzz_utils::kMaxWebPFileSize + 1));
diff --git a/tests/fuzzer/animencoder_fuzzer.cc b/tests/fuzzer/animencoder_fuzzer.cc
index ef6ec1e4..85b603a4 100644
--- a/tests/fuzzer/animencoder_fuzzer.cc
+++ b/tests/fuzzer/animencoder_fuzzer.cc
@@ -14,21 +14,48 @@
 //
 ////////////////////////////////////////////////////////////////////////////////
 
-#include <stdio.h>
-#include <stdlib.h>
+#include <cstddef>
+#include <cstdint>
+#include <cstdio>
+#include <cstdlib>
+#include <string_view>
+#include <utility>
+#include <vector>
 
 #include "./fuzz_utils.h"
+#include "src/dsp/cpu.h"
 #include "src/webp/encode.h"
 #include "src/webp/mux.h"
+#include "src/webp/mux_types.h"
 
 namespace {
 
-const VP8CPUInfo default_VP8GetCPUInfo = VP8GetCPUInfo;
+const VP8CPUInfo default_VP8GetCPUInfo = fuzz_utils::VP8GetCPUInfo;
+
+struct FrameConfig {
+  int use_argb;
+  int timestamp;
+  WebPConfig webp_config;
+  fuzz_utils::CropOrScaleParams crop_or_scale_params;
+  int source_image_index;
+};
+
+auto ArbitraryKMinKMax() {
+  return fuzztest::FlatMap(
+      [](int kmax) {
+        const int min_kmin = (kmax > 1) ? (kmax / 2) : 0;
+        const int max_kmin = (kmax > 1) ? (kmax - 1) : 0;
+        return fuzztest::PairOf(fuzztest::InRange(min_kmin, max_kmin),
+                                fuzztest::Just(kmax));
+      },
+      fuzztest::InRange(0, 15));
+}
 
 int AddFrame(WebPAnimEncoder** const enc,
              const WebPAnimEncoderOptions& anim_config, int* const width,
-             int* const height, int timestamp_ms, const uint8_t data[],
-             size_t size, uint32_t* const bit_pos) {
+             int* const height, int timestamp_ms,
+             const FrameConfig& frame_config, const uint8_t data[], size_t size,
+             uint32_t* const bit_pos) {
   if (enc == nullptr || width == nullptr || height == nullptr) {
     fprintf(stderr, "NULL parameters.\n");
     if (enc != nullptr) WebPAnimEncoderDelete(*enc);
@@ -36,27 +63,12 @@ int AddFrame(WebPAnimEncoder** const enc,
   }
 
   // Init the source picture.
-  WebPPicture pic;
-  if (!WebPPictureInit(&pic)) {
-    fprintf(stderr, "WebPPictureInit failed.\n");
-    WebPAnimEncoderDelete(*enc);
-    abort();
-  }
-  pic.use_argb = Extract(1, data, size, bit_pos);
-
-  // Read the source picture.
-  if (!ExtractSourcePicture(&pic, data, size, bit_pos)) {
-    const WebPEncodingError error_code = pic.error_code;
-    WebPAnimEncoderDelete(*enc);
-    WebPPictureFree(&pic);
-    if (error_code == VP8_ENC_ERROR_OUT_OF_MEMORY) return 0;
-    fprintf(stderr, "Can't read input image. Error code: %d\n", error_code);
-    abort();
-  }
+  WebPPicture pic = fuzz_utils::GetSourcePicture(
+      frame_config.source_image_index, frame_config.use_argb);
 
   // Crop and scale.
   if (*enc == nullptr) {  // First frame will set canvas width and height.
-    if (!ExtractAndCropOrScale(&pic, data, size, bit_pos)) {
+    if (!fuzz_utils::CropOrScale(&pic, frame_config.crop_or_scale_params)) {
       const WebPEncodingError error_code = pic.error_code;
       WebPPictureFree(&pic);
       if (error_code == VP8_ENC_ERROR_OUT_OF_MEMORY) return 0;
@@ -89,13 +101,7 @@ int AddFrame(WebPAnimEncoder** const enc,
   }
 
   // Create frame encoding config.
-  WebPConfig config;
-  if (!ExtractWebPConfig(&config, data, size, bit_pos)) {
-    fprintf(stderr, "ExtractWebPConfig failed.\n");
-    WebPAnimEncoderDelete(*enc);
-    WebPPictureFree(&pic);
-    abort();
-  }
+  WebPConfig config = frame_config.webp_config;
   // Skip slow settings on big images, it's likely to timeout.
   if (pic.width * pic.height > 32 * 32) {
     config.method = (config.method > 4) ? 4 : config.method;
@@ -125,14 +131,17 @@ int AddFrame(WebPAnimEncoder** const enc,
   return 1;
 }
 
-}  // namespace
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
+void AnimEncoderTest(std::string_view blob, bool minimize_size,
+                     std::pair<int, int> kmin_kmax, bool allow_mixed,
+                     const std::vector<FrameConfig>& frame_configs,
+                     int optimization_index) {
   WebPAnimEncoder* enc = nullptr;
   int width = 0, height = 0, timestamp_ms = 0;
   uint32_t bit_pos = 0;
+  const uint8_t* const data = reinterpret_cast<const uint8_t*>(blob.data());
+  const size_t size = blob.size();
 
-  ExtractAndDisableOptimizations(default_VP8GetCPUInfo, data, size, &bit_pos);
+  fuzz_utils::SetOptimization(default_VP8GetCPUInfo, optimization_index);
 
   // Extract a configuration from the packed bits.
   WebPAnimEncoderOptions anim_config;
@@ -140,26 +149,20 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
     fprintf(stderr, "WebPAnimEncoderOptionsInit failed.\n");
     abort();
   }
-  anim_config.minimize_size = Extract(1, data, size, &bit_pos);
-  anim_config.kmax = Extract(15, data, size, &bit_pos);
-  const int min_kmin = (anim_config.kmax > 1) ? (anim_config.kmax / 2) : 0;
-  const int max_kmin = (anim_config.kmax > 1) ? (anim_config.kmax - 1) : 0;
-  anim_config.kmin =
-      min_kmin + Extract((uint32_t)(max_kmin - min_kmin), data, size, &bit_pos);
-  anim_config.allow_mixed = Extract(1, data, size, &bit_pos);
+  anim_config.minimize_size = minimize_size;
+  anim_config.kmin = kmin_kmax.first;
+  anim_config.kmax = kmin_kmax.second;
+  anim_config.allow_mixed = allow_mixed;
   anim_config.verbose = 0;
 
-  const int nb_frames = 1 + Extract(15, data, size, &bit_pos);
-
   // For each frame.
-  for (int i = 0; i < nb_frames; ++i) {
-    if (!AddFrame(&enc, anim_config, &width, &height, timestamp_ms, data, size,
-                  &bit_pos)) {
-      return 0;
+  for (const FrameConfig& frame_config : frame_configs) {
+    if (!AddFrame(&enc, anim_config, &width, &height, timestamp_ms,
+                  frame_config, data, size, &bit_pos)) {
+      return;
     }
 
-    timestamp_ms += (1 << (2 + Extract(15, data, size, &bit_pos))) +
-                    Extract(1, data, size, &bit_pos);  // [1..131073], arbitrary
+    timestamp_ms += frame_config.timestamp;
   }
 
   // Assemble.
@@ -184,5 +187,22 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
 
   WebPAnimEncoderDelete(enc);
   WebPDataClear(&webp_data);
-  return 0;
 }
+
+}  // namespace
+
+FUZZ_TEST(AnimEncoder, AnimEncoderTest)
+    .WithDomains(
+        fuzztest::String(),
+        /*minimize_size=*/fuzztest::Arbitrary<bool>(), ArbitraryKMinKMax(),
+        /*allow_mixed=*/fuzztest::Arbitrary<bool>(),
+        fuzztest::VectorOf(
+            fuzztest::StructOf<FrameConfig>(
+                fuzztest::InRange<int>(0, 1), fuzztest::InRange<int>(0, 131073),
+                fuzz_utils::ArbitraryWebPConfig(),
+                fuzz_utils::ArbitraryCropOrScaleParams(),
+                fuzztest::InRange<int>(0, fuzz_utils::kNumSourceImages - 1)))
+            .WithMinSize(1)
+            .WithMaxSize(15),
+        /*optimization_index=*/
+        fuzztest::InRange<uint32_t>(0, fuzz_utils::kMaxOptimizationIndex));
diff --git a/tests/fuzzer/dec_fuzzer.cc b/tests/fuzzer/dec_fuzzer.cc
new file mode 100644
index 00000000..b91c7ef3
--- /dev/null
+++ b/tests/fuzzer/dec_fuzzer.cc
@@ -0,0 +1,48 @@
+// Copyright 2024 Google Inc.
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
+//
+////////////////////////////////////////////////////////////////////////////////
+
+#include <cstdint>
+#include <cstdio>
+#include <string_view>
+
+#include "src/webp/decode.h"
+#include "tests/fuzzer/fuzz_utils.h"
+
+namespace {
+
+void DecodeWebP(std::string_view arbitrary_bytes) {
+  WebPDecoderConfig decoder_config;
+  if (!WebPInitDecoderConfig(&decoder_config)) {
+    fprintf(stderr, "WebPInitDecoderConfig failed.\n");
+    abort();
+  }
+  const VP8StatusCode status =
+      WebPDecode(reinterpret_cast<const uint8_t*>(arbitrary_bytes.data()),
+                 arbitrary_bytes.size(), &decoder_config);
+  WebPFreeDecBuffer(&decoder_config.output);
+  // The decoding may fail (because the fuzzed input can be anything) but not
+  // for these reasons.
+  if (status == VP8_STATUS_SUSPENDED || status == VP8_STATUS_USER_ABORT) {
+    abort();
+  }
+}
+
+FUZZ_TEST(WebPSuite, DecodeWebP)
+    .WithDomains(
+        fuzztest::String()
+            .WithMaxSize(fuzz_utils::kMaxWebPFileSize + 1));
+
+}  // namespace
diff --git a/tests/fuzzer/enc_dec_fuzzer.cc b/tests/fuzzer/enc_dec_fuzzer.cc
index c5d46ae0..c6769aef 100644
--- a/tests/fuzzer/enc_dec_fuzzer.cc
+++ b/tests/fuzzer/enc_dec_fuzzer.cc
@@ -14,57 +14,37 @@
 //
 ////////////////////////////////////////////////////////////////////////////////
 
-#include <stdio.h>
-#include <stdlib.h>
+#include <cstddef>
+#include <cstdint>
+#include <cstdio>
 
 #include "./fuzz_utils.h"
+#include "src/dsp/cpu.h"
 #include "src/webp/decode.h"
 #include "src/webp/encode.h"
 
 namespace {
 
-const VP8CPUInfo default_VP8GetCPUInfo = VP8GetCPUInfo;
+const VP8CPUInfo default_VP8GetCPUInfo = fuzz_utils::VP8GetCPUInfo;
 
-}  // namespace
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
-  uint32_t bit_pos = 0;
-
-  ExtractAndDisableOptimizations(default_VP8GetCPUInfo, data, size, &bit_pos);
+void EncDecTest(bool use_argb, int source_image_index, WebPConfig config,
+                int optimization_index,
+                const fuzz_utils::CropOrScaleParams& crop_or_scale_params) {
+  fuzz_utils::SetOptimization(default_VP8GetCPUInfo, optimization_index);
 
   // Init the source picture.
-  WebPPicture pic;
-  if (!WebPPictureInit(&pic)) {
-    fprintf(stderr, "WebPPictureInit failed.\n");
-    abort();
-  }
-  pic.use_argb = Extract(1, data, size, &bit_pos);
-
-  // Read the source picture.
-  if (!ExtractSourcePicture(&pic, data, size, &bit_pos)) {
-    const WebPEncodingError error_code = pic.error_code;
-    WebPPictureFree(&pic);
-    if (error_code == VP8_ENC_ERROR_OUT_OF_MEMORY) return 0;
-    fprintf(stderr, "Can't read input image. Error code: %d\n", error_code);
-    abort();
-  }
+  WebPPicture pic = fuzz_utils::GetSourcePicture(source_image_index, use_argb);
 
   // Crop and scale.
-  if (!ExtractAndCropOrScale(&pic, data, size, &bit_pos)) {
+  if (!fuzz_utils::CropOrScale(&pic, crop_or_scale_params)) {
     const WebPEncodingError error_code = pic.error_code;
     WebPPictureFree(&pic);
-    if (error_code == VP8_ENC_ERROR_OUT_OF_MEMORY) return 0;
+    if (error_code == VP8_ENC_ERROR_OUT_OF_MEMORY) return;
     fprintf(stderr, "ExtractAndCropOrScale failed. Error code: %d\n",
             error_code);
     abort();
   }
 
-  // Extract a configuration from the packed bits.
-  WebPConfig config;
-  if (!ExtractWebPConfig(&config, data, size, &bit_pos)) {
-    fprintf(stderr, "ExtractWebPConfig failed.\n");
-    abort();
-  }
   // Skip slow settings on big images, it's likely to timeout.
   if (pic.width * pic.height > 32 * 32) {
     if (config.lossless) {
@@ -93,7 +73,7 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
     WebPPictureFree(&pic);
     if (error_code == VP8_ENC_ERROR_OUT_OF_MEMORY ||
         error_code == VP8_ENC_ERROR_BAD_WRITE) {
-      return 0;
+      return;
     }
     fprintf(stderr, "WebPEncode failed. Error code: %d\n", error_code);
     abort();
@@ -157,5 +137,16 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
   WebPFreeDecBuffer(&dec_config.output);
   WebPMemoryWriterClear(&memory_writer);
   WebPPictureFree(&pic);
-  return 0;
 }
+
+}  // namespace
+
+FUZZ_TEST(EncDec, EncDecTest)
+    .WithDomains(/*use_argb=*/fuzztest::Arbitrary<bool>(),
+                 /*source_image_index=*/
+                 fuzztest::InRange<int>(0, fuzz_utils::kNumSourceImages - 1),
+                 fuzz_utils::ArbitraryWebPConfig(),
+                 /*optimization_index=*/
+                 fuzztest::InRange<uint32_t>(0,
+                                             fuzz_utils::kMaxOptimizationIndex),
+                 fuzz_utils::ArbitraryCropOrScaleParams());
diff --git a/tests/fuzzer/enc_fuzzer.cc b/tests/fuzzer/enc_fuzzer.cc
new file mode 100644
index 00000000..52de0b6e
--- /dev/null
+++ b/tests/fuzzer/enc_fuzzer.cc
@@ -0,0 +1,140 @@
+// Copyright 2024 Google Inc.
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
+//
+////////////////////////////////////////////////////////////////////////////////
+
+#include <cstddef>
+#include <cstdint>
+#include <cstdlib>
+#include <iostream>
+#include <string>
+#include <string_view>
+
+#include "imageio/image_dec.h"
+#include "src/dsp/cpu.h"
+#include "src/webp/decode.h"
+#include "src/webp/encode.h"
+#include "src/webp/types.h"
+#include "tests/fuzzer/fuzz_utils.h"
+
+namespace {
+
+const VP8CPUInfo default_VP8GetCPUInfo = fuzz_utils::VP8GetCPUInfo;
+
+void EncTest(std::string_view file, uint32_t optimization_index, bool use_argb,
+             WebPConfig config,
+             const fuzz_utils::CropOrScaleParams& crop_or_scale_params) {
+  fuzz_utils::SetOptimization(default_VP8GetCPUInfo, optimization_index);
+
+  // Init the source picture.
+  WebPPicture pic;
+  if (!WebPPictureInit(&pic)) {
+    std::cerr << "WebPPictureInit failed.\n";
+    abort();
+  }
+  pic.use_argb = use_argb;
+
+  const uint8_t* const file_data =
+      reinterpret_cast<const uint8_t*>(file.data());
+  if (fuzz_utils::IsImageTooBig(file_data, file.size())) return;
+  WebPImageReader reader = WebPGuessImageReader(file_data, file.size());
+  if (!reader(file_data, file.size(), &pic, 1, NULL)) return;
+
+  // Crop and scale.
+  if (!CropOrScale(&pic, crop_or_scale_params)) {
+    const WebPEncodingError error_code = pic.error_code;
+    WebPPictureFree(&pic);
+    if (error_code == VP8_ENC_ERROR_OUT_OF_MEMORY) return;
+    std::cerr << "CropOrScale failed. Error code: " << error_code << "\n";
+    abort();
+  }
+
+  // Skip the cruncher except on small images, it's likely to timeout.
+  if (config.lossless && config.quality == 100. && config.method == 6 &&
+      pic.width * pic.height >= 16384) {
+    config.lossless = 0;
+  }
+
+  // Encode.
+  WebPMemoryWriter memory_writer;
+  WebPMemoryWriterInit(&memory_writer);
+  pic.writer = WebPMemoryWrite;
+  pic.custom_ptr = &memory_writer;
+  if (!WebPEncode(&config, &pic)) {
+    const WebPEncodingError error_code = pic.error_code;
+    WebPMemoryWriterClear(&memory_writer);
+    WebPPictureFree(&pic);
+    if (error_code == VP8_ENC_ERROR_OUT_OF_MEMORY) return;
+    std::cerr << "WebPEncode failed. Error code: " << error_code
+              << " \nFile starts with: " << file.substr(0, 20) << "\n";
+    abort();
+  }
+
+  // Try decoding the result.
+  int w, h;
+  const uint8_t* const out_data = memory_writer.mem;
+  const size_t out_size = memory_writer.size;
+  uint8_t* const rgba = WebPDecodeBGRA(out_data, out_size, &w, &h);
+  if (rgba == nullptr || w != pic.width || h != pic.height) {
+    std::cerr << "WebPDecodeBGRA failed.\nFile starts with: "
+              << file.substr(0, 20) << "\n";
+    WebPFree(rgba);
+    WebPMemoryWriterClear(&memory_writer);
+    WebPPictureFree(&pic);
+    abort();
+  }
+
+  // Compare the results if exact encoding.
+  if (pic.use_argb && config.lossless && config.near_lossless == 100) {
+    const uint32_t* src1 = (const uint32_t*)rgba;
+    const uint32_t* src2 = pic.argb;
+    for (int y = 0; y < h; ++y, src1 += w, src2 += pic.argb_stride) {
+      for (int x = 0; x < w; ++x) {
+        uint32_t v1 = src1[x], v2 = src2[x];
+        if (!config.exact) {
+          if ((v1 & 0xff000000u) == 0 || (v2 & 0xff000000u) == 0) {
+            // Only keep alpha for comparison of fully transparent area.
+            v1 &= 0xff000000u;
+            v2 &= 0xff000000u;
+          }
+        }
+        if (v1 != v2) {
+          std::cerr
+              << "Lossless compression failed pixel-exactness.\nFile starts "
+                 "with: "
+              << file.substr(0, 20) << "\n";
+          WebPFree(rgba);
+          WebPMemoryWriterClear(&memory_writer);
+          WebPPictureFree(&pic);
+          abort();
+        }
+      }
+    }
+  }
+
+  WebPFree(rgba);
+  WebPMemoryWriterClear(&memory_writer);
+  WebPPictureFree(&pic);
+}
+
+}  // namespace
+
+FUZZ_TEST(Enc, EncTest)
+    .WithDomains(
+        fuzztest::Arbitrary<std::string>(),
+        /*optimization_index=*/
+        fuzztest::InRange<uint32_t>(0, fuzz_utils::kMaxOptimizationIndex),
+        /*use_argb=*/fuzztest::Arbitrary<bool>(),
+        fuzz_utils::ArbitraryWebPConfig(),
+        fuzz_utils::ArbitraryCropOrScaleParams());
diff --git a/tests/fuzzer/fuzz_utils.cc b/tests/fuzzer/fuzz_utils.cc
new file mode 100644
index 00000000..f0941b08
--- /dev/null
+++ b/tests/fuzzer/fuzz_utils.cc
@@ -0,0 +1,200 @@
+// Copyright 2024 Google LLC
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
+//
+////////////////////////////////////////////////////////////////////////////////
+
+#include "./fuzz_utils.h"
+
+#include <algorithm>
+#include <cassert>
+#include <cstddef>
+#include <cstdint>
+#include <cstdlib>
+#include <fstream>
+#include <iostream>
+#include <string>
+#include <string_view>
+#include <tuple>
+#include <vector>
+
+#include "./img_alpha.h"
+#include "./img_grid.h"
+#include "./img_peak.h"
+#include "src/dsp/cpu.h"
+#include "src/webp/decode.h"
+#include "src/webp/encode.h"
+#include "src/webp/types.h"
+
+namespace fuzz_utils {
+
+WebPPicture GetSourcePicture(int image_index, bool use_argb) {
+  WebPPicture pic;
+  if (!WebPPictureInit(&pic)) abort();
+  pic.use_argb = use_argb;
+
+  // Pick a source picture.
+  const int kImagesWidth[] = {kImgAlphaWidth, kImgGridWidth, kImgPeakWidth};
+  const int kImagesHeight[] = {kImgAlphaHeight, kImgGridHeight, kImgPeakHeight};
+  const uint8_t* const image_data = kImagesData[image_index];
+  pic.width = kImagesWidth[image_index];
+  pic.height = kImagesHeight[image_index];
+  pic.argb_stride = pic.width * 4 * sizeof(uint8_t);
+
+  // Read the bytes.
+  if (!WebPPictureImportRGBA(&pic, image_data, pic.argb_stride)) abort();
+  return pic;
+}
+
+//------------------------------------------------------------------------------
+
+int CropOrScale(WebPPicture* const pic, const CropOrScaleParams& params) {
+  if (pic == NULL) return 0;
+#if !defined(WEBP_REDUCE_SIZE)
+  if (params.alter_input) {
+    if (params.crop_or_scale) {
+      const int cropped_width = std::max(1, pic->width / params.width_ratio);
+      const int cropped_height = std::max(1, pic->height / params.height_ratio);
+      const int cropped_left = (pic->width - cropped_width) / params.left_ratio;
+      const int cropped_top = (pic->height - cropped_height) / params.top_ratio;
+      return WebPPictureCrop(pic, cropped_left, cropped_top, cropped_width,
+                             cropped_height);
+    } else {
+      const int scaled_width = 1 + (pic->width * params.width_ratio) / 8;
+      const int scaled_height = 1 + (pic->height * params.height_ratio) / 8;
+      return WebPPictureRescale(pic, scaled_width, scaled_height);
+    }
+  }
+#else   // defined(WEBP_REDUCE_SIZE)
+  (void)pic;
+  (void)params;
+#endif  // !defined(WEBP_REDUCE_SIZE)
+  return 1;
+}
+
+extern "C" VP8CPUInfo VP8GetCPUInfo;
+static VP8CPUInfo GetCPUInfo;
+
+static WEBP_INLINE int GetCPUInfoNoSSE41(CPUFeature feature) {
+  if (feature == kSSE4_1 || feature == kAVX) return 0;
+  return GetCPUInfo(feature);
+}
+
+static WEBP_INLINE int GetCPUInfoNoAVX(CPUFeature feature) {
+  if (feature == kAVX) return 0;
+  return GetCPUInfo(feature);
+}
+
+static WEBP_INLINE int GetCPUInfoForceSlowSSSE3(CPUFeature feature) {
+  if (feature == kSlowSSSE3 && GetCPUInfo(kSSE3)) {
+    return 1;  // we have SSE3 -> force SlowSSSE3
+  }
+  return GetCPUInfo(feature);
+}
+
+static WEBP_INLINE int GetCPUInfoOnlyC(CPUFeature feature) {
+  (void)feature;
+  return 0;
+}
+
+void SetOptimization(VP8CPUInfo default_VP8GetCPUInfo, uint32_t index) {
+  assert(index <= kMaxOptimizationIndex);
+  GetCPUInfo = default_VP8GetCPUInfo;
+  const VP8CPUInfo kVP8CPUInfos[kMaxOptimizationIndex + 1] = {
+      GetCPUInfoOnlyC, GetCPUInfoForceSlowSSSE3, GetCPUInfoNoSSE41,
+      GetCPUInfoNoAVX, GetCPUInfo};
+  VP8GetCPUInfo = kVP8CPUInfos[index];
+}
+
+//------------------------------------------------------------------------------
+
+std::vector<std::string> ReadFilesFromDirectory(std::string_view dir) {
+  std::vector<std::tuple<std::string>> tuples =
+      fuzztest::ReadFilesFromDirectory(dir);
+  std::vector<std::string> strings(tuples.size());
+  for (size_t i = 0; i < tuples.size(); ++i) {
+    using std::swap;
+    swap(std::get<0>(tuples[i]), strings[i]);
+  }
+  return strings;
+}
+
+//------------------------------------------------------------------------------
+// The code in this section is copied from
+// https://github.com/webmproject/sjpeg/blob/
+//                1c025b3dbc2246de3e1d7c287970f1a01291800f/src/jpeg_tools.cc#L47
+// (same license as this file).
+
+namespace {
+// Constants below are marker codes defined in JPEG spec
+// ISO/IEC 10918-1 : 1993(E) Table B.1
+// See also: http://www.w3.org/Graphics/JPEG/itu-t81.pdf
+
+#define M_SOF0 0xffc0
+#define M_SOF1 0xffc1
+
+const uint8_t* GetSOFData(const uint8_t* src, int size) {
+  if (src == NULL) return NULL;
+  const uint8_t* const end = src + size - 8;  // 8 bytes of safety, for marker
+  src += 2;                                   // skip M_SOI
+  for (; src < end && *src != 0xff; ++src) {  /* search first 0xff marker */
+  }
+  while (src < end) {
+    const uint32_t marker = static_cast<uint32_t>((src[0] << 8) | src[1]);
+    if (marker == M_SOF0 || marker == M_SOF1) return src;
+    const size_t s = 2 + ((src[2] << 8) | src[3]);
+    src += s;
+  }
+  return NULL;  // No SOF marker found
+}
+
+bool SjpegDimensions(const uint8_t* src0, size_t size, int* width, int* height,
+                     int* is_yuv420) {
+  if (width == NULL || height == NULL) return false;
+  const uint8_t* src = GetSOFData(src0, size);
+  const size_t left_over = size - (src - src0);
+  if (src == NULL || left_over < 8 + 3 * 1) return false;
+  if (height != NULL) *height = (src[5] << 8) | src[6];
+  if (width != NULL) *width = (src[7] << 8) | src[8];
+  if (is_yuv420 != NULL) {
+    const size_t nb_comps = src[9];
+    *is_yuv420 = (nb_comps == 3);
+    if (left_over < 11 + 3 * nb_comps) return false;
+    for (int c = 0; *is_yuv420 && c < 3; ++c) {
+      const int expected_dim = (c == 0 ? 0x22 : 0x11);
+      *is_yuv420 &= (src[11 + c * 3] == expected_dim);
+    }
+  }
+  return true;
+}
+}  // namespace
+
+//------------------------------------------------------------------------------
+
+bool IsImageTooBig(const uint8_t* data, size_t size) {
+  int width, height, components;
+  if (SjpegDimensions(data, size, &width, &height, &components) ||
+      WebPGetInfo(data, size, &width, &height)) {
+    // Look at the number of 8x8px blocks rather than the overall pixel count
+    // when comparing to memory and duration thresholds.
+    const size_t ceiled_width = ((size_t)width + 7) / 8 * 8;
+    const size_t ceiled_height = ((size_t)height + 7) / 8 * 8;
+    // Threshold to avoid out-of-memory and timeout issues.
+    // The threshold is arbitrary but below the fuzzer limit of 2 GB.
+    // The value cannot be 2 GB because of the added memory by MSAN.
+    if (ceiled_width * ceiled_height > kFuzzPxLimit) return true;
+  }
+  return false;
+}
+
+}  // namespace fuzz_utils
diff --git a/tests/fuzzer/fuzz_utils.h b/tests/fuzzer/fuzz_utils.h
index c3fc366d..1d92a077 100644
--- a/tests/fuzzer/fuzz_utils.h
+++ b/tests/fuzzer/fuzz_utils.h
@@ -1,4 +1,4 @@
-// Copyright 2018 Google Inc.
+// Copyright 2018-2024 Google LLC
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -17,14 +17,23 @@
 #ifndef WEBP_TESTS_FUZZER_FUZZ_UTILS_H_
 #define WEBP_TESTS_FUZZER_FUZZ_UTILS_H_
 
-#include <stdint.h>
-#include <stdlib.h>
+#include <cstddef>
+#include <cstdint>
+#include <cstdlib>
+#include <optional>
+#include <string>
+#include <string_view>
+#include <utility>
+#include <vector>
 
 #include "./img_alpha.h"
 #include "./img_grid.h"
 #include "./img_peak.h"
-#include "src/dsp/dsp.h"
+#include "src/dsp/cpu.h"
 #include "src/webp/encode.h"
+#include "fuzztest/fuzztest.h"
+
+namespace fuzz_utils {
 
 //------------------------------------------------------------------------------
 // Arbitrary limits to prevent OOM, timeout, or slow execution.
@@ -54,170 +63,139 @@ static WEBP_INLINE uint8_t FuzzHash(const uint8_t* const data, size_t size) {
   return value;
 }
 
-//------------------------------------------------------------------------------
-// Extract an integer in [0, max_value].
-
-static WEBP_INLINE uint32_t Extract(uint32_t max_value,
-                                    const uint8_t data[], size_t size,
-                                    uint32_t* const bit_pos) {
-  uint32_t v = 0;
-  uint32_t range = 1;
-  while (*bit_pos < 8 * size && range <= max_value) {
-    const uint8_t mask = 1u << (*bit_pos & 7);
-    v = (v << 1) | !!(data[*bit_pos >> 3] & mask);
-    range <<= 1;
-    ++*bit_pos;
-  }
-  return v % (max_value + 1);
-}
-
-//------------------------------------------------------------------------------
-// Some functions to override VP8GetCPUInfo and disable some optimizations.
-
 #ifdef __cplusplus
 extern "C" VP8CPUInfo VP8GetCPUInfo;
 #else
 extern VP8CPUInfo VP8GetCPUInfo;
 #endif
-static VP8CPUInfo GetCPUInfo;
 
-static WEBP_INLINE int GetCPUInfoNoSSE41(CPUFeature feature) {
-  if (feature == kSSE4_1 || feature == kAVX) return 0;
-  return GetCPUInfo(feature);
-}
+//------------------------------------------------------------------------------
 
-static WEBP_INLINE int GetCPUInfoNoAVX(CPUFeature feature) {
-  if (feature == kAVX) return 0;
-  return GetCPUInfo(feature);
+constexpr const uint8_t* kImagesData[] = {kImgAlphaData, kImgGridData,
+                                          kImgPeakData};
+constexpr size_t kNumSourceImages =
+    sizeof(kImagesData) / sizeof(kImagesData[0]);
+
+WebPPicture GetSourcePicture(int image_index, bool use_argb);
+
+static inline auto ArbitraryWebPConfig() {
+  return fuzztest::Map(
+      [](int lossless, int quality, int method, int image_hint, int segments,
+         int sns_strength, int filter_strength, int filter_sharpness,
+         int filter_type, int autofilter, int alpha_compression,
+         int alpha_filtering, int alpha_quality, int pass, int preprocessing,
+         int partitions, int partition_limit, int emulate_jpeg_size,
+         int thread_level, int low_memory, int near_lossless, int exact,
+         int use_delta_palette, int use_sharp_yuv) -> WebPConfig {
+        WebPConfig config;
+        if (!WebPConfigInit(&config)) abort();
+        config.lossless = lossless;
+        config.quality = quality;
+        config.method = method;
+        config.image_hint = (WebPImageHint)image_hint;
+        config.segments = segments;
+        config.sns_strength = sns_strength;
+        config.filter_strength = filter_strength;
+        config.filter_sharpness = filter_sharpness;
+        config.filter_type = filter_type;
+        config.autofilter = autofilter;
+        config.alpha_compression = alpha_compression;
+        config.alpha_filtering = alpha_filtering;
+        config.alpha_quality = alpha_quality;
+        config.pass = pass;
+        config.show_compressed = 1;
+        config.preprocessing = preprocessing;
+        config.partitions = partitions;
+        config.partition_limit = 10 * partition_limit;
+        config.emulate_jpeg_size = emulate_jpeg_size;
+        config.thread_level = thread_level;
+        config.low_memory = low_memory;
+        config.near_lossless = 20 * near_lossless;
+        config.exact = exact;
+        config.use_delta_palette = use_delta_palette;
+        config.use_sharp_yuv = use_sharp_yuv;
+        if (!WebPValidateConfig(&config)) abort();
+        return config;
+      },
+      /*lossless=*/fuzztest::InRange<int>(0, 1),
+      /*quality=*/fuzztest::InRange<int>(0, 100),
+      /*method=*/fuzztest::InRange<int>(0, 6),
+      /*image_hint=*/fuzztest::InRange<int>(0, WEBP_HINT_LAST - 1),
+      /*segments=*/fuzztest::InRange<int>(1, 4),
+      /*sns_strength=*/fuzztest::InRange<int>(0, 100),
+      /*filter_strength=*/fuzztest::InRange<int>(0, 100),
+      /*filter_sharpness=*/fuzztest::InRange<int>(0, 7),
+      /*filter_type=*/fuzztest::InRange<int>(0, 1),
+      /*autofilter=*/fuzztest::InRange<int>(0, 1),
+      /*alpha_compression=*/fuzztest::InRange<int>(0, 1),
+      /*alpha_filtering=*/fuzztest::InRange<int>(0, 2),
+      /*alpha_quality=*/fuzztest::InRange<int>(0, 100),
+      /*pass=*/fuzztest::InRange<int>(1, 10),
+      /*preprocessing=*/fuzztest::InRange<int>(0, 2),
+      /*partitions=*/fuzztest::InRange<int>(0, 3),
+      /*partition_limit=*/fuzztest::InRange<int>(0, 10),
+      /*emulate_jpeg_size=*/fuzztest::InRange<int>(0, 1),
+      /*thread_level=*/fuzztest::InRange<int>(0, 1),
+      /*low_memory=*/fuzztest::InRange<int>(0, 1),
+      /*near_lossless=*/fuzztest::InRange<int>(0, 5),
+      /*exact=*/fuzztest::InRange<int>(0, 1),
+      /*use_delta_palette=*/fuzztest::InRange<int>(0, 1),
+      /*use_sharp_yuv=*/fuzztest::InRange<int>(0, 1));
 }
 
-static WEBP_INLINE int GetCPUInfoForceSlowSSSE3(CPUFeature feature) {
-  if (feature == kSlowSSSE3 && GetCPUInfo(kSSE3)) {
-    return 1;  // we have SSE3 -> force SlowSSSE3
-  }
-  return GetCPUInfo(feature);
+struct CropOrScaleParams {
+  bool alter_input;
+  bool crop_or_scale;
+  int width_ratio;
+  int height_ratio;
+  int left_ratio;
+  int top_ratio;
+};
+
+static inline auto ArbitraryCropOrScaleParams() {
+  return fuzztest::Map(
+      [](const std::optional<std::pair<int, int>>& width_height_ratio,
+         const std::optional<std::pair<int, int>>& left_top_ratio)
+          -> CropOrScaleParams {
+        CropOrScaleParams params;
+        params.alter_input = width_height_ratio.has_value();
+        if (params.alter_input) {
+          params.width_ratio = width_height_ratio->first;
+          params.height_ratio = width_height_ratio->second;
+          params.crop_or_scale = left_top_ratio.has_value();
+          if (params.crop_or_scale) {
+            params.left_ratio = left_top_ratio->first;
+            params.top_ratio = left_top_ratio->second;
+          }
+        }
+        return params;
+      },
+      fuzztest::OptionalOf(
+          fuzztest::PairOf(fuzztest::InRange(1, 8), fuzztest::InRange(1, 8))),
+      fuzztest::OptionalOf(
+          fuzztest::PairOf(fuzztest::InRange(1, 8), fuzztest::InRange(1, 8))));
 }
 
-static WEBP_INLINE int GetCPUInfoOnlyC(CPUFeature feature) {
-  (void)feature;
-  return 0;
-}
+// Crops or scales a picture according to the given params.
+int CropOrScale(WebPPicture* pic, const CropOrScaleParams& params);
 
-static WEBP_INLINE void ExtractAndDisableOptimizations(
-    VP8CPUInfo default_VP8GetCPUInfo, const uint8_t data[], size_t size,
-    uint32_t* const bit_pos) {
-  GetCPUInfo = default_VP8GetCPUInfo;
-  const VP8CPUInfo kVP8CPUInfos[5] = {GetCPUInfoOnlyC, GetCPUInfoForceSlowSSSE3,
-                                      GetCPUInfoNoSSE41, GetCPUInfoNoAVX,
-                                      GetCPUInfo};
-  int VP8GetCPUInfo_index = Extract(4, data, size, bit_pos);
-  VP8GetCPUInfo = kVP8CPUInfos[VP8GetCPUInfo_index];
-}
+// Imposes a level of optimization among one of the kMaxOptimizationIndex+1
+// possible values: OnlyC, ForceSlowSSSE3, NoSSE41, NoAVX, default.
+static constexpr uint32_t kMaxOptimizationIndex = 4;
+void SetOptimization(VP8CPUInfo default_VP8GetCPUInfo, uint32_t index);
 
 //------------------------------------------------------------------------------
 
-static WEBP_INLINE int ExtractWebPConfig(WebPConfig* const config,
-                                         const uint8_t data[], size_t size,
-                                         uint32_t* const bit_pos) {
-  if (config == NULL || !WebPConfigInit(config)) return 0;
-  config->lossless = Extract(1, data, size, bit_pos);
-  config->quality = Extract(100, data, size, bit_pos);
-  config->method = Extract(6, data, size, bit_pos);
-  config->image_hint =
-      (WebPImageHint)Extract(WEBP_HINT_LAST - 1, data, size, bit_pos);
-  config->segments = 1 + Extract(3, data, size, bit_pos);
-  config->sns_strength = Extract(100, data, size, bit_pos);
-  config->filter_strength = Extract(100, data, size, bit_pos);
-  config->filter_sharpness = Extract(7, data, size, bit_pos);
-  config->filter_type = Extract(1, data, size, bit_pos);
-  config->autofilter = Extract(1, data, size, bit_pos);
-  config->alpha_compression = Extract(1, data, size, bit_pos);
-  config->alpha_filtering = Extract(2, data, size, bit_pos);
-  config->alpha_quality = Extract(100, data, size, bit_pos);
-  config->pass = 1 + Extract(9, data, size, bit_pos);
-  config->show_compressed = 1;
-  config->preprocessing = Extract(2, data, size, bit_pos);
-  config->partitions = Extract(3, data, size, bit_pos);
-  config->partition_limit = 10 * Extract(10, data, size, bit_pos);
-  config->emulate_jpeg_size = Extract(1, data, size, bit_pos);
-  config->thread_level = Extract(1, data, size, bit_pos);
-  config->low_memory = Extract(1, data, size, bit_pos);
-  config->near_lossless = 20 * Extract(5, data, size, bit_pos);
-  config->exact = Extract(1, data, size, bit_pos);
-  config->use_delta_palette = Extract(1, data, size, bit_pos);
-  config->use_sharp_yuv = Extract(1, data, size, bit_pos);
-  return WebPValidateConfig(config);
-}
-
-//------------------------------------------------------------------------------
+// See https://developers.google.com/speed/webp/docs/riff_container.
+static constexpr size_t kMaxWebPFileSize = (1ull << 32) - 2;  // 4 GiB - 2
 
-static WEBP_INLINE int ExtractSourcePicture(WebPPicture* const pic,
-                                            const uint8_t data[], size_t size,
-                                            uint32_t* const bit_pos) {
-  if (pic == NULL) return 0;
-
-  // Pick a source picture.
-  const uint8_t* kImagesData[] = {
-      kImgAlphaData,
-      kImgGridData,
-      kImgPeakData
-  };
-  const int kImagesWidth[] = {
-      kImgAlphaWidth,
-      kImgGridWidth,
-      kImgPeakWidth
-  };
-  const int kImagesHeight[] = {
-      kImgAlphaHeight,
-      kImgGridHeight,
-      kImgPeakHeight
-  };
-  const size_t kNbImages = sizeof(kImagesData) / sizeof(kImagesData[0]);
-  const size_t image_index = Extract(kNbImages - 1, data, size, bit_pos);
-  const uint8_t* const image_data = kImagesData[image_index];
-  pic->width = kImagesWidth[image_index];
-  pic->height = kImagesHeight[image_index];
-  pic->argb_stride = pic->width * 4 * sizeof(uint8_t);
-
-  // Read the bytes.
-  return WebPPictureImportRGBA(pic, image_data, pic->argb_stride);
-}
+std::vector<std::string> GetDictionaryFromFiles(
+    const std::vector<std::string_view>& file_paths);
 
-//------------------------------------------------------------------------------
+// Checks whether the binary blob containing a JPEG or WebP is too big for the
+// fuzzer.
+bool IsImageTooBig(const uint8_t* data, size_t size);
 
-static WEBP_INLINE int Max(int a, int b) { return ((a < b) ? b : a); }
-
-static WEBP_INLINE int ExtractAndCropOrScale(WebPPicture* const pic,
-                                             const uint8_t data[], size_t size,
-                                             uint32_t* const bit_pos) {
-  if (pic == NULL) return 0;
-#if !defined(WEBP_REDUCE_SIZE)
-  const int alter_input = Extract(1, data, size, bit_pos);
-  const int crop_or_scale = Extract(1, data, size, bit_pos);
-  const int width_ratio = 1 + Extract(7, data, size, bit_pos);
-  const int height_ratio = 1 + Extract(7, data, size, bit_pos);
-  if (alter_input) {
-    if (crop_or_scale) {
-      const uint32_t left_ratio = 1 + Extract(7, data, size, bit_pos);
-      const uint32_t top_ratio = 1 + Extract(7, data, size, bit_pos);
-      const int cropped_width = Max(1, pic->width / width_ratio);
-      const int cropped_height = Max(1, pic->height / height_ratio);
-      const int cropped_left = (pic->width - cropped_width) / left_ratio;
-      const int cropped_top = (pic->height - cropped_height) / top_ratio;
-      return WebPPictureCrop(pic, cropped_left, cropped_top, cropped_width,
-                             cropped_height);
-    } else {
-      const int scaled_width = 1 + (pic->width * width_ratio) / 8;
-      const int scaled_height = 1 + (pic->height * height_ratio) / 8;
-      return WebPPictureRescale(pic, scaled_width, scaled_height);
-    }
-  }
-#else   // defined(WEBP_REDUCE_SIZE)
-  (void)data;
-  (void)size;
-  (void)bit_pos;
-#endif  // !defined(WEBP_REDUCE_SIZE)
-  return 1;
-}
+}  // namespace fuzz_utils
 
 #endif  // WEBP_TESTS_FUZZER_FUZZ_UTILS_H_
diff --git a/tests/fuzzer/huffman_fuzzer.c b/tests/fuzzer/huffman_fuzzer.cc
similarity index 76%
rename from tests/fuzzer/huffman_fuzzer.c
rename to tests/fuzzer/huffman_fuzzer.cc
index 03e1fdc4..c048b0b9 100644
--- a/tests/fuzzer/huffman_fuzzer.c
+++ b/tests/fuzzer/huffman_fuzzer.cc
@@ -14,22 +14,29 @@
 //
 ////////////////////////////////////////////////////////////////////////////////
 
-#include <stdint.h>
-#include <string.h>
+#include <cstddef>
+#include <cstdint>
+#include <string_view>
 
+#include "./fuzz_utils.h"
 #include "src/dec/vp8li_dec.h"
 #include "src/utils/bit_reader_utils.h"
 #include "src/utils/huffman_utils.h"
 #include "src/utils/utils.h"
 #include "src/webp/format_constants.h"
 
-int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
+namespace {
+
+void HuffmanTest(std::string_view blob) {
+  const uint8_t* const data = reinterpret_cast<const uint8_t*>(blob.data());
+  const size_t size = blob.size();
+
   // Number of bits to initialize data.
   static const int kColorCacheBitsBits = 4;
   // 'num_htree_groups' is contained in the RG channel, hence 16 bits.
   static const int kNumHtreeGroupsBits = 16;
   if (size * sizeof(*data) < kColorCacheBitsBits + kNumHtreeGroupsBits) {
-    return 0;
+    return;
   }
 
   // A non-NULL mapping brings minor changes that are tested by the normal
@@ -39,27 +46,32 @@ int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
   memset(&huffman_tables, 0, sizeof(huffman_tables));
   HTreeGroup* htree_groups = NULL;
 
+  int num_htree_groups, num_htree_groups_max, color_cache_bits;
+  VP8LBitReader* br;
   VP8LDecoder* dec = VP8LNew();
   if (dec == NULL) goto Error;
-  VP8LBitReader* const br = &dec->br_;
+  br = &dec->br_;
   VP8LInitBitReader(br, data, size);
 
-  const int color_cache_bits = VP8LReadBits(br, kColorCacheBitsBits);
+  color_cache_bits = VP8LReadBits(br, kColorCacheBitsBits);
   if (color_cache_bits < 1 || color_cache_bits > MAX_CACHE_BITS) goto Error;
 
-  const int num_htree_groups = VP8LReadBits(br, kNumHtreeGroupsBits);
+  num_htree_groups = VP8LReadBits(br, kNumHtreeGroupsBits);
   // 'num_htree_groups' cannot be 0 as it is built from a non-empty image.
   if (num_htree_groups == 0) goto Error;
   // This variable is only useful when mapping is not NULL.
-  const int num_htree_groups_max = num_htree_groups;
+  num_htree_groups_max = num_htree_groups;
   (void)ReadHuffmanCodesHelper(color_cache_bits, num_htree_groups,
                                num_htree_groups_max, mapping, dec,
                                &huffman_tables, &htree_groups);
 
- Error:
+Error:
   WebPSafeFree(mapping);
   VP8LHtreeGroupsFree(htree_groups);
   VP8LHuffmanTablesDeallocate(&huffman_tables);
   VP8LDelete(dec);
-  return 0;
 }
+
+}  // namespace
+
+FUZZ_TEST(Huffman, HuffmanTest).WithDomains(fuzztest::String());
diff --git a/tests/fuzzer/imageio_fuzzer.cc b/tests/fuzzer/imageio_fuzzer.cc
new file mode 100644
index 00000000..600c78a2
--- /dev/null
+++ b/tests/fuzzer/imageio_fuzzer.cc
@@ -0,0 +1,76 @@
+// Copyright 2024 Google Inc.
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
+//
+////////////////////////////////////////////////////////////////////////////////
+
+// Fuzzing of libwebp's image readers
+
+#include <cstddef>
+#include <cstdint>
+#include <cstdlib>
+#include <iostream>
+#include <string_view>
+
+#include "imageio/image_dec.h"
+#include "imageio/metadata.h"
+#include "src/webp/encode.h"
+#include "tests/fuzzer/fuzz_utils.h"
+
+namespace {
+
+void TestReader(const uint8_t *data, size_t size, WebPImageReader reader,
+                bool keep_alpha, bool use_argb) {
+  WebPPicture pic;
+  if (!WebPPictureInit(&pic)) {
+    std::cerr << "WebPPictureInit failed" << std::endl;
+    abort();
+  }
+  Metadata metadata;
+  MetadataInit(&metadata);
+  pic.use_argb = use_argb ? 1 : 0;
+
+  if (!fuzz_utils::IsImageTooBig(data, size)) {
+    (void)(*reader)(data, size, &pic, keep_alpha ? 1 : 0, &metadata);
+  }
+  WebPPictureFree(&pic);
+  MetadataFree(&metadata);
+}
+
+constexpr WebPInputFileFormat kUnknown = WEBP_UNSUPPORTED_FORMAT;
+
+void Decode(std::string_view arbitrary_bytes, WebPInputFileFormat format,
+            bool keep_alpha, bool use_argb) {
+  const uint8_t *data =
+      reinterpret_cast<const uint8_t *>(arbitrary_bytes.data());
+  const size_t size = arbitrary_bytes.size();
+  if (format == kUnknown) {
+    (void)WebPGuessImageType(data, size);  // shouldn't fail
+    TestReader(data, size, WebPGuessImageReader(data, size), keep_alpha,
+               use_argb);
+  } else {
+    TestReader(data, size, WebPGetImageReader(format), keep_alpha, use_argb);
+  }
+}
+
+FUZZ_TEST(ImageIOSuite, Decode)
+    .WithDomains(
+        fuzztest::String()
+            .WithMaxSize(fuzz_utils::kMaxWebPFileSize + 1),
+        fuzztest::ElementOf<WebPInputFileFormat>(
+            {WEBP_PNG_FORMAT, WEBP_JPEG_FORMAT, WEBP_TIFF_FORMAT,
+             WEBP_WEBP_FORMAT, WEBP_PNM_FORMAT, kUnknown}),
+        /*keep_alpha=*/fuzztest::Arbitrary<bool>(),
+        /*use_argb=*/fuzztest::Arbitrary<bool>());
+
+}  // namespace
diff --git a/tests/fuzzer/makefile.unix b/tests/fuzzer/makefile.unix
deleted file mode 100644
index 3a3aff0a..00000000
--- a/tests/fuzzer/makefile.unix
+++ /dev/null
@@ -1,31 +0,0 @@
-# This Makefile will compile all fuzzing targets. It doesn't check tool
-# requirements and paths may need to be updated depending on your environment.
-# Note a clang 6+ toolchain is assumed for use of -fsanitize=fuzzer.
-
-CC = clang
-CXX = clang++
-CFLAGS = -fsanitize=fuzzer -I../../src -I../.. -Wall -Wextra
-CXXFLAGS = $(CFLAGS)
-LDFLAGS = -fsanitize=fuzzer
-LDLIBS = ../../src/mux/libwebpmux.a ../../src/demux/libwebpdemux.a
-LDLIBS += ../../src/libwebp.a ../../imageio/libimageio_util.a
-LDLIBS += ../../sharpyuv/libsharpyuv.a
-
-FUZZERS = advanced_api_fuzzer animation_api_fuzzer animdecoder_fuzzer
-FUZZERS += animencoder_fuzzer enc_dec_fuzzer huffman_fuzzer
-FUZZERS += mux_demux_api_fuzzer simple_api_fuzzer
-
-%.o: fuzz_utils.h img_alpha.h img_grid.h img_peak.h
-all: $(FUZZERS)
-
-define FUZZER_template
-$(1): $$(addsuffix .o, $(1)) $(LDLIBS)
-OBJS += $$(addsuffix .o, $(1))
-endef
-
-$(foreach fuzzer, $(FUZZERS), $(eval $(call FUZZER_template, $(fuzzer))))
-
-clean:
-	$(RM) $(FUZZERS) $(OBJS)
-
-.PHONY: all clean
diff --git a/tests/fuzzer/mux_demux_api_fuzzer.c b/tests/fuzzer/mux_demux_api_fuzzer.cc
similarity index 79%
rename from tests/fuzzer/mux_demux_api_fuzzer.c
rename to tests/fuzzer/mux_demux_api_fuzzer.cc
index f5983e8d..9d7307dd 100644
--- a/tests/fuzzer/mux_demux_api_fuzzer.c
+++ b/tests/fuzzer/mux_demux_api_fuzzer.cc
@@ -14,23 +14,30 @@
 //
 ////////////////////////////////////////////////////////////////////////////////
 
+#include <cstddef>
+#include <cstdint>
+#include <string_view>
+
 #include "./fuzz_utils.h"
 #include "src/webp/demux.h"
 #include "src/webp/mux.h"
 
-int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
+namespace {
+
+void MuxDemuxApiTest(std::string_view data_in, bool use_mux_api) {
+  const size_t size = data_in.size();
   WebPData webp_data;
   WebPDataInit(&webp_data);
   webp_data.size = size;
-  webp_data.bytes = data;
+  webp_data.bytes = reinterpret_cast<const uint8_t*>(data_in.data());
 
   // Extracted chunks and frames are not processed or decoded,
   // which is already covered extensively by the other fuzz targets.
 
-  if (size & 1) {
+  if (use_mux_api) {
     // Mux API
     WebPMux* mux = WebPMuxCreate(&webp_data, size & 2);
-    if (!mux) return 0;
+    if (!mux) return;
 
     WebPData chunk;
     (void)WebPMuxGetChunk(mux, "EXIF", &chunk);
@@ -45,7 +52,7 @@ int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
 
     WebPMuxError status;
     WebPMuxFrameInfo info;
-    for (int i = 0; i < kFuzzFrameLimit; i++) {
+    for (int i = 0; i < fuzz_utils::kFuzzFrameLimit; i++) {
       status = WebPMuxGetFrame(mux, i + 1, &info);
       if (status == WEBP_MUX_NOT_FOUND) {
         break;
@@ -63,11 +70,11 @@ int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
       demux = WebPDemuxPartial(&webp_data, &state);
       if (state < WEBP_DEMUX_PARSED_HEADER) {
         WebPDemuxDelete(demux);
-        return 0;
+        return;
       }
     } else {
       demux = WebPDemux(&webp_data);
-      if (!demux) return 0;
+      if (!demux) return;
     }
 
     WebPChunkIterator chunk_iter;
@@ -83,7 +90,7 @@ int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
 
     WebPIterator iter;
     if (WebPDemuxGetFrame(demux, 1, &iter)) {
-      for (int i = 1; i < kFuzzFrameLimit; i++) {
+      for (int i = 1; i < fuzz_utils::kFuzzFrameLimit; i++) {
         if (!WebPDemuxNextFrame(&iter)) break;
       }
     }
@@ -91,6 +98,12 @@ int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
     WebPDemuxReleaseIterator(&iter);
     WebPDemuxDelete(demux);
   }
-
-  return 0;
 }
+
+}  // namespace
+
+FUZZ_TEST(MuxDemuxApi, MuxDemuxApiTest)
+    .WithDomains(
+        fuzztest::String()
+            .WithMaxSize(fuzz_utils::kMaxWebPFileSize + 1),
+        /*mux=*/fuzztest::Arbitrary<bool>());
diff --git a/tests/fuzzer/oss-fuzz/build.sh b/tests/fuzzer/oss-fuzz/build.sh
new file mode 100644
index 00000000..dece65bc
--- /dev/null
+++ b/tests/fuzzer/oss-fuzz/build.sh
@@ -0,0 +1,86 @@
+#!/bin/bash
+# Copyright 2018 Google Inc.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+################################################################################
+
+# This script is meant to be run by the oss-fuzz infrastructure from the script
+# https://github.com/google/oss-fuzz/blob/master/projects/libwebp/build.sh
+# It builds the different fuzz targets.
+# Only the libfuzzer engine is supported.
+
+# To test changes to this file:
+# - make changes and commit to your REPO
+# - run:
+#     git clone --depth=1 git@github.com:google/oss-fuzz.git
+#     cd oss-fuzz
+# - modify projects/libwebp/Dockerfile to point to your REPO
+# - run:
+#     python3 infra/helper.py build_image libwebp
+#     # enter 'y' and wait for everything to be downloaded
+# - run:
+#     python3 infra/helper.py build_fuzzers --sanitizer address libwebp
+#     # wait for the tests to be built
+# And then run the fuzzer locally, for example:
+#     python3 infra/helper.py run_fuzzer libwebp \
+#     --sanitizer address \
+#     animencoder_fuzzer@AnimEncoder.AnimEncoderTest
+
+set -eu
+
+EXTRA_CMAKE_FLAGS=""
+export CXXFLAGS="${CXXFLAGS} -DFUZZTEST_COMPATIBILITY_MODE"
+EXTRA_CMAKE_FLAGS="-DFUZZTEST_COMPATIBILITY_MODE=libfuzzer"
+
+# limit allocation size to reduce spurious OOMs
+WEBP_CFLAGS="$CFLAGS -DWEBP_MAX_IMAGE_SIZE=838860800" # 800MiB
+
+export CFLAGS="$WEBP_CFLAGS"
+cmake -S . -B build -DWEBP_BUILD_FUZZTEST=ON ${EXTRA_CMAKE_FLAGS}
+cd build && make -j$(nproc) && cd ..
+
+find $SRC/libwebp-test-data -type f -size -32k -iname "*.webp" \
+  -exec zip -qju fuzz_seed_corpus.zip "{}" \;
+
+# The following is taken from https://github.com/google/oss-fuzz/blob/31ac7244748ea7390015455fb034b1f4eda039d9/infra/base-images/base-builder/compile_fuzztests.sh#L59
+# Iterate the fuzz binaries and list each fuzz entrypoint in the binary. For
+# each entrypoint create a wrapper script that calls into the binaries the
+# given entrypoint as argument.
+# The scripts will be named:
+# {binary_name}@{fuzztest_entrypoint}
+FUZZ_TEST_BINARIES_OUT_PATHS=$(find ./build/tests/fuzzer/ -executable -type f)
+echo "Fuzz binaries: $FUZZ_TEST_BINARIES_OUT_PATHS"
+for fuzz_main_file in $FUZZ_TEST_BINARIES_OUT_PATHS; do
+  FUZZ_TESTS=$($fuzz_main_file --list_fuzz_tests | cut -d ' ' -f 4)
+  cp -f ${fuzz_main_file} $OUT/
+  fuzz_basename=$(basename $fuzz_main_file)
+  chmod -x $OUT/$fuzz_basename
+  for fuzz_entrypoint in $FUZZ_TESTS; do
+    TARGET_FUZZER="${fuzz_basename}@$fuzz_entrypoint"
+    # Write executer script
+    cat << EOF > $OUT/$TARGET_FUZZER
+#!/bin/sh
+# LLVMFuzzerTestOneInput for fuzzer detection.
+this_dir=\$(dirname "\$0")
+export TEST_DATA_DIRS=\$this_dir/corpus
+chmod +x \$this_dir/$fuzz_basename
+\$this_dir/$fuzz_basename --fuzz=$fuzz_entrypoint -- \$@
+chmod -x \$this_dir/$fuzz_basename
+EOF
+    chmod +x $OUT/$TARGET_FUZZER
+  done
+  # Copy data.
+  cp fuzz_seed_corpus.zip $OUT/${fuzz_basename}_seed_corpus.zip
+  cp tests/fuzzer/fuzz.dict $OUT/${fuzz_basename}.dict
+done
diff --git a/tests/fuzzer/patch.sh b/tests/fuzzer/patch.sh
new file mode 100755
index 00000000..7034d10f
--- /dev/null
+++ b/tests/fuzzer/patch.sh
@@ -0,0 +1,10 @@
+#!/bin/sh
+# Fixes for https://github.com/google/fuzztest/issues/1124
+sed -i -e "s/-fsanitize=address//g" -e "s/-DADDRESS_SANITIZER//g" \
+  ./cmake/FuzzTestFlagSetup.cmake
+# Fixes for https://github.com/google/fuzztest/issues/1125
+before="if (IsEnginePlaceholderInput(data)) return;"
+after="if (data.size() == 0) return;"
+sed -i "s/${before}/${after}/" ./fuzztest/internal/compatibility_mode.cc
+sed -i "s/set(GTEST_HAS_ABSL ON)/set(GTEST_HAS_ABSL OFF)/" \
+  ./cmake/BuildDependencies.cmake
diff --git a/tests/fuzzer/simple_api_fuzzer.c b/tests/fuzzer/simple_api_fuzzer.cc
similarity index 84%
rename from tests/fuzzer/simple_api_fuzzer.c
rename to tests/fuzzer/simple_api_fuzzer.cc
index 3a4288a4..3d1b5c3b 100644
--- a/tests/fuzzer/simple_api_fuzzer.c
+++ b/tests/fuzzer/simple_api_fuzzer.cc
@@ -14,15 +14,23 @@
 //
 ////////////////////////////////////////////////////////////////////////////////
 
+#include <cstddef>
+#include <cstdint>
+#include <string_view>
+
 #include "./fuzz_utils.h"
 #include "src/webp/decode.h"
 
-int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
+namespace {
+
+void SimpleApiTest(std::string_view data_in) {
+  const uint8_t* const data = reinterpret_cast<const uint8_t*>(data_in.data());
+  const size_t size = data_in.size();
   int w, h;
-  if (!WebPGetInfo(data, size, &w, &h)) return 0;
-  if ((size_t)w * h > kFuzzPxLimit) return 0;
+  if (!WebPGetInfo(data, size, &w, &h)) return;
+  if ((size_t)w * h > fuzz_utils::kFuzzPxLimit) return;
 
-  const uint8_t value = FuzzHash(data, size);
+  const uint8_t value = fuzz_utils::FuzzHash(data, size);
   uint8_t* buf = NULL;
 
   // For *Into functions, which decode into an external buffer, an
@@ -84,6 +92,11 @@ int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
   }
 
   if (buf) WebPFree(buf);
-
-  return 0;
 }
+
+}  // namespace
+
+FUZZ_TEST(SimpleApi, SimpleApiTest)
+    .WithDomains(
+        fuzztest::String()
+            .WithMaxSize(fuzz_utils::kMaxWebPFileSize + 1));
diff --git a/tests/fuzzer/webp_info_fuzzer.cc b/tests/fuzzer/webp_info_fuzzer.cc
new file mode 100644
index 00000000..3b1c7f2e
--- /dev/null
+++ b/tests/fuzzer/webp_info_fuzzer.cc
@@ -0,0 +1,43 @@
+// Copyright 2024 Google Inc.
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
+//
+////////////////////////////////////////////////////////////////////////////////
+
+#include <cstdint>
+#include <string_view>
+
+#include "src/webp/mux_types.h"
+#include "tests/fuzzer/fuzz_utils.h"
+
+// Don't do that at home!
+#define main exec_main
+#include "examples/webpinfo.c"
+#undef main
+
+void WebPInfoTest(std::string_view data) {
+  WebPInfo webp_info;
+  WebPInfoInit(&webp_info);
+  webp_info.quiet_ = 1;
+  webp_info.show_summary_ = 0;
+  webp_info.show_diagnosis_ = 0;
+  webp_info.parse_bitstream_ = 1;
+  WebPData webp_data = {reinterpret_cast<const uint8_t *>(data.data()),
+                        data.size()};
+  AnalyzeWebP(&webp_info, &webp_data);
+}
+
+FUZZ_TEST(WebPInfo, WebPInfoTest)
+    .WithDomains(
+        fuzztest::String()
+            .WithMaxSize(fuzz_utils::kMaxWebPFileSize + 1));
diff --git a/xcframeworkbuild.sh b/xcframeworkbuild.sh
index 14b987d4..a54b449b 100755
--- a/xcframeworkbuild.sh
+++ b/xcframeworkbuild.sh
@@ -172,7 +172,9 @@ for (( i = 0; i < $NUM_PLATFORMS; ++i )); do
     CFLAGS="-pipe -isysroot ${SDKROOT} -O3 -DNDEBUG"
     case "${PLATFORM}" in
       iPhone*)
-        CFLAGS+=" -fembed-bitcode"
+        if [[ "${XCODE%%.*}" -lt 16 ]]; then
+          CFLAGS+=" -fembed-bitcode"
+        fi
         CFLAGS+=" -target ${ARCH}-apple-ios${IOS_MIN_VERSION}"
         [[ "${PLATFORM}" == *Simulator* ]] && CFLAGS+="-simulator"
         ;;
```

