```diff
diff --git a/AUTHORS b/AUTHORS
index 84c63b2f1..a12d6b255 100644
--- a/AUTHORS
+++ b/AUTHORS
@@ -32,6 +32,7 @@ Arild Fuldseth <arilfuld@cisco.com>
 Aron Rosenberg <arosenberg@logitech.com>
 Arpad Panyik <Arpad.Panyik@arm.com>
 Arun Singh Negi <arun.negi@ittiam.com>
+Athulya Raj Raji Mohini <AthulyaRaj.RajiMohini@arm.com>
 Attila Nagy <attilanagy@google.com>
 Balaji Anandapadmanaban <balaji.anandapadmanaban@arm.com>
 Bohan Li <bohanli@google.com>
diff --git a/CHANGELOG b/CHANGELOG
index fce8dc94a..76d870632 100644
--- a/CHANGELOG
+++ b/CHANGELOG
@@ -1,3 +1,19 @@
+2025-04-11 v3.12.1
+  This release includes several bug fixes. This release is ABI
+  compatible with the last release. See
+  https://aomedia.googlesource.com/aom/+log/v3.12.0..v3.12.1 for all the
+  commits in this release.
+
+  - Bug Fixes
+    * b:396169342: Assertion
+      `av1_is_subpelmv_in_range(&ms_params.mv_limits, start_mv)' failed.
+    * b:401671154: typo in void init_src_params(...)
+    * Coverity defect 323670: Uninitialized scalar variable in
+      encode_with_and_without_superres()
+    * cmake: bump minimum version to 3.16
+    * cfl_ppc: fix subtract_average_vsx
+    * Fix an incorrect index in av1_highbd_pixel_proj_error_neon
+
 2025-02-10 v3.12.0
   This release includes new codec interfaces, compression efficiency and
   perceptual improvements, speedup and memory optimizations, and bug
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 1ac01d940..50b426189 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -8,11 +8,7 @@
 # License 1.0 was not distributed with this source code in the PATENTS file, you
 # can obtain it at www.aomedia.org/license/patent.
 #
-if(CONFIG_TFLITE)
-  cmake_minimum_required(VERSION 3.11)
-else()
-  cmake_minimum_required(VERSION 3.9)
-endif()
+cmake_minimum_required(VERSION 3.16)
 
 set(AOM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
 set(AOM_CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}")
@@ -59,7 +55,7 @@ endif()
 #
 # We set SO_FILE_VERSION = [c-a].a.r
 set(LT_CURRENT 15)
-set(LT_REVISION 0)
+set(LT_REVISION 1)
 set(LT_AGE 12)
 math(EXPR SO_VERSION "${LT_CURRENT} - ${LT_AGE}")
 set(SO_FILE_VERSION "${SO_VERSION}.${LT_AGE}.${LT_REVISION}")
diff --git a/METADATA b/METADATA
index de6afe0de..084bf04d2 100644
--- a/METADATA
+++ b/METADATA
@@ -13,12 +13,12 @@ third_party {
   license_note: "would be NOTICE save for Alliance for Open Media patent license:\n   libaom/PATENTS,\n and in headers for 930 other files like:\n   config/arm/config/aom_config.asm\n   config/arm/config/aom_config.c\n   ... \n   tools/txfm_analyzer/txfm_graph.h\n   tools/wrap-commit-msg.py"
   last_upgrade_date {
     year: 2025
-    month: 2
-    day: 21
+    month: 4
+    day: 14
   }
   identifier {
     type: "Git"
     value: "https://aomedia.googlesource.com/aom/"
-    version: "v3.12.0"
+    version: "v3.12.1"
   }
 }
diff --git a/av1/common/ppc/cfl_ppc.c b/av1/common/ppc/cfl_ppc.c
index 36defe04e..c2a25c929 100644
--- a/av1/common/ppc/cfl_ppc.c
+++ b/av1/common/ppc/cfl_ppc.c
@@ -19,7 +19,6 @@
 #define OFF_1 16
 #define OFF_2 32
 #define OFF_3 48
-#define CFL_BUF_LINE_BYTES 64
 #define CFL_LINE_1 64
 #define CFL_LINE_2 128
 #define CFL_LINE_3 192
@@ -35,8 +34,6 @@ typedef vector unsigned long long uint64x2_t;  // NOLINT(runtime/int)
 static inline void subtract_average_vsx(const uint16_t *src_ptr, int16_t *dst,
                                         int width, int height, int round_offset,
                                         int num_pel_log2) {
-  //  int16_t *dst = dst_ptr;
-  const int16_t *dst_end = dst + height * CFL_BUF_LINE;
   const int16_t *sum_buf = (const int16_t *)src_ptr;
   const int16_t *end = sum_buf + height * CFL_BUF_LINE;
   const uint32x4_t div_shift = vec_splats((uint32_t)num_pel_log2);
@@ -63,7 +60,8 @@ static inline void subtract_average_vsx(const uint16_t *src_ptr, int16_t *dst,
       sum_32x4_1 =
           vec_sum4s(vec_vsx_ld(OFF_3 + CFL_LINE_1, sum_buf), sum_32x4_1);
     }
-  } while ((sum_buf += (CFL_BUF_LINE * 2)) < end);
+    sum_buf += CFL_BUF_LINE * 2;
+  } while (sum_buf < end);
   int32x4_t sum_32x4 = vec_add(sum_32x4_0, sum_32x4_1);
 
   const int32x4_t perm_64 = vec_perm(sum_32x4, sum_32x4, mask_64);
@@ -72,41 +70,44 @@ static inline void subtract_average_vsx(const uint16_t *src_ptr, int16_t *dst,
   sum_32x4 = vec_add(sum_32x4, perm_32);
   const int32x4_t avg = vec_sr(sum_32x4, div_shift);
   const int16x8_t vec_avg = vec_pack(avg, avg);
+  const int16_t *src = (const int16_t *)src_ptr;
   do {
-    vec_vsx_st(vec_sub(vec_vsx_ld(OFF_0, dst), vec_avg), OFF_0, dst);
-    vec_vsx_st(vec_sub(vec_vsx_ld(OFF_0 + CFL_LINE_1, dst), vec_avg),
-               OFF_0 + CFL_BUF_LINE_BYTES, dst);
-    vec_vsx_st(vec_sub(vec_vsx_ld(OFF_0 + CFL_LINE_2, dst), vec_avg),
+    vec_vsx_st(vec_sub(vec_vsx_ld(OFF_0, src), vec_avg), OFF_0, dst);
+    vec_vsx_st(vec_sub(vec_vsx_ld(OFF_0 + CFL_LINE_1, src), vec_avg),
+               OFF_0 + CFL_LINE_1, dst);
+    vec_vsx_st(vec_sub(vec_vsx_ld(OFF_0 + CFL_LINE_2, src), vec_avg),
                OFF_0 + CFL_LINE_2, dst);
-    vec_vsx_st(vec_sub(vec_vsx_ld(OFF_0 + CFL_LINE_3, dst), vec_avg),
+    vec_vsx_st(vec_sub(vec_vsx_ld(OFF_0 + CFL_LINE_3, src), vec_avg),
                OFF_0 + CFL_LINE_3, dst);
     if (width >= 16) {
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_1, dst), vec_avg), OFF_1, dst);
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_1 + CFL_LINE_1, dst), vec_avg),
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_1, src), vec_avg), OFF_1, dst);
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_1 + CFL_LINE_1, src), vec_avg),
                  OFF_1 + CFL_LINE_1, dst);
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_1 + CFL_LINE_2, dst), vec_avg),
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_1 + CFL_LINE_2, src), vec_avg),
                  OFF_1 + CFL_LINE_2, dst);
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_1 + CFL_LINE_3, dst), vec_avg),
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_1 + CFL_LINE_3, src), vec_avg),
                  OFF_1 + CFL_LINE_3, dst);
     }
     if (width == 32) {
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_2, dst), vec_avg), OFF_2, dst);
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_2 + CFL_LINE_1, dst), vec_avg),
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_2, src), vec_avg), OFF_2, dst);
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_2 + CFL_LINE_1, src), vec_avg),
                  OFF_2 + CFL_LINE_1, dst);
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_2 + CFL_LINE_2, dst), vec_avg),
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_2 + CFL_LINE_2, src), vec_avg),
                  OFF_2 + CFL_LINE_2, dst);
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_2 + CFL_LINE_3, dst), vec_avg),
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_2 + CFL_LINE_3, src), vec_avg),
                  OFF_2 + CFL_LINE_3, dst);
 
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_3, dst), vec_avg), OFF_3, dst);
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_3 + CFL_LINE_1, dst), vec_avg),
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_3, src), vec_avg), OFF_3, dst);
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_3 + CFL_LINE_1, src), vec_avg),
                  OFF_3 + CFL_LINE_1, dst);
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_3 + CFL_LINE_2, dst), vec_avg),
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_3 + CFL_LINE_2, src), vec_avg),
                  OFF_3 + CFL_LINE_2, dst);
-      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_3 + CFL_LINE_3, dst), vec_avg),
+      vec_vsx_st(vec_sub(vec_vsx_ld(OFF_3 + CFL_LINE_3, src), vec_avg),
                  OFF_3 + CFL_LINE_3, dst);
     }
-  } while ((dst += CFL_BUF_LINE * 4) < dst_end);
+    src += CFL_BUF_LINE * 4;
+    dst += CFL_BUF_LINE * 4;
+  } while (src < end);
 }
 
 // Declare wrappers for VSX sizes
diff --git a/av1/encoder/arm/highbd_pickrst_neon.c b/av1/encoder/arm/highbd_pickrst_neon.c
index 00f88bcf0..bb85a4b92 100644
--- a/av1/encoder/arm/highbd_pickrst_neon.c
+++ b/av1/encoder/arm/highbd_pickrst_neon.c
@@ -1902,7 +1902,7 @@ int64_t av1_highbd_pixel_proj_error_neon(
 
       for (int k = j; k < width; ++k) {
         int32_t v = 1 << (SGRPROJ_RST_BITS + SGRPROJ_PRJ_BITS - 1);
-        v += xq_active * (int32_t)((uint32_t)flt[j] - (uint16_t)(dat[k] << 4));
+        v += xq_active * (int32_t)((uint32_t)flt[k] - (uint16_t)(dat[k] << 4));
         const int32_t e =
             (v >> (SGRPROJ_RST_BITS + SGRPROJ_PRJ_BITS)) + dat[k] - src[k];
         sse += ((int64_t)e * e);
diff --git a/av1/encoder/encoder.c b/av1/encoder/encoder.c
index 31d885393..87f25157f 100644
--- a/av1/encoder/encoder.c
+++ b/av1/encoder/encoder.c
@@ -3372,6 +3372,7 @@ static int encode_with_and_without_superres(AV1_COMP *cpi, size_t *size,
         const int this_index = denom - (SCALE_NUMERATOR + 1);
         superres_sses[this_index] = INT64_MAX;
         superres_rates[this_index] = INT64_MAX;
+        superres_largest_tile_ids[this_index] = 0;
       }
     }
     // Encode without superres.
diff --git a/av1/encoder/nonrd_pickmode.c b/av1/encoder/nonrd_pickmode.c
index 96070ab32..fd01565e5 100644
--- a/av1/encoder/nonrd_pickmode.c
+++ b/av1/encoder/nonrd_pickmode.c
@@ -322,10 +322,10 @@ static int search_new_mv(AV1_COMP *cpi, MACROBLOCK *x,
 
     int me_search_size_col = block_size_wide[bsize] >> 1;
     int me_search_size_row = block_size_high[bsize] >> 1;
+    MV ref_mv = av1_get_ref_mv(x, 0).as_mv;
     tmp_sad = av1_int_pro_motion_estimation(
-        cpi, x, bsize, mi_row, mi_col,
-        &x->mbmi_ext.ref_mv_stack[ref_frame][0].this_mv.as_mv, &y_sad_zero,
-        me_search_size_col, me_search_size_row);
+        cpi, x, bsize, mi_row, mi_col, &ref_mv, &y_sad_zero, me_search_size_col,
+        me_search_size_row);
 
     if (tmp_sad > x->pred_mv_sad[LAST_FRAME]) return -1;
 
@@ -333,7 +333,6 @@ static int search_new_mv(AV1_COMP *cpi, MACROBLOCK *x,
     int_mv best_mv = mi->mv[0];
     best_mv.as_mv.row >>= 3;
     best_mv.as_mv.col >>= 3;
-    MV ref_mv = av1_get_ref_mv(x, 0).as_mv;
     this_ref_frm_newmv->as_mv.row >>= 3;
     this_ref_frm_newmv->as_mv.col >>= 3;
 
diff --git a/av1/encoder/pickcdef.c b/av1/encoder/pickcdef.c
index f2943cf0d..5e3f1b46f 100644
--- a/av1/encoder/pickcdef.c
+++ b/av1/encoder/pickcdef.c
@@ -230,7 +230,7 @@ static inline void init_src_params(int *src_stride, int *width, int *height,
   *width = block_size_wide[bsize];
   *height = block_size_high[bsize];
   *width_log2 = MI_SIZE_LOG2 + mi_size_wide_log2[bsize];
-  *height_log2 = MI_SIZE_LOG2 + mi_size_wide_log2[bsize];
+  *height_log2 = MI_SIZE_LOG2 + mi_size_high_log2[bsize];
 }
 #if CONFIG_AV1_HIGHBITDEPTH
 /* Compute MSE only on the blocks we filtered. */
diff --git a/build/cmake/dist.cmake b/build/cmake/dist.cmake
index 24db93e29..511f34a2e 100644
--- a/build/cmake/dist.cmake
+++ b/build/cmake/dist.cmake
@@ -8,7 +8,7 @@
 # License 1.0 was not distributed with this source code in the PATENTS file, you
 # can obtain it at www.aomedia.org/license/patent.
 #
-cmake_minimum_required(VERSION 3.5)
+cmake_minimum_required(VERSION 3.16)
 
 # Converts spaces in $in_string to semicolons and writes the output to
 # $out_string. In CMake's eyes this converts the input string to a list.
diff --git a/build/cmake/generate_aom_config_templates.cmake b/build/cmake/generate_aom_config_templates.cmake
index 743d007dd..17e4c2d04 100644
--- a/build/cmake/generate_aom_config_templates.cmake
+++ b/build/cmake/generate_aom_config_templates.cmake
@@ -8,7 +8,7 @@
 # License 1.0 was not distributed with this source code in the PATENTS file, you
 # can obtain it at www.aomedia.org/license/patent.
 #
-cmake_minimum_required(VERSION 3.5)
+cmake_minimum_required(VERSION 3.16)
 
 string(TIMESTAMP year "%Y")
 set(asm_file_header_block "\;
diff --git a/build/cmake/generate_exports.cmake b/build/cmake/generate_exports.cmake
index 10a6a8fbe..bab165d70 100644
--- a/build/cmake/generate_exports.cmake
+++ b/build/cmake/generate_exports.cmake
@@ -8,7 +8,7 @@
 # License 1.0 was not distributed with this source code in the PATENTS file, you
 # can obtain it at www.aomedia.org/license/patent.
 #
-cmake_minimum_required(VERSION 3.5)
+cmake_minimum_required(VERSION 3.16)
 
 # CMAKE_SHARED_LIBRARY_PREFIX can be empty
 set(REQUIRED_ARGS "AOM_ROOT" "AOM_CONFIG_DIR" "AOM_TARGET_SYSTEM" "AOM_SYM_FILE"
diff --git a/build/cmake/pkg_config.cmake b/build/cmake/pkg_config.cmake
index 7fb94e724..88a33a58a 100644
--- a/build/cmake/pkg_config.cmake
+++ b/build/cmake/pkg_config.cmake
@@ -8,7 +8,7 @@
 # License 1.0 was not distributed with this source code in the PATENTS file, you
 # can obtain it at www.aomedia.org/license/patent.
 #
-cmake_minimum_required(VERSION 3.5)
+cmake_minimum_required(VERSION 3.16)
 
 set(REQUIRED_ARGS "AOM_ROOT" "AOM_CONFIG_DIR" "CMAKE_INSTALL_PREFIX"
                   "CMAKE_INSTALL_BINDIR" "CMAKE_INSTALL_INCLUDEDIR"
diff --git a/build/cmake/version.cmake b/build/cmake/version.cmake
index 24fbf9c33..3b2842ee4 100644
--- a/build/cmake/version.cmake
+++ b/build/cmake/version.cmake
@@ -8,7 +8,7 @@
 # License 1.0 was not distributed with this source code in the PATENTS file, you
 # can obtain it at www.aomedia.org/license/patent.
 #
-cmake_minimum_required(VERSION 3.5)
+cmake_minimum_required(VERSION 3.16)
 
 set(REQUIRED_ARGS "AOM_ROOT" "AOM_CONFIG_DIR" "GIT_EXECUTABLE"
                   "PERL_EXECUTABLE")
diff --git a/config/config/aom_version.h b/config/config/aom_version.h
index cd4b7a418..03206ba2c 100644
--- a/config/config/aom_version.h
+++ b/config/config/aom_version.h
@@ -13,10 +13,10 @@
 #define AOM_VERSION_H_
 #define VERSION_MAJOR 3
 #define VERSION_MINOR 12
-#define VERSION_PATCH 0
-#define VERSION_EXTRA "467-g474d494cd0"
+#define VERSION_PATCH 1
+#define VERSION_EXTRA "487-g1ca45cb9d4"
 #define VERSION_PACKED \
   ((VERSION_MAJOR << 16) | (VERSION_MINOR << 8) | (VERSION_PATCH))
-#define VERSION_STRING_NOSP "3.12.0-467-g474d494cd0"
-#define VERSION_STRING " 3.12.0-467-g474d494cd0"
+#define VERSION_STRING_NOSP "3.12.1-487-g1ca45cb9d4"
+#define VERSION_STRING " 3.12.1-487-g1ca45cb9d4"
 #endif  // AOM_VERSION_H_
diff --git a/docs.cmake b/docs.cmake
index 901e8c4a0..154cb0d72 100644
--- a/docs.cmake
+++ b/docs.cmake
@@ -13,7 +13,7 @@ if(AOM_DOCS_CMAKE_)
 endif() # AOM_DOCS_CMAKE_
 set(AOM_DOCS_CMAKE_ 1)
 
-cmake_minimum_required(VERSION 3.5)
+cmake_minimum_required(VERSION 3.16)
 
 set(AOM_DOXYFILE "${AOM_CONFIG_DIR}/doxyfile")
 set(AOM_DOXYGEN_CONFIG_TEMPLATE "libs.doxy_template")
diff --git a/test/acm_random.h b/test/acm_random.h
index 6fb6d566a..67f7aa862 100644
--- a/test/acm_random.h
+++ b/test/acm_random.h
@@ -40,7 +40,7 @@ class ACMRandom {
 
   int16_t Rand16Signed() { return static_cast<int16_t>(Rand16()); }
 
-  int16_t Rand15() {
+  uint16_t Rand15() {
     const uint32_t value =
         random_.Generate(testing::internal::Random::kMaxRange);
     // There's a bit more entropy in the upper bits of this implementation.
diff --git a/test/cfl_test.cc b/test/cfl_test.cc
index e093c4e35..3f9330500 100644
--- a/test/cfl_test.cc
+++ b/test/cfl_test.cc
@@ -175,7 +175,7 @@ class CFLTestWithAlignedData : public CFLTest {
 typedef cfl_subtract_average_fn (*sub_avg_fn)(TX_SIZE tx_size);
 typedef std::tuple<TX_SIZE, sub_avg_fn> sub_avg_param;
 class CFLSubAvgTest : public ::testing::TestWithParam<sub_avg_param>,
-                      public CFLTestWithData<int16_t> {
+                      public CFLTestWithData<uint16_t> {
  public:
   void SetUp() override {
     CFLTest::init(std::get<0>(this->GetParam()));
@@ -191,27 +191,31 @@ class CFLSubAvgTest : public ::testing::TestWithParam<sub_avg_param>,
 GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(CFLSubAvgTest);
 
 TEST_P(CFLSubAvgTest, SubAvgTest) {
+  int16_t dst[CFL_BUF_SQUARE];
+  int16_t dst_ref[CFL_BUF_SQUARE];
   for (int it = 0; it < NUM_ITERATIONS; it++) {
     randData(&ACMRandom::Rand15);
-    sub_avg((uint16_t *)data, data);
-    sub_avg_ref((uint16_t *)data_ref, data_ref);
-    assert_eq<int16_t>(data, data_ref, width, height);
+    sub_avg(data, dst);
+    sub_avg_ref(data_ref, dst_ref);
+    assert_eq<int16_t>(dst, dst_ref, width, height);
   }
 }
 
 TEST_P(CFLSubAvgTest, DISABLED_SubAvgSpeedTest) {
+  int16_t dst[CFL_BUF_SQUARE];
+  int16_t dst_ref[CFL_BUF_SQUARE];
   aom_usec_timer ref_timer;
   aom_usec_timer timer;
   randData(&ACMRandom::Rand15);
   aom_usec_timer_start(&ref_timer);
   for (int k = 0; k < NUM_ITERATIONS_SPEED; k++) {
-    sub_avg_ref((uint16_t *)data_ref, data_ref);
+    sub_avg_ref(data_ref, dst_ref);
   }
   aom_usec_timer_mark(&ref_timer);
   int ref_elapsed_time = (int)aom_usec_timer_elapsed(&ref_timer);
   aom_usec_timer_start(&timer);
   for (int k = 0; k < NUM_ITERATIONS_SPEED; k++) {
-    sub_avg((uint16_t *)data, data);
+    sub_avg(data, dst);
   }
   aom_usec_timer_mark(&timer);
   int elapsed_time = (int)aom_usec_timer_elapsed(&timer);
@@ -261,13 +265,13 @@ class CFLSubsampleTest : public ::testing::TestWithParam<S>,
     CFLTestWithData<I>::randData(random);
     aom_usec_timer_start(&ref_timer);
     for (int k = 0; k < NUM_ITERATIONS_SPEED; k++) {
-      fun_ref(this->data_ref, CFL_BUF_LINE, sub_luma_pels);
+      fun_ref(this->data_ref, CFL_BUF_LINE, sub_luma_pels_ref);
     }
     aom_usec_timer_mark(&ref_timer);
     int ref_elapsed_time = (int)aom_usec_timer_elapsed(&ref_timer);
     aom_usec_timer_start(&timer);
     for (int k = 0; k < NUM_ITERATIONS_SPEED; k++) {
-      fun(this->data, CFL_BUF_LINE, sub_luma_pels_ref);
+      fun(this->data, CFL_BUF_LINE, sub_luma_pels);
     }
     aom_usec_timer_mark(&timer);
     int elapsed_time = (int)aom_usec_timer_elapsed(&timer);
diff --git a/test/datarate_test.cc b/test/datarate_test.cc
index e1d6a1d02..97fa32a0d 100644
--- a/test/datarate_test.cc
+++ b/test/datarate_test.cc
@@ -21,9 +21,59 @@
 #include "test/y4m_video_source.h"
 #include "aom/aom_codec.h"
 
+#if CONFIG_LIBYUV
+#include "third_party/libyuv/include/libyuv/scale.h"
+#endif
+
 namespace datarate_test {
 namespace {
 
+#if CONFIG_LIBYUV
+class ResizingVideoSource : public ::libaom_test::DummyVideoSource {
+ public:
+  ResizingVideoSource(const int width, const int height, const int input_width,
+                      const int input_height, const std::string file_name,
+                      int limit)
+      : width_(width), height_(height), input_width_(input_width),
+        input_height_(input_height), limit_(limit) {
+    SetSize(width_, height_);
+    img_input_ = aom_img_alloc(nullptr, AOM_IMG_FMT_I420, input_width_,
+                               input_height_, 32);
+    raw_size_ = input_width_ * input_height_ * 3 / 2;
+    input_file_ = ::libaom_test::OpenTestDataFile(file_name);
+  }
+
+  ~ResizingVideoSource() override {
+    aom_img_free(img_input_);
+    fclose(input_file_);
+  }
+
+ protected:
+  void FillFrame() override {
+    // Read frame from input_file and scale up.
+    ASSERT_NE(input_file_, nullptr);
+    fread(img_input_->img_data, raw_size_, 1, input_file_);
+    libyuv::I420Scale(
+        img_input_->planes[AOM_PLANE_Y], img_input_->stride[AOM_PLANE_Y],
+        img_input_->planes[AOM_PLANE_U], img_input_->stride[AOM_PLANE_U],
+        img_input_->planes[AOM_PLANE_V], img_input_->stride[AOM_PLANE_V],
+        input_width_, input_height_, img_->planes[AOM_PLANE_Y],
+        img_->stride[AOM_PLANE_Y], img_->planes[AOM_PLANE_U],
+        img_->stride[AOM_PLANE_U], img_->planes[AOM_PLANE_V],
+        img_->stride[AOM_PLANE_V], width_, height_, libyuv::kFilterBox);
+  }
+
+  const int width_;
+  const int height_;
+  const int input_width_;
+  const int input_height_;
+  const int limit_;
+  aom_image_t *img_input_;
+  size_t raw_size_;
+  FILE *input_file_;
+};
+#endif  // CONFIG_LIBYUV
+
 // Params: test mode, speed, aq mode and index for bitrate array.
 class DatarateTestLarge
     : public ::libaom_test::CodecTestWith4Params<libaom_test::TestMode, int,
@@ -86,6 +136,27 @@ class DatarateTestLarge
         << " The datarate for the file is greater than target by too much!";
   }
 
+#if CONFIG_LIBYUV
+  // Test for an encoding mode that triggers an assert in nonrd_pickmode
+  // (in av1_is_subpelmv_in_range), issue b:396169342.
+  // The assert is triggered on a 2456x2054 resolution with settings defined
+  // with the flag avif_mode_. This test upsamples a QVGA clip to the target
+  // resolution, using libyuv for the scaling.
+  virtual void BasicRateTargetingCBRAssertAvifModeTest() {
+    cfg_.rc_min_quantizer = 0;
+    cfg_.rc_max_quantizer = 63;
+    cfg_.rc_end_usage = AOM_CBR;
+    cfg_.g_lag_in_frames = 0;
+    ResizingVideoSource video(2456, 2054, 320, 240,
+                              "pixel_capture_w320h240.yuv", 100);
+    const int bitrate_array[2] = { 1000, 2000 };
+    cfg_.rc_target_bitrate = bitrate_array[GET_PARAM(4)];
+    ResetModel();
+    avif_mode_ = 1;
+    ASSERT_NO_FATAL_FAILURE(RunLoop(&video));
+  }
+#endif  // CONFIG_LIBYUV
+
   virtual void BasicRateTargetingCBRSpikeTest() {
     cfg_.rc_buf_initial_sz = 500;
     cfg_.rc_buf_optimal_sz = 500;
@@ -555,6 +626,13 @@ TEST_P(DatarateTestRealtime, BasicRateTargetingCBR) {
   BasicRateTargetingCBRTest();
 }
 
+#if CONFIG_LIBYUV
+// Check basic rate targeting for CBR, special case.
+TEST_P(DatarateTestRealtime, BasicRateTargetingCBRAssertAvifMode) {
+  BasicRateTargetingCBRAssertAvifModeTest();
+}
+#endif
+
 // Check basic rate targeting for CBR. Use a longer clip,
 // and verify #encode size spikes above threshold.
 TEST_P(DatarateTestRealtime, BasicRateTargetingCBRSpike) {
diff --git a/test/datarate_test.h b/test/datarate_test.h
index 9c88ef528..9064d1d9f 100644
--- a/test/datarate_test.h
+++ b/test/datarate_test.h
@@ -57,6 +57,7 @@ class DatarateTest : public ::libaom_test::EncoderTest {
       bits_total_dynamic_[i] = 0;
       effective_datarate_dynamic_[i] = 0.0;
     }
+    avif_mode_ = 0;
   }
 
   void PreEncodeFrameHook(::libaom_test::VideoSource *video,
@@ -90,6 +91,21 @@ class DatarateTest : public ::libaom_test::EncoderTest {
         encoder->Control(AV1E_SET_ENABLE_PALETTE, 1);
         encoder->Control(AV1E_SET_ENABLE_INTRABC, 0);
       }
+      if (avif_mode_) {
+        encoder->Control(AV1E_SET_COEFF_COST_UPD_FREQ, 0);
+        encoder->Control(AV1E_SET_MODE_COST_UPD_FREQ, 0);
+        encoder->Control(AV1E_SET_MV_COST_UPD_FREQ, 0);
+#if !CONFIG_REALTIME_ONLY
+        encoder->Control(AV1E_SET_DELTAQ_MODE, 3);
+#endif
+#if CONFIG_QUANT_MATRIX
+        encoder->Control(AV1E_SET_ENABLE_QM, 1);
+#endif
+        encoder->Control(AOME_SET_SHARPNESS, 1);
+        encoder->Control(AV1E_SET_ENABLE_CHROMA_DELTAQ, 1);
+        encoder->Control(AOME_SET_CQ_LEVEL, 0);
+        encoder->Control(AV1E_SET_AQ_MODE, (aq_mode_ > 0) ? 1 : 0);
+      }
     }
 
     if (speed_change_test_) {
@@ -227,6 +243,7 @@ class DatarateTest : public ::libaom_test::EncoderTest {
   double effective_datarate_dynamic_[3];
   int64_t bits_total_dynamic_[3];
   int frame_number_dynamic_[3];
+  int avif_mode_;
 };
 
 }  // namespace
diff --git a/test/test.cmake b/test/test.cmake
index b3227b893..55fcc14d3 100644
--- a/test/test.cmake
+++ b/test/test.cmake
@@ -501,7 +501,13 @@ function(setup_aom_test_targets)
     endif()
   endif()
 
-  target_link_libraries(test_libaom ${AOM_LIB_LINK_TYPE} aom aom_gtest)
+  if(CONFIG_LIBYUV)
+    # link test_libaom with yuv
+    target_link_libraries(test_libaom ${AOM_LIB_LINK_TYPE} aom aom_gtest yuv)
+  else()
+    # do not link test_libaom with yuv
+    target_link_libraries(test_libaom ${AOM_LIB_LINK_TYPE} aom aom_gtest)
+  endif()
 
   if(CONFIG_WEBM_IO)
     target_sources(test_libaom PRIVATE $<TARGET_OBJECTS:webm>)
```

