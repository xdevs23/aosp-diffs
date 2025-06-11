```diff
diff --git a/Android.bp b/Android.bp
index 93deae4..d13bf35 100644
--- a/Android.bp
+++ b/Android.bp
@@ -215,17 +215,17 @@ cc_library_static {
     srcs: [
         "src/buffer_pool.cc",
         "src/frame_buffer.cc",
-        "src/obu_parser.cc",
         "src/internal_frame_buffer_list.cc",
+        "src/obu_parser.cc",
+        "src/quantizer.cc",
         "src/status_code.cc",
+        "src/symbol_decoder_context.cc",
         "src/utils/bit_reader.cc",
         "src/utils/constants.cc",
         "src/utils/logging.cc",
         "src/utils/raw_bit_reader.cc",
         "src/utils/segmentation.cc",
         "src/utils/segmentation_map.cc",
-        "src/symbol_decoder_context.cc",
-        "src/quantizer.cc",
         "src/yuv_buffer.cc",
     ],
 }
diff --git a/METADATA b/METADATA
index 38ae79a..eb8932e 100644
--- a/METADATA
+++ b/METADATA
@@ -1,23 +1,20 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update libgav1
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/libgav1
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libgav1"
 description: "Google\'s decoder implementation of the AV1 video codec."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "http://go/libgav1-doc"
-  }
-  url {
-    type: GIT
-    value: "https://chromium.googlesource.com/codecs/libgav1"
-  }
-  version: "v0.19.0"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2023
-    month: 10
-    day: 31
+    year: 2025
+    month: 1
+    day: 23
+  }
+  homepage: "http://go/libgav1-doc"
+  identifier {
+    type: "Git"
+    value: "https://chromium.googlesource.com/codecs/libgav1"
+    version: "v0.20.0"
   }
 }
diff --git a/README.md b/README.md
index bdf598c..03eef8f 100644
--- a/README.md
+++ b/README.md
@@ -81,6 +81,7 @@ Configuration options:
     decoding will be used if |threads| > |tile_count| * this multiplier. Has to
     be an integer > 0. The default value is 4. This is an advanced setting
     intended for testing purposes.
+*   `CHROMIUM`: apply Chromium-specific changes if set.
 
 For additional options see:
 
diff --git a/cmake/libgav1_build_definitions.cmake b/cmake/libgav1_build_definitions.cmake
index 1465679..80148df 100644
--- a/cmake/libgav1_build_definitions.cmake
+++ b/cmake/libgav1_build_definitions.cmake
@@ -31,7 +31,7 @@ macro(libgav1_set_build_definitions)
   # passed to libtool.
   #
   # We set LIBGAV1_SOVERSION = [c-a].a.r
-  set(LT_CURRENT 1)
+  set(LT_CURRENT 2)
   set(LT_REVISION 0)
   set(LT_AGE 0)
   math(EXPR LIBGAV1_SOVERSION_MAJOR "${LT_CURRENT} - ${LT_AGE}")
diff --git a/examples/file_reader.cc b/examples/file_reader.cc
index a01b7ab..39820f8 100644
--- a/examples/file_reader.cc
+++ b/examples/file_reader.cc
@@ -17,6 +17,7 @@
 #include <algorithm>
 #include <cstdint>
 #include <cstdio>
+#include <memory>
 #include <new>
 #include <string>
 #include <vector>
diff --git a/examples/file_reader_factory.cc b/examples/file_reader_factory.cc
index d5260eb..d71729a 100644
--- a/examples/file_reader_factory.cc
+++ b/examples/file_reader_factory.cc
@@ -14,7 +14,10 @@
 
 #include "examples/file_reader_factory.h"
 
+#include <memory>
 #include <new>
+#include <string>
+#include <vector>
 
 #include "examples/logging.h"
 
diff --git a/examples/file_reader_test.cc b/examples/file_reader_test.cc
index 53e27f7..28d9871 100644
--- a/examples/file_reader_test.cc
+++ b/examples/file_reader_test.cc
@@ -17,6 +17,7 @@
 #include <cstdint>
 #include <cstdio>
 #include <memory>
+#include <string>
 #include <vector>
 
 #include "examples/file_reader_interface.h"
diff --git a/examples/file_writer.cc b/examples/file_writer.cc
index 54afe14..a673ed5 100644
--- a/examples/file_writer.cc
+++ b/examples/file_writer.cc
@@ -17,6 +17,7 @@
 #include <cerrno>
 #include <cstdio>
 #include <cstring>
+#include <memory>
 #include <new>
 #include <string>
 
diff --git a/examples/gav1_decode.cc b/examples/gav1_decode.cc
index 1408e8c..24f1c95 100644
--- a/examples/gav1_decode.cc
+++ b/examples/gav1_decode.cc
@@ -47,6 +47,7 @@ struct Options {
   int threads = 1;
   bool frame_parallel = false;
   bool output_all_layers = false;
+  bool parse_only = false;
   int operating_point = 0;
   int limit = 0;
   int skip = 0;
@@ -80,6 +81,9 @@ void PrintHelp(FILE* const fout) {
   fprintf(fout, "  --raw (Default true).\n");
   fprintf(fout, "  -v logging verbosity, can be used multiple times.\n");
   fprintf(fout, "  --all_layers.\n");
+  fprintf(fout,
+          "  --parse_only, only parses the encoded video without producing "
+          "decoded frames.\n");
   fprintf(fout,
           "  --operating_point <integer between 0 and 31> (Default 0).\n");
   fprintf(fout,
@@ -140,6 +144,8 @@ void ParseOptions(int argc, char* argv[], Options* const options) {
       options->threads = value;
     } else if (strcmp(argv[i], "--frame_parallel") == 0) {
       options->frame_parallel = true;
+    } else if (strcmp(argv[i], "--parse_only") == 0) {
+      options->parse_only = true;
     } else if (strcmp(argv[i], "--all_layers") == 0) {
       options->output_all_layers = true;
     } else if (strcmp(argv[i], "--operating_point") == 0) {
@@ -196,6 +202,15 @@ void ParseOptions(int argc, char* argv[], Options* const options) {
     PrintHelp(stderr);
     exit(EXIT_FAILURE);
   }
+
+  if (options->parse_only &&
+      (options->threads > 1 || options->frame_parallel)) {
+    fprintf(stderr,
+            "Neither --threads nor --frame_parallel can be set together "
+            "with the --parse_only option.\n");
+    PrintHelp(stderr);
+    exit(EXIT_FAILURE);
+  }
 }
 
 using InputBuffer = std::vector<uint8_t>;
@@ -280,6 +295,7 @@ int main(int argc, char* argv[]) {
   settings.post_filter_mask = options.post_filter_mask;
   settings.threads = options.threads;
   settings.frame_parallel = options.frame_parallel;
+  settings.parse_only = options.parse_only;
   settings.output_all_layers = options.output_all_layers;
   settings.operating_point = options.operating_point;
   settings.blocking_dequeue = true;
@@ -309,6 +325,7 @@ int main(int argc, char* argv[]) {
 
   int input_frames = 0;
   int decoded_frames = 0;
+  int parsed_frames = 0;
   Timing timing = {};
   std::vector<FrameTiming> frame_timing;
   const bool record_frame_timing = frame_timing_file != nullptr;
@@ -379,6 +396,26 @@ int main(int argc, char* argv[]) {
               libgav1::GetErrorString(status));
       return EXIT_FAILURE;
     }
+    if (options.parse_only) {
+      // Example of how the QP values per frame in decoding/parsing
+      // order can be obtained.
+      std::vector<int> qp_vec = decoder.GetFramesMeanQpInTemporalUnit();
+      if (qp_vec.empty()) {
+        fprintf(stderr,
+                "The latest temporal unit did not contain any decodable "
+                "frames. Hence, no QP values to show.");
+      } else {
+        fprintf(
+            stderr,
+            "The QP values for the frames in the latest temporal unit are: ");
+      }
+      while (!qp_vec.empty()) {
+        fprintf(stderr, "%d, ", qp_vec.front());
+        qp_vec.erase(qp_vec.begin());
+        ++parsed_frames;
+      }
+      fprintf(stderr, "\n");
+    }
     dequeue_finished = false;
     if (buffer == nullptr) continue;
     ++decoded_frames;
@@ -443,12 +480,21 @@ int main(int argc, char* argv[]) {
   if (options.verbose > 0) {
     fprintf(stderr, "time to read input: %d us\n",
             static_cast<int>(absl::ToInt64Microseconds(timing.input)));
-    const int decode_time_us =
+    const int process_time_us =
         static_cast<int>(absl::ToInt64Microseconds(timing.dequeue));
-    const double decode_fps =
-        (decode_time_us == 0) ? 0.0 : 1.0e6 * decoded_frames / decode_time_us;
-    fprintf(stderr, "time to decode input: %d us (%d frames, %.2f fps)\n",
-            decode_time_us, decoded_frames, decode_fps);
+    if (options.parse_only) {
+      const double parse_fps = (process_time_us == 0)
+                                   ? 0.0
+                                   : 1.0e6 * parsed_frames / process_time_us;
+      fprintf(stderr, "time to parse input: %d us (%d frames, %.2f fps)\n",
+              process_time_us, parsed_frames, parse_fps);
+    } else {
+      const double decode_fps = (process_time_us == 0)
+                                    ? 0.0
+                                    : 1.0e6 * decoded_frames / process_time_us;
+      fprintf(stderr, "time to decode input: %d us (%d frames, %.2f fps)\n",
+              process_time_us, decoded_frames, decode_fps);
+    }
   }
 
   return EXIT_SUCCESS;
diff --git a/src/buffer_pool.cc b/src/buffer_pool.cc
index 582f13c..862d065 100644
--- a/src/buffer_pool.cc
+++ b/src/buffer_pool.cc
@@ -14,8 +14,11 @@
 
 #include "src/buffer_pool.h"
 
+#include <array>
 #include <cassert>
 #include <cstring>
+#include <mutex>  // NOLINT (unapproved c++11 header)
+#include <new>
 
 #include "src/utils/common.h"
 #include "src/utils/constants.h"
diff --git a/src/decoder.cc b/src/decoder.cc
index b9e43e0..28036a9 100644
--- a/src/decoder.cc
+++ b/src/decoder.cc
@@ -16,6 +16,7 @@
 
 #include <memory>
 #include <new>
+#include <vector>
 
 #include "src/decoder_impl.h"
 
@@ -40,6 +41,7 @@ Libgav1StatusCode Libgav1DecoderCreate(const Libgav1DecoderSettings* settings,
   cxx_settings.output_all_layers = settings->output_all_layers != 0;
   cxx_settings.operating_point = settings->operating_point;
   cxx_settings.post_filter_mask = settings->post_filter_mask;
+  cxx_settings.parse_only = settings->parse_only != 0;
 
   const Libgav1StatusCode status = cxx_decoder->Init(&cxx_settings);
   if (status == kLibgav1StatusOk) {
@@ -101,7 +103,11 @@ StatusCode Decoder::EnqueueFrame(const uint8_t* data, const size_t size,
 
 StatusCode Decoder::DequeueFrame(const DecoderBuffer** out_ptr) {
   if (impl_ == nullptr) return kStatusNotInitialized;
-  return impl_->DequeueFrame(out_ptr);
+  StatusCode status = impl_->DequeueFrame(out_ptr);
+  if (settings_.parse_only) {
+    frame_mean_qps_ = impl_->GetFrameQps();
+  }
+  return status;
 }
 
 StatusCode Decoder::SignalEOS() {
@@ -116,4 +122,8 @@ StatusCode Decoder::SignalEOS() {
 // static.
 int Decoder::GetMaxBitdepth() { return DecoderImpl::GetMaxBitdepth(); }
 
+std::vector<int> Decoder::GetFramesMeanQpInTemporalUnit() {
+  return frame_mean_qps_;
+}
+
 }  // namespace libgav1
diff --git a/src/decoder_impl.cc b/src/decoder_impl.cc
index e8de64a..2344593 100644
--- a/src/decoder_impl.cc
+++ b/src/decoder_impl.cc
@@ -17,9 +17,14 @@
 #include <algorithm>
 #include <atomic>
 #include <cassert>
+#include <cmath>
+#include <condition_variable>  // NOLINT (unapproved c++11 header)
 #include <iterator>
+#include <memory>
+#include <mutex>  // NOLINT (unapproved c++11 header)
 #include <new>
 #include <utility>
+#include <vector>
 
 #include "src/dsp/common.h"
 #include "src/dsp/constants.h"
@@ -211,6 +216,16 @@ StatusCode DecodeTilesThreadedNonFrameParallel(
   return kStatusOk;
 }
 
+StatusCode ParseTiles(const Vector<std::unique_ptr<Tile>>& tiles) {
+  for (const auto& tile : tiles) {
+    if (!tile->Parse()) {
+      LIBGAV1_DLOG(ERROR, "Failed to parse tile number: %d\n", tile->number());
+      return kStatusUnknownError;
+    }
+  }
+  return kStatusOk;
+}
+
 StatusCode DecodeTilesFrameParallel(
     const ObuSequenceHeader& sequence_header,
     const ObuFrameHeader& frame_header,
@@ -220,12 +235,8 @@ StatusCode DecodeTilesFrameParallel(
     FrameScratchBuffer* const frame_scratch_buffer,
     PostFilter* const post_filter, RefCountedBuffer* const current_frame) {
   // Parse the frame.
-  for (const auto& tile : tiles) {
-    if (!tile->Parse()) {
-      LIBGAV1_DLOG(ERROR, "Failed to parse tile number: %d\n", tile->number());
-      return kStatusUnknownError;
-    }
-  }
+  StatusCode status = ParseTiles(tiles);
+  if (status != kStatusOk) return status;
   if (frame_header.enable_frame_end_update_cdf) {
     frame_scratch_buffer->symbol_decoder_context = saved_symbol_decoder_context;
   }
@@ -580,6 +591,22 @@ StatusCode DecodeTilesThreadedFrameParallel(
   return kStatusOk;
 }
 
+int CalcFrameMeanQp(const Vector<std::unique_ptr<Tile>>& tiles) {
+  int cumulative_frame_qp = 0;
+  for (const auto& tile : tiles) {
+    cumulative_frame_qp += tile->GetTileMeanQP();
+  }
+  const int frame_mean_qp = static_cast<int>(
+      std::round(cumulative_frame_qp / static_cast<float>(tiles.size())));
+  if (frame_mean_qp > 255 || frame_mean_qp < 0) {
+    LIBGAV1_DLOG(
+        WARNING,
+        "The mean QP value for the frame is %d, i.e., out of bounds for AV1.",
+        frame_mean_qp);
+  }
+  return frame_mean_qp;
+}
+
 }  // namespace
 
 // static
@@ -597,6 +624,14 @@ StatusCode DecoderImpl::Create(const DecoderSettings* settings,
       return kStatusInvalidArgument;
     }
   }
+  if (settings->parse_only &&
+      (settings->threads > 1 || settings->frame_parallel)) {
+    LIBGAV1_DLOG(
+        ERROR,
+        "The number of threads cannot be more than 1 (default) and "
+        "the frame_parallel option cannot be used in the parse_only mode.");
+    return kStatusInvalidArgument;
+  }
   std::unique_ptr<DecoderImpl> impl(new (std::nothrow) DecoderImpl(settings));
   if (impl == nullptr) {
     LIBGAV1_DLOG(ERROR, "Failed to allocate DecoderImpl.");
@@ -824,6 +859,8 @@ StatusCode DecoderImpl::DequeueFrame(const DecoderBuffer** out_ptr) {
   return kStatusOk;
 }
 
+std::vector<int> DecoderImpl::GetFrameQps() { return frame_mean_qps_; }
+
 StatusCode DecoderImpl::ParseAndSchedule(const uint8_t* data, size_t size,
                                          int64_t user_private_data,
                                          void* buffer_private_data) {
@@ -1023,6 +1060,7 @@ StatusCode DecoderImpl::DecodeTemporalUnit(const TemporalUnit& temporal_unit,
     LIBGAV1_DLOG(ERROR, "Failed to allocate OBU parser.");
     return kStatusOutOfMemory;
   }
+  frame_mean_qps_.clear();
   if (has_sequence_header_) {
     obu->set_sequence_header(sequence_header_);
   }
@@ -1081,6 +1119,9 @@ StatusCode DecoderImpl::DecodeTemporalUnit(const TemporalUnit& temporal_unit,
       status = DecodeTiles(obu->sequence_header(), obu->frame_header(),
                            obu->tile_buffers(), state_,
                            frame_scratch_buffer.get(), current_frame.get());
+      if (settings_.parse_only) {
+        frame_mean_qps_.push_back(frame_mean_qp_);
+      }
       if (status != kStatusOk) {
         return status;
       }
@@ -1097,13 +1138,15 @@ StatusCode DecoderImpl::DecodeTemporalUnit(const TemporalUnit& temporal_unit,
         assert(output_frame_queue_.Size() == 1);
         output_frame_queue_.Pop();
       }
-      RefCountedBufferPtr film_grain_frame;
-      status = ApplyFilmGrain(
-          obu->sequence_header(), obu->frame_header(), current_frame,
-          &film_grain_frame,
-          frame_scratch_buffer->threading_strategy.film_grain_thread_pool());
-      if (status != kStatusOk) return status;
-      output_frame_queue_.Push(std::move(film_grain_frame));
+      if (!settings_.parse_only) {
+        RefCountedBufferPtr film_grain_frame;
+        status = ApplyFilmGrain(
+            obu->sequence_header(), obu->frame_header(), current_frame,
+            &film_grain_frame,
+            frame_scratch_buffer->threading_strategy.film_grain_thread_pool());
+        if (status != kStatusOk) return status;
+        output_frame_queue_.Push(std::move(film_grain_frame));
+      }
     }
   }
   if (output_frame_queue_.Empty()) {
@@ -1327,7 +1370,8 @@ StatusCode DecoderImpl::DecodeTiles(
     return kStatusOutOfMemory;
   }
 
-  if (threading_strategy.row_thread_pool(0) != nullptr || is_frame_parallel_) {
+  if (threading_strategy.row_thread_pool(0) != nullptr || is_frame_parallel_ ||
+      settings_.parse_only) {
     if (frame_scratch_buffer->residual_buffer_pool == nullptr) {
       frame_scratch_buffer->residual_buffer_pool.reset(
           new (std::nothrow) ResidualBufferPool(
@@ -1528,7 +1572,8 @@ StatusCode DecoderImpl::DecodeTiles(
         current_frame, state, frame_scratch_buffer, wedge_masks_,
         quantizer_matrix_, &saved_symbol_decoder_context, prev_segment_ids,
         &post_filter, dsp, threading_strategy.row_thread_pool(tile_number),
-        &pending_tiles, is_frame_parallel_, use_intra_prediction_buffer);
+        &pending_tiles, is_frame_parallel_, use_intra_prediction_buffer,
+        settings_.parse_only);
     if (tile == nullptr) {
       LIBGAV1_DLOG(ERROR, "Failed to create tile.");
       return kStatusOutOfMemory;
@@ -1536,25 +1581,34 @@ StatusCode DecoderImpl::DecodeTiles(
     tiles.push_back_unchecked(std::move(tile));
   }
   assert(tiles.size() == static_cast<size_t>(tile_count));
-  if (is_frame_parallel_) {
-    if (frame_scratch_buffer->threading_strategy.thread_pool() == nullptr) {
-      return DecodeTilesFrameParallel(
+  if (settings_.parse_only) {  // Parse only.
+    if (ParseTiles(tiles) != kStatusOk) {
+      return kStatusUnknownError;
+    }
+    frame_mean_qp_ = CalcFrameMeanQp(tiles);
+  } else {  // Decode.
+    if (is_frame_parallel_) {
+      if (frame_scratch_buffer->threading_strategy.thread_pool() == nullptr) {
+        return DecodeTilesFrameParallel(sequence_header, frame_header, tiles,
+                                        saved_symbol_decoder_context,
+                                        prev_segment_ids, frame_scratch_buffer,
+                                        &post_filter, current_frame);
+      }
+      return DecodeTilesThreadedFrameParallel(
           sequence_header, frame_header, tiles, saved_symbol_decoder_context,
           prev_segment_ids, frame_scratch_buffer, &post_filter, current_frame);
     }
-    return DecodeTilesThreadedFrameParallel(
-        sequence_header, frame_header, tiles, saved_symbol_decoder_context,
-        prev_segment_ids, frame_scratch_buffer, &post_filter, current_frame);
-  }
-  StatusCode status;
-  if (settings_.threads == 1) {
-    status = DecodeTilesNonFrameParallel(sequence_header, frame_header, tiles,
-                                         frame_scratch_buffer, &post_filter);
-  } else {
-    status = DecodeTilesThreadedNonFrameParallel(tiles, frame_scratch_buffer,
-                                                 &post_filter, &pending_tiles);
+    StatusCode status;
+    if (settings_.threads == 1) {
+      status = DecodeTilesNonFrameParallel(sequence_header, frame_header, tiles,
+                                           frame_scratch_buffer, &post_filter);
+    } else {
+      status = DecodeTilesThreadedNonFrameParallel(
+          tiles, frame_scratch_buffer, &post_filter, &pending_tiles);
+    }
+    if (status != kStatusOk) return status;
   }
-  if (status != kStatusOk) return status;
+
   if (frame_header.enable_frame_end_update_cdf) {
     frame_scratch_buffer->symbol_decoder_context = saved_symbol_decoder_context;
   }
diff --git a/src/decoder_impl.h b/src/decoder_impl.h
index b75417d..0049765 100644
--- a/src/decoder_impl.h
+++ b/src/decoder_impl.h
@@ -23,6 +23,7 @@
 #include <cstdint>
 #include <memory>
 #include <mutex>  // NOLINT (unapproved c++11 header)
+#include <vector>
 
 #include "src/buffer_pool.h"
 #include "src/decoder_state.h"
@@ -146,6 +147,7 @@ class DecoderImpl : public Allocable {
                   "LIBGAV1_MAX_BITDEPTH must be 8, 10 or 12.");
     return LIBGAV1_MAX_BITDEPTH;
   }
+  std::vector<int> GetFrameQps();
 
  private:
   explicit DecoderImpl(const DecoderSettings* settings);
@@ -244,7 +246,7 @@ class DecoderImpl : public Allocable {
   FrameScratchBufferPool frame_scratch_buffer_pool_;
 
   // Used to synchronize the accesses into |temporal_units_| in order to update
-  // the "decoded" state of an temporal unit.
+  // the "decoded" state of a temporal unit.
   std::mutex mutex_;
   std::condition_variable decoded_condvar_;
   bool is_frame_parallel_;
@@ -265,6 +267,9 @@ class DecoderImpl : public Allocable {
 
   const DecoderSettings& settings_;
   bool seen_first_frame_ = false;
+
+  std::vector<int> frame_mean_qps_;
+  int frame_mean_qp_ = 0;
 };
 
 }  // namespace libgav1
diff --git a/src/decoder_settings.cc b/src/decoder_settings.cc
index 9399073..20d53ee 100644
--- a/src/decoder_settings.cc
+++ b/src/decoder_settings.cc
@@ -28,6 +28,7 @@ void Libgav1DecoderSettingsInitDefault(Libgav1DecoderSettings* settings) {
   settings->output_all_layers = 0;  // false
   settings->operating_point = 0;
   settings->post_filter_mask = 0x1f;
+  settings->parse_only = 0;  // false
 }
 
 }  // extern "C"
diff --git a/src/decoder_test.cc b/src/decoder_test.cc
index 52ec5cc..0646509 100644
--- a/src/decoder_test.cc
+++ b/src/decoder_test.cc
@@ -18,6 +18,7 @@
 #include <cstdint>
 #include <memory>
 #include <new>
+#include <vector>
 
 #include "gtest/gtest.h"
 #include "src/decoder_test_data.h"
@@ -27,8 +28,10 @@ namespace {
 
 constexpr uint8_t kFrame1[] = {OBU_TEMPORAL_DELIMITER, OBU_SEQUENCE_HEADER,
                                OBU_FRAME_1};
+constexpr uint8_t kFrame1MeanQp = 81;
 
 constexpr uint8_t kFrame2[] = {OBU_TEMPORAL_DELIMITER, OBU_FRAME_2};
+constexpr uint8_t kFrame2MeanQp = 81;
 
 constexpr uint8_t kFrame1WithHdrCllAndHdrMdcv[] = {
     OBU_TEMPORAL_DELIMITER, OBU_SEQUENCE_HEADER, OBU_METADATA_HDR_CLL,
@@ -378,5 +381,56 @@ TEST_F(DecoderTest, MetadataObu) {
   EXPECT_EQ(frames_in_use_, 0);
 }
 
+class ParseOnlyTest : public testing::Test {
+ public:
+  void SetUp() override;
+
+ protected:
+  std::unique_ptr<Decoder> decoder_;
+};
+
+void ParseOnlyTest::SetUp() {
+  decoder_.reset(new (std::nothrow) Decoder());
+  ASSERT_NE(decoder_, nullptr);
+  DecoderSettings settings = {};
+  settings.parse_only = true;  // parse_only mode activated
+  ASSERT_EQ(decoder_->Init(&settings), kStatusOk);
+}
+
+TEST_F(ParseOnlyTest, NonFrameParallelModeParseOnly) {
+  StatusCode status;
+  const DecoderBuffer* buffer;
+
+  // Enqueue frame1 for decoding.
+  status = decoder_->EnqueueFrame(kFrame1, sizeof(kFrame1), 0,
+                                  const_cast<uint8_t*>(kFrame1));
+  ASSERT_EQ(status, kStatusOk);
+
+  // Dequeue the output of frame1.
+  status = decoder_->DequeueFrame(&buffer);
+  ASSERT_EQ(status, kStatusOk);
+  ASSERT_EQ(buffer,
+            nullptr);  // in the parse only case the buffer should be nullptr
+
+  // Frame 1 has 1 coding block and the value of it is kFrame1MeanQp.
+  std::vector<int> frame1_qp = decoder_->GetFramesMeanQpInTemporalUnit();
+  EXPECT_EQ(frame1_qp[0], kFrame1MeanQp);
+
+  // Enqueue frame2 for decoding.
+  status = decoder_->EnqueueFrame(kFrame2, sizeof(kFrame2), 0,
+                                  const_cast<uint8_t*>(kFrame2));
+  ASSERT_EQ(status, kStatusOk);
+
+  // Dequeue the output of frame2.
+  status = decoder_->DequeueFrame(&buffer);
+  ASSERT_EQ(status, kStatusOk);
+  ASSERT_EQ(buffer,
+            nullptr);  // in the parse only case the buffer should be nullptr
+
+  // Frame 2 has 4 coding blocks and the mean value of them is kFrame2MeanQp.
+  std::vector<int> frame2_qp = decoder_->GetFramesMeanQpInTemporalUnit();
+  EXPECT_EQ(frame2_qp[0], kFrame2MeanQp);
+}
+
 }  // namespace
 }  // namespace libgav1
diff --git a/src/dsp/arm/common_neon.h b/src/dsp/arm/common_neon.h
index c0af2c1..e153c0a 100644
--- a/src/dsp/arm/common_neon.h
+++ b/src/dsp/arm/common_neon.h
@@ -188,8 +188,6 @@ inline void PrintHex(const int x, const char* name) {
 #define PX(x) PrintHex(x, #x)
 
 #if LIBGAV1_MSAN
-#include <sanitizer/msan_interface.h>
-
 inline void PrintShadow(const void* r, const char* const name,
                         const size_t size) {
   if (kEnablePrintRegs) {
diff --git a/src/dsp/cdef.cc b/src/dsp/cdef.cc
index 9dd9287..6bfd434 100644
--- a/src/dsp/cdef.cc
+++ b/src/dsp/cdef.cc
@@ -18,6 +18,7 @@
 #include <cassert>
 #include <cstddef>
 #include <cstdint>
+#include <cstdlib>
 #include <cstring>
 
 #include "src/dsp/constants.h"
diff --git a/src/dsp/inverse_transform.cc b/src/dsp/inverse_transform.cc
index 0bbdffa..911cda2 100644
--- a/src/dsp/inverse_transform.cc
+++ b/src/dsp/inverse_transform.cc
@@ -17,6 +17,7 @@
 #include <algorithm>
 #include <cassert>
 #include <cstdint>
+#include <cstdlib>
 #include <cstring>
 #include <type_traits>
 
diff --git a/src/film_grain.cc b/src/film_grain.cc
index 44a2543..7ec5851 100644
--- a/src/film_grain.cc
+++ b/src/film_grain.cc
@@ -15,6 +15,7 @@
 #include "src/film_grain.h"
 
 #include <algorithm>
+#include <atomic>
 #include <cassert>
 #include <cstddef>
 #include <cstdint>
@@ -278,6 +279,14 @@ FilmGrain<bitdepth>::FilmGrain(const FilmGrainParams& params,
                                                : kMaxChromaHeight),
       thread_pool_(thread_pool) {}
 
+template <int bitdepth>
+FilmGrain<bitdepth>::~FilmGrain() {
+  // Clear the earlier poisoning to avoid false reports when the memory range
+  // is reused.
+  ASAN_UNPOISON_MEMORY_REGION(luma_grain_, sizeof(luma_grain_));
+  ASAN_UNPOISON_MEMORY_REGION(scaling_lut_y_, sizeof(scaling_lut_y_));
+}
+
 template <int bitdepth>
 bool FilmGrain<bitdepth>::Init() {
   // Section 7.18.3.3. Generate grain process.
diff --git a/src/film_grain.h b/src/film_grain.h
index bda8458..b5d9983 100644
--- a/src/film_grain.h
+++ b/src/film_grain.h
@@ -73,6 +73,7 @@ class FilmGrain {
   FilmGrain(const FilmGrainParams& params, bool is_monochrome,
             bool color_matrix_is_identity, int subsampling_x, int subsampling_y,
             int width, int height, ThreadPool* thread_pool);
+  ~FilmGrain();
 
   // Note: These static methods are declared public so that the unit tests can
   // call them.
diff --git a/src/gav1/decoder.h b/src/gav1/decoder.h
index da08da9..1886f80 100644
--- a/src/gav1/decoder.h
+++ b/src/gav1/decoder.h
@@ -21,6 +21,7 @@
 #include <cstddef>
 #include <cstdint>
 #include <memory>
+#include <vector>
 #else
 #include <stddef.h>
 #include <stdint.h>
@@ -136,10 +137,21 @@ class LIBGAV1_PUBLIC Decoder {
   // Returns the maximum bitdepth that is supported by this decoder.
   static int GetMaxBitdepth();
 
+  // Returns a vector with the QP values for all the frames in the last temporal
+  // unit in encoding/decoding order (Note: not display order). If no frames are
+  // present in the last temporal unit the method returns an empty vector.
+  //
+  // NOTE: This function is C++ only and is not exposed via the C API.
+  //
+  // TODO(vardar): return a map that contains a QP per spatial layer for each
+  // temporal layer.
+  std::vector<int> GetFramesMeanQpInTemporalUnit();
+
  private:
   DecoderSettings settings_;
   // The object is initialized if and only if impl_ != nullptr.
   std::unique_ptr<DecoderImpl> impl_;
+  std::vector<int> frame_mean_qps_;
 };
 
 }  // namespace libgav1
diff --git a/src/gav1/decoder_settings.h b/src/gav1/decoder_settings.h
index 7ee487f..e4eb1dd 100644
--- a/src/gav1/decoder_settings.h
+++ b/src/gav1/decoder_settings.h
@@ -83,6 +83,9 @@ typedef struct Libgav1DecoderSettings {
   //   Bit 4: Film grain synthesis.
   //   All the bits other than the last 5 are ignored.
   uint8_t post_filter_mask;
+  // A boolean. If set to 1, the decoder will only parse the bitstream, i.e., no
+  // decoding will take place.
+  int parse_only;
 } Libgav1DecoderSettings;
 
 LIBGAV1_PUBLIC void Libgav1DecoderSettingsInitDefault(
@@ -139,6 +142,9 @@ struct DecoderSettings {
   //   Bit 4: Film grain synthesis.
   //   All the bits other than the last 5 are ignored.
   uint8_t post_filter_mask = 0x1f;
+  // If set to true, the decoder will only parse the bitstream, i.e., no
+  // decoding will take place.
+  bool parse_only = false;
 };
 
 }  // namespace libgav1
diff --git a/src/gav1/version.h b/src/gav1/version.h
index cca2383..f80002d 100644
--- a/src/gav1/version.h
+++ b/src/gav1/version.h
@@ -23,7 +23,7 @@
 // (https://semver.org).
 
 #define LIBGAV1_MAJOR_VERSION 0
-#define LIBGAV1_MINOR_VERSION 19
+#define LIBGAV1_MINOR_VERSION 20
 #define LIBGAV1_PATCH_VERSION 0
 
 #define LIBGAV1_VERSION                                           \
diff --git a/src/motion_vector.cc b/src/motion_vector.cc
index 36018ab..35de934 100644
--- a/src/motion_vector.cc
+++ b/src/motion_vector.cc
@@ -15,9 +15,11 @@
 #include "src/motion_vector.h"
 
 #include <algorithm>
+#include <array>
 #include <cassert>
 #include <cstdint>
 #include <cstdlib>
+#include <iterator>
 #include <memory>
 
 #include "src/dsp/dsp.h"
diff --git a/src/obu_parser.cc b/src/obu_parser.cc
index d1815ed..16814b9 100644
--- a/src/obu_parser.cc
+++ b/src/obu_parser.cc
@@ -22,12 +22,21 @@
 #include <cstdint>
 #include <cstring>
 #include <memory>
+#include <new>
+#include <utility>
 
 #include "src/buffer_pool.h"
-#include "src/decoder_impl.h"
-#include "src/motion_vector.h"
+#include "src/decoder_state.h"
+#include "src/gav1/decoder_buffer.h"
+#include "src/gav1/status_code.h"
+#include "src/quantizer.h"
 #include "src/utils/common.h"
+#include "src/utils/constants.h"
 #include "src/utils/logging.h"
+#include "src/utils/raw_bit_reader.h"
+#include "src/utils/reference_info.h"
+#include "src/utils/segmentation.h"
+#include "src/utils/types.h"
 
 namespace libgav1 {
 namespace {
@@ -2191,6 +2200,24 @@ bool ObuParser::ParseFrameHeader() {
   if (sequence_header_.film_grain_params_present) {
     current_frame_->set_film_grain_params(frame_header_.film_grain_params);
   }
+  if (sequence_header_changed_ &&
+      (frame_header_.frame_type != kFrameKey || !frame_header_.show_frame ||
+       frame_header_.show_existing_frame ||
+       current_frame_->temporal_id() != 0)) {
+    // Section 7.5. Ordering of OBUs: A new coded video sequence is defined to
+    // start at each temporal unit which satisfies both of the following
+    // conditions:
+    //   * A sequence header OBU appears before the first frame header.
+    //   * The first frame header has frame_type equal to KEY_FRAME, show_frame
+    //     equal to 1, show_existing_frame equal to 0, and temporal_id equal to
+    //     0.
+    LIBGAV1_DLOG(
+        WARNING,
+        "The first frame successive to sequence header OBU should be a "
+        "keyframe with show_frame=1, show_existing_frame=0 and "
+        "temporal_id=0");
+  }
+
   return true;
 }
 
@@ -2603,9 +2630,14 @@ bool ObuParser::ParseHeader() {
   obu_header.has_extension = extension_flag;
   if (extension_flag) {
     if (extension_disallowed_) {
+#ifdef CHROMIUM
+      LIBGAV1_DLOG(WARNING,
+                   "OperatingPointIdc is 0, but obu_extension_flag is 1.");
+#else   // !CHROMIUM
       LIBGAV1_DLOG(ERROR,
                    "OperatingPointIdc is 0, but obu_extension_flag is 1.");
       return false;
+#endif  // CHROMIUM
     }
     OBU_READ_LITERAL_OR_FAIL(3);
     obu_header.temporal_id = scratch;
@@ -2998,7 +3030,7 @@ StatusCode ObuParser::ParseBasicStreamInfo(const uint8_t* data, size_t size,
       LIBGAV1_DLOG(
           ERROR,
           "Parsed OBU size (%zu bits) is greater than expected OBU size "
-          "(%zu bytes)..",
+          "(%zu bytes).",
           parsed_obu_size_in_bits, obu_size);
       return kStatusBitstreamError;
     }
@@ -3014,7 +3046,8 @@ StatusCode ObuParser::ParseBasicStreamInfo(const uint8_t* data, size_t size,
         parser.bit_reader_->byte_offset() - obu_start_offset;
     return kStatusOk;
   }
-  // Sequence header was never found.
+
+  LIBGAV1_DLOG(ERROR, "Sequence header was never found.");
   return kStatusBitstreamError;
 }
 
diff --git a/src/obu_parser.h b/src/obu_parser.h
index 594e86b..dafce6f 100644
--- a/src/obu_parser.h
+++ b/src/obu_parser.h
@@ -26,15 +26,13 @@
 
 #include "src/buffer_pool.h"
 #include "src/decoder_state.h"
-#include "src/dsp/common.h"
 #include "src/gav1/decoder_buffer.h"
 #include "src/gav1/status_code.h"
-#include "src/quantizer.h"
-#include "src/utils/common.h"
 #include "src/utils/compiler_attributes.h"
 #include "src/utils/constants.h"
+#include "src/utils/memory.h"
 #include "src/utils/raw_bit_reader.h"
-#include "src/utils/segmentation.h"
+#include "src/utils/types.h"
 #include "src/utils/vector.h"
 
 namespace libgav1 {
diff --git a/src/obu_parser_test.cc b/src/obu_parser_test.cc
index a471037..c0838ce 100644
--- a/src/obu_parser_test.cc
+++ b/src/obu_parser_test.cc
@@ -25,7 +25,6 @@
 
 #include "gtest/gtest.h"
 #include "src/buffer_pool.h"
-#include "src/decoder_impl.h"
 #include "src/decoder_state.h"
 #include "src/gav1/decoder_buffer.h"
 #include "src/gav1/status_code.h"
diff --git a/src/post_filter/cdef.cc b/src/post_filter/cdef.cc
index ced4096..99b4db7 100644
--- a/src/post_filter/cdef.cc
+++ b/src/post_filter/cdef.cc
@@ -11,6 +11,9 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
+
+#include <algorithm>
+#include <atomic>
 #include <cassert>
 
 #include "src/post_filter.h"
diff --git a/src/post_filter/deblock.cc b/src/post_filter/deblock.cc
index daee01c..6e5d089 100644
--- a/src/post_filter/deblock.cc
+++ b/src/post_filter/deblock.cc
@@ -11,6 +11,8 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
+
+#include <algorithm>
 #include <atomic>
 
 #include "src/post_filter.h"
diff --git a/src/post_filter/loop_restoration.cc b/src/post_filter/loop_restoration.cc
index b5e1432..50e214c 100644
--- a/src/post_filter/loop_restoration.cc
+++ b/src/post_filter/loop_restoration.cc
@@ -11,6 +11,10 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
+
+#include <algorithm>
+#include <atomic>
+
 #include "src/post_filter.h"
 #include "src/utils/blocking_counter.h"
 
diff --git a/src/post_filter/post_filter.cc b/src/post_filter/post_filter.cc
index 9745a01..2a5ec95 100644
--- a/src/post_filter/post_filter.cc
+++ b/src/post_filter/post_filter.cc
@@ -15,6 +15,7 @@
 #include "src/post_filter.h"
 
 #include <algorithm>
+#include <array>
 #include <atomic>
 #include <cassert>
 #include <cstddef>
diff --git a/src/post_filter/super_res.cc b/src/post_filter/super_res.cc
index 2133a8a..2aeab9c 100644
--- a/src/post_filter/super_res.cc
+++ b/src/post_filter/super_res.cc
@@ -11,6 +11,10 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
+
+#include <algorithm>
+#include <array>
+
 #include "src/post_filter.h"
 #include "src/utils/blocking_counter.h"
 
diff --git a/src/residual_buffer_pool.cc b/src/residual_buffer_pool.cc
index 44a842c..f59d05a 100644
--- a/src/residual_buffer_pool.cc
+++ b/src/residual_buffer_pool.cc
@@ -14,6 +14,7 @@
 
 #include "src/residual_buffer_pool.h"
 
+#include <memory>
 #include <mutex>  // NOLINT (unapproved c++11 header)
 #include <utility>
 
diff --git a/src/symbol_decoder_context.h b/src/symbol_decoder_context.h
index 1bea76c..9bc52ae 100644
--- a/src/symbol_decoder_context.h
+++ b/src/symbol_decoder_context.h
@@ -104,7 +104,6 @@ struct SymbolDecoderContext {
   // Returns the cdf array index for inter_tx_type or intra_tx_type based on
   // |tx_set|.
   static int TxTypeIndex(TransformSet tx_set) {
-    assert(tx_set != kTransformSetDctOnly);
     switch (tx_set) {
       case kTransformSetInter1:
       case kTransformSetIntra1:
@@ -115,7 +114,10 @@ struct SymbolDecoderContext {
       case kTransformSetInter3:
         return 2;
       default:
-        return -1;
+        // This path should not be hit. 0 is returned rather than -1 to avoid
+        // -Warray-bounds.
+        assert(tx_set != kTransformSetDctOnly && tx_set != kNumTransformSets);
+        return 0;
     }
   }
 
diff --git a/src/threading_strategy.cc b/src/threading_strategy.cc
index 17ce18f..cd26df3 100644
--- a/src/threading_strategy.cc
+++ b/src/threading_strategy.cc
@@ -17,6 +17,7 @@
 #include <algorithm>
 #include <cassert>
 #include <memory>
+#include <utility>
 
 #include "src/frame_scratch_buffer.h"
 #include "src/utils/constants.h"
diff --git a/src/tile.h b/src/tile.h
index fcab963..d37f7ba 100644
--- a/src/tile.h
+++ b/src/tile.h
@@ -20,12 +20,12 @@
 #include <algorithm>
 #include <array>
 #include <cassert>
+#include <cmath>
 #include <condition_variable>  // NOLINT (unapproved c++11 header)
 #include <cstddef>
 #include <cstdint>
 #include <memory>
 #include <mutex>  // NOLINT (unapproved c++11 header)
-#include <vector>
 
 #include "src/buffer_pool.h"
 #include "src/decoder_state.h"
@@ -80,13 +80,13 @@ class Tile : public MaxAlignedAllocable {
       const SegmentationMap* prev_segment_ids, PostFilter* const post_filter,
       const dsp::Dsp* const dsp, ThreadPool* const thread_pool,
       BlockingCounterWithStatus* const pending_tiles, bool frame_parallel,
-      bool use_intra_prediction_buffer) {
+      bool use_intra_prediction_buffer, bool parse_only) {
     std::unique_ptr<Tile> tile(new (std::nothrow) Tile(
         tile_number, data, size, sequence_header, frame_header, current_frame,
         state, frame_scratch_buffer, wedge_masks, quantizer_matrix,
         saved_symbol_decoder_context, prev_segment_ids, post_filter, dsp,
-        thread_pool, pending_tiles, frame_parallel,
-        use_intra_prediction_buffer));
+        thread_pool, pending_tiles, frame_parallel, use_intra_prediction_buffer,
+        parse_only));
     return (tile != nullptr && tile->Init()) ? std::move(tile) : nullptr;
   }
 
@@ -188,6 +188,12 @@ class Tile : public MaxAlignedAllocable {
   int column4x4_start() const { return column4x4_start_; }
   int column4x4_end() const { return column4x4_end_; }
 
+  int GetTileMeanQP() const {
+    return static_cast<int>(
+        std::round(static_cast<float>(weighted_cumulative_block_qp_) /
+                   cumulative_block_weights_));
+  }
+
  private:
   // Stores the transform tree state when reading variable size transform trees
   // and when applying the transform tree. When applying the transform tree,
@@ -250,7 +256,7 @@ class Tile : public MaxAlignedAllocable {
        const SegmentationMap* prev_segment_ids, PostFilter* post_filter,
        const dsp::Dsp* dsp, ThreadPool* thread_pool,
        BlockingCounterWithStatus* pending_tiles, bool frame_parallel,
-       bool use_intra_prediction_buffer);
+       bool use_intra_prediction_buffer, bool parse_only);
 
   // Performs member initializations that may fail. Helper function used by
   // Create().
@@ -637,6 +643,13 @@ class Tile : public MaxAlignedAllocable {
 
   // current_quantizer_index_ is in the range [0, 255].
   uint8_t current_quantizer_index_;
+  // The weighted sum of the QP values per block for a tile. The weights are in
+  // terms of 4x4 blocks. E.g., a block of size 32x16 has the weight 32/4 *
+  // 16/4.
+  int64_t weighted_cumulative_block_qp_ = 0;
+  // The sums of the weights per block in a tile.
+  int64_t cumulative_block_weights_ = 0;
+
   // These two arrays (|coefficient_levels_| and |dc_categories_|) are used to
   // store the entropy context. Their dimensions are as follows: First -
   // left/top; Second - plane; Third - row4x4 (if first dimension is
@@ -781,6 +794,8 @@ class Tile : public MaxAlignedAllocable {
   // the access index will be the corresponding SuperBlockColumnIndex()'th
   // entry.
   DynamicBuffer<BlockCdfContext> top_context_;
+  // Whether the tile should only be parsed and not decoded.
+  const bool parse_only_;
 };
 
 struct Tile::Block {
diff --git a/src/tile/tile.cc b/src/tile/tile.cc
index 10ebbf2..2dd13e3 100644
--- a/src/tile/tile.cc
+++ b/src/tile/tile.cc
@@ -18,9 +18,11 @@
 #include <array>
 #include <cassert>
 #include <climits>
+#include <condition_variable>  // NOLINT (unapproved c++11 header)
 #include <cstdlib>
 #include <cstring>
 #include <memory>
+#include <mutex>  // NOLINT (unapproved c++11 header)
 #include <new>
 #include <numeric>
 #include <type_traits>
@@ -425,7 +427,7 @@ Tile::Tile(int tile_number, const uint8_t* const data, size_t size,
            PostFilter* const post_filter, const dsp::Dsp* const dsp,
            ThreadPool* const thread_pool,
            BlockingCounterWithStatus* const pending_tiles, bool frame_parallel,
-           bool use_intra_prediction_buffer)
+           bool use_intra_prediction_buffer, bool parse_only)
     : number_(tile_number),
       row_(number_ / frame_header.tile_info.tile_columns),
       column_(number_ % frame_header.tile_info.tile_columns),
@@ -475,7 +477,8 @@ Tile::Tile(int tile_number, const uint8_t* const data, size_t size,
       intra_prediction_buffer_(
           use_intra_prediction_buffer_
               ? &frame_scratch_buffer->intra_prediction_buffers.get()[row_]
-              : nullptr) {
+              : nullptr),
+      parse_only_(parse_only) {
   row4x4_start_ = frame_header.tile_info.tile_row_start[row_];
   row4x4_end_ = frame_header.tile_info.tile_row_start[row_ + 1];
   column4x4_start_ = frame_header.tile_info.tile_column_start[column_];
@@ -489,14 +492,15 @@ Tile::Tile(int tile_number, const uint8_t* const data, size_t size,
       block_width4x4_log2;
   // If |split_parse_and_decode_| is true, we do the necessary setup for
   // splitting the parsing and the decoding steps. This is done in the following
-  // two cases:
+  // three cases:
   //  1) If there is multi-threading within a tile (this is done if
   //     |thread_pool_| is not nullptr and if there are at least as many
   //     superblock columns as |intra_block_copy_lag_|).
   //  2) If |frame_parallel| is true.
+  //  3) If |parse_only_| is true.
   split_parse_and_decode_ = (thread_pool_ != nullptr &&
                              superblock_columns_ > intra_block_copy_lag_) ||
-                            frame_parallel;
+                            frame_parallel || parse_only_;
   if (frame_parallel_) {
     reference_frame_progress_cache_.fill(INT_MIN);
   }
@@ -1066,18 +1070,29 @@ void Tile::ReadTransformType(const Block& block, int x4, int y4,
           break;
       }
     } else {
-      const PredictionMode intra_direction =
+      // Backup the current set of warnings and disable -Warray-bounds for this
+      // block as the compiler cannot, in all cases, determine whether
+      // |intra_mode| is within [0, kIntraPredictionModesY).
+#ifdef __GNUC__
+#pragma GCC diagnostic push
+#pragma GCC diagnostic ignored "-Warray-bounds"
+#endif
+      const PredictionMode intra_mode =
           block.bp->prediction_parameters->use_filter_intra
               ? kFilterIntraModeToIntraPredictor[block.bp->prediction_parameters
                                                      ->filter_intra_mode]
               : bp.y_mode;
-      cdf =
-          symbol_decoder_context_
-              .intra_tx_type_cdf[cdf_index][cdf_tx_size_index][intra_direction];
+      assert(intra_mode < kIntraPredictionModesY);
+      cdf = symbol_decoder_context_
+                .intra_tx_type_cdf[cdf_index][cdf_tx_size_index][intra_mode];
       assert(tx_set == kTransformSetIntra1 || tx_set == kTransformSetIntra2);
       tx_type = static_cast<TransformType>((tx_set == kTransformSetIntra1)
                                                ? reader_.ReadSymbol<7>(cdf)
                                                : reader_.ReadSymbol<5>(cdf));
+      // Restore the previous set of compiler warnings.
+#ifdef __GNUC__
+#pragma GCC diagnostic pop
+#endif
     }
 
     // This array does not contain an entry for kTransformSetDctOnly, so the
@@ -2183,9 +2198,11 @@ bool Tile::ProcessBlock(int row4x4, int column4x4, BlockSize block_size,
     // to decode the blocks in the correct order.
     const int sb_row_index = SuperBlockRowIndex(row4x4);
     const int sb_column_index = SuperBlockColumnIndex(column4x4);
-    residual_buffer_threaded_[sb_row_index][sb_column_index]
-        ->partition_tree_order()
-        ->Push(PartitionTreeNode(row4x4, column4x4, block_size));
+    if (!parse_only_) {
+      residual_buffer_threaded_[sb_row_index][sb_column_index]
+          ->partition_tree_order()
+          ->Push(PartitionTreeNode(row4x4, column4x4, block_size));
+    }
   }
 
   BlockParameters* bp_ptr =
@@ -2203,6 +2220,11 @@ bool Tile::ProcessBlock(int row4x4, int column4x4, BlockSize block_size,
                               : std::move(prediction_parameters_);
   if (bp.prediction_parameters == nullptr) return false;
   if (!DecodeModeInfo(block)) return false;
+  if (parse_only_) {
+    const int block_weight = kBlockWeight[block_size];
+    weighted_cumulative_block_qp_ += current_quantizer_index_ * block_weight;
+    cumulative_block_weights_ += block_weight;
+  }
   PopulateDeblockFilterLevel(block);
   if (!ReadPaletteTokens(block)) return false;
   DecodeTransformSize(block);
@@ -2522,6 +2544,10 @@ bool Tile::ProcessSuperBlock(int row4x4, int column4x4,
                    column4x4);
       return false;
     }
+    if (parse_only_) {
+      residual_buffer_pool_->Release(
+          std::move(residual_buffer_threaded_[sb_row_index][sb_column_index]));
+    }
   } else {
     if (!DecodeSuperBlock(sb_row_index, sb_column_index, scratch_buffer)) {
       LIBGAV1_DLOG(ERROR, "Error decoding superblock row: %d column: %d",
diff --git a/src/utils/block_parameters_holder.cc b/src/utils/block_parameters_holder.cc
index 3bb9f1e..bf5f66f 100644
--- a/src/utils/block_parameters_holder.cc
+++ b/src/utils/block_parameters_holder.cc
@@ -15,6 +15,8 @@
 #include "src/utils/block_parameters_holder.h"
 
 #include <algorithm>
+#include <atomic>
+#include <new>
 
 #include "src/utils/common.h"
 #include "src/utils/constants.h"
diff --git a/src/utils/compiler_attributes.h b/src/utils/compiler_attributes.h
index 09f0035..33fbe16 100644
--- a/src/utils/compiler_attributes.h
+++ b/src/utils/compiler_attributes.h
@@ -74,12 +74,17 @@
 #if LIBGAV1_ASAN
 #include <sanitizer/asan_interface.h>
 #else
-#define ASAN_POISON_MEMORY_REGION(addr, size) \
-  (static_cast<void>(addr), static_cast<void>(size))
-#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
-  (static_cast<void>(addr), static_cast<void>(size))
+#define ASAN_POISON_MEMORY_REGION(addr, size) ((void)(addr), (void)(size))
+#define ASAN_UNPOISON_MEMORY_REGION(addr, size) ((void)(addr), (void)(size))
 #endif
 
+//------------------------------------------------------------------------------
+// MemorySanitizer support.
+
+#if LIBGAV1_MSAN
+#include <sanitizer/msan_interface.h>
+#endif  // LIBGAV1_MSAN
+
 //------------------------------------------------------------------------------
 // Function attributes.
 // GCC: https://gcc.gnu.org/onlinedocs/gcc/Function-Attributes.html
diff --git a/src/utils/constants.cc b/src/utils/constants.cc
index 80d7acb..bf7c803 100644
--- a/src/utils/constants.cc
+++ b/src/utils/constants.cc
@@ -14,6 +14,8 @@
 
 #include "src/utils/constants.h"
 
+#include <cstdint>
+
 namespace libgav1 {
 
 const uint8_t k4x4WidthLog2[kMaxBlockSizes] = {0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
@@ -871,4 +873,8 @@ const int16_t kDirectionalIntraPredictorDerivative[44] = {
 const uint8_t kDeblockFilterLevelIndex[kMaxPlanes][kNumLoopFilterTypes] = {
     {0, 1}, {2, 2}, {3, 3}};
 
+const uint16_t kBlockWeight[kMaxBlockSizes] = {
+    1,  2,  4,  2,  4,   8,  16,  4,   8,   16,  32,
+    64, 16, 32, 64, 128, 64, 128, 256, 512, 512, 1024};
+
 }  // namespace libgav1
diff --git a/src/utils/constants.h b/src/utils/constants.h
index 8281aad..46dc8f3 100644
--- a/src/utils/constants.h
+++ b/src/utils/constants.h
@@ -810,6 +810,8 @@ extern const int16_t kDirectionalIntraPredictorDerivative[44];
 
 extern const uint8_t kDeblockFilterLevelIndex[kMaxPlanes][kNumLoopFilterTypes];
 
+extern const uint16_t kBlockWeight[kMaxBlockSizes];
+
 }  // namespace libgav1
 
 #endif  // LIBGAV1_SRC_UTILS_CONSTANTS_H_
diff --git a/src/utils/logging.cc b/src/utils/logging.cc
index 26e3e15..529426a 100644
--- a/src/utils/logging.cc
+++ b/src/utils/logging.cc
@@ -16,6 +16,7 @@
 
 #include <cstdarg>
 #include <cstdio>
+#include <ios>
 #include <sstream>
 #include <thread>  // NOLINT (unapproved c++11 header)
 
diff --git a/src/utils/threadpool.cc b/src/utils/threadpool.cc
index 6fa2e88..ad79ba2 100644
--- a/src/utils/threadpool.cc
+++ b/src/utils/threadpool.cc
@@ -31,6 +31,8 @@
 #include <cstdint>
 #include <cstdio>
 #include <cstring>
+#include <functional>
+#include <memory>
 #include <new>
 #include <utility>
 
diff --git a/src/warp_prediction.cc b/src/warp_prediction.cc
index 0da8a1f..3c0b990 100644
--- a/src/warp_prediction.cc
+++ b/src/warp_prediction.cc
@@ -18,11 +18,9 @@
 #include <cstdint>
 #include <cstdlib>
 
-#include "src/tile.h"
-#include "src/utils/block_parameters_holder.h"
 #include "src/utils/common.h"
 #include "src/utils/constants.h"
-#include "src/utils/logging.h"
+#include "src/utils/types.h"
 
 namespace libgav1 {
 namespace {
diff --git a/src/warp_prediction.h b/src/warp_prediction.h
index 6c86df3..ad6f55f 100644
--- a/src/warp_prediction.h
+++ b/src/warp_prediction.h
@@ -17,7 +17,6 @@
 #ifndef LIBGAV1_SRC_WARP_PREDICTION_H_
 #define LIBGAV1_SRC_WARP_PREDICTION_H_
 
-#include "src/obu_parser.h"
 #include "src/utils/constants.h"
 #include "src/utils/types.h"
 
diff --git a/tests/fuzzer/decoder_fuzzer.cc b/tests/fuzzer/decoder_fuzzer.cc
index 236fd3c..07b86c8 100644
--- a/tests/fuzzer/decoder_fuzzer.cc
+++ b/tests/fuzzer/decoder_fuzzer.cc
@@ -36,6 +36,8 @@ constexpr int kMaxFrames = 5;
 constexpr size_t kMaxDataSize = 200 * 1024;
 #endif
 
+constexpr int kFrequencyParseOnly = 10;
+
 void Decode(const uint8_t* const data, const size_t size,
             libgav1::Decoder* const decoder) {
   decoder->EnqueueFrame(data, size, /*user_private_data=*/0,
@@ -58,6 +60,7 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
   // We use both nibbles of the lower byte as this results in values != 1 much
   // more quickly than using the lower nibble alone.
   settings.threads = (size >= 13) ? ((data[12] >> 4 | data[12]) & 0xF) + 1 : 1;
+  settings.parse_only = size % kFrequencyParseOnly == 0;
   if (decoder.Init(&settings) != libgav1::kStatusOk) return 0;
 
   // Treat the input as a raw OBU stream.
diff --git a/tests/fuzzer/decoder_fuzzer_frame_parallel.cc b/tests/fuzzer/decoder_fuzzer_frame_parallel.cc
index d1b1c54..b4ff197 100644
--- a/tests/fuzzer/decoder_fuzzer_frame_parallel.cc
+++ b/tests/fuzzer/decoder_fuzzer_frame_parallel.cc
@@ -16,6 +16,7 @@
 #include <cstdint>
 #include <deque>
 #include <memory>
+#include <new>
 #include <vector>
 
 #include "examples/file_reader.h"
diff --git a/tests/libgav1_tests.cmake b/tests/libgav1_tests.cmake
index 95f6361..eefa1bf 100644
--- a/tests/libgav1_tests.cmake
+++ b/tests/libgav1_tests.cmake
@@ -40,7 +40,10 @@ if((CMAKE_CXX_COMPILER_ID
     MATCHES
     "Clang|GNU"
     AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "5")
-   OR (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19"))
+   OR (CMAKE_CXX_COMPILER_ID
+       STREQUAL
+       "MSVC"
+       AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19"))
   macro(libgav1_add_tests_targets)
 
   endmacro()
@@ -1222,6 +1225,7 @@ macro(libgav1_add_tests_targets)
                          ${libgav1_test_objlib_deps}
                          LIB_DEPS
                          absl::strings
+                         absl::time
                          ${libgav1_common_test_absl_deps}
                          libgav1_gtest
                          libgav1_gtest_main)
```

