```diff
diff --git a/abs32_utils.cc b/abs32_utils.cc
index ad1c85e..27e7e11 100644
--- a/abs32_utils.cc
+++ b/abs32_utils.cc
@@ -110,7 +110,7 @@ Abs32RvaExtractorWin32::Abs32RvaExtractorWin32(Abs32RvaExtractorWin32&&) =
 
 Abs32RvaExtractorWin32::~Abs32RvaExtractorWin32() = default;
 
-absl::optional<Abs32RvaExtractorWin32::Unit> Abs32RvaExtractorWin32::GetNext() {
+std::optional<Abs32RvaExtractorWin32::Unit> Abs32RvaExtractorWin32::GetNext() {
   while (cur_abs32_ < end_abs32_) {
     offset_t location = *(cur_abs32_++);
     if (!addr_.Read(location, image_))
@@ -120,7 +120,7 @@ absl::optional<Abs32RvaExtractorWin32::Unit> Abs32RvaExtractorWin32::GetNext() {
       continue;
     return Unit{location, target_rva};
   }
-  return absl::nullopt;
+  return std::nullopt;
 }
 
 /******** Abs32ReaderWin32 ********/
@@ -132,7 +132,7 @@ Abs32ReaderWin32::Abs32ReaderWin32(Abs32RvaExtractorWin32&& abs32_rva_extractor,
 
 Abs32ReaderWin32::~Abs32ReaderWin32() = default;
 
-absl::optional<Reference> Abs32ReaderWin32::GetNext() {
+std::optional<Reference> Abs32ReaderWin32::GetNext() {
   for (auto unit = abs32_rva_extractor_.GetNext(); unit.has_value();
        unit = abs32_rva_extractor_.GetNext()) {
     offset_t location = unit->location;
@@ -140,7 +140,7 @@ absl::optional<Reference> Abs32ReaderWin32::GetNext() {
     if (unsafe_target != kInvalidOffset)
       return Reference{location, unsafe_target};
   }
-  return absl::nullopt;
+  return std::nullopt;
 }
 
 /******** Abs32WriterWin32 ********/
diff --git a/abs32_utils.h b/abs32_utils.h
index 07503b5..ecdb61a 100644
--- a/abs32_utils.h
+++ b/abs32_utils.h
@@ -8,12 +8,12 @@
 #include <stddef.h>
 #include <stdint.h>
 
+#include <optional>
 #include <vector>
 
 #include "components/zucchini/address_translator.h"
 #include "components/zucchini/buffer_view.h"
 #include "components/zucchini/image_utils.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -77,8 +77,8 @@ class Abs32RvaExtractorWin32 {
   ~Abs32RvaExtractorWin32();
 
   // Visits given abs32 locations, rejects invalid locations and non-existent
-  // RVAs, and returns reference as Unit, or absl::nullopt on completion.
-  absl::optional<Unit> GetNext();
+  // RVAs, and returns reference as Unit, or std::nullopt on completion.
+  std::optional<Unit> GetNext();
 
  private:
   ConstBufferView image_;
@@ -98,7 +98,7 @@ class Abs32ReaderWin32 : public ReferenceReader {
   ~Abs32ReaderWin32() override;
 
   // ReferenceReader:
-  absl::optional<Reference> GetNext() override;
+  std::optional<Reference> GetNext() override;
 
  private:
   Abs32RvaExtractorWin32 abs32_rva_extractor_;
diff --git a/abs32_utils_unittest.cc b/abs32_utils_unittest.cc
index ddbb685..9b044a7 100644
--- a/abs32_utils_unittest.cc
+++ b/abs32_utils_unittest.cc
@@ -287,7 +287,7 @@ TEST(Abs32UtilsTest, Win32Read32) {
     Abs32ReaderWin32 reader(std::move(extractor), translator);
 
     // Loop over |expected_ref| to check element-by-element.
-    absl::optional<Reference> ref;
+    std::optional<Reference> ref;
     for (const auto& expected_ref : test_case.expected_refs) {
       ref = reader.GetNext();
       EXPECT_TRUE(ref.has_value());
@@ -322,7 +322,7 @@ TEST(Abs32UtilsTest, Win32Read64) {
   Abs32ReaderWin32 reader(std::move(extractor), translator);
 
   std::vector<Reference> refs;
-  absl::optional<Reference> ref;
+  std::optional<Reference> ref;
   for (ref = reader.GetNext(); ref.has_value(); ref = reader.GetNext())
     refs.push_back(ref.value());
   EXPECT_EQ(expected_refs, refs);
diff --git a/aosp/include/third_party/abseil-cpp/absl/types/optional.h b/aosp/include/third_party/abseil-cpp/absl/types/optional.h
deleted file mode 100644
index 3321c72..0000000
--- a/aosp/include/third_party/abseil-cpp/absl/types/optional.h
+++ /dev/null
@@ -1,28 +0,0 @@
-//
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-
-#ifndef __ZUCCHINI_AOSP_ABSL_OPTIONAL_H
-#define __ZUCCHINI_AOSP_ABSL_OPTIONAL_H
-
-#include <optional>
-
-namespace absl {
-    template <typename T> using optional = std::optional<T>;
-    inline constexpr auto nullopt = std::nullopt;
-}
-
-#endif
-
diff --git a/disassembler.cc b/disassembler.cc
index 4a210ac..5dce221 100644
--- a/disassembler.cc
+++ b/disassembler.cc
@@ -10,8 +10,8 @@ namespace zucchini {
 
 /******** EmptyReferenceReader ********/
 
-absl::optional<Reference> EmptyReferenceReader::GetNext() {
-  return absl::nullopt;
+std::optional<Reference> EmptyReferenceReader::GetNext() {
+  return std::nullopt;
 }
 
 /******** EmptyReferenceWriter ********/
diff --git a/disassembler.h b/disassembler.h
index 48ee0fb..7ec739b 100644
--- a/disassembler.h
+++ b/disassembler.h
@@ -8,6 +8,7 @@
 #include <stddef.h>
 
 #include <memory>
+#include <optional>
 #include <string>
 #include <vector>
 
@@ -19,7 +20,7 @@ namespace zucchini {
 // A vacuous ReferenceReader that produces no references.
 class EmptyReferenceReader : public ReferenceReader {
  public:
-  absl::optional<Reference> GetNext() override;
+  std::optional<Reference> GetNext() override;
 };
 
 // A vacuous EmptyReferenceWriter that does not write.
diff --git a/disassembler_dex.cc b/disassembler_dex.cc
index 8ea0314..fe1110f 100644
--- a/disassembler_dex.cc
+++ b/disassembler_dex.cc
@@ -11,6 +11,7 @@
 #include <cctype>
 #include <cmath>
 #include <iterator>
+#include <optional>
 #include <set>
 #include <utility>
 
@@ -23,7 +24,6 @@
 #include "components/zucchini/buffer_source.h"
 #include "components/zucchini/buffer_view.h"
 #include "components/zucchini/io_utils.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -368,13 +368,13 @@ class InstructionReferenceReader : public ReferenceReader {
   }
 
   // ReferenceReader:
-  absl::optional<Reference> GetNext() override {
+  std::optional<Reference> GetNext() override {
     while (true) {
       while (parser_.ReadNext()) {
         const auto& v = parser_.value();
         DCHECK_NE(v.instr, nullptr);
         if (v.instr_offset >= hi_)
-          return absl::nullopt;
+          return std::nullopt;
         const offset_t location = filter_.Run(v);
         if (location == kInvalidOffset || location < lo_)
           continue;
@@ -382,7 +382,7 @@ class InstructionReferenceReader : public ReferenceReader {
         // assumption |hi_| and |lo_| do not straddle the body of a Reference.
         // So |reference_width| is unneeded.
         if (location >= hi_)
-          return absl::nullopt;
+          return std::nullopt;
         offset_t target = mapper_.Run(location);
         if (target != kInvalidOffset)
           return Reference{location, target};
@@ -391,7 +391,7 @@ class InstructionReferenceReader : public ReferenceReader {
       }
       ++cur_it_;
       if (cur_it_ == end_it_)
-        return absl::nullopt;
+        return std::nullopt;
       parser_ = InstructionParser(image_, *cur_it_);
     }
   }
@@ -458,7 +458,7 @@ class ItemReferenceReader : public ReferenceReader {
   }
 
   // ReferenceReader:
-  absl::optional<Reference> GetNext() override {
+  std::optional<Reference> GetNext() override {
     while (cur_idx_ < num_items_) {
       const offset_t item_offset = OffsetOfIndex(cur_idx_);
       const offset_t location = item_offset + rel_location_;
@@ -496,7 +496,7 @@ class ItemReferenceReader : public ReferenceReader {
       ++cur_idx_;
       return Reference{location, target};
     }
-    return absl::nullopt;
+    return std::nullopt;
   }
 
  private:
@@ -653,7 +653,7 @@ class CachedItemListReferenceReader : public ReferenceReader {
       const CachedItemListReferenceReader&) = delete;
 
   // ReferenceReader:
-  absl::optional<Reference> GetNext() override {
+  std::optional<Reference> GetNext() override {
     while (cur_it_ < end_it_) {
       const offset_t location = *cur_it_ + rel_location_;
       if (location >= hi_)  // Check is simplified by atomicity assumption.
@@ -671,7 +671,7 @@ class CachedItemListReferenceReader : public ReferenceReader {
         continue;
       return Reference{location, target};
     }
-    return absl::nullopt;
+    return std::nullopt;
   }
 
  private:
diff --git a/disassembler_ztf.cc b/disassembler_ztf.cc
index dfe9045..4a6c5ad 100644
--- a/disassembler_ztf.cc
+++ b/disassembler_ztf.cc
@@ -292,7 +292,7 @@ class ZtfReferenceReader : public ReferenceReader {
 
   // Walks |offset_| from |lo| to |hi_| running |parser_|. If any matches are
   // found they are returned.
-  absl::optional<Reference> GetNext() override {
+  std::optional<Reference> GetNext() override {
     T line_col;
     for (; offset_ < hi_; ++offset_) {
       if (!parser_.MatchAtOffset(offset_, &line_col))
@@ -306,7 +306,7 @@ class ZtfReferenceReader : public ReferenceReader {
       offset_ += config_.Width(line_col);
       return Reference{location, target};
     }
-    return absl::nullopt;
+    return std::nullopt;
   }
 
  private:
@@ -458,12 +458,12 @@ offset_t ZtfTranslator::LineColToOffset(ztf::LineCol lc) const {
   return target;
 }
 
-absl::optional<ztf::LineCol> ZtfTranslator::OffsetToLineCol(
+std::optional<ztf::LineCol> ZtfTranslator::OffsetToLineCol(
     offset_t offset) const {
   DCHECK(!line_starts_.empty());
   // Don't place a target outside the image.
   if (offset >= line_starts_.back())
-    return absl::nullopt;
+    return std::nullopt;
   auto it = SearchForRange(offset);
   ztf::LineCol lc;
   lc.line = std::distance(line_starts_.cbegin(), it) + 1;
diff --git a/disassembler_ztf.h b/disassembler_ztf.h
index 9b4a94b..8283959 100644
--- a/disassembler_ztf.h
+++ b/disassembler_ztf.h
@@ -9,13 +9,13 @@
 #include <stdlib.h>
 
 #include <memory>
+#include <optional>
 #include <string>
 #include <vector>
 
 #include "components/zucchini/disassembler.h"
 #include "components/zucchini/image_utils.h"
 #include "components/zucchini/type_ztf.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -98,8 +98,8 @@ class ZtfTranslator {
   offset_t LineColToOffset(ztf::LineCol line_col) const;
 
   // Returns the ztf::LineCol for an |offset| if it is valid. Otherwise returns
-  // absl::nullopt.
-  absl::optional<ztf::LineCol> OffsetToLineCol(offset_t offset) const;
+  // std::nullopt.
+  std::optional<ztf::LineCol> OffsetToLineCol(offset_t offset) const;
 
  private:
   // Returns an iterator to the range containing |offset|. Which is represented
diff --git a/element_detection.cc b/element_detection.cc
index 2d260e4..4d4a1c6 100644
--- a/element_detection.cc
+++ b/element_detection.cc
@@ -169,11 +169,11 @@ uint16_t DisassemblerVersionOfType(ExecutableType exe_type) {
   }
 }
 
-absl::optional<Element> DetectElementFromDisassembler(ConstBufferView image) {
+std::optional<Element> DetectElementFromDisassembler(ConstBufferView image) {
   std::unique_ptr<Disassembler> disasm = MakeDisassemblerWithoutFallback(image);
   if (disasm)
     return Element({0, disasm->size()}, disasm->GetExeType());
-  return absl::nullopt;
+  return std::nullopt;
 }
 
 /******** ProgramScanner ********/
@@ -183,18 +183,18 @@ ElementFinder::ElementFinder(ConstBufferView image, ElementDetector&& detector)
 
 ElementFinder::~ElementFinder() = default;
 
-absl::optional<Element> ElementFinder::GetNext() {
+std::optional<Element> ElementFinder::GetNext() {
   for (; pos_ < image_.size(); ++pos_) {
     ConstBufferView test_image =
         ConstBufferView::FromRange(image_.begin() + pos_, image_.end());
-    absl::optional<Element> element = detector_.Run(test_image);
+    std::optional<Element> element = detector_.Run(test_image);
     if (element) {
       element->offset += pos_;
       pos_ = element->EndOffset();
       return element;
     }
   }
-  return absl::nullopt;
+  return std::nullopt;
 }
 
 }  // namespace zucchini
diff --git a/element_detection.h b/element_detection.h
index febedc5..7d4b0bc 100644
--- a/element_detection.h
+++ b/element_detection.h
@@ -8,11 +8,11 @@
 #include <stddef.h>
 
 #include <memory>
+#include <optional>
 
 #include "base/callback.h"
 #include "components/zucchini/buffer_view.h"
 #include "components/zucchini/image_utils.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -34,10 +34,10 @@ uint16_t DisassemblerVersionOfType(ExecutableType exe_type);
 // Attempts to detect an element associated with |image| and returns it, or
 // returns nullopt if no element is detected.
 using ElementDetector =
-    base::RepeatingCallback<absl::optional<Element>(ConstBufferView image)>;
+    base::RepeatingCallback<std::optional<Element>(ConstBufferView image)>;
 
 // Implementation of ElementDetector using disassemblers.
-absl::optional<Element> DetectElementFromDisassembler(ConstBufferView image);
+std::optional<Element> DetectElementFromDisassembler(ConstBufferView image);
 
 // A class to scan through an image and iteratively detect elements.
 class ElementFinder {
@@ -49,7 +49,7 @@ class ElementFinder {
 
   // Scans for the next executable using |detector|. Returns the next element
   // found, or nullopt if no more element can be found.
-  absl::optional<Element> GetNext();
+  std::optional<Element> GetNext();
 
  private:
   ConstBufferView image_;
diff --git a/element_detection_unittest.cc b/element_detection_unittest.cc
index 319a88a..b3519ed 100644
--- a/element_detection_unittest.cc
+++ b/element_detection_unittest.cc
@@ -45,7 +45,7 @@ class ElementDetectionTest : public ::testing::Test {
         image,
         base::BindRepeating(
             [](ExeTypeMap exe_map, ConstBufferView image,
-               ConstBufferView region) -> absl::optional<Element> {
+               ConstBufferView region) -> std::optional<Element> {
               EXPECT_GE(region.begin(), image.begin());
               EXPECT_LE(region.end(), image.end());
               EXPECT_GE(region.size(), 0U);
@@ -56,7 +56,7 @@ class ElementDetectionTest : public ::testing::Test {
                   ++length;
                 return Element{{0, length}, exe_map[region[0]]};
               }
-              return absl::nullopt;
+              return std::nullopt;
             },
             exe_map_, image));
     std::vector<Element> elements;
@@ -74,10 +74,10 @@ TEST_F(ElementDetectionTest, ElementFinderEmpty) {
   std::vector<uint8_t> buffer(10, 0);
   ElementFinder finder(
       ConstBufferView(buffer.data(), buffer.size()),
-      base::BindRepeating([](ConstBufferView image) -> absl::optional<Element> {
-        return absl::nullopt;
+      base::BindRepeating([](ConstBufferView image) -> std::optional<Element> {
+        return std::nullopt;
       }));
-  EXPECT_EQ(absl::nullopt, finder.GetNext());
+  EXPECT_EQ(std::nullopt, finder.GetNext());
 }
 
 TEST_F(ElementDetectionTest, ElementFinder) {
diff --git a/fuzzers/patch_fuzzer.cc b/fuzzers/patch_fuzzer.cc
index 83bebcf..fe34e09 100644
--- a/fuzzers/patch_fuzzer.cc
+++ b/fuzzers/patch_fuzzer.cc
@@ -5,15 +5,16 @@
 #include <stddef.h>
 #include <stdint.h>
 
+#include <optional>
+
 #include "components/zucchini/buffer_view.h"
 #include "components/zucchini/patch_reader.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 // Entry point for LibFuzzer.
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
   logging::SetMinLogLevel(3);  // Disable console spamming.
   zucchini::ConstBufferView patch(data, size);
-  absl::optional<zucchini::EnsemblePatchReader> patch_reader =
+  std::optional<zucchini::EnsemblePatchReader> patch_reader =
       zucchini::EnsemblePatchReader::Create(patch);
   return 0;
 }
diff --git a/heuristic_ensemble_matcher.cc b/heuristic_ensemble_matcher.cc
index 2f01d34..53ef090 100644
--- a/heuristic_ensemble_matcher.cc
+++ b/heuristic_ensemble_matcher.cc
@@ -26,9 +26,9 @@ namespace {
 /******** Helper Functions ********/
 
 // Uses |detector| to find embedded executables inside |image|, and returns the
-// result on success, or absl::nullopt on failure,  which occurs if too many (>
+// result on success, or std::nullopt on failure,  which occurs if too many (>
 // |kElementLimit|) elements are found.
-absl::optional<std::vector<Element>> FindEmbeddedElements(
+std::optional<std::vector<Element>> FindEmbeddedElements(
     ConstBufferView image,
     const std::string& name,
     ElementDetector&& detector) {
@@ -46,7 +46,7 @@ absl::optional<std::vector<Element>> FindEmbeddedElements(
   }
   if (elements.size() >= kElementLimit) {
     LOG(WARNING) << name << ": Found too many elements.";
-    return absl::nullopt;
+    return std::nullopt;
   }
   LOG(INFO) << name << ": Found " << elements.size() << " elements.";
   return elements;
@@ -244,12 +244,12 @@ bool HeuristicEnsembleMatcher::RunMatch(ConstBufferView old_image,
   LOG(INFO) << "Start matching.";
 
   // Find all elements in "old" and "new".
-  absl::optional<std::vector<Element>> old_elements =
+  std::optional<std::vector<Element>> old_elements =
       FindEmbeddedElements(old_image, "Old file",
                            base::BindRepeating(DetectElementFromDisassembler));
   if (!old_elements.has_value())
     return false;
-  absl::optional<std::vector<Element>> new_elements =
+  std::optional<std::vector<Element>> new_elements =
       FindEmbeddedElements(new_image, "New file",
                            base::BindRepeating(DetectElementFromDisassembler));
   if (!new_elements.has_value())
diff --git a/image_utils.h b/image_utils.h
index 748e20b..7bfa8cf 100644
--- a/image_utils.h
+++ b/image_utils.h
@@ -8,6 +8,7 @@
 #include <stddef.h>
 #include <stdint.h>
 
+#include <optional>
 #include <string>
 
 #include "base/format_macros.h"
@@ -15,7 +16,6 @@
 #include "base/strings/stringprintf.h"
 #include "components/zucchini/buffer_view.h"
 #include "components/zucchini/typed_value.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -93,7 +93,7 @@ class ReferenceReader {
 
   // Returns the next available Reference, or nullopt_t if exhausted.
   // Extracted References must be ordered by their location in the image.
-  virtual absl::optional<Reference> GetNext() = 0;
+  virtual std::optional<Reference> GetNext() = 0;
 };
 
 // Interface for writing References through member function
diff --git a/imposed_ensemble_matcher.cc b/imposed_ensemble_matcher.cc
index 1c1301b..14e6c91 100644
--- a/imposed_ensemble_matcher.cc
+++ b/imposed_ensemble_matcher.cc
@@ -89,8 +89,8 @@ ImposedMatchParser::Status ImposedMatchParser::Parse(
       continue;
     }
     // Check executable types of sub-images.
-    absl::optional<Element> old_element = detector.Run(old_sub_image);
-    absl::optional<Element> new_element = detector.Run(new_sub_image);
+    std::optional<Element> old_element = detector.Run(old_sub_image);
+    std::optional<Element> new_element = detector.Run(new_sub_image);
     if (!old_element || !new_element) {
       // Skip unknown types, including those mixed with known types.
       bad_matches_.push_back(matches_[read_idx]);
diff --git a/imposed_ensemble_matcher_unittest.cc b/imposed_ensemble_matcher_unittest.cc
index 9a6dc7d..4e98fe7 100644
--- a/imposed_ensemble_matcher_unittest.cc
+++ b/imposed_ensemble_matcher_unittest.cc
@@ -5,6 +5,7 @@
 #include <stddef.h>
 #include <stdint.h>
 
+#include <optional>
 #include <string>
 #include <utility>
 #include <vector>
@@ -19,7 +20,6 @@
 #include "components/zucchini/element_detection.h"
 #include "components/zucchini/image_utils.h"
 #include "testing/gtest/include/gtest/gtest.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -36,14 +36,14 @@ class TestElementDetector {
  public:
   TestElementDetector() {}
 
-  absl::optional<Element> Run(ConstBufferView image) const {
+  std::optional<Element> Run(ConstBufferView image) const {
     DCHECK_GT(image.size(), 0U);
     char first_char = *image.begin();
     if (first_char == 'W' || first_char == 'w')
       return Element(image.local_region(), kExeTypeWin32X86);
     if (first_char == 'E' || first_char == 'e')
       return Element(image.local_region(), kExeTypeElfX86);
-    return absl::nullopt;
+    return std::nullopt;
   }
 };
 
diff --git a/integration_test.cc b/integration_test.cc
index 1baccc3..2bcb4f2 100644
--- a/integration_test.cc
+++ b/integration_test.cc
@@ -5,6 +5,7 @@
 #include <stdint.h>
 
 #include <algorithm>
+#include <optional>
 #include <string>
 #include <vector>
 
@@ -16,7 +17,6 @@
 #include "components/zucchini/patch_writer.h"
 #include "components/zucchini/zucchini.h"
 #include "testing/gtest/include/gtest/gtest.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -59,7 +59,7 @@ void TestGenApply(const std::string& old_filename,
   patch_writer.SerializeInto({patch_buffer.data(), patch_buffer.size()});
 
   // Read back generated patch.
-  absl::optional<EnsemblePatchReader> patch_reader =
+  std::optional<EnsemblePatchReader> patch_reader =
       EnsemblePatchReader::Create({patch_buffer.data(), patch_buffer.size()});
   ASSERT_TRUE(patch_reader.has_value());
 
diff --git a/patch_reader.cc b/patch_reader.cc
index 50ee199..168389f 100644
--- a/patch_reader.cc
+++ b/patch_reader.cc
@@ -86,42 +86,42 @@ bool EquivalenceSource::Initialize(BufferSource* source) {
          patch::ParseBuffer(source, &copy_count_);
 }
 
-absl::optional<Equivalence> EquivalenceSource::GetNext() {
+std::optional<Equivalence> EquivalenceSource::GetNext() {
   if (src_skip_.empty() || dst_skip_.empty() || copy_count_.empty())
-    return absl::nullopt;
+    return std::nullopt;
 
   Equivalence equivalence = {};
 
   uint32_t length = 0;
   if (!patch::ParseVarUInt<uint32_t>(&copy_count_, &length))
-    return absl::nullopt;
+    return std::nullopt;
   equivalence.length = base::strict_cast<offset_t>(length);
 
   int32_t src_offset_diff = 0;  // Intentionally signed.
   if (!patch::ParseVarInt<int32_t>(&src_skip_, &src_offset_diff))
-    return absl::nullopt;
+    return std::nullopt;
   base::CheckedNumeric<offset_t> src_offset =
       previous_src_offset_ + src_offset_diff;
   if (!src_offset.IsValid())
-    return absl::nullopt;
+    return std::nullopt;
 
   equivalence.src_offset = src_offset.ValueOrDie();
   previous_src_offset_ = src_offset + equivalence.length;
   if (!previous_src_offset_.IsValid())
-    return absl::nullopt;
+    return std::nullopt;
 
   uint32_t dst_offset_diff = 0;  // Intentionally unsigned.
   if (!patch::ParseVarUInt<uint32_t>(&dst_skip_, &dst_offset_diff))
-    return absl::nullopt;
+    return std::nullopt;
   base::CheckedNumeric<offset_t> dst_offset =
       previous_dst_offset_ + dst_offset_diff;
   if (!dst_offset.IsValid())
-    return absl::nullopt;
+    return std::nullopt;
 
   equivalence.dst_offset = dst_offset.ValueOrDie();
   previous_dst_offset_ = equivalence.dst_offset + equivalence.length;
   if (!previous_dst_offset_.IsValid())
-    return absl::nullopt;
+    return std::nullopt;
 
   // Caveat: |equivalence| is assumed to be safe only once the
   // ValidateEquivalencesAndExtraData() method has returned true. Prior to this
@@ -139,10 +139,10 @@ bool ExtraDataSource::Initialize(BufferSource* source) {
   return patch::ParseBuffer(source, &extra_data_);
 }
 
-absl::optional<ConstBufferView> ExtraDataSource::GetNext(offset_t size) {
+std::optional<ConstBufferView> ExtraDataSource::GetNext(offset_t size) {
   ConstBufferView buffer;
   if (!extra_data_.GetRegion(size, &buffer))
-    return absl::nullopt;
+    return std::nullopt;
   // |buffer| is assumed to always be safe/valid.
   return buffer;
 }
@@ -158,32 +158,32 @@ bool RawDeltaSource::Initialize(BufferSource* source) {
          patch::ParseBuffer(source, &raw_delta_diff_);
 }
 
-absl::optional<RawDeltaUnit> RawDeltaSource::GetNext() {
+std::optional<RawDeltaUnit> RawDeltaSource::GetNext() {
   if (raw_delta_skip_.empty() || raw_delta_diff_.empty())
-    return absl::nullopt;
+    return std::nullopt;
 
   RawDeltaUnit raw_delta = {};
   uint32_t copy_offset_diff = 0;
   if (!patch::ParseVarUInt<uint32_t>(&raw_delta_skip_, &copy_offset_diff))
-    return absl::nullopt;
+    return std::nullopt;
   base::CheckedNumeric<offset_t> copy_offset =
       copy_offset_diff + copy_offset_compensation_;
   if (!copy_offset.IsValid())
-    return absl::nullopt;
+    return std::nullopt;
   raw_delta.copy_offset = copy_offset.ValueOrDie();
 
   if (!raw_delta_diff_.GetValue<int8_t>(&raw_delta.diff))
-    return absl::nullopt;
+    return std::nullopt;
 
   // A 0 value for a delta.diff is considered invalid since it has no meaning.
   if (!raw_delta.diff)
-    return absl::nullopt;
+    return std::nullopt;
 
   // We keep track of the compensation needed for next offset, taking into
   // account delta encoding and bias of -1.
   copy_offset_compensation_ = copy_offset + 1;
   if (!copy_offset_compensation_.IsValid())
-    return absl::nullopt;
+    return std::nullopt;
   // |raw_delta| is assumed to always be safe/valid.
   return raw_delta;
 }
@@ -199,12 +199,12 @@ bool ReferenceDeltaSource::Initialize(BufferSource* source) {
   return patch::ParseBuffer(source, &source_);
 }
 
-absl::optional<int32_t> ReferenceDeltaSource::GetNext() {
+std::optional<int32_t> ReferenceDeltaSource::GetNext() {
   if (source_.empty())
-    return absl::nullopt;
+    return std::nullopt;
   int32_t ref_delta = 0;
   if (!patch::ParseVarInt<int32_t>(&source_, &ref_delta))
-    return absl::nullopt;
+    return std::nullopt;
   // |ref_delta| is assumed to always be safe/valid.
   return ref_delta;
 }
@@ -219,22 +219,22 @@ bool TargetSource::Initialize(BufferSource* source) {
   return patch::ParseBuffer(source, &extra_targets_);
 }
 
-absl::optional<offset_t> TargetSource::GetNext() {
+std::optional<offset_t> TargetSource::GetNext() {
   if (extra_targets_.empty())
-    return absl::nullopt;
+    return std::nullopt;
 
   uint32_t target_diff = 0;
   if (!patch::ParseVarUInt<uint32_t>(&extra_targets_, &target_diff))
-    return absl::nullopt;
+    return std::nullopt;
   base::CheckedNumeric<offset_t> target = target_diff + target_compensation_;
   if (!target.IsValid())
-    return absl::nullopt;
+    return std::nullopt;
 
   // We keep track of the compensation needed for next target, taking into
   // account delta encoding and bias of -1.
   target_compensation_ = target + 1;
   if (!target_compensation_.IsValid())
-    return absl::nullopt;
+    return std::nullopt;
   // Caveat: |target| will be a valid offset_t, but it's up to the caller to
   // check whether it's a valid offset for an image.
   return offset_t(target.ValueOrDie());
@@ -320,12 +320,12 @@ bool PatchElementReader::ValidateEquivalencesAndExtraData() {
 
 /******** EnsemblePatchReader ********/
 
-absl::optional<EnsemblePatchReader> EnsemblePatchReader::Create(
+std::optional<EnsemblePatchReader> EnsemblePatchReader::Create(
     ConstBufferView buffer) {
   BufferSource source(buffer);
   EnsemblePatchReader patch;
   if (!patch.Initialize(&source))
-    return absl::nullopt;
+    return std::nullopt;
   return patch;
 }
 
diff --git a/patch_reader.h b/patch_reader.h
index 93d64b0..ed0ab9c 100644
--- a/patch_reader.h
+++ b/patch_reader.h
@@ -9,6 +9,7 @@
 #include <stdint.h>
 
 #include <map>
+#include <optional>
 #include <vector>
 
 #include "base/debug/stack_trace.h"
@@ -18,7 +19,6 @@
 #include "components/zucchini/buffer_view.h"
 #include "components/zucchini/image_utils.h"
 #include "components/zucchini/patch_utils.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -77,8 +77,8 @@ bool ParseVarInt(BufferSource* source, T* value) {
 // - bool Initialize(BufferSource* source): Consumes data from BufferSource and
 //   initializes internal states. Returns true if successful, and false
 //   otherwise (|source| may be partially consumed).
-// - absl::optional<MAIN_TYPE> GetNext(OPT_PARAMS): Decodes consumed data and
-//   returns the next item as absl::optional (returns absl::nullopt on failure).
+// - std::optional<MAIN_TYPE> GetNext(OPT_PARAMS): Decodes consumed data and
+//   returns the next item as std::optional (returns std::nullopt on failure).
 // - bool Done() const: Returns true if no more items remain; otherwise false.
 //
 // Usage of *Source instances don't mix, and GetNext() have dissimilar
@@ -94,7 +94,7 @@ class EquivalenceSource {
 
   // Core functions.
   bool Initialize(BufferSource* source);
-  absl::optional<Equivalence> GetNext();
+  std::optional<Equivalence> GetNext();
   bool Done() const {
     return src_skip_.empty() && dst_skip_.empty() && copy_count_.empty();
   }
@@ -123,7 +123,7 @@ class ExtraDataSource {
   // Core functions.
   bool Initialize(BufferSource* source);
   // |size| is the size in bytes of the buffer requested.
-  absl::optional<ConstBufferView> GetNext(offset_t size);
+  std::optional<ConstBufferView> GetNext(offset_t size);
   bool Done() const { return extra_data_.empty(); }
 
   // Accessors for unittest.
@@ -142,7 +142,7 @@ class RawDeltaSource {
 
   // Core functions.
   bool Initialize(BufferSource* source);
-  absl::optional<RawDeltaUnit> GetNext();
+  std::optional<RawDeltaUnit> GetNext();
   bool Done() const {
     return raw_delta_skip_.empty() && raw_delta_diff_.empty();
   }
@@ -167,7 +167,7 @@ class ReferenceDeltaSource {
 
   // Core functions.
   bool Initialize(BufferSource* source);
-  absl::optional<int32_t> GetNext();
+  std::optional<int32_t> GetNext();
   bool Done() const { return source_.empty(); }
 
   // Accessors for unittest.
@@ -186,7 +186,7 @@ class TargetSource {
 
   // Core functions.
   bool Initialize(BufferSource* source);
-  absl::optional<offset_t> GetNext();
+  std::optional<offset_t> GetNext();
   bool Done() const { return extra_targets_.empty(); }
 
   // Accessors for unittest.
@@ -256,8 +256,8 @@ class PatchElementReader {
 class EnsemblePatchReader {
  public:
   // If data read from |buffer| is well-formed, initializes and returns
-  // an instance of EnsemblePatchReader. Otherwise returns absl::nullopt.
-  static absl::optional<EnsemblePatchReader> Create(ConstBufferView buffer);
+  // an instance of EnsemblePatchReader. Otherwise returns std::nullopt.
+  static std::optional<EnsemblePatchReader> Create(ConstBufferView buffer);
 
   EnsemblePatchReader();
   EnsemblePatchReader(EnsemblePatchReader&&);
diff --git a/patch_writer.h b/patch_writer.h
index 26b7baf..9bcaad8 100644
--- a/patch_writer.h
+++ b/patch_writer.h
@@ -9,6 +9,7 @@
 #include <stdint.h>
 
 #include <map>
+#include <optional>
 #include <utility>
 #include <vector>
 
@@ -17,7 +18,6 @@
 #include "components/zucchini/buffer_view.h"
 #include "components/zucchini/image_utils.h"
 #include "components/zucchini/patch_utils.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -223,10 +223,10 @@ class PatchElementWriter {
 
  private:
   ElementMatch element_match_;
-  absl::optional<EquivalenceSink> equivalences_;
-  absl::optional<ExtraDataSink> extra_data_;
-  absl::optional<RawDeltaSink> raw_delta_;
-  absl::optional<ReferenceDeltaSink> reference_delta_;
+  std::optional<EquivalenceSink> equivalences_;
+  std::optional<ExtraDataSink> extra_data_;
+  std::optional<RawDeltaSink> raw_delta_;
+  std::optional<ReferenceDeltaSink> reference_delta_;
   std::map<PoolTag, TargetSink> extra_targets_;
 };
 
diff --git a/rel32_utils.cc b/rel32_utils.cc
index c22cb23..3790ed0 100644
--- a/rel32_utils.cc
+++ b/rel32_utils.cc
@@ -30,7 +30,7 @@ Rel32ReaderX86::Rel32ReaderX86(ConstBufferView image,
 
 Rel32ReaderX86::~Rel32ReaderX86() = default;
 
-absl::optional<Reference> Rel32ReaderX86::GetNext() {
+std::optional<Reference> Rel32ReaderX86::GetNext() {
   while (current_ < last_ && *current_ < hi_) {
     offset_t loc_offset = *(current_++);
     DCHECK_LE(loc_offset + 4, image_.size());  // Sanity check.
@@ -41,7 +41,7 @@ absl::optional<Reference> Rel32ReaderX86::GetNext() {
     DCHECK_NE(kInvalidOffset, target_offset);
     return Reference{loc_offset, target_offset};
   }
-  return absl::nullopt;
+  return std::nullopt;
 }
 
 /******** Rel32ReceptorX86 ********/
diff --git a/rel32_utils.h b/rel32_utils.h
index f54c5cd..30dd4af 100644
--- a/rel32_utils.h
+++ b/rel32_utils.h
@@ -8,6 +8,7 @@
 #include <algorithm>
 #include <deque>
 #include <memory>
+#include <optional>
 
 #include "base/logging.h"
 #include "components/zucchini/address_translator.h"
@@ -15,7 +16,6 @@
 #include "components/zucchini/buffer_view.h"
 #include "components/zucchini/image_utils.h"
 #include "components/zucchini/io_utils.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -37,8 +37,8 @@ class Rel32ReaderX86 : public ReferenceReader {
   const Rel32ReaderX86& operator=(const Rel32ReaderX86&) = delete;
   ~Rel32ReaderX86() override;
 
-  // Returns the next reference, or absl::nullopt if exhausted.
-  absl::optional<Reference> GetNext() override;
+  // Returns the next reference, or std::nullopt if exhausted.
+  std::optional<Reference> GetNext() override;
 
  private:
   ConstBufferView image_;
@@ -93,7 +93,7 @@ class Rel32ReaderArm : public ReferenceReader {
   Rel32ReaderArm(const Rel32ReaderArm&) = delete;
   const Rel32ReaderArm& operator=(const Rel32ReaderArm&) = delete;
 
-  absl::optional<Reference> GetNext() override {
+  std::optional<Reference> GetNext() override {
     while (cur_it_ < rel32_end_ && *cur_it_ < hi_) {
       offset_t location = *(cur_it_++);
       CODE_T code = ADDR_TRAITS::Fetch(view_, location);
@@ -105,7 +105,7 @@ class Rel32ReaderArm : public ReferenceReader {
           return Reference{location, target};
       }
     }
-    return absl::nullopt;
+    return std::nullopt;
   }
 
  private:
diff --git a/rel32_utils_unittest.cc b/rel32_utils_unittest.cc
index f4a6bde..0283f30 100644
--- a/rel32_utils_unittest.cc
+++ b/rel32_utils_unittest.cc
@@ -8,6 +8,7 @@
 
 #include <deque>
 #include <memory>
+#include <optional>
 #include <utility>
 #include <vector>
 
@@ -16,7 +17,6 @@
 #include "components/zucchini/arm_utils.h"
 #include "components/zucchini/image_utils.h"
 #include "testing/gtest/include/gtest/gtest.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -40,7 +40,7 @@ void CheckReader(const std::vector<Reference>& expected_refs,
     EXPECT_TRUE(ref.has_value());
     EXPECT_EQ(expected_ref, ref.value());
   }
-  EXPECT_EQ(absl::nullopt, reader->GetNext());  // Nothing should be left.
+  EXPECT_EQ(std::nullopt, reader->GetNext());  // Nothing should be left.
 }
 
 // Copies displacements from |bytes1| to |bytes2| and checks results against
diff --git a/reloc_elf.cc b/reloc_elf.cc
index a7d1b38..9deaade 100644
--- a/reloc_elf.cc
+++ b/reloc_elf.cc
@@ -89,7 +89,7 @@ rva_t RelocReaderElf::GetRelocationTarget(elf::Elf64_Rel rel) const {
   return kInvalidRva;
 }
 
-absl::optional<Reference> RelocReaderElf::GetNext() {
+std::optional<Reference> RelocReaderElf::GetNext() {
   offset_t cur_entry_size = cur_section_dimensions_->entry_size;
   offset_t cur_section_dimensions_end =
       base::checked_cast<offset_t>(cur_section_dimensions_->region.hi());
@@ -98,12 +98,12 @@ absl::optional<Reference> RelocReaderElf::GetNext() {
     while (cursor_ >= cur_section_dimensions_end) {
       ++cur_section_dimensions_;
       if (cur_section_dimensions_ == reloc_section_dimensions_.end())
-        return absl::nullopt;
+        return std::nullopt;
       cur_entry_size = cur_section_dimensions_->entry_size;
       cursor_ =
           base::checked_cast<offset_t>(cur_section_dimensions_->region.offset);
       if (cursor_ + cur_entry_size > hi_)
-        return absl::nullopt;
+        return std::nullopt;
       cur_section_dimensions_end =
           base::checked_cast<offset_t>(cur_section_dimensions_->region.hi());
     }
@@ -132,7 +132,7 @@ absl::optional<Reference> RelocReaderElf::GetNext() {
     cursor_ += cur_entry_size;
     return Reference{location, target};
   }
-  return absl::nullopt;
+  return std::nullopt;
 }
 
 /******** RelocWriterElf ********/
diff --git a/reloc_elf.h b/reloc_elf.h
index ebf2577..f53aff2 100644
--- a/reloc_elf.h
+++ b/reloc_elf.h
@@ -8,6 +8,7 @@
 #include <stddef.h>
 #include <stdint.h>
 
+#include <optional>
 #include <vector>
 
 #include "base/numerics/safe_conversions.h"
@@ -15,7 +16,6 @@
 #include "components/zucchini/buffer_view.h"
 #include "components/zucchini/image_utils.h"
 #include "components/zucchini/type_elf.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -68,7 +68,7 @@ class RelocReaderElf : public ReferenceReader {
   rva_t GetRelocationTarget(elf::Elf64_Rel rel) const;
 
   // ReferenceReader:
-  absl::optional<Reference> GetNext() override;
+  std::optional<Reference> GetNext() override;
 
  private:
   const ConstBufferView image_;
diff --git a/reloc_elf_unittest.cc b/reloc_elf_unittest.cc
index 8a1b932..6d90a1a 100644
--- a/reloc_elf_unittest.cc
+++ b/reloc_elf_unittest.cc
@@ -87,7 +87,7 @@ class FakeImageWithReloc {
 
     // Read all references and check.
     std::vector<Reference> refs;
-    for (absl::optional<Reference> ref = reader->GetNext(); ref.has_value();
+    for (std::optional<Reference> ref = reader->GetNext(); ref.has_value();
          ref = reader->GetNext()) {
       refs.push_back(ref.value());
     }
diff --git a/reloc_win32.cc b/reloc_win32.cc
index b70aa8a..a39bd35 100644
--- a/reloc_win32.cc
+++ b/reloc_win32.cc
@@ -93,14 +93,14 @@ RelocRvaReaderWin32::RelocRvaReaderWin32(RelocRvaReaderWin32&&) = default;
 RelocRvaReaderWin32::~RelocRvaReaderWin32() = default;
 
 // Unrolls a nested loop: outer = reloc blocks and inner = reloc entries.
-absl::optional<RelocUnitWin32> RelocRvaReaderWin32::GetNext() {
+std::optional<RelocUnitWin32> RelocRvaReaderWin32::GetNext() {
   // "Outer loop" to find non-empty reloc block.
   while (cur_reloc_units_.Remaining() < kRelocUnitSize) {
     if (!LoadRelocBlock(cur_reloc_units_.end()))
-      return absl::nullopt;
+      return std::nullopt;
   }
   if (end_it_ - cur_reloc_units_.begin() < kRelocUnitSize)
-    return absl::nullopt;
+    return std::nullopt;
   // "Inner loop" to extract single reloc unit.
   offset_t location =
       base::checked_cast<offset_t>(cur_reloc_units_.begin() - image_.begin());
@@ -144,8 +144,8 @@ RelocReaderWin32::RelocReaderWin32(RelocRvaReaderWin32&& reloc_rva_reader,
 RelocReaderWin32::~RelocReaderWin32() = default;
 
 // ReferenceReader:
-absl::optional<Reference> RelocReaderWin32::GetNext() {
-  for (absl::optional<RelocUnitWin32> unit = reloc_rva_reader_.GetNext();
+std::optional<Reference> RelocReaderWin32::GetNext() {
+  for (std::optional<RelocUnitWin32> unit = reloc_rva_reader_.GetNext();
        unit.has_value(); unit = reloc_rva_reader_.GetNext()) {
     if (unit->type != reloc_type_)
       continue;
@@ -158,7 +158,7 @@ absl::optional<Reference> RelocReaderWin32::GetNext() {
     offset_t location = unit->location;
     return Reference{location, target};
   }
-  return absl::nullopt;
+  return std::nullopt;
 }
 
 /******** RelocWriterWin32 ********/
diff --git a/reloc_win32.h b/reloc_win32.h
index 6393702..b378659 100644
--- a/reloc_win32.h
+++ b/reloc_win32.h
@@ -8,13 +8,13 @@
 #include <stddef.h>
 #include <stdint.h>
 
+#include <optional>
 #include <vector>
 
 #include "components/zucchini/address_translator.h"
 #include "components/zucchini/buffer_source.h"
 #include "components/zucchini/buffer_view.h"
 #include "components/zucchini/image_utils.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -65,9 +65,9 @@ class RelocRvaReaderWin32 {
   RelocRvaReaderWin32(RelocRvaReaderWin32&&);
   ~RelocRvaReaderWin32();
 
-  // Successively visits and returns data for each reloc unit, or absl::nullopt
+  // Successively visits and returns data for each reloc unit, or std::nullopt
   // when all reloc units are found. Encapsulates block transition details.
-  absl::optional<RelocUnitWin32> GetNext();
+  std::optional<RelocUnitWin32> GetNext();
 
  private:
   // Assuming that |block_begin| points to the beginning of a reloc block, loads
@@ -102,7 +102,7 @@ class RelocReaderWin32 : public ReferenceReader {
   ~RelocReaderWin32() override;
 
   // ReferenceReader:
-  absl::optional<Reference> GetNext() override;
+  std::optional<Reference> GetNext() override;
 
  private:
   RelocRvaReaderWin32 reloc_rva_reader_;
diff --git a/reloc_win32_unittest.cc b/reloc_win32_unittest.cc
index e3d33ca..c2fc99c 100644
--- a/reloc_win32_unittest.cc
+++ b/reloc_win32_unittest.cc
@@ -219,7 +219,7 @@ TEST_F(RelocUtilsWin32Test, ReadWrite) {
 
   // Read all references and check.
   std::vector<Reference> refs;
-  for (absl::optional<Reference> ref = reader->GetNext(); ref.has_value();
+  for (std::optional<Reference> ref = reader->GetNext(); ref.has_value();
        ref = reader->GetNext()) {
     refs.push_back(ref.value());
   }
diff --git a/test_reference_reader.cc b/test_reference_reader.cc
index b7f8ece..eb9898d 100644
--- a/test_reference_reader.cc
+++ b/test_reference_reader.cc
@@ -11,9 +11,9 @@ TestReferenceReader::TestReferenceReader(const std::vector<Reference>& refs)
 
 TestReferenceReader::~TestReferenceReader() = default;
 
-absl::optional<Reference> TestReferenceReader::GetNext() {
+std::optional<Reference> TestReferenceReader::GetNext() {
   if (index_ == references_.size())
-    return absl::nullopt;
+    return std::nullopt;
   return references_[index_++];
 }
 
diff --git a/test_reference_reader.h b/test_reference_reader.h
index cc8c0de..3849eb9 100644
--- a/test_reference_reader.h
+++ b/test_reference_reader.h
@@ -7,10 +7,10 @@
 
 #include <stddef.h>
 
+#include <optional>
 #include <vector>
 
 #include "components/zucchini/image_utils.h"
-#include "third_party/abseil-cpp/absl/types/optional.h"
 
 namespace zucchini {
 
@@ -20,7 +20,7 @@ class TestReferenceReader : public ReferenceReader {
   explicit TestReferenceReader(const std::vector<Reference>& refs);
   ~TestReferenceReader() override;
 
-  absl::optional<Reference> GetNext() override;
+  std::optional<Reference> GetNext() override;
 
  private:
   std::vector<Reference> references_;
diff --git a/zucchini_apply.cc b/zucchini_apply.cc
index 10c5638..76142e0 100644
--- a/zucchini_apply.cc
+++ b/zucchini_apply.cc
@@ -32,7 +32,7 @@ bool ApplyEquivalenceAndExtraData(ConstBufferView old_image,
     CHECK(next_dst_it >= dst_it);
 
     offset_t gap = static_cast<offset_t>(next_dst_it - dst_it);
-    absl::optional<ConstBufferView> extra_data = extra_data_source.GetNext(gap);
+    std::optional<ConstBufferView> extra_data = extra_data_source.GetNext(gap);
     if (!extra_data) {
       LOG(ERROR) << "Error reading extra_data";
       return false;
@@ -46,7 +46,7 @@ bool ApplyEquivalenceAndExtraData(ConstBufferView old_image,
     CHECK_EQ(dst_it, next_dst_it + equivalence->length);
   }
   offset_t gap = static_cast<offset_t>(new_image.end() - dst_it);
-  absl::optional<ConstBufferView> extra_data = extra_data_source.GetNext(gap);
+  std::optional<ConstBufferView> extra_data = extra_data_source.GetNext(gap);
   if (!extra_data) {
     LOG(ERROR) << "Error reading extra_data";
     return false;
```

