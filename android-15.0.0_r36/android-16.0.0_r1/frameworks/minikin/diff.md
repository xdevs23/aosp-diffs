```diff
diff --git a/include/minikin/SparseBitSet.h b/include/minikin/SparseBitSet.h
index 33047e8..2b3639c 100644
--- a/include/minikin/SparseBitSet.h
+++ b/include/minikin/SparseBitSet.h
@@ -18,6 +18,7 @@
 #define MINIKIN_SPARSE_BIT_SET_H
 
 #include <minikin/Buffer.h>
+#include <stdlib.h>
 #include <sys/types.h>
 
 #include <cstdint>
diff --git a/libs/minikin/LayoutCore.cpp b/libs/minikin/LayoutCore.cpp
index 06dd709..c4c231b 100644
--- a/libs/minikin/LayoutCore.cpp
+++ b/libs/minikin/LayoutCore.cpp
@@ -361,7 +361,7 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
 
         // Note: scriptRunStart and scriptRunEnd, as well as run.start and run.end, run between 0
         // and count.
-        for (const auto [range, script] : ScriptText(textBuf, run.start, run.end)) {
+        for (const auto [range, script] : ScriptText(substr, run.start, run.end)) {
             ssize_t scriptRunStart = range.getStart();
             ssize_t scriptRunEnd = range.getEnd();
 
diff --git a/libs/minikin/OptimalLineBreaker.cpp b/libs/minikin/OptimalLineBreaker.cpp
index 8824d43..4695131 100644
--- a/libs/minikin/OptimalLineBreaker.cpp
+++ b/libs/minikin/OptimalLineBreaker.cpp
@@ -207,9 +207,6 @@ std::vector<DesperateBreak> populateDesperatePoints(const U16StringPiece& textBu
         if (calculateFallback && i == (uint32_t)next) {
             out.emplace_back(i, width, SCORE_FALLBACK);
             next = wb.next();
-            if (!range.contains(next)) {
-                break;
-            }
         } else {
             out.emplace_back(i, width, SCORE_DESPERATE);
         }
diff --git a/rust/hyphenator.rs b/rust/hyphenator.rs
index 3b87e8c..ad93b2c 100644
--- a/rust/hyphenator.rs
+++ b/rust/hyphenator.rs
@@ -313,11 +313,11 @@ impl<'a> Header<'a> {
     pub fn alphabet_table(&self) -> Option<Box<dyn AlphabetLookup + 'a>> {
         let offset = self.data.read_u32(8);
         let version = self.data.read_u32(offset);
-        return match version {
+        match version {
             0 => Some(Box::new(AlphabetTable0::new(self.read_offset_and_slice(8)))),
             1 => Some(Box::new(AlphabetTable1::new(self.read_offset_and_slice(8)))),
             _ => None,
-        };
+        }
     }
 
     /// Returns the reader of the trie struct.
@@ -375,7 +375,7 @@ impl<'a> AlphabetTable0<'a> {
     }
 }
 
-impl<'a> AlphabetLookup for AlphabetTable0<'a> {
+impl AlphabetLookup for AlphabetTable0<'_> {
     /// Returns an entry of the specified offset.
     fn get_at(&self, offset: u32) -> Option<u16> {
         if offset < self.min_codepoint || offset >= self.max_codepoint {
@@ -420,7 +420,7 @@ impl<'a> AlphabetTable1<'a> {
     }
 }
 
-impl<'a> AlphabetLookup for AlphabetTable1<'a> {
+impl AlphabetLookup for AlphabetTable1<'_> {
     fn get_at(&self, c: u32) -> Option<u16> {
         if let Some(r) = self.lower_bounds(c << 11) {
             let entry = AlphabetTable1Entry::new(self.data.read_u32(8 + r * 4));
diff --git a/tests/unittest/OptimalLineBreakerTest.cpp b/tests/unittest/OptimalLineBreakerTest.cpp
index 360c179..862c114 100644
--- a/tests/unittest/OptimalLineBreakerTest.cpp
+++ b/tests/unittest/OptimalLineBreakerTest.cpp
@@ -96,7 +96,8 @@ protected:
                                            float lineWidth) {
         MeasuredTextBuilder builder;
         auto family1 = buildFontFamily("Japanese.ttf");
-        std::vector<std::shared_ptr<FontFamily>> families = {family1};
+        auto family2 = buildFontFamily("Ascii.ttf");
+        std::vector<std::shared_ptr<FontFamily>> families = {family1, family2};
         auto fc = FontCollection::create(families);
         MinikinPaint paint(fc);
         paint.size = 10.0f;  // Make 1em=10px
@@ -2494,6 +2495,33 @@ TEST_F(OptimalLineBreakerTest, testPhraseBreakAuto) {
     }
 }
 
+TEST_F(OptimalLineBreakerTest, testPhraseBreakAuto_Fallback) {
+    // For short hand of writing expectation for lines.
+    auto line = [](std::string t, float w) -> LineBreakExpectation {
+        return {t, w, StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, ASCENT, DESCENT};
+    };
+
+    // Note that disable clang-format everywhere since aligned expectation is more readable.
+    {
+        const std::vector<uint16_t> textBuf = utf8ToUtf16("\u672C\u65E5_A_B_C_D");
+        constexpr float LINE_WIDTH = 30;
+        // clang-format off
+        std::vector<LineBreakExpectation> expect = {
+                line("\u672C\u65E5", 20),
+                line("_A_", 30),
+                line("B_C", 30),
+                line("_D", 20),
+        };
+        // clang-format on
+
+        const auto actual =
+                doLineBreakForJapanese(textBuf, LineBreakWordStyle::Phrase, "ja-JP", LINE_WIDTH);
+        EXPECT_TRUE(sameLineBreak(expect, actual)) << toString(expect) << std::endl
+                                                   << " vs " << std::endl
+                                                   << toString(textBuf, actual);
+    }
+}
+
 TEST_F(OptimalLineBreakerTest, testBreakLetterSpacing) {
     constexpr BreakStrategy HIGH_QUALITY = BreakStrategy::HighQuality;
     constexpr HyphenationFrequency NO_HYPHEN = HyphenationFrequency::None;
```

