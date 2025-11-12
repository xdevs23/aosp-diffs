```diff
diff --git a/include/minikin/Font.h b/include/minikin/Font.h
index 22e9217..1bba9c2 100644
--- a/include/minikin/Font.h
+++ b/include/minikin/Font.h
@@ -39,6 +39,12 @@
 
 namespace minikin {
 
+// Material Typescale defines 15 Typescales.
+// {Display, Headline, Title, Body, Label} x {Large, Medium, Small}
+// And emphasized variants are defined. Therefore, at least 30 size should be reserved for holding
+// all typescale.
+constexpr uint32_t VARIATION_LRU_CACHE_SIZE = 32;
+
 // Represents a single font file.
 class Font {
 public:
@@ -126,8 +132,8 @@ private:
         ExternalRefs(std::shared_ptr<MinikinFont>&& typeface, HbFontUniquePtr&& baseFont)
                 : mTypeface(std::move(typeface)),
                   mBaseFont(std::move(baseFont)),
-                  mVarTypefaceCache2(16),
-                  mVarFontCache2(16) {}
+                  mVarTypefaceCache2(VARIATION_LRU_CACHE_SIZE),
+                  mVarFontCache2(VARIATION_LRU_CACHE_SIZE) {}
 
         std::shared_ptr<MinikinFont> mTypeface;
         HbFontUniquePtr mBaseFont;
diff --git a/include/minikin/Layout.h b/include/minikin/Layout.h
index c5ccabe..fdce71f 100644
--- a/include/minikin/Layout.h
+++ b/include/minikin/Layout.h
@@ -195,13 +195,14 @@ private:
                                    const MinikinPaint& paint, size_t dstStart,
                                    StartHyphenEdit startHyphen, EndHyphenEdit endHyphen,
                                    Layout* layout, float* advances, MinikinRect* bounds,
-                                   uint32_t* clusterCount);
+                                   uint32_t* clusterCount, LayoutContext* layoutContext);
 
     // Lay out a single word
     static float doLayoutWord(const uint16_t* buf, size_t start, size_t count, size_t bufSize,
                               bool isRtl, const MinikinPaint& paint, size_t bufStart,
                               StartHyphenEdit startHyphen, EndHyphenEdit endHyphen, Layout* layout,
-                              float* advances, MinikinRect* bounds, uint32_t* clusterCount);
+                              float* advances, MinikinRect* bounds, uint32_t* clusterCount,
+                              LayoutContext* layoutContext);
 
     // Lay out a single bidi run
     void doLayoutRun(const uint16_t* buf, size_t start, size_t count, size_t bufSize, bool isRtl,
diff --git a/include/minikin/LayoutCache.h b/include/minikin/LayoutCache.h
index 40812ac..3ade586 100644
--- a/include/minikin/LayoutCache.h
+++ b/include/minikin/LayoutCache.h
@@ -156,10 +156,10 @@ public:
     template <typename F>
     void getOrCreate(const U16StringPiece& text, const Range& range, const MinikinPaint& paint,
                      bool dir, StartHyphenEdit startHyphen, EndHyphenEdit endHyphen,
-                     bool boundsCalculation, F& f) {
+                     bool boundsCalculation, LayoutContext* ctx, F& f) {
         LayoutCacheKey key(text, range, paint, dir, startHyphen, endHyphen);
         if (range.getLength() >= CHAR_LIMIT_FOR_CACHE) {
-            LayoutPiece piece(text, range, dir, paint, startHyphen, endHyphen);
+            LayoutPiece piece(text, range, dir, paint, startHyphen, endHyphen, ctx);
             if (boundsCalculation) {
                 f(piece, paint, LayoutPiece::calculateBounds(piece, paint));
             } else {
@@ -188,13 +188,13 @@ public:
 
         std::unique_ptr<LayoutSlot> slot;
         if (boundsCalculation) {
-            LayoutPiece lp = LayoutPiece(text, range, dir, paint, startHyphen, endHyphen);
+            LayoutPiece lp = LayoutPiece(text, range, dir, paint, startHyphen, endHyphen, ctx);
             MinikinRect rect = LayoutPiece::calculateBounds(lp, paint);
 
             slot = std::make_unique<LayoutSlot>(std::move(lp), std::move(rect));
         } else {
             slot = std::make_unique<LayoutSlot>(
-                    LayoutPiece(text, range, dir, paint, startHyphen, endHyphen));
+                    LayoutPiece(text, range, dir, paint, startHyphen, endHyphen, ctx));
         }
 
         f(slot->mLayout, paint, slot->mBounds);
diff --git a/include/minikin/LayoutCore.h b/include/minikin/LayoutCore.h
index e576365..ed539c0 100644
--- a/include/minikin/LayoutCore.h
+++ b/include/minikin/LayoutCore.h
@@ -42,11 +42,14 @@ using PointVector = PackedVector<Point>;
 using ClusterVector = PackedVector<uint8_t, 12>;
 using AdvanceVector = PackedVector<float>;
 
+struct LayoutContext;
+
 // Immutable, recycle-able layout result.
 class LayoutPiece {
 public:
     LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool isRtl,
-                const MinikinPaint& paint, StartHyphenEdit startHyphen, EndHyphenEdit endHyphen);
+                const MinikinPaint& paint, StartHyphenEdit startHyphen, EndHyphenEdit endHyphen,
+                LayoutContext* context);
     ~LayoutPiece();
 
     // Low level accessors.
diff --git a/include/minikin/LayoutPieces.h b/include/minikin/LayoutPieces.h
index d98ba35..009ea75 100644
--- a/include/minikin/LayoutPieces.h
+++ b/include/minikin/LayoutPieces.h
@@ -92,7 +92,8 @@ struct LayoutPieces {
     template <typename F>
     void getOrCreate(const U16StringPiece& textBuf, const Range& range, const Range& context,
                      const MinikinPaint& paint, bool dir, StartHyphenEdit startEdit,
-                     EndHyphenEdit endEdit, uint32_t paintId, bool boundsCalculation, F& f) const {
+                     EndHyphenEdit endEdit, uint32_t paintId, bool boundsCalculation,
+                     LayoutContext* ctx, F& f) const {
         const HyphenEdit edit = packHyphenEdit(startEdit, endEdit);
         auto it = offsetMap.find(Key(range, edit, dir, paintId));
         if (it != offsetMap.end()) {
@@ -108,7 +109,7 @@ struct LayoutPieces {
 
         LayoutCache::getInstance().getOrCreate(textBuf.substr(context), range - context.getStart(),
                                                paint, dir, startEdit, endEdit, boundsCalculation,
-                                               f);
+                                               ctx, f);
     }
 
     uint32_t findPaintId(const MinikinPaint& paint) const {
diff --git a/include/minikin/MeasuredText.h b/include/minikin/MeasuredText.h
index 7c36eab..77b7c87 100644
--- a/include/minikin/MeasuredText.h
+++ b/include/minikin/MeasuredText.h
@@ -107,8 +107,8 @@ public:
     virtual float measureHyphenPiece(const U16StringPiece& /* text */,
                                      const Range& /* hyphenPieceRange */,
                                      StartHyphenEdit /* startHyphen */,
-                                     EndHyphenEdit /* endHyphen */,
-                                     LayoutPieces* /* pieces */) const {
+                                     EndHyphenEdit /* endHyphen */, LayoutPieces* /* pieces */,
+                                     LayoutContext* /* layoutContext */) const {
         return 0.0;
     }
 
@@ -171,7 +171,7 @@ public:
 
     float measureHyphenPiece(const U16StringPiece& text, const Range& range,
                              StartHyphenEdit startHyphen, EndHyphenEdit endHyphen,
-                             LayoutPieces* pieces) const override;
+                             LayoutPieces* pieces, LayoutContext* ctx) const override;
     float measureText(const U16StringPiece& text) const;
 
 private:
diff --git a/include/minikin/MinikinExtent.h b/include/minikin/MinikinExtent.h
index baa56ff..770afcf 100644
--- a/include/minikin/MinikinExtent.h
+++ b/include/minikin/MinikinExtent.h
@@ -26,9 +26,11 @@ struct MinikinExtent {
     MinikinExtent() : ascent(0), descent(0) {}
     MinikinExtent(float ascent, float descent) : ascent(ascent), descent(descent) {}
 
-    void extendBy(const MinikinExtent& e) {
-        ascent = std::min(ascent, e.ascent);
-        descent = std::max(descent, e.descent);
+    void extendBy(const MinikinExtent& e) { extendBy(e.ascent, e.descent); }
+
+    void extendBy(float newAscent, float newDescent) {
+        ascent = std::min(ascent, newAscent);
+        descent = std::max(descent, newDescent);
     }
 
     float ascent;   // negative
diff --git a/libs/minikin/Android.bp b/libs/minikin/Android.bp
index 242bddd..acc2292 100644
--- a/libs/minikin/Android.bp
+++ b/libs/minikin/Android.bp
@@ -25,7 +25,6 @@ cc_library_headers {
 
 cc_library_static {
     name: "libminikin_from_rust_to_cpp",
-    cpp_std: "c++20",
     host_supported: true,
     cflags: [
         "-Wall",
@@ -64,6 +63,9 @@ cc_library_static {
                 "libicuuc",
             ],
         },
+        windows: {
+            enabled: true,
+        },
     },
 }
 
@@ -131,6 +133,10 @@ cc_library {
         "libutils_headers",
     ],
     export_header_lib_headers: ["libminikin_headers"],
+    generated_headers: [
+        "cxx-bridge-header",
+        "libminikin_cxx_bridge_header",
+    ],
 
     target: {
         android: {
@@ -142,10 +148,6 @@ cc_library {
             export_shared_lib_headers: [
                 "libicu",
             ],
-            generated_headers: [
-                "cxx-bridge-header",
-                "libminikin_cxx_bridge_header",
-            ],
             whole_static_libs: [
                 "libminikin_rust_ffi",
                 "libflags_rust_cpp_bridge",
@@ -160,12 +162,8 @@ cc_library {
                 "libicui18n",
                 "libicuuc",
             ],
-            generated_headers: [
-                "cxx-bridge-header",
-                "libminikin_cxx_bridge_header",
-            ],
         },
-        linux: {
+        not_windows: {
             whole_static_libs: [
                 "libminikin_rust_ffi",
             ],
@@ -176,6 +174,9 @@ cc_library {
                 "-Wno-ignored-attributes",
                 "-Wno-thread-safety",
             ],
+            static_libs: [
+                "libminikin_rust_ffi",
+            ],
         },
     },
 
diff --git a/libs/minikin/FeatureFlags.h b/libs/minikin/FeatureFlags.h
index 36be29e..d88568d 100644
--- a/libs/minikin/FeatureFlags.h
+++ b/libs/minikin/FeatureFlags.h
@@ -38,6 +38,7 @@ namespace features {
 
 DEFINE_FEATURE_FLAG_ACCESSOROR(rust_hyphenator);
 DEFINE_FEATURE_FLAG_ACCESSOROR(typeface_redesign_readonly);
+DEFINE_FEATURE_FLAG_ACCESSOROR(language_specific_extent);
 
 }  // namespace features
 
diff --git a/libs/minikin/Font.cpp b/libs/minikin/Font.cpp
index df2f4d2..2f04e32 100644
--- a/libs/minikin/Font.cpp
+++ b/libs/minikin/Font.cpp
@@ -24,6 +24,7 @@
 
 #include "FeatureFlags.h"
 #include "FontUtils.h"
+#include "Locale.h"
 #include "LocaleListCache.h"
 #include "MinikinInternal.h"
 #include "minikin/Constants.h"
@@ -31,6 +32,7 @@
 #include "minikin/HbUtils.h"
 #include "minikin/MinikinFont.h"
 #include "minikin/MinikinFontFactory.h"
+#include "minikin/MinikinPaint.h"
 
 namespace minikin {
 
diff --git a/libs/minikin/FontCollection.cpp b/libs/minikin/FontCollection.cpp
index 41d8948..a084a7e 100644
--- a/libs/minikin/FontCollection.cpp
+++ b/libs/minikin/FontCollection.cpp
@@ -16,6 +16,7 @@
 
 #include "minikin/FontCollection.h"
 
+#include <hb-ot.h>
 #include <log/log.h>
 #include <unicode/unorm2.h>
 
@@ -121,6 +122,51 @@ uint32_t getGlyphScore(U16StringPiece text, uint32_t start, uint32_t end,
     return numGlyphs;
 }
 
+void extentFontMetrics(const HbFontUniquePtr& hbFont, const MinikinFont& font,
+                       const MinikinPaint& paint, const FontFakery& fakery, MinikinExtent* out) {
+    MinikinExtent tmp = {};
+    font.GetFontExtent(&tmp, paint, fakery);
+    out->extendBy(tmp);
+
+    if (!features::language_specific_extent()) {
+        return;
+    }
+
+    const LocaleList& localeList = LocaleListCache::getById(paint.localeListId);
+    if (localeList.empty()) {
+        return;
+    }
+
+    float fontSize = paint.size;
+    float scaleX = paint.scaleX;
+
+    hb_font_set_ppem(hbFont.get(), fontSize * scaleX, fontSize);
+    hb_font_set_scale(hbFont.get(), HBFloatToFixed(fontSize * scaleX), HBFloatToFixed(fontSize));
+
+    // In the extent table, only horizontal/vertical direction needs to be considered.
+    hb_direction_t direction = paint.verticalText ? HB_DIRECTION_TTB : HB_DIRECTION_LTR;
+
+    float ascent = 0;
+    float descent = 0;
+    hb_font_extents_t hbextent = {};
+
+    for (size_t i = 0; i < localeList.size(); ++i) {
+        const Locale& locale = localeList[i];
+        if (!locale.hasLanguage() || !locale.hasScript()) {
+            continue;
+        }
+        hb_language_t language = localeList.getHbLanguage(i);
+        hb_script_t script = locale.getHbScript();
+
+        if (hb_ot_layout_get_font_extents2(hbFont.get(), direction, script, language, &hbextent)) {
+            ascent = std::min(-HBFixedToFloat(hbextent.ascender), ascent);
+            descent = std::max(-HBFixedToFloat(hbextent.descender), descent);
+        }
+    }
+
+    out->extendBy(ascent, descent);
+}
+
 }  // namespace
 
 // static
@@ -647,6 +693,9 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
         return e;
     }
 
+    float fontSize = paint.size;
+    float scaleX = paint.scaleX;
+
     MinikinExtent result(0, 0);
     // Reserve the custom font's extent.
     for (uint8_t i = 0; i < mFamilyCount; ++i) {
@@ -656,11 +705,9 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
         }
 
         // Use this family
-        MinikinExtent extent(0, 0);
         FakedFont font =
                 getFamilyAt(i)->getClosestMatch(paint.fontStyle, paint.fontVariationSettings);
-        font.typeface()->GetFontExtent(&extent, paint, font.fakery);
-        result.extendBy(extent);
+        extentFontMetrics(font.hbFont(), *font.typeface(), paint, font.fakery, &result);
     }
 
     if (localeId == LocaleListCache::kInvalidListId) {
@@ -684,10 +731,8 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
             return true;  // continue other families
         }
 
-        MinikinExtent extent(0, 0);
         FakedFont font = family.getClosestMatch(paint.fontStyle, paint.fontVariationSettings);
-        font.typeface()->GetFontExtent(&extent, paint, font.fakery);
-        result.extendBy(extent);
+        extentFontMetrics(font.hbFont(), *font.typeface(), paint, font.fakery, &result);
 
         familyFound = true;
         return false;  // We found it, stop searching.
@@ -696,10 +741,8 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
     // If nothing matches, try non-variant match cases since it is used for fallback.
     filterFamilyByLocale(requestedLocaleList, [&](const FontFamily& family) {
         // Use this family
-        MinikinExtent extent(0, 0);
         FakedFont font = family.getClosestMatch(paint.fontStyle, paint.fontVariationSettings);
-        font.typeface()->GetFontExtent(&extent, paint, font.fakery);
-        result.extendBy(extent);
+        extentFontMetrics(font.hbFont(), *font.typeface(), paint, font.fakery, &result);
 
         familyFound = true;
         return false;  // We found it. stop searching.
@@ -709,7 +752,7 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
     if (!familyFound) {
         FakedFont font =
                 getFamilyAt(0)->getClosestMatch(paint.fontStyle, paint.fontVariationSettings);
-        font.typeface()->GetFontExtent(&result, paint, font.fakery);
+        extentFontMetrics(font.hbFont(), *font.typeface(), paint, font.fakery, &result);
     }
 
     mExtentCacheForLocale.put(key, result);
diff --git a/libs/minikin/GreedyLineBreaker.cpp b/libs/minikin/GreedyLineBreaker.cpp
index 8541eea..b85dd46 100644
--- a/libs/minikin/GreedyLineBreaker.cpp
+++ b/libs/minikin/GreedyLineBreaker.cpp
@@ -16,6 +16,7 @@
 
 #include "FeatureFlags.h"
 #include "HyphenatorMap.h"
+#include "LayoutContext.h"
 #include "LineBreakerUtil.h"
 #include "Locale.h"
 #include "LocaleListCache.h"
@@ -204,6 +205,8 @@ bool GreedyLineBreaker::tryLineBreakWithHyphenation(const Range& range, WordBrea
     uint32_t prevOffset = NOWHERE;
     float prevWidth = 0;
 
+    LayoutContext context;
+
     // Look up the hyphenation point from the begining.
     for (uint32_t i = targetRange.getStart(); i < targetRange.getEnd(); ++i) {
         const HyphenationType hyph = hyphenResult[targetRange.toRangeOffset(i)];
@@ -211,9 +214,9 @@ bool GreedyLineBreaker::tryLineBreakWithHyphenation(const Range& range, WordBrea
             continue;  // Not a hyphenation point.
         }
 
-        const float width =
-                targetRun->measureHyphenPiece(mTextBuf, contextRange.split(i).first,
-                                              mStartHyphenEdit, editForThisLine(hyph), nullptr);
+        const float width = targetRun->measureHyphenPiece(mTextBuf, contextRange.split(i).first,
+                                                          mStartHyphenEdit, editForThisLine(hyph),
+                                                          nullptr, &context);
 
         if (width <= mLineWidthLimit) {
             // There are still space, remember current offset and look up next hyphenation point.
@@ -232,7 +235,7 @@ bool GreedyLineBreaker::tryLineBreakWithHyphenation(const Range& range, WordBrea
             const StartHyphenEdit nextLineStartHyphenEdit = editForNextLine(hyph);
             const float remainingCharWidths = targetRun->measureHyphenPiece(
                     mTextBuf, contextRange.split(prevOffset).second, nextLineStartHyphenEdit,
-                    EndHyphenEdit::NO_EDIT, nullptr);
+                    EndHyphenEdit::NO_EDIT, nullptr, &context);
             breakLineAt(prevOffset, prevWidth,
                         remainingCharWidths - (mSumOfCharWidths - mLineWidth), remainingCharWidths,
                         editForThisLine(hyph), nextLineStartHyphenEdit);
@@ -261,7 +264,7 @@ bool GreedyLineBreaker::tryLineBreakWithHyphenation(const Range& range, WordBrea
         const StartHyphenEdit nextLineStartHyphenEdit = editForNextLine(hyph);
         const float remainingCharWidths = targetRun->measureHyphenPiece(
                 mTextBuf, contextRange.split(prevOffset).second, nextLineStartHyphenEdit,
-                EndHyphenEdit::NO_EDIT, nullptr);
+                EndHyphenEdit::NO_EDIT, nullptr, &context);
 
         breakLineAt(prevOffset, prevWidth, remainingCharWidths - (mSumOfCharWidths - mLineWidth),
                     remainingCharWidths, editForThisLine(hyph), nextLineStartHyphenEdit);
diff --git a/libs/minikin/Hyphenator.cpp b/libs/minikin/Hyphenator.cpp
index bea773c..47942ba 100644
--- a/libs/minikin/Hyphenator.cpp
+++ b/libs/minikin/Hyphenator.cpp
@@ -27,10 +27,7 @@
 #include "FeatureFlags.h"
 #include "MinikinInternal.h"
 #include "minikin/Characters.h"
-
-#ifdef __linux__
 #include "minikin_cxx_bridge.rs.h"
-#endif  // __linux__
 
 namespace minikin {
 
@@ -102,7 +99,6 @@ struct Header {
     }
 };
 
-#ifdef __linux__
 class HyphenatorRust : public Hyphenator {
 public:
     HyphenatorRust(const uint8_t* patternData, size_t dataSize, size_t minPrefix, size_t minSuffix,
@@ -120,32 +116,21 @@ public:
 private:
     ::rust::Box<rust::Hyphenator> mHyphenator;
 };
-#endif  // __linux__
 
 // static
 Hyphenator* Hyphenator::loadBinary(const uint8_t* patternData, size_t dataSize, size_t minPrefix,
                                    size_t minSuffix, const std::string& locale) {
-#ifdef __linux__
     if (features::rust_hyphenator()) {
         return new HyphenatorRust(patternData, dataSize, minPrefix, minSuffix, locale);
     }
-#endif  // __linux__
     return HyphenatorCXX::loadBinary(patternData, dataSize, minPrefix, minSuffix, locale);
 }
 
-#ifdef __linux__
 Hyphenator* Hyphenator::loadBinaryForRust(const uint8_t* patternData, size_t dataSize,
                                           size_t minPrefix, size_t minSuffix,
                                           const std::string& locale) {
     return new HyphenatorRust(patternData, dataSize, minPrefix, minSuffix, locale);
 }
-#else   // __linux__
-Hyphenator* Hyphenator::loadBinaryForRust(const uint8_t* /*patternData*/, size_t /*dataSize*/,
-                                          size_t /*minPrefix*/, size_t /*minSuffix*/,
-                                          const std::string& /*locale*/) {
-    MINIKIN_NOT_REACHED("Rust implementation is only available on linux/Android");
-}
-#endif  // __linux__
 
 // static
 Hyphenator* HyphenatorCXX::loadBinary(const uint8_t* patternData, size_t, size_t minPrefix,
diff --git a/libs/minikin/Layout.cpp b/libs/minikin/Layout.cpp
index ca90668..cad8dab 100644
--- a/libs/minikin/Layout.cpp
+++ b/libs/minikin/Layout.cpp
@@ -31,6 +31,7 @@
 
 #include "BidiUtils.h"
 #include "FeatureFlags.h"
+#include "LayoutContext.h"
 #include "LayoutSplitter.h"
 #include "LayoutUtils.h"
 #include "LetterSpacingUtils.h"
@@ -212,10 +213,11 @@ void Layout::doLayout(const U16StringPiece& textBuf, const Range& range, Bidi bi
     const uint32_t count = range.getLength();
     mAdvances.resize(count, 0);
     mGlyphs.reserve(count);
+    LayoutContext layoutContext;
     const BidiText bidiText(textBuf, range, bidiFlags);
     for (const BidiText::RunInfo& runInfo : bidiText) {
         doLayoutRunCached(textBuf, runInfo.range, runInfo.isRtl, paint, range.getStart(),
-                          startHyphen, endHyphen, this, nullptr, nullptr, nullptr);
+                          startHyphen, endHyphen, this, nullptr, nullptr, nullptr, &layoutContext);
     }
     U16StringPiece substr = textBuf.substr(range);
     adjustGlyphLetterSpacingEdge(substr, paint, runFlag, &mGlyphs);
@@ -241,13 +243,14 @@ float Layout::measureText(const U16StringPiece& textBuf, const Range& range, Bid
 
     MinikinRect tmpBounds;
     const BidiText bidiText(textBuf, range, bidiFlags);
+    LayoutContext layoutContext;
     for (const BidiText::RunInfo& runInfo : bidiText) {
         const size_t offset = range.toRangeOffset(runInfo.range.getStart());
         float* advancesForRun = advances ? advances + offset : nullptr;
         tmpBounds.setEmpty();
-        float run_advance = doLayoutRunCached(textBuf, runInfo.range, runInfo.isRtl, paint, 0,
-                                              startHyphen, endHyphen, nullptr, advancesForRun,
-                                              bounds ? &tmpBounds : nullptr, clusterCount);
+        float run_advance = doLayoutRunCached(
+                textBuf, runInfo.range, runInfo.isRtl, paint, 0, startHyphen, endHyphen, nullptr,
+                advancesForRun, bounds ? &tmpBounds : nullptr, clusterCount, &layoutContext);
         if (bounds) {
             if (paint.verticalText) {
                 bounds->join(tmpBounds, 0, advance);
@@ -266,7 +269,7 @@ float Layout::doLayoutRunCached(const U16StringPiece& textBuf, const Range& rang
                                 const MinikinPaint& paint, size_t dstStart,
                                 StartHyphenEdit startHyphen, EndHyphenEdit endHyphen,
                                 Layout* layout, float* advances, MinikinRect* bounds,
-                                uint32_t* clusterCount) {
+                                uint32_t* clusterCount, LayoutContext* layoutContext) {
     if (!range.isValid()) {
         return 0.0f;  // ICU failed to retrieve the bidi run?
     }
@@ -285,7 +288,7 @@ float Layout::doLayoutRunCached(const U16StringPiece& textBuf, const Range& rang
                 textBuf.data() + context.getStart(), piece.getStart() - context.getStart(),
                 piece.getLength(), context.getLength(), isRtl, paint, piece.getStart() - dstStart,
                 pieceStartHyphen, pieceEndHyphen, layout, advancesForRun,
-                bounds ? &tmpBounds : nullptr, clusterCount);
+                bounds ? &tmpBounds : nullptr, clusterCount, layoutContext);
         if (bounds) {
             if (paint.verticalText) {
                 bounds->join(tmpBounds, 0, advance);
@@ -343,7 +346,8 @@ private:
 float Layout::doLayoutWord(const uint16_t* buf, size_t start, size_t count, size_t bufSize,
                            bool isRtl, const MinikinPaint& paint, size_t bufStart,
                            StartHyphenEdit startHyphen, EndHyphenEdit endHyphen, Layout* layout,
-                           float* advances, MinikinRect* bounds, uint32_t* clusterCount) {
+                           float* advances, MinikinRect* bounds, uint32_t* clusterCount,
+                           LayoutContext* layoutContext) {
     float wordSpacing = count == 1 && isWordSpace(buf[start]) ? paint.wordSpacing : 0;
     float totalAdvance = 0;
     const bool boundsCalculation = bounds != nullptr;
@@ -352,7 +356,7 @@ float Layout::doLayoutWord(const uint16_t* buf, size_t start, size_t count, size
     const Range range(start, start + count);
     LayoutAppendFunctor f(layout, advances, bufStart, wordSpacing, bounds);
     LayoutCache::getInstance().getOrCreate(textBuf, range, paint, isRtl, startHyphen, endHyphen,
-                                           boundsCalculation, f);
+                                           boundsCalculation, layoutContext, f);
     totalAdvance = f.getTotalAdvance();
     if (clusterCount) {
         *clusterCount += f.getClusterCount();
diff --git a/libs/minikin/LayoutContext.h b/libs/minikin/LayoutContext.h
new file mode 100644
index 0000000..4332324
--- /dev/null
+++ b/libs/minikin/LayoutContext.h
@@ -0,0 +1,44 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef MINIKIN_LAYOUT_CONTEXT_H
+#define MINIKIN_LAYOUT_CONTEXT_H
+
+#include <hb.h>
+#include <minikin/MinikinExtent.h>
+
+#include <map>
+
+namespace minikin {
+
+class MinikinFont;
+
+using ScriptExtentCache = std::map<hb_script_t, MinikinExtent>;
+
+// A class that holds the context of the text layout calculation.
+// The meaning context here is the same Paint parameters. So, the same context should not be used
+// for the different text size, typeface, etc.
+struct LayoutContext {
+    // A cache of the script specific extent for the given font.
+    std::map<MinikinFont*, ScriptExtentCache> scriptExtentCache;
+
+    // A cache of the extent for the given font.
+    std::map<MinikinFont*, MinikinExtent> extentCache;
+};
+
+}  // namespace minikin
+
+#endif  // MINIKIN_LAYOUT_CONTEXT_H
diff --git a/libs/minikin/LayoutCore.cpp b/libs/minikin/LayoutCore.cpp
index c4c231b..da2767e 100644
--- a/libs/minikin/LayoutCore.cpp
+++ b/libs/minikin/LayoutCore.cpp
@@ -34,6 +34,8 @@
 #include <vector>
 
 #include "BidiUtils.h"
+#include "FeatureFlags.h"
+#include "LayoutContext.h"
 #include "LayoutUtils.h"
 #include "LetterSpacingUtils.h"
 #include "LocaleListCache.h"
@@ -272,11 +274,37 @@ static inline uint32_t addToHbBuffer(const HbBufferUniquePtr& buffer, const uint
     return cpInfo[0].cluster;
 }
 
+void extentByBASETable(const HbFontUniquePtr& hbFont, const MinikinPaint& paint, hb_script_t script,
+                       hb_direction_t direction, MinikinExtent* out) {
+    const LocaleList& localeList = LocaleListCache::getById(paint.localeListId);
+    if (localeList.empty()) {
+        return;
+    }
+
+    float ascent = 0;
+    float descent = 0;
+    hb_font_extents_t hbextent = {};
+
+    for (size_t i = 0; i < localeList.size(); ++i) {
+        const Locale& locale = localeList[i];
+        if (!locale.hasLanguage() || !locale.hasScript()) {
+            continue;
+        }
+        hb_language_t language = localeList.getHbLanguage(i);
+
+        if (hb_ot_layout_get_font_extents2(hbFont.get(), direction, script, language, &hbextent)) {
+            ascent = std::min(-HBFixedToFloat(hbextent.ascender), ascent);
+            descent = std::max(-HBFixedToFloat(hbextent.descender), descent);
+        }
+    }
+    out->extendBy(ascent, descent);
+}
+
 }  // namespace
 
 LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool isRtl,
                          const MinikinPaint& paint, StartHyphenEdit startHyphen,
-                         EndHyphenEdit endHyphen) {
+                         EndHyphenEdit endHyphen, LayoutContext* ctx) {
     const uint16_t* buf = textBuf.data();
     const size_t start = range.getStart();
     const size_t count = range.getLength();
@@ -347,10 +375,23 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
             }
         }
         if (needExtent) {
-            MinikinExtent verticalExtent;
-            typeface->GetFontExtent(&verticalExtent, paint, fakedFont.fakery);
-            mExtent.extendBy(verticalExtent);
+            if (features::language_specific_extent()) {
+                auto it = ctx->extentCache.find(typeface.get());
+                if (it != ctx->extentCache.end()) {
+                    mExtent.extendBy(it->second);
+                } else {
+                    MinikinExtent verticalExtent;
+                    typeface->GetFontExtent(&verticalExtent, paint, fakedFont.fakery);
+                    mExtent.extendBy(verticalExtent);
+                    ctx->extentCache[typeface.get()] = verticalExtent;
+                }
+            } else {
+                MinikinExtent verticalExtent;
+                typeface->GetFontExtent(&verticalExtent, paint, fakedFont.fakery);
+                mExtent.extendBy(verticalExtent);
+            }
         }
+        ScriptExtentCache& scriptExtentCache = ctx->scriptExtentCache[typeface.get()];
 
         hb_font_set_ppem(hbFont.get(), size * scaleX, size);
         hb_font_set_scale(hbFont.get(), HBFloatToFixed(size * scaleX), HBFloatToFixed(size));
@@ -382,11 +423,14 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
 
             hb_buffer_clear_contents(buffer.get());
             hb_buffer_set_script(buffer.get(), script);
+            hb_direction_t direction;
             if (paint.verticalText) {
-                hb_buffer_set_direction(buffer.get(), HB_DIRECTION_TTB);
+                direction = HB_DIRECTION_TTB;
             } else {
-                hb_buffer_set_direction(buffer.get(), isRtl ? HB_DIRECTION_RTL : HB_DIRECTION_LTR);
+                direction = isRtl ? HB_DIRECTION_RTL : HB_DIRECTION_LTR;
             }
+            hb_buffer_set_direction(buffer.get(), direction);
+
             const LocaleList& localeList = LocaleListCache::getById(paint.localeListId);
             if (localeList.size() != 0) {
                 hb_language_t hbLanguage = localeList.getHbLanguage(0);
@@ -399,6 +443,19 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
                 hb_buffer_set_language(buffer.get(), hbLanguage);
             }
 
+            if (features::language_specific_extent() && needExtent && localeList.size() != 0) {
+                auto it = scriptExtentCache.find(script);
+
+                if (it == scriptExtentCache.end()) {
+                    MinikinExtent extent = {};
+                    extentByBASETable(hbFont, paint, script, direction, &extent);
+                    mExtent.extendBy(extent);
+                    scriptExtentCache[script] = extent;
+                } else {
+                    mExtent.extendBy(it->second);
+                }
+            }
+
             const uint32_t clusterStart =
                     addToHbBuffer(buffer, buf, start, count, bufSize, scriptRunStart, scriptRunEnd,
                                   startHyphen, endHyphen, hbFont);
diff --git a/libs/minikin/LineBreakerUtil.h b/libs/minikin/LineBreakerUtil.h
index 5c0a0eb..5ea1cd5 100644
--- a/libs/minikin/LineBreakerUtil.h
+++ b/libs/minikin/LineBreakerUtil.h
@@ -81,7 +81,8 @@ inline void populateHyphenationPoints(
         const std::vector<float>& charWidths,  // Char width used for hyphen piece estimation.
         bool ignoreKerning,                    // True use full shaping for hyphenation piece.
         std::vector<HyphenBreak>* out,         // An output to be appended.
-        LayoutPieces* pieces) {                // An output of layout pieces. Maybe null.
+        LayoutContext* ctx,
+        LayoutPieces* pieces) {  // An output of layout pieces. Maybe null.
     if (!run.getRange().contains(contextRange) || !contextRange.contains(hyphenationTargetRange)) {
         return;
     }
@@ -98,14 +99,14 @@ inline void populateHyphenationPoints(
             auto hyphenPart = contextRange.split(i);
             U16StringPiece firstText = textBuf.substr(hyphenPart.first);
             U16StringPiece secondText = textBuf.substr(hyphenPart.second);
-            const float first =
-                    run.measureHyphenPiece(firstText, Range(0, firstText.size()),
-                                           StartHyphenEdit::NO_EDIT /* start hyphen edit */,
-                                           editForThisLine(hyph) /* end hyphen edit */, pieces);
-            const float second =
-                    run.measureHyphenPiece(secondText, Range(0, secondText.size()),
-                                           editForNextLine(hyph) /* start hyphen edit */,
-                                           EndHyphenEdit::NO_EDIT /* end hyphen edit */, pieces);
+            const float first = run.measureHyphenPiece(
+                    firstText, Range(0, firstText.size()),
+                    StartHyphenEdit::NO_EDIT /* start hyphen edit */,
+                    editForThisLine(hyph) /* end hyphen edit */, pieces, ctx);
+            const float second = run.measureHyphenPiece(
+                    secondText, Range(0, secondText.size()),
+                    editForNextLine(hyph) /* start hyphen edit */,
+                    EndHyphenEdit::NO_EDIT /* end hyphen edit */, pieces, ctx);
 
             out->emplace_back(i, hyph, first, second);
         } else {
diff --git a/libs/minikin/Locale.cpp b/libs/minikin/Locale.cpp
index f7e7323..d9c55af 100644
--- a/libs/minikin/Locale.cpp
+++ b/libs/minikin/Locale.cpp
@@ -511,6 +511,10 @@ int Locale::calcScoreFor(const LocaleList& supported) const {
     return 0;
 }
 
+hb_script_t Locale::getHbScript() const {
+    return hb_script_from_iso15924_tag(unpackScript(mScript));
+}
+
 static hb_language_t buildHbLanguage(const Locale& locale) {
     return locale.isSupported() ? hb_language_from_string(locale.getString().c_str(), -1)
                                 : HB_LANGUAGE_INVALID;
diff --git a/libs/minikin/Locale.h b/libs/minikin/Locale.h
index a19daa9..7f87533 100644
--- a/libs/minikin/Locale.h
+++ b/libs/minikin/Locale.h
@@ -125,6 +125,8 @@ public:
     bool supportsScript(uint32_t script) const;
     bool supportsScript(char c1, char c2, char c3, char c4) const;
 
+    hb_script_t getHbScript() const;
+
     std::string getString() const;
 
     std::string getStringWithLineBreakOption(LineBreakStyle lbStyle,
diff --git a/libs/minikin/MeasuredText.cpp b/libs/minikin/MeasuredText.cpp
index cd32bd0..b40d26e 100644
--- a/libs/minikin/MeasuredText.cpp
+++ b/libs/minikin/MeasuredText.cpp
@@ -17,6 +17,7 @@
 #include "minikin/MeasuredText.h"
 
 #include "BidiUtils.h"
+#include "LayoutContext.h"
 #include "LayoutSplitter.h"
 #include "LayoutUtils.h"
 #include "LineBreakerUtil.h"
@@ -68,18 +69,19 @@ void StyleRun::getMetrics(const U16StringPiece& textBuf, std::vector<float>* adv
     const Bidi bidiFlag = mIsRtl ? Bidi::FORCE_RTL : Bidi::FORCE_LTR;
     const uint32_t paintId =
             (precomputed == nullptr) ? LayoutPieces::kNoPaintId : precomputed->findPaintId(mPaint);
+    LayoutContext ctx;
     for (const BidiText::RunInfo info : BidiText(textBuf, mRange, bidiFlag)) {
         for (const auto[context, piece] : LayoutSplitter(textBuf, info.range, info.isRtl)) {
             compositor.setNextRange(piece, info.isRtl);
             if (paintId == LayoutPieces::kNoPaintId) {
                 LayoutCache::getInstance().getOrCreate(
                         textBuf.substr(context), piece - context.getStart(), mPaint, info.isRtl,
-                        StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, boundsCalculation,
+                        StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, boundsCalculation, &ctx,
                         compositor);
             } else {
                 precomputed->getOrCreate(textBuf, piece, context, mPaint, info.isRtl,
                                          StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, paintId,
-                                         boundsCalculation, compositor);
+                                         boundsCalculation, &ctx, compositor);
             }
         }
     }
@@ -106,11 +108,12 @@ float StyleRun::measureText(const U16StringPiece& textBuf) const {
     TotalAdvancesCompositor compositor;
     const Bidi bidiFlag = mIsRtl ? Bidi::FORCE_RTL : Bidi::FORCE_LTR;
     LayoutCache& layoutCache = LayoutCache::getInstance();
+    LayoutContext ctx;
     for (const BidiText::RunInfo info : BidiText(textBuf, Range(0, textBuf.length()), bidiFlag)) {
         for (const auto [context, piece] : LayoutSplitter(textBuf, info.range, info.isRtl)) {
             layoutCache.getOrCreate(textBuf.substr(context), piece - context.getStart(), mPaint,
                                     info.isRtl, StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT,
-                                    false /* bounds calculation */, compositor);
+                                    false /* bounds calculation */, &ctx, compositor);
         }
     }
     return compositor.getTotalAdvance();
@@ -147,7 +150,7 @@ private:
 
 float StyleRun::measureHyphenPiece(const U16StringPiece& textBuf, const Range& range,
                                    StartHyphenEdit startHyphen, EndHyphenEdit endHyphen,
-                                   LayoutPieces* pieces) const {
+                                   LayoutPieces* pieces, LayoutContext* ctx) const {
     TotalAdvanceCompositor compositor(pieces);
     const Bidi bidiFlag = mIsRtl ? Bidi::FORCE_RTL : Bidi::FORCE_LTR;
     for (const BidiText::RunInfo info : BidiText(textBuf, range, bidiFlag)) {
@@ -160,7 +163,7 @@ float StyleRun::measureHyphenPiece(const U16StringPiece& textBuf, const Range& r
             compositor.setNextContext(piece, packHyphenEdit(startEdit, endEdit), info.isRtl);
             LayoutCache::getInstance().getOrCreate(
                     textBuf.substr(context), piece - context.getStart(), mPaint, info.isRtl,
-                    startEdit, endEdit, false /* bounds calculation */, compositor);
+                    startEdit, endEdit, false /* bounds calculation */, ctx, compositor);
         }
     }
     return compositor.advance();
@@ -185,6 +188,7 @@ void MeasuredText::measure(const U16StringPiece& textBuf, bool computeHyphenatio
         }
 
         proc.updateLocaleIfNecessary(*run, false /* forceWordStyleAutoToPhrase */);
+        LayoutContext ctx;
         for (uint32_t i = range.getStart(); i < range.getEnd(); ++i) {
             // Even if the run is not a candidate of line break, treat the end of run as the line
             // break candidate.
@@ -198,7 +202,7 @@ void MeasuredText::measure(const U16StringPiece& textBuf, bool computeHyphenatio
 
             populateHyphenationPoints(textBuf, *run, *proc.hyphenator, proc.contextRange(),
                                       proc.wordRange(), widths, ignoreHyphenKerning, &hyphenBreaks,
-                                      piecesOut);
+                                      &ctx, piecesOut);
         }
     }
 }
@@ -235,6 +239,7 @@ void StyleRun::appendLayout(const U16StringPiece& textBuf, const Range& range,
     LayoutCompositor compositor(outLayout, wordSpacing);
     const Bidi bidiFlag = mIsRtl ? Bidi::FORCE_RTL : Bidi::FORCE_LTR;
     const uint32_t paintId = pieces.findPaintId(mPaint);
+    LayoutContext ctx;
     for (const BidiText::RunInfo info : BidiText(textBuf, range, bidiFlag)) {
         for (const auto[context, piece] : LayoutSplitter(textBuf, info.range, info.isRtl)) {
             compositor.setOutOffset(piece.getStart() - outOrigin);
@@ -245,11 +250,11 @@ void StyleRun::appendLayout(const U16StringPiece& textBuf, const Range& range,
 
             if (canUsePrecomputedResult) {
                 pieces.getOrCreate(textBuf, piece, context, mPaint, info.isRtl, startEdit, endEdit,
-                                   paintId, boundsCalculation, compositor);
+                                   paintId, boundsCalculation, &ctx, compositor);
             } else {
                 LayoutCache::getInstance().getOrCreate(
                         textBuf.substr(context), piece - context.getStart(), paint, info.isRtl,
-                        startEdit, endEdit, boundsCalculation, compositor);
+                        startEdit, endEdit, boundsCalculation, &ctx, compositor);
             }
         }
     }
@@ -283,11 +288,12 @@ std::pair<float, MinikinRect> StyleRun::getBounds(const U16StringPiece& textBuf,
     BoundsCompositor compositor;
     const Bidi bidiFlag = mIsRtl ? Bidi::FORCE_RTL : Bidi::FORCE_LTR;
     const uint32_t paintId = pieces.findPaintId(mPaint);
+    LayoutContext ctx;
     for (const BidiText::RunInfo info : BidiText(textBuf, range, bidiFlag)) {
         for (const auto[context, piece] : LayoutSplitter(textBuf, info.range, info.isRtl)) {
             pieces.getOrCreate(textBuf, piece, context, mPaint, info.isRtl,
                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, paintId,
-                               true /* bounds calculation */, compositor);
+                               true /* bounds calculation */, &ctx, compositor);
         }
     }
     return std::make_pair(compositor.advance(), compositor.bounds());
@@ -314,11 +320,12 @@ MinikinExtent StyleRun::getExtent(const U16StringPiece& textBuf, const Range& ra
     ExtentCompositor compositor;
     Bidi bidiFlag = mIsRtl ? Bidi::FORCE_RTL : Bidi::FORCE_LTR;
     const uint32_t paintId = pieces.findPaintId(mPaint);
+    LayoutContext ctx;
     for (const BidiText::RunInfo info : BidiText(textBuf, range, bidiFlag)) {
         for (const auto[context, piece] : LayoutSplitter(textBuf, info.range, info.isRtl)) {
             pieces.getOrCreate(textBuf, piece, context, mPaint, info.isRtl,
                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, paintId,
-                               false /* bounds calculation */, compositor);
+                               false /* bounds calculation */, &ctx, compositor);
         }
     }
     return compositor.extent();
@@ -344,11 +351,12 @@ LineMetrics StyleRun::getLineMetrics(const U16StringPiece& textBuf, const Range&
     LineMetricsCompositor compositor;
     Bidi bidiFlag = mIsRtl ? Bidi::FORCE_RTL : Bidi::FORCE_LTR;
     const uint32_t paintId = pieces.findPaintId(mPaint);
+    LayoutContext ctx;
     for (const BidiText::RunInfo info : BidiText(textBuf, range, bidiFlag)) {
         for (const auto [context, piece] : LayoutSplitter(textBuf, info.range, info.isRtl)) {
             pieces.getOrCreate(textBuf, piece, context, mPaint, info.isRtl,
                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, paintId,
-                               true /* bounds calculation */, compositor);
+                               true /* bounds calculation */, &ctx, compositor);
         }
     }
     return compositor.metrics();
diff --git a/libs/minikin/Measurement.cpp b/libs/minikin/Measurement.cpp
index 724cde0..32bfc45 100644
--- a/libs/minikin/Measurement.cpp
+++ b/libs/minikin/Measurement.cpp
@@ -20,6 +20,7 @@
 #include <cmath>
 
 #include "BidiUtils.h"
+#include "LayoutContext.h"
 #include "LayoutSplitter.h"
 #include "minikin/GraphemeBreak.h"
 #include "minikin/LayoutCache.h"
@@ -213,6 +214,7 @@ void getBounds(const U16StringPiece& str, const Range& range, Bidi bidiFlag,
                const MinikinPaint& paint, StartHyphenEdit startHyphen, EndHyphenEdit endHyphen,
                MinikinRect* out) {
     BoundsComposer bc;
+    LayoutContext ctx;
     for (const BidiText::RunInfo info : BidiText(str, range, bidiFlag)) {
         for (const auto [context, piece] : LayoutSplitter(str, info.range, info.isRtl)) {
             const StartHyphenEdit pieceStartHyphen =
@@ -221,7 +223,7 @@ void getBounds(const U16StringPiece& str, const Range& range, Bidi bidiFlag,
                     (piece.getEnd() == range.getEnd()) ? endHyphen : EndHyphenEdit::NO_EDIT;
             LayoutCache::getInstance().getOrCreate(
                     str.substr(context), piece - context.getStart(), paint, info.isRtl,
-                    pieceStartHyphen, pieceEndHyphen, true /* bounds calculation */, bc);
+                    pieceStartHyphen, pieceEndHyphen, true /* bounds calculation */, &ctx, bc);
             // Increment word spacing for spacer
             if (piece.getLength() == 1 && isWordSpace(str[piece.getStart()])) {
                 bc.mAdvance += paint.wordSpacing;
@@ -244,12 +246,13 @@ struct ExtentComposer {
 MinikinExtent getFontExtent(const U16StringPiece& textBuf, const Range& range, Bidi bidiFlag,
                             const MinikinPaint& paint) {
     ExtentComposer composer;
+    LayoutContext ctx;
     for (const BidiText::RunInfo info : BidiText(textBuf, range, bidiFlag)) {
         for (const auto [context, piece] : LayoutSplitter(textBuf, info.range, info.isRtl)) {
             LayoutCache::getInstance().getOrCreate(textBuf.substr(context),
                                                    piece - context.getStart(), paint, info.isRtl,
                                                    StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT,
-                                                   false /* bounds calculation */, composer);
+                                                   false /* bounds calculation */, &ctx, composer);
         }
     }
     return composer.extent;
diff --git a/rust/Android.bp b/rust/Android.bp
index 8c7a99d..0c2639e 100644
--- a/rust/Android.bp
+++ b/rust/Android.bp
@@ -38,6 +38,9 @@ rust_defaults {
                 "libandroid_text_flags_rust",
             ],
         },
+        windows: {
+            enabled: true,
+        },
     },
 }
 
diff --git a/tests/Android.bp b/tests/Android.bp
index f94ce7a..d0616f8 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -7,6 +7,7 @@ filegroup {
     srcs: [
         "data/Arabic.ttf",
         "data/Ascii.ttf",
+        "data/BaseTableFont.ttf",
         "data/Bbox.ttf",
         "data/BiDi.ttf",
         "data/Bold.ttf",
diff --git a/tests/data/BaseTableFont.ttf b/tests/data/BaseTableFont.ttf
new file mode 100644
index 0000000..6740065
Binary files /dev/null and b/tests/data/BaseTableFont.ttf differ
diff --git a/tests/data/BaseTableFont.ttx b/tests/data/BaseTableFont.ttx
new file mode 100644
index 0000000..9665cda
--- /dev/null
+++ b/tests/data/BaseTableFont.ttx
@@ -0,0 +1,223 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<ttFont sfntVersion="\x00\x01\x00\x00" ttLibVersion="3.0">
+
+  <GlyphOrder>
+    <GlyphID id="0" name=".notdef"/>
+    <GlyphID id="1" name="a"/>
+  </GlyphOrder>
+
+  <head>
+    <tableVersion value="1.0"/>
+    <fontRevision value="1.0"/>
+    <checkSumAdjustment value="0x640cdb2f"/>
+    <magicNumber value="0x5f0f3cf5"/>
+    <flags value="00000000 00000011"/>
+    <unitsPerEm value="1000"/>
+    <created value="Thu Mar 27 00:00:00 2025"/>
+    <macStyle value="00000000 00000000"/>
+    <lowestRecPPEM value="7"/>
+    <fontDirectionHint value="2"/>
+    <glyphDataFormat value="0"/>
+  </head>
+
+  <hhea>
+    <tableVersion value="0x0010000"/>
+    <ascent value="800"/>
+    <descent value="-200"/>
+    <lineGap value="0"/>
+    <caretSlopeRise value="1"/>
+    <caretSlopeRun value="0"/>
+    <caretOffset value="0"/>
+    <reserved0 value="0"/>
+    <reserved1 value="0"/>
+    <reserved2 value="0"/>
+    <reserved3 value="0"/>
+    <metricDataFormat value="0"/>
+  </hhea>
+
+  <maxp>
+    <tableVersion value="0x10000"/>
+    <maxZones value="0"/>
+    <maxTwilightPoints value="0"/>
+    <maxStorage value="0"/>
+    <maxFunctionDefs value="0"/>
+    <maxInstructionDefs value="0"/>
+    <maxStackElements value="0"/>
+    <maxSizeOfInstructions value="0"/>
+    <maxComponentElements value="0"/>
+  </maxp>
+
+  <OS_2>
+    <!-- The fields 'usFirstCharIndex' and 'usLastCharIndex'
+         will be recalculated by the compiler -->
+    <version value="3"/>
+    <xAvgCharWidth value="594"/>
+    <usWeightClass value="400"/>
+    <usWidthClass value="5"/>
+    <fsType value="00000000 00001000"/>
+    <ySubscriptXSize value="650"/>
+    <ySubscriptYSize value="600"/>
+    <ySubscriptXOffset value="0"/>
+    <ySubscriptYOffset value="75"/>
+    <ySuperscriptXSize value="650"/>
+    <ySuperscriptYSize value="600"/>
+    <ySuperscriptXOffset value="0"/>
+    <ySuperscriptYOffset value="350"/>
+    <yStrikeoutSize value="50"/>
+    <yStrikeoutPosition value="300"/>
+    <sFamilyClass value="0"/>
+    <panose>
+      <bFamilyType value="0"/>
+      <bSerifStyle value="0"/>
+      <bWeight value="5"/>
+      <bProportion value="0"/>
+      <bContrast value="0"/>
+      <bStrokeVariation value="0"/>
+      <bArmStyle value="0"/>
+      <bLetterForm value="0"/>
+      <bMidline value="0"/>
+      <bXHeight value="0"/>
+    </panose>
+    <ulUnicodeRange1 value="00000000 00000000 00000000 00000001"/>
+    <ulUnicodeRange2 value="00000000 00000000 00000000 00000000"/>
+    <ulUnicodeRange3 value="00000000 00000000 00000000 00000000"/>
+    <ulUnicodeRange4 value="00000000 00000000 00000000 00000000"/>
+    <achVendID value="UKWN"/>
+    <fsSelection value="00000000 01000000"/>
+    <usFirstCharIndex value="32"/>
+    <usLastCharIndex value="122"/>
+    <sTypoAscender value="800"/>
+    <sTypoDescender value="-200"/>
+    <sTypoLineGap value="200"/>
+    <usWinAscent value="1000"/>
+    <usWinDescent value="200"/>
+    <ulCodePageRange1 value="00000000 00000000 00000000 00000001"/>
+    <ulCodePageRange2 value="00000000 00000000 00000000 00000000"/>
+    <sxHeight value="500"/>
+    <sCapHeight value="700"/>
+    <usDefaultChar value="0"/>
+    <usBreakChar value="32"/>
+    <usMaxContext value="0"/>
+  </OS_2>
+
+  <hmtx>
+    <mtx name=".notdef" width="500" lsb="93"/>
+    <mtx name="a" width="500" lsb="93"/>
+  </hmtx>
+
+  <cmap>
+    <tableVersion version="0"/>
+    <cmap_format_4 platformID="3" platEncID="10" language="0">
+      <map code="0x0061" name="a" />
+      <map code="0x0062" name="a" />
+      <map code="0x0063" name="a" />
+    </cmap_format_4>
+  </cmap>
+
+  <loca>
+    <!-- The 'loca' table will be calculated by the compiler -->
+  </loca>
+
+  <glyf>
+    <TTGlyph name=".notdef" xMin="0" yMin="0" xMax="0" yMax="0" />
+    <TTGlyph name="a" xMin="0" yMin="0" xMax="0" yMax="0" />
+  </glyf>
+
+  <name>
+    <namerecord nameID="0" platformID="3" platEncID="1" langID="0x409">
+      Copyright (C) 2017 The Android Open Source Project
+    </namerecord>
+    <namerecord nameID="1" platformID="3" platEncID="1" langID="0x409">
+      Vietnamese TallScript
+    </namerecord>
+    <namerecord nameID="2" platformID="3" platEncID="1" langID="0x409">
+      Regular
+    </namerecord>
+    <namerecord nameID="4" platformID="3" platEncID="1" langID="0x409">
+      Vietnamese TallScript
+    </namerecord>
+    <namerecord nameID="6" platformID="3" platEncID="1" langID="0x409">
+      VietnameseTallScript-Regular
+    </namerecord>
+    <namerecord nameID="13" platformID="3" platEncID="1" langID="0x409">
+      Licensed under the Apache License, Version 2.0 (the "License");
+      you may not use this file except in compliance with the License.
+      Unless required by applicable law or agreed to in writing, software
+      distributed under the License is distributed on an "AS IS" BASIS
+      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+      See the License for the specific language governing permissions and
+      limitations under the License.
+    </namerecord>
+    <namerecord nameID="14" platformID="3" platEncID="1" langID="0x409">
+      http://www.apache.org/licenses/LICENSE-2.0
+    </namerecord>
+  </name>
+
+  <BASE>
+    <Version value="0x00010000"/>
+    <HorizAxis>
+      <BaseScriptList>
+        <!-- BaseScriptCount=2 -->
+        <BaseScriptRecord index="0">
+          <BaseScriptTag value="DFLT"/>
+          <BaseScript>
+            <BaseValues>
+              <DefaultIndex value="0"/>
+              <!-- BaseCoordCount=0 -->
+            </BaseValues>
+            <!-- BaseLangSysCount=0 -->
+          </BaseScript>
+        </BaseScriptRecord>
+        <BaseScriptRecord index="1">
+          <BaseScriptTag value="latn"/>
+          <BaseScript>
+            <BaseValues>
+              <DefaultIndex value="0"/>
+              <!-- BaseCoordCount=0 -->
+            </BaseValues>
+            <!-- BaseLangSysCount=1 -->
+            <BaseLangSysRecord index="0">
+              <BaseLangSysTag value="VIT "/>
+              <MinMax>
+                <MinCoord Format="1">
+                  <Coordinate value="-400"/>
+                </MinCoord>
+                <MaxCoord Format="1">
+                  <Coordinate value="1000"/>
+                </MaxCoord>
+                <!-- FeatMinMaxCount=0 -->
+              </MinMax>
+            </BaseLangSysRecord>
+          </BaseScript>
+        </BaseScriptRecord>
+      </BaseScriptList>
+    </HorizAxis>
+  </BASE>
+
+  <post>
+    <formatType value="3.0"/>
+    <italicAngle value="0.0"/>
+    <underlinePosition value="-75"/>
+    <underlineThickness value="50"/>
+    <isFixedPitch value="0"/>
+    <minMemType42 value="0"/>
+    <maxMemType42 value="0"/>
+    <minMemType1 value="0"/>
+    <maxMemType1 value="0"/>
+  </post>
+
+</ttFont>
diff --git a/tests/unittest/FontCollectionTest.cpp b/tests/unittest/FontCollectionTest.cpp
index 8790a90..663acfa 100644
--- a/tests/unittest/FontCollectionTest.cpp
+++ b/tests/unittest/FontCollectionTest.cpp
@@ -24,6 +24,7 @@
 #include "MinikinInternal.h"
 #include "minikin/Constants.h"
 #include "minikin/FontCollection.h"
+#include "minikin/MinikinPaint.h"
 
 namespace minikin {
 
@@ -375,4 +376,33 @@ TEST_WITH_FLAGS(FontCollectionTest, getBestFont,
                       .fakery.variationSettings());
 }
 
+TEST_WITH_FLAGS(FontCollectionTest, getReferenceExtentForLocale_withBASETable,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
+                                                    language_specific_extent))) {
+    auto minikinFont =
+            std::make_shared<FreeTypeMinikinFontForTest>(getTestFontPath("BaseTableFont.ttf"));
+    auto font = Font::Builder(minikinFont).build();
+    auto family = FontFamily::create({font});
+    auto fc = FontCollection::create({family});
+
+    MinikinPaint paint(fc);
+    paint.size = 100;  // make 1em = 100px
+
+    // Vertical metrics from hhea table for Latin script
+    {
+        paint.localeListId = registerLocaleList("en-US");
+        auto extent = fc->getReferenceExtentForLocale(paint);
+        EXPECT_EQ(-80, extent.ascent);
+        EXPECT_EQ(20, extent.descent);
+    }
+
+    // Vertical metrics from BASE table for Vietnamese script
+    {
+        paint.localeListId = registerLocaleList("vi-VI");
+        auto extent = fc->getReferenceExtentForLocale(paint);
+        EXPECT_EQ(-100, extent.ascent);
+        EXPECT_EQ(40, extent.descent);
+    }
+}
+
 }  // namespace minikin
diff --git a/tests/unittest/LayoutCacheTest.cpp b/tests/unittest/LayoutCacheTest.cpp
index 5d20456..5698d0b 100644
--- a/tests/unittest/LayoutCacheTest.cpp
+++ b/tests/unittest/LayoutCacheTest.cpp
@@ -14,15 +14,14 @@
  * limitations under the License.
  */
 
-#include "minikin/Layout.h"
-
 #include <gtest/gtest.h>
 
-#include "minikin/LayoutCache.h"
-
 #include "FontTestUtils.h"
+#include "LayoutContext.h"
 #include "LocaleListCache.h"
 #include "UnicodeUtils.h"
+#include "minikin/Layout.h"
+#include "minikin/LayoutCache.h"
 
 namespace minikin {
 
@@ -51,6 +50,7 @@ private:
 };
 
 TEST(LayoutCacheTest, cacheHitTest) {
+    LayoutContext ctx;
     auto text = utf8ToUtf16("android");
     Range range(0, text.size());
     MinikinPaint paint(buildFontCollection("Ascii.ttf"));
@@ -59,11 +59,11 @@ TEST(LayoutCacheTest, cacheHitTest) {
 
     LayoutCapture layout1;
     layoutCache.getOrCreate(text, range, paint, false /* LTR */, StartHyphenEdit::NO_EDIT,
-                            EndHyphenEdit::NO_EDIT, false, layout1);
+                            EndHyphenEdit::NO_EDIT, false, &ctx, layout1);
 
     LayoutCapture layout2;
     layoutCache.getOrCreate(text, range, paint, false /* LTR */, StartHyphenEdit::NO_EDIT,
-                            EndHyphenEdit::NO_EDIT, false, layout2);
+                            EndHyphenEdit::NO_EDIT, false, &ctx, layout2);
 
     EXPECT_EQ(layout1.get(), layout2.get());
 }
@@ -75,56 +75,67 @@ TEST(LayoutCacheTest, cacheMissTest) {
 
     TestableLayoutCache layoutCache(10);
 
+    LayoutContext ctx;
     LayoutCapture layout1;
     LayoutCapture layout2;
 
     {
         SCOPED_TRACE("Different text");
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         layoutCache.getOrCreate(text2, Range(0, text2.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
         SCOPED_TRACE("Different range");
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         layoutCache.getOrCreate(text1, Range(1, text1.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
         SCOPED_TRACE("Different text");
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         layoutCache.getOrCreate(text2, Range(0, text2.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
         SCOPED_TRACE("Different direction");
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, true /* RTL */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
         SCOPED_TRACE("Different start hyphenation");
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
-                                StartHyphenEdit::INSERT_HYPHEN, EndHyphenEdit::NO_EDIT, false,
+                                StartHyphenEdit::INSERT_HYPHEN, EndHyphenEdit::NO_EDIT, false, &ctx,
                                 layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
         SCOPED_TRACE("Different end hyphen");
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::INSERT_HYPHEN, false,
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::INSERT_HYPHEN, false, &ctx,
                                 layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
@@ -132,10 +143,12 @@ TEST(LayoutCacheTest, cacheMissTest) {
         SCOPED_TRACE("Different collection");
         MinikinPaint paint1(buildFontCollection("Ascii.ttf"));
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint1, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         MinikinPaint paint2(buildFontCollection("Emoji.ttf"));
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint2, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
@@ -144,11 +157,13 @@ TEST(LayoutCacheTest, cacheMissTest) {
         MinikinPaint paint1(collection);
         paint1.size = 10.0f;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint1, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         MinikinPaint paint2(collection);
         paint2.size = 20.0f;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint2, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
@@ -157,11 +172,13 @@ TEST(LayoutCacheTest, cacheMissTest) {
         MinikinPaint paint1(collection);
         paint1.scaleX = 1.0f;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint1, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         MinikinPaint paint2(collection);
         paint2.scaleX = 2.0f;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint2, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
@@ -170,11 +187,13 @@ TEST(LayoutCacheTest, cacheMissTest) {
         MinikinPaint paint1(collection);
         paint1.skewX = 1.0f;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint1, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         MinikinPaint paint2(collection);
         paint2.skewX = 2.0f;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint2, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
@@ -183,11 +202,13 @@ TEST(LayoutCacheTest, cacheMissTest) {
         MinikinPaint paint1(collection);
         paint1.letterSpacing = 0.0f;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint1, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         MinikinPaint paint2(collection);
         paint2.letterSpacing = 1.0f;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint2, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
@@ -196,11 +217,13 @@ TEST(LayoutCacheTest, cacheMissTest) {
         MinikinPaint paint1(collection);
         paint1.wordSpacing = 0.0f;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint1, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         MinikinPaint paint2(collection);
         paint2.wordSpacing = 1.0f;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint2, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
@@ -209,11 +232,13 @@ TEST(LayoutCacheTest, cacheMissTest) {
         MinikinPaint paint1(collection);
         paint1.fontFlags = 0;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint1, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         MinikinPaint paint2(collection);
         paint2.fontFlags = LinearMetrics_Flag;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint2, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
@@ -222,11 +247,13 @@ TEST(LayoutCacheTest, cacheMissTest) {
         MinikinPaint paint1(collection);
         paint1.localeListId = LocaleListCache::getId("en-US");
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint1, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         MinikinPaint paint2(collection);
         paint2.localeListId = LocaleListCache::getId("ja-JP");
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint2, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
@@ -235,11 +262,13 @@ TEST(LayoutCacheTest, cacheMissTest) {
         MinikinPaint paint1(collection);
         paint1.familyVariant = FamilyVariant::DEFAULT;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint1, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         MinikinPaint paint2(collection);
         paint2.familyVariant = FamilyVariant::COMPACT;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint2, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
     {
@@ -248,16 +277,19 @@ TEST(LayoutCacheTest, cacheMissTest) {
         MinikinPaint paint1(collection);
         paint1.fontFeatureSettings = FontFeature::parse("");
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint1, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout1);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout1);
         MinikinPaint paint2(collection);
         paint2.fontFeatureSettings = FontFeature::parse("'liga' on");
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint2, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
         EXPECT_NE(layout1.get(), layout2.get());
     }
 }
 
 TEST(LayoutCacheTest, cacheOverflowTest) {
+    LayoutContext ctx;
     auto text = utf8ToUtf16("android");
     Range range(0, text.size());
     MinikinPaint paint(buildFontCollection("Ascii.ttf"));
@@ -266,22 +298,24 @@ TEST(LayoutCacheTest, cacheOverflowTest) {
 
     LayoutCapture layout1;
     layoutCache.getOrCreate(text, range, paint, false /* LTR */, StartHyphenEdit::NO_EDIT,
-                            EndHyphenEdit::NO_EDIT, false, layout1);
+                            EndHyphenEdit::NO_EDIT, false, &ctx, layout1);
 
     for (char c = 'a'; c <= 'z'; c++) {
         auto text1 = utf8ToUtf16(std::string(10, c));
         LayoutCapture layout2;
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
-                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, layout2);
+                                StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, false, &ctx,
+                                layout2);
     }
 
     LayoutCapture layout3;
     layoutCache.getOrCreate(text, range, paint, false /* LTR */, StartHyphenEdit::NO_EDIT,
-                            EndHyphenEdit::NO_EDIT, false, layout3);
+                            EndHyphenEdit::NO_EDIT, false, &ctx, layout3);
     EXPECT_NE(layout1.get(), layout3.get());
 }
 
 TEST(LayoutCacheTest, cacheLengthLimitTest) {
+    LayoutContext ctx;
     auto text = utf8ToUtf16(std::string(130, 'a'));
     Range range(0, text.size());
     MinikinPaint paint(buildFontCollection("Ascii.ttf"));
@@ -290,7 +324,7 @@ TEST(LayoutCacheTest, cacheLengthLimitTest) {
 
     LayoutCapture layout;
     layoutCache.getOrCreate(text, range, paint, false /* LTR */, StartHyphenEdit::NO_EDIT,
-                            EndHyphenEdit::NO_EDIT, false, layout);
+                            EndHyphenEdit::NO_EDIT, false, &ctx, layout);
 
     EXPECT_EQ(layoutCache.getCacheSize(), 0u);
 }
@@ -301,6 +335,7 @@ TEST(LayoutCacheTest, boundsCalculation) {
 
     TestableLayoutCache layoutCache(10);
 
+    LayoutContext ctx;
     LayoutCapture layout1;
     LayoutCapture layout2;
 
@@ -309,10 +344,10 @@ TEST(LayoutCacheTest, boundsCalculation) {
         layoutCache.clear();
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
                                 StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT,
-                                false /* calculateBounds */, layout1);
+                                false /* calculateBounds */, &ctx, layout1);
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
                                 StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT,
-                                true /* calculateBounds */, layout2);
+                                true /* calculateBounds */, &ctx, layout2);
         EXPECT_NE(layout1.get(), layout2.get());
         EXPECT_FALSE(layout1.bounds().isValid());
         EXPECT_TRUE(layout2.bounds().isValid());
@@ -322,10 +357,10 @@ TEST(LayoutCacheTest, boundsCalculation) {
         layoutCache.clear();
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
                                 StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT,
-                                true /* calculateBounds */, layout1);
+                                true /* calculateBounds */, &ctx, layout1);
         layoutCache.getOrCreate(text1, Range(0, text1.size()), paint, false /* LTR */,
                                 StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT,
-                                false /* calculateBounds */, layout2);
+                                false /* calculateBounds */, &ctx, layout2);
         EXPECT_EQ(layout1.get(), layout2.get());
         EXPECT_TRUE(layout1.bounds().isValid());
     }
diff --git a/tests/unittest/LayoutCoreTest.cpp b/tests/unittest/LayoutCoreTest.cpp
index 9ce6c34..bee4c2a 100644
--- a/tests/unittest/LayoutCoreTest.cpp
+++ b/tests/unittest/LayoutCoreTest.cpp
@@ -14,30 +14,33 @@
  * limitations under the License.
  */
 
-#include "minikin/LayoutCore.h"
-
+#include <com_android_text_flags.h>
+#include <flag_macros.h>
 #include <gtest/gtest.h>
 
-#include "minikin/FontCollection.h"
-#include "minikin/LayoutPieces.h"
-
 #include "FontTestUtils.h"
+#include "LayoutContext.h"
 #include "UnicodeUtils.h"
+#include "minikin/FontCollection.h"
+#include "minikin/LayoutCore.h"
+#include "minikin/LayoutPieces.h"
 
 namespace minikin {
 namespace {
 
 static LayoutPiece buildLayout(const std::string& text, const MinikinPaint& paint) {
     auto utf16 = utf8ToUtf16(text);
+    LayoutContext ctx;
     return LayoutPiece(utf16, Range(0, utf16.size()), false /* rtl */, paint,
-                       StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT);
+                       StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, &ctx);
 }
 
 static LayoutPiece buildLayout(const std::string& text, const Range& range,
                                const MinikinPaint& paint) {
     auto utf16 = utf8ToUtf16(text);
+    LayoutContext ctx;
     return LayoutPiece(utf16, range, false /* rtl */, paint, StartHyphenEdit::NO_EDIT,
-                       EndHyphenEdit::NO_EDIT);
+                       EndHyphenEdit::NO_EDIT, &ctx);
 }
 
 static LayoutPiece buildLayout(const std::string& text, std::shared_ptr<FontCollection> fc) {
@@ -51,8 +54,9 @@ static std::pair<LayoutPiece, MinikinRect> buildLayoutAndBounds(
     MinikinPaint paint(fc);
     paint.size = 10.0f;  // make 1em = 10px
     auto utf16 = utf8ToUtf16(text);
+    LayoutContext ctx;
     LayoutPiece lp = LayoutPiece(utf16, Range(0, utf16.size()), false /* rtl */, paint,
-                                 StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT);
+                                 StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, &ctx);
     MinikinRect rect = LayoutPiece::calculateBounds(lp, paint);
     return std::make_pair(lp, rect);
 }
@@ -403,5 +407,29 @@ TEST(LayoutPieceTest, doLayoutLongTextTest) {
     EXPECT_EQ(1024u, layout.clusterCount());
 }
 
+TEST_WITH_FLAGS(LayoutExtentTest, VerticalLayoutBaseTable,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
+                                                    language_specific_extent))) {
+    auto fc = makeFontCollection({"BaseTableFont.ttf"});
+    MinikinPaint paint(fc);
+    paint.size = 100.0f;  // make 1em = 10px
+
+    // Vertical metrics from hhea table for Latin script
+    {
+        paint.localeListId = registerLocaleList("en-US");
+        auto layout = buildLayout("a", paint);
+        EXPECT_EQ(-80, layout.extent().ascent);
+        EXPECT_EQ(20, layout.extent().descent);
+    }
+
+    // Vertical metrics from BASE table for Vietnamese script
+    {
+        paint.localeListId = registerLocaleList("vi-VI");
+        auto layout = buildLayout("a", paint);
+        EXPECT_EQ(-100, layout.extent().ascent);
+        EXPECT_EQ(40, layout.extent().descent);
+    }
+}
+
 }  // namespace
 }  // namespace minikin
diff --git a/tests/unittest/LineBreakerTestHelper.h b/tests/unittest/LineBreakerTestHelper.h
index cb1d161..1e09522 100644
--- a/tests/unittest/LineBreakerTestHelper.h
+++ b/tests/unittest/LineBreakerTestHelper.h
@@ -83,8 +83,8 @@ public:
     virtual const MinikinPaint* getPaint() const { return &mPaint; }
 
     virtual float measureHyphenPiece(const U16StringPiece&, const Range& range,
-                                     StartHyphenEdit start, EndHyphenEdit end,
-                                     LayoutPieces*) const {
+                                     StartHyphenEdit start, EndHyphenEdit end, LayoutPieces*,
+                                     LayoutContext*) const {
         uint32_t extraCharForHyphen = 0;
         if (isInsertion(start)) {
             extraCharForHyphen++;
```

