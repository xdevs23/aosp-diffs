```diff
diff --git a/include/minikin/Constants.h b/include/minikin/Constants.h
index eacac07..708d277 100644
--- a/include/minikin/Constants.h
+++ b/include/minikin/Constants.h
@@ -36,6 +36,7 @@ const uint32_t TAG_fvar = MakeTag('f', 'v', 'a', 'r');
 // Axis tags
 const uint32_t TAG_wght = MakeTag('w', 'g', 'h', 't');
 const uint32_t TAG_ital = MakeTag('i', 't', 'a', 'l');
+const uint32_t TAG_slnt = MakeTag('s', 'l', 'n', 't');
 
 }  // namespace minikin
 
diff --git a/include/minikin/Debug.h b/include/minikin/Debug.h
index a08b234..223cc80 100644
--- a/include/minikin/Debug.h
+++ b/include/minikin/Debug.h
@@ -20,6 +20,8 @@
 #include <string>
 #include <vector>
 
+#include "minikin/FontVariation.h"
+
 namespace minikin {
 
 struct Point;
@@ -27,6 +29,7 @@ struct MinikinRect;
 struct MinikinExtent;
 struct MinikinPaint;
 struct FontFeature;
+class FontStyle;
 class Range;
 class U16StringPiece;
 class LayoutPiece;
@@ -44,6 +47,8 @@ std::string toString(const LayoutPiece& layout);
 std::string toString(const MinikinPaint& paint);
 std::string toString(const FontFeature& feature);
 std::string toString(const std::vector<FontFeature>& features);
+std::string toString(const FontStyle& style);
+std::string toString(const VariationSettings& varSettings);
 
 }  // namespace debug
 
diff --git a/include/minikin/Font.h b/include/minikin/Font.h
index 0329cb4..22e9217 100644
--- a/include/minikin/Font.h
+++ b/include/minikin/Font.h
@@ -18,6 +18,7 @@
 #define MINIKIN_FONT_H
 
 #include <gtest/gtest_prod.h>
+#include <utils/LruCache.h>
 
 #include <atomic>
 #include <functional>
@@ -38,8 +39,6 @@
 
 namespace minikin {
 
-class Font;
-
 // Represents a single font file.
 class Font {
 public:
@@ -89,7 +88,7 @@ public:
     void writeTo(BufferWriter* writer) const;
 
     // Create font instance with axes override.
-    Font(const std::shared_ptr<Font>& parent, const std::vector<FontVariation>& axes);
+    Font(const std::shared_ptr<Font>& parent, const VariationSettings& axes);
 
     Font(Font&& o) noexcept;
     Font& operator=(Font&& o) noexcept;
@@ -105,7 +104,10 @@ public:
     // Returns an adjusted hb_font_t instance and MinikinFont instance.
     // Passing -1 each means do not override the current variation settings.
     HbFontUniquePtr getAdjustedFont(int wght, int ital) const;
-    const std::shared_ptr<MinikinFont>& getAdjustedTypeface(int wght, int ital) const;
+    std::shared_ptr<MinikinFont> getAdjustedTypeface(int wght, int ital) const;
+
+    HbFontUniquePtr getAdjustedFont(const VariationSettings& varSettings) const;
+    std::shared_ptr<MinikinFont> getAdjustedTypeface(const VariationSettings& varSettings) const;
 
     BufferReader typefaceMetadataReader() const { return mTypefaceMetadataReader; }
 
@@ -122,17 +124,31 @@ private:
     class ExternalRefs {
     public:
         ExternalRefs(std::shared_ptr<MinikinFont>&& typeface, HbFontUniquePtr&& baseFont)
-                : mTypeface(std::move(typeface)), mBaseFont(std::move(baseFont)) {}
+                : mTypeface(std::move(typeface)),
+                  mBaseFont(std::move(baseFont)),
+                  mVarTypefaceCache2(16),
+                  mVarFontCache2(16) {}
 
         std::shared_ptr<MinikinFont> mTypeface;
         HbFontUniquePtr mBaseFont;
 
+        // TODO: remove wght/ital only adjusted typeface pool once redesign typeface flag
+        //       is removed.
         const std::shared_ptr<MinikinFont>& getAdjustedTypeface(int wght, int ital) const;
         HbFontUniquePtr getAdjustedFont(int wght, int ital) const;
         mutable std::mutex mMutex;
         mutable std::map<uint16_t, std::shared_ptr<MinikinFont>> mVarTypefaceCache
                 GUARDED_BY(mMutex);
         mutable std::map<uint16_t, HbFontUniquePtr> mVarFontCache GUARDED_BY(mMutex);
+
+        std::shared_ptr<MinikinFont> getAdjustedTypeface(const VariationSettings& varSettings,
+                                                         const FVarTable& fvarTable) const;
+        HbFontUniquePtr getAdjustedFont(const VariationSettings& varSettings,
+                                        const FVarTable& fvarTable) const;
+        mutable android::LruCache<VariationSettings, std::shared_ptr<MinikinFont>>
+                mVarTypefaceCache2 GUARDED_BY(mMutex);
+        mutable android::LruCache<VariationSettings, HbFontUniquePtr*> mVarFontCache2
+                GUARDED_BY(mMutex);
     };
 
     // Use Builder instead.
@@ -183,13 +199,8 @@ struct FakedFont {
     }
     inline bool operator!=(const FakedFont& o) const { return !(*this == o); }
 
-    HbFontUniquePtr hbFont() const {
-        return font->getAdjustedFont(fakery.wghtAdjustment(), fakery.italAdjustment());
-    }
-
-    const std::shared_ptr<MinikinFont>& typeface() const {
-        return font->getAdjustedTypeface(fakery.wghtAdjustment(), fakery.italAdjustment());
-    }
+    HbFontUniquePtr hbFont() const;
+    std::shared_ptr<MinikinFont> typeface() const;
 
     // ownership is the enclosing FontCollection
     // FakedFont will be stored in the LayoutCache. It is not a good idea too keep font instance
diff --git a/include/minikin/FontCollection.h b/include/minikin/FontCollection.h
index 18635d2..d85b794 100644
--- a/include/minikin/FontCollection.h
+++ b/include/minikin/FontCollection.h
@@ -155,7 +155,11 @@ public:
         int end;
     };
 
-    FakedFont getBestFont(U16StringPiece textBuf, const Run& run, FontStyle style);
+    FakedFont getBestFont(U16StringPiece textBuf, const Run& run, FontStyle style,
+                          const VariationSettings& variationSettings);
+    FakedFont getBestFont(U16StringPiece textBuf, const Run& run, FontStyle style) {
+        return getBestFont(textBuf, run, style, VariationSettings());
+    }
 
     // Perform the itemization until given max runs.
     std::vector<Run> itemize(U16StringPiece text, FontStyle style, uint32_t localeListId,
@@ -180,7 +184,7 @@ public:
     // Creates new FontCollection based on this collection while applying font variations. Returns
     // nullptr if none of variations apply to this collection.
     std::shared_ptr<FontCollection> createCollectionWithVariation(
-            const std::vector<FontVariation>& variations);
+            const VariationSettings& variations);
     // Creates new FontCollection that uses the specified families as top families and
     // families from this FontCollection as fallback.
     std::shared_ptr<FontCollection> createCollectionWithFamilies(
diff --git a/include/minikin/FontFakery.h b/include/minikin/FontFakery.h
index b98cfa8..d37a84a 100644
--- a/include/minikin/FontFakery.h
+++ b/include/minikin/FontFakery.h
@@ -17,6 +17,8 @@
 #ifndef MINIKIN_FONT_FAKERY_H
 #define MINIKIN_FONT_FAKERY_H
 
+#include "minikin/FVarTable.h"
+#include "minikin/FontStyle.h"
 #include "minikin/FontVariation.h"
 
 namespace minikin {
@@ -98,6 +100,29 @@ private:
     const VariationSettings mVariationSettings;
 };
 
+// Merge font variation settings along with font style and returns FontFakery.
+//
+// The param baseVS is a base variation settings. It comes from font instance.
+// The param targetVS is a target variation settings. It is came from Paint settings.
+// The param baseStyle is a base font style. It is came from font instance.
+// The param targetStyle is a target font style. It is came from Paint settings.
+//
+// The basic concept of the merge strategy is use target variation settings as the first priority,
+// then use the target style second, then use the base variation settings finally.
+//
+// It works like as follows:
+// Step 1. The target font style is translated to the variation settings based on the axis
+//         availability. For example, if the font support `wght` axis, the 700 of the font weight
+//         in the target font style is translated to `wght` 700.
+// Step 2. Merge the derived variation settings and target variation settings. If there is a common
+//         tag, the value of the target variation settings is used.
+// Step 3. Merge the base variation settings and the derived variation settings in Step 2. If there
+//         is a common tag, the value of the target variation settings is used.
+//
+// The fake bold and fake italic of the FontFakery is resolved based on the font capabilities.
+FontFakery merge(const FVarTable& fvar, const VariationSettings& baseVS,
+                 const VariationSettings& targetVS, FontStyle baseStyle, FontStyle targetStyle);
+
 }  // namespace minikin
 
 #endif  // MINIKIN_FONT_FAKERY_H
diff --git a/include/minikin/FontFamily.h b/include/minikin/FontFamily.h
index 29f81cf..b3d2839 100644
--- a/include/minikin/FontFamily.h
+++ b/include/minikin/FontFamily.h
@@ -49,7 +49,7 @@ public:
 
     // Create FontFamily with axes override.
     static std::shared_ptr<FontFamily> create(const std::shared_ptr<FontFamily>& parent,
-                                              const std::vector<FontVariation>& axesOverride);
+                                              const VariationSettings& axesOverride);
 
     FontFamily(FontFamily&&) = default;
     FontFamily& operator=(FontFamily&&) = default;
@@ -58,7 +58,10 @@ public:
     static void writeVector(BufferWriter* writer,
                             const std::vector<std::shared_ptr<FontFamily>>& families);
 
-    FakedFont getClosestMatch(FontStyle style) const;
+    FakedFont getClosestMatch(FontStyle style, const VariationSettings& axes) const;
+    FakedFont getClosestMatch(FontStyle style) const {
+        return getClosestMatch(style, VariationSettings());
+    }
     FakedFont getVariationFamilyAdjustment(FontStyle style) const;
 
     uint32_t localeListId() const { return mLocaleListId; }
@@ -104,14 +107,13 @@ public:
     // Creates new FontFamily based on this family while applying font variations. Returns nullptr
     // if none of variations apply to this family.
     std::shared_ptr<FontFamily> createFamilyWithVariation(
-            const std::vector<FontVariation>& variations) const;
+            const VariationSettings& variations) const;
 
 private:
     FontFamily(uint32_t localeListId, FamilyVariant variant,
                std::vector<std::shared_ptr<Font>>&& fonts, bool isCustomFallback,
                bool isDefaultFallback, VariationFamilyType varFamilyType);
-    FontFamily(const std::shared_ptr<FontFamily>& parent,
-               const std::vector<FontVariation>& axesOverride);
+    FontFamily(const std::shared_ptr<FontFamily>& parent, const VariationSettings& axesOverride);
     explicit FontFamily(BufferReader* reader, const std::shared_ptr<std::vector<Font>>& fonts);
 
     void writeTo(BufferWriter* writer, uint32_t* fontIndex) const;
@@ -127,7 +129,7 @@ private:
     // This field is empty if mParent is set. Use mParent's coverage instead.
     std::unique_ptr<SparseBitSet[]> mCmapFmt14Coverage;
     std::shared_ptr<FontFamily> mParent;
-    std::vector<FontVariation> mVarOverride;
+    VariationSettings mVarOverride;
     uint32_t mLocaleListId;  // 4 bytes
     uint32_t mFontsCount;    // 4 bytes
     // OpenType supports up to 2^16-1 (uint16) axes.
@@ -140,6 +142,7 @@ private:
     bool mIsDefaultFallback;           // 1 byte
     VariationFamilyType mVarFamilyType;  // 1byte
 
+    bool mIsVariationFamily;
     MINIKIN_PREVENT_COPY_AND_ASSIGN(FontFamily);
 };
 
diff --git a/include/minikin/FontStyle.h b/include/minikin/FontStyle.h
index 7a9e597..5ba6c04 100644
--- a/include/minikin/FontStyle.h
+++ b/include/minikin/FontStyle.h
@@ -62,6 +62,7 @@ public:
 
     constexpr uint16_t weight() const { return mWeight; }
     constexpr Slant slant() const { return mSlant; }
+    bool isItalic() const { return mSlant == Slant::ITALIC; }
 
     constexpr uint32_t identifier() const {
         return (static_cast<uint32_t>(weight()) << 16) | static_cast<uint32_t>(slant());
diff --git a/include/minikin/FontVariation.h b/include/minikin/FontVariation.h
index d3d405f..516fa59 100644
--- a/include/minikin/FontVariation.h
+++ b/include/minikin/FontVariation.h
@@ -18,6 +18,7 @@
 #define MINIKIN_FONT_VARIATION_H
 
 #include <cstdint>
+#include <iostream>
 
 #include "minikin/SortedPackedVector.h"
 
@@ -57,7 +58,24 @@ constexpr bool operator>=(const FontVariation& l, const FontVariation& r) {
 }
 
 // Immutable variation settings
-using VariationSettings = SortedPackedVector<FontVariation>;
+using VariationSettings = SortedPackedVector<FontVariation, 2, uint16_t>;
+
+inline std::ostream& operator<<(std::ostream& os, const FontVariation& variation) {
+    return os << "'" << static_cast<char>(variation.axisTag >> 24)
+              << static_cast<char>(variation.axisTag >> 16)
+              << static_cast<char>(variation.axisTag >> 8) << static_cast<char>(variation.axisTag)
+              << "' " << variation.value;
+}
+
+inline std::ostream& operator<<(std::ostream& os, const VariationSettings& varSettings) {
+    for (size_t i = 0; i < varSettings.size(); ++i) {
+        if (i != 0) {
+            os << ", ";
+        }
+        os << varSettings[i];
+    }
+    return os;
+}
 
 }  // namespace minikin
 
diff --git a/include/minikin/Hasher.h b/include/minikin/Hasher.h
index 3121c33..f0bbcc1 100644
--- a/include/minikin/Hasher.h
+++ b/include/minikin/Hasher.h
@@ -74,6 +74,24 @@ public:
         return *this;
     }
 
+    inline Hasher& update(const VariationSettings& vars) {
+        update(vars.size());
+        for (const FontVariation& var : vars) {
+            update(var.axisTag);
+            update(var.value);
+        }
+        return *this;
+    }
+
+    template <typename V>
+    inline Hasher& updatePackedVector(const V& vec) {
+        using T = typename V::value_type;
+        for (const T& p : vec) {
+            update(p);
+        }
+        return *this;
+    }
+
     inline Hasher& updateShorts(const uint16_t* data, uint32_t length) {
         update(length);
         uint32_t i;
@@ -127,6 +145,16 @@ public:
         return hash;
     }
 
+#ifdef __APPLE__
+    inline Hasher& update(uintptr_t data) {
+        update(static_cast<uint32_t>(data));
+        if (sizeof(uintptr_t) > sizeof(uint32_t)) {
+            update(static_cast<uint32_t>(data >> 32));
+        }
+        return *this;
+    }
+#endif
+
 private:
     uint32_t mHash;
 };
diff --git a/include/minikin/Layout.h b/include/minikin/Layout.h
index 11ae7ca..c5ccabe 100644
--- a/include/minikin/Layout.h
+++ b/include/minikin/Layout.h
@@ -132,8 +132,8 @@ public:
     size_t nGlyphs() const { return mGlyphs.size(); }
     const Font* getFont(int i) const { return mGlyphs[i].font.font.get(); }
     const std::shared_ptr<Font>& getFontRef(int i) const { return mGlyphs[i].font.font; }
-    FontFakery getFakery(int i) const { return mGlyphs[i].font.fakery; }
-    const std::shared_ptr<MinikinFont>& typeface(int i) const { return mGlyphs[i].font.typeface(); }
+    const FontFakery& getFakery(int i) const { return mGlyphs[i].font.fakery; }
+    std::shared_ptr<MinikinFont> typeface(int i) const { return mGlyphs[i].font.typeface(); }
     unsigned int getGlyphId(int i) const { return mGlyphs[i].glyph_id; }
     float getX(int i) const { return mGlyphs[i].x; }
     float getY(int i) const { return mGlyphs[i].y; }
diff --git a/include/minikin/LayoutCache.h b/include/minikin/LayoutCache.h
index fe44370..40812ac 100644
--- a/include/minikin/LayoutCache.h
+++ b/include/minikin/LayoutCache.h
@@ -26,6 +26,7 @@
 #include "minikin/Hasher.h"
 #include "minikin/LayoutCore.h"
 #include "minikin/MinikinPaint.h"
+#include "minikin/PackedVector.h"
 
 #ifdef _WIN32
 #include <io.h>
@@ -37,10 +38,10 @@ class LayoutCacheKey {
 public:
     LayoutCacheKey(const U16StringPiece& text, const Range& range, const MinikinPaint& paint,
                    bool dir, StartHyphenEdit startHyphen, EndHyphenEdit endHyphen)
-            : mChars(text.data()),
-              mNchars(text.size()),
+            : mChars(text.data(), text.size()),
               mStart(range.getStart()),
               mCount(range.getLength()),
+              mFontFlags(paint.fontFlags),
               mId(paint.font->getId()),
               mStyle(paint.fontStyle),
               mSize(paint.size),
@@ -48,13 +49,14 @@ public:
               mSkewX(paint.skewX),
               mLetterSpacing(paint.letterSpacing),
               mWordSpacing(paint.wordSpacing),
-              mFontFlags(paint.fontFlags),
               mLocaleListId(paint.localeListId),
+              mVerticalText(paint.verticalText),
               mFamilyVariant(paint.familyVariant),
               mStartHyphen(startHyphen),
               mEndHyphen(endHyphen),
               mIsRtl(dir),
               mFontFeatureSettings(paint.fontFeatureSettings),
+              mVariationSettings(paint.fontVariationSettings),
               mHash(computeHash()) {}
 
     bool operator==(const LayoutCacheKey& o) const {
@@ -62,32 +64,23 @@ public:
                mSize == o.mSize && mScaleX == o.mScaleX && mSkewX == o.mSkewX &&
                mLetterSpacing == o.mLetterSpacing && mWordSpacing == o.mWordSpacing &&
                mFontFlags == o.mFontFlags && mLocaleListId == o.mLocaleListId &&
-               mFamilyVariant == o.mFamilyVariant && mStartHyphen == o.mStartHyphen &&
-               mEndHyphen == o.mEndHyphen && mIsRtl == o.mIsRtl && mNchars == o.mNchars &&
-               mFontFeatureSettings == o.mFontFeatureSettings &&
-               !memcmp(mChars, o.mChars, mNchars * sizeof(uint16_t));
+               mVerticalText == o.mVerticalText && mFamilyVariant == o.mFamilyVariant &&
+               mStartHyphen == o.mStartHyphen && mEndHyphen == o.mEndHyphen && mIsRtl == o.mIsRtl &&
+               mFontFeatureSettings == o.mFontFeatureSettings && mChars == o.mChars &&
+               mVariationSettings == o.mVariationSettings;
     }
 
     android::hash_t hash() const { return mHash; }
 
-    void copyText() {
-        uint16_t* charsCopy = new uint16_t[mNchars];
-        memcpy(charsCopy, mChars, mNchars * sizeof(uint16_t));
-        mChars = charsCopy;
-    }
-    void freeText() {
-        delete[] mChars;
-        mChars = NULL;
-        mFontFeatureSettings.clear();
+    uint32_t getMemoryUsage() const {
+        return sizeof(LayoutCacheKey) + sizeof(uint16_t) * mChars.size();
     }
 
-    uint32_t getMemoryUsage() const { return sizeof(LayoutCacheKey) + sizeof(uint16_t) * mNchars; }
-
 private:
-    const uint16_t* mChars;
-    uint32_t mNchars;
-    uint32_t mStart;
-    uint32_t mCount;
+    PackedVector<uint16_t, 12> mChars;
+    uint8_t mStart;
+    uint8_t mCount;
+    uint8_t mFontFlags;
     uint32_t mId;  // for the font collection
     FontStyle mStyle;
     float mSize;
@@ -95,13 +88,14 @@ private:
     float mSkewX;
     float mLetterSpacing;
     float mWordSpacing;
-    int32_t mFontFlags;
     uint32_t mLocaleListId;
+    bool mVerticalText;
     FamilyVariant mFamilyVariant;
     StartHyphenEdit mStartHyphen;
     EndHyphenEdit mEndHyphen;
     bool mIsRtl;
-    std::vector<FontFeature> mFontFeatureSettings;
+    PackedVector<FontFeature> mFontFeatureSettings;
+    VariationSettings mVariationSettings;
     // Note: any fields added to MinikinPaint must also be reflected here.
     // TODO: language matching (possibly integrate into style)
     android::hash_t mHash;
@@ -116,14 +110,16 @@ private:
                 .update(mScaleX)
                 .update(mSkewX)
                 .update(mLetterSpacing)
+                .update(mVerticalText)
                 .update(mWordSpacing)
                 .update(mFontFlags)
                 .update(mLocaleListId)
                 .update(static_cast<uint8_t>(mFamilyVariant))
                 .update(packHyphenEdit(mStartHyphen, mEndHyphen))
                 .update(mIsRtl)
-                .updateShorts(mChars, mNchars)
-                .update(mFontFeatureSettings)
+                .updateShorts(mChars.data(), mChars.size())
+                .updatePackedVector(mFontFeatureSettings)
+                .update(mVariationSettings)
                 .hash();
     }
 };
@@ -189,9 +185,6 @@ public:
                 return;
             }
         }
-        // Doing text layout takes long time, so releases the mutex during doing layout.
-        // Don't care even if we do the same layout in other thred.
-        key.copyText();
 
         std::unique_ptr<LayoutSlot> slot;
         if (boundsCalculation) {
@@ -228,10 +221,7 @@ protected:
 
 private:
     // callback for OnEntryRemoved
-    void operator()(LayoutCacheKey& key, LayoutSlot*& value) {
-        key.freeText();
-        delete value;
-    }
+    void operator()(LayoutCacheKey&, LayoutSlot*& value) { delete value; }
 
     android::LruCache<LayoutCacheKey, LayoutSlot*> mCache GUARDED_BY(mMutex);
 
diff --git a/include/minikin/LayoutCore.h b/include/minikin/LayoutCore.h
index 134cc48..e576365 100644
--- a/include/minikin/LayoutCore.h
+++ b/include/minikin/LayoutCore.h
@@ -27,6 +27,7 @@
 #include "minikin/MinikinExtent.h"
 #include "minikin/MinikinFont.h"
 #include "minikin/MinikinRect.h"
+#include "minikin/PackedVector.h"
 #include "minikin/Point.h"
 #include "minikin/Range.h"
 #include "minikin/U16StringPiece.h"
@@ -35,6 +36,12 @@ namespace minikin {
 
 struct MinikinPaint;
 
+using FontIndexVector = PackedVector<uint8_t, 12>;
+using GlyphIdVector = PackedVector<uint16_t, 12>;
+using PointVector = PackedVector<Point>;
+using ClusterVector = PackedVector<uint8_t, 12>;
+using AdvanceVector = PackedVector<float>;
+
 // Immutable, recycle-able layout result.
 class LayoutPiece {
 public:
@@ -43,10 +50,8 @@ public:
     ~LayoutPiece();
 
     // Low level accessors.
-    const std::vector<uint8_t>& fontIndices() const { return mFontIndices; }
-    const std::vector<uint32_t>& glyphIds() const { return mGlyphIds; }
-    const std::vector<Point>& points() const { return mPoints; }
-    const std::vector<float>& advances() const { return mAdvances; }
+    const PointVector& points() const { return mPoints; }
+    const AdvanceVector& advances() const { return mAdvances; }
     float advance() const { return mAdvance; }
     const MinikinExtent& extent() const { return mExtent; }
     const std::vector<FakedFont>& fonts() const { return mFonts; }
@@ -58,6 +63,7 @@ public:
     uint32_t glyphIdAt(int glyphPos) const { return mGlyphIds[glyphPos]; }
     const Point& pointAt(int glyphPos) const { return mPoints[glyphPos]; }
     uint16_t clusterAt(int glyphPos) const { return mClusters[glyphPos]; }
+    bool isVerticalText() const { return mVerticalText; }
 
     uint32_t getMemoryUsage() const {
         return sizeof(uint8_t) * mFontIndices.size() + sizeof(uint32_t) * mGlyphIds.size() +
@@ -70,16 +76,17 @@ public:
 private:
     FRIEND_TEST(LayoutTest, doLayoutWithPrecomputedPiecesTest);
 
-    std::vector<uint8_t> mFontIndices;      // per glyph
-    std::vector<uint32_t> mGlyphIds;        // per glyph
-    std::vector<Point> mPoints;             // per glyph
-    std::vector<uint8_t> mClusters;         // per glyph
+    FontIndexVector mFontIndices;  // per glyph
+    GlyphIdVector mGlyphIds;       // per glyph
+    PointVector mPoints;           // per glyph
+    ClusterVector mClusters;       // per glyph
 
-    std::vector<float> mAdvances;  // per code units
+    AdvanceVector mAdvances;  // per code units
 
     float mAdvance;
     MinikinExtent mExtent;
     uint32_t mClusterCount;
+    bool mVerticalText;
 
     std::vector<FakedFont> mFonts;
 };
diff --git a/include/minikin/MinikinFont.h b/include/minikin/MinikinFont.h
index 6d5f006..0d9dc07 100644
--- a/include/minikin/MinikinFont.h
+++ b/include/minikin/MinikinFont.h
@@ -69,10 +69,9 @@ public:
 
     virtual int GetSourceId() const { return 0; }
 
-    virtual const std::vector<minikin::FontVariation>& GetAxes() const = 0;
+    virtual const VariationSettings& GetAxes() const = 0;
 
-    virtual std::shared_ptr<MinikinFont> createFontWithVariation(
-            const std::vector<FontVariation>&) const {
+    virtual std::shared_ptr<MinikinFont> createFontWithVariation(const VariationSettings&) const {
         return nullptr;
     }
 };
diff --git a/include/minikin/MinikinPaint.h b/include/minikin/MinikinPaint.h
index 9705b3c..ccc605a 100644
--- a/include/minikin/MinikinPaint.h
+++ b/include/minikin/MinikinPaint.h
@@ -57,6 +57,7 @@ struct MinikinPaint {
               fontFlags(0),
               localeListId(0),
               familyVariant(FamilyVariant::DEFAULT),
+              verticalText(false),
               fontFeatureSettings(),
               font(font) {}
 
@@ -69,6 +70,7 @@ struct MinikinPaint {
     uint32_t localeListId;
     FontStyle fontStyle;
     FamilyVariant familyVariant;
+    bool verticalText;
     std::vector<FontFeature> fontFeatureSettings;
     std::shared_ptr<FontCollection> font;
     VariationSettings fontVariationSettings;
@@ -89,7 +91,8 @@ struct MinikinPaint {
                fontFlags == paint.fontFlags && localeListId == paint.localeListId &&
                fontStyle == paint.fontStyle && familyVariant == paint.familyVariant &&
                fontFeatureSettings == paint.fontFeatureSettings && font.get() == paint.font.get() &&
-               fontVariationSettings == paint.fontVariationSettings;
+               fontVariationSettings == paint.fontVariationSettings &&
+               verticalText == paint.verticalText;
     }
 
     uint32_t hash() const {
@@ -104,6 +107,7 @@ struct MinikinPaint {
                 .update(fontStyle.identifier())
                 .update(static_cast<uint8_t>(familyVariant))
                 .update(fontFeatureSettings)
+                .update(verticalText)
                 .update(font->getId())
                 .update(fontVariationSettings)
                 .hash();
diff --git a/include/minikin/PackedVector.h b/include/minikin/PackedVector.h
index e383f16..fcd551b 100644
--- a/include/minikin/PackedVector.h
+++ b/include/minikin/PackedVector.h
@@ -26,7 +26,7 @@ namespace minikin {
 
 // PackedVector optimize short term allocations for small size objects.
 // The public interfaces are following the std::vector.
-template <typename T, size_t ARRAY_SIZE = 2>
+template <typename T, size_t ARRAY_SIZE = 2, typename SIZE_TYPE = uint32_t>
 class PackedVector {
 private:
     // At least two elements of pointer array is reserved.
@@ -42,9 +42,9 @@ public:
 
     // Constructors
     PackedVector() : mSize(0), mCapacity(ARRAY_CAPACITY) {}
-    PackedVector(const T* ptr, uint16_t size) : PackedVector() { copy(ptr, size); }
+    PackedVector(const T* ptr, SIZE_TYPE size) : PackedVector() { copy(ptr, size); }
     PackedVector(const std::vector<T>& src) : PackedVector() {
-        LOG_ALWAYS_FATAL_IF(src.size() >= std::numeric_limits<uint16_t>::max());
+        LOG_ALWAYS_FATAL_IF(src.size() >= std::numeric_limits<SIZE_TYPE>::max());
         copy(src.data(), src.size());
     }
     PackedVector(std::initializer_list<T> init) : PackedVector() {
@@ -76,12 +76,12 @@ public:
     const T* data() const { return getPtr(); }
     T* data() { return getPtr(); }
 
-    const T& operator[](uint16_t i) const { return getPtr()[i]; }
-    T& operator[](uint16_t i) { return getPtr()[i]; }
+    const T& operator[](SIZE_TYPE i) const { return getPtr()[i]; }
+    T& operator[](SIZE_TYPE i) { return getPtr()[i]; }
 
-    void reserve(uint16_t capacity) { ensureCapacity(capacity); }
+    void reserve(SIZE_TYPE capacity) { ensureCapacity(capacity); }
 
-    void resize(uint16_t size, T value = T()) {
+    void resize(SIZE_TYPE size, T value = T()) {
         if (mSize == size) {
             return;
         } else if (mSize > size) {  // reduce size
@@ -106,7 +106,7 @@ public:
         } else {  // mSize < size  // increase size
             ensureCapacity(size);
             T* ptr = getPtr();
-            for (uint16_t i = mSize; i < size; ++i) {
+            for (SIZE_TYPE i = mSize; i < size; ++i) {
                 ptr[i] = value;
             }
             mSize = size;
@@ -116,7 +116,7 @@ public:
     void push_back(const T& x) {
         if (mSize >= mCapacity) [[unlikely]] {
             // exponential backoff
-            constexpr uint16_t kMaxIncrease = static_cast<uint16_t>(4096 / sizeof(T));
+            constexpr SIZE_TYPE kMaxIncrease = static_cast<SIZE_TYPE>(4096 / sizeof(T));
             ensureCapacity(mCapacity + std::min(mCapacity, kMaxIncrease));
         }
         *(getPtr() + mSize) = x;
@@ -153,15 +153,15 @@ public:
 
     bool empty() const { return mSize == 0; }
 
-    uint16_t size() const { return mSize; }
-    uint16_t capacity() const { return mCapacity; }
+    SIZE_TYPE size() const { return mSize; }
+    SIZE_TYPE capacity() const { return mCapacity; }
 
 private:
     uintptr_t mArray[PTR_ARRAY_SIZE];
-    uint16_t mSize;
-    uint16_t mCapacity;
+    SIZE_TYPE mSize;
+    SIZE_TYPE mCapacity;
 
-    void copy(const T* src, uint16_t count) {
+    void copy(const T* src, SIZE_TYPE count) {
         clear();
         ensureCapacity(count);
         mSize = count;
@@ -181,7 +181,7 @@ private:
 
     inline bool isArrayUsed() const { return mCapacity <= ARRAY_CAPACITY; }
 
-    void ensureCapacity(uint16_t capacity) {
+    void ensureCapacity(SIZE_TYPE capacity) {
         if (capacity <= mCapacity) {
             return;
         }
diff --git a/include/minikin/Point.h b/include/minikin/Point.h
index c3fe2f3..01c68ac 100644
--- a/include/minikin/Point.h
+++ b/include/minikin/Point.h
@@ -22,7 +22,6 @@
 namespace minikin {
 
 struct Point {
-    Point(float x, float y) : x(x), y(y) {}
     float x, y;
 };
 
diff --git a/include/minikin/SortedPackedVector.h b/include/minikin/SortedPackedVector.h
index f3367af..75e6a0a 100644
--- a/include/minikin/SortedPackedVector.h
+++ b/include/minikin/SortedPackedVector.h
@@ -25,11 +25,11 @@
 namespace minikin {
 
 // An immutable packed vector that elements are sorted.
-template <typename T, size_t ARRAY_SIZE = 2>
+template <typename T, size_t ARRAY_SIZE = 2, typename SIZE_TYPE = uint32_t>
 class SortedPackedVector {
 public:
     SortedPackedVector() {}
-    SortedPackedVector(const T* ptr, uint16_t count, bool sorted = false) : mPacked(ptr, count) {
+    SortedPackedVector(const T* ptr, SIZE_TYPE count, bool sorted = false) : mPacked(ptr, count) {
         if (!sorted) {
             sort();
         }
@@ -50,15 +50,15 @@ public:
     SortedPackedVector(SortedPackedVector&& o) = default;
     SortedPackedVector& operator=(SortedPackedVector&& o) = default;
 
-    uint16_t size() const { return mPacked.size(); }
+    SIZE_TYPE size() const { return mPacked.size(); }
     bool empty() const { return size() == 0; }
 
-    const T& operator[](uint16_t i) const { return mPacked[i]; }
+    const T& operator[](SIZE_TYPE i) const { return mPacked[i]; }
     const T* data() const { return mPacked.data(); }
 
-    inline bool operator==(const SortedPackedVector<T>& o) const { return mPacked == o.mPacked; }
+    inline bool operator==(const SortedPackedVector& o) const { return mPacked == o.mPacked; }
 
-    inline bool operator!=(const SortedPackedVector<T>& o) const { return !(*this == o); }
+    inline bool operator!=(const SortedPackedVector& o) const { return !(*this == o); }
 
     inline const T* begin() const { return mPacked.begin(); }
     inline const T* end() const { return mPacked.end(); }
@@ -66,7 +66,7 @@ public:
 private:
     void sort() { std::sort(mPacked.begin(), mPacked.end()); }
 
-    PackedVector<T, ARRAY_SIZE> mPacked;
+    PackedVector<T, ARRAY_SIZE, SIZE_TYPE> mPacked;
 };
 
 }  // namespace minikin
diff --git a/libs/minikin/Android.bp b/libs/minikin/Android.bp
index d7db300..242bddd 100644
--- a/libs/minikin/Android.bp
+++ b/libs/minikin/Android.bp
@@ -76,6 +76,7 @@ cc_library {
         "Emoji.cpp",
         "Font.cpp",
         "FontCollection.cpp",
+        "FontFakery.cpp",
         "FontFamily.cpp",
         "FontFeatureUtils.cpp",
         "FontFileParser.cpp",
diff --git a/libs/minikin/Debug.cpp b/libs/minikin/Debug.cpp
index 8168a77..0a5ba62 100644
--- a/libs/minikin/Debug.cpp
+++ b/libs/minikin/Debug.cpp
@@ -118,6 +118,18 @@ std::string toString(const MinikinPaint& paint) {
     return ss.str();
 }
 
+std::string toString(const FontStyle& style) {
+    std::stringstream ss;
+    ss << "{ weight=" << style.weight() << ", italic=" << style.isItalic() << "}";
+    return ss.str();
+}
+
+std::string toString(const VariationSettings& varSettings) {
+    std::stringstream ss;
+    ss << varSettings;
+    return ss.str();
+}
+
 }  // namespace debug
 
 }  // namespace minikin
diff --git a/libs/minikin/FeatureFlags.h b/libs/minikin/FeatureFlags.h
index 88afdc2..36be29e 100644
--- a/libs/minikin/FeatureFlags.h
+++ b/libs/minikin/FeatureFlags.h
@@ -37,7 +37,7 @@ namespace features {
 #endif  //  __ANDROID__
 
 DEFINE_FEATURE_FLAG_ACCESSOROR(rust_hyphenator);
-DEFINE_FEATURE_FLAG_ACCESSOROR(typeface_redesign);
+DEFINE_FEATURE_FLAG_ACCESSOROR(typeface_redesign_readonly);
 
 }  // namespace features
 
diff --git a/libs/minikin/Font.cpp b/libs/minikin/Font.cpp
index 0d3d610..df2f4d2 100644
--- a/libs/minikin/Font.cpp
+++ b/libs/minikin/Font.cpp
@@ -22,10 +22,12 @@
 
 #include <vector>
 
+#include "FeatureFlags.h"
 #include "FontUtils.h"
 #include "LocaleListCache.h"
 #include "MinikinInternal.h"
 #include "minikin/Constants.h"
+#include "minikin/Hasher.h"
 #include "minikin/HbUtils.h"
 #include "minikin/MinikinFont.h"
 #include "minikin/MinikinFontFactory.h"
@@ -54,6 +56,10 @@ inline uint16_t packKey(int wght, int ital) {
 
 }  // namespace
 
+inline android::hash_t hash_type(const VariationSettings& vars) {
+    return Hasher().update(vars).hash();
+}
+
 std::shared_ptr<Font> Font::Builder::build() {
     if (mIsWeightSet && mIsSlantSet) {
         // No need to read OS/2 header of the font file.
@@ -93,7 +99,7 @@ Font::Font(BufferReader* reader)
     MinikinFontFactory::getInstance().skip(reader);
 }
 
-Font::Font(const std::shared_ptr<Font>& parent, const std::vector<FontVariation>& axes)
+Font::Font(const std::shared_ptr<Font>& parent, const VariationSettings& axes)
         : mExternalRefsHolder(nullptr), mTypefaceMetadataReader(nullptr) {
     mStyle = parent->style();
     mLocaleListId = parent->getLocaleListId();
@@ -324,7 +330,7 @@ HbFontUniquePtr Font::ExternalRefs::getAdjustedFont(int wght, int ital) const {
     return font;
 }
 
-const std::shared_ptr<MinikinFont>& Font::getAdjustedTypeface(int wght, int ital) const {
+std::shared_ptr<MinikinFont> Font::getAdjustedTypeface(int wght, int ital) const {
     return getExternalRefs()->getAdjustedTypeface(wght, ital);
 }
 
@@ -368,4 +374,82 @@ const std::shared_ptr<MinikinFont>& Font::ExternalRefs::getAdjustedTypeface(int
     return result_iterator->second;
 }
 
+HbFontUniquePtr Font::getAdjustedFont(const VariationSettings& axes) const {
+    return getExternalRefs()->getAdjustedFont(axes, getFVarTable());
+}
+
+HbFontUniquePtr Font::ExternalRefs::getAdjustedFont(const VariationSettings& axes,
+                                                    const FVarTable& table) const {
+    if (axes.empty()) {
+        return HbFontUniquePtr(hb_font_reference(mBaseFont.get()));
+    }
+
+    std::lock_guard<std::mutex> lock(mMutex);
+    HbFontUniquePtr* cached = mVarFontCache2.get(axes);
+    if (cached != nullptr) {
+        return HbFontUniquePtr(hb_font_reference(cached->get()));
+    }
+
+    HbFontUniquePtr font(hb_font_create_sub_font(mBaseFont.get()));
+    std::vector<hb_variation_t> variations;
+    variations.reserve(axes.size());
+    for (const FontVariation& variation : axes) {
+        auto it = table.find(variation.axisTag);
+        if (it == table.end() || it->second.defValue == variation.value) {
+            continue;
+        }
+        variations.push_back({variation.axisTag, variation.value});
+    }
+    hb_font_set_variations(font.get(), variations.data(), variations.size());
+    mVarFontCache2.put(axes, new HbFontUniquePtr(hb_font_reference(font.get())));
+    return font;
+}
+
+std::shared_ptr<MinikinFont> Font::getAdjustedTypeface(const VariationSettings& axes) const {
+    return getExternalRefs()->getAdjustedTypeface(axes, getFVarTable());
+}
+
+std::shared_ptr<MinikinFont> Font::ExternalRefs::getAdjustedTypeface(const VariationSettings& axes,
+                                                                     const FVarTable& table) const {
+    if (axes.empty()) {
+        return mTypeface;
+    }
+
+    std::lock_guard<std::mutex> lock(mMutex);
+    const std::shared_ptr<MinikinFont>& cached = mVarTypefaceCache2.get(axes);
+    if (cached != nullptr) {
+        return cached;
+    }
+
+    std::vector<FontVariation> variations;
+    variations.reserve(axes.size());
+    for (const FontVariation& variation : axes) {
+        auto it = table.find(variation.axisTag);
+        if (it == table.end() || it->second.defValue == variation.value) {
+            continue;
+        }
+        variations.push_back({variation.axisTag, variation.value});
+    }
+    std::shared_ptr<MinikinFont> newTypeface =
+            mTypeface->createFontWithVariation(VariationSettings(variations, false));
+    mVarTypefaceCache2.put(axes, newTypeface);
+    return mVarTypefaceCache2.get(axes);
+}
+
+HbFontUniquePtr FakedFont::hbFont() const {
+    if (features::typeface_redesign_readonly()) {
+        return font->getAdjustedFont(fakery.variationSettings());
+    } else {
+        return font->getAdjustedFont(fakery.wghtAdjustment(), fakery.italAdjustment());
+    }
+}
+
+std::shared_ptr<MinikinFont> FakedFont::typeface() const {
+    if (features::typeface_redesign_readonly()) {
+        return font->getAdjustedTypeface(fakery.variationSettings());
+    } else {
+        return font->getAdjustedTypeface(fakery.wghtAdjustment(), fakery.italAdjustment());
+    }
+}
+
 }  // namespace minikin
diff --git a/libs/minikin/FontCollection.cpp b/libs/minikin/FontCollection.cpp
index ded7643..41d8948 100644
--- a/libs/minikin/FontCollection.cpp
+++ b/libs/minikin/FontCollection.cpp
@@ -151,7 +151,7 @@ void FontCollection::init(const vector<std::shared_ptr<FontFamily>>& typefaces)
     std::unordered_set<AxisTag> supportedAxesSet;
     for (size_t i = 0; i < nTypefaces; i++) {
         const std::shared_ptr<FontFamily>& family = typefaces[i];
-        if (family->getClosestMatch(defaultStyle).font == nullptr) {
+        if (family->getNumFonts() == 0) {
             continue;
         }
         const SparseBitSet& coverage = family->getCoverage();
@@ -657,7 +657,8 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
 
         // Use this family
         MinikinExtent extent(0, 0);
-        FakedFont font = getFamilyAt(i)->getClosestMatch(paint.fontStyle);
+        FakedFont font =
+                getFamilyAt(i)->getClosestMatch(paint.fontStyle, paint.fontVariationSettings);
         font.typeface()->GetFontExtent(&extent, paint, font.fakery);
         result.extendBy(extent);
     }
@@ -684,7 +685,7 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
         }
 
         MinikinExtent extent(0, 0);
-        FakedFont font = family.getClosestMatch(paint.fontStyle);
+        FakedFont font = family.getClosestMatch(paint.fontStyle, paint.fontVariationSettings);
         font.typeface()->GetFontExtent(&extent, paint, font.fakery);
         result.extendBy(extent);
 
@@ -696,7 +697,7 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
     filterFamilyByLocale(requestedLocaleList, [&](const FontFamily& family) {
         // Use this family
         MinikinExtent extent(0, 0);
-        FakedFont font = family.getClosestMatch(paint.fontStyle);
+        FakedFont font = family.getClosestMatch(paint.fontStyle, paint.fontVariationSettings);
         font.typeface()->GetFontExtent(&extent, paint, font.fakery);
         result.extendBy(extent);
 
@@ -706,7 +707,8 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
 
     // If nothing matches, use default font.
     if (!familyFound) {
-        FakedFont font = getFamilyAt(0)->getClosestMatch(paint.fontStyle);
+        FakedFont font =
+                getFamilyAt(0)->getClosestMatch(paint.fontStyle, paint.fontVariationSettings);
         font.typeface()->GetFontExtent(&result, paint, font.fakery);
     }
 
@@ -866,7 +868,8 @@ std::vector<FontCollection::Run> FontCollection::itemize(U16StringPiece text, Fo
     return result;
 }
 
-FakedFont FontCollection::getBestFont(U16StringPiece text, const Run& run, FontStyle style) {
+FakedFont FontCollection::getBestFont(U16StringPiece text, const Run& run, FontStyle style,
+                                      const VariationSettings& variationSettings) {
     uint8_t bestIndex = 0;
     uint32_t bestScore = 0xFFFFFFFF;
 
@@ -885,7 +888,7 @@ FakedFont FontCollection::getBestFont(U16StringPiece text, const Run& run, FontS
     } else {
         bestIndex = run.familyMatch[0];
     }
-    return getFamilyAt(bestIndex)->getClosestMatch(style);
+    return getFamilyAt(bestIndex)->getClosestMatch(style, variationSettings);
 }
 
 FakedFont FontCollection::baseFontFaked(FontStyle style) {
@@ -893,7 +896,7 @@ FakedFont FontCollection::baseFontFaked(FontStyle style) {
 }
 
 std::shared_ptr<FontCollection> FontCollection::createCollectionWithVariation(
-        const std::vector<FontVariation>& variations) {
+        const VariationSettings& variations) {
     if (variations.empty() || mSupportedAxesCount == 0) {
         return nullptr;
     }
diff --git a/libs/minikin/FontFakery.cpp b/libs/minikin/FontFakery.cpp
new file mode 100644
index 0000000..4461c6c
--- /dev/null
+++ b/libs/minikin/FontFakery.cpp
@@ -0,0 +1,177 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include "minikin/FontFakery.h"
+
+#include "minikin/Constants.h"
+#include "minikin/FVarTable.h"
+#include "minikin/FontStyle.h"
+#include "minikin/FontVariation.h"
+
+namespace minikin {
+
+FontFakery merge(const FVarTable& fvar, const VariationSettings& baseVS,
+                 const VariationSettings& targetVS, FontStyle baseStyle, FontStyle targetStyle) {
+    const bool hasItal = fvar.count(TAG_ital);
+    const bool hasSlnt = fvar.count(TAG_slnt);
+    const bool hasWght = fvar.count(TAG_wght);
+
+    // Reserve size of base and target plus 2 which is the upper bounds resolved axes.
+    FontVariation* adjustedVars;
+    constexpr uint32_t FIXED_BUFFER_SIZE = 8;
+    FontVariation fixedBuffer[FIXED_BUFFER_SIZE];
+    std::unique_ptr<FontVariation[]> heap;
+    if (baseVS.size() + targetVS.size() + 2 > FIXED_BUFFER_SIZE) {
+        heap = std::make_unique<FontVariation[]>(baseVS.size() + targetVS.size() + 2);
+        adjustedVars = heap.get();
+    } else {
+        adjustedVars = fixedBuffer;
+    }
+
+    // Convert target font style into font variation settings.
+    FontVariation styleVars[2];
+    uint32_t styleVarsSize = 0;
+    if (hasSlnt) {
+        if (targetStyle.slant() == FontStyle::Slant::ITALIC) {
+            styleVars[styleVarsSize++] = {TAG_slnt, -10};
+        } else {
+            styleVars[styleVarsSize++] = {TAG_slnt, 0};
+        }
+    } else if (hasItal) {
+        if (targetStyle.slant() == FontStyle::Slant::ITALIC) {
+            styleVars[styleVarsSize++] = {TAG_ital, 1};
+        } else {
+            styleVars[styleVarsSize++] = {TAG_ital, 0};
+        }
+    }
+    if (hasWght) {
+        styleVars[styleVarsSize++] = {TAG_wght, static_cast<float>(targetStyle.weight())};
+    }
+
+    // Main merge loop: do the three sorted array merge.
+    constexpr uint32_t END = 0xFFFFFFFF;
+    bool fakeBold;
+    uint32_t baseIdx = 0;
+    uint32_t targetIdx = 0;
+    uint32_t styleIdx = 0;
+
+    uint32_t adjustedHead = 0;  // head of the output vector.
+    while (baseIdx < baseVS.size() || targetIdx < targetVS.size() || styleIdx < styleVarsSize) {
+        const AxisTag baseTag = baseIdx < baseVS.size() ? baseVS[baseIdx].axisTag : END;
+        const AxisTag targetTag = targetIdx < targetVS.size() ? targetVS[targetIdx].axisTag : END;
+        const AxisTag styleTag = styleIdx < styleVarsSize ? styleVars[styleIdx].axisTag : END;
+
+        AxisTag tag;
+        float value;
+        bool styleValueUsed = false;
+        if (baseTag < targetTag) {
+            if (styleTag < baseTag) {
+                // style < base < target: only process style.
+                tag = styleTag;
+                value = styleVars[styleIdx].value;
+                styleValueUsed = true;
+                styleIdx++;
+            } else if (styleTag == baseTag) {
+                // style == base < target: process base and style. base is used.
+                tag = styleTag;
+                value = baseVS[baseIdx].value;
+                baseIdx++;
+                styleIdx++;
+            } else {
+                //  base < style < target: only process base.
+                tag = baseTag;
+                value = baseVS[baseIdx].value;
+                baseIdx++;
+            }
+        } else if (targetTag < baseTag) {
+            if (styleTag < targetTag) {
+                // style < target < base: process style only.
+                tag = styleTag;
+                value = styleVars[styleIdx].value;
+                styleValueUsed = true;
+                styleIdx++;
+            } else if (styleTag == targetTag) {
+                // style = target < base: process style and target. target is used.
+                tag = targetTag;
+                value = targetVS[targetIdx].value;
+                styleIdx++;
+                targetIdx++;
+            } else {
+                // target < style < base: process target only.
+                tag = targetTag;
+                value = targetVS[targetIdx].value;
+                targetIdx++;
+            }
+        } else {
+            if (styleTag < baseTag) {
+                // style < base == target: only process style.
+                tag = styleTag;
+                value = styleVars[styleIdx].value;
+                styleValueUsed = true;
+                styleIdx++;
+            } else if (styleTag == baseTag) {
+                //  base == target == style: process all. target is used.
+                tag = targetTag;
+                value = targetVS[targetIdx].value;
+                baseIdx++;
+                targetIdx++;
+                styleIdx++;
+            } else {
+                //  base == target < style: process base and target. target is used.
+                tag = targetTag;
+                value = targetVS[targetIdx].value;
+                baseIdx++;
+                targetIdx++;
+            }
+        }
+
+        const auto& it = fvar.find(tag);
+        if (it == fvar.end()) {
+            continue;  // unsupported axis. Skip.
+        }
+        const FVarEntry& fvarEntry = it->second;
+
+        if (styleValueUsed && value == fvarEntry.defValue) {
+            // Skip the default value if it came from style.
+            continue;
+        }
+        const float clamped = std::clamp(value, fvarEntry.minValue, fvarEntry.maxValue);
+        adjustedVars[adjustedHead++] = {tag, clamped};
+        if (tag == TAG_wght) {
+            // Fake bold is enabled when the max value is more than 200 of difference.
+            fakeBold = targetStyle.weight() >= 600 && (targetStyle.weight() - clamped) >= 200;
+        }
+    }
+
+    // Fake weight is enabled when the TAG_wght is not supported and the weight value has more than
+    // 200 of difference.
+    if (!hasWght) {
+        fakeBold =
+                targetStyle.weight() >= 600 && (targetStyle.weight() - baseStyle.weight()) >= 200;
+    }
+    // Fake italic is enabled when the style is italic and font doesn't support ital or slnt axis.
+    bool fakeItalic = false;
+    if (targetStyle.isItalic()) {
+        if (hasItal || hasSlnt) {
+            fakeItalic = false;
+        } else {
+            fakeItalic = !baseStyle.isItalic();
+        }
+    }
+    return FontFakery(fakeBold, fakeItalic, VariationSettings(adjustedVars, adjustedHead));
+}
+
+}  // namespace minikin
diff --git a/libs/minikin/FontFamily.cpp b/libs/minikin/FontFamily.cpp
index d821ea0..42cd07e 100644
--- a/libs/minikin/FontFamily.cpp
+++ b/libs/minikin/FontFamily.cpp
@@ -22,6 +22,7 @@
 #include <unordered_set>
 #include <vector>
 
+#include "FeatureFlags.h"
 #include "FontUtils.h"
 #include "Locale.h"
 #include "LocaleListCache.h"
@@ -64,7 +65,7 @@ std::shared_ptr<FontFamily> FontFamily::create(uint32_t localeListId, FamilyVari
 }
 
 std::shared_ptr<FontFamily> FontFamily::create(const std::shared_ptr<FontFamily>& parent,
-                                               const std::vector<FontVariation>& axes) {
+                                               const VariationSettings& axes) {
     if (axes.empty() || parent->getSupportedAxesCount() == 0) {
         return nullptr;
     }
@@ -87,7 +88,7 @@ std::shared_ptr<FontFamily> FontFamily::create(const std::shared_ptr<FontFamily>
 }
 
 FontFamily::FontFamily(const std::shared_ptr<FontFamily>& parent,
-                       const std::vector<FontVariation>& axesOverride)
+                       const VariationSettings& axesOverride)
         : mFonts(),
           mSupportedAxes(std::make_unique<AxisTag[]>(parent->getSupportedAxesCount())),
           mCoverage(),
@@ -102,7 +103,8 @@ FontFamily::FontFamily(const std::shared_ptr<FontFamily>& parent,
           mIsColorEmoji(parent->mIsColorEmoji),
           mIsCustomFallback(parent->mIsCustomFallback),
           mIsDefaultFallback(parent->mIsDefaultFallback),
-          mVarFamilyType(VariationFamilyType::None) {
+          mVarFamilyType(VariationFamilyType::None),
+          mIsVariationFamily(true) {
     // Filter only the axis supported font.
     std::vector<std::shared_ptr<Font>> overriddenFonts;
     for (uint16_t i = 0; i < mFontsCount; ++i) {
@@ -147,7 +149,8 @@ FontFamily::FontFamily(uint32_t localeListId, FamilyVariant variant,
                         EmojiStyle::EMOJI),
           mIsCustomFallback(isCustomFallback),
           mIsDefaultFallback(isDefaultFallback),
-          mVarFamilyType(varFamilyType) {
+          mVarFamilyType(varFamilyType),
+          mIsVariationFamily(false) {
     MINIKIN_ASSERT(!fonts.empty(), "FontFamily must contain at least one font.");
     MINIKIN_ASSERT(fonts.size() <= std::numeric_limits<uint32_t>::max(),
                    "Number of fonts must be less than 2^32.");
@@ -183,6 +186,7 @@ FontFamily::FontFamily(BufferReader* reader, const std::shared_ptr<std::vector<F
     mIsCustomFallback = static_cast<bool>(reader->read<uint8_t>());
     mIsDefaultFallback = static_cast<bool>(reader->read<uint8_t>());
     mVarFamilyType = reader->read<VariationFamilyType>();
+    mIsVariationFamily = false;
     mCoverage = SparseBitSet(reader);
     // Read mCmapFmt14Coverage. As it can have null entries, it is stored in the buffer as a sparse
     // array (size, non-null entry count, array of (index, entry)).
@@ -300,7 +304,36 @@ static FontFakery computeFakery(FontStyle wanted, FontStyle actual) {
     return FontFakery(isFakeBold, isFakeItalic);
 }
 
-FakedFont FontFamily::getClosestMatch(FontStyle style) const {
+FakedFont FontFamily::getClosestMatch(FontStyle style, const VariationSettings& axes) const {
+    if (features::typeface_redesign_readonly()) {
+        int bestIndex = 0;
+        Font* bestFont = mFonts[bestIndex].get();
+        int bestMatch = computeMatch(bestFont->style(), style);
+        for (size_t i = 1; i < mFontsCount; i++) {
+            Font* font = mFonts[i].get();
+            int match = computeMatch(font->style(), style);
+            if (i == 0 || match < bestMatch) {
+                bestFont = font;
+                bestIndex = i;
+                bestMatch = match;
+            }
+        }
+
+        if (mIsVariationFamily) {
+            // For backward compatibility reasons, we don't merge the variation settings because it
+            // is developer provided configuration.
+            return FakedFont{mFonts[bestIndex], computeFakery(style, bestFont->style())};
+        }
+
+        if (axes.empty() && style == bestFont->style()) {
+            // Easy case, no merge is necessary.
+            return FakedFont{mFonts[bestIndex], FontFakery(false, false)};
+        }
+        FontFakery fakery = merge(bestFont->getFVarTable(), bestFont->baseTypeface()->GetAxes(),
+                                  axes, bestFont->style(), style);
+        return FakedFont(mFonts[bestIndex], fakery);
+    }
+
     if (mVarFamilyType != VariationFamilyType::None) {
         return getVariationFamilyAdjustment(style);
     }
@@ -334,7 +367,7 @@ FakedFont FontFamily::getVariationFamilyAdjustment(FontStyle style) const {
 }
 
 void FontFamily::computeCoverage() {
-    const std::shared_ptr<Font>& font = getClosestMatch(FontStyle()).font;
+    const std::shared_ptr<Font>& font = getClosestMatch(FontStyle(), VariationSettings()).font;
     HbBlob cmapTable(font->baseFont(), MakeTag('c', 'm', 'a', 'p'));
     if (cmapTable.get() == nullptr) {
         ALOGE("Could not get cmap table size!\n");
@@ -398,7 +431,7 @@ bool FontFamily::hasGlyph(uint32_t codepoint, uint32_t variationSelector) const
 }
 
 std::shared_ptr<FontFamily> FontFamily::createFamilyWithVariation(
-        const std::vector<FontVariation>& variations) const {
+        const VariationSettings& variations) const {
     if (variations.empty() || mSupportedAxesCount == 0) {
         return nullptr;
     }
diff --git a/libs/minikin/Layout.cpp b/libs/minikin/Layout.cpp
index e612130..ca90668 100644
--- a/libs/minikin/Layout.cpp
+++ b/libs/minikin/Layout.cpp
@@ -68,7 +68,11 @@ void adjustGlyphLetterSpacingEdge(const U16StringPiece& textBuf, const MinikinPa
             if (!isLetterSpacingCapableCodePoint(cp)) {
                 break;
             }
-            glyphs->at(i).x -= letterSpacingHalf;
+            if (paint.verticalText) {
+                glyphs->at(i).y -= letterSpacingHalf;
+            } else {
+                glyphs->at(i).x -= letterSpacingHalf;
+            }
         }
     }
 
@@ -87,7 +91,11 @@ void adjustGlyphLetterSpacingEdge(const U16StringPiece& textBuf, const MinikinPa
 
         if (i < glyphCount) {
             for (uint32_t j = glyphCount - i; j < glyphCount; ++j) {
-                glyphs->at(j).x -= letterSpacingHalf;
+                if (paint.verticalText) {
+                    glyphs->at(j).y -= letterSpacingHalf;
+                } else {
+                    glyphs->at(j).x -= letterSpacingHalf;
+                }
             }
         }
     }
@@ -180,12 +188,21 @@ void adjustBoundsLetterSpacingEdge(const MinikinPaint& paint, RunFlag runFlag,
         return;
     }
     if (runFlag & RunFlag::LEFT_EDGE) {
-        bounds->mLeft -= letterSpacingHalf;
-        bounds->mRight -= letterSpacingHalf;
+        if (paint.verticalText) {
+            bounds->mTop -= letterSpacingHalf;
+            bounds->mBottom -= letterSpacingHalf;
+        } else {
+            bounds->mLeft -= letterSpacingHalf;
+            bounds->mRight -= letterSpacingHalf;
+        }
     }
 
     if (runFlag & RunFlag::RIGHT_EDGE) {
-        bounds->mRight -= letterSpacingHalf;
+        if (paint.verticalText) {
+            bounds->mBottom -= letterSpacingHalf;
+        } else {
+            bounds->mRight -= letterSpacingHalf;
+        }
     }
 }
 
@@ -232,7 +249,11 @@ float Layout::measureText(const U16StringPiece& textBuf, const Range& range, Bid
                                               startHyphen, endHyphen, nullptr, advancesForRun,
                                               bounds ? &tmpBounds : nullptr, clusterCount);
         if (bounds) {
-            bounds->join(tmpBounds, advance, 0);
+            if (paint.verticalText) {
+                bounds->join(tmpBounds, 0, advance);
+            } else {
+                bounds->join(tmpBounds, advance, 0);
+            }
         }
         advance += run_advance;
     }
@@ -266,7 +287,11 @@ float Layout::doLayoutRunCached(const U16StringPiece& textBuf, const Range& rang
                 pieceStartHyphen, pieceEndHyphen, layout, advancesForRun,
                 bounds ? &tmpBounds : nullptr, clusterCount);
         if (bounds) {
-            bounds->join(tmpBounds, advance, 0);
+            if (paint.verticalText) {
+                bounds->join(tmpBounds, 0, advance);
+            } else {
+                bounds->join(tmpBounds, advance, 0);
+            }
         }
         advance += word_advance;
     }
@@ -289,11 +314,14 @@ public:
             mLayout->appendLayout(layoutPiece, mOutOffset, mWordSpacing);
         }
         if (mAdvances) {
-            const std::vector<float>& advances = layoutPiece.advances();
-            std::copy(advances.begin(), advances.end(), mAdvances);
+            std::copy(layoutPiece.advances().begin(), layoutPiece.advances().end(), mAdvances);
         }
         if (mBounds) {
-            mBounds->join(bounds, mTotalAdvance, 0);
+            if (layoutPiece.isVerticalText()) {
+                mBounds->join(bounds, 0, mTotalAdvance);
+            } else {
+                mBounds->join(bounds, mTotalAdvance, 0);
+            }
         }
         mTotalAdvance += layoutPiece.advance();
         mClusterCount += layoutPiece.clusterCount();
@@ -340,7 +368,9 @@ float Layout::doLayoutWord(const uint16_t* buf, size_t start, size_t count, size
 }
 
 void Layout::appendLayout(const LayoutPiece& src, size_t start, float extraAdvance) {
-    if (features::typeface_redesign()) {
+    float xAdvance = src.isVerticalText() ? 0 : mAdvance;
+    float yAdvance = src.isVerticalText() ? mAdvance : 0;
+    if (features::typeface_redesign_readonly()) {
         if (src.glyphCount() == 0) {
             return;
         }
@@ -363,15 +393,15 @@ void Layout::appendLayout(const LayoutPiece& src, size_t start, float extraAdvan
             }
 
             mGlyphs.emplace_back(src.fontAt(i), src.glyphIdAt(i), src.clusterAt(i) + start,
-                                 mAdvance + src.pointAt(i).x, src.pointAt(i).y);
+                                 xAdvance + src.pointAt(i).x, yAdvance + src.pointAt(i).y);
         }
     } else {
         for (size_t i = 0; i < src.glyphCount(); i++) {
             mGlyphs.emplace_back(src.fontAt(i), src.glyphIdAt(i), src.clusterAt(i) + start,
-                                 mAdvance + src.pointAt(i).x, src.pointAt(i).y);
+                                 xAdvance + src.pointAt(i).x, yAdvance + src.pointAt(i).y);
         }
     }
-    const std::vector<float>& advances = src.advances();
+    const AdvanceVector& advances = src.advances();
     for (size_t i = 0; i < advances.size(); i++) {
         mAdvances[i + start] = advances[i];
         if (i == 0) {
diff --git a/libs/minikin/LayoutCore.cpp b/libs/minikin/LayoutCore.cpp
index b32566b..06dd709 100644
--- a/libs/minikin/LayoutCore.cpp
+++ b/libs/minikin/LayoutCore.cpp
@@ -301,10 +301,11 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
     double size = paint.size;
     double scaleX = paint.scaleX;
 
-    std::unordered_map<const MinikinFont*, uint32_t> fontMap;
+    std::unordered_map<std::shared_ptr<MinikinFont>, uint32_t> fontMap;
 
     float x = 0;
     float y = 0;
+    float* dir = paint.verticalText ? &y : &x;
 
     constexpr uint32_t MAX_LENGTH_FOR_BITSET = 256;  // std::bit_ceil(CHAR_LIMIT_FOR_CACHE);
     std::bitset<MAX_LENGTH_FOR_BITSET> clusterSet;
@@ -315,22 +316,23 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
          isRtl ? run_ix >= 0 : run_ix < static_cast<int>(items.size());
          isRtl ? --run_ix : ++run_ix) {
         FontCollection::Run& run = items[run_ix];
-        FakedFont fakedFont = paint.font->getBestFont(substr, run, paint.fontStyle);
-        const std::shared_ptr<MinikinFont>& typeface = fakedFont.typeface();
-        auto it = fontMap.find(typeface.get());
+        FakedFont fakedFont =
+                paint.font->getBestFont(substr, run, paint.fontStyle, paint.fontVariationSettings);
+        std::shared_ptr<MinikinFont> typeface = fakedFont.typeface();
+        auto it = fontMap.find(typeface);
         uint8_t font_ix;
         if (it == fontMap.end()) {
             // First time to see this font.
             font_ix = mFonts.size();
             mFonts.push_back(fakedFont);
-            fontMap.insert(std::make_pair(typeface.get(), font_ix));
+            fontMap.insert(std::make_pair(typeface, font_ix));
 
             // We override some functions which are not thread safe.
             HbFontUniquePtr font(hb_font_create_sub_font(fakedFont.hbFont().get()));
-            hb_font_set_funcs(
-                    font.get(), isColorBitmapFont(font) ? getFontFuncsForEmoji() : getFontFuncs(),
-                    new SkiaArguments({fakedFont.typeface().get(), &paint, fakedFont.fakery}),
-                    [](void* data) { delete reinterpret_cast<SkiaArguments*>(data); });
+            hb_font_set_funcs(font.get(),
+                              isColorBitmapFont(font) ? getFontFuncsForEmoji() : getFontFuncs(),
+                              new SkiaArguments({typeface.get(), &paint, fakedFont.fakery}),
+                              [](void* data) { delete reinterpret_cast<SkiaArguments*>(data); });
             hbFonts.push_back(std::move(font));
         } else {
             font_ix = it->second;
@@ -380,7 +382,11 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
 
             hb_buffer_clear_contents(buffer.get());
             hb_buffer_set_script(buffer.get(), script);
-            hb_buffer_set_direction(buffer.get(), isRtl ? HB_DIRECTION_RTL : HB_DIRECTION_LTR);
+            if (paint.verticalText) {
+                hb_buffer_set_direction(buffer.get(), HB_DIRECTION_TTB);
+            } else {
+                hb_buffer_set_direction(buffer.get(), isRtl ? HB_DIRECTION_RTL : HB_DIRECTION_LTR);
+            }
             const LocaleList& localeList = LocaleListCache::getById(paint.localeListId);
             if (localeList.size() != 0) {
                 hb_language_t hbLanguage = localeList.getHbLanguage(0);
@@ -416,7 +422,7 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
                 const uint32_t cp = textBuf.codePointAt(advIndex + start);
                 if (!u_iscntrl(cp)) {
                     mAdvances[advIndex] += letterSpaceHalf;
-                    x += letterSpaceHalf;
+                    *dir += letterSpaceHalf;
                 }
             }
             for (unsigned int i = 0; i < numGlyphs; i++) {
@@ -439,9 +445,9 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
                     // To avoid rounding error, add full letter spacing when the both prev and
                     // current code point are non-control characters.
                     if (!isCtrl && !isPrevCtrl) {
-                        x += letterSpace;
+                        *dir += letterSpace;
                     } else if (!isCtrl || !isPrevCtrl) {
-                        x += letterSpaceHalf;
+                        *dir += letterSpaceHalf;
                     }
                 }
 
@@ -451,8 +457,9 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
                 xoff += yoff * paint.skewX;
                 mFontIndices.push_back(font_ix);
                 mGlyphIds.push_back(glyph_ix);
-                mPoints.emplace_back(x + xoff, y + yoff);
-                float xAdvance = HBFixedToFloat(positions[i].x_advance);
+                mPoints.push_back({x + xoff, y + yoff});
+                float advance = paint.verticalText ? -HBFixedToFloat(positions[i].y_advance)
+                                                   : HBFixedToFloat(positions[i].x_advance);
                 mClusters.push_back(clusterBaseIndex);
                 if (useLargeSet) {
                     clusterSetForLarge.insert(clusterBaseIndex);
@@ -461,19 +468,19 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
                 }
 
                 if (clusterBaseIndex < count) {
-                    mAdvances[clusterBaseIndex] += xAdvance;
+                    mAdvances[clusterBaseIndex] += advance;
                 } else {
                     ALOGE("cluster %zu (start %zu) out of bounds of count %zu", clusterBaseIndex,
                           start, count);
                 }
-                x += xAdvance;
+                *dir += advance;
             }
             if (numGlyphs && letterSpace != 0) {
                 const uint32_t lastAdvIndex = info[numGlyphs - 1].cluster - clusterOffset;
                 const uint32_t lastCp = textBuf.codePointAt(lastAdvIndex + start);
                 if (!u_iscntrl(lastCp)) {
                     mAdvances[lastAdvIndex] += letterSpaceHalf;
-                    x += letterSpaceHalf;
+                    *dir += letterSpaceHalf;
                 }
             }
         }
@@ -482,12 +489,13 @@ LayoutPiece::LayoutPiece(const U16StringPiece& textBuf, const Range& range, bool
     mGlyphIds.shrink_to_fit();
     mPoints.shrink_to_fit();
     mClusters.shrink_to_fit();
-    mAdvance = x;
+    mAdvance = *dir;
     if (useLargeSet) {
         mClusterCount = clusterSetForLarge.size();
     } else {
         mClusterCount = clusterSet.count();
     }
+    mVerticalText = paint.verticalText;
 }
 
 // static
diff --git a/libs/minikin/MeasuredText.cpp b/libs/minikin/MeasuredText.cpp
index 20d5aa3..cd32bd0 100644
--- a/libs/minikin/MeasuredText.cpp
+++ b/libs/minikin/MeasuredText.cpp
@@ -39,8 +39,8 @@ public:
 
     void operator()(const LayoutPiece& layoutPiece, const MinikinPaint& paint,
                     const MinikinRect& bounds) {
-        const std::vector<float>& advances = layoutPiece.advances();
-        std::copy(advances.begin(), advances.end(), mOutAdvances->begin() + mRange.getStart());
+        std::copy(layoutPiece.advances().begin(), layoutPiece.advances().end(),
+                  mOutAdvances->begin() + mRange.getStart());
 
         if (bounds.mLeft < 0 || bounds.mRight > layoutPiece.advance()) {
             for (uint32_t i : mRange) {
@@ -262,7 +262,11 @@ public:
 
     void operator()(const LayoutPiece& layoutPiece, const MinikinPaint& /* paint */,
                     const MinikinRect& bounds) {
-        mBounds.join(bounds, mAdvance, 0);
+        if (layoutPiece.isVerticalText()) {
+            mBounds.join(bounds, 0, mAdvance);
+        } else {
+            mBounds.join(bounds, mAdvance, 0);
+        }
         mAdvance += layoutPiece.advance();
     }
 
@@ -381,7 +385,16 @@ MinikinRect MeasuredText::getBounds(const U16StringPiece& textBuf, const Range&
         }
         auto[advance, bounds] =
                 run->getBounds(textBuf, Range::intersection(runRange, range), layoutPieces);
-        rect.join(bounds, totalAdvance, 0);
+        const MinikinPaint* paint = run->getPaint();
+        if (paint != nullptr) {
+            if (paint->verticalText) {
+                rect.join(bounds, 0, totalAdvance);
+            } else {
+                rect.join(bounds, totalAdvance, 0);
+            }
+        } else {
+            rect.join(bounds, totalAdvance, 0);
+        }
         totalAdvance += advance;
     }
     return rect;
diff --git a/libs/minikin/Measurement.cpp b/libs/minikin/Measurement.cpp
index 413dab9..724cde0 100644
--- a/libs/minikin/Measurement.cpp
+++ b/libs/minikin/Measurement.cpp
@@ -197,7 +197,11 @@ struct BoundsComposer {
 
     void operator()(const LayoutPiece& layoutPiece, const MinikinPaint& /* paint */,
                     const MinikinRect& bounds) {
-        mBounds.join(bounds, mAdvance, 0);
+        if (layoutPiece.isVerticalText()) {
+            mBounds.join(bounds, 0, mAdvance);
+        } else {
+            mBounds.join(bounds, mAdvance, 0);
+        }
         mAdvance += layoutPiece.advance();
     }
 
diff --git a/tests/unittest/FontCollectionTest.cpp b/tests/unittest/FontCollectionTest.cpp
index 28e6094..8790a90 100644
--- a/tests/unittest/FontCollectionTest.cpp
+++ b/tests/unittest/FontCollectionTest.cpp
@@ -14,9 +14,12 @@
  * limitations under the License.
  */
 
+#include <com_android_text_flags.h>
+#include <flag_macros.h>
 #include <gtest/gtest.h>
 
 #include "FontTestUtils.h"
+#include "FontVariationTestUtils.h"
 #include "FreeTypeMinikinFontForTest.h"
 #include "MinikinInternal.h"
 #include "minikin/Constants.h"
@@ -332,4 +335,44 @@ TEST(FontCollectionTest, FamilyMatchResultTest_intersect) {
                                                            Builder().add(1).add(3).add(5).build()));
 }
 
+TEST_WITH_FLAGS(FontCollectionTest, getBestFont,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
+                                                    typeface_redesign_readonly))) {
+    FreeTypeMinikinFontForTestFactory::init();
+
+    const uint32_t localeListId = registerLocaleList("en-US");
+
+    auto minikinFont = std::make_shared<FreeTypeMinikinFontForTest>(
+            getTestFontPath("WeightEqualsEmVariableFont.ttf"));
+    auto font = Font::Builder(minikinFont).build();
+    auto family = FontFamily::create({font});
+    auto fc = FontCollection::create({family});
+
+    auto getBestFont = [&](FontStyle style, const VariationSettings& varSettings) -> FakedFont {
+        std::vector<uint16_t> text = {'a'};
+        auto runs = fc->itemize(text, style, localeListId, FamilyVariant::DEFAULT, 1);
+        EXPECT_EQ(1u, runs.size());
+        return fc->getBestFont(text, runs[0], style, varSettings);
+    };
+
+    EXPECT_EQ(parseVariationSettings(""),
+              getBestFont(FontStyle(), VariationSettings()).fakery.variationSettings());
+    EXPECT_EQ(parseVariationSettings("'wght' 700"),
+              getBestFont(FontStyle(FontStyle::Weight::BOLD), VariationSettings())
+                      .fakery.variationSettings());
+    EXPECT_EQ(parseVariationSettings("'wght' 700"),
+              getBestFont(FontStyle(), parseVariationSettings("'wght' 700"))
+                      .fakery.variationSettings());
+    EXPECT_EQ(parseVariationSettings("'ital' 1"),
+              getBestFont(FontStyle(FontStyle::Slant::ITALIC), VariationSettings())
+                      .fakery.variationSettings());
+    EXPECT_EQ(parseVariationSettings("'ital' 1, 'wght' 500"),
+              getBestFont(FontStyle(FontStyle::Weight::MEDIUM, FontStyle::Slant::ITALIC),
+                          VariationSettings())
+                      .fakery.variationSettings());
+    EXPECT_EQ(parseVariationSettings("'ital' 1, 'wght' 500"),
+              getBestFont(FontStyle(FontStyle::Slant::ITALIC), parseVariationSettings("'wght' 500"))
+                      .fakery.variationSettings());
+}
+
 }  // namespace minikin
diff --git a/tests/unittest/FontFakeryTest.cpp b/tests/unittest/FontFakeryTest.cpp
index b0fe521..5422a7d 100644
--- a/tests/unittest/FontFakeryTest.cpp
+++ b/tests/unittest/FontFakeryTest.cpp
@@ -16,11 +16,35 @@
 
 #include <gtest/gtest.h>
 
+#include "FontVariationTestUtils.h"
 #include "minikin/Constants.h"
 #include "minikin/FontFakery.h"
 
 namespace minikin {
 
+namespace {
+
+constexpr FontStyle THIN = FontStyle(FontStyle::Weight::THIN, FontStyle::Slant::UPRIGHT);
+constexpr FontStyle REGULAR = FontStyle(FontStyle::Weight::NORMAL, FontStyle::Slant::UPRIGHT);
+constexpr FontStyle MEDIUM = FontStyle(FontStyle::Weight::MEDIUM, FontStyle::Slant::UPRIGHT);
+constexpr FontStyle BOLD = FontStyle(FontStyle::Weight::BOLD, FontStyle::Slant::UPRIGHT);
+constexpr FontStyle BLACK = FontStyle(FontStyle::Weight::BLACK, FontStyle::Slant::UPRIGHT);
+constexpr FontStyle ITALIC = FontStyle(FontStyle::Weight::NORMAL, FontStyle::Slant::ITALIC);
+constexpr FontStyle BOLD_ITALIC = FontStyle(FontStyle::Weight::BOLD, FontStyle::Slant::ITALIC);
+
+FontFakery merge(const FVarTable& fvar, const std::string& base, const std::string& target,
+                 FontStyle baseStyle, FontStyle targetStyle) {
+    return merge(fvar, parseVariationSettings(base), parseVariationSettings(target), baseStyle,
+                 targetStyle);
+}
+
+}  // namespace
+
+inline bool operator==(const char* expect, const VariationSettings& vs) {
+    VariationSettings expectVarSettings = parseVariationSettings(expect);
+    return expectVarSettings == vs;
+}
+
 TEST(FontFakeryTest, testConstruct) {
     EXPECT_EQ(FontFakery(), FontFakery(false, false));
     EXPECT_NE(FontFakery(), FontFakery(true, false));
@@ -57,4 +81,144 @@ TEST(FontFakeryTest, testVariationSettings) {
     EXPECT_EQ(400, ff.variationSettings()[1].value);
 }
 
+TEST(FontFakeryTest, testMerge) {
+    FVarTable fvar = {{MakeTag('A', 'B', 'C', 'D'), {0, 100, 50}}};
+
+    // Override should be used.
+    EXPECT_EQ("'ABCD' 100", merge(fvar, "", "'ABCD' 100", REGULAR, REGULAR).variationSettings());
+    // Base should be remains
+    EXPECT_EQ("'ABCD' 0", merge(fvar, "'ABCD' 0", "", REGULAR, REGULAR).variationSettings());
+    // The default value from the target VS should be preserved.
+    EXPECT_EQ("'ABCD' 50", merge(fvar, "", "'ABCD' 50", REGULAR, REGULAR).variationSettings());
+    // Override should override the base settings.
+    EXPECT_EQ("'ABCD' 100",
+              merge(fvar, "'ABCD' 0", "'ABCD' 100", REGULAR, REGULAR).variationSettings());
+}
+
+TEST(FontFakeryTest, testMerge_twoAxes) {
+    FVarTable fvar = {{MakeTag('A', 'B', 'C', 'D'), {0, 100, 50}},
+                      {MakeTag('E', 'F', 'G', 'H'), {0, 100, 50}}};
+
+    // Different axes should be preserved.
+    EXPECT_EQ("'ABCD' 100, 'EFGH' 100",
+              merge(fvar, "'ABCD' 100", "'EFGH' 100", REGULAR, REGULAR).variationSettings());
+    // Overrides override only matched axis.
+    EXPECT_EQ(
+            "'ABCD' 0, 'EFGH' 100",
+            merge(fvar, "'ABCD' 0, 'EFGH' 0", "'EFGH' 100", REGULAR, REGULAR).variationSettings());
+}
+
+TEST(FontFakeryTest, testMerge_styleWeight) {
+    FVarTable fvar = {{TAG_wght, {100, 900, 400}}, {TAG_ital, {0, 1, 0}}};
+
+    // Default FontStyle sets wght 400 and it is dropped.
+    EXPECT_EQ("", merge(fvar, "", "", REGULAR, REGULAR).variationSettings());
+    // Use weight of FontStyle if no override is specified.
+    EXPECT_EQ("'wght' 100", merge(fvar, "", "", REGULAR, THIN).variationSettings());
+    // If override is spseicied, it is used instead of FontStyle.
+    EXPECT_EQ("'wght' 500", merge(fvar, "", "'wght' 500", REGULAR, THIN).variationSettings());
+}
+
+TEST(FontFakeryTest, testMerge_styleItal) {
+    FVarTable fvar = {{TAG_wght, {100, 900, 400}}, {TAG_ital, {0, 1, 0}}};
+
+    // Use weight of FontStyle if no override is specified.
+    EXPECT_EQ("'ital' 1", merge(fvar, "", "", REGULAR, ITALIC).variationSettings());
+    EXPECT_EQ("'ital' 1", merge(fvar, "'ital' 1", "", REGULAR, REGULAR).variationSettings());
+    EXPECT_EQ("'ital' 0", merge(fvar, "'ital' 0", "", REGULAR, ITALIC).variationSettings());
+    // If override is spseicied, it is used instead of FontStyle.
+    EXPECT_EQ("'ital' 0", merge(fvar, "", "'ital' 0", REGULAR, ITALIC).variationSettings());
+}
+
+TEST(FontFakeryTest, testMerge_styleSlnt) {
+    FVarTable fvar = {{TAG_wght, {100, 900, 400}}, {TAG_slnt, {-10, 0, 0}}};
+
+    // Use weight of FontStyle if no override is specified.
+    EXPECT_EQ("'slnt' -10", merge(fvar, "", "", REGULAR, ITALIC).variationSettings());
+    // If override is spseicied, it is used instead of FontStyle.
+    EXPECT_EQ("'slnt' 0", merge(fvar, "", "'slnt' 0", REGULAR, ITALIC).variationSettings());
+}
+
+TEST(FontFakeryTest, testMerge_complex) {
+    FVarTable fvar = {
+            {TAG_wght, {100, 900, 400}},
+            {TAG_slnt, {-10, 0, 0}},
+            {MakeTag('A', 'B', 'C', 'D'), {0, 100, 50}},
+    };
+
+    EXPECT_EQ("'wght' 750, 'slnt' -10, 'ABCD' 75",
+              merge(fvar, "'wght' 650", "'wght' 750, 'ABCD' 75", REGULAR, ITALIC)
+                      .variationSettings());
+}
+
+TEST(FontFakeryTest, testMerge_fakeBold_unsupported_font) {
+    FVarTable fvar = {};
+
+    // The same weight won't enable fake bold.
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, REGULAR).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", BOLD, BOLD).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", THIN, THIN).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", BLACK, BLACK).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, ITALIC).isFakeBold());
+
+    // If the weight diff is more than 200, fake bold is enabled.
+    EXPECT_TRUE(merge(fvar, "", "", REGULAR, BOLD).isFakeBold());
+    EXPECT_TRUE(merge(fvar, "", "", REGULAR, BLACK).isFakeBold());
+    EXPECT_TRUE(merge(fvar, "", "", BOLD, BLACK).isFakeBold());
+
+    // If the requested weight is less than 600, the fake bold is not enabled.
+    EXPECT_FALSE(merge(fvar, "", "", THIN, REGULAR).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", THIN, MEDIUM).isFakeBold());
+}
+
+TEST(FontFakeryTest, testMerge_fakeBold_fullrange_font) {
+    FVarTable fvar = {{TAG_wght, {100, 900, 400}}};
+
+    // If the given font supports full range of weight, the fake bold is never enabled.
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, THIN).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, REGULAR).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, MEDIUM).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, BOLD).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, BLACK).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, ITALIC).isFakeBold());
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, BOLD_ITALIC).isFakeBold());
+}
+
+TEST(FontFakeryTest, testMerge_fakeBold_limited_range_font) {
+    FVarTable fvar = {{TAG_wght, {100, 700, 400}}};
+
+    // If the weight diff from the upper limit of the weight is more than 200, fake bold is enabled.
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, BOLD).isFakeBold());
+    EXPECT_TRUE(merge(fvar, "", "", REGULAR, BLACK).isFakeBold());
+}
+
+TEST(FontFakeryTest, testMerge_fakeItalic_unsupported_font) {
+    FVarTable fvar = {};
+
+    // The same italic won't enable fake italic.
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, REGULAR).isFakeItalic());
+    EXPECT_FALSE(merge(fvar, "", "", ITALIC, ITALIC).isFakeItalic());
+    EXPECT_FALSE(merge(fvar, "", "", BOLD_ITALIC, BOLD_ITALIC).isFakeItalic());
+
+    // If the target style is italic but base style is not, fake bold is enabled.
+    EXPECT_TRUE(merge(fvar, "", "", REGULAR, ITALIC).isFakeItalic());
+    EXPECT_TRUE(merge(fvar, "", "", REGULAR, BOLD_ITALIC).isFakeItalic());
+}
+
+TEST(FontFakeryTest, testMerge_fakeItalic_ital_font) {
+    FVarTable fvar = {{TAG_ital, {0, 1, 0}}};
+
+    // If the font supports ital tag, the fake italic is never enabled.
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, ITALIC).isFakeItalic());
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, BOLD_ITALIC).isFakeItalic());
+}
+
+TEST(FontFakeryTest, testMerge_fakeItalic_slnt_font) {
+    FVarTable fvar = {{TAG_slnt, {-10, 0, 0}}};
+
+    // If the font supports slnt tag, the fake italic is never enabled.
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, ITALIC).isFakeItalic());
+    EXPECT_FALSE(merge(fvar, "", "", REGULAR, BOLD_ITALIC).isFakeItalic());
+}
+
 }  // namespace minikin
diff --git a/tests/unittest/FontTest.cpp b/tests/unittest/FontTest.cpp
index ea3ca8d..a080e67 100644
--- a/tests/unittest/FontTest.cpp
+++ b/tests/unittest/FontTest.cpp
@@ -14,11 +14,14 @@
  * limitations under the License.
  */
 
+#include <com_android_text_flags.h>
+#include <flag_macros.h>
 #include <gtest/gtest.h>
 #include <minikin/Constants.h>
 
 #include "BufferUtils.h"
 #include "FontTestUtils.h"
+#include "FontVariationTestUtils.h"
 #include "FreeTypeMinikinFontForTest.h"
 #include "minikin/Font.h"
 
@@ -276,10 +279,10 @@ TEST(FontTest, getAdjustedTypefaceTest) {
         EXPECT_NE(minikinFontBase.get(), font->baseTypeface().get());
         auto axes = minikinFontBase->GetAxes();
         ASSERT_EQ(2u, axes.size());
-        EXPECT_EQ(TAG_wght, axes[0].axisTag);
-        EXPECT_EQ(TAG_ital, axes[1].axisTag);
-        EXPECT_EQ(400, axes[0].value);
-        EXPECT_EQ(1, axes[1].value);
+        EXPECT_EQ(TAG_ital, axes[0].axisTag);
+        EXPECT_EQ(TAG_wght, axes[1].axisTag);
+        EXPECT_EQ(1, axes[0].value);
+        EXPECT_EQ(400, axes[1].value);
     }
     {
         // Override existing ital axis.
@@ -288,10 +291,10 @@ TEST(FontTest, getAdjustedTypefaceTest) {
         EXPECT_NE(minikinFontBase.get(), font->baseTypeface().get());
         auto axes = minikinFontBase->GetAxes();
         ASSERT_EQ(2u, axes.size());
-        EXPECT_EQ(TAG_wght, axes[0].axisTag);
-        EXPECT_EQ(TAG_ital, axes[1].axisTag);
-        EXPECT_EQ(700, axes[0].value);
-        EXPECT_EQ(1, axes[1].value);
+        EXPECT_EQ(TAG_ital, axes[0].axisTag);
+        EXPECT_EQ(TAG_wght, axes[1].axisTag);
+        EXPECT_EQ(1, axes[0].value);
+        EXPECT_EQ(700, axes[1].value);
     }
 }
 
@@ -337,4 +340,44 @@ TEST(FontTest, FVarTableTest) {
     EXPECT_EQ(1, italTable.maxValue);
 }
 
+FakedFont fakedFont(const std::shared_ptr<Font>& font, const std::string& varSettings) {
+    return {font, FontFakery(false, false, parseVariationSettings(varSettings))};
+}
+
+TEST_WITH_FLAGS(FontTest, FakedFont_cached_hbFont,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
+                                                    typeface_redesign_readonly))) {
+    FreeTypeMinikinFontForTestFactory::init();
+
+    auto minikinFont = std::make_shared<FreeTypeMinikinFontForTest>(
+            getTestFontPath("WeightEqualsEmVariableFont.ttf"));
+    std::shared_ptr<Font> font = Font::Builder(minikinFont).build();
+
+    FakedFont faked300 = fakedFont(font, "'wght' 300");
+    FakedFont faked400 = fakedFont(font, "'wght' 400");
+    FakedFont faked300_2 = fakedFont(font, "'wght' 300");
+
+    EXPECT_EQ(faked300.hbFont().get(), faked300.hbFont().get());
+    EXPECT_EQ(faked300.hbFont().get(), faked300_2.hbFont().get());
+    EXPECT_NE(faked300.hbFont().get(), faked400.hbFont().get());
+}
+
+TEST_WITH_FLAGS(FontTest, FakedFont_cached_typeface,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
+                                                    typeface_redesign_readonly))) {
+    FreeTypeMinikinFontForTestFactory::init();
+
+    auto minikinFont = std::make_shared<FreeTypeMinikinFontForTest>(
+            getTestFontPath("WeightEqualsEmVariableFont.ttf"));
+    std::shared_ptr<Font> font = Font::Builder(minikinFont).build();
+
+    FakedFont faked300 = fakedFont(font, "'wght' 300");
+    FakedFont faked400 = fakedFont(font, "'wght' 400");
+    FakedFont faked300_2 = fakedFont(font, "'wght' 300");
+
+    EXPECT_EQ(faked300.typeface(), faked300.typeface());
+    EXPECT_EQ(faked300.typeface(), faked300_2.typeface());
+    EXPECT_NE(faked300.typeface(), faked400.typeface());
+}
+
 }  // namespace minikin
diff --git a/tests/unittest/LayoutTest.cpp b/tests/unittest/LayoutTest.cpp
index 4213c8e..fd0b5f2 100644
--- a/tests/unittest/LayoutTest.cpp
+++ b/tests/unittest/LayoutTest.cpp
@@ -490,7 +490,7 @@ TEST_F(LayoutTest, measuredTextTest) {
 
 TEST_F_WITH_FLAGS(LayoutTest, testFontRun,
                   REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      typeface_redesign))) {
+                                                      typeface_redesign_readonly))) {
     auto latinFamily = buildFontFamily("Ascii.ttf");
     auto jaFamily = buildFontFamily("Hiragana.ttf");
     const std::vector<std::shared_ptr<FontFamily>> families = {latinFamily, jaFamily};
diff --git a/tests/unittest/PackedVectorTest.cpp b/tests/unittest/PackedVectorTest.cpp
index e0f4124..bf669f9 100644
--- a/tests/unittest/PackedVectorTest.cpp
+++ b/tests/unittest/PackedVectorTest.cpp
@@ -27,14 +27,14 @@ struct Data {
 TEST(PackedVector, construct) {
     {
         PackedVector<int> packed;
-        EXPECT_EQ(0, packed.size());
+        EXPECT_EQ(0u, packed.size());
         EXPECT_TRUE(packed.empty());
     }
     {
         int data[] = {1, 2, 3, 4, 5};
 
         PackedVector<int> packed(data, 5);
-        EXPECT_EQ(5, packed.size());
+        EXPECT_EQ(5u, packed.size());
         EXPECT_EQ(1, packed[0]);
         EXPECT_EQ(2, packed[1]);
         EXPECT_EQ(3, packed[2]);
@@ -45,7 +45,7 @@ TEST(PackedVector, construct) {
         int data[] = {1, 2, 3, 4, 5};
 
         PackedVector<int> packed(data + 2, 2);
-        EXPECT_EQ(2, packed.size());
+        EXPECT_EQ(2u, packed.size());
         EXPECT_EQ(3, packed[0]);
         EXPECT_EQ(4, packed[1]);
     }
@@ -53,7 +53,7 @@ TEST(PackedVector, construct) {
         std::vector<int> data = {1, 2, 3, 4, 5};
 
         PackedVector<int> packed(data);
-        EXPECT_EQ(5, packed.size());
+        EXPECT_EQ(5u, packed.size());
         EXPECT_EQ(1, packed[0]);
         EXPECT_EQ(2, packed[1]);
         EXPECT_EQ(3, packed[2]);
@@ -66,14 +66,14 @@ TEST(PackedVector, push_back) {
     PackedVector<int> packed;
 
     packed.push_back(0);
-    EXPECT_EQ(1, packed.size());
+    EXPECT_EQ(1u, packed.size());
     EXPECT_FALSE(packed.empty());
     EXPECT_EQ(0, packed[0]);
     EXPECT_EQ(0, packed.data()[0]);
     EXPECT_EQ(0, *packed.back());
 
     packed.push_back(10);
-    EXPECT_EQ(2, packed.size());
+    EXPECT_EQ(2u, packed.size());
     EXPECT_FALSE(packed.empty());
     EXPECT_EQ(10, packed[1]);
     EXPECT_EQ(10, packed.data()[1]);
@@ -122,13 +122,13 @@ TEST(PackedVector, reserve) {
     {
         PackedVector<int> packed;
         packed.reserve(100);
-        EXPECT_EQ(0, packed.size());
-        EXPECT_EQ(100, packed.capacity());
+        EXPECT_EQ(0u, packed.size());
+        EXPECT_EQ(100u, packed.capacity());
         packed.shrink_to_fit();
-        EXPECT_EQ(0, packed.size());
+        EXPECT_EQ(0u, packed.size());
         // The PackedVector has minimum capacity for the space of pointers. So cannot expect it
         // becomes 0.
-        EXPECT_NE(100, packed.capacity());
+        EXPECT_NE(100u, packed.capacity());
     }
     {
         PackedVector<int> packed;
@@ -136,11 +136,11 @@ TEST(PackedVector, reserve) {
         for (int i = 0; i < 50; ++i) {
             packed.push_back(i);
         }
-        EXPECT_EQ(50, packed.size());
-        EXPECT_EQ(100, packed.capacity());
+        EXPECT_EQ(50u, packed.size());
+        EXPECT_EQ(100u, packed.capacity());
         packed.shrink_to_fit();
-        EXPECT_EQ(50, packed.size());
-        EXPECT_EQ(50, packed.capacity());
+        EXPECT_EQ(50u, packed.size());
+        EXPECT_EQ(50u, packed.capacity());
     }
 }
 
@@ -157,91 +157,91 @@ TEST(PackedVector, resize) {
         // Reduction
         PackedVector<int> packed = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
         packed.resize(10);
-        EXPECT_EQ(10, packed.size());
-        EXPECT_EQ(10, packed.capacity());
+        EXPECT_EQ(10u, packed.size());
+        EXPECT_EQ(10u, packed.capacity());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), packed);
 
         packed.resize(9);
-        EXPECT_EQ(9, packed.size());
+        EXPECT_EQ(9u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8, 9}), packed);
 
         packed.resize(8);
-        EXPECT_EQ(8, packed.size());
+        EXPECT_EQ(8u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8}), packed);
 
         packed.resize(7);
-        EXPECT_EQ(7, packed.size());
+        EXPECT_EQ(7u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7}), packed);
 
         packed.resize(6);
-        EXPECT_EQ(6, packed.size());
+        EXPECT_EQ(6u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6}), packed);
 
         packed.resize(5);
-        EXPECT_EQ(5, packed.size());
+        EXPECT_EQ(5u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5}), packed);
 
         packed.resize(4);
-        EXPECT_EQ(4, packed.size());
+        EXPECT_EQ(4u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4}), packed);
 
         packed.resize(3);
-        EXPECT_EQ(3, packed.size());
+        EXPECT_EQ(3u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3}), packed);
 
         packed.resize(2);
-        EXPECT_EQ(2, packed.size());
+        EXPECT_EQ(2u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2}), packed);
 
         packed.resize(1);
-        EXPECT_EQ(1, packed.size());
+        EXPECT_EQ(1u, packed.size());
         EXPECT_EQ(PackedVector<int>({1}), packed);
 
         packed.resize(0);
-        EXPECT_EQ(0, packed.size());
+        EXPECT_EQ(0u, packed.size());
         EXPECT_EQ(PackedVector<int>({}), packed);
     }
     {
         // Expansion
         PackedVector<int> packed = {};
         packed.resize(1, 1);
-        EXPECT_EQ(1, packed.size());
+        EXPECT_EQ(1u, packed.size());
         EXPECT_EQ(PackedVector<int>({1}), packed);
 
         packed.resize(2, 2);
-        EXPECT_EQ(2, packed.size());
+        EXPECT_EQ(2u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2}), packed);
 
         packed.resize(3, 3);
-        EXPECT_EQ(3, packed.size());
+        EXPECT_EQ(3u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3}), packed);
 
         packed.resize(4, 4);
-        EXPECT_EQ(4, packed.size());
+        EXPECT_EQ(4u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4}), packed);
 
         packed.resize(5, 5);
-        EXPECT_EQ(5, packed.size());
+        EXPECT_EQ(5u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5}), packed);
 
         packed.resize(6, 6);
-        EXPECT_EQ(6, packed.size());
+        EXPECT_EQ(6u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6}), packed);
 
         packed.resize(7, 7);
-        EXPECT_EQ(7, packed.size());
+        EXPECT_EQ(7u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7}), packed);
 
         packed.resize(8, 8);
-        EXPECT_EQ(8, packed.size());
+        EXPECT_EQ(8u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8}), packed);
 
         packed.resize(9, 9);
-        EXPECT_EQ(9, packed.size());
+        EXPECT_EQ(9u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8, 9}), packed);
 
         packed.resize(10, 10);
-        EXPECT_EQ(10, packed.size());
+        EXPECT_EQ(10u, packed.size());
         EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), packed);
     }
 }
diff --git a/tests/unittest/SortedPackedVectorTest.cpp b/tests/unittest/SortedPackedVectorTest.cpp
index 361c98a..4e25750 100644
--- a/tests/unittest/SortedPackedVectorTest.cpp
+++ b/tests/unittest/SortedPackedVectorTest.cpp
@@ -23,7 +23,7 @@ namespace minikin {
 TEST(SortedPackedVector, construct) {
     {
         auto sorted = SortedPackedVector({1, 2, 3, 4, 5});
-        EXPECT_EQ(5, sorted.size());
+        EXPECT_EQ(5u, sorted.size());
         EXPECT_EQ(1, sorted[0]);
         EXPECT_EQ(2, sorted[1]);
         EXPECT_EQ(3, sorted[2]);
@@ -32,7 +32,7 @@ TEST(SortedPackedVector, construct) {
     }
     {
         auto sorted = SortedPackedVector({1, 2, 3, 4, 5}, true);
-        EXPECT_EQ(5, sorted.size());
+        EXPECT_EQ(5u, sorted.size());
         EXPECT_EQ(1, sorted[0]);
         EXPECT_EQ(2, sorted[1]);
         EXPECT_EQ(3, sorted[2]);
@@ -41,7 +41,7 @@ TEST(SortedPackedVector, construct) {
     }
     {
         auto sorted = SortedPackedVector({2, 1, 4, 3, 5});
-        EXPECT_EQ(5, sorted.size());
+        EXPECT_EQ(5u, sorted.size());
         EXPECT_EQ(1, sorted[0]);
         EXPECT_EQ(2, sorted[1]);
         EXPECT_EQ(3, sorted[2]);
@@ -51,7 +51,7 @@ TEST(SortedPackedVector, construct) {
     {
         std::vector<int> vec = {2, 1, 4, 3, 5};
         auto sorted = SortedPackedVector(vec);
-        EXPECT_EQ(5, sorted.size());
+        EXPECT_EQ(5u, sorted.size());
         EXPECT_EQ(1, sorted[0]);
         EXPECT_EQ(2, sorted[1]);
         EXPECT_EQ(3, sorted[2]);
@@ -61,7 +61,7 @@ TEST(SortedPackedVector, construct) {
     {
         auto sorted = SortedPackedVector({1, 2, 3, 4, 5});
         auto copied = SortedPackedVector(sorted);
-        EXPECT_EQ(5, copied.size());
+        EXPECT_EQ(5u, copied.size());
         EXPECT_EQ(1, copied[0]);
         EXPECT_EQ(2, copied[1]);
         EXPECT_EQ(3, copied[2]);
@@ -71,7 +71,7 @@ TEST(SortedPackedVector, construct) {
     {
         auto sorted = SortedPackedVector({1, 2, 3, 4, 5});
         auto moved = SortedPackedVector(std::move(sorted));
-        EXPECT_EQ(5, moved.size());
+        EXPECT_EQ(5u, moved.size());
         EXPECT_EQ(1, moved[0]);
         EXPECT_EQ(2, moved[1]);
         EXPECT_EQ(3, moved[2]);
diff --git a/tests/util/Android.bp b/tests/util/Android.bp
index d8c153d..6f12e8b 100644
--- a/tests/util/Android.bp
+++ b/tests/util/Android.bp
@@ -7,6 +7,7 @@ cc_library_static {
     srcs: [
         "FileUtils.cpp",
         "FontTestUtils.cpp",
+        "FontVariationTestUtils.cpp",
         "FreeTypeMinikinFontForTest.cpp",
         "PathUtils.cpp",
         "UnicodeUtils.cpp",
diff --git a/tests/util/FontVariationTestUtils.cpp b/tests/util/FontVariationTestUtils.cpp
new file mode 100644
index 0000000..7ff8d7f
--- /dev/null
+++ b/tests/util/FontVariationTestUtils.cpp
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <hb.h>
+
+#include <vector>
+
+#include "StringPiece.h"
+#include "minikin/FontVariation.h"
+
+namespace minikin {
+
+VariationSettings parseVariationSettings(const std::string& varSettings) {
+    std::vector<FontVariation> variations;
+
+    SplitIterator it(varSettings, ',');
+    while (it.hasNext()) {
+        StringPiece var = it.next();
+
+        static hb_variation_t variation;
+        if (hb_variation_from_string(var.data(), var.size(), &variation)) {
+            variations.push_back({static_cast<AxisTag>(variation.tag), variation.value});
+        }
+    }
+    return VariationSettings(variations);
+}
+
+}  // namespace minikin
diff --git a/tests/util/FontVariationTestUtils.h b/tests/util/FontVariationTestUtils.h
new file mode 100644
index 0000000..d4ef23a
--- /dev/null
+++ b/tests/util/FontVariationTestUtils.h
@@ -0,0 +1,27 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#ifndef MINIKIN_FONT_VARIATION_TEST_UTILS_H
+#define MINIKIN_FONT_VARIATION_TEST_UTILS_H
+
+#include "minikin/FontVariation.h"
+
+namespace minikin {
+
+VariationSettings parseVariationSettings(const std::string& varSettings);
+
+}  // namespace minikin
+#endif  // MINIKIN_FONT_VARIATION_TEST_UTILS_H
diff --git a/tests/util/FreeTypeMinikinFontForTest.cpp b/tests/util/FreeTypeMinikinFontForTest.cpp
index ee04662..ab0e0dd 100644
--- a/tests/util/FreeTypeMinikinFontForTest.cpp
+++ b/tests/util/FreeTypeMinikinFontForTest.cpp
@@ -58,7 +58,7 @@ void loadGlyphOrDie(uint32_t glyphId, float size, FT_Face face) {
 }  // namespace
 
 FreeTypeMinikinFontForTest::FreeTypeMinikinFontForTest(const std::string& font_path, int index,
-                                                       const std::vector<FontVariation>& axes)
+                                                       const VariationSettings& axes)
         : mFontPath(font_path), mFontIndex(index), mAxes(axes) {
     int fd = open(font_path.c_str(), O_RDONLY);
     LOG_ALWAYS_FATAL_IF(fd == -1, "Open failed: %s", font_path.c_str());
@@ -135,7 +135,7 @@ void FreeTypeMinikinFontForTestFactory::skip(BufferReader* reader) const {
 }
 
 std::shared_ptr<MinikinFont> FreeTypeMinikinFontForTest::createFontWithVariation(
-        const std::vector<FontVariation>& axes) const {
+        const VariationSettings& axes) const {
     return std::make_shared<FreeTypeMinikinFontForTest>(mFontPath, mFontIndex, axes);
 }
 
diff --git a/tests/util/FreeTypeMinikinFontForTest.h b/tests/util/FreeTypeMinikinFontForTest.h
index f684ec6..4b19f2d 100644
--- a/tests/util/FreeTypeMinikinFontForTest.h
+++ b/tests/util/FreeTypeMinikinFontForTest.h
@@ -34,11 +34,11 @@ namespace minikin {
 class FreeTypeMinikinFontForTest : public MinikinFont {
 public:
     FreeTypeMinikinFontForTest(const std::string& font_path, int index,
-                               const std::vector<FontVariation>& axes);
+                               const VariationSettings& axes);
     FreeTypeMinikinFontForTest(const std::string& font_path, int index)
-            : FreeTypeMinikinFontForTest(font_path, index, std::vector<FontVariation>()) {}
+            : FreeTypeMinikinFontForTest(font_path, index, VariationSettings()) {}
     FreeTypeMinikinFontForTest(const std::string& font_path)
-            : FreeTypeMinikinFontForTest(font_path, 0, std::vector<FontVariation>()) {}
+            : FreeTypeMinikinFontForTest(font_path, 0, VariationSettings()) {}
     virtual ~FreeTypeMinikinFontForTest();
 
     // MinikinFont overrides.
@@ -53,15 +53,15 @@ public:
     const void* GetFontData() const { return mFontData; }
     size_t GetFontSize() const { return mFontSize; }
     int GetFontIndex() const { return mFontIndex; }
-    const std::vector<minikin::FontVariation>& GetAxes() const { return mAxes; }
-    std::shared_ptr<MinikinFont> createFontWithVariation(const std::vector<FontVariation>&) const;
+    const VariationSettings& GetAxes() const { return mAxes; }
+    std::shared_ptr<MinikinFont> createFontWithVariation(const VariationSettings&) const;
 
 private:
     const std::string mFontPath;
     const int mFontIndex;
     void* mFontData;
     size_t mFontSize;
-    std::vector<minikin::FontVariation> mAxes;
+    VariationSettings mAxes;
 
     FT_Library mFtLibrary;
     FT_Face mFtFace;
```

