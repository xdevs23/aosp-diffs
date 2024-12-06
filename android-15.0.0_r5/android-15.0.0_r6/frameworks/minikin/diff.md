```diff
diff --git a/Android.bp b/Android.bp
index 8988459..1dea825 100644
--- a/Android.bp
+++ b/Android.bp
@@ -9,6 +9,7 @@ cc_defaults {
         "-Werror",
         "-Wextra",
         "-Wthread-safety",
+        "-DLOG_TAG=\"Minikin\"",
     ],
 }
 
diff --git a/fuzz/hyphenator_fuzzer/Android.bp b/fuzz/hyphenator_fuzzer/Android.bp
index 0b7efda..1633c65 100644
--- a/fuzz/hyphenator_fuzzer/Android.bp
+++ b/fuzz/hyphenator_fuzzer/Android.bp
@@ -38,6 +38,7 @@ cc_fuzz {
         "libicu",
         "libutils",
         "aconfig_text_flags_c_lib",
+        "server_configurable_flags",
     ],
     header_libs: [
         "libminikin_headers",
diff --git a/fuzz/locale_fuzzer/Android.bp b/fuzz/locale_fuzzer/Android.bp
index 25d0583..f0953b6 100644
--- a/fuzz/locale_fuzzer/Android.bp
+++ b/fuzz/locale_fuzzer/Android.bp
@@ -43,4 +43,16 @@ cc_fuzz {
         "libminikin-headers-for-tests",
     ],
     dictionary: "locale.dict",
+    fuzz_config: {
+        cc: [
+            "android-text@google.com",
+            "nona@google.com",
+        ],
+        componentid: 25699,
+        description: "The fuzzer targets the APIs of libminikin",
+        vector: "remote",
+        service_privilege: "privileged",
+        users: "multi_user",
+        fuzzed_code_usage: "shipped",
+    },
 }
diff --git a/include/minikin/Constants.h b/include/minikin/Constants.h
index 26eb860..eacac07 100644
--- a/include/minikin/Constants.h
+++ b/include/minikin/Constants.h
@@ -31,6 +31,8 @@ constexpr uint32_t MakeTag(char c1, char c2, char c3, char c4) {
     return ((uint32_t)c1 << 24) | ((uint32_t)c2 << 16) | ((uint32_t)c3 << 8) | (uint32_t)c4;
 }
 
+const uint32_t TAG_fvar = MakeTag('f', 'v', 'a', 'r');
+
 // Axis tags
 const uint32_t TAG_wght = MakeTag('w', 'g', 'h', 't');
 const uint32_t TAG_ital = MakeTag('i', 't', 'a', 'l');
diff --git a/include/minikin/FVarTable.h b/include/minikin/FVarTable.h
new file mode 100644
index 0000000..d450c9e
--- /dev/null
+++ b/include/minikin/FVarTable.h
@@ -0,0 +1,36 @@
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
+#ifndef MINIKIN_FVAR_TABLE_H
+#define MINIKIN_FVAR_TABLE_H
+
+#include <map>
+
+#include "minikin/FontVariation.h"
+
+namespace minikin {
+
+struct FVarEntry {
+    float minValue;
+    float maxValue;
+    float defValue;
+};
+
+typedef std::map<AxisTag, FVarEntry> FVarTable;
+
+}  // namespace minikin
+
+#endif  // MINIKIN_FVAR_TABLE_H
diff --git a/include/minikin/Font.h b/include/minikin/Font.h
index dc3782c..0329cb4 100644
--- a/include/minikin/Font.h
+++ b/include/minikin/Font.h
@@ -27,6 +27,8 @@
 #include <unordered_set>
 
 #include "minikin/Buffer.h"
+#include "minikin/FVarTable.h"
+#include "minikin/FontFakery.h"
 #include "minikin/FontStyle.h"
 #include "minikin/FontVariation.h"
 #include "minikin/HbUtils.h"
@@ -38,70 +40,6 @@ namespace minikin {
 
 class Font;
 
-// attributes representing transforms (fake bold, fake italic) to match styles
-class FontFakery {
-public:
-    FontFakery() : FontFakery(false, false, -1, -1) {}
-    FontFakery(bool fakeBold, bool fakeItalic) : FontFakery(fakeBold, fakeItalic, -1, -1) {}
-    FontFakery(bool fakeBold, bool fakeItalic, int16_t wghtAdjustment, int8_t italAdjustment)
-            : mBits(pack(fakeBold, fakeItalic, wghtAdjustment, italAdjustment)) {}
-
-    // TODO: want to support graded fake bolding
-    bool isFakeBold() { return (mBits & MASK_FAKE_BOLD) != 0; }
-    bool isFakeItalic() { return (mBits & MASK_FAKE_ITALIC) != 0; }
-    bool hasAdjustment() const { return hasWghtAdjustment() || hasItalAdjustment(); }
-    bool hasWghtAdjustment() const { return (mBits & MASK_HAS_WGHT_ADJUSTMENT) != 0; }
-    bool hasItalAdjustment() const { return (mBits & MASK_HAS_ITAL_ADJUSTMENT) != 0; }
-    int16_t wghtAdjustment() const {
-        if (hasWghtAdjustment()) {
-            return (mBits & MASK_WGHT_ADJUSTMENT) >> WGHT_ADJUSTMENT_SHIFT;
-        } else {
-            return -1;
-        }
-    }
-
-    int8_t italAdjustment() const {
-        if (hasItalAdjustment()) {
-            return (mBits & MASK_ITAL_ADJUSTMENT) != 0 ? 1 : 0;
-        } else {
-            return -1;
-        }
-    }
-
-    uint16_t bits() const { return mBits; }
-
-    inline bool operator==(const FontFakery& o) const { return mBits == o.mBits; }
-    inline bool operator!=(const FontFakery& o) const { return !(*this == o); }
-
-private:
-    static constexpr uint16_t MASK_FAKE_BOLD = 1u;
-    static constexpr uint16_t MASK_FAKE_ITALIC = 1u << 1;
-    static constexpr uint16_t MASK_HAS_WGHT_ADJUSTMENT = 1u << 2;
-    static constexpr uint16_t MASK_HAS_ITAL_ADJUSTMENT = 1u << 3;
-    static constexpr uint16_t MASK_ITAL_ADJUSTMENT = 1u << 4;
-    static constexpr uint16_t MASK_WGHT_ADJUSTMENT = 0b1111111111u << 5;
-    static constexpr uint16_t WGHT_ADJUSTMENT_SHIFT = 5;
-
-    uint16_t pack(bool isFakeBold, bool isFakeItalic, int16_t wghtAdjustment,
-                  int8_t italAdjustment) {
-        uint16_t bits = 0u;
-        bits |= isFakeBold ? MASK_FAKE_BOLD : 0;
-        bits |= isFakeItalic ? MASK_FAKE_ITALIC : 0;
-        if (wghtAdjustment != -1) {
-            bits |= MASK_HAS_WGHT_ADJUSTMENT;
-            bits |= (static_cast<uint16_t>(wghtAdjustment) << WGHT_ADJUSTMENT_SHIFT) &
-                    MASK_WGHT_ADJUSTMENT;
-        }
-        if (italAdjustment != -1) {
-            bits |= MASK_HAS_ITAL_ADJUSTMENT;
-            bits |= (italAdjustment == 1) ? MASK_ITAL_ADJUSTMENT : 0;
-        }
-        return bits;
-    }
-
-    const uint16_t mBits;
-};
-
 // Represents a single font file.
 class Font {
 public:
@@ -175,6 +113,8 @@ public:
     const AxisTag* getSupportedAxes() const { return mSupportedAxes.get(); }
     bool isAxisSupported(uint32_t tag) const;
 
+    const FVarTable& getFVarTable() const;
+
 private:
     // ExternalRefs holds references to objects provided by external libraries.
     // Because creating these external objects is costly,
@@ -224,6 +164,8 @@ private:
 
     void calculateSupportedAxes();
 
+    mutable std::atomic<FVarTable*> mFVarTableHolder;
+
     // Non-null if created by readFrom().
     BufferReader mTypefaceMetadataReader;
 
diff --git a/include/minikin/FontCollection.h b/include/minikin/FontCollection.h
index c14335b..18635d2 100644
--- a/include/minikin/FontCollection.h
+++ b/include/minikin/FontCollection.h
@@ -246,7 +246,7 @@ private:
     bool isPrimaryFamily(const std::shared_ptr<FontFamily>& fontFamily) const;
 
     void filterFamilyByLocale(const LocaleList& localeList,
-                              const std::function<void(const FontFamily& family)>& callback) const;
+                              const std::function<bool(const FontFamily& family)>& callback) const;
 
     static uint32_t calcLocaleMatchingScore(uint32_t userLocaleListId,
                                             const FontFamily& fontFamily);
diff --git a/include/minikin/FontFakery.h b/include/minikin/FontFakery.h
new file mode 100644
index 0000000..b98cfa8
--- /dev/null
+++ b/include/minikin/FontFakery.h
@@ -0,0 +1,103 @@
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
+#ifndef MINIKIN_FONT_FAKERY_H
+#define MINIKIN_FONT_FAKERY_H
+
+#include "minikin/FontVariation.h"
+
+namespace minikin {
+
+// attributes representing transforms (fake bold, fake italic) to match styles
+class FontFakery {
+public:
+    FontFakery() : FontFakery(false, false, -1, -1, VariationSettings()) {}
+    FontFakery(bool fakeBold, bool fakeItalic)
+            : FontFakery(fakeBold, fakeItalic, -1, -1, VariationSettings()) {}
+    FontFakery(bool fakeBold, bool fakeItalic, int16_t wghtAdjustment, int8_t italAdjustment)
+            : FontFakery(fakeBold, fakeItalic, wghtAdjustment, italAdjustment,
+                         VariationSettings()) {}
+    FontFakery(bool fakeBold, bool fakeItalic, VariationSettings&& variationSettings)
+            : FontFakery(fakeBold, fakeItalic, -1, -1, std::move(variationSettings)) {}
+    FontFakery(bool fakeBold, bool fakeItalic, int16_t wghtAdjustment, int8_t italAdjustment,
+               VariationSettings&& variationSettings)
+            : mBits(pack(fakeBold, fakeItalic, wghtAdjustment, italAdjustment)),
+              mVariationSettings(std::move(variationSettings)) {}
+
+    // TODO: want to support graded fake bolding
+    bool isFakeBold() const { return (mBits & MASK_FAKE_BOLD) != 0; }
+    bool isFakeItalic() const { return (mBits & MASK_FAKE_ITALIC) != 0; }
+    bool hasAdjustment() const { return hasWghtAdjustment() || hasItalAdjustment(); }
+    bool hasWghtAdjustment() const { return (mBits & MASK_HAS_WGHT_ADJUSTMENT) != 0; }
+    bool hasItalAdjustment() const { return (mBits & MASK_HAS_ITAL_ADJUSTMENT) != 0; }
+    int16_t wghtAdjustment() const {
+        if (hasWghtAdjustment()) {
+            return (mBits & MASK_WGHT_ADJUSTMENT) >> WGHT_ADJUSTMENT_SHIFT;
+        } else {
+            return -1;
+        }
+    }
+
+    int8_t italAdjustment() const {
+        if (hasItalAdjustment()) {
+            return (mBits & MASK_ITAL_ADJUSTMENT) != 0 ? 1 : 0;
+        } else {
+            return -1;
+        }
+    }
+
+    uint16_t bits() const { return mBits; }
+
+    const VariationSettings& variationSettings() const { return mVariationSettings; }
+
+    inline bool operator==(const FontFakery& o) const {
+        return mBits == o.mBits && mVariationSettings == o.mVariationSettings;
+    }
+    inline bool operator!=(const FontFakery& o) const { return !(*this == o); }
+
+private:
+    static constexpr uint16_t MASK_FAKE_BOLD = 1u;
+    static constexpr uint16_t MASK_FAKE_ITALIC = 1u << 1;
+    static constexpr uint16_t MASK_HAS_WGHT_ADJUSTMENT = 1u << 2;
+    static constexpr uint16_t MASK_HAS_ITAL_ADJUSTMENT = 1u << 3;
+    static constexpr uint16_t MASK_ITAL_ADJUSTMENT = 1u << 4;
+    static constexpr uint16_t MASK_WGHT_ADJUSTMENT = 0b1111111111u << 5;
+    static constexpr uint16_t WGHT_ADJUSTMENT_SHIFT = 5;
+
+    uint16_t pack(bool isFakeBold, bool isFakeItalic, int16_t wghtAdjustment,
+                  int8_t italAdjustment) {
+        uint16_t bits = 0u;
+        bits |= isFakeBold ? MASK_FAKE_BOLD : 0;
+        bits |= isFakeItalic ? MASK_FAKE_ITALIC : 0;
+        if (wghtAdjustment != -1) {
+            bits |= MASK_HAS_WGHT_ADJUSTMENT;
+            bits |= (static_cast<uint16_t>(wghtAdjustment) << WGHT_ADJUSTMENT_SHIFT) &
+                    MASK_WGHT_ADJUSTMENT;
+        }
+        if (italAdjustment != -1) {
+            bits |= MASK_HAS_ITAL_ADJUSTMENT;
+            bits |= (italAdjustment == 1) ? MASK_ITAL_ADJUSTMENT : 0;
+        }
+        return bits;
+    }
+
+    const uint16_t mBits;
+    const VariationSettings mVariationSettings;
+};
+
+}  // namespace minikin
+
+#endif  // MINIKIN_FONT_FAKERY_H
diff --git a/include/minikin/FontVariation.h b/include/minikin/FontVariation.h
index e0567c1..d3d405f 100644
--- a/include/minikin/FontVariation.h
+++ b/include/minikin/FontVariation.h
@@ -19,6 +19,8 @@
 
 #include <cstdint>
 
+#include "minikin/SortedPackedVector.h"
+
 namespace minikin {
 
 typedef uint32_t AxisTag;
@@ -30,6 +32,33 @@ struct FontVariation {
     float value;
 };
 
+constexpr bool operator==(const FontVariation& l, const FontVariation& r) {
+    return l.axisTag == r.axisTag && l.value == r.value;
+}
+
+constexpr bool operator!=(const FontVariation& l, const FontVariation& r) {
+    return !(l == r);
+}
+
+constexpr bool operator<(const FontVariation& l, const FontVariation& r) {
+    return l.axisTag < r.axisTag;
+}
+
+constexpr bool operator>(const FontVariation& l, const FontVariation& r) {
+    return l.axisTag > r.axisTag;
+}
+
+constexpr bool operator<=(const FontVariation& l, const FontVariation& r) {
+    return l.axisTag <= r.axisTag;
+}
+
+constexpr bool operator>=(const FontVariation& l, const FontVariation& r) {
+    return l.axisTag >= r.axisTag;
+}
+
+// Immutable variation settings
+using VariationSettings = SortedPackedVector<FontVariation>;
+
 }  // namespace minikin
 
 #endif  // MINIKIN_FONT_VARIATION_H
diff --git a/include/minikin/Hasher.h b/include/minikin/Hasher.h
index dcfdd0b..3121c33 100644
--- a/include/minikin/Hasher.h
+++ b/include/minikin/Hasher.h
@@ -21,7 +21,9 @@
 #include <string>
 
 #include "minikin/FontFeature.h"
+#include "minikin/FontVariation.h"
 #include "minikin/Macros.h"
+#include "minikin/SortedPackedVector.h"
 
 namespace minikin {
 
@@ -101,6 +103,22 @@ public:
         return *this;
     }
 
+    inline Hasher& update(const FontVariation& var) {
+        update(static_cast<uint32_t>(var.axisTag));
+        update(static_cast<float>(var.value));
+        return *this;
+    }
+
+    template <typename T, size_t ARRAYSIZE>
+    inline Hasher& update(const SortedPackedVector<T, ARRAYSIZE>& vec) {
+        uint32_t size = vec.size();
+        update(size);
+        for (uint32_t i = 0; i < size; ++i) {
+            update(vec[i]);
+        }
+        return *this;
+    }
+
     IGNORE_INTEGER_OVERFLOW inline uint32_t hash() {
         uint32_t hash = mHash;
         hash += (hash << 3);
diff --git a/include/minikin/Hyphenator.h b/include/minikin/Hyphenator.h
index 4cbe058..d17b85d 100644
--- a/include/minikin/Hyphenator.h
+++ b/include/minikin/Hyphenator.h
@@ -122,7 +122,7 @@ inline bool isInsertion(EndHyphenEdit hyph) {
 }
 
 template <typename T, size_t size>
-constexpr size_t ARRAYSIZE(T const (&)[size]) {
+constexpr size_t ARRAY_SIZE(T const (&)[size]) {
     return size;
 }
 constexpr uint16_t HYPHEN_STR_ZWJ[] = {CHAR_ZWJ};
@@ -132,7 +132,7 @@ constexpr uint16_t HYPHEN_STR_MAQAF[] = {CHAR_MAQAF};
 constexpr uint16_t HYPHEN_STR_UCAS_HYPHEN[] = {CHAR_UCAS_HYPHEN};
 constexpr uint16_t HYPHEN_STR_ZWJ_AND_HYPHEN[] = {CHAR_ZWJ, CHAR_HYPHEN};
 constexpr std::pair<const uint16_t*, size_t> EMPTY_HYPHEN_STR(nullptr, 0);
-#define MAKE_HYPHEN_STR(chars) std::make_pair((chars), ARRAYSIZE(chars))
+#define MAKE_HYPHEN_STR(chars) std::make_pair((chars), ARRAY_SIZE(chars))
 
 inline std::pair<const uint16_t*, size_t> getHyphenString(StartHyphenEdit hyph) {
     if (hyph == StartHyphenEdit::INSERT_ZWJ) {
@@ -217,6 +217,7 @@ protected:
         CATALAN = 1,
         POLISH = 2,
         SLOVENIAN = 3,
+        PORTUGUESE = 4,
     };
 };
 
@@ -262,7 +263,7 @@ private:
 
     // calculate hyphenation from patterns, assuming alphabet lookup has already been done
     void hyphenateFromCodes(const uint16_t* codes, size_t len, HyphenationType hyphenValue,
-                            HyphenationType* out) const;
+                            const U16StringPiece& word, HyphenationType* out) const;
 
     // See also LONGEST_HYPHENATED_WORD in LineBreaker.cpp. Here the constant is used so
     // that temporary buffers can be stack-allocated without waste, which is a slightly
diff --git a/include/minikin/Layout.h b/include/minikin/Layout.h
index bc920af..11ae7ca 100644
--- a/include/minikin/Layout.h
+++ b/include/minikin/Layout.h
@@ -141,6 +141,15 @@ public:
     float getCharAdvance(size_t i) const { return mAdvances[i]; }
     const std::vector<float>& getAdvances() const { return mAdvances; }
 
+    // Returns number of font runs.
+    uint32_t getFontRunCount() const { return mFonts.size(); }
+    // Returns inclusive start offset of the font run.
+    uint32_t getFontRunStart(uint32_t i) const { return i == 0 ? 0 : mEnds[i - 1]; }
+    // Returns exclusive end offset of the font run.
+    uint32_t getFontRunEnd(uint32_t i) const { return mEnds[i]; }
+    // Returns the font associated to the given run index.
+    const FakedFont& getFontRunFont(uint32_t i) const { return mFonts[i]; }
+
     // Purge all caches, useful in low memory conditions
     static void purgeCaches();
 
@@ -199,6 +208,8 @@ private:
                      const MinikinPaint& paint, StartHyphenEdit startHyphen,
                      EndHyphenEdit endHyphen, MinikinRect* bounds, uint32_t* clusterCount);
 
+    std::vector<FakedFont> mFonts;
+    std::vector<uint32_t> mEnds;
     std::vector<LayoutGlyph> mGlyphs;
 
     // This vector defined per code unit, so their length is identical to the input text.
diff --git a/include/minikin/LayoutCache.h b/include/minikin/LayoutCache.h
index e58325e..fe44370 100644
--- a/include/minikin/LayoutCache.h
+++ b/include/minikin/LayoutCache.h
@@ -162,7 +162,7 @@ public:
                      bool dir, StartHyphenEdit startHyphen, EndHyphenEdit endHyphen,
                      bool boundsCalculation, F& f) {
         LayoutCacheKey key(text, range, paint, dir, startHyphen, endHyphen);
-        if (paint.skipCache() || range.getLength() >= CHAR_LIMIT_FOR_CACHE) {
+        if (range.getLength() >= CHAR_LIMIT_FOR_CACHE) {
             LayoutPiece piece(text, range, dir, paint, startHyphen, endHyphen);
             if (boundsCalculation) {
                 f(piece, paint, LayoutPiece::calculateBounds(piece, paint));
diff --git a/include/minikin/MinikinPaint.h b/include/minikin/MinikinPaint.h
index bbae800..9705b3c 100644
--- a/include/minikin/MinikinPaint.h
+++ b/include/minikin/MinikinPaint.h
@@ -60,8 +60,6 @@ struct MinikinPaint {
               fontFeatureSettings(),
               font(font) {}
 
-    bool skipCache() const;
-
     float size;
     float scaleX;
     float skewX;
@@ -73,6 +71,7 @@ struct MinikinPaint {
     FamilyVariant familyVariant;
     std::vector<FontFeature> fontFeatureSettings;
     std::shared_ptr<FontCollection> font;
+    VariationSettings fontVariationSettings;
 
     void copyFrom(const MinikinPaint& paint) { *this = paint; }
 
@@ -89,7 +88,8 @@ struct MinikinPaint {
                letterSpacing == paint.letterSpacing && wordSpacing == paint.wordSpacing &&
                fontFlags == paint.fontFlags && localeListId == paint.localeListId &&
                fontStyle == paint.fontStyle && familyVariant == paint.familyVariant &&
-               fontFeatureSettings == paint.fontFeatureSettings && font.get() == paint.font.get();
+               fontFeatureSettings == paint.fontFeatureSettings && font.get() == paint.font.get() &&
+               fontVariationSettings == paint.fontVariationSettings;
     }
 
     uint32_t hash() const {
@@ -105,6 +105,7 @@ struct MinikinPaint {
                 .update(static_cast<uint8_t>(familyVariant))
                 .update(fontFeatureSettings)
                 .update(font->getId())
+                .update(fontVariationSettings)
                 .hash();
     }
 };
diff --git a/include/minikin/PackedVector.h b/include/minikin/PackedVector.h
new file mode 100644
index 0000000..e383f16
--- /dev/null
+++ b/include/minikin/PackedVector.h
@@ -0,0 +1,228 @@
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
+#ifndef MINIKIN_PACKED_VECTOR_H
+#define MINIKIN_PACKED_VECTOR_H
+
+#include <log/log.h>
+
+#include <type_traits>
+#include <vector>
+
+namespace minikin {
+
+// PackedVector optimize short term allocations for small size objects.
+// The public interfaces are following the std::vector.
+template <typename T, size_t ARRAY_SIZE = 2>
+class PackedVector {
+private:
+    // At least two elements of pointer array is reserved.
+    static constexpr size_t PTR_ARRAY_SIZE =
+            std::max(static_cast<size_t>(2),
+                     (ARRAY_SIZE * sizeof(T) + sizeof(uintptr_t) - 1) / sizeof(uintptr_t));
+    // Number of elements can be stored into array.
+    static constexpr size_t ARRAY_CAPACITY = PTR_ARRAY_SIZE * sizeof(uintptr_t) / sizeof(T);
+    static_assert(std::is_pod<T>::value, "only POD can be stored in PackedVector.");
+
+public:
+    typedef T value_type;
+
+    // Constructors
+    PackedVector() : mSize(0), mCapacity(ARRAY_CAPACITY) {}
+    PackedVector(const T* ptr, uint16_t size) : PackedVector() { copy(ptr, size); }
+    PackedVector(const std::vector<T>& src) : PackedVector() {
+        LOG_ALWAYS_FATAL_IF(src.size() >= std::numeric_limits<uint16_t>::max());
+        copy(src.data(), src.size());
+    }
+    PackedVector(std::initializer_list<T> init) : PackedVector() {
+        copy(init.begin(), init.size());
+    }
+
+    // Assignments
+    PackedVector(const PackedVector& o) : PackedVector() { copy(o.getPtr(), o.mSize); }
+    PackedVector& operator=(const PackedVector& o) {
+        copy(o.getPtr(), o.mSize);
+        return *this;
+    }
+
+    // Movement
+    PackedVector(PackedVector&& o) : PackedVector() { move(std::move(o)); }
+    PackedVector& operator=(PackedVector&& o) {
+        move(std::move(o));
+        return *this;
+    }
+
+    ~PackedVector() { free(); }
+
+    // Compare
+    inline bool operator==(const PackedVector& o) const {
+        return mSize == o.mSize && memcmp(getPtr(), o.getPtr(), mSize * sizeof(T)) == 0;
+    }
+    inline bool operator!=(const PackedVector& o) const { return !(*this == o); }
+
+    const T* data() const { return getPtr(); }
+    T* data() { return getPtr(); }
+
+    const T& operator[](uint16_t i) const { return getPtr()[i]; }
+    T& operator[](uint16_t i) { return getPtr()[i]; }
+
+    void reserve(uint16_t capacity) { ensureCapacity(capacity); }
+
+    void resize(uint16_t size, T value = T()) {
+        if (mSize == size) {
+            return;
+        } else if (mSize > size) {  // reduce size
+            if (isArrayUsed()) {    // array to array reduction, so no need to reallocate.
+                mSize = size;
+            } else if (size > ARRAY_CAPACITY) {  // heap to heap reduction
+                T* newPtr = new T[size];
+                const T* oldPtr = getPtr();
+                std::copy(oldPtr, oldPtr + size, newPtr);
+                free();
+                mArray[0] = reinterpret_cast<uintptr_t>(newPtr);
+                mSize = size;
+                mCapacity = size;
+            } else {  // heap to array reduction.
+                const T* oldPtr = getPtr();
+                T* newPtr = reinterpret_cast<T*>(&mArray[0]);
+                std::copy(oldPtr, oldPtr + size, newPtr);
+                delete[] oldPtr;  // we cannot use free() here because we wrote data to mArray.
+                mSize = size;
+                mCapacity = ARRAY_CAPACITY;
+            }
+        } else {  // mSize < size  // increase size
+            ensureCapacity(size);
+            T* ptr = getPtr();
+            for (uint16_t i = mSize; i < size; ++i) {
+                ptr[i] = value;
+            }
+            mSize = size;
+        }
+    }
+
+    void push_back(const T& x) {
+        if (mSize >= mCapacity) [[unlikely]] {
+            // exponential backoff
+            constexpr uint16_t kMaxIncrease = static_cast<uint16_t>(4096 / sizeof(T));
+            ensureCapacity(mCapacity + std::min(mCapacity, kMaxIncrease));
+        }
+        *(getPtr() + mSize) = x;
+        mSize++;
+    }
+
+    void shrink_to_fit() {
+        if (mSize == mCapacity || mCapacity == ARRAY_CAPACITY) {
+            return;
+        }
+
+        bool needFree = !isArrayUsed();
+
+        const T* oldPtr = getPtr();
+        T* newPtr;
+        if (mSize <= ARRAY_CAPACITY) {
+            newPtr = reinterpret_cast<T*>(&mArray[0]);
+            mCapacity = ARRAY_CAPACITY;
+            std::copy(oldPtr, oldPtr + mSize, newPtr);
+        } else {
+            newPtr = new T[mSize];
+            mCapacity = mSize;
+            std::copy(oldPtr, oldPtr + mSize, newPtr);
+            mArray[0] = reinterpret_cast<uintptr_t>(newPtr);
+        }
+        if (needFree) {
+            delete[] oldPtr;
+        }
+    }
+
+    void clear() {
+        mSize = 0;  // don't free up until free is called.
+    }
+
+    bool empty() const { return mSize == 0; }
+
+    uint16_t size() const { return mSize; }
+    uint16_t capacity() const { return mCapacity; }
+
+private:
+    uintptr_t mArray[PTR_ARRAY_SIZE];
+    uint16_t mSize;
+    uint16_t mCapacity;
+
+    void copy(const T* src, uint16_t count) {
+        clear();
+        ensureCapacity(count);
+        mSize = count;
+        memcpy(getPtr(), src, count * sizeof(T));
+    }
+
+    void move(PackedVector&& o) {
+        mSize = o.mSize;
+        o.mSize = 0;
+        mCapacity = o.mCapacity;
+        o.mCapacity = ARRAY_CAPACITY;
+        for (uint32_t i = 0; i < PTR_ARRAY_SIZE; ++i) {
+            mArray[i] = o.mArray[i];
+            o.mArray[i] = 0;
+        }
+    }
+
+    inline bool isArrayUsed() const { return mCapacity <= ARRAY_CAPACITY; }
+
+    void ensureCapacity(uint16_t capacity) {
+        if (capacity <= mCapacity) {
+            return;
+        }
+
+        if (capacity > ARRAY_CAPACITY) {
+            T* newPtr = new T[capacity];
+            const T* oldPtr = getPtr();
+            std::copy(oldPtr, oldPtr + mSize, newPtr);
+            free();
+            mArray[0] = reinterpret_cast<uintptr_t>(newPtr);
+            mCapacity = capacity;
+        } else {
+            mCapacity = ARRAY_CAPACITY;
+        }
+    }
+
+    void free() {
+        if (!isArrayUsed()) {
+            delete[] reinterpret_cast<T*>(mArray[0]);
+            mArray[0] = 0;
+            mCapacity = ARRAY_CAPACITY;
+        }
+    }
+
+    inline T* getPtr() {
+        return isArrayUsed() ? reinterpret_cast<T*>(&mArray[0]) : reinterpret_cast<T*>(mArray[0]);
+    }
+
+    inline const T* getPtr() const {
+        return isArrayUsed() ? reinterpret_cast<const T*>(&mArray[0])
+                             : reinterpret_cast<const T*>(mArray[0]);
+    }
+
+public:
+    inline const T* begin() const { return getPtr(); }
+    inline const T* end() const { return getPtr() + mSize; }
+    inline const T* back() const { return getPtr() + mSize - 1; }
+    inline T* begin() { return getPtr(); }
+    inline T* end() { return getPtr() + mSize; }
+    inline T* back() { return getPtr() + mSize - 1; }
+};
+
+}  // namespace minikin
+#endif  // MINIKIN_PACKED_VECTOR_H
diff --git a/include/minikin/SortedPackedVector.h b/include/minikin/SortedPackedVector.h
new file mode 100644
index 0000000..f3367af
--- /dev/null
+++ b/include/minikin/SortedPackedVector.h
@@ -0,0 +1,73 @@
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
+#ifndef MINIKIN_SORTED_VECTOR_H
+#define MINIKIN_SORTED_VECTOR_H
+
+#include <algorithm>
+#include <vector>
+
+#include "minikin/PackedVector.h"
+
+namespace minikin {
+
+// An immutable packed vector that elements are sorted.
+template <typename T, size_t ARRAY_SIZE = 2>
+class SortedPackedVector {
+public:
+    SortedPackedVector() {}
+    SortedPackedVector(const T* ptr, uint16_t count, bool sorted = false) : mPacked(ptr, count) {
+        if (!sorted) {
+            sort();
+        }
+    }
+    SortedPackedVector(const std::vector<T>& vec, bool sorted = false) : mPacked(vec) {
+        if (!sorted) {
+            sort();
+        }
+    }
+    SortedPackedVector(std::initializer_list<T> init, bool sorted = false) : mPacked(init) {
+        if (!sorted) {
+            sort();
+        }
+    }
+
+    SortedPackedVector(const SortedPackedVector& o) = default;
+    SortedPackedVector& operator=(const SortedPackedVector& o) = default;
+    SortedPackedVector(SortedPackedVector&& o) = default;
+    SortedPackedVector& operator=(SortedPackedVector&& o) = default;
+
+    uint16_t size() const { return mPacked.size(); }
+    bool empty() const { return size() == 0; }
+
+    const T& operator[](uint16_t i) const { return mPacked[i]; }
+    const T* data() const { return mPacked.data(); }
+
+    inline bool operator==(const SortedPackedVector<T>& o) const { return mPacked == o.mPacked; }
+
+    inline bool operator!=(const SortedPackedVector<T>& o) const { return !(*this == o); }
+
+    inline const T* begin() const { return mPacked.begin(); }
+    inline const T* end() const { return mPacked.end(); }
+
+private:
+    void sort() { std::sort(mPacked.begin(), mPacked.end()); }
+
+    PackedVector<T, ARRAY_SIZE> mPacked;
+};
+
+}  // namespace minikin
+#endif  // MINIKIN_SORTED_VECTOR_H
diff --git a/libs/minikin/Android.bp b/libs/minikin/Android.bp
index 33b8977..d7db300 100644
--- a/libs/minikin/Android.bp
+++ b/libs/minikin/Android.bp
@@ -45,12 +45,26 @@ cc_library_static {
     lto: {
         never: true,
     },
-    shared_libs: [
-        "libicu",
-    ],
-    export_shared_lib_headers: [
-        "libicu",
-    ],
+    target: {
+        android: {
+            shared_libs: [
+                "libicu",
+            ],
+            export_shared_lib_headers: [
+                "libicu",
+            ],
+        },
+        host: {
+            shared_libs: [
+                "libicui18n",
+                "libicuuc",
+            ],
+            export_shared_lib_headers: [
+                "libicui18n",
+                "libicuuc",
+            ],
+        },
+    },
 }
 
 cc_library {
@@ -122,6 +136,7 @@ cc_library {
             shared_libs: [
                 "libicu",
                 "aconfig_text_flags_c_lib",
+                "server_configurable_flags",
             ],
             export_shared_lib_headers: [
                 "libicu",
@@ -132,6 +147,7 @@ cc_library {
             ],
             whole_static_libs: [
                 "libminikin_rust_ffi",
+                "libflags_rust_cpp_bridge",
             ],
         },
         host: {
@@ -148,7 +164,7 @@ cc_library {
                 "libminikin_cxx_bridge_header",
             ],
         },
-        not_windows: {
+        linux: {
             whole_static_libs: [
                 "libminikin_rust_ffi",
             ],
diff --git a/libs/minikin/BidiUtils.cpp b/libs/minikin/BidiUtils.cpp
index 5000c4a..a588291 100644
--- a/libs/minikin/BidiUtils.cpp
+++ b/libs/minikin/BidiUtils.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "BidiUtils.h"
 
 #include <algorithm>
diff --git a/libs/minikin/BidiUtils.h b/libs/minikin/BidiUtils.h
index 8647b54..d3413f0 100644
--- a/libs/minikin/BidiUtils.h
+++ b/libs/minikin/BidiUtils.h
@@ -17,8 +17,6 @@
 #ifndef MINIKIN_BIDI_UTILS_H
 #define MINIKIN_BIDI_UTILS_H
 
-#define LOG_TAG "Minikin"
-
 #include "minikin/Layout.h"
 
 #include <memory>
diff --git a/libs/minikin/FeatureFlags.h b/libs/minikin/FeatureFlags.h
index 60071fe..88afdc2 100644
--- a/libs/minikin/FeatureFlags.h
+++ b/libs/minikin/FeatureFlags.h
@@ -36,11 +36,8 @@ namespace features {
     }
 #endif  //  __ANDROID__
 
-DEFINE_FEATURE_FLAG_ACCESSOROR(phrase_strict_fallback)
-DEFINE_FEATURE_FLAG_ACCESSOROR(word_style_auto)
-DEFINE_FEATURE_FLAG_ACCESSOROR(letter_spacing_justification)
-DEFINE_FEATURE_FLAG_ACCESSOROR(lazy_variation_instance)
 DEFINE_FEATURE_FLAG_ACCESSOROR(rust_hyphenator);
+DEFINE_FEATURE_FLAG_ACCESSOROR(typeface_redesign);
 
 }  // namespace features
 
diff --git a/libs/minikin/Font.cpp b/libs/minikin/Font.cpp
index fefb407..0d3d610 100644
--- a/libs/minikin/Font.cpp
+++ b/libs/minikin/Font.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "minikin/Font.h"
 
 #include <hb-ot.h>
@@ -160,6 +158,11 @@ bool Font::isAxisSupported(uint32_t tag) const {
 
 Font::~Font() {
     resetExternalRefs(nullptr);
+
+    FVarTable* fvarTable = mFVarTableHolder.exchange(nullptr);
+    if (fvarTable != nullptr) {
+        delete fvarTable;
+    }
 }
 
 void Font::resetExternalRefs(ExternalRefs* refs) {
@@ -210,6 +213,24 @@ const Font::ExternalRefs* Font::getExternalRefs() const {
     }
 }
 
+const FVarTable& Font::getFVarTable() const {
+    FVarTable* fvarTable = mFVarTableHolder.load();
+    if (fvarTable) return *fvarTable;
+
+    FVarTable* newFvar = new FVarTable();
+    HbBlob fvarBlob(baseFont(), TAG_fvar);
+    if (fvarBlob) {
+        readFVarTable(fvarBlob.get(), fvarBlob.size(), newFvar);
+    }
+    FVarTable* expected = nullptr;
+    if (mFVarTableHolder.compare_exchange_strong(expected, newFvar)) {
+        return *newFvar;
+    } else {
+        delete newFvar;
+        return *expected;
+    }
+}
+
 // static
 HbFontUniquePtr Font::prepareFont(const std::shared_ptr<MinikinFont>& typeface) {
     const char* buf = reinterpret_cast<const char*>(typeface->GetFontData());
diff --git a/libs/minikin/FontCollection.cpp b/libs/minikin/FontCollection.cpp
index 8605537..ded7643 100644
--- a/libs/minikin/FontCollection.cpp
+++ b/libs/minikin/FontCollection.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "minikin/FontCollection.h"
 
 #include <log/log.h>
@@ -611,7 +609,7 @@ FontCollection::FamilyMatchResult FontCollection::FamilyMatchResult::intersect(
 
 void FontCollection::filterFamilyByLocale(
         const LocaleList& localeList,
-        const std::function<void(const FontFamily& family)>& callback) const {
+        const std::function<bool(const FontFamily& family)>& callback) const {
     if (localeList.empty()) {
         return;
     }
@@ -627,8 +625,12 @@ void FontCollection::filterFamilyByLocale(
         const LocaleList& fontLocaleList = LocaleListCache::getById(fontLocaleId);
         for (uint32_t i = 0; i < fontLocaleList.size(); ++i) {
             if (fontLocaleList[i].isEqualScript(locale)) {
-                callback(*family.get());
-                break;
+                bool cont = callback(*family.get());
+                if (cont) {
+                    break;
+                } else {
+                    return;
+                }
             }
         }
     }
@@ -646,6 +648,7 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
     }
 
     MinikinExtent result(0, 0);
+    // Reserve the custom font's extent.
     for (uint8_t i = 0; i < mFamilyCount; ++i) {
         const auto& family = getFamilyAt(i);
         if (!family->isCustomFallback()) {
@@ -677,7 +680,7 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
                                                     : family.variant();
 
         if (familyVariant != requestVariant) {
-            return;
+            return true;  // continue other families
         }
 
         MinikinExtent extent(0, 0);
@@ -686,6 +689,7 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
         result.extendBy(extent);
 
         familyFound = true;
+        return false;  // We found it, stop searching.
     });
 
     // If nothing matches, try non-variant match cases since it is used for fallback.
@@ -697,6 +701,7 @@ MinikinExtent FontCollection::getReferenceExtentForLocale(const MinikinPaint& pa
         result.extendBy(extent);
 
         familyFound = true;
+        return false;  // We found it. stop searching.
     });
 
     // If nothing matches, use default font.
@@ -909,9 +914,7 @@ std::shared_ptr<FontCollection> FontCollection::createCollectionWithVariation(
     std::vector<std::shared_ptr<FontFamily>> families;
     for (size_t i = 0; i < getFamilyCount(); ++i) {
         const std::shared_ptr<FontFamily>& family = getFamilyAt(i);
-        std::shared_ptr<FontFamily> newFamily =
-                features::lazy_variation_instance() ? FontFamily::create(family, variations)
-                                                    : family->createFamilyWithVariation(variations);
+        std::shared_ptr<FontFamily> newFamily = FontFamily::create(family, variations);
         if (newFamily) {
             families.push_back(newFamily);
         } else {
diff --git a/libs/minikin/FontFamily.cpp b/libs/minikin/FontFamily.cpp
index a85678e..d821ea0 100644
--- a/libs/minikin/FontFamily.cpp
+++ b/libs/minikin/FontFamily.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "minikin/FontFamily.h"
 
 #include <log/log.h>
diff --git a/libs/minikin/FontFileParser.cpp b/libs/minikin/FontFileParser.cpp
index a7d5210..b55853a 100644
--- a/libs/minikin/FontFileParser.cpp
+++ b/libs/minikin/FontFileParser.cpp
@@ -16,8 +16,6 @@
 
 #include "minikin/FontFileParser.h"
 
-#define LOG_TAG "Minikin"
-
 #include <hb-ot.h>
 #include <hb.h>
 
diff --git a/libs/minikin/FontUtils.cpp b/libs/minikin/FontUtils.cpp
index 560b309..fe66383 100644
--- a/libs/minikin/FontUtils.cpp
+++ b/libs/minikin/FontUtils.cpp
@@ -31,6 +31,12 @@ static uint32_t readU32(const uint8_t* data, size_t offset) {
            ((uint32_t)data[offset + 2]) << 8 | ((uint32_t)data[offset + 3]);
 }
 
+static float read1616Fixed(const uint8_t* data, size_t offset) {
+    uint32_t bits = readU32(data, offset);
+    int32_t fixed = *reinterpret_cast<int32_t*>(&bits);
+    return fixed / float(0x10000);
+}
+
 bool analyzeStyle(const uint8_t* os2_data, size_t os2_size, int* weight, bool* italic) {
     const size_t kUsWeightClassOffset = 4;
     const size_t kFsSelectionOffset = 62;
@@ -79,4 +85,40 @@ bool analyzeAxes(const uint8_t* fvar_data, size_t fvar_size, std::unordered_set<
     }
     return true;
 }
+
+bool readFVarTable(const uint8_t* fvar_data, size_t fvar_size, FVarTable* out) {
+    const size_t kMajorVersionOffset = 0;
+    const size_t kMinorVersionOffset = 2;
+    const size_t kOffsetToAxesArrayOffset = 4;
+    const size_t kAxisCountOffset = 8;
+    const size_t kAxisSizeOffset = 10;
+
+    out->clear();
+
+    if (fvar_size < kAxisSizeOffset + 2) {
+        return false;
+    }
+    const uint16_t majorVersion = readU16(fvar_data, kMajorVersionOffset);
+    const uint16_t minorVersion = readU16(fvar_data, kMinorVersionOffset);
+    const uint32_t axisOffset = readU16(fvar_data, kOffsetToAxesArrayOffset);
+    const uint32_t axisCount = readU16(fvar_data, kAxisCountOffset);
+    const uint32_t axisSize = readU16(fvar_data, kAxisSizeOffset);
+
+    if (majorVersion != 1 || minorVersion != 0 || axisOffset != 0x10 || axisSize != 0x14) {
+        return false;  // Unsupported version.
+    }
+    if (fvar_size < axisOffset + axisSize * axisCount) {
+        return false;  // Invalid table size.
+    }
+    for (uint32_t i = 0; i < axisCount; ++i) {
+        size_t axisRecordOffset = axisOffset + i * axisSize;
+        uint32_t tag = readU32(fvar_data, axisRecordOffset);
+        float minValue = read1616Fixed(fvar_data, axisRecordOffset + 4);
+        float defValue = read1616Fixed(fvar_data, axisRecordOffset + 8);
+        float maxValue = read1616Fixed(fvar_data, axisRecordOffset + 12);
+        FVarEntry entry = {minValue, maxValue, defValue};
+        out->emplace(tag, entry);
+    }
+    return true;
+}
 }  // namespace minikin
diff --git a/libs/minikin/FontUtils.h b/libs/minikin/FontUtils.h
index 15ee4d0..537584e 100644
--- a/libs/minikin/FontUtils.h
+++ b/libs/minikin/FontUtils.h
@@ -20,10 +20,13 @@
 #include <cstdint>
 #include <unordered_set>
 
+#include "minikin/FVarTable.h"
+
 namespace minikin {
 
 bool analyzeStyle(const uint8_t* os2_data, size_t os2_size, int* weight, bool* italic);
 bool analyzeAxes(const uint8_t* fvar_data, size_t fvar_size, std::unordered_set<uint32_t>* axes);
+bool readFVarTable(const uint8_t* fvar_data, size_t fvar_size, FVarTable* out);
 
 }  // namespace minikin
 
diff --git a/libs/minikin/GreedyLineBreaker.cpp b/libs/minikin/GreedyLineBreaker.cpp
index fa16344..8541eea 100644
--- a/libs/minikin/GreedyLineBreaker.cpp
+++ b/libs/minikin/GreedyLineBreaker.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "GreedyLineBreak"
-
 #include "FeatureFlags.h"
 #include "HyphenatorMap.h"
 #include "LineBreakerUtil.h"
@@ -304,9 +302,6 @@ bool GreedyLineBreaker::doLineBreakWithGraphemeBounds(const Range& range) {
 }
 
 bool GreedyLineBreaker::doLineBreakWithFallback(const Range& range) {
-    if (!features::phrase_strict_fallback()) {
-        return false;
-    }
     Run* targetRun = nullptr;
     for (const auto& run : mMeasuredText.runs) {
         if (run->getRange().contains(range)) {
@@ -456,14 +451,9 @@ void GreedyLineBreaker::process(bool forceWordStyleAutoToPhrase) {
     uint32_t nextWordBoundaryOffset = 0;
     for (uint32_t runIndex = 0; runIndex < mMeasuredText.runs.size(); ++runIndex) {
         const std::unique_ptr<Run>& run = mMeasuredText.runs[runIndex];
-        if (features::letter_spacing_justification()) {
-            mCurrentLetterSpacing = run->getLetterSpacingInPx();
-            if (runIndex == 0) {
-                mLineStartLetterSpacing = mCurrentLetterSpacing;
-            }
-        } else {
-            mCurrentLetterSpacing = 0;
-            mLineStartLetterSpacing = 0;
+        mCurrentLetterSpacing = run->getLetterSpacingInPx();
+        if (runIndex == 0) {
+            mLineStartLetterSpacing = mCurrentLetterSpacing;
         }
         const Range range = run->getRange();
 
@@ -559,10 +549,6 @@ LineBreakResult breakLineGreedy(const U16StringPiece& textBuf, const MeasuredTex
     lineBreaker.process(false);
     LineBreakResult res = lineBreaker.getResult();
 
-    if (!features::word_style_auto()) {
-        return res;
-    }
-
     // The line breaker says that retry with phrase based word break because of the auto option and
     // given locales.
     if (!lineBreaker.retryWithPhraseWordBreak) {
diff --git a/libs/minikin/Hyphenator.cpp b/libs/minikin/Hyphenator.cpp
index 635d201..bea773c 100644
--- a/libs/minikin/Hyphenator.cpp
+++ b/libs/minikin/Hyphenator.cpp
@@ -28,9 +28,9 @@
 #include "MinikinInternal.h"
 #include "minikin/Characters.h"
 
-#ifndef _WIN32
+#ifdef __linux__
 #include "minikin_cxx_bridge.rs.h"
-#endif  // _WIN32
+#endif  // __linux__
 
 namespace minikin {
 
@@ -102,7 +102,7 @@ struct Header {
     }
 };
 
-#ifndef _WIN32
+#ifdef __linux__
 class HyphenatorRust : public Hyphenator {
 public:
     HyphenatorRust(const uint8_t* patternData, size_t dataSize, size_t minPrefix, size_t minSuffix,
@@ -120,35 +120,33 @@ public:
 private:
     ::rust::Box<rust::Hyphenator> mHyphenator;
 };
-#endif  // _WIN32
+#endif  // __linux__
 
 // static
 Hyphenator* Hyphenator::loadBinary(const uint8_t* patternData, size_t dataSize, size_t minPrefix,
                                    size_t minSuffix, const std::string& locale) {
-#ifdef _WIN32
-    return HyphenatorCXX::loadBinary(patternData, dataSize, minPrefix, minSuffix, locale);
-#else   // _WIN32
+#ifdef __linux__
     if (features::rust_hyphenator()) {
         return new HyphenatorRust(patternData, dataSize, minPrefix, minSuffix, locale);
-    } else {
-        return HyphenatorCXX::loadBinary(patternData, dataSize, minPrefix, minSuffix, locale);
     }
-#endif  // _WIN32
+#endif  // __linux__
+    return HyphenatorCXX::loadBinary(patternData, dataSize, minPrefix, minSuffix, locale);
 }
 
-#ifdef _WIN32
-Hyphenator* Hyphenator::loadBinaryForRust(const uint8_t* /*patternData*/, size_t /*dataSize*/,
-                                          size_t /*minPrefix*/, size_t /*minSuffix*/,
-                                          const std::string& /*locale*/) {
-    MINIKIN_NOT_REACHED("Rust implementation is not available on Win32");
-}
-#else   // _WIN32
+#ifdef __linux__
 Hyphenator* Hyphenator::loadBinaryForRust(const uint8_t* patternData, size_t dataSize,
                                           size_t minPrefix, size_t minSuffix,
                                           const std::string& locale) {
     return new HyphenatorRust(patternData, dataSize, minPrefix, minSuffix, locale);
 }
-#endif  // _WIN32
+#else   // __linux__
+Hyphenator* Hyphenator::loadBinaryForRust(const uint8_t* /*patternData*/, size_t /*dataSize*/,
+                                          size_t /*minPrefix*/, size_t /*minSuffix*/,
+                                          const std::string& /*locale*/) {
+    MINIKIN_NOT_REACHED("Rust implementation is only available on linux/Android");
+}
+#endif  // __linux__
+
 // static
 Hyphenator* HyphenatorCXX::loadBinary(const uint8_t* patternData, size_t, size_t minPrefix,
                                       size_t minSuffix, const std::string& locale) {
@@ -159,6 +157,8 @@ Hyphenator* HyphenatorCXX::loadBinary(const uint8_t* patternData, size_t, size_t
         hyphenLocale = HyphenationLocale::CATALAN;
     } else if (locale == "sl") {
         hyphenLocale = HyphenationLocale::SLOVENIAN;
+    } else if (locale == "pt") {
+        hyphenLocale = HyphenationLocale::PORTUGUESE;
     }
     return new HyphenatorCXX(patternData, minPrefix, minSuffix, hyphenLocale);
 }
@@ -179,7 +179,7 @@ void HyphenatorCXX::hyphenate(const U16StringPiece& word, HyphenationType* out)
         const HyphenationType hyphenValue = alphabetLookup(alpha_codes, word);
 
         if (hyphenValue != HyphenationType::DONT_BREAK) {
-            hyphenateFromCodes(alpha_codes, paddedLen, hyphenValue, out);
+            hyphenateFromCodes(alpha_codes, paddedLen, hyphenValue, word, out);
             return;
         }
         // TODO: try NFC normalization
@@ -403,7 +403,8 @@ HyphenationType HyphenatorCXX::alphabetLookup(uint16_t* alpha_codes,
  * Note: len here is the padded length including 0 codes at start and end.
  **/
 void HyphenatorCXX::hyphenateFromCodes(const uint16_t* codes, size_t len,
-                                       HyphenationType hyphenValue, HyphenationType* out) const {
+                                       HyphenationType hyphenValue, const U16StringPiece& word,
+                                       HyphenationType* out) const {
     static_assert(sizeof(HyphenationType) == sizeof(uint8_t), "HyphnationType must be uint8_t.");
     // Reuse the result array as a buffer for calculating intermediate hyphenation numbers.
     uint8_t* buffer = reinterpret_cast<uint8_t*>(out);
@@ -450,6 +451,22 @@ void HyphenatorCXX::hyphenateFromCodes(const uint16_t* codes, size_t len,
     for (size_t i = mMinPrefix; i < maxOffset; i++) {
         // Hyphenation opportunities happen when the hyphenation numbers are odd.
         out[i] = (buffer[i] & 1u) ? hyphenValue : HyphenationType::DONT_BREAK;
+        if (i > 0 && isLineBreakingHyphen(word[i - 1])) {
+            if (mHyphenationLocale == HyphenationLocale::PORTUGUESE) {
+                // In Portuguese, prefer to break before the hyphen, i.e. the line start with
+                // the hyphen. If we see hyphenation break point after the hyphen character,
+                // prefer to break before the hyphen.
+                out[i - 1] = HyphenationType::BREAK_AND_DONT_INSERT_HYPHEN;
+                out[i] = HyphenationType::DONT_BREAK;  // Not prefer to break here because
+                                                       // this character is just after the
+                                                       // hyphen character.
+            } else {
+                // If we see hyphen character just before this character, add hyphenation break
+                // point and don't break here.
+                out[i - 1] = HyphenationType::DONT_BREAK;
+                out[i] = HyphenationType::BREAK_AND_DONT_INSERT_HYPHEN;
+            }
+        }
     }
 }
 
diff --git a/libs/minikin/Layout.cpp b/libs/minikin/Layout.cpp
index a7b4444..e612130 100644
--- a/libs/minikin/Layout.cpp
+++ b/libs/minikin/Layout.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "minikin/Layout.h"
 
 #include <hb-icu.h>
@@ -32,6 +30,7 @@
 #include <vector>
 
 #include "BidiUtils.h"
+#include "FeatureFlags.h"
 #include "LayoutSplitter.h"
 #include "LayoutUtils.h"
 #include "LetterSpacingUtils.h"
@@ -341,9 +340,36 @@ float Layout::doLayoutWord(const uint16_t* buf, size_t start, size_t count, size
 }
 
 void Layout::appendLayout(const LayoutPiece& src, size_t start, float extraAdvance) {
-    for (size_t i = 0; i < src.glyphCount(); i++) {
-        mGlyphs.emplace_back(src.fontAt(i), src.glyphIdAt(i), src.clusterAt(i) + start,
-                             mAdvance + src.pointAt(i).x, src.pointAt(i).y);
+    if (features::typeface_redesign()) {
+        if (src.glyphCount() == 0) {
+            return;
+        }
+        if (mFonts.empty()) {
+            mFonts.push_back(src.fontAt(0));
+            mEnds.push_back(1);
+        }
+        FakedFont* lastFont = &mFonts.back();
+
+        for (size_t i = 0; i < src.glyphCount(); i++) {
+            const FakedFont& font = src.fontAt(i);
+
+            if (font != *lastFont) {
+                mEnds.back() = mGlyphs.size();
+                mFonts.push_back(font);
+                mEnds.push_back(mGlyphs.size() + 1);
+                lastFont = &mFonts.back();
+            } else if (i == src.glyphCount() - 1) {
+                mEnds.back() = mGlyphs.size() + 1;
+            }
+
+            mGlyphs.emplace_back(src.fontAt(i), src.glyphIdAt(i), src.clusterAt(i) + start,
+                                 mAdvance + src.pointAt(i).x, src.pointAt(i).y);
+        }
+    } else {
+        for (size_t i = 0; i < src.glyphCount(); i++) {
+            mGlyphs.emplace_back(src.fontAt(i), src.glyphIdAt(i), src.clusterAt(i) + start,
+                                 mAdvance + src.pointAt(i).x, src.pointAt(i).y);
+        }
     }
     const std::vector<float>& advances = src.advances();
     for (size_t i = 0; i < advances.size(); i++) {
diff --git a/libs/minikin/LayoutCore.cpp b/libs/minikin/LayoutCore.cpp
index 3c52635..b32566b 100644
--- a/libs/minikin/LayoutCore.cpp
+++ b/libs/minikin/LayoutCore.cpp
@@ -14,7 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
 #define ATRACE_TAG ATRACE_TAG_VIEW
 
 #include "minikin/LayoutCore.h"
diff --git a/libs/minikin/LayoutSplitter.h b/libs/minikin/LayoutSplitter.h
index 319a702..7a9b2f8 100644
--- a/libs/minikin/LayoutSplitter.h
+++ b/libs/minikin/LayoutSplitter.h
@@ -17,8 +17,6 @@
 #ifndef MINIKIN_LAYOUT_SPLITTER_H
 #define MINIKIN_LAYOUT_SPLITTER_H
 
-#define LOG_TAG "Minikin"
-
 #include "minikin/Layout.h"
 
 #include <memory>
diff --git a/libs/minikin/LetterSpacingUtils.h b/libs/minikin/LetterSpacingUtils.h
index 21798fb..48cbc0f 100644
--- a/libs/minikin/LetterSpacingUtils.h
+++ b/libs/minikin/LetterSpacingUtils.h
@@ -17,8 +17,6 @@
 #ifndef MINIKIN_LETTER_SPACING_UTILS_H
 #define MINIKIN_LETTER_SPACING_UTILS_H
 
-#define LOG_TAG "Minikin"
-
 #include <hb.h>
 
 namespace minikin {
diff --git a/libs/minikin/LocaleListCache.cpp b/libs/minikin/LocaleListCache.cpp
index acda312..95de47e 100644
--- a/libs/minikin/LocaleListCache.cpp
+++ b/libs/minikin/LocaleListCache.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "LocaleListCache.h"
 
 #include <unordered_set>
diff --git a/libs/minikin/MeasuredText.cpp b/libs/minikin/MeasuredText.cpp
index 8a37dc7..20d5aa3 100644
--- a/libs/minikin/MeasuredText.cpp
+++ b/libs/minikin/MeasuredText.cpp
@@ -14,7 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
 #include "minikin/MeasuredText.h"
 
 #include "BidiUtils.h"
diff --git a/libs/minikin/MinikinFontFactory.cpp b/libs/minikin/MinikinFontFactory.cpp
index 77f13d8..1a9eba9 100644
--- a/libs/minikin/MinikinFontFactory.cpp
+++ b/libs/minikin/MinikinFontFactory.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "minikin/MinikinFontFactory.h"
 
 #include <log/log.h>
diff --git a/libs/minikin/MinikinInternal.cpp b/libs/minikin/MinikinInternal.cpp
index dd60280..0b21e50 100644
--- a/libs/minikin/MinikinInternal.cpp
+++ b/libs/minikin/MinikinInternal.cpp
@@ -15,8 +15,6 @@
  */
 // Definitions internal to Minikin
 
-#define LOG_TAG "Minikin"
-
 #include "MinikinInternal.h"
 
 #include <log/log.h>
@@ -48,12 +46,4 @@ bool isVariationSelector(uint32_t codePoint) {
     return isBMPVariationSelector(codePoint) || isVariationSelectorSupplement(codePoint);
 }
 
-bool MinikinPaint::skipCache() const {
-    if (features::letter_spacing_justification()) {
-        return false;  // if the flag is on, do not skip the cache.
-    } else {
-        return !fontFeatureSettings.empty();
-    }
-}
-
 }  // namespace minikin
diff --git a/libs/minikin/OptimalLineBreaker.cpp b/libs/minikin/OptimalLineBreaker.cpp
index e7f32a2..8824d43 100644
--- a/libs/minikin/OptimalLineBreaker.cpp
+++ b/libs/minikin/OptimalLineBreaker.cpp
@@ -191,42 +191,29 @@ std::vector<DesperateBreak> populateDesperatePoints(const U16StringPiece& textBu
                                                     const Range& range, const Run& run) {
     std::vector<DesperateBreak> out;
 
-    if (!features::phrase_strict_fallback() ||
-        run.lineBreakWordStyle() == LineBreakWordStyle::None) {
-        ParaWidth width = measured.widths[range.getStart()];
-        for (uint32_t i = range.getStart() + 1; i < range.getEnd(); ++i) {
-            const float w = measured.widths[i];
-            if (w == 0) {
-                continue;  // w == 0 means here is not a grapheme bounds. Don't break here.
-            }
-            out.emplace_back(i, width, SCORE_DESPERATE);
-            width += w;
+    WordBreaker wb;
+    wb.setText(textBuf.data(), textBuf.length());
+    ssize_t next =
+            wb.followingWithLocale(getEffectiveLocale(run.getLocaleListId()), run.lineBreakStyle(),
+                                   LineBreakWordStyle::None, range.getStart());
+
+    const bool calculateFallback = range.contains(next);
+    ParaWidth width = measured.widths[range.getStart()];
+    for (uint32_t i = range.getStart() + 1; i < range.getEnd(); ++i) {
+        const float w = measured.widths[i];
+        if (w == 0) {
+            continue;  // w == 0 means here is not a grapheme bounds. Don't break here.
         }
-    } else {
-        WordBreaker wb;
-        wb.setText(textBuf.data(), textBuf.length());
-        ssize_t next = wb.followingWithLocale(getEffectiveLocale(run.getLocaleListId()),
-                                              run.lineBreakStyle(), LineBreakWordStyle::None,
-                                              range.getStart());
-
-        const bool calculateFallback = range.contains(next);
-        ParaWidth width = measured.widths[range.getStart()];
-        for (uint32_t i = range.getStart() + 1; i < range.getEnd(); ++i) {
-            const float w = measured.widths[i];
-            if (w == 0) {
-                continue;  // w == 0 means here is not a grapheme bounds. Don't break here.
-            }
-            if (calculateFallback && i == (uint32_t)next) {
-                out.emplace_back(i, width, SCORE_FALLBACK);
-                next = wb.next();
-                if (!range.contains(next)) {
-                    break;
-                }
-            } else {
-                out.emplace_back(i, width, SCORE_DESPERATE);
+        if (calculateFallback && i == (uint32_t)next) {
+            out.emplace_back(i, width, SCORE_FALLBACK);
+            next = wb.next();
+            if (!range.contains(next)) {
+                break;
             }
-            width += w;
+        } else {
+            out.emplace_back(i, width, SCORE_DESPERATE);
         }
+        width += w;
     }
 
     return out;
@@ -267,14 +254,10 @@ OptimizeContext populateCandidates(const U16StringPiece& textBuf, const Measured
     CharProcessor proc(textBuf);
 
     float initialLetterSpacing;
-    if (features::letter_spacing_justification()) {
-        if (measured.runs.empty()) {
-            initialLetterSpacing = 0;
-        } else {
-            initialLetterSpacing = measured.runs[0]->getLetterSpacingInPx();
-        }
-    } else {
+    if (measured.runs.empty()) {
         initialLetterSpacing = 0;
+    } else {
+        initialLetterSpacing = measured.runs[0]->getLetterSpacingInPx();
     }
     OptimizeContext result(initialLetterSpacing);
 
@@ -284,8 +267,7 @@ OptimizeContext populateCandidates(const U16StringPiece& textBuf, const Measured
     for (const auto& run : measured.runs) {
         const bool isRtl = run->isRtl();
         const Range& range = run->getRange();
-        const float letterSpacing =
-                features::letter_spacing_justification() ? run->getLetterSpacingInPx() : 0;
+        const float letterSpacing = run->getLetterSpacingInPx();
 
         // Compute penalty parameters.
         float hyphenPenalty = 0.0f;
@@ -535,10 +517,6 @@ LineBreakResult breakLineOptimal(const U16StringPiece& textBuf, const MeasuredTe
     LineBreakResult res = optimizer.computeBreaks(context, textBuf, measured, lineWidth, strategy,
                                                   justified, useBoundsForWidth);
 
-    if (!features::word_style_auto()) {
-        return res;
-    }
-
     // The line breaker says that retry with phrase based word break because of the auto option and
     // given locales.
     if (!context.retryWithPhraseWordBreak) {
diff --git a/libs/minikin/ScriptUtils.cpp b/libs/minikin/ScriptUtils.cpp
index 90bd5de..3c2b2d5 100644
--- a/libs/minikin/ScriptUtils.cpp
+++ b/libs/minikin/ScriptUtils.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "ScriptUtils.h"
 
 #include <unicode/ubidi.h>
diff --git a/libs/minikin/ScriptUtils.h b/libs/minikin/ScriptUtils.h
index 6eb2766..2d08f63 100644
--- a/libs/minikin/ScriptUtils.h
+++ b/libs/minikin/ScriptUtils.h
@@ -17,8 +17,6 @@
 #ifndef MINIKIN_SCRIPT_UTILS_H
 #define MINIKIN_SCRIPT_UTILS_H
 
-#define LOG_TAG "Minikin"
-
 #include <unicode/ubidi.h>
 
 #include <memory>
diff --git a/libs/minikin/SystemFonts.cpp b/libs/minikin/SystemFonts.cpp
index b263d66..0c4432c 100644
--- a/libs/minikin/SystemFonts.cpp
+++ b/libs/minikin/SystemFonts.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "minikin/SystemFonts.h"
 
 namespace minikin {
diff --git a/libs/minikin/WordBreaker.cpp b/libs/minikin/WordBreaker.cpp
index a1e9526..1626336 100644
--- a/libs/minikin/WordBreaker.cpp
+++ b/libs/minikin/WordBreaker.cpp
@@ -16,18 +16,18 @@
 
 #include "WordBreaker.h"
 
-#include <list>
-#include <map>
-
 #include <unicode/ubrk.h>
 #include <unicode/uchar.h>
 #include <unicode/utf16.h>
 
-#include "minikin/Emoji.h"
-#include "minikin/Hyphenator.h"
+#include <list>
+#include <map>
 
+#include "FeatureFlags.h"
 #include "Locale.h"
 #include "MinikinInternal.h"
+#include "minikin/Emoji.h"
+#include "minikin/Hyphenator.h"
 
 namespace minikin {
 
@@ -230,6 +230,10 @@ enum ScanState {
 };
 
 void WordBreaker::detectEmailOrUrl() {
+    if (mIcuBreaker.lbStyle == LineBreakStyle::NoBreak) {
+        mInEmailOrUrl = false;
+        return;
+    }
     // scan forward from current ICU position for email address or URL
     if (mLast >= mScanOffset) {
         ScanState state = START;
diff --git a/rust/Android.bp b/rust/Android.bp
index 7a79214..8c7a99d 100644
--- a/rust/Android.bp
+++ b/rust/Android.bp
@@ -21,13 +21,24 @@ rust_defaults {
         "libcxx",
         "liblogger",
         "liblog_rust",
+        "libflags_rust",
     ],
     whole_static_libs: [
         "libminikin_from_rust_to_cpp",
     ],
+    static_libs: [
+        "libflags_rust_cpp_bridge",
+    ],
     shared_libs: [
         "libbase",
     ],
+    target: {
+        android: {
+            rustlibs: [
+                "libandroid_text_flags_rust",
+            ],
+        },
+    },
 }
 
 rust_ffi_static {
diff --git a/rust/hyphenator.rs b/rust/hyphenator.rs
index b65c0d0..3b87e8c 100644
--- a/rust/hyphenator.rs
+++ b/rust/hyphenator.rs
@@ -149,6 +149,8 @@ pub enum HyphenationLocale {
     Polish = 2,
     /// Slovenian
     Slovenian = 3,
+    /// Portuguese
+    Portuguese = 4,
 }
 
 const MAX_HYPHEN_SIZE: u32 = 64;
@@ -565,6 +567,8 @@ impl Hyphenator {
                 HyphenationLocale::Catalan
             } else if locale == "sl" {
                 HyphenationLocale::Slovenian
+            } else if locale == "pt" {
+                HyphenationLocale::Portuguese
             } else {
                 HyphenationLocale::Other
             },
@@ -588,7 +592,7 @@ impl Hyphenator {
             };
 
             if hyphen_value != HyphenationType::DontBreak {
-                self.hyphenate_from_codes(alpha_codes, padded_len, hyphen_value, out);
+                self.hyphenate_from_codes(alpha_codes, padded_len, hyphen_value, word, out);
                 return;
             }
             // TODO: try NFC normalization
@@ -713,6 +717,7 @@ impl Hyphenator {
         codes: [u16; MAX_HYPHEN_SIZE as usize],
         len: u32,
         hyphen_value: HyphenationType,
+        word: &[u16],
         out: &mut [u8],
     ) {
         let header = Header::new(self.data);
@@ -759,8 +764,31 @@ impl Hyphenator {
 
         // Since the above calculation does not modify values outside
         // [mMinPrefix, len - mMinSuffix], they are left as 0 = DONT_BREAK.
-        for r in out.iter_mut().take(max_offset as usize).skip(self.min_prefix as usize) {
-            *r = if *r & 1 != 0 { hyphen_value as u8 } else { HyphenationType::DontBreak as u8 };
+        for i in self.min_prefix as usize..max_offset as usize {
+            if out[i] & 1 == 0 {
+                out[i] = HyphenationType::DontBreak as u8;
+                continue;
+            }
+
+            if i == 0 || !Self::is_line_breaking_hyphen(word[i - 1]) {
+                out[i] = hyphen_value as u8;
+                continue;
+            }
+
+            if self.locale == HyphenationLocale::Portuguese {
+                // In Portuguese, prefer to break before the hyphen, i.e. the line start with
+                // the hyphen. If we see hyphenation break point after the hyphen character,
+                // prefer to break before the hyphen.
+                out[i - 1] = HyphenationType::BreakAndDontInsertHyphen as u8;
+                out[i] = HyphenationType::DontBreak as u8; // Not prefer to break here because
+                                                           // this character is just after the
+                                                           // hyphen character.
+            } else {
+                // If we see hyphen character just before this character, add hyphenation break
+                // point and don't break here.
+                out[i - 1] = HyphenationType::DontBreak as u8;
+                out[i] = HyphenationType::BreakAndDontInsertHyphen as u8;
+            }
         }
     }
 
diff --git a/rust/minikin.rs b/rust/minikin.rs
index d281f1c..8e24ab3 100644
--- a/rust/minikin.rs
+++ b/rust/minikin.rs
@@ -20,6 +20,7 @@ mod hyphenator;
 
 pub use hyphenator::Hyphenator;
 
+#[allow(clippy::needless_maybe_sized)]
 #[cxx::bridge(namespace = "minikin::rust")]
 mod ffi {
     #[namespace = "minikin::rust"]
diff --git a/tests/unittest/Android.bp b/tests/unittest/Android.bp
index 5a653a2..2e530ad 100644
--- a/tests/unittest/Android.bp
+++ b/tests/unittest/Android.bp
@@ -54,6 +54,7 @@ cc_test {
         "BufferTest.cpp",
         "CmapCoverageTest.cpp",
         "EmojiTest.cpp",
+        "FontFakeryTest.cpp",
         "FontTest.cpp",
         "FontCollectionTest.cpp",
         "FontCollectionItemizeTest.cpp",
@@ -76,8 +77,11 @@ cc_test {
         "LocaleListTest.cpp",
         "MeasuredTextTest.cpp",
         "MeasurementTests.cpp",
+        "MinikinPaintTest.cpp",
         "OptimalLineBreakerTest.cpp",
+        "PackedVectorTest.cpp",
         "ScriptUtilsTest.cpp",
+        "SortedPackedVectorTest.cpp",
         "SparseBitSetTest.cpp",
         "StringPieceTest.cpp",
         "SystemFontsTest.cpp",
diff --git a/tests/unittest/FontFakeryTest.cpp b/tests/unittest/FontFakeryTest.cpp
new file mode 100644
index 0000000..b0fe521
--- /dev/null
+++ b/tests/unittest/FontFakeryTest.cpp
@@ -0,0 +1,60 @@
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
+#include <gtest/gtest.h>
+
+#include "minikin/Constants.h"
+#include "minikin/FontFakery.h"
+
+namespace minikin {
+
+TEST(FontFakeryTest, testConstruct) {
+    EXPECT_EQ(FontFakery(), FontFakery(false, false));
+    EXPECT_NE(FontFakery(), FontFakery(true, false));
+    EXPECT_NE(FontFakery(), FontFakery(false, true));
+    EXPECT_NE(FontFakery(), FontFakery(true, true));
+
+    EXPECT_TRUE(FontFakery(true, true).isFakeBold());
+    EXPECT_TRUE(FontFakery(true, true).isFakeItalic());
+    EXPECT_TRUE(FontFakery(true, true).variationSettings().empty());
+
+    EXPECT_FALSE(FontFakery(false, false).isFakeBold());
+    EXPECT_FALSE(FontFakery(false, false).isFakeItalic());
+    EXPECT_TRUE(FontFakery(false, false).variationSettings().empty());
+
+    EXPECT_TRUE(FontFakery(true, false).isFakeBold());
+    EXPECT_FALSE(FontFakery(true, false).isFakeItalic());
+    EXPECT_TRUE(FontFakery(true, false).variationSettings().empty());
+
+    EXPECT_FALSE(FontFakery(false, true).isFakeBold());
+    EXPECT_TRUE(FontFakery(false, true).isFakeItalic());
+    EXPECT_TRUE(FontFakery(false, true).variationSettings().empty());
+}
+
+TEST(FontFakeryTest, testVariationSettings) {
+    VariationSettings variationSettings = {FontVariation(TAG_wght, 400),
+                                           FontVariation(TAG_ital, 1)};
+
+    auto ff = FontFakery(false, false, std::move(variationSettings));
+
+    EXPECT_EQ(2u, ff.variationSettings().size());
+    EXPECT_EQ(TAG_ital, ff.variationSettings()[0].axisTag);
+    EXPECT_EQ(1, ff.variationSettings()[0].value);
+    EXPECT_EQ(TAG_wght, ff.variationSettings()[1].axisTag);
+    EXPECT_EQ(400, ff.variationSettings()[1].value);
+}
+
+}  // namespace minikin
diff --git a/tests/unittest/FontFeatureTest.cpp b/tests/unittest/FontFeatureTest.cpp
index be0a141..4906508 100644
--- a/tests/unittest/FontFeatureTest.cpp
+++ b/tests/unittest/FontFeatureTest.cpp
@@ -156,20 +156,4 @@ protected:
     virtual void SetUp() override { font = buildFontCollection("Ascii.ttf"); }
 };
 
-TEST_F_WITH_FLAGS(FontFeatureTest, do_not_skip_cache_if_flagEnabled,
-                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      letter_spacing_justification))) {
-    auto paint = MinikinPaint(font);
-    paint.fontFeatureSettings = FontFeature::parse("\"palt\" on");
-    EXPECT_FALSE(paint.skipCache());
-}
-
-TEST_F_WITH_FLAGS(FontFeatureTest, do_not_skip_cache_if_flagDisabled,
-                  REQUIRES_FLAGS_DISABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                       letter_spacing_justification))) {
-    auto paint = MinikinPaint(font);
-    paint.fontFeatureSettings = FontFeature::parse("\"palt\" on");
-    EXPECT_TRUE(paint.skipCache());
-}
-
 }  // namespace minikin
diff --git a/tests/unittest/FontTest.cpp b/tests/unittest/FontTest.cpp
index 2e791a5..ea3ca8d 100644
--- a/tests/unittest/FontTest.cpp
+++ b/tests/unittest/FontTest.cpp
@@ -312,4 +312,29 @@ TEST(FontTest, ChildLazyCreationTest) {
     EXPECT_EQ(MakeTag('w', 'g', 'h', 't'), overridden->baseTypeface()->GetAxes()[0].axisTag);
 }
 
+TEST(FontTest, FVarTableTest) {
+    FreeTypeMinikinFontForTestFactory::init();
+    auto minikinFont = std::make_shared<FreeTypeMinikinFontForTest>(
+            getTestFontPath("WeightEqualsEmVariableFont.ttf"));
+    std::shared_ptr<Font> font = Font::Builder(minikinFont).build();
+
+    uint32_t wght = MakeTag('w', 'g', 'h', 't');
+    uint32_t ital = MakeTag('i', 't', 'a', 'l');
+
+    const FVarTable& fvar = font->getFVarTable();
+    EXPECT_TRUE(fvar.contains(wght));
+    EXPECT_TRUE(fvar.contains(ital));
+    EXPECT_FALSE(fvar.contains(MakeTag('w', 'd', 't', 'h')));
+
+    const FVarEntry& wghtTable = fvar.find(wght)->second;
+    EXPECT_EQ(0, wghtTable.minValue);
+    EXPECT_EQ(400, wghtTable.defValue);
+    EXPECT_EQ(1000, wghtTable.maxValue);
+
+    const FVarEntry& italTable = fvar.find(ital)->second;
+    EXPECT_EQ(0, italTable.minValue);
+    EXPECT_EQ(0, italTable.defValue);
+    EXPECT_EQ(1, italTable.maxValue);
+}
+
 }  // namespace minikin
diff --git a/tests/unittest/GreedyLineBreakerTest.cpp b/tests/unittest/GreedyLineBreakerTest.cpp
index cee9c51..e8bfa1b 100644
--- a/tests/unittest/GreedyLineBreakerTest.cpp
+++ b/tests/unittest/GreedyLineBreakerTest.cpp
@@ -1920,9 +1920,7 @@ TEST_F(GreedyLineBreakerTest, testBreakWithHyphenation_NoHyphenationSpan) {
     }
 }
 
-TEST_F_WITH_FLAGS(GreedyLineBreakerTest, testPhraseBreakNone,
-                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      word_style_auto))) {
+TEST_F(GreedyLineBreakerTest, testPhraseBreakNone) {
     // For short hand of writing expectation for lines.
     auto line = [](std::string t, float w) -> LineBreakExpectation {
         return {t, w, StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, ASCENT, DESCENT};
@@ -2034,9 +2032,7 @@ TEST_F_WITH_FLAGS(GreedyLineBreakerTest, testPhraseBreakNone,
     }
 }
 
-TEST_F_WITH_FLAGS(GreedyLineBreakerTest, testPhraseBreakPhrase,
-                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      word_style_auto))) {
+TEST_F(GreedyLineBreakerTest, testPhraseBreakPhrase) {
     // For short hand of writing expectation for lines.
     auto line = [](std::string t, float w) -> LineBreakExpectation {
         return {t, w, StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, ASCENT, DESCENT};
@@ -2150,9 +2146,7 @@ TEST_F_WITH_FLAGS(GreedyLineBreakerTest, testPhraseBreakPhrase,
     }
 }
 
-TEST_F_WITH_FLAGS(GreedyLineBreakerTest, testPhraseBreakAuto,
-                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      word_style_auto))) {
+TEST_F(GreedyLineBreakerTest, testPhraseBreakAuto) {
     // For short hand of writing expectation for lines.
     auto line = [](std::string t, float w) -> LineBreakExpectation {
         return {t, w, StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, ASCENT, DESCENT};
@@ -2265,9 +2259,7 @@ TEST_F_WITH_FLAGS(GreedyLineBreakerTest, testPhraseBreakAuto,
     }
 }
 
-TEST_F_WITH_FLAGS(GreedyLineBreakerTest, testPhraseBreak_Korean,
-                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      word_style_auto))) {
+TEST_F(GreedyLineBreakerTest, testPhraseBreak_Korean) {
     // For short hand of writing expectation for lines.
     auto line = [](std::string t, float w) -> LineBreakExpectation {
         return {t, w, StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, ASCENT, DESCENT};
@@ -2327,9 +2319,7 @@ TEST_F_WITH_FLAGS(GreedyLineBreakerTest, testPhraseBreak_Korean,
     }
 }
 
-TEST_F_WITH_FLAGS(GreedyLineBreakerTest, testBreakWithLetterSpacing,
-                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      letter_spacing_justification))) {
+TEST_F(GreedyLineBreakerTest, testBreakWithLetterSpacing) {
     const std::vector<uint16_t> textBuf = utf8ToUtf16("This is an example text.");
 
     constexpr StartHyphenEdit NO_START_HYPHEN = StartHyphenEdit::NO_EDIT;
diff --git a/tests/unittest/HyphenatorTest.cpp b/tests/unittest/HyphenatorTest.cpp
index ecf024e..28a5f71 100644
--- a/tests/unittest/HyphenatorTest.cpp
+++ b/tests/unittest/HyphenatorTest.cpp
@@ -14,11 +14,11 @@
  * limitations under the License.
  */
 
-#include "minikin/Hyphenator.h"
-
 #include <gtest/gtest.h>
 
+#include "FeatureFlags.h"
 #include "FileUtils.h"
+#include "minikin/Hyphenator.h"
 
 #ifndef NELEM
 #define NELEM(x) ((sizeof(x) / sizeof((x)[0])))
@@ -27,6 +27,7 @@
 namespace minikin {
 
 const char* usHyph = "/system/usr/hyphen-data/hyph-en-us.hyb";
+const char* ptHyph = "/system/usr/hyphen-data/hyph-pt.hyb";
 const char* malayalamHyph = "/system/usr/hyphen-data/hyph-ml.hyb";
 
 const uint16_t HYPHEN_MINUS = 0x002D;
@@ -49,7 +50,7 @@ typedef std::function<Hyphenator*(const uint8_t*, size_t, size_t, size_t, const
 class HyphenatorTest : public testing::TestWithParam<Generator> {};
 
 INSTANTIATE_TEST_SUITE_P(HyphenatorInstantiation, HyphenatorTest,
-                         testing::Values(Hyphenator::loadBinary, Hyphenator::loadBinaryForRust),
+                         testing::Values(HyphenatorCXX::loadBinary, Hyphenator::loadBinaryForRust),
                          [](const testing::TestParamInfo<HyphenatorTest::ParamType>& info) {
                              switch (info.index) {
                                  case 0:
@@ -356,4 +357,25 @@ TEST_P(HyphenatorTest, startingHyphenMinus) {
     EXPECT_EQ(HyphenationType::DONT_BREAK, result[1]);
 }
 
+TEST_P(HyphenatorTest, hyphenationWithHyphen) {
+    std::vector<uint8_t> patternData = readWholeFile(ptHyph);
+    Hyphenator* hyphenator = GetParam()(patternData.data(), patternData.size(), 2, 3, "pt");
+    const uint16_t word[] = {'b', 'o', 'a', 's', '-', 'v', 'i', 'n', 'd', 'a', 's'};
+    std::vector<HyphenationType> result;
+    hyphenator->hyphenate(word, &result);
+    EXPECT_EQ((size_t)11, result.size());
+    EXPECT_EQ(HyphenationType::DONT_BREAK, result[0]);
+    EXPECT_EQ(HyphenationType::DONT_BREAK, result[1]);
+    EXPECT_EQ(HyphenationType::BREAK_AND_INSERT_HYPHEN, result[2]);
+    EXPECT_EQ(HyphenationType::DONT_BREAK, result[3]);
+    EXPECT_EQ(HyphenationType::BREAK_AND_DONT_INSERT_HYPHEN, result[4]);
+    EXPECT_EQ(HyphenationType::DONT_BREAK, result[5]);
+    EXPECT_EQ(HyphenationType::DONT_BREAK, result[6]);
+    EXPECT_EQ(HyphenationType::DONT_BREAK, result[7]);
+    EXPECT_EQ(HyphenationType::BREAK_AND_INSERT_HYPHEN, result[8]);
+    EXPECT_EQ(HyphenationType::DONT_BREAK, result[9]);
+    EXPECT_EQ(HyphenationType::DONT_BREAK, result[10]);
+    EXPECT_EQ(HyphenationType::DONT_BREAK, result[11]);
+}
+
 }  // namespace minikin
diff --git a/tests/unittest/LayoutTest.cpp b/tests/unittest/LayoutTest.cpp
index 8fd641c..4213c8e 100644
--- a/tests/unittest/LayoutTest.cpp
+++ b/tests/unittest/LayoutTest.cpp
@@ -14,17 +14,17 @@
  * limitations under the License.
  */
 
-#include "minikin/Layout.h"
-
+#include <com_android_text_flags.h>
+#include <flag_macros.h>
 #include <gtest/gtest.h>
 
+#include "FontTestUtils.h"
+#include "UnicodeUtils.h"
 #include "minikin/FontCollection.h"
+#include "minikin/Layout.h"
 #include "minikin/LayoutPieces.h"
 #include "minikin/Measurement.h"
 
-#include "FontTestUtils.h"
-#include "UnicodeUtils.h"
-
 namespace minikin {
 
 static void expectAdvances(const std::vector<float>& expected, const std::vector<float>& advances) {
@@ -488,4 +488,59 @@ TEST_F(LayoutTest, measuredTextTest) {
     }
 }
 
+TEST_F_WITH_FLAGS(LayoutTest, testFontRun,
+                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
+                                                      typeface_redesign))) {
+    auto latinFamily = buildFontFamily("Ascii.ttf");
+    auto jaFamily = buildFontFamily("Hiragana.ttf");
+    const std::vector<std::shared_ptr<FontFamily>> families = {latinFamily, jaFamily};
+    auto fc = FontCollection::create(families);
+    {
+        MinikinPaint paint(fc);
+        paint.size = 10;
+        auto text = utf8ToUtf16("abc");  // (0, 3): Latin letters
+        Range range(0, text.size());
+        Layout layout(text, range, Bidi::LTR, paint, StartHyphenEdit::NO_EDIT,
+                      EndHyphenEdit::NO_EDIT, RunFlag::NONE);
+        EXPECT_EQ(1ul, layout.getFontRunCount());
+        EXPECT_EQ(0ul, layout.getFontRunStart(0));
+        EXPECT_EQ(3ul, layout.getFontRunEnd(0));
+        EXPECT_EQ("Ascii.ttf", getBasename(layout.getFontRunFont(0).typeface()->GetFontPath()));
+    }
+    {
+        MinikinPaint paint(fc);
+        paint.size = 10;
+        auto text = utf8ToUtf16("abcあいう");  // (0, 3): Latin letters, (3, 6): Japanese letters.
+        Range range(0, text.size());
+        Layout layout(text, range, Bidi::LTR, paint, StartHyphenEdit::NO_EDIT,
+                      EndHyphenEdit::NO_EDIT, RunFlag::NONE);
+        EXPECT_EQ(2ul, layout.getFontRunCount());
+        EXPECT_EQ(0ul, layout.getFontRunStart(0));
+        EXPECT_EQ(3ul, layout.getFontRunEnd(0));
+        EXPECT_EQ("Ascii.ttf", getBasename(layout.getFontRunFont(0).typeface()->GetFontPath()));
+        EXPECT_EQ(3ul, layout.getFontRunStart(1));
+        EXPECT_EQ(6ul, layout.getFontRunEnd(1));
+        EXPECT_EQ("Hiragana.ttf", getBasename(layout.getFontRunFont(1).typeface()->GetFontPath()));
+    }
+    {
+        MinikinPaint paint(fc);
+        paint.size = 10;
+        // (0, 3): Latin letters, (3, 6): Japanese letters, (6, 9): Latin letters.
+        auto text = utf8ToUtf16("abcあいうdef");
+        Range range(0, text.size());
+        Layout layout(text, range, Bidi::LTR, paint, StartHyphenEdit::NO_EDIT,
+                      EndHyphenEdit::NO_EDIT, RunFlag::NONE);
+        EXPECT_EQ(3ul, layout.getFontRunCount());
+        EXPECT_EQ(0ul, layout.getFontRunStart(0));
+        EXPECT_EQ(3ul, layout.getFontRunEnd(0));
+        EXPECT_EQ("Ascii.ttf", getBasename(layout.getFontRunFont(0).typeface()->GetFontPath()));
+        EXPECT_EQ(3ul, layout.getFontRunStart(1));
+        EXPECT_EQ(6ul, layout.getFontRunEnd(1));
+        EXPECT_EQ("Hiragana.ttf", getBasename(layout.getFontRunFont(1).typeface()->GetFontPath()));
+        EXPECT_EQ(6ul, layout.getFontRunStart(2));
+        EXPECT_EQ(9ul, layout.getFontRunEnd(2));
+        EXPECT_EQ("Ascii.ttf", getBasename(layout.getFontRunFont(2).typeface()->GetFontPath()));
+    }
+}
+
 }  // namespace minikin
diff --git a/tests/unittest/MinikinPaintTest.cpp b/tests/unittest/MinikinPaintTest.cpp
new file mode 100644
index 0000000..fa4dec0
--- /dev/null
+++ b/tests/unittest/MinikinPaintTest.cpp
@@ -0,0 +1,60 @@
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
+#include <gtest/gtest.h>
+
+#include "FontTestUtils.h"
+#include "minikin/Constants.h"
+#include "minikin/MinikinPaint.h"
+
+namespace minikin {
+
+TEST(MinikinPaintTest, variationSettings_empty_default) {
+    auto fc = buildFontCollection("Ascii.ttf");
+    MinikinPaint paint(fc);
+    EXPECT_TRUE(paint.fontVariationSettings.empty());
+}
+
+TEST(MinikinPaintTest, variationSettings_varsettings_produce_different_hash) {
+    auto fc = buildFontCollection("Ascii.ttf");
+    MinikinPaint left(fc);
+    MinikinPaint right(fc);
+    left.fontVariationSettings = VariationSettings({{TAG_wght, 400}, {TAG_ital, 1}});
+
+    EXPECT_NE(left, right);
+}
+
+TEST(MinikinPaintTest, variationSettings_different_varsettings) {
+    auto fc = buildFontCollection("Ascii.ttf");
+    MinikinPaint left(fc);
+    MinikinPaint right(fc);
+    left.fontVariationSettings = VariationSettings({{TAG_wght, 400}, {TAG_ital, 1}});
+    right.fontVariationSettings = VariationSettings({{TAG_wght, 500}, {TAG_ital, 1}});
+
+    EXPECT_NE(left, right);
+}
+
+TEST(MinikinPaintTest, variationSettings) {
+    auto fc = buildFontCollection("Ascii.ttf");
+    MinikinPaint left(fc);
+    MinikinPaint right(fc);
+    left.fontVariationSettings = VariationSettings({{TAG_wght, 400}, {TAG_ital, 1}});
+    right.fontVariationSettings = VariationSettings({{TAG_ital, 1}, {TAG_wght, 400}});
+    EXPECT_EQ(left.hash(), right.hash());
+    EXPECT_EQ(left, right);
+}
+
+}  // namespace minikin
diff --git a/tests/unittest/OptimalLineBreakerTest.cpp b/tests/unittest/OptimalLineBreakerTest.cpp
index a75923b..360c179 100644
--- a/tests/unittest/OptimalLineBreakerTest.cpp
+++ b/tests/unittest/OptimalLineBreakerTest.cpp
@@ -2155,9 +2155,7 @@ TEST_F(OptimalLineBreakerTest, testBreakWithHyphenation_NoHyphenSpan) {
     }
 }
 
-TEST_F_WITH_FLAGS(OptimalLineBreakerTest, testPhraseBreakNone,
-                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      word_style_auto))) {
+TEST_F(OptimalLineBreakerTest, testPhraseBreakNone) {
     // For short hand of writing expectation for lines.
     auto line = [](std::string t, float w) -> LineBreakExpectation {
         return {t, w, StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, ASCENT, DESCENT};
@@ -2269,9 +2267,7 @@ TEST_F_WITH_FLAGS(OptimalLineBreakerTest, testPhraseBreakNone,
     }
 }
 
-TEST_F_WITH_FLAGS(OptimalLineBreakerTest, testPhraseBreakPhrase,
-                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      word_style_auto))) {
+TEST_F(OptimalLineBreakerTest, testPhraseBreakPhrase) {
     // For short hand of writing expectation for lines.
     auto line = [](std::string t, float w) -> LineBreakExpectation {
         return {t, w, StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, ASCENT, DESCENT};
@@ -2385,9 +2381,7 @@ TEST_F_WITH_FLAGS(OptimalLineBreakerTest, testPhraseBreakPhrase,
     }
 }
 
-TEST_F_WITH_FLAGS(OptimalLineBreakerTest, testPhraseBreakAuto,
-                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      word_style_auto))) {
+TEST_F(OptimalLineBreakerTest, testPhraseBreakAuto) {
     // For short hand of writing expectation for lines.
     auto line = [](std::string t, float w) -> LineBreakExpectation {
         return {t, w, StartHyphenEdit::NO_EDIT, EndHyphenEdit::NO_EDIT, ASCENT, DESCENT};
@@ -2500,9 +2494,7 @@ TEST_F_WITH_FLAGS(OptimalLineBreakerTest, testPhraseBreakAuto,
     }
 }
 
-TEST_F_WITH_FLAGS(OptimalLineBreakerTest, testBreakLetterSpacing,
-                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::text::flags,
-                                                      letter_spacing_justification))) {
+TEST_F(OptimalLineBreakerTest, testBreakLetterSpacing) {
     constexpr BreakStrategy HIGH_QUALITY = BreakStrategy::HighQuality;
     constexpr HyphenationFrequency NO_HYPHEN = HyphenationFrequency::None;
     const std::vector<uint16_t> textBuf = utf8ToUtf16("This is an example text.");
diff --git a/tests/unittest/PackedVectorTest.cpp b/tests/unittest/PackedVectorTest.cpp
new file mode 100644
index 0000000..e0f4124
--- /dev/null
+++ b/tests/unittest/PackedVectorTest.cpp
@@ -0,0 +1,248 @@
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
+#include <gtest/gtest.h>
+
+#include "minikin/PackedVector.h"
+
+namespace minikin {
+
+struct Data {
+    int x, y;
+};
+
+TEST(PackedVector, construct) {
+    {
+        PackedVector<int> packed;
+        EXPECT_EQ(0, packed.size());
+        EXPECT_TRUE(packed.empty());
+    }
+    {
+        int data[] = {1, 2, 3, 4, 5};
+
+        PackedVector<int> packed(data, 5);
+        EXPECT_EQ(5, packed.size());
+        EXPECT_EQ(1, packed[0]);
+        EXPECT_EQ(2, packed[1]);
+        EXPECT_EQ(3, packed[2]);
+        EXPECT_EQ(4, packed[3]);
+        EXPECT_EQ(5, packed[4]);
+    }
+    {
+        int data[] = {1, 2, 3, 4, 5};
+
+        PackedVector<int> packed(data + 2, 2);
+        EXPECT_EQ(2, packed.size());
+        EXPECT_EQ(3, packed[0]);
+        EXPECT_EQ(4, packed[1]);
+    }
+    {
+        std::vector<int> data = {1, 2, 3, 4, 5};
+
+        PackedVector<int> packed(data);
+        EXPECT_EQ(5, packed.size());
+        EXPECT_EQ(1, packed[0]);
+        EXPECT_EQ(2, packed[1]);
+        EXPECT_EQ(3, packed[2]);
+        EXPECT_EQ(4, packed[3]);
+        EXPECT_EQ(5, packed[4]);
+    }
+}
+
+TEST(PackedVector, push_back) {
+    PackedVector<int> packed;
+
+    packed.push_back(0);
+    EXPECT_EQ(1, packed.size());
+    EXPECT_FALSE(packed.empty());
+    EXPECT_EQ(0, packed[0]);
+    EXPECT_EQ(0, packed.data()[0]);
+    EXPECT_EQ(0, *packed.back());
+
+    packed.push_back(10);
+    EXPECT_EQ(2, packed.size());
+    EXPECT_FALSE(packed.empty());
+    EXPECT_EQ(10, packed[1]);
+    EXPECT_EQ(10, packed.data()[1]);
+    EXPECT_EQ(10, *packed.back());
+}
+
+TEST(PackedVector, compare) {
+    {
+        PackedVector<int> left = {1, 2, 3, 4, 5};
+        PackedVector<int> right = {1, 2, 3, 4, 5};
+
+        EXPECT_TRUE(left == right);
+        EXPECT_FALSE(left != right);
+    }
+    {
+        PackedVector<int> left = {1, 2, 3, 4, 5};
+        PackedVector<int> right = {1, 2, 3, 4, 5, 6};
+
+        EXPECT_FALSE(left == right);
+        EXPECT_TRUE(left != right);
+    }
+    {
+        PackedVector<int> left = {};
+        PackedVector<int> right = {};
+
+        EXPECT_TRUE(left == right);
+        EXPECT_FALSE(left != right);
+    }
+    {
+        PackedVector<Data> left = {{0, 1}, {2, 3}};
+        PackedVector<Data> right = {{0, 1}, {2, 3}};
+
+        EXPECT_TRUE(left == right);
+        EXPECT_FALSE(left != right);
+    }
+    {
+        PackedVector<Data> left = {{0, 1}, {2, 3}};
+        PackedVector<Data> right = {{0, 1}};
+
+        EXPECT_FALSE(left == right);
+        EXPECT_TRUE(left != right);
+    }
+}
+
+TEST(PackedVector, reserve) {
+    {
+        PackedVector<int> packed;
+        packed.reserve(100);
+        EXPECT_EQ(0, packed.size());
+        EXPECT_EQ(100, packed.capacity());
+        packed.shrink_to_fit();
+        EXPECT_EQ(0, packed.size());
+        // The PackedVector has minimum capacity for the space of pointers. So cannot expect it
+        // becomes 0.
+        EXPECT_NE(100, packed.capacity());
+    }
+    {
+        PackedVector<int> packed;
+        packed.reserve(100);
+        for (int i = 0; i < 50; ++i) {
+            packed.push_back(i);
+        }
+        EXPECT_EQ(50, packed.size());
+        EXPECT_EQ(100, packed.capacity());
+        packed.shrink_to_fit();
+        EXPECT_EQ(50, packed.size());
+        EXPECT_EQ(50, packed.capacity());
+    }
+}
+
+TEST(PackedVector, iterator) {
+    {
+        PackedVector<int> packed = {0, 1, 2, 3, 4, 5};
+        std::vector<int> copied(packed.begin(), packed.end());
+        EXPECT_EQ(std::vector<int>({0, 1, 2, 3, 4, 5}), copied);
+    }
+}
+
+TEST(PackedVector, resize) {
+    {
+        // Reduction
+        PackedVector<int> packed = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
+        packed.resize(10);
+        EXPECT_EQ(10, packed.size());
+        EXPECT_EQ(10, packed.capacity());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), packed);
+
+        packed.resize(9);
+        EXPECT_EQ(9, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8, 9}), packed);
+
+        packed.resize(8);
+        EXPECT_EQ(8, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8}), packed);
+
+        packed.resize(7);
+        EXPECT_EQ(7, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7}), packed);
+
+        packed.resize(6);
+        EXPECT_EQ(6, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6}), packed);
+
+        packed.resize(5);
+        EXPECT_EQ(5, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5}), packed);
+
+        packed.resize(4);
+        EXPECT_EQ(4, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4}), packed);
+
+        packed.resize(3);
+        EXPECT_EQ(3, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3}), packed);
+
+        packed.resize(2);
+        EXPECT_EQ(2, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2}), packed);
+
+        packed.resize(1);
+        EXPECT_EQ(1, packed.size());
+        EXPECT_EQ(PackedVector<int>({1}), packed);
+
+        packed.resize(0);
+        EXPECT_EQ(0, packed.size());
+        EXPECT_EQ(PackedVector<int>({}), packed);
+    }
+    {
+        // Expansion
+        PackedVector<int> packed = {};
+        packed.resize(1, 1);
+        EXPECT_EQ(1, packed.size());
+        EXPECT_EQ(PackedVector<int>({1}), packed);
+
+        packed.resize(2, 2);
+        EXPECT_EQ(2, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2}), packed);
+
+        packed.resize(3, 3);
+        EXPECT_EQ(3, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3}), packed);
+
+        packed.resize(4, 4);
+        EXPECT_EQ(4, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4}), packed);
+
+        packed.resize(5, 5);
+        EXPECT_EQ(5, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5}), packed);
+
+        packed.resize(6, 6);
+        EXPECT_EQ(6, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6}), packed);
+
+        packed.resize(7, 7);
+        EXPECT_EQ(7, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7}), packed);
+
+        packed.resize(8, 8);
+        EXPECT_EQ(8, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8}), packed);
+
+        packed.resize(9, 9);
+        EXPECT_EQ(9, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8, 9}), packed);
+
+        packed.resize(10, 10);
+        EXPECT_EQ(10, packed.size());
+        EXPECT_EQ(PackedVector<int>({1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), packed);
+    }
+}
+}  // namespace minikin
diff --git a/tests/unittest/SortedPackedVectorTest.cpp b/tests/unittest/SortedPackedVectorTest.cpp
new file mode 100644
index 0000000..361c98a
--- /dev/null
+++ b/tests/unittest/SortedPackedVectorTest.cpp
@@ -0,0 +1,83 @@
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
+#include <gtest/gtest.h>
+
+#include "minikin/SortedPackedVector.h"
+
+namespace minikin {
+
+TEST(SortedPackedVector, construct) {
+    {
+        auto sorted = SortedPackedVector({1, 2, 3, 4, 5});
+        EXPECT_EQ(5, sorted.size());
+        EXPECT_EQ(1, sorted[0]);
+        EXPECT_EQ(2, sorted[1]);
+        EXPECT_EQ(3, sorted[2]);
+        EXPECT_EQ(4, sorted[3]);
+        EXPECT_EQ(5, sorted[4]);
+    }
+    {
+        auto sorted = SortedPackedVector({1, 2, 3, 4, 5}, true);
+        EXPECT_EQ(5, sorted.size());
+        EXPECT_EQ(1, sorted[0]);
+        EXPECT_EQ(2, sorted[1]);
+        EXPECT_EQ(3, sorted[2]);
+        EXPECT_EQ(4, sorted[3]);
+        EXPECT_EQ(5, sorted[4]);
+    }
+    {
+        auto sorted = SortedPackedVector({2, 1, 4, 3, 5});
+        EXPECT_EQ(5, sorted.size());
+        EXPECT_EQ(1, sorted[0]);
+        EXPECT_EQ(2, sorted[1]);
+        EXPECT_EQ(3, sorted[2]);
+        EXPECT_EQ(4, sorted[3]);
+        EXPECT_EQ(5, sorted[4]);
+    }
+    {
+        std::vector<int> vec = {2, 1, 4, 3, 5};
+        auto sorted = SortedPackedVector(vec);
+        EXPECT_EQ(5, sorted.size());
+        EXPECT_EQ(1, sorted[0]);
+        EXPECT_EQ(2, sorted[1]);
+        EXPECT_EQ(3, sorted[2]);
+        EXPECT_EQ(4, sorted[3]);
+        EXPECT_EQ(5, sorted[4]);
+    }
+    {
+        auto sorted = SortedPackedVector({1, 2, 3, 4, 5});
+        auto copied = SortedPackedVector(sorted);
+        EXPECT_EQ(5, copied.size());
+        EXPECT_EQ(1, copied[0]);
+        EXPECT_EQ(2, copied[1]);
+        EXPECT_EQ(3, copied[2]);
+        EXPECT_EQ(4, copied[3]);
+        EXPECT_EQ(5, copied[4]);
+    }
+    {
+        auto sorted = SortedPackedVector({1, 2, 3, 4, 5});
+        auto moved = SortedPackedVector(std::move(sorted));
+        EXPECT_EQ(5, moved.size());
+        EXPECT_EQ(1, moved[0]);
+        EXPECT_EQ(2, moved[1]);
+        EXPECT_EQ(3, moved[2]);
+        EXPECT_EQ(4, moved[3]);
+        EXPECT_EQ(5, moved[4]);
+    }
+}
+
+}  // namespace minikin
diff --git a/tests/unittest/WordBreakerTests.cpp b/tests/unittest/WordBreakerTests.cpp
index fe7f953..adaff16 100644
--- a/tests/unittest/WordBreakerTests.cpp
+++ b/tests/unittest/WordBreakerTests.cpp
@@ -14,13 +14,14 @@
  * limitations under the License.
  */
 
-#include "WordBreaker.h"
+#include <com_android_text_flags.h>
+#include <flag_macros.h>
+#include <gtest/gtest.h>
 
 #include <cstdio>
 
-#include <gtest/gtest.h>
-
 #include "UnicodeUtils.h"
+#include "WordBreaker.h"
 
 #ifndef NELEM
 #define NELEM(x) ((sizeof(x) / sizeof((x)[0])))
@@ -727,4 +728,44 @@ TEST(WordBreakerTest, LineBreakerPool_exceeds_pool_size) {
     }
 }
 
+TEST(WordBreakerTest, noBreak_urlNoHyphenBreak) {
+    uint16_t buf[] = {'h', 't', 't', 'p', ':', '/', '/', 'a', '-', '/', 'b'};
+    auto lbStyle = LineBreakStyle::NoBreak;
+    auto lbWordStyle = LineBreakWordStyle::None;
+    WordBreaker breaker;
+    breaker.setText(buf, NELEM(buf));
+    EXPECT_EQ(0, breaker.current());
+    EXPECT_EQ(11, breaker.followingWithLocale(Locale("en-US"), lbStyle, lbWordStyle, 0));
+    EXPECT_EQ(0, breaker.wordStart());
+    EXPECT_EQ(11, breaker.current());
+    EXPECT_EQ(11, breaker.next());
+}
+
+TEST(WordBreakerTest, noBreak_urlEndsWithSlash) {
+    uint16_t buf[] = {'h', 't', 't', 'p', ':', '/', '/', 'a', '/'};
+    auto lbStyle = LineBreakStyle::NoBreak;
+    auto lbWordStyle = LineBreakWordStyle::None;
+    WordBreaker breaker;
+    breaker.setText(buf, NELEM(buf));
+    EXPECT_EQ(0, breaker.current());
+    EXPECT_EQ(9, breaker.followingWithLocale(Locale("en-US"), lbStyle, lbWordStyle, 0));
+    EXPECT_EQ(0, breaker.wordStart());
+    EXPECT_EQ(9, breaker.next());
+}
+
+TEST(WordBreakerTest, noBreak_setLocaleInsideUrl) {
+    std::vector<uint16_t> buf = utf8ToUtf16("Hello http://abc/d.html World");
+    auto lbStyle = LineBreakStyle::NoBreak;
+    auto lbWordStyle = LineBreakWordStyle::None;
+    WordBreaker breaker;
+    breaker.setText(buf.data(), buf.size());
+    EXPECT_EQ(0, breaker.current());
+    EXPECT_EQ(29, breaker.followingWithLocale(Locale("en-US"), lbStyle, lbWordStyle, 0));
+    EXPECT_EQ(0, breaker.wordStart());
+    EXPECT_EQ(29, breaker.wordEnd());
+
+    EXPECT_EQ(29, breaker.current());
+    EXPECT_EQ(29, breaker.next());
+}
+
 }  // namespace minikin
diff --git a/tests/util/FontTestUtils.cpp b/tests/util/FontTestUtils.cpp
index 0d563b8..87de72c 100644
--- a/tests/util/FontTestUtils.cpp
+++ b/tests/util/FontTestUtils.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "FontTestUtils.h"
 
 #include <libxml/parser.h>
diff --git a/tests/util/FreeTypeMinikinFontForTest.cpp b/tests/util/FreeTypeMinikinFontForTest.cpp
index 1c262ba..ee04662 100644
--- a/tests/util/FreeTypeMinikinFontForTest.cpp
+++ b/tests/util/FreeTypeMinikinFontForTest.cpp
@@ -14,8 +14,6 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "Minikin"
-
 #include "FreeTypeMinikinFontForTest.h"
 
 #include <fcntl.h>
```

