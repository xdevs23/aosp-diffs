```diff
diff --git a/Android.bp b/Android.bp
index 72f421a..3ce158c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -124,3 +124,9 @@ cc_test_host {
     ],
     test_suites: ["general-tests"],
 }
+
+dirgroup {
+    name: "trusty_dirgroup_system_libcppbor",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/README.md b/README.md
index 6463766..090b2e1 100644
--- a/README.md
+++ b/README.md
@@ -6,10 +6,10 @@ parsing CBOR messages.  It does not (yet) support all features of
 CBOR, nor (yet) support validation against CDDL schemata, though both
 are planned.  CBOR features that aren't supported include:
 
-* Parsing Indefinite length values for major types 2 (byte string) and 3 (text string)
+* Parsing Indefinite length view-only values for major types 2 (byte string) and 3 (text string)
 * Writing Indefinite length values
 * Semantic tagging
-* Floating point
+* Half floating point
 
 LibCppBor requires C++-17.
 
@@ -38,7 +38,10 @@ they correspond.  They are:
   variable-length array of pairs of `Item`s.
 * `Simple` corresponds to major type 7.  It's an abstract class since
   items require more specific type.
-* `Bool` is the only currently-implemented subclass of `Simple`.
+* `Bool` is implemented as a subclass of `Simple`.
+* `Null` is implemented as a subclass of `Simple`.
+* `Float` is implemented as a subclass of `Simple`.
+* `Double` is implemented as a subclass of `Simple`.
 
 Note that major type 6, semantic tag, is not yet implemented.
 
diff --git a/include/cppbor/cppbor.h b/include/cppbor/cppbor.h
index 0589e0c..d57b837 100644
--- a/include/cppbor/cppbor.h
+++ b/include/cppbor/cppbor.h
@@ -18,32 +18,42 @@
 
 #include <algorithm>
 #include <cassert>
+#include <cstddef>
 #include <cstdint>
+#include <cstring>
 #include <functional>
 #include <iterator>
 #include <memory>
 #include <numeric>
-#include <span>
 #include <string>
 #include <string_view>
 #include <vector>
-#include <algorithm>
+
+#if ABSL_INTERNAL_CPLUSPLUS_LANG >= 202002L || __cplusplus >= 202002L
+#include <span>
+#else  // not ABSL_INTERNAL_CPLUSPLUS_LANG >= 202002L || __cplusplus >= 202002L
+#include "span.h"
+#endif  // not ABSL_INTERNAL_CPLUSPLUS_LANG >= 202002L || __cplusplus >= 202002L
 
 #ifdef OS_WINDOWS
 #include <basetsd.h>
 
 #define ssize_t SSIZE_T
-#endif // OS_WINDOWS
+#endif  // OS_WINDOWS
 
 #ifdef TRUE
 #undef TRUE
-#endif // TRUE
+#endif  // TRUE
 #ifdef FALSE
 #undef FALSE
-#endif // FALSE
+#endif  // FALSE
 
 namespace cppbor {
 
+#if ABSL_INTERNAL_CPLUSPLUS_LANG >= 202002L || __cplusplus >= 202002L
+using std::span;
+#endif  // ABSL_INTERNAL_CPLUSPLUS_LANG >= 202002L || __cplusplus >= 202002L
+
 enum MajorType : uint8_t {
     UINT = 0 << 5,
     NINT = 1 << 5,
@@ -57,7 +67,9 @@ enum MajorType : uint8_t {
 
 enum SimpleType {
     BOOLEAN,
-    NULL_T,  // Only two supported, as yet.
+    NULL_T,
+    FLOAT,
+    DOUBLE,  // Only four supported, as yet.
 };
 
 enum SpecialAddlInfoValues : uint8_t {
@@ -67,7 +79,9 @@ enum SpecialAddlInfoValues : uint8_t {
     ONE_BYTE_LENGTH = 24,
     TWO_BYTE_LENGTH = 25,
     FOUR_BYTE_LENGTH = 26,
+    FLOAT_V = 26,
     EIGHT_BYTE_LENGTH = 27,
+    DOUBLE_V = 27,
     INDEFINITE_LENGTH = 31,
 };
 
@@ -86,6 +100,8 @@ class SemanticTag;
 class EncodedItem;
 class ViewTstr;
 class ViewBstr;
+class Float;
+class Double;
 
 /**
  * Returns the size of a CBOR header that contains the additional info value addlInfo.
@@ -149,6 +165,10 @@ class Item {
     const Bool* asBool() const { return const_cast<Item*>(this)->asBool(); }
     virtual Null* asNull() { return nullptr; }
     const Null* asNull() const { return const_cast<Item*>(this)->asNull(); }
+    virtual Float* asFloat() { return nullptr; }
+    const Float* asFloat() const { return const_cast<Item*>(this)->asFloat(); }
+    virtual Double* asDouble() { return nullptr; }
+    const Double* asDouble() const { return const_cast<Item*>(this)->asDouble(); }
 
     virtual Map* asMap() { return nullptr; }
     const Map* asMap() const { return const_cast<Item*>(this)->asMap(); }
@@ -185,8 +205,8 @@ class Item {
      *
      * The tstr "AES" is tagged with 6.  The combined entity ("AES" tagged with 6) is tagged with 5,
      * etc.  So in this example, semanticTagCount() would return 3, and semanticTag(0) would return
-     * 5 semanticTag(1) would return 5 and semanticTag(2) would return 4.  For values of n > 2,
-     * semanticTag(n) will return 0, but this is a meaningless value.
+     * 6, semanticTag(1) would return 5, and semanticTag(2) would return 4.  For values of n > 2,
+     * semanticTag(n) would return 0, but this is a meaningless value.
      *
      * If this layering is confusing, you probably don't have to worry about it. Nested tagging does
      * not appear to be common, so semanticTag(0) is the only one you'll use.
@@ -436,14 +456,15 @@ class Bstr : public Item {
 
     std::unique_ptr<Item> clone() const override { return std::make_unique<Bstr>(mValue); }
 
+  protected:
+    std::vector<uint8_t> mValue;
+
   private:
     void encodeValue(EncodeCallback encodeCallback) const;
-
-    std::vector<uint8_t> mValue;
 };
 
 /**
- * ViewBstr is a read-only version of Bstr backed by std::span
+ * ViewBstr is a read-only version of Bstr backed by span
  */
 class ViewBstr : public Item {
   public:
@@ -453,7 +474,7 @@ class ViewBstr : public Item {
     explicit ViewBstr() {}
 
     // Construct from a span of uint8_t values
-    explicit ViewBstr(std::span<const uint8_t> v) : mView(std::move(v)) {}
+    explicit ViewBstr(span<const uint8_t> v) : mView(std::move(v)) {}
 
     // Construct from a string_view
     explicit ViewBstr(std::string_view v)
@@ -466,8 +487,7 @@ class ViewBstr : public Item {
     ViewBstr(I1 begin, I2 end) : mView(begin, end) {}
 
     // Construct from a uint8_t pointer pair
-    ViewBstr(const uint8_t* begin, const uint8_t* end)
-        : mView(begin, std::distance(begin, end)) {}
+    ViewBstr(const uint8_t* begin, const uint8_t* end) : mView(begin, std::distance(begin, end)) {}
 
     bool operator==(const ViewBstr& other) const& {
         return std::equal(mView.begin(), mView.end(), other.mView.begin(), other.mView.end());
@@ -484,14 +504,14 @@ class ViewBstr : public Item {
         encodeValue(encodeCallback);
     }
 
-    const std::span<const uint8_t>& view() const { return mView; }
+    const span<const uint8_t>& view() const { return mView; }
 
     std::unique_ptr<Item> clone() const override { return std::make_unique<ViewBstr>(mView); }
 
   private:
     void encodeValue(EncodeCallback encodeCallback) const;
 
-    std::span<const uint8_t> mView;
+    span<const uint8_t> mView;
 };
 
 /**
@@ -501,6 +521,9 @@ class Tstr : public Item {
   public:
     static constexpr MajorType kMajorType = TSTR;
 
+    // Construct an empty Tstr
+    explicit Tstr() {}
+
     // Construct from a string
     explicit Tstr(std::string v) : mValue(std::move(v)) {}
 
@@ -540,10 +563,11 @@ class Tstr : public Item {
 
     std::unique_ptr<Item> clone() const override { return std::make_unique<Tstr>(mValue); }
 
+  protected:
+    std::string mValue;
+
   private:
     void encodeValue(EncodeCallback encodeCallback) const;
-
-    std::string mValue;
 };
 
 /**
@@ -567,8 +591,7 @@ class ViewTstr : public Item {
 
     // Construct from a uint8_t pointer pair
     ViewTstr(const uint8_t* begin, const uint8_t* end)
-        : mView(reinterpret_cast<const char*>(begin),
-                std::distance(begin, end)) {}
+        : mView(reinterpret_cast<const char*>(begin), std::distance(begin, end)) {}
 
     bool operator==(const ViewTstr& other) const& { return mView == other.mView; }
 
@@ -929,6 +952,78 @@ class Null : public Simple {
     std::unique_ptr<Item> clone() const override { return std::make_unique<Null>(); }
 };
 
+#if defined(__STDC_IEC_559__) || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+/**
+ * Float is a concrete type that implements CBOR major type 7, with additional item value for
+ * FLOAT.
+ */
+class Float : public Simple {
+  public:
+    static constexpr SimpleType kSimpleType = FLOAT;
+
+    explicit Float(float v) : mValue(v) {}
+
+    SimpleType simpleType() const override { return kSimpleType; }
+    Float* asFloat() override { return this; }
+
+    float value() const { return mValue; }
+    size_t encodedSize() const override { return 5; }
+
+    using Item::encode;
+    uint8_t* encode(uint8_t* pos, const uint8_t* end) const override {
+        uint32_t bits;
+        std::memcpy(&bits, &mValue, sizeof(float));
+        return encodeHeader(bits, pos, end);
+    }
+    void encode(EncodeCallback encodeCallback) const override {
+        uint32_t bits;
+        std::memcpy(&bits, &mValue, sizeof(float));
+        encodeHeader(bits, encodeCallback);
+    }
+
+    std::unique_ptr<Item> clone() const override { return std::make_unique<Float>(mValue); }
+
+  private:
+    float mValue;
+};
+#endif  // __STDC_IEC_559__ || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+
+#if defined(__STDC_IEC_559__) || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
+/**
+ * Double is a concrete type that implements CBOR major type 7, with additional item value for
+ * DOUBLE.
+ */
+class Double : public Simple {
+  public:
+    static constexpr SimpleType kSimpleType = DOUBLE;
+
+    explicit Double(double v) : mValue(v) {}
+
+    SimpleType simpleType() const override { return kSimpleType; }
+    Double* asDouble() override { return this; }
+
+    double value() const { return mValue; }
+    size_t encodedSize() const override { return 9; }
+
+    using Item::encode;
+    uint8_t* encode(uint8_t* pos, const uint8_t* end) const override {
+        uint64_t bits;
+        std::memcpy(&bits, &mValue, sizeof(double));
+        return encodeHeader(bits, pos, end);
+    }
+    void encode(EncodeCallback encodeCallback) const override {
+        uint64_t bits;
+        std::memcpy(&bits, &mValue, sizeof(double));
+        encodeHeader(bits, encodeCallback);
+    }
+
+    std::unique_ptr<Item> clone() const override { return std::make_unique<Double>(mValue); }
+
+  private:
+    double mValue;
+};
+#endif  // __STDC_IEC_559__ || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
+
 /**
  * Returns pretty-printed CBOR for |item|
  *
@@ -1067,17 +1162,17 @@ inline void map_helper(Map& map, Key&& key, Value&& value, Rest&&... rest) {
 }  // namespace details
 
 template <typename... Args,
-         /* Prevent implicit construction with a single argument. */
-         typename = std::enable_if_t<(sizeof...(Args)) != 1>>
+          /* Prevent implicit construction with a single argument. */
+          typename = std::enable_if_t<(sizeof...(Args)) != 1>>
 Array::Array(Args&&... args) {
     mEntries.reserve(sizeof...(args));
     (mEntries.push_back(details::makeItem(std::forward<Args>(args))), ...);
 }
 
 template <typename T,
-         /* Prevent use as copy constructor. */
-         typename = std::enable_if_t<
-            !std::is_same_v<Array, std::remove_cv_t<std::remove_reference_t<T>>>>>
+          /* Prevent use as copy constructor. */
+          typename = std::enable_if_t<
+                  !std::is_same_v<Array, std::remove_cv_t<std::remove_reference_t<T>>>>>
 Array::Array(T&& v) {
     mEntries.push_back(details::makeItem(std::forward<T>(v)));
 }
diff --git a/include/cppbor/cppbor_parse.h b/include/cppbor/cppbor_parse.h
index 22cd18d..3896734 100644
--- a/include/cppbor/cppbor_parse.h
+++ b/include/cppbor/cppbor_parse.h
@@ -116,8 +116,7 @@ inline ParseResult parseWithViews(const uint8_t* begin, size_t size) {
  * problem encountered.
  */
 inline ParseResult parse(const Bstr* bstr) {
-    if (!bstr)
-        return ParseResult(nullptr, nullptr, "Null Bstr pointer");
+    if (!bstr) return ParseResult(nullptr, nullptr, "Null Bstr pointer");
     return parse(bstr->value());
 }
 
diff --git a/include/cppbor/span.h b/include/cppbor/span.h
new file mode 100644
index 0000000..ed1ed15
--- /dev/null
+++ b/include/cppbor/span.h
@@ -0,0 +1,44 @@
+/*
+ * Copyright 2024 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <cstddef>
+
+#if ABSL_INTERNAL_CPLUSPLUS_LANG >= 202002L || __cplusplus >= 202002L
+#error This trivial span.h should not be used if the platform supports std::span
+#endif  // ABSL_INTERNAL_CPLUSPLUS_LANG >= 202002L || __cplusplus >= 202002L
+
+namespace cppbor {
+
+template <class T>
+class span {
+  public:
+    constexpr span() : mBegin(nullptr), mLen(0) {}
+    explicit constexpr span(T* begin, size_t len) : mBegin(begin), mLen(len) {}
+
+    constexpr T* begin() const noexcept { return mBegin; }
+    constexpr T* end() const noexcept { return mBegin + mLen; }
+    constexpr T* data() const noexcept { return mBegin; }
+
+    constexpr size_t size() const noexcept { return mLen; }
+
+  private:
+    T* mBegin;
+    size_t mLen;
+};
+
+}  // namespace cppbor
diff --git a/src/cppbor.cpp b/src/cppbor.cpp
index d916ce4..1877c67 100644
--- a/src/cppbor.cpp
+++ b/src/cppbor.cpp
@@ -19,6 +19,7 @@
 #include <inttypes.h>
 #include <openssl/sha.h>
 #include <cstdint>
+#include <cstdio>
 
 #include "cppbor_parse.h"
 
@@ -237,17 +238,40 @@ bool prettyPrintInternal(const Item* item, string& out, size_t indent, size_t ma
         } break;
 
         case SIMPLE:
-            const Bool* asBool = item->asSimple()->asBool();
-            const Null* asNull = item->asSimple()->asNull();
-            if (asBool != nullptr) {
-                out.append(asBool->value() ? "true" : "false");
-            } else if (asNull != nullptr) {
-                out.append("null");
-            } else {
+            switch (item->asSimple()->simpleType()) {
+                case BOOLEAN:
+                    out.append(item->asSimple()->asBool()->value() ? "true" : "false");
+                    break;
+                case NULL_T:
+                    out.append("null");
+                    break;
+                case FLOAT:
+#if defined(__STDC_IEC_559__) || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+                    snprintf(buf, sizeof(buf), "%f", item->asSimple()->asFloat()->value());
+                    out.append(buf);
+                    break;
+#else
+#ifndef __TRUSTY__
+                    LOG(ERROR) << "float not supported for this platform.";
+#endif // __TRUSTY__
+                    return false;
+#endif // __STDC_IEC_559__ || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+                case DOUBLE:
+#if defined(__STDC_IEC_559__) || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
+                    snprintf(buf, sizeof(buf), "%f", item->asSimple()->asDouble()->value());
+                    out.append(buf);
+                    break;
+#else
+#ifndef __TRUSTY__
+                    LOG(ERROR) << "double not supported for this platform.";
+#endif  // __TRUSTY__
+                    return false;
+#endif  // __STDC_IEC_559__ || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
+                default:
 #ifndef __TRUSTY__
-                LOG(ERROR) << "Only boolean/null is implemented for SIMPLE";
+                    LOG(ERROR) << "Only boolean/null/float/double is implemented for SIMPLE";
 #endif  // __TRUSTY__
-                return false;
+                    return false;
             }
             break;
     }
@@ -372,6 +396,14 @@ bool Simple::operator==(const Simple& other) const& {
             return *asBool() == *(other.asBool());
         case NULL_T:
             return true;
+#if defined(__STDC_IEC_559__) || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+        case FLOAT:
+            return *asFloat() == *(other.asFloat());
+#endif  // __STDC_IEC_559__ || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+#if defined(__STDC_IEC_559__) || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
+        case DOUBLE:
+            return *asDouble() == *(other.asDouble());
+#endif  // __STDC_IEC_559__ || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
         default:
             CHECK(false);  // Impossible to get here.
             return false;
diff --git a/src/cppbor_parse.cpp b/src/cppbor_parse.cpp
index 19ed3e0..e84b625 100644
--- a/src/cppbor_parse.cpp
+++ b/src/cppbor_parse.cpp
@@ -16,11 +16,16 @@
 
 #include "cppbor_parse.h"
 
+#include <algorithm>
+#include <cstdint>
+#include <cstring>
 #include <memory>
 #include <optional>
 #include <sstream>
 #include <stack>
+#include <tuple>
 #include <type_traits>
+
 #include "cppbor.h"
 
 #ifndef __TRUSTY__
@@ -35,6 +40,7 @@ namespace cppbor {
 namespace {
 
 const unsigned kMaxParseDepth = 1000;
+const size_t kMaxReserveSize = 8192;
 
 std::string insufficientLengthString(size_t bytesNeeded, size_t bytesAvail,
                                      const std::string& type) {
@@ -99,6 +105,30 @@ std::tuple<const uint8_t*, ParseClient*> handleNull(const uint8_t* hdrBegin, con
             parseClient->item(item, hdrBegin, hdrEnd /* valueBegin */, hdrEnd /* itemEnd */)};
 }
 
+#if defined(__STDC_IEC_559__) || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+std::tuple<const uint8_t*, ParseClient*> handleFloat(uint32_t value, const uint8_t* hdrBegin,
+                                                     const uint8_t* hdrEnd,
+                                                     ParseClient* parseClient) {
+    float f;
+    std::memcpy(&f, &value, sizeof(float));
+    std::unique_ptr<Item> item = std::make_unique<Float>(f);
+    return {hdrEnd,
+            parseClient->item(item, hdrBegin, hdrEnd /* valueBegin */, hdrEnd /* itemEnd */)};
+}
+#endif  // __STDC_IEC_559__ || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+
+#if defined(__STDC_IEC_559__) || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
+std::tuple<const uint8_t*, ParseClient*> handleDouble(uint64_t value, const uint8_t* hdrBegin,
+                                                      const uint8_t* hdrEnd,
+                                                      ParseClient* parseClient) {
+    double d;
+    std::memcpy(&d, &value, sizeof(double));
+    std::unique_ptr<Item> item = std::make_unique<Double>(d);
+    return {hdrEnd,
+            parseClient->item(item, hdrBegin, hdrEnd /* valueBegin */, hdrEnd /* itemEnd */)};
+}
+#endif  // __STDC_IEC_559__ || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
+
 template <typename T>
 std::tuple<const uint8_t*, ParseClient*> handleString(uint64_t length, const uint8_t* hdrBegin,
                                                       const uint8_t* valueBegin, const uint8_t* end,
@@ -115,6 +145,33 @@ std::tuple<const uint8_t*, ParseClient*> handleString(uint64_t length, const uin
             parseClient->item(item, hdrBegin, valueBegin, valueBegin + length)};
 }
 
+std::tuple<const uint8_t*, ParseClient*> handleIncompleteString(
+        std::unique_ptr<Item> item, const uint8_t* hdrBegin, const uint8_t* valueBegin,
+        const uint8_t* end, const std::string& errLabel, bool emitViews, ParseClient* parseClient,
+        unsigned depth) {
+    parseClient =
+            parseClient->item(item, hdrBegin, valueBegin, valueBegin /* don't know the end yet */);
+    if (!parseClient) return {hdrBegin, nullptr};
+
+    const uint8_t* pos = valueBegin;
+    while (true) {
+        if (pos == end) {
+            parseClient->error(hdrBegin, "Not enough entries for " + errLabel + ".");
+            return {hdrBegin, nullptr /* end parsing */};
+        }
+        if (*pos == 0xFF) {
+            // We found a stop code.
+            ++pos;
+            break;
+        }
+        std::tie(pos, parseClient) = parseRecursively(pos, end, emitViews, parseClient, depth + 1);
+        if (!parseClient) return {hdrBegin, nullptr};
+    }
+    if (!parseClient) return {hdrBegin, nullptr};
+
+    return {pos, parseClient->itemEnd(item, hdrBegin, valueBegin, pos)};
+}
+
 class IncompleteItem {
   public:
     static IncompleteItem* cast(Item* item);
@@ -124,16 +181,59 @@ class IncompleteItem {
     virtual std::unique_ptr<Item> finalize() && = 0;
 };
 
+class IncompleteBstr : public Bstr, public IncompleteItem {
+  public:
+    explicit IncompleteBstr() {}
+
+    // The finalized version creates a copy which will not have this overridden.
+    bool isCompound() const override { return true; }
+
+    void add(std::unique_ptr<Item> item) override {
+        if (item->type() == BSTR) {
+            mValue.insert(mValue.end(), item->asBstr()->moveValue().begin(),
+                          item->asBstr()->moveValue().end());
+        } else {
+#ifndef __TRUSTY__
+            LOG(FATAL) << "Should not happen: Expected BSTR";
+#endif  // __TRUSTY__
+        }
+    }
+
+    std::unique_ptr<Item> finalize() && override { return std::make_unique<Bstr>(mValue); }
+};
+
+class IncompleteTstr : public Tstr, public IncompleteItem {
+  public:
+    explicit IncompleteTstr() {}
+
+    // The finalized version creates a copy which will not have this overridden.
+    bool isCompound() const override { return true; }
+
+    void add(std::unique_ptr<Item> item) override {
+        if (item->type() == TSTR) {
+            ss << item->asTstr()->moveValue();
+        } else {
+#ifndef __TRUSTY__
+            LOG(FATAL) << "Should not happen: Expected TSTR";
+#endif  // __TRUSTY__
+        }
+    }
+
+    std::unique_ptr<Item> finalize() && override { return std::make_unique<Tstr>(ss.str()); }
+
+  private:
+    std::stringstream ss;
+};
+
 class IncompleteArray : public Array, public IncompleteItem {
   public:
     explicit IncompleteArray(std::optional<size_t> size) : mSize(size) {}
 
     // If the "complete" size is known, return it, otherwise return the current size.
-    size_t size() const override {
-        return mSize.value_or(Array::size());
-    }
+    size_t size() const override { return mSize.value_or(Array::size()); }
 
     void add(std::unique_ptr<Item> item) override {
+        if (mSize) mEntries.reserve(std::min(mSize.value(), kMaxReserveSize));
         mEntries.push_back(std::move(item));
     }
 
@@ -152,12 +252,11 @@ class IncompleteMap : public Map, public IncompleteItem {
     explicit IncompleteMap(std::optional<size_t> size) : mSize(size) {}
 
     // If the "complete" size is known, return it, otherwise return the current size.
-    size_t size() const override {
-        return mSize.value_or(Map::size());
-    }
+    size_t size() const override { return mSize.value_or(Map::size()); }
 
     void add(std::unique_ptr<Item> item) override {
         if (mKeyHeldForAdding) {
+            if (mSize) mEntries.reserve(std::min(mSize.value(), kMaxReserveSize));
             mEntries.push_back({std::move(mKeyHeldForAdding), std::move(item)});
         } else {
             mKeyHeldForAdding = std::move(item);
@@ -205,6 +304,16 @@ IncompleteItem* IncompleteItem::cast(Item* item) {
         CHECK(dynamic_cast<IncompleteMap*>(item));
 #endif
         return static_cast<IncompleteMap*>(item);
+    } else if (item->type() == BSTR) {
+#if __has_feature(cxx_rtti)
+        CHECK(dynamic_cast<IncompleteBstr*>(item));
+#endif
+        return static_cast<IncompleteBstr*>(item);
+    } else if (item->type() == TSTR) {
+#if __has_feature(cxx_rtti)
+        CHECK(dynamic_cast<IncompleteTstr*>(item));
+#endif
+        return static_cast<IncompleteTstr*>(item);
     } else {
         CHECK(false);  // Impossible to get here.
     }
@@ -217,15 +326,15 @@ std::tuple<const uint8_t*, ParseClient*> handleEntries(std::optional<size_t> ent
                                                        const std::string& typeName, bool emitViews,
                                                        ParseClient* parseClient, unsigned depth) {
     while (entryCount.value_or(1) > 0) {
-        if(entryCount.has_value()) {
+        if (entryCount.has_value()) {
             --*entryCount;
         }
         if (pos == end) {
             parseClient->error(hdrBegin, "Not enough entries for " + typeName + ".");
             return {hdrBegin, nullptr /* end parsing */};
         }
-        if (*pos == 0xFF) {
-            // Next character is the "break" Stop Code
+        if (!entryCount.has_value() && *pos == 0xFF) {
+            // We're in an indeterminate-length object and found a stop code.
             ++pos;
             break;
         }
@@ -256,8 +365,7 @@ std::tuple<const uint8_t*, ParseClient*> parseRecursively(const uint8_t* begin,
                                                           unsigned depth) {
     if (begin == end) {
         parseClient->error(
-                begin,
-                "Input buffer is empty. Begin and end cannot point to the same location.");
+                begin, "Input buffer is empty. Begin and end cannot point to the same location.");
         return {begin, nullptr};
     }
 
@@ -302,7 +410,9 @@ std::tuple<const uint8_t*, ParseClient*> parseRecursively(const uint8_t* begin,
                 break;
 
             case INDEFINITE_LENGTH:
-                if (type != ARRAY && type != MAP) {
+                // View only strings are not yet supported due to their disjoint nature.
+                if (type != ARRAY && type != MAP && !(type == BSTR && !emitViews) &&
+                    !(type == TSTR && !emitViews)) {
                     parseClient->error(begin, "Unsupported indefinite length item.");
                     return {begin, nullptr};
                 }
@@ -325,45 +435,63 @@ std::tuple<const uint8_t*, ParseClient*> parseRecursively(const uint8_t* begin,
             return handleNint(*addlData, begin, pos, parseClient);
 
         case BSTR:
-            if (emitViews) {
-                return handleString<ViewBstr>(*addlData, begin, pos, end,
-                                              "byte string", parseClient);
+            if (!addlData.has_value()) {
+                return handleIncompleteString(std::make_unique<IncompleteBstr>(), begin, pos, end,
+                                              "byte string", emitViews, parseClient, depth);
+            } else if (emitViews) {
+                return handleString<ViewBstr>(*addlData, begin, pos, end, "byte string",
+                                              parseClient);
             } else {
-                return handleString<Bstr>(*addlData, begin, pos, end,
-                                          "byte string", parseClient);
+                return handleString<Bstr>(*addlData, begin, pos, end, "byte string", parseClient);
             }
 
         case TSTR:
-            if (emitViews) {
-                return handleString<ViewTstr>(*addlData, begin, pos, end,
-                                              "text string", parseClient);
+            if (!addlData.has_value()) {
+                return handleIncompleteString(std::make_unique<IncompleteTstr>(), begin, pos, end,
+                                              "text string", emitViews, parseClient, depth);
+            } else if (emitViews) {
+                return handleString<ViewTstr>(*addlData, begin, pos, end, "text string",
+                                              parseClient);
             } else {
-                return handleString<Tstr>(*addlData, begin, pos, end,
-                                          "text string", parseClient);
+                return handleString<Tstr>(*addlData, begin, pos, end, "text string", parseClient);
             }
 
         case ARRAY:
-            return handleCompound(std::make_unique<IncompleteArray>(addlData), addlData,
-                                  begin, pos, end, "array", emitViews, parseClient, depth);
+            return handleCompound(std::make_unique<IncompleteArray>(addlData), addlData, begin, pos,
+                                  end, "array", emitViews, parseClient, depth);
 
         case MAP:
             return handleCompound(std::make_unique<IncompleteMap>(addlData),
-                    addlData.has_value() ? *addlData * 2 : addlData, begin, pos, end,
-                    "map", emitViews, parseClient, depth);
+                                  addlData.has_value() ? *addlData * 2 : addlData, begin, pos, end,
+                                  "map", emitViews, parseClient, depth);
 
         case SEMANTIC:
             return handleCompound(std::make_unique<IncompleteSemanticTag>(*addlData), 1, begin, pos,
                                   end, "semantic", emitViews, parseClient, depth);
 
         case SIMPLE:
-            switch (*addlData) {
+            switch (tagInt) {
                 case TRUE:
                 case FALSE:
                     return handleBool(*addlData, begin, pos, parseClient);
+                case FLOAT_V:
+#if defined(__STDC_IEC_559__) || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+                    return handleFloat(*addlData, begin, pos, parseClient);
+#else
+                    parseClient->error(begin, "Value float is not supported for platform.");
+                    return {begin, nullptr};
+#endif  // __STDC_IEC_559__ || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+                case DOUBLE_V:
+#if defined(__STDC_IEC_559__) || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
+                    return handleDouble(*addlData, begin, pos, parseClient);
+#else
+                    parseClient->error(begin, "Value double is not supported for platform.");
+                    return {begin, nullptr};
+#endif  // __STDC_IEC_559__ || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
                 case NULL_V:
                     return handleNull(begin, pos, parseClient);
                 default:
-                    parseClient->error(begin, "Unsupported floating-point or simple value.");
+                    parseClient->error(begin, "Unsupported half-floating-point or simple value.");
                     return {begin, nullptr};
             }
     }
@@ -389,8 +517,7 @@ class FullParseClient : public ParseClient {
             mParentStack.push(item.get());
             return this;
         } else {
-            appendToLastParent(std::move(item));
-            return this;
+            return appendToLastParent(std::move(item));
         }
     }
 
@@ -406,8 +533,7 @@ class FullParseClient : public ParseClient {
             mPosition = end;
             return nullptr;  // We're done
         } else {
-            appendToLastParent(std::move(finalizedItem));
-            return this;
+            return appendToLastParent(std::move(finalizedItem));
         }
     }
 
@@ -424,9 +550,28 @@ class FullParseClient : public ParseClient {
     }
 
   private:
-    void appendToLastParent(std::unique_ptr<Item> item) {
+    ParseClient* appendToLastParent(std::unique_ptr<Item> item) {
         auto parent = mParentStack.top();
-        IncompleteItem::cast(parent)->add(std::move(item));
+        switch (parent->type()) {
+            case BSTR:
+                if (item->type() != BSTR) {
+                    mErrorMessage += "Expected BSTR in indefinite-length string.";
+                    return nullptr;
+                }
+                IncompleteItem::cast(parent)->add(std::move(item));
+                break;
+            case TSTR:
+                if (item->type() != TSTR) {
+                    mErrorMessage += "Expected TSTR in indefinite-length string.";
+                    return nullptr;
+                }
+                IncompleteItem::cast(parent)->add(std::move(item));
+                break;
+            default:
+                IncompleteItem::cast(parent)->add(std::move(item));
+                break;
+        }
+        return this;
     }
 
     std::unique_ptr<Item> mTheItem;
diff --git a/tests/cppbor_test.cpp b/tests/cppbor_test.cpp
index 2a62672..0a3bb47 100644
--- a/tests/cppbor_test.cpp
+++ b/tests/cppbor_test.cpp
@@ -14,6 +14,8 @@
  * limitations under the License.
  */
 
+#include <cfloat>
+#include <cmath>
 #include <cstdint>
 #include <iomanip>
 #include <sstream>
@@ -988,7 +990,7 @@ TEST(ConvertTest, ViewBstr) {
     EXPECT_NE(nullptr, item->asViewBstr());
 
     auto toVec = [](span<const uint8_t> view) {
-      return std::vector<uint8_t>(view.begin(), view.end());
+        return std::vector<uint8_t>(view.begin(), view.end());
     };
     EXPECT_EQ(toVec(view), toVec(item->asViewBstr()->view()));
 }
@@ -1581,27 +1583,27 @@ TEST(StreamParseTest, ViewBstr) {
 }
 
 TEST(StreamParseTest, AllowDepth1000) {
-  std::vector<uint8_t> data(/* count */ 1000, /* value = array with one entry */ 0x81);
-  data.push_back(0);
+    std::vector<uint8_t> data(/* count */ 1000, /* value = array with one entry */ 0x81);
+    data.push_back(0);
 
-  MockParseClient mpc;
-  EXPECT_CALL(mpc, item).Times(1001).WillRepeatedly(Return(&mpc));
-  EXPECT_CALL(mpc, itemEnd).Times(1000).WillRepeatedly(Return(&mpc));
-  EXPECT_CALL(mpc, error(_, _)).Times(0);
+    MockParseClient mpc;
+    EXPECT_CALL(mpc, item).Times(1001).WillRepeatedly(Return(&mpc));
+    EXPECT_CALL(mpc, itemEnd).Times(1000).WillRepeatedly(Return(&mpc));
+    EXPECT_CALL(mpc, error(_, _)).Times(0);
 
-  parse(data.data(), data.data() + data.size(), &mpc);
+    parse(data.data(), data.data() + data.size(), &mpc);
 }
 
 TEST(StreamParseTest, DisallowDepth1001) {
-  std::vector<uint8_t> data(/* count */ 1001, /* value = array with one entry */ 0x81);
-  data.push_back(0);
+    std::vector<uint8_t> data(/* count */ 1001, /* value = array with one entry */ 0x81);
+    data.push_back(0);
 
-  MockParseClient mpc;
-  EXPECT_CALL(mpc, item).Times(1001).WillRepeatedly(Return(&mpc));
-  EXPECT_CALL(mpc, itemEnd).Times(0);
-  EXPECT_CALL(mpc, error(_, StartsWith("Max depth reached"))).Times(1);
+    MockParseClient mpc;
+    EXPECT_CALL(mpc, item).Times(1001).WillRepeatedly(Return(&mpc));
+    EXPECT_CALL(mpc, itemEnd).Times(0);
+    EXPECT_CALL(mpc, error(_, StartsWith("Max depth reached"))).Times(1);
 
-  parse(data.data(), data.data() + data.size(), &mpc);
+    parse(data.data(), data.data() + data.size(), &mpc);
 }
 
 TEST(FullParserTest, Uint) {
@@ -1648,11 +1650,47 @@ TEST(FullParserTest, Tstr) {
 }
 
 TEST(FullParserTest, IndefiniteLengthTstr) {
-    vector<uint8_t> indefiniteRangeTstr = {0x7F, 't', 'e', 's', 't'};
+    vector<uint8_t> indefiniteRangeTstr = {0x7F, 0x64, 't', 'e', 's', 't',
+                                           0x63, 'a',  'b', 'c', 0xFF};
+    Tstr val("testabc");
+
+    auto [item, pos, message] = parse(indefiniteRangeTstr);
+    EXPECT_THAT(item, MatchesItem(val));
+}
+
+TEST(FullParserTest, EmptyIndefiniteLengthTstr) {
+    vector<uint8_t> indefiniteRangeTstr = {0x7F, 0xFF};
+    Tstr val("");
+
+    auto [item, pos, message] = parse(indefiniteRangeTstr);
+    EXPECT_THAT(item, MatchesItem(val));
+}
+
+TEST(FullParserTest, EmptyChunkIndefiniteLengthTstr) {
+    vector<uint8_t> indefiniteRangeTstr = {0x7F, 0x60, 0xFF};
+    Tstr val("");
+
+    auto [item, pos, message] = parse(indefiniteRangeTstr);
+    EXPECT_THAT(item, MatchesItem(val));
+}
+
+TEST(FullParserTest, SingleChunkIndefiniteLengthTstr) {
+    vector<uint8_t> indefiniteRangeTstr = {0x7F, 0x64, 't', 'e', 's', 't', 0xFF};
+    Tstr val("test");
 
     auto [item, pos, message] = parse(indefiniteRangeTstr);
+    EXPECT_THAT(item, MatchesItem(val));
+}
+
+TEST(FullParserTest, IndefiniteLengthViewTstr) {
+    vector<uint8_t> indefiniteRangeViewTstr = {0x7F, 0x64, 't', 'e', 's', 't',
+                                               0x63, 'a',  'b', 'c', 0xFF};
+
+    auto [item, pos, message] =
+            parseWithViews(indefiniteRangeViewTstr.data(),
+                           indefiniteRangeViewTstr.data() + indefiniteRangeViewTstr.size());
     EXPECT_THAT(item, IsNull());
-    EXPECT_EQ(pos, indefiniteRangeTstr.data());
+    EXPECT_EQ(pos, indefiniteRangeViewTstr.data());
     EXPECT_EQ(message, "Unsupported indefinite length item.");
 }
 
@@ -1664,11 +1702,47 @@ TEST(FullParserTest, Bstr) {
 }
 
 TEST(FullParserTest, IndefiniteLengthBstr) {
-    vector<uint8_t> indefiniteRangeBstr = {0x5F, 0x41, 0x42, 0x43, 0x44};
+    vector<uint8_t> indefiniteRangeBstr = {0x5F, 0x44, 0xaa, 0xbb, 0xcc, 0xdd,
+                                           0x43, 0xee, 0xff, 0x99, 0xFF};
+    Bstr val("\xaa\xbb\xcc\xdd\xee\xff\x99"s);
 
     auto [item, pos, message] = parse(indefiniteRangeBstr);
+    EXPECT_THAT(item, MatchesItem(val));
+}
+
+TEST(FullParserTest, EmptyIndefiniteLengthBstr) {
+    vector<uint8_t> indefiniteRangeBstr = {0x5F, 0xFF};
+    Bstr val(""s);
+
+    auto [item, pos, message] = parse(indefiniteRangeBstr);
+    EXPECT_THAT(item, MatchesItem(val));
+}
+
+TEST(FullParserTest, EmptyChunkIndefiniteLengthBstr) {
+    vector<uint8_t> indefiniteRangeBstr = {0x5F, 0x40, 0xFF};
+    Bstr val(""s);
+
+    auto [item, pos, message] = parse(indefiniteRangeBstr);
+    EXPECT_THAT(item, MatchesItem(val));
+}
+
+TEST(FullParserTest, SingleChunkIndefiniteLengthBstr) {
+    vector<uint8_t> indefiniteRangeBstr = {0x5F, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0xFF};
+    Bstr val("\xaa\xbb\xcc\xdd"s);
+
+    auto [item, pos, message] = parse(indefiniteRangeBstr);
+    EXPECT_THAT(item, MatchesItem(val));
+}
+
+TEST(FullParserTest, IndefiniteLengthViewBstr) {
+    vector<uint8_t> indefiniteRangeViewBstr = {0x5F, 0x44, 0xaa, 0xbb, 0xcc, 0xdd,
+                                               0x43, 0xee, 0xff, 0x99, 0xFF};
+
+    auto [item, pos, message] =
+            parseWithViews(indefiniteRangeViewBstr.data(),
+                           indefiniteRangeViewBstr.data() + indefiniteRangeViewBstr.size());
     EXPECT_THAT(item, IsNull());
-    EXPECT_EQ(pos, indefiniteRangeBstr.data());
+    EXPECT_EQ(pos, indefiniteRangeViewBstr.data());
     EXPECT_EQ(message, "Unsupported indefinite length item.");
 }
 
@@ -1690,11 +1764,11 @@ TEST(FullParserTest, Array) {
 
 TEST(FullParserTest, ArrayTooBigForMemory) {
     vector<uint8_t> encoded = {
-      // Array with 2^64 - 1 data items.
-      0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
-      // First item.
-      0x01,
-      // Rest of the items are missing.
+            // Array with 2^64 - 1 data items.
+            0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
+            // First item.
+            0x01,
+            // Rest of the items are missing.
     };
 
     auto [item, pos, message] = parse(encoded);
@@ -1723,9 +1797,8 @@ TEST(FullParserTest, MutableOutput) {
     Array* parsedNestedArray = parsedNestedMap->get("array")->asArray();
     ASSERT_NE(nullptr, parsedNestedArray);
     parsedNestedArray->add("pie");
-    EXPECT_THAT(
-        updatedItem->asArray()->get(0)->asMap()->get("array")->asArray()->get(2),
-        MatchesItem(Tstr("pie")));
+    EXPECT_THAT(updatedItem->asArray()->get(0)->asMap()->get("array")->asArray()->get(2),
+                MatchesItem(Tstr("pie")));
 
     // encode the mutated item, then ensure the CBOR is valid
     const auto encodedUpdatedItem = updatedItem->encode();
@@ -1745,11 +1818,11 @@ TEST(FullParserTest, Map) {
 
 TEST(FullParserTest, MapTooBigForMemory) {
     vector<uint8_t> encoded = {
-      // Map with 2^64 - 1 pairs of data items.
-      0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
-      // First pair.
-      0x01, 0x01,
-      // Rest of the pairs are missing.
+            // Map with 2^64 - 1 pairs of data items.
+            0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
+            // First pair.
+            0x01, 0x01,
+            // Rest of the pairs are missing.
     };
 
     auto [item, pos, message] = parse(encoded);
@@ -1765,6 +1838,17 @@ TEST(FullParserTest, SemanticTag) {
     EXPECT_THAT(item, MatchesItem(ByRef(val)));
 }
 
+TEST(FullParserTest, SemanticTagWithInvalidContent) {
+    vector<uint8_t> invalidSemantic = {
+            0xc7,  // Semantic tag, value 7.
+            0xff,  // "Break" stop code.
+    };
+    auto [item, pos, message] = parse(invalidSemantic);
+    EXPECT_THAT(item, IsNull());
+    EXPECT_EQ(pos, invalidSemantic.data() + 1);
+    EXPECT_EQ(message, "Unsupported indefinite length item.");
+}
+
 TEST(FullParserTest, NestedSemanticTag) {
     SemanticTag val(10, SemanticTag(99, "Salem"));
 
@@ -1936,17 +2020,156 @@ TEST(FullParserTest, UnassignedSimpleValue) {
     auto [item, pos, message] = parse(unassignedSimpleValue);
     EXPECT_THAT(item, IsNull());
     EXPECT_EQ(pos, unassignedSimpleValue.data());
-    EXPECT_EQ("Unsupported floating-point or simple value.", message);
+    EXPECT_EQ("Unsupported half-floating-point or simple value.", message);
 }
 
+#if defined(__STDC_IEC_559__) || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
 TEST(FullParserTest, FloatingPointValue) {
     vector<uint8_t> floatingPointValue = {0xFA, 0x12, 0x75, 0x34, 0x37};
+    float f_val = 7.737272847557572e-28;
 
     auto [item, pos, message] = parse(floatingPointValue);
-    EXPECT_THAT(item, IsNull());
-    EXPECT_EQ(pos, floatingPointValue.data());
-    EXPECT_EQ("Unsupported floating-point or simple value.", message);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_EQ(item->asSimple()->asFloat()->value(), f_val);
+
+    Float f(f_val);
+    EXPECT_EQ(f.encode(), floatingPointValue);
+}
+
+TEST(FullParserTest, PositiveInfinityFloatingPointValue) {
+    vector<uint8_t> floatingPointValue = {0xFA, 0x7F, 0x80, 0x00, 0x00};
+    float f_val = std::numeric_limits<float>::infinity();
+
+    auto [item, pos, message] = parse(floatingPointValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_EQ(item->asSimple()->asFloat()->value(), f_val);
+
+    Float f(f_val);
+    EXPECT_EQ(f.encode(), floatingPointValue);
+}
+
+TEST(FullParserTest, NegativeInfinityFloatingPointValue) {
+    vector<uint8_t> floatingPointValue = {0xFA, 0xFF, 0x80, 0x00, 0x00};
+    float f_val = -std::numeric_limits<float>::infinity();
+
+    auto [item, pos, message] = parse(floatingPointValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_EQ(item->asSimple()->asFloat()->value(), f_val);
+
+    Float f(f_val);
+    EXPECT_EQ(f.encode(), floatingPointValue);
+}
+
+TEST(FullParserTest, QuietNaNFloatingPointValue) {
+    vector<uint8_t> floatingPointValue = {0xFA, 0x7F, 0xC0, 0x00, 0x00};
+
+    auto [item, pos, message] = parse(floatingPointValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_TRUE(std::isnan(item->asSimple()->asFloat()->value()));
+
+    float f_val = std::numeric_limits<float>::quiet_NaN();
+    Float f(f_val);
+    EXPECT_EQ(f.encode(), floatingPointValue);
+}
+
+TEST(FullParserTest, MaxFloatingPointValue) {
+    vector<uint8_t> floatingPointValue = {0xFA, 0x7F, 0x7F, 0xFF, 0xFF};
+    float f_val = std::numeric_limits<float>::max();
+
+    auto [item, pos, message] = parse(floatingPointValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_EQ(item->asSimple()->asFloat()->value(), f_val);
+
+    Float f(f_val);
+    EXPECT_EQ(f.encode(), floatingPointValue);
+}
+
+TEST(FullParserTest, MinFloatingPointValue) {
+    vector<uint8_t> floatingPointValue = {0xFA, 0x00, 0x80, 0x00, 0x00};
+    float f_val = std::numeric_limits<float>::min();
+
+    auto [item, pos, message] = parse(floatingPointValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_EQ(item->asSimple()->asFloat()->value(), f_val);
+
+    Float f(f_val);
+    EXPECT_EQ(f.encode(), floatingPointValue);
+}
+#endif  // defined(__STDC_IEC_559__) || FLT_MANT_DIG == 24 || __FLT_MANT_DIG__ == 24
+
+#if defined(__STDC_IEC_559__) || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
+TEST(FullParserTest, DoubleValue) {
+    vector<uint8_t> doubleValue = {0xFB, 0x40, 0x09, 0x21, 0xFB, 0x4D, 0x12, 0xD8, 0x4A};
+    double d_val = 3.1415926000000001;
+
+    auto [item, pos, message] = parse(doubleValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_EQ(item->asSimple()->asDouble()->value(), d_val);
+
+    Double d(d_val);
+    EXPECT_EQ(d.encode(), doubleValue);
+}
+
+TEST(FullParserTest, PositiveInfinityDoubleValue) {
+    vector<uint8_t> doubleValue = {0xFB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
+    double d_val = std::numeric_limits<double>::infinity();
+
+    auto [item, pos, message] = parse(doubleValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_EQ(item->asSimple()->asDouble()->value(), d_val);
+
+    Double d(d_val);
+    EXPECT_EQ(d.encode(), doubleValue);
+}
+
+TEST(FullParserTest, NegativeInfinityDoubleValue) {
+    vector<uint8_t> doubleValue = {0xFB, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
+    double d_val = -std::numeric_limits<double>::infinity();
+
+    auto [item, pos, message] = parse(doubleValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_EQ(item->asSimple()->asDouble()->value(), d_val);
+
+    Double d(d_val);
+    EXPECT_EQ(d.encode(), doubleValue);
+}
+
+TEST(FullParserTest, QuietNaNDoubleValue) {
+    vector<uint8_t> doubleValue = {0xFB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
+
+    auto [item, pos, message] = parse(doubleValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_TRUE(std::isnan(item->asSimple()->asDouble()->value()));
+
+    double d_val = std::numeric_limits<double>::quiet_NaN();
+    Double d(d_val);
+    EXPECT_EQ(d.encode(), doubleValue);
+}
+
+TEST(FullParserTest, MaxDoubleValue) {
+    vector<uint8_t> doubleValue = {0xFB, 0x7F, 0xEF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
+    double d_val = std::numeric_limits<double>::max();
+
+    auto [item, pos, message] = parse(doubleValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_EQ(item->asSimple()->asDouble()->value(), d_val);
+
+    Double d(d_val);
+    EXPECT_EQ(d.encode(), doubleValue);
+}
+
+TEST(FullParserTest, MinDoubleValue) {
+    vector<uint8_t> doubleValue = {0xFB, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
+    double d_val = std::numeric_limits<double>::min();
+
+    auto [item, pos, message] = parse(doubleValue);
+    EXPECT_THAT(item, NotNull());
+    EXPECT_EQ(item->asSimple()->asDouble()->value(), d_val);
+
+    Double d(d_val);
+    EXPECT_EQ(d.encode(), doubleValue);
 }
+#endif  // __STDC_IEC_559__ || DBL_MANT_DIG == 53 || __DBL_MANT_DIG__ == 53
 
 TEST(MapGetValueByKeyTest, Map) {
     Array compoundItem(1, 2, 3, 4, 5, Map(4, 5, "a", "b"));
```

