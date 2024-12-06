```diff
diff --git a/README.md b/README.md
index b23cc0f..6463766 100644
--- a/README.md
+++ b/README.md
@@ -6,7 +6,8 @@ parsing CBOR messages.  It does not (yet) support all features of
 CBOR, nor (yet) support validation against CDDL schemata, though both
 are planned.  CBOR features that aren't supported include:
 
-* Indefinite length values
+* Parsing Indefinite length values for major types 2 (byte string) and 3 (text string)
+* Writing Indefinite length values
 * Semantic tagging
 * Floating point
 
diff --git a/include/cppbor/cppbor.h b/include/cppbor/cppbor.h
index 2362e3c..0589e0c 100644
--- a/include/cppbor/cppbor.h
+++ b/include/cppbor/cppbor.h
@@ -68,6 +68,7 @@ enum SpecialAddlInfoValues : uint8_t {
     TWO_BYTE_LENGTH = 25,
     FOUR_BYTE_LENGTH = 26,
     EIGHT_BYTE_LENGTH = 27,
+    INDEFINITE_LENGTH = 31,
 };
 
 class Item;
diff --git a/src/cppbor_parse.cpp b/src/cppbor_parse.cpp
index c3fa070..19ed3e0 100644
--- a/src/cppbor_parse.cpp
+++ b/src/cppbor_parse.cpp
@@ -17,6 +17,7 @@
 #include "cppbor_parse.h"
 
 #include <memory>
+#include <optional>
 #include <sstream>
 #include <stack>
 #include <type_traits>
@@ -125,10 +126,12 @@ class IncompleteItem {
 
 class IncompleteArray : public Array, public IncompleteItem {
   public:
-    explicit IncompleteArray(size_t size) : mSize(size) {}
+    explicit IncompleteArray(std::optional<size_t> size) : mSize(size) {}
 
-    // We return the "complete" size, rather than the actual size.
-    size_t size() const override { return mSize; }
+    // If the "complete" size is known, return it, otherwise return the current size.
+    size_t size() const override {
+        return mSize.value_or(Array::size());
+    }
 
     void add(std::unique_ptr<Item> item) override {
         mEntries.push_back(std::move(item));
@@ -141,15 +144,17 @@ class IncompleteArray : public Array, public IncompleteItem {
     }
 
   private:
-    size_t mSize;
+    std::optional<size_t> mSize;
 };
 
 class IncompleteMap : public Map, public IncompleteItem {
   public:
-    explicit IncompleteMap(size_t size) : mSize(size) {}
+    explicit IncompleteMap(std::optional<size_t> size) : mSize(size) {}
 
-    // We return the "complete" size, rather than the actual size.
-    size_t size() const override { return mSize; }
+    // If the "complete" size is known, return it, otherwise return the current size.
+    size_t size() const override {
+        return mSize.value_or(Map::size());
+    }
 
     void add(std::unique_ptr<Item> item) override {
         if (mKeyHeldForAdding) {
@@ -165,7 +170,7 @@ class IncompleteMap : public Map, public IncompleteItem {
 
   private:
     std::unique_ptr<Item> mKeyHeldForAdding;
-    size_t mSize;
+    std::optional<size_t> mSize;
 };
 
 class IncompleteSemanticTag : public SemanticTag, public IncompleteItem {
@@ -206,16 +211,24 @@ IncompleteItem* IncompleteItem::cast(Item* item) {
     return nullptr;
 }
 
-std::tuple<const uint8_t*, ParseClient*> handleEntries(size_t entryCount, const uint8_t* hdrBegin,
-                                                       const uint8_t* pos, const uint8_t* end,
+std::tuple<const uint8_t*, ParseClient*> handleEntries(std::optional<size_t> entryCount,
+                                                       const uint8_t* hdrBegin, const uint8_t* pos,
+                                                       const uint8_t* end,
                                                        const std::string& typeName, bool emitViews,
                                                        ParseClient* parseClient, unsigned depth) {
-    while (entryCount > 0) {
-        --entryCount;
+    while (entryCount.value_or(1) > 0) {
+        if(entryCount.has_value()) {
+            --*entryCount;
+        }
         if (pos == end) {
             parseClient->error(hdrBegin, "Not enough entries for " + typeName + ".");
             return {hdrBegin, nullptr /* end parsing */};
         }
+        if (*pos == 0xFF) {
+            // Next character is the "break" Stop Code
+            ++pos;
+            break;
+        }
         std::tie(pos, parseClient) = parseRecursively(pos, end, emitViews, parseClient, depth + 1);
         if (!parseClient) return {hdrBegin, nullptr};
     }
@@ -223,7 +236,7 @@ std::tuple<const uint8_t*, ParseClient*> handleEntries(size_t entryCount, const
 }
 
 std::tuple<const uint8_t*, ParseClient*> handleCompound(
-        std::unique_ptr<Item> item, uint64_t entryCount, const uint8_t* hdrBegin,
+        std::unique_ptr<Item> item, std::optional<uint64_t> entryCount, const uint8_t* hdrBegin,
         const uint8_t* valueBegin, const uint8_t* end, const std::string& typeName, bool emitViews,
         ParseClient* parseClient, unsigned depth) {
     parseClient =
@@ -264,13 +277,11 @@ std::tuple<const uint8_t*, ParseClient*> parseRecursively(const uint8_t* begin,
     ++pos;
 
     bool success = true;
-    uint64_t addlData;
+    std::optional<uint64_t> addlData;
     if (tagInt < ONE_BYTE_LENGTH) {
         addlData = tagInt;
-    } else if (tagInt > EIGHT_BYTE_LENGTH) {
-        parseClient->error(
-                begin,
-                "Reserved additional information value or unsupported indefinite length item.");
+    } else if (tagInt > EIGHT_BYTE_LENGTH && tagInt != INDEFINITE_LENGTH) {
+        parseClient->error(begin, "Reserved additional information value.");
         return {begin, nullptr};
     } else {
         switch (tagInt) {
@@ -290,6 +301,14 @@ std::tuple<const uint8_t*, ParseClient*> parseRecursively(const uint8_t* begin,
                 std::tie(success, addlData, pos) = parseLength<uint64_t>(pos, end, parseClient);
                 break;
 
+            case INDEFINITE_LENGTH:
+                if (type != ARRAY && type != MAP) {
+                    parseClient->error(begin, "Unsupported indefinite length item.");
+                    return {begin, nullptr};
+                }
+                addlData = std::nullopt;
+                break;
+
             default:
                 CHECK(false);  //  It's impossible to get here
                 break;
@@ -300,42 +319,47 @@ std::tuple<const uint8_t*, ParseClient*> parseRecursively(const uint8_t* begin,
 
     switch (type) {
         case UINT:
-            return handleUint(addlData, begin, pos, parseClient);
+            return handleUint(*addlData, begin, pos, parseClient);
 
         case NINT:
-            return handleNint(addlData, begin, pos, parseClient);
+            return handleNint(*addlData, begin, pos, parseClient);
 
         case BSTR:
             if (emitViews) {
-                return handleString<ViewBstr>(addlData, begin, pos, end, "byte string", parseClient);
+                return handleString<ViewBstr>(*addlData, begin, pos, end,
+                                              "byte string", parseClient);
             } else {
-                return handleString<Bstr>(addlData, begin, pos, end, "byte string", parseClient);
+                return handleString<Bstr>(*addlData, begin, pos, end,
+                                          "byte string", parseClient);
             }
 
         case TSTR:
             if (emitViews) {
-                return handleString<ViewTstr>(addlData, begin, pos, end, "text string", parseClient);
+                return handleString<ViewTstr>(*addlData, begin, pos, end,
+                                              "text string", parseClient);
             } else {
-                return handleString<Tstr>(addlData, begin, pos, end, "text string", parseClient);
+                return handleString<Tstr>(*addlData, begin, pos, end,
+                                          "text string", parseClient);
             }
 
         case ARRAY:
-            return handleCompound(std::make_unique<IncompleteArray>(addlData), addlData, begin, pos,
-                                  end, "array", emitViews, parseClient, depth);
+            return handleCompound(std::make_unique<IncompleteArray>(addlData), addlData,
+                                  begin, pos, end, "array", emitViews, parseClient, depth);
 
         case MAP:
-            return handleCompound(std::make_unique<IncompleteMap>(addlData), addlData * 2, begin,
-                                  pos, end, "map", emitViews, parseClient, depth);
+            return handleCompound(std::make_unique<IncompleteMap>(addlData),
+                    addlData.has_value() ? *addlData * 2 : addlData, begin, pos, end,
+                    "map", emitViews, parseClient, depth);
 
         case SEMANTIC:
-            return handleCompound(std::make_unique<IncompleteSemanticTag>(addlData), 1, begin, pos,
+            return handleCompound(std::make_unique<IncompleteSemanticTag>(*addlData), 1, begin, pos,
                                   end, "semantic", emitViews, parseClient, depth);
 
         case SIMPLE:
-            switch (addlData) {
+            switch (*addlData) {
                 case TRUE:
                 case FALSE:
-                    return handleBool(addlData, begin, pos, parseClient);
+                    return handleBool(*addlData, begin, pos, parseClient);
                 case NULL_V:
                     return handleNull(begin, pos, parseClient);
                 default:
diff --git a/tests/cppbor_test.cpp b/tests/cppbor_test.cpp
index fadcaa9..2a62672 100644
--- a/tests/cppbor_test.cpp
+++ b/tests/cppbor_test.cpp
@@ -1647,6 +1647,15 @@ TEST(FullParserTest, Tstr) {
     EXPECT_THAT(item, MatchesItem(val));
 }
 
+TEST(FullParserTest, IndefiniteLengthTstr) {
+    vector<uint8_t> indefiniteRangeTstr = {0x7F, 't', 'e', 's', 't'};
+
+    auto [item, pos, message] = parse(indefiniteRangeTstr);
+    EXPECT_THAT(item, IsNull());
+    EXPECT_EQ(pos, indefiniteRangeTstr.data());
+    EXPECT_EQ(message, "Unsupported indefinite length item.");
+}
+
 TEST(FullParserTest, Bstr) {
     Bstr val("\x00\x01\0x02"s);
 
@@ -1654,6 +1663,15 @@ TEST(FullParserTest, Bstr) {
     EXPECT_THAT(item, MatchesItem(val));
 }
 
+TEST(FullParserTest, IndefiniteLengthBstr) {
+    vector<uint8_t> indefiniteRangeBstr = {0x5F, 0x41, 0x42, 0x43, 0x44};
+
+    auto [item, pos, message] = parse(indefiniteRangeBstr);
+    EXPECT_THAT(item, IsNull());
+    EXPECT_EQ(pos, indefiniteRangeBstr.data());
+    EXPECT_EQ(message, "Unsupported indefinite length item.");
+}
+
 TEST(FullParserTest, Array) {
     Array val("hello", -4, 3);
 
@@ -1858,18 +1876,58 @@ TEST(FullParserTest, ReservedAdditionalInformation) {
     auto [item, pos, message] = parse(reservedVal);
     EXPECT_THAT(item, IsNull());
     EXPECT_EQ(pos, reservedVal.data());
-    EXPECT_EQ("Reserved additional information value or unsupported indefinite length item.",
-              message);
+    EXPECT_EQ("Reserved additional information value.", message);
 }
 
-TEST(FullParserTest, IndefiniteArray) {
-    vector<uint8_t> indefiniteArray = {0x7F};
+TEST(FullParserTest, IndefiniteArrayEmpty) {
+    Bstr encoding("\x9F\xFF");
+    string expected = Array().toString();
 
-    auto [item, pos, message] = parse(indefiniteArray);
-    EXPECT_THAT(item, IsNull());
-    EXPECT_EQ(pos, indefiniteArray.data());
-    EXPECT_EQ("Reserved additional information value or unsupported indefinite length item.",
-              message);
+    auto [item, pos, message] = parse(&encoding);
+    EXPECT_EQ(expected, item->toString());
+}
+
+TEST(FullParserTest, IndefiniteArrayWithOneNumber) {
+    Bstr encoding("\x9F\x01\xFF");
+    string expected = Array(Uint(1)).toString();
+
+    auto [item, pos, message] = parse(&encoding);
+    EXPECT_EQ(expected, item->toString());
+}
+
+TEST(FullParserTest, IndefiniteArrayOfArray) {
+    Bstr encoding("\x9F\x9F\x01\xFF\xFF");
+
+    Array nested;
+    nested.add(Array(Uint(1)));
+    string expected = nested.toString();
+
+    auto [item, pos, message] = parse(&encoding);
+    EXPECT_EQ(expected, item->toString());
+}
+
+TEST(FullParserTest, IndefiniteMapEmpty) {
+    Bstr encoding("\xBF\xFF");
+    string expected = Map().toString();
+
+    auto [item, pos, message] = parse(&encoding);
+    EXPECT_EQ(expected, item->toString());
+}
+
+TEST(FullParserTest, IndefiniteMapsNested) {
+    Bstr encoding("\xBF\x01\xBF\xFF\xFF");
+    string expected = Map(Uint(1), Map()).toString();
+
+    auto [item, pos, message] = parse(&encoding);
+    EXPECT_EQ(expected, item->toString());
+}
+
+TEST(FullParserTest, IndefiniteMapWithOneEntry) {
+    Bstr encoding("\xBF\x01\x05\xFF");
+    string expected = Map(Uint(1), Uint(5)).toString();
+
+    auto [item, pos, message] = parse(&encoding);
+    EXPECT_EQ(expected, item->toString());
 }
 
 TEST(FullParserTest, UnassignedSimpleValue) {
```

