```diff
diff --git a/aidl.cpp b/aidl.cpp
index cf8c4861..1d81925c 100644
--- a/aidl.cpp
+++ b/aidl.cpp
@@ -16,31 +16,30 @@
 
 #include "aidl.h"
 
-#include <fcntl.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <sys/param.h>
-#include <sys/stat.h>
-#include <unistd.h>
 #include <algorithm>
-#include <iostream>
-#include <map>
+#include <functional>
 #include <memory>
-
-#ifdef _WIN32
-#include <io.h>
-#include <direct.h>
-#include <sys/stat.h>
-#endif
+#include <new>
+#include <set>
+#include <sstream>
+#include <string>
+#include <string_view>
+#include <utility>
+#include <vector>
 
 #include <android-base/strings.h>
 
 #include "aidl_checkapi.h"
 #include "aidl_dumpapi.h"
 #include "aidl_language.h"
+#include "aidl_to_cpp_common.h"
 #include "aidl_typenames.h"
 #include "check_valid.h"
+#include "code_writer.h"
+#include "diagnostics.h"
 #include "generate_aidl_mappings.h"
 #include "generate_cpp.h"
 #include "generate_cpp_analyzer.h"
@@ -48,6 +47,9 @@
 #include "generate_ndk.h"
 #include "generate_rust.h"
 #include "import_resolver.h"
+#include "include/aidl/transaction_ids.h"
+#include "io_delegate.h"
+#include "location.h"
 #include "logging.h"
 #include "options.h"
 #include "os.h"
diff --git a/aidl_checkapi.cpp b/aidl_checkapi.cpp
index 9580df11..4756affc 100644
--- a/aidl_checkapi.cpp
+++ b/aidl_checkapi.cpp
@@ -16,7 +16,11 @@
 
 #include "aidl.h"
 
+#include <algorithm>
+#include <cstddef>
+#include <iterator>
 #include <map>
+#include <set>
 #include <string>
 #include <vector>
 
@@ -26,7 +30,10 @@
 
 #include "aidl_dumpapi.h"
 #include "aidl_language.h"
-#include "import_resolver.h"
+#include "aidl_typenames.h"
+#include "code_writer.h"
+#include "io_delegate.h"
+#include "location.h"
 #include "logging.h"
 #include "options.h"
 
@@ -191,13 +198,6 @@ static bool are_compatible_interfaces(const AidlInterface& older, const AidlInte
     // has happened.
     const auto new_m = found->second;
 
-    // Adding oneway is an incompatible change, but removing oneway is not .
-    if (!old_m->IsOneway() && new_m->IsOneway()) {
-      AIDL_ERROR(new_m) << "Oneway attribute " << (old_m->IsOneway() ? "removed" : "added") << ": "
-                        << older.GetCanonicalName() << "." << old_m->Signature();
-      compatible = false;
-    }
-
     if (old_m->GetId() != new_m->GetId()) {
       AIDL_ERROR(new_m) << "Transaction ID changed: " << older.GetCanonicalName() << "."
                         << old_m->Signature() << " is changed from " << old_m->GetId() << " to "
diff --git a/aidl_const_expressions.cpp b/aidl_const_expressions.cpp
index b2a4c55a..bdce11ce 100644
--- a/aidl_const_expressions.cpp
+++ b/aidl_const_expressions.cpp
@@ -16,13 +16,23 @@
 
 #include "aidl_language.h"
 #include "aidl_typenames.h"
+#include "location.h"
 #include "logging.h"
 
 #include <stdlib.h>
 #include <algorithm>
+#include <cctype>
+#include <cstdint>
 #include <iostream>
 #include <limits>
 #include <memory>
+#include <new>
+#include <optional>
+#include <sstream>
+#include <string>
+#include <string_view>
+#include <utility>
+#include <vector>
 
 #include <android-base/parsedouble.h>
 #include <android-base/parseint.h>
diff --git a/aidl_dumpapi.cpp b/aidl_dumpapi.cpp
index 00957140..c690d43f 100644
--- a/aidl_dumpapi.cpp
+++ b/aidl_dumpapi.cpp
@@ -18,8 +18,18 @@
 
 #include <android-base/strings.h>
 
+#include <cstddef>
+#include <memory>
+#include <string>
+
 #include "aidl.h"
+#include "aidl_language.h"
+#include "aidl_typenames.h"
+#include "comments.h"
+#include "io_delegate.h"
+#include "location.h"
 #include "logging.h"
+#include "options.h"
 #include "os.h"
 
 using android::base::EndsWith;
diff --git a/aidl_language.cpp b/aidl_language.cpp
index 073622cd..1bc95051 100644
--- a/aidl_language.cpp
+++ b/aidl_language.cpp
@@ -16,28 +16,36 @@
 
 #include "aidl_language.h"
 #include "aidl_typenames.h"
-#include "parser.h"
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 #include <algorithm>
+#include <cctype>
+#include <cstdint>
+#include <functional>
 #include <iostream>
+#include <map>
+#include <memory>
+#include <new>
+#include <optional>
 #include <set>
 #include <sstream>
 #include <string>
+#include <unordered_set>
 #include <utility>
+#include <variant>
+#include <vector>
 
-#include <android-base/parsedouble.h>
-#include <android-base/parseint.h>
 #include <android-base/result.h>
 #include <android-base/strings.h>
 
-#include "aidl.h"
-#include "aidl_language_y.h"
 #include "comments.h"
+#include "io_delegate.h"
+#include "location.h"
 #include "logging.h"
+#include "options.h"
 #include "permission.h"
 
 #ifdef _WIN32
diff --git a/aidl_language.h b/aidl_language.h
index 5a724c57..44d5f86c 100644
--- a/aidl_language.h
+++ b/aidl_language.h
@@ -396,6 +396,137 @@ class AidlAnnotatable : public AidlCommentable {
   vector<std::unique_ptr<AidlAnnotation>> annotations_;
 };
 
+class AidlUnaryConstExpression;
+class AidlBinaryConstExpression;
+class AidlConstantReference;
+
+class AidlConstantValue : public AidlNode {
+ public:
+  enum class Type {
+    // WARNING: Don't change this order! The order is used to determine type
+    // promotion during a binary expression.
+    BOOLEAN,
+    INT8,
+    INT32,
+    INT64,
+    ARRAY,
+    CHARACTER,
+    STRING,
+    REF,
+    FLOATING,
+    UNARY,
+    BINARY,
+    ERROR,
+  };
+
+  // Returns the evaluated value. T> should match to the actual type.
+  template <typename T>
+  T EvaluatedValue() const {
+    is_evaluated_ || (CheckValid() && evaluate());
+    AIDL_FATAL_IF(!is_valid_, this);
+
+    if constexpr (is_vector<T>::value) {
+      AIDL_FATAL_IF(final_type_ != Type::ARRAY, this);
+      T result;
+      for (const auto& v : values_) {
+        result.push_back(v->EvaluatedValue<typename T::value_type>());
+      }
+      return result;
+    } else if constexpr (is_one_of<T, float, double>::value) {
+      AIDL_FATAL_IF(final_type_ != Type::FLOATING, this);
+      T result;
+      AIDL_FATAL_IF(!ParseFloating(value_, &result), this);
+      return result;
+    } else if constexpr (std::is_same<T, std::string>::value) {
+      AIDL_FATAL_IF(final_type_ != Type::STRING, this);
+      return final_string_value_.substr(1, final_string_value_.size() - 2);  // unquote "
+    } else if constexpr (is_one_of<T, int8_t, int32_t, int64_t>::value) {
+      AIDL_FATAL_IF(final_type_ < Type::INT8 && final_type_ > Type::INT64, this);
+      return static_cast<T>(final_value_);
+    } else if constexpr (std::is_same<T, char16_t>::value) {
+      AIDL_FATAL_IF(final_type_ != Type::CHARACTER, this);
+      return final_string_value_.at(1);  // unquote '
+    } else if constexpr (std::is_same<T, bool>::value) {
+      static_assert(std::is_same<T, bool>::value, "..");
+      AIDL_FATAL_IF(final_type_ != Type::BOOLEAN, this);
+      return final_value_ != 0;
+    } else {
+      static_assert(unsupported_type<T>::value);
+    }
+  }
+
+  virtual ~AidlConstantValue() = default;
+
+  // non-copyable, non-movable
+  AidlConstantValue(const AidlConstantValue&) = delete;
+  AidlConstantValue(AidlConstantValue&&) = delete;
+  AidlConstantValue& operator=(const AidlConstantValue&) = delete;
+  AidlConstantValue& operator=(AidlConstantValue&&) = delete;
+
+  // creates default value, when one isn't specified
+  // nullptr if no default available
+  static AidlConstantValue* Default(const AidlTypeSpecifier& specifier);
+
+  static AidlConstantValue* Boolean(const AidlLocation& location, bool value);
+  static AidlConstantValue* Character(const AidlLocation& location, const std::string& value);
+  // example: 123, -5498, maybe any size
+  static AidlConstantValue* Integral(const AidlLocation& location, const std::string& value);
+  static AidlConstantValue* Floating(const AidlLocation& location, const std::string& value);
+  static AidlConstantValue* Array(const AidlLocation& location,
+                                  std::unique_ptr<vector<unique_ptr<AidlConstantValue>>> values);
+  // example: "\"asdf\""
+  static AidlConstantValue* String(const AidlLocation& location, const string& value);
+
+  Type GetType() const { return final_type_; }
+  const std::string& Literal() const { return value_; }
+
+  bool Evaluate() const;
+  virtual bool CheckValid() const;
+
+  // Raw value of type (currently valid in C++ and Java). Empty string on error.
+  string ValueString(const AidlTypeSpecifier& type, const ConstantValueDecorator& decorator) const;
+
+  void TraverseChildren(std::function<void(const AidlNode&)> traverse) const override {
+    if (type_ == Type::ARRAY) {
+      for (const auto& v : values_) {
+        traverse(*v);
+      }
+    }
+  }
+  void DispatchVisit(AidlVisitor& visitor) const override { visitor.Visit(*this); }
+  size_t Size() const { return values_.size(); }
+  const AidlConstantValue& ValueAt(size_t index) const { return *values_.at(index); }
+  static string ToString(Type type);
+
+ private:
+  AidlConstantValue(const AidlLocation& location, Type parsed_type, int64_t parsed_value,
+                    const string& checked_value);
+  AidlConstantValue(const AidlLocation& location, Type type, const string& checked_value);
+  AidlConstantValue(const AidlLocation& location, Type type,
+                    std::unique_ptr<vector<unique_ptr<AidlConstantValue>>> values,
+                    const std::string& value);
+  static bool ParseIntegral(const string& value, int64_t* parsed_value, Type* parsed_type);
+  static bool IsHex(const string& value);
+
+  virtual bool evaluate() const;
+  bool IsLiteral() const;
+
+  const Type type_ = Type::ERROR;
+  const vector<unique_ptr<AidlConstantValue>> values_;  // if type_ == ARRAY
+  const string value_;                                  // otherwise
+
+  // State for tracking evaluation of expressions
+  mutable bool is_valid_ = false;      // cache of CheckValid, but may be marked false in evaluate
+  mutable bool is_evaluated_ = false;  // whether evaluate has been called
+  mutable Type final_type_;
+  mutable int64_t final_value_;
+  mutable string final_string_value_ = "";
+
+  friend AidlUnaryConstExpression;
+  friend AidlBinaryConstExpression;
+  friend AidlConstantReference;
+};
+
 // Represents `[]`
 struct DynamicArray {};
 // Represents `[N][M]..`
@@ -613,137 +744,6 @@ struct ArgumentAspect {
   std::set<AidlArgument::Direction> possible_directions;
 };
 
-class AidlUnaryConstExpression;
-class AidlBinaryConstExpression;
-class AidlConstantReference;
-
-class AidlConstantValue : public AidlNode {
- public:
-  enum class Type {
-    // WARNING: Don't change this order! The order is used to determine type
-    // promotion during a binary expression.
-    BOOLEAN,
-    INT8,
-    INT32,
-    INT64,
-    ARRAY,
-    CHARACTER,
-    STRING,
-    REF,
-    FLOATING,
-    UNARY,
-    BINARY,
-    ERROR,
-  };
-
-  // Returns the evaluated value. T> should match to the actual type.
-  template <typename T>
-  T EvaluatedValue() const {
-    is_evaluated_ || (CheckValid() && evaluate());
-    AIDL_FATAL_IF(!is_valid_, this);
-
-    if constexpr (is_vector<T>::value) {
-      AIDL_FATAL_IF(final_type_ != Type::ARRAY, this);
-      T result;
-      for (const auto& v : values_) {
-        result.push_back(v->EvaluatedValue<typename T::value_type>());
-      }
-      return result;
-    } else if constexpr (is_one_of<T, float, double>::value) {
-      AIDL_FATAL_IF(final_type_ != Type::FLOATING, this);
-      T result;
-      AIDL_FATAL_IF(!ParseFloating(value_, &result), this);
-      return result;
-    } else if constexpr (std::is_same<T, std::string>::value) {
-      AIDL_FATAL_IF(final_type_ != Type::STRING, this);
-      return final_string_value_.substr(1, final_string_value_.size() - 2);  // unquote "
-    } else if constexpr (is_one_of<T, int8_t, int32_t, int64_t>::value) {
-      AIDL_FATAL_IF(final_type_ < Type::INT8 && final_type_ > Type::INT64, this);
-      return static_cast<T>(final_value_);
-    } else if constexpr (std::is_same<T, char16_t>::value) {
-      AIDL_FATAL_IF(final_type_ != Type::CHARACTER, this);
-      return final_string_value_.at(1);  // unquote '
-    } else if constexpr (std::is_same<T, bool>::value) {
-      static_assert(std::is_same<T, bool>::value, "..");
-      AIDL_FATAL_IF(final_type_ != Type::BOOLEAN, this);
-      return final_value_ != 0;
-    } else {
-      static_assert(unsupported_type<T>::value);
-    }
-  }
-
-  virtual ~AidlConstantValue() = default;
-
-  // non-copyable, non-movable
-  AidlConstantValue(const AidlConstantValue&) = delete;
-  AidlConstantValue(AidlConstantValue&&) = delete;
-  AidlConstantValue& operator=(const AidlConstantValue&) = delete;
-  AidlConstantValue& operator=(AidlConstantValue&&) = delete;
-
-  // creates default value, when one isn't specified
-  // nullptr if no default available
-  static AidlConstantValue* Default(const AidlTypeSpecifier& specifier);
-
-  static AidlConstantValue* Boolean(const AidlLocation& location, bool value);
-  static AidlConstantValue* Character(const AidlLocation& location, const std::string& value);
-  // example: 123, -5498, maybe any size
-  static AidlConstantValue* Integral(const AidlLocation& location, const std::string& value);
-  static AidlConstantValue* Floating(const AidlLocation& location, const std::string& value);
-  static AidlConstantValue* Array(const AidlLocation& location,
-                                  std::unique_ptr<vector<unique_ptr<AidlConstantValue>>> values);
-  // example: "\"asdf\""
-  static AidlConstantValue* String(const AidlLocation& location, const string& value);
-
-  Type GetType() const { return final_type_; }
-  const std::string& Literal() const { return value_; }
-
-  bool Evaluate() const;
-  virtual bool CheckValid() const;
-
-  // Raw value of type (currently valid in C++ and Java). Empty string on error.
-  string ValueString(const AidlTypeSpecifier& type, const ConstantValueDecorator& decorator) const;
-
-  void TraverseChildren(std::function<void(const AidlNode&)> traverse) const override {
-    if (type_ == Type::ARRAY) {
-      for (const auto& v : values_) {
-        traverse(*v);
-      }
-    }
-  }
-  void DispatchVisit(AidlVisitor& visitor) const override { visitor.Visit(*this); }
-  size_t Size() const { return values_.size(); }
-  const AidlConstantValue& ValueAt(size_t index) const { return *values_.at(index); }
-  static string ToString(Type type);
-
- private:
-  AidlConstantValue(const AidlLocation& location, Type parsed_type, int64_t parsed_value,
-                    const string& checked_value);
-  AidlConstantValue(const AidlLocation& location, Type type, const string& checked_value);
-  AidlConstantValue(const AidlLocation& location, Type type,
-                    std::unique_ptr<vector<unique_ptr<AidlConstantValue>>> values,
-                    const std::string& value);
-  static bool ParseIntegral(const string& value, int64_t* parsed_value, Type* parsed_type);
-  static bool IsHex(const string& value);
-
-  virtual bool evaluate() const;
-  bool IsLiteral() const;
-
-  const Type type_ = Type::ERROR;
-  const vector<unique_ptr<AidlConstantValue>> values_;  // if type_ == ARRAY
-  const string value_;                                  // otherwise
-
-  // State for tracking evaluation of expressions
-  mutable bool is_valid_ = false;      // cache of CheckValid, but may be marked false in evaluate
-  mutable bool is_evaluated_ = false;  // whether evaluate has been called
-  mutable Type final_type_;
-  mutable int64_t final_value_;
-  mutable string final_string_value_ = "";
-
-  friend AidlUnaryConstExpression;
-  friend AidlBinaryConstExpression;
-  friend AidlConstantReference;
-};
-
 // Represents "<type>.<field>" which resolves to a constant which is one of
 // - constant declaration
 // - enumerator
diff --git a/aidl_to_common.cpp b/aidl_to_common.cpp
index c73aa1ba..b52a1d50 100644
--- a/aidl_to_common.cpp
+++ b/aidl_to_common.cpp
@@ -15,6 +15,8 @@
  */
 
 #include "aidl_to_common.h"
+#include "code_writer.h"
+#include "options.h"
 
 namespace android {
 namespace aidl {
diff --git a/aidl_to_cpp.cpp b/aidl_to_cpp.cpp
index aab00247..8ce2bd99 100644
--- a/aidl_to_cpp.cpp
+++ b/aidl_to_cpp.cpp
@@ -15,15 +15,21 @@
  */
 
 #include "aidl_to_cpp.h"
-#include "aidl_to_cpp_common.h"
 #include "aidl_language.h"
+#include "aidl_to_cpp_common.h"
+#include "aidl_typenames.h"
 #include "logging.h"
 
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 
-#include <functional>
+#include <map>
+#include <set>
+#include <sstream>
+#include <string>
 #include <unordered_map>
+#include <variant>
+#include <vector>
 
 using android::base::Join;
 using android::base::Split;
@@ -38,7 +44,7 @@ namespace {
 
 std::string RawParcelMethod(const AidlTypeSpecifier& type, const AidlTypenames& typenames,
                             bool readMethod) {
-  static map<string, string> kBuiltin = {
+  static std::map<std::string, std::string> kBuiltin = {
       {"byte", "Byte"},
       {"boolean", "Bool"},
       {"char", "Char"},
@@ -53,7 +59,7 @@ std::string RawParcelMethod(const AidlTypeSpecifier& type, const AidlTypenames&
       {"ParcelableHolder", "Parcelable"},
   };
 
-  static map<string, string> kBuiltinVector = {
+  static std::map<std::string, std::string> kBuiltinVector = {
       {"FileDescriptor", "UniqueFileDescriptorVector"},
       {"double", "DoubleVector"},
       {"char", "CharVector"},
@@ -84,7 +90,7 @@ std::string RawParcelMethod(const AidlTypeSpecifier& type, const AidlTypenames&
   }
 
   if (isVector) {
-    string element_name;
+    std::string element_name;
     if (typenames.IsList(type)) {
       AIDL_FATAL_IF(type.GetTypeParameters().size() != 1, type);
       element_name = type.GetTypeParameters().at(0)->GetName();
@@ -106,7 +112,7 @@ std::string RawParcelMethod(const AidlTypeSpecifier& type, const AidlTypenames&
     return "ParcelableVector";
   }
 
-  const string& type_name = type.GetName();
+  const std::string& type_name = type.GetName();
   if (kBuiltin.find(type_name) != kBuiltin.end()) {
     AIDL_FATAL_IF(!AidlTypenames::IsBuiltinTypename(type_name), type);
     if (type_name == "IBinder" && nullable && readMethod) {
@@ -162,7 +168,7 @@ std::string WrapIfNullable(const std::string type_str, const AidlTypeSpecifier&
 
 std::string GetCppName(const AidlTypeSpecifier& raw_type, const AidlTypenames& typenames) {
   // map from AIDL built-in type name to the corresponding Cpp type name
-  static map<string, string> m = {
+  static std::map<std::string, std::string> m = {
       {"boolean", "bool"},
       {"byte", "int8_t"},
       {"char", "char16_t"},
@@ -179,7 +185,7 @@ std::string GetCppName(const AidlTypeSpecifier& raw_type, const AidlTypenames& t
   };
   AIDL_FATAL_IF(typenames.IsList(raw_type) && raw_type.GetTypeParameters().size() != 1, raw_type);
   const auto& type = typenames.IsList(raw_type) ? (*raw_type.GetTypeParameters().at(0)) : raw_type;
-  const string& aidl_name = type.GetName();
+  const std::string& aidl_name = type.GetName();
   if (m.find(aidl_name) != m.end()) {
     AIDL_FATAL_IF(!AidlTypenames::IsBuiltinTypename(aidl_name), raw_type);
     if (aidl_name == "byte" && type.IsArray()) {
@@ -327,7 +333,7 @@ void AddHeaders(const AidlTypeSpecifier& type, const AidlTypenames& typenames,
     return;
   }
 
-  static const std::set<string> need_cstdint{"byte", "int", "long"};
+  static const std::set<std::string> need_cstdint{"byte", "int", "long"};
   if (need_cstdint.find(type.GetName()) != need_cstdint.end()) {
     headers->insert("cstdint");
     return;
diff --git a/aidl_to_cpp_common.cpp b/aidl_to_cpp_common.cpp
index eb6163d1..75dff95a 100644
--- a/aidl_to_cpp_common.cpp
+++ b/aidl_to_cpp_common.cpp
@@ -18,12 +18,27 @@
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 
+#include <algorithm>
+#include <cctype>
+#include <cstddef>
 #include <format>
-#include <limits>
+#include <map>
+#include <memory>
+#include <optional>
 #include <set>
-
+#include <sstream>
+#include <string>
+#include <utility>
+#include <variant>
+#include <vector>
+
+#include "aidl_language.h"
+#include "aidl_typenames.h"
+#include "code_writer.h"
 #include "comments.h"
+#include "location.h"
 #include "logging.h"
+#include "options.h"
 #include "os.h"
 
 using ::android::base::Join;
diff --git a/aidl_to_java.cpp b/aidl_to_java.cpp
index acbe6fed..610fc6b1 100644
--- a/aidl_to_java.cpp
+++ b/aidl_to_java.cpp
@@ -17,14 +17,17 @@
 #include "aidl_to_java.h"
 #include "aidl_language.h"
 #include "aidl_typenames.h"
+#include "code_writer.h"
+#include "location.h"
 #include "logging.h"
+#include "options.h"
 
 #include <android-base/strings.h>
 
 #include <functional>
-#include <iostream>
 #include <map>
 #include <string>
+#include <variant>
 #include <vector>
 
 namespace android {
diff --git a/aidl_to_ndk.cpp b/aidl_to_ndk.cpp
index f533c77c..2e61be0a 100644
--- a/aidl_to_ndk.cpp
+++ b/aidl_to_ndk.cpp
@@ -15,6 +15,8 @@
 #include "aidl_to_ndk.h"
 #include "aidl_language.h"
 #include "aidl_to_cpp_common.h"
+#include "aidl_typenames.h"
+#include "location.h"
 #include "logging.h"
 #include "os.h"
 
@@ -22,6 +24,11 @@
 #include <android-base/strings.h>
 
 #include <functional>
+#include <iterator>
+#include <map>
+#include <string>
+#include <variant>
+#include <vector>
 
 using ::android::base::Join;
 using ::android::base::Split;
diff --git a/aidl_to_rust.cpp b/aidl_to_rust.cpp
index f4e6bfcf..8b367a97 100644
--- a/aidl_to_rust.cpp
+++ b/aidl_to_rust.cpp
@@ -18,15 +18,18 @@
 #include "aidl_language.h"
 #include "aidl_typenames.h"
 #include "logging.h"
+#include "options.h"
 
 #include <android-base/parseint.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 
-#include <functional>
-#include <iostream>
+#include <algorithm>
+#include <cstdint>
 #include <map>
+#include <set>
 #include <string>
+#include <variant>
 #include <vector>
 
 using android::base::Join;
@@ -135,7 +138,7 @@ bool AutoConstructor(const AidlTypeSpecifier& type, const AidlTypenames& typenam
 std::string GetRustName(const AidlTypeSpecifier& type, const AidlTypenames& typenames,
                         StorageMode mode, bool is_vintf_stability) {
   // map from AIDL built-in type name to the corresponding Rust type name
-  static map<string, string> m = {
+  static std::map<std::string, std::string> m = {
       {"void", "()"},
       {"boolean", "bool"},
       {"byte", "i8"},
@@ -148,7 +151,7 @@ std::string GetRustName(const AidlTypeSpecifier& type, const AidlTypenames& type
       {"IBinder", "binder::SpIBinder"},
       {"ParcelFileDescriptor", "binder::ParcelFileDescriptor"},
   };
-  const string& type_name = type.GetName();
+  const std::string& type_name = type.GetName();
   if (m.find(type_name) != m.end()) {
     AIDL_FATAL_IF(!AidlTypenames::IsBuiltinTypename(type_name), type);
     if (type_name == "String" && mode == StorageMode::UNSIZED_ARGUMENT) {
diff --git a/aidl_typenames.cpp b/aidl_typenames.cpp
index 67da4e77..6ec319e3 100644
--- a/aidl_typenames.cpp
+++ b/aidl_typenames.cpp
@@ -16,13 +16,17 @@
 
 #include "aidl_typenames.h"
 #include "aidl_language.h"
+#include "location.h"
 #include "logging.h"
 
-#include <android-base/file.h>
 #include <android-base/strings.h>
 
+#include <algorithm>
+#include <functional>
 #include <map>
 #include <memory>
+#include <new>
+#include <optional>
 #include <set>
 #include <string>
 #include <utility>
@@ -42,32 +46,32 @@ namespace android {
 namespace aidl {
 
 // The built-in AIDL types..
-static const set<string> kBuiltinTypes = {"void",
-                                          "boolean",
-                                          "byte",
-                                          "char",
-                                          "int",
-                                          "long",
-                                          "float",
-                                          "double",
-                                          "String",
-                                          "List",
-                                          "Map",
-                                          "IBinder",
-                                          "FileDescriptor",
-                                          "CharSequence",
-                                          "ParcelFileDescriptor",
-                                          "ParcelableHolder"};
-
-static const set<string> kPrimitiveTypes = {"void", "boolean", "byte",  "char",
-                                            "int",  "long",    "float", "double"};
+static const std::set<std::string> kBuiltinTypes = {"void",
+                                                    "boolean",
+                                                    "byte",
+                                                    "char",
+                                                    "int",
+                                                    "long",
+                                                    "float",
+                                                    "double",
+                                                    "String",
+                                                    "List",
+                                                    "Map",
+                                                    "IBinder",
+                                                    "FileDescriptor",
+                                                    "CharSequence",
+                                                    "ParcelFileDescriptor",
+                                                    "ParcelableHolder"};
+
+static const std::set<std::string> kPrimitiveTypes = {"void", "boolean", "byte",  "char",
+                                                      "int",  "long",    "float", "double"};
 
 // Note: these types may look wrong because they look like Java
 // types, but they have long been supported from the time when Java
 // was the only target language of this compiler. They are added here for
 // backwards compatibility, but we internally treat them as List and Map,
 // respectively.
-static const map<string, string> kJavaLikeTypeToAidlType = {
+static const std::map<std::string, std::string> kJavaLikeTypeToAidlType = {
     {"java.util.List", "List"},
     {"java.util.Map", "Map"},
     {"android.os.ParcelFileDescriptor", "ParcelFileDescriptor"},
@@ -77,7 +81,7 @@ static const map<string, string> kJavaLikeTypeToAidlType = {
 // in Java and C++. Using these names will eventually cause compilation error,
 // so checking this here is not a must have, but early detection of errors
 // is always better.
-static const set<string> kCppOrJavaReservedWord = {
+static const std::set<std::string> kCppOrJavaReservedWord = {
     "break",  "case",   "catch", "char",     "class",  "continue", "default",
     "do",     "double", "else",  "enum",     "false",  "float",    "for",
     "goto",   "if",     "int",   "long",     "new",    "private",  "protected",
@@ -86,8 +90,8 @@ static const set<string> kCppOrJavaReservedWord = {
 
 static bool HasValidNameComponents(const AidlDefinedType& defined) {
   bool success = true;
-  vector<string> pieces = Split(defined.GetCanonicalName(), ".");
-  for (const string& piece : pieces) {
+  std::vector<std::string> pieces = Split(defined.GetCanonicalName(), ".");
+  for (const std::string& piece : pieces) {
     if (kCppOrJavaReservedWord.find(piece) != kCppOrJavaReservedWord.end()) {
       AIDL_ERROR(defined) << defined.GetCanonicalName() << " is an invalid name because '" << piece
                           << "' is a Java or C++ identifier.";
@@ -103,10 +107,10 @@ static bool HasValidNameComponents(const AidlDefinedType& defined) {
   return success;
 }
 
-bool AidlTypenames::IsIgnorableImport(const string& import) const {
+bool AidlTypenames::IsIgnorableImport(const std::string& import) const {
   if (IsBuiltinTypename(import)) return true;
 
-  static set<string> ignore_import = {
+  static std::set<std::string> ignore_import = {
       "android.os.IInterface",   "android.os.IBinder", "android.os.Parcelable", "android.os.Parcel",
       "android.content.Context", "java.lang.String",   "java.lang.CharSequence"};
   // these known built-in types don't need to be imported
@@ -192,16 +196,16 @@ const AidlDocument& AidlTypenames::MainDocument() const {
   return *(documents_[0]);
 }
 
-bool AidlTypenames::IsBuiltinTypename(const string& type_name) {
+bool AidlTypenames::IsBuiltinTypename(const std::string& type_name) {
   return kBuiltinTypes.find(type_name) != kBuiltinTypes.end() ||
       kJavaLikeTypeToAidlType.find(type_name) != kJavaLikeTypeToAidlType.end();
 }
 
-bool AidlTypenames::IsPrimitiveTypename(const string& type_name) {
+bool AidlTypenames::IsPrimitiveTypename(const std::string& type_name) {
   return kPrimitiveTypes.find(type_name) != kPrimitiveTypes.end();
 }
 
-bool AidlTypenames::IsParcelable(const string& type_name) const {
+bool AidlTypenames::IsParcelable(const std::string& type_name) const {
   if (IsBuiltinTypename(type_name)) {
     return type_name == "ParcelableHolder" || type_name == "ParcelFileDescriptor";
   }
@@ -211,7 +215,7 @@ bool AidlTypenames::IsParcelable(const string& type_name) const {
   return false;
 }
 
-const AidlDefinedType* AidlTypenames::TryGetDefinedType(const string& type_name) const {
+const AidlDefinedType* AidlTypenames::TryGetDefinedType(const std::string& type_name) const {
   auto found_def = defined_types_.find(type_name);
   if (found_def != defined_types_.end()) {
     return found_def->second;
@@ -233,7 +237,7 @@ std::vector<const AidlDefinedType*> AidlTypenames::AllDefinedTypes() const {
   return res;
 }
 
-AidlTypenames::ResolvedTypename AidlTypenames::ResolveTypename(const string& type_name) const {
+AidlTypenames::ResolvedTypename AidlTypenames::ResolveTypename(const std::string& type_name) const {
   if (IsBuiltinTypename(type_name)) {
     auto found = kJavaLikeTypeToAidlType.find(type_name);
     if (found != kJavaLikeTypeToAidlType.end()) {
@@ -250,7 +254,7 @@ AidlTypenames::ResolvedTypename AidlTypenames::ResolveTypename(const string& typ
 }
 
 std::unique_ptr<AidlTypeSpecifier> AidlTypenames::MakeResolvedType(const AidlLocation& location,
-                                                                   const string& name,
+                                                                   const std::string& name,
                                                                    bool is_array) const {
   std::optional<ArrayType> array;
   if (is_array) {
@@ -266,7 +270,7 @@ std::unique_ptr<AidlTypeSpecifier> AidlTypenames::MakeResolvedType(const AidlLoc
 // Only immutable Parcelable, primitive type, and String, and List, Map, array of the types can be
 // immutable.
 bool AidlTypenames::CanBeJavaOnlyImmutable(const AidlTypeSpecifier& type) const {
-  const string& name = type.GetName();
+  const std::string& name = type.GetName();
   if (type.IsGeneric()) {
     if (type.GetName() == "List" || type.GetName() == "Map") {
       const auto& types = type.GetTypeParameters();
@@ -296,7 +300,7 @@ bool AidlTypenames::CanBeJavaOnlyImmutable(const AidlTypeSpecifier& type) const
 // - primitive types and enum types
 // - fixed-size arrays of FixedSize types
 bool AidlTypenames::CanBeFixedSize(const AidlTypeSpecifier& type) const {
-  const string& name = type.GetName();
+  const std::string& name = type.GetName();
   if (type.IsGeneric() || type.IsNullable()) {
     return false;
   }
@@ -329,7 +333,7 @@ ArgumentAspect AidlTypenames::GetArgumentAspect(const AidlTypeSpecifier& type) c
             {AidlArgument::Direction::IN_DIR, AidlArgument::Direction::OUT_DIR,
              AidlArgument::Direction::INOUT_DIR}};
   }
-  const string& name = type.GetName();
+  const std::string& name = type.GetName();
   if (IsBuiltinTypename(name)) {
     if (name == "List" || name == "Map") {
       return {name,
diff --git a/aidl_unittest.cpp b/aidl_unittest.cpp
index 6b851697..83835d34 100644
--- a/aidl_unittest.cpp
+++ b/aidl_unittest.cpp
@@ -3924,13 +3924,11 @@ TEST_F(AidlTestIncompatibleChanges, IncompatibleChangesInNestedType) {
   EXPECT_THAT(GetCapturedStderr(), HasSubstr("Removed or changed method: p.Foo.IBar.foo()"));
 }
 
-TEST_F(AidlTestIncompatibleChanges, IncompatibleTwoWayToOneWay) {
+TEST_F(AidlTestCompatibleChanges, CompatibleTwoWayToOneWay) {
   io_delegate_.SetFileContents("old/p/IFoo.aidl", "package p; interface IFoo{ void foo();}");
   io_delegate_.SetFileContents("new/p/IFoo.aidl", "package p; interface IFoo{ oneway void foo();}");
 
-  CaptureStderr();
-  EXPECT_FALSE(::android::aidl::check_api(options_, io_delegate_));
-  EXPECT_THAT(GetCapturedStderr(), HasSubstr("Oneway attribute added: p.IFoo.foo()"));
+  EXPECT_TRUE(::android::aidl::check_api(options_, io_delegate_));
 }
 
 TEST_F(AidlTestCompatibleChanges, CompatibleOneWayToTwoWay) {
diff --git a/ast_java.cpp b/ast_java.cpp
index 7d95bd40..d5da6058 100644
--- a/ast_java.cpp
+++ b/ast_java.cpp
@@ -17,8 +17,11 @@
 #include "ast_java.h"
 #include "code_writer.h"
 
-using std::vector;
-using std::string;
+#include <cstddef>
+#include <memory>
+#include <string>
+#include <variant>
+#include <vector>
 
 template <class... Ts>
 struct overloaded : Ts... {
@@ -70,7 +73,7 @@ void WriteModifiers(CodeWriter* to, int mod, int mask) {
   }
 }
 
-void WriteArgumentList(CodeWriter* to, const vector<std::shared_ptr<Expression>>& arguments) {
+void WriteArgumentList(CodeWriter* to, const std::vector<std::shared_ptr<Expression>>& arguments) {
   size_t N = arguments.size();
   for (size_t i = 0; i < N; i++) {
     arguments[i]->Write(to);
@@ -96,19 +99,19 @@ void Field::Write(CodeWriter* to) const {
   to->Write(";\n");
 }
 
-LiteralExpression::LiteralExpression(const string& v) : value(v) {}
+LiteralExpression::LiteralExpression(const std::string& v) : value(v) {}
 
 void LiteralExpression::Write(CodeWriter* to) const {
   to->Write("%s", this->value.c_str());
 }
 
-StringLiteralExpression::StringLiteralExpression(const string& v) : value(v) {}
+StringLiteralExpression::StringLiteralExpression(const std::string& v) : value(v) {}
 
 void StringLiteralExpression::Write(CodeWriter* to) const {
   to->Write("\"%s\"", this->value.c_str());
 }
 
-Variable::Variable(const string& t, const string& n) : type(t), name(n) {}
+Variable::Variable(const std::string& t, const std::string& n) : type(t), name(n) {}
 
 void Variable::WriteDeclaration(CodeWriter* to) const {
   for (const auto& a : this->annotations) {
@@ -119,10 +122,10 @@ void Variable::WriteDeclaration(CodeWriter* to) const {
 
 void Variable::Write(CodeWriter* to) const { to->Write("%s", name.c_str()); }
 
-FieldVariable::FieldVariable(std::shared_ptr<Expression> o, const string& n)
+FieldVariable::FieldVariable(std::shared_ptr<Expression> o, const std::string& n)
     : receiver(o), name(n) {}
 
-FieldVariable::FieldVariable(const string& c, const string& n) : receiver(c), name(n) {}
+FieldVariable::FieldVariable(const std::string& c, const std::string& n) : receiver(c), name(n) {}
 
 void FieldVariable::Write(CodeWriter* to) const {
   visit(
@@ -167,7 +170,7 @@ void ExpressionStatement::Write(CodeWriter* to) const {
 Assignment::Assignment(std::shared_ptr<Variable> l, std::shared_ptr<Expression> r)
     : lvalue(l), rvalue(r) {}
 
-Assignment::Assignment(std::shared_ptr<Variable> l, std::shared_ptr<Expression> r, string c)
+Assignment::Assignment(std::shared_ptr<Variable> l, std::shared_ptr<Expression> r, std::string c)
     : lvalue(l), rvalue(r), cast(c) {}
 
 void Assignment::Write(CodeWriter* to) const {
@@ -179,20 +182,21 @@ void Assignment::Write(CodeWriter* to) const {
   this->rvalue->Write(to);
 }
 
-MethodCall::MethodCall(const string& n) : name(n) {}
+MethodCall::MethodCall(const std::string& n) : name(n) {}
 
-MethodCall::MethodCall(const string& n, const std::vector<std::shared_ptr<Expression>>& args)
+MethodCall::MethodCall(const std::string& n, const std::vector<std::shared_ptr<Expression>>& args)
     : name(n), arguments(args) {}
 
-MethodCall::MethodCall(std::shared_ptr<Expression> o, const string& n) : receiver(o), name(n) {}
+MethodCall::MethodCall(std::shared_ptr<Expression> o, const std::string& n)
+    : receiver(o), name(n) {}
 
-MethodCall::MethodCall(const std::string& t, const string& n) : receiver(t), name(n) {}
+MethodCall::MethodCall(const std::string& t, const std::string& n) : receiver(t), name(n) {}
 
-MethodCall::MethodCall(std::shared_ptr<Expression> o, const string& n,
+MethodCall::MethodCall(std::shared_ptr<Expression> o, const std::string& n,
                        const std::vector<std::shared_ptr<Expression>>& args)
     : receiver(o), name(n), arguments(args) {}
 
-MethodCall::MethodCall(const std::string& t, const string& n,
+MethodCall::MethodCall(const std::string& t, const std::string& n,
                        const std::vector<std::shared_ptr<Expression>>& args)
     : receiver(t), name(n), arguments(args) {}
 
@@ -209,7 +213,7 @@ void MethodCall::Write(CodeWriter* to) const {
   to->Write(")");
 }
 
-Comparison::Comparison(std::shared_ptr<Expression> l, const string& o,
+Comparison::Comparison(std::shared_ptr<Expression> l, const std::string& o,
                        std::shared_ptr<Expression> r)
     : lvalue(l), op(o), rvalue(r) {}
 
@@ -290,13 +294,15 @@ void FinallyStatement::Write(CodeWriter* to) const {
   this->statements->Write(to);
 }
 
-Case::Case(const string& c) { cases.push_back(c); }
+Case::Case(const std::string& c) {
+  cases.push_back(c);
+}
 
 void Case::Write(CodeWriter* to) const {
   int N = this->cases.size();
   if (N > 0) {
     for (int i = 0; i < N; i++) {
-      string s = this->cases[i];
+      std::string s = this->cases[i];
       if (s.length() != 0) {
         to->Write("case %s:\n", s.c_str());
       } else {
@@ -390,9 +396,9 @@ void Class::Write(CodeWriter* to) const {
     to->Write("interface ");
   }
 
-  string name = this->type;
+  std::string name = this->type;
   size_t pos = name.rfind('.');
-  if (pos != string::npos) {
+  if (pos != std::string::npos) {
     name = name.c_str() + pos + 1;
   }
 
diff --git a/build/aidl_api.go b/build/aidl_api.go
index 644e021a..94f39c23 100644
--- a/build/aidl_api.go
+++ b/build/aidl_api.go
@@ -15,17 +15,17 @@
 package aidl
 
 import (
-	"android/soong/aidl_library"
-	"android/soong/android"
-	"reflect"
-
 	"fmt"
 	"path/filepath"
+	"reflect"
 	"strconv"
 	"strings"
 
 	"github.com/google/blueprint"
 	"github.com/google/blueprint/proptools"
+
+	"android/soong/aidl_library"
+	"android/soong/android"
 )
 
 var (
@@ -51,7 +51,7 @@ var (
 )
 
 // Like android.OtherModuleProvider(), but will throw an error if the provider was not set
-func expectOtherModuleProvider[K any](ctx android.ModuleContext, module blueprint.Module, provider blueprint.ProviderKey[K]) K {
+func expectOtherModuleProvider[K any](ctx android.BaseModuleContext, module android.ModuleProxy, provider blueprint.ProviderKey[K]) K {
 	result, ok := android.OtherModuleProvider(ctx, module, provider)
 	if !ok {
 		var zero K
@@ -191,21 +191,19 @@ func (m *aidlInterface) migrateAndAppendVersion(
 		versions = append(versions, *version)
 	}
 	for _, v := range versions {
-		importIfaces := make(map[string]*aidlInterface)
-		ctx.VisitDirectDeps(func(dep android.Module) {
+		importIfaces := make(map[string]AidlInterfaceInfo)
+		importApis := make(map[string]aidlApiInfo)
+		ctx.VisitDirectDepsProxy(func(dep android.ModuleProxy) {
 			if _, ok := ctx.OtherModuleDependencyTag(dep).(importInterfaceDepTag); ok {
-				other := dep.(*aidlInterface)
-				importIfaces[other.BaseModuleName()] = other
+				other := expectOtherModuleProvider(ctx, dep, AidlInterfaceInfoProvider)
+				importIfaces[other.Name] = other
+				importApis[other.Name] = expectOtherModuleProvider(ctx, dep, aidlApiProvider)
 			}
 		})
 		imports := make([]string, 0, len(m.getImportsForVersion(v)))
 		needTransitiveFreeze := isFreezingApi && v == *version && transitive
 
 		if needTransitiveFreeze {
-			importApis := make(map[string]aidlApiInfo)
-			for name, intf := range importIfaces {
-				importApis[name] = expectOtherModuleProvider(ctx, intf, aidlApiProvider)
-			}
 			wrapWithDiffCheckIf(hasDevelopment, rb, func(rbc *android.RuleBuilderCommand) {
 				rbc.BuiltTool("bpmodify").
 					Text("-w -m " + m.ModuleBase.Name()).
@@ -216,7 +214,7 @@ func (m *aidlInterface) migrateAndAppendVersion(
 					moduleName, version := parseModuleWithVersion(im)
 
 					// Invoke an imported interface's freeze-api only if it depends on ToT version explicitly or implicitly.
-					if version == importIfaces[moduleName].nextVersion() || !hasVersionSuffix(im) {
+					if version == importIfaces[moduleName].NextVersion || !hasVersionSuffix(im) {
 						rb.Command().Text(fmt.Sprintf(`echo "Call %s-freeze-api because %s depends on %s."`, moduleName, m.ModuleBase.Name(), moduleName))
 						rbc.Implicit(importApis[moduleName].FreezeApiTimestamp)
 					}
@@ -225,8 +223,8 @@ func (m *aidlInterface) migrateAndAppendVersion(
 					} else {
 						rbc.Text("\"" + im + "-V'" + `$(if [ "$(cat `).
 							Input(importApis[im].HasDevelopment).
-							Text(`)" = "1" ]; then echo "` + importIfaces[im].nextVersion() +
-								`"; else echo "` + importIfaces[im].latestVersion() + `"; fi)'", `)
+							Text(`)" = "1" ]; then echo "` + importIfaces[im].NextVersion +
+								`"; else echo "` + importIfaces[im].LatestVersion + `"; fi)'", `)
 					}
 				}
 				rbc.Text("]}' ").
@@ -242,10 +240,10 @@ func (m *aidlInterface) migrateAndAppendVersion(
 				if hasVersionSuffix(im) {
 					imports = append(imports, im)
 				} else {
-					versionSuffix := importIfaces[im].latestVersion()
-					if !importIfaces[im].hasVersion() ||
-						importIfaces[im].isExplicitlyUnFrozen() {
-						versionSuffix = importIfaces[im].nextVersion()
+					versionSuffix := importIfaces[im].LatestVersion
+					if !importIfaces[im].HasVersion ||
+						importIfaces[im].ExplicitlyUnFrozen {
+						versionSuffix = importIfaces[im].NextVersion
 					}
 					imports = append(imports, im+"-V"+versionSuffix)
 				}
@@ -336,19 +334,19 @@ func getDeps(ctx android.ModuleContext, versionedImports map[string]string) deps
 	if m, ok := ctx.Module().(*aidlInterface); ok {
 		deps.imports = append(deps.imports, m.properties.Include_dirs...)
 	}
-	ctx.VisitDirectDeps(func(dep android.Module) {
+	ctx.VisitDirectDepsProxy(func(dep android.ModuleProxy) {
 		switch ctx.OtherModuleDependencyTag(dep).(type) {
 		case importInterfaceDepTag:
-			iface := dep.(*aidlInterface)
-			if version, ok := versionedImports[iface.BaseModuleName()]; ok {
-				if iface.preprocessed[version] == nil {
-					ctx.ModuleErrorf("can't import %v's preprocessed(version=%v)", iface.BaseModuleName(), version)
+			iface := expectOtherModuleProvider(ctx, dep, AidlInterfaceInfoProvider)
+			if version, ok := versionedImports[iface.Name]; ok {
+				if iface.Preprocessed[version] == nil {
+					ctx.ModuleErrorf("can't import %v's preprocessed(version=%v)", iface.Name, version)
 				}
-				deps.preprocessed = append(deps.preprocessed, iface.preprocessed[version])
+				deps.preprocessed = append(deps.preprocessed, iface.Preprocessed[version])
 			}
 		case interfaceDepTag:
-			iface := dep.(*aidlInterface)
-			deps.imports = append(deps.imports, iface.properties.Include_dirs...)
+			iface := expectOtherModuleProvider(ctx, dep, AidlInterfaceInfoProvider)
+			deps.imports = append(deps.imports, iface.IncludeDirs...)
 		case apiDepTag:
 			apiInfo := expectOtherModuleProvider(ctx, dep, aidlApiProvider)
 			// add imported module's checkapiTimestamps as implicits to make sure that imported apiDump is up-to-date
@@ -457,18 +455,18 @@ func (m *aidlInterface) checkIntegrity(ctx android.ModuleContext, dump apiDump)
 // map["foo":"3", "bar":1]
 func (m *aidlInterface) getLatestImportVersions(ctx android.ModuleContext) map[string]string {
 	var latest_versions = make(map[string]string)
-	ctx.VisitDirectDeps(func(dep android.Module) {
+	ctx.VisitDirectDepsProxy(func(dep android.ModuleProxy) {
 		switch ctx.OtherModuleDependencyTag(dep).(type) {
 		case apiDepTag:
-			intf := dep.(*aidlInterface)
-			if intf.hasVersion() {
-				if intf.properties.Frozen == nil || intf.isFrozen() {
-					latest_versions[intf.ModuleBase.Name()] = intf.latestVersion()
+			intf := expectOtherModuleProvider(ctx, dep, AidlInterfaceInfoProvider)
+			if intf.HasVersion {
+				if !intf.ExplicitlyUnFrozen {
+					latest_versions[intf.Name] = intf.LatestVersion
 				} else {
-					latest_versions[intf.ModuleBase.Name()] = intf.nextVersion()
+					latest_versions[intf.Name] = intf.NextVersion
 				}
 			} else {
-				latest_versions[intf.ModuleBase.Name()] = "1"
+				latest_versions[intf.Name] = "1"
 			}
 		}
 	})
diff --git a/build/aidl_gen_rule.go b/build/aidl_gen_rule.go
index b0c32631..5eb41562 100644
--- a/build/aidl_gen_rule.go
+++ b/build/aidl_gen_rule.go
@@ -15,16 +15,16 @@
 package aidl
 
 import (
-	"android/soong/android"
-	"android/soong/genrule"
-	"strconv"
-
 	"path/filepath"
+	"strconv"
 	"strings"
 
 	"github.com/google/blueprint"
 	"github.com/google/blueprint/pathtools"
 	"github.com/google/blueprint/proptools"
+
+	"android/soong/android"
+	"android/soong/genrule"
 )
 
 var (
@@ -78,6 +78,15 @@ var (
 	})
 )
 
+type AidlGenruleInfo struct {
+	BaseName string
+	HashFile android.Path
+	OutDir   android.Path
+	Outputs  android.Paths
+}
+
+var AidlGenruleInfoProvider = blueprint.NewProvider[AidlGenruleInfo]()
+
 type aidlGenProperties struct {
 	Srcs                []string `android:"path"`
 	AidlRoot            string   // base directory for the input aidl file
@@ -123,13 +132,16 @@ type aidlGenRule struct {
 var _ android.SourceFileProducer = (*aidlGenRule)(nil)
 var _ genrule.SourceFileGenerator = (*aidlGenRule)(nil)
 
-func (g *aidlGenRule) aidlInterface(ctx android.BaseModuleContext) *aidlInterface {
-	return ctx.GetDirectDepWithTag(g.properties.BaseName, interfaceDep).(*aidlInterface)
+func (g *aidlGenRule) aidlInterface(ctx android.BaseModuleContext) AidlInterfaceInfo {
+	return android.OtherModuleProviderOrDefault(ctx,
+		ctx.GetDirectDepProxyWithTag(g.properties.BaseName, interfaceDep),
+		AidlInterfaceInfoProvider)
 }
 
 func (g *aidlGenRule) getImports(ctx android.ModuleContext) map[string]string {
-	iface := g.aidlInterface(ctx)
-	return iface.getImports(g.properties.Version)
+	ifaceInfo := g.aidlInterface(ctx)
+
+	return ifaceInfo.getImports(g.properties.Version)
 }
 
 func (g *aidlGenRule) GenerateAndroidBuildActions(ctx android.ModuleContext) {
@@ -173,6 +185,13 @@ func (g *aidlGenRule) GenerateAndroidBuildActions(ctx android.ModuleContext) {
 		Output: android.PathForModuleOut(ctx, "timestamp"), // $out/timestamp
 		Inputs: g.genOutputs.Paths(),
 	})
+
+	android.SetProvider(ctx, AidlGenruleInfoProvider, AidlGenruleInfo{
+		BaseName: g.properties.BaseName,
+		HashFile: g.hashFile,
+		OutDir:   g.genOutDir,
+		Outputs:  g.genOutputs.Paths(),
+	})
 }
 
 func (g *aidlGenRule) generateBuildActionsForSingleAidl(ctx android.ModuleContext, src android.Path) (android.WritablePath, android.Paths) {
diff --git a/build/aidl_interface.go b/build/aidl_interface.go
index 14ac3fb2..350a4943 100644
--- a/build/aidl_interface.go
+++ b/build/aidl_interface.go
@@ -15,20 +15,21 @@
 package aidl
 
 import (
-	"android/soong/android"
-	"android/soong/cc"
-	"android/soong/java"
-	"android/soong/rust"
-
 	"fmt"
 	"path/filepath"
 	"regexp"
+	"slices"
 	"sort"
 	"strconv"
 	"strings"
 
 	"github.com/google/blueprint"
 	"github.com/google/blueprint/proptools"
+
+	"android/soong/android"
+	"android/soong/cc"
+	"android/soong/java"
+	"android/soong/rust"
 )
 
 const (
@@ -180,7 +181,7 @@ func checkAidlGeneratedModules(mctx android.BottomUpMutatorContext) {
 	}
 	// Collect/merge AidlVersionInfos from direct dependencies
 	var info AidlVersionInfo
-	mctx.VisitDirectDeps(func(dep android.Module) {
+	mctx.VisitDirectDepsProxy(func(dep android.ModuleProxy) {
 		if otherInfo, ok := android.OtherModuleProvider(mctx, dep, AidlVersionInfoProvider); ok {
 			if violators := info.merge(otherInfo); violators != nil {
 				reportMultipleVersionError(mctx, violators)
@@ -236,6 +237,88 @@ func isRelativePath(path string) bool {
 		!strings.HasPrefix(path, "../") && !strings.HasPrefix(path, "/")
 }
 
+type AidlInterfaceInfo struct {
+	AidlInterfaceImportsInfo
+	Stability     string
+	ComputedTypes []string
+	UseUnfrozen   bool
+	Preprocessed  map[string]android.WritablePath
+	IncludeDirs   []string
+}
+
+var AidlInterfaceInfoProvider = blueprint.NewProvider[AidlInterfaceInfo]()
+
+type AidlInterfaceImportsInfo struct {
+	Name                      string
+	Imports                   map[string][]string
+	Unstable                  bool
+	Versions                  []string
+	LatestVersion             string
+	NextVersion               string
+	HasVersion                bool
+	Frozen                    bool
+	ExplicitlyUnFrozen        bool
+	ShouldGenerateCppBackend  bool
+	ShouldGenerateJavaBackend bool
+	ShouldGenerateNdkBackend  bool
+	ShouldGenerateRustBackend bool
+	Owner                     string
+}
+
+var AidlInterfaceImportsInfoProvider = blueprint.NewMutatorProvider[AidlInterfaceImportsInfo]("addLanguagelibraries")
+
+func (i *AidlInterfaceImportsInfo) getImports(version string) map[string]string {
+	imports := make(map[string]string)
+	importsSrc := i.Imports[""]
+	if srcs, ok := i.Imports[version]; ok {
+		importsSrc = srcs
+	}
+
+	useLatestStable := !i.Unstable && version != "" && version != i.NextVersion
+	for _, importString := range importsSrc {
+		name, targetVersion := parseModuleWithVersion(importString)
+		if targetVersion == "" && useLatestStable {
+			targetVersion = "latest"
+		}
+		imports[name] = targetVersion
+	}
+	return imports
+}
+
+// importing aidl_interface's version  | imported aidl_interface | imported aidl_interface's version
+// --------------------------------------------------------------------------------------------------
+// whatever                            | unstable                | unstable version
+// ToT version(including unstable)     | whatever                | ToT version(unstable if unstable)
+// otherwise                           | whatever                | the latest stable version
+// In the case that import specifies the version which it wants to use, use that version.
+func (i *AidlInterfaceImportsInfo) getImportWithVersion(version string, anImport string, other AidlInterfaceImportsInfo) string {
+	if hasVersionSuffix(anImport) {
+		return anImport
+	}
+	if other.Unstable {
+		return anImport
+	}
+	if version == i.NextVersion || !other.HasVersion {
+		return other.versionedName(other.NextVersion)
+	}
+	return other.versionedName(other.LatestVersion)
+}
+
+// This function returns module name with version. Assume that there is foo of which latest version is 2
+// Version -> Module name
+// "1"->foo-V1
+// "2"->foo-V2
+// "3"->foo-V3
+// And assume that there is 'bar' which is an 'unstable' interface.
+// ""->bar
+func (i *AidlInterfaceImportsInfo) versionedName(version string) string {
+	name := i.Name
+	if version == "" {
+		return name
+	}
+	return name + "-V" + version
+}
+
 type CommonBackendProperties struct {
 	// Whether to generate code in the corresponding backend.
 	// Default:
@@ -686,7 +769,7 @@ func addInterfaceDeps(mctx android.BottomUpMutatorContext) {
 
 // Add libraries to the static_libs/shared_libs properties of language specific modules.
 // The libraries to add are determined based off of the aidl interface that the language module
-// was generated by, and the imported aidl interfaces of the origional aidl interface. Thus,
+// was generated by, and the imported aidl interfaces of the original aidl interface. Thus,
 // this needs to run after addInterfaceDeps() so that it can get information from all those
 // interfaces.
 func addLanguageLibraries(mctx android.BottomUpMutatorContext) {
@@ -720,6 +803,8 @@ func addLanguageLibraries(mctx android.BottomUpMutatorContext) {
 				break
 			}
 		}
+	case *aidlInterface:
+		i.setImportsProvider(mctx)
 	}
 }
 
@@ -731,23 +816,23 @@ func addLanguageLibraries(mctx android.BottomUpMutatorContext) {
 // clear that backend.java.enabled should be turned on.
 func checkImports(mctx android.BottomUpMutatorContext) {
 	if i, ok := mctx.Module().(*aidlInterface); ok {
-		mctx.VisitDirectDeps(func(dep android.Module) {
+		mctx.VisitDirectDepsProxy(func(dep android.ModuleProxy) {
 			tag, ok := mctx.OtherModuleDependencyTag(dep).(importInterfaceDepTag)
 			if !ok {
 				return
 			}
-			other := dep.(*aidlInterface)
-			anImport := other.ModuleBase.Name()
+			ifaceInfo := expectOtherModuleProvider(mctx, dep, AidlInterfaceImportsInfoProvider)
+			anImport := ifaceInfo.Name
 			anImportWithVersion := tag.anImport
 			_, version := parseModuleWithVersion(tag.anImport)
 
-			candidateVersions := other.getVersions()
-			if !proptools.Bool(other.properties.Frozen) {
-				candidateVersions = concat(candidateVersions, []string{other.nextVersion()})
+			candidateVersions := ifaceInfo.Versions
+			if !ifaceInfo.Frozen {
+				candidateVersions = concat(candidateVersions, []string{ifaceInfo.NextVersion})
 			}
 
 			if version == "" {
-				if !proptools.Bool(other.properties.Unstable) {
+				if !ifaceInfo.Unstable {
 					mctx.PropertyErrorf("imports", "%q depends on %q but does not specify a version (must be one of %q)", i.ModuleBase.Name(), anImport, candidateVersions)
 				}
 			} else {
@@ -755,35 +840,35 @@ func checkImports(mctx android.BottomUpMutatorContext) {
 					mctx.PropertyErrorf("imports", "%q depends on %q version %q(%q), which doesn't exist. The version must be one of %q", i.ModuleBase.Name(), anImport, version, anImportWithVersion, candidateVersions)
 				}
 			}
-			if i.shouldGenerateJavaBackend() && !other.shouldGenerateJavaBackend() {
+			if i.shouldGenerateJavaBackend() && !ifaceInfo.ShouldGenerateJavaBackend {
 				mctx.PropertyErrorf("backend.java.enabled",
 					"Java backend not enabled in the imported AIDL interface %q", anImport)
 			}
 
-			if i.shouldGenerateCppBackend() && !other.shouldGenerateCppBackend() {
+			if i.shouldGenerateCppBackend() && !ifaceInfo.ShouldGenerateCppBackend {
 				mctx.PropertyErrorf("backend.cpp.enabled",
 					"C++ backend not enabled in the imported AIDL interface %q", anImport)
 			}
 
-			if i.shouldGenerateNdkBackend() && !other.shouldGenerateNdkBackend() {
+			if i.shouldGenerateNdkBackend() && !ifaceInfo.ShouldGenerateNdkBackend {
 				mctx.PropertyErrorf("backend.ndk.enabled",
 					"NDK backend not enabled in the imported AIDL interface %q", anImport)
 			}
 
-			if i.shouldGenerateRustBackend() && !other.shouldGenerateRustBackend() {
+			if i.shouldGenerateRustBackend() && !ifaceInfo.ShouldGenerateRustBackend {
 				mctx.PropertyErrorf("backend.rust.enabled",
 					"Rust backend not enabled in the imported AIDL interface %q", anImport)
 			}
 
-			if i.isFrozen() && other.isExplicitlyUnFrozen() && version == "" {
+			if i.isFrozen() && ifaceInfo.ExplicitlyUnFrozen && version == "" {
 				mctx.PropertyErrorf("frozen",
 					"%q imports %q which is not frozen. Either %q must set 'frozen: false' or must explicitly import %q where * is one of %q",
 					i.ModuleBase.Name(), anImport, i.ModuleBase.Name(), anImport+"-V*", candidateVersions)
 			}
-			if i.Owner() == "" && other.Owner() != "" {
+			if i.Owner() == "" && ifaceInfo.Owner != "" {
 				mctx.PropertyErrorf("imports",
 					"%q imports %q which is an interface owned by %q. This is not allowed because the owned interface will not be frozen at the same time.",
-					i.ModuleBase.Name(), anImport, other.Owner())
+					i.ModuleBase.Name(), anImport, ifaceInfo.Owner)
 			}
 		})
 	}
@@ -1116,6 +1201,42 @@ func (i *aidlInterface) GenerateAndroidBuildActions(ctx android.ModuleContext) {
 		}
 		i.preprocessed[""] = i.preprocessed[i.nextVersion()]
 	}
+
+	importsInfo, _ := android.ModuleProvider(ctx, AidlInterfaceImportsInfoProvider)
+
+	android.SetProvider(ctx, AidlInterfaceInfoProvider, AidlInterfaceInfo{
+		AidlInterfaceImportsInfo: importsInfo,
+		Stability:                proptools.StringDefault(i.properties.Stability, ""),
+		ComputedTypes:            i.computedTypes,
+		UseUnfrozen:              i.useUnfrozen(ctx),
+		Preprocessed:             i.preprocessed,
+		IncludeDirs:              i.properties.Include_dirs,
+	})
+}
+
+func (i *aidlInterface) setImportsProvider(mctx android.BottomUpMutatorContext) {
+	imports := make(map[string][]string, len(i.properties.Versions_with_info)+1)
+	imports[""] = slices.Clone(i.properties.Imports)
+	for _, v := range i.properties.Versions_with_info {
+		imports[v.Version] = slices.Clone(v.Imports)
+	}
+
+	android.SetProvider(mctx, AidlInterfaceImportsInfoProvider, AidlInterfaceImportsInfo{
+		Name:                      i.ModuleBase.Name(),
+		Versions:                  i.getVersions(),
+		NextVersion:               i.nextVersion(),
+		LatestVersion:             i.latestVersion(),
+		HasVersion:                i.hasVersion(),
+		Unstable:                  proptools.Bool(i.properties.Unstable),
+		Frozen:                    proptools.Bool(i.properties.Frozen),
+		ExplicitlyUnFrozen:        i.isExplicitlyUnFrozen(),
+		ShouldGenerateCppBackend:  i.shouldGenerateCppBackend(),
+		ShouldGenerateJavaBackend: i.shouldGenerateJavaBackend(),
+		ShouldGenerateNdkBackend:  i.shouldGenerateNdkBackend(),
+		ShouldGenerateRustBackend: i.shouldGenerateRustBackend(),
+		Owner:                     i.Owner(),
+		Imports:                   imports,
+	})
 }
 
 func (i *aidlInterface) getImportsForVersion(version string) []string {
diff --git a/build/aidl_interface_backends.go b/build/aidl_interface_backends.go
index aade8208..a3f862d8 100644
--- a/build/aidl_interface_backends.go
+++ b/build/aidl_interface_backends.go
@@ -15,16 +15,16 @@
 package aidl
 
 import (
-	"android/soong/android"
-	"android/soong/cc"
-	"android/soong/java"
-	"android/soong/rust"
-
 	"fmt"
 	"path/filepath"
 	"strings"
 
 	"github.com/google/blueprint/proptools"
+
+	"android/soong/android"
+	"android/soong/cc"
+	"android/soong/java"
+	"android/soong/rust"
 )
 
 func addLibrary(mctx android.DefaultableHookContext, i *aidlInterface, version string, lang string, notFrozen bool, requireFrozenReason string) string {
@@ -391,15 +391,16 @@ func addRustLibrary(mctx android.DefaultableHookContext, i *aidlInterface, versi
 			"darwin": proptools.BoolPtr(false),
 			"":       nil,
 		}),
-		Crate_name:        rustCrateName,
-		Stem:              proptools.StringPtr("lib" + versionedRustName),
-		Defaults:          []string{"aidl-rust-module-defaults"},
-		Host_supported:    i.properties.Host_supported,
-		Vendor_available:  i.properties.Vendor_available,
-		Product_available: i.properties.Product_available,
-		Apex_available:    i.properties.Backend.Rust.Apex_available,
-		Min_sdk_version:   i.minSdkVersion(langRust),
-		Rustlibs:          i.properties.Backend.Rust.Additional_rustlibs,
+		Crate_name:         rustCrateName,
+		Stem:               proptools.StringPtr("lib" + versionedRustName),
+		Defaults:           []string{"aidl-rust-module-defaults"},
+		Host_supported:     i.properties.Host_supported,
+		Vendor_available:   i.properties.Vendor_available,
+		Product_available:  i.properties.Product_available,
+		Recovery_available: i.properties.Recovery_available,
+		Apex_available:     i.properties.Backend.Rust.Apex_available,
+		Min_sdk_version:    i.minSdkVersion(langRust),
+		Rustlibs:           i.properties.Backend.Rust.Additional_rustlibs,
 	}, &rust.SourceProviderProperties{
 		Source_stem: proptools.StringPtr(versionedRustName),
 	}, &aidlRustSourceProviderProperties{
@@ -464,38 +465,20 @@ func (i *aidlInterface) flagsForAidlGenRule(version string) (flags []string) {
 	return
 }
 
-// importing aidl_interface's version  | imported aidl_interface | imported aidl_interface's version
-// --------------------------------------------------------------------------------------------------
-// whatever                            | unstable                | unstable version
-// ToT version(including unstable)     | whatever                | ToT version(unstable if unstable)
-// otherwise                           | whatever                | the latest stable version
-// In the case that import specifies the version which it wants to use, use that version.
-func (i *aidlInterface) getImportWithVersion(version string, anImport string, other *aidlInterface) string {
-	if hasVersionSuffix(anImport) {
-		return anImport
-	}
-	if proptools.Bool(other.properties.Unstable) {
-		return anImport
-	}
-	if version == i.nextVersion() || !other.hasVersion() {
-		return other.versionedName(other.nextVersion())
-	}
-	return other.versionedName(other.latestVersion())
-}
-
 // Assuming that the context module has deps to its original aidl_interface and imported
 // aidl_interface modules with interfaceDepTag and importInterfaceDepTag, returns the list of
 // imported interfaces with versions.
 func getImportsWithVersion(ctx android.BaseModuleContext, interfaceName, version string) []string {
-	// We're using VisitDirectDepsWithTag instead of GetDirectDepWithTag because GetDirectDepWithTag
+	// We're using VisitDirectDepsProxyWithTag instead of GetDirectDepProxyWithTag because GetDirectDepProxyWithTag
 	// has weird behavior: if you're using a ModuleContext, it will find a dep based off the
 	// ModuleBase name, but if you're using a BaseModuleContext, it will find a dep based off of
 	// the outer module's name. We need the behavior to be consistent because we call this method
 	// with both types of contexts.
-	var i *aidlInterface
-	ctx.VisitDirectDepsWithTag(interfaceDep, func(visited android.Module) {
+	var i *AidlInterfaceImportsInfo
+	ctx.VisitDirectDepsProxyWithTag(interfaceDep, func(visited android.ModuleProxy) {
 		if i == nil && visited.Name() == interfaceName+aidlInterfaceSuffix {
-			i = visited.(*aidlInterface)
+			iface := expectOtherModuleProvider(ctx, visited, AidlInterfaceImportsInfoProvider)
+			i = &iface
 		}
 	})
 	if i == nil {
@@ -503,9 +486,9 @@ func getImportsWithVersion(ctx android.BaseModuleContext, interfaceName, version
 		return nil
 	}
 	var imports []string
-	ctx.VisitDirectDeps(func(dep android.Module) {
+	ctx.VisitDirectDepsProxy(func(dep android.ModuleProxy) {
 		if tag, ok := ctx.OtherModuleDependencyTag(dep).(importInterfaceDepTag); ok {
-			other := dep.(*aidlInterface)
+			other := expectOtherModuleProvider(ctx, dep, AidlInterfaceImportsInfoProvider)
 			imports = append(imports, i.getImportWithVersion(version, tag.anImport, other))
 		}
 	})
diff --git a/build/aidl_interface_metadata_singleton.go b/build/aidl_interface_metadata_singleton.go
index 4ba10378..f1fa8789 100644
--- a/build/aidl_interface_metadata_singleton.go
+++ b/build/aidl_interface_metadata_singleton.go
@@ -15,12 +15,11 @@
 package aidl
 
 import (
-	"android/soong/android"
-
 	"strings"
 
 	"github.com/google/blueprint"
-	"github.com/google/blueprint/proptools"
+
+	"android/soong/android"
 )
 
 var (
@@ -86,27 +85,26 @@ func (m *aidlInterfacesMetadataSingleton) GenerateAndroidBuildActions(ctx androi
 
 	// name -> ModuleInfo
 	moduleInfos := map[string]ModuleInfo{}
-	ctx.VisitDirectDeps(func(m android.Module) {
-		if !m.ExportedToMake() {
+	ctx.VisitDirectDepsProxy(func(m android.ModuleProxy) {
+		if info := android.OtherModulePointerProviderOrDefault(ctx, m, android.CommonModuleInfoProvider); !info.ExportedToMake {
 			return
 		}
 
-		switch t := m.(type) {
-		case *aidlInterface:
-			apiInfo := expectOtherModuleProvider(ctx, t, aidlApiProvider)
-			info := moduleInfos[t.ModuleBase.Name()]
-			info.Stability = proptools.StringDefault(t.properties.Stability, "")
-			info.ComputedTypes = t.computedTypes
-			info.Versions = t.getVersions()
-			info.UseUnfrozen = t.useUnfrozen(ctx)
+		if ifaceInfo, ok := android.OtherModuleProvider(ctx, m, AidlInterfaceInfoProvider); ok {
+			apiInfo := expectOtherModuleProvider(ctx, m, aidlApiProvider)
+			info := moduleInfos[ifaceInfo.Name]
+			info.Stability = ifaceInfo.Stability
+			info.ComputedTypes = ifaceInfo.ComputedTypes
+			info.Versions = ifaceInfo.Versions
+			info.UseUnfrozen = ifaceInfo.UseUnfrozen
 			info.HasDevelopment = apiInfo.HasDevelopment
-			moduleInfos[t.ModuleBase.Name()] = info
-		case *aidlGenRule:
-			info := moduleInfos[t.properties.BaseName]
-			if t.hashFile != nil {
-				info.HashFiles = append(info.HashFiles, t.hashFile.String())
+			moduleInfos[ifaceInfo.Name] = info
+		} else if genruleInfo, ok := android.OtherModuleProvider(ctx, m, AidlGenruleInfoProvider); ok {
+			info := moduleInfos[genruleInfo.BaseName]
+			if genruleInfo.HashFile != nil {
+				info.HashFiles = append(info.HashFiles, genruleInfo.HashFile.String())
 			}
-			moduleInfos[t.properties.BaseName] = info
+			moduleInfos[genruleInfo.BaseName] = info
 		}
 	})
 
diff --git a/build/aidl_rust_source_provider.go b/build/aidl_rust_source_provider.go
index d0f10176..3d057b86 100644
--- a/build/aidl_rust_source_provider.go
+++ b/build/aidl_rust_source_provider.go
@@ -52,10 +52,11 @@ func (sp *aidlRustSourceProvider) GenerateSource(ctx rust.ModuleContext, _ rust.
 	sourceStem := proptools.String(sp.BaseSourceProvider.Properties.Source_stem)
 	topLevelOutputFile := android.PathForModuleOut(ctx, sourceStem+".rs")
 
-	aidlGenModule := ctx.GetDirectDepWithTag(sp.properties.SourceGen, aidlRustSourceTag)
+	aidlGenModule := ctx.GetDirectDepProxyWithTag(sp.properties.SourceGen, aidlRustSourceTag)
 	// Find the gen directory for the source module
-	srcGenDir := aidlGenModule.(*aidlGenRule).genOutDir
-	srcPaths := aidlGenModule.(*aidlGenRule).genOutputs.Paths()
+	genruleInfo := expectOtherModuleProvider(ctx, aidlGenModule, AidlGenruleInfoProvider)
+	srcGenDir := genruleInfo.OutDir
+	srcPaths := genruleInfo.Outputs
 
 	// In Rust, we import our dependency crates into `mangled`:
 	//   use dependency::mangled::*;
diff --git a/build/aidl_test.go b/build/aidl_test.go
index e6b5c459..864b18c4 100644
--- a/build/aidl_test.go
+++ b/build/aidl_test.go
@@ -21,7 +21,6 @@ import (
 	"strings"
 	"testing"
 
-	"github.com/google/blueprint"
 	"github.com/google/blueprint/proptools"
 
 	"android/soong/aidl_library"
@@ -153,11 +152,13 @@ func _testAidl(t *testing.T, bp string, customizers ...android.FixturePreparer)
 		rust_library {
 			name: "libbinder_rs",
 			crate_name: "binder",
+			recovery_available: true,
 			srcs: [""],
 		}
 		rust_library {
 			name: "libstatic_assertions",
 			crate_name: "static_assertions",
+			recovery_available: true,
 			srcs: [""],
 		}
 		rust_proc_macro {
@@ -228,7 +229,7 @@ func assertModulesExists(t *testing.T, ctx *android.TestContext, names ...string
 	if len(missing) > 0 {
 		// find all the modules that do exist
 		allModuleNames := make(map[string]bool)
-		ctx.VisitAllModules(func(m blueprint.Module) {
+		ctx.VisitAllModules(func(m android.Module) {
 			allModuleNames[ctx.ModuleName(m)] = true
 		})
 		t.Errorf("expected modules(%v) not found. all modules: %v", missing, android.SortedKeys(allModuleNames))
@@ -1477,6 +1478,7 @@ func TestRecoveryAvailable(t *testing.T) {
 	`)
 	ctx.ModuleForTests(t, "myiface-V1-ndk", "android_recovery_arm64_armv8-a_shared")
 	ctx.ModuleForTests(t, "myiface-V1-cpp", "android_recovery_arm64_armv8-a_shared")
+	ctx.ModuleForTests(t, "myiface-V1-rust", "android_recovery_arm64_armv8-a_dylib")
 }
 
 func TestRustDuplicateNames(t *testing.T) {
@@ -1975,9 +1977,9 @@ func TestUseVersionedPreprocessedWhenImporotedWithVersions(t *testing.T) {
 func FindModule(t *testing.T, ctx *android.TestContext, name, variant, dir string) android.Module {
 	t.Helper()
 	var module android.Module
-	ctx.VisitAllModules(func(m blueprint.Module) {
+	ctx.VisitAllModules(func(m android.Module) {
 		if ctx.ModuleName(m) == name && ctx.ModuleSubDir(m) == variant && ctx.ModuleDir(m) == dir {
-			module = m.(android.Module)
+			module = m
 		}
 	})
 	if module == nil {
diff --git a/build/go.mod b/build/go.mod
index accec4a2..1bbdedf3 100644
--- a/build/go.mod
+++ b/build/go.mod
@@ -1,8 +1,3 @@
 module android/soong/aidl
 
 go 1.22
-
-require (
-	android/soong v0.0.0
-	github.com/google/blueprint v0.0.0
-)
diff --git a/build/go.work b/build/go.work
deleted file mode 100644
index 3d6211f9..00000000
--- a/build/go.work
+++ /dev/null
@@ -1,14 +0,0 @@
-go 1.22
-
-use (
-	.
-	../../../../build/soong
-	../../../../build/blueprint
-	../../../../external/golang-protobuf
-)
-
-replace (
-	github.com/golang/protobuf v0.0.0 => ../../../../external/golang-protobuf
-	github.com/google/blueprint v0.0.0 => ../../../../build/blueprint
-    android/soong v0.0.0 => ../../../../build/sooong
-)
diff --git a/build/properties.go b/build/properties.go
index 5a09b2bc..17aa65cf 100644
--- a/build/properties.go
+++ b/build/properties.go
@@ -95,19 +95,20 @@ type javaProperties struct {
 }
 
 type rustProperties struct {
-	Name              *string
-	Enabled           proptools.Configurable[bool]
-	Crate_name        string
-	Owner             *string
-	Defaults          []string
-	Host_supported    *bool
-	Vendor_available  *bool
-	Product_available *bool
-	Srcs              []string
-	Rustlibs          []string
-	Stem              *string
-	Apex_available    []string
-	Min_sdk_version   *string
+	Name               *string
+	Enabled            proptools.Configurable[bool]
+	Crate_name         string
+	Owner              *string
+	Defaults           []string
+	Host_supported     *bool
+	Vendor_available   *bool
+	Product_available  *bool
+	Recovery_available *bool
+	Srcs               []string
+	Rustlibs           []string
+	Stem               *string
+	Apex_available     []string
+	Min_sdk_version    *string
 }
 
 type phonyProperties struct {
diff --git a/check_valid.cpp b/check_valid.cpp
index b572d7d4..1ad05815 100644
--- a/check_valid.cpp
+++ b/check_valid.cpp
@@ -15,8 +15,13 @@
  */
 
 #include "check_valid.h"
-#include "aidl.h"
+#include "aidl_language.h"
+#include "logging.h"
+#include "options.h"
 
+#include <functional>
+#include <set>
+#include <utility>
 #include <vector>
 
 namespace android {
diff --git a/code_writer.cpp b/code_writer.cpp
index 8153b7ae..456c07fa 100644
--- a/code_writer.cpp
+++ b/code_writer.cpp
@@ -18,6 +18,11 @@
 #include "logging.h"
 
 #include <android-base/strings.h>
+#include <cstddef>
+#include <memory>
+#include <new>
+#include <string>
+#include <utility>
 
 #include <stdarg.h>
 #include <fstream>
diff --git a/codelab/README.md b/codelab/README.md
index 9100105e..e67eb46c 100644
--- a/codelab/README.md
+++ b/codelab/README.md
@@ -64,7 +64,7 @@ Note: go/android.bp has all of the available Soong modules and their supported
 fields.
 
 ```soong
-// File: `codelab/aidl/Android.bp`
+// File: `system/tools/aidl/codelab/aidl/Android.bp`
 aidl_interface {
   // Package name for the interface. This is used when generating the libraries
   // that the services and clients will depend on.
@@ -96,7 +96,7 @@ aidl_interface {
 Create your first AIDL file.
 
 ```java
-// File: `codelab/aidl/hello/world/IHello.aidl`
+// File: `system/tools/aidl/codelab/aidl/hello/world/IHello.aidl`
 // The package name is recommended to match the `name` in the `aidl_interface`
 package hello.world;
 
@@ -129,23 +129,23 @@ create the library that implements the interface first.
 Create a separate library for the interface implementation so it can be used
 for the service and for the fuzzer.
 
-* See [codelab/service/Android.bp](codelab/service/Android.bp)
+* See [service/Android.bp](service/Android.bp)
 
-* See [codelab/service/hello_service.rs](codelab/service/hello_service.rs)
+* See [service/hello_service.rs](service/hello_service.rs)
 
 #### Service binary
 
 Create the service that registers itself with servicemanager and joins the
 binder threadpool.
 
-* See [codelab/service/Android.bp](codelab/service/Android.bp)
+* See [service/Android.bp](service/Android.bp)
 
-* See [codelab/service/service_main.rs](codelab/service/service_main.rs)
+* See [service/service_main.rs](service/service_main.rs)
 
 An init.rc file is required for the process to be started on a device.
 
 * See
-  [codelab/service/hello-world-service-test.rc](codelab/service/hello-world-service-test.rc)
+  [service/hello-world-service-test.rc](service/hello-world-service-test.rc)
 
 #### Sepolicy for the service
 
@@ -191,9 +191,9 @@ hello.world.IHello/default u:object_r:hello_service:s0
 
 Create the fuzzer and use `fuzz_service` to do all of the hard work!
 
-* See [codelab/service/Android.bp](codelab/service/Android.bp)
+* See [service/Android.bp](service/Android.bp)
 
-* See [codelab/service/service_fuzzer.rs](codelab/service/service_fuzzer.rs)
+* See [service/service_fuzzer.rs](service/service_fuzzer.rs)
 
 Associate the fuzzer with the interface by adding the following to
 `system/sepolicy/build/soong/service_fuzzer_bindings.go`:
diff --git a/comments.cpp b/comments.cpp
index f576013f..60bdb0ee 100644
--- a/comments.cpp
+++ b/comments.cpp
@@ -18,11 +18,17 @@
 #include <android-base/result.h>
 #include <android-base/strings.h>
 
+#include <cctype>
+#include <cstddef>
+#include <iterator>
 #include <optional>
 #include <regex>
+#include <sstream>
 #include <string>
+#include <string_view>
 #include <vector>
 
+#include "location.h"
 #include "logging.h"
 
 using android::base::EndsWith;
diff --git a/diagnostics.cpp b/diagnostics.cpp
index 4f004b0c..80b78d60 100644
--- a/diagnostics.cpp
+++ b/diagnostics.cpp
@@ -15,12 +15,23 @@
  */
 #include "diagnostics.h"
 
+#include <algorithm>
+#include <cctype>
+#include <cstddef>
 #include <functional>
+#include <map>
+#include <memory>
+#include <set>
 #include <stack>
+#include <string>
+#include <utility>
+#include <vector>
 
 #include "aidl_language.h"
 #include "logging.h"
 
+#include <android-base/strings.h>
+
 using std::placeholders::_1;
 
 namespace android {
diff --git a/generate_aidl_mappings.cpp b/generate_aidl_mappings.cpp
index 4d2a5a03..8acd85cc 100644
--- a/generate_aidl_mappings.cpp
+++ b/generate_aidl_mappings.cpp
@@ -15,9 +15,11 @@
  */
 
 #include "generate_aidl_mappings.h"
+#include "aidl_language.h"
 #include "aidl_to_java.h"
 
 #include <sstream>
+#include <string>
 
 namespace android {
 namespace aidl {
diff --git a/generate_cpp.cpp b/generate_cpp.cpp
index ac004c6a..f60839e6 100644
--- a/generate_cpp.cpp
+++ b/generate_cpp.cpp
@@ -22,8 +22,10 @@
 #include <cstring>
 #include <format>
 #include <memory>
+#include <new>
 #include <set>
 #include <string>
+#include <vector>
 
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
@@ -31,9 +33,13 @@
 #include "aidl_language.h"
 #include "aidl_to_common.h"
 #include "aidl_to_cpp.h"
+#include "aidl_to_cpp_common.h"
 
 #include "aidl_typenames.h"
+#include "code_writer.h"
+#include "io_delegate.h"
 #include "logging.h"
+#include "options.h"
 
 using android::base::Join;
 using android::base::StringPrintf;
@@ -91,9 +97,9 @@ void GenerateGotoErrorOnBadStatus(CodeWriter& out) {
 //  for_declaration & !type_name_only: int a      // for method decl with type and arg
 //  for_declaration &  type_name_only: int /*a*/  // for method decl with type
 // !for_declaration                  :     a      // for method call with arg (with direction)
-string GenerateArgList(const AidlTypenames& typenames, const AidlMethod& method,
-                       bool for_declaration, bool type_name_only) {
-  vector<string> method_arguments;
+std::string GenerateArgList(const AidlTypenames& typenames, const AidlMethod& method,
+                            bool for_declaration, bool type_name_only) {
+  std::vector<std::string> method_arguments;
   for (const unique_ptr<AidlArgument>& a : method.GetArguments()) {
     string literal;
     // b/144943748: CppNameOf FileDescriptor is unique_fd. Don't pass it by
@@ -1277,7 +1283,8 @@ void GenerateParcelClassDecl(CodeWriter& out, const ParcelableType& parcel,
 
   const string canonical_name = parcel.GetCanonicalName();
   out << "static const ::android::String16& getParcelableDescriptor() {\n"
-      << "  static const ::android::StaticString16 DESCRIPTOR (u\"" << canonical_name << "\");\n"
+      << "  [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u\""
+      << canonical_name << "\");\n"
       << "  return DESCRIPTOR;\n"
       << "}\n";
 
diff --git a/generate_cpp_analyzer.cpp b/generate_cpp_analyzer.cpp
index 23c0ae64..d547c8bb 100644
--- a/generate_cpp_analyzer.cpp
+++ b/generate_cpp_analyzer.cpp
@@ -16,13 +16,18 @@
 
 #include "generate_cpp_analyzer.h"
 
-#include <string>
-#include "aidl.h"
 #include "aidl_language.h"
 #include "aidl_to_common.h"
 #include "aidl_to_cpp.h"
+#include "aidl_to_cpp_common.h"
+#include "aidl_typenames.h"
 #include "code_writer.h"
+#include "io_delegate.h"
 #include "logging.h"
+#include "options.h"
+
+#include <string>
+#include <vector>
 
 using std::string;
 using std::unique_ptr;
diff --git a/generate_java.cpp b/generate_java.cpp
index 2a5cd423..a90588b8 100644
--- a/generate_java.cpp
+++ b/generate_java.cpp
@@ -22,17 +22,30 @@
 
 #include <algorithm>
 #include <format>
+#include <iostream>
+#include <iterator>
 #include <map>
 #include <memory>
 #include <optional>
+#include <set>
 #include <sstream>
+#include <string>
+#include <vector>
 
-#include <android-base/stringprintf.h>
+#include <android-base/strings.h>
 
+#include "aidl_language.h"
 #include "aidl_to_common.h"
 #include "aidl_to_java.h"
+#include "aidl_typenames.h"
+#include "ast_java.h"
 #include "code_writer.h"
+#include "comments.h"
+#include "io_delegate.h"
+#include "location.h"
 #include "logging.h"
+#include "options.h"
+#include "permission.h"
 
 using ::android::base::EndsWith;
 using ::android::base::Join;
diff --git a/generate_java_binder.cpp b/generate_java_binder.cpp
index 47044e39..5b37d219 100644
--- a/generate_java_binder.cpp
+++ b/generate_java_binder.cpp
@@ -22,17 +22,23 @@
 #include "ast_java.h"
 #include "code_writer.h"
 #include "generate_java.h"
+#include "location.h"
 #include "logging.h"
 #include "options.h"
-#include "parser.h"
+#include "permission.h"
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 #include <algorithm>
+#include <cstdint>
+#include <memory>
+#include <set>
+#include <sstream>
+#include <string>
 #include <unordered_set>
-#include <utility>
+#include <variant>
 #include <vector>
 
 #include <android-base/stringprintf.h>
@@ -312,7 +318,7 @@ void StubClass::MakeConstructors(const AidlInterface* interfaceType) {
     code << "public Stub() {\n";
     code.Indent();
     code << "this(android.os.PermissionEnforcer.fromContext(\n";
-    code << "   android.app.ActivityThread.currentActivityThread().getSystemContext()));\n";
+    code << "   android.app.ActivityThread.currentSystemContext()));\n";
     code.Dedent();
     code << "}\n";
   }
diff --git a/generate_ndk.cpp b/generate_ndk.cpp
index a6563567..4ac19fdd 100644
--- a/generate_ndk.cpp
+++ b/generate_ndk.cpp
@@ -23,7 +23,24 @@
 #include "aidl_to_ndk.h"
 #include "logging.h"
 
+#include "aidl_typenames.h"
+#include "code_writer.h"
+#include "io_delegate.h"
+#include "options.h"
+
+#include <aidl/transaction_ids.h>
 #include <android-base/stringprintf.h>
+#include <android-base/strings.h>
+
+#include <algorithm>
+#include <cstddef>
+#include <functional>
+#include <memory>
+#include <optional>
+#include <set>
+#include <string>
+#include <tuple>
+#include <vector>
 
 namespace android {
 namespace aidl {
@@ -379,7 +396,10 @@ static void GenerateSourceIncludes(CodeWriter& out, const AidlTypenames& types,
   out << "\n";
 
   std::set<std::string, HeaderComp> includes = {self_header};
+  includes.insert("cstdint");
+  includes.insert("android/binder_parcel.h");
   includes.insert("android/binder_parcel_utils.h");
+  includes.insert("android/binder_status.h");
   types.IterateTypes([&](const AidlDefinedType& a_defined_type) {
     if (a_defined_type.AsInterface() != nullptr) {
       includes.insert(NdkHeaderFile(a_defined_type, ClassNames::CLIENT, false /*use_os_sep*/));
@@ -745,9 +765,6 @@ void GenerateClassSource(CodeWriter& out, const AidlTypenames& types,
   // Find the maxId used for AIDL method. If methods use skipped ids, only support till kMaxSkip.
   int maxId = GetMaxId(defined_type);
   int functionCount = maxId + 1;
-  std::string codeToFunction = GlobalClassVarName(defined_type) + "_" + kFunctionNames;
-  out << "static const char* " << codeToFunction << "[] = { ";
-
   // If tracing is off, don't populate this array. libbinder_ndk will still add traces based on
   // transaction code
   vector<std::string> functionNames;
@@ -761,12 +778,21 @@ void GenerateClassSource(CodeWriter& out, const AidlTypenames& types,
       }
       functionNames[method->GetId()] = method->GetName();
     }
+  }
 
+  std::string codeToFunction;
+  // Function name array is empty, pass nullptr to avoid zero sized symbols
+  if (functionNames.size() == 0) {
+    codeToFunction = "nullptr";
+  } else {
+    codeToFunction = GlobalClassVarName(defined_type) + "_" + kFunctionNames;
+    out << "static const char* " << codeToFunction << "[] = { ";
     for (const auto& method : functionNames) {
       out << "\"" << method << "\",";
     }
+    out << "};\n";
   }
-  out << "};\n";
+
   out << "static AIBinder_Class* " << GlobalClassVarName(defined_type)
       << " = ::ndk::ICInterface::defineClass(" << i_name << "::" << kDescriptor << ", "
       << on_transact << ", " << codeToFunction << ", " << std::to_string(functionNames.size())
diff --git a/generate_rust.cpp b/generate_rust.cpp
index 99564b0b..a5cfe149 100644
--- a/generate_rust.cpp
+++ b/generate_rust.cpp
@@ -16,22 +16,28 @@
 
 #include "generate_rust.h"
 
-#include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
-#include <map>
 #include <memory>
+#include <optional>
+#include <set>
 #include <sstream>
+#include <string>
+#include <vector>
 
+#include "aidl_language.h"
 #include "aidl_to_common.h"
 #include "aidl_to_cpp_common.h"
 #include "aidl_to_rust.h"
+#include "aidl_typenames.h"
 #include "code_writer.h"
 #include "comments.h"
+#include "io_delegate.h"
 #include "logging.h"
+#include "options.h"
 
 using android::base::Join;
 using android::base::Split;
@@ -62,7 +68,7 @@ struct MangledAliasVisitor : AidlVisitor {
   }
   // Return a mangled name for a type (including AIDL package)
   template <typename T>
-  string Mangled(const T& type) const {
+  std::string Mangled(const T& type) const {
     ostringstream alias;
     for (const auto& component : Split(type.GetCanonicalName(), ".")) {
       alias << "_" << component.size() << "_" << component;
@@ -100,8 +106,8 @@ void GenerateMangledAliases(CodeWriter& out, const AidlDefinedType& type) {
   out << "}\n";
 }
 
-string BuildArg(const AidlArgument& arg, const AidlTypenames& typenames, Lifetime lifetime,
-                bool is_vintf_stability, vector<string>& lifetimes) {
+std::string BuildArg(const AidlArgument& arg, const AidlTypenames& typenames, Lifetime lifetime,
+                     bool is_vintf_stability, std::vector<std::string>& lifetimes) {
   // We pass in parameters that are not primitives by const reference.
   // Arrays get passed in as slices, which is handled in RustNameOf.
   auto arg_mode = ArgumentStorageMode(arg, typenames);
diff --git a/import_resolver.cpp b/import_resolver.cpp
index c1c8593a..34541065 100644
--- a/import_resolver.cpp
+++ b/import_resolver.cpp
@@ -15,32 +15,23 @@
  */
 
 #include "import_resolver.h"
-#include "aidl_language.h"
+#include "io_delegate.h"
 #include "logging.h"
-
-#include <algorithm>
-
-#include <android-base/file.h>
-#include <android-base/strings.h>
-#include <unistd.h>
-
-#ifdef _WIN32
-#include <io.h>
-#endif
-
 #include "os.h"
 
-using std::set;
-using std::string;
-using std::vector;
+#include <android-base/strings.h>
+#include <set>
+#include <string>
+#include <utility>
+#include <vector>
 
 namespace android {
 namespace aidl {
 
-ImportResolver::ImportResolver(const IoDelegate& io_delegate, const string& input_file_name,
-                               const set<string>& import_paths)
+ImportResolver::ImportResolver(const IoDelegate& io_delegate, const std::string& input_file_name,
+                               const std::set<std::string>& import_paths)
     : io_delegate_(io_delegate), input_file_name_(input_file_name) {
-  for (string path : import_paths) {
+  for (std::string path : import_paths) {
     if (path.empty()) {
       path = ".";
     }
@@ -51,10 +42,10 @@ ImportResolver::ImportResolver(const IoDelegate& io_delegate, const string& inpu
   }
 }
 
-string ImportResolver::FindImportFile(const string& canonical_name) const {
+std::string ImportResolver::FindImportFile(const std::string& canonical_name) const {
   auto parts = base::Split(canonical_name, ".");
   while (!parts.empty()) {
-    string relative_path = base::Join(parts, OS_PATH_SEPARATOR) + ".aidl";
+    std::string relative_path = base::Join(parts, OS_PATH_SEPARATOR) + ".aidl";
     auto candidates = ScanImportPaths(relative_path);
     if (candidates.size() == 0) {
       // remove the last part & keep searching
@@ -76,9 +67,9 @@ string ImportResolver::FindImportFile(const string& canonical_name) const {
   return "";
 }
 
-set<string> ImportResolver::ScanImportPaths(const string& relative_path) const {
+std::set<std::string> ImportResolver::ScanImportPaths(const std::string& relative_path) const {
   // Look for that relative path at each of our import roots.
-  set<string> found;
+  std::set<std::string> found;
   for (const auto& path : import_paths_) {
     if (io_delegate_.FileIsReadable(path + relative_path)) {
       found.emplace(path + relative_path);
diff --git a/io_delegate.cpp b/io_delegate.cpp
index b903f1fa..37c9c4eb 100644
--- a/io_delegate.cpp
+++ b/io_delegate.cpp
@@ -16,23 +16,32 @@
 
 #include "io_delegate.h"
 
+#include <cerrno>
 #include <cstring>
 #include <fstream>
-#include <type_traits>
+#include <ios>
+#include <memory>
+#include <new>
+#include <string>
 #include <vector>
 
 #ifdef _WIN32
 #include <direct.h>
+#include <fileapi.h>
+#include <io.h>
+// NOLINTNEXTLINE(misc-include-cleaner)
 #include <windows.h>
+#include <type_traits>
+// NOLINTNEXTLINE(misc-include-cleaner)
 #undef ERROR
 #else
 #include <dirent.h>
 #include <sys/stat.h>
-#include <sys/types.h>
 #include <unistd.h>
 #endif
 
 #include <android-base/strings.h>
+#include "code_writer.h"
 
 #include "logging.h"
 #include "os.h"
@@ -53,7 +62,8 @@ bool IoDelegate::GetAbsolutePath(const string& path, string* absolute_path) {
 #ifdef _WIN32
 
   char buf[4096];
-  DWORD path_len = GetFullPathName(path.c_str(), sizeof(buf), buf, nullptr);
+  // NOLINTNEXTLINE(misc-include-cleaner)
+  DWORD path_len = GetFullPathNameA(path.c_str(), sizeof(buf), buf, nullptr);
   if (path_len <= 0 || path_len >= sizeof(buf)) {
     AIDL_ERROR(path) << "Failed to GetFullPathName";
     return false;
@@ -97,7 +107,7 @@ unique_ptr<string> IoDelegate::GetFileContents(
   }
   contents.reset(new string);
   in.seekg(0, std::ios::end);
-  ssize_t file_size = in.tellg();
+  std::streamoff file_size = in.tellg();
   contents->resize(file_size + content_suffix.length());
   in.seekg(0, std::ios::beg);
   // Read the file contents into the beginning of the string
@@ -189,6 +199,7 @@ unique_ptr<CodeWriter> IoDelegate::GetCodeWriter(
 static Result<void> add_list_files(const string& dirname, vector<string>* result) {
   AIDL_FATAL_IF(result == nullptr, dirname);
 
+  // NOLINTNEXTLINE(misc-include-cleaner)
   WIN32_FIND_DATA find_data;
   // Look up the first file.
   // See https://stackoverflow.com/a/14841564/112950 for why we use remove_pointer_t
@@ -197,10 +208,13 @@ static Result<void> add_list_files(const string& dirname, vector<string>* result
   // the directory. Otherwise Find{First,Next}File will only return the directory
   // itself and stop.
   const string path(dirname + "\\*");
+  // NOLINTNEXTLINE(misc-include-cleaner)
   std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&FindClose)> search_handle(
       FindFirstFile(path.c_str(), &find_data), FindClose);
 
+  // NOLINTNEXTLINE(misc-include-cleaner)
   if (search_handle.get() == INVALID_HANDLE_VALUE) {
+    // NOLINTNEXTLINE(misc-include-cleaner)
     return Error() << "Failed to read directory '" << dirname << "': " << GetLastError();
   }
 
@@ -209,6 +223,7 @@ static Result<void> add_list_files(const string& dirname, vector<string>* result
     const bool skip = !strcmp(find_data.cFileName, ".") || !strcmp(find_data.cFileName, "..");
 
     if (!skip) {
+      // NOLINTNEXTLINE(misc-include-cleaner)
       if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
         if (auto ret = add_list_files(dirname + OS_PATH_SEPARATOR + find_data.cFileName, result);
             !ret.ok()) {
@@ -219,9 +234,12 @@ static Result<void> add_list_files(const string& dirname, vector<string>* result
       }
     }
 
+    // NOLINTNEXTLINE(misc-include-cleaner)
     has_more_files = FindNextFile(search_handle.get(), &find_data);
     if (!has_more_files) {
+      // NOLINTNEXTLINE(misc-include-cleaner)
       const DWORD err = GetLastError();
+      // NOLINTNEXTLINE(misc-include-cleaner)
       if (err != ERROR_NO_MORE_FILES) {
         return Error() << "Failed to read directory entry in '" << dirname << "': " << err;
       }
diff --git a/location.cpp b/location.cpp
index 623df6ad..fa900c7e 100644
--- a/location.cpp
+++ b/location.cpp
@@ -15,6 +15,9 @@
  */
 
 #include "location.h"
+#include <optional>
+#include <ostream>
+#include <string>
 
 AidlLocation::AidlLocation(const std::string& file, Point begin, Point end, Source source)
     : file_(file), begin_(begin), end_(end), source_(source) {}
diff --git a/logging.cpp b/logging.cpp
index 3c755656..921243d8 100644
--- a/logging.cpp
+++ b/logging.cpp
@@ -16,7 +16,12 @@
 
 #include "logging.h"
 
+#include <cstdlib>
+#include <iostream>
+#include <string>
+
 #include "aidl_language.h"
+#include "location.h"
 
 bool AidlErrorLog::sHadError = false;
 
@@ -39,10 +44,10 @@ AidlErrorLog::AidlErrorLog(Severity severity, const std::string& filename)
 AidlErrorLog::~AidlErrorLog() {
   if (severity_ == NO_OP) return;
   (*os_) << suffix_ << std::endl;
-  if (severity_ == FATAL) abort();
+  if (severity_ == FATAL) std::abort();
   if (location_.IsInternal()) {
     (*os_) << "Logging an internal location should not happen. Offending location: " << location_
            << std::endl;
-    abort();
+    std::abort();
   }
 }
diff --git a/main.cpp b/main.cpp
index c0078bac..f746a9e7 100644
--- a/main.cpp
+++ b/main.cpp
@@ -16,11 +16,8 @@
 
 #include "aidl.h"
 #include "io_delegate.h"
-#include "logging.h"
 #include "options.h"
 
-#include <iostream>
-
 using android::aidl::Options;
 
 #ifdef AIDL_CPP_BUILD
diff --git a/options.cpp b/options.cpp
index 9f0489ae..9c92d16d 100644
--- a/options.cpp
+++ b/options.cpp
@@ -20,16 +20,21 @@
 #include <android-base/parseint.h>
 #include <android-base/result.h>
 #include <android-base/strings.h>
+
 #include <getopt.h>
 #include <stdlib.h>
-#include <unistd.h>
 
-#include <algorithm>
+#include <cstdint>
+#include <cstring>
 #include <iostream>
+#include <map>
 #include <sstream>
 #include <string>
+#include <vector>
 
 #include "aidl_language.h"
+#include "diagnostics.h"
+#include "location.h"
 #include "logging.h"
 #include "os.h"
 
diff --git a/parser.cpp b/parser.cpp
index cec403a1..7e026cbc 100644
--- a/parser.cpp
+++ b/parser.cpp
@@ -16,11 +16,28 @@
 
 #include "parser.h"
 
+#include <algorithm>
+#include <cstddef>
+#include <cstdio>
+#include <functional>
+#include <map>
+#include <memory>
+#include <new>
 #include <queue>
+#include <set>
+#include <string>
+#include <utility>
+#include <vector>
 
+#include "aidl_language.h"
 #include "aidl_language_y.h"
+#include "aidl_typenames.h"
+#include "io_delegate.h"
+#include "location.h"
 #include "logging.h"
 
+#include <android-base/strings.h>
+
 void yylex_init(void**);
 void yylex_destroy(void*);
 void yyset_in(FILE* f, void*);
diff --git a/permission.cpp b/permission.cpp
index 9f730da2..9606eb00 100644
--- a/permission.cpp
+++ b/permission.cpp
@@ -15,12 +15,8 @@
  */
 
 #include "permission.h"
-#include <memory>
 #include <string>
 #include <variant>
-#include <vector>
-
-#include <android-base/strings.h>
 
 namespace android {
 namespace aidl {
diff --git a/preprocess.cpp b/preprocess.cpp
index d4aa05c1..681d792d 100644
--- a/preprocess.cpp
+++ b/preprocess.cpp
@@ -16,9 +16,18 @@
 
 #include "preprocess.h"
 
+#include <memory>
+#include <string>
+
 #include <android-base/strings.h>
 
 #include "aidl.h"
+#include "aidl_language.h"
+#include "aidl_typenames.h"
+#include "code_writer.h"
+#include "comments.h"
+#include "io_delegate.h"
+#include "options.h"
 
 using android::base::Join;
 
diff --git a/tests/golden_output/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h b/tests/golden_output/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
index 3ba192e8..091b8e29 100644
--- a/tests/golden_output/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
+++ b/tests/golden_output/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
@@ -56,7 +56,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.fixedsizearray.FixedSizeArrayExample.IntParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.fixedsizearray.FixedSizeArrayExample.IntParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -291,7 +291,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.fixedsizearray.FixedSizeArrayExample");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.fixedsizearray.FixedSizeArrayExample");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp b/tests/golden_output/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
index b2d3f19e..5331bc15 100644
--- a/tests/golden_output/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
+++ b/tests/golden_output/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/fixedsizearray/FixedSizeArrayExample.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
@@ -1302,8 +1305,7 @@ static binder_status_t _aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_I
   return _aidl_ret_status;
 }
 
-static const char* _g_aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_clazz_code_to_function[] = { };
-static AIBinder_Class* _g_aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(FixedSizeArrayExample::IEmptyInterface::descriptor, _aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_onTransact, _g_aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_clazz_code_to_function, 0);
+static AIBinder_Class* _g_aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(FixedSizeArrayExample::IEmptyInterface::descriptor, _aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_onTransact, nullptr, 0);
 
 FixedSizeArrayExample::BpEmptyInterface::BpEmptyInterface(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
 FixedSizeArrayExample::BpEmptyInterface::~BpEmptyInterface() {}
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
index 037d0d07..4f06b06c 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
@@ -150,7 +150,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces.MyParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces.MyParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -248,7 +248,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces.MyUnion");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces.MyUnion");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -288,7 +288,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
index 87b834f6..8ba335a3 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
@@ -47,7 +47,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.CircularParcelable");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.CircularParcelable");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
index 07a82c9b..7b1ff661 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
@@ -41,7 +41,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.DeprecatedParcelable");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.DeprecatedParcelable");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
index 7a24985a..cf7cb4cc 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
@@ -123,7 +123,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnion");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnion");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -185,7 +185,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.EmptyParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.EmptyParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -232,7 +232,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -285,7 +285,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.ExplicitPaddingParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.ExplicitPaddingParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -373,7 +373,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionNoPadding");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionNoPadding");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -465,7 +465,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionSmallPadding");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionSmallPadding");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -557,7 +557,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionLongPadding");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionLongPadding");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -599,7 +599,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
index 82b9d4fc..2d2f34af 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
@@ -45,7 +45,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.GenericStructuredParcelable");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.GenericStructuredParcelable");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
index 0c3ee0a6..73904f81 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
@@ -94,7 +94,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.Empty");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.Empty");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -166,7 +166,7 @@ public:
       ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
       ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
       static const ::android::String16& getParcelableDescriptor() {
-        static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.HasDeprecated");
+        [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.HasDeprecated");
         return DESCRIPTOR;
       }
       inline std::string toString() const {
@@ -258,7 +258,7 @@ public:
       ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
       ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
       static const ::android::String16& getParcelableDescriptor() {
-        static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.UsingHasDeprecated");
+        [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.UsingHasDeprecated");
         return DESCRIPTOR;
       }
       inline std::string toString() const {
@@ -304,7 +304,7 @@ public:
         ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
         ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
         static const ::android::String16& getParcelableDescriptor() {
-          static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface.Nested");
+          [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface.Nested");
           return DESCRIPTOR;
         }
         inline std::string toString() const {
@@ -432,7 +432,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
index 8cad3e39..566f37a2 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
@@ -150,7 +150,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces.MyParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces.MyParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -248,7 +248,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces.MyUnion");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces.MyUnion");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -288,7 +288,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
index 7dad60c5..c2b706c5 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
@@ -42,7 +42,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.OtherParcelableForToString");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.OtherParcelableForToString");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
index 1bf45e7e..2d6ec6cc 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
@@ -77,7 +77,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ParcelableForToString");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ParcelableForToString");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
index e31c6b21..0b78203d 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
@@ -49,7 +49,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.RecursiveList");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.RecursiveList");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
index 5c5b375b..0319e45a 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
@@ -54,7 +54,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.StructuredParcelable.Empty");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.StructuredParcelable.Empty");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -147,7 +147,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.StructuredParcelable");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.StructuredParcelable");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
index b273f9cc..d42ff59c 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
@@ -122,7 +122,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.Union");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.Union");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
index 52e12f3c..a9e5cf7b 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
@@ -109,7 +109,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.UnionWithFd");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.UnionWithFd");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
index 6b0f5461..955c4eba 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
@@ -50,7 +50,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.ExtendableParcelable");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.ExtendableParcelable");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
index d287a904..e9b623ac 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
@@ -46,7 +46,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExt");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExt");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
index c4ec2b19..95e72c78 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
@@ -51,7 +51,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExt2");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExt2");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
index ae5c3d40..b0b805b4 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
@@ -45,7 +45,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExtLike");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExtLike");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
index 553f9f1a..90a222f0 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
@@ -56,7 +56,7 @@ public:
         ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
         ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
         static const ::android::String16& getParcelableDescriptor() {
-          static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B.C.D");
+          [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B.C.D");
           return DESCRIPTOR;
         }
         inline std::string toString() const {
@@ -88,7 +88,7 @@ public:
       ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
       ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
       static const ::android::String16& getParcelableDescriptor() {
-        static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B.C");
+        [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B.C");
         return DESCRIPTOR;
       }
       inline std::string toString() const {
@@ -120,7 +120,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -155,7 +155,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.A");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.A");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -188,7 +188,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
index 8e27f4d9..5b1d46c9 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
@@ -59,7 +59,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.INestedService.Result");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.INestedService.Result");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
index df130a2f..256c2eb0 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
@@ -52,7 +52,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.ParcelableWithNested");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.ParcelableWithNested");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
index c42b268b..1a6d87ec 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
@@ -115,7 +115,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.unions.EnumUnion");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.unions.EnumUnion");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
index 75b7b2ad..319135c5 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
@@ -110,7 +110,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.unions.UnionInUnion");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.unions.UnionInUnion");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
index 89aafc35..f21be8d5 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/ArrayOfInterfaces.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
@@ -58,8 +61,7 @@ static binder_status_t _aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterfac
   return _aidl_ret_status;
 }
 
-static const char* _g_aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_clazz_code_to_function[] = { };
-static AIBinder_Class* _g_aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(ArrayOfInterfaces::IEmptyInterface::descriptor, _aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_onTransact, _g_aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_clazz_code_to_function, 0);
+static AIBinder_Class* _g_aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(ArrayOfInterfaces::IEmptyInterface::descriptor, _aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_onTransact, nullptr, 0);
 
 ArrayOfInterfaces::BpEmptyInterface::BpEmptyInterface(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
 ArrayOfInterfaces::BpEmptyInterface::~BpEmptyInterface() {}
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/CircularParcelable.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/CircularParcelable.cpp
index d51dc64b..5cc3298a 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/CircularParcelable.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/CircularParcelable.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/CircularParcelable.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnCircular.h>
 #include <aidl/android/aidl/tests/BnNamedCallback.h>
 #include <aidl/android/aidl/tests/BnNewName.h>
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/DeprecatedParcelable.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/DeprecatedParcelable.cpp
index 45c80667..6104fc50 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/DeprecatedParcelable.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/DeprecatedParcelable.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/DeprecatedParcelable.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/FixedSize.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/FixedSize.cpp
index ac70438e..0f51f139 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/FixedSize.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/FixedSize.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/FixedSize.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
index 28ebb7e1..ed0de1ea 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/ICircular.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnCircular.h>
 #include <aidl/android/aidl/tests/BnNamedCallback.h>
 #include <aidl/android/aidl/tests/BnNewName.h>
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IDeprecated.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IDeprecated.cpp
index a251917d..90c4d203 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IDeprecated.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IDeprecated.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/IDeprecated.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnDeprecated.h>
 #include <aidl/android/aidl/tests/BpDeprecated.h>
 
@@ -27,8 +30,7 @@ static binder_status_t _aidl_android_aidl_tests_IDeprecated_onTransact(AIBinder*
   return _aidl_ret_status;
 }
 
-static const char* _g_aidl_android_aidl_tests_IDeprecated_clazz_code_to_function[] = { };
-static AIBinder_Class* _g_aidl_android_aidl_tests_IDeprecated_clazz = ::ndk::ICInterface::defineClass(IDeprecated::descriptor, _aidl_android_aidl_tests_IDeprecated_onTransact, _g_aidl_android_aidl_tests_IDeprecated_clazz_code_to_function, 0);
+static AIBinder_Class* _g_aidl_android_aidl_tests_IDeprecated_clazz = ::ndk::ICInterface::defineClass(IDeprecated::descriptor, _aidl_android_aidl_tests_IDeprecated_onTransact, nullptr, 0);
 
 #pragma clang diagnostic pop
 BpDeprecated::BpDeprecated(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
index 148d7a01..caa67be3 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/INamedCallback.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnNamedCallback.h>
 #include <aidl/android/aidl/tests/BpNamedCallback.h>
 
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
index 7a4674a2..b0f8254a 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/INewName.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnNewName.h>
 #include <aidl/android/aidl/tests/BpNewName.h>
 
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
index 422fb023..3008ff63 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/IOldName.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnOldName.h>
 #include <aidl/android/aidl/tests/BpOldName.h>
 
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
index 912ea9b9..427a9061 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/ITestService.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnCircular.h>
 #include <aidl/android/aidl/tests/BnNamedCallback.h>
 #include <aidl/android/aidl/tests/BnNewName.h>
@@ -5103,8 +5106,7 @@ static binder_status_t _aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_
   return _aidl_ret_status;
 }
 
-static const char* _g_aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_clazz_code_to_function[] = { };
-static AIBinder_Class* _g_aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_clazz = ::ndk::ICInterface::defineClass(ITestService::CompilerChecks::IFoo::descriptor, _aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_onTransact, _g_aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_clazz_code_to_function, 0);
+static AIBinder_Class* _g_aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_clazz = ::ndk::ICInterface::defineClass(ITestService::CompilerChecks::IFoo::descriptor, _aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_onTransact, nullptr, 0);
 
 ITestService::CompilerChecks::BpFoo::BpFoo(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
 ITestService::CompilerChecks::BpFoo::~BpFoo() {}
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
index 4346a48c..9826462b 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/ListOfInterfaces.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
@@ -58,8 +61,7 @@ static binder_status_t _aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface
   return _aidl_ret_status;
 }
 
-static const char* _g_aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_clazz_code_to_function[] = { };
-static AIBinder_Class* _g_aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(ListOfInterfaces::IEmptyInterface::descriptor, _aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_onTransact, _g_aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_clazz_code_to_function, 0);
+static AIBinder_Class* _g_aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(ListOfInterfaces::IEmptyInterface::descriptor, _aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_onTransact, nullptr, 0);
 
 ListOfInterfaces::BpEmptyInterface::BpEmptyInterface(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
 ListOfInterfaces::BpEmptyInterface::~BpEmptyInterface() {}
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/OtherParcelableForToString.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/OtherParcelableForToString.cpp
index be9e3176..a153572c 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/OtherParcelableForToString.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/OtherParcelableForToString.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/OtherParcelableForToString.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ParcelableForToString.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ParcelableForToString.cpp
index 4e92bdfc..055cf060 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ParcelableForToString.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ParcelableForToString.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/ParcelableForToString.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/RecursiveList.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/RecursiveList.cpp
index 7530c76f..3a5172ae 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/RecursiveList.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/RecursiveList.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/RecursiveList.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/StructuredParcelable.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/StructuredParcelable.cpp
index 5423b9a8..881787b1 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/StructuredParcelable.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/StructuredParcelable.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/StructuredParcelable.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/Union.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/Union.cpp
index 6ec79ba0..7f2b5334 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/Union.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/Union.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/Union.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/UnionWithFd.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/UnionWithFd.cpp
index 4d36f612..45321a8b 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/UnionWithFd.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/UnionWithFd.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/UnionWithFd.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/ExtendableParcelable.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/ExtendableParcelable.cpp
index 5368d898..6f99bcd1 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/ExtendableParcelable.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/ExtendableParcelable.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/extension/ExtendableParcelable.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt.cpp
index efa5dcbf..a7c4c863 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/extension/MyExt.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt2.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt2.cpp
index 60dbc018..95a5154f 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt2.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt2.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/extension/MyExt2.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExtLike.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExtLike.cpp
index 64791a89..548ced3c 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExtLike.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExtLike.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/extension/MyExtLike.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/DeeplyNested.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/DeeplyNested.cpp
index 32a36dbc..121226b2 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/DeeplyNested.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/DeeplyNested.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/nested/DeeplyNested.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
index ee606bfd..559361ed 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/nested/INestedService.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/nested/BnNestedService.h>
 #include <aidl/android/aidl/tests/nested/BpNestedService.h>
 
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/ParcelableWithNested.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/ParcelableWithNested.cpp
index c31e9fc3..85f2cc95 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/ParcelableWithNested.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/ParcelableWithNested.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/nested/ParcelableWithNested.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/EnumUnion.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/EnumUnion.cpp
index 1b1f8742..2b06591b 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/EnumUnion.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/EnumUnion.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/unions/EnumUnion.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/UnionInUnion.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/UnionInUnion.cpp
index ade398bb..f445676e 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/UnionInUnion.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/UnionInUnion.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/unions/UnionInUnion.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/GenericStructuredParcelable.h b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/GenericStructuredParcelable.h
index 8c1c76b8..434026d5 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/GenericStructuredParcelable.h
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/GenericStructuredParcelable.h
@@ -71,7 +71,10 @@ public:
 }  // namespace aidl
 #include "aidl/android/aidl/tests/GenericStructuredParcelable.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtected.java b/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtected.java
index b3add837..40c5b4a1 100644
--- a/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtected.java
+++ b/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtected.java
@@ -56,7 +56,7 @@ public interface IProtected extends android.os.IInterface
     /** Default constructor. */
     public Stub() {
       this(android.os.PermissionEnforcer.fromContext(
-         android.app.ActivityThread.currentActivityThread().getSystemContext()));
+         android.app.ActivityThread.currentSystemContext()));
     }
     /**
      * Cast an IBinder object into an android.aidl.tests.permission.IProtected interface,
diff --git a/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtectedInterface.java b/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtectedInterface.java
index 5acb24c3..2f18193a 100644
--- a/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtectedInterface.java
+++ b/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtectedInterface.java
@@ -40,7 +40,7 @@ public interface IProtectedInterface extends android.os.IInterface
     /** Default constructor. */
     public Stub() {
       this(android.os.PermissionEnforcer.fromContext(
-         android.app.ActivityThread.currentActivityThread().getSystemContext()));
+         android.app.ActivityThread.currentSystemContext()));
     }
     /**
      * Cast an IBinder object into an android.aidl.tests.permission.IProtectedInterface interface,
diff --git a/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/platform/IProtected.java b/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/platform/IProtected.java
index c1aeda6a..2c0d7411 100644
--- a/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/platform/IProtected.java
+++ b/tests/golden_output/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/platform/IProtected.java
@@ -37,7 +37,7 @@ public interface IProtected extends android.os.IInterface
     /** Default constructor. */
     public Stub() {
       this(android.os.PermissionEnforcer.fromContext(
-         android.app.ActivityThread.currentActivityThread().getSystemContext()));
+         android.app.ActivityThread.currentSystemContext()));
     }
     /**
      * Cast an IBinder object into an android.aidl.tests.permission.platform.IProtected interface,
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 821cabee..05f21e29 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -107,7 +107,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index 58e0a9ae..8fe7a938 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -42,7 +42,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp b/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
index 8d3693fc..ac6135e9 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/BazUnion.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp b/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
index 1e1c6c4d..10bda288 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/Foo.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index 608b5377..1de32338 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/IFooInterface.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/versioned/tests/BnFooInterface.h>
 #include <aidl/android/aidl/versioned/tests/BpFooInterface.h>
 
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 110ec1e7..7c577c9c 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -109,7 +109,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index 333bc3d5..19591db3 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -44,7 +44,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp b/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
index 03790663..74f58cf5 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/BazUnion.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp b/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
index e9bc8761..26c3917f 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/Foo.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index 8b41f63b..dc12826f 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/IFooInterface.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/versioned/tests/BnFooInterface.h>
 #include <aidl/android/aidl/versioned/tests/BpFooInterface.h>
 
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 65cf21d8..cb73c91c 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -109,7 +109,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index 339f8802..51c03918 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -44,7 +44,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp b/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
index ed3d79ba..e30c35e6 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/BazUnion.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp b/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
index 25c2641d..0ad01570 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/Foo.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index 9eb42451..e3bbd87b 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/IFooInterface.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/versioned/tests/BnFooInterface.h>
 #include <aidl/android/aidl/versioned/tests/BpFooInterface.h>
 
diff --git a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
index 00c62831..ae3c2b4f 100644
--- a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
+++ b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
@@ -49,7 +49,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.loggable.Data");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.loggable.Data");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
index 81ed48b4..80b06ee0 100644
--- a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
+++ b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
@@ -108,7 +108,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.loggable.Union");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.loggable.Union");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Data.cpp b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Data.cpp
index fd900bfe..fa658675 100644
--- a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Data.cpp
+++ b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Data.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/loggable/Data.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
index a2ba5fa4..e55b69ba 100644
--- a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
+++ b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/loggable/ILoggableInterface.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <android/binder_to_string.h>
 #include <aidl/android/aidl/loggable/BnLoggableInterface.h>
 #include <aidl/android/aidl/loggable/BpLoggableInterface.h>
diff --git a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Union.cpp b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Union.cpp
index 618dfee4..a2574978 100644
--- a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Union.cpp
+++ b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Union.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/loggable/Union.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h b/tests/golden_output/frozen/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
index 3ba192e8..091b8e29 100644
--- a/tests/golden_output/frozen/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
+++ b/tests/golden_output/frozen/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
@@ -56,7 +56,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.fixedsizearray.FixedSizeArrayExample.IntParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.fixedsizearray.FixedSizeArrayExample.IntParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -291,7 +291,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.fixedsizearray.FixedSizeArrayExample");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.fixedsizearray.FixedSizeArrayExample");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp b/tests/golden_output/frozen/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
index b2d3f19e..5331bc15 100644
--- a/tests/golden_output/frozen/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
+++ b/tests/golden_output/frozen/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/fixedsizearray/FixedSizeArrayExample.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
@@ -1302,8 +1305,7 @@ static binder_status_t _aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_I
   return _aidl_ret_status;
 }
 
-static const char* _g_aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_clazz_code_to_function[] = { };
-static AIBinder_Class* _g_aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(FixedSizeArrayExample::IEmptyInterface::descriptor, _aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_onTransact, _g_aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_clazz_code_to_function, 0);
+static AIBinder_Class* _g_aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(FixedSizeArrayExample::IEmptyInterface::descriptor, _aidl_android_aidl_fixedsizearray_FixedSizeArrayExample_IEmptyInterface_onTransact, nullptr, 0);
 
 FixedSizeArrayExample::BpEmptyInterface::BpEmptyInterface(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
 FixedSizeArrayExample::BpEmptyInterface::~BpEmptyInterface() {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
index 037d0d07..4f06b06c 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
@@ -150,7 +150,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces.MyParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces.MyParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -248,7 +248,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces.MyUnion");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces.MyUnion");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -288,7 +288,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ArrayOfInterfaces");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
index 87b834f6..8ba335a3 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
@@ -47,7 +47,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.CircularParcelable");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.CircularParcelable");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
index 07a82c9b..7b1ff661 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
@@ -41,7 +41,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.DeprecatedParcelable");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.DeprecatedParcelable");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
index 7a24985a..cf7cb4cc 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
@@ -123,7 +123,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnion");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnion");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -185,7 +185,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.EmptyParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.EmptyParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -232,7 +232,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -285,7 +285,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.ExplicitPaddingParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.ExplicitPaddingParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -373,7 +373,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionNoPadding");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionNoPadding");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -465,7 +465,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionSmallPadding");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionSmallPadding");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -557,7 +557,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionLongPadding");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize.FixedUnionLongPadding");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -599,7 +599,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.FixedSize");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
index 82b9d4fc..2d2f34af 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
@@ -45,7 +45,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.GenericStructuredParcelable");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.GenericStructuredParcelable");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
index 0c3ee0a6..73904f81 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
@@ -94,7 +94,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.Empty");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.Empty");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -166,7 +166,7 @@ public:
       ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
       ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
       static const ::android::String16& getParcelableDescriptor() {
-        static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.HasDeprecated");
+        [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.HasDeprecated");
         return DESCRIPTOR;
       }
       inline std::string toString() const {
@@ -258,7 +258,7 @@ public:
       ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
       ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
       static const ::android::String16& getParcelableDescriptor() {
-        static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.UsingHasDeprecated");
+        [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.UsingHasDeprecated");
         return DESCRIPTOR;
       }
       inline std::string toString() const {
@@ -304,7 +304,7 @@ public:
         ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
         ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
         static const ::android::String16& getParcelableDescriptor() {
-          static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface.Nested");
+          [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface.Nested");
           return DESCRIPTOR;
         }
         inline std::string toString() const {
@@ -432,7 +432,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ITestService.CompilerChecks");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
index 8cad3e39..566f37a2 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
@@ -150,7 +150,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces.MyParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces.MyParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -248,7 +248,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces.MyUnion");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces.MyUnion");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -288,7 +288,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ListOfInterfaces");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
index 7dad60c5..c2b706c5 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
@@ -42,7 +42,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.OtherParcelableForToString");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.OtherParcelableForToString");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
index 1bf45e7e..2d6ec6cc 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
@@ -77,7 +77,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ParcelableForToString");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.ParcelableForToString");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
index e31c6b21..0b78203d 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
@@ -49,7 +49,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.RecursiveList");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.RecursiveList");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
index 5c5b375b..0319e45a 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
@@ -54,7 +54,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.StructuredParcelable.Empty");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.StructuredParcelable.Empty");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -147,7 +147,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.StructuredParcelable");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.StructuredParcelable");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
index b273f9cc..d42ff59c 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
@@ -122,7 +122,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.Union");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.Union");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
index 52e12f3c..a9e5cf7b 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
@@ -109,7 +109,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.UnionWithFd");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.UnionWithFd");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
index 6b0f5461..955c4eba 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
@@ -50,7 +50,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.ExtendableParcelable");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.ExtendableParcelable");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
index d287a904..e9b623ac 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
@@ -46,7 +46,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExt");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExt");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
index c4ec2b19..95e72c78 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
@@ -51,7 +51,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExt2");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExt2");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
index ae5c3d40..b0b805b4 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
@@ -45,7 +45,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExtLike");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.extension.MyExtLike");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
index 553f9f1a..90a222f0 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
@@ -56,7 +56,7 @@ public:
         ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
         ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
         static const ::android::String16& getParcelableDescriptor() {
-          static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B.C.D");
+          [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B.C.D");
           return DESCRIPTOR;
         }
         inline std::string toString() const {
@@ -88,7 +88,7 @@ public:
       ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
       ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
       static const ::android::String16& getParcelableDescriptor() {
-        static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B.C");
+        [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B.C");
         return DESCRIPTOR;
       }
       inline std::string toString() const {
@@ -120,7 +120,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.B");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -155,7 +155,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.A");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested.A");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -188,7 +188,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.DeeplyNested");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
index 8e27f4d9..5b1d46c9 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
@@ -59,7 +59,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.INestedService.Result");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.INestedService.Result");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
index df130a2f..256c2eb0 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
@@ -52,7 +52,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.ParcelableWithNested");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.nested.ParcelableWithNested");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
index c42b268b..1a6d87ec 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
@@ -115,7 +115,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.unions.EnumUnion");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.unions.EnumUnion");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
index 75b7b2ad..319135c5 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
@@ -110,7 +110,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.unions.UnionInUnion");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.tests.unions.UnionInUnion");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
index 89aafc35..f21be8d5 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/ArrayOfInterfaces.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
@@ -58,8 +61,7 @@ static binder_status_t _aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterfac
   return _aidl_ret_status;
 }
 
-static const char* _g_aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_clazz_code_to_function[] = { };
-static AIBinder_Class* _g_aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(ArrayOfInterfaces::IEmptyInterface::descriptor, _aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_onTransact, _g_aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_clazz_code_to_function, 0);
+static AIBinder_Class* _g_aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(ArrayOfInterfaces::IEmptyInterface::descriptor, _aidl_android_aidl_tests_ArrayOfInterfaces_IEmptyInterface_onTransact, nullptr, 0);
 
 ArrayOfInterfaces::BpEmptyInterface::BpEmptyInterface(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
 ArrayOfInterfaces::BpEmptyInterface::~BpEmptyInterface() {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/CircularParcelable.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/CircularParcelable.cpp
index d51dc64b..5cc3298a 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/CircularParcelable.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/CircularParcelable.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/CircularParcelable.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnCircular.h>
 #include <aidl/android/aidl/tests/BnNamedCallback.h>
 #include <aidl/android/aidl/tests/BnNewName.h>
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/DeprecatedParcelable.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/DeprecatedParcelable.cpp
index 45c80667..6104fc50 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/DeprecatedParcelable.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/DeprecatedParcelable.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/DeprecatedParcelable.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/FixedSize.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/FixedSize.cpp
index ac70438e..0f51f139 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/FixedSize.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/FixedSize.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/FixedSize.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
index 28ebb7e1..ed0de1ea 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/ICircular.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnCircular.h>
 #include <aidl/android/aidl/tests/BnNamedCallback.h>
 #include <aidl/android/aidl/tests/BnNewName.h>
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IDeprecated.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IDeprecated.cpp
index a251917d..90c4d203 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IDeprecated.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IDeprecated.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/IDeprecated.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnDeprecated.h>
 #include <aidl/android/aidl/tests/BpDeprecated.h>
 
@@ -27,8 +30,7 @@ static binder_status_t _aidl_android_aidl_tests_IDeprecated_onTransact(AIBinder*
   return _aidl_ret_status;
 }
 
-static const char* _g_aidl_android_aidl_tests_IDeprecated_clazz_code_to_function[] = { };
-static AIBinder_Class* _g_aidl_android_aidl_tests_IDeprecated_clazz = ::ndk::ICInterface::defineClass(IDeprecated::descriptor, _aidl_android_aidl_tests_IDeprecated_onTransact, _g_aidl_android_aidl_tests_IDeprecated_clazz_code_to_function, 0);
+static AIBinder_Class* _g_aidl_android_aidl_tests_IDeprecated_clazz = ::ndk::ICInterface::defineClass(IDeprecated::descriptor, _aidl_android_aidl_tests_IDeprecated_onTransact, nullptr, 0);
 
 #pragma clang diagnostic pop
 BpDeprecated::BpDeprecated(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
index 148d7a01..caa67be3 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/INamedCallback.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnNamedCallback.h>
 #include <aidl/android/aidl/tests/BpNamedCallback.h>
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
index 7a4674a2..b0f8254a 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/INewName.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnNewName.h>
 #include <aidl/android/aidl/tests/BpNewName.h>
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
index 422fb023..3008ff63 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/IOldName.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnOldName.h>
 #include <aidl/android/aidl/tests/BpOldName.h>
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
index 912ea9b9..427a9061 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/ITestService.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/BnCircular.h>
 #include <aidl/android/aidl/tests/BnNamedCallback.h>
 #include <aidl/android/aidl/tests/BnNewName.h>
@@ -5103,8 +5106,7 @@ static binder_status_t _aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_
   return _aidl_ret_status;
 }
 
-static const char* _g_aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_clazz_code_to_function[] = { };
-static AIBinder_Class* _g_aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_clazz = ::ndk::ICInterface::defineClass(ITestService::CompilerChecks::IFoo::descriptor, _aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_onTransact, _g_aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_clazz_code_to_function, 0);
+static AIBinder_Class* _g_aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_clazz = ::ndk::ICInterface::defineClass(ITestService::CompilerChecks::IFoo::descriptor, _aidl_android_aidl_tests_ITestService_CompilerChecks_Foo_onTransact, nullptr, 0);
 
 ITestService::CompilerChecks::BpFoo::BpFoo(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
 ITestService::CompilerChecks::BpFoo::~BpFoo() {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
index 4346a48c..9826462b 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/ListOfInterfaces.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
@@ -58,8 +61,7 @@ static binder_status_t _aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface
   return _aidl_ret_status;
 }
 
-static const char* _g_aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_clazz_code_to_function[] = { };
-static AIBinder_Class* _g_aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(ListOfInterfaces::IEmptyInterface::descriptor, _aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_onTransact, _g_aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_clazz_code_to_function, 0);
+static AIBinder_Class* _g_aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_clazz = ::ndk::ICInterface::defineClass(ListOfInterfaces::IEmptyInterface::descriptor, _aidl_android_aidl_tests_ListOfInterfaces_IEmptyInterface_onTransact, nullptr, 0);
 
 ListOfInterfaces::BpEmptyInterface::BpEmptyInterface(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
 ListOfInterfaces::BpEmptyInterface::~BpEmptyInterface() {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/OtherParcelableForToString.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/OtherParcelableForToString.cpp
index be9e3176..a153572c 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/OtherParcelableForToString.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/OtherParcelableForToString.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/OtherParcelableForToString.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ParcelableForToString.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ParcelableForToString.cpp
index 4e92bdfc..055cf060 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ParcelableForToString.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ParcelableForToString.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/ParcelableForToString.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/RecursiveList.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/RecursiveList.cpp
index 7530c76f..3a5172ae 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/RecursiveList.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/RecursiveList.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/RecursiveList.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/StructuredParcelable.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/StructuredParcelable.cpp
index 5423b9a8..881787b1 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/StructuredParcelable.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/StructuredParcelable.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/StructuredParcelable.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/Union.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/Union.cpp
index 6ec79ba0..7f2b5334 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/Union.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/Union.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/Union.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/UnionWithFd.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/UnionWithFd.cpp
index 4d36f612..45321a8b 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/UnionWithFd.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/UnionWithFd.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/UnionWithFd.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/ExtendableParcelable.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/ExtendableParcelable.cpp
index 5368d898..6f99bcd1 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/ExtendableParcelable.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/ExtendableParcelable.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/extension/ExtendableParcelable.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt.cpp
index efa5dcbf..a7c4c863 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/extension/MyExt.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt2.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt2.cpp
index 60dbc018..95a5154f 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt2.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExt2.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/extension/MyExt2.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExtLike.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExtLike.cpp
index 64791a89..548ced3c 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExtLike.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/extension/MyExtLike.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/extension/MyExtLike.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/DeeplyNested.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/DeeplyNested.cpp
index 32a36dbc..121226b2 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/DeeplyNested.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/DeeplyNested.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/nested/DeeplyNested.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
index ee606bfd..559361ed 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/nested/INestedService.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/tests/nested/BnNestedService.h>
 #include <aidl/android/aidl/tests/nested/BpNestedService.h>
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/ParcelableWithNested.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/ParcelableWithNested.cpp
index c31e9fc3..85f2cc95 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/ParcelableWithNested.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/ParcelableWithNested.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/nested/ParcelableWithNested.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/EnumUnion.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/EnumUnion.cpp
index 1b1f8742..2b06591b 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/EnumUnion.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/EnumUnion.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/unions/EnumUnion.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/UnionInUnion.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/UnionInUnion.cpp
index ade398bb..f445676e 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/UnionInUnion.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/unions/UnionInUnion.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/tests/unions/UnionInUnion.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/GenericStructuredParcelable.h b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/GenericStructuredParcelable.h
index 8c1c76b8..434026d5 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/GenericStructuredParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/GenericStructuredParcelable.h
@@ -71,7 +71,10 @@ public:
 }  // namespace aidl
 #include "aidl/android/aidl/tests/GenericStructuredParcelable.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtected.java b/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtected.java
index b3add837..40c5b4a1 100644
--- a/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtected.java
+++ b/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtected.java
@@ -56,7 +56,7 @@ public interface IProtected extends android.os.IInterface
     /** Default constructor. */
     public Stub() {
       this(android.os.PermissionEnforcer.fromContext(
-         android.app.ActivityThread.currentActivityThread().getSystemContext()));
+         android.app.ActivityThread.currentSystemContext()));
     }
     /**
      * Cast an IBinder object into an android.aidl.tests.permission.IProtected interface,
diff --git a/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtectedInterface.java b/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtectedInterface.java
index 5acb24c3..2f18193a 100644
--- a/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtectedInterface.java
+++ b/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/IProtectedInterface.java
@@ -40,7 +40,7 @@ public interface IProtectedInterface extends android.os.IInterface
     /** Default constructor. */
     public Stub() {
       this(android.os.PermissionEnforcer.fromContext(
-         android.app.ActivityThread.currentActivityThread().getSystemContext()));
+         android.app.ActivityThread.currentSystemContext()));
     }
     /**
      * Cast an IBinder object into an android.aidl.tests.permission.IProtectedInterface interface,
diff --git a/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/platform/IProtected.java b/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/platform/IProtected.java
index c1aeda6a..2c0d7411 100644
--- a/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/platform/IProtected.java
+++ b/tests/golden_output/frozen/aidl-test-interface-permission-java-source/gen/android/aidl/tests/permission/platform/IProtected.java
@@ -37,7 +37,7 @@ public interface IProtected extends android.os.IInterface
     /** Default constructor. */
     public Stub() {
       this(android.os.PermissionEnforcer.fromContext(
-         android.app.ActivityThread.currentActivityThread().getSystemContext()));
+         android.app.ActivityThread.currentSystemContext()));
     }
     /**
      * Cast an IBinder object into an android.aidl.tests.permission.platform.IProtected interface,
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 821cabee..05f21e29 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -107,7 +107,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index 58e0a9ae..8fe7a938 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -42,7 +42,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
index 8d3693fc..ac6135e9 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/BazUnion.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
index 1e1c6c4d..10bda288 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/Foo.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index 608b5377..1de32338 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/IFooInterface.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/versioned/tests/BnFooInterface.h>
 #include <aidl/android/aidl/versioned/tests/BpFooInterface.h>
 
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 110ec1e7..7c577c9c 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -109,7 +109,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index 333bc3d5..19591db3 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -44,7 +44,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
index 03790663..74f58cf5 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/BazUnion.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
index e9bc8761..26c3917f 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/Foo.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index 8b41f63b..dc12826f 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/IFooInterface.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/versioned/tests/BnFooInterface.h>
 #include <aidl/android/aidl/versioned/tests/BpFooInterface.h>
 
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 65cf21d8..cb73c91c 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -109,7 +109,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.BazUnion");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index 339f8802..51c03918 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -44,7 +44,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.versioned.tests.Foo");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
index ed3d79ba..e30c35e6 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/BazUnion.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/BazUnion.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
index 25c2641d..0ad01570 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/Foo.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/Foo.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index 9eb42451..e3bbd87b 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/versioned/tests/IFooInterface.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <aidl/android/aidl/versioned/tests/BnFooInterface.h>
 #include <aidl/android/aidl/versioned/tests/BpFooInterface.h>
 
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
index 00c62831..ae3c2b4f 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
@@ -49,7 +49,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.loggable.Data");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.loggable.Data");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
index 81ed48b4..80b06ee0 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
@@ -108,7 +108,7 @@ public:
   ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
   ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
   static const ::android::String16& getParcelableDescriptor() {
-    static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.loggable.Union");
+    [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.loggable.Union");
     return DESCRIPTOR;
   }
   inline std::string toString() const {
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Data.cpp b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Data.cpp
index fd900bfe..fa658675 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Data.cpp
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Data.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/loggable/Data.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
index a2ba5fa4..e55b69ba 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/loggable/ILoggableInterface.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <android/binder_to_string.h>
 #include <aidl/android/aidl/loggable/BnLoggableInterface.h>
 #include <aidl/android/aidl/loggable/BpLoggableInterface.h>
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Union.cpp b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Union.cpp
index 618dfee4..a2574978 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Union.cpp
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/Union.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/loggable/Union.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index 9a49b97e..84995560 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -71,7 +71,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -168,7 +168,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyUnion");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyUnion");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
index 66dc407d..0249798c 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/test/trunk/ITrunkStableTest.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <android/binder_to_string.h>
 #include <aidl/android/aidl/test/trunk/BnTrunkStableTest.h>
 #include <aidl/android/aidl/test/trunk/BpTrunkStableTest.h>
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index 2f87c2d6..2e4bc4ba 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -75,7 +75,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -176,7 +176,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyUnion");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyUnion");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -219,7 +219,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyOtherParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyOtherParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
index 7887c10a..2936577b 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/test/trunk/ITrunkStableTest.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <android/binder_to_string.h>
 #include <aidl/android/aidl/test/trunk/BnTrunkStableTest.h>
 #include <aidl/android/aidl/test/trunk/BpTrunkStableTest.h>
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index 9a49b97e..84995560 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -71,7 +71,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -168,7 +168,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyUnion");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyUnion");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
index 66dc407d..0249798c 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/test/trunk/ITrunkStableTest.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <android/binder_to_string.h>
 #include <aidl/android/aidl/test/trunk/BnTrunkStableTest.h>
 #include <aidl/android/aidl/test/trunk/BpTrunkStableTest.h>
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index 7136de55..741e1833 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -72,7 +72,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -173,7 +173,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyUnion");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyUnion");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
@@ -216,7 +216,7 @@ public:
     ::android::status_t readFromParcel(const ::android::Parcel* _aidl_parcel) final;
     ::android::status_t writeToParcel(::android::Parcel* _aidl_parcel) const final;
     static const ::android::String16& getParcelableDescriptor() {
-      static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyOtherParcelable");
+      [[clang::no_destroy]] static const ::android::StaticString16 DESCRIPTOR (u"android.aidl.test.trunk.ITrunkStableTest.MyOtherParcelable");
       return DESCRIPTOR;
     }
     inline std::string toString() const {
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
index e7668d33..14bdef03 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
@@ -8,7 +8,10 @@
  */
 #include "aidl/android/aidl/test/trunk/ITrunkStableTest.h"
 
+#include <cstdint>
+#include <android/binder_parcel.h>
 #include <android/binder_parcel_utils.h>
+#include <android/binder_status.h>
 #include <android/binder_to_string.h>
 #include <aidl/android/aidl/test/trunk/BnTrunkStableTest.h>
 #include <aidl/android/aidl/test/trunk/BpTrunkStableTest.h>
```

