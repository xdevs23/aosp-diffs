```diff
diff --git a/Android.bp b/Android.bp
index 9f527841..abffd0c2 100644
--- a/Android.bp
+++ b/Android.bp
@@ -58,7 +58,10 @@ cc_defaults {
         "-performance-unnecessary-copy-initialization",
         "-performance-unnecessary-value-param",
     ],
-    header_libs: ["libgtest_prod_headers"],
+    header_libs: [
+        "libgtest_prod_headers",
+        "libaidl_transactions",
+    ],
     static_libs: [
         "libbase",
         "libgtest",
@@ -201,6 +204,10 @@ cc_test {
         "liblog",
     ],
 
+    header_libs: [
+        "libaidl_transactions",
+    ],
+
     target: {
         host: {
             sanitize: {
@@ -222,6 +229,10 @@ cc_fuzz {
         "tests/corpus/*",
     ],
 
+    header_libs: [
+        "libaidl_transactions",
+    ],
+
     fuzz_config: {
         cc: [
             "aidl-bugs@google.com",
@@ -319,6 +330,21 @@ cc_library_headers {
     ],
 }
 
+cc_library_headers {
+    name: "libaidl_transactions",
+    host_supported: true,
+    export_include_dirs: ["include"],
+    visibility: [
+       ":__subpackages__",
+       "//frameworks/native/libs/binder/tests:__subpackages__",
+    ],
+    target: {
+        windows: {
+            enabled: true,
+        },
+    },
+}
+
 cc_library {
     name: "libsimpleparcelable",
     export_include_dirs: [
diff --git a/aidl.h b/aidl.h
index 4dff19b6..5e95e7c8 100644
--- a/aidl.h
+++ b/aidl.h
@@ -21,6 +21,7 @@
 #include <string>
 #include <vector>
 
+#include <aidl/transaction_ids.h>
 #include "aidl_language.h"
 #include "import_resolver.h"
 #include "io_delegate.h"
@@ -51,31 +52,6 @@ bool dump_mappings(const Options& options, const IoDelegate& io_delegate);
 // main entry point to AIDL
 int aidl_entry(const Options& options, const IoDelegate& io_delegate);
 
-// Copied from android.is.IBinder.[FIRST|LAST]_CALL_TRANSACTION
-const int kFirstCallTransaction = 1;
-const int kLastCallTransaction = 0x00ffffff;
-
-// Following IDs are all offsets from  kFirstCallTransaction
-
-// IDs for meta transactions. Most of the meta transactions are implemented in
-// the framework side (Binder.java or Binder.cpp). But these are the ones that
-// are auto-implemented by the AIDL compiler.
-const int kFirstMetaMethodId = kLastCallTransaction - kFirstCallTransaction;
-const int kGetInterfaceVersionId = kFirstMetaMethodId;
-const int kGetInterfaceHashId = kFirstMetaMethodId - 1;
-// Additional meta transactions implemented by AIDL should use
-// kFirstMetaMethodId -1, -2, ...and so on.
-
-// Reserve 100 IDs for meta methods, which is more than enough. If we don't reserve,
-// in the future, a newly added meta transaction ID will have a chance to
-// collide with the user-defined methods that were added in the past. So,
-// let's prevent users from using IDs in this range from the beginning.
-const int kLastMetaMethodId = kFirstMetaMethodId - 99;
-
-// Range of IDs that is allowed for user-defined methods.
-const int kMinUserSetMethodId = 0;
-const int kMaxUserSetMethodId = kLastMetaMethodId - 1;
-
 const char kPreamble[] =
     R"(///////////////////////////////////////////////////////////////////////////////
 // THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
diff --git a/aidl_checkapi.cpp b/aidl_checkapi.cpp
index 0103dc18..9580df11 100644
--- a/aidl_checkapi.cpp
+++ b/aidl_checkapi.cpp
@@ -82,6 +82,10 @@ static vector<string> get_strict_annotations(const AidlAnnotatable& node) {
   // tools/aidl/build/hash_gen.sh.
   static const set<AidlAnnotation::Type> kIgnoreAnnotations{
       AidlAnnotation::Type::NULLABLE,
+      // Runtime configuration. We don't usually add these to AIDL because
+      // they are not part of the API, but in some cases, it's not possible
+      // to implement features without changes
+      AidlAnnotation::Type::SENSITIVE_DATA,
       // @JavaDerive doesn't affect read/write
       AidlAnnotation::Type::JAVA_DERIVE,
       AidlAnnotation::Type::JAVA_DEFAULT,
@@ -187,7 +191,8 @@ static bool are_compatible_interfaces(const AidlInterface& older, const AidlInte
     // has happened.
     const auto new_m = found->second;
 
-    if (old_m->IsOneway() != new_m->IsOneway()) {
+    // Adding oneway is an incompatible change, but removing oneway is not .
+    if (!old_m->IsOneway() && new_m->IsOneway()) {
       AIDL_ERROR(new_m) << "Oneway attribute " << (old_m->IsOneway() ? "removed" : "added") << ": "
                         << older.GetCanonicalName() << "." << old_m->Signature();
       compatible = false;
diff --git a/aidl_const_expressions.cpp b/aidl_const_expressions.cpp
index 7de68d37..b2a4c55a 100644
--- a/aidl_const_expressions.cpp
+++ b/aidl_const_expressions.cpp
@@ -1140,6 +1140,13 @@ bool AidlBinaryConstExpression::evaluate() const {
     return true;
   }
 
+  if (left_val_->final_type_ == Type::ARRAY) {
+    AIDL_ERROR(this) << "Operation '" << op_ << "' is not supported with array literals";
+    final_type_ = Type::ERROR;
+    is_valid_ = false;
+    return false;
+  }
+
   // CASE: + - *  / % | ^ & < > <= >= == !=
   if (isArithmeticOrBitflip || OP_IS_BIN_COMP) {
     // promoted kind for both operands.
diff --git a/aidl_language.h b/aidl_language.h
index 8d25e619..5a724c57 100644
--- a/aidl_language.h
+++ b/aidl_language.h
@@ -167,7 +167,7 @@ class AidlNode {
   static void ClearUnvisitedNodes();
   static const std::vector<AidlLocation>& GetLocationsOfUnvisitedNodes();
   void MarkVisited() const;
-  bool IsUserDefined() const { return !GetLocation().IsInternal(); }
+  bool IsUserDefined() const { return !GetLocation().IsInternal() && !GetLocation().IsDerived(); }
 
  private:
   std::string PrintLine() const;
diff --git a/aidl_to_common.h b/aidl_to_common.h
index 93f6a87f..c5cfba9d 100644
--- a/aidl_to_common.h
+++ b/aidl_to_common.h
@@ -33,6 +33,12 @@ enum class CommunicationSide {
   BOTH = WRITE | READ,
 };
 
+constexpr const char* kDowngradeComment =
+    "// Interface is being downgraded to the last frozen version due to\n"
+    "// RELEASE_AIDL_USE_UNFROZEN. See\n"
+    "// "
+    "https://source.android.com/docs/core/architecture/aidl/stable-aidl#flag-based-development\n";
+
 constexpr int kDowngradeCommunicationBitmap = static_cast<int>(CommunicationSide::BOTH);
 
 // This is used when adding the trunk stable downgrade to unfrozen interfaces.
diff --git a/aidl_to_cpp_common.cpp b/aidl_to_cpp_common.cpp
index 24716a3c..eb6163d1 100644
--- a/aidl_to_cpp_common.cpp
+++ b/aidl_to_cpp_common.cpp
@@ -15,13 +15,12 @@
  */
 #include "aidl_to_cpp_common.h"
 
-#include <android-base/format.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 
+#include <format>
 #include <limits>
 #include <set>
-#include <unordered_map>
 
 #include "comments.h"
 #include "logging.h"
@@ -353,12 +352,12 @@ void GenerateParcelableComparisonOperators(CodeWriter& out, const AidlParcelable
     auto name = parcelable.GetName();
     auto max_tag = parcelable.GetFields().back()->GetName();
     auto min_tag = parcelable.GetFields().front()->GetName();
-    constexpr auto tmpl = R"--(static int _cmp(const {name}& _lhs, const {name}& _rhs) {{
-  return _cmp_value(_lhs.getTag(), _rhs.getTag()) || _cmp_value_at<{max_tag}>(_lhs, _rhs);
+    constexpr auto tmpl = R"--(static int _cmp(const {0}& _lhs, const {0}& _rhs) {{
+  return _cmp_value(_lhs.getTag(), _rhs.getTag()) || _cmp_value_at<{2}>(_lhs, _rhs);
 }}
 template <Tag _Tag>
-static int _cmp_value_at(const {name}& _lhs, const {name}& _rhs) {{
-  if constexpr (_Tag == {min_tag}) {{
+static int _cmp_value_at(const {0}& _lhs, const {0}& _rhs) {{
+  if constexpr (_Tag == {1}) {{
     return _cmp_value(_lhs.get<_Tag>(), _rhs.get<_Tag>());
   }} else {{
     return (_lhs.getTag() == _Tag)
@@ -371,8 +370,7 @@ static int _cmp_value(const _Type& _lhs, const _Type& _rhs) {{
   return (_lhs == _rhs) ? 0 : (_lhs < _rhs) ? -1 : 1;
 }}
 )--";
-    out << fmt::format(tmpl, fmt::arg("name", name), fmt::arg("min_tag", min_tag),
-                       fmt::arg("max_tag", max_tag));
+    out << std::format(tmpl, name, min_tag, max_tag);
     for (const auto& op : operators) {
       out << "inline bool operator" << op << "(const " << name << "&_rhs) const {\n";
       out << "  return _cmp(*this, _rhs) " << op << " 0;\n";
@@ -410,20 +408,20 @@ static int _cmp_value(const _Type& _lhs, const _Type& _rhs) {{
   }
   // Delegate other ops to < and == for *this, which lets a custom parcelable
   // to be used with structured parcelables without implementation all operations.
-  out << fmt::format(R"--(inline bool operator!=(const {name}& _rhs) const {{
+  out << std::format(R"--(inline bool operator!=(const {0}& _rhs) const {{
   return !(*this == _rhs);
 }}
-inline bool operator>(const {name}& _rhs) const {{
+inline bool operator>(const {0}& _rhs) const {{
   return _rhs < *this;
 }}
-inline bool operator>=(const {name}& _rhs) const {{
+inline bool operator>=(const {0}& _rhs) const {{
   return !(*this < _rhs);
 }}
-inline bool operator<=(const {name}& _rhs) const {{
+inline bool operator<=(const {0}& _rhs) const {{
   return !(_rhs < *this);
 }}
 )--",
-                     fmt::arg("name", parcelable.GetName()));
+                     parcelable.GetName());
   out << "\n";
 }
 
@@ -697,19 +695,19 @@ void UnionWriter::PublicFields(CodeWriter& out) const {
   }
 
   const auto& name = decl.GetName();
+  vector<string> field_types;
+  for (const auto& f : decl.GetFields()) {
+    field_types.push_back(name_of(f->GetType(), typenames));
+  }
+  auto typelist = Join(field_types, ", ");
 
   if (decl.IsFixedSize()) {
-    vector<string> field_types;
-    for (const auto& f : decl.GetFields()) {
-      field_types.push_back(name_of(f->GetType(), typenames));
-    }
-    auto typelist = Join(field_types, ", ");
     constexpr auto tmpl = R"--(
 template <Tag _Tag>
-using _at = typename std::tuple_element<static_cast<size_t>(_Tag), std::tuple<{typelist}>>::type;
+using _at = typename std::tuple_element<static_cast<size_t>(_Tag), std::tuple<{1}>>::type;
 template <Tag _Tag, typename _Type>
-static {name} make(_Type&& _arg) {{
-  {name} _inst;
+static {0} make(_Type&& _arg) {{
+  {0} _inst;
   _inst.set<_Tag>(std::forward<_Type>(_arg));
   return _inst;
 }}
@@ -732,7 +730,7 @@ void set(_Type&& _arg) {{
   get<_Tag>() = std::forward<_Type>(_arg);
 }}
 )--";
-    out << fmt::format(tmpl, fmt::arg("name", name), fmt::arg("typelist", typelist));
+    out << std::format(tmpl, name, typelist);
   } else {
     AIDL_FATAL_IF(decl.GetFields().empty(), decl) << "Union '" << name << "' is empty.";
     const auto& first_field = decl.GetFields()[0];
@@ -742,27 +740,30 @@ void set(_Type&& _arg) {{
 
     constexpr auto tmpl = R"--(
 template<typename _Tp>
-static constexpr bool _not_self = !std::is_same_v<std::remove_cv_t<std::remove_reference_t<_Tp>>, {name}>;
+static constexpr bool _not_self = !std::is_same_v<std::remove_cv_t<std::remove_reference_t<_Tp>>, {0}>;
 
-{name}() : _value(std::in_place_index<static_cast<size_t>({default_name})>, {default_value}) {{ }}
+{0}() : _value(std::in_place_index<static_cast<size_t>({1})>, {2}) {{ }}
 
-template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+template <typename _Tp, typename = std::enable_if_t<
+    _not_self<_Tp> &&
+    std::is_constructible_v<std::variant<{3}>, _Tp>
+  >>
 // NOLINTNEXTLINE(google-explicit-constructor)
-constexpr {name}(_Tp&& _arg)
+constexpr {0}(_Tp&& _arg)
     : _value(std::forward<_Tp>(_arg)) {{}}
 
 template <size_t _Np, typename... _Tp>
-constexpr explicit {name}(std::in_place_index_t<_Np>, _Tp&&... _args)
+constexpr explicit {0}(std::in_place_index_t<_Np>, _Tp&&... _args)
     : _value(std::in_place_index<_Np>, std::forward<_Tp>(_args)...) {{}}
 
 template <Tag _tag, typename... _Tp>
-static {name} make(_Tp&&... _args) {{
-  return {name}(std::in_place_index<static_cast<size_t>(_tag)>, std::forward<_Tp>(_args)...);
+static {0} make(_Tp&&... _args) {{
+  return {0}(std::in_place_index<static_cast<size_t>(_tag)>, std::forward<_Tp>(_args)...);
 }}
 
 template <Tag _tag, typename _Tp, typename... _Up>
-static {name} make(std::initializer_list<_Tp> _il, _Up&&... _args) {{
-  return {name}(std::in_place_index<static_cast<size_t>(_tag)>, std::move(_il), std::forward<_Up>(_args)...);
+static {0} make(std::initializer_list<_Tp> _il, _Up&&... _args) {{
+  return {0}(std::in_place_index<static_cast<size_t>(_tag)>, std::move(_il), std::forward<_Up>(_args)...);
 }}
 
 Tag getTag() const {{
@@ -787,8 +788,7 @@ void set(_Tp&&... _args) {{
 }}
 
 )--";
-    out << fmt::format(tmpl, fmt::arg("name", name), fmt::arg("default_name", default_name),
-                       fmt::arg("default_value", default_value));
+    out << std::format(tmpl, name, default_name, default_value, typelist);
   }
 }
 
@@ -802,41 +802,41 @@ void UnionWriter::ReadFromParcel(CodeWriter& out, const ParcelWriterContext& ctx
   const string status = "_aidl_ret_status";
 
   auto read_var = [&](const string& var, const AidlTypeSpecifier& type) {
-    out << fmt::format("{} {};\n", name_of(type, typenames), var);
-    out << fmt::format("if (({} = ", status);
+    out << std::format("{} {};\n", name_of(type, typenames), var);
+    out << std::format("if (({} = ", status);
     ctx.read_func(out, var, type);
-    out << fmt::format(") != {}) return {};\n", ctx.status_ok, status);
+    out << std::format(") != {}) return {};\n", ctx.status_ok, status);
   };
 
-  out << fmt::format("{} {};\n", ctx.status_type, status);
+  out << std::format("{} {};\n", ctx.status_type, status);
   read_var(tag, *tag_type);
-  out << fmt::format("switch (static_cast<Tag>({})) {{\n", tag);
+  out << std::format("switch (static_cast<Tag>({})) {{\n", tag);
   for (const auto& variable : decl.GetFields()) {
-    out << fmt::format("case {}: {{\n", variable->GetName());
+    out << std::format("case {}: {{\n", variable->GetName());
     out.Indent();
     if (variable->IsNew()) {
-      out << fmt::format("if (true) return {};\n", ctx.status_bad);
+      out << std::format("if (true) return {};\n", ctx.status_bad);
     }
     const auto& type = variable->GetType();
     read_var(value, type);
-    out << fmt::format("if constexpr (std::is_trivially_copyable_v<{}>) {{\n",
+    out << std::format("if constexpr (std::is_trivially_copyable_v<{}>) {{\n",
                        name_of(type, typenames));
     out.Indent();
-    out << fmt::format("set<{}>({});\n", variable->GetName(), value);
+    out << std::format("set<{}>({});\n", variable->GetName(), value);
     out.Dedent();
     out << "} else {\n";
     out.Indent();
     // Even when the `if constexpr` is false, the compiler runs the tidy check for the
     // next line, which doesn't make sense. Silence the check for the unreachable code.
     out << "// NOLINTNEXTLINE(performance-move-const-arg)\n";
-    out << fmt::format("set<{}>(std::move({}));\n", variable->GetName(), value);
+    out << std::format("set<{}>(std::move({}));\n", variable->GetName(), value);
     out.Dedent();
     out << "}\n";
-    out << fmt::format("return {}; }}\n", ctx.status_ok);
+    out << std::format("return {}; }}\n", ctx.status_ok);
     out.Dedent();
   }
   out << "}\n";
-  out << fmt::format("return {};\n", ctx.status_bad);
+  out << std::format("return {};\n", ctx.status_bad);
 }
 
 void UnionWriter::WriteToParcel(CodeWriter& out, const ParcelWriterContext& ctx) const {
@@ -848,10 +848,10 @@ void UnionWriter::WriteToParcel(CodeWriter& out, const ParcelWriterContext& ctx)
   const string value = "_aidl_value";
   const string status = "_aidl_ret_status";
 
-  out << fmt::format("{} {} = ", ctx.status_type, status);
+  out << std::format("{} {} = ", ctx.status_type, status);
   ctx.write_func(out, "static_cast<int32_t>(getTag())", *tag_type);
   out << ";\n";
-  out << fmt::format("if ({} != {}) return {};\n", status, ctx.status_ok, status);
+  out << std::format("if ({} != {}) return {};\n", status, ctx.status_ok, status);
   out << "switch (getTag()) {\n";
   for (const auto& variable : decl.GetFields()) {
     if (variable->IsDeprecated()) {
@@ -859,9 +859,9 @@ void UnionWriter::WriteToParcel(CodeWriter& out, const ParcelWriterContext& ctx)
       out << "#pragma clang diagnostic ignored \"-Wdeprecated-declarations\"\n";
     }
     if (variable->IsNew()) {
-      out << fmt::format("case {}: return true ? {} : ", variable->GetName(), ctx.status_bad);
+      out << std::format("case {}: return true ? {} : ", variable->GetName(), ctx.status_bad);
     } else {
-      out << fmt::format("case {}: return ", variable->GetName());
+      out << std::format("case {}: return ", variable->GetName());
     }
     ctx.write_func(out, "get<" + variable->GetName() + ">()", variable->GetType());
     out << ";\n";
diff --git a/aidl_unittest.cpp b/aidl_unittest.cpp
index 4075b2af..6b851697 100644
--- a/aidl_unittest.cpp
+++ b/aidl_unittest.cpp
@@ -16,11 +16,11 @@
 
 #include "aidl.h"
 
-#include <android-base/format.h>
 #include <android-base/stringprintf.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 
+#include <format>
 #include <map>
 #include <memory>
 #include <set>
@@ -63,14 +63,14 @@ namespace aidl {
 namespace {
 
 const char kExpectedDepFileContents[] =
-R"(place/for/output/p/IFoo.java : \
+    R"(place/for/output/p/IFoo.java : \
   p/IFoo.aidl
 
 p/IFoo.aidl :
 )";
 
 const char kExpectedNinjaDepFileContents[] =
-R"(place/for/output/p/IFoo.java : \
+    R"(place/for/output/p/IFoo.java : \
   p/IFoo.aidl
 )";
 
@@ -854,8 +854,9 @@ TEST_F(AidlTest, ParsesPreprocessedFileWithWhitespace) {
 
 TEST_P(AidlTest, PreferImportToPreprocessed) {
   io_delegate_.SetFileContents("preprocessed", "interface another.IBar;");
-  io_delegate_.SetFileContents("one/IBar.aidl", "package one; "
-                                                "interface IBar {}");
+  io_delegate_.SetFileContents("one/IBar.aidl",
+                               "package one; "
+                               "interface IBar {}");
   preprocessed_files_.push_back("preprocessed");
   import_paths_.emplace("");
   auto parse_result = Parse("p/IFoo.aidl", "package p; import one.IBar; interface IFoo {}",
@@ -894,10 +895,10 @@ TEST_P(AidlTest, B147918827) {
 }
 
 TEST_F(AidlTest, WritePreprocessedFile) {
-  io_delegate_.SetFileContents("p/Outer.aidl",
-                               "package p; parcelable Outer.Inner;");
-  io_delegate_.SetFileContents("one/IBar.aidl", "package one; import p.Outer;"
-                                                "interface IBar {}");
+  io_delegate_.SetFileContents("p/Outer.aidl", "package p; parcelable Outer.Inner;");
+  io_delegate_.SetFileContents("one/IBar.aidl",
+                               "package one; import p.Outer;"
+                               "interface IBar {}");
 
   vector<string> args{"aidl", "--preprocess", "preprocessed",
                       "-I.",  "p/Outer.aidl", "one/IBar.aidl"};
@@ -1225,8 +1226,7 @@ TEST_P(AidlTest, RequireOuterClass) {
   const string expected_stderr =
       "ERROR: p/IFoo.aidl: Couldn't find import for class Inner. Searched here:\n - ./\nERROR: "
       "p/IFoo.aidl:1.54-60: Failed to resolve 'Inner'\n";
-  io_delegate_.SetFileContents("p/Outer.aidl",
-                               "package p; parcelable Outer.Inner;");
+  io_delegate_.SetFileContents("p/Outer.aidl", "package p; parcelable Outer.Inner;");
   import_paths_.emplace("");
   CaptureStderr();
   EXPECT_EQ(nullptr, Parse("p/IFoo.aidl",
@@ -1795,8 +1795,9 @@ TEST_P(AidlTest, UnderstandsNestedUnstructuredParcelables) {
                                "ndk_header \"ndk/baz/header\" rust_type \"baz::Inner\";");
   import_paths_.emplace("");
   const string input_path = "p/IFoo.aidl";
-  const string input = "package p; import p.Outer; interface IFoo"
-                       " { Outer.Inner get(); }";
+  const string input =
+      "package p; import p.Outer; interface IFoo"
+      " { Outer.Inner get(); }";
 
   auto parse_result = Parse(input_path, input, typenames_, GetLanguage());
   EXPECT_NE(nullptr, parse_result);
@@ -2316,9 +2317,8 @@ TEST_F(AidlTest, CppNameOf_GenericType) {
 }
 
 TEST_P(AidlTest, UnderstandsNativeParcelables) {
-  io_delegate_.SetFileContents(
-      "p/Bar.aidl",
-      "package p; parcelable Bar cpp_header \"baz/header\";");
+  io_delegate_.SetFileContents("p/Bar.aidl",
+                               "package p; parcelable Bar cpp_header \"baz/header\";");
   import_paths_.emplace("");
   const string input_path = "p/IFoo.aidl";
   const string input = "package p; import p.Bar; interface IFoo { }";
@@ -2556,8 +2556,8 @@ TEST_F(AidlTest, ApiDump) {
                                "   @nullable String[] c;\n"
                                "}\n");
   io_delegate_.SetFileContents("api.aidl", "");
-  vector<string> args = {"aidl", "--dumpapi", "--out=dump", "--include=.",
-                         "foo/bar/IFoo.aidl", "foo/bar/Data.aidl"};
+  vector<string> args = {"aidl",        "--dumpapi",         "--out=dump",
+                         "--include=.", "foo/bar/IFoo.aidl", "foo/bar/Data.aidl"};
   Options options = Options::From(args);
   bool result = dump_api(options, io_delegate_);
   ASSERT_TRUE(result);
@@ -2598,14 +2598,13 @@ parcelable Data {
 }
 
 TEST_F(AidlTest, ApiDumpWithManualIds) {
-  io_delegate_.SetFileContents(
-      "foo/bar/IFoo.aidl",
-      "package foo.bar;\n"
-      "interface IFoo {\n"
-      "    int foo() = 1;\n"
-      "    int bar() = 2;\n"
-      "    int baz() = 10;\n"
-      "}\n");
+  io_delegate_.SetFileContents("foo/bar/IFoo.aidl",
+                               "package foo.bar;\n"
+                               "interface IFoo {\n"
+                               "    int foo() = 1;\n"
+                               "    int bar() = 2;\n"
+                               "    int baz() = 10;\n"
+                               "}\n");
 
   vector<string> args = {"aidl", "-I . ", "--dumpapi", "-o dump", "foo/bar/IFoo.aidl"};
   Options options = Options::From(args);
@@ -2626,14 +2625,13 @@ TEST_F(AidlTest, ApiDumpWithManualIdsOnlyOnSomeMethods) {
   const string expected_stderr =
       "ERROR: foo/bar/IFoo.aidl:4.8-12: You must either assign id's to all methods or to none of "
       "them.\n";
-  io_delegate_.SetFileContents(
-      "foo/bar/IFoo.aidl",
-      "package foo.bar;\n"
-      "interface IFoo {\n"
-      "    int foo() = 1;\n"
-      "    int bar();\n"
-      "    int baz() = 10;\n"
-      "}\n");
+  io_delegate_.SetFileContents("foo/bar/IFoo.aidl",
+                               "package foo.bar;\n"
+                               "interface IFoo {\n"
+                               "    int foo() = 1;\n"
+                               "    int bar();\n"
+                               "    int baz() = 10;\n"
+                               "}\n");
 
   vector<string> args = {"aidl", "-I . ", "--dumpapi", "-o dump", "foo/bar/IFoo.aidl"};
   Options options = Options::From(args);
@@ -2897,24 +2895,23 @@ TEST_P(AidlTest, FailParseOnEmptyFile) {
 }
 
 TEST_F(AidlTest, MultipleInputFiles) {
-  Options options = Options::From(
-      "aidl --lang=java -o out -I . foo/bar/IFoo.aidl foo/bar/Data.aidl");
+  Options options =
+      Options::From("aidl --lang=java -o out -I . foo/bar/IFoo.aidl foo/bar/Data.aidl");
 
   io_delegate_.SetFileContents(options.InputFiles().at(0),
-      "package foo.bar;\n"
-      "import foo.bar.Data;\n"
-      "interface IFoo { Data getData(); }\n");
+                               "package foo.bar;\n"
+                               "import foo.bar.Data;\n"
+                               "interface IFoo { Data getData(); }\n");
 
   io_delegate_.SetFileContents(options.InputFiles().at(1),
-        "package foo.bar;\n"
-        "import foo.bar.IFoo;\n"
-        "parcelable Data { IFoo foo; }\n");
+                               "package foo.bar;\n"
+                               "import foo.bar.IFoo;\n"
+                               "parcelable Data { IFoo foo; }\n");
 
   EXPECT_TRUE(compile_aidl(options, io_delegate_));
 
   string content;
-  for (const auto file : {
-    "out/foo/bar/IFoo.java", "out/foo/bar/Data.java"}) {
+  for (const auto file : {"out/foo/bar/IFoo.java", "out/foo/bar/Data.java"}) {
     content.clear();
     EXPECT_TRUE(io_delegate_.GetWrittenContents(file, &content));
     EXPECT_FALSE(content.empty());
@@ -2927,23 +2924,22 @@ TEST_F(AidlTest, MultipleInputFilesCpp) {
       "-I . foo/bar/IFoo.aidl foo/bar/Data.aidl");
 
   io_delegate_.SetFileContents(options.InputFiles().at(0),
-      "package foo.bar;\n"
-      "import foo.bar.Data;\n"
-      "interface IFoo { Data getData(); }\n");
+                               "package foo.bar;\n"
+                               "import foo.bar.Data;\n"
+                               "interface IFoo { Data getData(); }\n");
 
   io_delegate_.SetFileContents(options.InputFiles().at(1),
-        "package foo.bar;\n"
-        "import foo.bar.IFoo;\n"
-        "parcelable Data { IFoo foo; }\n");
+                               "package foo.bar;\n"
+                               "import foo.bar.IFoo;\n"
+                               "parcelable Data { IFoo foo; }\n");
 
   EXPECT_TRUE(compile_aidl(options, io_delegate_));
 
   string content;
-  for (const auto file : {
-    "out/foo/bar/IFoo.cpp", "out/foo/bar/Data.cpp",
-    "out/include/foo/bar/IFoo.h", "out/include/foo/bar/Data.h",
-    "out/include/foo/bar/BpFoo.h", "out/include/foo/bar/BpData.h",
-    "out/include/foo/bar/BnFoo.h", "out/include/foo/bar/BnData.h"}) {
+  for (const auto file :
+       {"out/foo/bar/IFoo.cpp", "out/foo/bar/Data.cpp", "out/include/foo/bar/IFoo.h",
+        "out/include/foo/bar/Data.h", "out/include/foo/bar/BpFoo.h", "out/include/foo/bar/BpData.h",
+        "out/include/foo/bar/BnFoo.h", "out/include/foo/bar/BnData.h"}) {
     content.clear();
     EXPECT_TRUE(io_delegate_.GetWrittenContents(file, &content));
     EXPECT_FALSE(content.empty());
@@ -3401,6 +3397,22 @@ TEST_F(AidlTestIncompatibleChanges, RemovedType) {
   EXPECT_EQ(expected_stderr, GetCapturedStderr());
 }
 
+TEST_F(AidlTestIncompatibleChanges, RemovedTypeNotInternal) {
+  // We create new Tag enums internal to unions and they show up in these logs
+  const string expected_stderr =
+      "ERROR: old/p/Foo.aidl:1.16-20: Removed type: p.Foo\n"
+      "ERROR: (derived from)old/p/Foo.aidl:1.16-20: Removed type: p.Foo.Tag\n";
+  io_delegate_.SetFileContents("old/p/Foo.aidl",
+                               "package p;"
+                               "union Foo {"
+                               "  int foo;"
+                               "  int bar;"
+                               "}");
+  CaptureStderr();
+  EXPECT_FALSE(::android::aidl::check_api(options_, io_delegate_));
+  EXPECT_EQ(expected_stderr, GetCapturedStderr());
+}
+
 TEST_F(AidlTestIncompatibleChanges, RemovedMethod) {
   const string expected_stderr =
       "ERROR: old/p/IFoo.aidl:1.61-65: Removed or changed method: p.IFoo.bar(String)\n";
@@ -3556,7 +3568,8 @@ TEST_F(AidlTestIncompatibleChanges, RemovedEnumerator) {
 
 TEST_F(AidlTestIncompatibleChanges, RemovedUnionField) {
   const string expected_stderr =
-      "ERROR: new/p/Union.aidl:1.16-22: Number of fields in p.Union is reduced from 2 to 1.\n";
+      "ERROR: new/p/Union.aidl:1.16-22: Number of fields in p.Union is reduced from 2 to 1.\n"
+      "ERROR: (derived from)new/p/Union.aidl:1.16-22: Removed enumerator from p.Union.Tag: num\n";
   io_delegate_.SetFileContents("old/p/Union.aidl",
                                "package p;"
                                "union Union {"
@@ -3911,6 +3924,22 @@ TEST_F(AidlTestIncompatibleChanges, IncompatibleChangesInNestedType) {
   EXPECT_THAT(GetCapturedStderr(), HasSubstr("Removed or changed method: p.Foo.IBar.foo()"));
 }
 
+TEST_F(AidlTestIncompatibleChanges, IncompatibleTwoWayToOneWay) {
+  io_delegate_.SetFileContents("old/p/IFoo.aidl", "package p; interface IFoo{ void foo();}");
+  io_delegate_.SetFileContents("new/p/IFoo.aidl", "package p; interface IFoo{ oneway void foo();}");
+
+  CaptureStderr();
+  EXPECT_FALSE(::android::aidl::check_api(options_, io_delegate_));
+  EXPECT_THAT(GetCapturedStderr(), HasSubstr("Oneway attribute added: p.IFoo.foo()"));
+}
+
+TEST_F(AidlTestCompatibleChanges, CompatibleOneWayToTwoWay) {
+  io_delegate_.SetFileContents("old/p/IFoo.aidl", "package p; interface IFoo{ oneway void foo();}");
+  io_delegate_.SetFileContents("new/p/IFoo.aidl", "package p; interface IFoo{ void foo();}");
+
+  EXPECT_TRUE(::android::aidl::check_api(options_, io_delegate_));
+}
+
 TEST_P(AidlTest, RejectNonFixedSizeFromFixedSize) {
   const string expected_stderr =
       "ERROR: Foo.aidl:2.8-10: The @FixedSize parcelable 'Foo' has a non-fixed size field named "
@@ -4209,7 +4238,7 @@ TEST_F(AidlTest, UnusedImportDoesNotContributeInclude) {
 TEST_F(AidlTest, BasePathAsImportPath) {
   Options options = Options::From("aidl --lang=java -I some -I other some/dir/pkg/name/IFoo.aidl");
   io_delegate_.SetFileContents("some/dir/pkg/name/IFoo.aidl",
-      "package pkg.name; interface IFoo { void foo(); }");
+                               "package pkg.name; interface IFoo { void foo(); }");
   const string expected_stderr =
       "ERROR: some/dir/pkg/name/IFoo.aidl:1.18-28: directory some/dir/ is not found in any of "
       "the import paths:\n - other/\n - some/\n";
@@ -5498,6 +5527,17 @@ TEST_P(AidlTest, UnknownConstReference) {
   EXPECT_EQ(err, GetCapturedStderr());
 }
 
+TEST_P(AidlTest, ConstExpressionArrays) {
+  io_delegate_.SetFileContents("Foo.aidl", " parcelable Foo { int[] field = {} - {1,2}; }");
+  auto options =
+      Options::From("aidl -I . --lang " + to_string(GetLanguage()) + " -o out -h out Foo.aidl");
+  const string err =
+      "ERROR: Foo.aidl:1.32-35: Operation '-' is not supported with array literals\n";
+  CaptureStderr();
+  EXPECT_FALSE(compile_aidl(options, io_delegate_));
+  EXPECT_EQ(err, GetCapturedStderr());
+}
+
 TEST_P(AidlTest, JavaCompatibleBuiltinTypes) {
   string contents = R"(
 import android.os.IBinder;
@@ -5856,13 +5896,14 @@ class AidlTypeParamTest
     io.SetFileContents("a/Enum.aidl", "package a; enum Enum { A }");
     io.SetFileContents("a/Union.aidl", "package a; union Union { int a; }");
     io.SetFileContents("a/Foo.aidl", "package a; parcelable Foo { int a; }");
-    std::string decl = fmt::format(fmt::runtime(generic_type_decl), std::get<1>(param).literal);
+    std::string decl =
+        std::vformat(generic_type_decl, std::make_format_args(std::get<1>(param).literal));
     if (nullable) {
       decl = "@nullable " + decl;
     }
     io.SetFileContents("a/Target.aidl", "package a; parcelable Target { " + decl + " f; }");
 
-    const auto options = Options::From(fmt::format(
+    const auto options = Options::From(std::format(
         "aidl -I . --min_sdk_version current --lang={} a/Target.aidl -o out -h out", lang));
     CaptureStderr();
     compile_aidl(options, io);
diff --git a/build/aidl_api.go b/build/aidl_api.go
index 0913bd38..644e021a 100644
--- a/build/aidl_api.go
+++ b/build/aidl_api.go
@@ -685,8 +685,9 @@ type freezeApiSingleton struct{}
 func (f *freezeApiSingleton) GenerateBuildActions(ctx android.SingletonContext) {
 	ownersToFreeze := strings.Fields(ctx.Config().Getenv("AIDL_FREEZE_OWNERS"))
 	var files android.Paths
-	ctx.VisitAllModules(func(module android.Module) {
-		if !module.Enabled(ctx) {
+	ctx.VisitAllModuleProxies(func(module android.ModuleProxy) {
+		commonInfo := android.OtherModulePointerProviderOrDefault(ctx, module, android.CommonModuleInfoProvider)
+		if !commonInfo.Enabled {
 			return
 		}
 		if apiInfo, ok := android.OtherModuleProvider(ctx, module, aidlApiProvider); ok {
@@ -695,9 +696,9 @@ func (f *freezeApiSingleton) GenerateBuildActions(ctx android.SingletonContext)
 			}
 			var shouldBeFrozen bool
 			if len(ownersToFreeze) > 0 {
-				shouldBeFrozen = android.InList(module.Owner(), ownersToFreeze)
+				shouldBeFrozen = android.InList(commonInfo.Owner, ownersToFreeze)
 			} else {
-				shouldBeFrozen = module.Owner() == ""
+				shouldBeFrozen = commonInfo.Owner == ""
 			}
 			if shouldBeFrozen {
 				files = append(files, apiInfo.FreezeApiTimestamp)
diff --git a/build/aidl_interface.go b/build/aidl_interface.go
index 8b42200a..14ac3fb2 100644
--- a/build/aidl_interface.go
+++ b/build/aidl_interface.go
@@ -281,6 +281,15 @@ type DumpApiProperties struct {
 }
 
 type aidlInterfaceProperties struct {
+	// AIDL generates modules with '(-V[0-9]+)-<backend>' names. To see all possible variants,
+	// try `allmod | grep <name>` where 'name' is the name of your aidl_interface. See
+	// also backend-specific documentation.
+	//
+	// aidl_interface name is recommended to be the package name, for consistency.
+	//
+	// Name must be unique across all modules of all types.
+	Name *string
+
 	// Whether the library can be installed on the vendor image.
 	Vendor_available *bool
 
@@ -368,7 +377,8 @@ type aidlInterfaceProperties struct {
 
 	Backend struct {
 		// Backend of the compiler generating code for Java clients.
-		// When enabled, this creates a target called "<name>-java".
+		// When enabled, this creates a target called "<name>-java"
+		// or, if there are versions, "<name>-V[0-9]+-java".
 		Java struct {
 			CommonBackendProperties
 			// Additional java libraries, for unstructured parcelables
@@ -387,16 +397,16 @@ type aidlInterfaceProperties struct {
 		}
 		// Backend of the compiler generating code for C++ clients using
 		// libbinder (unstable C++ interface)
-		// When enabled, this creates a target called "<name>-cpp".
+		// When enabled, this creates a target called "<name>-cpp"
+		// or, if there are versions, "<name>-V[0-9]+-cpp".
 		Cpp struct {
 			CommonNativeBackendProperties
 		}
 		// Backend of the compiler generating code for C++ clients using libbinder_ndk
 		// (stable C interface to system's libbinder) When enabled, this creates a target
 		// called "<name>-V<ver>-ndk" (for both apps and platform) and
-		// "<name>-V<ver>-ndk_platform" (for platform only).
-		// TODO(b/161456198): remove the ndk_platform backend as the ndk backend can serve
-		// the same purpose.
+		// "<name>-V<ver>-ndk_platform" (for platform only)
+		// or, if there are versions, "<name>-V[0-9]+-ndk...".
 		Ndk struct {
 			CommonNativeBackendProperties
 
@@ -411,7 +421,8 @@ type aidlInterfaceProperties struct {
 			Apps_enabled *bool
 		}
 		// Backend of the compiler generating code for Rust clients.
-		// When enabled, this creates a target called "<name>-rust".
+		// When enabled, this creates a target called "<name>-rust"
+		// or, if there are versions, "<name>-V[0-9]+-rust".
 		Rust struct {
 			CommonBackendProperties
 
diff --git a/build/aidl_test.go b/build/aidl_test.go
index 2ace3f68..e6b5c459 100644
--- a/build/aidl_test.go
+++ b/build/aidl_test.go
@@ -1141,7 +1141,7 @@ func TestNativeOutputIsAlwaysVersioned(t *testing.T) {
 	var ctx *android.TestContext
 	assertOutput := func(moduleName, variant, outputFilename string) {
 		t.Helper()
-		paths := ctx.ModuleForTests(moduleName, variant).OutputFiles(ctx, t, "")
+		paths := ctx.ModuleForTests(t, moduleName, variant).OutputFiles(ctx, t, "")
 		if len(paths) != 1 || paths[0].Base() != outputFilename {
 			t.Errorf("%s(%s): expected output %q, but got %v", moduleName, variant, outputFilename, paths)
 		}
@@ -1318,17 +1318,17 @@ func TestImports(t *testing.T) {
 		}
 	`)
 
-	ldRule := ctx.ModuleForTests("foo-V1-cpp", nativeVariant).Rule("ld")
+	ldRule := ctx.ModuleForTests(t, "foo-V1-cpp", nativeVariant).Rule("ld")
 	libFlags := ldRule.Args["libFlags"]
 	libBar := filepath.Join("bar.1-V1-cpp", nativeVariant, "bar.1-V1-cpp.so")
 	if !strings.Contains(libFlags, libBar) {
 		t.Errorf("%q is not found in %q", libBar, libFlags)
 	}
 
-	rustcRule := ctx.ModuleForTests("foo-V1-rust", nativeRustVariant).Rule("rustc")
+	rustcRule := ctx.ModuleForTests(t, "foo-V1-rust", nativeRustVariant).Rule("rustc")
 	libFlags = rustcRule.Args["libFlags"]
 	libBar = filepath.Join("out", "soong", ".intermediates", "bar.1-V1-rust", nativeRustVariant, "unstripped", "libbar_1_V1.dylib.so")
-	libBarFlag := "--extern bar_1=" + libBar
+	libBarFlag := "--extern force:bar_1=" + libBar
 	if !strings.Contains(libFlags, libBarFlag) {
 		t.Errorf("%q is not found in %q", libBarFlag, libFlags)
 	}
@@ -1475,8 +1475,8 @@ func TestRecoveryAvailable(t *testing.T) {
 			srcs: ["IFoo.aidl"],
 		}
 	`)
-	ctx.ModuleForTests("myiface-V1-ndk", "android_recovery_arm64_armv8-a_shared")
-	ctx.ModuleForTests("myiface-V1-cpp", "android_recovery_arm64_armv8-a_shared")
+	ctx.ModuleForTests(t, "myiface-V1-ndk", "android_recovery_arm64_armv8-a_shared")
+	ctx.ModuleForTests(t, "myiface-V1-cpp", "android_recovery_arm64_armv8-a_shared")
 }
 
 func TestRustDuplicateNames(t *testing.T) {
@@ -1547,7 +1547,7 @@ func TestAidlImportFlagsForImportedModules(t *testing.T) {
 
 	// checkapidump rule is to compare "compatibility" between ToT(dump) and "current"
 	{
-		rule := ctx.ModuleForTests("foo-iface_interface", "").Output("checkapi_dump.timestamp")
+		rule := ctx.ModuleForTests(t, "foo-iface_interface", "").Output("checkapi_dump.timestamp")
 		android.AssertStringEquals(t, "checkapi(dump == current) imports", "-Iboq", rule.Args["imports"])
 		android.AssertStringDoesContain(t, "checkapi(dump == current) optionalFlags",
 			rule.Args["optionalFlags"],
@@ -1557,7 +1557,7 @@ func TestAidlImportFlagsForImportedModules(t *testing.T) {
 	// has_development rule runs --checkapi for equality between latest("1")
 	// and ToT
 	{
-		rule := ctx.ModuleForTests("foo-iface_interface", "").Output("has_development")
+		rule := ctx.ModuleForTests(t, "foo-iface_interface", "").Output("has_development")
 		android.AssertStringDoesContain(t, "checkapi(dump == latest(1)) should import import's preprocessed",
 			rule.RuleParams.Command,
 			"-pout/soong/.intermediates/bar/bar-iface_interface/2/preprocessed.aidl")
@@ -1565,7 +1565,7 @@ func TestAidlImportFlagsForImportedModules(t *testing.T) {
 
 	// compile (v1)
 	{
-		rule := ctx.ModuleForTests("foo-iface-V1-cpp-source", "").Output("a/Foo.cpp")
+		rule := ctx.ModuleForTests(t, "foo-iface-V1-cpp-source", "").Output("a/Foo.cpp")
 		android.AssertStringEquals(t, "compile(old=1) should import aidl_api/1",
 			"-Iboq -Nfoo/aidl_api/foo-iface/1",
 			rule.Args["imports"]+" "+rule.Args["nextImports"])
@@ -1575,7 +1575,7 @@ func TestAidlImportFlagsForImportedModules(t *testing.T) {
 	}
 	// compile ToT(v2)
 	{
-		rule := ctx.ModuleForTests("foo-iface-V2-cpp-source", "").Output("a/Foo.cpp")
+		rule := ctx.ModuleForTests(t, "foo-iface-V2-cpp-source", "").Output("a/Foo.cpp")
 		android.AssertStringEquals(t, "compile(tot=2) should import base dirs of srcs", "-Iboq -Nfoo", rule.Args["imports"]+" "+rule.Args["nextImports"])
 		android.AssertStringDoesContain(t, "compile(tot=2) should import bar.preprocessed",
 			rule.Args["optionalFlags"],
@@ -1615,7 +1615,7 @@ func TestAidlPreprocess(t *testing.T) {
 	})
 	ctx, _ := testAidl(t, ``, customizer)
 
-	rule := ctx.ModuleForTests("foo-iface_interface", "").Output("preprocessed.aidl")
+	rule := ctx.ModuleForTests(t, "foo-iface_interface", "").Output("preprocessed.aidl")
 	android.AssertStringDoesContain(t, "preprocessing should import srcs and include_dirs",
 		rule.RuleParams.Command,
 		"-Ifoo/src -Ipath1 -Ipath2/sub")
@@ -1656,7 +1656,7 @@ func TestAidlImportFlagsForUnstable(t *testing.T) {
 	})
 	ctx, _ := testAidl(t, ``, customizer)
 
-	rule := ctx.ModuleForTests("foo-iface-cpp-source", "").Output("foo/Foo.cpp")
+	rule := ctx.ModuleForTests(t, "foo-iface-cpp-source", "").Output("foo/Foo.cpp")
 	android.AssertStringEquals(t, "compile(unstable) should import foo/base_dirs(target) and bar/base_dirs(imported)",
 		"-Ipath1 -Ipath2/sub -Nfoo/src",
 		rule.Args["imports"]+" "+rule.Args["nextImports"])
@@ -1724,7 +1724,7 @@ func TestSupportsGenruleAndFilegroup(t *testing.T) {
 
 	// aidlCompile for snapshots (v1)
 	{
-		rule := ctx.ModuleForTests("foo-iface-V1-cpp-source", "").Output("foo/Foo.cpp")
+		rule := ctx.ModuleForTests(t, "foo-iface-V1-cpp-source", "").Output("foo/Foo.cpp")
 		android.AssertStringEquals(t, "compile(1) should import foo/aidl_api/1",
 			"-Ipath1 -Ipath2/sub -Nfoo/aidl_api/foo-iface/1",
 			rule.Args["imports"]+" "+rule.Args["nextImports"])
@@ -1734,7 +1734,7 @@ func TestSupportsGenruleAndFilegroup(t *testing.T) {
 	}
 	// aidlCompile for ToT (v2)
 	{
-		rule := ctx.ModuleForTests("foo-iface-V2-cpp-source", "").Output("foo/Foo.cpp")
+		rule := ctx.ModuleForTests(t, "foo-iface-V2-cpp-source", "").Output("foo/Foo.cpp")
 		android.AssertStringEquals(t, "compile(tot=2) should import foo.base_dirs",
 			"-Ipath1 -Ipath2/sub -Nfoo/src -Nfoo/filegroup/sub -Nout/soong/.intermediates/foo/gen1/gen",
 			rule.Args["imports"]+" "+rule.Args["nextImports"])
@@ -1745,7 +1745,7 @@ func TestSupportsGenruleAndFilegroup(t *testing.T) {
 
 	// dumpapi
 	{
-		rule := ctx.ModuleForTests("foo-iface_interface", "").Rule("aidlDumpApiRule")
+		rule := ctx.ModuleForTests(t, "foo-iface_interface", "").Rule("aidlDumpApiRule")
 		android.AssertPathsRelativeToTopEquals(t, "dumpapi should dump srcs/filegroups/genrules", []string{
 			"foo/src/foo/Foo.aidl",
 			"foo/filegroup/sub/pkg/Bar.aidl",
@@ -1786,7 +1786,7 @@ func TestAidlFlags(t *testing.T) {
 	} {
 		for _, output := range outputs {
 			t.Run(module+"/"+output, func(t *testing.T) {
-				params := ctx.ModuleForTests(module, "").Output(output)
+				params := ctx.ModuleForTests(t, module, "").Output(output)
 				assertContains(t, params.Args["optionalFlags"], "-Weverything")
 				assertContains(t, params.Args["optionalFlags"], "-Werror")
 			})
@@ -1806,7 +1806,7 @@ func TestAidlModuleJavaSdkVersionDeterminesMinSdkVersion(t *testing.T) {
 			},
 		}
 	`, java.FixtureWithPrebuiltApis(map[string][]string{"28": {"foo"}}))
-	params := ctx.ModuleForTests("myiface-V1-java-source", "").Output("a/Foo.java")
+	params := ctx.ModuleForTests(t, "myiface-V1-java-source", "").Output("a/Foo.java")
 	assertContains(t, params.Args["optionalFlags"], "--min_sdk_version 28")
 }
 
@@ -1853,7 +1853,7 @@ func TestExplicitAidlModuleImport(t *testing.T) {
 			"aidl_api/bar/1/.hash":    nil,
 		}))
 		for _, foo := range []string{"foo-V1-cpp", "foo-V2-cpp"} {
-			ldRule := ctx.ModuleForTests(foo, nativeVariant).Rule("ld")
+			ldRule := ctx.ModuleForTests(t, foo, nativeVariant).Rule("ld")
 			libFlags := ldRule.Args["libFlags"]
 			libBar := filepath.Join("bar-"+importVersion+"-cpp", nativeVariant, "bar-"+importVersion+"-cpp.so")
 			if !strings.Contains(libFlags, libBar) {
@@ -1943,21 +1943,21 @@ func TestUseVersionedPreprocessedWhenImporotedWithVersions(t *testing.T) {
 		"aidl_api/baz/1/.hash":        nil,
 	}))
 	{
-		rule := ctx.ModuleForTests("foo-V2-java-source", "").Output("foo/Foo.java")
+		rule := ctx.ModuleForTests(t, "foo-V2-java-source", "").Output("foo/Foo.java")
 		android.AssertStringDoesContain(t, "foo-V2(tot) imports bar-V1 for 'bar-V1'", rule.Args["optionalFlags"],
 			"-pout/soong/.intermediates/bar_interface/1/preprocessed.aidl")
 		android.AssertStringDoesContain(t, "foo-V2(tot) imports baz-V1 for 'baz-V1'", rule.Args["optionalFlags"],
 			"-pout/soong/.intermediates/baz_interface/1/preprocessed.aidl")
 	}
 	{
-		rule := ctx.ModuleForTests("foo-V1-java-source", "").Output("foo/Foo.java")
+		rule := ctx.ModuleForTests(t, "foo-V1-java-source", "").Output("foo/Foo.java")
 		android.AssertStringDoesContain(t, "foo-V1 imports bar-V1(latest) for 'bar'", rule.Args["optionalFlags"],
 			"-pout/soong/.intermediates/bar_interface/1/preprocessed.aidl")
 		android.AssertStringDoesContain(t, "foo-V1 imports baz-V1 for 'baz-V1'", rule.Args["optionalFlags"],
 			"-pout/soong/.intermediates/baz_interface/1/preprocessed.aidl")
 	}
 	{
-		rule := ctx.ModuleForTests("unstable-foo-java-source", "").Output("foo/Foo.java")
+		rule := ctx.ModuleForTests(t, "unstable-foo-java-source", "").Output("foo/Foo.java")
 		android.AssertStringDoesContain(t, "unstable-foo imports bar-V2(latest) for 'bar'", rule.Args["optionalFlags"],
 			"-pout/soong/.intermediates/bar_interface/2/preprocessed.aidl")
 		android.AssertStringDoesContain(t, "unstable-foo imports baz-V1 for 'baz-V1'", rule.Args["optionalFlags"],
@@ -1966,13 +1966,14 @@ func TestUseVersionedPreprocessedWhenImporotedWithVersions(t *testing.T) {
 			"-pout/soong/.intermediates/unstable-bar_interface/preprocessed.aidl")
 	}
 	{
-		rule := ctx.ModuleForTests("foo-no-versions-V1-java-source", "").Output("foo/Foo.java")
+		rule := ctx.ModuleForTests(t, "foo-no-versions-V1-java-source", "").Output("foo/Foo.java")
 		android.AssertStringDoesContain(t, "foo-no-versions-V1(latest) imports bar-V2(latest) for 'bar'", rule.Args["optionalFlags"],
 			"-pout/soong/.intermediates/bar_interface/2/preprocessed.aidl")
 	}
 }
 
-func FindModule(ctx *android.TestContext, name, variant, dir string) android.Module {
+func FindModule(t *testing.T, ctx *android.TestContext, name, variant, dir string) android.Module {
+	t.Helper()
 	var module android.Module
 	ctx.VisitAllModules(func(m blueprint.Module) {
 		if ctx.ModuleName(m) == name && ctx.ModuleSubDir(m) == variant && ctx.ModuleDir(m) == dir {
@@ -1980,9 +1981,9 @@ func FindModule(ctx *android.TestContext, name, variant, dir string) android.Mod
 		}
 	})
 	if module == nil {
-		m := ctx.ModuleForTests(name, variant).Module()
-		panic(fmt.Errorf("failed to find module %q variant %q dir %q, but found one in %q",
-			name, variant, dir, ctx.ModuleDir(m)))
+		m := ctx.ModuleForTests(t, name, variant).Module()
+		t.Fatalf("failed to find module %q variant %q dir %q, but found one in %q",
+			name, variant, dir, ctx.ModuleDir(m))
 	}
 	return module
 }
@@ -2024,10 +2025,10 @@ func TestDuplicateInterfacesWithTheSameNameInDifferentSoongNamespaces(t *testing
 		`),
 	}))
 
-	aFooV1Java := FindModule(ctx, "foo-V1-java", "android_common", "vendor/a/foo").(*java.Library)
+	aFooV1Java := FindModule(t, ctx, "foo-V1-java", "android_common", "vendor/a/foo").(*java.Library)
 	android.AssertStringListContains(t, "a/foo deps", aFooV1Java.CompilerDeps(), "common-V1-java")
 
-	bFooV1Java := FindModule(ctx, "foo-V1-java", "android_common", "vendor/b/foo").(*java.Library)
+	bFooV1Java := FindModule(t, ctx, "foo-V1-java", "android_common", "vendor/b/foo").(*java.Library)
 	android.AssertStringListContains(t, "a/foo deps", bFooV1Java.CompilerDeps(), "common-V2-java")
 }
 
@@ -2129,13 +2130,13 @@ func TestVersionsWithInfo(t *testing.T) {
 		"foo/aidl_api/foo/2/.hash":     nil,
 	}))
 
-	fooV1Java := FindModule(ctx, "foo-V1-java", "android_common", "foo").(*java.Library)
+	fooV1Java := FindModule(t, ctx, "foo-V1-java", "android_common", "foo").(*java.Library)
 	android.AssertStringListContains(t, "a/foo-v1 deps", fooV1Java.CompilerDeps(), "common-V1-java")
 
-	fooV2Java := FindModule(ctx, "foo-V2-java", "android_common", "foo").(*java.Library)
+	fooV2Java := FindModule(t, ctx, "foo-V2-java", "android_common", "foo").(*java.Library)
 	android.AssertStringListContains(t, "a/foo-v2 deps", fooV2Java.CompilerDeps(), "common-V2-java")
 
-	fooV3Java := FindModule(ctx, "foo-V3-java", "android_common", "foo").(*java.Library)
+	fooV3Java := FindModule(t, ctx, "foo-V3-java", "android_common", "foo").(*java.Library)
 	android.AssertStringListContains(t, "a/foo-v3 deps", fooV3Java.CompilerDeps(), "common-V3-java")
 }
 
@@ -2215,8 +2216,8 @@ func TestFreezeApiDeps(t *testing.T) {
 
 			ctx, _ := testAidl(t, ``, customizers...)
 			shouldHaveDep := transitive && testcase.bool
-			fooFreezeApiRule := ctx.ModuleForTests("foo_interface", "").Output("update_or_freeze_api_3.timestamp")
-			commonFreezeApiOutput := ctx.ModuleForTests("common_interface", "").Output("update_or_freeze_api_3.timestamp").Output.String()
+			fooFreezeApiRule := ctx.ModuleForTests(t, "foo_interface", "").Output("update_or_freeze_api_3.timestamp")
+			commonFreezeApiOutput := ctx.ModuleForTests(t, "common_interface", "").Output("update_or_freeze_api_3.timestamp").Output.String()
 			testMethod := android.AssertStringListDoesNotContain
 			if shouldHaveDep {
 				testMethod = android.AssertStringListContains
@@ -2248,21 +2249,21 @@ func TestAidlNoUnfrozen(t *testing.T) {
 
 	// compile (v1)
 	{
-		rule := ctx.ModuleForTests("foo-iface-V1-cpp-source", "").Output("a/Foo.cpp")
+		rule := ctx.ModuleForTests(t, "foo-iface-V1-cpp-source", "").Output("a/Foo.cpp")
 		android.AssertStringDoesNotContain(t, "Frozen versions should not have the -previous_api_dir set",
 			rule.Args["optionalFlags"],
 			"-previous")
 	}
 	// compile (v2)
 	{
-		rule := ctx.ModuleForTests("foo-iface-V2-cpp-source", "").Output("a/Foo.cpp")
+		rule := ctx.ModuleForTests(t, "foo-iface-V2-cpp-source", "").Output("a/Foo.cpp")
 		android.AssertStringDoesNotContain(t, "Frozen versions should not have the -previous_api_dir set",
 			rule.Args["optionalFlags"],
 			"-previous")
 	}
 	// compile ToT(v3)
 	{
-		rule := ctx.ModuleForTests("foo-iface-V3-cpp-source", "").Output("a/Foo.cpp")
+		rule := ctx.ModuleForTests(t, "foo-iface-V3-cpp-source", "").Output("a/Foo.cpp")
 		android.AssertStringDoesContain(t, "An unfrozen interface with previously frozen version must have --previous_api_dir when RELEASE_AIDL_USE_UNFROZEN is false (setReleaseEnv())",
 			rule.Args["optionalFlags"],
 			"-previous_api_dir")
@@ -2295,14 +2296,14 @@ func TestAidlUsingUnfrozen(t *testing.T) {
 
 	// compile (v2)
 	{
-		rule := ctx.ModuleForTests("foo-iface-V2-cpp-source", "").Output("a/Foo.cpp")
+		rule := ctx.ModuleForTests(t, "foo-iface-V2-cpp-source", "").Output("a/Foo.cpp")
 		android.AssertStringDoesNotContain(t, "Frozen versions should not have the -previous_api_dir set",
 			rule.Args["optionalFlags"],
 			"-previous")
 	}
 	// compile ToT(v3)
 	{
-		rule := ctx.ModuleForTests("foo-iface-V3-cpp-source", "").Output("a/Foo.cpp")
+		rule := ctx.ModuleForTests(t, "foo-iface-V3-cpp-source", "").Output("a/Foo.cpp")
 		android.AssertStringDoesNotContain(t, "Unfrozen versions should not have the -previous options when RELEASE_AIDL_USE_UNFROZEN is true (default)",
 			rule.Args["optionalFlags"],
 			"-previous")
@@ -2323,7 +2324,7 @@ func TestAidlUseUnfrozenOverrideFalse(t *testing.T) {
 	})
 	ctx, _ := testAidl(t, ``, setUseUnfrozenOverrideEnvFalse(), customizer)
 
-	rule := ctx.ModuleForTests("foo-iface-V2-cpp-source", "").Output("a/Foo.cpp")
+	rule := ctx.ModuleForTests(t, "foo-iface-V2-cpp-source", "").Output("a/Foo.cpp")
 	android.AssertStringDoesContain(t, "Unfrozen interfaces should have -previous_api_dir set when overriding the RELEASE_AIDL_USE_UNFROZEN flag",
 		rule.Args["optionalFlags"],
 		"-previous")
@@ -2343,7 +2344,7 @@ func TestAidlUseUnfrozenOverrideTrue(t *testing.T) {
 	})
 	ctx, _ := testAidl(t, ``, setUseUnfrozenOverrideEnvTrue(), customizer)
 
-	rule := ctx.ModuleForTests("foo-iface-V2-cpp-source", "").Output("a/Foo.cpp")
+	rule := ctx.ModuleForTests(t, "foo-iface-V2-cpp-source", "").Output("a/Foo.cpp")
 	android.AssertStringDoesNotContain(t, "Unfrozen interfaces should not have -previous_api_dir set when overriding the RELEASE_AIDL_USE_UNFROZEN flag",
 		rule.Args["optionalFlags"],
 		"-previous")
diff --git a/codelab/README.md b/codelab/README.md
new file mode 100644
index 00000000..9100105e
--- /dev/null
+++ b/codelab/README.md
@@ -0,0 +1,280 @@
+# Android Platform Binder Codelab
+
+go/android-binder-codelab
+
+This Android Platform Developer codelab explores the use of Binder in the
+Android Platform. go/android-codelab is a prerequisite for this work. In this
+codelab, you create an AIDL interface along with client and server processes
+that communicate with each other over Binder.
+
+## Goals
+
+There are four goals for this codelab:
+
+1.  Introduce you to Binder, Android's core IPC mechanism
+2.  Use AIDL to define a Binder interface for a simple client/server interaction
+3.  Use Binder's Service Management infrastructure to make the service available
+    to clients
+4.  Get and use the service with basic error handling
+
+## What to expect
+
+### Estimated time
+
+*   Hands-off time ~4 hours
+*   Hands-on time ~1 hours
+
+### Prerequisites
+
+**Before** taking this codelab, complete go/android-codelab first. If external,
+follow https://source.android.com/docs/setup/start.
+
+You will need an Android repo with the ability to make changes, build, deploy,
+test, and upload the changes. All of this is covered in go/android-codelab.
+
+See the slides at go/onboarding-binder for a summary of key concepts that will
+help you understand the steps in this codelab.
+
+## Codelab
+
+Most of this code can be found in `system/tools/aidl/codelab`, but the example
+service isn't installed on real devices. The build code to install the service
+on the device and the sepolicy changes are described in this `README.md` but not
+submitted.
+
+### Create the new AIDL interface
+
+Choose a location for the AIDL interface definition.
+
+*   `hardware/interfaces` - for
+    [HAL](https://source.android.com/docs/core/architecture/hal) interfaces that
+    device-specific processes implement and the Android Platform depends on as a
+    client
+*   `frameworks/hardware/interfaces` - for interfaces that the Android Framework
+    implements for device-specific clients
+*   `system/hardware/interfaces` - for interfaces that Android system process
+    implement for device-specific clients
+*   Any other directory for interfaces that are used between processes that are
+    installed on the same
+    [partitions](https://source.android.com/docs/core/architecture/partitions)
+
+Create a new `aidl_interface` module in a new or existing `Android.bp` file.
+
+Note: go/android.bp has all of the available Soong modules and their supported
+fields.
+
+```soong
+// File: `codelab/aidl/Android.bp`
+aidl_interface {
+  // Package name for the interface. This is used when generating the libraries
+  // that the services and clients will depend on.
+  name: "hello.world",
+  // The source `.aidl` files that define this interface. It is recommended to
+  // create them in a directory next to this Android.bp file with a
+  // directory structure that follows the package name. If you want to change
+  // this, use `local_include_dir` to point to the new directory.
+  srcs: [
+    "hello/world/*.aidl",
+  ],
+  // For simplicity we start with an unstable interface. See
+  // https://source.android.com/docs/core/architecture/aidl/stable-aidl
+  // for details on stable interfaces.
+  unstable: true,
+  // This field controls which libraries are generated at build time and their
+  // backend-specific configurations. AIDL supports different languages.
+  backend: {
+    ndk: {
+      enabled: true,
+    }
+    rust: {
+      enabled: true,
+    }
+  }
+}
+```
+
+Create your first AIDL file.
+
+```java
+// File: `codelab/aidl/hello/world/IHello.aidl`
+// The package name is recommended to match the `name` in the `aidl_interface`
+package hello.world;
+
+interface IHello {
+  // Have the service log a message for us
+  void LogMessage(String message);
+  // Get a "hello world" message from the service
+  String getMessage();
+}
+```
+
+Build the generated AIDL libraries.
+
+```shell
+m hello.world-ndk hello.world-rust
+```
+
+Note: `m hello.world` without the backend suffix will not build anything.
+
+### Create the service
+
+Android encourages Rust for native services so let's build a Rust service!
+
+Binder has easy-to-use libraries to facilitate fuzzing of binder services that
+require the service being defined in its own library. With that in mind, we
+create the library that implements the interface first.
+
+#### Interface implementation
+
+Create a separate library for the interface implementation so it can be used
+for the service and for the fuzzer.
+
+* See [codelab/service/Android.bp](codelab/service/Android.bp)
+
+* See [codelab/service/hello_service.rs](codelab/service/hello_service.rs)
+
+#### Service binary
+
+Create the service that registers itself with servicemanager and joins the
+binder threadpool.
+
+* See [codelab/service/Android.bp](codelab/service/Android.bp)
+
+* See [codelab/service/service_main.rs](codelab/service/service_main.rs)
+
+An init.rc file is required for the process to be started on a device.
+
+* See
+  [codelab/service/hello-world-service-test.rc](codelab/service/hello-world-service-test.rc)
+
+#### Sepolicy for the service
+
+Associate the service binary with a selinux context so init can start it.
+```
+// File: system/sepolicy/private/file_contexts
+/system/bin/hello-world-service-test u:object_r:hello_exec:s0
+```
+
+Add a file for the service to define its types, associate the binary to the
+types, and give permissions to the service..
+```
+// File: system/sepolicy/private/hello.te
+
+// Permissions required for the process to start
+type hello, domain;
+typeattribute hello coredomain;
+type hello_exec, system_file_type, exec_type, file_type;
+init_daemon_domain(hello)
+
+// Permissions to be a binder service and talk to service_manager
+binder_service(hello)
+binder_use(hello)
+binder_call(hello, binderservicedomain)
+
+// Give permissions to this service to register itself with service_manager
+allow hello hello_service:service_manager { add find };
+```
+
+Declare this service as a service_manager_type
+```
+// File: system/sepolicy/public/service.te
+type hello_service,             service_manager_type;
+```
+
+Associate the AIDL interface/instance with this service
+```
+// File: system/sepolicy/private/service_contexts
+hello.world.IHello/default u:object_r:hello_service:s0
+```
+
+#### Fuzzer
+
+Create the fuzzer and use `fuzz_service` to do all of the hard work!
+
+* See [codelab/service/Android.bp](codelab/service/Android.bp)
+
+* See [codelab/service/service_fuzzer.rs](codelab/service/service_fuzzer.rs)
+
+Associate the fuzzer with the interface by adding the following to
+`system/sepolicy/build/soong/service_fuzzer_bindings.go`:
+```
+"hello.world.IHello/default":             []string{"hello-world-fuzzer"},
+```
+This step is required by the build system once we add the sepolicy for the
+service in the previous step.
+
+### Create the client
+
+#### Sepolicy for the client
+
+We skip these details by creating the client in a `cc_test`.
+
+The clients need permission to `find` the service through servicemanager:
+
+`allow <client> hello_service:servicemanager find;`
+
+The clients need permission to `call` the service, pass the binders to other
+processes, and use any file descriptors returned through the interface. The
+`binder_call` macro handles all this for us.
+
+`binder_call(<client>, hello_service);`
+
+### Test the changes
+
+Add the service to the device. Since this is a system service it needs to be
+added to the system partition. We add the following to
+`build/make/target/product/base_system.mk`.
+
+```
+PRODUCT_PACKAGES += hello-world-service-test
+```
+
+Build the device.
+
+Launch the device.
+
+Verify the service is in the `dumpsys -l` output.
+
+`atest hello-world-client-test` and verify it passes!
+
+## Wrap up
+
+Congratulations! You are now familiar with some core concepts of Binder and AIDL
+in Android.
+When you think of IPC in Android, think of Binder.
+When you think of Binder, think of AIDL.
+
+See https://source.android.com/docs/core/architecture/aidl for related AIDL and
+Binder documentation.
+Check out https://source.android.com/docs/core/architecture/aidl/aidl-hals for
+details that are more specific to Hardware Abstraction Layer (HAL) services.
+
+### Supporting documentation
+
+*   go/onboarding-binder
+*   go/binder-ipc
+*   go/stable-aidl
+*   go/aidl-backends
+*   go/aidl (for app developers with Java/Kotlin)
+
+See all of the other AIDL related pages in our external documentation:
+https://source.android.com/docs/core/architecture/aidl.
+
+### Feedback
+
+If you are external please see
+https://source.android.com/docs/setup/contribute/report-bugs to find out how to
+create a Bug for questions, suggestions, or reporting bugs.
+
+Please write to android-idl-discuss@google.com.
+
+Anyone is free to create and upload CLs in `system/tools/aidl/codelab/` with any
+suggestions or corrections.
+
+### Wish list
+
+Add your suggested additions and updates to this codelab here!
+
+1.  I wish this codelab would dive deeper into `DeathRecipients` and remote
+    reference counting
+
diff --git a/codelab/aidl/Android.bp b/codelab/aidl/Android.bp
new file mode 100644
index 00000000..f3ad901c
--- /dev/null
+++ b/codelab/aidl/Android.bp
@@ -0,0 +1,43 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aidl_interface {
+    // Package name for the interface. This is used when generating the libraries
+    // that the services and clients will depend on.
+    name: "hello.world",
+
+    // The source `.aidl` files that define this interface. It is recommended to
+    // create them in an `aidl/` directory next to this Android.bp file with a
+    // directory structure that follows the package name.
+    srcs: [
+        "hello/world/*.aidl",
+    ],
+
+    // For simplicity we start with an unstable interface. See
+    // https://source.android.com/docs/core/architecture/aidl/stable-aidl
+    // for details on stable interfaces.
+    unstable: true,
+
+    // This field controls which libraries are generated at build time and their
+    // backend-specific configurations.
+    backend: {
+        java: {
+            enabled: true,
+            platform_apis: true,
+        },
+        rust: {
+            enabled: true,
+        },
+    },
+}
diff --git a/codelab/aidl/hello/world/IHello.aidl b/codelab/aidl/hello/world/IHello.aidl
new file mode 100644
index 00000000..2b9694f7
--- /dev/null
+++ b/codelab/aidl/hello/world/IHello.aidl
@@ -0,0 +1,8 @@
+package hello.world;
+
+interface IHello {
+    // Have the service log a message for us
+    void LogMessage(String message);
+    // Get a "hello world" message from the service
+    String getMessage();
+}
diff --git a/codelab/client/Android.bp b/codelab/client/Android.bp
new file mode 100644
index 00000000..d6fe14a0
--- /dev/null
+++ b/codelab/client/Android.bp
@@ -0,0 +1,24 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+cc_test {
+    name: "hello-world-client-test",
+    srcs: ["testClient.cpp"],
+    shared_libs: [
+        "libbinder_ndk",
+    ],
+    static_libs: [
+        "hello.world-ndk",
+    ],
+}
diff --git a/codelab/client/testClient.cpp b/codelab/client/testClient.cpp
new file mode 100644
index 00000000..f0fa985a
--- /dev/null
+++ b/codelab/client/testClient.cpp
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include <gtest/gtest.h>
+
+#include <android/binder_auto_utils.h>
+#include <android/binder_manager.h>
+
+#include <aidl/hello/world/IHello.h>
+
+using aidl::hello::world::IHello;
+
+TEST(HelloWorldTestClient, GetServiceSayHello) {
+  // Clients will get the binder service using the name that they registered
+  // with. This is up to the service. For this example, we use the interface
+  // descriptor that AIDL generates + "/default".
+  std::string instance = std::string(IHello::descriptor) + "/default";
+  ndk::SpAIBinder binder = ndk::SpAIBinder(AServiceManager_waitForService(instance.c_str()));
+  ASSERT_NE(binder, nullptr);
+
+  // If this is the wrong interface, this result will be null
+  auto hello = IHello::fromBinder(binder);
+  ASSERT_NE(hello, nullptr);
+
+  // All AIDL generated interfaces have a return value with the status of the
+  // transaction, even for void methods.
+  auto res = hello->LogMessage("Hello service!");
+  EXPECT_TRUE(res.isOk()) << res;
+}
diff --git a/codelab/service/Android.bp b/codelab/service/Android.bp
new file mode 100644
index 00000000..0116d457
--- /dev/null
+++ b/codelab/service/Android.bp
@@ -0,0 +1,57 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+rust_binary {
+    name: "hello-world-service-test",
+    srcs: [
+        "service_main.rs",
+    ],
+    rustlibs: [
+        "libhello_service",
+        "libbinder_rs",
+        "liblog_rust",
+        // The generated AIDL libraries have the backend appended to the
+        // end of the name.
+        // `hello.world-<backend>`. In this case the backend is `rust`
+        "hello.world-rust",
+    ],
+    init_rc: ["hello-world-service-test.rc"],
+}
+
+rust_fuzz {
+    name: "hello-world-fuzzer",
+    srcs: ["service_fuzzer.rs"],
+    // These fuzzer defaults have everything needed for the service fuzzer outside
+    // of the specific dependencies of this service.
+    defaults: ["service_fuzzer_defaults_rs"],
+    rustlibs: [
+        "libhello_service",
+        "liblog_rust",
+        "hello.world-rust",
+    ],
+}
+
+// Implementation of the interface. This is in its own library
+// so we can use it for the service on the device AND use it in the fuzzer
+// to find bugs.
+rust_library {
+    name: "libhello_service",
+    crate_name: "hello_service",
+    srcs: ["hello_service.rs"],
+    rustlibs: [
+        "libbinder_rs",
+        "liblog_rust",
+        "hello.world-rust",
+    ],
+}
diff --git a/codelab/service/hello-world-service-test.rc b/codelab/service/hello-world-service-test.rc
new file mode 100644
index 00000000..741832d4
--- /dev/null
+++ b/codelab/service/hello-world-service-test.rc
@@ -0,0 +1,4 @@
+service hello-world-service-test /system/bin/hello-world-service-test
+    class core
+    user system
+    group nobody
diff --git a/codelab/service/hello_service.rs b/codelab/service/hello_service.rs
new file mode 100644
index 00000000..ec35c076
--- /dev/null
+++ b/codelab/service/hello_service.rs
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+//! Implements and serves the hello.world.IHello interface for the
+//! AIDL / Binder codelab
+
+use binder::{Interface, Result};
+use hello_world::aidl::hello::world::IHello::IHello;
+use log::info;
+
+//pub mod hello_service;
+
+/// Implementation for the IHello service used for a codelab
+pub struct Hello;
+
+impl Hello {}
+
+impl Interface for Hello {}
+
+impl IHello for Hello {
+    fn LogMessage(&self, msg: &str) -> Result<()> {
+        info!("{}", msg);
+        Ok(())
+    }
+    fn getMessage(&self) -> Result<String> {
+        Ok("Hello World!".to_string())
+    }
+}
diff --git a/codelab/service/service_fuzzer.rs b/codelab/service/service_fuzzer.rs
new file mode 100644
index 00000000..58387851
--- /dev/null
+++ b/codelab/service/service_fuzzer.rs
@@ -0,0 +1,28 @@
+/*
+ * Copyright (C) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#![no_main]
+//! Fuzzer for the IHello service implementation
+
+use binder::BinderFeatures;
+use binder_random_parcel_rs::fuzz_service;
+use hello_service::Hello;
+use hello_world::aidl::hello::world::IHello::BnHello;
+use libfuzzer_sys::fuzz_target;
+
+fuzz_target!(|data: &[u8]| {
+    let service = BnHello::new_binder(Hello, BinderFeatures::default());
+    fuzz_service(&mut service.as_binder(), data);
+});
diff --git a/codelab/service/service_main.rs b/codelab/service/service_main.rs
new file mode 100644
index 00000000..cddc8a4d
--- /dev/null
+++ b/codelab/service/service_main.rs
@@ -0,0 +1,33 @@
+/*
+ * Copyright (C) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+//! Service that registers the IHello interface for a codelab
+
+use hello_service::Hello;
+use hello_world::aidl::hello::world::IHello::{BnHello, IHello};
+
+fn main() {
+    // We join the threadpool with this main thread and never exit. We don't
+    // have any callback binders in this interface, so the single thread is OK.
+    // Set the max to 0 here so libbinder doesn't spawn any additional threads.
+    binder::ProcessState::set_thread_pool_max_thread_count(0);
+
+    let service = BnHello::new_binder(Hello, binder::BinderFeatures::default());
+    let service_name = format!("{}/default", Hello::get_descriptor());
+    binder::add_service(&service_name, service.as_binder())
+        .expect("Failed to register IHello service!");
+
+    binder::ProcessState::join_thread_pool()
+}
diff --git a/diagnostics.cpp b/diagnostics.cpp
index 5c51f03d..4f004b0c 100644
--- a/diagnostics.cpp
+++ b/diagnostics.cpp
@@ -61,7 +61,7 @@ class DiagnosticsContext {
   DiagnosticsContext(DiagnosticMapping mapping) : mapping_({std::move(mapping)}) {}
   AidlErrorLog Report(const AidlLocation& loc, DiagnosticID id,
                       DiagnosticSeverity force_severity = DiagnosticSeverity::DISABLED) {
-    if (loc.IsInternal()) {
+    if (loc.IsDerived() || loc.IsInternal()) {
       return AidlErrorLog(AidlErrorLog::NO_OP, loc);
     }
     const std::string suffix = " [-W" + to_string(id) + "]";
diff --git a/generate_cpp.cpp b/generate_cpp.cpp
index 7965ea87..ac004c6a 100644
--- a/generate_cpp.cpp
+++ b/generate_cpp.cpp
@@ -20,12 +20,11 @@
 #include <algorithm>
 #include <cctype>
 #include <cstring>
+#include <format>
 #include <memory>
-#include <random>
 #include <set>
 #include <string>
 
-#include <android-base/format.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 
@@ -35,7 +34,6 @@
 
 #include "aidl_typenames.h"
 #include "logging.h"
-#include "os.h"
 
 using android::base::Join;
 using android::base::StringPrintf;
@@ -183,8 +181,9 @@ void GenerateClientTransaction(CodeWriter& out, const AidlTypenames& typenames,
   }
   out.Write("%s.markForBinder(remoteStrong());\n", kDataVarName);
 
-  // Even if we're oneway, the transact method still takes a parcel.
-  out.Write("%s %s;\n", kAndroidParcelLiteral, kReplyVarName);
+  if (!method.IsOneway()) {
+    out.Write("%s %s;\n", kAndroidParcelLiteral, kReplyVarName);
+  }
 
   // Declare the status_t variable we need for error handling.
   out.Write("%s %s = %s;\n", kAndroidStatusLiteral, kAndroidStatusVarName, kAndroidStatusOk);
@@ -239,8 +238,9 @@ void GenerateClientTransaction(CodeWriter& out, const AidlTypenames& typenames,
   if (method.IsOneway()) flags.push_back("::android::IBinder::FLAG_ONEWAY");
   if (interface.IsSensitiveData()) flags.push_back("::android::IBinder::FLAG_CLEAR_BUF");
 
-  out.Write("%s = remote()->transact(%s, %s, &%s, %s);\n", kAndroidStatusVarName,
-            GetTransactionIdFor(bn_name, method).c_str(), kDataVarName, kReplyVarName,
+  out.Write("%s = remote()->transact(%s, %s, %s%s, %s);\n", kAndroidStatusVarName,
+            GetTransactionIdFor(bn_name, method).c_str(), kDataVarName,
+            method.IsOneway() ? "" : "&", method.IsOneway() ? "nullptr" : kReplyVarName,
             flags.empty() ? "0" : Join(flags, " | ").c_str());
 
   // If the method is not implemented in the remote side, try to call the
@@ -499,7 +499,7 @@ void GenerateServerTransaction(CodeWriter& out, const AidlInterface& interface,
   }
 
   // Deserialize each "in" parameter to the transaction.
-  for (const auto& a: method.GetArguments()) {
+  for (const auto& a : method.GetArguments()) {
     // Deserialization looks roughly like:
     //     _aidl_ret_status = _aidl_data.ReadInt32(&in_param_name);
     //     if (_aidl_ret_status != ::android::OK) { break; }
@@ -719,11 +719,11 @@ void GenerateInterfaceSource(CodeWriter& out, const AidlInterface& interface,
   EnterNamespace(out, interface);
 
   if (auto parent = interface.GetParentType(); parent) {
-    out << fmt::format("DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_NESTED_INTERFACE({}, {}, \"{}\")\n",
+    out << std::format("DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_NESTED_INTERFACE({}, {}, \"{}\")\n",
                        GetQualifiedName(*parent, ClassNames::MAYBE_INTERFACE),
                        ClassName(interface, ClassNames::BASE), interface.GetDescriptor());
   } else {
-    out << fmt::format("DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE({}, \"{}\")\n",
+    out << std::format("DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE({}, \"{}\")\n",
                        ClassName(interface, ClassNames::BASE), interface.GetDescriptor());
   }
 
@@ -855,7 +855,7 @@ void GenerateServerClassDecl(CodeWriter& out, const AidlInterface& interface,
         << ";\n";
   }
   out << "explicit " << bn_name << "();\n";
-  out << fmt::format("{} onTransact(uint32_t {}, const {}& {}, {}* {}, uint32_t {}) override;\n",
+  out << std::format("{} onTransact(uint32_t {}, const {}& {}, {}* {}, uint32_t {}) override;\n",
                      kAndroidStatusLiteral, kCodeVarName, kAndroidParcelLiteral, kDataVarName,
                      kAndroidParcelLiteral, kReplyVarName, kFlagsVarName);
   if (options.Version() > 0) {
@@ -1035,6 +1035,7 @@ void GenerateInterfaceClassDecl(CodeWriter& out, const AidlInterface& interface,
   out << "DECLARE_META_INTERFACE(" << ClassName(interface, ClassNames::BASE) << ")\n";
   if (options.Version() > 0) {
     if (options.IsLatestUnfrozenVersion()) {
+      out << kDowngradeComment;
       out << "static inline const int32_t VERSION = true ? "
           << std::to_string(options.PreviousVersion()) << " : " << std::to_string(options.Version())
           << ";\n";
@@ -1188,12 +1189,12 @@ ParcelWriterContext GetParcelWriterContext(const AidlTypenames& typenames) {
       .status_bad = kAndroidStatusBadValue,
       .read_func =
           [&](CodeWriter& out, const string& var, const AidlTypeSpecifier& type) {
-            out << fmt::format("{}->{}({})", kParcelVarName, ParcelReadMethodOf(type, typenames),
+            out << std::format("{}->{}({})", kParcelVarName, ParcelReadMethodOf(type, typenames),
                                ParcelReadCastOf(type, typenames, "&" + var));
           },
       .write_func =
           [&](CodeWriter& out, const string& value, const AidlTypeSpecifier& type) {
-            out << fmt::format("{}->{}({})", kParcelVarName, ParcelWriteMethodOf(type, typenames),
+            out << std::format("{}->{}({})", kParcelVarName, ParcelWriteMethodOf(type, typenames),
                                ParcelWriteCastOf(type, typenames, value));
           },
   };
diff --git a/generate_java.cpp b/generate_java.cpp
index 4b4a215d..2a5cd423 100644
--- a/generate_java.cpp
+++ b/generate_java.cpp
@@ -21,12 +21,12 @@
 #include <string.h>
 
 #include <algorithm>
+#include <format>
 #include <map>
 #include <memory>
 #include <optional>
 #include <sstream>
 
-#include <android-base/format.h>
 #include <android-base/stringprintf.h>
 
 #include "aidl_to_common.h"
@@ -634,7 +634,7 @@ void GenerateEnumClass(CodeWriter& out, const AidlEnumDeclaration& enum_decl) {
   for (const auto& enumerator : enum_decl.GetEnumerators()) {
     out << GenerateComments(*enumerator);
     out << GenerateAnnotations(*enumerator);
-    out << fmt::format("public static final {} {} = {};\n", raw_type, enumerator->GetName(),
+    out << std::format("public static final {} {} = {};\n", raw_type, enumerator->GetName(),
                        enumerator->ValueString(backing_type, ConstantValueDecorator));
   }
   if (enum_decl.JavaDerive("toString")) {
@@ -649,7 +649,7 @@ void GenerateEnumClass(CodeWriter& out, const AidlEnumDeclaration& enum_decl) {
     out << "return " << boxing_type << ".toString(_aidl_v);\n";
     out.Dedent();
     out << "}\n";
-    out << fmt::format(R"(static String arrayToString(Object _aidl_v) {{
+    out << std::format(R"(static String arrayToString(Object _aidl_v) {{
   if (_aidl_v == null) return "null";
   Class<?> _aidl_cls = _aidl_v.getClass();
   if (!_aidl_cls.isArray()) throw new IllegalArgumentException("not an array: " + _aidl_v);
@@ -660,15 +660,15 @@ void GenerateEnumClass(CodeWriter& out, const AidlEnumDeclaration& enum_decl) {
       _aidl_sj.add(arrayToString(java.lang.reflect.Array.get(_aidl_v, _aidl_i)));
     }}
   }} else {{
-    if (_aidl_cls != {raw_type}[].class) throw new IllegalArgumentException("wrong type: " + _aidl_cls);
-    for ({raw_type} e : ({raw_type}[]) _aidl_v) {{
+    if (_aidl_cls != {0}[].class) throw new IllegalArgumentException("wrong type: " + _aidl_cls);
+    for ({0} e : ({0}[]) _aidl_v) {{
       _aidl_sj.add(toString(e));
     }}
   }}
   return _aidl_sj.toString();
 }}
 )",
-                       fmt::arg("raw_type", raw_type));
+                       raw_type);
     out.Dedent();
     out << "}\n";
   }
diff --git a/generate_java_binder.cpp b/generate_java_binder.cpp
index 0374526f..47044e39 100644
--- a/generate_java_binder.cpp
+++ b/generate_java_binder.cpp
@@ -1339,6 +1339,7 @@ std::unique_ptr<Class> GenerateInterfaceClass(const AidlInterface* iface,
   if (!options.Hash().empty() || options.IsLatestUnfrozenVersion()) {
     std::ostringstream code;
     if (options.IsLatestUnfrozenVersion()) {
+      code << kDowngradeComment;
       code << "public static final String HASH = \"" << options.PreviousHash() << "\";\n";
     } else {
       code << "public static final String HASH = \"" << options.Hash() << "\";\n";
diff --git a/generate_ndk.cpp b/generate_ndk.cpp
index 8207ff25..a6563567 100644
--- a/generate_ndk.cpp
+++ b/generate_ndk.cpp
@@ -1179,6 +1179,7 @@ void GenerateInterfaceClassDecl(CodeWriter& out, const AidlTypenames& types,
   GenerateConstantDeclarations(out, types, defined_type);
   if (options.Version() > 0) {
     if (options.IsLatestUnfrozenVersion()) {
+      out << kDowngradeComment;
       out << "static inline const int32_t " << kVersion << " = true ? "
           << std::to_string(options.PreviousVersion()) << " : " << std::to_string(options.Version())
           << ";\n";
diff --git a/generate_rust.cpp b/generate_rust.cpp
index 3b478ae7..99564b0b 100644
--- a/generate_rust.cpp
+++ b/generate_rust.cpp
@@ -357,8 +357,7 @@ void GenerateClientMethod(CodeWriter& out, const AidlInterface& iface, const Aid
   vector<string> flags;
   if (method.IsOneway()) flags.push_back("binder::binder_impl::FLAG_ONEWAY");
   if (iface.IsSensitiveData()) flags.push_back("binder::binder_impl::FLAG_CLEAR_BUF");
-  flags.push_back("binder::binder_impl::FLAG_PRIVATE_LOCAL");
-
+  flags.push_back("FLAG_PRIVATE_LOCAL");
   string transact_flags = flags.empty() ? "0" : Join(flags, " | ");
 
   switch (kind) {
@@ -626,6 +625,11 @@ void GenerateRustInterface(CodeWriter* code_writer, const AidlInterface* iface,
   *code_writer << "#![allow(non_snake_case)]\n";
   // Import IBinderInternal for transact()
   *code_writer << "#[allow(unused_imports)] use binder::binder_impl::IBinderInternal;\n";
+  *code_writer << "#[cfg(any(android_vndk, not(android_ndk)))]\n";
+  *code_writer << "const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = "
+                  "binder::binder_impl::FLAG_PRIVATE_LOCAL;\n";
+  *code_writer << "#[cfg(not(any(android_vndk, not(android_ndk))))]\n";
+  *code_writer << "const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;\n";
 
   auto trait_name = ClassName(*iface, cpp::ClassNames::INTERFACE);
   auto trait_name_async = trait_name + "Async";
@@ -940,6 +944,7 @@ void GenerateRustInterface(CodeWriter* code_writer, const AidlInterface* iface,
   // https://doc.rust-lang.org/reference/items/traits.html#object-safety
   if (options.Version() > 0) {
     if (options.IsLatestUnfrozenVersion()) {
+      *code_writer << kDowngradeComment;
       *code_writer << "pub const VERSION: i32 = if true {"
                    << std::to_string(options.PreviousVersion()) << "} else {"
                    << std::to_string(options.Version()) << "};\n";
diff --git a/include/aidl/transaction_ids.h b/include/aidl/transaction_ids.h
new file mode 100644
index 00000000..5c292840
--- /dev/null
+++ b/include/aidl/transaction_ids.h
@@ -0,0 +1,48 @@
+/*
+ * Copyright (C) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
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
+namespace android {
+namespace aidl {
+
+// Copied from android.is.IBinder.[FIRST|LAST]_CALL_TRANSACTION
+const int kFirstCallTransaction = 1;
+const int kLastCallTransaction = 0x00ffffff;
+
+// Following IDs are all offsets from  kFirstCallTransaction
+
+// IDs for meta transactions. Most of the meta transactions are implemented in
+// the framework side (Binder.java or Binder.cpp). But these are the ones that
+// are auto-implemented by the AIDL compiler.
+const int kFirstMetaMethodId = kLastCallTransaction - kFirstCallTransaction;
+const int kGetInterfaceVersionId = kFirstMetaMethodId;
+const int kGetInterfaceHashId = kFirstMetaMethodId - 1;
+// Additional meta transactions implemented by AIDL should use
+// kFirstMetaMethodId -1, -2, ...and so on.
+
+// Reserve 100 IDs for meta methods, which is more than enough. If we don't reserve,
+// in the future, a newly added meta transaction ID will have a chance to
+// collide with the user-defined methods that were added in the past. So,
+// let's prevent users from using IDs in this range from the beginning.
+const int kLastMetaMethodId = kFirstMetaMethodId - 99;
+
+// Range of IDs that is allowed for user-defined methods.
+const int kMinUserSetMethodId = 0;
+const int kMaxUserSetMethodId = kLastMetaMethodId - 1;
+
+}  // namespace aidl
+}  // namespace android
diff --git a/location.cpp b/location.cpp
index 4b8a2787..623df6ad 100644
--- a/location.cpp
+++ b/location.cpp
@@ -20,6 +20,9 @@ AidlLocation::AidlLocation(const std::string& file, Point begin, Point end, Sour
     : file_(file), begin_(begin), end_(end), source_(source) {}
 
 std::ostream& operator<<(std::ostream& os, const AidlLocation& l) {
+  if (l.source_ == AidlLocation::Source::DERIVED_INTERNAL) {
+    os << "(derived from)";
+  }
   os << l.file_;
   if (l.LocationKnown()) {
     os << ":" << l.begin_.line << "." << l.begin_.column << "-";
@@ -30,3 +33,8 @@ std::ostream& operator<<(std::ostream& os, const AidlLocation& l) {
   }
   return os;
 }
+
+std::optional<AidlLocation> AidlLocation::ToDerivedLocation() const {
+  if (source_ != Source::EXTERNAL) return std::nullopt;
+  return AidlLocation(file_, begin_, end_, Source::DERIVED_INTERNAL);
+}
diff --git a/location.h b/location.h
index 9ccad24c..d46c46a6 100644
--- a/location.h
+++ b/location.h
@@ -17,6 +17,7 @@
 #pragma once
 
 #include <iostream>
+#include <optional>
 #include <string>
 
 class AidlLocation {
@@ -28,9 +29,13 @@ class AidlLocation {
 
   enum class Source {
     // From internal aidl source code
-    INTERNAL = 0,
+    INTERNAL,
     // From a parsed file
-    EXTERNAL = 1
+    EXTERNAL,
+    // Derived from a parsed file. These are used for types generated by
+    // the compiler that we still want to track mostly like EXTERNAL types.
+    // An example is the Tag enum that is generated for each EXTERNAL union.
+    DERIVED_INTERNAL,
   };
 
   AidlLocation(const std::string& file, Point begin, Point end, Source source);
@@ -38,12 +43,17 @@ class AidlLocation {
       : AidlLocation(file, {0, 0}, {0, 0}, source) {}
 
   bool IsInternal() const { return source_ == Source::INTERNAL; }
+  bool IsDerived() const { return source_ == Source::DERIVED_INTERNAL; }
 
   // The first line of a file is line 1.
   bool LocationKnown() const { return begin_.line != 0; }
 
   std::string GetFile() const { return file_; }
 
+  // Get an AidlLocation derived from this external location.
+  // nullopt if this location is not EXTERNAL
+  std::optional<AidlLocation> ToDerivedLocation() const;
+
   friend std::ostream& operator<<(std::ostream& os, const AidlLocation& l);
   friend class AidlNode;
 
@@ -60,4 +70,4 @@ class AidlLocation {
 #define AIDL_LOCATION_HERE \
   (AidlLocation{__FILE__, {__LINE__, 0}, {__LINE__, 0}, AidlLocation::Source::INTERNAL})
 
-std::ostream& operator<<(std::ostream& os, const AidlLocation& l);
\ No newline at end of file
+std::ostream& operator<<(std::ostream& os, const AidlLocation& l);
diff --git a/options.cpp b/options.cpp
index 77f81490..9f0489ae 100644
--- a/options.cpp
+++ b/options.cpp
@@ -608,6 +608,10 @@ Options::Options(int argc, const char* const raw_argv[], Options::Language defau
       error_message_ << "--previous_hash must be set if --previous_api_dir is set" << endl;
       return;
     }
+    if (version_ <= 1) {
+      error_message_ << "--previous_api_dir must not be set for version 1." << endl;
+      return;
+    }
   } else {
     if (!previous_hash_.empty()) {
       error_message_ << "--previous_hash must not be set if --previous_api_dir is not set" << endl;
diff --git a/options_unittest.cpp b/options_unittest.cpp
index 36627738..8907ac80 100644
--- a/options_unittest.cpp
+++ b/options_unittest.cpp
@@ -523,5 +523,24 @@ TEST(OptionsTest, RejectRpcOnOldSdkVersion) {
               testing::HasSubstr("RPC code requires minimum SDK version of at least"));
 }
 
+TEST(OptionsTests, PreviousApiDir) {
+  // if this is V1, there is no previous API directory.
+  string expected_error = "--previous_api_dir must not be set for version 1.";
+  CaptureStderr();
+  const char* arg_with_no_out_dir[] = {
+      "aidl",
+      "--lang=java",
+      kCompileCommandIncludePath,
+      "directory/input1.aidl",
+      "--previous_api_dir=/some/dir",
+      "--previous_hash=alskdfjlkasdfj",
+      "--version=1",
+      "--out=out",
+      nullptr,
+  };
+  EXPECT_EQ(false, GetOptions(arg_with_no_out_dir)->Ok());
+  EXPECT_THAT(GetCapturedStderr(), testing::HasSubstr(expected_error));
+}
+
 }  // namespace aidl
 }  // namespace android
diff --git a/parser.cpp b/parser.cpp
index edb110bd..cec403a1 100644
--- a/parser.cpp
+++ b/parser.cpp
@@ -34,10 +34,16 @@ struct UnionTagGenerater : AidlVisitor {
   void Visit(const AidlUnionDecl& decl) override {
     std::vector<std::unique_ptr<AidlEnumerator>> enumerators;
     for (const auto& field : decl.GetFields()) {
-      enumerators.push_back(std::make_unique<AidlEnumerator>(AIDL_LOCATION_HERE, field->GetName(),
-                                                             nullptr, field->GetComments()));
+      auto derived = field->GetLocation().ToDerivedLocation();
+      AIDL_FATAL_IF(!derived, field)
+          << "Failed to get a derived location. Is this not an external type?";
+      enumerators.push_back(std::make_unique<AidlEnumerator>(*derived, field->GetName(), nullptr,
+                                                             field->GetComments()));
     }
-    auto tag_enum = std::make_unique<AidlEnumDeclaration>(AIDL_LOCATION_HERE, "Tag", &enumerators,
+    auto derived = decl.GetLocation().ToDerivedLocation();
+    AIDL_FATAL_IF(!derived, decl)
+        << "Failed to get a derived location. Is this not an external type?";
+    auto tag_enum = std::make_unique<AidlEnumDeclaration>(*derived, "Tag", &enumerators,
                                                           decl.GetPackage(), Comments{});
     // Tag for @FixedSize union is limited to "byte" type so that it can be passed via FMQ with
     // with lower overhead.
diff --git a/tests/aidl_integration_test.py b/tests/aidl_integration_test.py
index 6e57d0c8..6c688937 100755
--- a/tests/aidl_integration_test.py
+++ b/tests/aidl_integration_test.py
@@ -3,8 +3,8 @@
 from itertools import product
 from time import sleep
 
-import pipes
 import re
+import shlex
 import subprocess
 import sys
 import textwrap
@@ -86,7 +86,7 @@ class AdbHost(object):
             # outer redirection to /dev/null required to avoid subprocess.Popen blocking
             # on the FDs being closed
             command = '(( %s ) </dev/null 2>&1 | log -t %s &) >/dev/null 2>&1' % (command, background)
-        return self.adb('shell %s' % pipes.quote(command),
+        return self.adb('shell %s' % shlex.quote(command),
                         ignore_status=ignore_status)
 
     def adb(self, command, ignore_status=False):
diff --git a/tests/aidl_test_client_primitives.cpp b/tests/aidl_test_client_primitives.cpp
index 1544f3b1..e6736bfe 100644
--- a/tests/aidl_test_client_primitives.cpp
+++ b/tests/aidl_test_client_primitives.cpp
@@ -83,6 +83,19 @@ TEST_F(AidlPrimitiveTest, aInt) {
   DoTest(&ITestService::RepeatInt, int32_t{1 << 30});
 }
 
+TEST_F(AidlPrimitiveTest, IntEnum) {
+  DoTest(&ITestService::RepeatIntEnum, IntEnum::FOO);
+}
+
+TEST_F(AidlPrimitiveTest, IntEnumUndefined) {
+  DoTest(&ITestService::RepeatIntEnum, static_cast<IntEnum>(12));
+}
+
+TEST_F(AidlPrimitiveTest, IntEnumIncorrectBitwiseOp) {
+  DoTest(&ITestService::RepeatIntEnum, static_cast<IntEnum>(static_cast<int32_t>(IntEnum::FOO) |
+                                                            static_cast<int32_t>(IntEnum::BAR)));
+}
+
 TEST_F(AidlPrimitiveTest, aLong) {
   DoTest(&ITestService::RepeatLong, int64_t{1LL << 60});
 }
diff --git a/tests/android/aidl/tests/IntEnum.aidl b/tests/android/aidl/tests/IntEnum.aidl
index 7ab63f3b..1f026204 100644
--- a/tests/android/aidl/tests/IntEnum.aidl
+++ b/tests/android/aidl/tests/IntEnum.aidl
@@ -19,6 +19,15 @@ package android.aidl.tests;
 @JavaDerive(toString=true)
 @Backing(type="int")
 enum IntEnum {
+    ZERO,
+    ONE,
+    TWO,
+    /**
+     * Reserved: 12 and 2040
+     * We are using 12 and (FOO | BAR) in some tests because
+     * they _are not_ defined in this enum.
+     * Please do not add them here.
+     */
     FOO = 1000,
     BAR = 2000,
     BAZ,
diff --git a/tests/golden_output/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs b/tests/golden_output/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
index fc709024..a37689cc 100644
--- a/tests/golden_output/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
+++ b/tests/golden_output/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
@@ -368,6 +368,10 @@ pub mod r#IRepeatFixedSizeArray {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IRepeatFixedSizeArray["android.aidl.fixedsizearray.FixedSizeArrayExample.IRepeatFixedSizeArray"] {
@@ -696,42 +700,42 @@ pub mod r#IRepeatFixedSizeArray {
   impl IRepeatFixedSizeArray for BpRepeatFixedSizeArray {
     fn r#RepeatBytes<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [u8; 3], _arg_repeated: &'l2 mut [u8; 3]) -> binder::Result<[u8; 3]> {
       let _aidl_data = self.build_parcel_RepeatBytes(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBytes, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBytes, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_RepeatBytes(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#RepeatInts<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [i32; 3], _arg_repeated: &'l2 mut [i32; 3]) -> binder::Result<[i32; 3]> {
       let _aidl_data = self.build_parcel_RepeatInts(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatInts, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatInts, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_RepeatInts(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#RepeatBinders<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [binder::SpIBinder; 3], _arg_repeated: &'l2 mut [Option<binder::SpIBinder>; 3]) -> binder::Result<[binder::SpIBinder; 3]> {
       let _aidl_data = self.build_parcel_RepeatBinders(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBinders, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBinders, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_RepeatBinders(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#RepeatParcelables<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3], _arg_repeated: &'l2 mut [crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]) -> binder::Result<[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]> {
       let _aidl_data = self.build_parcel_RepeatParcelables(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatParcelables, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatParcelables, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_RepeatParcelables(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#Repeat2dBytes<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [[u8; 3]; 2], _arg_repeated: &'l2 mut [[u8; 3]; 2]) -> binder::Result<[[u8; 3]; 2]> {
       let _aidl_data = self.build_parcel_Repeat2dBytes(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dBytes, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dBytes, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_Repeat2dBytes(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#Repeat2dInts<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [[i32; 3]; 2], _arg_repeated: &'l2 mut [[i32; 3]; 2]) -> binder::Result<[[i32; 3]; 2]> {
       let _aidl_data = self.build_parcel_Repeat2dInts(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dInts, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dInts, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_Repeat2dInts(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#Repeat2dBinders<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [[binder::SpIBinder; 3]; 2], _arg_repeated: &'l2 mut [[Option<binder::SpIBinder>; 3]; 2]) -> binder::Result<[[binder::SpIBinder; 3]; 2]> {
       let _aidl_data = self.build_parcel_Repeat2dBinders(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dBinders, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dBinders, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_Repeat2dBinders(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#Repeat2dParcelables<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2], _arg_repeated: &'l2 mut [[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]) -> binder::Result<[[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]> {
       let _aidl_data = self.build_parcel_Repeat2dParcelables(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dParcelables, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dParcelables, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_Repeat2dParcelables(_arg_input, _arg_repeated, _aidl_reply)
     }
   }
@@ -743,7 +747,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#RepeatBytes, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#RepeatBytes, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_RepeatBytes(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -756,7 +760,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#RepeatInts, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#RepeatInts, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_RepeatInts(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -769,7 +773,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#RepeatBinders, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#RepeatBinders, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_RepeatBinders(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -782,7 +786,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#RepeatParcelables, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#RepeatParcelables, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_RepeatParcelables(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -795,7 +799,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#Repeat2dBytes, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#Repeat2dBytes, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_Repeat2dBytes(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -808,7 +812,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#Repeat2dInts, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#Repeat2dInts, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_Repeat2dInts(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -821,7 +825,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#Repeat2dBinders, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#Repeat2dBinders, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_Repeat2dBinders(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -834,7 +838,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#Repeat2dParcelables, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#Repeat2dParcelables, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_Repeat2dParcelables(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -1037,6 +1041,10 @@ pub mod r#IEmptyInterface {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IEmptyInterface["android.aidl.fixedsizearray.FixedSizeArrayExample.IEmptyInterface"] {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/android/aidl/tests/ITestService.cpp b/tests/golden_output/aidl-test-interface-cpp-source/gen/android/aidl/tests/ITestService.cpp
index 80a0b7be..43797826 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/android/aidl/tests/ITestService.cpp
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/android/aidl/tests/ITestService.cpp
@@ -113,7 +113,6 @@ BpTestService::BpTestService(const ::android::sp<::android::IBinder>& _aidl_impl
   ::android::Parcel _aidl_data;
   _aidl_data.markSensitive();
   _aidl_data.markForBinder(remoteStrong());
-  ::android::Parcel _aidl_reply;
   ::android::status_t _aidl_ret_status = ::android::OK;
   ::android::binder::Status _aidl_status;
   ::android::binder::ScopedTrace _aidl_trace(ATRACE_TAG_AIDL, "AIDL::cpp::ITestService::TestOneway::cppClient");
@@ -121,7 +120,7 @@ BpTestService::BpTestService(const ::android::sp<::android::IBinder>& _aidl_impl
   if (((_aidl_ret_status) != (::android::OK))) {
     goto _aidl_error;
   }
-  _aidl_ret_status = remote()->transact(BnTestService::TRANSACTION_TestOneway, _aidl_data, &_aidl_reply, ::android::IBinder::FLAG_ONEWAY | ::android::IBinder::FLAG_CLEAR_BUF);
+  _aidl_ret_status = remote()->transact(BnTestService::TRANSACTION_TestOneway, _aidl_data, nullptr, ::android::IBinder::FLAG_ONEWAY | ::android::IBinder::FLAG_CLEAR_BUF);
   if (_aidl_ret_status == ::android::UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) [[unlikely]] {
      return ITestService::getDefaultImpl()->TestOneway();
   }
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
index 25375baf..037d0d07 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
@@ -183,7 +183,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(iface)>, ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>()) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>, ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>, ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
index 0dca94a5..0c3ee0a6 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
@@ -193,7 +193,10 @@ public:
 
       UsingHasDeprecated() : _value(std::in_place_index<static_cast<size_t>(n)>, int32_t(0)) { }
 
-      template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+      template <typename _Tp, typename = std::enable_if_t<
+          _not_self<_Tp> &&
+          std::is_constructible_v<std::variant<int32_t, ::android::aidl::tests::ITestService::CompilerChecks::HasDeprecated>, _Tp>
+        >>
       // NOLINTNEXTLINE(google-explicit-constructor)
       constexpr UsingHasDeprecated(_Tp&& _arg)
           : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IntEnum.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IntEnum.h
index 095614f4..b4baa492 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IntEnum.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IntEnum.h
@@ -17,6 +17,9 @@ namespace android {
 namespace aidl {
 namespace tests {
 enum class IntEnum : int32_t {
+  ZERO = 0,
+  ONE = 1,
+  TWO = 2,
   FOO = 1000,
   BAR = 2000,
   BAZ = 2001,
@@ -32,6 +35,12 @@ namespace tests {
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
 [[nodiscard]] static inline std::string toString(IntEnum val) {
   switch(val) {
+  case IntEnum::ZERO:
+    return "ZERO";
+  case IntEnum::ONE:
+    return "ONE";
+  case IntEnum::TWO:
+    return "TWO";
   case IntEnum::FOO:
     return "FOO";
   case IntEnum::BAR:
@@ -54,7 +63,10 @@ namespace internal {
 #pragma clang diagnostic ignored "-Wc++17-extensions"
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
 template <>
-constexpr inline std::array<::android::aidl::tests::IntEnum, 4> enum_values<::android::aidl::tests::IntEnum> = {
+constexpr inline std::array<::android::aidl::tests::IntEnum, 7> enum_values<::android::aidl::tests::IntEnum> = {
+  ::android::aidl::tests::IntEnum::ZERO,
+  ::android::aidl::tests::IntEnum::ONE,
+  ::android::aidl::tests::IntEnum::TWO,
   ::android::aidl::tests::IntEnum::FOO,
   ::android::aidl::tests::IntEnum::BAR,
   ::android::aidl::tests::IntEnum::BAZ,
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
index c36da212..8cad3e39 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
@@ -183,7 +183,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(iface)>, ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>()) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>, ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>, ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
index 1d3125d5..b273f9cc 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
@@ -56,7 +56,10 @@ public:
 
   Union() : _value(std::in_place_index<static_cast<size_t>(ns)>, ::std::vector<int32_t>({})) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<::std::vector<int32_t>, int32_t, int32_t, ::std::string, ::android::sp<::android::IBinder>, ::std::vector<::std::string>, ::android::aidl::tests::ByteEnum>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr Union(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
index 8c9469e5..52e12f3c 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
@@ -44,7 +44,10 @@ public:
 
   UnionWithFd() : _value(std::in_place_index<static_cast<size_t>(num)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, ::android::os::ParcelFileDescriptor>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr UnionWithFd(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
index 758b7f9c..c42b268b 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
@@ -50,7 +50,10 @@ public:
 
   EnumUnion() : _value(std::in_place_index<static_cast<size_t>(intEnum)>, ::android::aidl::tests::IntEnum(::android::aidl::tests::IntEnum::FOO)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<::android::aidl::tests::IntEnum, ::android::aidl::tests::LongEnum, int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr EnumUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
index f7de5df6..75b7b2ad 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
@@ -45,7 +45,10 @@ public:
 
   UnionInUnion() : _value(std::in_place_index<static_cast<size_t>(first)>, ::android::aidl::tests::unions::EnumUnion()) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<::android::aidl::tests::unions::EnumUnion, int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr UnionInUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/IntEnum.java b/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/IntEnum.java
index 55dd7062..cde75ad0 100644
--- a/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/IntEnum.java
+++ b/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/IntEnum.java
@@ -8,6 +8,15 @@
  */
 package android.aidl.tests;
 public @interface IntEnum {
+  public static final int ZERO = 0;
+  public static final int ONE = 1;
+  public static final int TWO = 2;
+  /**
+   * Reserved: 12 and 2040
+   * We are using 12 and (FOO | BAR) in some tests because
+   * they _are not_ defined in this enum.
+   * Please do not add them here.
+   */
   public static final int FOO = 1000;
   public static final int BAR = 2000;
   public static final int BAZ = 2001;
@@ -16,6 +25,9 @@ public @interface IntEnum {
   public static final int QUX = 2002;
   interface $ {
     static String toString(int _aidl_v) {
+      if (_aidl_v == ZERO) return "ZERO";
+      if (_aidl_v == ONE) return "ONE";
+      if (_aidl_v == TWO) return "TWO";
       if (_aidl_v == FOO) return "FOO";
       if (_aidl_v == BAR) return "BAR";
       if (_aidl_v == BAZ) return "BAZ";
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ArrayOfInterfaces.h b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ArrayOfInterfaces.h
index f9f90d11..cfe1be6d 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ArrayOfInterfaces.h
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ArrayOfInterfaces.h
@@ -186,7 +186,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(iface)>, std::shared_ptr<::aidl::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>()) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<std::shared_ptr<::aidl::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>, std::shared_ptr<::aidl::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>, std::vector<std::shared_ptr<::aidl::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>, std::optional<std::vector<std::shared_ptr<::aidl::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ITestService.h b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ITestService.h
index 33e7fdb7..3ae508ab 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ITestService.h
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ITestService.h
@@ -211,7 +211,10 @@ public:
 
       UsingHasDeprecated() : _value(std::in_place_index<static_cast<size_t>(n)>, int32_t(0)) { }
 
-      template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+      template <typename _Tp, typename = std::enable_if_t<
+          _not_self<_Tp> &&
+          std::is_constructible_v<std::variant<int32_t, ::aidl::android::aidl::tests::ITestService::CompilerChecks::HasDeprecated>, _Tp>
+        >>
       // NOLINTNEXTLINE(google-explicit-constructor)
       constexpr UsingHasDeprecated(_Tp&& _arg)
           : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/IntEnum.h b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/IntEnum.h
index c1b3e0d6..298abe89 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/IntEnum.h
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/IntEnum.h
@@ -24,6 +24,9 @@ namespace android {
 namespace aidl {
 namespace tests {
 enum class IntEnum : int32_t {
+  ZERO = 0,
+  ONE = 1,
+  TWO = 2,
   FOO = 1000,
   BAR = 2000,
   BAZ = 2001,
@@ -42,6 +45,12 @@ namespace tests {
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
 [[nodiscard]] static inline std::string toString(IntEnum val) {
   switch(val) {
+  case IntEnum::ZERO:
+    return "ZERO";
+  case IntEnum::ONE:
+    return "ONE";
+  case IntEnum::TWO:
+    return "TWO";
   case IntEnum::FOO:
     return "FOO";
   case IntEnum::BAR:
@@ -65,7 +74,10 @@ namespace internal {
 #pragma clang diagnostic ignored "-Wc++17-extensions"
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
 template <>
-constexpr inline std::array<aidl::android::aidl::tests::IntEnum, 4> enum_values<aidl::android::aidl::tests::IntEnum> = {
+constexpr inline std::array<aidl::android::aidl::tests::IntEnum, 7> enum_values<aidl::android::aidl::tests::IntEnum> = {
+  aidl::android::aidl::tests::IntEnum::ZERO,
+  aidl::android::aidl::tests::IntEnum::ONE,
+  aidl::android::aidl::tests::IntEnum::TWO,
   aidl::android::aidl::tests::IntEnum::FOO,
   aidl::android::aidl::tests::IntEnum::BAR,
   aidl::android::aidl::tests::IntEnum::BAZ,
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ListOfInterfaces.h b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ListOfInterfaces.h
index 1a2a7c23..f24e932f 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ListOfInterfaces.h
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ListOfInterfaces.h
@@ -186,7 +186,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(iface)>, std::shared_ptr<::aidl::android::aidl::tests::ListOfInterfaces::IEmptyInterface>()) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<std::shared_ptr<::aidl::android::aidl::tests::ListOfInterfaces::IEmptyInterface>, std::shared_ptr<::aidl::android::aidl::tests::ListOfInterfaces::IEmptyInterface>, std::vector<std::shared_ptr<::aidl::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>, std::optional<std::vector<std::shared_ptr<::aidl::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/Union.h b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/Union.h
index 7ae2f672..1f7bc5c8 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/Union.h
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/Union.h
@@ -64,7 +64,10 @@ public:
 
   Union() : _value(std::in_place_index<static_cast<size_t>(ns)>, std::vector<int32_t>({})) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<std::vector<int32_t>, int32_t, int32_t, std::string, ::ndk::SpAIBinder, std::vector<std::string>, ::aidl::android::aidl::tests::ByteEnum>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr Union(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/UnionWithFd.h b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/UnionWithFd.h
index b18bd940..5c4cc3d7 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/UnionWithFd.h
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/UnionWithFd.h
@@ -53,7 +53,10 @@ public:
 
   UnionWithFd() : _value(std::in_place_index<static_cast<size_t>(num)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, ::ndk::ScopedFileDescriptor>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr UnionWithFd(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/EnumUnion.h b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/EnumUnion.h
index f3e54f48..028b9bac 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/EnumUnion.h
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/EnumUnion.h
@@ -60,7 +60,10 @@ public:
 
   EnumUnion() : _value(std::in_place_index<static_cast<size_t>(intEnum)>, ::aidl::android::aidl::tests::IntEnum(::aidl::android::aidl::tests::IntEnum::FOO)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<::aidl::android::aidl::tests::IntEnum, ::aidl::android::aidl::tests::LongEnum, int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr EnumUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/UnionInUnion.h b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/UnionInUnion.h
index a4587da9..4c301178 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/UnionInUnion.h
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/UnionInUnion.h
@@ -55,7 +55,10 @@ public:
 
   UnionInUnion() : _value(std::in_place_index<static_cast<size_t>(first)>, ::aidl::android::aidl::tests::unions::EnumUnion()) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<::aidl::android::aidl::tests::unions::EnumUnion, int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr UnionInUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
index 0891ec2d..8501fbd0 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
@@ -38,6 +38,10 @@ pub mod r#IEmptyInterface {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IEmptyInterface["android.aidl.tests.ArrayOfInterfaces.IEmptyInterface"] {
@@ -131,6 +135,10 @@ pub mod r#IMyInterface {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IMyInterface["android.aidl.tests.ArrayOfInterfaces.IMyInterface"] {
@@ -252,7 +260,7 @@ pub mod r#IMyInterface {
   impl IMyInterface for BpMyInterface {
     fn r#methodWithInterfaces<'a, 'l1, 'l2, 'l3, 'l4, 'l5, 'l6, 'l7, 'l8, >(&'a self, _arg_iface: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&'l2 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_iface_array_in: &'l3 [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>], _arg_iface_array_out: &'l4 mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>, _arg_iface_array_inout: &'l5 mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_array_in: Option<&'l6 [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_array_out: &'l7 mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_array_inout: &'l8 mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>> {
       let _aidl_data = self.build_parcel_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_array_in, _arg_iface_array_out, _arg_iface_array_inout, _arg_nullable_iface_array_in, _arg_nullable_iface_array_out, _arg_nullable_iface_array_inout)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_array_in, _arg_iface_array_out, _arg_iface_array_inout, _arg_nullable_iface_array_in, _arg_nullable_iface_array_out, _arg_nullable_iface_array_inout, _aidl_reply)
     }
   }
@@ -264,7 +272,7 @@ pub mod r#IMyInterface {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_array_in, _arg_iface_array_out, _arg_iface_array_inout, _arg_nullable_iface_array_in, _arg_nullable_iface_array_out, _arg_nullable_iface_array_inout, _aidl_reply)
         }
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
index b9371082..8195fa7d 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   ICircular["android.aidl.tests.ICircular"] {
@@ -120,7 +124,7 @@ impl BpCircular {
 impl ICircular for BpCircular {
   fn r#GetTestService<'a, >(&'a self) -> binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_12_ITestService>>> {
     let _aidl_data = self.build_parcel_GetTestService()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetTestService, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetTestService, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_GetTestService(_aidl_reply)
   }
 }
@@ -132,7 +136,7 @@ impl<P: binder::BinderAsyncPool> ICircularAsync<P> for BpCircular {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetTestService, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetTestService, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetTestService(_aidl_reply)
       }
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
index ea7c552a..b3d604ac 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   IDeprecated["android.aidl.tests.IDeprecated"] {
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
index fb90c196..62ea9300 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   INamedCallback["android.aidl.tests.INamedCallback"] {
@@ -120,7 +124,7 @@ impl BpNamedCallback {
 impl INamedCallback for BpNamedCallback {
   fn r#GetName<'a, >(&'a self) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_GetName()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetName, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_GetName(_aidl_reply)
   }
 }
@@ -132,7 +136,7 @@ impl<P: binder::BinderAsyncPool> INamedCallbackAsync<P> for BpNamedCallback {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetName, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetName(_aidl_reply)
       }
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
index 55916bf1..d018ce89 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   INewName["android.aidl.tests.IOldName"] {
@@ -120,7 +124,7 @@ impl BpNewName {
 impl INewName for BpNewName {
   fn r#RealName<'a, >(&'a self) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_RealName()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RealName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RealName, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_RealName(_aidl_reply)
   }
 }
@@ -132,7 +136,7 @@ impl<P: binder::BinderAsyncPool> INewNameAsync<P> for BpNewName {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RealName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RealName, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RealName(_aidl_reply)
       }
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
index 259b7f52..3960e51f 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   IOldName["android.aidl.tests.IOldName"] {
@@ -120,7 +124,7 @@ impl BpOldName {
 impl IOldName for BpOldName {
   fn r#RealName<'a, >(&'a self) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_RealName()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RealName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RealName, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_RealName(_aidl_reply)
   }
 }
@@ -132,7 +136,7 @@ impl<P: binder::BinderAsyncPool> IOldNameAsync<P> for BpOldName {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RealName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RealName, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RealName(_aidl_reply)
       }
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
index df0cab46..c6491780 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   ITestService["android.aidl.tests.ITestService"] {
@@ -2412,357 +2416,357 @@ impl BpTestService {
 impl ITestService for BpTestService {
   fn r#UnimplementedMethod<'a, >(&'a self, _arg_arg: i32) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_UnimplementedMethod(_arg_arg)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#UnimplementedMethod, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#UnimplementedMethod, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_UnimplementedMethod(_arg_arg, _aidl_reply)
   }
   fn r#Deprecated<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_Deprecated()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#Deprecated, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#Deprecated, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_Deprecated(_aidl_reply)
   }
   fn r#TestOneway<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_TestOneway()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_TestOneway(_aidl_reply)
   }
   fn r#RepeatBoolean<'a, >(&'a self, _arg_token: bool) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_RepeatBoolean(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatBoolean(_arg_token, _aidl_reply)
   }
   fn r#RepeatByte<'a, >(&'a self, _arg_token: i8) -> binder::Result<i8> {
     let _aidl_data = self.build_parcel_RepeatByte(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatByte(_arg_token, _aidl_reply)
   }
   fn r#RepeatChar<'a, >(&'a self, _arg_token: u16) -> binder::Result<u16> {
     let _aidl_data = self.build_parcel_RepeatChar(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatChar(_arg_token, _aidl_reply)
   }
   fn r#RepeatInt<'a, >(&'a self, _arg_token: i32) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_RepeatInt(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatInt(_arg_token, _aidl_reply)
   }
   fn r#RepeatLong<'a, >(&'a self, _arg_token: i64) -> binder::Result<i64> {
     let _aidl_data = self.build_parcel_RepeatLong(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatLong(_arg_token, _aidl_reply)
   }
   fn r#RepeatFloat<'a, >(&'a self, _arg_token: f32) -> binder::Result<f32> {
     let _aidl_data = self.build_parcel_RepeatFloat(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatFloat(_arg_token, _aidl_reply)
   }
   fn r#RepeatDouble<'a, >(&'a self, _arg_token: f64) -> binder::Result<f64> {
     let _aidl_data = self.build_parcel_RepeatDouble(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatDouble(_arg_token, _aidl_reply)
   }
   fn r#RepeatString<'a, 'l1, >(&'a self, _arg_token: &'l1 str) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_RepeatString(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatString(_arg_token, _aidl_reply)
   }
   fn r#RepeatByteEnum<'a, >(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum> {
     let _aidl_data = self.build_parcel_RepeatByteEnum(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatByteEnum(_arg_token, _aidl_reply)
   }
   fn r#RepeatIntEnum<'a, >(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum> {
     let _aidl_data = self.build_parcel_RepeatIntEnum(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatIntEnum(_arg_token, _aidl_reply)
   }
   fn r#RepeatLongEnum<'a, >(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum> {
     let _aidl_data = self.build_parcel_RepeatLongEnum(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatLongEnum(_arg_token, _aidl_reply)
   }
   fn r#ReverseBoolean<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [bool], _arg_repeated: &'l2 mut Vec<bool>) -> binder::Result<Vec<bool>> {
     let _aidl_data = self.build_parcel_ReverseBoolean(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseBoolean(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseByte<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [u8], _arg_repeated: &'l2 mut Vec<u8>) -> binder::Result<Vec<u8>> {
     let _aidl_data = self.build_parcel_ReverseByte(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseByte(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseChar<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [u16], _arg_repeated: &'l2 mut Vec<u16>) -> binder::Result<Vec<u16>> {
     let _aidl_data = self.build_parcel_ReverseChar(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseChar(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseInt<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [i32], _arg_repeated: &'l2 mut Vec<i32>) -> binder::Result<Vec<i32>> {
     let _aidl_data = self.build_parcel_ReverseInt(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseInt(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseLong<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [i64], _arg_repeated: &'l2 mut Vec<i64>) -> binder::Result<Vec<i64>> {
     let _aidl_data = self.build_parcel_ReverseLong(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseLong(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseFloat<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [f32], _arg_repeated: &'l2 mut Vec<f32>) -> binder::Result<Vec<f32>> {
     let _aidl_data = self.build_parcel_ReverseFloat(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseFloat(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseDouble<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [f64], _arg_repeated: &'l2 mut Vec<f64>) -> binder::Result<Vec<f64>> {
     let _aidl_data = self.build_parcel_ReverseDouble(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseDouble(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseString<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [String], _arg_repeated: &'l2 mut Vec<String>) -> binder::Result<Vec<String>> {
     let _aidl_data = self.build_parcel_ReverseString(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseString(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseByteEnum<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum], _arg_repeated: &'l2 mut Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>) -> binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>> {
     let _aidl_data = self.build_parcel_ReverseByteEnum(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseByteEnum(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseIntEnum<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum], _arg_repeated: &'l2 mut Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>) -> binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>> {
     let _aidl_data = self.build_parcel_ReverseIntEnum(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseIntEnum(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseLongEnum<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum], _arg_repeated: &'l2 mut Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>) -> binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>> {
     let _aidl_data = self.build_parcel_ReverseLongEnum(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseLongEnum(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#GetOtherTestService<'a, 'l1, >(&'a self, _arg_name: &'l1 str) -> binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>> {
     let _aidl_data = self.build_parcel_GetOtherTestService(_arg_name)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetOtherTestService(_arg_name, _aidl_reply)
   }
   fn r#SetOtherTestService<'a, 'l1, 'l2, >(&'a self, _arg_name: &'l1 str, _arg_service: &'l2 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_SetOtherTestService(_arg_name, _arg_service)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#SetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#SetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_SetOtherTestService(_arg_name, _arg_service, _aidl_reply)
   }
   fn r#VerifyName<'a, 'l1, 'l2, >(&'a self, _arg_service: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>, _arg_name: &'l2 str) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_VerifyName(_arg_service, _arg_name)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyName, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyName, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_VerifyName(_arg_service, _arg_name, _aidl_reply)
   }
   fn r#GetInterfaceArray<'a, 'l1, >(&'a self, _arg_names: &'l1 [String]) -> binder::Result<Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>> {
     let _aidl_data = self.build_parcel_GetInterfaceArray(_arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetInterfaceArray(_arg_names, _aidl_reply)
   }
   fn r#VerifyNamesWithInterfaceArray<'a, 'l1, 'l2, >(&'a self, _arg_services: &'l1 [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>], _arg_names: &'l2 [String]) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_VerifyNamesWithInterfaceArray(_arg_services, _arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_VerifyNamesWithInterfaceArray(_arg_services, _arg_names, _aidl_reply)
   }
   fn r#GetNullableInterfaceArray<'a, 'l1, >(&'a self, _arg_names: Option<&'l1 [Option<String>]>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>>> {
     let _aidl_data = self.build_parcel_GetNullableInterfaceArray(_arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetNullableInterfaceArray(_arg_names, _aidl_reply)
   }
   fn r#VerifyNamesWithNullableInterfaceArray<'a, 'l1, 'l2, >(&'a self, _arg_services: Option<&'l1 [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>]>, _arg_names: Option<&'l2 [Option<String>]>) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_VerifyNamesWithNullableInterfaceArray(_arg_services, _arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_VerifyNamesWithNullableInterfaceArray(_arg_services, _arg_names, _aidl_reply)
   }
   fn r#GetInterfaceList<'a, 'l1, >(&'a self, _arg_names: Option<&'l1 [Option<String>]>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>>> {
     let _aidl_data = self.build_parcel_GetInterfaceList(_arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetInterfaceList(_arg_names, _aidl_reply)
   }
   fn r#VerifyNamesWithInterfaceList<'a, 'l1, 'l2, >(&'a self, _arg_services: Option<&'l1 [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>]>, _arg_names: Option<&'l2 [Option<String>]>) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_VerifyNamesWithInterfaceList(_arg_services, _arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_VerifyNamesWithInterfaceList(_arg_services, _arg_names, _aidl_reply)
   }
   fn r#ReverseStringList<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [String], _arg_repeated: &'l2 mut Vec<String>) -> binder::Result<Vec<String>> {
     let _aidl_data = self.build_parcel_ReverseStringList(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseStringList(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#RepeatParcelFileDescriptor<'a, 'l1, >(&'a self, _arg_read: &'l1 binder::ParcelFileDescriptor) -> binder::Result<binder::ParcelFileDescriptor> {
     let _aidl_data = self.build_parcel_RepeatParcelFileDescriptor(_arg_read)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatParcelFileDescriptor, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatParcelFileDescriptor, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatParcelFileDescriptor(_arg_read, _aidl_reply)
   }
   fn r#ReverseParcelFileDescriptorArray<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [binder::ParcelFileDescriptor], _arg_repeated: &'l2 mut Vec<Option<binder::ParcelFileDescriptor>>) -> binder::Result<Vec<binder::ParcelFileDescriptor>> {
     let _aidl_data = self.build_parcel_ReverseParcelFileDescriptorArray(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseParcelFileDescriptorArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseParcelFileDescriptorArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseParcelFileDescriptorArray(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ThrowServiceException<'a, >(&'a self, _arg_code: i32) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_ThrowServiceException(_arg_code)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ThrowServiceException, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ThrowServiceException, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ThrowServiceException(_arg_code, _aidl_reply)
   }
   fn r#RepeatNullableIntArray<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [i32]>) -> binder::Result<Option<Vec<i32>>> {
     let _aidl_data = self.build_parcel_RepeatNullableIntArray(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableIntArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableIntArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableIntArray(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableByteEnumArray<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum]>) -> binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>>> {
     let _aidl_data = self.build_parcel_RepeatNullableByteEnumArray(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableByteEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableByteEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableByteEnumArray(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableIntEnumArray<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum]>) -> binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>>> {
     let _aidl_data = self.build_parcel_RepeatNullableIntEnumArray(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableIntEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableIntEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableIntEnumArray(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableLongEnumArray<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum]>) -> binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>>> {
     let _aidl_data = self.build_parcel_RepeatNullableLongEnumArray(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableLongEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableLongEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableLongEnumArray(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableString<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 str>) -> binder::Result<Option<String>> {
     let _aidl_data = self.build_parcel_RepeatNullableString(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableString(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableStringList<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [Option<String>]>) -> binder::Result<Option<Vec<Option<String>>>> {
     let _aidl_data = self.build_parcel_RepeatNullableStringList(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableStringList(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableParcelable<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>) -> binder::Result<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>> {
     let _aidl_data = self.build_parcel_RepeatNullableParcelable(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableParcelable(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableParcelableArray<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>]>) -> binder::Result<Option<Vec<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>>>> {
     let _aidl_data = self.build_parcel_RepeatNullableParcelableArray(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelableArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelableArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableParcelableArray(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableParcelableList<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>]>) -> binder::Result<Option<Vec<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>>>> {
     let _aidl_data = self.build_parcel_RepeatNullableParcelableList(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelableList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelableList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableParcelableList(_arg_input, _aidl_reply)
   }
   fn r#TakesAnIBinder<'a, 'l1, >(&'a self, _arg_input: &'l1 binder::SpIBinder) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_TakesAnIBinder(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesAnIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesAnIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_TakesAnIBinder(_arg_input, _aidl_reply)
   }
   fn r#TakesANullableIBinder<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 binder::SpIBinder>) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_TakesANullableIBinder(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesANullableIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesANullableIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_TakesANullableIBinder(_arg_input, _aidl_reply)
   }
   fn r#TakesAnIBinderList<'a, 'l1, >(&'a self, _arg_input: &'l1 [binder::SpIBinder]) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_TakesAnIBinderList(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesAnIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesAnIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_TakesAnIBinderList(_arg_input, _aidl_reply)
   }
   fn r#TakesANullableIBinderList<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [Option<binder::SpIBinder>]>) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_TakesANullableIBinderList(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesANullableIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesANullableIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_TakesANullableIBinderList(_arg_input, _aidl_reply)
   }
   fn r#RepeatUtf8CppString<'a, 'l1, >(&'a self, _arg_token: &'l1 str) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_RepeatUtf8CppString(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatUtf8CppString(_arg_token, _aidl_reply)
   }
   fn r#RepeatNullableUtf8CppString<'a, 'l1, >(&'a self, _arg_token: Option<&'l1 str>) -> binder::Result<Option<String>> {
     let _aidl_data = self.build_parcel_RepeatNullableUtf8CppString(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableUtf8CppString(_arg_token, _aidl_reply)
   }
   fn r#ReverseUtf8CppString<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [String], _arg_repeated: &'l2 mut Vec<String>) -> binder::Result<Vec<String>> {
     let _aidl_data = self.build_parcel_ReverseUtf8CppString(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseUtf8CppString(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseNullableUtf8CppString<'a, 'l1, 'l2, >(&'a self, _arg_input: Option<&'l1 [Option<String>]>, _arg_repeated: &'l2 mut Option<Vec<Option<String>>>) -> binder::Result<Option<Vec<Option<String>>>> {
     let _aidl_data = self.build_parcel_ReverseNullableUtf8CppString(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseNullableUtf8CppString(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseUtf8CppStringList<'a, 'l1, 'l2, >(&'a self, _arg_input: Option<&'l1 [Option<String>]>, _arg_repeated: &'l2 mut Option<Vec<Option<String>>>) -> binder::Result<Option<Vec<Option<String>>>> {
     let _aidl_data = self.build_parcel_ReverseUtf8CppStringList(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseUtf8CppStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseUtf8CppStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseUtf8CppStringList(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#GetCallback<'a, >(&'a self, _arg_return_null: bool) -> binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>> {
     let _aidl_data = self.build_parcel_GetCallback(_arg_return_null)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCallback, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCallback, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetCallback(_arg_return_null, _aidl_reply)
   }
   fn r#FillOutStructuredParcelable<'a, 'l1, >(&'a self, _arg_parcel: &'l1 mut crate::mangled::_7_android_4_aidl_5_tests_20_StructuredParcelable) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_FillOutStructuredParcelable(_arg_parcel)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#FillOutStructuredParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#FillOutStructuredParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_FillOutStructuredParcelable(_arg_parcel, _aidl_reply)
   }
   fn r#RepeatExtendableParcelable<'a, 'l1, 'l2, >(&'a self, _arg_ep: &'l1 crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable, _arg_ep2: &'l2 mut crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_RepeatExtendableParcelable(_arg_ep, _arg_ep2)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatExtendableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatExtendableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatExtendableParcelable(_arg_ep, _arg_ep2, _aidl_reply)
   }
   fn r#RepeatExtendableParcelableVintf<'a, 'l1, 'l2, >(&'a self, _arg_ep: &'l1 crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable, _arg_ep2: &'l2 mut crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_RepeatExtendableParcelableVintf(_arg_ep, _arg_ep2)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatExtendableParcelableVintf, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatExtendableParcelableVintf, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatExtendableParcelableVintf(_arg_ep, _arg_ep2, _aidl_reply)
   }
   fn r#ReverseList<'a, 'l1, >(&'a self, _arg_list: &'l1 crate::mangled::_7_android_4_aidl_5_tests_13_RecursiveList) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_13_RecursiveList> {
     let _aidl_data = self.build_parcel_ReverseList(_arg_list)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseList(_arg_list, _aidl_reply)
   }
   fn r#ReverseIBinderArray<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [binder::SpIBinder], _arg_repeated: &'l2 mut Vec<Option<binder::SpIBinder>>) -> binder::Result<Vec<binder::SpIBinder>> {
     let _aidl_data = self.build_parcel_ReverseIBinderArray(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseIBinderArray(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseNullableIBinderArray<'a, 'l1, 'l2, >(&'a self, _arg_input: Option<&'l1 [Option<binder::SpIBinder>]>, _arg_repeated: &'l2 mut Option<Vec<Option<binder::SpIBinder>>>) -> binder::Result<Option<Vec<Option<binder::SpIBinder>>>> {
     let _aidl_data = self.build_parcel_ReverseNullableIBinderArray(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseNullableIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseNullableIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseNullableIBinderArray(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#RepeatSimpleParcelable<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 simple_parcelable::SimpleParcelable, _arg_repeat: &'l2 mut simple_parcelable::SimpleParcelable) -> binder::Result<simple_parcelable::SimpleParcelable> {
     let _aidl_data = self.build_parcel_RepeatSimpleParcelable(_arg_input, _arg_repeat)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatSimpleParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatSimpleParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatSimpleParcelable(_arg_input, _arg_repeat, _aidl_reply)
   }
   fn r#ReverseSimpleParcelables<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [simple_parcelable::SimpleParcelable], _arg_repeated: &'l2 mut Vec<simple_parcelable::SimpleParcelable>) -> binder::Result<Vec<simple_parcelable::SimpleParcelable>> {
     let _aidl_data = self.build_parcel_ReverseSimpleParcelables(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseSimpleParcelables, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseSimpleParcelables, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseSimpleParcelables(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#GetOldNameInterface<'a, >(&'a self) -> binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_8_IOldName>> {
     let _aidl_data = self.build_parcel_GetOldNameInterface()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetOldNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetOldNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetOldNameInterface(_aidl_reply)
   }
   fn r#GetNewNameInterface<'a, >(&'a self) -> binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_8_INewName>> {
     let _aidl_data = self.build_parcel_GetNewNameInterface()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetNewNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetNewNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetNewNameInterface(_aidl_reply)
   }
   fn r#GetUnionTags<'a, 'l1, >(&'a self, _arg_input: &'l1 [crate::mangled::_7_android_4_aidl_5_tests_5_Union]) -> binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_5_Union_3_Tag>> {
     let _aidl_data = self.build_parcel_GetUnionTags(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetUnionTags, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetUnionTags, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetUnionTags(_arg_input, _aidl_reply)
   }
   fn r#GetCppJavaTests<'a, >(&'a self) -> binder::Result<Option<binder::SpIBinder>> {
     let _aidl_data = self.build_parcel_GetCppJavaTests()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCppJavaTests, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCppJavaTests, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetCppJavaTests(_aidl_reply)
   }
   fn r#getBackendType<'a, >(&'a self) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_11_BackendType> {
     let _aidl_data = self.build_parcel_getBackendType()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getBackendType, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getBackendType, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_getBackendType(_aidl_reply)
   }
   fn r#GetCircular<'a, 'l1, >(&'a self, _arg_cp: &'l1 mut crate::mangled::_7_android_4_aidl_5_tests_18_CircularParcelable) -> binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_9_ICircular>> {
     let _aidl_data = self.build_parcel_GetCircular(_arg_cp)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCircular, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCircular, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetCircular(_arg_cp, _aidl_reply)
   }
 }
@@ -2774,7 +2778,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#UnimplementedMethod, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#UnimplementedMethod, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_UnimplementedMethod(_arg_arg, _aidl_reply)
       }
@@ -2787,7 +2791,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#Deprecated, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#Deprecated, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_Deprecated(_aidl_reply)
       }
@@ -2800,7 +2804,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_TestOneway(_aidl_reply)
       }
@@ -2813,7 +2817,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatBoolean(_arg_token, _aidl_reply)
       }
@@ -2826,7 +2830,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatByte(_arg_token, _aidl_reply)
       }
@@ -2839,7 +2843,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatChar(_arg_token, _aidl_reply)
       }
@@ -2852,7 +2856,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatInt(_arg_token, _aidl_reply)
       }
@@ -2865,7 +2869,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatLong(_arg_token, _aidl_reply)
       }
@@ -2878,7 +2882,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatFloat(_arg_token, _aidl_reply)
       }
@@ -2891,7 +2895,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatDouble(_arg_token, _aidl_reply)
       }
@@ -2904,7 +2908,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatString(_arg_token, _aidl_reply)
       }
@@ -2917,7 +2921,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatByteEnum(_arg_token, _aidl_reply)
       }
@@ -2930,7 +2934,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatIntEnum(_arg_token, _aidl_reply)
       }
@@ -2943,7 +2947,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatLongEnum(_arg_token, _aidl_reply)
       }
@@ -2956,7 +2960,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseBoolean(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -2969,7 +2973,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseByte(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -2982,7 +2986,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseChar(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -2995,7 +2999,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseInt(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3008,7 +3012,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseLong(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3021,7 +3025,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseFloat(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3034,7 +3038,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseDouble(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3047,7 +3051,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseString(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3060,7 +3064,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseByteEnum(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3073,7 +3077,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseIntEnum(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3086,7 +3090,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseLongEnum(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3099,7 +3103,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetOtherTestService(_arg_name, _aidl_reply)
       }
@@ -3112,7 +3116,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#SetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#SetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_SetOtherTestService(_arg_name, _arg_service, _aidl_reply)
       }
@@ -3125,7 +3129,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#VerifyName, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#VerifyName, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_VerifyName(_arg_service, _arg_name, _aidl_reply)
       }
@@ -3138,7 +3142,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetInterfaceArray(_arg_names, _aidl_reply)
       }
@@ -3151,7 +3155,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#VerifyNamesWithInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#VerifyNamesWithInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_VerifyNamesWithInterfaceArray(_arg_services, _arg_names, _aidl_reply)
       }
@@ -3164,7 +3168,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetNullableInterfaceArray(_arg_names, _aidl_reply)
       }
@@ -3177,7 +3181,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#VerifyNamesWithNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#VerifyNamesWithNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_VerifyNamesWithNullableInterfaceArray(_arg_services, _arg_names, _aidl_reply)
       }
@@ -3190,7 +3194,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetInterfaceList(_arg_names, _aidl_reply)
       }
@@ -3203,7 +3207,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#VerifyNamesWithInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#VerifyNamesWithInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_VerifyNamesWithInterfaceList(_arg_services, _arg_names, _aidl_reply)
       }
@@ -3216,7 +3220,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseStringList(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3229,7 +3233,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatParcelFileDescriptor, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatParcelFileDescriptor, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatParcelFileDescriptor(_arg_read, _aidl_reply)
       }
@@ -3242,7 +3246,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseParcelFileDescriptorArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseParcelFileDescriptorArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseParcelFileDescriptorArray(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3255,7 +3259,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ThrowServiceException, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ThrowServiceException, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ThrowServiceException(_arg_code, _aidl_reply)
       }
@@ -3268,7 +3272,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableIntArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableIntArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableIntArray(_arg_input, _aidl_reply)
       }
@@ -3281,7 +3285,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableByteEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableByteEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableByteEnumArray(_arg_input, _aidl_reply)
       }
@@ -3294,7 +3298,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableIntEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableIntEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableIntEnumArray(_arg_input, _aidl_reply)
       }
@@ -3307,7 +3311,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableLongEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableLongEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableLongEnumArray(_arg_input, _aidl_reply)
       }
@@ -3320,7 +3324,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableString(_arg_input, _aidl_reply)
       }
@@ -3333,7 +3337,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableStringList(_arg_input, _aidl_reply)
       }
@@ -3346,7 +3350,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableParcelable(_arg_input, _aidl_reply)
       }
@@ -3359,7 +3363,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableParcelableArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableParcelableArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableParcelableArray(_arg_input, _aidl_reply)
       }
@@ -3372,7 +3376,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableParcelableList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableParcelableList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableParcelableList(_arg_input, _aidl_reply)
       }
@@ -3385,7 +3389,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#TakesAnIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#TakesAnIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_TakesAnIBinder(_arg_input, _aidl_reply)
       }
@@ -3398,7 +3402,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#TakesANullableIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#TakesANullableIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_TakesANullableIBinder(_arg_input, _aidl_reply)
       }
@@ -3411,7 +3415,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#TakesAnIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#TakesAnIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_TakesAnIBinderList(_arg_input, _aidl_reply)
       }
@@ -3424,7 +3428,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#TakesANullableIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#TakesANullableIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_TakesANullableIBinderList(_arg_input, _aidl_reply)
       }
@@ -3437,7 +3441,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatUtf8CppString(_arg_token, _aidl_reply)
       }
@@ -3450,7 +3454,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableUtf8CppString(_arg_token, _aidl_reply)
       }
@@ -3463,7 +3467,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseUtf8CppString(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3476,7 +3480,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseNullableUtf8CppString(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3489,7 +3493,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseUtf8CppStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseUtf8CppStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseUtf8CppStringList(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3502,7 +3506,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetCallback, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetCallback, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetCallback(_arg_return_null, _aidl_reply)
       }
@@ -3515,7 +3519,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#FillOutStructuredParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#FillOutStructuredParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_FillOutStructuredParcelable(_arg_parcel, _aidl_reply)
       }
@@ -3528,7 +3532,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatExtendableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatExtendableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatExtendableParcelable(_arg_ep, _arg_ep2, _aidl_reply)
       }
@@ -3541,7 +3545,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatExtendableParcelableVintf, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatExtendableParcelableVintf, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatExtendableParcelableVintf(_arg_ep, _arg_ep2, _aidl_reply)
       }
@@ -3554,7 +3558,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseList(_arg_list, _aidl_reply)
       }
@@ -3567,7 +3571,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseIBinderArray(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3580,7 +3584,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseNullableIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseNullableIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseNullableIBinderArray(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3593,7 +3597,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatSimpleParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatSimpleParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatSimpleParcelable(_arg_input, _arg_repeat, _aidl_reply)
       }
@@ -3606,7 +3610,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseSimpleParcelables, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseSimpleParcelables, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseSimpleParcelables(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3619,7 +3623,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetOldNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetOldNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetOldNameInterface(_aidl_reply)
       }
@@ -3632,7 +3636,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetNewNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetNewNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetNewNameInterface(_aidl_reply)
       }
@@ -3645,7 +3649,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetUnionTags, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetUnionTags, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetUnionTags(_arg_input, _aidl_reply)
       }
@@ -3658,7 +3662,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetCppJavaTests, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetCppJavaTests, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetCppJavaTests(_aidl_reply)
       }
@@ -3671,7 +3675,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getBackendType, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getBackendType, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getBackendType(_aidl_reply)
       }
@@ -3684,7 +3688,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetCircular, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetCircular, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetCircular(_arg_cp, _aidl_reply)
       }
@@ -4837,6 +4841,10 @@ pub mod r#CompilerChecks {
     #![allow(non_upper_case_globals)]
     #![allow(non_snake_case)]
     #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+    #[cfg(any(android_vndk, not(android_ndk)))]
+    const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+    #[cfg(not(any(android_vndk, not(android_ndk))))]
+    const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
     use binder::declare_binder_interface;
     declare_binder_interface! {
       IFoo["android.aidl.tests.ITestService.CompilerChecks.Foo"] {
@@ -5025,6 +5033,10 @@ pub mod r#CompilerChecks {
     #![allow(non_upper_case_globals)]
     #![allow(non_snake_case)]
     #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+    #[cfg(any(android_vndk, not(android_ndk)))]
+    const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+    #[cfg(not(any(android_vndk, not(android_ndk))))]
+    const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
     use binder::declare_binder_interface;
     declare_binder_interface! {
       INoPrefixInterface["android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface"] {
@@ -5133,7 +5145,7 @@ pub mod r#CompilerChecks {
     impl INoPrefixInterface for BpNoPrefixInterface {
       fn r#foo<'a, >(&'a self) -> binder::Result<()> {
         let _aidl_data = self.build_parcel_foo()?;
-        let _aidl_reply = self.binder.submit_transact(transactions::r#foo, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+        let _aidl_reply = self.binder.submit_transact(transactions::r#foo, _aidl_data, FLAG_PRIVATE_LOCAL);
         self.read_response_foo(_aidl_reply)
       }
     }
@@ -5145,7 +5157,7 @@ pub mod r#CompilerChecks {
         };
         let binder = self.binder.clone();
         P::spawn(
-          move || binder.submit_transact(transactions::r#foo, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+          move || binder.submit_transact(transactions::r#foo, _aidl_data, FLAG_PRIVATE_LOCAL),
           move |_aidl_reply| async move {
             self.read_response_foo(_aidl_reply)
           }
@@ -5202,6 +5214,10 @@ pub mod r#CompilerChecks {
       #![allow(non_upper_case_globals)]
       #![allow(non_snake_case)]
       #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+      #[cfg(any(android_vndk, not(android_ndk)))]
+      const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+      #[cfg(not(any(android_vndk, not(android_ndk))))]
+      const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
       use binder::declare_binder_interface;
       declare_binder_interface! {
         INestedNoPrefixInterface["android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface.NestedNoPrefixInterface"] {
@@ -5310,7 +5326,7 @@ pub mod r#CompilerChecks {
       impl INestedNoPrefixInterface for BpNestedNoPrefixInterface {
         fn r#foo<'a, >(&'a self) -> binder::Result<()> {
           let _aidl_data = self.build_parcel_foo()?;
-          let _aidl_reply = self.binder.submit_transact(transactions::r#foo, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+          let _aidl_reply = self.binder.submit_transact(transactions::r#foo, _aidl_data, FLAG_PRIVATE_LOCAL);
           self.read_response_foo(_aidl_reply)
         }
       }
@@ -5322,7 +5338,7 @@ pub mod r#CompilerChecks {
           };
           let binder = self.binder.clone();
           P::spawn(
-            move || binder.submit_transact(transactions::r#foo, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+            move || binder.submit_transact(transactions::r#foo, _aidl_data, FLAG_PRIVATE_LOCAL),
             move |_aidl_reply| async move {
               self.read_response_foo(_aidl_reply)
             }
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IntEnum.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IntEnum.rs
index 98ed005c..0be6697b 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IntEnum.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IntEnum.rs
@@ -12,7 +12,10 @@
 use binder::declare_binder_enum;
 declare_binder_enum! {
   #[repr(C, align(4))]
-  r#IntEnum : [i32; 4] {
+  r#IntEnum : [i32; 7] {
+    r#ZERO = 0,
+    r#ONE = 1,
+    r#TWO = 2,
     r#FOO = 1000,
     r#BAR = 2000,
     r#BAZ = 2001,
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
index 6540b0d5..7ce8e8af 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
@@ -38,6 +38,10 @@ pub mod r#IEmptyInterface {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IEmptyInterface["android.aidl.tests.ListOfInterfaces.IEmptyInterface"] {
@@ -131,6 +135,10 @@ pub mod r#IMyInterface {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IMyInterface["android.aidl.tests.ListOfInterfaces.IMyInterface"] {
@@ -250,7 +258,7 @@ pub mod r#IMyInterface {
   impl IMyInterface for BpMyInterface {
     fn r#methodWithInterfaces<'a, 'l1, 'l2, 'l3, 'l4, 'l5, 'l6, 'l7, 'l8, >(&'a self, _arg_iface: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&'l2 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_iface_list_in: &'l3 [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>], _arg_iface_list_out: &'l4 mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>, _arg_iface_list_inout: &'l5 mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_list_in: Option<&'l6 [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_list_out: &'l7 mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_list_inout: &'l8 mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>> {
       let _aidl_data = self.build_parcel_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_list_in, _arg_iface_list_out, _arg_iface_list_inout, _arg_nullable_iface_list_in, _arg_nullable_iface_list_out, _arg_nullable_iface_list_inout)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_list_in, _arg_iface_list_out, _arg_iface_list_inout, _arg_nullable_iface_list_in, _arg_nullable_iface_list_out, _arg_nullable_iface_list_inout, _aidl_reply)
     }
   }
@@ -262,7 +270,7 @@ pub mod r#IMyInterface {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_list_in, _arg_iface_list_out, _arg_iface_list_inout, _arg_nullable_iface_list_in, _arg_nullable_iface_list_out, _arg_nullable_iface_list_inout, _aidl_reply)
         }
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
index af40d2f3..da9251c5 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   INestedService["android.aidl.tests.nested.INestedService"] {
@@ -151,12 +155,12 @@ impl BpNestedService {
 impl INestedService for BpNestedService {
   fn r#flipStatus<'a, 'l1, >(&'a self, _arg_p: &'l1 crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_6_Result> {
     let _aidl_data = self.build_parcel_flipStatus(_arg_p)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#flipStatus, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#flipStatus, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_flipStatus(_arg_p, _aidl_reply)
   }
   fn r#flipStatusWithCallback<'a, 'l1, >(&'a self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status, _arg_cb: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_9_ICallback>) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_flipStatusWithCallback(_arg_status, _arg_cb)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#flipStatusWithCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#flipStatusWithCallback, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_flipStatusWithCallback(_arg_status, _arg_cb, _aidl_reply)
   }
 }
@@ -168,7 +172,7 @@ impl<P: binder::BinderAsyncPool> INestedServiceAsync<P> for BpNestedService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#flipStatus, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#flipStatus, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_flipStatus(_arg_p, _aidl_reply)
       }
@@ -181,7 +185,7 @@ impl<P: binder::BinderAsyncPool> INestedServiceAsync<P> for BpNestedService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#flipStatusWithCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#flipStatusWithCallback, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_flipStatusWithCallback(_arg_status, _arg_cb, _aidl_reply)
       }
@@ -259,6 +263,10 @@ pub mod r#ICallback {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     ICallback["android.aidl.tests.nested.INestedService.ICallback"] {
@@ -368,7 +376,7 @@ pub mod r#ICallback {
   impl ICallback for BpCallback {
     fn r#done<'a, >(&'a self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status) -> binder::Result<()> {
       let _aidl_data = self.build_parcel_done(_arg_status)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#done, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#done, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_done(_arg_status, _aidl_reply)
     }
   }
@@ -380,7 +388,7 @@ pub mod r#ICallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#done, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#done, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_done(_arg_status, _aidl_reply)
         }
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index bd3fead4..821cabee 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -42,7 +42,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
index 76f4de4c..210c13c4 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
@@ -52,7 +52,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index ef3db178..81d51c36 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   IFooInterface["android.aidl.versioned.tests.IFooInterface"] {
@@ -255,29 +259,29 @@ impl BpFooInterface {
 impl IFooInterface for BpFooInterface {
   fn r#originalApi<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_originalApi()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_originalApi(_aidl_reply)
   }
   fn r#acceptUnionAndReturnString<'a, 'l1, >(&'a self, _arg_u: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_acceptUnionAndReturnString(_arg_u)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
   }
   fn r#ignoreParcelablesAndRepeatInt<'a, 'l1, 'l2, 'l3, >(&'a self, _arg_inFoo: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'l2 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'l3 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
   }
   fn r#returnsLengthOfFooArray<'a, 'l1, >(&'a self, _arg_foos: &'l1 [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_returnsLengthOfFooArray(_arg_foos)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
   }
   fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
     let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
     if _aidl_version != -1 { return Ok(_aidl_version); }
     let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceVersion(_aidl_reply)
   }
   fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -288,7 +292,7 @@ impl IFooInterface for BpFooInterface {
       }
     }
     let _aidl_data = self.build_parcel_getInterfaceHash()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceHash(_aidl_reply)
   }
 }
@@ -300,7 +304,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_originalApi(_aidl_reply)
       }
@@ -313,7 +317,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
       }
@@ -326,7 +330,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
       }
@@ -339,7 +343,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
       }
@@ -354,7 +358,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceVersion(_aidl_reply)
       }
@@ -373,7 +377,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceHash(_aidl_reply)
       }
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 76da1dae..110ec1e7 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -44,7 +44,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, int64_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
index e26691db..16a3f184 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
@@ -54,7 +54,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, int64_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index a59c8821..daa792e2 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   IFooInterface["android.aidl.versioned.tests.IFooInterface"] {
@@ -283,34 +287,34 @@ impl BpFooInterface {
 impl IFooInterface for BpFooInterface {
   fn r#originalApi<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_originalApi()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_originalApi(_aidl_reply)
   }
   fn r#acceptUnionAndReturnString<'a, 'l1, >(&'a self, _arg_u: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_acceptUnionAndReturnString(_arg_u)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
   }
   fn r#ignoreParcelablesAndRepeatInt<'a, 'l1, 'l2, 'l3, >(&'a self, _arg_inFoo: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'l2 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'l3 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
   }
   fn r#returnsLengthOfFooArray<'a, 'l1, >(&'a self, _arg_foos: &'l1 [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_returnsLengthOfFooArray(_arg_foos)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
   }
   fn r#newApi<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_newApi()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#newApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#newApi, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_newApi(_aidl_reply)
   }
   fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
     let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
     if _aidl_version != -1 { return Ok(_aidl_version); }
     let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceVersion(_aidl_reply)
   }
   fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -321,7 +325,7 @@ impl IFooInterface for BpFooInterface {
       }
     }
     let _aidl_data = self.build_parcel_getInterfaceHash()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceHash(_aidl_reply)
   }
 }
@@ -333,7 +337,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_originalApi(_aidl_reply)
       }
@@ -346,7 +350,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
       }
@@ -359,7 +363,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
       }
@@ -372,7 +376,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
       }
@@ -385,7 +389,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#newApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#newApi, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_newApi(_aidl_reply)
       }
@@ -400,7 +404,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceVersion(_aidl_reply)
       }
@@ -419,7 +423,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceHash(_aidl_reply)
       }
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 87ea15cb..65cf21d8 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -44,7 +44,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, int64_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
index 7aeec485..ac2e5de8 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
@@ -54,7 +54,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, int64_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index 185fe103..c17c912f 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   IFooInterface["android.aidl.versioned.tests.IFooInterface"] {
@@ -283,34 +287,34 @@ impl BpFooInterface {
 impl IFooInterface for BpFooInterface {
   fn r#originalApi<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_originalApi()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_originalApi(_aidl_reply)
   }
   fn r#acceptUnionAndReturnString<'a, 'l1, >(&'a self, _arg_u: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_acceptUnionAndReturnString(_arg_u)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
   }
   fn r#ignoreParcelablesAndRepeatInt<'a, 'l1, 'l2, 'l3, >(&'a self, _arg_inFoo: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'l2 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'l3 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
   }
   fn r#returnsLengthOfFooArray<'a, 'l1, >(&'a self, _arg_foos: &'l1 [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_returnsLengthOfFooArray(_arg_foos)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
   }
   fn r#newApi<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_newApi()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#newApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#newApi, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_newApi(_aidl_reply)
   }
   fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
     let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
     if _aidl_version != -1 { return Ok(_aidl_version); }
     let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceVersion(_aidl_reply)
   }
   fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -321,7 +325,7 @@ impl IFooInterface for BpFooInterface {
       }
     }
     let _aidl_data = self.build_parcel_getInterfaceHash()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceHash(_aidl_reply)
   }
 }
@@ -333,7 +337,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_originalApi(_aidl_reply)
       }
@@ -346,7 +350,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
       }
@@ -359,7 +363,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
       }
@@ -372,7 +376,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
       }
@@ -385,7 +389,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#newApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#newApi, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_newApi(_aidl_reply)
       }
@@ -400,7 +404,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceVersion(_aidl_reply)
       }
@@ -419,7 +423,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceHash(_aidl_reply)
       }
diff --git a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
index 101de17b..81ed48b4 100644
--- a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
+++ b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
@@ -43,7 +43,10 @@ public:
 
   Union() : _value(std::in_place_index<static_cast<size_t>(num)>, int32_t(43)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, ::std::string>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr Union(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/Union.h b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/Union.h
index 11f0cd28..8f307c79 100644
--- a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/Union.h
+++ b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/Union.h
@@ -53,7 +53,10 @@ public:
 
   Union() : _value(std::in_place_index<static_cast<size_t>(num)>, int32_t(43)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, std::string>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr Union(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs b/tests/golden_output/frozen/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
index fc709024..a37689cc 100644
--- a/tests/golden_output/frozen/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
+++ b/tests/golden_output/frozen/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
@@ -368,6 +368,10 @@ pub mod r#IRepeatFixedSizeArray {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IRepeatFixedSizeArray["android.aidl.fixedsizearray.FixedSizeArrayExample.IRepeatFixedSizeArray"] {
@@ -696,42 +700,42 @@ pub mod r#IRepeatFixedSizeArray {
   impl IRepeatFixedSizeArray for BpRepeatFixedSizeArray {
     fn r#RepeatBytes<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [u8; 3], _arg_repeated: &'l2 mut [u8; 3]) -> binder::Result<[u8; 3]> {
       let _aidl_data = self.build_parcel_RepeatBytes(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBytes, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBytes, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_RepeatBytes(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#RepeatInts<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [i32; 3], _arg_repeated: &'l2 mut [i32; 3]) -> binder::Result<[i32; 3]> {
       let _aidl_data = self.build_parcel_RepeatInts(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatInts, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatInts, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_RepeatInts(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#RepeatBinders<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [binder::SpIBinder; 3], _arg_repeated: &'l2 mut [Option<binder::SpIBinder>; 3]) -> binder::Result<[binder::SpIBinder; 3]> {
       let _aidl_data = self.build_parcel_RepeatBinders(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBinders, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBinders, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_RepeatBinders(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#RepeatParcelables<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3], _arg_repeated: &'l2 mut [crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]) -> binder::Result<[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]> {
       let _aidl_data = self.build_parcel_RepeatParcelables(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatParcelables, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatParcelables, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_RepeatParcelables(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#Repeat2dBytes<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [[u8; 3]; 2], _arg_repeated: &'l2 mut [[u8; 3]; 2]) -> binder::Result<[[u8; 3]; 2]> {
       let _aidl_data = self.build_parcel_Repeat2dBytes(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dBytes, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dBytes, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_Repeat2dBytes(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#Repeat2dInts<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [[i32; 3]; 2], _arg_repeated: &'l2 mut [[i32; 3]; 2]) -> binder::Result<[[i32; 3]; 2]> {
       let _aidl_data = self.build_parcel_Repeat2dInts(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dInts, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dInts, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_Repeat2dInts(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#Repeat2dBinders<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [[binder::SpIBinder; 3]; 2], _arg_repeated: &'l2 mut [[Option<binder::SpIBinder>; 3]; 2]) -> binder::Result<[[binder::SpIBinder; 3]; 2]> {
       let _aidl_data = self.build_parcel_Repeat2dBinders(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dBinders, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dBinders, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_Repeat2dBinders(_arg_input, _arg_repeated, _aidl_reply)
     }
     fn r#Repeat2dParcelables<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2], _arg_repeated: &'l2 mut [[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]) -> binder::Result<[[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]> {
       let _aidl_data = self.build_parcel_Repeat2dParcelables(_arg_input, _arg_repeated)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dParcelables, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#Repeat2dParcelables, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_Repeat2dParcelables(_arg_input, _arg_repeated, _aidl_reply)
     }
   }
@@ -743,7 +747,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#RepeatBytes, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#RepeatBytes, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_RepeatBytes(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -756,7 +760,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#RepeatInts, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#RepeatInts, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_RepeatInts(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -769,7 +773,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#RepeatBinders, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#RepeatBinders, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_RepeatBinders(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -782,7 +786,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#RepeatParcelables, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#RepeatParcelables, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_RepeatParcelables(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -795,7 +799,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#Repeat2dBytes, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#Repeat2dBytes, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_Repeat2dBytes(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -808,7 +812,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#Repeat2dInts, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#Repeat2dInts, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_Repeat2dInts(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -821,7 +825,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#Repeat2dBinders, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#Repeat2dBinders, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_Repeat2dBinders(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -834,7 +838,7 @@ pub mod r#IRepeatFixedSizeArray {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#Repeat2dParcelables, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#Repeat2dParcelables, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_Repeat2dParcelables(_arg_input, _arg_repeated, _aidl_reply)
         }
@@ -1037,6 +1041,10 @@ pub mod r#IEmptyInterface {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IEmptyInterface["android.aidl.fixedsizearray.FixedSizeArrayExample.IEmptyInterface"] {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/android/aidl/tests/ITestService.cpp b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/android/aidl/tests/ITestService.cpp
index 80a0b7be..43797826 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/android/aidl/tests/ITestService.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/android/aidl/tests/ITestService.cpp
@@ -113,7 +113,6 @@ BpTestService::BpTestService(const ::android::sp<::android::IBinder>& _aidl_impl
   ::android::Parcel _aidl_data;
   _aidl_data.markSensitive();
   _aidl_data.markForBinder(remoteStrong());
-  ::android::Parcel _aidl_reply;
   ::android::status_t _aidl_ret_status = ::android::OK;
   ::android::binder::Status _aidl_status;
   ::android::binder::ScopedTrace _aidl_trace(ATRACE_TAG_AIDL, "AIDL::cpp::ITestService::TestOneway::cppClient");
@@ -121,7 +120,7 @@ BpTestService::BpTestService(const ::android::sp<::android::IBinder>& _aidl_impl
   if (((_aidl_ret_status) != (::android::OK))) {
     goto _aidl_error;
   }
-  _aidl_ret_status = remote()->transact(BnTestService::TRANSACTION_TestOneway, _aidl_data, &_aidl_reply, ::android::IBinder::FLAG_ONEWAY | ::android::IBinder::FLAG_CLEAR_BUF);
+  _aidl_ret_status = remote()->transact(BnTestService::TRANSACTION_TestOneway, _aidl_data, nullptr, ::android::IBinder::FLAG_ONEWAY | ::android::IBinder::FLAG_CLEAR_BUF);
   if (_aidl_ret_status == ::android::UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) [[unlikely]] {
      return ITestService::getDefaultImpl()->TestOneway();
   }
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
index 25375baf..037d0d07 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
@@ -183,7 +183,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(iface)>, ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>()) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>, ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>, ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
index 0dca94a5..0c3ee0a6 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
@@ -193,7 +193,10 @@ public:
 
       UsingHasDeprecated() : _value(std::in_place_index<static_cast<size_t>(n)>, int32_t(0)) { }
 
-      template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+      template <typename _Tp, typename = std::enable_if_t<
+          _not_self<_Tp> &&
+          std::is_constructible_v<std::variant<int32_t, ::android::aidl::tests::ITestService::CompilerChecks::HasDeprecated>, _Tp>
+        >>
       // NOLINTNEXTLINE(google-explicit-constructor)
       constexpr UsingHasDeprecated(_Tp&& _arg)
           : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IntEnum.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IntEnum.h
index 095614f4..b4baa492 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IntEnum.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IntEnum.h
@@ -17,6 +17,9 @@ namespace android {
 namespace aidl {
 namespace tests {
 enum class IntEnum : int32_t {
+  ZERO = 0,
+  ONE = 1,
+  TWO = 2,
   FOO = 1000,
   BAR = 2000,
   BAZ = 2001,
@@ -32,6 +35,12 @@ namespace tests {
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
 [[nodiscard]] static inline std::string toString(IntEnum val) {
   switch(val) {
+  case IntEnum::ZERO:
+    return "ZERO";
+  case IntEnum::ONE:
+    return "ONE";
+  case IntEnum::TWO:
+    return "TWO";
   case IntEnum::FOO:
     return "FOO";
   case IntEnum::BAR:
@@ -54,7 +63,10 @@ namespace internal {
 #pragma clang diagnostic ignored "-Wc++17-extensions"
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
 template <>
-constexpr inline std::array<::android::aidl::tests::IntEnum, 4> enum_values<::android::aidl::tests::IntEnum> = {
+constexpr inline std::array<::android::aidl::tests::IntEnum, 7> enum_values<::android::aidl::tests::IntEnum> = {
+  ::android::aidl::tests::IntEnum::ZERO,
+  ::android::aidl::tests::IntEnum::ONE,
+  ::android::aidl::tests::IntEnum::TWO,
   ::android::aidl::tests::IntEnum::FOO,
   ::android::aidl::tests::IntEnum::BAR,
   ::android::aidl::tests::IntEnum::BAZ,
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
index c36da212..8cad3e39 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
@@ -183,7 +183,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(iface)>, ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>()) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>, ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>, ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
index 1d3125d5..b273f9cc 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
@@ -56,7 +56,10 @@ public:
 
   Union() : _value(std::in_place_index<static_cast<size_t>(ns)>, ::std::vector<int32_t>({})) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<::std::vector<int32_t>, int32_t, int32_t, ::std::string, ::android::sp<::android::IBinder>, ::std::vector<::std::string>, ::android::aidl::tests::ByteEnum>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr Union(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
index 8c9469e5..52e12f3c 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
@@ -44,7 +44,10 @@ public:
 
   UnionWithFd() : _value(std::in_place_index<static_cast<size_t>(num)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, ::android::os::ParcelFileDescriptor>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr UnionWithFd(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
index 758b7f9c..c42b268b 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
@@ -50,7 +50,10 @@ public:
 
   EnumUnion() : _value(std::in_place_index<static_cast<size_t>(intEnum)>, ::android::aidl::tests::IntEnum(::android::aidl::tests::IntEnum::FOO)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<::android::aidl::tests::IntEnum, ::android::aidl::tests::LongEnum, int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr EnumUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
index f7de5df6..75b7b2ad 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
@@ -45,7 +45,10 @@ public:
 
   UnionInUnion() : _value(std::in_place_index<static_cast<size_t>(first)>, ::android::aidl::tests::unions::EnumUnion()) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<::android::aidl::tests::unions::EnumUnion, int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr UnionInUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/IntEnum.java b/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/IntEnum.java
index 55dd7062..cde75ad0 100644
--- a/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/IntEnum.java
+++ b/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/IntEnum.java
@@ -8,6 +8,15 @@
  */
 package android.aidl.tests;
 public @interface IntEnum {
+  public static final int ZERO = 0;
+  public static final int ONE = 1;
+  public static final int TWO = 2;
+  /**
+   * Reserved: 12 and 2040
+   * We are using 12 and (FOO | BAR) in some tests because
+   * they _are not_ defined in this enum.
+   * Please do not add them here.
+   */
   public static final int FOO = 1000;
   public static final int BAR = 2000;
   public static final int BAZ = 2001;
@@ -16,6 +25,9 @@ public @interface IntEnum {
   public static final int QUX = 2002;
   interface $ {
     static String toString(int _aidl_v) {
+      if (_aidl_v == ZERO) return "ZERO";
+      if (_aidl_v == ONE) return "ONE";
+      if (_aidl_v == TWO) return "TWO";
       if (_aidl_v == FOO) return "FOO";
       if (_aidl_v == BAR) return "BAR";
       if (_aidl_v == BAZ) return "BAZ";
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ArrayOfInterfaces.h b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ArrayOfInterfaces.h
index f9f90d11..cfe1be6d 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ArrayOfInterfaces.h
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ArrayOfInterfaces.h
@@ -186,7 +186,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(iface)>, std::shared_ptr<::aidl::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>()) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<std::shared_ptr<::aidl::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>, std::shared_ptr<::aidl::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>, std::vector<std::shared_ptr<::aidl::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>, std::optional<std::vector<std::shared_ptr<::aidl::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ITestService.h b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ITestService.h
index 33e7fdb7..3ae508ab 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ITestService.h
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ITestService.h
@@ -211,7 +211,10 @@ public:
 
       UsingHasDeprecated() : _value(std::in_place_index<static_cast<size_t>(n)>, int32_t(0)) { }
 
-      template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+      template <typename _Tp, typename = std::enable_if_t<
+          _not_self<_Tp> &&
+          std::is_constructible_v<std::variant<int32_t, ::aidl::android::aidl::tests::ITestService::CompilerChecks::HasDeprecated>, _Tp>
+        >>
       // NOLINTNEXTLINE(google-explicit-constructor)
       constexpr UsingHasDeprecated(_Tp&& _arg)
           : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/IntEnum.h b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/IntEnum.h
index c1b3e0d6..298abe89 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/IntEnum.h
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/IntEnum.h
@@ -24,6 +24,9 @@ namespace android {
 namespace aidl {
 namespace tests {
 enum class IntEnum : int32_t {
+  ZERO = 0,
+  ONE = 1,
+  TWO = 2,
   FOO = 1000,
   BAR = 2000,
   BAZ = 2001,
@@ -42,6 +45,12 @@ namespace tests {
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
 [[nodiscard]] static inline std::string toString(IntEnum val) {
   switch(val) {
+  case IntEnum::ZERO:
+    return "ZERO";
+  case IntEnum::ONE:
+    return "ONE";
+  case IntEnum::TWO:
+    return "TWO";
   case IntEnum::FOO:
     return "FOO";
   case IntEnum::BAR:
@@ -65,7 +74,10 @@ namespace internal {
 #pragma clang diagnostic ignored "-Wc++17-extensions"
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
 template <>
-constexpr inline std::array<aidl::android::aidl::tests::IntEnum, 4> enum_values<aidl::android::aidl::tests::IntEnum> = {
+constexpr inline std::array<aidl::android::aidl::tests::IntEnum, 7> enum_values<aidl::android::aidl::tests::IntEnum> = {
+  aidl::android::aidl::tests::IntEnum::ZERO,
+  aidl::android::aidl::tests::IntEnum::ONE,
+  aidl::android::aidl::tests::IntEnum::TWO,
   aidl::android::aidl::tests::IntEnum::FOO,
   aidl::android::aidl::tests::IntEnum::BAR,
   aidl::android::aidl::tests::IntEnum::BAZ,
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ListOfInterfaces.h b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ListOfInterfaces.h
index 1a2a7c23..f24e932f 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ListOfInterfaces.h
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/ListOfInterfaces.h
@@ -186,7 +186,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(iface)>, std::shared_ptr<::aidl::android::aidl::tests::ListOfInterfaces::IEmptyInterface>()) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<std::shared_ptr<::aidl::android::aidl::tests::ListOfInterfaces::IEmptyInterface>, std::shared_ptr<::aidl::android::aidl::tests::ListOfInterfaces::IEmptyInterface>, std::vector<std::shared_ptr<::aidl::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>, std::optional<std::vector<std::shared_ptr<::aidl::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/Union.h b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/Union.h
index 7ae2f672..1f7bc5c8 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/Union.h
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/Union.h
@@ -64,7 +64,10 @@ public:
 
   Union() : _value(std::in_place_index<static_cast<size_t>(ns)>, std::vector<int32_t>({})) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<std::vector<int32_t>, int32_t, int32_t, std::string, ::ndk::SpAIBinder, std::vector<std::string>, ::aidl::android::aidl::tests::ByteEnum>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr Union(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/UnionWithFd.h b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/UnionWithFd.h
index b18bd940..5c4cc3d7 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/UnionWithFd.h
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/UnionWithFd.h
@@ -53,7 +53,10 @@ public:
 
   UnionWithFd() : _value(std::in_place_index<static_cast<size_t>(num)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, ::ndk::ScopedFileDescriptor>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr UnionWithFd(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/EnumUnion.h b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/EnumUnion.h
index f3e54f48..028b9bac 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/EnumUnion.h
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/EnumUnion.h
@@ -60,7 +60,10 @@ public:
 
   EnumUnion() : _value(std::in_place_index<static_cast<size_t>(intEnum)>, ::aidl::android::aidl::tests::IntEnum(::aidl::android::aidl::tests::IntEnum::FOO)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<::aidl::android::aidl::tests::IntEnum, ::aidl::android::aidl::tests::LongEnum, int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr EnumUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/UnionInUnion.h b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/UnionInUnion.h
index a4587da9..4c301178 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/UnionInUnion.h
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/include/aidl/android/aidl/tests/unions/UnionInUnion.h
@@ -55,7 +55,10 @@ public:
 
   UnionInUnion() : _value(std::in_place_index<static_cast<size_t>(first)>, ::aidl::android::aidl::tests::unions::EnumUnion()) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<::aidl::android::aidl::tests::unions::EnumUnion, int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr UnionInUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
index 0891ec2d..8501fbd0 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
@@ -38,6 +38,10 @@ pub mod r#IEmptyInterface {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IEmptyInterface["android.aidl.tests.ArrayOfInterfaces.IEmptyInterface"] {
@@ -131,6 +135,10 @@ pub mod r#IMyInterface {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IMyInterface["android.aidl.tests.ArrayOfInterfaces.IMyInterface"] {
@@ -252,7 +260,7 @@ pub mod r#IMyInterface {
   impl IMyInterface for BpMyInterface {
     fn r#methodWithInterfaces<'a, 'l1, 'l2, 'l3, 'l4, 'l5, 'l6, 'l7, 'l8, >(&'a self, _arg_iface: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&'l2 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_iface_array_in: &'l3 [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>], _arg_iface_array_out: &'l4 mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>, _arg_iface_array_inout: &'l5 mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_array_in: Option<&'l6 [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_array_out: &'l7 mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_array_inout: &'l8 mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>> {
       let _aidl_data = self.build_parcel_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_array_in, _arg_iface_array_out, _arg_iface_array_inout, _arg_nullable_iface_array_in, _arg_nullable_iface_array_out, _arg_nullable_iface_array_inout)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_array_in, _arg_iface_array_out, _arg_iface_array_inout, _arg_nullable_iface_array_in, _arg_nullable_iface_array_out, _arg_nullable_iface_array_inout, _aidl_reply)
     }
   }
@@ -264,7 +272,7 @@ pub mod r#IMyInterface {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_array_in, _arg_iface_array_out, _arg_iface_array_inout, _arg_nullable_iface_array_in, _arg_nullable_iface_array_out, _arg_nullable_iface_array_inout, _aidl_reply)
         }
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
index b9371082..8195fa7d 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   ICircular["android.aidl.tests.ICircular"] {
@@ -120,7 +124,7 @@ impl BpCircular {
 impl ICircular for BpCircular {
   fn r#GetTestService<'a, >(&'a self) -> binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_12_ITestService>>> {
     let _aidl_data = self.build_parcel_GetTestService()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetTestService, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetTestService, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_GetTestService(_aidl_reply)
   }
 }
@@ -132,7 +136,7 @@ impl<P: binder::BinderAsyncPool> ICircularAsync<P> for BpCircular {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetTestService, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetTestService, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetTestService(_aidl_reply)
       }
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
index ea7c552a..b3d604ac 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   IDeprecated["android.aidl.tests.IDeprecated"] {
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
index fb90c196..62ea9300 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   INamedCallback["android.aidl.tests.INamedCallback"] {
@@ -120,7 +124,7 @@ impl BpNamedCallback {
 impl INamedCallback for BpNamedCallback {
   fn r#GetName<'a, >(&'a self) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_GetName()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetName, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_GetName(_aidl_reply)
   }
 }
@@ -132,7 +136,7 @@ impl<P: binder::BinderAsyncPool> INamedCallbackAsync<P> for BpNamedCallback {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetName, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetName(_aidl_reply)
       }
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
index 55916bf1..d018ce89 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   INewName["android.aidl.tests.IOldName"] {
@@ -120,7 +124,7 @@ impl BpNewName {
 impl INewName for BpNewName {
   fn r#RealName<'a, >(&'a self) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_RealName()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RealName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RealName, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_RealName(_aidl_reply)
   }
 }
@@ -132,7 +136,7 @@ impl<P: binder::BinderAsyncPool> INewNameAsync<P> for BpNewName {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RealName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RealName, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RealName(_aidl_reply)
       }
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
index 259b7f52..3960e51f 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   IOldName["android.aidl.tests.IOldName"] {
@@ -120,7 +124,7 @@ impl BpOldName {
 impl IOldName for BpOldName {
   fn r#RealName<'a, >(&'a self) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_RealName()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RealName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RealName, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_RealName(_aidl_reply)
   }
 }
@@ -132,7 +136,7 @@ impl<P: binder::BinderAsyncPool> IOldNameAsync<P> for BpOldName {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RealName, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RealName, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RealName(_aidl_reply)
       }
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
index df0cab46..c6491780 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   ITestService["android.aidl.tests.ITestService"] {
@@ -2412,357 +2416,357 @@ impl BpTestService {
 impl ITestService for BpTestService {
   fn r#UnimplementedMethod<'a, >(&'a self, _arg_arg: i32) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_UnimplementedMethod(_arg_arg)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#UnimplementedMethod, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#UnimplementedMethod, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_UnimplementedMethod(_arg_arg, _aidl_reply)
   }
   fn r#Deprecated<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_Deprecated()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#Deprecated, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#Deprecated, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_Deprecated(_aidl_reply)
   }
   fn r#TestOneway<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_TestOneway()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_TestOneway(_aidl_reply)
   }
   fn r#RepeatBoolean<'a, >(&'a self, _arg_token: bool) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_RepeatBoolean(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatBoolean(_arg_token, _aidl_reply)
   }
   fn r#RepeatByte<'a, >(&'a self, _arg_token: i8) -> binder::Result<i8> {
     let _aidl_data = self.build_parcel_RepeatByte(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatByte(_arg_token, _aidl_reply)
   }
   fn r#RepeatChar<'a, >(&'a self, _arg_token: u16) -> binder::Result<u16> {
     let _aidl_data = self.build_parcel_RepeatChar(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatChar(_arg_token, _aidl_reply)
   }
   fn r#RepeatInt<'a, >(&'a self, _arg_token: i32) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_RepeatInt(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatInt(_arg_token, _aidl_reply)
   }
   fn r#RepeatLong<'a, >(&'a self, _arg_token: i64) -> binder::Result<i64> {
     let _aidl_data = self.build_parcel_RepeatLong(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatLong(_arg_token, _aidl_reply)
   }
   fn r#RepeatFloat<'a, >(&'a self, _arg_token: f32) -> binder::Result<f32> {
     let _aidl_data = self.build_parcel_RepeatFloat(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatFloat(_arg_token, _aidl_reply)
   }
   fn r#RepeatDouble<'a, >(&'a self, _arg_token: f64) -> binder::Result<f64> {
     let _aidl_data = self.build_parcel_RepeatDouble(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatDouble(_arg_token, _aidl_reply)
   }
   fn r#RepeatString<'a, 'l1, >(&'a self, _arg_token: &'l1 str) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_RepeatString(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatString(_arg_token, _aidl_reply)
   }
   fn r#RepeatByteEnum<'a, >(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum> {
     let _aidl_data = self.build_parcel_RepeatByteEnum(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatByteEnum(_arg_token, _aidl_reply)
   }
   fn r#RepeatIntEnum<'a, >(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum> {
     let _aidl_data = self.build_parcel_RepeatIntEnum(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatIntEnum(_arg_token, _aidl_reply)
   }
   fn r#RepeatLongEnum<'a, >(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum> {
     let _aidl_data = self.build_parcel_RepeatLongEnum(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatLongEnum(_arg_token, _aidl_reply)
   }
   fn r#ReverseBoolean<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [bool], _arg_repeated: &'l2 mut Vec<bool>) -> binder::Result<Vec<bool>> {
     let _aidl_data = self.build_parcel_ReverseBoolean(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseBoolean(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseByte<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [u8], _arg_repeated: &'l2 mut Vec<u8>) -> binder::Result<Vec<u8>> {
     let _aidl_data = self.build_parcel_ReverseByte(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseByte(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseChar<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [u16], _arg_repeated: &'l2 mut Vec<u16>) -> binder::Result<Vec<u16>> {
     let _aidl_data = self.build_parcel_ReverseChar(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseChar(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseInt<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [i32], _arg_repeated: &'l2 mut Vec<i32>) -> binder::Result<Vec<i32>> {
     let _aidl_data = self.build_parcel_ReverseInt(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseInt(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseLong<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [i64], _arg_repeated: &'l2 mut Vec<i64>) -> binder::Result<Vec<i64>> {
     let _aidl_data = self.build_parcel_ReverseLong(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseLong(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseFloat<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [f32], _arg_repeated: &'l2 mut Vec<f32>) -> binder::Result<Vec<f32>> {
     let _aidl_data = self.build_parcel_ReverseFloat(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseFloat(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseDouble<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [f64], _arg_repeated: &'l2 mut Vec<f64>) -> binder::Result<Vec<f64>> {
     let _aidl_data = self.build_parcel_ReverseDouble(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseDouble(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseString<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [String], _arg_repeated: &'l2 mut Vec<String>) -> binder::Result<Vec<String>> {
     let _aidl_data = self.build_parcel_ReverseString(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseString(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseByteEnum<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum], _arg_repeated: &'l2 mut Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>) -> binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>> {
     let _aidl_data = self.build_parcel_ReverseByteEnum(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseByteEnum(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseIntEnum<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum], _arg_repeated: &'l2 mut Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>) -> binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>> {
     let _aidl_data = self.build_parcel_ReverseIntEnum(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseIntEnum(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseLongEnum<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum], _arg_repeated: &'l2 mut Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>) -> binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>> {
     let _aidl_data = self.build_parcel_ReverseLongEnum(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseLongEnum(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#GetOtherTestService<'a, 'l1, >(&'a self, _arg_name: &'l1 str) -> binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>> {
     let _aidl_data = self.build_parcel_GetOtherTestService(_arg_name)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetOtherTestService(_arg_name, _aidl_reply)
   }
   fn r#SetOtherTestService<'a, 'l1, 'l2, >(&'a self, _arg_name: &'l1 str, _arg_service: &'l2 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_SetOtherTestService(_arg_name, _arg_service)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#SetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#SetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_SetOtherTestService(_arg_name, _arg_service, _aidl_reply)
   }
   fn r#VerifyName<'a, 'l1, 'l2, >(&'a self, _arg_service: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>, _arg_name: &'l2 str) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_VerifyName(_arg_service, _arg_name)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyName, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyName, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_VerifyName(_arg_service, _arg_name, _aidl_reply)
   }
   fn r#GetInterfaceArray<'a, 'l1, >(&'a self, _arg_names: &'l1 [String]) -> binder::Result<Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>> {
     let _aidl_data = self.build_parcel_GetInterfaceArray(_arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetInterfaceArray(_arg_names, _aidl_reply)
   }
   fn r#VerifyNamesWithInterfaceArray<'a, 'l1, 'l2, >(&'a self, _arg_services: &'l1 [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>], _arg_names: &'l2 [String]) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_VerifyNamesWithInterfaceArray(_arg_services, _arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_VerifyNamesWithInterfaceArray(_arg_services, _arg_names, _aidl_reply)
   }
   fn r#GetNullableInterfaceArray<'a, 'l1, >(&'a self, _arg_names: Option<&'l1 [Option<String>]>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>>> {
     let _aidl_data = self.build_parcel_GetNullableInterfaceArray(_arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetNullableInterfaceArray(_arg_names, _aidl_reply)
   }
   fn r#VerifyNamesWithNullableInterfaceArray<'a, 'l1, 'l2, >(&'a self, _arg_services: Option<&'l1 [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>]>, _arg_names: Option<&'l2 [Option<String>]>) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_VerifyNamesWithNullableInterfaceArray(_arg_services, _arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_VerifyNamesWithNullableInterfaceArray(_arg_services, _arg_names, _aidl_reply)
   }
   fn r#GetInterfaceList<'a, 'l1, >(&'a self, _arg_names: Option<&'l1 [Option<String>]>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>>> {
     let _aidl_data = self.build_parcel_GetInterfaceList(_arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetInterfaceList(_arg_names, _aidl_reply)
   }
   fn r#VerifyNamesWithInterfaceList<'a, 'l1, 'l2, >(&'a self, _arg_services: Option<&'l1 [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>]>, _arg_names: Option<&'l2 [Option<String>]>) -> binder::Result<bool> {
     let _aidl_data = self.build_parcel_VerifyNamesWithInterfaceList(_arg_services, _arg_names)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#VerifyNamesWithInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_VerifyNamesWithInterfaceList(_arg_services, _arg_names, _aidl_reply)
   }
   fn r#ReverseStringList<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [String], _arg_repeated: &'l2 mut Vec<String>) -> binder::Result<Vec<String>> {
     let _aidl_data = self.build_parcel_ReverseStringList(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseStringList(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#RepeatParcelFileDescriptor<'a, 'l1, >(&'a self, _arg_read: &'l1 binder::ParcelFileDescriptor) -> binder::Result<binder::ParcelFileDescriptor> {
     let _aidl_data = self.build_parcel_RepeatParcelFileDescriptor(_arg_read)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatParcelFileDescriptor, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatParcelFileDescriptor, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatParcelFileDescriptor(_arg_read, _aidl_reply)
   }
   fn r#ReverseParcelFileDescriptorArray<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [binder::ParcelFileDescriptor], _arg_repeated: &'l2 mut Vec<Option<binder::ParcelFileDescriptor>>) -> binder::Result<Vec<binder::ParcelFileDescriptor>> {
     let _aidl_data = self.build_parcel_ReverseParcelFileDescriptorArray(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseParcelFileDescriptorArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseParcelFileDescriptorArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseParcelFileDescriptorArray(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ThrowServiceException<'a, >(&'a self, _arg_code: i32) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_ThrowServiceException(_arg_code)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ThrowServiceException, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ThrowServiceException, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ThrowServiceException(_arg_code, _aidl_reply)
   }
   fn r#RepeatNullableIntArray<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [i32]>) -> binder::Result<Option<Vec<i32>>> {
     let _aidl_data = self.build_parcel_RepeatNullableIntArray(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableIntArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableIntArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableIntArray(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableByteEnumArray<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum]>) -> binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>>> {
     let _aidl_data = self.build_parcel_RepeatNullableByteEnumArray(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableByteEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableByteEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableByteEnumArray(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableIntEnumArray<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum]>) -> binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>>> {
     let _aidl_data = self.build_parcel_RepeatNullableIntEnumArray(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableIntEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableIntEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableIntEnumArray(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableLongEnumArray<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum]>) -> binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>>> {
     let _aidl_data = self.build_parcel_RepeatNullableLongEnumArray(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableLongEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableLongEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableLongEnumArray(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableString<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 str>) -> binder::Result<Option<String>> {
     let _aidl_data = self.build_parcel_RepeatNullableString(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableString(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableStringList<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [Option<String>]>) -> binder::Result<Option<Vec<Option<String>>>> {
     let _aidl_data = self.build_parcel_RepeatNullableStringList(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableStringList(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableParcelable<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>) -> binder::Result<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>> {
     let _aidl_data = self.build_parcel_RepeatNullableParcelable(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableParcelable(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableParcelableArray<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>]>) -> binder::Result<Option<Vec<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>>>> {
     let _aidl_data = self.build_parcel_RepeatNullableParcelableArray(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelableArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelableArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableParcelableArray(_arg_input, _aidl_reply)
   }
   fn r#RepeatNullableParcelableList<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>]>) -> binder::Result<Option<Vec<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>>>> {
     let _aidl_data = self.build_parcel_RepeatNullableParcelableList(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelableList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableParcelableList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableParcelableList(_arg_input, _aidl_reply)
   }
   fn r#TakesAnIBinder<'a, 'l1, >(&'a self, _arg_input: &'l1 binder::SpIBinder) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_TakesAnIBinder(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesAnIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesAnIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_TakesAnIBinder(_arg_input, _aidl_reply)
   }
   fn r#TakesANullableIBinder<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 binder::SpIBinder>) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_TakesANullableIBinder(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesANullableIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesANullableIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_TakesANullableIBinder(_arg_input, _aidl_reply)
   }
   fn r#TakesAnIBinderList<'a, 'l1, >(&'a self, _arg_input: &'l1 [binder::SpIBinder]) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_TakesAnIBinderList(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesAnIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesAnIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_TakesAnIBinderList(_arg_input, _aidl_reply)
   }
   fn r#TakesANullableIBinderList<'a, 'l1, >(&'a self, _arg_input: Option<&'l1 [Option<binder::SpIBinder>]>) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_TakesANullableIBinderList(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesANullableIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#TakesANullableIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_TakesANullableIBinderList(_arg_input, _aidl_reply)
   }
   fn r#RepeatUtf8CppString<'a, 'l1, >(&'a self, _arg_token: &'l1 str) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_RepeatUtf8CppString(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatUtf8CppString(_arg_token, _aidl_reply)
   }
   fn r#RepeatNullableUtf8CppString<'a, 'l1, >(&'a self, _arg_token: Option<&'l1 str>) -> binder::Result<Option<String>> {
     let _aidl_data = self.build_parcel_RepeatNullableUtf8CppString(_arg_token)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatNullableUtf8CppString(_arg_token, _aidl_reply)
   }
   fn r#ReverseUtf8CppString<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [String], _arg_repeated: &'l2 mut Vec<String>) -> binder::Result<Vec<String>> {
     let _aidl_data = self.build_parcel_ReverseUtf8CppString(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseUtf8CppString(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseNullableUtf8CppString<'a, 'l1, 'l2, >(&'a self, _arg_input: Option<&'l1 [Option<String>]>, _arg_repeated: &'l2 mut Option<Vec<Option<String>>>) -> binder::Result<Option<Vec<Option<String>>>> {
     let _aidl_data = self.build_parcel_ReverseNullableUtf8CppString(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseNullableUtf8CppString(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseUtf8CppStringList<'a, 'l1, 'l2, >(&'a self, _arg_input: Option<&'l1 [Option<String>]>, _arg_repeated: &'l2 mut Option<Vec<Option<String>>>) -> binder::Result<Option<Vec<Option<String>>>> {
     let _aidl_data = self.build_parcel_ReverseUtf8CppStringList(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseUtf8CppStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseUtf8CppStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseUtf8CppStringList(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#GetCallback<'a, >(&'a self, _arg_return_null: bool) -> binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>> {
     let _aidl_data = self.build_parcel_GetCallback(_arg_return_null)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCallback, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCallback, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetCallback(_arg_return_null, _aidl_reply)
   }
   fn r#FillOutStructuredParcelable<'a, 'l1, >(&'a self, _arg_parcel: &'l1 mut crate::mangled::_7_android_4_aidl_5_tests_20_StructuredParcelable) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_FillOutStructuredParcelable(_arg_parcel)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#FillOutStructuredParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#FillOutStructuredParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_FillOutStructuredParcelable(_arg_parcel, _aidl_reply)
   }
   fn r#RepeatExtendableParcelable<'a, 'l1, 'l2, >(&'a self, _arg_ep: &'l1 crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable, _arg_ep2: &'l2 mut crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_RepeatExtendableParcelable(_arg_ep, _arg_ep2)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatExtendableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatExtendableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatExtendableParcelable(_arg_ep, _arg_ep2, _aidl_reply)
   }
   fn r#RepeatExtendableParcelableVintf<'a, 'l1, 'l2, >(&'a self, _arg_ep: &'l1 crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable, _arg_ep2: &'l2 mut crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_RepeatExtendableParcelableVintf(_arg_ep, _arg_ep2)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatExtendableParcelableVintf, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatExtendableParcelableVintf, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatExtendableParcelableVintf(_arg_ep, _arg_ep2, _aidl_reply)
   }
   fn r#ReverseList<'a, 'l1, >(&'a self, _arg_list: &'l1 crate::mangled::_7_android_4_aidl_5_tests_13_RecursiveList) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_13_RecursiveList> {
     let _aidl_data = self.build_parcel_ReverseList(_arg_list)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseList(_arg_list, _aidl_reply)
   }
   fn r#ReverseIBinderArray<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [binder::SpIBinder], _arg_repeated: &'l2 mut Vec<Option<binder::SpIBinder>>) -> binder::Result<Vec<binder::SpIBinder>> {
     let _aidl_data = self.build_parcel_ReverseIBinderArray(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseIBinderArray(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#ReverseNullableIBinderArray<'a, 'l1, 'l2, >(&'a self, _arg_input: Option<&'l1 [Option<binder::SpIBinder>]>, _arg_repeated: &'l2 mut Option<Vec<Option<binder::SpIBinder>>>) -> binder::Result<Option<Vec<Option<binder::SpIBinder>>>> {
     let _aidl_data = self.build_parcel_ReverseNullableIBinderArray(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseNullableIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseNullableIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseNullableIBinderArray(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#RepeatSimpleParcelable<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 simple_parcelable::SimpleParcelable, _arg_repeat: &'l2 mut simple_parcelable::SimpleParcelable) -> binder::Result<simple_parcelable::SimpleParcelable> {
     let _aidl_data = self.build_parcel_RepeatSimpleParcelable(_arg_input, _arg_repeat)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatSimpleParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#RepeatSimpleParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_RepeatSimpleParcelable(_arg_input, _arg_repeat, _aidl_reply)
   }
   fn r#ReverseSimpleParcelables<'a, 'l1, 'l2, >(&'a self, _arg_input: &'l1 [simple_parcelable::SimpleParcelable], _arg_repeated: &'l2 mut Vec<simple_parcelable::SimpleParcelable>) -> binder::Result<Vec<simple_parcelable::SimpleParcelable>> {
     let _aidl_data = self.build_parcel_ReverseSimpleParcelables(_arg_input, _arg_repeated)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseSimpleParcelables, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ReverseSimpleParcelables, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_ReverseSimpleParcelables(_arg_input, _arg_repeated, _aidl_reply)
   }
   fn r#GetOldNameInterface<'a, >(&'a self) -> binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_8_IOldName>> {
     let _aidl_data = self.build_parcel_GetOldNameInterface()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetOldNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetOldNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetOldNameInterface(_aidl_reply)
   }
   fn r#GetNewNameInterface<'a, >(&'a self) -> binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_8_INewName>> {
     let _aidl_data = self.build_parcel_GetNewNameInterface()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetNewNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetNewNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetNewNameInterface(_aidl_reply)
   }
   fn r#GetUnionTags<'a, 'l1, >(&'a self, _arg_input: &'l1 [crate::mangled::_7_android_4_aidl_5_tests_5_Union]) -> binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_5_Union_3_Tag>> {
     let _aidl_data = self.build_parcel_GetUnionTags(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetUnionTags, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetUnionTags, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetUnionTags(_arg_input, _aidl_reply)
   }
   fn r#GetCppJavaTests<'a, >(&'a self) -> binder::Result<Option<binder::SpIBinder>> {
     let _aidl_data = self.build_parcel_GetCppJavaTests()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCppJavaTests, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCppJavaTests, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetCppJavaTests(_aidl_reply)
   }
   fn r#getBackendType<'a, >(&'a self) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_11_BackendType> {
     let _aidl_data = self.build_parcel_getBackendType()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getBackendType, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getBackendType, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_getBackendType(_aidl_reply)
   }
   fn r#GetCircular<'a, 'l1, >(&'a self, _arg_cp: &'l1 mut crate::mangled::_7_android_4_aidl_5_tests_18_CircularParcelable) -> binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_9_ICircular>> {
     let _aidl_data = self.build_parcel_GetCircular(_arg_cp)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCircular, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#GetCircular, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL);
     self.read_response_GetCircular(_arg_cp, _aidl_reply)
   }
 }
@@ -2774,7 +2778,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#UnimplementedMethod, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#UnimplementedMethod, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_UnimplementedMethod(_arg_arg, _aidl_reply)
       }
@@ -2787,7 +2791,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#Deprecated, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#Deprecated, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_Deprecated(_aidl_reply)
       }
@@ -2800,7 +2804,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_TestOneway(_aidl_reply)
       }
@@ -2813,7 +2817,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatBoolean(_arg_token, _aidl_reply)
       }
@@ -2826,7 +2830,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatByte(_arg_token, _aidl_reply)
       }
@@ -2839,7 +2843,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatChar(_arg_token, _aidl_reply)
       }
@@ -2852,7 +2856,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatInt(_arg_token, _aidl_reply)
       }
@@ -2865,7 +2869,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatLong(_arg_token, _aidl_reply)
       }
@@ -2878,7 +2882,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatFloat(_arg_token, _aidl_reply)
       }
@@ -2891,7 +2895,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatDouble(_arg_token, _aidl_reply)
       }
@@ -2904,7 +2908,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatString(_arg_token, _aidl_reply)
       }
@@ -2917,7 +2921,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatByteEnum(_arg_token, _aidl_reply)
       }
@@ -2930,7 +2934,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatIntEnum(_arg_token, _aidl_reply)
       }
@@ -2943,7 +2947,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatLongEnum(_arg_token, _aidl_reply)
       }
@@ -2956,7 +2960,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseBoolean, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseBoolean(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -2969,7 +2973,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseByte, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseByte(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -2982,7 +2986,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseChar, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseChar(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -2995,7 +2999,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseInt, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseInt(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3008,7 +3012,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseLong, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseLong(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3021,7 +3025,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseFloat, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseFloat(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3034,7 +3038,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseDouble, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseDouble(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3047,7 +3051,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseString(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3060,7 +3064,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseByteEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseByteEnum(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3073,7 +3077,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseIntEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseIntEnum(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3086,7 +3090,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseLongEnum, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseLongEnum(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3099,7 +3103,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetOtherTestService(_arg_name, _aidl_reply)
       }
@@ -3112,7 +3116,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#SetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#SetOtherTestService, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_SetOtherTestService(_arg_name, _arg_service, _aidl_reply)
       }
@@ -3125,7 +3129,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#VerifyName, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#VerifyName, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_VerifyName(_arg_service, _arg_name, _aidl_reply)
       }
@@ -3138,7 +3142,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetInterfaceArray(_arg_names, _aidl_reply)
       }
@@ -3151,7 +3155,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#VerifyNamesWithInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#VerifyNamesWithInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_VerifyNamesWithInterfaceArray(_arg_services, _arg_names, _aidl_reply)
       }
@@ -3164,7 +3168,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetNullableInterfaceArray(_arg_names, _aidl_reply)
       }
@@ -3177,7 +3181,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#VerifyNamesWithNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#VerifyNamesWithNullableInterfaceArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_VerifyNamesWithNullableInterfaceArray(_arg_services, _arg_names, _aidl_reply)
       }
@@ -3190,7 +3194,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetInterfaceList(_arg_names, _aidl_reply)
       }
@@ -3203,7 +3207,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#VerifyNamesWithInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#VerifyNamesWithInterfaceList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_VerifyNamesWithInterfaceList(_arg_services, _arg_names, _aidl_reply)
       }
@@ -3216,7 +3220,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseStringList(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3229,7 +3233,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatParcelFileDescriptor, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatParcelFileDescriptor, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatParcelFileDescriptor(_arg_read, _aidl_reply)
       }
@@ -3242,7 +3246,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseParcelFileDescriptorArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseParcelFileDescriptorArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseParcelFileDescriptorArray(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3255,7 +3259,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ThrowServiceException, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ThrowServiceException, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ThrowServiceException(_arg_code, _aidl_reply)
       }
@@ -3268,7 +3272,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableIntArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableIntArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableIntArray(_arg_input, _aidl_reply)
       }
@@ -3281,7 +3285,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableByteEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableByteEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableByteEnumArray(_arg_input, _aidl_reply)
       }
@@ -3294,7 +3298,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableIntEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableIntEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableIntEnumArray(_arg_input, _aidl_reply)
       }
@@ -3307,7 +3311,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableLongEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableLongEnumArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableLongEnumArray(_arg_input, _aidl_reply)
       }
@@ -3320,7 +3324,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableString(_arg_input, _aidl_reply)
       }
@@ -3333,7 +3337,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableStringList(_arg_input, _aidl_reply)
       }
@@ -3346,7 +3350,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableParcelable(_arg_input, _aidl_reply)
       }
@@ -3359,7 +3363,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableParcelableArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableParcelableArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableParcelableArray(_arg_input, _aidl_reply)
       }
@@ -3372,7 +3376,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableParcelableList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableParcelableList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableParcelableList(_arg_input, _aidl_reply)
       }
@@ -3385,7 +3389,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#TakesAnIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#TakesAnIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_TakesAnIBinder(_arg_input, _aidl_reply)
       }
@@ -3398,7 +3402,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#TakesANullableIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#TakesANullableIBinder, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_TakesANullableIBinder(_arg_input, _aidl_reply)
       }
@@ -3411,7 +3415,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#TakesAnIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#TakesAnIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_TakesAnIBinderList(_arg_input, _aidl_reply)
       }
@@ -3424,7 +3428,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#TakesANullableIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#TakesANullableIBinderList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_TakesANullableIBinderList(_arg_input, _aidl_reply)
       }
@@ -3437,7 +3441,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatUtf8CppString(_arg_token, _aidl_reply)
       }
@@ -3450,7 +3454,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatNullableUtf8CppString(_arg_token, _aidl_reply)
       }
@@ -3463,7 +3467,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseUtf8CppString(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3476,7 +3480,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseNullableUtf8CppString, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseNullableUtf8CppString(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3489,7 +3493,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseUtf8CppStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseUtf8CppStringList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseUtf8CppStringList(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3502,7 +3506,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetCallback, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetCallback, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetCallback(_arg_return_null, _aidl_reply)
       }
@@ -3515,7 +3519,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#FillOutStructuredParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#FillOutStructuredParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_FillOutStructuredParcelable(_arg_parcel, _aidl_reply)
       }
@@ -3528,7 +3532,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatExtendableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatExtendableParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatExtendableParcelable(_arg_ep, _arg_ep2, _aidl_reply)
       }
@@ -3541,7 +3545,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatExtendableParcelableVintf, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatExtendableParcelableVintf, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatExtendableParcelableVintf(_arg_ep, _arg_ep2, _aidl_reply)
       }
@@ -3554,7 +3558,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseList, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseList(_arg_list, _aidl_reply)
       }
@@ -3567,7 +3571,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseIBinderArray(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3580,7 +3584,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseNullableIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseNullableIBinderArray, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseNullableIBinderArray(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3593,7 +3597,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#RepeatSimpleParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#RepeatSimpleParcelable, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_RepeatSimpleParcelable(_arg_input, _arg_repeat, _aidl_reply)
       }
@@ -3606,7 +3610,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ReverseSimpleParcelables, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ReverseSimpleParcelables, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ReverseSimpleParcelables(_arg_input, _arg_repeated, _aidl_reply)
       }
@@ -3619,7 +3623,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetOldNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetOldNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetOldNameInterface(_aidl_reply)
       }
@@ -3632,7 +3636,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetNewNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetNewNameInterface, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetNewNameInterface(_aidl_reply)
       }
@@ -3645,7 +3649,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetUnionTags, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetUnionTags, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetUnionTags(_arg_input, _aidl_reply)
       }
@@ -3658,7 +3662,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetCppJavaTests, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetCppJavaTests, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetCppJavaTests(_aidl_reply)
       }
@@ -3671,7 +3675,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getBackendType, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getBackendType, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getBackendType(_aidl_reply)
       }
@@ -3684,7 +3688,7 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#GetCircular, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#GetCircular, _aidl_data, binder::binder_impl::FLAG_CLEAR_BUF | FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_GetCircular(_arg_cp, _aidl_reply)
       }
@@ -4837,6 +4841,10 @@ pub mod r#CompilerChecks {
     #![allow(non_upper_case_globals)]
     #![allow(non_snake_case)]
     #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+    #[cfg(any(android_vndk, not(android_ndk)))]
+    const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+    #[cfg(not(any(android_vndk, not(android_ndk))))]
+    const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
     use binder::declare_binder_interface;
     declare_binder_interface! {
       IFoo["android.aidl.tests.ITestService.CompilerChecks.Foo"] {
@@ -5025,6 +5033,10 @@ pub mod r#CompilerChecks {
     #![allow(non_upper_case_globals)]
     #![allow(non_snake_case)]
     #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+    #[cfg(any(android_vndk, not(android_ndk)))]
+    const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+    #[cfg(not(any(android_vndk, not(android_ndk))))]
+    const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
     use binder::declare_binder_interface;
     declare_binder_interface! {
       INoPrefixInterface["android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface"] {
@@ -5133,7 +5145,7 @@ pub mod r#CompilerChecks {
     impl INoPrefixInterface for BpNoPrefixInterface {
       fn r#foo<'a, >(&'a self) -> binder::Result<()> {
         let _aidl_data = self.build_parcel_foo()?;
-        let _aidl_reply = self.binder.submit_transact(transactions::r#foo, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+        let _aidl_reply = self.binder.submit_transact(transactions::r#foo, _aidl_data, FLAG_PRIVATE_LOCAL);
         self.read_response_foo(_aidl_reply)
       }
     }
@@ -5145,7 +5157,7 @@ pub mod r#CompilerChecks {
         };
         let binder = self.binder.clone();
         P::spawn(
-          move || binder.submit_transact(transactions::r#foo, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+          move || binder.submit_transact(transactions::r#foo, _aidl_data, FLAG_PRIVATE_LOCAL),
           move |_aidl_reply| async move {
             self.read_response_foo(_aidl_reply)
           }
@@ -5202,6 +5214,10 @@ pub mod r#CompilerChecks {
       #![allow(non_upper_case_globals)]
       #![allow(non_snake_case)]
       #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+      #[cfg(any(android_vndk, not(android_ndk)))]
+      const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+      #[cfg(not(any(android_vndk, not(android_ndk))))]
+      const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
       use binder::declare_binder_interface;
       declare_binder_interface! {
         INestedNoPrefixInterface["android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface.NestedNoPrefixInterface"] {
@@ -5310,7 +5326,7 @@ pub mod r#CompilerChecks {
       impl INestedNoPrefixInterface for BpNestedNoPrefixInterface {
         fn r#foo<'a, >(&'a self) -> binder::Result<()> {
           let _aidl_data = self.build_parcel_foo()?;
-          let _aidl_reply = self.binder.submit_transact(transactions::r#foo, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+          let _aidl_reply = self.binder.submit_transact(transactions::r#foo, _aidl_data, FLAG_PRIVATE_LOCAL);
           self.read_response_foo(_aidl_reply)
         }
       }
@@ -5322,7 +5338,7 @@ pub mod r#CompilerChecks {
           };
           let binder = self.binder.clone();
           P::spawn(
-            move || binder.submit_transact(transactions::r#foo, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+            move || binder.submit_transact(transactions::r#foo, _aidl_data, FLAG_PRIVATE_LOCAL),
             move |_aidl_reply| async move {
               self.read_response_foo(_aidl_reply)
             }
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IntEnum.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IntEnum.rs
index 98ed005c..0be6697b 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IntEnum.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IntEnum.rs
@@ -12,7 +12,10 @@
 use binder::declare_binder_enum;
 declare_binder_enum! {
   #[repr(C, align(4))]
-  r#IntEnum : [i32; 4] {
+  r#IntEnum : [i32; 7] {
+    r#ZERO = 0,
+    r#ONE = 1,
+    r#TWO = 2,
     r#FOO = 1000,
     r#BAR = 2000,
     r#BAZ = 2001,
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
index 6540b0d5..7ce8e8af 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
@@ -38,6 +38,10 @@ pub mod r#IEmptyInterface {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IEmptyInterface["android.aidl.tests.ListOfInterfaces.IEmptyInterface"] {
@@ -131,6 +135,10 @@ pub mod r#IMyInterface {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IMyInterface["android.aidl.tests.ListOfInterfaces.IMyInterface"] {
@@ -250,7 +258,7 @@ pub mod r#IMyInterface {
   impl IMyInterface for BpMyInterface {
     fn r#methodWithInterfaces<'a, 'l1, 'l2, 'l3, 'l4, 'l5, 'l6, 'l7, 'l8, >(&'a self, _arg_iface: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&'l2 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_iface_list_in: &'l3 [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>], _arg_iface_list_out: &'l4 mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>, _arg_iface_list_inout: &'l5 mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_list_in: Option<&'l6 [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_list_out: &'l7 mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_list_inout: &'l8 mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>> {
       let _aidl_data = self.build_parcel_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_list_in, _arg_iface_list_out, _arg_iface_list_inout, _arg_nullable_iface_list_in, _arg_nullable_iface_list_out, _arg_nullable_iface_list_inout)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_list_in, _arg_iface_list_out, _arg_iface_list_inout, _arg_nullable_iface_list_in, _arg_nullable_iface_list_out, _arg_nullable_iface_list_inout, _aidl_reply)
     }
   }
@@ -262,7 +270,7 @@ pub mod r#IMyInterface {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#methodWithInterfaces, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_list_in, _arg_iface_list_out, _arg_iface_list_inout, _arg_nullable_iface_list_in, _arg_nullable_iface_list_out, _arg_nullable_iface_list_inout, _aidl_reply)
         }
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
index af40d2f3..da9251c5 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   INestedService["android.aidl.tests.nested.INestedService"] {
@@ -151,12 +155,12 @@ impl BpNestedService {
 impl INestedService for BpNestedService {
   fn r#flipStatus<'a, 'l1, >(&'a self, _arg_p: &'l1 crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_6_Result> {
     let _aidl_data = self.build_parcel_flipStatus(_arg_p)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#flipStatus, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#flipStatus, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_flipStatus(_arg_p, _aidl_reply)
   }
   fn r#flipStatusWithCallback<'a, 'l1, >(&'a self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status, _arg_cb: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_9_ICallback>) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_flipStatusWithCallback(_arg_status, _arg_cb)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#flipStatusWithCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#flipStatusWithCallback, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_flipStatusWithCallback(_arg_status, _arg_cb, _aidl_reply)
   }
 }
@@ -168,7 +172,7 @@ impl<P: binder::BinderAsyncPool> INestedServiceAsync<P> for BpNestedService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#flipStatus, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#flipStatus, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_flipStatus(_arg_p, _aidl_reply)
       }
@@ -181,7 +185,7 @@ impl<P: binder::BinderAsyncPool> INestedServiceAsync<P> for BpNestedService {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#flipStatusWithCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#flipStatusWithCallback, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_flipStatusWithCallback(_arg_status, _arg_cb, _aidl_reply)
       }
@@ -259,6 +263,10 @@ pub mod r#ICallback {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     ICallback["android.aidl.tests.nested.INestedService.ICallback"] {
@@ -368,7 +376,7 @@ pub mod r#ICallback {
   impl ICallback for BpCallback {
     fn r#done<'a, >(&'a self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status) -> binder::Result<()> {
       let _aidl_data = self.build_parcel_done(_arg_status)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#done, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#done, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_done(_arg_status, _aidl_reply)
     }
   }
@@ -380,7 +388,7 @@ pub mod r#ICallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#done, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#done, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_done(_arg_status, _aidl_reply)
         }
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index bd3fead4..821cabee 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -42,7 +42,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
index 76f4de4c..210c13c4 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
@@ -52,7 +52,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index ef3db178..81d51c36 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   IFooInterface["android.aidl.versioned.tests.IFooInterface"] {
@@ -255,29 +259,29 @@ impl BpFooInterface {
 impl IFooInterface for BpFooInterface {
   fn r#originalApi<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_originalApi()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_originalApi(_aidl_reply)
   }
   fn r#acceptUnionAndReturnString<'a, 'l1, >(&'a self, _arg_u: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_acceptUnionAndReturnString(_arg_u)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
   }
   fn r#ignoreParcelablesAndRepeatInt<'a, 'l1, 'l2, 'l3, >(&'a self, _arg_inFoo: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'l2 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'l3 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
   }
   fn r#returnsLengthOfFooArray<'a, 'l1, >(&'a self, _arg_foos: &'l1 [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_returnsLengthOfFooArray(_arg_foos)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
   }
   fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
     let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
     if _aidl_version != -1 { return Ok(_aidl_version); }
     let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceVersion(_aidl_reply)
   }
   fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -288,7 +292,7 @@ impl IFooInterface for BpFooInterface {
       }
     }
     let _aidl_data = self.build_parcel_getInterfaceHash()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceHash(_aidl_reply)
   }
 }
@@ -300,7 +304,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_originalApi(_aidl_reply)
       }
@@ -313,7 +317,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
       }
@@ -326,7 +330,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
       }
@@ -339,7 +343,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
       }
@@ -354,7 +358,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceVersion(_aidl_reply)
       }
@@ -373,7 +377,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceHash(_aidl_reply)
       }
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 76da1dae..110ec1e7 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -44,7 +44,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, int64_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
index e26691db..16a3f184 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
@@ -54,7 +54,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, int64_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index a59c8821..daa792e2 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   IFooInterface["android.aidl.versioned.tests.IFooInterface"] {
@@ -283,34 +287,34 @@ impl BpFooInterface {
 impl IFooInterface for BpFooInterface {
   fn r#originalApi<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_originalApi()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_originalApi(_aidl_reply)
   }
   fn r#acceptUnionAndReturnString<'a, 'l1, >(&'a self, _arg_u: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_acceptUnionAndReturnString(_arg_u)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
   }
   fn r#ignoreParcelablesAndRepeatInt<'a, 'l1, 'l2, 'l3, >(&'a self, _arg_inFoo: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'l2 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'l3 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
   }
   fn r#returnsLengthOfFooArray<'a, 'l1, >(&'a self, _arg_foos: &'l1 [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_returnsLengthOfFooArray(_arg_foos)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
   }
   fn r#newApi<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_newApi()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#newApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#newApi, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_newApi(_aidl_reply)
   }
   fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
     let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
     if _aidl_version != -1 { return Ok(_aidl_version); }
     let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceVersion(_aidl_reply)
   }
   fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -321,7 +325,7 @@ impl IFooInterface for BpFooInterface {
       }
     }
     let _aidl_data = self.build_parcel_getInterfaceHash()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceHash(_aidl_reply)
   }
 }
@@ -333,7 +337,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_originalApi(_aidl_reply)
       }
@@ -346,7 +350,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
       }
@@ -359,7 +363,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
       }
@@ -372,7 +376,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
       }
@@ -385,7 +389,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#newApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#newApi, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_newApi(_aidl_reply)
       }
@@ -400,7 +404,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceVersion(_aidl_reply)
       }
@@ -419,7 +423,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceHash(_aidl_reply)
       }
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 87ea15cb..65cf21d8 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -44,7 +44,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, int64_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
index 7aeec485..ac2e5de8 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/include/aidl/android/aidl/versioned/tests/BazUnion.h
@@ -54,7 +54,10 @@ public:
 
   BazUnion() : _value(std::in_place_index<static_cast<size_t>(intNum)>, int32_t(0)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, int64_t>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr BazUnion(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index 185fe103..c17c912f 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   IFooInterface["android.aidl.versioned.tests.IFooInterface"] {
@@ -283,34 +287,34 @@ impl BpFooInterface {
 impl IFooInterface for BpFooInterface {
   fn r#originalApi<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_originalApi()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_originalApi(_aidl_reply)
   }
   fn r#acceptUnionAndReturnString<'a, 'l1, >(&'a self, _arg_u: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::Result<String> {
     let _aidl_data = self.build_parcel_acceptUnionAndReturnString(_arg_u)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
   }
   fn r#ignoreParcelablesAndRepeatInt<'a, 'l1, 'l2, 'l3, >(&'a self, _arg_inFoo: &'l1 crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'l2 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'l3 mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
   }
   fn r#returnsLengthOfFooArray<'a, 'l1, >(&'a self, _arg_foos: &'l1 [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::Result<i32> {
     let _aidl_data = self.build_parcel_returnsLengthOfFooArray(_arg_foos)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
   }
   fn r#newApi<'a, >(&'a self) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_newApi()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#newApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#newApi, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_newApi(_aidl_reply)
   }
   fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
     let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
     if _aidl_version != -1 { return Ok(_aidl_version); }
     let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceVersion(_aidl_reply)
   }
   fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -321,7 +325,7 @@ impl IFooInterface for BpFooInterface {
       }
     }
     let _aidl_data = self.build_parcel_getInterfaceHash()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceHash(_aidl_reply)
   }
 }
@@ -333,7 +337,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#originalApi, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_originalApi(_aidl_reply)
       }
@@ -346,7 +350,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#acceptUnionAndReturnString, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_acceptUnionAndReturnString(_arg_u, _aidl_reply)
       }
@@ -359,7 +363,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#ignoreParcelablesAndRepeatInt, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value, _aidl_reply)
       }
@@ -372,7 +376,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#returnsLengthOfFooArray, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_returnsLengthOfFooArray(_arg_foos, _aidl_reply)
       }
@@ -385,7 +389,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#newApi, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#newApi, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_newApi(_aidl_reply)
       }
@@ -400,7 +404,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceVersion(_aidl_reply)
       }
@@ -419,7 +423,7 @@ impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for BpFooInterface {
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceHash(_aidl_reply)
       }
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
index 101de17b..81ed48b4 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
@@ -43,7 +43,10 @@ public:
 
   Union() : _value(std::in_place_index<static_cast<size_t>(num)>, int32_t(43)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, ::std::string>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr Union(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/Union.h b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/Union.h
index 11f0cd28..8f307c79 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/Union.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/Union.h
@@ -53,7 +53,10 @@ public:
 
   Union() : _value(std::in_place_index<static_cast<size_t>(num)>, int32_t(43)) { }
 
-  template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+  template <typename _Tp, typename = std::enable_if_t<
+      _not_self<_Tp> &&
+      std::is_constructible_v<std::variant<int32_t, std::string>, _Tp>
+    >>
   // NOLINTNEXTLINE(google-explicit-constructor)
   constexpr Union(_Tp&& _arg)
       : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index dbad778d..9a49b97e 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -103,7 +103,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(a)>, int32_t(0)) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<int32_t, int32_t>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
index 07cdc48a..257eed89 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
@@ -114,7 +114,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(a)>, int32_t(0)) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<int32_t, int32_t>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
index 59d61917..5e4a046a 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   ITrunkStableTest["android.aidl.test.trunk.ITrunkStableTest"] {
@@ -252,29 +256,29 @@ impl BpTrunkStableTest {
 impl ITrunkStableTest for BpTrunkStableTest {
   fn r#repeatParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
     let _aidl_data = self.build_parcel_repeatParcelable(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatParcelable(_arg_input, _aidl_reply)
   }
   fn r#repeatEnum<'a, >(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum> {
     let _aidl_data = self.build_parcel_repeatEnum(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatEnum(_arg_input, _aidl_reply)
   }
   fn r#repeatUnion<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion> {
     let _aidl_data = self.build_parcel_repeatUnion(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatUnion(_arg_input, _aidl_reply)
   }
   fn r#callMyCallback<'a, 'l1, >(&'a self, _arg_cb: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_11_IMyCallback>) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_callMyCallback(_arg_cb)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#callMyCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#callMyCallback, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_callMyCallback(_arg_cb, _aidl_reply)
   }
   fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
     let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
     if _aidl_version != -1 { return Ok(_aidl_version); }
     let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceVersion(_aidl_reply)
   }
   fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -285,7 +289,7 @@ impl ITrunkStableTest for BpTrunkStableTest {
       }
     }
     let _aidl_data = self.build_parcel_getInterfaceHash()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceHash(_aidl_reply)
   }
 }
@@ -297,7 +301,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatParcelable(_arg_input, _aidl_reply)
       }
@@ -310,7 +314,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatEnum(_arg_input, _aidl_reply)
       }
@@ -323,7 +327,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatUnion(_arg_input, _aidl_reply)
       }
@@ -336,7 +340,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#callMyCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#callMyCallback, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_callMyCallback(_arg_cb, _aidl_reply)
       }
@@ -351,7 +355,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceVersion(_aidl_reply)
       }
@@ -370,7 +374,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceHash(_aidl_reply)
       }
@@ -575,6 +579,10 @@ pub mod r#IMyCallback {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IMyCallback["android.aidl.test.trunk.ITrunkStableTest.IMyCallback"] {
@@ -787,24 +795,24 @@ pub mod r#IMyCallback {
   impl IMyCallback for BpMyCallback {
     fn r#repeatParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
       let _aidl_data = self.build_parcel_repeatParcelable(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatParcelable(_arg_input, _aidl_reply)
     }
     fn r#repeatEnum<'a, >(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum> {
       let _aidl_data = self.build_parcel_repeatEnum(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatEnum(_arg_input, _aidl_reply)
     }
     fn r#repeatUnion<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion> {
       let _aidl_data = self.build_parcel_repeatUnion(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatUnion(_arg_input, _aidl_reply)
     }
     fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
       let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
       if _aidl_version != -1 { return Ok(_aidl_version); }
       let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_getInterfaceVersion(_aidl_reply)
     }
     fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -815,7 +823,7 @@ pub mod r#IMyCallback {
         }
       }
       let _aidl_data = self.build_parcel_getInterfaceHash()?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_getInterfaceHash(_aidl_reply)
     }
   }
@@ -827,7 +835,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatParcelable(_arg_input, _aidl_reply)
         }
@@ -840,7 +848,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatEnum(_arg_input, _aidl_reply)
         }
@@ -853,7 +861,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatUnion(_arg_input, _aidl_reply)
         }
@@ -868,7 +876,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_getInterfaceVersion(_aidl_reply)
         }
@@ -887,7 +895,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_getInterfaceHash(_aidl_reply)
         }
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index f42c96df..2f87c2d6 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -43,6 +43,9 @@ class LIBBINDER_EXPORTED ITrunkStableTest : public ::android::IInterface {
 public:
   typedef ITrunkStableTestDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(TrunkStableTest)
+  // Interface is being downgraded to the last frozen version due to
+  // RELEASE_AIDL_USE_UNFROZEN. See
+  // https://source.android.com/docs/core/architecture/aidl/stable-aidl#flag-based-development
   static inline const int32_t VERSION = true ? 1 : 2;
   static inline const std::string HASH = true ? "88311b9118fb6fe9eff4a2ca19121de0587f6d5f" : "notfrozen";
   class LIBBINDER_EXPORTED MyParcelable : public ::android::Parcelable {
@@ -108,7 +111,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(a)>, int32_t(0)) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<int32_t, int32_t, int32_t>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
@@ -231,6 +237,9 @@ public:
   public:
     typedef IMyCallbackDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(MyCallback)
+    // Interface is being downgraded to the last frozen version due to
+    // RELEASE_AIDL_USE_UNFROZEN. See
+    // https://source.android.com/docs/core/architecture/aidl/stable-aidl#flag-based-development
     static inline const int32_t VERSION = true ? 1 : 2;
     static inline const std::string HASH = true ? "88311b9118fb6fe9eff4a2ca19121de0587f6d5f" : "notfrozen";
     virtual ::android::binder::Status repeatParcelable(const ::android::aidl::test::trunk::ITrunkStableTest::MyParcelable& input, ::android::aidl::test::trunk::ITrunkStableTest::MyParcelable* _aidl_return) = 0;
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-java-source/gen/android/aidl/test/trunk/ITrunkStableTest.java b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-java-source/gen/android/aidl/test/trunk/ITrunkStableTest.java
index d2fa7656..869fd4c8 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-java-source/gen/android/aidl/test/trunk/ITrunkStableTest.java
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-java-source/gen/android/aidl/test/trunk/ITrunkStableTest.java
@@ -16,6 +16,9 @@ public interface ITrunkStableTest extends android.os.IInterface
    * that the remote object is implementing.
    */
   public static final int VERSION = true ? 1 : 2;
+  // Interface is being downgraded to the last frozen version due to
+  // RELEASE_AIDL_USE_UNFROZEN. See
+  // https://source.android.com/docs/core/architecture/aidl/stable-aidl#flag-based-development
   public static final String HASH = "88311b9118fb6fe9eff4a2ca19121de0587f6d5f";
   /** Default implementation for ITrunkStableTest. */
   public static class Default implements android.aidl.test.trunk.ITrunkStableTest
@@ -619,6 +622,9 @@ public interface ITrunkStableTest extends android.os.IInterface
      * that the remote object is implementing.
      */
     public static final int VERSION = true ? 1 : 2;
+    // Interface is being downgraded to the last frozen version due to
+    // RELEASE_AIDL_USE_UNFROZEN. See
+    // https://source.android.com/docs/core/architecture/aidl/stable-aidl#flag-based-development
     public static final String HASH = "88311b9118fb6fe9eff4a2ca19121de0587f6d5f";
     /** Default implementation for IMyCallback. */
     public static class Default implements android.aidl.test.trunk.ITrunkStableTest.IMyCallback
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
index 02bc4609..4fcd29af 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
@@ -119,7 +119,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(a)>, int32_t(0)) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<int32_t, int32_t, int32_t>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
@@ -245,6 +248,9 @@ public:
     IMyCallback();
     virtual ~IMyCallback();
 
+    // Interface is being downgraded to the last frozen version due to
+    // RELEASE_AIDL_USE_UNFROZEN. See
+    // https://source.android.com/docs/core/architecture/aidl/stable-aidl#flag-based-development
     static inline const int32_t version = true ? 1 : 2;
     static inline const std::string hash = true ? "88311b9118fb6fe9eff4a2ca19121de0587f6d5f" : "notfrozen";
     static constexpr uint32_t TRANSACTION_repeatParcelable = FIRST_CALL_TRANSACTION + 0;
@@ -332,6 +338,9 @@ public:
     ::ndk::SpAIBinder createBinder() override;
   private:
   };
+  // Interface is being downgraded to the last frozen version due to
+  // RELEASE_AIDL_USE_UNFROZEN. See
+  // https://source.android.com/docs/core/architecture/aidl/stable-aidl#flag-based-development
   static inline const int32_t version = true ? 1 : 2;
   static inline const std::string hash = true ? "88311b9118fb6fe9eff4a2ca19121de0587f6d5f" : "notfrozen";
   static constexpr uint32_t TRANSACTION_repeatParcelable = FIRST_CALL_TRANSACTION + 0;
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
index c9c48d1f..91cd98f4 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   ITrunkStableTest["android.aidl.test.trunk.ITrunkStableTest"] {
@@ -167,6 +171,9 @@ pub mod transactions {
 }
 pub type ITrunkStableTestDefaultRef = Option<std::sync::Arc<dyn ITrunkStableTestDefault>>;
 static DEFAULT_IMPL: std::sync::Mutex<ITrunkStableTestDefaultRef> = std::sync::Mutex::new(None);
+// Interface is being downgraded to the last frozen version due to
+// RELEASE_AIDL_USE_UNFROZEN. See
+// https://source.android.com/docs/core/architecture/aidl/stable-aidl#flag-based-development
 pub const VERSION: i32 = if true {1} else {2};
 pub const HASH: &str = if true {"88311b9118fb6fe9eff4a2ca19121de0587f6d5f"} else {"notfrozen"};
 impl BpTrunkStableTest {
@@ -282,22 +289,22 @@ impl BpTrunkStableTest {
 impl ITrunkStableTest for BpTrunkStableTest {
   fn r#repeatParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
     let _aidl_data = self.build_parcel_repeatParcelable(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatParcelable(_arg_input, _aidl_reply)
   }
   fn r#repeatEnum<'a, >(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum> {
     let _aidl_data = self.build_parcel_repeatEnum(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatEnum(_arg_input, _aidl_reply)
   }
   fn r#repeatUnion<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion> {
     let _aidl_data = self.build_parcel_repeatUnion(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatUnion(_arg_input, _aidl_reply)
   }
   fn r#callMyCallback<'a, 'l1, >(&'a self, _arg_cb: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_11_IMyCallback>) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_callMyCallback(_arg_cb)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#callMyCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#callMyCallback, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_callMyCallback(_arg_cb, _aidl_reply)
   }
   fn r#repeatOtherParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable> {
@@ -305,7 +312,7 @@ impl ITrunkStableTest for BpTrunkStableTest {
      return Err(binder::Status::from(binder::StatusCode::UNKNOWN_TRANSACTION));
     } else {
       let _aidl_data = self.build_parcel_repeatOtherParcelable(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatOtherParcelable(_arg_input, _aidl_reply)
     }
   }
@@ -313,7 +320,7 @@ impl ITrunkStableTest for BpTrunkStableTest {
     let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
     if _aidl_version != -1 { return Ok(_aidl_version); }
     let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceVersion(_aidl_reply)
   }
   fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -324,7 +331,7 @@ impl ITrunkStableTest for BpTrunkStableTest {
       }
     }
     let _aidl_data = self.build_parcel_getInterfaceHash()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceHash(_aidl_reply)
   }
 }
@@ -336,7 +343,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatParcelable(_arg_input, _aidl_reply)
       }
@@ -349,7 +356,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatEnum(_arg_input, _aidl_reply)
       }
@@ -362,7 +369,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatUnion(_arg_input, _aidl_reply)
       }
@@ -375,7 +382,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#callMyCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#callMyCallback, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_callMyCallback(_arg_cb, _aidl_reply)
       }
@@ -391,7 +398,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatOtherParcelable(_arg_input, _aidl_reply)
         }
@@ -407,7 +414,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceVersion(_aidl_reply)
       }
@@ -426,7 +433,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceHash(_aidl_reply)
       }
@@ -678,6 +685,10 @@ pub mod r#IMyCallback {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IMyCallback["android.aidl.test.trunk.ITrunkStableTest.IMyCallback"] {
@@ -821,6 +832,9 @@ pub mod r#IMyCallback {
   }
   pub type IMyCallbackDefaultRef = Option<std::sync::Arc<dyn IMyCallbackDefault>>;
   static DEFAULT_IMPL: std::sync::Mutex<IMyCallbackDefaultRef> = std::sync::Mutex::new(None);
+  // Interface is being downgraded to the last frozen version due to
+  // RELEASE_AIDL_USE_UNFROZEN. See
+  // https://source.android.com/docs/core/architecture/aidl/stable-aidl#flag-based-development
   pub const VERSION: i32 = if true {1} else {2};
   pub const HASH: &str = if true {"88311b9118fb6fe9eff4a2ca19121de0587f6d5f"} else {"notfrozen"};
   impl BpMyCallback {
@@ -920,17 +934,17 @@ pub mod r#IMyCallback {
   impl IMyCallback for BpMyCallback {
     fn r#repeatParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
       let _aidl_data = self.build_parcel_repeatParcelable(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatParcelable(_arg_input, _aidl_reply)
     }
     fn r#repeatEnum<'a, >(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum> {
       let _aidl_data = self.build_parcel_repeatEnum(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatEnum(_arg_input, _aidl_reply)
     }
     fn r#repeatUnion<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion> {
       let _aidl_data = self.build_parcel_repeatUnion(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatUnion(_arg_input, _aidl_reply)
     }
     fn r#repeatOtherParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable> {
@@ -938,7 +952,7 @@ pub mod r#IMyCallback {
        return Err(binder::Status::from(binder::StatusCode::UNKNOWN_TRANSACTION));
       } else {
         let _aidl_data = self.build_parcel_repeatOtherParcelable(_arg_input)?;
-        let _aidl_reply = self.binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+        let _aidl_reply = self.binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
         self.read_response_repeatOtherParcelable(_arg_input, _aidl_reply)
       }
     }
@@ -946,7 +960,7 @@ pub mod r#IMyCallback {
       let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
       if _aidl_version != -1 { return Ok(_aidl_version); }
       let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_getInterfaceVersion(_aidl_reply)
     }
     fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -957,7 +971,7 @@ pub mod r#IMyCallback {
         }
       }
       let _aidl_data = self.build_parcel_getInterfaceHash()?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_getInterfaceHash(_aidl_reply)
     }
   }
@@ -969,7 +983,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatParcelable(_arg_input, _aidl_reply)
         }
@@ -982,7 +996,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatEnum(_arg_input, _aidl_reply)
         }
@@ -995,7 +1009,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatUnion(_arg_input, _aidl_reply)
         }
@@ -1011,7 +1025,7 @@ pub mod r#IMyCallback {
         };
         let binder = self.binder.clone();
         P::spawn(
-          move || binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+          move || binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
           move |_aidl_reply| async move {
             self.read_response_repeatOtherParcelable(_arg_input, _aidl_reply)
           }
@@ -1027,7 +1041,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_getInterfaceVersion(_aidl_reply)
         }
@@ -1046,7 +1060,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_getInterfaceHash(_aidl_reply)
         }
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index dbad778d..9a49b97e 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -103,7 +103,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(a)>, int32_t(0)) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<int32_t, int32_t>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
index 07cdc48a..257eed89 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
@@ -114,7 +114,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(a)>, int32_t(0)) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<int32_t, int32_t>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
index 59d61917..5e4a046a 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   ITrunkStableTest["android.aidl.test.trunk.ITrunkStableTest"] {
@@ -252,29 +256,29 @@ impl BpTrunkStableTest {
 impl ITrunkStableTest for BpTrunkStableTest {
   fn r#repeatParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
     let _aidl_data = self.build_parcel_repeatParcelable(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatParcelable(_arg_input, _aidl_reply)
   }
   fn r#repeatEnum<'a, >(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum> {
     let _aidl_data = self.build_parcel_repeatEnum(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatEnum(_arg_input, _aidl_reply)
   }
   fn r#repeatUnion<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion> {
     let _aidl_data = self.build_parcel_repeatUnion(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatUnion(_arg_input, _aidl_reply)
   }
   fn r#callMyCallback<'a, 'l1, >(&'a self, _arg_cb: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_11_IMyCallback>) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_callMyCallback(_arg_cb)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#callMyCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#callMyCallback, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_callMyCallback(_arg_cb, _aidl_reply)
   }
   fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
     let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
     if _aidl_version != -1 { return Ok(_aidl_version); }
     let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceVersion(_aidl_reply)
   }
   fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -285,7 +289,7 @@ impl ITrunkStableTest for BpTrunkStableTest {
       }
     }
     let _aidl_data = self.build_parcel_getInterfaceHash()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceHash(_aidl_reply)
   }
 }
@@ -297,7 +301,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatParcelable(_arg_input, _aidl_reply)
       }
@@ -310,7 +314,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatEnum(_arg_input, _aidl_reply)
       }
@@ -323,7 +327,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatUnion(_arg_input, _aidl_reply)
       }
@@ -336,7 +340,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#callMyCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#callMyCallback, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_callMyCallback(_arg_cb, _aidl_reply)
       }
@@ -351,7 +355,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceVersion(_aidl_reply)
       }
@@ -370,7 +374,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceHash(_aidl_reply)
       }
@@ -575,6 +579,10 @@ pub mod r#IMyCallback {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IMyCallback["android.aidl.test.trunk.ITrunkStableTest.IMyCallback"] {
@@ -787,24 +795,24 @@ pub mod r#IMyCallback {
   impl IMyCallback for BpMyCallback {
     fn r#repeatParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
       let _aidl_data = self.build_parcel_repeatParcelable(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatParcelable(_arg_input, _aidl_reply)
     }
     fn r#repeatEnum<'a, >(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum> {
       let _aidl_data = self.build_parcel_repeatEnum(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatEnum(_arg_input, _aidl_reply)
     }
     fn r#repeatUnion<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion> {
       let _aidl_data = self.build_parcel_repeatUnion(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatUnion(_arg_input, _aidl_reply)
     }
     fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
       let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
       if _aidl_version != -1 { return Ok(_aidl_version); }
       let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_getInterfaceVersion(_aidl_reply)
     }
     fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -815,7 +823,7 @@ pub mod r#IMyCallback {
         }
       }
       let _aidl_data = self.build_parcel_getInterfaceHash()?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_getInterfaceHash(_aidl_reply)
     }
   }
@@ -827,7 +835,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatParcelable(_arg_input, _aidl_reply)
         }
@@ -840,7 +848,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatEnum(_arg_input, _aidl_reply)
         }
@@ -853,7 +861,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatUnion(_arg_input, _aidl_reply)
         }
@@ -868,7 +876,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_getInterfaceVersion(_aidl_reply)
         }
@@ -887,7 +895,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_getInterfaceHash(_aidl_reply)
         }
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index 512f1e8f..7136de55 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -108,7 +108,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(a)>, int32_t(0)) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<int32_t, int32_t, int32_t>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
index 65c24407..2a248e84 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
@@ -119,7 +119,10 @@ public:
 
     MyUnion() : _value(std::in_place_index<static_cast<size_t>(a)>, int32_t(0)) { }
 
-    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
+    template <typename _Tp, typename = std::enable_if_t<
+        _not_self<_Tp> &&
+        std::is_constructible_v<std::variant<int32_t, int32_t, int32_t>, _Tp>
+      >>
     // NOLINTNEXTLINE(google-explicit-constructor)
     constexpr MyUnion(_Tp&& _arg)
         : _value(std::forward<_Tp>(_arg)) {}
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
index ff804080..1033a750 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
@@ -11,6 +11,10 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_snake_case)]
 #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+#[cfg(any(android_vndk, not(android_ndk)))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+#[cfg(not(any(android_vndk, not(android_ndk))))]
+const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
 use binder::declare_binder_interface;
 declare_binder_interface! {
   ITrunkStableTest["android.aidl.test.trunk.ITrunkStableTest"] {
@@ -282,34 +286,34 @@ impl BpTrunkStableTest {
 impl ITrunkStableTest for BpTrunkStableTest {
   fn r#repeatParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
     let _aidl_data = self.build_parcel_repeatParcelable(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatParcelable(_arg_input, _aidl_reply)
   }
   fn r#repeatEnum<'a, >(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum> {
     let _aidl_data = self.build_parcel_repeatEnum(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatEnum(_arg_input, _aidl_reply)
   }
   fn r#repeatUnion<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion> {
     let _aidl_data = self.build_parcel_repeatUnion(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatUnion(_arg_input, _aidl_reply)
   }
   fn r#callMyCallback<'a, 'l1, >(&'a self, _arg_cb: &'l1 binder::Strong<dyn crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_11_IMyCallback>) -> binder::Result<()> {
     let _aidl_data = self.build_parcel_callMyCallback(_arg_cb)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#callMyCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#callMyCallback, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_callMyCallback(_arg_cb, _aidl_reply)
   }
   fn r#repeatOtherParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable> {
     let _aidl_data = self.build_parcel_repeatOtherParcelable(_arg_input)?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_repeatOtherParcelable(_arg_input, _aidl_reply)
   }
   fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
     let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
     if _aidl_version != -1 { return Ok(_aidl_version); }
     let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceVersion(_aidl_reply)
   }
   fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -320,7 +324,7 @@ impl ITrunkStableTest for BpTrunkStableTest {
       }
     }
     let _aidl_data = self.build_parcel_getInterfaceHash()?;
-    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+    let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
     self.read_response_getInterfaceHash(_aidl_reply)
   }
 }
@@ -332,7 +336,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatParcelable(_arg_input, _aidl_reply)
       }
@@ -345,7 +349,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatEnum(_arg_input, _aidl_reply)
       }
@@ -358,7 +362,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatUnion(_arg_input, _aidl_reply)
       }
@@ -371,7 +375,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#callMyCallback, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#callMyCallback, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_callMyCallback(_arg_cb, _aidl_reply)
       }
@@ -384,7 +388,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_repeatOtherParcelable(_arg_input, _aidl_reply)
       }
@@ -399,7 +403,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceVersion(_aidl_reply)
       }
@@ -418,7 +422,7 @@ impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for BpTrunkStableTest
     };
     let binder = self.binder.clone();
     P::spawn(
-      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
       move |_aidl_reply| async move {
         self.read_response_getInterfaceHash(_aidl_reply)
       }
@@ -654,6 +658,10 @@ pub mod r#IMyCallback {
   #![allow(non_upper_case_globals)]
   #![allow(non_snake_case)]
   #[allow(unused_imports)] use binder::binder_impl::IBinderInternal;
+  #[cfg(any(android_vndk, not(android_ndk)))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = binder::binder_impl::FLAG_PRIVATE_LOCAL;
+  #[cfg(not(any(android_vndk, not(android_ndk))))]
+  const FLAG_PRIVATE_LOCAL: binder::binder_impl::TransactionFlags = 0;
   use binder::declare_binder_interface;
   declare_binder_interface! {
     IMyCallback["android.aidl.test.trunk.ITrunkStableTest.IMyCallback"] {
@@ -896,29 +904,29 @@ pub mod r#IMyCallback {
   impl IMyCallback for BpMyCallback {
     fn r#repeatParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
       let _aidl_data = self.build_parcel_repeatParcelable(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatParcelable(_arg_input, _aidl_reply)
     }
     fn r#repeatEnum<'a, >(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum> {
       let _aidl_data = self.build_parcel_repeatEnum(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatEnum(_arg_input, _aidl_reply)
     }
     fn r#repeatUnion<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion> {
       let _aidl_data = self.build_parcel_repeatUnion(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatUnion(_arg_input, _aidl_reply)
     }
     fn r#repeatOtherParcelable<'a, 'l1, >(&'a self, _arg_input: &'l1 crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable> {
       let _aidl_data = self.build_parcel_repeatOtherParcelable(_arg_input)?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_repeatOtherParcelable(_arg_input, _aidl_reply)
     }
     fn r#getInterfaceVersion<'a, >(&'a self) -> binder::Result<i32> {
       let _aidl_version = self.cached_version.load(std::sync::atomic::Ordering::Relaxed);
       if _aidl_version != -1 { return Ok(_aidl_version); }
       let _aidl_data = self.build_parcel_getInterfaceVersion()?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_getInterfaceVersion(_aidl_reply)
     }
     fn r#getInterfaceHash<'a, >(&'a self) -> binder::Result<String> {
@@ -929,7 +937,7 @@ pub mod r#IMyCallback {
         }
       }
       let _aidl_data = self.build_parcel_getInterfaceHash()?;
-      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL);
+      let _aidl_reply = self.binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL);
       self.read_response_getInterfaceHash(_aidl_reply)
     }
   }
@@ -941,7 +949,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatParcelable(_arg_input, _aidl_reply)
         }
@@ -954,7 +962,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatEnum, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatEnum(_arg_input, _aidl_reply)
         }
@@ -967,7 +975,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatUnion, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatUnion(_arg_input, _aidl_reply)
         }
@@ -980,7 +988,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#repeatOtherParcelable, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_repeatOtherParcelable(_arg_input, _aidl_reply)
         }
@@ -995,7 +1003,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#getInterfaceVersion, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_getInterfaceVersion(_aidl_reply)
         }
@@ -1014,7 +1022,7 @@ pub mod r#IMyCallback {
       };
       let binder = self.binder.clone();
       P::spawn(
-        move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, binder::binder_impl::FLAG_PRIVATE_LOCAL),
+        move || binder.submit_transact(transactions::r#getInterfaceHash, _aidl_data, FLAG_PRIVATE_LOCAL),
         move |_aidl_reply| async move {
           self.read_response_getInterfaceHash(_aidl_reply)
         }
diff --git a/tests/java/src/android/aidl/tests/TestServiceClient.java b/tests/java/src/android/aidl/tests/TestServiceClient.java
index fe4b5315..b6f1751b 100644
--- a/tests/java/src/android/aidl/tests/TestServiceClient.java
+++ b/tests/java/src/android/aidl/tests/TestServiceClient.java
@@ -188,6 +188,18 @@ public class TestServiceClient {
         assertThat(service.RepeatIntEnum(query), is(query));
     }
 
+    @Test
+    public void testIntEnumRepeatUndefined() throws RemoteException {
+      int query = 12;
+      assertThat(service.RepeatIntEnum(query), is(query));
+    }
+
+    @Test
+    public void testIntEnumRepeatWrongBitwiseOperation() throws RemoteException {
+      int query = IntEnum.FOO | IntEnum.BAR;
+      assertThat(service.RepeatIntEnum(query), is(query));
+    }
+
     @Test
     public void testLongEnumRepeat() throws RemoteException {
         long query = LongEnum.FOO;
@@ -932,11 +944,13 @@ public class TestServiceClient {
     @Test
     public void testEnumToString() {
       assertThat(IntEnum.$.toString(IntEnum.FOO), is("FOO"));
-      assertThat(IntEnum.$.toString(0), is("0"));
+      assertThat(IntEnum.$.toString(0), is("ZERO"));
+      // Undefined enumerator falls back to the int
+      assertThat(IntEnum.$.toString(12), is("12"));
       assertThat(IntEnum.$.arrayToString(null), is("null"));
       assertThat(IntEnum.$.arrayToString(new int[] {}), is("[]"));
       assertThat(IntEnum.$.arrayToString(new int[] {IntEnum.FOO, IntEnum.BAR}), is("[FOO, BAR]"));
-      assertThat(IntEnum.$.arrayToString(new int[] {IntEnum.FOO, 0}), is("[FOO, 0]"));
+      assertThat(IntEnum.$.arrayToString(new int[] {IntEnum.FOO, 12}), is("[FOO, 12]"));
       assertThat(IntEnum.$.arrayToString(new int[][] {{IntEnum.FOO, IntEnum.BAR}, {IntEnum.BAZ}}),
           is("[[FOO, BAR], [BAZ]]"));
       assertThrows(IllegalArgumentException.class, () -> IntEnum.$.arrayToString(IntEnum.FOO));
diff --git a/tests/rust/test_client.rs b/tests/rust/test_client.rs
index a1900275..842f545f 100644
--- a/tests/rust/test_client.rs
+++ b/tests/rust/test_client.rs
@@ -181,6 +181,10 @@ test_primitive! {test_primitive_constant12, RepeatInt, ITestService::CONSTANT12}
 test_primitive! {test_primitive_long_constant, RepeatLong, ITestService::LONG_CONSTANT}
 test_primitive! {test_primitive_byte_enum, RepeatByteEnum, ByteEnum::FOO}
 test_primitive! {test_primitive_int_enum, RepeatIntEnum, IntEnum::BAR}
+test_primitive! {test_primitive_int_enum_undefined, RepeatIntEnum, IntEnum(12)}
+test_primitive! {test_primitive_int_enum_bitwise_or, RepeatIntEnum, IntEnum::FOO | IntEnum::BAR}
+test_primitive! {test_primitive_int_enum_bitwise_and, RepeatIntEnum, IntEnum::FOO & IntEnum::BAR}
+test_primitive! {test_primitive_int_enum_bitwise_xor, RepeatIntEnum, IntEnum::FOO ^ IntEnum::BAR}
 test_primitive! {test_primitive_long_enum, RepeatLongEnum, LongEnum::FOO}
 test_primitive! {test_primitive_float_constant, RepeatFloat, ITestService::FLOAT_CONSTANT}
 test_primitive! {test_primitive_float_constant2, RepeatFloat, ITestService::FLOAT_CONSTANT2}
@@ -217,6 +221,70 @@ fn test_repeat_string() {
     }
 }
 
+#[test]
+fn test_enum_or() {
+    assert_eq!(IntEnum::FOO | IntEnum::BAR, IntEnum(1000 | 2000));
+}
+
+#[test]
+fn test_enum_or_assign() {
+    let mut var = IntEnum(0);
+    var |= IntEnum::FOO;
+    assert_eq!(var, IntEnum::FOO);
+    var |= IntEnum::BAR;
+    assert_eq!(var, IntEnum::FOO | IntEnum::BAR)
+}
+
+#[test]
+fn test_enum_xor() {
+    assert_eq!(IntEnum(0) ^ IntEnum::BAR, IntEnum::BAR);
+
+    let var_both = IntEnum::FOO | IntEnum::BAR;
+    let int_both = 1000 | 2000;
+    assert_eq!(var_both ^ IntEnum::BAR, IntEnum(int_both ^ 2000));
+    assert_eq!(var_both ^ IntEnum::FOO, IntEnum(int_both ^ 1000));
+}
+
+#[test]
+fn test_enum_xor_assign() {
+    let mut var = IntEnum(0);
+    var ^= IntEnum::BAR;
+    assert_eq!(var, IntEnum::BAR);
+
+    var = IntEnum::FOO | IntEnum::BAR;
+    var ^= IntEnum::BAR;
+    assert_eq!(var, IntEnum((1000 | 2000) ^ 2000));
+}
+
+#[test]
+fn test_enum_and() {
+    assert_eq!(IntEnum::FOO & IntEnum::BAR, IntEnum(1000 & 2000));
+
+    let var_both = IntEnum::FOO | IntEnum::BAR;
+    assert_eq!(var_both & IntEnum::BAR, IntEnum::BAR);
+    assert_eq!(var_both & IntEnum::FOO, IntEnum::FOO);
+}
+
+#[test]
+fn test_enum_and_assign() {
+    let mut var = IntEnum(0x7FFFFFFF);
+    var &= IntEnum::FOO;
+    assert_eq!(var, IntEnum::FOO);
+    var &= IntEnum(0);
+    assert_eq!(var, IntEnum(0));
+
+    var = IntEnum(0x7FFFFFFF);
+    var &= IntEnum(0xFF);
+    assert_eq!(var, IntEnum(0xFF));
+}
+
+#[test]
+fn test_enum_shift() {
+    assert_eq!(IntEnum(1 << IntEnum::ZERO.get()), IntEnum(0b1));
+    assert_eq!(IntEnum(1 << IntEnum::ONE.get()), IntEnum(0b10));
+    assert_eq!(IntEnum(1 << IntEnum::TWO.get()), IntEnum(0b100));
+}
+
 #[test]
 fn test_repeat_parcelable() {
     let service = get_test_service();
```

