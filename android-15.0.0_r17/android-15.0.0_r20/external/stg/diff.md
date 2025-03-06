```diff
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 3849b1c..850225f 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -146,6 +146,7 @@ else()
     reporting_test
     runtime_test
     scc_test
+    scope_test
     stgdiff_test
   )
 
diff --git a/abigail_reader.cc b/abigail_reader.cc
index 8708fc3..23c301b 100644
--- a/abigail_reader.cc
+++ b/abigail_reader.cc
@@ -21,7 +21,6 @@
 #include "abigail_reader.h"
 
 #include <fcntl.h>
-#include <unistd.h>
 
 #include <algorithm>
 #include <array>
@@ -41,8 +40,10 @@
 #include <utility>
 #include <vector>
 
+#include <libxml/globals.h>  // xmlFree moves to xmlmemory.h later
 #include <libxml/parser.h>
 #include <libxml/tree.h>
+#include <libxml/xmlstring.h>
 #include "error.h"
 #include "file_descriptor.h"
 #include "graph.h"
@@ -163,7 +164,9 @@ std::optional<bool> Parse<bool>(const std::string& value) {
 template <>
 std::optional<ElfSymbol::SymbolType> Parse<ElfSymbol::SymbolType>(
     const std::string& value) {
-  if (value == "object-type") {
+  if (value == "no-type") {
+    return {ElfSymbol::SymbolType::NOTYPE};
+  } else if (value == "object-type") {
     return {ElfSymbol::SymbolType::OBJECT};
   } else if (value == "func-type") {
     return {ElfSymbol::SymbolType::FUNCTION};
@@ -856,7 +859,7 @@ class Abigail {
       symbol_id_and_full_name_;
 
   // Full name of the current scope.
-  Scope scope_name_;
+  Scope scope_;
 
   Id GetEdge(xmlNodePtr element);
   Id GetVariadic();
@@ -1070,12 +1073,12 @@ void Abigail::ProcessInstr(xmlNodePtr instr) {
 
 void Abigail::ProcessNamespace(xmlNodePtr scope) {
   const auto name = GetAttributeOrDie(scope, "name");
-  const PushScopeName push_scope_name(scope_name_, "namespace", name);
+  const PushScopeName push_scope_name(scope_, "namespace", name);
   ProcessScope(scope);
 }
 
 Id Abigail::ProcessDecl(bool is_variable, xmlNodePtr decl) {
-  const auto name = scope_name_ + GetAttributeOrDie(decl, "name");
+  const auto name = scope_.name + GetAttributeOrDie(decl, "name");
   const auto symbol_id = GetAttribute(decl, "elf-symbol-id");
   const auto type = is_variable ? GetEdge(decl)
                                 : maker_.Add<Function>(MakeFunctionType(decl));
@@ -1096,7 +1099,7 @@ void Abigail::ProcessFunctionType(const std::string& id, xmlNodePtr function) {
 
 void Abigail::ProcessTypedef(const std::string& id,
                              xmlNodePtr type_definition) {
-  const auto name = scope_name_ + GetAttributeOrDie(type_definition, "name");
+  const auto name = scope_.name + GetAttributeOrDie(type_definition, "name");
   const auto type = GetEdge(type_definition);
   maker_.MaybeSet<Typedef>(id, name, type);
 }
@@ -1171,7 +1174,7 @@ void Abigail::ProcessArray(const std::string& id, xmlNodePtr array) {
 }
 
 void Abigail::ProcessTypeDecl(const std::string& id, xmlNodePtr type_decl) {
-  const auto name = scope_name_ + GetAttributeOrDie(type_decl, "name");
+  const auto name = scope_.name + GetAttributeOrDie(type_decl, "name");
   const auto bits = ReadAttribute<size_t>(type_decl, "size-in-bits", 0);
   if (bits % 8) {
     Die() << "size-in-bits is not a multiple of 8";
@@ -1202,8 +1205,8 @@ void Abigail::ProcessStructUnion(const std::string& id, bool is_struct,
   const auto name =
       is_anonymous ? std::string() : GetAttributeOrDie(struct_union, "name");
   const auto full_name =
-      is_anonymous ? std::string() : scope_name_ + name;
-  const PushScopeName push_scope_name(scope_name_, kind, name);
+      is_anonymous ? std::string() : scope_.name + name;
+  const PushScopeName push_scope_name(scope_, kind, name);
   if (forward) {
     maker_.MaybeSet<StructUnion>(id, kind, full_name);
     return;
@@ -1241,7 +1244,7 @@ void Abigail::ProcessEnum(const std::string& id, xmlNodePtr enumeration) {
       ReadAttribute<bool>(enumeration, "is-declaration-only", false);
   const auto name = ReadAttribute<bool>(enumeration, "is-anonymous", false)
                     ? std::string()
-                    : scope_name_ + GetAttributeOrDie(enumeration, "name");
+                    : scope_.name + GetAttributeOrDie(enumeration, "name");
   if (forward) {
     maker_.MaybeSet<Enumeration>(id, name);
     return;
diff --git a/abigail_reader_test.cc b/abigail_reader_test.cc
index 25c5121..c86a6d9 100644
--- a/abigail_reader_test.cc
+++ b/abigail_reader_test.cc
@@ -19,14 +19,12 @@
 
 #include <cstddef>
 #include <filesystem>
-#include <fstream>
 #include <iostream>
 #include <optional>
-#include <ostream>
-#include <sstream>
 #include <vector>
 
 #include <catch2/catch.hpp>
+#include <libxml/tree.h>
 #include "abigail_reader.h"
 #include "equality.h"
 #include "graph.h"
diff --git a/btf_reader.cc b/btf_reader.cc
index ad5248d..5c3c9e2 100644
--- a/btf_reader.cc
+++ b/btf_reader.cc
@@ -22,16 +22,11 @@
 
 #include "btf_reader.h"
 
-#include <fcntl.h>
-#include <libelf.h>
-
 #include <algorithm>
-#include <array>
 #include <cstddef>
 #include <cstdint>
 #include <cstring>
 #include <map>
-#include <memory>
 #include <optional>
 #include <sstream>
 #include <string>
@@ -43,7 +38,6 @@
 #include "elf_dwarf_handle.h"
 #include "elf_loader.h"
 #include "error.h"
-#include "file_descriptor.h"
 #include "graph.h"
 #include "reader_options.h"
 
diff --git a/btf_reader.h b/btf_reader.h
index 74896cf..9570a0c 100644
--- a/btf_reader.h
+++ b/btf_reader.h
@@ -22,6 +22,7 @@
 #define STG_BTF_READER_H_
 
 #include <string>
+#include <string_view>
 
 #include "graph.h"
 #include "reader_options.h"
diff --git a/comparison.cc b/comparison.cc
index b748de5..e53a3d2 100644
--- a/comparison.cc
+++ b/comparison.cc
@@ -24,28 +24,35 @@
 #include <algorithm>
 #include <array>
 #include <cstddef>
+#include <functional>
 #include <map>
 #include <optional>
 #include <ostream>
+#include <set>
 #include <sstream>
 #include <string>
 #include <string_view>
+#include <unordered_map>
 #include <utility>
 #include <vector>
 
 #include "error.h"
 #include "graph.h"
 #include "order.h"
+#include "runtime.h"
+#include "scc.h"
 
 namespace stg {
 namespace diff {
 
+namespace {
+
 struct IgnoreDescriptor {
   std::string_view name;
   Ignore::Value value;
 };
 
-static constexpr std::array<IgnoreDescriptor, 9> kIgnores{{
+constexpr std::array<IgnoreDescriptor, 9> kIgnores{{
   {"type_declaration_status",  Ignore::TYPE_DECLARATION_STATUS  },
   {"symbol_type_presence",     Ignore::SYMBOL_TYPE_PRESENCE     },
   {"primitive_type_encoding",  Ignore::PRIMITIVE_TYPE_ENCODING  },
@@ -57,6 +64,8 @@ static constexpr std::array<IgnoreDescriptor, 9> kIgnores{{
   {"type_definition_addition", Ignore::TYPE_DEFINITION_ADDITION },
 }};
 
+}  // namespace
+
 std::optional<Ignore::Value> ParseIgnore(std::string_view ignore) {
   for (const auto& [name, value] : kIgnores) {
     if (name == ignore) {
@@ -74,238 +83,212 @@ std::ostream& operator<<(std::ostream& os, IgnoreUsage) {
   return os << '\n';
 }
 
-std::string QualifiersMessage(Qualifier qualifier, const std::string& action) {
-  std::ostringstream os;
-  os << "qualifier " << qualifier << ' ' << action;
-  return os.str();
-}
+namespace {
 
-/*
- * We compute a diff for every visited node.
- *
- * Each node has one of:
- * 1. equals = true; perhaps only tentative edge differences
- * 2. equals = false; at least one definitive node or edge difference
- *
- * On the first visit to a node we can put a placeholder in, the equals value is
- * irrelevant, the diff may contain local and edge differences. If an SCC
- * contains only internal edge differences (and equivalently equals is true)
- * then the differences can all (eventually) be discarded.
- *
- * On exit from the first visit to a node, equals reflects the tree of
- * comparisons below that node in the DFS and similarly, the diff graph starting
- * from the node contains a subtree of this tree plus potentially edges to
- * existing nodes to the side or below (already visited SCCs, sharing), or above
- * (back links forming cycles).
- *
- * When an SCC is closed, all equals implies deleting all diffs, any false
- * implies updating all to false.
- *
- * On subsequent visits to a node, there are 2 cases. The node is still open:
- * return true and an edge diff. The node is closed, return the stored value and
- * an edge diff.
- */
-std::pair<bool, std::optional<Comparison>> Compare::operator()(Id id1, Id id2) {
-  const Comparison comparison{{id1}, {id2}};
-  ++queried;
-
-  // 1. Check if the comparison has an already known result.
-  auto already_known = known.find(comparison);
-  if (already_known != known.end()) {
-    // Already visited and closed.
-    ++already_compared;
-    if (already_known->second) {
-      return {true, {}};
-    } else  {
-      return {false, {comparison}};
-    }
-  }
-  // Either open or not visited at all
-
-  // 2. Record node with Strongly-Connected Component finder.
-  auto handle = scc.Open(comparison);
-  if (!handle) {
-    // Already open.
-    //
-    // Return a dummy true outcome and some tentative diffs. The diffs may end
-    // up not being used and, while it would be nice to be lazier, they encode
-    // all the cycling-breaking edges needed to recreate a full diff structure.
-    ++being_compared;
-    return {true, {comparison}};
-  }
-  // Comparison opened, need to close it before returning.
-  ++really_compared;
-
-  Result result;
-
-  const auto [unqualified1, qualifiers1] = ResolveQualifiers(graph, id1);
-  const auto [unqualified2, qualifiers2] = ResolveQualifiers(graph, id2);
-  if (!qualifiers1.empty() || !qualifiers2.empty()) {
-    // 3.1 Qualified type difference.
-    auto it1 = qualifiers1.begin();
-    auto it2 = qualifiers2.begin();
-    const auto end1 = qualifiers1.end();
-    const auto end2 = qualifiers2.end();
-    while (it1 != end1 || it2 != end2) {
-      if (it2 == end2 || (it1 != end1 && *it1 < *it2)) {
-        if (!ignore.Test(Ignore::QUALIFIER)) {
-          result.AddNodeDiff(QualifiersMessage(*it1, "removed"));
-        }
-        ++it1;
-      } else if (it1 == end1 || (it2 != end2 && *it1 > *it2)) {
-        if (!ignore.Test(Ignore::QUALIFIER)) {
-          result.AddNodeDiff(QualifiersMessage(*it2, "added"));
-        }
-        ++it2;
-      } else {
-        ++it1;
-        ++it2;
-      }
+struct Result {
+  // Used when two nodes cannot be meaningfully compared.
+  Result& MarkIncomparable() {
+    same = false;
+    diff.has_changes = true;
+    return *this;
+  }
+
+  // Used when a node attribute has changed.
+  void AddNodeDiff(const std::string& text) {
+    same = false;
+    diff.has_changes = true;
+    diff.Add(text, {});
+  }
+
+  // Used when a node attribute may have changed.
+  template <typename T>
+  void MaybeAddNodeDiff(
+      const std::string& text, const T& before, const T& after) {
+    if (before != after) {
+      std::ostringstream os;
+      os << text << " changed from " << before << " to " << after;
+      AddNodeDiff(os.str());
     }
-    const auto type_diff = (*this)(unqualified1, unqualified2);
-    result.MaybeAddEdgeDiff("underlying", type_diff);
-  } else {
-    const auto [resolved1, typedefs1] = ResolveTypedefs(graph, unqualified1);
-    const auto [resolved2, typedefs2] = ResolveTypedefs(graph, unqualified2);
-    if (unqualified1 != resolved1 || unqualified2 != resolved2) {
-      // 3.2 Typedef difference.
-      result.diff_.holds_changes = !typedefs1.empty() && !typedefs2.empty()
-                                   && typedefs1[0] == typedefs2[0];
-      result.MaybeAddEdgeDiff("resolved", (*this)(resolved1, resolved2));
-    } else {
-      // 4. Compare nodes, if possible.
-      result = graph.Apply2<Result>(*this, unqualified1, unqualified2);
+  }
+
+  // Used when a node attribute may have changed, lazy version.
+  template <typename T>
+  void MaybeAddNodeDiff(const std::function<void(std::ostream&)>& text,
+                        const T& before, const T& after) {
+    if (before != after) {
+      std::ostringstream os;
+      text(os);
+      os << " changed from " << before << " to " << after;
+      AddNodeDiff(os.str());
     }
   }
 
-  // 5. Update result and check for a complete Strongly-Connected Component.
-  provisional.insert({comparison, result.diff_});
-  auto comparisons = scc.Close(*handle);
-  auto size = comparisons.size();
-  if (size) {
-    scc_size.Add(size);
-    // Closed SCC.
-    //
-    // Note that result now incorporates every inequality and difference in the
-    // SCC via the DFS spanning tree.
-    for (auto& c : comparisons) {
-      // Record equality / inequality.
-      known.insert({c, result.equals_});
-      const auto it = provisional.find(c);
-      Check(it != provisional.end())
-          << "internal error: missing provisional diffs";
-      if (!result.equals_) {
-        // Record differences.
-        outcomes.insert(*it);
-      }
-      provisional.erase(it);
+  // Used when node attributes are optional values.
+  template <typename T>
+  void MaybeAddNodeDiff(const std::string& text, const std::optional<T>& before,
+                        const std::optional<T>& after) {
+    if (before && after) {
+      MaybeAddNodeDiff(text, *before, *after);
+    } else if (before) {
+      std::ostringstream os;
+      os << text << ' ' << *before << " was removed";
+      AddNodeDiff(os.str());
+    } else if (after) {
+      std::ostringstream os;
+      os << text << ' ' << *after << " was added";
+      AddNodeDiff(os.str());
     }
-    if (result.equals_) {
-      equivalent += size;
-      return {true, {}};
-    } else {
-      inequivalent += size;
-      return {false, {comparison}};
+  }
+
+  // Used when an edge has been removed or added.
+  void AddEdgeDiff(const std::string& text, const Comparison& comparison) {
+    same = false;
+    diff.Add(text, comparison);
+  }
+
+  // Used when an edge to a possible comparison is present.
+  void MaybeAddEdgeDiff(const std::string& text,
+                        const std::pair<bool, Comparison>& p) {
+    same &= p.first;
+    const auto& comparison = p.second;
+    if (comparison != Comparison{}) {
+      diff.Add(text, comparison);
     }
   }
 
-  // Note that both equals and diff are tentative as comparison is still open.
-  return {result.equals_, {comparison}};
-}
+  // Used when an edge to a possible comparison is present, lazy version.
+  void MaybeAddEdgeDiff(const std::function<void(std::ostream&)>& text,
+                        const std::pair<bool, Comparison>& p) {
+    same &= p.first;
+    const auto& comparison = p.second;
+    if (comparison != Comparison{}) {
+      std::ostringstream os;
+      text(os);
+      diff.Add(os.str(), comparison);
+    }
+  }
 
-Comparison Compare::Removed(Id id) {
-  Comparison comparison{{id}, {}};
-  outcomes.insert({comparison, {}});
-  return comparison;
-}
+  bool same = true;
+  Diff diff;
+};
 
-Comparison Compare::Added(Id id) {
-  Comparison comparison{{}, {id}};
-  outcomes.insert({comparison, {}});
-  return comparison;
-}
+struct ResolveTypedef {
+  ResolveTypedef(const Graph& graph, Id& id, std::vector<std::string>& names)
+      : graph(graph), id(id), names(names) {}
 
-Result Compare::Mismatch() {
-  return Result().MarkIncomparable();
-}
+  bool operator()(const Typedef& x) {
+    id = x.referred_type_id;
+    names.push_back(x.name);
+    return true;
+  }
 
-Result Compare::operator()(const Special& x1, const Special& x2) {
-  Result result;
-  if (x1.kind != x2.kind) {
-    return result.MarkIncomparable();
+  template <typename Node>
+  bool operator()(const Node&) {
+    return false;
   }
-  return result;
-}
 
-Result Compare::operator()(const PointerReference& x1,
-                           const PointerReference& x2) {
-  Result result;
-  if (x1.kind != x2.kind) {
-    return result.MarkIncomparable();
+  const Graph& graph;
+  Id& id;
+  std::vector<std::string>& names;
+};
+
+using Qualifiers = std::set<Qualifier>;
+
+struct ResolveQualifier {
+  ResolveQualifier(const Graph& graph, Id& id, Qualifiers& qualifiers)
+      : graph(graph), id(id), qualifiers(qualifiers) {}
+
+  bool operator()(const Qualified& x) {
+    id = x.qualified_type_id;
+    qualifiers.insert(x.qualifier);
+    return true;
+  }
+
+  bool operator()(const Array&) {
+    // There should be no qualifiers here.
+    qualifiers.clear();
+    return false;
+  }
+
+  bool operator()(const Function&) {
+    // There should be no qualifiers here.
+    qualifiers.clear();
+    return false;
   }
-  const auto type_diff = (*this)(x1.pointee_type_id, x2.pointee_type_id);
-  const auto text =
-      x1.kind == PointerReference::Kind::POINTER ? "pointed-to" : "referred-to";
-  result.MaybeAddEdgeDiff(text, type_diff);
-  return result;
-}
 
-Result Compare::operator()(const PointerToMember& x1,
-                           const PointerToMember& x2) {
-  Result result;
-  result.MaybeAddEdgeDiff(
-      "containing", (*this)(x1.containing_type_id, x2.containing_type_id));
-  result.MaybeAddEdgeDiff("", (*this)(x1.pointee_type_id, x2.pointee_type_id));
+  template <typename Node>
+  bool operator()(const Node&) {
+    return false;
+  }
+
+  const Graph& graph;
+  Id& id;
+  Qualifiers& qualifiers;
+};
+
+// Separate qualifiers from underlying type.
+//
+// The caller must always be prepared to receive a different type as qualifiers
+// are sometimes discarded.
+std::pair<Id, Qualifiers> ResolveQualifiers(const Graph& graph, Id id) {
+  std::pair<Id, Qualifiers> result = {id, {}};
+  ResolveQualifier resolve(graph, result.first, result.second);
+  while (graph.Apply(resolve, result.first)) {}
   return result;
 }
 
-Result Compare::operator()(const Typedef&, const Typedef&) {
-  // Compare will never attempt to directly compare Typedefs.
-  Die() << "internal error: Compare(Typedef)";
-}
+struct MatchingKey {
+  explicit MatchingKey(const Graph& graph) : graph(graph) {}
 
-Result Compare::operator()(const Qualified&, const Qualified&) {
-  // Compare will never attempt to directly compare Qualifiers.
-  Die() << "internal error: Compare(Qualified)";
-}
+  std::string operator()(Id id) {
+    return graph.Apply(*this, id);
+  }
 
-Result Compare::operator()(const Primitive& x1, const Primitive& x2) {
-  Result result;
-  if (x1.name != x2.name) {
-    return result.MarkIncomparable();
+  std::string operator()(const BaseClass& x) {
+    return (*this)(x.type_id);
   }
-  result.diff_.holds_changes = !x1.name.empty();
-  if (!ignore.Test(Ignore::PRIMITIVE_TYPE_ENCODING)) {
-    result.MaybeAddNodeDiff("encoding", x1.encoding, x2.encoding);
+
+  std::string operator()(const Method& x) {
+    return x.name + ',' + x.mangled_name;
   }
-  result.MaybeAddNodeDiff("byte size", x1.bytesize, x2.bytesize);
-  return result;
-}
 
-Result Compare::operator()(const Array& x1, const Array& x2) {
-  Result result;
-  result.MaybeAddNodeDiff("number of elements",
-                          x1.number_of_elements, x2.number_of_elements);
-  const auto type_diff = (*this)(x1.element_type_id, x2.element_type_id);
-  result.MaybeAddEdgeDiff("element", type_diff);
-  return result;
-}
+  std::string operator()(const Member& x) {
+    if (!x.name.empty()) {
+      return x.name;
+    }
+    return (*this)(x.type_id);
+  }
 
-void Compare::CompareDefined(bool defined1, bool defined2, Result& result) {
-  if (defined1 != defined2) {
-    if (!ignore.Test(Ignore::TYPE_DECLARATION_STATUS)
-        && !(ignore.Test(Ignore::TYPE_DEFINITION_ADDITION) && defined2)) {
-      std::ostringstream os;
-      os << "was " << (defined1 ? "fully defined" : "only declared")
-         << ", is now " << (defined2 ? "fully defined" : "only declared");
-      result.AddNodeDiff(os.str());
+  std::string operator()(const VariantMember& x) {
+    return x.name;
+  }
+
+  std::string operator()(const StructUnion& x) {
+    if (!x.name.empty()) {
+      return x.name;
     }
+    if (x.definition) {
+      const auto& members = x.definition->members;
+      for (const auto& member : members) {
+        const auto recursive = (*this)(member);
+        if (!recursive.empty()) {
+          return recursive + '+';
+        }
+      }
+    }
+    return {};
   }
-}
 
-namespace {
+  template <typename Node>
+  std::string operator()(const Node&) {
+    return {};
+  }
+
+  const Graph& graph;
+};
 
 using KeyIndexPairs = std::vector<std::pair<std::string, size_t>>;
+
 KeyIndexPairs MatchingKeys(const Graph& graph, const std::vector<Id>& ids) {
   KeyIndexPairs keys;
   const auto size = ids.size();
@@ -322,8 +305,21 @@ KeyIndexPairs MatchingKeys(const Graph& graph, const std::vector<Id>& ids) {
   return keys;
 }
 
+KeyIndexPairs MatchingKeys(const Enumeration::Enumerators& enums) {
+  KeyIndexPairs names;
+  const auto size = enums.size();
+  names.reserve(size);
+  for (size_t ix = 0; ix < size; ++ix) {
+    const auto& name = enums[ix].first;
+    names.emplace_back(name, ix);
+  }
+  std::stable_sort(names.begin(), names.end());
+  return names;
+}
+
 using MatchedPairs =
     std::vector<std::pair<std::optional<size_t>, std::optional<size_t>>>;
+
 MatchedPairs PairUp(const KeyIndexPairs& keys1, const KeyIndexPairs& keys2) {
   MatchedPairs pairs;
   pairs.reserve(std::max(keys1.size(), keys2.size()));
@@ -350,462 +346,634 @@ MatchedPairs PairUp(const KeyIndexPairs& keys1, const KeyIndexPairs& keys2) {
   return pairs;
 }
 
-void CompareNodes(Result& result, Compare& compare, const std::vector<Id>& ids1,
-                  const std::vector<Id>& ids2) {
-  const auto keys1 = MatchingKeys(compare.graph, ids1);
-  const auto keys2 = MatchingKeys(compare.graph, ids2);
-  auto pairs = PairUp(keys1, keys2);
-  Reorder(pairs);
-  for (const auto& [index1, index2] : pairs) {
-    if (index1 && !index2) {
-      // removed
-      const auto& x1 = ids1[*index1];
-      result.AddEdgeDiff("", compare.Removed(x1));
-    } else if (!index1 && index2) {
-      // added
-      const auto& x2 = ids2[*index2];
-      result.AddEdgeDiff("", compare.Added(x2));
-    } else if (index1 && index2) {
-      // in both
-      const auto& x1 = ids1[*index1];
-      const auto& x2 = ids2[*index2];
-      result.MaybeAddEdgeDiff("", compare(x1, x2));
-    } else {
-      Die() << "CompareNodes: impossible pair";
-    }
-  }
+std::string QualifiersMessage(Qualifier qualifier, const std::string& action) {
+  std::ostringstream os;
+  os << "qualifier " << qualifier << ' ' << action;
+  return os.str();
 }
 
-void CompareNodes(Result& result, Compare& compare,
-                  const std::map<std::string, Id>& x1,
-                  const std::map<std::string, Id>& x2,
-                  bool ignore_added) {
-  // Group diffs into removed, added and changed symbols for readability.
-  std::vector<Id> removed;
-  std::vector<Id> added;
-  std::vector<std::pair<Id, Id>> in_both;
-
-  auto it1 = x1.begin();
-  auto it2 = x2.begin();
-  const auto end1 = x1.end();
-  const auto end2 = x2.end();
-  while (it1 != end1 || it2 != end2) {
-    if (it2 == end2 || (it1 != end1 && it1->first < it2->first)) {
-      // removed
-      removed.push_back(it1->second);
-      ++it1;
-    } else if (it1 == end1 || (it2 != end2 && it1->first > it2->first)) {
-      // added
-      if (!ignore_added) {
-        added.push_back(it2->second);
+struct CompareWorker {
+  CompareWorker(Runtime& runtime, const Ignore& ignore, const Graph& graph,
+                Outcomes& outcomes)
+      : ignore(ignore), graph(graph), outcomes(outcomes),
+        queried(runtime, "compare.queried"),
+        already_compared(runtime, "compare.already_compared"),
+        being_compared(runtime, "compare.being_compared"),
+        really_compared(runtime, "compare.really_compared"),
+        equivalent(runtime, "compare.equivalent"),
+        inequivalent(runtime, "compare.inequivalent"),
+        scc_size(runtime, "compare.scc_size") {}
+
+  /*
+   * We compute a diff for every visited node.
+   *
+   * Each node has one of:
+   *
+   * 1. same == true; perhaps only tentative edge differences
+   * 2. same == false; at least one definitive node or edge difference
+   *
+   * On the first visit to a node we can put a placeholder in, the value of same
+   * is irrelevant, the diff may contain local and edge differences. If an SCC
+   * contains only internal edge differences (and equivalently same is true)
+   * then the differences can all (eventually) be discarded.
+   *
+   * On exit from the first visit to a node, same reflects the tree of
+   * comparisons below that node in the DFS and similarly, the diff graph
+   * starting from the node contains a subtree of this tree plus potentially
+   * edges to existing nodes to the side or below (already visited SCCs,
+   * sharing), or above (back links forming cycles).
+   *
+   * When an SCC is closed, all same implies deleting all diffs, any not same
+   * implies updating all to false.
+   *
+   * On subsequent visits to a node, there are 2 cases. The node is still open:
+   * return true and an edge diff. The node is closed, return the stored value
+   * and an edge diff.
+   */
+  std::pair<bool, Comparison> operator()(Id id1, Id id2) {
+    const Comparison comparison{{id1}, {id2}};
+    ++queried;
+
+    // 1. Check if the comparison has an already known result.
+    const auto already_known = known.find(comparison);
+    if (already_known != known.end()) {
+      // Already visited and closed.
+      ++already_compared;
+      return already_known->second
+          ? std::make_pair(true, Comparison{})
+          : std::make_pair(false, comparison);
+    }
+    // Either open or not visited at all
+
+    // 2. Record node with Strongly-Connected Component finder.
+    const auto handle = scc.Open(comparison);
+    if (!handle) {
+      // Already open.
+      //
+      // Return a dummy true outcome and some tentative diffs. The diffs may end
+      // up not being used and, while it would be nice to be lazier, they encode
+      // all the cycling-breaking edges needed to recreate a full diff
+      // structure.
+      ++being_compared;
+      return {true, comparison};
+    }
+    // Comparison opened, need to close it before returning.
+    ++really_compared;
+
+    Result result;
+
+    const auto [unqualified1, qualifiers1] = ResolveQualifiers(graph, id1);
+    const auto [unqualified2, qualifiers2] = ResolveQualifiers(graph, id2);
+    if (!qualifiers1.empty() || !qualifiers2.empty()) {
+      // 3.1 Qualified type difference.
+      auto it1 = qualifiers1.begin();
+      auto it2 = qualifiers2.begin();
+      const auto end1 = qualifiers1.end();
+      const auto end2 = qualifiers2.end();
+      while (it1 != end1 || it2 != end2) {
+        if (it2 == end2 || (it1 != end1 && *it1 < *it2)) {
+          if (!ignore.Test(Ignore::QUALIFIER)) {
+            result.AddNodeDiff(QualifiersMessage(*it1, "removed"));
+          }
+          ++it1;
+        } else if (it1 == end1 || (it2 != end2 && *it1 > *it2)) {
+          if (!ignore.Test(Ignore::QUALIFIER)) {
+            result.AddNodeDiff(QualifiersMessage(*it2, "added"));
+          }
+          ++it2;
+        } else {
+          ++it1;
+          ++it2;
+        }
       }
-      ++it2;
+      const auto type_diff = (*this)(unqualified1, unqualified2);
+      result.MaybeAddEdgeDiff("underlying", type_diff);
     } else {
-      // in both
-      in_both.emplace_back(it1->second, it2->second);
-      ++it1;
-      ++it2;
+      const auto [resolved1, typedefs1] = ResolveTypedefs(graph, unqualified1);
+      const auto [resolved2, typedefs2] = ResolveTypedefs(graph, unqualified2);
+      if (unqualified1 != resolved1 || unqualified2 != resolved2) {
+        // 3.2 Typedef difference.
+        result.diff.holds_changes = !typedefs1.empty() && !typedefs2.empty()
+                                    && typedefs1[0] == typedefs2[0];
+        result.MaybeAddEdgeDiff("resolved", (*this)(resolved1, resolved2));
+      } else {
+        // 4. Compare nodes, if possible.
+        result = graph.Apply2(*this, unqualified1, unqualified2);
+      }
     }
-  }
-
-  for (const auto symbol1 : removed) {
-    result.AddEdgeDiff("", compare.Removed(symbol1));
-  }
-  for (const auto symbol2 : added) {
-    result.AddEdgeDiff("", compare.Added(symbol2));
-  }
-  for (const auto& [symbol1, symbol2] : in_both) {
-    result.MaybeAddEdgeDiff("", compare(symbol1, symbol2));
-  }
-}
-
-}  // namespace
-
-Result Compare::operator()(const BaseClass& x1, const BaseClass& x2) {
-  Result result;
-  result.MaybeAddNodeDiff("inheritance", x1.inheritance, x2.inheritance);
-  result.MaybeAddNodeDiff("offset", x1.offset, x2.offset);
-  result.MaybeAddEdgeDiff("", (*this)(x1.type_id, x2.type_id));
-  return result;
-}
-
-Result Compare::operator()(const Method& x1, const Method& x2) {
-  Result result;
-  result.MaybeAddNodeDiff("vtable offset", x1.vtable_offset, x2.vtable_offset);
-  result.MaybeAddEdgeDiff("", (*this)(x1.type_id, x2.type_id));
-  return result;
-}
 
-Result Compare::operator()(const Member& x1, const Member& x2) {
-  Result result;
-  result.MaybeAddNodeDiff("offset", x1.offset, x2.offset);
-  if (!ignore.Test(Ignore::MEMBER_SIZE)) {
-    const bool bitfield1 = x1.bitsize > 0;
-    const bool bitfield2 = x2.bitsize > 0;
-    if (bitfield1 != bitfield2) {
-      std::ostringstream os;
-      os << "was " << (bitfield1 ? "a bit-field" : "not a bit-field")
-         << ", is now " << (bitfield2 ? "a bit-field" : "not a bit-field");
-      result.AddNodeDiff(os.str());
-    } else {
-      result.MaybeAddNodeDiff("bit-field size", x1.bitsize, x2.bitsize);
+    // 5. Update result and check for a complete Strongly-Connected Component.
+    const bool same = result.same;
+    provisional.insert({comparison, result.diff});
+    const auto comparisons = scc.Close(*handle);
+    if (comparisons.empty()) {
+      // Open SCC.
+      //
+      // Note that both same and diff are tentative as comparison is still
+      // open.
+      return {same, comparison};
     }
-  }
-  result.MaybeAddEdgeDiff("", (*this)(x1.type_id, x2.type_id));
-  return result;
-}
 
-Result Compare::operator()(const VariantMember& x1, const VariantMember& x2) {
-  Result result;
-  result.MaybeAddNodeDiff("discriminant", x1.discriminant_value,
-                          x2.discriminant_value);
-  result.MaybeAddEdgeDiff("", (*this)(x1.type_id, x2.type_id));
-  return result;
-}
-
-Result Compare::operator()(const StructUnion& x1, const StructUnion& x2) {
-  Result result;
-  // Compare two anonymous types recursively, not holding diffs.
-  // Compare two identically named types recursively, holding diffs.
-  // Everything else treated as distinct. No recursion.
-  if (x1.kind != x2.kind || x1.name != x2.name) {
-    return result.MarkIncomparable();
-  }
-  result.diff_.holds_changes = !x1.name.empty();
-
-  const auto& definition1 = x1.definition;
-  const auto& definition2 = x2.definition;
-  CompareDefined(definition1.has_value(), definition2.has_value(), result);
-
-  if (definition1.has_value() && definition2.has_value()) {
-    result.MaybeAddNodeDiff(
-        "byte size", definition1->bytesize, definition2->bytesize);
-    CompareNodes(
-        result, *this, definition1->base_classes, definition2->base_classes);
-    CompareNodes(result, *this, definition1->methods, definition2->methods);
-    CompareNodes(result, *this, definition1->members, definition2->members);
+    // Closed SCC.
+    //
+    // Note that result now incorporates every inequality and difference in the
+    // SCC via the DFS spanning tree.
+    const auto size = comparisons.size();
+    scc_size.Add(size);
+    for (const auto& c : comparisons) {
+      // Record equality / inequality.
+      known.insert({c, same});
+      const auto it = provisional.find(c);
+      Check(it != provisional.end())
+          << "internal error: missing provisional diffs";
+      if (!same) {
+        // Record differences.
+        outcomes.insert(*it);
+      }
+      provisional.erase(it);
+    }
+    (same ? equivalent : inequivalent) += size;
+    return same
+        ? std::make_pair(true, Comparison{})
+        : std::make_pair(false, comparison);
   }
 
-  return result;
-}
-
-static KeyIndexPairs MatchingKeys(const Enumeration::Enumerators& enums) {
-  KeyIndexPairs names;
-  const auto size = enums.size();
-  names.reserve(size);
-  for (size_t ix = 0; ix < size; ++ix) {
-    const auto& name = enums[ix].first;
-    names.emplace_back(name, ix);
+  Comparison Removed(Id id) {
+    Comparison comparison{{id}, {}};
+    outcomes.insert({comparison, {}});
+    return comparison;
   }
-  std::stable_sort(names.begin(), names.end());
-  return names;
-}
 
-Result Compare::operator()(const Enumeration& x1, const Enumeration& x2) {
-  Result result;
-  // Compare two anonymous types recursively, not holding diffs.
-  // Compare two identically named types recursively, holding diffs.
-  // Everything else treated as distinct. No recursion.
-  if (x1.name != x2.name) {
-    return result.MarkIncomparable();
+  Comparison Added(Id id) {
+    Comparison comparison{{}, {id}};
+    outcomes.insert({comparison, {}});
+    return comparison;
   }
-  result.diff_.holds_changes = !x1.name.empty();
 
-  const auto& definition1 = x1.definition;
-  const auto& definition2 = x2.definition;
-  CompareDefined(definition1.has_value(), definition2.has_value(), result);
-
-  if (definition1.has_value() && definition2.has_value()) {
-    if (!ignore.Test(Ignore::ENUM_UNDERLYING_TYPE)) {
-      const auto type_diff = (*this)(definition1->underlying_type_id,
-                                     definition2->underlying_type_id);
-      result.MaybeAddEdgeDiff("underlying", type_diff);
+  void Defined(bool defined1, bool defined2, Result& result) {
+    if (defined1 != defined2) {
+      if (!ignore.Test(Ignore::TYPE_DECLARATION_STATUS)
+          && !(ignore.Test(Ignore::TYPE_DEFINITION_ADDITION) && defined2)) {
+        std::ostringstream os;
+        os << "was " << (defined1 ? "fully defined" : "only declared")
+           << ", is now " << (defined2 ? "fully defined" : "only declared");
+        result.AddNodeDiff(os.str());
+      }
     }
+  }
 
-    const auto enums1 = definition1->enumerators;
-    const auto enums2 = definition2->enumerators;
-    const auto keys1 = MatchingKeys(enums1);
-    const auto keys2 = MatchingKeys(enums2);
+  void Nodes(const std::vector<Id>& ids1, const std::vector<Id>& ids2,
+             Result& result) {
+    const auto keys1 = MatchingKeys(graph, ids1);
+    const auto keys2 = MatchingKeys(graph, ids2);
     auto pairs = PairUp(keys1, keys2);
     Reorder(pairs);
     for (const auto& [index1, index2] : pairs) {
       if (index1 && !index2) {
         // removed
-        const auto& enum1 = enums1[*index1];
-        std::ostringstream os;
-        os << "enumerator '" << enum1.first
-           << "' (" << enum1.second << ") was removed";
-        result.AddNodeDiff(os.str());
+        const auto& x1 = ids1[*index1];
+        result.AddEdgeDiff("", Removed(x1));
       } else if (!index1 && index2) {
         // added
-        const auto& enum2 = enums2[*index2];
-        std::ostringstream os;
-        os << "enumerator '" << enum2.first
-           << "' (" << enum2.second << ") was added";
-        result.AddNodeDiff(os.str());
+        const auto& x2 = ids2[*index2];
+        result.AddEdgeDiff("", Added(x2));
       } else if (index1 && index2) {
         // in both
-        const auto& enum1 = enums1[*index1];
-        const auto& enum2 = enums2[*index2];
-        result.MaybeAddNodeDiff(
-            [&](std::ostream& os) {
-              os << "enumerator '" << enum1.first << "' value";
-            },
-            enum1.second, enum2.second);
+        const auto& x1 = ids1[*index1];
+        const auto& x2 = ids2[*index2];
+        result.MaybeAddEdgeDiff("", (*this)(x1, x2));
       } else {
-        Die() << "Compare(Enumeration): impossible pair";
+        Die() << "CompareWorker::Nodes: impossible pair";
       }
     }
   }
 
-  return result;
-}
+  void Nodes(const std::map<std::string, Id>& x1,
+             const std::map<std::string, Id>& x2,
+             bool ignore_added, Result& result) {
+    // Group diffs into removed, added and changed symbols for readability.
+    std::vector<Id> removed;
+    std::vector<Id> added;
+    std::vector<std::pair<Id, Id>> in_both;
 
-Result Compare::operator()(const Variant& x1, const Variant& x2) {
-  Result result;
-  // Compare two identically named variants recursively, holding diffs.
-  // Everything else treated as distinct. No recursion.
-  if (x1.name != x2.name) {
-    return result.MarkIncomparable();
-  }
-  result.diff_.holds_changes = true;  // Anonymous variants are not allowed.
-
-  result.MaybeAddNodeDiff("bytesize", x1.bytesize, x2.bytesize);
-  if (x1.discriminant.has_value() && x2.discriminant.has_value()) {
-    const auto type_diff =
-        (*this)(x1.discriminant.value(), x2.discriminant.value());
-    result.MaybeAddEdgeDiff("discriminant", type_diff);
-  } else if (x1.discriminant.has_value()) {
-    result.AddEdgeDiff("", Removed(x1.discriminant.value()));
-  } else if (x2.discriminant.has_value()) {
-    result.AddEdgeDiff("", Added(x2.discriminant.value()));
-  }
-  CompareNodes(result, *this, x1.members, x2.members);
-  return result;
-}
+    auto it1 = x1.begin();
+    auto it2 = x2.begin();
+    const auto end1 = x1.end();
+    const auto end2 = x2.end();
+    while (it1 != end1 || it2 != end2) {
+      if (it2 == end2 || (it1 != end1 && it1->first < it2->first)) {
+        // removed
+        removed.push_back(it1->second);
+        ++it1;
+      } else if (it1 == end1 || (it2 != end2 && it1->first > it2->first)) {
+        // added
+        if (!ignore_added) {
+          added.push_back(it2->second);
+        }
+        ++it2;
+      } else {
+        // in both
+        in_both.emplace_back(it1->second, it2->second);
+        ++it1;
+        ++it2;
+      }
+    }
 
-Result Compare::operator()(const Function& x1, const Function& x2) {
-  Result result;
-  const auto type_diff = (*this)(x1.return_type_id, x2.return_type_id);
-  result.MaybeAddEdgeDiff("return", type_diff);
-
-  const auto& parameters1 = x1.parameters;
-  const auto& parameters2 = x2.parameters;
-  const size_t min = std::min(parameters1.size(), parameters2.size());
-  for (size_t i = 0; i < min; ++i) {
-    const Id p1 = parameters1.at(i);
-    const Id p2 = parameters2.at(i);
-    result.MaybeAddEdgeDiff(
-        [&](std::ostream& os) {
-          os << "parameter " << i + 1;
-        },
-        (*this)(p1, p2));
+    for (const auto symbol1 : removed) {
+      result.AddEdgeDiff("", Removed(symbol1));
+    }
+    for (const auto symbol2 : added) {
+      result.AddEdgeDiff("", Added(symbol2));
+    }
+    for (const auto& [symbol1, symbol2] : in_both) {
+      result.MaybeAddEdgeDiff("", (*this)(symbol1, symbol2));
+    }
   }
 
-  const bool added = parameters1.size() < parameters2.size();
-  const auto& which = added ? x2 : x1;
-  const auto& parameters = which.parameters;
-  for (size_t i = min; i < parameters.size(); ++i) {
-    const Id parameter = parameters.at(i);
-    std::ostringstream os;
-    os << "parameter " << i + 1 << " of";
-    auto diff = added ? Added(parameter) : Removed(parameter);
-    result.AddEdgeDiff(os.str(), diff);
+  Result Mismatch() {
+    return Result().MarkIncomparable();
   }
 
-  return result;
-}
+  Result operator()(const Special& x1, const Special& x2) {
+    Result result;
+    if (x1.kind != x2.kind) {
+      return result.MarkIncomparable();
+    }
+    return result;
+  }
 
-Result Compare::operator()(const ElfSymbol& x1, const ElfSymbol& x2) {
-  // ELF symbols have a lot of different attributes that can impact ABI
-  // compatibility and others that either cannot or are subsumed by information
-  // elsewhere.
-  //
-  // Not all attributes are exposed by elf_symbol and fewer still in ABI XML.
-  //
-  // name - definitely part of the key
-  //
-  // type - (ELF symbol type, not C type) one important distinction here would
-  // be global vs thread-local variables
-  //
-  // section - not exposed (modulo aliasing information) and don't care
-  //
-  // value (address, usually) - not exposed (modulo aliasing information) and
-  // don't care
-  //
-  // size - don't care (for variables, subsumed by type information)
-  //
-  // binding - global vs weak vs unique vs local
-  //
-  // visibility - default > protected > hidden > internal
-  //
-  // version / is-default-version - in theory the "hidden" bit (separate from
-  // hidden and local above) can be set independently of the version, but in
-  // practice at most one version of given name is non-hidden; version
-  // (including its presence or absence) is definitely part of the key; we
-  // should probably treat is-default-version as a non-key attribute
-  //
-  // defined - rather fundamental; libabigail currently doesn't track undefined
-  // symbols but we should obviously be prepared in case it does
+  Result operator()(const PointerReference& x1, const PointerReference& x2) {
+    Result result;
+    if (x1.kind != x2.kind) {
+      return result.MarkIncomparable();
+    }
+    const auto type_diff = (*this)(x1.pointee_type_id, x2.pointee_type_id);
+    const char* text = x1.kind == PointerReference::Kind::POINTER
+                       ? "pointed-to" : "referred-to";
+    result.MaybeAddEdgeDiff(text, type_diff);
+    return result;
+  }
 
-  // There are also some externalities which libabigail cares about, which may
-  // or may not be exposed in the XML
-  //
-  // index - don't care
-  //
-  // is-common and friends - don't care
-  //
-  // aliases - exposed, but we don't really care; however we should see what
-  // compilers do, if anything, in terms of propagating type information to
-  // aliases
+  Result operator()(const PointerToMember& x1, const PointerToMember& x2) {
+    Result result;
+    result.MaybeAddEdgeDiff(
+        "containing", (*this)(x1.containing_type_id, x2.containing_type_id));
+    result.MaybeAddEdgeDiff(
+        "", (*this)(x1.pointee_type_id, x2.pointee_type_id));
+    return result;
+  }
 
-  // Linux kernel things.
-  //
-  // MODVERSIONS CRC - fundamental to ABI compatibility, if present
-  //
-  // Symbol namespace - fundamental to ABI compatibility, if present
+  Result operator()(const Typedef&, const Typedef&) {
+    // Compare will never attempt to directly compare Typedefs.
+    Die() << "internal error: CompareWorker(Typedef)";
+  }
 
-  Result result;
-  result.MaybeAddNodeDiff("name", x1.symbol_name, x2.symbol_name);
+  Result operator()(const Qualified&, const Qualified&) {
+    // Compare will never attempt to directly compare Qualifiers.
+    Die() << "internal error: CompareWorker(Qualified)";
+  }
+
+  Result operator()(const Primitive& x1, const Primitive& x2) {
+    Result result;
+    if (x1.name != x2.name) {
+      return result.MarkIncomparable();
+    }
+    result.diff.holds_changes = !x1.name.empty();
+    if (!ignore.Test(Ignore::PRIMITIVE_TYPE_ENCODING)) {
+      result.MaybeAddNodeDiff("encoding", x1.encoding, x2.encoding);
+    }
+    result.MaybeAddNodeDiff("byte size", x1.bytesize, x2.bytesize);
+    return result;
+  }
 
-  if (x1.version_info && x2.version_info) {
-    result.MaybeAddNodeDiff("version", x1.version_info->name,
-                            x2.version_info->name);
-    result.MaybeAddNodeDiff("default version", x1.version_info->is_default,
-                            x2.version_info->is_default);
-  } else {
-    result.MaybeAddNodeDiff("has version", x1.version_info.has_value(),
-                            x2.version_info.has_value());
+  Result operator()(const Array& x1, const Array& x2) {
+    Result result;
+    result.MaybeAddNodeDiff("number of elements",
+                            x1.number_of_elements, x2.number_of_elements);
+    const auto type_diff = (*this)(x1.element_type_id, x2.element_type_id);
+    result.MaybeAddEdgeDiff("element", type_diff);
+    return result;
   }
 
-  result.MaybeAddNodeDiff("defined", x1.is_defined, x2.is_defined);
-  result.MaybeAddNodeDiff("symbol type", x1.symbol_type, x2.symbol_type);
-  result.MaybeAddNodeDiff("binding", x1.binding, x2.binding);
-  result.MaybeAddNodeDiff("visibility", x1.visibility, x2.visibility);
-  if (!ignore.Test(Ignore::SYMBOL_CRC)) {
-    result.MaybeAddNodeDiff("CRC", x1.crc, x2.crc);
+  Result operator()(const BaseClass& x1, const BaseClass& x2) {
+    Result result;
+    result.MaybeAddNodeDiff("inheritance", x1.inheritance, x2.inheritance);
+    result.MaybeAddNodeDiff("offset", x1.offset, x2.offset);
+    result.MaybeAddEdgeDiff("", (*this)(x1.type_id, x2.type_id));
+    return result;
   }
-  result.MaybeAddNodeDiff("namespace", x1.ns, x2.ns);
 
-  if (x1.type_id && x2.type_id) {
-    result.MaybeAddEdgeDiff("", (*this)(*x1.type_id, *x2.type_id));
-  } else if (x1.type_id) {
-    if (!ignore.Test(Ignore::SYMBOL_TYPE_PRESENCE)) {
-      result.AddEdgeDiff("", Removed(*x1.type_id));
-    }
-  } else if (x2.type_id) {
-    if (!ignore.Test(Ignore::SYMBOL_TYPE_PRESENCE)) {
-      result.AddEdgeDiff("", Added(*x2.type_id));
+  Result operator()(const Method& x1, const Method& x2) {
+    Result result;
+    result.MaybeAddNodeDiff(
+        "vtable offset", x1.vtable_offset, x2.vtable_offset);
+    result.MaybeAddEdgeDiff("", (*this)(x1.type_id, x2.type_id));
+    return result;
+  }
+
+  Result operator()(const Member& x1, const Member& x2) {
+    Result result;
+    result.MaybeAddNodeDiff("offset", x1.offset, x2.offset);
+    if (!ignore.Test(Ignore::MEMBER_SIZE)) {
+      const bool bitfield1 = x1.bitsize > 0;
+      const bool bitfield2 = x2.bitsize > 0;
+      if (bitfield1 != bitfield2) {
+        std::ostringstream os;
+        os << "was " << (bitfield1 ? "a bit-field" : "not a bit-field")
+           << ", is now " << (bitfield2 ? "a bit-field" : "not a bit-field");
+        result.AddNodeDiff(os.str());
+      } else {
+        result.MaybeAddNodeDiff("bit-field size", x1.bitsize, x2.bitsize);
+      }
     }
-  } else {
-    // both types missing, we have nothing to say
+    result.MaybeAddEdgeDiff("", (*this)(x1.type_id, x2.type_id));
+    return result;
   }
 
-  return result;
-}
+  Result operator()(const VariantMember& x1, const VariantMember& x2) {
+    Result result;
+    result.MaybeAddNodeDiff("discriminant", x1.discriminant_value,
+                            x2.discriminant_value);
+    result.MaybeAddEdgeDiff("", (*this)(x1.type_id, x2.type_id));
+    return result;
+  }
 
-Result Compare::operator()(const Interface& x1, const Interface& x2) {
-  Result result;
-  result.diff_.holds_changes = true;
-  const bool ignore_added = ignore.Test(Ignore::INTERFACE_ADDITION);
-  CompareNodes(result, *this, x1.symbols, x2.symbols, ignore_added);
-  CompareNodes(result, *this, x1.types, x2.types, ignore_added);
-  return result;
-}
+  Result operator()(const StructUnion& x1, const StructUnion& x2) {
+    Result result;
+    // Compare two anonymous types recursively, not holding diffs.
+    // Compare two identically named types recursively, holding diffs.
+    // Everything else treated as distinct. No recursion.
+    if (x1.kind != x2.kind || x1.name != x2.name) {
+      return result.MarkIncomparable();
+    }
+    result.diff.holds_changes = !x1.name.empty();
+
+    const auto& definition1 = x1.definition;
+    const auto& definition2 = x2.definition;
+    Defined(definition1.has_value(), definition2.has_value(), result);
+
+    if (definition1.has_value() && definition2.has_value()) {
+      result.MaybeAddNodeDiff(
+          "byte size", definition1->bytesize, definition2->bytesize);
+      Nodes(definition1->base_classes, definition2->base_classes, result);
+      Nodes(definition1->methods, definition2->methods, result);
+      Nodes(definition1->members, definition2->members, result);
+    }
 
-std::pair<Id, Qualifiers> ResolveQualifiers(const Graph& graph, Id id) {
-  std::pair<Id, Qualifiers> result = {id, {}};
-  ResolveQualifier resolve(graph, result.first, result.second);
-  while (graph.Apply<bool>(resolve, result.first)) {
+    return result;
   }
-  return result;
-}
 
-bool ResolveQualifier::operator()(const Array&) {
-  // There should be no qualifiers here.
-  qualifiers.clear();
-  return false;
-}
+  Result operator()(const Enumeration& x1, const Enumeration& x2) {
+    Result result;
+    // Compare two anonymous types recursively, not holding diffs.
+    // Compare two identically named types recursively, holding diffs.
+    // Everything else treated as distinct. No recursion.
+    if (x1.name != x2.name) {
+      return result.MarkIncomparable();
+    }
+    result.diff.holds_changes = !x1.name.empty();
 
-bool ResolveQualifier::operator()(const Function&) {
-  // There should be no qualifiers here.
-  qualifiers.clear();
-  return false;
-}
+    const auto& definition1 = x1.definition;
+    const auto& definition2 = x2.definition;
+    Defined(definition1.has_value(), definition2.has_value(), result);
 
-bool ResolveQualifier::operator()(const Qualified& x) {
-  id = x.qualified_type_id;
-  qualifiers.insert(x.qualifier);
-  return true;
-}
+    if (definition1.has_value() && definition2.has_value()) {
+      if (!ignore.Test(Ignore::ENUM_UNDERLYING_TYPE)) {
+        const auto type_diff = (*this)(definition1->underlying_type_id,
+                                       definition2->underlying_type_id);
+        result.MaybeAddEdgeDiff("underlying", type_diff);
+      }
 
-template <typename Node>
-bool ResolveQualifier::operator()(const Node&) {
-  return false;
-}
+      const auto enums1 = definition1->enumerators;
+      const auto enums2 = definition2->enumerators;
+      const auto keys1 = MatchingKeys(enums1);
+      const auto keys2 = MatchingKeys(enums2);
+      auto pairs = PairUp(keys1, keys2);
+      Reorder(pairs);
+      for (const auto& [index1, index2] : pairs) {
+        if (index1 && !index2) {
+          // removed
+          const auto& enum1 = enums1[*index1];
+          std::ostringstream os;
+          os << "enumerator '" << enum1.first
+             << "' (" << enum1.second << ") was removed";
+          result.AddNodeDiff(os.str());
+        } else if (!index1 && index2) {
+          // added
+          const auto& enum2 = enums2[*index2];
+          std::ostringstream os;
+          os << "enumerator '" << enum2.first
+             << "' (" << enum2.second << ") was added";
+          result.AddNodeDiff(os.str());
+        } else if (index1 && index2) {
+          // in both
+          const auto& enum1 = enums1[*index1];
+          const auto& enum2 = enums2[*index2];
+          result.MaybeAddNodeDiff(
+              [&](std::ostream& os) {
+                os << "enumerator '" << enum1.first << "' value";
+              },
+              enum1.second, enum2.second);
+        } else {
+          Die() << "CompareWorker(Enumeration): impossible pair";
+        }
+      }
+    }
 
-std::pair<Id, std::vector<std::string>> ResolveTypedefs(
-    const Graph& graph, Id id) {
-  std::pair<Id, std::vector<std::string>> result = {id, {}};
-  ResolveTypedef resolve(graph, result.first, result.second);
-  while (graph.Apply<bool>(resolve, result.first)) {
+    return result;
   }
-  return result;
-}
 
-bool ResolveTypedef::operator()(const Typedef& x) {
-  id = x.referred_type_id;
-  names.push_back(x.name);
-  return true;
-}
+  Result operator()(const Variant& x1, const Variant& x2) {
+    Result result;
+    // Compare two identically named variants recursively, holding diffs.
+    // Everything else treated as distinct. No recursion.
+    if (x1.name != x2.name) {
+      return result.MarkIncomparable();
+    }
+    result.diff.holds_changes = true;  // Anonymous variants are not allowed.
+
+    result.MaybeAddNodeDiff("bytesize", x1.bytesize, x2.bytesize);
+    if (x1.discriminant.has_value() && x2.discriminant.has_value()) {
+      const auto type_diff =
+          (*this)(x1.discriminant.value(), x2.discriminant.value());
+      result.MaybeAddEdgeDiff("discriminant", type_diff);
+    } else if (x1.discriminant.has_value()) {
+      result.AddEdgeDiff("", Removed(x1.discriminant.value()));
+    } else if (x2.discriminant.has_value()) {
+      result.AddEdgeDiff("", Added(x2.discriminant.value()));
+    }
+    Nodes(x1.members, x2.members, result);
+    return result;
+  }
+
+  Result operator()(const Function& x1, const Function& x2) {
+    Result result;
+    const auto type_diff = (*this)(x1.return_type_id, x2.return_type_id);
+    result.MaybeAddEdgeDiff("return", type_diff);
+
+    const auto& parameters1 = x1.parameters;
+    const auto& parameters2 = x2.parameters;
+    const size_t min = std::min(parameters1.size(), parameters2.size());
+    for (size_t i = 0; i < min; ++i) {
+      const Id p1 = parameters1.at(i);
+      const Id p2 = parameters2.at(i);
+      result.MaybeAddEdgeDiff(
+          [&](std::ostream& os) {
+            os << "parameter " << i + 1;
+          },
+          (*this)(p1, p2));
+    }
 
-template <typename Node>
-bool ResolveTypedef::operator()(const Node&) {
-  return false;
-}
+    const bool added = parameters1.size() < parameters2.size();
+    const auto& which = added ? x2 : x1;
+    const auto& parameters = which.parameters;
+    for (size_t i = min; i < parameters.size(); ++i) {
+      const Id parameter = parameters.at(i);
+      std::ostringstream os;
+      os << "parameter " << i + 1 << " of";
+      auto diff = added ? Added(parameter) : Removed(parameter);
+      result.AddEdgeDiff(os.str(), diff);
+    }
 
-std::string MatchingKey::operator()(Id id) {
-  return graph.Apply<std::string>(*this, id);
-}
+    return result;
+  }
 
-std::string MatchingKey::operator()(const BaseClass& x) {
-  return (*this)(x.type_id);
-}
+  Result operator()(const ElfSymbol& x1, const ElfSymbol& x2) {
+    // ELF symbols have a lot of different attributes that can impact ABI
+    // compatibility and others that either cannot or are subsumed by
+    // information elsewhere.
+    //
+    // Not all attributes are exposed by elf_symbol and fewer still in ABI XML.
+    //
+    // name - definitely part of the key
+    //
+    // type - (ELF symbol type, not C type) one important distinction here would
+    // be global vs thread-local variables
+    //
+    // section - not exposed (modulo aliasing information) and don't care
+    //
+    // value (address, usually) - not exposed (modulo aliasing information) and
+    // don't care
+    //
+    // size - don't care (for variables, subsumed by type information)
+    //
+    // binding - global vs weak vs unique vs local
+    //
+    // visibility - default > protected > hidden > internal
+    //
+    // version / is-default-version - in theory the "hidden" bit (separate from
+    // hidden and local above) can be set independently of the version, but in
+    // practice at most one version of given name is non-hidden; version
+    // (including its presence or absence) is definitely part of the key; we
+    // should probably treat is-default-version as a non-key attribute
+    //
+    // defined - rather fundamental; libabigail currently doesn't track
+    // undefined symbols but we should obviously be prepared in case it does
 
-std::string MatchingKey::operator()(const Method& x) {
-  return x.name + ',' + x.mangled_name;
-}
+    // There are also some externalities which libabigail cares about, which may
+    // or may not be exposed in the XML
+    //
+    // index - don't care
+    //
+    // is-common and friends - don't care
+    //
+    // aliases - exposed, but we don't really care; however we should see what
+    // compilers do, if anything, in terms of propagating type information to
+    // aliases
 
-std::string MatchingKey::operator()(const Member& x) {
-  if (!x.name.empty()) {
-    return x.name;
-  }
-  return (*this)(x.type_id);
-}
+    // Linux kernel things.
+    //
+    // MODVERSIONS CRC - fundamental to ABI compatibility, if present
+    //
+    // Symbol namespace - fundamental to ABI compatibility, if present
 
-std::string MatchingKey::operator()(const VariantMember& x) {
-  return x.name;
-}
+    Result result;
+    result.MaybeAddNodeDiff("name", x1.symbol_name, x2.symbol_name);
 
-std::string MatchingKey::operator()(const StructUnion& x) {
-  if (!x.name.empty()) {
-    return x.name;
-  }
-  if (x.definition) {
-    const auto& members = x.definition->members;
-    for (const auto& member : members) {
-      const auto recursive = (*this)(member);
-      if (!recursive.empty()) {
-        return recursive + '+';
+    if (x1.version_info && x2.version_info) {
+      result.MaybeAddNodeDiff("version", x1.version_info->name,
+                              x2.version_info->name);
+      result.MaybeAddNodeDiff("default version", x1.version_info->is_default,
+                              x2.version_info->is_default);
+    } else {
+      result.MaybeAddNodeDiff("has version", x1.version_info.has_value(),
+                              x2.version_info.has_value());
+    }
+
+    result.MaybeAddNodeDiff("defined", x1.is_defined, x2.is_defined);
+    result.MaybeAddNodeDiff("symbol type", x1.symbol_type, x2.symbol_type);
+    result.MaybeAddNodeDiff("binding", x1.binding, x2.binding);
+    result.MaybeAddNodeDiff("visibility", x1.visibility, x2.visibility);
+    if (!ignore.Test(Ignore::SYMBOL_CRC)) {
+      result.MaybeAddNodeDiff("CRC", x1.crc, x2.crc);
+    }
+    result.MaybeAddNodeDiff("namespace", x1.ns, x2.ns);
+
+    if (x1.type_id && x2.type_id) {
+      result.MaybeAddEdgeDiff("", (*this)(*x1.type_id, *x2.type_id));
+    } else if (x1.type_id) {
+      if (!ignore.Test(Ignore::SYMBOL_TYPE_PRESENCE)) {
+        result.AddEdgeDiff("", Removed(*x1.type_id));
+      }
+    } else if (x2.type_id) {
+      if (!ignore.Test(Ignore::SYMBOL_TYPE_PRESENCE)) {
+        result.AddEdgeDiff("", Added(*x2.type_id));
       }
+    } else {
+      // both types missing, we have nothing to say
     }
-  }
-  return {};
+
+    return result;
+  }
+
+  Result operator()(const Interface& x1, const Interface& x2) {
+    Result result;
+    result.diff.holds_changes = true;
+    const bool ignore_added = ignore.Test(Ignore::INTERFACE_ADDITION);
+    Nodes(x1.symbols, x2.symbols, ignore_added, result);
+    Nodes(x1.types, x2.types, ignore_added, result);
+    return result;
+  }
+
+  const Ignore ignore;
+  const Graph& graph;
+  Outcomes& outcomes;
+  Outcomes provisional;
+  std::unordered_map<Comparison, bool, HashComparison> known;
+  SCC<Comparison, HashComparison> scc;
+  Counter queried;
+  Counter already_compared;
+  Counter being_compared;
+  Counter really_compared;
+  Counter equivalent;
+  Counter inequivalent;
+  Histogram scc_size;
+};
+
+}  // namespace
+
+std::pair<Id, std::vector<std::string>> ResolveTypedefs(
+    const Graph& graph, Id id) {
+  std::pair<Id, std::vector<std::string>> result = {id, {}};
+  ResolveTypedef resolve(graph, result.first, result.second);
+  while (graph.Apply(resolve, result.first)) {}
+  return result;
 }
 
-template <typename Node>
-std::string MatchingKey::operator()(const Node&) {
-  return {};
+Comparison Compare(Runtime& runtime, Ignore ignore, const Graph& graph,
+                   Id root1, Id root2, Outcomes& outcomes) {
+  // The root node (Comparison{{id1}, {id2}}) must be the last node to be
+  // completely visited by the SCC finder and the SCC finder state must be empty
+  // on return from this function call. In particular, the returns where the SCC
+  // is "open" are impossible. The remaining cases (of which one is impossible
+  // for the root node) both have the same two possible return values:
+  //
+  // * (true, Comparison{})
+  // * (false, Comparison{{id1}, {id2}}
+  //
+  // So the invariant value.first == (value.second == Comparison{}) holds and we
+  // can unambiguously return value.second.
+  return CompareWorker(runtime, ignore, graph, outcomes)(root1, root2).second;
 }
 
 }  // namespace diff
diff --git a/comparison.h b/comparison.h
index 4ccc613..4d1e124 100644
--- a/comparison.h
+++ b/comparison.h
@@ -25,12 +25,8 @@
 #include <cstddef>
 #include <cstdint>
 #include <functional>
-#include <map>
-#include <memory>
 #include <optional>
 #include <ostream>
-#include <set>
-#include <sstream>
 #include <string>
 #include <string_view>
 #include <unordered_map>
@@ -39,7 +35,6 @@
 
 #include "graph.h"
 #include "runtime.h"
-#include "scc.h"
 
 namespace stg {
 namespace diff {
@@ -73,7 +68,7 @@ struct Ignore {
     bitset = bitset | (1 << other);
   }
   bool Test(Value other) const {
-    return bitset & (1 << other);
+    return (bitset & (1 << other)) != 0;
   }
 
   Bitset bitset = 0;
@@ -87,10 +82,10 @@ std::ostream& operator<<(std::ostream& os, IgnoreUsage);
 using Comparison = std::pair<std::optional<Id>, std::optional<Id>>;
 
 struct DiffDetail {
-  DiffDetail(const std::string& text, const std::optional<Comparison>& edge)
-      : text_(text), edge_(edge) {}
-  std::string text_;
-  std::optional<Comparison> edge_;
+  DiffDetail(const std::string& text, const Comparison& edge)
+      : text(text), edge(edge) {}
+  std::string text;
+  Comparison edge;
 };
 
 struct Diff {
@@ -101,99 +96,11 @@ struct Diff {
   bool has_changes = false;
   std::vector<DiffDetail> details;
 
-  void Add(const std::string& text,
-           const std::optional<Comparison>& comparison) {
+  void Add(const std::string& text, const Comparison& comparison) {
     details.emplace_back(text, comparison);
   }
 };
 
-struct Result {
-  // Used when two nodes cannot be meaningfully compared.
-  Result& MarkIncomparable() {
-    equals_ = false;
-    diff_.has_changes = true;
-    return *this;
-  }
-
-  // Used when a node attribute has changed.
-  void AddNodeDiff(const std::string& text) {
-    equals_ = false;
-    diff_.has_changes = true;
-    diff_.Add(text, {});
-  }
-
-  // Used when a node attribute may have changed.
-  template <typename T>
-  void MaybeAddNodeDiff(
-      const std::string& text, const T& before, const T& after) {
-    if (before != after) {
-      std::ostringstream os;
-      os << text << " changed from " << before << " to " << after;
-      AddNodeDiff(os.str());
-    }
-  }
-
-  // Used when a node attribute may have changed, lazy version.
-  template <typename T>
-  void MaybeAddNodeDiff(const std::function<void(std::ostream&)>& text,
-                        const T& before, const T& after) {
-    if (before != after) {
-      std::ostringstream os;
-      text(os);
-      os << " changed from " << before << " to " << after;
-      AddNodeDiff(os.str());
-    }
-  }
-
-  // Used when node attributes are optional values.
-  template <typename T>
-  void MaybeAddNodeDiff(const std::string& text, const std::optional<T>& before,
-                        const std::optional<T>& after) {
-    if (before && after) {
-      MaybeAddNodeDiff(text, *before, *after);
-    } else if (before) {
-      std::ostringstream os;
-      os << text << ' ' << *before << " was removed";
-      AddNodeDiff(os.str());
-    } else if (after) {
-      std::ostringstream os;
-      os << text << ' ' << *after << " was added";
-      AddNodeDiff(os.str());
-    }
-  }
-
-  // Used when an edge has been removed or added.
-  void AddEdgeDiff(const std::string& text, const Comparison& comparison) {
-    equals_ = false;
-    diff_.Add(text, {comparison});
-  }
-
-  // Used when an edge to a possible comparison is present.
-  void MaybeAddEdgeDiff(const std::string& text,
-                        const std::pair<bool, std::optional<Comparison>>& p) {
-    equals_ &= p.first;
-    const auto& comparison = p.second;
-    if (comparison) {
-      diff_.Add(text, comparison);
-    }
-  }
-
-  // Used when an edge to a possible comparison is present, lazy version.
-  void MaybeAddEdgeDiff(const std::function<void(std::ostream&)>& text,
-                        const std::pair<bool, std::optional<Comparison>>& p) {
-    equals_ &= p.first;
-    const auto& comparison = p.second;
-    if (comparison) {
-      std::ostringstream os;
-      text(os);
-      diff_.Add(os.str(), comparison);
-    }
-  }
-
-  bool equals_ = true;
-  Diff diff_;
-};
-
 struct HashComparison {
   size_t operator()(const Comparison& comparison) const {
     size_t seed = 0;
@@ -209,105 +116,11 @@ struct HashComparison {
 
 using Outcomes = std::unordered_map<Comparison, Diff, HashComparison>;
 
-struct MatchingKey {
-  explicit MatchingKey(const Graph& graph) : graph(graph) {}
-  std::string operator()(Id id);
-  std::string operator()(const BaseClass&);
-  std::string operator()(const Method&);
-  std::string operator()(const Member&);
-  std::string operator()(const VariantMember&);
-  std::string operator()(const StructUnion&);
-  template <typename Node>
-  std::string operator()(const Node&);
-  const Graph& graph;
-};
-
 std::pair<Id, std::vector<std::string>> ResolveTypedefs(
     const Graph& graph, Id id);
 
-struct ResolveTypedef {
-  ResolveTypedef(const Graph& graph, Id& id, std::vector<std::string>& names)
-      : graph(graph), id(id), names(names) {}
-  bool operator()(const Typedef&);
-  template <typename Node>
-  bool operator()(const Node&);
-
-  const Graph& graph;
-  Id& id;
-  std::vector<std::string>& names;
-};
-
-using Qualifiers = std::set<Qualifier>;
-
-// Separate qualifiers from underlying type.
-//
-// The caller must always be prepared to receive a different type as qualifiers
-// are sometimes discarded.
-std::pair<Id, Qualifiers> ResolveQualifiers(const Graph& graph, Id id);
-
-struct ResolveQualifier {
-  ResolveQualifier(const Graph& graph, Id& id, Qualifiers& qualifiers)
-      : graph(graph), id(id), qualifiers(qualifiers) {}
-  bool operator()(const Qualified&);
-  bool operator()(const Array&);
-  bool operator()(const Function&);
-  template <typename Node>
-  bool operator()(const Node&);
-
-  const Graph& graph;
-  Id& id;
-  Qualifiers& qualifiers;
-};
-
-struct Compare {
-  Compare(Runtime& runtime, const Graph& graph, const Ignore& ignore)
-      : graph(graph), ignore(ignore),
-        queried(runtime, "compare.queried"),
-        already_compared(runtime, "compare.already_compared"),
-        being_compared(runtime, "compare.being_compared"),
-        really_compared(runtime, "compare.really_compared"),
-        equivalent(runtime, "compare.equivalent"),
-        inequivalent(runtime, "compare.inequivalent"),
-        scc_size(runtime, "compare.scc_size") {}
-  std::pair<bool, std::optional<Comparison>>  operator()(Id id1, Id id2);
-
-  Comparison Removed(Id id);
-  Comparison Added(Id id);
-  void CompareDefined(bool defined1, bool defined2, Result& result);
-
-  Result Mismatch();
-  Result operator()(const Special&, const Special&);
-  Result operator()(const PointerReference&, const PointerReference&);
-  Result operator()(const PointerToMember&, const PointerToMember&);
-  Result operator()(const Typedef&, const Typedef&);
-  Result operator()(const Qualified&, const Qualified&);
-  Result operator()(const Primitive&, const Primitive&);
-  Result operator()(const Array&, const Array&);
-  Result operator()(const BaseClass&, const BaseClass&);
-  Result operator()(const Method&, const Method&);
-  Result operator()(const Member&, const Member&);
-  Result operator()(const VariantMember&, const VariantMember&);
-  Result operator()(const StructUnion&, const StructUnion&);
-  Result operator()(const Enumeration&, const Enumeration&);
-  Result operator()(const Variant&, const Variant&);
-  Result operator()(const Function&, const Function&);
-  Result operator()(const ElfSymbol&, const ElfSymbol&);
-  Result operator()(const Interface&, const Interface&);
-
-  const Graph& graph;
-  const Ignore ignore;
-  std::unordered_map<Comparison, bool, HashComparison> known;
-  Outcomes outcomes;
-  Outcomes provisional;
-  SCC<Comparison, HashComparison> scc;
-  Counter queried;
-  Counter already_compared;
-  Counter being_compared;
-  Counter really_compared;
-  Counter equivalent;
-  Counter inequivalent;
-  Histogram scc_size;
-};
+Comparison Compare(Runtime& runtime, Ignore ignore, const Graph& graph,
+                   Id root1, Id root2, Outcomes& outcomes);
 
 }  // namespace diff
 }  // namespace stg
diff --git a/deduplication.cc b/deduplication.cc
index b71c599..aaeffbe 100644
--- a/deduplication.cc
+++ b/deduplication.cc
@@ -82,14 +82,14 @@ Id Deduplicate(Runtime& runtime, Graph& graph, Id root, const Hashes& hashes) {
   // Keep one representative of each set of duplicates.
   Counter unique(runtime, "deduplicate.unique");
   Counter duplicate(runtime, "deduplicate.duplicate");
-  auto remap = [&cache](Id& id) {
+  const auto remap = [&cache](Id& id) {
     // update id to representative id, avoiding silent stores
     const Id fid = cache.Find(id);
     if (fid != id) {
       id = fid;
     }
   };
-  Substitute substitute(graph, remap);
+  const Substitute substitute(graph, remap);
   {
     const Time x(runtime, "rewrite");
     for (const auto& [id, fp] : hashes) {
diff --git a/deduplication.h b/deduplication.h
index adb8c89..723bb19 100644
--- a/deduplication.h
+++ b/deduplication.h
@@ -20,7 +20,6 @@
 #ifndef STG_DEDUPLICATION_H_
 #define STG_DEDUPLICATION_H_
 
-#include <cstdint>
 #include <unordered_map>
 
 #include "graph.h"
diff --git a/doc/DIFFS.md b/doc/DIFFS.md
deleted file mode 100644
index 8e63eb7..0000000
--- a/doc/DIFFS.md
+++ /dev/null
@@ -1,300 +0,0 @@
-# Diffs
-
-Consider two directed graphs, containing labelled nodes and edges. Given a
-designated starting node in each graph, describe how the reachable subgraphs are
-different in a textual report.
-
-STG separates the problem of reporting graph differences into two pieces:
-
-1. comparison - generating difference graphs
-1. reporting - serialising difference graphs
-
-The main benefits are:
-
-* separation of responsibility allowing reporting to vary without significant
-  changes to the comparison code
-* a single difference graph can be used to generate multiple reports with
-  guaranteed consistency and modest time savings
-* the difference graph data structure may be presented as a graph, manipulated,
-  subject to further analysis or stored
-
-## Abstract Graph Diffs
-
-There are 3 kinds of node difference and each node comparison pair can have any
-number of these:
-
-1. node label difference - a purely local change
-1. outgoing edge with matching labels - a recursive difference
-1. added or removed outgoing edge - modelled as a recursive difference with an
-   "absent" node
-
-STG models comparisons as pairs of nodes where either node can be absent. While
-absent-absent comparisons can result from the composition of an addition and a
-removal, they do not occur naturally during pairwise comparison.
-
-## Comparison Implementation
-
-Comparison is mostly done pair-wise recursively with a DFS, by the function
-object `Compare` and with the help of the [SCC finder](SCC.md).
-
-The algorithm divides responsibility between `operator()(Id, Id)` and various
-`operator()(Node, Node)` methods. There are also trivial helpers `Removed`,
-`Added` and `Mismatch`.
-
-The `Result` type encapsulates the difference between two nodes being compared.
-It contains both a list (`Diff`) of differences (`DiffDetail`) and a boolean
-equality outcome. The latter is used to propagate inequality information in the
-presence of cycles in the diff comparison graph.
-
-### `operator()(Node, Node)`
-
-For a given `Node` type, this method has the job of computing local differences,
-matching edges and obtaining edge differences from recursive calls to
-`operator()(Id, Id)` (or `Removed` and `Added`, if edge labels are unmatched).
-
-Local differences can easily be rendered as text, but edge differences need
-recursive calls, the results of which are merged into the local differences
-`Result` with helper methods.
-
-In general we want each comparison operator to be as small as possible,
-containing no boilerplate and simply mirroring the node data. The helper
-functions were therefore chosen for power, laziness and concision.
-
-### `Added` and `Removed`
-
-These take care of comparisons where one side is absent.
-
-There are several reasons for not folding this functionality into `operator(Id,
-Id)` itself:
-
-* it would result in unnecessary extra work for unmatched edges as its callers
-  would pack and the function would unpack `std::optional<Id>` arguments
-* added and removed nodes have none of the other interesting features that it
-  handles
-* `Added` and `Removed` don't need to decorate their return values with any
-  difference information
-
-### `operator(Id, Id)`
-
-This controls recursion and handles some special cases before delegating to some
-`operator()(Node, Node)` in the "normal" case.
-
-It takes care of the following:
-
-* revisited, completed comparisons
-* revisited, in-progress comparison
-* qualified types
-* typedefs
-* incomparable and comparable nodes - handled by `Mismatch` and delegated,
-  respectively
-
-Note that the non-trivial special cases relating to typedefs and qualified types
-(and their current concrete representations) require non-parallel traversals of
-the graphs being compared.
-
-#### Revisited Nodes and Recursive Comparison
-
-STG comparison relies on `SCC` to control recursion and behaviour in the face of
-graphs containing arbitrary cycles. Any difference found affecting one node in a
-comparison cycle affects all nodes in that cycle.
-
-Excluding the two special cases documented in the following sections, the
-comparison steps are approximately:
-
-1. if the comparison already has a known result then return this
-1. if the comparison already is in progress then return a potential difference
-1. start node visit, register the node with the SCC finder
-   1. (special cases for qualified types and typedefs)
-   1. incomparable nodes go to `Mismatch` which returns a difference
-   1. otherwise delegate node comparison (with possible recursion)
-   1. result is a tentative node comparion
-1. finish node visit, informing the SCC finder
-1. if an SCC was closed, we've just finished its root comparison
-   1. root compared equal? discard unwanted potential differences
-   1. difference found? record confirmed differences
-   1. record all its comparisons as final
-1. return result (whether final or tentative)
-
-#### Typedefs
-
-Typedefs are just named type aliases which cannot refer to themselves or later
-defined types. The referred-to type is exactly identical to the typedef. So for
-difference *finding*, typedefs should just be resolved and skipped over.
-However, for *reporting*, it may be still useful to say where a difference came
-from. This requires extra handling to collect the typedef names on each side of
-the comparison, when there is something to report.
-
-If `operator()(Id, Id)` sees a comparison involving a typedef, it resolves
-typedef chains on both sides and keeps track of the names. Then it calls itself
-recursively. If the result is no-diff, it returns no-diff, otherwise, it reports
-the differences between the types at the end of the typedef chains.
-
-An alternative would be to genuinely just follow the epsilons. Store the
-typedefs in the diff tree but record the comparison of what they resolve to. The
-presentation layer can decorate the comparison text with resolution chains.
-
-Note that qualified typedefs present extra complications.
-
-#### Qualified Types
-
-STG currently represents type qualifiers as separate, individual nodes. They are
-relevant for finding differences but there may be no guarantee of the order in
-which they will appear. For diff reporting, STG currently reports added and
-removed qualifiers but also compares the underlying types.
-
-This implies that when faced with a comparison involving a qualifier,
-`operator()(Id, Id)` should collect and compare all qualifiers on both sides and
-treat the types as compound objects consisting of their qualifiers and the
-underlying types, either or both of which may have differences to report.
-Comparing the underlying types requires recursive calls.
-
-Note that qualified typedefs present extra complications.
-
-#### Qualified typedefs
-
-Qualifiers and typedefs have subtle interactions. For example:
-
-Before:
-
-```c++
-const int quux;
-```
-
-After 1:
-
-```c++
-typedef int foo;
-const foo quux;
-```
-
-After 2:
-
-```c++
-typedef const int foo;
-foo quux;
-```
-
-After 3:
-
-```c++
-typedef const int foo;
-const foo quux;
-```
-
-In all cases above, the type of `quux` is unchanged. These examples strongly
-suggest that a better model of C types would involve tracking qualification as a
-decoration present on every type node, including typedefs.
-
-Note that this behaviour implies C's type system is not purely constructive as
-there is machinery to discard duplicate qualifiers which would be illegal
-elsewhere.
-
-For the moment, we can pretend that outer qualifications are always significant,
-even though they may be absorbed by inner ones, and risk occasional false
-positives.
-
-A worse case is:
-
-Before:
-
-```c++
-const int quux[];
-```
-
-After 1:
-
-```c++
-typedef int foo[];
-const foo quux;
-```
-
-After 2:
-
-```c++
-typedef const int foo[];
-foo quux;
-```
-
-After 3:
-
-```c++
-typedef const int foo[];
-const foo quux;
-```
-
-All the `quux` are identically typed. There is an additional wart that what
-would normally be illegal qualifiers on an array type instead decorate its
-element type.
-
-Finally, worst is:
-
-
-Before:
-
-```c++
-const int quux();
-```
-
-After 1:
-
-```c++
-typedef int foo();
-const foo quux;
-```
-
-After 2:
-
-```c++
-typedef const int foo();
-foo quux;
-```
-
-After 3:
-
-```c++
-typedef const int foo();
-const foo quux;
-```
-
-The two `const foo quux` cases invoke undefined behaviour. The consistently
-crazy behaviour would have been to decorate the return type instead.
-
-### Diff helpers
-
-These are mainly used by the `Compare::operator()(Node, Node)` methods.
-
-* `MarkIncomparable` - nodes are just different
-* `AddNodeDiff` - add node difference, unconditionally
-* `AddEdgeDiff` - add edge difference (addition or removal), unconditionally
-* `MaybeAddNodeDiff` - add node difference (label change), conditionally
-* `MaybeAddEdgeDiff` - add matching edge recursive difference, conditionally
-
-Variants are possible where text is generated lazily on a recursive diff being
-found, as are ones where labels are compared and serialised only if different.
-
-## Diff Presentation
-
-In general, there are two problems to solve:
-
-* generating suitable text, for
-   * nodes and edges
-   * node and edge differences
-* building a report with some meaningful structure
-
-Node and edge description and report structure are the responsibility of the
-*reporting* code. See [Names](NAMES.md) for more detailed notes on node
-description, mainly C type name syntax.
-
-Several report formats are supported and the simplest is (omitting various
-complications) a rendering of a difference graph as a difference *tree* where
-revisiting nodes is avoided by reporting 2 additional artificial kinds of
-difference:
-
-1. already reported - to handle diff sharing
-1. being compared - to handle diff cycles
-
-The various formats are not documented further here.
-
-Finally, node and edge difference description is currently the responsibility of
-the *comparison* code. This may change in the future, but might require a typed
-difference graph.
diff --git a/doc/comparison.md b/doc/comparison.md
new file mode 100644
index 0000000..955529d
--- /dev/null
+++ b/doc/comparison.md
@@ -0,0 +1,421 @@
+# Comparison
+
+This is implemented in `comparison.{h,cc}`.
+
+Graph comparison is the basis of all STG difference reporting.
+
+All the various STG node attributes (such as `size` or `name`) and edge
+identifiers (whether explicit or not, such as function parameter index) can be
+reduced to generic labels. This (over)simplification reduces the problem to
+solve to:
+
+*   given two rooted directed graphs, containing labelled nodes and edges
+*   generate a graph that encapsulates all the differences found by following
+    matching pairs of edges
+
+Report generation from such a graph is the subject of [Reporting](reporting.md).
+
+STG compares the graphs starting at the root nodes and recursing along edges
+with matching labels. The recursion stops at incomparable nodes (such as a
+`struct` and `int`). Otherwise a comparison specific to the kind of node is
+performed.
+
+Given that the graph will in general not be a tree and may contain cycles, STG
+
+*   memoises comparisons with known results
+*   detects comparison cycles and ensures correct termination and propagation of
+    results
+
+Overall, this ensures that any given pair of nodes (one from each graph) is
+compared at most once. In the case of a small change to a typical ABI graph of
+size *N*, *O(N)* node comparisons are performed.
+
+## Ignoring certain kinds of differences
+
+It has proved useful to add selective suppression of certain kinds of
+differences, for distinct purposes.
+
+| **ignore**               | **directionality** | **purpose**               |
+| ------------------------ | ------------------ | ------------------------- |
+| interface addition       | asymmetric         | compatibility checking    |
+| type definition addition | asymmetric         | compatibility checking    |
+| primitive type encoding  | symmetric          | cross comparison noise    |
+:                          :                    : reduction                 :
+| member size              | symmetric          | cross comparison noise    |
+:                          :                    : reduction                 :
+| enum underlying type     | symmetric          | cross comparison noise    |
+:                          :                    : reduction                 :
+| qualifier                | symmetric          | cross comparison noise    |
+:                          :                    : reduction                 :
+| symbol CRC               | symmetric          | cross comparison noise    |
+:                          :                    : reduction                 :
+| symbol type presence     | symmetric          | libabigail XML comparison |
+:                          :                    : noise reduction           :
+| type declaration status  | symmetric          | libabigail XML comparison |
+:                          :                    : noise reduction           :
+
+The first two options can be used to test whether one ABI is a subset of
+another.
+
+It can be useful to cross compare ABIs extracted in different ways to validate
+the fidelity of one ABI source against another. Where the models or
+implementations differ systematically, suppressing those differences will make
+the remainder more obvious.
+
+The libabigail versions used in Android's GKI project often generated ABIs with
+spurious differences due to the disappearance (or reappearance) of type
+definitions and (occasionally) symbol types. The corresponding ignore options
+replicate the behaviour of libabigail's `abidiff`.
+
+## Differences and difference graphs
+
+When comparing a pair of nodes, each difference falls into one of the following
+categories:
+
+*   node label - a purely local difference
+*   matching edge - a recursive difference found by following edges with
+    matching labels
+*   added or removed labelled edges, where edges are identified by label -
+    modelled as a recursive difference with a node absent on one side
+
+Each node in an STG difference graph is one of the following[^1]:
+
+*   a node removal or addition, containing
+    *   a reference to either a node in first graph or one in the second
+*   a node change, containing
+    *   a reference to two nodes, one in each of the two graphs
+    *   a possibly-empty list of differences which can each be one of
+        *   a node attribute difference in the form of some informative text
+        *   an edge difference in the form of a link to a difference node
+
+[^1]: STG models comparisons as pairs of nodes where either node can be absent.
+    The absent-absent comparison is used to represent "no change". All such
+    edges, except those representing the root of a "no change" graph comparison,
+    are pruned during diff graph creation.
+
+Note that STG's difference nodes are *unkinded*, there is only one kind of
+difference node, unlike STG's data nodes where there is a separate kind of node
+for each kind of C type etc.
+
+## Matching and comparing collections of edges
+
+While an algorithm based on generic label comparison will work, there are a
+couple of issues:
+
+*   collections of outgoing edges may not have an obvious label to assign
+    (multiple anonymous members of a `struct`, for example)
+*   edges are often ordered (parameters and members, for example) and we want to
+    preserve this order when reporting differences
+
+Comparing two pointer types is straightforward, just compare the pointed-to
+types. However, symbol tables, function arguments and struct members all require
+comparisons of multiple entities simultaneously.
+
+STG compares edge aggregates as follows:
+
+*   arrays (like function arguments): by index, comparing recursively items with
+    the same index, reporting removals and additions of the remaining items
+*   maps (like the symbol table): by key, comparing recursively items with
+    matching keys, reporting removals and additions of unmatched items
+*   otherwise synthesise a key for comparison, compare by key, report
+    differences in the original order of items being compared (favouring the
+    second list's order over the first's); the reordering is an *O(n²)*
+    operation and it might be possible to adapt the more general Myer's diff
+    algorithm to reduce this
+
+## Implementation Details
+
+Comparison is mostly done pair-wise recursively with a DFS, by the function
+object `CompareWorker` and with the help of the [SCC finder](scc.md).
+
+The algorithm divides responsibility between `operator()(Id, Id)` and various
+`operator()(Node, Node)` methods. There are also various helpers in and outside
+`CompareWorker`.
+
+The `Result` type encapsulates the difference between two nodes being compared.
+It contains both a list (`Diff`) of differences (`DiffDetail`) and a boolean
+equality outcome. The latter is used to propagate inequality information in the
+presence of cycles in the diff comparison graph.
+
+### `operator()(Node, Node)`
+
+Specialised for each `Node` type, these methods have the job of computing local
+differences, matching edges and obtaining edge differences from recursive calls
+to `operator()(Id, Id)` (or `Removed` and `Added`, if edge labels are
+unmatched).
+
+Local differences can easily be rendered as text, but edge differences need
+recursive calls, the results of which are merged into the local differences
+`Result` with helper methods.
+
+These methods form the bulk of the comparison code, so in general we want them
+to be as small as possible, containing no boilerplate and simply mirroring the
+node data. The helper functions were therefore chosen for power, laziness and
+concision.
+
+### `Added` and `Removed`
+
+These take care of comparisons where one side is absent.
+
+There are several reasons for not folding this functionality into `operator(Id,
+Id)` itself:
+
+*   it would result in unnecessary extra work as its callers would need to pack
+    and the function would need to unpack `optional<Id>` arguments
+*   added and removed nodes have none of the other interesting features that it
+    handles
+*   `Added` and `Removed` don't need to decorate their return values with any
+    difference information
+
+### `Defined`
+
+This takes care of comparisons of user-defined types which may be forward
+declarations or full definitions.
+
+### `Nodes`
+
+These take care of comparisons of sequences of arbitrary nodes (or enumerators).
+
+STG uses "matching keys" to reduce the problem of comparing sequences to
+comparing maps. It attempts to preserve original sequence order as described in
+`order.h`.
+
+### `operator(Id, Id)`
+
+This controls recursion and handles some special cases before delegating to some
+`operator()(Node, Node)` in the "normal" case.
+
+It takes care of the following:
+
+*   revisited, completed comparisons
+*   revisited, in-progress comparison
+*   qualified types
+*   typedefs
+*   incomparable and comparable nodes
+*   comparison cycles
+
+Note that the non-trivial special cases relating to typedefs and qualified types
+(and their current concrete representations) require non-parallel traversals of
+the graphs being compared; this is the only place where the comparison is not
+purely structural.
+
+#### Revisited Nodes and Recursive Comparison
+
+STG comparison relies on `SCC` to control recursion and behaviour in the face of
+graphs containing arbitrary cycles. Any difference found affecting one node in a
+comparison cycle affects all nodes in that cycle.
+
+Excluding the two special cases documented in the following sections, the
+comparison steps are approximately:
+
+1.  if the comparison already has a known result then return this
+2.  if the comparison already is in progress then return a potential difference
+3.  start node visit, register the node with the SCC finder
+    1.  (special handling of qualified types and typedefs)
+    2.  incomparable nodes (such as a `struct` and an `int`) go to `Mismatch`
+        which returns a difference; there is no further recursion
+    3.  otherwise delegate node comparison to a node-specific function; with
+        possible recursion
+    4.  the comparison result here is tentative, due to potential cycles
+4.  finish node visit, informing the SCC finder
+5.  if an SCC was closed, we've just finished its root comparison
+    1.  root compared equal? discard unwanted potential differences
+    2.  difference found? record confirmed differences
+    3.  record all its comparison results as final
+6.  return result (which will be final if an SCC was closed)
+
+#### Typedefs
+
+This special handling is subject to change.
+
+*   `typedef` foo bar ⇔ foo
+
+Typedefs are named type aliases which cannot refer to themselves or later
+defined types. The referred-to type is exactly identical to the typedef. So for
+difference *finding*, typedefs should just be resolved and skipped over.
+However, for *reporting*, it may be still useful to say where a difference came
+from. This requires extra handling to collect the typedef names on each side of
+the comparison, when there is something to report.
+
+If `operator()(Id, Id)` sees a comparison involving a typedef, it resolves
+typedef chains on both sides and keeps track of the names. Then it calls itself
+recursively. If the result is no-diff, it returns no-diff, otherwise, it reports
+the differences between the types at the end of the typedef chains.
+
+An alternative would be to genuinely just follow the epsilons. Store the
+typedefs in the diff tree but record the comparison of what they resolve to. The
+presentation layer can decorate the comparison text with resolution chains.
+
+Note that qualified typedefs present extra complications.
+
+#### Qualified Types
+
+This special handling is subject to change.
+
+*   `const` → `volatile` → foo ⇔ `volatile` → `const` → foo
+
+STG currently represents type qualifiers as separate, individual nodes. They are
+relevant for finding differences but there may be no guarantee of the order in
+which they will appear. For diff reporting, STG currently reports added and
+removed qualifiers but also compares the underlying types.
+
+This implies that when faced with a comparison involving a qualifier,
+`operator()(Id, Id)` should collect and compare all qualifiers on both sides and
+treat the types as compound objects consisting of their qualifiers and the
+underlying types, either or both of which may have differences to report.
+Comparing the underlying types requires recursive calls.
+
+Note that qualified typedefs present extra complications.
+
+#### Qualified typedefs
+
+STG does not currently do anything special for qualified typedefs which can have
+subtle and surprising behaviours. For example:
+
+Before:
+
+```c++
+const int quux;
+```
+
+After 1:
+
+```c++
+typedef int foo;
+const foo quux;
+```
+
+After 2:
+
+```c++
+typedef const int foo;
+foo quux;
+```
+
+After 3:
+
+```c++
+typedef const int foo;
+const foo quux;
+```
+
+In all cases above, the type of `quux` is unchanged. These examples strongly
+suggest that a better model of C types would involve tracking qualification as a
+decoration present on every type node, including typedefs.
+
+Note that this behaviour implies C's type system is not purely constructive as
+there is machinery to discard duplicate qualifiers which would be illegal
+elsewhere.
+
+For the moment, we can pretend that outer qualifications are always significant,
+even though they may be absorbed by inner ones, and risk occasional false
+positives.
+
+A worse case is:
+
+Before:
+
+```c++
+const int quux[];
+```
+
+After 1:
+
+```c++
+typedef int foo[];
+const foo quux;
+```
+
+After 2:
+
+```c++
+typedef const int foo[];
+foo quux;
+```
+
+After 3:
+
+```c++
+typedef const int foo[];
+const foo quux;
+```
+
+All the `quux` are identically typed. There is an additional wart that what
+would normally be illegal qualifiers on an array type instead decorate its
+element type.
+
+Finally, worst is:
+
+Before:
+
+```c++
+const int quux();
+```
+
+After 1:
+
+```c++
+typedef int foo();
+const foo quux;
+```
+
+After 2:
+
+```c++
+typedef const int foo();
+foo quux;
+```
+
+After 3:
+
+```c++
+typedef const int foo();
+const foo quux;
+```
+
+The two `const foo quux` cases invoke undefined behaviour. The consistently
+crazy behaviour would have been to decorate the return type instead.
+
+The "worstest" case is GCC allowing the specification of typedef alignment
+different to the defining type. This abomination should not exist and should
+never be used. Alignment is not currently modelled by STG.
+
+### Diff helpers
+
+These are mainly used by the `CompareWorker::operator()(Node, Node)` methods.
+
+*   `MarkIncomparable` - nodes are just different
+*   `AddNodeDiff` - add node difference, unconditionally
+*   `AddEdgeDiff` - add edge difference (addition or removal), unconditionally
+*   `MaybeAddNodeDiff` - add node difference (label change), conditionally
+*   `MaybeAddEdgeDiff` - add matching edge recursive difference, conditionally
+
+Variants are possible where text is generated lazily on a recursive diff being
+found, as are ones where labels are compared and serialised only if different.
+
+## Diff Presentation
+
+In general, there are two problems to solve:
+
+*   generating suitable text, for
+    *   nodes and edges
+    *   node and edge differences
+*   building a report with some meaningful structure
+
+Node and edge description and report structure are the responsibility of the
+*reporting* code. See [Naming](naming.md) for more detailed notes on node
+description, mainly C type name syntax.
+
+Several report formats are supported and the simplest is (omitting various
+complications) a rendering of a difference graph as a difference *tree* where
+revisiting nodes is avoided by reporting 2 additional artificial kinds of
+difference:
+
+1.  already reported - to handle diff sharing
+2.  being compared - to handle diff cycles
+
+The various formats are not documented further here.
+
+Finally, node and edge difference description is currently the responsibility of
+the *comparison* code. This may change in the future, but might require a typed
+difference graph.
diff --git a/doc/index.md b/doc/index.md
new file mode 100644
index 0000000..c6b1fc6
--- /dev/null
+++ b/doc/index.md
@@ -0,0 +1,24 @@
+# Documentation
+
+First-time users should start with the [tutorial](tutorial.md).
+
+## Manual Pages
+
+These describe all the various command line options.
+
+*   [`stg`](stg.md): ABI extraction and transformation
+*   [`stgdiff`](stgdiff.md): ABI comparison and reporting
+
+## Reference
+
+*   [`reference`](reference.md): work-in-progress covering concepts etc.
+
+## Design and Implementation
+
+Incomplete descriptions of some of the more interesting things that make up
+`stgdiff`.
+
+*   [Comparison](comparison.md): how STG compares graphs
+*   [Naming](naming.md): how STG builds C type name syntax
+*   [Reporting](reporting.md): how STG serialises reports
+*   [SCC](scc.md): how STG efficiently and safely handles cyclic graphs
diff --git a/doc/NAMES.md b/doc/naming.md
similarity index 71%
rename from doc/NAMES.md
rename to doc/naming.md
index b1e51a5..6976274 100644
--- a/doc/NAMES.md
+++ b/doc/naming.md
@@ -1,7 +1,10 @@
 # C Type Names
 
-STG does not contain full type names for every type node in the graph. If full
-type names are needed then we need to generate them ourselves.
+This is implementated in `naming.{h,cc}`.
+
+STG does not contain full type names for every type node in the graph. In order
+to meaningfully describe type changes, STG needs to be able to render C and C++
+type names back into source-level syntax.
 
 ## Implementation
 
@@ -25,27 +28,27 @@ In sensible operator grammars, composition can be done using precedence levels.
 Example with binary operators (there are minor adjustments needed if operators
 have left or right associativity):
 
-| op  | precedence |
-| --- | ---------- |
-| +   | 0          |
-| *   | 1          |
-| num | 2          |
+**op** | **precedence**
+------ | --------------
+`+`    | 0
+`*`    | 1
+*num*  | 2
 
 ```haskell
-show x = show_prec 0 x
+data Expr = Number Int | Times Expr Expr | Plus Expr Expr
 
 show_paren p x = if p then "(" ++ x ++ ")" else x
 
-show_prec _ (Number n) = to_string n
-show_prec prec (Mult e1 e2) = show_paren (prec > 1) (show_prec 2 e1 ++ "*" ++ show_prec 2 e2)
-show_prec prec (Add e1 e2) = show_paren (prec > 2) (show_prec 3 e1 ++ "+" ++ show_prec 3 e2)
+shows_prec p (Number n) = show n
+shows_prec p (Times e1 e2) = show_paren (p > 1) $ shows_prec 2 e1 ++ "*" ++ shows_prec 2 e2
+shows_prec p (Plus e1 e2) = show_paren (p > 0) $ shows_prec 1 e1 ++ "+" ++ shows_prec 1 e2
 ```
 
 The central idea is that expressions are rendered in the context of a precedence
 level. Parentheses are needed if the context precedence is higher than the
-expression's own precedence. Atomic values can be viewed as having maximal
-precedence. The default precedence context for printing an expression is the
-minimal one; no parentheses will be emitted.
+expression's own precedence. Atomic values can be viewed as expressions having
+maximal precedence. The default precedence context for printing an expression is
+the minimal one; no parentheses will be emitted.
 
 ## The more-than-slightly-bonkers C declaration syntax
 
@@ -53,13 +56,13 @@ C's type syntax is closely related to the inside-out declaration syntax it uses
 and has the same precedence rules. A simplified, partial precedence table for
 types might look like this.
 
-thing      | precedence
----------- | ----------
-int        | 0
-refer *    | 1
-elt[N]     | 2
-ret(args)  | 2
-identifier | 3
+**thing**    | **precedence**
+------------ | --------------
+`int`        | 0
+`refer *`    | 1
+`elt[N]`     | 2
+`ret(args)`  | 2
+`identifier` | 3
 
 The basic (lowest precedence) elements are:
 
@@ -69,19 +72,22 @@ The basic (lowest precedence) elements are:
 
 The "operators" in increasing precedence level order are:
 
-* pointer-to, possibly CVR-qualified
-* function (return type) and array (element type)
+*   pointer-to, possibly CVR-qualified
+*   function (return type) and array (element type)
 
 The atomic (highest precedence) elements are:
 
-* variable names
-* function names
+*   variable names
+*   function names
 
 ### CVR-qualifiers
 
 The qualifiers `const`, `volatile` and `restrict` appear to the right of the
 pointer-to operator `*` and are idiomatically placed to the left of the basic
-elements. They can be considered as transparent to precedence.
+elements.[^1] They can be considered as transparent to precedence.
+
+[^1]: They can be idiomatically placed to the right, but that's a different
+    idiom.
 
 ### User-defined types
 
@@ -141,19 +147,26 @@ recursion needs to keep track of a left piece, a right piece and the precedence
 level of the hole in the middle.
 
 ```haskell
-render (Basic type) = (type, 0, "")
-render (Ptr ref) = add Left 1 "*" (render ref)
-render (Function ret args) = add Right 2 ("(" ++ render_args args ++ ")") (render ret)
-render (Array elt size) = add Right 2 ("[" ++ render_size size ++ "]") (render elt)
-render (Decl name type) = add Left 3 name (render type)
+data LR = L | R deriving Eq
+
+data Type = Basic String | Ptr Type | Function Type [Type] | Array Type Int | Decl String Type
+
+render_final expr = ll ++ rr where
+  (ll, _, rr) = render expr
+
+render (Basic name) = (name, 0, "")
+render (Ptr ref) = add L 1 "*" (render ref)
+render (Function ret args) = add R 2 ("(" ++ intercalate ", " (map final_render args) ++ ")") (render ret)
+render (Array elt size) = add R 2 ("[" ++ show size ++ "]") (render elt)
+render (Decl name t) = add L 3 name (render t)
 
 add side prec text (l, p, r) =
   case side of
-    Left => (ll ++ text, prec, rr)
-    Right => (ll, prec, text ++ rr)
+    L -> (ll ++ text, prec, rr)
+    R -> (ll, prec, text ++ rr)
   where
     paren = prec < p
-    ll = if paren then l ++ "(" else if side == LEFT then l ++ " " else l
+    ll = if paren then l ++ "(" else if side == L then l ++ " " else l
     rr = if paren then ")" ++ r else r
 ```
 
diff --git a/doc/reference.md b/doc/reference.md
new file mode 100644
index 0000000..21bf8d2
--- /dev/null
+++ b/doc/reference.md
@@ -0,0 +1,193 @@
+# STG
+
+STG stands for Symbol-Type Graph.
+
+# Overview
+
+STG models Application Binary Interfaces. It supports extraction of ABIs from
+DWARF and ingestion of BTF and libabigail XML into its model. Its primary
+purpose is monitoring an ABI for changes over time and reporting such changes in
+a comprehensible fashion.
+
+STG captures symbol information, the size and layout of structs, function
+argument and return types and much more, in a graph representation. Difference
+reporting happens via a graph comparison.
+
+Currently, STG functionality is exposed as two command-line tools, `stg` (for
+ABI extraction) and `stgdiff` (for ABI comparison), and a native file format.
+
+## Model
+
+STG's model is an *abstraction* which does not and cannot capture every possible
+interface property, invariant or behaviour. Conversely, the model includes
+distinctions which are API significant but not ABI significant.
+
+Concretely, STG's model is a rooted, connected, directed graph where each kind
+of node corresponds to a meaningful ABI entity such as a symbol, function type
+or struct member.
+
+Nodes have specific attributes, such as name or size. Outgoing edges specify
+things like return type. STG's model does not impose any constraints on which
+nodes may be joined by edges.
+
+Each node has an identity. However, for the purpose of comparison, nodes are
+considered equal if they are of the same kind, have the same attributes and
+matching outgoing edges and all nodes reachable via a pair of matching edges are
+(recursively) equal. Renumbering nodes, (de)duplicating nodes and
+adding/removing unreachable nodes do not affect this relationship.
+
+### Symbols
+
+As modelled by STG, symbols correspond closely to ELF symbols as seen in
+`.dynsym` for shared object files or in `.symtab` for object files. In the case
+of the Linux kernel, the `.symtab` is enriched with metadata and the effective
+"ksymtab" is actually a subset of the ELF symbols together with CRC and
+namespace information.
+
+STG links symbols to their source-level types where these are known. Symbols
+defined purely in assembly language will not have type information.
+
+The symbol table is contained in the root node of the graph, which is an
+*Interface* node.
+
+### Types
+
+STG models the C, C++ and (to a limited extent) Rust type systems.
+
+For example, C++ template value parameters are poorly modelled for the simple
+reason that this would require modelling C++ *values* as well as types,
+something that DWARF itself doesn't do to the full extent permitted by C++20.
+
+As type definitions are in general mutually recursive, an STG ABI is in general
+a cyclic graph.
+
+The root node of the graph can also contain a list of interface types, which may
+not necessarily be reachable from the interface symbols.
+
+## Supported Input Formats, Parsers and Limitations
+
+STG can read its own native format for processing or comparison. It can also
+process libabigail XML and BTF (`.BTF` ELF sections), with some limitations due
+to model, design and implementation differences including missing features.
+
+### Kinds of Node
+
+STG has the following kinds of node.
+
+*   **Special** - used for `void` and `...`
+*   **Pointer / Reference** - `*`, `&` and `&&`
+*   **Pointer to Member** - `foo::*`
+*   **Typedef** - `typedef` and `using ... = ...`
+*   **Qualified** - `const` and friends
+*   **Primitive** - concrete types such as `int` and friends
+*   **Array** - `foo[N]` - there is no distinction between zero and
+    indeterminate length in the model
+*   **Base Class** - inheritance metadata
+*   **Method** - (only) virtual function
+*   **Member** - data member
+*   **Variant Member** - discriminated member
+*   **Struct / Union** - `struct foo` etc., Rust tuples too
+*   **Enumeration** - including the underlying value type - only values that are
+    within the range of signed 64-bit integer are correctly modelled
+*   **Variant** - for Rust enums holding data
+*   **Function** - multiple argument, single return type
+*   **ELF Symbol** - name, version, ELF metadata, Linux kernel metadata
+*   **Interface** - top-level collection of symbols and types
+
+An STG ABI consists of a rooted, connected graph of such nodes, and *nothing
+else*. STG is blind to anything that cannot be represented by its model.
+
+### Native Format
+
+STG's native file format is a protocol buffer text format. It is suitable for
+revision control, rather than human consumption. It is effectively described by
+[`stg.proto`](../stg.proto).
+
+In this textual serialisation of ABI graphs, external node identifiers and node
+order are chosen to minimise file changes when a small subset of the graph
+changes.
+
+As an example, this is the definition of the **Typedef** node kind:
+
+```proto
+message Typedef {
+  fixed32 id = 1;
+  string name = 2;
+  fixed32 referred_type_id = 3;
+}
+```
+
+### Abigail (a.k.a. libabigail XML)
+
+[libabigail](https://sourceware.org/libabigail/) is another project for ABI
+monitoring. It uses a format that can be parsed as XML.
+
+This command will transform Abigail into STG:
+
+```shell
+stg --abi library.xml --output library.stg
+```
+
+The main features modelled in Abigail but not STG are:
+
+*   source file, line and column information
+*   C++ access specifiers (public, protected, private)
+
+The Abigail reader has these distinct phases of operation:
+
+1.  text parsed into an XML tree
+2.  XML cleaning - whitespace and unused attributes are stripped
+3.  XML tidying - issues like duplicate nodes are resolved, if possible
+4.  XML parsed into a graph with symbol information held separately
+5.  symbols and root node added to the graph
+6.  useless type qualifiers are stripped in post-processing
+
+### BTF
+
+[BTF](https://docs.kernel.org/bpf/btf.html) is typically used for the Linux
+kernel where it is generated by `pahole -J` from ELF and DWARF information. It
+can also be generated natively instead of DWARF using `gcc -gbtf` and by Clang,
+but only for eBPF targets.
+
+This command will transform BTF into STG:
+
+```shell
+stg --btf vmlinux --output vmlinux.stg
+```
+
+STG has primarily been tested against the `pahole` (libbtf) dialect of BTF and
+support is not complete.
+
+*   split BTF is not supported at all
+*   any `.BTF.ext` section is just ignored
+*   some kinds of BTF node are not handled:
+    *   `BTF_KIND_DATASEC` - skip
+    *   `BTF_KIND_DECL_TAG` - abort
+    *   `BTF_KIND_TYPE_TAG` - abort
+
+The BTF reader has these distinct phases of operation:
+
+1.  file is opened as ELF and `.BTF` section data found
+2.  BTF header processed
+3.  BTF nodes parsed into a graph with symbol information held separately
+4.  symbols and root node added to the graph
+
+### DWARF
+
+The ELF / DWARF reader operates similarly to the other readers at a high level,
+but much more work has to be done to turn ELF symbols and DWARF DIEs into STG
+nodes.
+
+1.  the ELF file is checked for DWARF - missing DWARF results in a warning
+2.  the ELF symbols are read (from `.dynsym` in the case of shared object file)
+3.  the DWARF information is parsed into a partial STG graph
+4.  the ELF and DWARF information are stitched together, adding symbols and a
+    root node to the graph
+5.  useless type qualifiers are stripped in post-processing
+
+## Output preprocessing
+
+Before `stg` outputs a serialised graph, it performs:
+
+1.  a type normalisation step that unifies overlapping type definitions
+2.  a final deduplication step to eliminate other redundant nodes
diff --git a/doc/reporting.md b/doc/reporting.md
new file mode 100644
index 0000000..c03e01e
--- /dev/null
+++ b/doc/reporting.md
@@ -0,0 +1,30 @@
+# Reporting
+
+This is implemented in `reporting.{h,cc}`.
+
+STG difference reporting is built on [comparison](comparison.md) and
+[naming](naming.md). All that remains is to serialise the difference graph into
+a readable or usable format.
+
+Just as ABI graphs may contain cycles, so can difference graphs. STG currently
+supports the following reporting options.
+
+| **format** | **description**                                                 |
+| ---------- | --------------------------------------------------------------- |
+| plain      | simple recursion, avoiding repeated node visits - unreadable    |
+:            : for deep graphs                                                 :
+| flat       | graph is split into fragments each rooted at a node that "owns" |
+:            : differences                                                     :
+| small      | like flat, but empty sub graphs are omitted                     |
+| short      | like small, but with lossy compression of repetitive            |
+:            : differences                                                     :
+| viz        | Graphviz - infeasible for rendering once the graphs become      |
+:            : large                                                           :
+
+The most useful option is `small`. Use `flat` if you need to see the impact on
+the interface symbols and types. Use `short` if large reports should be
+condensed.
+
+The `flat` reporting and its derivatives will misbehave (go into an infinite
+loop) in the current implementation, if the difference graph contains a cycle
+where none of the nodes refers to a named type.
diff --git a/doc/SCC.md b/doc/scc.md
similarity index 91%
rename from doc/SCC.md
rename to doc/scc.md
index 6e7e37c..d12126c 100644
--- a/doc/SCC.md
+++ b/doc/scc.md
@@ -16,11 +16,9 @@ There are three commonly-studied asymptotically-optimal approaches to
 determining the Strongly-Connected Components of a directed graph. Each of these
 admits various optimisations and specialisations for different purposes.
 
-* [Kosaraju's algorithm](https://en.wikipedia.org/wiki/Kosaraju%27s_algorithm)
-* [Tarjan's
-  algorithm](https://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm)
-* [The path-based
-  algorithm](https://en.wikipedia.org/wiki/Path-based_strong_component_algorithm)
+*   [Kosaraju's algorithm](https://en.wikipedia.org/wiki/Kosaraju%27s_algorithm)
+*   [Tarjan's algorithm](https://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm)
+*   [The path-based algorithm](https://en.wikipedia.org/wiki/Path-based_strong_component_algorithm)
 
 Kosaraju's algorithm is unsuited to DFS-generated graphs (such as type
 comparison graphs) as it requires both forwards and reverse edges to be known
@@ -67,10 +65,10 @@ classification:
 
 1.  never visited before - the node should immediately transition to open and
     known to the SCC finder
-1.  open - the link just followed would create a cycle and the SCC finder
+2.  open - the link just followed would create a cycle and the SCC finder
     algorithm needs to do some state maintenance; the user code must not
     recursively process the node
-1.  closed - the link just followed reaches a node already fully processed and
+3.  closed - the link just followed reaches a node already fully processed and
     assigned to a SCC; the user code must not recursively process the node
 
 There are at least 3 different ways of structuring program logic to distinguish
@@ -80,9 +78,9 @@ these paths.
 
 Node lifecycle:
 
-1. unvisited + not open
-1. visited + open
-1. visited + not open
+1.  unvisited + not open
+2.  visited + open
+3.  visited + not open
 
 If a node has never been visited, it can be unconditionally opened. If it has
 been visited, we must still check if it's open. This is a bit odd in the context
@@ -118,9 +116,9 @@ if (!nodes.empty()) {
 
 Node lifecycle:
 
-1. not open + unvisited (never visited)
-1. open (being visited)
-1. not open + visited (closed)
+1.  not open + unvisited (never visited)
+2.  open (being visited)
+3.  not open + visited (closed)
 
 This scheme also requires separate `is_open` and `really_open` operations as
 nodes musn't be reopened (-simplicity, -efficiency). It does allow the user to
@@ -151,9 +149,9 @@ NOTE: This is the currently implemented approach.
 
 Node lifecycle:
 
-1. unvisited + not open
-1. unvisited + open
-1. visited + not open
+1.  unvisited + not open
+2.  unvisited + open
+3.  visited + not open
 
 This is the purest form of the algorithm with the `open` and `close` operations
 clearly bracketing "real" work. `really_open` and `is_open` operations are
diff --git a/doc/stg.md b/doc/stg.md
index 2bc68b4..c314c9d 100644
--- a/doc/stg.md
+++ b/doc/stg.md
@@ -87,7 +87,7 @@ types with references to full definitions, if that would result in equal types.
 
 There are two types of filters that can be applied to STG output:
 
-1.  `-F|--files|--file-filter <filter>`
+*   `-F|--files|--file-filter <filter>`
 
     Filter type definitions by source location.
 
@@ -99,7 +99,7 @@ There are two types of filters that can be applied to STG output:
     File filters are only applicable to ELF binary objects containing DWARF with
     source location information; any other kind of input will be unaffected.
 
-1.  `-S|--symbols|--symbol-filter <filter>`
+*   `-S|--symbols|--symbol-filter <filter>`
 
     Filter ELF symbols by name (which may include a `@version` or `@@version`
     suffix).
@@ -125,8 +125,8 @@ Symbol filters:
 *   `jiffies |panic` - keep just the symbols `jiffies` and `panic`
 *   `str*` - keep symbols beginning with `str` such as `strncpy_from_user`
 *   `!(*@* & ! *@@*`) - drop versioned symbols that are not the default versions
-*   ` !*@*|*@@*` - the same
-*   `:include & !:exclude ` - keep symbols that are in the symbol list file
+*   `!*@*|*@@*` - the same
+*   `:include & !:exclude` - keep symbols that are in the symbol list file
     `include` but not in the symbol list file `exclude`
 
 File filters:
diff --git a/doc/stgdiff.md b/doc/stgdiff.md
index 7f0c33b..3dd31d5 100644
--- a/doc/stgdiff.md
+++ b/doc/stgdiff.md
@@ -16,7 +16,7 @@ stgdiff
   [{-f|--format} <output-format>] ...
   [{-o|--output} {filename|-}] ...
   [{-F|--fidelity} {filename|-}]
-implicit defaults: --abi --format plain
+implicit defaults: --abi --format small
 --exact (node equality) cannot be combined with --output
 output formats: plain flat small short viz
 ignore options: type_declaration_status symbol_type_presence primitive_type_encoding member_size enum_underlying_type qualifier linux_symbol_crc interface_addition type_definition_addition
@@ -106,9 +106,9 @@ in how much (DWARF) information they preserve.
 
 *   `linux_symbol_crc`
 
-    Ignore Linux kernel symbol CRC changes during comparison. This can be
-    useful for ABI comparisons across different toolchains, where CRC changes
-    are often large and not useful.
+    Ignore Linux kernel symbol CRC changes during comparison. This can be useful
+    for ABI comparisons across different toolchains, where CRC changes are often
+    large and not useful.
 
 These two options can be used for ABI compatibility testing where the first ABI
 is expected to be a subset of the second.
diff --git a/doc/tutorial.md b/doc/tutorial.md
new file mode 100644
index 0000000..4697d74
--- /dev/null
+++ b/doc/tutorial.md
@@ -0,0 +1,386 @@
+# Tutorial
+
+The simplest use for the STG tools is to extract, store and compare ABI
+representations.
+
+This tutorial uses long options throughout. Equivalent short options can be
+found in the manual pages for [`stg`](stg.md) and [`stgdiff`](stgdiff.md). Both
+tools understand `-` as a shorthand for `/dev/stdout`.
+
+<details>
+<summary>Working Example - code and compilation</summary>
+
+This small code sample will be used as a working example. Copy it into a file
+called `tree.c`.
+
+```c
+struct N {
+  struct N * left;
+  struct N * right;
+  int value;
+};
+
+unsigned int count(struct N * tree) {
+  return tree ? count(tree->left) + count(tree->right) + 1 : 0;
+}
+
+int sum(struct N * tree) {
+  return tree ? sum(tree->left) + sum(tree->right) + tree->value : 0;
+}
+```
+
+Compile it:
+
+```shell
+gcc -Wall -Wextra -g -c tree.c -o tree.o
+```
+
+</details>
+
+## Extraction from ELF / DWARF
+
+`stg` is the tool for extracting ABI representations, though it can do more
+sophisticated things as well. The simplest invocation of `stg` looks something
+like this:
+
+```shell
+stg --elf library.so --output library.stg
+```
+
+Adding the `--annotate` option can be useful, especially if trying to debug ABI
+issues or when experimenting with the tools, like now.
+
+If the output consists of just symbols and you get a warning about missing DWARF
+information, this means that `library.so` has no DWARF debugging information.
+For meaningful results, `stg` should be run on an *unstripped* ELF file which
+may require build system adjustments.
+
+<details>
+<summary>Working Example - ABI extraction</summary>
+
+Run this:
+
+```shell
+stg --elf tree.o --annotate --output -
+```
+
+And you should get something like this:
+
+<details>
+<summary>Output</summary>
+
+```proto
+version: 0x00000002
+root_id: 0x84ea5130  # interface
+pointer_reference {
+  id: 0x32b38621
+  kind: POINTER
+  pointee_type_id: 0xe08efe1a  # struct N
+}
+primitive {
+  id: 0x4585663f
+  name: "unsigned int"
+  encoding: UNSIGNED_INTEGER
+  bytesize: 0x00000004
+}
+primitive {
+  id: 0x6720d32f
+  name: "int"
+  encoding: SIGNED_INTEGER
+  bytesize: 0x00000004
+}
+member {
+  id: 0x35cbdb23
+  name: "left"
+  type_id: 0x32b38621  # struct N*
+}
+member {
+  id: 0x0b440ffb
+  name: "right"
+  type_id: 0x32b38621  # struct N*
+  offset: 64
+}
+member {
+  id: 0xa06f75d5
+  name: "value"
+  type_id: 0x6720d32f  # int
+  offset: 128
+}
+struct_union {
+  id: 0xe08efe1a
+  kind: STRUCT
+  name: "N"
+  definition {
+    bytesize: 24
+    member_id: 0x35cbdb23  # struct N* left
+    member_id: 0x0b440ffb  # struct N* right
+    member_id: 0xa06f75d5  # int value
+  }
+}
+function {
+  id: 0x912c02a7
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x32b38621  # struct N*
+}
+function {
+  id: 0xc2779f73
+  return_type_id: 0x4585663f  # unsigned int
+  parameter_id: 0x32b38621  # struct N*
+}
+elf_symbol {
+  id: 0xbb237197
+  name: "count"
+  is_defined: true
+  symbol_type: FUNCTION
+  type_id: 0xc2779f73  # unsigned int(struct N*)
+  full_name: "count"
+}
+elf_symbol {
+  id: 0x4fdeca38
+  name: "sum"
+  is_defined: true
+  symbol_type: FUNCTION
+  type_id: 0x912c02a7  # int(struct N*)
+  full_name: "sum"
+}
+interface {
+  id: 0x84ea5130
+  symbol_id: 0xbb237197  # unsigned int count(struct N*)
+  symbol_id: 0x4fdeca38  # int sum(struct N*)
+}
+```
+
+</details>
+
+</details>
+
+## Filtering
+
+One issue when first starting to manage the ABI of a binary is the wish to
+restrict the interface surface to just the necessary minimum. Any superfluous
+symbols or type definitions in the ABI representation can result in spurious ABI
+differences in reports later on.
+
+When it comes to the symbols exposed, it's common to control symbol
+*visibility*. Type definitions can be either exposed in public header files or
+hidden in private header files, with perhaps only public forward declarations,
+but this does not remove any type definitions in the DWARF information.
+
+STG provides filtering facilities for both symbols and types, for example:
+
+```shell
+stg --files '*.h' --elf library.so --output library.stg
+```
+
+This will ensure that definitions of any types defined outside any header files,
+and perhaps used as opaque pointer handles, are omitted from the ABI
+representation. If you separate public and private headers, then use an
+appropriate glob pattern that distinguishes the two.
+
+Sets of symbol or file names can be read from a file. In this example, all
+symbols whose names begin with `api_`, except those in the `obsolete` file, are
+kept.
+
+```shell
+stg --symbols 'api_* & ! :obsolete' --elf library.so --output library.stg
+```
+
+For historical reasons, the literal filter file format is compatible with
+libabigail's symbol list one, but this is subject to change.
+
+```ini
+[list]
+ # one symbol per line
+ foo # comments, whitespace and empty lines are all ignored
+ bar
+
+ baz
+```
+
+<details>
+<summary>Working Example - filtering the ABI</summary>
+
+Let's say that `struct N` is supposed to be an opaque type that user code only
+gets pointers to and, additionally, the function `count` should be excluded from
+the ABI (perhaps due to an argument over its return type). We can exclude the
+definition of `struct N`, along with that of any other types defined in
+`tree.c`, using a file filter. The symbol can be excluded by name.
+
+Run this:
+
+```shell
+stg --elf tree.o --files '*.h' --symbols '!count' --output -
+```
+
+The result should be something like this:
+
+<details>
+<summary>Output</summary>
+
+```proto
+version: 0x00000002
+root_id: 0x84ea5130
+pointer_reference {
+  id: 0x26944aa7
+  kind: POINTER
+  pointee_type_id: 0xb011cc02
+}
+primitive {
+  id: 0x6720d32f
+  name: "int"
+  encoding: SIGNED_INTEGER
+  bytesize: 0x00000004
+}
+struct_union {
+  id: 0xb011cc02
+  kind: STRUCT
+  name: "N"
+}
+function {
+  id: 0x9425f186
+  return_type_id: 0x6720d32f
+  parameter_id: 0x26944aa7
+}
+elf_symbol {
+  id: 0x4fdeca38
+  name: "sum"
+  is_defined: true
+  symbol_type: FUNCTION
+  type_id: 0x9425f186
+  full_name: "sum"
+}
+interface {
+  id: 0x84ea5130
+  symbol_id: 0x4fdeca38
+}
+```
+
+</details>
+
+</details>
+
+## ABI Comparison
+
+`stgdiff` is the tool for comparing ABI representations and reporting
+differences, though it has some other, more specialised, uses. The simplest
+invocation of `stgdiff` looks something like this:
+
+```shell
+stgdiff --stg old/library.stg new/library.stg --output -
+```
+
+This will report ABI differences in the default (`small`) format.
+
+<details>
+<summary>Working Example - ABI differences - small format</summary>
+
+The function `sum` has a type that depends on `struct N`. Any change to either
+might affect the ABI exposed via `sum`. For example, if the type of the `value`
+member is changed to `short` and the file is recompiled, STG can detect this
+difference.
+
+First rerun the STG extraction, specifying `--output tree-old.stg`. Make the
+source code change, recompile and extract the ABI with `--output tree-new.stg`.
+
+Then run this:
+
+```shell
+stgdiff --stg tree-old.stg tree-new.stg --output -
+```
+
+To get this:
+
+```text
+type 'struct N' changed
+  member changed from 'int value' to 'short int value'
+    type changed from 'int' to 'short int'
+
+```
+
+</details>
+
+The `small` format omits parts of the ABI graph which haven't changed.[^1] To
+see all impacted nodes, use `--format flat` instead.
+
+[^1]: The similarly named `short` format goes a bit further and will omit and
+    summarise certain repetitive differences.
+
+<details>
+<summary>Working Example - ABI differences - flat format</summary>
+
+```text
+function symbol 'int sum(struct N*)' changed
+  type 'int(struct N*)' changed
+    parameter 1 type 'struct N*' changed
+      pointed-to type 'struct N' changed
+
+type 'struct N' changed
+  member 'struct N* left' changed
+    type 'struct N*' changed
+      pointed-to type 'struct N' changed
+  member 'struct N* right' changed
+    type 'struct N*' changed
+      pointed-to type 'struct N' changed
+  member changed from 'int value' to 'short int value'
+    type changed from 'int' to 'short int'
+
+```
+
+</details>
+
+And if you really want to see more of the graph structure, use `--format plain`.
+
+<details>
+<summary>Working Example - ABI differences - plain format</summary>
+
+```text
+function symbol 'int sum(struct N*)' changed
+  type 'int(struct N*)' changed
+    parameter 1 type 'struct N*' changed
+      pointed-to type 'struct N' changed
+        member 'struct N* left' changed
+          type 'struct N*' changed
+            pointed-to type 'struct N' changed
+              (being reported)
+        member 'struct N* right' changed
+          type 'struct N*' changed
+            pointed-to type 'struct N' changed
+              (being reported)
+        member changed from 'int value' to 'short int value'
+          type changed from 'int' to 'short int'
+
+```
+
+</details>
+
+Or just use `--format viz` which generates input for
+[Graphviz](https://graphviz.org/).
+
+<details>
+<summary>Working Example - ABI differences - viz format</summary>
+
+```dot
+digraph "ABI diff" {
+  "0" [shape=rectangle, label="'interface'"]
+  "1" [label="'int sum(struct N*)'"]
+  "2" [label="'int(struct N*)'"]
+  "3" [label="'struct N*'"]
+  "4" [shape=rectangle, label="'struct N'"]
+  "5" [label="'struct N* left'"]
+  "5" -> "3" [label=""]
+  "4" -> "5" [label=""]
+  "6" [label="'struct N* right'"]
+  "6" -> "3" [label=""]
+  "4" -> "6" [label=""]
+  "7" [label="'int value' → 'short int value'"]
+  "8" [color=red, label="'int' → 'short int'"]
+  "7" -> "8" [label=""]
+  "4" -> "7" [label=""]
+  "3" -> "4" [label="pointed-to"]
+  "2" -> "3" [label="parameter 1"]
+  "1" -> "2" [label=""]
+  "0" -> "1" [label=""]
+}
+```
+
+</details>
diff --git a/dwarf_processor.cc b/dwarf_processor.cc
index beee31f..99ce18c 100644
--- a/dwarf_processor.cc
+++ b/dwarf_processor.cc
@@ -30,7 +30,6 @@
 #include <sstream>
 #include <string>
 #include <string_view>
-#include <unordered_map>
 #include <utility>
 #include <vector>
 
@@ -435,7 +434,7 @@ class Processor {
 
   void ProcessTypedef(Entry& entry) {
     const auto type_name = GetName(entry);
-    const auto full_name = scope_ + type_name;
+    const auto full_name = scope_.name + type_name;
     const Id referred_type_id = GetReferredTypeId(MaybeGetReferredType(entry));
     const Id id = AddProcessedNode<Typedef>(entry, full_name, referred_type_id);
     if (!ShouldKeepDefinition(entry, type_name)) {
@@ -486,7 +485,8 @@ class Processor {
 
   void ProcessStructUnion(Entry& entry, StructUnion::Kind kind) {
     const auto type_name = GetNameOrEmpty(entry);
-    const auto full_name = type_name.empty() ? type_name : scope_ + type_name;
+    const auto full_name =
+        type_name.empty() ? type_name : scope_.name + type_name;
     const PushScopeName push_scope_name(scope_, kind, type_name);
 
     std::vector<Id> base_classes;
@@ -714,7 +714,8 @@ class Processor {
 
   void ProcessEnum(Entry& entry) {
     const auto type_name = GetNameOrEmpty(entry);
-    const auto full_name = type_name.empty() ? type_name : scope_ + type_name;
+    const auto full_name =
+        type_name.empty() ? type_name : scope_.name + type_name;
 
     if (entry.GetFlag(DW_AT_declaration)) {
       // It is expected to have only name and no children in declaration.
@@ -855,7 +856,7 @@ class Processor {
       result.unscoped_name = std::string();
     }
     if (result.unscoped_name) {
-      result.scoped_name = scope_ + *result.unscoped_name;
+      result.scoped_name = scope_.name + *result.unscoped_name;
       scoped_names_.emplace_back(
           entry.GetOffset(), *result.scoped_name);
     }
@@ -1036,7 +1037,9 @@ class Processor {
   }
 
   void AddNamedTypeNode(Id id) {
-    result_.named_type_ids.push_back(id);
+    if (scope_.named) {
+      result_.named_type_ids.push_back(id);
+    }
   }
 
   Maker<Hex<Dwarf_Off>> maker_;
diff --git a/dwarf_processor.h b/dwarf_processor.h
index 7eaa8ed..93947a7 100644
--- a/dwarf_processor.h
+++ b/dwarf_processor.h
@@ -23,7 +23,7 @@
 #include <elfutils/libdw.h>
 
 #include <cstddef>
-#include <optional>
+#include <memory>
 #include <string>
 #include <vector>
 
diff --git a/dwarf_wrappers.cc b/dwarf_wrappers.cc
index 9924a43..8306a8f 100644
--- a/dwarf_wrappers.cc
+++ b/dwarf_wrappers.cc
@@ -20,10 +20,7 @@
 #include "dwarf_wrappers.h"
 
 #include <dwarf.h>
-#include <elf.h>
 #include <elfutils/libdw.h>
-#include <elfutils/libdwfl.h>
-#include <fcntl.h>
 
 #include <cstddef>
 #include <cstdint>
@@ -40,7 +37,12 @@ namespace stg {
 namespace dwarf {
 
 std::ostream& operator<<(std::ostream& os, const Address& address) {
-  return os << Hex(address.value) << (address.is_tls ? " (TLS)" : "");
+  switch (address.kind) {
+    case Address::Kind::ADDRESS:
+      return os << Hex(address.value);
+    case Address::Kind::TLS:
+      return os << "TLS:" << Hex(address.value);
+  }
 }
 
 namespace {
@@ -266,13 +268,21 @@ std::optional<Address> GetAddressFromLocation(Dwarf_Attribute& attribute) {
     uint64_t address;
     Check(dwarf_formaddr(&result_attribute, &address) == kReturnOk)
         << "dwarf_formaddr returned error";
-    return Address{.value = address, .is_tls = false};
+    return Address{Address::Kind::ADDRESS, address};
   }
+
   if (expression.length == 1 && expression[0].atom == DW_OP_addr) {
     // DW_OP_addr is unsupported by dwarf_getlocation_attr, so we need to
     // manually extract the address from expression.
-    return Address{.value = expression[0].number, .is_tls = false};
+    return Address{Address::Kind::ADDRESS, expression[0].number};
   }
+  if (expression.length == 2 && expression[0].atom == DW_OP_addr &&
+      expression[1].atom == DW_OP_plus_uconst) {
+    // A rather odd case seen from Clang.
+    return Address{Address::Kind::ADDRESS,
+                   expression[0].number + expression[1].number};
+  }
+
   // TLS operation has different encodings in Clang and GCC:
   // * Clang 14 uses DW_OP_GNU_push_tls_address
   // * GCC 12 uses DW_OP_form_tls_address
@@ -283,7 +293,7 @@ std::optional<Address> GetAddressFromLocation(Dwarf_Attribute& attribute) {
     // relocations. Resetting it to zero the same way as it is done in
     // elf::Reader::MaybeAddTypeInfo.
     // TODO: match TLS variables by address
-    return Address{.value = 0, .is_tls = true};
+    return Address{Address::Kind::TLS, 0};
   }
 
   Die() << "Unsupported data location expression";
@@ -300,11 +310,10 @@ std::optional<Address> Entry::MaybeGetAddress(uint32_t attribute) {
     return GetAddressFromLocation(*dwarf_attribute);
   }
 
-  Address address;
-  Check(dwarf_formaddr(&dwarf_attribute.value(), &address.value) == kReturnOk)
+  uint64_t address;
+  Check(dwarf_formaddr(&dwarf_attribute.value(), &address) == kReturnOk)
       << "dwarf_formaddr returned error";
-  address.is_tls = false;
-  return address;
+  return Address{Address::Kind::ADDRESS, address};
 }
 
 std::optional<uint64_t> Entry::MaybeGetMemberByteOffset() {
diff --git a/dwarf_wrappers.h b/dwarf_wrappers.h
index ad43413..cddd414 100644
--- a/dwarf_wrappers.h
+++ b/dwarf_wrappers.h
@@ -20,7 +20,6 @@
 #ifndef STG_DWARF_WRAPPERS_H_
 #define STG_DWARF_WRAPPERS_H_
 
-#include <elf.h>
 #include <elfutils/libdw.h>
 
 #include <cstddef>
@@ -34,10 +33,16 @@ namespace stg {
 namespace dwarf {
 
 struct Address {
+  // ADDRESS - relocated, section-relative offset
+  // TLS - broken (elfutils bug), TLS-relative offset
+  //       TODO: match TLS variables by address
+  enum class Kind { ADDRESS, TLS };
+
+  Address(Kind kind, uint64_t value) : kind(kind), value(value) {}
   auto operator<=>(const Address&) const = default;
 
+  Kind kind;
   uint64_t value;
-  bool is_tls;
 };
 
 std::ostream& operator<<(std::ostream& os, const Address& address);
diff --git a/elf_dwarf_handle.cc b/elf_dwarf_handle.cc
index b03ad06..5c5664f 100644
--- a/elf_dwarf_handle.cc
+++ b/elf_dwarf_handle.cc
@@ -21,7 +21,6 @@
 
 #include <elfutils/libdw.h>
 #include <elfutils/libdwfl.h>
-#include <fcntl.h>
 #include <gelf.h>
 #include <libelf.h>
 
diff --git a/elf_dwarf_handle.h b/elf_dwarf_handle.h
index cca4a0e..37face6 100644
--- a/elf_dwarf_handle.h
+++ b/elf_dwarf_handle.h
@@ -20,9 +20,9 @@
 #ifndef STG_ELF_DWARF_HANDLE_H_
 #define STG_ELF_DWARF_HANDLE_H_
 
-#include <elf.h>
 #include <elfutils/libdw.h>
 #include <elfutils/libdwfl.h>
+#include <libelf.h>
 
 #include <cstddef>
 #include <functional>
diff --git a/elf_loader.cc b/elf_loader.cc
index cad551d..cfa751a 100644
--- a/elf_loader.cc
+++ b/elf_loader.cc
@@ -26,13 +26,13 @@
 #include <libelf.h>
 
 #include <cstddef>
+#include <cstdint>
 #include <cstring>
 #include <functional>
 #include <limits>
 #include <ostream>
 #include <string>
 #include <string_view>
-#include <utility>
 #include <vector>
 
 #include "error.h"
@@ -507,6 +507,7 @@ std::string_view ElfLoader::GetElfSymbolNamespace(
       << "Namespace symbol address is above namespace section end";
 
   const char* begin = reinterpret_cast<const char*>(data->d_buf) + offset;
+  // TODO: replace strnlen with something in a standard library
   const size_t length = strnlen(begin, data->d_size - offset);
   Check(offset + length < data->d_size)
       << "Namespace string should be null-terminated";
diff --git a/elf_loader.h b/elf_loader.h
index 561e1dd..8eaf9bc 100644
--- a/elf_loader.h
+++ b/elf_loader.h
@@ -24,9 +24,7 @@
 
 #include <cstddef>
 #include <cstdint>
-#include <memory>
 #include <ostream>
-#include <string>
 #include <string_view>
 #include <vector>
 
diff --git a/elf_reader.cc b/elf_reader.cc
index b3def7f..9728ddd 100644
--- a/elf_reader.cc
+++ b/elf_reader.cc
@@ -29,6 +29,7 @@
 #include <vector>
 
 #include "dwarf_processor.h"
+#include "dwarf_wrappers.h"
 #include "elf_dwarf_handle.h"
 #include "elf_loader.h"
 #include "error.h"
@@ -334,15 +335,14 @@ class Reader {
       const SymbolIndex& address_name_to_index,
       const std::vector<dwarf::Types::Symbol>& dwarf_symbols,
       size_t address_value, ElfSymbol& node, Unification& unification) {
-    const bool is_tls = node.symbol_type == ElfSymbol::SymbolType::TLS;
-    if (is_tls) {
-      // TLS symbols address may be incorrect because of unsupported
-      // relocations. Resetting it to zero the same way as it is done in
-      // dwarf::Entry::GetAddressFromLocation.
-      // TODO: match TLS variables by address
-      address_value = 0;
-    }
-    const dwarf::Address address{.value = address_value, .is_tls = is_tls};
+    // TLS symbols address may be incorrect because of unsupported
+    // relocations. Resetting it to zero the same way as it is done in
+    // dwarf::Entry::GetAddressFromLocation.
+    // TODO: match TLS variables by address
+    const dwarf::Address address =
+        node.symbol_type == ElfSymbol::SymbolType::TLS
+            ? dwarf::Address{dwarf::Address::Kind::TLS, 0}
+            : dwarf::Address{dwarf::Address::Kind::ADDRESS, address_value};
     // try to find the first symbol with given address
     const auto start_it = address_name_to_index.lower_bound(
         std::make_pair(address, std::string()));
@@ -446,7 +446,7 @@ Id Reader::Read() {
   (this->*get_symbols)(all_symbols, symbols);
   symbols.shrink_to_fit();
 
-  Id root = BuildRoot(symbols);
+  const Id root = BuildRoot(symbols);
 
   // Types produced by ELF/DWARF readers may require removing useless
   // qualifiers.
diff --git a/elf_reader_test.cc b/elf_reader_test.cc
index 58d69dc..02ddb8b 100644
--- a/elf_reader_test.cc
+++ b/elf_reader_test.cc
@@ -22,7 +22,6 @@
 #include <catch2/catch.hpp>
 #include "elf_loader.h"
 #include "elf_reader.h"
-#include "graph.h"
 
 namespace Test {
 
diff --git a/equality.h b/equality.h
index 6f96bc1..e9c8fe0 100644
--- a/equality.h
+++ b/equality.h
@@ -59,7 +59,7 @@ struct Equals {
     }
     // Comparison opened, need to close it before returning.
 
-    const auto result = graph.Apply2<bool>(*this, id1, id2);
+    const auto result = graph.Apply2(*this, id1, id2);
 
     // Check for a complete Strongly-Connected Component.
     auto comparisons = scc.Close(*handle);
diff --git a/equality_cache.h b/equality_cache.h
index c1aa42b..138e0c1 100644
--- a/equality_cache.h
+++ b/equality_cache.h
@@ -21,10 +21,10 @@
 #define STG_EQUALITY_CACHE_H_
 
 #include <cstddef>
-#include <cstdint>
 #include <optional>
 #include <unordered_map>
 #include <unordered_set>
+#include <utility>
 #include <vector>
 
 #include "graph.h"
diff --git a/error.h b/error.h
index 4680cae..a88e345 100644
--- a/error.h
+++ b/error.h
@@ -26,6 +26,7 @@
 #include <ostream>
 #include <sstream>
 #include <string>
+#include <system_error>
 
 namespace stg {
 
diff --git a/fidelity.cc b/fidelity.cc
index 66ab9d2..1032f9a 100644
--- a/fidelity.cc
+++ b/fidelity.cc
@@ -70,7 +70,7 @@ struct Fidelity {
 
 void Fidelity::operator()(Id id) {
   if (seen.Insert(id)) {
-    graph.Apply<void>(*this, id, id);
+    graph.Apply(*this, id, id);
   }
 }
 
diff --git a/file_descriptor.cc b/file_descriptor.cc
index 8c4fc91..3f4117d 100644
--- a/file_descriptor.cc
+++ b/file_descriptor.cc
@@ -21,6 +21,7 @@
 #include "file_descriptor.h"
 
 #include <fcntl.h>
+#include <sys/types.h>
 #include <unistd.h>
 
 #include <cerrno>
diff --git a/file_descriptor_test.cc b/file_descriptor_test.cc
index 844d97a..b97fef9 100644
--- a/file_descriptor_test.cc
+++ b/file_descriptor_test.cc
@@ -29,12 +29,12 @@
 namespace Test {
 
 TEST_CASE("default construction") {
-  stg::FileDescriptor fd;
+  const stg::FileDescriptor fd;
   CHECK_THROWS(fd.Value());
 }
 
 TEST_CASE("successful open") {
-  stg::FileDescriptor fd("/dev/null", O_RDONLY);
+  const stg::FileDescriptor fd("/dev/null", O_RDONLY);
   CHECK(fd.Value());
 }
 
@@ -44,7 +44,7 @@ TEST_CASE("failed open") {
 
 TEST_CASE("double close") {
   CHECK_THROWS([]() {
-    stg::FileDescriptor fd("/dev/null", O_RDONLY);
+    const stg::FileDescriptor fd("/dev/null", O_RDONLY);
     close(fd.Value());
     CHECK_NOTHROW(fd.Value());  // value is still ok
   }());                         // throws on destruction
@@ -60,7 +60,7 @@ TEST_CASE("ownership transfer on move") {
   CHECK_THROWS(fd.Value());
   CHECK(fd_val == fd2.Value());
 
-  auto fd3(std::move(fd2));
+  const auto fd3(std::move(fd2));
   CHECK_THROWS(fd2.Value());
   CHECK(fd_val == fd3.Value());
 }
diff --git a/filter.cc b/filter.cc
index cff06b3..748f6ce 100644
--- a/filter.cc
+++ b/filter.cc
@@ -21,8 +21,8 @@
 
 #include <fnmatch.h>
 
-#include <array>
 #include <cctype>
+#include <cerrno>
 #include <cstddef>
 #include <cstring>
 #include <fstream>
diff --git a/fingerprint.cc b/fingerprint.cc
index 740e237..eca6e4c 100644
--- a/fingerprint.cc
+++ b/fingerprint.cc
@@ -186,7 +186,7 @@ struct Hasher {
     }
     // Comparison opened, need to close it before returning.
 
-    auto result = graph.Apply<HashValue>(*this, id);
+    auto result = graph.Apply(*this, id);
 
     // Check for a complete Strongly-Connected Component.
     auto ids = scc.Close(*handle);
diff --git a/fingerprint.h b/fingerprint.h
index 43fe694..f05d042 100644
--- a/fingerprint.h
+++ b/fingerprint.h
@@ -20,7 +20,6 @@
 #ifndef STG_FINGERPRINT_H_
 #define STG_FINGERPRINT_H_
 
-#include <cstdint>
 #include <unordered_map>
 
 #include "graph.h"
diff --git a/fuzz/abigail_reader_fuzzer.cc b/fuzz/abigail_reader_fuzzer.cc
index 09b6247..4b8cada 100644
--- a/fuzz/abigail_reader_fuzzer.cc
+++ b/fuzz/abigail_reader_fuzzer.cc
@@ -17,17 +17,22 @@
 //
 // Author: Matthias Maennich
 
-#include <string>
+#include <cstddef>
 
 #include <libxml/parser.h>
 #include <libxml/tree.h>
+#include <libxml/xmlerror.h>
 #include "abigail_reader.h"
 #include "error.h"
 #include "graph.h"
 
-static void DoNothing(void*, const char*, ...) {}
+namespace {
 
-extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
+void DoNothing(void*, const char*, ...) {}
+
+}  // namespace
+
+extern "C" int LLVMFuzzerTestOneInput(const char* data, size_t size) {
   xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
   // Suppress libxml error messages.
   xmlSetGenericErrorFunc(ctxt, (xmlGenericErrorFunc) DoNothing);
diff --git a/fuzz/btf_reader_fuzzer.cc b/fuzz/btf_reader_fuzzer.cc
index 4ce6de0..584869f 100644
--- a/fuzz/btf_reader_fuzzer.cc
+++ b/fuzz/btf_reader_fuzzer.cc
@@ -17,13 +17,14 @@
 //
 // Author: Matthias Maennich
 
+#include <cstddef>
 #include <string_view>
 
 #include "btf_reader.h"
 #include "error.h"
 #include "graph.h"
 
-extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
+extern "C" int LLVMFuzzerTestOneInput(const char* data, size_t size) {
   try {
     stg::Graph graph;
     stg::btf::ReadSection(graph, std::string_view(data, size));
diff --git a/fuzz/elf_reader_fuzzer.cc b/fuzz/elf_reader_fuzzer.cc
index ea9af18..b9096bc 100644
--- a/fuzz/elf_reader_fuzzer.cc
+++ b/fuzz/elf_reader_fuzzer.cc
@@ -18,6 +18,7 @@
 // Author: Matthias Maennich
 // Author: Aleksei Vetrov
 
+#include <cstddef>
 #include <sstream>
 #include <vector>
 
@@ -28,7 +29,7 @@
 #include "reader_options.h"
 #include "runtime.h"
 
-extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
+extern "C" int LLVMFuzzerTestOneInput(const char* data, size_t size) {
   try {
     // Fuzzer forbids changing "data", but libdwfl, used in elf::Read, requires
     // read and write access to memory.
diff --git a/fuzz/proto_reader_fuzzer.cc b/fuzz/proto_reader_fuzzer.cc
index 7a102e0..6e2a4e7 100644
--- a/fuzz/proto_reader_fuzzer.cc
+++ b/fuzz/proto_reader_fuzzer.cc
@@ -17,15 +17,16 @@
 //
 // Author: Matthias Maennich
 
+#include <cstddef>
 #include <sstream>
-#include <string>
+#include <string_view>
 
 #include "error.h"
 #include "graph.h"
 #include "proto_reader.h"
 #include "runtime.h"
 
-extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
+extern "C" int LLVMFuzzerTestOneInput(const char* data, size_t size) {
   try {
     std::ostringstream os;
     stg::Runtime runtime(os, false);
diff --git a/graph.cc b/graph.cc
index 6c5ca05..7572acc 100644
--- a/graph.cc
+++ b/graph.cc
@@ -21,7 +21,6 @@
 
 #include "graph.h"
 
-#include <ios>
 #include <limits>
 #include <ostream>
 #include <string>
diff --git a/graph.h b/graph.h
index 3a31540..673e3d0 100644
--- a/graph.h
+++ b/graph.h
@@ -22,9 +22,9 @@
 #ifndef STG_GRAPH_H_
 #define STG_GRAPH_H_
 
-#include <compare>
 #include <cstddef>
 #include <cstdint>
+#include <exception>
 #include <functional>
 #include <map>
 #include <optional>
@@ -438,17 +438,18 @@ class Graph {
     Deallocate(id);
   }
 
-  template <typename Result, typename FunctionObject, typename... Args>
-  Result Apply(FunctionObject& function, Id id, Args&&... args) const;
+  template <typename FunctionObject, typename... Args>
+  decltype(auto) Apply(FunctionObject&& function, Id id, Args&&... args) const;
 
-  template <typename Result, typename FunctionObject, typename... Args>
-  Result Apply2(FunctionObject& function, Id id1, Id id2, Args&&... args) const;
+  template <typename FunctionObject, typename... Args>
+  decltype(auto) Apply2(
+      FunctionObject&& function, Id id1, Id id2, Args&&... args) const;
 
-  template <typename Result, typename FunctionObject, typename... Args>
-  Result Apply(FunctionObject& function, Id id, Args&&... args);
+  template <typename FunctionObject, typename... Args>
+  decltype(auto) Apply(FunctionObject&& function, Id id, Args&&... args);
 
-  template <typename Function>
-  void ForEach(Id start, Id limit, Function&& function) const {
+  template <typename FunctionObject>
+  void ForEach(Id start, Id limit, FunctionObject&& function) const {
     for (size_t ix = start.ix_; ix < limit.ix_; ++ix) {
       const Id id(ix);
       if (Is(id)) {
@@ -500,8 +501,9 @@ class Graph {
   std::vector<Interface> interface_;
 };
 
-template <typename Result, typename FunctionObject, typename... Args>
-Result Graph::Apply(FunctionObject& function, Id id, Args&&... args) const {
+template <typename FunctionObject, typename... Args>
+decltype(auto) Graph::Apply(
+    FunctionObject&& function, Id id, Args&&... args) const {
   const auto& [which, ix] = indirection_[id.ix_];
   switch (which) {
     case Which::ABSENT:
@@ -543,9 +545,9 @@ Result Graph::Apply(FunctionObject& function, Id id, Args&&... args) const {
   }
 }
 
-template <typename Result, typename FunctionObject, typename... Args>
-Result Graph::Apply2(
-    FunctionObject& function, Id id1, Id id2, Args&&... args) const {
+template <typename FunctionObject, typename... Args>
+decltype(auto) Graph::Apply2(
+    FunctionObject&& function, Id id1, Id id2, Args&&... args) const {
   const auto& [which1, ix1] = indirection_[id1.ix_];
   const auto& [which2, ix2] = indirection_[id2.ix_];
   if (which1 != which2) {
@@ -608,20 +610,20 @@ Result Graph::Apply2(
   }
 }
 
-template <typename Result, typename FunctionObject, typename... Args>
+template <typename FunctionObject, typename... Args>
 struct ConstAdapter {
   explicit ConstAdapter(FunctionObject& function) : function(function) {}
   template <typename Node>
-  Result operator()(const Node& node, Args&&... args) {
+  decltype(auto) operator()(const Node& node, Args&&... args) {
     return function(const_cast<Node&>(node), std::forward<Args>(args)...);
   }
   FunctionObject& function;
 };
 
-template <typename Result, typename FunctionObject, typename... Args>
-Result Graph::Apply(FunctionObject& function, Id id, Args&&... args) {
-  ConstAdapter<Result, FunctionObject, Args&&...> adapter(function);
-  return static_cast<const Graph&>(*this).Apply<Result>(
+template <typename FunctionObject, typename... Args>
+decltype(auto) Graph::Apply(FunctionObject&& function, Id id, Args&&... args) {
+  ConstAdapter<FunctionObject, Args&&...> adapter(function);
+  return static_cast<const Graph&>(*this).Apply(
       adapter, id, std::forward<Args>(args)...);
 }
 
@@ -629,7 +631,7 @@ struct InterfaceKey {
   explicit InterfaceKey(const Graph& graph) : graph(graph) {}
 
   std::string operator()(Id id) const {
-    return graph.Apply<std::string>(*this, id);
+    return graph.Apply(*this, id);
   }
 
   std::string operator()(const stg::Typedef& x) const {
diff --git a/hashing.h b/hashing.h
index 71fef1e..41efeba 100644
--- a/hashing.h
+++ b/hashing.h
@@ -21,7 +21,6 @@
 #ifndef STG_HASHING_H_
 #define STG_HASHING_H_
 
-#include <compare>
 #include <cstddef>
 #include <cstdint>
 #include <functional>
diff --git a/naming.cc b/naming.cc
index ab1507a..4041b0f 100644
--- a/naming.cc
+++ b/naming.cc
@@ -104,205 +104,241 @@ std::ostream& operator<<(std::ostream& os, const Name& name) {
   return name.Print(os);
 }
 
-Name Describe::operator()(Id id) {
-  // infinite recursion prevention - insert at most once
-  static const Name black_hole{"#"};
-  auto insertion = names.insert({id, black_hole});
-  Name& cached = insertion.first->second;
-  if (insertion.second) {
-    cached = graph.Apply<Name>(*this, id);
+namespace {
+
+struct DescribeWorker {
+  DescribeWorker(const Graph& graph, NameCache& names)
+      : graph(graph), names(names) {}
+
+  Name operator()(Id id) {
+    // infinite recursion prevention - insert at most once
+    static const Name black_hole{"#"};
+    auto insertion = names.insert({id, black_hole});
+    Name& cached = insertion.first->second;
+    if (insertion.second) {
+      cached = graph.Apply(*this, id);
+    }
+    return cached;
   }
-  return cached;
-}
 
-Name Describe::operator()(const Special& x) {
-  switch (x.kind) {
-    case Special::Kind::VOID:
-      return Name{"void"};
-    case Special::Kind::VARIADIC:
-      return Name{"..."};
-    case Special::Kind::NULLPTR:
-      return Name{"decltype(nullptr)"};
+  Name operator()(const Special& x) {
+    switch (x.kind) {
+      case Special::Kind::VOID:
+        return Name{"void"};
+      case Special::Kind::VARIADIC:
+        return Name{"..."};
+      case Special::Kind::NULLPTR:
+        return Name{"decltype(nullptr)"};
+    }
   }
-}
 
-Name Describe::operator()(const PointerReference& x) {
-  std::string sign;
-  switch (x.kind) {
-    case PointerReference::Kind::POINTER:
-      sign = "*";
-      break;
-    case PointerReference::Kind::LVALUE_REFERENCE:
-      sign = "&";
-      break;
-    case PointerReference::Kind::RVALUE_REFERENCE:
-      sign = "&&";
-      break;
+  Name operator()(const PointerReference& x) {
+    std::string sign;
+    switch (x.kind) {
+      case PointerReference::Kind::POINTER:
+        sign = "*";
+        break;
+      case PointerReference::Kind::LVALUE_REFERENCE:
+        sign = "&";
+        break;
+      case PointerReference::Kind::RVALUE_REFERENCE:
+        sign = "&&";
+        break;
+    }
+    return (*this)(x.pointee_type_id)
+            .Add(Side::LEFT, Precedence::POINTER, sign);
   }
-  return (*this)(x.pointee_type_id)
-          .Add(Side::LEFT, Precedence::POINTER, sign);
-}
-
-Name Describe::operator()(const PointerToMember& x) {
-  std::ostringstream os;
-  os << (*this)(x.containing_type_id) << "::*";
-  return (*this)(x.pointee_type_id).Add(Side::LEFT, Precedence::POINTER,
-                                        os.str());
-}
 
-Name Describe::operator()(const Typedef& x) {
-  return Name{x.name};
-}
+  Name operator()(const PointerToMember& x) {
+    std::ostringstream os;
+    os << (*this)(x.containing_type_id) << "::*";
+    return (*this)(x.pointee_type_id).Add(Side::LEFT, Precedence::POINTER,
+                                          os.str());
+  }
 
-Name Describe::operator()(const Qualified& x) {
-  return (*this)(x.qualified_type_id).Qualify(x.qualifier);
-}
+  Name operator()(const Typedef& x) {
+    return Name{x.name};
+  }
 
-Name Describe::operator()(const Primitive& x) {
-  return Name{x.name};
-}
+  Name operator()(const Qualified& x) {
+    return (*this)(x.qualified_type_id).Qualify(x.qualifier);
+  }
 
-Name Describe::operator()(const Array& x) {
-  std::ostringstream os;
-  os << '[' << x.number_of_elements << ']';
-  return (*this)(x.element_type_id)
-          .Add(Side::RIGHT, Precedence::ARRAY_FUNCTION, os.str());
-}
+  Name operator()(const Primitive& x) {
+    return Name{x.name};
+  }
 
-Name Describe::operator()(const BaseClass& x) {
-  return (*this)(x.type_id);
-}
+  Name operator()(const Array& x) {
+    std::ostringstream os;
+    os << '[' << x.number_of_elements << ']';
+    return (*this)(x.element_type_id)
+            .Add(Side::RIGHT, Precedence::ARRAY_FUNCTION, os.str());
+  }
 
-Name Describe::operator()(const Method& x) {
-  return (*this)(x.type_id).Add(Side::LEFT, Precedence::ATOMIC, x.name);
-}
+  Name operator()(const BaseClass& x) {
+    return (*this)(x.type_id);
+  }
 
-Name Describe::operator()(const Member& x) {
-  auto description = (*this)(x.type_id);
-  if (!x.name.empty()) {
-    description = description.Add(Side::LEFT, Precedence::ATOMIC, x.name);
+  Name operator()(const Method& x) {
+    return (*this)(x.type_id).Add(Side::LEFT, Precedence::ATOMIC, x.name);
   }
-  if (x.bitsize) {
-    description = description.Add(
-        Side::RIGHT, Precedence::ATOMIC, ':' + std::to_string(x.bitsize));
+
+  Name operator()(const Member& x) {
+    auto description = (*this)(x.type_id);
+    if (!x.name.empty()) {
+      description = description.Add(Side::LEFT, Precedence::ATOMIC, x.name);
+    }
+    if (x.bitsize) {
+      description = description.Add(
+          Side::RIGHT, Precedence::ATOMIC, ':' + std::to_string(x.bitsize));
+    }
+    return description;
   }
-  return description;
-}
 
-Name Describe::operator()(const VariantMember& x) {
-  auto description = (*this)(x.type_id);
-  description = description.Add(Side::LEFT, Precedence::ATOMIC, x.name);
-  return description;
-}
+  Name operator()(const VariantMember& x) {
+    auto description = (*this)(x.type_id);
+    description = description.Add(Side::LEFT, Precedence::ATOMIC, x.name);
+    return description;
+  }
 
-Name Describe::operator()(const StructUnion& x) {
-  std::ostringstream os;
-  os << x.kind << ' ';
-  if (!x.name.empty()) {
-    os << x.name;
-  } else if (x.definition) {
-    os << "{ ";
-    for (const auto& member : x.definition->members) {
-      os << (*this)(member) << "; ";
+  Name operator()(const StructUnion& x) {
+    std::ostringstream os;
+    os << x.kind;
+    if (!x.name.empty()) {
+      os << ' ' << x.name;
+    } else if (x.definition) {
+      os << " { ";
+      for (const auto& member : x.definition->members) {
+        os << (*this)(member) << "; ";
+      }
+      os << '}';
     }
-    os << '}';
+    return Name{os.str()};
   }
-  return Name{os.str()};
-}
 
-Name Describe::operator()(const Enumeration& x) {
-  std::ostringstream os;
-  os << "enum ";
-  if (!x.name.empty()) {
-    os << x.name;
-  } else if (x.definition) {
-    os << "{ ";
-    for (const auto& e : x.definition->enumerators) {
-      os << e.first << " = " << e.second << ", ";
+  Name operator()(const Enumeration& x) {
+    std::ostringstream os;
+    os << "enum";
+    if (!x.name.empty()) {
+      os << ' ' << x.name;
+    } else if (x.definition) {
+      os << " { ";
+      for (const auto& e : x.definition->enumerators) {
+        os << e.first << " = " << e.second << ", ";
+      }
+      os << '}';
     }
-    os << '}';
+    return Name{os.str()};
   }
-  return Name{os.str()};
-}
 
-Name Describe::operator()(const Variant& x) {
-  std::ostringstream os;
-  os << "variant " << x.name;
-  return Name{os.str()};
-}
+  Name operator()(const Variant& x) {
+    std::ostringstream os;
+    os << "variant " << x.name;
+    return Name{os.str()};
+  }
 
-Name Describe::operator()(const Function& x) {
-  std::ostringstream os;
-  os << '(';
-  bool sep = false;
-  for (const Id p : x.parameters) {
-    if (sep) {
-      os << ", ";
-    } else {
-      sep = true;
+  Name operator()(const Function& x) {
+    std::ostringstream os;
+    os << '(';
+    bool sep = false;
+    for (const Id p : x.parameters) {
+      if (sep) {
+        os << ", ";
+      } else {
+        sep = true;
+      }
+      os << (*this)(p);
     }
-    os << (*this)(p);
+    os << ')';
+    return (*this)(x.return_type_id)
+            .Add(Side::RIGHT, Precedence::ARRAY_FUNCTION, os.str());
   }
-  os << ')';
-  return (*this)(x.return_type_id)
-          .Add(Side::RIGHT, Precedence::ARRAY_FUNCTION, os.str());
-}
 
-Name Describe::operator()(const ElfSymbol& x) {
-  const auto& name = x.full_name ? *x.full_name : x.symbol_name;
-  return x.type_id
-      ? (*this)(*x.type_id).Add(Side::LEFT, Precedence::ATOMIC, name)
-      : Name{name};
-}
+  Name operator()(const ElfSymbol& x) {
+    const auto& name = x.full_name ? *x.full_name : x.symbol_name;
+    return x.type_id
+        ? (*this)(*x.type_id).Add(Side::LEFT, Precedence::ATOMIC, name)
+        : Name{name};
+  }
 
-Name Describe::operator()(const Interface&) {
-  return Name{"interface"};
-}
+  Name operator()(const Interface&) {
+    return Name{"interface"};
+  }
 
-std::string DescribeKind::operator()(Id id) {
-  return graph.Apply<std::string>(*this, id);
-}
+  const Graph& graph;
+  NameCache& names;
+};
 
-std::string DescribeKind::operator()(const BaseClass&) {
-  return "base class";
-}
+struct DescribeKindWorker {
+  explicit DescribeKindWorker(const Graph& graph) : graph(graph) {}
 
-std::string DescribeKind::operator()(const Method&) {
-  return "method";
-}
+  std::string operator()(Id id) {
+    return graph.Apply(*this, id);
+  }
 
-std::string DescribeKind::operator()(const Member&) {
-  return "member";
-}
+  std::string operator()(const BaseClass&) {
+    return "base class";
+  }
 
-std::string DescribeKind::operator()(const ElfSymbol& x) {
-  std::ostringstream os;
-  os << x.symbol_type << " symbol";
-  return os.str();
-}
+  std::string operator()(const Method&) {
+    return "method";
+  }
 
-std::string DescribeKind::operator()(const Interface&) {
-  return "interface";
-}
+  std::string operator()(const Member&) {
+    return "member";
+  }
 
-template <typename Node>
-std::string DescribeKind::operator()(const Node&) {
-  return "type";
-}
+  std::string operator()(const ElfSymbol& x) {
+    std::ostringstream os;
+    os << x.symbol_type << " symbol";
+    return os.str();
+  }
 
-std::string DescribeExtra::operator()(Id id) {
-  return graph.Apply<std::string>(*this, id);
+  std::string operator()(const Interface&) {
+    return "interface";
+  }
+
+  template <typename Node>
+      std::string operator()(const Node&) {
+    return "type";
+  }
+
+  const Graph& graph;
+};
+
+struct DescribeExtraWorker {
+  explicit DescribeExtraWorker(const Graph& graph) : graph(graph) {}
+
+  std::string operator()(Id id) {
+    return graph.Apply(*this, id);
+  }
+
+  std::string operator()(const ElfSymbol& x) {
+    const auto& name = x.full_name ? *x.full_name : x.symbol_name;
+    auto versioned = VersionedSymbolName(x);
+    return name == versioned ? std::string() : " {" + versioned + '}';
+  }
+
+  template <typename Node>
+      std::string operator()(const Node&) {
+    return {};
+  }
+
+  const Graph& graph;
+};
+
+}  // namespace
+
+Name Describe::operator()(Id id) {
+  return DescribeWorker(graph, names)(id);
 }
 
-std::string DescribeExtra::operator()(const ElfSymbol& x) {
-  const auto& name = x.full_name ? *x.full_name : x.symbol_name;
-  auto versioned = VersionedSymbolName(x);
-  return name == versioned ? std::string() : " {" + versioned + '}';
+std::string DescribeKind::operator()(Id id) {
+  return DescribeKindWorker(graph)(id);
 }
 
-template <typename Node>
-std::string DescribeExtra::operator()(const Node&) {
-  return {};
+std::string DescribeExtra::operator()(Id id) {
+  return DescribeExtraWorker(graph)(id);
 }
 
 }  // namespace stg
diff --git a/naming.h b/naming.h
index 87496b3..b8b1aee 100644
--- a/naming.h
+++ b/naming.h
@@ -29,7 +29,7 @@
 
 namespace stg {
 
-// See NAMES.md for conceptual documentation.
+// See naming.md for conceptual documentation.
 
 enum class Precedence { NIL, POINTER, ARRAY_FUNCTION, ATOMIC };
 enum class Side { LEFT, RIGHT };
@@ -58,23 +58,6 @@ using NameCache = std::unordered_map<Id, Name>;
 struct Describe {
   Describe(const Graph& graph, NameCache& names) : graph(graph), names(names) {}
   Name operator()(Id id);
-  Name operator()(const Special&);
-  Name operator()(const PointerReference&);
-  Name operator()(const PointerToMember&);
-  Name operator()(const Typedef&);
-  Name operator()(const Qualified&);
-  Name operator()(const Primitive&);
-  Name operator()(const Array&);
-  Name operator()(const BaseClass&);
-  Name operator()(const Method&);
-  Name operator()(const Member&);
-  Name operator()(const VariantMember&);
-  Name operator()(const StructUnion&);
-  Name operator()(const Enumeration&);
-  Name operator()(const Variant&);
-  Name operator()(const Function&);
-  Name operator()(const ElfSymbol&);
-  Name operator()(const Interface&);
   const Graph& graph;
   NameCache& names;
 };
@@ -82,22 +65,12 @@ struct Describe {
 struct DescribeKind {
   explicit DescribeKind(const Graph& graph) : graph(graph) {}
   std::string operator()(Id id);
-  std::string operator()(const BaseClass&);
-  std::string operator()(const Method&);
-  std::string operator()(const Member&);
-  std::string operator()(const ElfSymbol&);
-  std::string operator()(const Interface&);
-  template <typename Node>
-  std::string operator()(const Node&);
   const Graph& graph;
 };
 
 struct DescribeExtra {
   explicit DescribeExtra(const Graph& graph) : graph(graph) {}
   std::string operator()(Id id);
-  std::string operator()(const ElfSymbol&);
-  template <typename Node>
-  std::string operator()(const Node&);
   const Graph& graph;
 };
 
diff --git a/order.h b/order.h
index c60ab56..ab1dce0 100644
--- a/order.h
+++ b/order.h
@@ -135,8 +135,8 @@ void Permute(std::vector<T>& data, std::vector<size_t>& permutation) {
 //
 // Each pair gives 1 or 2 abstract positions for the corresponding data item.
 //
-// The first and second positions are interpreted separately, with the first's
-// implied ordering having precedence in the event of a conflict.
+// The first and second positions are interpreted separately, with the second
+// implied ordering having precedence over the first in the event of a conflict.
 //
 // The real work is done by CombineOrders and Permute.
 //
diff --git a/order_test.cc b/order_test.cc
index b14fe62..ee367bf 100644
--- a/order_test.cc
+++ b/order_test.cc
@@ -60,7 +60,7 @@ std::vector<size_t> MakePermutation(size_t k, G& gen) {
   for (size_t i = 0; i < k; ++i) {
     // pick one of [i, k)
     std::uniform_int_distribution<size_t> toss(i, k - 1);
-    auto pick = toss(gen);
+    const auto pick = toss(gen);
     using std::swap;
     swap(result[i], result[pick]);
   }
@@ -208,7 +208,7 @@ TEST_CASE("hand-curated ordering sequences") {
   // NOTES:
   //   The output sequence MUST include the second sequence as a subsequence.
   //   The first sequence's ordering is respected as far as possible.
-  std::vector<std::tuple<Sequence, Sequence, Sequence>> cases = {
+  const std::vector<std::tuple<Sequence, Sequence, Sequence>> cases = {
     {{"rose", "george", "emily"}, {"george", "ted", "emily"},
       {"rose", "george", "ted", "emily"}},
     {{}, {}, {}},
@@ -236,7 +236,7 @@ TEST_CASE("hand-curated reorderings with input order randomisation") {
   //   item added at position y: {}, {y}
   //   item modified at positions x and y: {x}, {y}
   //   input item order should be irrelevant to output order
-  std::vector<std::pair<Constraints, Constraints>> cases = {
+  const std::vector<std::pair<Constraints, Constraints>> cases = {
     {
       {
         {{2}, {2}},  // emily
diff --git a/post_processing.cc b/post_processing.cc
index aec1b24..ccb0b79 100644
--- a/post_processing.cc
+++ b/post_processing.cc
@@ -21,6 +21,7 @@
 
 #include <algorithm>
 #include <cstddef>
+#include <cstdint>
 #include <iostream>
 #include <map>
 #include <ostream>
@@ -33,6 +34,8 @@
 
 namespace stg {
 
+namespace {
+
 std::vector<std::string> SummariseCRCChanges(
     const std::vector<std::string>& report, size_t limit) {
   const std::regex symbol_changed_re("^.* symbol .* changed$");
@@ -190,12 +193,61 @@ std::vector<std::string> GroupRemovedAddedSymbols(
   return new_report;
 }
 
-std::vector<std::string> PostProcess(const std::vector<std::string>& report,
-                                     size_t max_crc_only_changes) {
+std::vector<std::string> SummariseEnumeratorAdditionsAndRemovals(
+    const std::vector<std::string>& report, size_t limit) {
+  const std::regex re("^( *)enumerator (.*) was (added|removed)$");
+
+  std::vector<std::string> new_report;
+  size_t indent = 0;
+  std::string which;
+  std::vector<std::string> pending;
+
+  auto emit_pending = [&]() {
+    for (size_t ix = 0; ix < std::min(pending.size(), limit); ++ix) {
+      new_report.push_back(pending[ix]);
+    }
+    if (pending.size() > limit) {
+      std::ostringstream os;
+      os << std::string(indent, ' ') << "... " << pending.size() - limit
+         << " other enumerator(s) " << which;
+      new_report.push_back(os.str());
+    }
+    pending.clear();
+  };
+
+  for (const auto& line : report) {
+    std::smatch match;
+    if (std::regex_match(line, match, re)) {
+      const size_t new_indent = match[1].length();
+      const std::string new_which = match[3].str();
+      if (new_indent != indent || new_which != which) {
+        emit_pending();
+        indent = new_indent;
+        which = new_which;
+      }
+      pending.push_back(line);
+    } else {
+      emit_pending();
+      new_report.push_back(line);
+    }
+  }
+
+  emit_pending();
+  return new_report;
+}
+
+}  // namespace
+
+std::vector<std::string> PostProcess(const std::vector<std::string>& report) {
   std::vector<std::string> new_report;
-  new_report = SummariseCRCChanges(report, max_crc_only_changes);
+  // limit the mentions of symbols with only CRC changes
+  new_report = SummariseCRCChanges(report, 3);
+  // collect together function / object symbol additions / removals
   new_report = GroupRemovedAddedSymbols(new_report);
+  // collapse runs of identical member offset changes
   new_report = SummariseOffsetChanges(new_report);
+  // limit the mentions of consecutive enumerator additions / removals
+  new_report = SummariseEnumeratorAdditionsAndRemovals(new_report, 1);
   return new_report;
 }
 
diff --git a/post_processing.h b/post_processing.h
index b964e30..94421dd 100644
--- a/post_processing.h
+++ b/post_processing.h
@@ -20,14 +20,12 @@
 #ifndef STG_POST_PROCESSING_H_
 #define STG_POST_PROCESSING_H_
 
-#include <cstddef>
 #include <string>
 #include <vector>
 
 namespace stg {
 
-std::vector<std::string> PostProcess(const std::vector<std::string>& report,
-                                     size_t max_crc_only_changes);
+std::vector<std::string> PostProcess(const std::vector<std::string>& report);
 
 }  // namespace stg
 
diff --git a/proto_writer.cc b/proto_writer.cc
index 915981f..663b4e6 100644
--- a/proto_writer.cc
+++ b/proto_writer.cc
@@ -26,7 +26,6 @@
 #include <ios>
 #include <ostream>
 #include <sstream>
-#include <string>
 #include <tuple>
 #include <unordered_map>
 #include <unordered_set>
@@ -123,7 +122,7 @@ uint32_t Transform<MapId>::operator()(Id id) {
       ++mapped_id;
     }
     it->second = mapped_id;
-    graph.Apply<void>(*this, id, mapped_id);
+    graph.Apply(*this, id, mapped_id);
   }
   return it->second;
 }
@@ -562,7 +561,7 @@ const uint32_t kWrittenFormatVersion = 2;
 // This collection is used to register the AnnotationHexPrinter for each of the
 // fields, which will print a description of the node in STG to which the edge
 // points.
-const std::array<const google::protobuf::FieldDescriptor*, 18> edge_descriptors = {
+const std::array<const google::protobuf::FieldDescriptor*, 19> edge_descriptors = {
     PointerReference::descriptor()->FindFieldByNumber(3),
     PointerToMember::descriptor()->FindFieldByNumber(3),
     Typedef::descriptor()->FindFieldByNumber(3),
@@ -571,6 +570,7 @@ const std::array<const google::protobuf::FieldDescriptor*, 18> edge_descriptors
     BaseClass::descriptor()->FindFieldByNumber(2),
     Method::descriptor()->FindFieldByNumber(5),
     Member::descriptor()->FindFieldByNumber(3),
+    VariantMember::descriptor()->FindFieldByNumber(4),
     StructUnion::Definition::descriptor()->FindFieldByNumber(2),
     StructUnion::Definition::descriptor()->FindFieldByNumber(3),
     StructUnion::Definition::descriptor()->FindFieldByNumber(4),
diff --git a/reporting.cc b/reporting.cc
index 66bd998..bf4195b 100644
--- a/reporting.cc
+++ b/reporting.cc
@@ -38,17 +38,20 @@
 #include "error.h"
 #include "fidelity.h"
 #include "graph.h"
+#include "naming.h"
 #include "post_processing.h"
 
 namespace stg {
 namespace reporting {
 
+namespace {
+
 struct FormatDescriptor {
   std::string_view name;
   OutputFormat value;
 };
 
-static constexpr std::array<FormatDescriptor, 5> kFormats{{
+constexpr std::array<FormatDescriptor, 5> kFormats{{
   {"plain", OutputFormat::PLAIN},
   {"flat",  OutputFormat::FLAT },
   {"small", OutputFormat::SMALL},
@@ -56,6 +59,8 @@ static constexpr std::array<FormatDescriptor, 5> kFormats{{
   {"viz",   OutputFormat::VIZ  },
 }};
 
+}  // namespace
+
 std::optional<OutputFormat> ParseOutputFormat(std::string_view format) {
   for (const auto& [name, value] : kFormats) {
     if (name == format) {
@@ -135,7 +140,7 @@ bool PrintComparison(const Reporting& reporting,
   return false;
 }
 
-static constexpr size_t INDENT_INCREMENT = 2;
+constexpr size_t INDENT_INCREMENT = 2;
 
 class Plain {
   // unvisited (absent) -> started (false) -> finished (true)
@@ -184,10 +189,10 @@ void Plain::Print(const diff::Comparison& comparison, size_t indent,
   }
 
   for (const auto& detail : diff.details) {
-    if (!detail.edge_) {
-      output_ << std::string(indent, ' ') << detail.text_ << '\n';
+    if (detail.edge == diff::Comparison{}) {
+      output_ << std::string(indent, ' ') << detail.text << '\n';
     } else {
-      Print(*detail.edge_, indent, detail.text_);
+      Print(detail.edge, indent, detail.text);
     }
   }
 
@@ -200,7 +205,7 @@ void Plain::Report(const diff::Comparison& comparison) {
   // unpack then print - want symbol diff forest rather than symbols diff tree
   const auto& diff = reporting_.outcomes.at(comparison);
   for (const auto& detail : diff.details) {
-    Print(*detail.edge_, 0, {});
+    Print(detail.edge, 0, {});
     // paragraph spacing
     output_ << '\n';
   }
@@ -261,8 +266,8 @@ bool Flat::Print(const diff::Comparison& comparison, bool stop,
   indent += INDENT_INCREMENT;
   bool interesting = diff.has_changes;
   for (const auto& detail : diff.details) {
-    if (!detail.edge_) {
-      os << std::string(indent, ' ') << detail.text_ << '\n';
+    if (detail.edge == diff::Comparison{}) {
+      os << std::string(indent, ' ') << detail.text << '\n';
       // Node changes may not be interesting, if we allow non-change diff
       // details at some point. Just trust the has_changes flag.
     } else {
@@ -270,7 +275,7 @@ bool Flat::Print(const diff::Comparison& comparison, bool stop,
       std::ostringstream sub_os;
       // Set the stop flag to prevent recursion past diff-holding nodes.
       const bool sub_interesting =
-          Print(*detail.edge_, true, sub_os, indent, detail.text_);
+          Print(detail.edge, true, sub_os, indent, detail.text);
       // If the sub-tree was interesting, add it.
       if (sub_interesting || full_) {
         os << sub_os.str();
@@ -287,7 +292,7 @@ void Flat::Report(const diff::Comparison& comparison) {
   const auto& diff = reporting_.outcomes.at(comparison);
   for (const auto& detail : diff.details) {
     std::ostringstream os;
-    const bool interesting = Print(*detail.edge_, true, os, 0, {});
+    const bool interesting = Print(detail.edge, true, os, 0, {});
     if (interesting || full_) {
       output_ << os.str() << '\n';
     }
@@ -355,22 +360,22 @@ void VizPrint(
        << description1 << "\"]\n";
   } else {
     os << "  \"" << node << "\" [" << colour << shape << "label=\""
-       << description1 << " -> " << description2 << "\"]\n";
+       << description1 << " → " << description2 << "\"]\n";
   }
 
   size_t index = 0;
   for (const auto& detail : diff.details) {
-    if (!detail.edge_) {
+    if (detail.edge == diff::Comparison{}) {
       // attribute change, create an implicit edge and node
       os << "  \"" << node << "\" -> \"" << node << ':' << index << "\"\n"
          << "  \"" << node << ':' << index << "\" [color=red, label=\""
-         << detail.text_ << "\"]\n";
+         << detail.text << "\"]\n";
       ++index;
     } else {
-      const auto& to = *detail.edge_;
+      const auto& to = detail.edge;
       VizPrint(reporting, to, seen, ids, os);
       os << "  \"" << node << "\" -> \"" << VizId(ids, to) << "\" [label=\""
-         << detail.text_ << "\"]\n";
+         << detail.text << "\"]\n";
     }
   }
 }
@@ -418,8 +423,7 @@ void Report(const Reporting& reporting, const diff::Comparison& comparison,
       while (std::getline(report, line)) {
         report_lines.push_back(line);
       }
-      report_lines = stg::PostProcess(report_lines,
-                                      reporting.options.max_crc_only_changes);
+      report_lines = stg::PostProcess(report_lines);
       for (const auto& line : report_lines) {
         output << line << '\n';
       }
diff --git a/reporting.h b/reporting.h
index 04c3b98..929aec6 100644
--- a/reporting.h
+++ b/reporting.h
@@ -20,7 +20,6 @@
 #ifndef STG_REPORTING_H_
 #define STG_REPORTING_H_
 
-#include <cstddef>
 #include <optional>
 #include <ostream>
 #include <string_view>
@@ -42,7 +41,6 @@ std::ostream& operator<<(std::ostream&, OutputFormatUsage);
 
 struct Options {
   const OutputFormat format;
-  const size_t max_crc_only_changes;  // only for SHORT
 };
 
 struct Reporting {
diff --git a/reporting_test.cc b/reporting_test.cc
index f41db1b..e15a300 100644
--- a/reporting_test.cc
+++ b/reporting_test.cc
@@ -35,7 +35,7 @@ std::string filename_to_path(const std::string& f) {
 }
 
 TEST_CASE("fidelity diff") {
-  stg::FidelityDiff diff = {
+  const stg::FidelityDiff diff = {
       .symbol_transitions =
           {
               {{SymbolFidelity::TYPED, SymbolFidelity::UNTYPED},
@@ -66,7 +66,8 @@ TEST_CASE("fidelity diff") {
   std::ostringstream report;
   CHECK(reporting::FidelityDiff(diff, report));
 
-  std::ifstream expected_report_file(filename_to_path("fidelity_diff_report"));
+  const std::ifstream expected_report_file(
+      filename_to_path("fidelity_diff_report"));
   std::ostringstream expected_report;
   expected_report << expected_report_file.rdbuf();
   CHECK(report.str() == expected_report.str());
diff --git a/runtime.cc b/runtime.cc
index 025f87c..78f6291 100644
--- a/runtime.cc
+++ b/runtime.cc
@@ -19,9 +19,9 @@
 
 #include "runtime.h"
 
-#include <cstddef>
+#include <time.h>
+
 #include <iomanip>
-#include <map>
 #include <ostream>
 
 namespace stg {
diff --git a/scc.h b/scc.h
index 3199a53..374c982 100644
--- a/scc.h
+++ b/scc.h
@@ -22,6 +22,7 @@
 
 #include <cstddef>
 #include <exception>
+#include <functional>
 #include <iterator>
 #include <optional>
 #include <unordered_map>
@@ -62,6 +63,8 @@ namespace stg {
  *
  * USAGE
  *
+ * Create an SCC finder with a lifetime bracketing a top-level DFS invocation.
+ *
  * Before examining a node, check it's not been assigned to an SCC already and
  * then call Open. If the node is already "open" (i.e., is already waiting to be
  * assigned to an SCC), this will return an empty optional value and the node
@@ -78,8 +81,8 @@ namespace stg {
  * the nodes as visited), this should be done now. Otherwise, an empty vector
  * will be returned.
  *
- * After a top-level DFS has completed, the SCC finder should be carrying no
- * state. This can be verified by calling Empty.
+ * On destruction, after a top-level DFS invocation has completed, the SCC
+ * finder will check that it is carrying no state.
  */
 template <typename Node, typename Hash = std::hash<Node>>
 class SCC {
diff --git a/scc_test.cc b/scc_test.cc
index 47f5de8..09a26c9 100644
--- a/scc_test.cc
+++ b/scc_test.cc
@@ -184,14 +184,14 @@ TEST_CASE("randomly-generated graphs") {
   //   Graphs of size 6 are plenty big enough to shake out bugs.
   //   There are O(2^k^2) possible directed graphs of size k.
   //   Testing costs are O(k^3) so we restrict accordingly.
-  uint64_t budget = 10000;
+  const uint64_t budget = 10000;
   for (size_t k = 0; k < 7; ++k) {
-    uint64_t count = std::min(static_cast<uint64_t>(1) << (k * k),
-                              budget / (k ? k * k * k : 1));
+    const uint64_t count = std::min(static_cast<uint64_t>(1) << (k * k),
+                                    budget / (k ? k * k * k : 1));
     INFO("testing with " << count << " graphs of size " << k);
     for (uint64_t n = 0; n < count; ++n, ++seed) {
       gen.seed(seed);
-      Graph g = invent(k, gen);
+      const Graph g = invent(k, gen);
       std::ostringstream os;
       os << "a graph of " << k << " nodes generated using seed " << seed;
       GIVEN(os.str()) {
diff --git a/scope.h b/scope.h
index e02e76e..627daac 100644
--- a/scope.h
+++ b/scope.h
@@ -1,7 +1,7 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 // -*- mode: C++ -*-
 //
-// Copyright 2022-2023 Google LLC
+// Copyright 2022-2024 Google LLC
 //
 // Licensed under the Apache License v2.0 with LLVM Exceptions (the
 // "License"); you may not use this file except in compliance with the
@@ -26,32 +26,39 @@
 
 namespace stg {
 
-using Scope = std::string;
+struct Scope {
+  std::string name;
+  bool named = true;
+};
 
 class PushScopeName {
  public:
   template <typename Kind>
-  PushScopeName(Scope& scope_, Kind&& kind, const std::string& name)
-      : scope_name_(scope_), old_size_(scope_name_.size()) {
+  PushScopeName(Scope& scope, Kind&& kind, const std::string& name)
+      : scope_(scope), old_size_(scope_.name.size()),
+        old_named_(scope_.named) {
     if (name.empty()) {
-      scope_name_ += "<unnamed ";
-      scope_name_ += kind;
-      scope_name_ += ">::";
+      scope_.name += "<unnamed ";
+      scope_.name += kind;
+      scope_.name += ">::";
+      scope_.named = false;
     } else {
-      scope_name_ += name;
-      scope_name_ += "::";
+      scope_.name += name;
+      scope_.name += "::";
     }
   }
 
   PushScopeName(const PushScopeName& other) = delete;
   PushScopeName& operator=(const PushScopeName& other) = delete;
   ~PushScopeName() {
-    scope_name_.resize(old_size_);
+    scope_.name.resize(old_size_);
+    scope_.named = old_named_;
   }
 
  private:
-  std::string& scope_name_;
+  Scope& scope_;
   const size_t old_size_;
+  const bool old_named_;
 };
 
 }  // namespace stg
diff --git a/scope_test.cc b/scope_test.cc
new file mode 100644
index 0000000..c860c99
--- /dev/null
+++ b/scope_test.cc
@@ -0,0 +1,58 @@
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+// -*- mode: C++ -*-
+//
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License v2.0 with LLVM Exceptions (the
+// "License"); you may not use this file except in compliance with the
+// License.  You may obtain a copy of the License at
+//
+//     https://llvm.org/LICENSE.txt
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+// Author: Giuliano Procida
+
+#include "scope.h"
+
+#include <string>
+
+#include <catch2/catch.hpp>
+
+namespace Test {
+
+using stg::Scope;
+using stg::PushScopeName;
+
+TEST_CASE("scope") {
+  Scope scope;
+  CHECK(scope.name.empty());
+  CHECK(scope.named);
+  {
+    const PushScopeName p1(scope, "1", "A");
+    CHECK(!scope.name.empty());
+    CHECK(scope.named);
+    {
+      const PushScopeName p2 (scope, "2", std::string());
+      CHECK(!scope.name.empty());
+      CHECK(!scope.named);
+      {
+        const PushScopeName p3(scope, "3", "B");
+        CHECK(!scope.name.empty());
+        CHECK(!scope.named);
+      }
+      CHECK(!scope.name.empty());
+      CHECK(!scope.named);
+    }
+    CHECK(!scope.name.empty());
+    CHECK(scope.named);
+  }
+  CHECK(scope.name.empty());
+  CHECK(scope.named);
+}
+
+}  // namespace Test
diff --git a/stable_hash.cc b/stable_hash.cc
index 5982072..17f5891 100644
--- a/stable_hash.cc
+++ b/stable_hash.cc
@@ -19,10 +19,9 @@
 
 #include "stable_hash.h"
 
-#include <algorithm>
 #include <cstdint>
-#include <sstream>
 #include <string>
+#include <unordered_map>
 #include <utility>
 #include <vector>
 
@@ -58,132 +57,146 @@ HashValue DecayHashCombineInReverse(const std::vector<Type>& hashables,
   return result;
 }
 
-}  // namespace
+struct StableHashWorker {
+  StableHashWorker(const Graph& graph, std::unordered_map<Id, HashValue>& cache)
+      : graph(graph), cache(cache) {}
 
-HashValue StableHash::operator()(Id id) {
-  auto [it, inserted] = cache_.emplace(id, 0);
-  if (inserted) {
-    it->second = graph_.Apply<HashValue>(*this, id);
+  HashValue operator()(Id id) {
+    auto [it, inserted] = cache.emplace(id, 0);
+    if (inserted) {
+      it->second = graph.Apply(*this, id);
+    }
+    return it->second;
   }
-  return it->second;
-}
 
-HashValue StableHash::operator()(const Special& x) {
-  switch (x.kind) {
-    case Special::Kind::VOID:
-      return hash_("void");
-    case Special::Kind::VARIADIC:
-      return hash_("variadic");
-    case Special::Kind::NULLPTR:
-      return hash_("nullptr");
+  HashValue operator()(const Special& x) {
+    switch (x.kind) {
+      case Special::Kind::VOID:
+        return hash("void");
+      case Special::Kind::VARIADIC:
+        return hash("variadic");
+      case Special::Kind::NULLPTR:
+        return hash("nullptr");
+    }
   }
-}
 
-HashValue StableHash::operator()(const PointerReference& x) {
-  return DecayHashCombine<2>(hash_('r', static_cast<uint32_t>(x.kind)),
-                             (*this)(x.pointee_type_id));
-}
-
-HashValue StableHash::operator()(const PointerToMember& x) {
-  return DecayHashCombine<16>(hash_('n', (*this)(x.containing_type_id)),
-                              (*this)(x.pointee_type_id));
-}
+  HashValue operator()(const PointerReference& x) {
+    return DecayHashCombine<2>(hash('r', static_cast<uint32_t>(x.kind)),
+                               (*this)(x.pointee_type_id));
+  }
 
-HashValue StableHash::operator()(const Typedef& x) {
-  return hash_('t', x.name);
-}
+  HashValue operator()(const PointerToMember& x) {
+    return DecayHashCombine<16>(hash('n', (*this)(x.containing_type_id)),
+                                (*this)(x.pointee_type_id));
+  }
 
-HashValue StableHash::operator()(const Qualified& x) {
-  return DecayHashCombine<2>(hash_('q', static_cast<uint32_t>(x.qualifier)),
-                             (*this)(x.qualified_type_id));
-}
+  HashValue operator()(const Typedef& x) {
+    return hash('t', x.name);
+  }
 
-HashValue StableHash::operator()(const Primitive& x) {
-  return hash_('p', x.name);
-}
+  HashValue operator()(const Qualified& x) {
+    return DecayHashCombine<2>(hash('q', static_cast<uint32_t>(x.qualifier)),
+                               (*this)(x.qualified_type_id));
+  }
 
-HashValue StableHash::operator()(const Array& x) {
-  return DecayHashCombine<2>(hash_('a', x.number_of_elements),
-                             (*this)(x.element_type_id));
-}
+  HashValue operator()(const Primitive& x) {
+    return hash('p', x.name);
+  }
 
-HashValue StableHash::operator()(const BaseClass& x) {
-  return DecayHashCombine<2>(hash_('b', static_cast<uint32_t>(x.inheritance)),
-                             (*this)(x.type_id));
-}
+  HashValue operator()(const Array& x) {
+    return DecayHashCombine<2>(hash('a', x.number_of_elements),
+                               (*this)(x.element_type_id));
+  }
 
-HashValue StableHash::operator()(const Method& x) {
-  return hash_(x.mangled_name);
-}
+  HashValue operator()(const BaseClass& x) {
+    return DecayHashCombine<2>(hash('b', static_cast<uint32_t>(x.inheritance)),
+                               (*this)(x.type_id));
+  }
 
-HashValue StableHash::operator()(const Member& x) {
-  HashValue hash = hash_('m', x.name, x.bitsize);
-  hash = DecayHashCombine<20>(hash, hash_(x.offset));
-  if (x.name.empty()) {
-    return DecayHashCombine<2>(hash, (*this)(x.type_id));
-  } else {
-    return DecayHashCombine<8>(hash, (*this)(x.type_id));
+  HashValue operator()(const Method& x) {
+    return hash(x.mangled_name);
   }
-}
 
-HashValue StableHash::operator()(const VariantMember& x) {
-  HashValue hash = hash_('v', x.name);
-  hash = DecayHashCombine<8>(hash, (*this)(x.type_id));
-  return x.discriminant_value
-             ? DecayHashCombine<20>(hash, hash_(*x.discriminant_value))
-             : hash;
-}
+  HashValue operator()(const Member& x) {
+    HashValue value = hash('m', x.name, x.bitsize);
+    value = DecayHashCombine<20>(value, hash(x.offset));
+    if (x.name.empty()) {
+      return DecayHashCombine<2>(value, (*this)(x.type_id));
+    } else {
+      return DecayHashCombine<8>(value, (*this)(x.type_id));
+    }
+  }
 
-HashValue StableHash::operator()(const StructUnion& x) {
-  HashValue hash = hash_('S', static_cast<uint32_t>(x.kind), x.name,
-                         static_cast<bool>(x.definition));
-  if (!x.name.empty() || !x.definition) {
-    return hash;
+  HashValue operator()(const VariantMember& x) {
+    HashValue value = hash('v', x.name);
+    value = DecayHashCombine<8>(value, (*this)(x.type_id));
+    return x.discriminant_value
+        ? DecayHashCombine<20>(value, hash(*x.discriminant_value))
+        : value;
   }
 
-  auto h1 = DecayHashCombineInReverse<8>(x.definition->methods, *this);
-  auto h2 = DecayHashCombineInReverse<8>(x.definition->members, *this);
-  return DecayHashCombine<2>(hash, HashValue(h1.value ^ h2.value));
-}
+  HashValue operator()(const StructUnion& x) {
+    HashValue value = hash('S', static_cast<uint32_t>(x.kind), x.name,
+                           static_cast<bool>(x.definition));
+    if (!x.name.empty() || !x.definition) {
+      return value;
+    }
 
-HashValue StableHash::operator()(const Enumeration& x) {
-  HashValue hash = hash_('e', x.name, static_cast<bool>(x.definition));
-  if (!x.name.empty() || !x.definition) {
-    return hash;
+    auto h1 = DecayHashCombineInReverse<8>(x.definition->methods, *this);
+    auto h2 = DecayHashCombineInReverse<8>(x.definition->members, *this);
+    return DecayHashCombine<2>(value, HashValue(h1.value ^ h2.value));
   }
 
-  auto hash_enum = [this](const std::pair<std::string, int64_t>& e) {
-    return hash_(e.first, e.second);
-  };
-  return DecayHashCombine<2>(
-      hash, DecayHashCombineInReverse<8>(x.definition->enumerators, hash_enum));
-}
+  HashValue operator()(const Enumeration& x) {
+    HashValue value = hash('e', x.name, static_cast<bool>(x.definition));
+    if (!x.name.empty() || !x.definition) {
+      return value;
+    }
+
+    auto hash_enum = [this](const std::pair<std::string, int64_t>& e) {
+      return hash(e.first, e.second);
+    };
+    return DecayHashCombine<2>(value, DecayHashCombineInReverse<8>(
+        x.definition->enumerators, hash_enum));
+  }
 
-HashValue StableHash::operator()(const Variant& x) {
-  HashValue hash = hash_('V', x.name, x.bytesize);
-  if (x.discriminant.has_value()) {
-    hash = DecayHashCombine<12>(hash, (*this)(x.discriminant.value()));
+  HashValue operator()(const Variant& x) {
+    HashValue value = hash('V', x.name, x.bytesize);
+    if (x.discriminant.has_value()) {
+      value = DecayHashCombine<12>(value, (*this)(x.discriminant.value()));
+    }
+    return DecayHashCombine<2>(value,
+                               DecayHashCombineInReverse<8>(x.members, *this));
   }
-  return DecayHashCombine<2>(hash,
-                             DecayHashCombineInReverse<8>(x.members, *this));
-}
 
-HashValue StableHash::operator()(const Function& x) {
-  return DecayHashCombine<2>(hash_('f', (*this)(x.return_type_id)),
-                             DecayHashCombineInReverse<4>(x.parameters, *this));
-}
+  HashValue operator()(const Function& x) {
+    return DecayHashCombine<2>(
+        hash('f', (*this)(x.return_type_id)),
+        DecayHashCombineInReverse<4>(x.parameters, *this));
+  }
 
-HashValue StableHash::operator()(const ElfSymbol& x) {
-  HashValue hash = hash_('s', x.symbol_name);
-  if (x.version_info) {
-    hash = DecayHashCombine<16>(
-        hash, hash_(x.version_info->name, x.version_info->is_default));
+  HashValue operator()(const ElfSymbol& x) {
+    HashValue value = hash('s', x.symbol_name);
+    if (x.version_info) {
+      value = DecayHashCombine<16>(
+          value, hash(x.version_info->name, x.version_info->is_default));
+    }
+    return value;
+  }
+
+  HashValue operator()(const Interface&) {
+    return hash("interface");
   }
-  return hash;
-}
 
-HashValue StableHash::operator()(const Interface&) {
-  return hash_("interface");
+  const Hash hash;
+  const Graph& graph;
+  std::unordered_map<Id, HashValue>& cache;
+};
+
+}  // namespace
+
+HashValue StableHash::operator()(Id id) {
+  return StableHashWorker(graph_, cache_)(id);
 }
 
 }  // namespace stg
diff --git a/stable_hash.h b/stable_hash.h
index b0b9265..6935f76 100644
--- a/stable_hash.h
+++ b/stable_hash.h
@@ -20,10 +20,7 @@
 #ifndef STG_STABLE_HASH_H_
 #define STG_STABLE_HASH_H_
 
-#include <cstdint>
-#include <iostream>
 #include <unordered_map>
-#include <vector>
 
 #include "graph.h"
 #include "hashing.h"
@@ -33,32 +30,11 @@ namespace stg {
 class StableHash {
  public:
   explicit StableHash(const Graph& graph) : graph_(graph) {}
-
   HashValue operator()(Id);
-  HashValue operator()(const Special&);
-  HashValue operator()(const PointerReference&);
-  HashValue operator()(const PointerToMember&);
-  HashValue operator()(const Typedef&);
-  HashValue operator()(const Qualified&);
-  HashValue operator()(const Primitive&);
-  HashValue operator()(const Array&);
-  HashValue operator()(const BaseClass&);
-  HashValue operator()(const Method&);
-  HashValue operator()(const Member&);
-  HashValue operator()(const VariantMember&);
-  HashValue operator()(const StructUnion&);
-  HashValue operator()(const Enumeration&);
-  HashValue operator()(const Variant&);
-  HashValue operator()(const Function&);
-  HashValue operator()(const ElfSymbol&);
-  HashValue operator()(const Interface&);
 
  private:
   const Graph& graph_;
   std::unordered_map<Id, HashValue> cache_;
-
-  // Function object: (Args...) -> HashValue
-  Hash hash_;
 };
 
 }  // namespace stg
diff --git a/stg.cc b/stg.cc
index e9a6b8e..5c6675f 100644
--- a/stg.cc
+++ b/stg.cc
@@ -19,6 +19,7 @@
 
 #include <fcntl.h>
 #include <getopt.h>
+#include <sys/stat.h>
 
 #include <cstring>
 #include <iostream>
@@ -65,7 +66,7 @@ Id Merge(Runtime& runtime, Graph& graph, const std::vector<Id>& roots) {
   std::map<std::string, Id> types;
   const GetInterface get;
   for (auto root : roots) {
-    const auto& interface = graph.Apply<Interface&>(get, root);
+    const auto& interface = graph.Apply(get, root);
     for (const auto& x : interface.symbols) {
       if (!symbols.insert(x).second) {
         Warn() << "duplicate symbol during merge: " << x.first;
@@ -91,7 +92,7 @@ Id Merge(Runtime& runtime, Graph& graph, const std::vector<Id>& roots) {
 void FilterSymbols(Graph& graph, Id root, const Filter& filter) {
   std::map<std::string, Id> symbols;
   GetInterface get;
-  auto& interface = graph.Apply<Interface&>(get, root);
+  auto& interface = graph.Apply(get, root);
   for (const auto& x : interface.symbols) {
     if (filter(x.first)) {
       symbols.insert(x);
diff --git a/stgdiff.cc b/stgdiff.cc
index d737767..f0c0b5b 100644
--- a/stgdiff.cc
+++ b/stgdiff.cc
@@ -21,7 +21,6 @@
 
 #include <getopt.h>
 
-#include <cstddef>
 #include <cstring>
 #include <fstream>
 #include <iostream>
@@ -46,7 +45,6 @@ namespace {
 
 const int kAbiChange = 4;
 const int kFidelityChange = 8;
-const size_t kMaxCrcOnlyChanges = 3;
 
 using Inputs = std::vector<std::pair<stg::InputFormat, const char*>>;
 using Outputs =
@@ -104,25 +102,26 @@ int Run(stg::Runtime& runtime, const stg::Graph& graph,
         const std::vector<stg::Id>& roots, const Outputs& outputs,
         stg::diff::Ignore ignore, std::optional<const char*> fidelity) {
   // Compute differences.
-  stg::diff::Compare compare{runtime, graph, ignore};
-  std::pair<bool, std::optional<stg::diff::Comparison>> result;
+  stg::diff::Outcomes outcomes;
+  stg::diff::Comparison comparison;
   {
     const stg::Time compute(runtime, "compute diffs");
-    result = compare(roots[0], roots[1]);
+    comparison = stg::diff::Compare(
+        runtime, ignore, graph, roots[0], roots[1], outcomes);
   }
-  const auto& [equals, comparison] = result;
-  int status = equals ? 0 : kAbiChange;
+  const bool same = comparison == stg::diff::Comparison{};
+  int status = same ? 0 : kAbiChange;
 
   // Write reports.
   stg::NameCache names;
   for (const auto& [format, filename] : outputs) {
     std::ofstream output(filename);
-    if (comparison) {
+    if (!same) {
       const stg::Time report(runtime, "report diffs");
-      const stg::reporting::Options options{format, kMaxCrcOnlyChanges};
-      const stg::reporting::Reporting reporting{graph, compare.outcomes,
-        options, names};
-      Report(reporting, *comparison, output);
+      const stg::reporting::Options options{format};
+      const stg::reporting::Reporting reporting{graph, outcomes, options,
+        names};
+      Report(reporting, comparison, output);
       output << std::flush;
     }
     if (!output) {
@@ -150,7 +149,7 @@ int main(int argc, char* argv[]) {
   stg::diff::Ignore opt_ignore;
   stg::InputFormat opt_input_format = stg::InputFormat::ABI;
   stg::reporting::OutputFormat opt_output_format =
-      stg::reporting::OutputFormat::PLAIN;
+      stg::reporting::OutputFormat::SMALL;
   Inputs inputs;
   Outputs outputs;
   static option opts[] = {
@@ -178,7 +177,7 @@ int main(int argc, char* argv[]) {
               << "  [{-f|--format} <output-format>] ...\n"
               << "  [{-o|--output} {filename|-}] ...\n"
               << "  [{-F|--fidelity} {filename|-}]\n"
-              << "implicit defaults: --abi --format plain\n"
+              << "implicit defaults: --abi --format small\n"
               << "--exact (node equality) cannot be combined with --output\n"
               << stg::reporting::OutputFormatUsage()
               << stg::diff::IgnoreUsage();
diff --git a/stgdiff_test.cc b/stgdiff_test.cc
index b0f82cc..0adcf96 100644
--- a/stgdiff_test.cc
+++ b/stgdiff_test.cc
@@ -24,245 +24,250 @@
 
 #include <catch2/catch.hpp>
 #include "comparison.h"
+#include "fidelity.h"
 #include "graph.h"
 #include "input.h"
+#include "naming.h"
 #include "reader_options.h"
 #include "reporting.h"
 #include "runtime.h"
 
+namespace stg {
 namespace {
 
 struct IgnoreTestCase {
   const std::string name;
-  const stg::InputFormat format0;
+  const InputFormat format0;
   const std::string file0;
-  const stg::InputFormat format1;
+  const InputFormat format1;
   const std::string file1;
-  const stg::diff::Ignore ignore;
+  const diff::Ignore ignore;
   const std::string expected_output;
-  const bool expected_equals;
+  const bool expected_same;
 };
 
 std::string filename_to_path(const std::string& f) {
   return std::filesystem::path("testdata") / f;
 }
 
-stg::Id Read(stg::Runtime& runtime, stg::Graph& graph, stg::InputFormat format,
-             const std::string& input) {
-  return stg::Read(runtime, graph, format, filename_to_path(input).c_str(),
-                   stg::ReadOptions(), nullptr);
+Id Read(Runtime& runtime, Graph& graph, InputFormat format,
+        const std::string& input) {
+  return Read(runtime, graph, format, filename_to_path(input).c_str(),
+              ReadOptions(), nullptr);
 }
 
 TEST_CASE("ignore") {
   const auto test = GENERATE(
       IgnoreTestCase(
           {"symbol type presence change",
-           stg::InputFormat::ABI,
+           InputFormat::ABI,
            "symbol_type_presence_0.xml",
-           stg::InputFormat::ABI,
+           InputFormat::ABI,
            "symbol_type_presence_1.xml",
-           stg::diff::Ignore(),
+           diff::Ignore(),
            "symbol_type_presence_small_diff",
            false}),
       IgnoreTestCase(
           {"symbol type presence change pruned",
-           stg::InputFormat::ABI,
+           InputFormat::ABI,
            "symbol_type_presence_0.xml",
-           stg::InputFormat::ABI,
+           InputFormat::ABI,
            "symbol_type_presence_1.xml",
-           stg::diff::Ignore(stg::diff::Ignore::SYMBOL_TYPE_PRESENCE),
+           diff::Ignore(diff::Ignore::SYMBOL_TYPE_PRESENCE),
            "empty",
            true}),
       IgnoreTestCase(
           {"type declaration status change",
-           stg::InputFormat::ABI,
+           InputFormat::ABI,
            "type_declaration_status_0.xml",
-           stg::InputFormat::ABI,
+           InputFormat::ABI,
            "type_declaration_status_1.xml",
-           stg::diff::Ignore(),
+           diff::Ignore(),
            "type_declaration_status_small_diff",
            false}),
       IgnoreTestCase(
           {"type declaration status change pruned",
-           stg::InputFormat::ABI,
+           InputFormat::ABI,
            "type_declaration_status_0.xml",
-           stg::InputFormat::ABI,
+           InputFormat::ABI,
            "type_declaration_status_1.xml",
-           stg::diff::Ignore(stg::diff::Ignore::TYPE_DECLARATION_STATUS),
+           diff::Ignore(diff::Ignore::TYPE_DECLARATION_STATUS),
            "empty",
            true}),
       IgnoreTestCase(
           {"primitive type encoding",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "primitive_type_encoding_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "primitive_type_encoding_1.stg",
-           stg::diff::Ignore(),
+           diff::Ignore(),
            "primitive_type_encoding_small_diff",
            false}),
       IgnoreTestCase(
           {"primitive type encoding ignored",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "primitive_type_encoding_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "primitive_type_encoding_1.stg",
-           stg::diff::Ignore(stg::diff::Ignore::PRIMITIVE_TYPE_ENCODING),
+           diff::Ignore(diff::Ignore::PRIMITIVE_TYPE_ENCODING),
            "empty",
            true}),
       IgnoreTestCase(
           {"member size",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "member_size_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "member_size_1.stg",
-           stg::diff::Ignore(),
+           diff::Ignore(),
            "member_size_small_diff",
            false}),
       IgnoreTestCase(
           {"member size ignored",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "member_size_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "member_size_1.stg",
-           stg::diff::Ignore(stg::diff::Ignore::MEMBER_SIZE),
+           diff::Ignore(diff::Ignore::MEMBER_SIZE),
            "empty",
            true}),
       IgnoreTestCase(
           {"enum underlying type",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "enum_underlying_type_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "enum_underlying_type_1.stg",
-           stg::diff::Ignore(),
+           diff::Ignore(),
            "enum_underlying_type_small_diff",
            false}),
       IgnoreTestCase(
           {"enum underlying type ignored",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "enum_underlying_type_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "enum_underlying_type_1.stg",
-           stg::diff::Ignore(stg::diff::Ignore::ENUM_UNDERLYING_TYPE),
+           diff::Ignore(diff::Ignore::ENUM_UNDERLYING_TYPE),
            "empty",
            true}),
       IgnoreTestCase(
           {"qualifier",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "qualifier_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "qualifier_1.stg",
-           stg::diff::Ignore(),
+           diff::Ignore(),
            "qualifier_small_diff",
            false}),
       IgnoreTestCase(
           {"qualifier ignored",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "qualifier_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "qualifier_1.stg",
-           stg::diff::Ignore(stg::diff::Ignore::QUALIFIER),
+           diff::Ignore(diff::Ignore::QUALIFIER),
            "empty",
            true}),
       IgnoreTestCase(
           {"CRC change",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "crc_change_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "crc_change_1.stg",
-           stg::diff::Ignore(),
+           diff::Ignore(),
            "crc_change_small_diff",
            false}),
       IgnoreTestCase(
           {"CRC change ignored",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "crc_change_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "crc_change_1.stg",
-           stg::diff::Ignore(stg::diff::Ignore::SYMBOL_CRC),
+           diff::Ignore(diff::Ignore::SYMBOL_CRC),
            "empty",
            true}),
       IgnoreTestCase(
           {"interface addition",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "interface_addition_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "interface_addition_1.stg",
-           stg::diff::Ignore(),
+           diff::Ignore(),
            "interface_addition_small_diff",
            false}),
       IgnoreTestCase(
           {"interface addition ignored",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "interface_addition_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "interface_addition_1.stg",
-           stg::diff::Ignore(stg::diff::Ignore::INTERFACE_ADDITION),
+           diff::Ignore(diff::Ignore::INTERFACE_ADDITION),
            "empty",
            true}),
       IgnoreTestCase(
           {"type addition",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "type_addition_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "type_addition_1.stg",
-           stg::diff::Ignore(),
+           diff::Ignore(),
            "type_addition_small_diff",
            false}),
       IgnoreTestCase(
           {"type addition ignored",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "type_addition_0.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "type_addition_1.stg",
-           stg::diff::Ignore(stg::diff::Ignore::INTERFACE_ADDITION),
+           diff::Ignore(diff::Ignore::INTERFACE_ADDITION),
            "empty",
            true}),
       IgnoreTestCase(
           {"type definition addition",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "type_addition_1.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "type_addition_2.stg",
-           stg::diff::Ignore(),
+           diff::Ignore(),
            "type_definition_addition_small_diff",
            false}),
       IgnoreTestCase(
           {"type definition addition ignored",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "type_addition_1.stg",
-           stg::InputFormat::STG,
+           InputFormat::STG,
            "type_addition_2.stg",
-           stg::diff::Ignore(stg::diff::Ignore::TYPE_DEFINITION_ADDITION),
+           diff::Ignore(diff::Ignore::TYPE_DEFINITION_ADDITION),
            "empty",
            true})
       );
 
   SECTION(test.name) {
     std::ostringstream os;
-    stg::Runtime runtime(os, false);
+    Runtime runtime(os, false);
 
     // Read inputs.
-    stg::Graph graph;
-    const auto id0 = Read(runtime, graph, test.format0, test.file0);
-    const auto id1 = Read(runtime, graph, test.format1, test.file1);
+    Graph graph;
+    const Id id0 = Read(runtime, graph, test.format0, test.file0);
+    const Id id1 = Read(runtime, graph, test.format1, test.file1);
 
     // Compute differences.
-    stg::diff::Compare compare{runtime, graph, test.ignore};
-    const auto& [equals, comparison] = compare(id0, id1);
+    stg::diff::Outcomes outcomes;
+    const auto comparison =
+        diff::Compare(runtime, test.ignore, graph, id0, id1, outcomes);
+    const bool same = comparison == diff::Comparison{};
 
     // Write SMALL reports.
     std::ostringstream output;
-    if (comparison) {
-      stg::NameCache names;
-      stg::reporting::Options options{stg::reporting::OutputFormat::SMALL, 0};
-      stg::reporting::Reporting reporting{graph, compare.outcomes, options,
-                                          names};
-      Report(reporting, *comparison, output);
+    if (!same) {
+      NameCache names;
+      const reporting::Options options{reporting::OutputFormat::SMALL};
+      const reporting::Reporting reporting{graph, outcomes, options, names};
+      Report(reporting, comparison, output);
     }
 
     // Check comparison outcome and report output.
-    CHECK(equals == test.expected_equals);
-    std::ifstream expected_output_file(filename_to_path(test.expected_output));
+    CHECK(same == test.expected_same);
+    const std::ifstream expected_output_file(
+        filename_to_path(test.expected_output));
     std::ostringstream expected_output;
     expected_output << expected_output_file.rdbuf();
     CHECK(output.str() == expected_output.str());
@@ -271,53 +276,66 @@ TEST_CASE("ignore") {
 
 struct ShortReportTestCase {
   const std::string name;
-  const std::string xml0;
-  const std::string xml1;
+  InputFormat format;
+  const std::string file0;
+  const std::string file1;
   const std::string expected_output;
 };
 
 TEST_CASE("short report") {
   const auto test = GENERATE(
       ShortReportTestCase(
-          {"crc changes", "crc_0.xml", "crc_1.xml", "crc_changes_short_diff"}),
-      ShortReportTestCase({"only crc changes", "crc_only_0.xml",
-                           "crc_only_1.xml", "crc_only_changes_short_diff"}),
-      ShortReportTestCase({"offset changes", "offset_0.xml", "offset_1.xml",
-                           "offset_changes_short_diff"}),
+          {"crc changes", InputFormat::ABI, "crc_0.xml", "crc_1.xml",
+           "crc_changes_short_diff"}),
+      ShortReportTestCase(
+          {"only crc changes", InputFormat::ABI, "crc_only_0.xml",
+           "crc_only_1.xml", "crc_only_changes_short_diff"}),
+      ShortReportTestCase(
+          {"offset changes", InputFormat::ABI, "offset_0.xml",
+           "offset_1.xml", "offset_changes_short_diff"}),
+      ShortReportTestCase(
+          {"symbols added and removed", InputFormat::ABI,
+           "added_removed_symbols_0.xml", "added_removed_symbols_1.xml",
+           "added_removed_symbols_short_diff"}),
+      ShortReportTestCase(
+          {"symbols added and removed only", InputFormat::ABI,
+           "added_removed_symbols_only_0.xml",
+           "added_removed_symbols_only_1.xml",
+           "added_removed_symbols_only_short_diff"}),
       ShortReportTestCase(
-          {"symbols added and removed", "added_removed_symbols_0.xml",
-           "added_removed_symbols_1.xml", "added_removed_symbols_short_diff"}),
-      ShortReportTestCase({"symbols added and removed only",
-                           "added_removed_symbols_only_0.xml",
-                           "added_removed_symbols_only_1.xml",
-                           "added_removed_symbols_only_short_diff"}));
+          {"enumerators added and removed", stg::InputFormat::STG,
+           "added_removed_enumerators_0.stg",
+           "added_removed_enumerators_1.stg",
+           "added_removed_enumerators_short_diff"}));
 
   SECTION(test.name) {
     std::ostringstream os;
-    stg::Runtime runtime(os, false);
+    Runtime runtime(os, false);
 
     // Read inputs.
-    stg::Graph graph;
-    const auto id0 = Read(runtime, graph, stg::InputFormat::ABI, test.xml0);
-    const auto id1 = Read(runtime, graph, stg::InputFormat::ABI, test.xml1);
+    Graph graph;
+    const Id id0 = Read(runtime, graph, test.format, test.file0);
+    const Id id1 = Read(runtime, graph, test.format, test.file1);
 
     // Compute differences.
-    stg::diff::Compare compare{runtime, graph, {}};
-    const auto& [equals, comparison] = compare(id0, id1);
+    stg::diff::Outcomes outcomes;
+    const auto comparison =
+        diff::Compare(runtime, {}, graph, id0, id1, outcomes);
+    const bool same = comparison == diff::Comparison{};
 
     // Write SHORT reports.
     std::stringstream output;
-    if (comparison) {
-      stg::NameCache names;
-      stg::reporting::Options options{stg::reporting::OutputFormat::SHORT, 2};
-      stg::reporting::Reporting reporting{graph, compare.outcomes, options,
-                                          names};
-      Report(reporting, *comparison, output);
+    if (!same) {
+      NameCache names;
+      const reporting::Options options{reporting::OutputFormat::SHORT};
+      const reporting::Reporting reporting{graph, outcomes, options, names};
+      Report(reporting, comparison, output);
     }
 
     // Check comparison outcome and report output.
-    CHECK(equals == false);
-    std::ifstream expected_output_file(filename_to_path(test.expected_output));
+    CHECK(!same);
+    const std::ifstream expected_output_file(
+        filename_to_path(test.expected_output));
     std::ostringstream expected_output;
     expected_output << expected_output_file.rdbuf();
     CHECK(output.str() == expected_output.str());
@@ -326,27 +344,27 @@ TEST_CASE("short report") {
 
 TEST_CASE("fidelity diff") {
   std::ostringstream os;
-  stg::Runtime runtime(os, false);
+  Runtime runtime(os, false);
 
   // Read inputs.
-  stg::Graph graph;
-  const auto id0 =
-      Read(runtime, graph, stg::InputFormat::STG, "fidelity_diff_0.stg");
-  const auto id1 =
-      Read(runtime, graph, stg::InputFormat::STG, "fidelity_diff_1.stg");
+  Graph graph;
+  const Id id0 = Read(runtime, graph, InputFormat::STG, "fidelity_diff_0.stg");
+  const Id id1 = Read(runtime, graph, InputFormat::STG, "fidelity_diff_1.stg");
 
   // Compute fidelity diff.
-  auto fidelity_diff = stg::GetFidelityTransitions(graph, id0, id1);
+  auto fidelity_diff = GetFidelityTransitions(graph, id0, id1);
 
   // Write fidelity diff report.
   std::ostringstream report;
-  stg::reporting::FidelityDiff(fidelity_diff, report);
+  reporting::FidelityDiff(fidelity_diff, report);
 
   // Check report.
-  std::ifstream expected_report_file(filename_to_path("fidelity_diff_report"));
+  const std::ifstream expected_report_file(
+      filename_to_path("fidelity_diff_report"));
   std::ostringstream expected_report;
   expected_report << expected_report_file.rdbuf();
   CHECK(report.str() == expected_report.str());
 }
 
 }  // namespace
+}  // namespace stg
diff --git a/substitution.h b/substitution.h
index 43768cf..39092cf 100644
--- a/substitution.h
+++ b/substitution.h
@@ -58,52 +58,52 @@ struct Substitute {
     }
   }
 
-  void operator()(Id id) {
-    return graph.Apply<void>(*this, id);
+  void operator()(Id id) const {
+    return graph.Apply(*this, id);
   }
 
-  void operator()(Special&) {}
+  void operator()(Special&) const {}
 
-  void operator()(PointerReference& x) {
+  void operator()(PointerReference& x) const {
     Update(x.pointee_type_id);
   }
 
-  void operator()(PointerToMember& x) {
+  void operator()(PointerToMember& x) const {
     Update(x.containing_type_id);
     Update(x.pointee_type_id);
   }
 
-  void operator()(Typedef& x) {
+  void operator()(Typedef& x) const {
     Update(x.referred_type_id);
   }
 
-  void operator()(Qualified& x) {
+  void operator()(Qualified& x) const {
     Update(x.qualified_type_id);
   }
 
-  void operator()(Primitive&) {}
+  void operator()(Primitive&) const {}
 
-  void operator()(Array& x) {
+  void operator()(Array& x) const {
     Update(x.element_type_id);
   }
 
-  void operator()(BaseClass& x) {
+  void operator()(BaseClass& x) const {
     Update(x.type_id);
   }
 
-  void operator()(Method& x) {
+  void operator()(Method& x) const {
     Update(x.type_id);
   }
 
-  void operator()(Member& x) {
+  void operator()(Member& x) const {
     Update(x.type_id);
   }
 
-  void operator()(VariantMember& x) {
+  void operator()(VariantMember& x) const {
     Update(x.type_id);
   }
 
-  void operator()(StructUnion& x) {
+  void operator()(StructUnion& x) const {
     if (x.definition.has_value()) {
       auto& definition = x.definition.value();
       Update(definition.base_classes);
@@ -112,32 +112,32 @@ struct Substitute {
     }
   }
 
-  void operator()(Enumeration& x) {
+  void operator()(Enumeration& x) const {
     if (x.definition.has_value()) {
       auto& definition = x.definition.value();
       Update(definition.underlying_type_id);
     }
   }
 
-  void operator()(Variant& x) {
+  void operator()(Variant& x) const {
     if (x.discriminant.has_value()) {
       Update(x.discriminant.value());
     }
     Update(x.members);
   }
 
-  void operator()(Function& x) {
+  void operator()(Function& x) const {
     Update(x.parameters);
     Update(x.return_type_id);
   }
 
-  void operator()(ElfSymbol& x) {
+  void operator()(ElfSymbol& x) const {
     if (x.type_id) {
       Update(*x.type_id);
     }
   }
 
-  void operator()(Interface& x) {
+  void operator()(Interface& x) const {
     Update(x.symbols);
     Update(x.types);
   }
diff --git a/test_cases/diff_tests/array/expected/length_c.btf_btf_viz b/test_cases/diff_tests/array/expected/length_c.btf_btf_viz
index a569b99..685d409 100644
--- a/test_cases/diff_tests/array/expected/length_c.btf_btf_viz
+++ b/test_cases/diff_tests/array/expected/length_c.btf_btf_viz
@@ -7,8 +7,8 @@ digraph "ABI diff" {
   "5" [color=red, shape=rectangle, label="'struct foo'"]
   "5" -> "5:0"
   "5:0" [color=red, label="byte size changed from 4 to 8"]
-  "6" [label="'int bar[1]' -> 'int bar[2]'"]
-  "7" [color=red, label="'int[1]' -> 'int[2]'"]
+  "6" [label="'int bar[1]' → 'int bar[2]'"]
+  "7" [color=red, label="'int[1]' → 'int[2]'"]
   "7" -> "7:0"
   "7:0" [color=red, label="number of elements changed from 1 to 2"]
   "6" -> "7" [label=""]
diff --git a/test_cases/diff_tests/array/expected/length_c.o_o_viz b/test_cases/diff_tests/array/expected/length_c.o_o_viz
index a569b99..685d409 100644
--- a/test_cases/diff_tests/array/expected/length_c.o_o_viz
+++ b/test_cases/diff_tests/array/expected/length_c.o_o_viz
@@ -7,8 +7,8 @@ digraph "ABI diff" {
   "5" [color=red, shape=rectangle, label="'struct foo'"]
   "5" -> "5:0"
   "5:0" [color=red, label="byte size changed from 4 to 8"]
-  "6" [label="'int bar[1]' -> 'int bar[2]'"]
-  "7" [color=red, label="'int[1]' -> 'int[2]'"]
+  "6" [label="'int bar[1]' → 'int bar[2]'"]
+  "7" [color=red, label="'int[1]' → 'int[2]'"]
   "7" -> "7:0"
   "7:0" [color=red, label="number of elements changed from 1 to 2"]
   "6" -> "7" [label=""]
diff --git a/test_cases/diff_tests/array/expected/multidimensional_c.o_o_viz b/test_cases/diff_tests/array/expected/multidimensional_c.o_o_viz
index 9a02e79..bcd1f21 100644
--- a/test_cases/diff_tests/array/expected/multidimensional_c.o_o_viz
+++ b/test_cases/diff_tests/array/expected/multidimensional_c.o_o_viz
@@ -1,8 +1,8 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int x[1][2][3]' -> 'int x[1][4][3]'"]
-  "2" [label="'int[1][2][3]' -> 'int[1][4][3]'"]
-  "3" [color=red, label="'int[2][3]' -> 'int[4][3]'"]
+  "1" [label="'int x[1][2][3]' → 'int x[1][4][3]'"]
+  "2" [label="'int[1][2][3]' → 'int[1][4][3]'"]
+  "3" [color=red, label="'int[2][3]' → 'int[4][3]'"]
   "3" -> "3:0"
   "3:0" [color=red, label="number of elements changed from 2 to 4"]
   "2" -> "3" [label="element"]
diff --git a/test_cases/diff_tests/array/expected/multidimensional_cc.o_o_viz b/test_cases/diff_tests/array/expected/multidimensional_cc.o_o_viz
index 9a02e79..bcd1f21 100644
--- a/test_cases/diff_tests/array/expected/multidimensional_cc.o_o_viz
+++ b/test_cases/diff_tests/array/expected/multidimensional_cc.o_o_viz
@@ -1,8 +1,8 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int x[1][2][3]' -> 'int x[1][4][3]'"]
-  "2" [label="'int[1][2][3]' -> 'int[1][4][3]'"]
-  "3" [color=red, label="'int[2][3]' -> 'int[4][3]'"]
+  "1" [label="'int x[1][2][3]' → 'int x[1][4][3]'"]
+  "2" [label="'int[1][2][3]' → 'int[1][4][3]'"]
+  "3" [color=red, label="'int[2][3]' → 'int[4][3]'"]
   "3" -> "3:0"
   "3:0" [color=red, label="number of elements changed from 2 to 4"]
   "2" -> "3" [label="element"]
diff --git a/test_cases/diff_tests/array/expected/simple_array_c.btf_btf_viz b/test_cases/diff_tests/array/expected/simple_array_c.btf_btf_viz
index ce7bf14..285d0c7 100644
--- a/test_cases/diff_tests/array/expected/simple_array_c.btf_btf_viz
+++ b/test_cases/diff_tests/array/expected/simple_array_c.btf_btf_viz
@@ -4,9 +4,9 @@ digraph "ABI diff" {
   "2" [label="'void(struct leaf*)'"]
   "3" [label="'struct leaf*'"]
   "4" [shape=rectangle, label="'struct leaf'"]
-  "5" [label="'unsigned int numbers[2]' -> 'int numbers[2]'"]
-  "6" [label="'unsigned int[2]' -> 'int[2]'"]
-  "7" [color=red, label="'unsigned int' -> 'int'"]
+  "5" [label="'unsigned int numbers[2]' → 'int numbers[2]'"]
+  "6" [label="'unsigned int[2]' → 'int[2]'"]
+  "7" [color=red, label="'unsigned int' → 'int'"]
   "6" -> "7" [label="element"]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
diff --git a/test_cases/diff_tests/array/expected/simple_array_c.o_o_viz b/test_cases/diff_tests/array/expected/simple_array_c.o_o_viz
index ce7bf14..285d0c7 100644
--- a/test_cases/diff_tests/array/expected/simple_array_c.o_o_viz
+++ b/test_cases/diff_tests/array/expected/simple_array_c.o_o_viz
@@ -4,9 +4,9 @@ digraph "ABI diff" {
   "2" [label="'void(struct leaf*)'"]
   "3" [label="'struct leaf*'"]
   "4" [shape=rectangle, label="'struct leaf'"]
-  "5" [label="'unsigned int numbers[2]' -> 'int numbers[2]'"]
-  "6" [label="'unsigned int[2]' -> 'int[2]'"]
-  "7" [color=red, label="'unsigned int' -> 'int'"]
+  "5" [label="'unsigned int numbers[2]' → 'int numbers[2]'"]
+  "6" [label="'unsigned int[2]' → 'int[2]'"]
+  "7" [color=red, label="'unsigned int' → 'int'"]
   "6" -> "7" [label="element"]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
diff --git a/test_cases/diff_tests/array/expected/simple_array_cc.o_o_viz b/test_cases/diff_tests/array/expected/simple_array_cc.o_o_viz
index 29c7fbe..e2fef80 100644
--- a/test_cases/diff_tests/array/expected/simple_array_cc.o_o_viz
+++ b/test_cases/diff_tests/array/expected/simple_array_cc.o_o_viz
@@ -4,9 +4,9 @@ digraph "ABI diff" {
   "2" [label="'void(struct leaf*)'"]
   "3" [label="'struct leaf*'"]
   "4" [shape=rectangle, label="'struct leaf'"]
-  "5" [label="'unsigned int numbers[2]' -> 'int numbers[2]'"]
-  "6" [label="'unsigned int[2]' -> 'int[2]'"]
-  "7" [color=red, label="'unsigned int' -> 'int'"]
+  "5" [label="'unsigned int numbers[2]' → 'int numbers[2]'"]
+  "6" [label="'unsigned int[2]' → 'int[2]'"]
+  "7" [color=red, label="'unsigned int' → 'int'"]
   "6" -> "7" [label="element"]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/anonymous_cc.o_o_viz b/test_cases/diff_tests/composite/expected/anonymous_cc.o_o_viz
index d217dbc..b70fd27 100644
--- a/test_cases/diff_tests/composite/expected/anonymous_cc.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/anonymous_cc.o_o_viz
@@ -4,42 +4,42 @@ digraph "ABI diff" {
   "2" [color=red, shape=rectangle, label="'struct Foo'"]
   "2" -> "2:0"
   "2:0" [color=red, label="byte size changed from 16 to 32"]
-  "3" [label="'struct { int x; } anon_class' -> 'struct { long x; } anon_class'"]
-  "4" [color=red, label="'struct { int x; }' -> 'struct { long x; }'"]
+  "3" [label="'struct { int x; } anon_class' → 'struct { long x; } anon_class'"]
+  "4" [color=red, label="'struct { int x; }' → 'struct { long x; }'"]
   "4" -> "4:0"
   "4:0" [color=red, label="byte size changed from 4 to 8"]
-  "5" [label="'int x' -> 'long x'"]
-  "6" [color=red, label="'int' -> 'long'"]
+  "5" [label="'int x' → 'long x'"]
+  "6" [color=red, label="'int' → 'long'"]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
   "2" -> "3" [label=""]
-  "7" [color=red, label="'struct { int x; } anon_struct' -> 'struct { long x; } anon_struct'"]
+  "7" [color=red, label="'struct { int x; } anon_struct' → 'struct { long x; } anon_struct'"]
   "7" -> "7:0"
   "7:0" [color=red, label="offset changed from 32 to 64"]
-  "8" [color=red, label="'struct { int x; }' -> 'struct { long x; }'"]
+  "8" [color=red, label="'struct { int x; }' → 'struct { long x; }'"]
   "8" -> "8:0"
   "8:0" [color=red, label="byte size changed from 4 to 8"]
-  "9" [label="'int x' -> 'long x'"]
+  "9" [label="'int x' → 'long x'"]
   "9" -> "6" [label=""]
   "8" -> "9" [label=""]
   "7" -> "8" [label=""]
   "2" -> "7" [label=""]
-  "10" [color=red, label="'union { int x; } anon_union' -> 'union { long x; } anon_union'"]
+  "10" [color=red, label="'union { int x; } anon_union' → 'union { long x; } anon_union'"]
   "10" -> "10:0"
   "10:0" [color=red, label="offset changed from 64 to 128"]
-  "11" [color=red, label="'union { int x; }' -> 'union { long x; }'"]
+  "11" [color=red, label="'union { int x; }' → 'union { long x; }'"]
   "11" -> "11:0"
   "11:0" [color=red, label="byte size changed from 4 to 8"]
-  "12" [label="'int x' -> 'long x'"]
+  "12" [label="'int x' → 'long x'"]
   "12" -> "6" [label=""]
   "11" -> "12" [label=""]
   "10" -> "11" [label=""]
   "2" -> "10" [label=""]
-  "13" [color=red, label="'enum { X = 1, } anon_enum' -> 'enum { X = 2, } anon_enum'"]
+  "13" [color=red, label="'enum { X = 1, } anon_enum' → 'enum { X = 2, } anon_enum'"]
   "13" -> "13:0"
   "13:0" [color=red, label="offset changed from 96 to 192"]
-  "14" [color=red, label="'enum { X = 1, }' -> 'enum { X = 2, }'"]
+  "14" [color=red, label="'enum { X = 1, }' → 'enum { X = 2, }'"]
   "14" -> "14:0"
   "14:0" [color=red, label="enumerator 'X' value changed from 1 to 2"]
   "13" -> "14" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/anonymous_member_c.o_o_viz b/test_cases/diff_tests/composite/expected/anonymous_member_c.o_o_viz
index b05509f..b9aa86d 100644
--- a/test_cases/diff_tests/composite/expected/anonymous_member_c.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/anonymous_member_c.o_o_viz
@@ -1,7 +1,7 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'struct { struct { int one; }; struct { int two; }; struct { int four; }; struct { int eight; }; } v' -> 'struct { struct { int zero; }; struct { int two; }; struct { int four; }; struct { int six; }; struct { int eight; }; } v'"]
-  "2" [color=red, label="'struct { struct { int one; }; struct { int two; }; struct { int four; }; struct { int eight; }; }' -> 'struct { struct { int zero; }; struct { int two; }; struct { int four; }; struct { int six; }; struct { int eight; }; }'"]
+  "1" [label="'struct { struct { int one; }; struct { int two; }; struct { int four; }; struct { int eight; }; } v' → 'struct { struct { int zero; }; struct { int two; }; struct { int four; }; struct { int six; }; struct { int eight; }; } v'"]
+  "2" [color=red, label="'struct { struct { int one; }; struct { int two; }; struct { int four; }; struct { int eight; }; }' → 'struct { struct { int zero; }; struct { int two; }; struct { int four; }; struct { int six; }; struct { int eight; }; }'"]
   "2" -> "2:0"
   "2:0" [color=red, label="byte size changed from 16 to 20"]
   "3" [color=red, label="removed(struct { int one; })"]
diff --git a/test_cases/diff_tests/composite/expected/anonymous_member_chain_c.btf_btf_viz b/test_cases/diff_tests/composite/expected/anonymous_member_chain_c.btf_btf_viz
index 8c9e3f6..18fcd99 100644
--- a/test_cases/diff_tests/composite/expected/anonymous_member_chain_c.btf_btf_viz
+++ b/test_cases/diff_tests/composite/expected/anonymous_member_chain_c.btf_btf_viz
@@ -5,16 +5,16 @@ digraph "ABI diff" {
   "3" [color=red, shape=rectangle, label="'struct A'"]
   "3" -> "3:0"
   "3:0" [color=red, label="byte size changed from 8 to 4"]
-  "4" [label="'union { struct { int x; }; struct { long y; }; }' -> 'union { struct { int x; }; struct { char y; }; }'"]
-  "5" [color=red, label="'union { struct { int x; }; struct { long y; }; }' -> 'union { struct { int x; }; struct { char y; }; }'"]
+  "4" [label="'union { struct { int x; }; struct { long y; }; }' → 'union { struct { int x; }; struct { char y; }; }'"]
+  "5" [color=red, label="'union { struct { int x; }; struct { long y; }; }' → 'union { struct { int x; }; struct { char y; }; }'"]
   "5" -> "5:0"
   "5:0" [color=red, label="byte size changed from 8 to 4"]
-  "6" [label="'struct { long y; }' -> 'struct { char y; }'"]
-  "7" [color=red, label="'struct { long y; }' -> 'struct { char y; }'"]
+  "6" [label="'struct { long y; }' → 'struct { char y; }'"]
+  "7" [color=red, label="'struct { long y; }' → 'struct { char y; }'"]
   "7" -> "7:0"
   "7:0" [color=red, label="byte size changed from 8 to 1"]
-  "8" [label="'long y' -> 'char y'"]
-  "9" [color=red, label="'long' -> 'char'"]
+  "8" [label="'long y' → 'char y'"]
+  "9" [color=red, label="'long' → 'char'"]
   "8" -> "9" [label=""]
   "7" -> "8" [label=""]
   "6" -> "7" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/anonymous_member_chain_c.o_o_viz b/test_cases/diff_tests/composite/expected/anonymous_member_chain_c.o_o_viz
index 8c9e3f6..18fcd99 100644
--- a/test_cases/diff_tests/composite/expected/anonymous_member_chain_c.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/anonymous_member_chain_c.o_o_viz
@@ -5,16 +5,16 @@ digraph "ABI diff" {
   "3" [color=red, shape=rectangle, label="'struct A'"]
   "3" -> "3:0"
   "3:0" [color=red, label="byte size changed from 8 to 4"]
-  "4" [label="'union { struct { int x; }; struct { long y; }; }' -> 'union { struct { int x; }; struct { char y; }; }'"]
-  "5" [color=red, label="'union { struct { int x; }; struct { long y; }; }' -> 'union { struct { int x; }; struct { char y; }; }'"]
+  "4" [label="'union { struct { int x; }; struct { long y; }; }' → 'union { struct { int x; }; struct { char y; }; }'"]
+  "5" [color=red, label="'union { struct { int x; }; struct { long y; }; }' → 'union { struct { int x; }; struct { char y; }; }'"]
   "5" -> "5:0"
   "5:0" [color=red, label="byte size changed from 8 to 4"]
-  "6" [label="'struct { long y; }' -> 'struct { char y; }'"]
-  "7" [color=red, label="'struct { long y; }' -> 'struct { char y; }'"]
+  "6" [label="'struct { long y; }' → 'struct { char y; }'"]
+  "7" [color=red, label="'struct { long y; }' → 'struct { char y; }'"]
   "7" -> "7:0"
   "7:0" [color=red, label="byte size changed from 8 to 1"]
-  "8" [label="'long y' -> 'char y'"]
-  "9" [color=red, label="'long' -> 'char'"]
+  "8" [label="'long y' → 'char y'"]
+  "9" [color=red, label="'long' → 'char'"]
   "8" -> "9" [label=""]
   "7" -> "8" [label=""]
   "6" -> "7" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/base_class_size_cc.o_o_viz b/test_cases/diff_tests/composite/expected/base_class_size_cc.o_o_viz
index 1b1de44..2095c50 100644
--- a/test_cases/diff_tests/composite/expected/base_class_size_cc.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/base_class_size_cc.o_o_viz
@@ -8,8 +8,8 @@ digraph "ABI diff" {
   "4" [color=red, shape=rectangle, label="'struct B'"]
   "4" -> "4:0"
   "4:0" [color=red, label="byte size changed from 4 to 8"]
-  "5" [label="'int y' -> 'long y'"]
-  "6" [color=red, label="'int' -> 'long'"]
+  "5" [label="'int y' → 'long y'"]
+  "6" [color=red, label="'int' → 'long'"]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
@@ -24,8 +24,8 @@ digraph "ABI diff" {
   "9" [shape=rectangle, label="'struct SameSize'"]
   "10" [label="'struct A'"]
   "11" [shape=rectangle, label="'struct A'"]
-  "12" [label="'int x' -> 'unsigned int x'"]
-  "13" [color=red, label="'int' -> 'unsigned int'"]
+  "12" [label="'int x' → 'unsigned int x'"]
+  "13" [color=red, label="'int' → 'unsigned int'"]
   "12" -> "13" [label=""]
   "11" -> "12" [label=""]
   "10" -> "11" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/forward_c.btf_btf_viz b/test_cases/diff_tests/composite/expected/forward_c.btf_btf_viz
index b3c0825..cafa976 100644
--- a/test_cases/diff_tests/composite/expected/forward_c.btf_btf_viz
+++ b/test_cases/diff_tests/composite/expected/forward_c.btf_btf_viz
@@ -40,30 +40,30 @@ digraph "ABI diff" {
   "2" -> "13" [label="parameter 6"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "15" [label="'int f2(enum K*, enum L*, struct M*, struct N*, union O*, union P*)' -> 'int f2(struct K*, union L*, union M*, enum N*, enum O*, struct P*)'"]
-  "16" [label="'int(enum K*, enum L*, struct M*, struct N*, union O*, union P*)' -> 'int(struct K*, union L*, union M*, enum N*, enum O*, struct P*)'"]
-  "17" [label="'enum K*' -> 'struct K*'"]
-  "18" [color=red, label="'enum K' -> 'struct K'"]
+  "15" [label="'int f2(enum K*, enum L*, struct M*, struct N*, union O*, union P*)' → 'int f2(struct K*, union L*, union M*, enum N*, enum O*, struct P*)'"]
+  "16" [label="'int(enum K*, enum L*, struct M*, struct N*, union O*, union P*)' → 'int(struct K*, union L*, union M*, enum N*, enum O*, struct P*)'"]
+  "17" [label="'enum K*' → 'struct K*'"]
+  "18" [color=red, label="'enum K' → 'struct K'"]
   "17" -> "18" [label="pointed-to"]
   "16" -> "17" [label="parameter 1"]
-  "19" [label="'enum L*' -> 'union L*'"]
-  "20" [color=red, label="'enum L' -> 'union L'"]
+  "19" [label="'enum L*' → 'union L*'"]
+  "20" [color=red, label="'enum L' → 'union L'"]
   "19" -> "20" [label="pointed-to"]
   "16" -> "19" [label="parameter 2"]
-  "21" [label="'struct M*' -> 'union M*'"]
-  "22" [color=red, label="'struct M' -> 'union M'"]
+  "21" [label="'struct M*' → 'union M*'"]
+  "22" [color=red, label="'struct M' → 'union M'"]
   "21" -> "22" [label="pointed-to"]
   "16" -> "21" [label="parameter 3"]
-  "23" [label="'struct N*' -> 'enum N*'"]
-  "24" [color=red, label="'struct N' -> 'enum N'"]
+  "23" [label="'struct N*' → 'enum N*'"]
+  "24" [color=red, label="'struct N' → 'enum N'"]
   "23" -> "24" [label="pointed-to"]
   "16" -> "23" [label="parameter 4"]
-  "25" [label="'union O*' -> 'enum O*'"]
-  "26" [color=red, label="'union O' -> 'enum O'"]
+  "25" [label="'union O*' → 'enum O*'"]
+  "26" [color=red, label="'union O' → 'enum O'"]
   "25" -> "26" [label="pointed-to"]
   "16" -> "25" [label="parameter 5"]
-  "27" [label="'union P*' -> 'struct P*'"]
-  "28" [color=red, label="'union P' -> 'struct P'"]
+  "27" [label="'union P*' → 'struct P*'"]
+  "28" [color=red, label="'union P' → 'struct P'"]
   "27" -> "28" [label="pointed-to"]
   "16" -> "27" [label="parameter 6"]
   "15" -> "16" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/forward_c.o_o_viz b/test_cases/diff_tests/composite/expected/forward_c.o_o_viz
index b3c0825..cafa976 100644
--- a/test_cases/diff_tests/composite/expected/forward_c.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/forward_c.o_o_viz
@@ -40,30 +40,30 @@ digraph "ABI diff" {
   "2" -> "13" [label="parameter 6"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "15" [label="'int f2(enum K*, enum L*, struct M*, struct N*, union O*, union P*)' -> 'int f2(struct K*, union L*, union M*, enum N*, enum O*, struct P*)'"]
-  "16" [label="'int(enum K*, enum L*, struct M*, struct N*, union O*, union P*)' -> 'int(struct K*, union L*, union M*, enum N*, enum O*, struct P*)'"]
-  "17" [label="'enum K*' -> 'struct K*'"]
-  "18" [color=red, label="'enum K' -> 'struct K'"]
+  "15" [label="'int f2(enum K*, enum L*, struct M*, struct N*, union O*, union P*)' → 'int f2(struct K*, union L*, union M*, enum N*, enum O*, struct P*)'"]
+  "16" [label="'int(enum K*, enum L*, struct M*, struct N*, union O*, union P*)' → 'int(struct K*, union L*, union M*, enum N*, enum O*, struct P*)'"]
+  "17" [label="'enum K*' → 'struct K*'"]
+  "18" [color=red, label="'enum K' → 'struct K'"]
   "17" -> "18" [label="pointed-to"]
   "16" -> "17" [label="parameter 1"]
-  "19" [label="'enum L*' -> 'union L*'"]
-  "20" [color=red, label="'enum L' -> 'union L'"]
+  "19" [label="'enum L*' → 'union L*'"]
+  "20" [color=red, label="'enum L' → 'union L'"]
   "19" -> "20" [label="pointed-to"]
   "16" -> "19" [label="parameter 2"]
-  "21" [label="'struct M*' -> 'union M*'"]
-  "22" [color=red, label="'struct M' -> 'union M'"]
+  "21" [label="'struct M*' → 'union M*'"]
+  "22" [color=red, label="'struct M' → 'union M'"]
   "21" -> "22" [label="pointed-to"]
   "16" -> "21" [label="parameter 3"]
-  "23" [label="'struct N*' -> 'enum N*'"]
-  "24" [color=red, label="'struct N' -> 'enum N'"]
+  "23" [label="'struct N*' → 'enum N*'"]
+  "24" [color=red, label="'struct N' → 'enum N'"]
   "23" -> "24" [label="pointed-to"]
   "16" -> "23" [label="parameter 4"]
-  "25" [label="'union O*' -> 'enum O*'"]
-  "26" [color=red, label="'union O' -> 'enum O'"]
+  "25" [label="'union O*' → 'enum O*'"]
+  "26" [color=red, label="'union O' → 'enum O'"]
   "25" -> "26" [label="pointed-to"]
   "16" -> "25" [label="parameter 5"]
-  "27" [label="'union P*' -> 'struct P*'"]
-  "28" [color=red, label="'union P' -> 'struct P'"]
+  "27" [label="'union P*' → 'struct P*'"]
+  "28" [color=red, label="'union P' → 'struct P'"]
   "27" -> "28" [label="pointed-to"]
   "16" -> "27" [label="parameter 6"]
   "15" -> "16" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/indirect_c.btf_btf_viz b/test_cases/diff_tests/composite/expected/indirect_c.btf_btf_viz
index e437afe..bc505b0 100644
--- a/test_cases/diff_tests/composite/expected/indirect_c.btf_btf_viz
+++ b/test_cases/diff_tests/composite/expected/indirect_c.btf_btf_viz
@@ -9,8 +9,8 @@ digraph "ABI diff" {
   "7" [color=red, shape=rectangle, label="'struct leaf'"]
   "7" -> "7:0"
   "7:0" [color=red, label="byte size changed from 8 to 12"]
-  "8" [label="'int numbers[2]' -> 'int numbers[3]'"]
-  "9" [color=red, label="'int[2]' -> 'int[3]'"]
+  "8" [label="'int numbers[2]' → 'int numbers[3]'"]
+  "9" [color=red, label="'int[2]' → 'int[3]'"]
   "9" -> "9:0"
   "9:0" [color=red, label="number of elements changed from 2 to 3"]
   "8" -> "9" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/indirect_c.o_o_viz b/test_cases/diff_tests/composite/expected/indirect_c.o_o_viz
index e437afe..bc505b0 100644
--- a/test_cases/diff_tests/composite/expected/indirect_c.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/indirect_c.o_o_viz
@@ -9,8 +9,8 @@ digraph "ABI diff" {
   "7" [color=red, shape=rectangle, label="'struct leaf'"]
   "7" -> "7:0"
   "7:0" [color=red, label="byte size changed from 8 to 12"]
-  "8" [label="'int numbers[2]' -> 'int numbers[3]'"]
-  "9" [color=red, label="'int[2]' -> 'int[3]'"]
+  "8" [label="'int numbers[2]' → 'int numbers[3]'"]
+  "9" [color=red, label="'int[2]' → 'int[3]'"]
   "9" -> "9:0"
   "9:0" [color=red, label="number of elements changed from 2 to 3"]
   "8" -> "9" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/kind_cc.o_o_viz b/test_cases/diff_tests/composite/expected/kind_cc.o_o_viz
index 046b4cf..9e46a61 100644
--- a/test_cases/diff_tests/composite/expected/kind_cc.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/kind_cc.o_o_viz
@@ -4,35 +4,35 @@ digraph "ABI diff" {
   "2" [color=red, shape=rectangle, label="'struct ClassToStruct'"]
   "2" -> "2:0"
   "2:0" [color=red, label="byte size changed from 4 to 8"]
-  "3" [label="'int x' -> 'long x'"]
-  "4" [color=red, label="'int' -> 'long'"]
+  "3" [label="'int x' → 'long x'"]
+  "4" [color=red, label="'int' → 'long'"]
   "3" -> "4" [label=""]
   "2" -> "3" [label=""]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "5" [label="'struct ClassToUnion class_to_union' -> 'union ClassToUnion class_to_union'"]
-  "6" [color=red, label="'struct ClassToUnion' -> 'union ClassToUnion'"]
+  "5" [label="'struct ClassToUnion class_to_union' → 'union ClassToUnion class_to_union'"]
+  "6" [color=red, label="'struct ClassToUnion' → 'union ClassToUnion'"]
   "5" -> "6" [label=""]
   "0" -> "5" [label=""]
   "7" [label="'struct StructToClass struct_to_class'"]
   "8" [color=red, shape=rectangle, label="'struct StructToClass'"]
   "8" -> "8:0"
   "8:0" [color=red, label="byte size changed from 4 to 8"]
-  "9" [label="'int x' -> 'long x'"]
+  "9" [label="'int x' → 'long x'"]
   "9" -> "4" [label=""]
   "8" -> "9" [label=""]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
-  "10" [label="'struct StructToUnion struct_to_union' -> 'union StructToUnion struct_to_union'"]
-  "11" [color=red, label="'struct StructToUnion' -> 'union StructToUnion'"]
+  "10" [label="'struct StructToUnion struct_to_union' → 'union StructToUnion struct_to_union'"]
+  "11" [color=red, label="'struct StructToUnion' → 'union StructToUnion'"]
   "10" -> "11" [label=""]
   "0" -> "10" [label=""]
-  "12" [label="'union UnionToClass union_to_class' -> 'struct UnionToClass union_to_class'"]
-  "13" [color=red, label="'union UnionToClass' -> 'struct UnionToClass'"]
+  "12" [label="'union UnionToClass union_to_class' → 'struct UnionToClass union_to_class'"]
+  "13" [color=red, label="'union UnionToClass' → 'struct UnionToClass'"]
   "12" -> "13" [label=""]
   "0" -> "12" [label=""]
-  "14" [label="'union UnionToStruct union_to_struct' -> 'struct UnionToStruct union_to_struct'"]
-  "15" [color=red, label="'union UnionToStruct' -> 'struct UnionToStruct'"]
+  "14" [label="'union UnionToStruct union_to_struct' → 'struct UnionToStruct union_to_struct'"]
+  "15" [color=red, label="'union UnionToStruct' → 'struct UnionToStruct'"]
   "14" -> "15" [label=""]
   "0" -> "14" [label=""]
 }
diff --git a/test_cases/diff_tests/composite/expected/members_c.btf_btf_viz b/test_cases/diff_tests/composite/expected/members_c.btf_btf_viz
index e3f1995..70da3fb 100644
--- a/test_cases/diff_tests/composite/expected/members_c.btf_btf_viz
+++ b/test_cases/diff_tests/composite/expected/members_c.btf_btf_viz
@@ -5,25 +5,25 @@ digraph "ABI diff" {
   "3" [color=red, shape=rectangle, label="'struct s'"]
   "3" -> "3:0"
   "3:0" [color=red, label="byte size changed from 64 to 88"]
-  "4" [label="'int a' -> 'long a'"]
-  "5" [color=red, label="'int' -> 'long'"]
+  "4" [label="'int a' → 'long a'"]
+  "5" [color=red, label="'int' → 'long'"]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
-  "6" [label="'int* b' -> 'long* b'"]
-  "7" [label="'int*' -> 'long*'"]
+  "6" [label="'int* b' → 'long* b'"]
+  "7" [label="'int*' → 'long*'"]
   "7" -> "5" [label="pointed-to"]
   "6" -> "7" [label=""]
   "3" -> "6" [label=""]
-  "8" [label="'int c[7]' -> 'long c[7]'"]
-  "9" [label="'int[7]' -> 'long[7]'"]
+  "8" [label="'int c[7]' → 'long c[7]'"]
+  "9" [label="'int[7]' → 'long[7]'"]
   "9" -> "5" [label="element"]
   "8" -> "9" [label=""]
   "3" -> "8" [label=""]
-  "10" [color=red, label="'int(* d)()' -> 'long(* d)()'"]
+  "10" [color=red, label="'int(* d)()' → 'long(* d)()'"]
   "10" -> "10:0"
   "10:0" [color=red, label="offset changed from 384 to 576"]
-  "11" [label="'int(*)()' -> 'long(*)()'"]
-  "12" [label="'int()' -> 'long()'"]
+  "11" [label="'int(*)()' → 'long(*)()'"]
+  "12" [label="'int()' → 'long()'"]
   "12" -> "5" [label="return"]
   "11" -> "12" [label="pointed-to"]
   "10" -> "11" [label=""]
@@ -31,7 +31,7 @@ digraph "ABI diff" {
   "13" [color=red, label="'thing e'"]
   "13" -> "13:0"
   "13:0" [color=red, label="offset changed from 448 to 640"]
-  "14" [shape=rectangle, label="'thing' = 'int' -> 'thing' = 'long'"]
+  "14" [shape=rectangle, label="'thing' = 'int' → 'thing' = 'long'"]
   "14" -> "5" [label="resolved"]
   "13" -> "14" [label=""]
   "3" -> "13" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/members_c.o_o_viz b/test_cases/diff_tests/composite/expected/members_c.o_o_viz
index e3f1995..70da3fb 100644
--- a/test_cases/diff_tests/composite/expected/members_c.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/members_c.o_o_viz
@@ -5,25 +5,25 @@ digraph "ABI diff" {
   "3" [color=red, shape=rectangle, label="'struct s'"]
   "3" -> "3:0"
   "3:0" [color=red, label="byte size changed from 64 to 88"]
-  "4" [label="'int a' -> 'long a'"]
-  "5" [color=red, label="'int' -> 'long'"]
+  "4" [label="'int a' → 'long a'"]
+  "5" [color=red, label="'int' → 'long'"]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
-  "6" [label="'int* b' -> 'long* b'"]
-  "7" [label="'int*' -> 'long*'"]
+  "6" [label="'int* b' → 'long* b'"]
+  "7" [label="'int*' → 'long*'"]
   "7" -> "5" [label="pointed-to"]
   "6" -> "7" [label=""]
   "3" -> "6" [label=""]
-  "8" [label="'int c[7]' -> 'long c[7]'"]
-  "9" [label="'int[7]' -> 'long[7]'"]
+  "8" [label="'int c[7]' → 'long c[7]'"]
+  "9" [label="'int[7]' → 'long[7]'"]
   "9" -> "5" [label="element"]
   "8" -> "9" [label=""]
   "3" -> "8" [label=""]
-  "10" [color=red, label="'int(* d)()' -> 'long(* d)()'"]
+  "10" [color=red, label="'int(* d)()' → 'long(* d)()'"]
   "10" -> "10:0"
   "10:0" [color=red, label="offset changed from 384 to 576"]
-  "11" [label="'int(*)()' -> 'long(*)()'"]
-  "12" [label="'int()' -> 'long()'"]
+  "11" [label="'int(*)()' → 'long(*)()'"]
+  "12" [label="'int()' → 'long()'"]
   "12" -> "5" [label="return"]
   "11" -> "12" [label="pointed-to"]
   "10" -> "11" [label=""]
@@ -31,7 +31,7 @@ digraph "ABI diff" {
   "13" [color=red, label="'thing e'"]
   "13" -> "13:0"
   "13:0" [color=red, label="offset changed from 448 to 640"]
-  "14" [shape=rectangle, label="'thing' = 'int' -> 'thing' = 'long'"]
+  "14" [shape=rectangle, label="'thing' = 'int' → 'thing' = 'long'"]
   "14" -> "5" [label="resolved"]
   "13" -> "14" [label=""]
   "3" -> "13" [label=""]
diff --git a/test_cases/diff_tests/composite/expected/named_change_c.o_o_viz b/test_cases/diff_tests/composite/expected/named_change_c.o_o_viz
index 7a13129..706d2f6 100644
--- a/test_cases/diff_tests/composite/expected/named_change_c.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/named_change_c.o_o_viz
@@ -1,11 +1,11 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'struct S1 v1' -> 'struct { int a1; } v1'"]
-  "2" [color=red, label="'struct S1' -> 'struct { int a1; }'"]
+  "1" [label="'struct S1 v1' → 'struct { int a1; } v1'"]
+  "2" [color=red, label="'struct S1' → 'struct { int a1; }'"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "3" [label="'struct { int a2; } v2' -> 'struct S2 v2'"]
-  "4" [color=red, label="'struct { int a2; }' -> 'struct S2'"]
+  "3" [label="'struct { int a2; } v2' → 'struct S2 v2'"]
+  "4" [color=red, label="'struct { int a2; }' → 'struct S2'"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
 }
diff --git a/test_cases/diff_tests/composite/expected/named_definition_change_c.o_o_viz b/test_cases/diff_tests/composite/expected/named_definition_change_c.o_o_viz
index fc6a7aa..a3f454d 100644
--- a/test_cases/diff_tests/composite/expected/named_definition_change_c.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/named_definition_change_c.o_o_viz
@@ -1,11 +1,11 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'struct S1 v1' -> 'struct { int a1; int b1; } v1'"]
-  "2" [color=red, label="'struct S1' -> 'struct { int a1; int b1; }'"]
+  "1" [label="'struct S1 v1' → 'struct { int a1; int b1; } v1'"]
+  "2" [color=red, label="'struct S1' → 'struct { int a1; int b1; }'"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "3" [label="'struct { int a2; } v2' -> 'struct S2 v2'"]
-  "4" [color=red, label="'struct { int a2; }' -> 'struct S2'"]
+  "3" [label="'struct { int a2; } v2' → 'struct S2 v2'"]
+  "4" [color=red, label="'struct { int a2; }' → 'struct S2'"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
 }
diff --git a/test_cases/diff_tests/composite/expected/struct_vs_union_c.btf_btf_viz b/test_cases/diff_tests/composite/expected/struct_vs_union_c.btf_btf_viz
index f1e92a7..8f267e2 100644
--- a/test_cases/diff_tests/composite/expected/struct_vs_union_c.btf_btf_viz
+++ b/test_cases/diff_tests/composite/expected/struct_vs_union_c.btf_btf_viz
@@ -1,10 +1,10 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'void fun(const struct A*)' -> 'void fun(const union A*)'"]
-  "2" [label="'void(const struct A*)' -> 'void(const union A*)'"]
-  "3" [label="'const struct A*' -> 'const union A*'"]
-  "4" [label="'const struct A' -> 'const union A'"]
-  "5" [color=red, label="'struct A' -> 'union A'"]
+  "1" [label="'void fun(const struct A*)' → 'void fun(const union A*)'"]
+  "2" [label="'void(const struct A*)' → 'void(const union A*)'"]
+  "3" [label="'const struct A*' → 'const union A*'"]
+  "4" [label="'const struct A' → 'const union A'"]
+  "5" [color=red, label="'struct A' → 'union A'"]
   "4" -> "5" [label="underlying"]
   "3" -> "4" [label="pointed-to"]
   "2" -> "3" [label="parameter 1"]
diff --git a/test_cases/diff_tests/composite/expected/struct_vs_union_c.o_o_viz b/test_cases/diff_tests/composite/expected/struct_vs_union_c.o_o_viz
index f1e92a7..8f267e2 100644
--- a/test_cases/diff_tests/composite/expected/struct_vs_union_c.o_o_viz
+++ b/test_cases/diff_tests/composite/expected/struct_vs_union_c.o_o_viz
@@ -1,10 +1,10 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'void fun(const struct A*)' -> 'void fun(const union A*)'"]
-  "2" [label="'void(const struct A*)' -> 'void(const union A*)'"]
-  "3" [label="'const struct A*' -> 'const union A*'"]
-  "4" [label="'const struct A' -> 'const union A'"]
-  "5" [color=red, label="'struct A' -> 'union A'"]
+  "1" [label="'void fun(const struct A*)' → 'void fun(const union A*)'"]
+  "2" [label="'void(const struct A*)' → 'void(const union A*)'"]
+  "3" [label="'const struct A*' → 'const union A*'"]
+  "4" [label="'const struct A' → 'const union A'"]
+  "5" [color=red, label="'struct A' → 'union A'"]
   "4" -> "5" [label="underlying"]
   "3" -> "4" [label="pointed-to"]
   "2" -> "3" [label="parameter 1"]
diff --git a/test_cases/diff_tests/describe/expected/types_c.btf_btf_viz b/test_cases/diff_tests/describe/expected/types_c.btf_btf_viz
index 4e449ad..59b31ad 100644
--- a/test_cases/diff_tests/describe/expected/types_c.btf_btf_viz
+++ b/test_cases/diff_tests/describe/expected/types_c.btf_btf_viz
@@ -1,20 +1,20 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int N()' -> 'int(* N())[7]'"]
-  "2" [label="'int()' -> 'int(*())[7]'"]
-  "3" [color=red, label="'int' -> 'int(*)[7]'"]
+  "1" [label="'int N()' → 'int(* N())[7]'"]
+  "2" [label="'int()' → 'int(*())[7]'"]
+  "3" [color=red, label="'int' → 'int(*)[7]'"]
   "2" -> "3" [label="return"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "4" [label="'int O()' -> 'int* O()'"]
-  "5" [label="'int()' -> 'int*()'"]
-  "6" [color=red, label="'int' -> 'int*'"]
+  "4" [label="'int O()' → 'int* O()'"]
+  "5" [label="'int()' → 'int*()'"]
+  "6" [color=red, label="'int' → 'int*'"]
   "5" -> "6" [label="return"]
   "4" -> "5" [label=""]
   "0" -> "4" [label=""]
-  "7" [label="'int P()' -> 'int(* P())()'"]
-  "8" [label="'int()' -> 'int(*())()'"]
-  "9" [color=red, label="'int' -> 'int(*)()'"]
+  "7" [label="'int P()' → 'int(* P())()'"]
+  "8" [label="'int()' → 'int(*())()'"]
+  "9" [color=red, label="'int' → 'int(*)()'"]
   "8" -> "9" [label="return"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
@@ -24,164 +24,164 @@ digraph "ABI diff" {
   "13" [color=red, shape=rectangle, label="'struct amusement'"]
   "13" -> "13:0"
   "13:0" [color=red, label="byte size changed from 96 to 816"]
-  "14" [label="'int A' -> 'int A[7]'"]
-  "15" [color=red, label="'int' -> 'int[7]'"]
+  "14" [label="'int A' → 'int A[7]'"]
+  "15" [color=red, label="'int' → 'int[7]'"]
   "14" -> "15" [label=""]
   "13" -> "14" [label=""]
-  "16" [color=red, label="'int B' -> 'int* B'"]
+  "16" [color=red, label="'int B' → 'int* B'"]
   "16" -> "16:0"
   "16:0" [color=red, label="offset changed from 32 to 256"]
   "16" -> "6" [label=""]
   "13" -> "16" [label=""]
-  "17" [color=red, label="'int C' -> 'int(* C)()'"]
+  "17" [color=red, label="'int C' → 'int(* C)()'"]
   "17" -> "17:0"
   "17:0" [color=red, label="offset changed from 64 to 320"]
   "17" -> "9" [label=""]
   "13" -> "17" [label=""]
-  "18" [color=red, label="'int D' -> 'int D[49]'"]
+  "18" [color=red, label="'int D' → 'int D[49]'"]
   "18" -> "18:0"
   "18:0" [color=red, label="offset changed from 96 to 384"]
-  "19" [color=red, label="'int' -> 'int[49]'"]
+  "19" [color=red, label="'int' → 'int[49]'"]
   "18" -> "19" [label=""]
   "13" -> "18" [label=""]
-  "20" [color=red, label="'int E' -> 'int* E[7]'"]
+  "20" [color=red, label="'int E' → 'int* E[7]'"]
   "20" -> "20:0"
   "20:0" [color=red, label="offset changed from 128 to 1984"]
-  "21" [color=red, label="'int' -> 'int*[7]'"]
+  "21" [color=red, label="'int' → 'int*[7]'"]
   "20" -> "21" [label=""]
   "13" -> "20" [label=""]
-  "22" [color=red, label="'int F' -> 'int(* F[7])()'"]
+  "22" [color=red, label="'int F' → 'int(* F[7])()'"]
   "22" -> "22:0"
   "22:0" [color=red, label="offset changed from 160 to 2432"]
-  "23" [color=red, label="'int' -> 'int(*[7])()'"]
+  "23" [color=red, label="'int' → 'int(*[7])()'"]
   "22" -> "23" [label=""]
   "13" -> "22" [label=""]
-  "24" [color=red, label="'int G' -> 'int(* G)[7]'"]
+  "24" [color=red, label="'int G' → 'int(* G)[7]'"]
   "24" -> "24:0"
   "24:0" [color=red, label="offset changed from 192 to 2880"]
   "24" -> "3" [label=""]
   "13" -> "24" [label=""]
-  "25" [color=red, label="'int H' -> 'int** H'"]
+  "25" [color=red, label="'int H' → 'int** H'"]
   "25" -> "25:0"
   "25:0" [color=red, label="offset changed from 224 to 2944"]
-  "26" [color=red, label="'int' -> 'int**'"]
+  "26" [color=red, label="'int' → 'int**'"]
   "25" -> "26" [label=""]
   "13" -> "25" [label=""]
-  "27" [color=red, label="'int I' -> 'int(* I)()'"]
+  "27" [color=red, label="'int I' → 'int(* I)()'"]
   "27" -> "27:0"
   "27:0" [color=red, label="offset changed from 256 to 3008"]
   "27" -> "9" [label=""]
   "13" -> "27" [label=""]
-  "28" [color=red, label="'int J' -> 'int(*(* J)())[7]'"]
+  "28" [color=red, label="'int J' → 'int(*(* J)())[7]'"]
   "28" -> "28:0"
   "28:0" [color=red, label="offset changed from 288 to 3072"]
-  "29" [color=red, label="'int' -> 'int(*(*)())[7]'"]
+  "29" [color=red, label="'int' → 'int(*(*)())[7]'"]
   "28" -> "29" [label=""]
   "13" -> "28" [label=""]
-  "30" [color=red, label="'int K' -> 'int*(* K)()'"]
+  "30" [color=red, label="'int K' → 'int*(* K)()'"]
   "30" -> "30:0"
   "30:0" [color=red, label="offset changed from 320 to 3136"]
-  "31" [color=red, label="'int' -> 'int*(*)()'"]
+  "31" [color=red, label="'int' → 'int*(*)()'"]
   "30" -> "31" [label=""]
   "13" -> "30" [label=""]
-  "32" [color=red, label="'int L' -> 'int(*(* L)())()'"]
+  "32" [color=red, label="'int L' → 'int(*(* L)())()'"]
   "32" -> "32:0"
   "32:0" [color=red, label="offset changed from 352 to 3200"]
-  "33" [color=red, label="'int' -> 'int(*(*)())()'"]
+  "33" [color=red, label="'int' → 'int(*(*)())()'"]
   "32" -> "33" [label=""]
   "13" -> "32" [label=""]
-  "34" [color=red, label="'int a' -> 'volatile int a[7]'"]
+  "34" [color=red, label="'int a' → 'volatile int a[7]'"]
   "34" -> "34:0"
   "34:0" [color=red, label="offset changed from 384 to 3264"]
-  "35" [color=red, label="'int' -> 'volatile int[7]'"]
+  "35" [color=red, label="'int' → 'volatile int[7]'"]
   "34" -> "35" [label=""]
   "13" -> "34" [label=""]
-  "36" [color=red, label="'int b' -> 'volatile int* const b'"]
+  "36" [color=red, label="'int b' → 'volatile int* const b'"]
   "36" -> "36:0"
   "36:0" [color=red, label="offset changed from 416 to 3520"]
-  "37" [color=red, label="'int' -> 'volatile int* const'"]
+  "37" [color=red, label="'int' → 'volatile int* const'"]
   "37" -> "37:0"
   "37:0" [color=red, label="qualifier const added"]
-  "38" [color=red, label="'int' -> 'volatile int*'"]
+  "38" [color=red, label="'int' → 'volatile int*'"]
   "37" -> "38" [label="underlying"]
   "36" -> "37" [label=""]
   "13" -> "36" [label=""]
-  "39" [color=red, label="'int c' -> 'int(* const c)()'"]
+  "39" [color=red, label="'int c' → 'int(* const c)()'"]
   "39" -> "39:0"
   "39:0" [color=red, label="offset changed from 448 to 3584"]
-  "40" [color=red, label="'int' -> 'int(* const)()'"]
+  "40" [color=red, label="'int' → 'int(* const)()'"]
   "40" -> "40:0"
   "40:0" [color=red, label="qualifier const added"]
   "40" -> "9" [label="underlying"]
   "39" -> "40" [label=""]
   "13" -> "39" [label=""]
-  "41" [color=red, label="'int d' -> 'volatile int d[49]'"]
+  "41" [color=red, label="'int d' → 'volatile int d[49]'"]
   "41" -> "41:0"
   "41:0" [color=red, label="offset changed from 480 to 3648"]
-  "42" [color=red, label="'int' -> 'volatile int[49]'"]
+  "42" [color=red, label="'int' → 'volatile int[49]'"]
   "41" -> "42" [label=""]
   "13" -> "41" [label=""]
-  "43" [color=red, label="'int e' -> 'volatile int* const e[7]'"]
+  "43" [color=red, label="'int e' → 'volatile int* const e[7]'"]
   "43" -> "43:0"
   "43:0" [color=red, label="offset changed from 512 to 5248"]
-  "44" [color=red, label="'int' -> 'volatile int* const[7]'"]
+  "44" [color=red, label="'int' → 'volatile int* const[7]'"]
   "43" -> "44" [label=""]
   "13" -> "43" [label=""]
-  "45" [color=red, label="'int f' -> 'int(* const f[7])()'"]
+  "45" [color=red, label="'int f' → 'int(* const f[7])()'"]
   "45" -> "45:0"
   "45:0" [color=red, label="offset changed from 544 to 5696"]
-  "46" [color=red, label="'int' -> 'int(* const[7])()'"]
+  "46" [color=red, label="'int' → 'int(* const[7])()'"]
   "45" -> "46" [label=""]
   "13" -> "45" [label=""]
-  "47" [color=red, label="'int g' -> 'volatile int(* const g)[7]'"]
+  "47" [color=red, label="'int g' → 'volatile int(* const g)[7]'"]
   "47" -> "47:0"
   "47:0" [color=red, label="offset changed from 576 to 6144"]
-  "48" [color=red, label="'int' -> 'volatile int(* const)[7]'"]
+  "48" [color=red, label="'int' → 'volatile int(* const)[7]'"]
   "48" -> "48:0"
   "48:0" [color=red, label="qualifier const added"]
-  "49" [color=red, label="'int' -> 'volatile int(*)[7]'"]
+  "49" [color=red, label="'int' → 'volatile int(*)[7]'"]
   "48" -> "49" [label="underlying"]
   "47" -> "48" [label=""]
   "13" -> "47" [label=""]
-  "50" [color=red, label="'int h' -> 'volatile int* const* const h'"]
+  "50" [color=red, label="'int h' → 'volatile int* const* const h'"]
   "50" -> "50:0"
   "50:0" [color=red, label="offset changed from 608 to 6208"]
-  "51" [color=red, label="'int' -> 'volatile int* const* const'"]
+  "51" [color=red, label="'int' → 'volatile int* const* const'"]
   "51" -> "51:0"
   "51:0" [color=red, label="qualifier const added"]
-  "52" [color=red, label="'int' -> 'volatile int* const*'"]
+  "52" [color=red, label="'int' → 'volatile int* const*'"]
   "51" -> "52" [label="underlying"]
   "50" -> "51" [label=""]
   "13" -> "50" [label=""]
-  "53" [color=red, label="'int i' -> 'int(* const i)()'"]
+  "53" [color=red, label="'int i' → 'int(* const i)()'"]
   "53" -> "53:0"
   "53:0" [color=red, label="offset changed from 640 to 6272"]
   "53" -> "40" [label=""]
   "13" -> "53" [label=""]
-  "54" [color=red, label="'int j' -> 'volatile int(*(* const j)())[7]'"]
+  "54" [color=red, label="'int j' → 'volatile int(*(* const j)())[7]'"]
   "54" -> "54:0"
   "54:0" [color=red, label="offset changed from 672 to 6336"]
-  "55" [color=red, label="'int' -> 'volatile int(*(* const)())[7]'"]
+  "55" [color=red, label="'int' → 'volatile int(*(* const)())[7]'"]
   "55" -> "55:0"
   "55:0" [color=red, label="qualifier const added"]
-  "56" [color=red, label="'int' -> 'volatile int(*(*)())[7]'"]
+  "56" [color=red, label="'int' → 'volatile int(*(*)())[7]'"]
   "55" -> "56" [label="underlying"]
   "54" -> "55" [label=""]
   "13" -> "54" [label=""]
-  "57" [color=red, label="'int k' -> 'volatile int*(* const k)()'"]
+  "57" [color=red, label="'int k' → 'volatile int*(* const k)()'"]
   "57" -> "57:0"
   "57:0" [color=red, label="offset changed from 704 to 6400"]
-  "58" [color=red, label="'int' -> 'volatile int*(* const)()'"]
+  "58" [color=red, label="'int' → 'volatile int*(* const)()'"]
   "58" -> "58:0"
   "58:0" [color=red, label="qualifier const added"]
-  "59" [color=red, label="'int' -> 'volatile int*(*)()'"]
+  "59" [color=red, label="'int' → 'volatile int*(*)()'"]
   "58" -> "59" [label="underlying"]
   "57" -> "58" [label=""]
   "13" -> "57" [label=""]
-  "60" [color=red, label="'int l' -> 'int(*(* const l)())()'"]
+  "60" [color=red, label="'int l' → 'int(*(* const l)())()'"]
   "60" -> "60:0"
   "60:0" [color=red, label="offset changed from 736 to 6464"]
-  "61" [color=red, label="'int' -> 'int(*(* const)())()'"]
+  "61" [color=red, label="'int' → 'int(*(* const)())()'"]
   "61" -> "61:0"
   "61:0" [color=red, label="qualifier const added"]
   "61" -> "33" [label="underlying"]
@@ -191,17 +191,17 @@ digraph "ABI diff" {
   "11" -> "12" [label="return"]
   "10" -> "11" [label=""]
   "0" -> "10" [label=""]
-  "62" [label="'int n()' -> 'volatile int(* n())[7]'"]
-  "63" [label="'int()' -> 'volatile int(*())[7]'"]
+  "62" [label="'int n()' → 'volatile int(* n())[7]'"]
+  "63" [label="'int()' → 'volatile int(*())[7]'"]
   "63" -> "49" [label="return"]
   "62" -> "63" [label=""]
   "0" -> "62" [label=""]
-  "64" [label="'int o()' -> 'volatile int* o()'"]
-  "65" [label="'int()' -> 'volatile int*()'"]
+  "64" [label="'int o()' → 'volatile int* o()'"]
+  "65" [label="'int()' → 'volatile int*()'"]
   "65" -> "38" [label="return"]
   "64" -> "65" [label=""]
   "0" -> "64" [label=""]
-  "66" [label="'int p()' -> 'int(* p())()'"]
+  "66" [label="'int p()' → 'int(* p())()'"]
   "66" -> "8" [label=""]
   "0" -> "66" [label=""]
 }
diff --git a/test_cases/diff_tests/describe/expected/types_c.o_o_viz b/test_cases/diff_tests/describe/expected/types_c.o_o_viz
index f038944..04947d3 100644
--- a/test_cases/diff_tests/describe/expected/types_c.o_o_viz
+++ b/test_cases/diff_tests/describe/expected/types_c.o_o_viz
@@ -1,20 +1,20 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int N()' -> 'int(* N())[7]'"]
-  "2" [label="'int()' -> 'int(*())[7]'"]
-  "3" [color=red, label="'int' -> 'int(*)[7]'"]
+  "1" [label="'int N()' → 'int(* N())[7]'"]
+  "2" [label="'int()' → 'int(*())[7]'"]
+  "3" [color=red, label="'int' → 'int(*)[7]'"]
   "2" -> "3" [label="return"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "4" [label="'int O()' -> 'int* O()'"]
-  "5" [label="'int()' -> 'int*()'"]
-  "6" [color=red, label="'int' -> 'int*'"]
+  "4" [label="'int O()' → 'int* O()'"]
+  "5" [label="'int()' → 'int*()'"]
+  "6" [color=red, label="'int' → 'int*'"]
   "5" -> "6" [label="return"]
   "4" -> "5" [label=""]
   "0" -> "4" [label=""]
-  "7" [label="'int P()' -> 'int(* P())()'"]
-  "8" [label="'int()' -> 'int(*())()'"]
-  "9" [color=red, label="'int' -> 'int(*)()'"]
+  "7" [label="'int P()' → 'int(* P())()'"]
+  "8" [label="'int()' → 'int(*())()'"]
+  "9" [color=red, label="'int' → 'int(*)()'"]
   "8" -> "9" [label="return"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
@@ -24,164 +24,164 @@ digraph "ABI diff" {
   "13" [color=red, shape=rectangle, label="'struct amusement'"]
   "13" -> "13:0"
   "13:0" [color=red, label="byte size changed from 96 to 816"]
-  "14" [label="'int A' -> 'int A[7]'"]
-  "15" [color=red, label="'int' -> 'int[7]'"]
+  "14" [label="'int A' → 'int A[7]'"]
+  "15" [color=red, label="'int' → 'int[7]'"]
   "14" -> "15" [label=""]
   "13" -> "14" [label=""]
-  "16" [color=red, label="'int B' -> 'int* B'"]
+  "16" [color=red, label="'int B' → 'int* B'"]
   "16" -> "16:0"
   "16:0" [color=red, label="offset changed from 32 to 256"]
   "16" -> "6" [label=""]
   "13" -> "16" [label=""]
-  "17" [color=red, label="'int C' -> 'int(* C)()'"]
+  "17" [color=red, label="'int C' → 'int(* C)()'"]
   "17" -> "17:0"
   "17:0" [color=red, label="offset changed from 64 to 320"]
   "17" -> "9" [label=""]
   "13" -> "17" [label=""]
-  "18" [color=red, label="'int D' -> 'int D[7][7]'"]
+  "18" [color=red, label="'int D' → 'int D[7][7]'"]
   "18" -> "18:0"
   "18:0" [color=red, label="offset changed from 96 to 384"]
-  "19" [color=red, label="'int' -> 'int[7][7]'"]
+  "19" [color=red, label="'int' → 'int[7][7]'"]
   "18" -> "19" [label=""]
   "13" -> "18" [label=""]
-  "20" [color=red, label="'int E' -> 'int* E[7]'"]
+  "20" [color=red, label="'int E' → 'int* E[7]'"]
   "20" -> "20:0"
   "20:0" [color=red, label="offset changed from 128 to 1984"]
-  "21" [color=red, label="'int' -> 'int*[7]'"]
+  "21" [color=red, label="'int' → 'int*[7]'"]
   "20" -> "21" [label=""]
   "13" -> "20" [label=""]
-  "22" [color=red, label="'int F' -> 'int(* F[7])()'"]
+  "22" [color=red, label="'int F' → 'int(* F[7])()'"]
   "22" -> "22:0"
   "22:0" [color=red, label="offset changed from 160 to 2432"]
-  "23" [color=red, label="'int' -> 'int(*[7])()'"]
+  "23" [color=red, label="'int' → 'int(*[7])()'"]
   "22" -> "23" [label=""]
   "13" -> "22" [label=""]
-  "24" [color=red, label="'int G' -> 'int(* G)[7]'"]
+  "24" [color=red, label="'int G' → 'int(* G)[7]'"]
   "24" -> "24:0"
   "24:0" [color=red, label="offset changed from 192 to 2880"]
   "24" -> "3" [label=""]
   "13" -> "24" [label=""]
-  "25" [color=red, label="'int H' -> 'int** H'"]
+  "25" [color=red, label="'int H' → 'int** H'"]
   "25" -> "25:0"
   "25:0" [color=red, label="offset changed from 224 to 2944"]
-  "26" [color=red, label="'int' -> 'int**'"]
+  "26" [color=red, label="'int' → 'int**'"]
   "25" -> "26" [label=""]
   "13" -> "25" [label=""]
-  "27" [color=red, label="'int I' -> 'int(* I)()'"]
+  "27" [color=red, label="'int I' → 'int(* I)()'"]
   "27" -> "27:0"
   "27:0" [color=red, label="offset changed from 256 to 3008"]
   "27" -> "9" [label=""]
   "13" -> "27" [label=""]
-  "28" [color=red, label="'int J' -> 'int(*(* J)())[7]'"]
+  "28" [color=red, label="'int J' → 'int(*(* J)())[7]'"]
   "28" -> "28:0"
   "28:0" [color=red, label="offset changed from 288 to 3072"]
-  "29" [color=red, label="'int' -> 'int(*(*)())[7]'"]
+  "29" [color=red, label="'int' → 'int(*(*)())[7]'"]
   "28" -> "29" [label=""]
   "13" -> "28" [label=""]
-  "30" [color=red, label="'int K' -> 'int*(* K)()'"]
+  "30" [color=red, label="'int K' → 'int*(* K)()'"]
   "30" -> "30:0"
   "30:0" [color=red, label="offset changed from 320 to 3136"]
-  "31" [color=red, label="'int' -> 'int*(*)()'"]
+  "31" [color=red, label="'int' → 'int*(*)()'"]
   "30" -> "31" [label=""]
   "13" -> "30" [label=""]
-  "32" [color=red, label="'int L' -> 'int(*(* L)())()'"]
+  "32" [color=red, label="'int L' → 'int(*(* L)())()'"]
   "32" -> "32:0"
   "32:0" [color=red, label="offset changed from 352 to 3200"]
-  "33" [color=red, label="'int' -> 'int(*(*)())()'"]
+  "33" [color=red, label="'int' → 'int(*(*)())()'"]
   "32" -> "33" [label=""]
   "13" -> "32" [label=""]
-  "34" [color=red, label="'int a' -> 'volatile int a[7]'"]
+  "34" [color=red, label="'int a' → 'volatile int a[7]'"]
   "34" -> "34:0"
   "34:0" [color=red, label="offset changed from 384 to 3264"]
-  "35" [color=red, label="'int' -> 'volatile int[7]'"]
+  "35" [color=red, label="'int' → 'volatile int[7]'"]
   "34" -> "35" [label=""]
   "13" -> "34" [label=""]
-  "36" [color=red, label="'int b' -> 'volatile int* const b'"]
+  "36" [color=red, label="'int b' → 'volatile int* const b'"]
   "36" -> "36:0"
   "36:0" [color=red, label="offset changed from 416 to 3520"]
-  "37" [color=red, label="'int' -> 'volatile int* const'"]
+  "37" [color=red, label="'int' → 'volatile int* const'"]
   "37" -> "37:0"
   "37:0" [color=red, label="qualifier const added"]
-  "38" [color=red, label="'int' -> 'volatile int*'"]
+  "38" [color=red, label="'int' → 'volatile int*'"]
   "37" -> "38" [label="underlying"]
   "36" -> "37" [label=""]
   "13" -> "36" [label=""]
-  "39" [color=red, label="'int c' -> 'int(* const c)()'"]
+  "39" [color=red, label="'int c' → 'int(* const c)()'"]
   "39" -> "39:0"
   "39:0" [color=red, label="offset changed from 448 to 3584"]
-  "40" [color=red, label="'int' -> 'int(* const)()'"]
+  "40" [color=red, label="'int' → 'int(* const)()'"]
   "40" -> "40:0"
   "40:0" [color=red, label="qualifier const added"]
   "40" -> "9" [label="underlying"]
   "39" -> "40" [label=""]
   "13" -> "39" [label=""]
-  "41" [color=red, label="'int d' -> 'volatile int d[7][7]'"]
+  "41" [color=red, label="'int d' → 'volatile int d[7][7]'"]
   "41" -> "41:0"
   "41:0" [color=red, label="offset changed from 480 to 3648"]
-  "42" [color=red, label="'int' -> 'volatile int[7][7]'"]
+  "42" [color=red, label="'int' → 'volatile int[7][7]'"]
   "41" -> "42" [label=""]
   "13" -> "41" [label=""]
-  "43" [color=red, label="'int e' -> 'volatile int* const e[7]'"]
+  "43" [color=red, label="'int e' → 'volatile int* const e[7]'"]
   "43" -> "43:0"
   "43:0" [color=red, label="offset changed from 512 to 5248"]
-  "44" [color=red, label="'int' -> 'volatile int* const[7]'"]
+  "44" [color=red, label="'int' → 'volatile int* const[7]'"]
   "43" -> "44" [label=""]
   "13" -> "43" [label=""]
-  "45" [color=red, label="'int f' -> 'int(* const f[7])()'"]
+  "45" [color=red, label="'int f' → 'int(* const f[7])()'"]
   "45" -> "45:0"
   "45:0" [color=red, label="offset changed from 544 to 5696"]
-  "46" [color=red, label="'int' -> 'int(* const[7])()'"]
+  "46" [color=red, label="'int' → 'int(* const[7])()'"]
   "45" -> "46" [label=""]
   "13" -> "45" [label=""]
-  "47" [color=red, label="'int g' -> 'volatile int(* const g)[7]'"]
+  "47" [color=red, label="'int g' → 'volatile int(* const g)[7]'"]
   "47" -> "47:0"
   "47:0" [color=red, label="offset changed from 576 to 6144"]
-  "48" [color=red, label="'int' -> 'volatile int(* const)[7]'"]
+  "48" [color=red, label="'int' → 'volatile int(* const)[7]'"]
   "48" -> "48:0"
   "48:0" [color=red, label="qualifier const added"]
-  "49" [color=red, label="'int' -> 'volatile int(*)[7]'"]
+  "49" [color=red, label="'int' → 'volatile int(*)[7]'"]
   "48" -> "49" [label="underlying"]
   "47" -> "48" [label=""]
   "13" -> "47" [label=""]
-  "50" [color=red, label="'int h' -> 'volatile int* const* const h'"]
+  "50" [color=red, label="'int h' → 'volatile int* const* const h'"]
   "50" -> "50:0"
   "50:0" [color=red, label="offset changed from 608 to 6208"]
-  "51" [color=red, label="'int' -> 'volatile int* const* const'"]
+  "51" [color=red, label="'int' → 'volatile int* const* const'"]
   "51" -> "51:0"
   "51:0" [color=red, label="qualifier const added"]
-  "52" [color=red, label="'int' -> 'volatile int* const*'"]
+  "52" [color=red, label="'int' → 'volatile int* const*'"]
   "51" -> "52" [label="underlying"]
   "50" -> "51" [label=""]
   "13" -> "50" [label=""]
-  "53" [color=red, label="'int i' -> 'int(* const i)()'"]
+  "53" [color=red, label="'int i' → 'int(* const i)()'"]
   "53" -> "53:0"
   "53:0" [color=red, label="offset changed from 640 to 6272"]
   "53" -> "40" [label=""]
   "13" -> "53" [label=""]
-  "54" [color=red, label="'int j' -> 'volatile int(*(* const j)())[7]'"]
+  "54" [color=red, label="'int j' → 'volatile int(*(* const j)())[7]'"]
   "54" -> "54:0"
   "54:0" [color=red, label="offset changed from 672 to 6336"]
-  "55" [color=red, label="'int' -> 'volatile int(*(* const)())[7]'"]
+  "55" [color=red, label="'int' → 'volatile int(*(* const)())[7]'"]
   "55" -> "55:0"
   "55:0" [color=red, label="qualifier const added"]
-  "56" [color=red, label="'int' -> 'volatile int(*(*)())[7]'"]
+  "56" [color=red, label="'int' → 'volatile int(*(*)())[7]'"]
   "55" -> "56" [label="underlying"]
   "54" -> "55" [label=""]
   "13" -> "54" [label=""]
-  "57" [color=red, label="'int k' -> 'volatile int*(* const k)()'"]
+  "57" [color=red, label="'int k' → 'volatile int*(* const k)()'"]
   "57" -> "57:0"
   "57:0" [color=red, label="offset changed from 704 to 6400"]
-  "58" [color=red, label="'int' -> 'volatile int*(* const)()'"]
+  "58" [color=red, label="'int' → 'volatile int*(* const)()'"]
   "58" -> "58:0"
   "58:0" [color=red, label="qualifier const added"]
-  "59" [color=red, label="'int' -> 'volatile int*(*)()'"]
+  "59" [color=red, label="'int' → 'volatile int*(*)()'"]
   "58" -> "59" [label="underlying"]
   "57" -> "58" [label=""]
   "13" -> "57" [label=""]
-  "60" [color=red, label="'int l' -> 'int(*(* const l)())()'"]
+  "60" [color=red, label="'int l' → 'int(*(* const l)())()'"]
   "60" -> "60:0"
   "60:0" [color=red, label="offset changed from 736 to 6464"]
-  "61" [color=red, label="'int' -> 'int(*(* const)())()'"]
+  "61" [color=red, label="'int' → 'int(*(* const)())()'"]
   "61" -> "61:0"
   "61:0" [color=red, label="qualifier const added"]
   "61" -> "33" [label="underlying"]
@@ -191,18 +191,18 @@ digraph "ABI diff" {
   "11" -> "12" [label="return"]
   "10" -> "11" [label=""]
   "0" -> "10" [label=""]
-  "62" [label="'int n()' -> 'volatile int(* n())[7]'"]
-  "63" [label="'int()' -> 'volatile int(*())[7]'"]
+  "62" [label="'int n()' → 'volatile int(* n())[7]'"]
+  "63" [label="'int()' → 'volatile int(*())[7]'"]
   "63" -> "49" [label="return"]
   "62" -> "63" [label=""]
   "0" -> "62" [label=""]
-  "64" [label="'int o()' -> 'volatile int* o()'"]
-  "65" [label="'int()' -> 'volatile int*()'"]
+  "64" [label="'int o()' → 'volatile int* o()'"]
+  "65" [label="'int()' → 'volatile int*()'"]
   "65" -> "38" [label="return"]
   "64" -> "65" [label=""]
   "0" -> "64" [label=""]
-  "66" [label="'int p()' -> 'int(* p())()'"]
-  "67" [label="'int()' -> 'int(*())()'"]
+  "66" [label="'int p()' → 'int(* p())()'"]
+  "67" [label="'int()' → 'int(*())()'"]
   "67" -> "9" [label="return"]
   "66" -> "67" [label=""]
   "0" -> "66" [label=""]
diff --git a/test_cases/diff_tests/enum/expected/automatic_underlying_type_c.btf_btf_viz b/test_cases/diff_tests/enum/expected/automatic_underlying_type_c.btf_btf_viz
index 040b82a..7acbe41 100644
--- a/test_cases/diff_tests/enum/expected/automatic_underlying_type_c.btf_btf_viz
+++ b/test_cases/diff_tests/enum/expected/automatic_underlying_type_c.btf_btf_viz
@@ -3,7 +3,7 @@ digraph "ABI diff" {
   "1" [label="'unsigned int fun(enum A, enum B, enum C, enum D)'"]
   "2" [label="'unsigned int(enum A, enum B, enum C, enum D)'"]
   "3" [color=red, shape=rectangle, label="'enum A'"]
-  "4" [color=red, label="'enum-underlying-unsigned-32' -> 'enum-underlying-unsigned-64'"]
+  "4" [color=red, label="'enum-underlying-unsigned-32' → 'enum-underlying-unsigned-64'"]
   "3" -> "4" [label="underlying"]
   "3" -> "3:0"
   "3:0" [color=red, label="enumerator 'Ae' value changed from 16777216 to 281474976710656"]
@@ -13,13 +13,13 @@ digraph "ABI diff" {
   "5:0" [color=red, label="enumerator 'Be' value changed from 2147483647 to 2147483648"]
   "2" -> "5" [label="parameter 2"]
   "6" [color=red, shape=rectangle, label="'enum C'"]
-  "7" [color=red, label="'enum-underlying-signed-64' -> 'enum-underlying-unsigned-64'"]
+  "7" [color=red, label="'enum-underlying-signed-64' → 'enum-underlying-unsigned-64'"]
   "6" -> "7" [label="underlying"]
   "6" -> "6:0"
   "6:0" [color=red, label="enumerator 'Ce' value changed from -9223372036854775808 to -1"]
   "2" -> "6" [label="parameter 3"]
   "8" [color=red, shape=rectangle, label="'enum D'"]
-  "9" [color=red, label="'enum-underlying-signed-32' -> 'enum-underlying-unsigned-32'"]
+  "9" [color=red, label="'enum-underlying-signed-32' → 'enum-underlying-unsigned-32'"]
   "8" -> "9" [label="underlying"]
   "8" -> "8:0"
   "8:0" [color=red, label="enumerator 'De' value changed from -1 to 1"]
diff --git a/test_cases/diff_tests/enum/expected/automatic_underlying_type_c.o_o_viz b/test_cases/diff_tests/enum/expected/automatic_underlying_type_c.o_o_viz
index 82eb2eb..a422c5f 100644
--- a/test_cases/diff_tests/enum/expected/automatic_underlying_type_c.o_o_viz
+++ b/test_cases/diff_tests/enum/expected/automatic_underlying_type_c.o_o_viz
@@ -3,7 +3,7 @@ digraph "ABI diff" {
   "1" [label="'unsigned int fun(enum A, enum B, enum C, enum D)'"]
   "2" [label="'unsigned int(enum A, enum B, enum C, enum D)'"]
   "3" [color=red, shape=rectangle, label="'enum A'"]
-  "4" [color=red, label="'unsigned int' -> 'unsigned long'"]
+  "4" [color=red, label="'unsigned int' → 'unsigned long'"]
   "3" -> "4" [label="underlying"]
   "3" -> "3:0"
   "3:0" [color=red, label="enumerator 'Ae' value changed from 16777216 to 281474976710656"]
@@ -13,13 +13,13 @@ digraph "ABI diff" {
   "5:0" [color=red, label="enumerator 'Be' value changed from 2147483647 to 2147483648"]
   "2" -> "5" [label="parameter 2"]
   "6" [color=red, shape=rectangle, label="'enum C'"]
-  "7" [color=red, label="'long' -> 'unsigned long'"]
+  "7" [color=red, label="'long' → 'unsigned long'"]
   "6" -> "7" [label="underlying"]
   "6" -> "6:0"
   "6:0" [color=red, label="enumerator 'Ce' value changed from -9223372036854775808 to -1"]
   "2" -> "6" [label="parameter 3"]
   "8" [color=red, shape=rectangle, label="'enum D'"]
-  "9" [color=red, label="'int' -> 'unsigned int'"]
+  "9" [color=red, label="'int' → 'unsigned int'"]
   "8" -> "9" [label="underlying"]
   "8" -> "8:0"
   "8:0" [color=red, label="enumerator 'De' value changed from -1 to 1"]
diff --git a/test_cases/diff_tests/enum/expected/fixed_underlying_type_cc.o_o_viz b/test_cases/diff_tests/enum/expected/fixed_underlying_type_cc.o_o_viz
index 7f51c4c..4f082cd 100644
--- a/test_cases/diff_tests/enum/expected/fixed_underlying_type_cc.o_o_viz
+++ b/test_cases/diff_tests/enum/expected/fixed_underlying_type_cc.o_o_viz
@@ -3,11 +3,11 @@ digraph "ABI diff" {
   "1" [label="'unsigned int fun(enum A, enum B)' {_Z3fun1A1B}"]
   "2" [label="'unsigned int(enum A, enum B)'"]
   "3" [shape=rectangle, label="'enum A'"]
-  "4" [color=red, label="'signed char' -> 'unsigned char'"]
+  "4" [color=red, label="'signed char' → 'unsigned char'"]
   "3" -> "4" [label="underlying"]
   "2" -> "3" [label="parameter 1"]
   "5" [shape=rectangle, label="'enum B'"]
-  "6" [color=red, label="'signed char' -> 'unsigned long'"]
+  "6" [color=red, label="'signed char' → 'unsigned long'"]
   "5" -> "6" [label="underlying"]
   "2" -> "5" [label="parameter 2"]
   "1" -> "2" [label=""]
diff --git a/test_cases/diff_tests/enum/expected/named_change_c.o_o_viz b/test_cases/diff_tests/enum/expected/named_change_c.o_o_viz
index a40d935..d409f7d 100644
--- a/test_cases/diff_tests/enum/expected/named_change_c.o_o_viz
+++ b/test_cases/diff_tests/enum/expected/named_change_c.o_o_viz
@@ -1,11 +1,11 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'enum E1 v1' -> 'enum { a1 = 1, } v1'"]
-  "2" [color=red, label="'enum E1' -> 'enum { a1 = 1, }'"]
+  "1" [label="'enum E1 v1' → 'enum { a1 = 1, } v1'"]
+  "2" [color=red, label="'enum E1' → 'enum { a1 = 1, }'"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "3" [label="'enum { a2 = 2, } v2' -> 'enum E2 v2'"]
-  "4" [color=red, label="'enum { a2 = 2, }' -> 'enum E2'"]
+  "3" [label="'enum { a2 = 2, } v2' → 'enum E2 v2'"]
+  "4" [color=red, label="'enum { a2 = 2, }' → 'enum E2'"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
 }
diff --git a/test_cases/diff_tests/enum/expected/named_definition_change_c.o_o_viz b/test_cases/diff_tests/enum/expected/named_definition_change_c.o_o_viz
index 5eb85be..8d4fa63 100644
--- a/test_cases/diff_tests/enum/expected/named_definition_change_c.o_o_viz
+++ b/test_cases/diff_tests/enum/expected/named_definition_change_c.o_o_viz
@@ -1,11 +1,11 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'enum E1 v1' -> 'enum { a1 = 1, b1 = 1, } v1'"]
-  "2" [color=red, label="'enum E1' -> 'enum { a1 = 1, b1 = 1, }'"]
+  "1" [label="'enum E1 v1' → 'enum { a1 = 1, b1 = 1, } v1'"]
+  "2" [color=red, label="'enum E1' → 'enum { a1 = 1, b1 = 1, }'"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "3" [label="'enum { a2 = 2, } v2' -> 'enum E2 v2'"]
-  "4" [color=red, label="'enum { a2 = 2, }' -> 'enum E2'"]
+  "3" [label="'enum { a2 = 2, } v2' → 'enum E2 v2'"]
+  "4" [color=red, label="'enum { a2 = 2, }' → 'enum E2'"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
 }
diff --git a/test_cases/diff_tests/enum/expected/order_c.o_o_viz b/test_cases/diff_tests/enum/expected/order_c.o_o_viz
index 80a2e94..5a56ea9 100644
--- a/test_cases/diff_tests/enum/expected/order_c.o_o_viz
+++ b/test_cases/diff_tests/enum/expected/order_c.o_o_viz
@@ -1,7 +1,7 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'enum { one = 1, two = 2, four = 4, } v' -> 'enum { zero = 0, one = 1, two = 2, three = 3, four = 4, five = 5, } v'"]
-  "2" [color=red, label="'enum { one = 1, two = 2, four = 4, }' -> 'enum { zero = 0, one = 1, two = 2, three = 3, four = 4, five = 5, }'"]
+  "1" [label="'enum { one = 1, two = 2, four = 4, } v' → 'enum { zero = 0, one = 1, two = 2, three = 3, four = 4, five = 5, } v'"]
+  "2" [color=red, label="'enum { one = 1, two = 2, four = 4, }' → 'enum { zero = 0, one = 1, two = 2, three = 3, four = 4, five = 5, }'"]
   "2" -> "2:0"
   "2:0" [color=red, label="enumerator 'zero' (0) was added"]
   "2" -> "2:1"
diff --git a/test_cases/diff_tests/function/expected/array_parameter_c.o_o_viz b/test_cases/diff_tests/function/expected/array_parameter_c.o_o_viz
index 961b530..c1e572f 100644
--- a/test_cases/diff_tests/function/expected/array_parameter_c.o_o_viz
+++ b/test_cases/diff_tests/function/expected/array_parameter_c.o_o_viz
@@ -1,8 +1,8 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'const unsigned short l' -> 'const unsigned long l'"]
-  "2" [label="'const unsigned short' -> 'const unsigned long'"]
-  "3" [color=red, label="'unsigned short' -> 'unsigned long'"]
+  "1" [label="'const unsigned short l' → 'const unsigned long l'"]
+  "2" [label="'const unsigned short' → 'const unsigned long'"]
+  "3" [color=red, label="'unsigned short' → 'unsigned long'"]
   "2" -> "3" [label="underlying"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
diff --git a/test_cases/diff_tests/function/expected/methods_cc.o_o_viz b/test_cases/diff_tests/function/expected/methods_cc.o_o_viz
index 4204760..d41074c 100644
--- a/test_cases/diff_tests/function/expected/methods_cc.o_o_viz
+++ b/test_cases/diff_tests/function/expected/methods_cc.o_o_viz
@@ -16,15 +16,15 @@ digraph "ABI diff" {
   "0" -> "7" [label=""]
   "8" [color=red, label="added(int Func::change_parameter_type(struct Func*, long) {_ZN4Func21change_parameter_typeEl})"]
   "0" -> "8" [label=""]
-  "9" [label="'int Func::change_return_type(struct Func*)' {_ZN4Func18change_return_typeEv} -> 'long Func::change_return_type(struct Func*)' {_ZN4Func18change_return_typeEv}"]
-  "10" [label="'int(struct Func*)' -> 'long(struct Func*)'"]
-  "11" [color=red, label="'int' -> 'long'"]
+  "9" [label="'int Func::change_return_type(struct Func*)' {_ZN4Func18change_return_typeEv} → 'long Func::change_return_type(struct Func*)' {_ZN4Func18change_return_typeEv}"]
+  "10" [label="'int(struct Func*)' → 'long(struct Func*)'"]
+  "11" [color=red, label="'int' → 'long'"]
   "10" -> "11" [label="return"]
   "12" [label="'struct Func*'"]
   "13" [color=red, shape=rectangle, label="'struct Func'"]
   "13" -> "13:0"
   "13:0" [color=red, label="byte size changed from 4 to 8"]
-  "14" [label="'int x' -> 'long x'"]
+  "14" [label="'int x' → 'long x'"]
   "14" -> "11" [label=""]
   "13" -> "14" [label=""]
   "12" -> "13" [label="pointed-to"]
diff --git a/test_cases/diff_tests/function/expected/parameters_c.btf_btf_viz b/test_cases/diff_tests/function/expected/parameters_c.btf_btf_viz
index 13177ff..ddc6761 100644
--- a/test_cases/diff_tests/function/expected/parameters_c.btf_btf_viz
+++ b/test_cases/diff_tests/function/expected/parameters_c.btf_btf_viz
@@ -1,39 +1,39 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int f01(int, int, int)' -> 'int f01(int, int)'"]
-  "2" [label="'int(int, int, int)' -> 'int(int, int)'"]
+  "1" [label="'int f01(int, int, int)' → 'int f01(int, int)'"]
+  "2" [label="'int(int, int, int)' → 'int(int, int)'"]
   "3" [color=red, label="removed(int)"]
   "2" -> "3" [label="parameter 3 of"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "4" [label="'int f02(int, int, int)' -> 'int f02(int, int)'"]
-  "5" [label="'int(int, int, int)' -> 'int(int, int)'"]
+  "4" [label="'int f02(int, int, int)' → 'int f02(int, int)'"]
+  "5" [label="'int(int, int, int)' → 'int(int, int)'"]
   "5" -> "3" [label="parameter 3 of"]
   "4" -> "5" [label=""]
   "0" -> "4" [label=""]
-  "6" [label="'int f03(int, int, int)' -> 'int f03(int, int)'"]
-  "7" [label="'int(int, int, int)' -> 'int(int, int)'"]
+  "6" [label="'int f03(int, int, int)' → 'int f03(int, int)'"]
+  "7" [label="'int(int, int, int)' → 'int(int, int)'"]
   "7" -> "3" [label="parameter 3 of"]
   "6" -> "7" [label=""]
   "0" -> "6" [label=""]
-  "8" [label="'int f09(int, int, int)' -> 'int f09(int, int, int, int)'"]
-  "9" [label="'int(int, int, int)' -> 'int(int, int, int, int)'"]
+  "8" [label="'int f09(int, int, int)' → 'int f09(int, int, int, int)'"]
+  "9" [label="'int(int, int, int)' → 'int(int, int, int, int)'"]
   "10" [color=red, label="added(int)"]
   "9" -> "10" [label="parameter 4 of"]
   "8" -> "9" [label=""]
   "0" -> "8" [label=""]
-  "11" [label="'int f10(int, int, int)' -> 'int f10(int, int, int, int)'"]
-  "12" [label="'int(int, int, int)' -> 'int(int, int, int, int)'"]
+  "11" [label="'int f10(int, int, int)' → 'int f10(int, int, int, int)'"]
+  "12" [label="'int(int, int, int)' → 'int(int, int, int, int)'"]
   "12" -> "10" [label="parameter 4 of"]
   "11" -> "12" [label=""]
   "0" -> "11" [label=""]
-  "13" [label="'int f11(int, int, int)' -> 'int f11(int, int, int, int)'"]
-  "14" [label="'int(int, int, int)' -> 'int(int, int, int, int)'"]
+  "13" [label="'int f11(int, int, int)' → 'int f11(int, int, int, int)'"]
+  "14" [label="'int(int, int, int)' → 'int(int, int, int, int)'"]
   "14" -> "10" [label="parameter 4 of"]
   "13" -> "14" [label=""]
   "0" -> "13" [label=""]
-  "15" [label="'int f12(int, int, int)' -> 'int f12(int, int, int, int)'"]
-  "16" [label="'int(int, int, int)' -> 'int(int, int, int, int)'"]
+  "15" [label="'int f12(int, int, int)' → 'int f12(int, int, int, int)'"]
+  "16" [label="'int(int, int, int)' → 'int(int, int, int, int)'"]
   "16" -> "10" [label="parameter 4 of"]
   "15" -> "16" [label=""]
   "0" -> "15" [label=""]
diff --git a/test_cases/diff_tests/function/expected/parameters_c.o_o_viz b/test_cases/diff_tests/function/expected/parameters_c.o_o_viz
index 8f8966e..2187a1b 100644
--- a/test_cases/diff_tests/function/expected/parameters_c.o_o_viz
+++ b/test_cases/diff_tests/function/expected/parameters_c.o_o_viz
@@ -1,71 +1,71 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int f01(int, int, int)' -> 'int f01(int, int)'"]
-  "2" [label="'int(int, int, int)' -> 'int(int, int)'"]
+  "1" [label="'int f01(int, int, int)' → 'int f01(int, int)'"]
+  "2" [label="'int(int, int, int)' → 'int(int, int)'"]
   "3" [color=red, label="removed(int)"]
   "2" -> "3" [label="parameter 3 of"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "4" [label="'int f02(int, int, int)' -> 'int f02(int, int)'"]
-  "5" [label="'int(int, int, int)' -> 'int(int, int)'"]
+  "4" [label="'int f02(int, int, int)' → 'int f02(int, int)'"]
+  "5" [label="'int(int, int, int)' → 'int(int, int)'"]
   "5" -> "3" [label="parameter 3 of"]
   "4" -> "5" [label=""]
   "0" -> "4" [label=""]
-  "6" [label="'int f03(int, int, int)' -> 'int f03(int, int)'"]
-  "7" [label="'int(int, int, int)' -> 'int(int, int)'"]
+  "6" [label="'int f03(int, int, int)' → 'int f03(int, int)'"]
+  "7" [label="'int(int, int, int)' → 'int(int, int)'"]
   "7" -> "3" [label="parameter 3 of"]
   "6" -> "7" [label=""]
   "0" -> "6" [label=""]
-  "8" [label="'int f09(int, int, int)' -> 'int f09(int, int, int, int)'"]
-  "9" [label="'int(int, int, int)' -> 'int(int, int, int, int)'"]
+  "8" [label="'int f09(int, int, int)' → 'int f09(int, int, int, int)'"]
+  "9" [label="'int(int, int, int)' → 'int(int, int, int, int)'"]
   "10" [color=red, label="added(int)"]
   "9" -> "10" [label="parameter 4 of"]
   "8" -> "9" [label=""]
   "0" -> "8" [label=""]
-  "11" [label="'int f10(int, int, int)' -> 'int f10(int, int, int, int)'"]
-  "12" [label="'int(int, int, int)' -> 'int(int, int, int, int)'"]
+  "11" [label="'int f10(int, int, int)' → 'int f10(int, int, int, int)'"]
+  "12" [label="'int(int, int, int)' → 'int(int, int, int, int)'"]
   "12" -> "10" [label="parameter 4 of"]
   "11" -> "12" [label=""]
   "0" -> "11" [label=""]
-  "13" [label="'int f11(int, int, int)' -> 'int f11(int, int, int, int)'"]
-  "14" [label="'int(int, int, int)' -> 'int(int, int, int, int)'"]
+  "13" [label="'int f11(int, int, int)' → 'int f11(int, int, int, int)'"]
+  "14" [label="'int(int, int, int)' → 'int(int, int, int, int)'"]
   "14" -> "10" [label="parameter 4 of"]
   "13" -> "14" [label=""]
   "0" -> "13" [label=""]
-  "15" [label="'int f12(int, int, int)' -> 'int f12(int, int, int, int)'"]
-  "16" [label="'int(int, int, int)' -> 'int(int, int, int, int)'"]
+  "15" [label="'int f12(int, int, int)' → 'int f12(int, int, int, int)'"]
+  "16" [label="'int(int, int, int)' → 'int(int, int, int, int)'"]
   "16" -> "10" [label="parameter 4 of"]
   "15" -> "16" [label=""]
   "0" -> "15" [label=""]
   "17" [label="'struct S s'"]
   "18" [shape=rectangle, label="'struct S'"]
-  "19" [label="'int(* f01)(int, int, int)' -> 'int(* f01)(int, int)'"]
-  "20" [label="'int(*)(int, int, int)' -> 'int(*)(int, int)'"]
-  "21" [label="'int(int, int, int)' -> 'int(int, int)'"]
+  "19" [label="'int(* f01)(int, int, int)' → 'int(* f01)(int, int)'"]
+  "20" [label="'int(*)(int, int, int)' → 'int(*)(int, int)'"]
+  "21" [label="'int(int, int, int)' → 'int(int, int)'"]
   "21" -> "3" [label="parameter 3 of"]
   "20" -> "21" [label="pointed-to"]
   "19" -> "20" [label=""]
   "18" -> "19" [label=""]
-  "22" [label="'int(* f02)(int, int, int)' -> 'int(* f02)(int, int)'"]
+  "22" [label="'int(* f02)(int, int, int)' → 'int(* f02)(int, int)'"]
   "22" -> "20" [label=""]
   "18" -> "22" [label=""]
-  "23" [label="'int(* f03)(int, int, int)' -> 'int(* f03)(int, int)'"]
+  "23" [label="'int(* f03)(int, int, int)' → 'int(* f03)(int, int)'"]
   "23" -> "20" [label=""]
   "18" -> "23" [label=""]
-  "24" [label="'int(* f09)(int, int, int)' -> 'int(* f09)(int, int, int, int)'"]
-  "25" [label="'int(*)(int, int, int)' -> 'int(*)(int, int, int, int)'"]
-  "26" [label="'int(int, int, int)' -> 'int(int, int, int, int)'"]
+  "24" [label="'int(* f09)(int, int, int)' → 'int(* f09)(int, int, int, int)'"]
+  "25" [label="'int(*)(int, int, int)' → 'int(*)(int, int, int, int)'"]
+  "26" [label="'int(int, int, int)' → 'int(int, int, int, int)'"]
   "26" -> "10" [label="parameter 4 of"]
   "25" -> "26" [label="pointed-to"]
   "24" -> "25" [label=""]
   "18" -> "24" [label=""]
-  "27" [label="'int(* f10)(int, int, int)' -> 'int(* f10)(int, int, int, int)'"]
+  "27" [label="'int(* f10)(int, int, int)' → 'int(* f10)(int, int, int, int)'"]
   "27" -> "25" [label=""]
   "18" -> "27" [label=""]
-  "28" [label="'int(* f11)(int, int, int)' -> 'int(* f11)(int, int, int, int)'"]
+  "28" [label="'int(* f11)(int, int, int)' → 'int(* f11)(int, int, int, int)'"]
   "28" -> "25" [label=""]
   "18" -> "28" [label=""]
-  "29" [label="'int(* f12)(int, int, int)' -> 'int(* f12)(int, int, int, int)'"]
+  "29" [label="'int(* f12)(int, int, int)' → 'int(* f12)(int, int, int, int)'"]
   "29" -> "25" [label=""]
   "18" -> "29" [label=""]
   "17" -> "18" [label=""]
diff --git a/test_cases/diff_tests/function/expected/static_vs_non_virtual_cc.o_o_viz b/test_cases/diff_tests/function/expected/static_vs_non_virtual_cc.o_o_viz
index 143e48b..5d482a1 100644
--- a/test_cases/diff_tests/function/expected/static_vs_non_virtual_cc.o_o_viz
+++ b/test_cases/diff_tests/function/expected/static_vs_non_virtual_cc.o_o_viz
@@ -4,14 +4,14 @@ digraph "ABI diff" {
   "0" -> "1" [label=""]
   "2" [color=red, label="added(int NormalToStatic::st {_ZN14NormalToStatic2stE})"]
   "0" -> "2" [label=""]
-  "3" [label="'int NormalToStatic::print(struct NormalToStatic*)' {_ZN14NormalToStatic5printEv} -> 'int NormalToStatic::print()' {_ZN14NormalToStatic5printEv}"]
-  "4" [label="'int(struct NormalToStatic*)' -> 'int()'"]
+  "3" [label="'int NormalToStatic::print(struct NormalToStatic*)' {_ZN14NormalToStatic5printEv} → 'int NormalToStatic::print()' {_ZN14NormalToStatic5printEv}"]
+  "4" [label="'int(struct NormalToStatic*)' → 'int()'"]
   "5" [color=red, label="removed(struct NormalToStatic*)"]
   "4" -> "5" [label="parameter 1 of"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
-  "6" [label="'int StaticToNormal::print()' {_ZN14StaticToNormal5printEv} -> 'int StaticToNormal::print(struct StaticToNormal*)' {_ZN14StaticToNormal5printEv}"]
-  "7" [label="'int()' -> 'int(struct StaticToNormal*)'"]
+  "6" [label="'int StaticToNormal::print()' {_ZN14StaticToNormal5printEv} → 'int StaticToNormal::print(struct StaticToNormal*)' {_ZN14StaticToNormal5printEv}"]
+  "7" [label="'int()' → 'int(struct StaticToNormal*)'"]
   "8" [color=red, label="added(struct StaticToNormal*)"]
   "7" -> "8" [label="parameter 1 of"]
   "6" -> "7" [label=""]
diff --git a/test_cases/diff_tests/function/expected/static_vs_virtual_cc.o_o_viz b/test_cases/diff_tests/function/expected/static_vs_virtual_cc.o_o_viz
index e25534e..6adb42d 100644
--- a/test_cases/diff_tests/function/expected/static_vs_virtual_cc.o_o_viz
+++ b/test_cases/diff_tests/function/expected/static_vs_virtual_cc.o_o_viz
@@ -16,14 +16,14 @@ digraph "ABI diff" {
   "0" -> "7" [label=""]
   "8" [color=red, label="added(_ZTV15StaticToVirtual)"]
   "0" -> "8" [label=""]
-  "9" [label="'int StaticToVirtual::print()' {_ZN15StaticToVirtual5printEv} -> 'int StaticToVirtual::print(struct StaticToVirtual*)' {_ZN15StaticToVirtual5printEv}"]
-  "10" [label="'int()' -> 'int(struct StaticToVirtual*)'"]
+  "9" [label="'int StaticToVirtual::print()' {_ZN15StaticToVirtual5printEv} → 'int StaticToVirtual::print(struct StaticToVirtual*)' {_ZN15StaticToVirtual5printEv}"]
+  "10" [label="'int()' → 'int(struct StaticToVirtual*)'"]
   "11" [color=red, label="added(struct StaticToVirtual*)"]
   "10" -> "11" [label="parameter 1 of"]
   "9" -> "10" [label=""]
   "0" -> "9" [label=""]
-  "12" [label="'int VirtualToStatic::print(struct VirtualToStatic*)' {_ZN15VirtualToStatic5printEv} -> 'int VirtualToStatic::print()' {_ZN15VirtualToStatic5printEv}"]
-  "13" [label="'int(struct VirtualToStatic*)' -> 'int()'"]
+  "12" [label="'int VirtualToStatic::print(struct VirtualToStatic*)' {_ZN15VirtualToStatic5printEv} → 'int VirtualToStatic::print()' {_ZN15VirtualToStatic5printEv}"]
+  "13" [label="'int(struct VirtualToStatic*)' → 'int()'"]
   "14" [color=red, label="removed(struct VirtualToStatic*)"]
   "13" -> "14" [label="parameter 1 of"]
   "12" -> "13" [label=""]
diff --git a/test_cases/diff_tests/member/expected/bitfield_c.btf_btf_viz b/test_cases/diff_tests/member/expected/bitfield_c.btf_btf_viz
index d01d85b..903ceb9 100644
--- a/test_cases/diff_tests/member/expected/bitfield_c.btf_btf_viz
+++ b/test_cases/diff_tests/member/expected/bitfield_c.btf_btf_viz
@@ -5,47 +5,47 @@ digraph "ABI diff" {
   "3" [label="'const struct B*'"]
   "4" [label="'const struct B'"]
   "5" [shape=rectangle, label="'struct B'"]
-  "6" [color=red, label="'unsigned long long b:1' -> 'unsigned long long b:2'"]
+  "6" [color=red, label="'unsigned long long b:1' → 'unsigned long long b:2'"]
   "6" -> "6:0"
   "6:0" [color=red, label="bit-field size changed from 1 to 2"]
   "5" -> "6" [label=""]
-  "7" [color=red, label="'unsigned long long c:2' -> 'unsigned long long c:3'"]
+  "7" [color=red, label="'unsigned long long c:2' → 'unsigned long long c:3'"]
   "7" -> "7:0"
   "7:0" [color=red, label="offset changed from 2 to 3"]
   "7" -> "7:1"
   "7:1" [color=red, label="bit-field size changed from 2 to 3"]
   "5" -> "7" [label=""]
-  "8" [color=red, label="'unsigned long long d:3' -> 'unsigned long long d:5'"]
+  "8" [color=red, label="'unsigned long long d:3' → 'unsigned long long d:5'"]
   "8" -> "8:0"
   "8:0" [color=red, label="offset changed from 4 to 6"]
   "8" -> "8:1"
   "8:1" [color=red, label="bit-field size changed from 3 to 5"]
   "5" -> "8" [label=""]
-  "9" [color=red, label="'unsigned long long e:5' -> 'unsigned long long e:8'"]
+  "9" [color=red, label="'unsigned long long e:5' → 'unsigned long long e:8'"]
   "9" -> "9:0"
   "9:0" [color=red, label="offset changed from 7 to 11"]
   "9" -> "9:1"
   "9:1" [color=red, label="bit-field size changed from 5 to 8"]
   "5" -> "9" [label=""]
-  "10" [color=red, label="'unsigned long long f:8' -> 'unsigned long long f:13'"]
+  "10" [color=red, label="'unsigned long long f:8' → 'unsigned long long f:13'"]
   "10" -> "10:0"
   "10:0" [color=red, label="offset changed from 12 to 19"]
   "10" -> "10:1"
   "10:1" [color=red, label="bit-field size changed from 8 to 13"]
   "5" -> "10" [label=""]
-  "11" [color=red, label="'unsigned long long g:13' -> 'unsigned long long g:21'"]
+  "11" [color=red, label="'unsigned long long g:13' → 'unsigned long long g:21'"]
   "11" -> "11:0"
   "11:0" [color=red, label="offset changed from 20 to 32"]
   "11" -> "11:1"
   "11:1" [color=red, label="bit-field size changed from 13 to 21"]
   "5" -> "11" [label=""]
-  "12" [color=red, label="'unsigned long long h:21' -> 'unsigned long long h:34'"]
+  "12" [color=red, label="'unsigned long long h:21' → 'unsigned long long h:34'"]
   "12" -> "12:0"
   "12:0" [color=red, label="offset changed from 33 to 64"]
   "12" -> "12:1"
   "12:1" [color=red, label="bit-field size changed from 21 to 34"]
   "5" -> "12" [label=""]
-  "13" [color=red, label="'unsigned long long i:34' -> 'unsigned long long i:55'"]
+  "13" [color=red, label="'unsigned long long i:34' → 'unsigned long long i:55'"]
   "13" -> "13:0"
   "13:0" [color=red, label="offset changed from 64 to 128"]
   "13" -> "13:1"
diff --git a/test_cases/diff_tests/member/expected/bitfield_c.o_o_viz b/test_cases/diff_tests/member/expected/bitfield_c.o_o_viz
index d01d85b..903ceb9 100644
--- a/test_cases/diff_tests/member/expected/bitfield_c.o_o_viz
+++ b/test_cases/diff_tests/member/expected/bitfield_c.o_o_viz
@@ -5,47 +5,47 @@ digraph "ABI diff" {
   "3" [label="'const struct B*'"]
   "4" [label="'const struct B'"]
   "5" [shape=rectangle, label="'struct B'"]
-  "6" [color=red, label="'unsigned long long b:1' -> 'unsigned long long b:2'"]
+  "6" [color=red, label="'unsigned long long b:1' → 'unsigned long long b:2'"]
   "6" -> "6:0"
   "6:0" [color=red, label="bit-field size changed from 1 to 2"]
   "5" -> "6" [label=""]
-  "7" [color=red, label="'unsigned long long c:2' -> 'unsigned long long c:3'"]
+  "7" [color=red, label="'unsigned long long c:2' → 'unsigned long long c:3'"]
   "7" -> "7:0"
   "7:0" [color=red, label="offset changed from 2 to 3"]
   "7" -> "7:1"
   "7:1" [color=red, label="bit-field size changed from 2 to 3"]
   "5" -> "7" [label=""]
-  "8" [color=red, label="'unsigned long long d:3' -> 'unsigned long long d:5'"]
+  "8" [color=red, label="'unsigned long long d:3' → 'unsigned long long d:5'"]
   "8" -> "8:0"
   "8:0" [color=red, label="offset changed from 4 to 6"]
   "8" -> "8:1"
   "8:1" [color=red, label="bit-field size changed from 3 to 5"]
   "5" -> "8" [label=""]
-  "9" [color=red, label="'unsigned long long e:5' -> 'unsigned long long e:8'"]
+  "9" [color=red, label="'unsigned long long e:5' → 'unsigned long long e:8'"]
   "9" -> "9:0"
   "9:0" [color=red, label="offset changed from 7 to 11"]
   "9" -> "9:1"
   "9:1" [color=red, label="bit-field size changed from 5 to 8"]
   "5" -> "9" [label=""]
-  "10" [color=red, label="'unsigned long long f:8' -> 'unsigned long long f:13'"]
+  "10" [color=red, label="'unsigned long long f:8' → 'unsigned long long f:13'"]
   "10" -> "10:0"
   "10:0" [color=red, label="offset changed from 12 to 19"]
   "10" -> "10:1"
   "10:1" [color=red, label="bit-field size changed from 8 to 13"]
   "5" -> "10" [label=""]
-  "11" [color=red, label="'unsigned long long g:13' -> 'unsigned long long g:21'"]
+  "11" [color=red, label="'unsigned long long g:13' → 'unsigned long long g:21'"]
   "11" -> "11:0"
   "11:0" [color=red, label="offset changed from 20 to 32"]
   "11" -> "11:1"
   "11:1" [color=red, label="bit-field size changed from 13 to 21"]
   "5" -> "11" [label=""]
-  "12" [color=red, label="'unsigned long long h:21' -> 'unsigned long long h:34'"]
+  "12" [color=red, label="'unsigned long long h:21' → 'unsigned long long h:34'"]
   "12" -> "12:0"
   "12:0" [color=red, label="offset changed from 33 to 64"]
   "12" -> "12:1"
   "12:1" [color=red, label="bit-field size changed from 21 to 34"]
   "5" -> "12" [label=""]
-  "13" [color=red, label="'unsigned long long i:34' -> 'unsigned long long i:55'"]
+  "13" [color=red, label="'unsigned long long i:34' → 'unsigned long long i:55'"]
   "13" -> "13:0"
   "13:0" [color=red, label="offset changed from 64 to 128"]
   "13" -> "13:1"
diff --git a/test_cases/diff_tests/member/expected/bitfield_status_c.o_o_viz b/test_cases/diff_tests/member/expected/bitfield_status_c.o_o_viz
index 80ae972..3074758 100644
--- a/test_cases/diff_tests/member/expected/bitfield_status_c.o_o_viz
+++ b/test_cases/diff_tests/member/expected/bitfield_status_c.o_o_viz
@@ -2,19 +2,19 @@ digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
   "1" [label="'struct X x'"]
   "2" [shape=rectangle, label="'struct X'"]
-  "3" [color=red, label="'int a' -> 'int a:32'"]
+  "3" [color=red, label="'int a' → 'int a:32'"]
   "3" -> "3:0"
   "3:0" [color=red, label="was not a bit-field, is now a bit-field"]
   "2" -> "3" [label=""]
-  "4" [color=red, label="'int b:32' -> 'int b'"]
+  "4" [color=red, label="'int b:32' → 'int b'"]
   "4" -> "4:0"
   "4:0" [color=red, label="was a bit-field, is now not a bit-field"]
   "2" -> "4" [label=""]
-  "5" [color=red, label="'int c' -> 'int c:16'"]
+  "5" [color=red, label="'int c' → 'int c:16'"]
   "5" -> "5:0"
   "5:0" [color=red, label="was not a bit-field, is now a bit-field"]
   "2" -> "5" [label=""]
-  "6" [color=red, label="'int d:16' -> 'int d'"]
+  "6" [color=red, label="'int d:16' → 'int d'"]
   "6" -> "6:0"
   "6:0" [color=red, label="was a bit-field, is now not a bit-field"]
   "2" -> "6" [label=""]
diff --git a/test_cases/diff_tests/member/expected/member_types_cc.o_o_viz b/test_cases/diff_tests/member/expected/member_types_cc.o_o_viz
index 5473a90..3355827 100644
--- a/test_cases/diff_tests/member/expected/member_types_cc.o_o_viz
+++ b/test_cases/diff_tests/member/expected/member_types_cc.o_o_viz
@@ -4,8 +4,8 @@ digraph "ABI diff" {
   "2" [color=red, shape=rectangle, label="'struct Scope::ClassDecl'"]
   "2" -> "2:0"
   "2:0" [color=red, label="byte size changed from 4 to 8"]
-  "3" [label="'int x' -> 'long x'"]
-  "4" [color=red, label="'int' -> 'long'"]
+  "3" [label="'int x' → 'long x'"]
+  "4" [color=red, label="'int' → 'long'"]
   "3" -> "4" [label=""]
   "2" -> "3" [label=""]
   "1" -> "2" [label=""]
@@ -20,13 +20,13 @@ digraph "ABI diff" {
   "8" [color=red, shape=rectangle, label="'struct Scope::StructDecl'"]
   "8" -> "8:0"
   "8:0" [color=red, label="byte size changed from 4 to 8"]
-  "9" [label="'int x' -> 'long x'"]
+  "9" [label="'int x' → 'long x'"]
   "9" -> "4" [label=""]
   "8" -> "9" [label=""]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
   "10" [label="'Scope::TypedefDecl typedef_decl'"]
-  "11" [shape=rectangle, label="'Scope::TypedefDecl' = 'int' -> 'Scope::TypedefDecl' = 'long'"]
+  "11" [shape=rectangle, label="'Scope::TypedefDecl' = 'int' → 'Scope::TypedefDecl' = 'long'"]
   "11" -> "4" [label="resolved"]
   "10" -> "11" [label=""]
   "0" -> "10" [label=""]
@@ -34,7 +34,7 @@ digraph "ABI diff" {
   "13" [color=red, shape=rectangle, label="'union Scope::UnionDecl'"]
   "13" -> "13:0"
   "13:0" [color=red, label="byte size changed from 4 to 8"]
-  "14" [label="'int x' -> 'long x'"]
+  "14" [label="'int x' → 'long x'"]
   "14" -> "4" [label=""]
   "13" -> "14" [label=""]
   "12" -> "13" [label=""]
diff --git a/test_cases/diff_tests/member/expected/order_c.o_o_viz b/test_cases/diff_tests/member/expected/order_c.o_o_viz
index 6cdd6b2..d432a9c 100644
--- a/test_cases/diff_tests/member/expected/order_c.o_o_viz
+++ b/test_cases/diff_tests/member/expected/order_c.o_o_viz
@@ -1,7 +1,7 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'struct { int one; int two; int three; int four; int five; int six; } v' -> 'struct { int zero; int one; int two; double e; int three; double pi; int four; int five; int six; double tau; } v'"]
-  "2" [color=red, label="'struct { int one; int two; int three; int four; int five; int six; }' -> 'struct { int zero; int one; int two; double e; int three; double pi; int four; int five; int six; double tau; }'"]
+  "1" [label="'struct { int one; int two; int three; int four; int five; int six; } v' → 'struct { int zero; int one; int two; double e; int three; double pi; int four; int five; int six; double tau; } v'"]
+  "2" [color=red, label="'struct { int one; int two; int three; int four; int five; int six; }' → 'struct { int zero; int one; int two; double e; int three; double pi; int four; int five; int six; double tau; }'"]
   "2" -> "2:0"
   "2:0" [color=red, label="byte size changed from 24 to 64"]
   "3" [color=red, label="added(int zero)"]
diff --git a/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_viz b/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_viz
index b1cbb30..ed68853 100644
--- a/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_viz
+++ b/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_viz
@@ -40,11 +40,11 @@ digraph "ABI diff" {
   "0" -> "19" [label=""]
   "20" [color=red, label="added(const int struct S::* volatile s9)"]
   "0" -> "20" [label=""]
-  "21" [label="'char struct A::* diff' -> 'int struct B::* diff'"]
-  "22" [label="'char struct A::*' -> 'int struct B::*'"]
-  "23" [color=red, label="'struct A' -> 'struct B'"]
+  "21" [label="'char struct A::* diff' → 'int struct B::* diff'"]
+  "22" [label="'char struct A::*' → 'int struct B::*'"]
+  "23" [color=red, label="'struct A' → 'struct B'"]
   "22" -> "23" [label="containing"]
-  "24" [color=red, label="'char' -> 'int'"]
+  "24" [color=red, label="'char' → 'int'"]
   "22" -> "24" [label=""]
   "21" -> "22" [label=""]
   "0" -> "21" [label=""]
diff --git a/test_cases/diff_tests/misc/expected/enum_cc.o_o_viz b/test_cases/diff_tests/misc/expected/enum_cc.o_o_viz
index 00d4d90..4e75dcf 100644
--- a/test_cases/diff_tests/misc/expected/enum_cc.o_o_viz
+++ b/test_cases/diff_tests/misc/expected/enum_cc.o_o_viz
@@ -5,7 +5,7 @@ digraph "ABI diff" {
   "3" [label="'const enum Colour&'"]
   "4" [label="'const enum Colour'"]
   "5" [shape=rectangle, label="'enum Colour'"]
-  "6" [color=red, label="'unsigned int' -> 'unsigned char'"]
+  "6" [color=red, label="'unsigned int' → 'unsigned char'"]
   "5" -> "6" [label="underlying"]
   "4" -> "5" [label="underlying"]
   "3" -> "4" [label="referred-to"]
diff --git a/test_cases/diff_tests/misc/expected/enum_const_c.btf_btf_viz b/test_cases/diff_tests/misc/expected/enum_const_c.btf_btf_viz
index 33a89fd..a4fa4b6 100644
--- a/test_cases/diff_tests/misc/expected/enum_const_c.btf_btf_viz
+++ b/test_cases/diff_tests/misc/expected/enum_const_c.btf_btf_viz
@@ -1,14 +1,14 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'Foo getEnum(Foo)' -> 'Foo getEnum(const Foo)'"]
-  "2" [label="'Foo(Foo)' -> 'Foo(const Foo)'"]
+  "1" [label="'Foo getEnum(Foo)' → 'Foo getEnum(const Foo)'"]
+  "2" [label="'Foo(Foo)' → 'Foo(const Foo)'"]
   "3" [shape=rectangle, label="'Foo' = 'enum Foo'"]
   "4" [color=red, shape=rectangle, label="'enum Foo'"]
   "4" -> "4:0"
   "4:0" [color=red, label="enumerator 'FOO_TWO' value changed from 100 to 2"]
   "3" -> "4" [label="resolved"]
   "2" -> "3" [label="return"]
-  "5" [color=red, label="'Foo' = 'enum Foo' -> 'const Foo'"]
+  "5" [color=red, label="'Foo' = 'enum Foo' → 'const Foo'"]
   "5" -> "5:0"
   "5:0" [color=red, label="qualifier const added"]
   "5" -> "3" [label="underlying"]
diff --git a/test_cases/diff_tests/namespace/expected/nested_anonymous_types_cc.o_o_viz b/test_cases/diff_tests/namespace/expected/nested_anonymous_types_cc.o_o_viz
index 330492d..7763889 100644
--- a/test_cases/diff_tests/namespace/expected/nested_anonymous_types_cc.o_o_viz
+++ b/test_cases/diff_tests/namespace/expected/nested_anonymous_types_cc.o_o_viz
@@ -1,42 +1,42 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
   "1" [label="'Scope::AnonClass anon_class'"]
-  "2" [shape=rectangle, label="'Scope::AnonClass' = 'struct { int x; }' -> 'Scope::AnonClass' = 'struct { long x; }'"]
-  "3" [color=red, label="'struct { int x; }' -> 'struct { long x; }'"]
+  "2" [shape=rectangle, label="'Scope::AnonClass' = 'struct { int x; }' → 'Scope::AnonClass' = 'struct { long x; }'"]
+  "3" [color=red, label="'struct { int x; }' → 'struct { long x; }'"]
   "3" -> "3:0"
   "3:0" [color=red, label="byte size changed from 4 to 8"]
-  "4" [label="'int x' -> 'long x'"]
-  "5" [color=red, label="'int' -> 'long'"]
+  "4" [label="'int x' → 'long x'"]
+  "5" [color=red, label="'int' → 'long'"]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
   "2" -> "3" [label="resolved"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
   "6" [label="'Scope::AnonEnum anon_enum'"]
-  "7" [shape=rectangle, label="'Scope::AnonEnum' = 'enum { X = 1, }' -> 'Scope::AnonEnum' = 'enum { X = 2, }'"]
-  "8" [color=red, label="'enum { X = 1, }' -> 'enum { X = 2, }'"]
+  "7" [shape=rectangle, label="'Scope::AnonEnum' = 'enum { X = 1, }' → 'Scope::AnonEnum' = 'enum { X = 2, }'"]
+  "8" [color=red, label="'enum { X = 1, }' → 'enum { X = 2, }'"]
   "8" -> "8:0"
   "8:0" [color=red, label="enumerator 'X' value changed from 1 to 2"]
   "7" -> "8" [label="resolved"]
   "6" -> "7" [label=""]
   "0" -> "6" [label=""]
   "9" [label="'Scope::AnonStruct anon_struct'"]
-  "10" [shape=rectangle, label="'Scope::AnonStruct' = 'struct { int x; }' -> 'Scope::AnonStruct' = 'struct { long x; }'"]
-  "11" [color=red, label="'struct { int x; }' -> 'struct { long x; }'"]
+  "10" [shape=rectangle, label="'Scope::AnonStruct' = 'struct { int x; }' → 'Scope::AnonStruct' = 'struct { long x; }'"]
+  "11" [color=red, label="'struct { int x; }' → 'struct { long x; }'"]
   "11" -> "11:0"
   "11:0" [color=red, label="byte size changed from 4 to 8"]
-  "12" [label="'int x' -> 'long x'"]
+  "12" [label="'int x' → 'long x'"]
   "12" -> "5" [label=""]
   "11" -> "12" [label=""]
   "10" -> "11" [label="resolved"]
   "9" -> "10" [label=""]
   "0" -> "9" [label=""]
   "13" [label="'Scope::AnonUnion anon_union'"]
-  "14" [shape=rectangle, label="'Scope::AnonUnion' = 'union { int x; }' -> 'Scope::AnonUnion' = 'union { long x; }'"]
-  "15" [color=red, label="'union { int x; }' -> 'union { long x; }'"]
+  "14" [shape=rectangle, label="'Scope::AnonUnion' = 'union { int x; }' → 'Scope::AnonUnion' = 'union { long x; }'"]
+  "15" [color=red, label="'union { int x; }' → 'union { long x; }'"]
   "15" -> "15:0"
   "15:0" [color=red, label="byte size changed from 4 to 8"]
-  "16" [label="'int x' -> 'long x'"]
+  "16" [label="'int x' → 'long x'"]
   "16" -> "5" [label=""]
   "15" -> "16" [label=""]
   "14" -> "15" [label="resolved"]
diff --git a/test_cases/diff_tests/namespace/expected/nested_cc.o_o_viz b/test_cases/diff_tests/namespace/expected/nested_cc.o_o_viz
index cd276a4..75b1aa3 100644
--- a/test_cases/diff_tests/namespace/expected/nested_cc.o_o_viz
+++ b/test_cases/diff_tests/namespace/expected/nested_cc.o_o_viz
@@ -4,8 +4,8 @@ digraph "ABI diff" {
   "2" [color=red, shape=rectangle, label="'struct n1::n2::n3::str'"]
   "2" -> "2:0"
   "2:0" [color=red, label="byte size changed from 4 to 8"]
-  "3" [label="'int x' -> 'long x'"]
-  "4" [color=red, label="'int' -> 'long'"]
+  "3" [label="'int x' → 'long x'"]
+  "4" [color=red, label="'int' → 'long'"]
   "3" -> "4" [label=""]
   "2" -> "3" [label=""]
   "1" -> "2" [label=""]
@@ -14,7 +14,7 @@ digraph "ABI diff" {
   "6" [color=red, shape=rectangle, label="'struct foo::str'"]
   "6" -> "6:0"
   "6:0" [color=red, label="byte size changed from 4 to 8"]
-  "7" [label="'int x' -> 'long x'"]
+  "7" [label="'int x' → 'long x'"]
   "7" -> "4" [label=""]
   "6" -> "7" [label=""]
   "5" -> "6" [label=""]
diff --git a/test_cases/diff_tests/namespace/expected/simple_cc.o_o_viz b/test_cases/diff_tests/namespace/expected/simple_cc.o_o_viz
index 4fac8d1..90a5814 100644
--- a/test_cases/diff_tests/namespace/expected/simple_cc.o_o_viz
+++ b/test_cases/diff_tests/namespace/expected/simple_cc.o_o_viz
@@ -4,27 +4,27 @@ digraph "ABI diff" {
   "0" -> "1" [label=""]
   "2" [color=red, label="added(int added_n::var {_ZN7added_n3varE})"]
   "0" -> "2" [label=""]
-  "3" [label="'int foo::x1' {_ZN3foo2x1E} -> 'long foo::x1' {_ZN3foo2x1E}"]
-  "4" [color=red, label="'int' -> 'long'"]
+  "3" [label="'int foo::x1' {_ZN3foo2x1E} → 'long foo::x1' {_ZN3foo2x1E}"]
+  "4" [color=red, label="'int' → 'long'"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
-  "5" [label="'int foo::x2[5]' {_ZN3foo2x2E} -> 'long foo::x2[5]' {_ZN3foo2x2E}"]
-  "6" [label="'int[5]' -> 'long[5]'"]
+  "5" [label="'int foo::x2[5]' {_ZN3foo2x2E} → 'long foo::x2[5]' {_ZN3foo2x2E}"]
+  "6" [label="'int[5]' → 'long[5]'"]
   "6" -> "4" [label="element"]
   "5" -> "6" [label=""]
   "0" -> "5" [label=""]
-  "7" [label="'const int foo::x3' {_ZN3foo2x3E} -> 'const long foo::x3' {_ZN3foo2x3E}"]
-  "8" [label="'const int' -> 'const long'"]
+  "7" [label="'const int foo::x3' {_ZN3foo2x3E} → 'const long foo::x3' {_ZN3foo2x3E}"]
+  "8" [label="'const int' → 'const long'"]
   "8" -> "4" [label="underlying"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
   "9" [label="'foo::type_definition foo::x4' {_ZN3foo2x4E}"]
-  "10" [shape=rectangle, label="'foo::type_definition' = 'int' -> 'foo::type_definition' = 'long'"]
+  "10" [shape=rectangle, label="'foo::type_definition' = 'int' → 'foo::type_definition' = 'long'"]
   "10" -> "4" [label="resolved"]
   "9" -> "10" [label=""]
   "0" -> "9" [label=""]
-  "11" [label="'int foo::x5()' {_ZN3foo2x5Ev} -> 'long foo::x5()' {_ZN3foo2x5Ev}"]
-  "12" [label="'int()' -> 'long()'"]
+  "11" [label="'int foo::x5()' {_ZN3foo2x5Ev} → 'long foo::x5()' {_ZN3foo2x5Ev}"]
+  "12" [label="'int()' → 'long()'"]
   "12" -> "4" [label="return"]
   "11" -> "12" [label=""]
   "0" -> "11" [label=""]
@@ -32,7 +32,7 @@ digraph "ABI diff" {
   "14" [color=red, shape=rectangle, label="'struct foo::S'"]
   "14" -> "14:0"
   "14:0" [color=red, label="byte size changed from 4 to 8"]
-  "15" [label="'int x' -> 'long x'"]
+  "15" [label="'int x' → 'long x'"]
   "15" -> "4" [label=""]
   "14" -> "15" [label=""]
   "13" -> "14" [label=""]
@@ -41,7 +41,7 @@ digraph "ABI diff" {
   "17" [color=red, shape=rectangle, label="'union foo::U'"]
   "17" -> "17:0"
   "17:0" [color=red, label="byte size changed from 4 to 8"]
-  "18" [label="'int x' -> 'long x'"]
+  "18" [label="'int x' → 'long x'"]
   "18" -> "4" [label=""]
   "17" -> "18" [label=""]
   "16" -> "17" [label=""]
diff --git a/test_cases/diff_tests/qualified/expected/mutant_qualifier_typedef_array_c.btf_btf_viz b/test_cases/diff_tests/qualified/expected/mutant_qualifier_typedef_array_c.btf_btf_viz
index 85aed30..9122e35 100644
--- a/test_cases/diff_tests/qualified/expected/mutant_qualifier_typedef_array_c.btf_btf_viz
+++ b/test_cases/diff_tests/qualified/expected/mutant_qualifier_typedef_array_c.btf_btf_viz
@@ -4,74 +4,74 @@ digraph "ABI diff" {
   "2" [label="'void(struct S*)'"]
   "3" [label="'struct S*'"]
   "4" [shape=rectangle, label="'struct S'"]
-  "5" [label="'A c_a' -> 'const A c_a'"]
-  "6" [color=red, label="'A' = 'int[7]' -> 'const A'"]
+  "5" [label="'A c_a' → 'const A c_a'"]
+  "6" [color=red, label="'A' = 'int[7]' → 'const A'"]
   "6" -> "6:0"
   "6:0" [color=red, label="qualifier const added"]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
-  "7" [label="'A v_a' -> 'volatile A v_a'"]
-  "8" [color=red, label="'A' = 'int[7]' -> 'volatile A'"]
+  "7" [label="'A v_a' → 'volatile A v_a'"]
+  "8" [color=red, label="'A' = 'int[7]' → 'volatile A'"]
   "8" -> "8:0"
   "8:0" [color=red, label="qualifier volatile added"]
   "7" -> "8" [label=""]
   "4" -> "7" [label=""]
-  "9" [label="'B c_b' -> 'const B c_b'"]
-  "10" [color=red, label="'B' = 'A' = 'int[7]' -> 'const B'"]
+  "9" [label="'B c_b' → 'const B c_b'"]
+  "10" [color=red, label="'B' = 'A' = 'int[7]' → 'const B'"]
   "10" -> "10:0"
   "10:0" [color=red, label="qualifier const added"]
   "9" -> "10" [label=""]
   "4" -> "9" [label=""]
-  "11" [label="'B v_b' -> 'volatile B v_b'"]
-  "12" [color=red, label="'B' = 'A' = 'int[7]' -> 'volatile B'"]
+  "11" [label="'B v_b' → 'volatile B v_b'"]
+  "12" [color=red, label="'B' = 'A' = 'int[7]' → 'volatile B'"]
   "12" -> "12:0"
   "12:0" [color=red, label="qualifier volatile added"]
   "11" -> "12" [label=""]
   "4" -> "11" [label=""]
-  "13" [label="'C c_c' -> 'const C c_c'"]
-  "14" [color=red, label="'C' = 'const B' -> 'const C'"]
+  "13" [label="'C c_c' → 'const C c_c'"]
+  "14" [color=red, label="'C' = 'const B' → 'const C'"]
   "14" -> "14:0"
   "14:0" [color=red, label="qualifier const added"]
   "13" -> "14" [label=""]
   "4" -> "13" [label=""]
-  "15" [label="'C v_c' -> 'volatile C v_c'"]
-  "16" [color=red, label="'C' = 'const B' -> 'volatile C'"]
+  "15" [label="'C v_c' → 'volatile C v_c'"]
+  "16" [color=red, label="'C' = 'const B' → 'volatile C'"]
   "16" -> "16:0"
   "16:0" [color=red, label="qualifier volatile added"]
   "15" -> "16" [label=""]
   "4" -> "15" [label=""]
-  "17" [label="'D c_d' -> 'const D c_d'"]
-  "18" [color=red, label="'D' = 'C' = 'const B' -> 'const D'"]
+  "17" [label="'D c_d' → 'const D c_d'"]
+  "18" [color=red, label="'D' = 'C' = 'const B' → 'const D'"]
   "18" -> "18:0"
   "18:0" [color=red, label="qualifier const added"]
   "17" -> "18" [label=""]
   "4" -> "17" [label=""]
-  "19" [label="'D v_d' -> 'volatile D v_d'"]
-  "20" [color=red, label="'D' = 'C' = 'const B' -> 'volatile D'"]
+  "19" [label="'D v_d' → 'volatile D v_d'"]
+  "20" [color=red, label="'D' = 'C' = 'const B' → 'volatile D'"]
   "20" -> "20:0"
   "20:0" [color=red, label="qualifier volatile added"]
   "19" -> "20" [label=""]
   "4" -> "19" [label=""]
-  "21" [label="'E c_e' -> 'const E c_e'"]
-  "22" [color=red, label="'E' = 'volatile D' -> 'const E'"]
+  "21" [label="'E c_e' → 'const E c_e'"]
+  "22" [color=red, label="'E' = 'volatile D' → 'const E'"]
   "22" -> "22:0"
   "22:0" [color=red, label="qualifier const added"]
   "21" -> "22" [label=""]
   "4" -> "21" [label=""]
-  "23" [label="'E v_e' -> 'volatile E v_e'"]
-  "24" [color=red, label="'E' = 'volatile D' -> 'volatile E'"]
+  "23" [label="'E v_e' → 'volatile E v_e'"]
+  "24" [color=red, label="'E' = 'volatile D' → 'volatile E'"]
   "24" -> "24:0"
   "24:0" [color=red, label="qualifier volatile added"]
   "23" -> "24" [label=""]
   "4" -> "23" [label=""]
-  "25" [label="'F c_f' -> 'const F c_f'"]
-  "26" [color=red, label="'F' = 'E' = 'volatile D' -> 'const F'"]
+  "25" [label="'F c_f' → 'const F c_f'"]
+  "26" [color=red, label="'F' = 'E' = 'volatile D' → 'const F'"]
   "26" -> "26:0"
   "26:0" [color=red, label="qualifier const added"]
   "25" -> "26" [label=""]
   "4" -> "25" [label=""]
-  "27" [label="'F v_f' -> 'volatile F v_f'"]
-  "28" [color=red, label="'F' = 'E' = 'volatile D' -> 'volatile F'"]
+  "27" [label="'F v_f' → 'volatile F v_f'"]
+  "28" [color=red, label="'F' = 'E' = 'volatile D' → 'volatile F'"]
   "28" -> "28:0"
   "28:0" [color=red, label="qualifier volatile added"]
   "27" -> "28" [label=""]
diff --git a/test_cases/diff_tests/qualified/expected/mutant_qualifier_typedef_array_c.o_o_viz b/test_cases/diff_tests/qualified/expected/mutant_qualifier_typedef_array_c.o_o_viz
index 85aed30..9122e35 100644
--- a/test_cases/diff_tests/qualified/expected/mutant_qualifier_typedef_array_c.o_o_viz
+++ b/test_cases/diff_tests/qualified/expected/mutant_qualifier_typedef_array_c.o_o_viz
@@ -4,74 +4,74 @@ digraph "ABI diff" {
   "2" [label="'void(struct S*)'"]
   "3" [label="'struct S*'"]
   "4" [shape=rectangle, label="'struct S'"]
-  "5" [label="'A c_a' -> 'const A c_a'"]
-  "6" [color=red, label="'A' = 'int[7]' -> 'const A'"]
+  "5" [label="'A c_a' → 'const A c_a'"]
+  "6" [color=red, label="'A' = 'int[7]' → 'const A'"]
   "6" -> "6:0"
   "6:0" [color=red, label="qualifier const added"]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
-  "7" [label="'A v_a' -> 'volatile A v_a'"]
-  "8" [color=red, label="'A' = 'int[7]' -> 'volatile A'"]
+  "7" [label="'A v_a' → 'volatile A v_a'"]
+  "8" [color=red, label="'A' = 'int[7]' → 'volatile A'"]
   "8" -> "8:0"
   "8:0" [color=red, label="qualifier volatile added"]
   "7" -> "8" [label=""]
   "4" -> "7" [label=""]
-  "9" [label="'B c_b' -> 'const B c_b'"]
-  "10" [color=red, label="'B' = 'A' = 'int[7]' -> 'const B'"]
+  "9" [label="'B c_b' → 'const B c_b'"]
+  "10" [color=red, label="'B' = 'A' = 'int[7]' → 'const B'"]
   "10" -> "10:0"
   "10:0" [color=red, label="qualifier const added"]
   "9" -> "10" [label=""]
   "4" -> "9" [label=""]
-  "11" [label="'B v_b' -> 'volatile B v_b'"]
-  "12" [color=red, label="'B' = 'A' = 'int[7]' -> 'volatile B'"]
+  "11" [label="'B v_b' → 'volatile B v_b'"]
+  "12" [color=red, label="'B' = 'A' = 'int[7]' → 'volatile B'"]
   "12" -> "12:0"
   "12:0" [color=red, label="qualifier volatile added"]
   "11" -> "12" [label=""]
   "4" -> "11" [label=""]
-  "13" [label="'C c_c' -> 'const C c_c'"]
-  "14" [color=red, label="'C' = 'const B' -> 'const C'"]
+  "13" [label="'C c_c' → 'const C c_c'"]
+  "14" [color=red, label="'C' = 'const B' → 'const C'"]
   "14" -> "14:0"
   "14:0" [color=red, label="qualifier const added"]
   "13" -> "14" [label=""]
   "4" -> "13" [label=""]
-  "15" [label="'C v_c' -> 'volatile C v_c'"]
-  "16" [color=red, label="'C' = 'const B' -> 'volatile C'"]
+  "15" [label="'C v_c' → 'volatile C v_c'"]
+  "16" [color=red, label="'C' = 'const B' → 'volatile C'"]
   "16" -> "16:0"
   "16:0" [color=red, label="qualifier volatile added"]
   "15" -> "16" [label=""]
   "4" -> "15" [label=""]
-  "17" [label="'D c_d' -> 'const D c_d'"]
-  "18" [color=red, label="'D' = 'C' = 'const B' -> 'const D'"]
+  "17" [label="'D c_d' → 'const D c_d'"]
+  "18" [color=red, label="'D' = 'C' = 'const B' → 'const D'"]
   "18" -> "18:0"
   "18:0" [color=red, label="qualifier const added"]
   "17" -> "18" [label=""]
   "4" -> "17" [label=""]
-  "19" [label="'D v_d' -> 'volatile D v_d'"]
-  "20" [color=red, label="'D' = 'C' = 'const B' -> 'volatile D'"]
+  "19" [label="'D v_d' → 'volatile D v_d'"]
+  "20" [color=red, label="'D' = 'C' = 'const B' → 'volatile D'"]
   "20" -> "20:0"
   "20:0" [color=red, label="qualifier volatile added"]
   "19" -> "20" [label=""]
   "4" -> "19" [label=""]
-  "21" [label="'E c_e' -> 'const E c_e'"]
-  "22" [color=red, label="'E' = 'volatile D' -> 'const E'"]
+  "21" [label="'E c_e' → 'const E c_e'"]
+  "22" [color=red, label="'E' = 'volatile D' → 'const E'"]
   "22" -> "22:0"
   "22:0" [color=red, label="qualifier const added"]
   "21" -> "22" [label=""]
   "4" -> "21" [label=""]
-  "23" [label="'E v_e' -> 'volatile E v_e'"]
-  "24" [color=red, label="'E' = 'volatile D' -> 'volatile E'"]
+  "23" [label="'E v_e' → 'volatile E v_e'"]
+  "24" [color=red, label="'E' = 'volatile D' → 'volatile E'"]
   "24" -> "24:0"
   "24:0" [color=red, label="qualifier volatile added"]
   "23" -> "24" [label=""]
   "4" -> "23" [label=""]
-  "25" [label="'F c_f' -> 'const F c_f'"]
-  "26" [color=red, label="'F' = 'E' = 'volatile D' -> 'const F'"]
+  "25" [label="'F c_f' → 'const F c_f'"]
+  "26" [color=red, label="'F' = 'E' = 'volatile D' → 'const F'"]
   "26" -> "26:0"
   "26:0" [color=red, label="qualifier const added"]
   "25" -> "26" [label=""]
   "4" -> "25" [label=""]
-  "27" [label="'F v_f' -> 'volatile F v_f'"]
-  "28" [color=red, label="'F' = 'E' = 'volatile D' -> 'volatile F'"]
+  "27" [label="'F v_f' → 'volatile F v_f'"]
+  "28" [color=red, label="'F' = 'E' = 'volatile D' → 'volatile F'"]
   "28" -> "28:0"
   "28:0" [color=red, label="qualifier volatile added"]
   "27" -> "28" [label=""]
diff --git a/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_viz b/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_viz
index 96578bf..af85ebd 100644
--- a/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_viz
+++ b/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_viz
@@ -4,21 +4,21 @@ digraph "ABI diff" {
   "0" -> "1" [label=""]
   "2" [color=red, label="added(int bar_2(struct foo*))"]
   "0" -> "2" [label=""]
-  "3" [label="'int bar(struct foo)' -> 'int bar(const volatile struct foo*)'"]
-  "4" [label="'int(struct foo)' -> 'int(const volatile struct foo*)'"]
-  "5" [color=red, label="'struct foo' -> 'const volatile struct foo*'"]
+  "3" [label="'int bar(struct foo)' → 'int bar(const volatile struct foo*)'"]
+  "4" [label="'int(struct foo)' → 'int(const volatile struct foo*)'"]
+  "5" [color=red, label="'struct foo' → 'const volatile struct foo*'"]
   "4" -> "5" [label="parameter 1"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
-  "6" [label="'int baz(int(*)(struct foo))' -> 'int baz(int(* volatile const)(const volatile struct foo*))'"]
-  "7" [label="'int(int(*)(struct foo))' -> 'int(int(* volatile const)(const volatile struct foo*))'"]
-  "8" [color=red, label="'int(*)(struct foo)' -> 'int(* volatile const)(const volatile struct foo*)'"]
+  "6" [label="'int baz(int(*)(struct foo))' → 'int baz(int(* volatile const)(const volatile struct foo*))'"]
+  "7" [label="'int(int(*)(struct foo))' → 'int(int(* volatile const)(const volatile struct foo*))'"]
+  "8" [color=red, label="'int(*)(struct foo)' → 'int(* volatile const)(const volatile struct foo*)'"]
   "8" -> "8:0"
   "8:0" [color=red, label="qualifier const added"]
   "8" -> "8:1"
   "8:1" [color=red, label="qualifier volatile added"]
-  "9" [label="'int(*)(struct foo)' -> 'int(*)(const volatile struct foo*)'"]
-  "10" [label="'int(struct foo)' -> 'int(const volatile struct foo*)'"]
+  "9" [label="'int(*)(struct foo)' → 'int(*)(const volatile struct foo*)'"]
+  "10" [label="'int(struct foo)' → 'int(const volatile struct foo*)'"]
   "10" -> "5" [label="parameter 1"]
   "9" -> "10" [label="pointed-to"]
   "8" -> "9" [label="underlying"]
diff --git a/test_cases/diff_tests/qualified/expected/useless_c.o_o_viz b/test_cases/diff_tests/qualified/expected/useless_c.o_o_viz
index 9b8691d..ca40962 100644
--- a/test_cases/diff_tests/qualified/expected/useless_c.o_o_viz
+++ b/test_cases/diff_tests/qualified/expected/useless_c.o_o_viz
@@ -4,23 +4,23 @@ digraph "ABI diff" {
   "0" -> "1" [label=""]
   "2" [color=red, label="added(int bar_2(struct foo*))"]
   "0" -> "2" [label=""]
-  "3" [label="'int bar(struct foo)' -> 'int bar(const volatile struct foo*)'"]
-  "4" [label="'int(struct foo)' -> 'int(const volatile struct foo*)'"]
-  "5" [color=red, label="'struct foo' -> 'const volatile struct foo*'"]
+  "3" [label="'int bar(struct foo)' → 'int bar(const volatile struct foo*)'"]
+  "4" [label="'int(struct foo)' → 'int(const volatile struct foo*)'"]
+  "5" [color=red, label="'struct foo' → 'const volatile struct foo*'"]
   "4" -> "5" [label="parameter 1"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
-  "6" [label="'int baz(int(*)(struct foo))' -> 'int baz(int(*)(const volatile struct foo*))'"]
-  "7" [label="'int(int(*)(struct foo))' -> 'int(int(*)(const volatile struct foo*))'"]
-  "8" [label="'int(*)(struct foo)' -> 'int(*)(const volatile struct foo*)'"]
-  "9" [label="'int(struct foo)' -> 'int(const volatile struct foo*)'"]
+  "6" [label="'int baz(int(*)(struct foo))' → 'int baz(int(*)(const volatile struct foo*))'"]
+  "7" [label="'int(int(*)(struct foo))' → 'int(int(*)(const volatile struct foo*))'"]
+  "8" [label="'int(*)(struct foo)' → 'int(*)(const volatile struct foo*)'"]
+  "9" [label="'int(struct foo)' → 'int(const volatile struct foo*)'"]
   "9" -> "5" [label="parameter 1"]
   "8" -> "9" [label="pointed-to"]
   "7" -> "8" [label="parameter 1"]
   "6" -> "7" [label=""]
   "0" -> "6" [label=""]
-  "10" [label="'int(* quux)(struct foo)' -> 'int(* volatile const quux)(const volatile struct foo*)'"]
-  "11" [color=red, label="'int(*)(struct foo)' -> 'int(* volatile const)(const volatile struct foo*)'"]
+  "10" [label="'int(* quux)(struct foo)' → 'int(* volatile const quux)(const volatile struct foo*)'"]
+  "11" [color=red, label="'int(*)(struct foo)' → 'int(* volatile const)(const volatile struct foo*)'"]
   "11" -> "11:0"
   "11:0" [color=red, label="qualifier const added"]
   "11" -> "11:1"
diff --git a/test_cases/diff_tests/reference/expected/kind_and_type_cc.o_o_viz b/test_cases/diff_tests/reference/expected/kind_and_type_cc.o_o_viz
index 64d5b93..a63c37f 100644
--- a/test_cases/diff_tests/reference/expected/kind_and_type_cc.o_o_viz
+++ b/test_cases/diff_tests/reference/expected/kind_and_type_cc.o_o_viz
@@ -3,28 +3,28 @@ digraph "ABI diff" {
   "1" [label="'int func(struct foo)' {_Z4func3foo}"]
   "2" [label="'int(struct foo)'"]
   "3" [shape=rectangle, label="'struct foo'"]
-  "4" [label="'int& lref_to_ptr' -> 'int* lref_to_ptr'"]
-  "5" [color=red, label="'int&' -> 'int*'"]
+  "4" [label="'int& lref_to_ptr' → 'int* lref_to_ptr'"]
+  "5" [color=red, label="'int&' → 'int*'"]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
-  "6" [label="'int* ptr_to_lref' -> 'int& ptr_to_lref'"]
-  "7" [color=red, label="'int*' -> 'int&'"]
+  "6" [label="'int* ptr_to_lref' → 'int& ptr_to_lref'"]
+  "7" [color=red, label="'int*' → 'int&'"]
   "6" -> "7" [label=""]
   "3" -> "6" [label=""]
-  "8" [label="'int&& rref_to_ptr' -> 'int* rref_to_ptr'"]
-  "9" [color=red, label="'int&&' -> 'int*'"]
+  "8" [label="'int&& rref_to_ptr' → 'int* rref_to_ptr'"]
+  "9" [color=red, label="'int&&' → 'int*'"]
   "8" -> "9" [label=""]
   "3" -> "8" [label=""]
-  "10" [label="'int* ptr_to_rref' -> 'int&& ptr_to_rref'"]
-  "11" [color=red, label="'int*' -> 'int&&'"]
+  "10" [label="'int* ptr_to_rref' → 'int&& ptr_to_rref'"]
+  "11" [color=red, label="'int*' → 'int&&'"]
   "10" -> "11" [label=""]
   "3" -> "10" [label=""]
-  "12" [label="'int& lref_to_rref' -> 'int&& lref_to_rref'"]
-  "13" [color=red, label="'int&' -> 'int&&'"]
+  "12" [label="'int& lref_to_rref' → 'int&& lref_to_rref'"]
+  "13" [color=red, label="'int&' → 'int&&'"]
   "12" -> "13" [label=""]
   "3" -> "12" [label=""]
-  "14" [label="'int&& rref_to_lref' -> 'int& rref_to_lref'"]
-  "15" [color=red, label="'int&&' -> 'int&'"]
+  "14" [label="'int&& rref_to_lref' → 'int& rref_to_lref'"]
+  "15" [color=red, label="'int&&' → 'int&'"]
   "14" -> "15" [label=""]
   "3" -> "14" [label=""]
   "2" -> "3" [label="parameter 1"]
diff --git a/test_cases/diff_tests/reference/expected/kind_cc.o_o_viz b/test_cases/diff_tests/reference/expected/kind_cc.o_o_viz
index f836f93..70178c0 100644
--- a/test_cases/diff_tests/reference/expected/kind_cc.o_o_viz
+++ b/test_cases/diff_tests/reference/expected/kind_cc.o_o_viz
@@ -3,28 +3,28 @@ digraph "ABI diff" {
   "1" [label="'void func(struct foo)' {_Z4func3foo}"]
   "2" [label="'void(struct foo)'"]
   "3" [shape=rectangle, label="'struct foo'"]
-  "4" [label="'int& lref_to_ptr' -> 'int* lref_to_ptr'"]
-  "5" [color=red, label="'int&' -> 'int*'"]
+  "4" [label="'int& lref_to_ptr' → 'int* lref_to_ptr'"]
+  "5" [color=red, label="'int&' → 'int*'"]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
-  "6" [label="'int* ptr_to_lref' -> 'int& ptr_to_lref'"]
-  "7" [color=red, label="'int*' -> 'int&'"]
+  "6" [label="'int* ptr_to_lref' → 'int& ptr_to_lref'"]
+  "7" [color=red, label="'int*' → 'int&'"]
   "6" -> "7" [label=""]
   "3" -> "6" [label=""]
-  "8" [label="'int&& rref_to_ptr' -> 'int* rref_to_ptr'"]
-  "9" [color=red, label="'int&&' -> 'int*'"]
+  "8" [label="'int&& rref_to_ptr' → 'int* rref_to_ptr'"]
+  "9" [color=red, label="'int&&' → 'int*'"]
   "8" -> "9" [label=""]
   "3" -> "8" [label=""]
-  "10" [label="'int* ptr_to_rref' -> 'int&& ptr_to_rref'"]
-  "11" [color=red, label="'int*' -> 'int&&'"]
+  "10" [label="'int* ptr_to_rref' → 'int&& ptr_to_rref'"]
+  "11" [color=red, label="'int*' → 'int&&'"]
   "10" -> "11" [label=""]
   "3" -> "10" [label=""]
-  "12" [label="'int& lref_to_rref' -> 'int&& lref_to_rref'"]
-  "13" [color=red, label="'int&' -> 'int&&'"]
+  "12" [label="'int& lref_to_rref' → 'int&& lref_to_rref'"]
+  "13" [color=red, label="'int&' → 'int&&'"]
   "12" -> "13" [label=""]
   "3" -> "12" [label=""]
-  "14" [label="'int&& rref_to_lref' -> 'int& rref_to_lref'"]
-  "15" [color=red, label="'int&&' -> 'int&'"]
+  "14" [label="'int&& rref_to_lref' → 'int& rref_to_lref'"]
+  "15" [color=red, label="'int&&' → 'int&'"]
   "14" -> "15" [label=""]
   "3" -> "14" [label=""]
   "2" -> "3" [label="parameter 1"]
diff --git a/test_cases/diff_tests/reference/expected/type_cc.o_o_viz b/test_cases/diff_tests/reference/expected/type_cc.o_o_viz
index e1d2baa..830d74f 100644
--- a/test_cases/diff_tests/reference/expected/type_cc.o_o_viz
+++ b/test_cases/diff_tests/reference/expected/type_cc.o_o_viz
@@ -1,22 +1,22 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int func(struct foo)' {_Z4func3foo} -> 'long func(struct foo)' {_Z4func3foo}"]
-  "2" [label="'int(struct foo)' -> 'long(struct foo)'"]
-  "3" [color=red, label="'int' -> 'long'"]
+  "1" [label="'int func(struct foo)' {_Z4func3foo} → 'long func(struct foo)' {_Z4func3foo}"]
+  "2" [label="'int(struct foo)' → 'long(struct foo)'"]
+  "3" [color=red, label="'int' → 'long'"]
   "2" -> "3" [label="return"]
   "4" [shape=rectangle, label="'struct foo'"]
-  "5" [label="'int* ptr' -> 'long* ptr'"]
-  "6" [label="'int*' -> 'long*'"]
+  "5" [label="'int* ptr' → 'long* ptr'"]
+  "6" [label="'int*' → 'long*'"]
   "6" -> "3" [label="pointed-to"]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
-  "7" [label="'int& lref' -> 'long& lref'"]
-  "8" [label="'int&' -> 'long&'"]
+  "7" [label="'int& lref' → 'long& lref'"]
+  "8" [label="'int&' → 'long&'"]
   "8" -> "3" [label="referred-to"]
   "7" -> "8" [label=""]
   "4" -> "7" [label=""]
-  "9" [label="'int&& rref' -> 'long&& rref'"]
-  "10" [label="'int&&' -> 'long&&'"]
+  "9" [label="'int&& rref' → 'long&& rref'"]
+  "10" [label="'int&&' → 'long&&'"]
   "10" -> "3" [label="referred-to"]
   "9" -> "10" [label=""]
   "4" -> "9" [label=""]
diff --git a/test_cases/diff_tests/scc/expected/simple_c.btf_btf_viz b/test_cases/diff_tests/scc/expected/simple_c.btf_btf_viz
index 0e27523..1f92428 100644
--- a/test_cases/diff_tests/scc/expected/simple_c.btf_btf_viz
+++ b/test_cases/diff_tests/scc/expected/simple_c.btf_btf_viz
@@ -8,8 +8,8 @@ digraph "ABI diff" {
   "5" -> "3" [label="pointed-to"]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
-  "6" [label="'char extra' -> 'short extra'"]
-  "7" [color=red, label="'char' -> 'short'"]
+  "6" [label="'char extra' → 'short extra'"]
+  "7" [color=red, label="'char' → 'short'"]
   "6" -> "7" [label=""]
   "3" -> "6" [label=""]
   "2" -> "3" [label="parameter 1"]
diff --git a/test_cases/diff_tests/scc/expected/simple_c.o_o_viz b/test_cases/diff_tests/scc/expected/simple_c.o_o_viz
index 0e27523..1f92428 100644
--- a/test_cases/diff_tests/scc/expected/simple_c.o_o_viz
+++ b/test_cases/diff_tests/scc/expected/simple_c.o_o_viz
@@ -8,8 +8,8 @@ digraph "ABI diff" {
   "5" -> "3" [label="pointed-to"]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
-  "6" [label="'char extra' -> 'short extra'"]
-  "7" [color=red, label="'char' -> 'short'"]
+  "6" [label="'char extra' → 'short extra'"]
+  "7" [color=red, label="'char' → 'short'"]
   "6" -> "7" [label=""]
   "3" -> "6" [label=""]
   "2" -> "3" [label="parameter 1"]
diff --git a/test_cases/diff_tests/static/expected/simple_cc.o_o_viz b/test_cases/diff_tests/static/expected/simple_cc.o_o_viz
index 8b5bdac..a369c61 100644
--- a/test_cases/diff_tests/static/expected/simple_cc.o_o_viz
+++ b/test_cases/diff_tests/static/expected/simple_cc.o_o_viz
@@ -8,12 +8,12 @@ digraph "ABI diff" {
   "0" -> "3" [label=""]
   "4" [color=red, label="added(int Rename::print_new() {_ZN6Rename9print_newEv})"]
   "0" -> "4" [label=""]
-  "5" [label="'int ChangeType::st' {_ZN10ChangeType2stE} -> 'long ChangeType::st' {_ZN10ChangeType2stE}"]
-  "6" [color=red, label="'int' -> 'long'"]
+  "5" [label="'int ChangeType::st' {_ZN10ChangeType2stE} → 'long ChangeType::st' {_ZN10ChangeType2stE}"]
+  "6" [color=red, label="'int' → 'long'"]
   "5" -> "6" [label=""]
   "0" -> "5" [label=""]
-  "7" [label="'int ChangeType::print()' {_ZN10ChangeType5printEv} -> 'long ChangeType::print()' {_ZN10ChangeType5printEv}"]
-  "8" [label="'int()' -> 'long()'"]
+  "7" [label="'int ChangeType::print()' {_ZN10ChangeType5printEv} → 'long ChangeType::print()' {_ZN10ChangeType5printEv}"]
+  "8" [label="'int()' → 'long()'"]
   "8" -> "6" [label="return"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
diff --git a/test_cases/diff_tests/struct/expected/nested_c.btf_btf_viz b/test_cases/diff_tests/struct/expected/nested_c.btf_btf_viz
index 54aded6..e507ae9 100644
--- a/test_cases/diff_tests/struct/expected/nested_c.btf_btf_viz
+++ b/test_cases/diff_tests/struct/expected/nested_c.btf_btf_viz
@@ -9,8 +9,8 @@ digraph "ABI diff" {
   "5" [color=red, shape=rectangle, label="'struct nested'"]
   "5" -> "5:0"
   "5:0" [color=red, label="byte size changed from 4 to 8"]
-  "6" [label="'int x' -> 'long x'"]
-  "7" [color=red, label="'int' -> 'long'"]
+  "6" [label="'int x' → 'long x'"]
+  "7" [color=red, label="'int' → 'long'"]
   "6" -> "7" [label=""]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
diff --git a/test_cases/diff_tests/struct/expected/nested_c.o_o_viz b/test_cases/diff_tests/struct/expected/nested_c.o_o_viz
index 54aded6..e507ae9 100644
--- a/test_cases/diff_tests/struct/expected/nested_c.o_o_viz
+++ b/test_cases/diff_tests/struct/expected/nested_c.o_o_viz
@@ -9,8 +9,8 @@ digraph "ABI diff" {
   "5" [color=red, shape=rectangle, label="'struct nested'"]
   "5" -> "5:0"
   "5:0" [color=red, label="byte size changed from 4 to 8"]
-  "6" [label="'int x' -> 'long x'"]
-  "7" [color=red, label="'int' -> 'long'"]
+  "6" [label="'int x' → 'long x'"]
+  "7" [color=red, label="'int' → 'long'"]
   "6" -> "7" [label=""]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
diff --git a/test_cases/diff_tests/struct/expected/nested_cc.o_o_viz b/test_cases/diff_tests/struct/expected/nested_cc.o_o_viz
index 9e5aaad..7d8ce28 100644
--- a/test_cases/diff_tests/struct/expected/nested_cc.o_o_viz
+++ b/test_cases/diff_tests/struct/expected/nested_cc.o_o_viz
@@ -9,8 +9,8 @@ digraph "ABI diff" {
   "5" [color=red, shape=rectangle, label="'struct nested'"]
   "5" -> "5:0"
   "5:0" [color=red, label="byte size changed from 4 to 8"]
-  "6" [label="'int x' -> 'long x'"]
-  "7" [color=red, label="'int' -> 'long'"]
+  "6" [label="'int x' → 'long x'"]
+  "7" [color=red, label="'int' → 'long'"]
   "6" -> "7" [label=""]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
diff --git a/test_cases/diff_tests/symbol/expected/alias_c.o_o_viz b/test_cases/diff_tests/symbol/expected/alias_c.o_o_viz
index b2c1491..a461af5 100644
--- a/test_cases/diff_tests/symbol/expected/alias_c.o_o_viz
+++ b/test_cases/diff_tests/symbol/expected/alias_c.o_o_viz
@@ -1,6 +1,6 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [color=red, label="'int a()' {c} -> 'int b()' {c}"]
+  "1" [color=red, label="'int a()' {c} → 'int b()' {c}"]
   "1" -> "1:0"
   "1:0" [color=red, label="binding changed from weak to global"]
   "0" -> "1" [label=""]
diff --git a/test_cases/diff_tests/symbol/expected/changes_c.o_o_viz b/test_cases/diff_tests/symbol/expected/changes_c.o_o_viz
index 2fa4294..524cd86 100644
--- a/test_cases/diff_tests/symbol/expected/changes_c.o_o_viz
+++ b/test_cases/diff_tests/symbol/expected/changes_c.o_o_viz
@@ -4,8 +4,8 @@ digraph "ABI diff" {
   "0" -> "1" [label=""]
   "2" [color=red, label="added(int added)"]
   "0" -> "2" [label=""]
-  "3" [label="'int diff' -> 'long diff'"]
-  "4" [color=red, label="'int' -> 'long'"]
+  "3" [label="'int diff' → 'long diff'"]
+  "4" [color=red, label="'int' → 'long'"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
 }
diff --git a/test_cases/diff_tests/symbol/expected/ifunc_c.btf_btf_viz b/test_cases/diff_tests/symbol/expected/ifunc_c.btf_btf_viz
index 603a6fd..7f2188c 100644
--- a/test_cases/diff_tests/symbol/expected/ifunc_c.btf_btf_viz
+++ b/test_cases/diff_tests/symbol/expected/ifunc_c.btf_btf_viz
@@ -1,15 +1,15 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'void my_func()' -> 'void my_func(int)'"]
-  "2" [label="'void()' -> 'void(int)'"]
+  "1" [label="'void my_func()' → 'void my_func(int)'"]
+  "2" [label="'void()' → 'void(int)'"]
   "3" [color=red, label="added(int)"]
   "2" -> "3" [label="parameter 1 of"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "4" [label="'void(* resolve_func())()' -> 'void(* resolve_func())(int)'"]
-  "5" [label="'void(*())()' -> 'void(*())(int)'"]
-  "6" [label="'void(*)()' -> 'void(*)(int)'"]
-  "7" [label="'void()' -> 'void(int)'"]
+  "4" [label="'void(* resolve_func())()' → 'void(* resolve_func())(int)'"]
+  "5" [label="'void(*())()' → 'void(*())(int)'"]
+  "6" [label="'void(*)()' → 'void(*)(int)'"]
+  "7" [label="'void()' → 'void(int)'"]
   "7" -> "3" [label="parameter 1 of"]
   "6" -> "7" [label="pointed-to"]
   "5" -> "6" [label="return"]
diff --git a/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_c.btf_btf_viz b/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_c.btf_btf_viz
index 07ae1f1..6336d6d 100644
--- a/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_c.btf_btf_viz
+++ b/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_c.btf_btf_viz
@@ -4,9 +4,9 @@ digraph "ABI diff" {
   "0" -> "1" [label=""]
   "2" [color=red, label="added(long added_fun())"]
   "0" -> "2" [label=""]
-  "3" [label="'int changed_fun()' -> 'long changed_fun()'"]
-  "4" [label="'int()' -> 'long()'"]
-  "5" [color=red, label="'int' -> 'long'"]
+  "3" [label="'int changed_fun()' → 'long changed_fun()'"]
+  "4" [label="'int()' → 'long()'"]
+  "5" [color=red, label="'int' → 'long'"]
   "4" -> "5" [label="return"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
diff --git a/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_c.o_o_viz b/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_c.o_o_viz
index a8d1ec6..c8cf0eb 100644
--- a/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_c.o_o_viz
+++ b/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_c.o_o_viz
@@ -8,13 +8,13 @@ digraph "ABI diff" {
   "0" -> "3" [label=""]
   "4" [color=red, label="added(long added_var)"]
   "0" -> "4" [label=""]
-  "5" [label="'int changed_fun()' -> 'long changed_fun()'"]
-  "6" [label="'int()' -> 'long()'"]
-  "7" [color=red, label="'int' -> 'long'"]
+  "5" [label="'int changed_fun()' → 'long changed_fun()'"]
+  "6" [label="'int()' → 'long()'"]
+  "7" [color=red, label="'int' → 'long'"]
   "6" -> "7" [label="return"]
   "5" -> "6" [label=""]
   "0" -> "5" [label=""]
-  "8" [label="'int changed_var' -> 'long changed_var'"]
+  "8" [label="'int changed_var' → 'long changed_var'"]
   "8" -> "7" [label=""]
   "0" -> "8" [label=""]
 }
diff --git a/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_cc.o_o_viz b/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_cc.o_o_viz
index ecde12f..271fef4 100644
--- a/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_cc.o_o_viz
+++ b/test_cases/diff_tests/symbol/expected/variable_function_removed_changed_added_cc.o_o_viz
@@ -8,13 +8,13 @@ digraph "ABI diff" {
   "0" -> "3" [label=""]
   "4" [color=red, label="added(long added_var)"]
   "0" -> "4" [label=""]
-  "5" [label="'int changed_fun()' {_Z11changed_funv} -> 'long changed_fun()' {_Z11changed_funv}"]
-  "6" [label="'int()' -> 'long()'"]
-  "7" [color=red, label="'int' -> 'long'"]
+  "5" [label="'int changed_fun()' {_Z11changed_funv} → 'long changed_fun()' {_Z11changed_funv}"]
+  "6" [label="'int()' → 'long()'"]
+  "7" [color=red, label="'int' → 'long'"]
   "6" -> "7" [label="return"]
   "5" -> "6" [label=""]
   "0" -> "5" [label=""]
-  "8" [label="'int changed_var' -> 'long changed_var'"]
+  "8" [label="'int changed_var' → 'long changed_var'"]
   "8" -> "7" [label=""]
   "0" -> "8" [label=""]
 }
diff --git a/test_cases/diff_tests/typedef/expected/chain_c.btf_btf_viz b/test_cases/diff_tests/typedef/expected/chain_c.btf_btf_viz
index 9316ffd..37b1126 100644
--- a/test_cases/diff_tests/typedef/expected/chain_c.btf_btf_viz
+++ b/test_cases/diff_tests/typedef/expected/chain_c.btf_btf_viz
@@ -1,12 +1,12 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int func(struct foo)' -> 'unsigned int func(struct foo)'"]
-  "2" [label="'int(struct foo)' -> 'unsigned int(struct foo)'"]
-  "3" [color=red, label="'int' -> 'unsigned int'"]
+  "1" [label="'int func(struct foo)' → 'unsigned int func(struct foo)'"]
+  "2" [label="'int(struct foo)' → 'unsigned int(struct foo)'"]
+  "3" [color=red, label="'int' → 'unsigned int'"]
   "2" -> "3" [label="return"]
   "4" [shape=rectangle, label="'struct foo'"]
   "5" [label="'INT_3 x'"]
-  "6" [shape=rectangle, label="'INT_3' = 'INT_2' = 'INT_1' = 'int' -> 'INT_3' = 'INT_2' = 'INT_1' = 'unsigned int'"]
+  "6" [shape=rectangle, label="'INT_3' = 'INT_2' = 'INT_1' = 'int' → 'INT_3' = 'INT_2' = 'INT_1' = 'unsigned int'"]
   "6" -> "3" [label="resolved"]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
diff --git a/test_cases/diff_tests/typedef/expected/chain_c.o_o_viz b/test_cases/diff_tests/typedef/expected/chain_c.o_o_viz
index 9316ffd..37b1126 100644
--- a/test_cases/diff_tests/typedef/expected/chain_c.o_o_viz
+++ b/test_cases/diff_tests/typedef/expected/chain_c.o_o_viz
@@ -1,12 +1,12 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int func(struct foo)' -> 'unsigned int func(struct foo)'"]
-  "2" [label="'int(struct foo)' -> 'unsigned int(struct foo)'"]
-  "3" [color=red, label="'int' -> 'unsigned int'"]
+  "1" [label="'int func(struct foo)' → 'unsigned int func(struct foo)'"]
+  "2" [label="'int(struct foo)' → 'unsigned int(struct foo)'"]
+  "3" [color=red, label="'int' → 'unsigned int'"]
   "2" -> "3" [label="return"]
   "4" [shape=rectangle, label="'struct foo'"]
   "5" [label="'INT_3 x'"]
-  "6" [shape=rectangle, label="'INT_3' = 'INT_2' = 'INT_1' = 'int' -> 'INT_3' = 'INT_2' = 'INT_1' = 'unsigned int'"]
+  "6" [shape=rectangle, label="'INT_3' = 'INT_2' = 'INT_1' = 'int' → 'INT_3' = 'INT_2' = 'INT_1' = 'unsigned int'"]
   "6" -> "3" [label="resolved"]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
diff --git a/test_cases/diff_tests/typedef/expected/scoped_composite_nested_struct_cc.o_o_viz b/test_cases/diff_tests/typedef/expected/scoped_composite_nested_struct_cc.o_o_viz
index 380beba..acd09d7 100644
--- a/test_cases/diff_tests/typedef/expected/scoped_composite_nested_struct_cc.o_o_viz
+++ b/test_cases/diff_tests/typedef/expected/scoped_composite_nested_struct_cc.o_o_viz
@@ -9,8 +9,8 @@ digraph "ABI diff" {
   "5" [color=red, shape=rectangle, label="'struct Scope::<unnamed struct>::Nested'"]
   "5" -> "5:0"
   "5:0" [color=red, label="byte size changed from 4 to 8"]
-  "6" [label="'int x' -> 'long x'"]
-  "7" [color=red, label="'int' -> 'long'"]
+  "6" [label="'int x' → 'long x'"]
+  "7" [color=red, label="'int' → 'long'"]
   "6" -> "7" [label=""]
   "5" -> "6" [label=""]
   "4" -> "5" [label=""]
@@ -38,7 +38,7 @@ digraph "ABI diff" {
   "16" [color=red, shape=rectangle, label="'struct Scope::<unnamed union>::Nested'"]
   "16" -> "16:0"
   "16:0" [color=red, label="byte size changed from 4 to 8"]
-  "17" [label="'int x' -> 'long x'"]
+  "17" [label="'int x' → 'long x'"]
   "17" -> "7" [label=""]
   "16" -> "17" [label=""]
   "15" -> "16" [label=""]
diff --git a/test_cases/diff_tests/typedef/expected/simple_c.btf_btf_viz b/test_cases/diff_tests/typedef/expected/simple_c.btf_btf_viz
index 0162196..0e76b70 100644
--- a/test_cases/diff_tests/typedef/expected/simple_c.btf_btf_viz
+++ b/test_cases/diff_tests/typedef/expected/simple_c.btf_btf_viz
@@ -5,17 +5,17 @@ digraph "ABI diff" {
   "3" [color=red, shape=rectangle, label="'struct foo'"]
   "3" -> "3:0"
   "3:0" [color=red, label="byte size changed from 2 to 4"]
-  "4" [label="'small x' -> 'large x'"]
-  "5" [label="'small' = 'short' -> 'large' = 'int'"]
-  "6" [color=red, label="'short' -> 'int'"]
+  "4" [label="'small x' → 'large x'"]
+  "5" [label="'small' = 'short' → 'large' = 'int'"]
+  "6" [color=red, label="'short' → 'int'"]
   "5" -> "6" [label="resolved"]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
   "2" -> "3" [label="parameter 1"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "7" [label="'long id2(small)' -> 'long id2(large)'"]
-  "8" [label="'long(small)' -> 'long(large)'"]
+  "7" [label="'long id2(small)' → 'long id2(large)'"]
+  "8" [label="'long(small)' → 'long(large)'"]
   "8" -> "5" [label="parameter 1"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
diff --git a/test_cases/diff_tests/typedef/expected/simple_c.o_o_viz b/test_cases/diff_tests/typedef/expected/simple_c.o_o_viz
index 0162196..0e76b70 100644
--- a/test_cases/diff_tests/typedef/expected/simple_c.o_o_viz
+++ b/test_cases/diff_tests/typedef/expected/simple_c.o_o_viz
@@ -5,17 +5,17 @@ digraph "ABI diff" {
   "3" [color=red, shape=rectangle, label="'struct foo'"]
   "3" -> "3:0"
   "3:0" [color=red, label="byte size changed from 2 to 4"]
-  "4" [label="'small x' -> 'large x'"]
-  "5" [label="'small' = 'short' -> 'large' = 'int'"]
-  "6" [color=red, label="'short' -> 'int'"]
+  "4" [label="'small x' → 'large x'"]
+  "5" [label="'small' = 'short' → 'large' = 'int'"]
+  "6" [color=red, label="'short' → 'int'"]
   "5" -> "6" [label="resolved"]
   "4" -> "5" [label=""]
   "3" -> "4" [label=""]
   "2" -> "3" [label="parameter 1"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "7" [label="'long id2(small)' -> 'long id2(large)'"]
-  "8" [label="'long(small)' -> 'long(large)'"]
+  "7" [label="'long id2(small)' → 'long id2(large)'"]
+  "8" [label="'long(small)' → 'long(large)'"]
   "8" -> "5" [label="parameter 1"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
diff --git a/test_cases/diff_tests/typedef/expected/simple_cc.o_o_viz b/test_cases/diff_tests/typedef/expected/simple_cc.o_o_viz
index 05415fc..008574f 100644
--- a/test_cases/diff_tests/typedef/expected/simple_cc.o_o_viz
+++ b/test_cases/diff_tests/typedef/expected/simple_cc.o_o_viz
@@ -9,9 +9,9 @@ digraph "ABI diff" {
   "5" [color=red, shape=rectangle, label="'struct foo'"]
   "5" -> "5:0"
   "5:0" [color=red, label="byte size changed from 2 to 4"]
-  "6" [label="'small x' -> 'large x'"]
-  "7" [label="'small' = 'short' -> 'large' = 'int'"]
-  "8" [color=red, label="'short' -> 'int'"]
+  "6" [label="'small x' → 'large x'"]
+  "7" [label="'small' = 'short' → 'large' = 'int'"]
+  "8" [color=red, label="'short' → 'int'"]
   "7" -> "8" [label="resolved"]
   "6" -> "7" [label=""]
   "5" -> "6" [label=""]
diff --git a/test_cases/diff_tests/types/expected/char_c.btf_btf_viz b/test_cases/diff_tests/types/expected/char_c.btf_btf_viz
index c68b05c..51f70ba 100644
--- a/test_cases/diff_tests/types/expected/char_c.btf_btf_viz
+++ b/test_cases/diff_tests/types/expected/char_c.btf_btf_viz
@@ -1,38 +1,38 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int u(char)' -> 'int u(unsigned char)'"]
-  "2" [label="'int(char)' -> 'int(unsigned char)'"]
-  "3" [color=red, label="'char' -> 'unsigned char'"]
+  "1" [label="'int u(char)' → 'int u(unsigned char)'"]
+  "2" [label="'int(char)' → 'int(unsigned char)'"]
+  "3" [color=red, label="'char' → 'unsigned char'"]
   "2" -> "3" [label="parameter 1"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "4" [label="'int v(unsigned char)' -> 'int v(signed char)'"]
-  "5" [label="'int(unsigned char)' -> 'int(signed char)'"]
-  "6" [color=red, label="'unsigned char' -> 'signed char'"]
+  "4" [label="'int v(unsigned char)' → 'int v(signed char)'"]
+  "5" [label="'int(unsigned char)' → 'int(signed char)'"]
+  "6" [color=red, label="'unsigned char' → 'signed char'"]
   "5" -> "6" [label="parameter 1"]
   "4" -> "5" [label=""]
   "0" -> "4" [label=""]
-  "7" [label="'int w(signed char)' -> 'int w(char)'"]
-  "8" [label="'int(signed char)' -> 'int(char)'"]
-  "9" [color=red, label="'signed char' -> 'char'"]
+  "7" [label="'int w(signed char)' → 'int w(char)'"]
+  "8" [label="'int(signed char)' → 'int(char)'"]
+  "9" [color=red, label="'signed char' → 'char'"]
   "8" -> "9" [label="parameter 1"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
-  "10" [label="'int x(char)' -> 'int x(signed char)'"]
-  "11" [label="'int(char)' -> 'int(signed char)'"]
-  "12" [color=red, label="'char' -> 'signed char'"]
+  "10" [label="'int x(char)' → 'int x(signed char)'"]
+  "11" [label="'int(char)' → 'int(signed char)'"]
+  "12" [color=red, label="'char' → 'signed char'"]
   "11" -> "12" [label="parameter 1"]
   "10" -> "11" [label=""]
   "0" -> "10" [label=""]
-  "13" [label="'int y(unsigned char)' -> 'int y(char)'"]
-  "14" [label="'int(unsigned char)' -> 'int(char)'"]
-  "15" [color=red, label="'unsigned char' -> 'char'"]
+  "13" [label="'int y(unsigned char)' → 'int y(char)'"]
+  "14" [label="'int(unsigned char)' → 'int(char)'"]
+  "15" [color=red, label="'unsigned char' → 'char'"]
   "14" -> "15" [label="parameter 1"]
   "13" -> "14" [label=""]
   "0" -> "13" [label=""]
-  "16" [label="'int z(signed char)' -> 'int z(unsigned char)'"]
-  "17" [label="'int(signed char)' -> 'int(unsigned char)'"]
-  "18" [color=red, label="'signed char' -> 'unsigned char'"]
+  "16" [label="'int z(signed char)' → 'int z(unsigned char)'"]
+  "17" [label="'int(signed char)' → 'int(unsigned char)'"]
+  "18" [color=red, label="'signed char' → 'unsigned char'"]
   "17" -> "18" [label="parameter 1"]
   "16" -> "17" [label=""]
   "0" -> "16" [label=""]
diff --git a/test_cases/diff_tests/types/expected/char_c.o_o_viz b/test_cases/diff_tests/types/expected/char_c.o_o_viz
index c68b05c..51f70ba 100644
--- a/test_cases/diff_tests/types/expected/char_c.o_o_viz
+++ b/test_cases/diff_tests/types/expected/char_c.o_o_viz
@@ -1,38 +1,38 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'int u(char)' -> 'int u(unsigned char)'"]
-  "2" [label="'int(char)' -> 'int(unsigned char)'"]
-  "3" [color=red, label="'char' -> 'unsigned char'"]
+  "1" [label="'int u(char)' → 'int u(unsigned char)'"]
+  "2" [label="'int(char)' → 'int(unsigned char)'"]
+  "3" [color=red, label="'char' → 'unsigned char'"]
   "2" -> "3" [label="parameter 1"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "4" [label="'int v(unsigned char)' -> 'int v(signed char)'"]
-  "5" [label="'int(unsigned char)' -> 'int(signed char)'"]
-  "6" [color=red, label="'unsigned char' -> 'signed char'"]
+  "4" [label="'int v(unsigned char)' → 'int v(signed char)'"]
+  "5" [label="'int(unsigned char)' → 'int(signed char)'"]
+  "6" [color=red, label="'unsigned char' → 'signed char'"]
   "5" -> "6" [label="parameter 1"]
   "4" -> "5" [label=""]
   "0" -> "4" [label=""]
-  "7" [label="'int w(signed char)' -> 'int w(char)'"]
-  "8" [label="'int(signed char)' -> 'int(char)'"]
-  "9" [color=red, label="'signed char' -> 'char'"]
+  "7" [label="'int w(signed char)' → 'int w(char)'"]
+  "8" [label="'int(signed char)' → 'int(char)'"]
+  "9" [color=red, label="'signed char' → 'char'"]
   "8" -> "9" [label="parameter 1"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
-  "10" [label="'int x(char)' -> 'int x(signed char)'"]
-  "11" [label="'int(char)' -> 'int(signed char)'"]
-  "12" [color=red, label="'char' -> 'signed char'"]
+  "10" [label="'int x(char)' → 'int x(signed char)'"]
+  "11" [label="'int(char)' → 'int(signed char)'"]
+  "12" [color=red, label="'char' → 'signed char'"]
   "11" -> "12" [label="parameter 1"]
   "10" -> "11" [label=""]
   "0" -> "10" [label=""]
-  "13" [label="'int y(unsigned char)' -> 'int y(char)'"]
-  "14" [label="'int(unsigned char)' -> 'int(char)'"]
-  "15" [color=red, label="'unsigned char' -> 'char'"]
+  "13" [label="'int y(unsigned char)' → 'int y(char)'"]
+  "14" [label="'int(unsigned char)' → 'int(char)'"]
+  "15" [color=red, label="'unsigned char' → 'char'"]
   "14" -> "15" [label="parameter 1"]
   "13" -> "14" [label=""]
   "0" -> "13" [label=""]
-  "16" [label="'int z(signed char)' -> 'int z(unsigned char)'"]
-  "17" [label="'int(signed char)' -> 'int(unsigned char)'"]
-  "18" [color=red, label="'signed char' -> 'unsigned char'"]
+  "16" [label="'int z(signed char)' → 'int z(unsigned char)'"]
+  "17" [label="'int(signed char)' → 'int(unsigned char)'"]
+  "18" [color=red, label="'signed char' → 'unsigned char'"]
   "17" -> "18" [label="parameter 1"]
   "16" -> "17" [label=""]
   "0" -> "16" [label=""]
diff --git a/test_cases/diff_tests/types/expected/pointer_c.o_o_viz b/test_cases/diff_tests/types/expected/pointer_c.o_o_viz
index 634416c..ad1f411 100644
--- a/test_cases/diff_tests/types/expected/pointer_c.o_o_viz
+++ b/test_cases/diff_tests/types/expected/pointer_c.o_o_viz
@@ -4,8 +4,8 @@ digraph "ABI diff" {
   "2" [color=red, shape=rectangle, label="'struct foo'"]
   "2" -> "2:0"
   "2:0" [color=red, label="byte size changed from 4 to 8"]
-  "3" [label="'int x' -> 'long x'"]
-  "4" [color=red, label="'int' -> 'long'"]
+  "3" [label="'int x' → 'long x'"]
+  "4" [color=red, label="'int' → 'long'"]
   "3" -> "4" [label=""]
   "2" -> "3" [label=""]
   "1" -> "2" [label=""]
diff --git a/test_cases/diff_tests/types/expected/pointer_reference_cc.o_o_viz b/test_cases/diff_tests/types/expected/pointer_reference_cc.o_o_viz
index 09c64e4..0fb5c41 100644
--- a/test_cases/diff_tests/types/expected/pointer_reference_cc.o_o_viz
+++ b/test_cases/diff_tests/types/expected/pointer_reference_cc.o_o_viz
@@ -4,8 +4,8 @@ digraph "ABI diff" {
   "2" [color=red, shape=rectangle, label="'struct foo'"]
   "2" -> "2:0"
   "2:0" [color=red, label="byte size changed from 4 to 8"]
-  "3" [label="'int x' -> 'long x'"]
-  "4" [color=red, label="'int' -> 'long'"]
+  "3" [label="'int x' → 'long x'"]
+  "4" [color=red, label="'int' → 'long'"]
   "3" -> "4" [label=""]
   "2" -> "3" [label=""]
   "1" -> "2" [label=""]
diff --git a/test_cases/info_tests/variant/expected/negative_discriminant_rs.elf_stg b/test_cases/info_tests/variant/expected/negative_discriminant_rs.elf_stg
index 021539c..ea773db 100644
--- a/test_cases/info_tests/variant/expected/negative_discriminant_rs.elf_stg
+++ b/test_cases/info_tests/variant/expected/negative_discriminant_rs.elf_stg
@@ -32,19 +32,19 @@ variant_member {
   id: 0x72c55dce
   name: "MinusTwo"
   discriminant_value: 65534
-  type_id: 0xc8fb9972
+  type_id: 0xc8fb9972  # struct negative_discriminant::Foo::MinusTwo
 }
 variant_member {
   id: 0x528ee922
   name: "MinusOne"
   discriminant_value: 65535
-  type_id: 0xdfc84a58
+  type_id: 0xdfc84a58  # struct negative_discriminant::Foo::MinusOne
 }
 variant_member {
   id: 0x27839c0b
   name: "Zero"
   discriminant_value: 0
-  type_id: 0x5da8c8f1
+  type_id: 0x5da8c8f1  # struct negative_discriminant::Foo::Zero
 }
 struct_union {
   id: 0xdfc84a58
diff --git a/test_cases/info_tests/variant/expected/offset_discriminant_rs.elf_stg b/test_cases/info_tests/variant/expected/offset_discriminant_rs.elf_stg
index e7ab069..6f802d8 100644
--- a/test_cases/info_tests/variant/expected/offset_discriminant_rs.elf_stg
+++ b/test_cases/info_tests/variant/expected/offset_discriminant_rs.elf_stg
@@ -19,8 +19,13 @@ primitive {
   bytesize: 0x00000004
 }
 member {
-  id: 0x16e523e2
+  id: 0x16e52ed9
   type_id: 0xd4bacb77  # u32
+}
+member {
+  id: 0x978131cb
+  name: "__0"
+  type_id: 0x384f7d7c  # char
   offset: 32
 }
 member {
@@ -37,19 +42,19 @@ member {
 variant_member {
   id: 0x56b9f935
   name: "Two"
-  type_id: 0x573dc947
+  type_id: 0x573dc947  # struct offset_discriminant::Foo::Two
 }
 variant_member {
   id: 0x69cfc441
   name: "One"
   discriminant_value: 1114112
-  type_id: 0x988e2459
+  type_id: 0x988e2459  # struct offset_discriminant::Foo::One
 }
 variant_member {
   id: 0x276cfc01
   name: "Zero"
   discriminant_value: 1114113
-  type_id: 0xb2cd8432
+  type_id: 0xb2cd8432  # struct offset_discriminant::Foo::Zero
 }
 struct_union {
   id: 0x988e2459
@@ -57,7 +62,7 @@ struct_union {
   name: "offset_discriminant::Foo::One"
   definition {
     bytesize: 8
-    member_id: 0x97813cf0  # char __0
+    member_id: 0x978131cb  # char __0
   }
 }
 struct_union {
@@ -82,7 +87,7 @@ variant {
   id: 0x82b2aa29
   name: "offset_discriminant::Foo"
   bytesize: 8
-  discriminant: 0x16e523e2
+  discriminant: 0x16e52ed9
   member_id: 0x56b9f935
   member_id: 0x69cfc441
   member_id: 0x276cfc01
diff --git a/test_cases/info_tests/variant/expected/optional_empty_rs.elf_stg b/test_cases/info_tests/variant/expected/optional_empty_rs.elf_stg
index 0584271..a54fa5f 100644
--- a/test_cases/info_tests/variant/expected/optional_empty_rs.elf_stg
+++ b/test_cases/info_tests/variant/expected/optional_empty_rs.elf_stg
@@ -14,12 +14,12 @@ member {
 variant_member {
   id: 0x5212c510
   name: "None"
-  type_id: 0x3d2f2a96
+  type_id: 0x3d2f2a96  # struct core::option::Option<optional_empty::Empty>::None
 }
 variant_member {
   id: 0x3107bf38
   name: "Some"
-  type_id: 0x0148ce39
+  type_id: 0x0148ce39  # struct core::option::Option<optional_empty::Empty>::Some
 }
 struct_union {
   id: 0x3d2f2a96
diff --git a/test_cases/info_tests/variant/expected/simple_rs.elf_stg b/test_cases/info_tests/variant/expected/simple_rs.elf_stg
index 8473682..217fc6f 100644
--- a/test_cases/info_tests/variant/expected/simple_rs.elf_stg
+++ b/test_cases/info_tests/variant/expected/simple_rs.elf_stg
@@ -62,19 +62,19 @@ variant_member {
   id: 0xfc632c0e
   name: "Unit"
   discriminant_value: 0
-  type_id: 0x624786fb
+  type_id: 0x624786fb  # struct simple::Foo::Unit
 }
 variant_member {
   id: 0xad130615
   name: "TwoU32s"
   discriminant_value: 1
-  type_id: 0x117f6853
+  type_id: 0x117f6853  # struct simple::Foo::TwoU32s
 }
 variant_member {
   id: 0xc48d72bf
   name: "ThreeI16s"
   discriminant_value: 2
-  type_id: 0x0e0db07a
+  type_id: 0x0e0db07a  # struct simple::Foo::ThreeI16s
 }
 struct_union {
   id: 0x0e0db07a
diff --git a/test_cases/info_tests/variant/expected/singleton_rs.elf_stg b/test_cases/info_tests/variant/expected/singleton_rs.elf_stg
index ed52414..15ab1d1 100644
--- a/test_cases/info_tests/variant/expected/singleton_rs.elf_stg
+++ b/test_cases/info_tests/variant/expected/singleton_rs.elf_stg
@@ -9,7 +9,7 @@ primitive {
 variant_member {
   id: 0xfc304e1e
   name: "Unit"
-  type_id: 0x312c753c
+  type_id: 0x312c753c  # struct singleton::Singleton::Unit
 }
 struct_union {
   id: 0x312c753c
diff --git a/testdata/added_removed_enumerators_0.stg b/testdata/added_removed_enumerators_0.stg
new file mode 100644
index 0000000..952be15
--- /dev/null
+++ b/testdata/added_removed_enumerators_0.stg
@@ -0,0 +1,117 @@
+version: 0x00000002
+root_id: 0x84ea5130
+primitive {
+  id: 0x4585663f
+  name: "unsigned int"
+  encoding: UNSIGNED_INTEGER
+  bytesize: 0x00000004
+}
+enumeration {
+  id: 0x5ccb42b9
+  definition {
+    underlying_type_id: 0x4585663f
+    enumerator {
+      name: "a"
+    }
+  }
+}
+enumeration {
+  id: 0x66fc3a74
+  definition {
+    underlying_type_id: 0x4585663f
+    enumerator {
+      name: "zero"
+    }
+    enumerator {
+      name: "one"
+      value: 1
+    }
+    enumerator {
+      name: "two"
+      value: 2
+    }
+    enumerator {
+      name: "three"
+      value: 3
+    }
+    enumerator {
+      name: "four"
+      value: 4
+    }
+    enumerator {
+      name: "five"
+      value: 5
+    }
+    enumerator {
+      name: "six"
+      value: 6
+    }
+    enumerator {
+      name: "seven"
+      value: 7
+    }
+    enumerator {
+      name: "eight"
+      value: 8
+    }
+    enumerator {
+      name: "nine"
+      value: 9
+    }
+  }
+}
+enumeration {
+  id: 0x7d6c4e42
+  definition {
+    underlying_type_id: 0x4585663f
+    enumerator {
+      name: "alpha"
+    }
+    enumerator {
+      name: "beta"
+      value: 1
+    }
+    enumerator {
+      name: "gamma"
+      value: 2
+    }
+    enumerator {
+      name: "delta"
+      value: 3
+    }
+    enumerator {
+      name: "epsilon"
+      value: 4
+    }
+  }
+}
+elf_symbol {
+  id: 0xb6ccf6fa
+  name: "u"
+  is_defined: true
+  symbol_type: OBJECT
+  type_id: 0x66fc3a74
+  full_name: "u"
+}
+elf_symbol {
+  id: 0xf48dba91
+  name: "v"
+  is_defined: true
+  symbol_type: OBJECT
+  type_id: 0x5ccb42b9
+  full_name: "v"
+}
+elf_symbol {
+  id: 0x354daa05
+  name: "w"
+  is_defined: true
+  symbol_type: OBJECT
+  type_id: 0x7d6c4e42
+  full_name: "w"
+}
+interface {
+  id: 0x84ea5130
+  symbol_id: 0xb6ccf6fa
+  symbol_id: 0xf48dba91
+  symbol_id: 0x354daa05
+}
diff --git a/testdata/added_removed_enumerators_1.stg b/testdata/added_removed_enumerators_1.stg
new file mode 100644
index 0000000..b3c7d30
--- /dev/null
+++ b/testdata/added_removed_enumerators_1.stg
@@ -0,0 +1,118 @@
+version: 0x00000002
+root_id: 0x84ea5130
+primitive {
+  id: 0x4585663f
+  name: "unsigned int"
+  encoding: UNSIGNED_INTEGER
+  bytesize: 0x00000004
+}
+enumeration {
+  id: 0x5499be13
+  definition {
+    underlying_type_id: 0x4585663f
+    enumerator {
+      name: "zeta"
+      value: 5
+    }
+    enumerator {
+      name: "eta"
+      value: 6
+    }
+    enumerator {
+      name: "theta"
+      value: 7
+    }
+    enumerator {
+      name: "iota"
+      value: 8
+    }
+    enumerator {
+      name: "kappa"
+      value: 9
+    }
+  }
+}
+enumeration {
+  id: 0x5cde5bba
+  definition {
+    underlying_type_id: 0x4585663f
+    enumerator {
+      name: "a"
+    }
+    enumerator {
+      name: "b"
+      value: 1
+    }
+    enumerator {
+      name: "c"
+      value: 2
+    }
+    enumerator {
+      name: "d"
+      value: 3
+    }
+    enumerator {
+      name: "e"
+      value: 4
+    }
+    enumerator {
+      name: "f"
+      value: 5
+    }
+    enumerator {
+      name: "g"
+      value: 6
+    }
+    enumerator {
+      name: "h"
+      value: 7
+    }
+    enumerator {
+      name: "i"
+      value: 8
+    }
+    enumerator {
+      name: "j"
+      value: 9
+    }
+  }
+}
+enumeration {
+  id: 0x66e4522f
+  definition {
+    underlying_type_id: 0x4585663f
+    enumerator {
+      name: "zero"
+    }
+  }
+}
+elf_symbol {
+  id: 0xb6ccf6fa
+  name: "u"
+  is_defined: true
+  symbol_type: OBJECT
+  type_id: 0x66e4522f
+  full_name: "u"
+}
+elf_symbol {
+  id: 0xf48dba91
+  name: "v"
+  is_defined: true
+  symbol_type: OBJECT
+  type_id: 0x5cde5bba
+  full_name: "v"
+}
+elf_symbol {
+  id: 0x354daa05
+  name: "w"
+  is_defined: true
+  symbol_type: OBJECT
+  type_id: 0x5499be13
+  full_name: "w"
+}
+interface {
+  id: 0x84ea5130
+  symbol_id: 0xb6ccf6fa
+  symbol_id: 0xf48dba91
+  symbol_id: 0x354daa05
+}
diff --git a/testdata/added_removed_enumerators_short_diff b/testdata/added_removed_enumerators_short_diff
new file mode 100644
index 0000000..6d107d1
--- /dev/null
+++ b/testdata/added_removed_enumerators_short_diff
@@ -0,0 +1,17 @@
+variable symbol changed from 'enum { zero = 0, one = 1, two = 2, three = 3, four = 4, five = 5, six = 6, seven = 7, eight = 8, nine = 9, } u' to 'enum { zero = 0, } u'
+  type changed from 'enum { zero = 0, one = 1, two = 2, three = 3, four = 4, five = 5, six = 6, seven = 7, eight = 8, nine = 9, }' to 'enum { zero = 0, }'
+    enumerator 'one' (1) was removed
+    ... 8 other enumerator(s) removed
+
+variable symbol changed from 'enum { a = 0, } v' to 'enum { a = 0, b = 1, c = 2, d = 3, e = 4, f = 5, g = 6, h = 7, i = 8, j = 9, } v'
+  type changed from 'enum { a = 0, }' to 'enum { a = 0, b = 1, c = 2, d = 3, e = 4, f = 5, g = 6, h = 7, i = 8, j = 9, }'
+    enumerator 'b' (1) was added
+    ... 8 other enumerator(s) added
+
+variable symbol changed from 'enum { alpha = 0, beta = 1, gamma = 2, delta = 3, epsilon = 4, } w' to 'enum { zeta = 5, eta = 6, theta = 7, iota = 8, kappa = 9, } w'
+  type changed from 'enum { alpha = 0, beta = 1, gamma = 2, delta = 3, epsilon = 4, }' to 'enum { zeta = 5, eta = 6, theta = 7, iota = 8, kappa = 9, }'
+    enumerator 'alpha' (0) was removed
+    ... 4 other enumerator(s) removed
+    enumerator 'zeta' (5) was added
+    ... 4 other enumerator(s) added
+
diff --git a/testdata/crc_0.xml b/testdata/crc_0.xml
index 13e9486..30b4a29 100644
--- a/testdata/crc_0.xml
+++ b/testdata/crc_0.xml
@@ -5,6 +5,7 @@
     <elf-symbol name='c' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0x1e91976d'/>
     <elf-symbol name='d' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0xb1221a47'/>
     <elf-symbol name='e' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0x9b3c3f73'/>
+    <elf-symbol name='f' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0x76f9876a'/>
   </elf-variable-symbols>
   <abi-instr address-size='64' path='test.cc' language='LANG_C_plus_plus_14'>
     <type-decl name='int' size-in-bits='32' id='95e97e5e'/>
@@ -21,5 +22,6 @@
     <var-decl name='c' type-id='95e97e5e' mangled-name='c' visibility='default' elf-symbol-id='c'/>
     <var-decl name='d' type-id='95e97e5e' mangled-name='d' visibility='default' elf-symbol-id='d'/>
     <var-decl name='e' type-id='95e97e5e' mangled-name='e' visibility='default' elf-symbol-id='e'/>
+    <var-decl name='f' type-id='95e97e5e' mangled-name='f' visibility='default' elf-symbol-id='f'/>
   </abi-instr>
 </abi-corpus>
diff --git a/testdata/crc_1.xml b/testdata/crc_1.xml
index 5d4b6e0..1b624f5 100644
--- a/testdata/crc_1.xml
+++ b/testdata/crc_1.xml
@@ -5,6 +5,7 @@
     <elf-symbol name='c' size='1' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0x10706189'/>
     <elf-symbol name='d' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0x9be92606'/>
     <elf-symbol name='e' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0x7eb59df3'/>
+    <elf-symbol name='f' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0xef67c813'/>
   </elf-variable-symbols>
   <abi-instr address-size='64' path='test.cc' language='LANG_C_plus_plus_14'>
     <type-decl name='char' size-in-bits='8' id='a84c031d'/>
@@ -25,5 +26,6 @@
     <var-decl name='c' type-id='a84c031d' mangled-name='c' visibility='default' elf-symbol-id='c'/>
     <var-decl name='d' type-id='95e97e5e' mangled-name='d' visibility='default' elf-symbol-id='d'/>
     <var-decl name='e' type-id='95e97e5e' mangled-name='e' visibility='default' elf-symbol-id='e'/>
+    <var-decl name='f' type-id='95e97e5e' mangled-name='f' visibility='default' elf-symbol-id='f'/>
   </abi-instr>
 </abi-corpus>
diff --git a/testdata/crc_changes_short_diff b/testdata/crc_changes_short_diff
index 116635c..223f6c6 100644
--- a/testdata/crc_changes_short_diff
+++ b/testdata/crc_changes_short_diff
@@ -8,7 +8,10 @@ variable symbol 'int b' changed
 variable symbol 'int d' changed
   CRC changed from 0xb1221a47 to 0x9be92606
 
-... 1 omitted; 3 symbols have only CRC changes
+variable symbol 'int e' changed
+  CRC changed from 0x9b3c3f73 to 0x7eb59df3
+
+... 1 omitted; 4 symbols have only CRC changes
 
 type 'struct A' changed
   byte size changed from 8 to 12
diff --git a/testdata/crc_only_0.xml b/testdata/crc_only_0.xml
index fc24fd9..d2a1a07 100644
--- a/testdata/crc_only_0.xml
+++ b/testdata/crc_only_0.xml
@@ -3,11 +3,13 @@
     <elf-symbol name='a' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0xb5b0e8c9' version='version'/>
     <elf-symbol name='b' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0xb70c2d59'/>
     <elf-symbol name='c' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0x1e91976d'/>
+    <elf-symbol name='d' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0xb1221a47'/>
   </elf-variable-symbols>
   <abi-instr address-size='64' path='test.cc' language='LANG_C_plus_plus_14'>
     <type-decl name='int' size-in-bits='32' id='95e97e5e'/>
     <var-decl name='a' type-id='95e97e5e' mangled-name='a' visibility='default' elf-symbol-id='a@version'/>
     <var-decl name='b' type-id='95e97e5e' mangled-name='b' visibility='default' elf-symbol-id='b'/>
     <var-decl name='c' type-id='95e97e5e' mangled-name='c' visibility='default' elf-symbol-id='c'/>
+    <var-decl name='d' type-id='95e97e5e' mangled-name='d' visibility='default' elf-symbol-id='d'/>
   </abi-instr>
 </abi-corpus>
diff --git a/testdata/crc_only_1.xml b/testdata/crc_only_1.xml
index cf17cf5..06f7ed9 100644
--- a/testdata/crc_only_1.xml
+++ b/testdata/crc_only_1.xml
@@ -3,11 +3,13 @@
     <elf-symbol name='a' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0xb7c5b6f1' version='version'/>
     <elf-symbol name='b' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0x9be92606'/>
     <elf-symbol name='c' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0x7eb59df3'/>
+    <elf-symbol name='d' size='4' type='object-type' binding='global-binding' visibility='default-visibility' is-defined='yes' crc='0x9be92606'/>
   </elf-variable-symbols>
   <abi-instr address-size='64' path='test.cc' language='LANG_C_plus_plus_14'>
     <type-decl name='int' size-in-bits='32' id='95e97e5e'/>
     <var-decl name='a' type-id='95e97e5e' mangled-name='a' visibility='default' elf-symbol-id='a@version'/>
     <var-decl name='b' type-id='95e97e5e' mangled-name='b' visibility='default' elf-symbol-id='b'/>
     <var-decl name='c' type-id='95e97e5e' mangled-name='c' visibility='default' elf-symbol-id='c'/>
+    <var-decl name='d' type-id='95e97e5e' mangled-name='d' visibility='default' elf-symbol-id='d'/>
   </abi-instr>
 </abi-corpus>
diff --git a/testdata/crc_only_changes_short_diff b/testdata/crc_only_changes_short_diff
index 8f3aa00..b6b805b 100644
--- a/testdata/crc_only_changes_short_diff
+++ b/testdata/crc_only_changes_short_diff
@@ -4,5 +4,8 @@ variable symbol 'int a' {a@version} changed
 variable symbol 'int b' changed
   CRC changed from 0xb70c2d59 to 0x9be92606
 
-... 1 omitted; 3 symbols have only CRC changes
+variable symbol 'int c' changed
+  CRC changed from 0x1e91976d to 0x7eb59df3
+
+... 1 omitted; 4 symbols have only CRC changes
 
diff --git a/type_normalisation.cc b/type_normalisation.cc
index e5d4a25..1d6a446 100644
--- a/type_normalisation.cc
+++ b/type_normalisation.cc
@@ -37,7 +37,7 @@ struct ResolveQualifiedChain {
       : graph(graph), resolved(resolved) {}
 
   Id operator()(Id node_id) {
-    return graph.Apply<Id>(*this, node_id, node_id);
+    return graph.Apply(*this, node_id, node_id);
   }
 
   Id operator()(const Qualified& x, Id node_id) {
@@ -72,7 +72,7 @@ struct FindQualifiedTypesAndFunctions {
 
   void operator()(Id id) {
     if (seen.insert(id).second) {
-      graph.Apply<void>(*this, id, id);
+      graph.Apply(*this, id, id);
     }
   }
 
@@ -187,7 +187,7 @@ struct RemoveFunctionQualifiers {
       : graph(graph), resolved(resolved) {}
 
   void operator()(Id id) {
-    graph.Apply<void>(*this, id);
+    graph.Apply(*this, id);
   }
 
   void operator()(Function& x) {
diff --git a/type_resolution.cc b/type_resolution.cc
index c9fe51d..c2734cc 100644
--- a/type_resolution.cc
+++ b/type_resolution.cc
@@ -68,7 +68,7 @@ struct NamedTypes {
   void operator()(Id id) {
     if (seen.Insert(id)) {
       ++nodes;
-      graph.Apply<void>(*this, id, id);
+      graph.Apply(*this, id, id);
     }
   }
 
diff --git a/unification.cc b/unification.cc
index 21ba792..935eece 100644
--- a/unification.cc
+++ b/unification.cc
@@ -20,8 +20,12 @@
 #include "unification.h"
 
 #include <cstddef>
+#include <map>
 #include <optional>
 #include <utility>
+#include <unordered_map>
+#include <unordered_set>
+#include <vector>
 
 #include "graph.h"
 
@@ -53,14 +57,16 @@ struct Unifier {
       return true;
     }
 
-    // Check if the comparison has an already known result.
+    // Check if the comparison has been (or is being) visited already. We don't
+    // need an SCC finder as any failure to unify will poison the entire DFS.
     //
-    // Opportunistic as seen is unaware of new mappings.
+    // This prevents infinite recursion, but maybe not immediately as seen is
+    // unaware of new mappings.
     if (!seen.emplace(fid1, fid2).second) {
       return true;
     }
 
-    const auto winner = graph.Apply2<Winner>(*this, fid1, fid2);
+    const auto winner = graph.Apply2(*this, fid1, fid2);
     if (winner == Neither) {
       return false;
     }
diff --git a/unification.h b/unification.h
index d8fde2e..85b4f56 100644
--- a/unification.h
+++ b/unification.h
@@ -21,8 +21,6 @@
 #define STG_UNIFICATION_H_
 
 #include <exception>
-#include <unordered_map>
-#include <unordered_set>
 
 #include "graph.h"
 #include "runtime.h"
@@ -53,10 +51,10 @@ class Unification {
     const Time time(runtime_, "unification.rewrite");
     Counter removed(runtime_, "unification.removed");
     Counter retained(runtime_, "unification.retained");
-    auto remap = [&](Id& id) {
+    const auto remap = [&](Id& id) {
       Update(id);
     };
-    ::stg::Substitute substitute(graph_, remap);
+    const Substitute substitute(graph_, remap);
     graph_.ForEach(start_, graph_.Limit(), [&](Id id) {
       if (Find(id) != id) {
         graph_.Remove(id);
@@ -78,12 +76,12 @@ class Unification {
     ++find_query_;
     // path halving - tiny performance gain
     while (true) {
-      // note: safe to take references as mapping cannot grow after this
+      // note: safe to take a reference as mapping cannot grow after this
       auto& parent = mapping_[id];
       if (parent == id) {
         return id;
       }
-      auto& parent_parent = mapping_[parent];
+      const auto parent_parent = mapping_[parent];
       if (parent_parent == parent) {
         return parent;
       }
```

