```diff
diff --git a/Android.bp b/Android.bp
index a5cf21c..2216dfa 100644
--- a/Android.bp
+++ b/Android.bp
@@ -40,13 +40,11 @@ cc_defaults {
     ],
     cpp_std: "c++20",
     cflags: [
-        "-DUSE_ANDROID_BUILD_NUMBER",
         "-fexceptions",
         "-Wno-error=unused-parameter",
     ],
     static_libs: [
         "libbpf",
-        "libbuildversion",
         "libdw",
         "libelf",
         "libicuuc",
diff --git a/comparison.cc b/comparison.cc
index e53a3d2..ae17ad6 100644
--- a/comparison.cc
+++ b/comparison.cc
@@ -176,14 +176,14 @@ struct ResolveTypedef {
   ResolveTypedef(const Graph& graph, Id& id, std::vector<std::string>& names)
       : graph(graph), id(id), names(names) {}
 
-  bool operator()(const Typedef& x) {
+  bool operator()(const Typedef& x) const {
     id = x.referred_type_id;
     names.push_back(x.name);
     return true;
   }
 
   template <typename Node>
-  bool operator()(const Node&) {
+  bool operator()(const Node&) const {
     return false;
   }
 
@@ -198,26 +198,26 @@ struct ResolveQualifier {
   ResolveQualifier(const Graph& graph, Id& id, Qualifiers& qualifiers)
       : graph(graph), id(id), qualifiers(qualifiers) {}
 
-  bool operator()(const Qualified& x) {
+  bool operator()(const Qualified& x) const {
     id = x.qualified_type_id;
     qualifiers.insert(x.qualifier);
     return true;
   }
 
-  bool operator()(const Array&) {
+  bool operator()(const Array&) const {
     // There should be no qualifiers here.
     qualifiers.clear();
     return false;
   }
 
-  bool operator()(const Function&) {
+  bool operator()(const Function&) const {
     // There should be no qualifiers here.
     qualifiers.clear();
     return false;
   }
 
   template <typename Node>
-  bool operator()(const Node&) {
+  bool operator()(const Node&) const {
     return false;
   }
 
@@ -240,30 +240,30 @@ std::pair<Id, Qualifiers> ResolveQualifiers(const Graph& graph, Id id) {
 struct MatchingKey {
   explicit MatchingKey(const Graph& graph) : graph(graph) {}
 
-  std::string operator()(Id id) {
+  std::string operator()(Id id) const {
     return graph.Apply(*this, id);
   }
 
-  std::string operator()(const BaseClass& x) {
+  std::string operator()(const BaseClass& x) const {
     return (*this)(x.type_id);
   }
 
-  std::string operator()(const Method& x) {
+  std::string operator()(const Method& x) const {
     return x.name + ',' + x.mangled_name;
   }
 
-  std::string operator()(const Member& x) {
+  std::string operator()(const Member& x) const {
     if (!x.name.empty()) {
       return x.name;
     }
     return (*this)(x.type_id);
   }
 
-  std::string operator()(const VariantMember& x) {
+  std::string operator()(const VariantMember& x) const {
     return x.name;
   }
 
-  std::string operator()(const StructUnion& x) {
+  std::string operator()(const StructUnion& x) const {
     if (!x.name.empty()) {
       return x.name;
     }
@@ -280,7 +280,7 @@ struct MatchingKey {
   }
 
   template <typename Node>
-  std::string operator()(const Node&) {
+  std::string operator()(const Node&) const {
     return {};
   }
 
@@ -369,11 +369,11 @@ struct CompareWorker {
    *
    * Each node has one of:
    *
-   * 1. same == true; perhaps only tentative edge differences
-   * 2. same == false; at least one definitive node or edge difference
+   * * same == true; perhaps only tentative edge differences
+   * * same == false; at least one definitive node or edge difference
    *
-   * On the first visit to a node we can put a placeholder in, the value of same
-   * is irrelevant, the diff may contain local and edge differences. If an SCC
+   * On the first visit to a node, the value of same is determined via recursive
+   * comparison and the diff may contain local and edge differences. If an SCC
    * contains only internal edge differences (and equivalently same is true)
    * then the differences can all (eventually) be discarded.
    *
@@ -383,18 +383,18 @@ struct CompareWorker {
    * edges to existing nodes to the side or below (already visited SCCs,
    * sharing), or above (back links forming cycles).
    *
-   * When an SCC is closed, all same implies deleting all diffs, any not same
-   * implies updating all to false.
+   * When an SCC is closed, same is true results in the deletion of all the
+   * nodes' diffs. The value of same is recorded for all nodes in the SCC.
    *
-   * On subsequent visits to a node, there are 2 cases. The node is still open:
-   * return true and an edge diff. The node is closed, return the stored value
-   * and an edge diff.
+   * On other visits to a node, there are 2 cases. The node is still open
+   * (meaning a recursive visit): return true and an edge diff. The node is
+   * closed (meaning a repeat visit): return the stored value and an edge diff.
    */
   std::pair<bool, Comparison> operator()(Id id1, Id id2) {
     const Comparison comparison{{id1}, {id2}};
     ++queried;
 
-    // 1. Check if the comparison has an already known result.
+    // Check if the comparison has an already known result.
     const auto already_known = known.find(comparison);
     if (already_known != known.end()) {
       // Already visited and closed.
@@ -403,9 +403,9 @@ struct CompareWorker {
           ? std::make_pair(true, Comparison{})
           : std::make_pair(false, comparison);
     }
-    // Either open or not visited at all
+    // The comparison is either already open or has not been visited at all.
 
-    // 2. Record node with Strongly-Connected Component finder.
+    // Record the comparison with the Strongly-Connected Component finder.
     const auto handle = scc.Open(comparison);
     if (!handle) {
       // Already open.
@@ -417,15 +417,48 @@ struct CompareWorker {
       ++being_compared;
       return {true, comparison};
     }
-    // Comparison opened, need to close it before returning.
+    // The comparison has now been opened, we must close it before returning.
+
+    // Really compare.
     ++really_compared;
+    const auto [same, diff] = CompareWithResolution(id1, id2);
 
-    Result result;
+    // Record the result and check for a complete Strongly-Connected Component.
+    outcomes.insert({comparison, diff});
+    const auto comparisons = scc.Close(*handle);
+    if (comparisons.empty()) {
+      // Open SCC.
+      //
+      // Note that both same and diff are tentative as comparison is still
+      // open.
+      return {same, comparison};
+    }
+    // Closed SCC.
+    //
+    // Note that same and diff now include every inequality and difference in
+    // the SCC via the DFS spanning tree.
+    const auto size = comparisons.size();
+    scc_size.Add(size);
+    (same ? equivalent : inequivalent) += size;
+    for (const auto& c : comparisons) {
+      // Record equality / inequality.
+      known.insert({c, same});
+      if (same) {
+        // Discard provisional diff.
+        outcomes.erase(c);
+      }
+    }
+    return same
+        ? std::make_pair(true, Comparison{})
+        : std::make_pair(false, comparison);
+  }
 
+  Result CompareWithResolution(Id id1, Id id2) {
     const auto [unqualified1, qualifiers1] = ResolveQualifiers(graph, id1);
     const auto [unqualified2, qualifiers2] = ResolveQualifiers(graph, id2);
     if (!qualifiers1.empty() || !qualifiers2.empty()) {
-      // 3.1 Qualified type difference.
+      // Qualified type difference.
+      Result result;
       auto it1 = qualifiers1.begin();
       auto it2 = qualifiers2.begin();
       const auto end1 = qualifiers1.end();
@@ -446,56 +479,24 @@ struct CompareWorker {
           ++it2;
         }
       }
-      const auto type_diff = (*this)(unqualified1, unqualified2);
-      result.MaybeAddEdgeDiff("underlying", type_diff);
-    } else {
-      const auto [resolved1, typedefs1] = ResolveTypedefs(graph, unqualified1);
-      const auto [resolved2, typedefs2] = ResolveTypedefs(graph, unqualified2);
-      if (unqualified1 != resolved1 || unqualified2 != resolved2) {
-        // 3.2 Typedef difference.
-        result.diff.holds_changes = !typedefs1.empty() && !typedefs2.empty()
-                                    && typedefs1[0] == typedefs2[0];
-        result.MaybeAddEdgeDiff("resolved", (*this)(resolved1, resolved2));
-      } else {
-        // 4. Compare nodes, if possible.
-        result = graph.Apply2(*this, unqualified1, unqualified2);
-      }
+      result.MaybeAddEdgeDiff("underlying",
+                              (*this)(unqualified1, unqualified2));
+      return result;
     }
 
-    // 5. Update result and check for a complete Strongly-Connected Component.
-    const bool same = result.same;
-    provisional.insert({comparison, result.diff});
-    const auto comparisons = scc.Close(*handle);
-    if (comparisons.empty()) {
-      // Open SCC.
-      //
-      // Note that both same and diff are tentative as comparison is still
-      // open.
-      return {same, comparison};
+    const auto [resolved1, typedefs1] = ResolveTypedefs(graph, unqualified1);
+    const auto [resolved2, typedefs2] = ResolveTypedefs(graph, unqualified2);
+    if (unqualified1 != resolved1 || unqualified2 != resolved2) {
+      // Typedef difference.
+      Result result;
+      result.diff.holds_changes = !typedefs1.empty() && !typedefs2.empty()
+                                  && typedefs1[0] == typedefs2[0];
+      result.MaybeAddEdgeDiff("resolved", (*this)(resolved1, resolved2));
+      return result;
     }
 
-    // Closed SCC.
-    //
-    // Note that result now incorporates every inequality and difference in the
-    // SCC via the DFS spanning tree.
-    const auto size = comparisons.size();
-    scc_size.Add(size);
-    for (const auto& c : comparisons) {
-      // Record equality / inequality.
-      known.insert({c, same});
-      const auto it = provisional.find(c);
-      Check(it != provisional.end())
-          << "internal error: missing provisional diffs";
-      if (!same) {
-        // Record differences.
-        outcomes.insert(*it);
-      }
-      provisional.erase(it);
-    }
-    (same ? equivalent : inequivalent) += size;
-    return same
-        ? std::make_pair(true, Comparison{})
-        : std::make_pair(false, comparison);
+    // Compare nodes directly.
+    return graph.Apply2(*this, unqualified1, unqualified2);
   }
 
   Comparison Removed(Id id) {
@@ -938,7 +939,6 @@ struct CompareWorker {
   const Ignore ignore;
   const Graph& graph;
   Outcomes& outcomes;
-  Outcomes provisional;
   std::unordered_map<Comparison, bool, HashComparison> known;
   SCC<Comparison, HashComparison> scc;
   Counter queried;
diff --git a/doc/scc.md b/doc/scc.md
index d12126c..91776ba 100644
--- a/doc/scc.md
+++ b/doc/scc.md
@@ -28,9 +28,9 @@ Tarjan's algorithm can be massaged into the form where it can be separated into
 a plain DFS traversal and SCC-specific pieces but the resulting code is a bit
 messy and responsibility for SCC state management is rather scattered.
 
-The path-based algorithm is the best fit and can be put in a form where the DFS
-traversal and SCC state management are cleanly separated. The concept of "open"
-nodes carries directly over to the implementation used here and SCC state
+The path-based algorithm is the best fit and can be put into a form where the
+DFS traversal and SCC state management are cleanly separated. The concept of
+"open" nodes carries directly over to the implementation used here and SCC state
 management occurs in two well-defined places.
 
 *   node visit starts; repeat visits to open nodes are detected
@@ -188,40 +188,3 @@ sharing- and cycle-breaking links.
 
 However, building a graph (say a copy of the traversal, or a diff graph)
 requires open node state to be squirrelled away somewhere.
-
-##### Enhancement
-
-The SCC finder data structure can be made to carry values associated with open
-nodes and hand them to the user on failure-to-open and closure. This allows us
-to retain purity and regain the ability to maintain simple state for open nodes
-separately from that for closed nodes, at the expense of a slightly
-heavier-touch interface (+power).
-
-In the simplest case, we'd want nothing stored at all (beyond the node identity)
-and actually supplying a second empty type would be an annoyance and an
-inefficiency (-simplicity, -power, -efficiency)). So the best thing to supply is
-the user's container's `value_type` and associated `value_compare` comparator.
-
-However, in this variation, it's painful to set up the SCC structures for
-efficient `open` as nodes need to exist in a map or set, independently of any
-payload. The approach could be revisited if there's a solution to this.
-
-```c++
-if (visited) {
-  // work-saving link to shared node
-  return;
-}
-[&node_state, token] = open(node_state);
-if (!token) {
-  // cycle-breaking back link
-  return;
-}
-...
-// do work, update node_state if you like
-...
-node_states = close(token.value())
-if (!node_states.empty()) {
-  ...
-  mark_visited();
-}
-```
diff --git a/dwarf_processor.cc b/dwarf_processor.cc
index 99ce18c..8d545c7 100644
--- a/dwarf_processor.cc
+++ b/dwarf_processor.cc
@@ -638,7 +638,7 @@ class Processor {
   void ProcessMethod(std::vector<Id>& methods, Entry& entry) {
     Subprogram subprogram = GetSubprogram(entry);
     auto id = maker_.Add<Function>(std::move(subprogram.node));
-    if (subprogram.external && subprogram.address) {
+    if (subprogram.external && subprogram.location) {
       // Only external functions with address are useful for ABI monitoring
       // TODO: cover virtual methods
       const auto new_symbol_idx = result_.symbols.size();
@@ -646,7 +646,7 @@ class Processor {
           .scoped_name = GetScopedNameForSymbol(
               new_symbol_idx, subprogram.name_with_context),
           .linkage_name = subprogram.linkage_name,
-          .address = *subprogram.address,
+          .location = *subprogram.location,
           .type_id = id});
     }
     const auto virtuality = entry.MaybeGetUnsignedConstant(DW_AT_virtuality)
@@ -895,14 +895,14 @@ class Processor {
     auto referred_type = GetReferredType(entry);
     const Id referred_type_id = GetIdForEntry(referred_type);
 
-    if (auto address = entry.MaybeGetAddress(DW_AT_location)) {
+    if (auto location = entry.MaybeGetLocation(DW_AT_location)) {
       // Only external variables with address are useful for ABI monitoring
       const auto new_symbol_idx = result_.symbols.size();
       result_.symbols.push_back(Types::Symbol{
           .scoped_name = GetScopedNameForSymbol(
               new_symbol_idx, name_with_context),
           .linkage_name = GetLinkageName(version_, entry),
-          .address = *address,
+          .location = *location,
           .type_id = referred_type_id});
     }
   }
@@ -910,14 +910,14 @@ class Processor {
   void ProcessFunction(Entry& entry) {
     Subprogram subprogram = GetSubprogram(entry);
     const Id id = AddProcessedNode<Function>(entry, std::move(subprogram.node));
-    if (subprogram.external && subprogram.address) {
+    if (subprogram.external && subprogram.location) {
       // Only external functions with address are useful for ABI monitoring
       const auto new_symbol_idx = result_.symbols.size();
       result_.symbols.push_back(Types::Symbol{
           .scoped_name = GetScopedNameForSymbol(
               new_symbol_idx, subprogram.name_with_context),
           .linkage_name = std::move(subprogram.linkage_name),
-          .address = *subprogram.address,
+          .location = *subprogram.location,
           .type_id = id});
     }
   }
@@ -926,7 +926,7 @@ class Processor {
     Function node;
     NameWithContext name_with_context;
     std::string linkage_name;
-    std::optional<Address> address;
+    std::optional<Location> location;
     bool external;
   };
 
@@ -1009,7 +1009,7 @@ class Processor {
     return Subprogram{.node = Function(return_type_id, parameters),
                       .name_with_context = GetNameWithContext(entry),
                       .linkage_name = GetLinkageName(version_, entry),
-                      .address = entry.MaybeGetAddress(DW_AT_low_pc),
+                      .location = entry.MaybeGetLocation(DW_AT_low_pc),
                       .external = entry.GetFlag(DW_AT_external)};
   }
 
diff --git a/dwarf_processor.h b/dwarf_processor.h
index 93947a7..75592d5 100644
--- a/dwarf_processor.h
+++ b/dwarf_processor.h
@@ -38,7 +38,7 @@ struct Types {
   struct Symbol {
     std::string scoped_name;
     std::string linkage_name;
-    Address address;
+    Location location;
     Id type_id;
   };
 
diff --git a/dwarf_wrappers.cc b/dwarf_wrappers.cc
index 8306a8f..96e51df 100644
--- a/dwarf_wrappers.cc
+++ b/dwarf_wrappers.cc
@@ -36,12 +36,12 @@
 namespace stg {
 namespace dwarf {
 
-std::ostream& operator<<(std::ostream& os, const Address& address) {
-  switch (address.kind) {
-    case Address::Kind::ADDRESS:
-      return os << Hex(address.value);
-    case Address::Kind::TLS:
-      return os << "TLS:" << Hex(address.value);
+std::ostream& operator<<(std::ostream& os, const Location& location) {
+  switch (location.kind) {
+    case Location::Kind::ADDRESS:
+      return os << Hex(location.value);
+    case Location::Kind::TLS:
+      return os << "TLS:" << Hex(location.value);
   }
 }
 
@@ -255,7 +255,7 @@ std::optional<Entry> Entry::MaybeGetReference(uint32_t attribute) {
 
 namespace {
 
-std::optional<Address> GetAddressFromLocation(Dwarf_Attribute& attribute) {
+std::optional<Location> GetLocationFromExpression(Dwarf_Attribute& attribute) {
   const auto expression_opt = MaybeGetExpression(attribute);
   if (!expression_opt) {
     return {};
@@ -268,19 +268,19 @@ std::optional<Address> GetAddressFromLocation(Dwarf_Attribute& attribute) {
     uint64_t address;
     Check(dwarf_formaddr(&result_attribute, &address) == kReturnOk)
         << "dwarf_formaddr returned error";
-    return Address{Address::Kind::ADDRESS, address};
+    return Location{Location::Kind::ADDRESS, address};
   }
 
   if (expression.length == 1 && expression[0].atom == DW_OP_addr) {
     // DW_OP_addr is unsupported by dwarf_getlocation_attr, so we need to
     // manually extract the address from expression.
-    return Address{Address::Kind::ADDRESS, expression[0].number};
+    return Location{Location::Kind::ADDRESS, expression[0].number};
   }
   if (expression.length == 2 && expression[0].atom == DW_OP_addr &&
       expression[1].atom == DW_OP_plus_uconst) {
     // A rather odd case seen from Clang.
-    return Address{Address::Kind::ADDRESS,
-                   expression[0].number + expression[1].number};
+    return Location{Location::Kind::ADDRESS,
+                    expression[0].number + expression[1].number};
   }
 
   // TLS operation has different encodings in Clang and GCC:
@@ -291,9 +291,9 @@ std::optional<Address> GetAddressFromLocation(Dwarf_Attribute& attribute) {
        expression[1].atom == DW_OP_form_tls_address)) {
     // TLS symbols address may be incorrect because of unsupported
     // relocations. Resetting it to zero the same way as it is done in
-    // elf::Reader::MaybeAddTypeInfo.
+    // elf::Reader::GetUserspaceSymbols.
     // TODO: match TLS variables by address
-    return Address{Address::Kind::TLS, 0};
+    return Location{Location::Kind::TLS, 0};
   }
 
   Die() << "Unsupported data location expression";
@@ -301,19 +301,19 @@ std::optional<Address> GetAddressFromLocation(Dwarf_Attribute& attribute) {
 
 }  // namespace
 
-std::optional<Address> Entry::MaybeGetAddress(uint32_t attribute) {
+std::optional<Location> Entry::MaybeGetLocation(uint32_t attribute) {
   auto dwarf_attribute = GetAttribute(&die, attribute);
   if (!dwarf_attribute) {
     return {};
   }
   if (attribute == DW_AT_location) {
-    return GetAddressFromLocation(*dwarf_attribute);
+    return GetLocationFromExpression(*dwarf_attribute);
   }
 
   uint64_t address;
   Check(dwarf_formaddr(&dwarf_attribute.value(), &address) == kReturnOk)
       << "dwarf_formaddr returned error";
-  return Address{Address::Kind::ADDRESS, address};
+  return Location{Location::Kind::ADDRESS, address};
 }
 
 std::optional<uint64_t> Entry::MaybeGetMemberByteOffset() {
diff --git a/dwarf_wrappers.h b/dwarf_wrappers.h
index cddd414..8319e47 100644
--- a/dwarf_wrappers.h
+++ b/dwarf_wrappers.h
@@ -32,20 +32,20 @@
 namespace stg {
 namespace dwarf {
 
-struct Address {
+struct Location {
   // ADDRESS - relocated, section-relative offset
   // TLS - broken (elfutils bug), TLS-relative offset
-  //       TODO: match TLS variables by address
+  //       TODO: match TLS variables by offset
   enum class Kind { ADDRESS, TLS };
 
-  Address(Kind kind, uint64_t value) : kind(kind), value(value) {}
-  auto operator<=>(const Address&) const = default;
+  Location(Kind kind, uint64_t value) : kind(kind), value(value) {}
+  auto operator<=>(const Location&) const = default;
 
   Kind kind;
   uint64_t value;
 };
 
-std::ostream& operator<<(std::ostream& os, const Address& address);
+std::ostream& operator<<(std::ostream& os, const Location& location);
 
 // C++ wrapper over Dwarf_Die, providing interface for its various properties.
 struct Entry {
@@ -75,7 +75,7 @@ struct Entry {
   uint64_t MustGetUnsignedConstant(uint32_t attribute);
   bool GetFlag(uint32_t attribute);
   std::optional<Entry> MaybeGetReference(uint32_t attribute);
-  std::optional<Address> MaybeGetAddress(uint32_t attribute);
+  std::optional<Location> MaybeGetLocation(uint32_t attribute);
   std::optional<uint64_t> MaybeGetMemberByteOffset();
   std::optional<uint64_t> MaybeGetVtableOffset();
   // Returns value of subrange element count if it is constant or nullopt if it
diff --git a/elf_loader.cc b/elf_loader.cc
index cfa751a..1580855 100644
--- a/elf_loader.cc
+++ b/elf_loader.cc
@@ -466,9 +466,9 @@ ElfSymbol::CRC ElfLoader::GetElfSymbolCRC(
     const SymbolTableEntry& symbol) const {
   Check(is_little_endian_binary_)
       << "CRC is not supported in big-endian binaries";
-  const auto address = GetAbsoluteAddress(symbol);
+
   if (symbol.value_type == SymbolTableEntry::ValueType::ABSOLUTE) {
-    return ElfSymbol::CRC{static_cast<uint32_t>(address)};
+    return ElfSymbol::CRC{static_cast<uint32_t>(symbol.value)};
   }
   Check(symbol.value_type == SymbolTableEntry::ValueType::RELATIVE_TO_SECTION)
       << "CRC symbol is expected to be absolute or relative to a section";
@@ -477,6 +477,7 @@ ElfSymbol::CRC ElfLoader::GetElfSymbolCRC(
   const auto [header, data] = GetSectionInfo(section);
   Check(data->d_buf != nullptr) << "Section has no data buffer";
 
+  const auto address = GetAbsoluteAddress(symbol);
   Check(address >= header.sh_addr)
       << "CRC symbol address is below CRC section start";
 
@@ -516,11 +517,8 @@ std::string_view ElfLoader::GetElfSymbolNamespace(
 }
 
 size_t ElfLoader::GetAbsoluteAddress(const SymbolTableEntry& symbol) const {
-  if (symbol.value_type == SymbolTableEntry::ValueType::ABSOLUTE) {
-    return symbol.value;
-  }
   Check(symbol.value_type == SymbolTableEntry::ValueType::RELATIVE_TO_SECTION)
-      << "Only absolute and relative to sections symbols are supported";
+      << "only relocatable symbols are supported";
   // In relocatable files, st_value holds a section offset for a defined symbol.
   if (is_relocatable_) {
     const auto section = GetSectionByIndex(elf_, symbol.section_index);
diff --git a/elf_reader.cc b/elf_reader.cc
index 9728ddd..2570c55 100644
--- a/elf_reader.cc
+++ b/elf_reader.cc
@@ -35,6 +35,7 @@
 #include "error.h"
 #include "filter.h"
 #include "graph.h"
+#include "hex.h"
 #include "reader_options.h"
 #include "runtime.h"
 #include "type_normalisation.h"
@@ -173,6 +174,11 @@ bool IsPublicFunctionOrVariable(const SymbolTableEntry& symbol) {
     return false;
   }
 
+  // Common symbols can only be seen in .o files emitted by old compilers.
+  if (symbol.value_type == SymbolTableEntry::ValueType::COMMON) {
+    Die() << "unexpected COMMON symbol: '" << symbol.name << '\'';
+  }
+
   // Local symbol is not visible outside the binary, so it is not public
   // and should be rejected.
   if (symbol.binding == SymbolTableEntry::Binding::LOCAL) {
@@ -197,8 +203,34 @@ bool IsLinuxKernelFunctionOrVariable(const SymbolNameList& ksymtab,
   if (symbol.binding == SymbolTableEntry::Binding::LOCAL) {
     return false;
   }
+
   // TODO: handle undefined ksymtab symbols
-  return ksymtab.contains(symbol.name);
+  if (symbol.value_type == SymbolTableEntry::ValueType::UNDEFINED) {
+    return false;
+  }
+
+  // Common symbols can only be seen in .o files emitted by old compilers.
+  if (symbol.value_type == SymbolTableEntry::ValueType::COMMON) {
+    Die() << "unexpected COMMON symbol: '" << symbol.name << '\'';
+  }
+
+  // Symbol linkage is determined by the ksymtab.
+  if (!ksymtab.contains(symbol.name)) {
+    return false;
+  }
+
+  const auto symbol_type = symbol.symbol_type;
+  // Keep function and object symbols, but not GNU indirect function or TLS ones
+  // as the module loader does not expect them.
+  if (symbol_type != SymbolTableEntry::SymbolType::FUNCTION
+      && symbol_type != SymbolTableEntry::SymbolType::OBJECT) {
+    // TODO: upgrade to Die after more testing / fixing
+    Warn() << "ignoring Linux kernel symbol '" << symbol.name << "' in section "
+           << Hex(symbol.section_index) << " of type " << symbol_type;
+    return false;
+  }
+
+  return true;
 }
 
 namespace {
@@ -218,16 +250,17 @@ class Reader {
 
  private:
   using SymbolIndex =
-      std::map<std::pair<dwarf::Address, std::string>, std::vector<size_t>>;
+      std::map<std::pair<dwarf::Location, std::string>, std::vector<size_t>>;
 
   void GetLinuxKernelSymbols(
       const std::vector<SymbolTableEntry>& all_symbols,
-      std::vector<std::pair<ElfSymbol, size_t>>& symbols) const;
+      std::vector<std::pair<ElfSymbol, dwarf::Location>>& symbols) const;
   void GetUserspaceSymbols(
       const std::vector<SymbolTableEntry>& all_symbols,
-      std::vector<std::pair<ElfSymbol, size_t>>& symbols) const;
+      std::vector<std::pair<ElfSymbol, dwarf::Location>>& symbols) const;
 
-  Id BuildRoot(const std::vector<std::pair<ElfSymbol, size_t>>& symbols) {
+  Id BuildRoot(
+      const std::vector<std::pair<ElfSymbol, dwarf::Location>>& symbols) {
     // On destruction, the unification object will remove or rewrite each graph
     // node for which it has a mapping.
     //
@@ -235,7 +268,7 @@ class Reader {
     // the nodes in consideration to the ones allocated by the DWARF processor
     // here and any symbol or type roots that follow. This is done by setting
     // the starting node ID to be the current graph limit.
-    Unification unification(runtime_, graph_, graph_.Limit());
+    const Id start = graph_.Limit();
 
     const dwarf::Types types =
         dwarf::Process(elf_dwarf_handle_.GetDwarf(),
@@ -243,9 +276,9 @@ class Reader {
 
     // A less important optimisation is avoiding copying the mapping array as it
     // is populated. This is done by reserving space to the new graph limit.
-    unification.Reserve(graph_.Limit());
+    Unification unification(runtime_, graph_, start, graph_.Limit());
 
-    // fill address to id
+    // fill location to id
     //
     // In general, we want to handle as many of the following cases as possible.
     // In practice, determining the correct ELF-DWARF match may be impossible.
@@ -257,10 +290,10 @@ class Reader {
     //   address
     // * assembly symbols - multiple declarations but no definition and no
     //   address in DWARF.
-    SymbolIndex address_name_to_index;
+    SymbolIndex location_and_name_to_index;
     for (size_t i = 0; i < types.symbols.size(); ++i) {
-      const auto& symbol = types.symbols[i];
-      address_name_to_index[{symbol.address, symbol.linkage_name}].push_back(i);
+      const auto& s = types.symbols[i];
+      location_and_name_to_index[{s.location, s.linkage_name}].push_back(i);
     }
 
     std::map<std::string, Id> symbols_map;
@@ -268,8 +301,8 @@ class Reader {
       // TODO: add VersionInfoToString to SymbolKey name
       // TODO: check for uniqueness of SymbolKey in map after
       // support for version info
-      MaybeAddTypeInfo(address_name_to_index, types.symbols, address, symbol,
-                       unification);
+      MaybeAddTypeInfo(location_and_name_to_index, types.symbols, address,
+                       symbol, unification);
       symbols_map.emplace(VersionedSymbolName(symbol),
                           graph_.Add<ElfSymbol>(symbol));
     }
@@ -285,7 +318,7 @@ class Reader {
       }
     }
 
-    Id root = graph_.Add<Interface>(
+    const Id root = graph_.Add<Interface>(
         std::move(symbols_map), std::move(types_map));
 
     // Use all named types and DWARF declarations as roots for type resolution.
@@ -301,8 +334,7 @@ class Reader {
 
     stg::ResolveTypes(runtime_, graph_, unification, {roots});
 
-    unification.Update(root);
-    return root;
+    return unification.Find(root);
   }
 
   static bool IsEqual(Unification& unification,
@@ -310,7 +342,7 @@ class Reader {
                       const dwarf::Types::Symbol& rhs) {
     return lhs.scoped_name == rhs.scoped_name
         && lhs.linkage_name == rhs.linkage_name
-        && lhs.address == rhs.address
+        && lhs.location == rhs.location
         && unification.Unify(lhs.type_id, rhs.type_id);
   }
 
@@ -332,40 +364,32 @@ class Reader {
   }
 
   static void MaybeAddTypeInfo(
-      const SymbolIndex& address_name_to_index,
+      const SymbolIndex& location_and_name_to_index,
       const std::vector<dwarf::Types::Symbol>& dwarf_symbols,
-      size_t address_value, ElfSymbol& node, Unification& unification) {
-    // TLS symbols address may be incorrect because of unsupported
-    // relocations. Resetting it to zero the same way as it is done in
-    // dwarf::Entry::GetAddressFromLocation.
-    // TODO: match TLS variables by address
-    const dwarf::Address address =
-        node.symbol_type == ElfSymbol::SymbolType::TLS
-            ? dwarf::Address{dwarf::Address::Kind::TLS, 0}
-            : dwarf::Address{dwarf::Address::Kind::ADDRESS, address_value};
-    // try to find the first symbol with given address
-    const auto start_it = address_name_to_index.lower_bound(
-        std::make_pair(address, std::string()));
-    auto best_symbols_it = address_name_to_index.end();
+      dwarf::Location location, ElfSymbol& node, Unification& unification) {
+    // try to find the first symbol with given location
+    const auto start_it = location_and_name_to_index.lower_bound(
+        std::make_pair(location, std::string()));
+    auto best_symbols_it = location_and_name_to_index.end();
     bool matched_by_name = false;
     size_t candidates = 0;
     for (auto it = start_it;
-         it != address_name_to_index.end() && it->first.first == address;
+         it != location_and_name_to_index.end() && it->first.first == location;
          ++it) {
       ++candidates;
-      // We have at least matching addresses.
+      // We have at least matching locations.
       if (it->first.second == node.symbol_name) {
         // If we have also matching names we can stop looking further.
         matched_by_name = true;
         best_symbols_it = it;
         break;
       }
-      if (best_symbols_it == address_name_to_index.end()) {
+      if (best_symbols_it == location_and_name_to_index.end()) {
         // Otherwise keep the first match.
         best_symbols_it = it;
       }
     }
-    if (best_symbols_it != address_name_to_index.end()) {
+    if (best_symbols_it != location_and_name_to_index.end()) {
       const auto& best_symbols = best_symbols_it->second;
       Check(!best_symbols.empty()) << "best_symbols.empty()";
       const auto& best_symbol = dwarf_symbols[best_symbols[0]];
@@ -374,13 +398,13 @@ class Reader {
         // TODO: allow "compatible" duplicates, for example
         // "void foo(int bar)" vs "void foo(const int bar)"
         if (!IsEqual(unification, best_symbol, other)) {
-          Die() << "Duplicate DWARF symbol: address="
+          Die() << "Duplicate DWARF symbol: location="
                 << best_symbols_it->first.first
                 << ", name=" << best_symbols_it->first.second;
         }
       }
       if (best_symbol.scoped_name.empty()) {
-        Die() << "Anonymous DWARF symbol: address="
+        Die() << "Anonymous DWARF symbol: location="
               << best_symbols_it->first.first
               << ", name=" << best_symbols_it->first.second;
       }
@@ -389,7 +413,7 @@ class Reader {
       // But if we have both situations at once, we can't match ELF to DWARF and
       // it should be fixed in analysed binary source code.
       Check(matched_by_name || candidates == 1)
-          << "Multiple candidate symbols without matching name: address="
+          << "Multiple candidate symbols without matching name: location="
           << best_symbols_it->first.first
           << ", name=" << best_symbols_it->first.second;
       node.type_id = best_symbol.type_id;
@@ -407,7 +431,7 @@ class Reader {
 
 void Reader::GetLinuxKernelSymbols(
     const std::vector<SymbolTableEntry>& all_symbols,
-    std::vector<std::pair<ElfSymbol, size_t>>& symbols) const {
+    std::vector<std::pair<ElfSymbol, dwarf::Location>>& symbols) const {
   const auto crcs = GetCRCValuesMap(all_symbols, elf_);
   const auto namespaces = GetNamespacesMap(all_symbols, elf_);
   const auto ksymtab_symbols = GetKsymtabSymbols(all_symbols);
@@ -415,23 +439,34 @@ void Reader::GetLinuxKernelSymbols(
     if (IsLinuxKernelFunctionOrVariable(ksymtab_symbols, symbol)) {
       const size_t address = elf_.GetAbsoluteAddress(symbol);
       symbols.emplace_back(
-          SymbolTableEntryToElfSymbol(crcs, namespaces, symbol), address);
+          SymbolTableEntryToElfSymbol(crcs, namespaces, symbol),
+          dwarf::Location{dwarf::Location::Kind::ADDRESS, address});
     }
   }
 }
 
 void Reader::GetUserspaceSymbols(
     const std::vector<SymbolTableEntry>& all_symbols,
-    std::vector<std::pair<ElfSymbol, size_t>>& symbols) const {
+    std::vector<std::pair<ElfSymbol, dwarf::Location>>& symbols) const {
   const auto cfi_address_map = GetCFIAddressMap(elf_.GetCFISymbols(), elf_);
   for (const auto& symbol : all_symbols) {
     if (IsPublicFunctionOrVariable(symbol)) {
-      const auto cfi_it = cfi_address_map.find(std::string(symbol.name));
-      const size_t address = cfi_it != cfi_address_map.end()
-                                 ? cfi_it->second
-                                 : elf_.GetAbsoluteAddress(symbol);
-      symbols.emplace_back(
-          SymbolTableEntryToElfSymbol({}, {}, symbol), address);
+      if (symbol.symbol_type == SymbolTableEntry::SymbolType::TLS) {
+        // TLS symbols offsets may be incorrect because of unsupported
+        // relocations. Resetting it to zero the same way as it is done in
+        // dwarf::Entry::GetLocationFromExpression.
+        // TODO: match TLS variables by offset
+        symbols.emplace_back(SymbolTableEntryToElfSymbol({}, {}, symbol),
+                             dwarf::Location{dwarf::Location::Kind::TLS, 0});
+      } else {
+        const auto cfi_it = cfi_address_map.find(std::string(symbol.name));
+        const size_t absolute = cfi_it != cfi_address_map.end()
+                                    ? cfi_it->second
+                                    : elf_.GetAbsoluteAddress(symbol);
+        symbols.emplace_back(
+            SymbolTableEntryToElfSymbol({}, {}, symbol),
+            dwarf::Location{dwarf::Location::Kind::ADDRESS, absolute});
+      }
     }
   }
 }
@@ -441,7 +476,7 @@ Id Reader::Read() {
   const auto get_symbols = elf_.IsLinuxKernelBinary()
                            ? &Reader::GetLinuxKernelSymbols
                            : &Reader::GetUserspaceSymbols;
-  std::vector<std::pair<ElfSymbol, size_t>> symbols;
+  std::vector<std::pair<ElfSymbol, dwarf::Location>> symbols;
   symbols.reserve(all_symbols.size());
   (this->*get_symbols)(all_symbols, symbols);
   symbols.shrink_to_fit();
diff --git a/fidelity.cc b/fidelity.cc
index 1032f9a..af2d1e4 100644
--- a/fidelity.cc
+++ b/fidelity.cc
@@ -36,9 +36,7 @@ namespace {
 
 struct Fidelity {
   Fidelity(const Graph& graph, NameCache& name_cache)
-      : graph(graph), describe(graph, name_cache), seen(Id(0)) {
-    seen.Reserve(graph.Limit());
-  }
+      : graph(graph), describe(graph, name_cache), seen(Id(0), graph.Limit()) {}
 
   void operator()(Id);
   void operator()(const std::vector<Id>&);
diff --git a/graph.h b/graph.h
index 673e3d0..5269792 100644
--- a/graph.h
+++ b/graph.h
@@ -677,8 +677,7 @@ struct InterfaceKey {
 // key set limited to allocated Ids.
 class DenseIdSet {
  public:
-  explicit DenseIdSet(Id start) : offset_(start.ix_) {}
-  void Reserve(Id limit) {
+  DenseIdSet(Id start, Id limit) : offset_(start.ix_) {
     ids_.reserve(limit.ix_ - offset_);
   }
   bool Insert(Id id) {
@@ -706,8 +705,7 @@ class DenseIdSet {
 // but with constant time operations and key set limited to allocated Ids.
 class DenseIdMapping {
  public:
-  explicit DenseIdMapping(Id start) : offset_(start.ix_) {}
-  void Reserve(Id limit) {
+  DenseIdMapping(Id start, Id limit) : offset_(start.ix_) {
     ids_.reserve(limit.ix_ - offset_);
   }
   Id& operator[](Id id) {
diff --git a/stg.cc b/stg.cc
index 5c6675f..74b5180 100644
--- a/stg.cc
+++ b/stg.cc
@@ -60,8 +60,7 @@ struct GetInterface {
 Id Merge(Runtime& runtime, Graph& graph, const std::vector<Id>& roots) {
   bool failed = false;
   // this rewrites the graph on destruction
-  Unification unification(runtime, graph, Id(0));
-  unification.Reserve(graph.Limit());
+  Unification unification(runtime, graph, Id(0), graph.Limit());
   std::map<std::string, Id> symbols;
   std::map<std::string, Id> types;
   const GetInterface get;
@@ -228,10 +227,9 @@ int main(int argc, char* argv[]) {
     }
     if (!opt_keep_duplicates) {
       {
-        stg::Unification unification(runtime, graph, stg::Id(0));
-        unification.Reserve(graph.Limit());
+        stg::Unification unification(runtime, graph, stg::Id(0), graph.Limit());
         stg::ResolveTypes(runtime, graph, unification, {root});
-        unification.Update(root);
+        root = unification.Find(root);
       }
       const auto hashes = stg::Fingerprint(runtime, graph, root);
       root = stg::Deduplicate(runtime, graph, root, hashes);
diff --git a/test_cases/info_tests/symbol/absolute_object.c b/test_cases/info_tests/symbol/absolute_object.c
index ba0afc3..55a10c1 100644
--- a/test_cases/info_tests/symbol/absolute_object.c
+++ b/test_cases/info_tests/symbol/absolute_object.c
@@ -2,6 +2,7 @@
 __asm__(
     ".global bar\n"
     ".type bar,object\n"
-    "bar = 0x1\n");
+    ".size bar,0\n"
+    "bar = 0\n");
 
-long x, y;
\ No newline at end of file
+long x, y;
diff --git a/type_resolution.cc b/type_resolution.cc
index c2734cc..916b5f8 100644
--- a/type_resolution.cc
+++ b/type_resolution.cc
@@ -37,13 +37,11 @@ namespace {
 struct NamedTypes {
   NamedTypes(Runtime& runtime, const Graph& graph)
       : graph(graph),
-        seen(Id(0)),
+        seen(Id(0), graph.Limit()),
         nodes(runtime, "named_types.nodes"),
         types(runtime, "named_types.types"),
         definitions(runtime, "named_types.definitions"),
-        declarations(runtime, "named_types.declarations") {
-    seen.Reserve(graph.Limit());
-  }
+        declarations(runtime, "named_types.declarations") {}
 
   enum class Tag { STRUCT, UNION, ENUM, TYPEDEF, VARIANT };
   using Type = std::pair<Tag, std::string>;
diff --git a/unification.cc b/unification.cc
index 935eece..0bfc02a 100644
--- a/unification.cc
+++ b/unification.cc
@@ -20,6 +20,7 @@
 #include "unification.h"
 
 #include <cstddef>
+#include <exception>
 #include <map>
 #include <optional>
 #include <utility>
@@ -28,6 +29,8 @@
 #include <vector>
 
 #include "graph.h"
+#include "runtime.h"
+#include "substitution.h"
 
 namespace stg {
 
@@ -281,6 +284,74 @@ struct Unifier {
 
 }  // namespace
 
+Unification::Unification(Runtime& runtime, Graph& graph, Id start, Id limit)
+    : graph_(graph),
+      start_(start),
+      mapping_(start, limit),
+      runtime_(runtime),
+      find_query_(runtime, "unification.find_query"),
+      find_halved_(runtime, "unification.find_halved"),
+      union_known_(runtime, "unification.union_known"),
+      union_unknown_(runtime, "unification.union_unknown") {}
+
+Unification::~Unification() noexcept(false) {
+  if (std::uncaught_exceptions() > 0) {
+    // abort unification
+    return;
+  }
+  // apply substitutions to the entire graph
+  const Time time(runtime_, "unification.rewrite");
+  Counter removed(runtime_, "unification.removed");
+  Counter retained(runtime_, "unification.retained");
+  const auto remap = [&](Id& id) {
+    // update id to representative id, avoiding silent stores
+    const Id fid = Find(id);
+    if (fid != id) {
+      id = fid;
+    }
+  };
+  const Substitute substitute(graph_, remap);
+  graph_.ForEach(start_, graph_.Limit(), [&](Id id) {
+    if (Find(id) != id) {
+      graph_.Remove(id);
+      ++removed;
+    } else {
+      substitute(id);
+      ++retained;
+    }
+  });
+}
+
+void Unification::Union(Id id1, Id id2) {
+  // always prefer Find(id2) as a parent
+  const Id fid1 = Find(id1);
+  const Id fid2 = Find(id2);
+  if (fid1 == fid2) {
+    ++union_known_;
+    return;
+  }
+  mapping_[fid1] = fid2;
+  ++union_unknown_;
+}
+
+Id Unification::Find(Id id) {
+  ++find_query_;
+  // path halving - tiny performance gain
+  while (true) {
+    // note: safe to take a reference as mapping cannot grow after this
+    auto& parent = mapping_[id];
+    if (parent == id) {
+      return id;
+    }
+    const auto parent_parent = mapping_[parent];
+    if (parent_parent == parent) {
+      return parent;
+    }
+    id = parent = parent_parent;
+    ++find_halved_;
+  }
+}
+
 bool Unification::Unify(Id id1, Id id2) {
   // TODO: Unifier only needs access to Unification::Find
   Unifier unifier(graph_, *this);
diff --git a/unification.h b/unification.h
index 85b4f56..df03f4a 100644
--- a/unification.h
+++ b/unification.h
@@ -1,7 +1,7 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 // -*- mode: C++ -*-
 //
-// Copyright 2022-2023 Google LLC
+// Copyright 2022-2024 Google LLC
 //
 // Licensed under the Apache License v2.0 with LLVM Exceptions (the
 // "License"); you may not use this file except in compliance with the
@@ -20,11 +20,8 @@
 #ifndef STG_UNIFICATION_H_
 #define STG_UNIFICATION_H_
 
-#include <exception>
-
 #include "graph.h"
 #include "runtime.h"
-#include "substitution.h"
 
 namespace stg {
 
@@ -32,85 +29,19 @@ namespace stg {
 // destruction.
 class Unification {
  public:
-  Unification(Runtime& runtime, Graph& graph, Id start)
-      : graph_(graph),
-        start_(start),
-        mapping_(start),
-        runtime_(runtime),
-        find_query_(runtime, "unification.find_query"),
-        find_halved_(runtime, "unification.find_halved"),
-        union_known_(runtime, "unification.union_known"),
-        union_unknown_(runtime, "unification.union_unknown") {}
-
-  ~Unification() {
-    if (std::uncaught_exceptions() > 0) {
-      // abort unification
-      return;
-    }
-    // apply substitutions to the entire graph
-    const Time time(runtime_, "unification.rewrite");
-    Counter removed(runtime_, "unification.removed");
-    Counter retained(runtime_, "unification.retained");
-    const auto remap = [&](Id& id) {
-      Update(id);
-    };
-    const Substitute substitute(graph_, remap);
-    graph_.ForEach(start_, graph_.Limit(), [&](Id id) {
-      if (Find(id) != id) {
-        graph_.Remove(id);
-        ++removed;
-      } else {
-        substitute(id);
-        ++retained;
-      }
-    });
-  }
+  Unification(Runtime& runtime, Graph& graph, Id start, Id limit);
 
-  void Reserve(Id limit) {
-    mapping_.Reserve(limit);
-  }
+  ~Unification() noexcept(false);
 
-  bool Unify(Id id1, Id id2);
+  // id2 will always be preferred as a parent node; interpreted as a
+  // substitution, id1 will be replaced by id2
+  void Union(Id id1, Id id2);
 
-  Id Find(Id id) {
-    ++find_query_;
-    // path halving - tiny performance gain
-    while (true) {
-      // note: safe to take a reference as mapping cannot grow after this
-      auto& parent = mapping_[id];
-      if (parent == id) {
-        return id;
-      }
-      const auto parent_parent = mapping_[parent];
-      if (parent_parent == parent) {
-        return parent;
-      }
-      id = parent = parent_parent;
-      ++find_halved_;
-    }
-  }
+  Id Find(Id id);
 
-  void Union(Id id1, Id id2) {
-    // id2 will always be preferred as a parent node; interpreted as a
-    // substitution, id1 will be replaced by id2
-    const Id fid1 = Find(id1);
-    const Id fid2 = Find(id2);
-    if (fid1 == fid2) {
-      ++union_known_;
-      return;
-    }
-    mapping_[fid1] = fid2;
-    ++union_unknown_;
-  }
-
-  // update id to representative id
-  void Update(Id& id) {
-    const Id fid = Find(id);
-    // avoid silent stores
-    if (fid != id) {
-      id = fid;
-    }
-  }
+  // attempt to unify, recursively, allowing types declarations to be replaced
+  // by definitions
+  bool Unify(Id id1, Id id2);
 
  private:
   Graph& graph_;
```

