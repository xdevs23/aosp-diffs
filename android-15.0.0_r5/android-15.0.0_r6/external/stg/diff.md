```diff
diff --git a/Android.bp b/Android.bp
index 1d0a4e3..a5cf21c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -75,6 +75,7 @@ cc_library_host_static {
         "deduplication.cc",
         "dwarf_processor.cc",
         "dwarf_wrappers.cc",
+        "elf_dwarf_handle.cc",
         "elf_loader.cc",
         "elf_reader.cc",
         "fidelity.cc",
diff --git a/CMakeLists.txt b/CMakeLists.txt
index f28e0d5..3849b1c 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -85,6 +85,7 @@ add_library(libstg OBJECT
   deduplication.cc
   dwarf_processor.cc
   dwarf_wrappers.cc
+  elf_dwarf_handle.cc
   elf_loader.cc
   elf_reader.cc
   fidelity.cc
@@ -140,6 +141,7 @@ else()
     error_test
     file_descriptor_test
     filter_test
+    hex_test
     order_test
     reporting_test
     runtime_test
diff --git a/abigail_reader.cc b/abigail_reader.cc
index f1deff3..8708fc3 100644
--- a/abigail_reader.cc
+++ b/abigail_reader.cc
@@ -1,7 +1,7 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 // -*- mode: C++ -*-
 //
-// Copyright 2021-2023 Google LLC
+// Copyright 2021-2024 Google LLC
 //
 // Licensed under the Apache License v2.0 with LLVM Exceptions (the
 // "License"); you may not use this file except in compliance with the
@@ -526,10 +526,10 @@ void FixBadDwarfElfLinks(xmlNodePtr root) {
 //
 // 2. Reanonymise anonymous types that have been given names.
 //
-// At some point abidw changed its behaviour given an anonymous with a naming
-// typedef. In addition to linking the typedef and type in both directions, the
-// code now gives (some) anonymous types the same name as the typedef. This
-// misrepresents the original types.
+// At some point abidw changed its behaviour given an anonymous type with a
+// naming typedef. In addition to linking the typedef and type in both
+// directions, the code now gives (some) anonymous types the same name as the
+// typedef. This misrepresents the original types.
 //
 // Such types should be anonymous. We set is-anonymous and drop the name.
 //
@@ -789,25 +789,124 @@ std::optional<PointerReference::Kind> ParseReferenceKind(
   return {};
 }
 
-}  // namespace
+// Parser for libabigail's ABI XML format, creating a Symbol-Type Graph.
+//
+// On construction Abigail consumes a libxml node tree and builds a graph.
+//
+// Note that the core parser sees a "clean and tidy" XML document due to
+// preprocessing that simplifies the XML and resolves several issues. One
+// notable exception is that duplicate nodes may still remain.
+//
+// The main producer of ABI XML is abidw. The format has no formal specification
+// and has very limited semantic versioning. This parser makes no attempt to
+// support or correct for deficiencies in older versions of the format.
+//
+// The parser detects and will abort on the presence of unexpected elements.
+//
+// The parser ignores attributes it doesn't care about, including member access
+// specifiers and (meaningless) type ids on array dimensions.
+//
+// The STG IR and libabigail ABI XML models diverge in some ways. The parser has
+// to do extra work for each of these, as follows.
+//
+// 0. XML uses type and symbol ids to link together elements. These become edges
+// in the graph between symbols and types and between types and types. Dangling
+// type references will cause an abort. libabigail is much more relaxed about
+// symbols without type information and these are modelled as such.
+//
+// 1. XML function declarations have in-line types. The parser creates
+// free-standing types on-the-fly. A useful space optimisation might be to
+// prevent duplicate creation of such types.
+//
+// 2. Variadic parameters are currently flagged with an XML attribute. A
+// variadic type node is created on demand and will be shared by all such
+// paramerters.
+//
+// 3. XML symbols and aliases have a rather poor repesentation with aliases
+// represented as comma-separated attribute values. Aliases are resolved in a
+// post-processing phase.
+//
+// 4. XML anonymous types may also have names, these are ignored.
+class Abigail {
+ public:
+  explicit Abigail(Graph& graph);
+  Id ProcessRoot(xmlNodePtr root);
+
+ private:
+  struct SymbolInfo {
+    std::string name;
+    std::optional<ElfSymbol::VersionInfo> version_info;
+    xmlNodePtr node;
+  };
 
-Abigail::Abigail(Graph& graph) : graph_(graph) {}
+  // Map from libabigail type ids to STG node ids; except for the type of
+  // variadic parameters.
+  Maker<std::string> maker_;
+  // The STG IR uses a distinct node type for the variadic parameter type; if
+  // allocated, this is its STG node id.
+  std::optional<Id> variadic_;
+
+  // symbol id to symbol information
+  std::unordered_map<std::string, SymbolInfo> symbol_info_map_;
+  // alias symbol id to main symbol id
+  std::unordered_map<std::string, std::string> alias_to_main_;
+  // libabigail decorates certain declarations with symbol ids; this is the
+  // mapping from symbol id to the corresponding type and full name.
+  std::unordered_map<std::string, std::pair<Id, std::string>>
+      symbol_id_and_full_name_;
+
+  // Full name of the current scope.
+  Scope scope_name_;
+
+  Id GetEdge(xmlNodePtr element);
+  Id GetVariadic();
+  Function MakeFunctionType(xmlNodePtr function);
+
+  void ProcessCorpusGroup(xmlNodePtr group);
+  void ProcessCorpus(xmlNodePtr corpus);
+  void ProcessSymbols(xmlNodePtr symbols);
+  void ProcessSymbol(xmlNodePtr symbol);
+
+  bool ProcessUserDefinedType(std::string_view name, const std::string& id,
+                              xmlNodePtr decl);
+  void ProcessScope(xmlNodePtr scope);
+
+  void ProcessInstr(xmlNodePtr instr);
+  void ProcessNamespace(xmlNodePtr scope);
+
+  Id ProcessDecl(bool is_variable, xmlNodePtr decl);
+
+  void ProcessFunctionType(const std::string& id, xmlNodePtr function);
+  void ProcessTypedef(const std::string& id, xmlNodePtr type_definition);
+  void ProcessPointer(const std::string& id, bool is_pointer,
+                      xmlNodePtr pointer);
+  void ProcessQualified(const std::string& id, xmlNodePtr qualified);
+  void ProcessArray(const std::string& id, xmlNodePtr array);
+  void ProcessTypeDecl(const std::string& id, xmlNodePtr type_decl);
+  void ProcessStructUnion(const std::string& id, bool is_struct,
+                          xmlNodePtr struct_union);
+  void ProcessEnum(const std::string& id, xmlNodePtr enumeration);
+
+  Id ProcessBaseClass(xmlNodePtr base_class);
+  std::optional<Id> ProcessDataMember(bool is_struct, xmlNodePtr data_member);
+  void ProcessMemberFunction(std::vector<Id>& methods, xmlNodePtr method);
+  void ProcessMemberType(xmlNodePtr member_type);
+
+  Id BuildSymbol(const SymbolInfo& info,
+                 std::optional<Id> type_id,
+                 const std::optional<std::string>& name);
+  Id BuildSymbols();
+};
 
-Id Abigail::GetNode(const std::string& type_id) {
-  const auto [it, inserted] = type_ids_.insert({type_id, Id(0)});
-  if (inserted) {
-    it->second = graph_.Allocate();
-  }
-  return it->second;
-}
+Abigail::Abigail(Graph& graph) : maker_(graph) {}
 
 Id Abigail::GetEdge(xmlNodePtr element) {
-  return GetNode(GetAttributeOrDie(element, "type-id"));
+  return maker_.Get(GetAttributeOrDie(element, "type-id"));
 }
 
 Id Abigail::GetVariadic() {
   if (!variadic_) {
-    variadic_ = {graph_.Add<Special>(Special::Kind::VARIADIC)};
+    variadic_ = {maker_.Add<Special>(Special::Kind::VARIADIC)};
   }
   return *variadic_;
 }
@@ -833,7 +932,7 @@ Function Abigail::MakeFunctionType(xmlNodePtr function) {
   if (!return_type) {
     Die() << "missing return-type";
   }
-  return Function(*return_type, parameters);
+  return {*return_type, parameters};
 }
 
 Id Abigail::ProcessRoot(xmlNodePtr root) {
@@ -847,14 +946,7 @@ Id Abigail::ProcessRoot(xmlNodePtr root) {
   } else {
     Die() << "unrecognised root element '" << name << "'";
   }
-  for (const auto& [type_id, id] : type_ids_) {
-    if (!graph_.Is(id)) {
-      Warn() << "no definition found for type '" << type_id << "'";
-    }
-  }
-  const Id id = BuildSymbols();
-  RemoveUselessQualifiers(graph_, id);
-  return id;
+  return BuildSymbols();
 }
 
 void Abigail::ProcessCorpusGroup(xmlNodePtr group) {
@@ -920,8 +1012,8 @@ void Abigail::ProcessSymbol(xmlNodePtr symbol) {
   }
 }
 
-bool Abigail::ProcessUserDefinedType(std::string_view name, Id id,
-                                     xmlNodePtr decl) {
+bool Abigail::ProcessUserDefinedType(
+    std::string_view name, const std::string& id, xmlNodePtr decl) {
   if (name == "typedef-decl") {
     ProcessTypedef(id, decl);
   } else if (name == "class-decl") {
@@ -939,14 +1031,10 @@ bool Abigail::ProcessUserDefinedType(std::string_view name, Id id,
 void Abigail::ProcessScope(xmlNodePtr scope) {
   for (auto* element = Child(scope); element; element = Next(element)) {
     const auto name = GetName(element);
-    const auto type_id = GetAttribute(element, "id");
+    const auto maybe_id = GetAttribute(element, "id");
     // all type elements have "id", all non-types do not
-    if (type_id) {
-      const auto id = GetNode(*type_id);
-      if (graph_.Is(id)) {
-        Warn() << "duplicate definition of type '" << *type_id << '\'';
-        continue;
-      }
+    if (maybe_id) {
+      const auto& id = *maybe_id;
       if (name == "function-type") {
         ProcessFunctionType(id, element);
       } else if (name == "pointer-type-def") {
@@ -990,7 +1078,7 @@ Id Abigail::ProcessDecl(bool is_variable, xmlNodePtr decl) {
   const auto name = scope_name_ + GetAttributeOrDie(decl, "name");
   const auto symbol_id = GetAttribute(decl, "elf-symbol-id");
   const auto type = is_variable ? GetEdge(decl)
-                                : graph_.Add<Function>(MakeFunctionType(decl));
+                                : maker_.Add<Function>(MakeFunctionType(decl));
   if (symbol_id) {
     // There's a link to an ELF symbol.
     const auto [it, inserted] = symbol_id_and_full_name_.emplace(
@@ -1002,25 +1090,27 @@ Id Abigail::ProcessDecl(bool is_variable, xmlNodePtr decl) {
   return type;
 }
 
-void Abigail::ProcessFunctionType(Id id, xmlNodePtr function) {
-  graph_.Set<Function>(id, MakeFunctionType(function));
+void Abigail::ProcessFunctionType(const std::string& id, xmlNodePtr function) {
+  maker_.MaybeSet<Function>(id, MakeFunctionType(function));
 }
 
-void Abigail::ProcessTypedef(Id id, xmlNodePtr type_definition) {
+void Abigail::ProcessTypedef(const std::string& id,
+                             xmlNodePtr type_definition) {
   const auto name = scope_name_ + GetAttributeOrDie(type_definition, "name");
   const auto type = GetEdge(type_definition);
-  graph_.Set<Typedef>(id, name, type);
+  maker_.MaybeSet<Typedef>(id, name, type);
 }
 
-void Abigail::ProcessPointer(Id id, bool is_pointer, xmlNodePtr pointer) {
+void Abigail::ProcessPointer(const std::string& id, bool is_pointer,
+                             xmlNodePtr pointer) {
   const auto type = GetEdge(pointer);
   const auto kind = is_pointer ? PointerReference::Kind::POINTER
                                : ReadAttribute<PointerReference::Kind>(
                                      pointer, "kind", &ParseReferenceKind);
-  graph_.Set<PointerReference>(id, kind, type);
+  maker_.MaybeSet<PointerReference>(id, kind, type);
 }
 
-void Abigail::ProcessQualified(Id id, xmlNodePtr qualified) {
+void Abigail::ProcessQualified(const std::string& id, xmlNodePtr qualified) {
   std::vector<Qualifier> qualifiers;
   // Do these in reverse order so we get CVR ordering.
   if (ReadAttribute<bool>(qualified, "restrict", false)) {
@@ -1041,14 +1131,14 @@ void Abigail::ProcessQualified(Id id, xmlNodePtr qualified) {
     --count;
     const Qualified node(qualifier, type);
     if (count) {
-      type = graph_.Add<Qualified>(node);
+      type = maker_.Add<Qualified>(node);
     } else {
-      graph_.Set<Qualified>(id, node);
+      maker_.MaybeSet<Qualified>(id, node);
     }
   }
 }
 
-void Abigail::ProcessArray(Id id, xmlNodePtr array) {
+void Abigail::ProcessArray(const std::string& id, xmlNodePtr array) {
   std::vector<size_t> dimensions;
   for (auto* child = Child(array); child; child = Next(child)) {
     CheckName("subrange", child);
@@ -1073,14 +1163,14 @@ void Abigail::ProcessArray(Id id, xmlNodePtr array) {
     const auto size = *it;
     const Array node(size, type);
     if (count) {
-      type = graph_.Add<Array>(node);
+      type = maker_.Add<Array>(node);
     } else {
-      graph_.Set<Array>(id, node);
+      maker_.MaybeSet<Array>(id, node);
     }
   }
 }
 
-void Abigail::ProcessTypeDecl(Id id, xmlNodePtr type_decl) {
+void Abigail::ProcessTypeDecl(const std::string& id, xmlNodePtr type_decl) {
   const auto name = scope_name_ + GetAttributeOrDie(type_decl, "name");
   const auto bits = ReadAttribute<size_t>(type_decl, "size-in-bits", 0);
   if (bits % 8) {
@@ -1089,15 +1179,15 @@ void Abigail::ProcessTypeDecl(Id id, xmlNodePtr type_decl) {
   const auto bytes = bits / 8;
 
   if (name == "void") {
-    graph_.Set<Special>(id, Special::Kind::VOID);
+    maker_.MaybeSet<Special>(id, Special::Kind::VOID);
   } else {
     // libabigail doesn't model encoding at all and we don't want to parse names
     // (which will not always work) in an attempt to reconstruct it.
-    graph_.Set<Primitive>(id, name, /* encoding= */ std::nullopt, bytes);
+    maker_.MaybeSet<Primitive>(id, name, /* encoding= */ std::nullopt, bytes);
   }
 }
 
-void Abigail::ProcessStructUnion(Id id, bool is_struct,
+void Abigail::ProcessStructUnion(const std::string& id, bool is_struct,
                                  xmlNodePtr struct_union) {
   // Libabigail sometimes reports is-declaration-only but still provides some
   // child elements. So we check both things.
@@ -1115,7 +1205,7 @@ void Abigail::ProcessStructUnion(Id id, bool is_struct,
       is_anonymous ? std::string() : scope_name_ + name;
   const PushScopeName push_scope_name(scope_name_, kind, name);
   if (forward) {
-    graph_.Set<StructUnion>(id, kind, full_name);
+    maker_.MaybeSet<StructUnion>(id, kind, full_name);
     return;
   }
   const auto bits = ReadAttribute<size_t>(struct_union, "size-in-bits", 0);
@@ -1142,18 +1232,18 @@ void Abigail::ProcessStructUnion(Id id, bool is_struct,
     }
   }
 
-  graph_.Set<StructUnion>(id, kind, full_name, bytes, base_classes, methods,
-                          members);
+  maker_.MaybeSet<StructUnion>(id, kind, full_name, bytes, base_classes,
+                               methods, members);
 }
 
-void Abigail::ProcessEnum(Id id, xmlNodePtr enumeration) {
+void Abigail::ProcessEnum(const std::string& id, xmlNodePtr enumeration) {
   const bool forward =
       ReadAttribute<bool>(enumeration, "is-declaration-only", false);
   const auto name = ReadAttribute<bool>(enumeration, "is-anonymous", false)
                     ? std::string()
                     : scope_name_ + GetAttributeOrDie(enumeration, "name");
   if (forward) {
-    graph_.Set<Enumeration>(id, name);
+    maker_.MaybeSet<Enumeration>(id, name);
     return;
   }
 
@@ -1173,7 +1263,7 @@ void Abigail::ProcessEnum(Id id, xmlNodePtr enumeration) {
     enumerators.emplace_back(enumerator_name, enumerator_value);
   }
 
-  graph_.Set<Enumeration>(id, name, type, enumerators);
+  maker_.MaybeSet<Enumeration>(id, name, type, enumerators);
 }
 
 Id Abigail::ProcessBaseClass(xmlNodePtr base_class) {
@@ -1183,7 +1273,7 @@ Id Abigail::ProcessBaseClass(xmlNodePtr base_class) {
   const auto inheritance = ReadAttribute<bool>(base_class, "is-virtual", false)
                            ? BaseClass::Inheritance::VIRTUAL
                            : BaseClass::Inheritance::NON_VIRTUAL;
-  return graph_.Add<BaseClass>(type, offset, inheritance);
+  return maker_.Add<BaseClass>(type, offset, inheritance);
 }
 
 std::optional<Id> Abigail::ProcessDataMember(bool is_struct,
@@ -1203,7 +1293,7 @@ std::optional<Id> Abigail::ProcessDataMember(bool is_struct,
   const auto type = GetEdge(decl);
 
   // Note: libabigail does not model member size, yet
-  return {graph_.Add<Member>(name, type, offset, 0)};
+  return {maker_.Add<Member>(name, type, offset, 0)};
 }
 
 void Abigail::ProcessMemberFunction(std::vector<Id>& methods,
@@ -1218,18 +1308,13 @@ void Abigail::ProcessMemberFunction(std::vector<Id>& methods,
     const auto mangled_name = ReadAttribute(decl, "mangled-name", missing);
     const auto name = GetAttributeOrDie(decl, "name");
     methods.push_back(
-        graph_.Add<Method>(mangled_name, name, vtable_offset.value(), type));
+        maker_.Add<Method>(mangled_name, name, vtable_offset.value(), type));
   }
 }
 
 void Abigail::ProcessMemberType(xmlNodePtr member_type) {
   const xmlNodePtr decl = GetOnlyChild(member_type);
-  const auto type_id = GetAttributeOrDie(decl, "id");
-  const auto id = GetNode(type_id);
-  if (graph_.Is(id)) {
-    Warn() << "duplicate definition of member type '" << type_id << '\'';
-    return;
-  }
+  const auto id = GetAttributeOrDie(decl, "id");
   const auto name = GetName(decl);
   if (!ProcessUserDefinedType(name, id, decl)) {
     Die() << "unrecognised member-type child element '" << name << "'";
@@ -1249,7 +1334,7 @@ Id Abigail::BuildSymbol(const SymbolInfo& info,
   const auto visibility =
       ReadAttributeOrDie<ElfSymbol::Visibility>(symbol, "visibility");
 
-  return graph_.Add<ElfSymbol>(
+  return maker_.Add<ElfSymbol>(
       info.name, info.version_info,
       is_defined, type, binding, visibility, crc, ns, type_id, name);
 }
@@ -1264,7 +1349,7 @@ Id Abigail::BuildSymbols() {
   //   symbol / alias -> type
   //
   for (const auto& [alias, main] : alias_to_main_) {
-    Check(!alias_to_main_.count(main))
+    Check(!alias_to_main_.contains(main))
         << "found main symbol and alias with id " << main;
   }
   // Build final symbol table, tying symbols to their types.
@@ -1282,34 +1367,59 @@ Id Abigail::BuildSymbols() {
     }
     symbols.insert({id, BuildSymbol(symbol_info, type_id, name)});
   }
-  return graph_.Add<Interface>(symbols);
+  return maker_.Add<Interface>(symbols);
 }
 
-Document Read(Runtime& runtime, const std::string& path) {
-  // Open input for reading.
-  const FileDescriptor fd(path.c_str(), O_RDONLY);
+using Parser = xmlDocPtr(xmlParserCtxtPtr context, const char* url,
+                         const char* encoding, int options);
 
-  // Read the XML.
+Document Parse(Runtime& runtime, const std::function<Parser>& parser) {
+  const std::unique_ptr<
+      std::remove_pointer_t<xmlParserCtxtPtr>, void(*)(xmlParserCtxtPtr)>
+      context(xmlNewParserCtxt(), xmlFreeParserCtxt);
   Document document(nullptr, xmlFreeDoc);
   {
     const Time t(runtime, "abigail.libxml_parse");
-    const std::unique_ptr<
-        std::remove_pointer_t<xmlParserCtxtPtr>, void(*)(xmlParserCtxtPtr)>
-        context(xmlNewParserCtxt(), xmlFreeParserCtxt);
-    document.reset(
-        xmlCtxtReadFd(context.get(), fd.Value(), nullptr, nullptr,
-                      XML_PARSE_NONET));
+    document.reset(parser(context.get(), nullptr, nullptr, XML_PARSE_NONET));
   }
   Check(document != nullptr) << "failed to parse input as XML";
-
   return document;
 }
 
+}  // namespace
+
+Id ProcessDocument(Graph& graph, xmlDocPtr document) {
+  xmlNodePtr root = xmlDocGetRootElement(document);
+  Check(root != nullptr) << "XML document has no root element";
+  const Id id = Abigail(graph).ProcessRoot(root);
+  return RemoveUselessQualifiers(graph, id);
+}
+
+Document Read(Runtime& runtime, const std::string& path) {
+  const FileDescriptor fd(path.c_str(), O_RDONLY);
+  return Parse(runtime, [&](xmlParserCtxtPtr context, const char* url,
+                            const char* encoding, int options) {
+    return xmlCtxtReadFd(context, fd.Value(), url, encoding, options);
+  });
+}
+
 Id Read(Runtime& runtime, Graph& graph, const std::string& path) {
+  // Read the XML.
   const Document document = Read(runtime, path);
-  const xmlNodePtr root = xmlDocGetRootElement(document.get());
-  Check(root != nullptr) << "XML document has no root element";
-  return Abigail(graph).ProcessRoot(root);
+  // Process the XML.
+  return ProcessDocument(graph, document.get());
+}
+
+Id ReadFromString(Runtime& runtime, Graph& graph, const std::string_view xml) {
+  // Read the XML.
+  const Document document =
+      Parse(runtime, [&](xmlParserCtxtPtr context, const char* url,
+                         const char* encoding, int options) {
+    return xmlCtxtReadMemory(context, xml.data(), static_cast<int>(xml.size()),
+                             url, encoding, options);
+  });
+  // Process the XML.
+  return ProcessDocument(graph, document.get());
 }
 
 }  // namespace abixml
diff --git a/abigail_reader.h b/abigail_reader.h
index 3123f93..3cd5617 100644
--- a/abigail_reader.h
+++ b/abigail_reader.h
@@ -1,7 +1,7 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 // -*- mode: C++ -*-
 //
-// Copyright 2021-2023 Google LLC
+// Copyright 2021-2024 Google LLC
 //
 // Licensed under the Apache License v2.0 with LLVM Exceptions (the
 // "License"); you may not use this file except in compliance with the
@@ -22,131 +22,20 @@
 #define STG_ABIGAIL_READER_H_
 
 #include <memory>
-#include <optional>
 #include <string>
 #include <string_view>
 #include <type_traits>
-#include <unordered_map>
-#include <utility>
-#include <vector>
 
 #include <libxml/tree.h>
 #include "graph.h"
 #include "runtime.h"
-#include "scope.h"
 
 namespace stg {
 namespace abixml {
 
-// Parser for libabigail's ABI XML format, creating a Symbol-Type Graph.
-//
-// On construction Abigail consumes a libxml node tree and builds a graph.
-//
-// The parser supports C types only, with C++ types to be added later.
-//
-// The main producer of ABI XML is abidw. The format has no formal specification
-// and has very limited semantic versioning. This parser makes no attempt to
-// support or correct for deficiencies in older versions of the format.
-//
-// The parser detects unexpected elements and will abort on the presence of at
-// least: namespace, base class and member function information.
-//
-// The parser ignores attributes it doesn't care about, including member access
-// specifiers and (meaningless) type ids on array dimensions.
-//
-// The STG IR and libabigail ABI XML models diverge in some ways. The parser has
-// to do extra work for each of these, as follows.
-//
-// 0. XML uses type and symbol ids to link together elements. These become edges
-// in the graph between symbols and types and between types and types. Dangling
-// type references will cause an abort. libabigail is much more relaxed about
-// symbols without type information and these are modelled as such.
-//
-// 1. XML function declarations have in-line types. The parser creates
-// free-standing types on-the-fly. A useful space optimisation might be to
-// prevent duplicate creation of such types.
-//
-// 2. Variadic parameters are currently flagged with an XML attribute. A
-// variadic type node is created on demand and will be shared by all such
-// paramerters.
-//
-// 3. XML symbols and aliases have a rather poor repesentation with aliases
-// represented as comma-separated attribute values. Aliases are resolved in a
-// post-processing phase.
-//
-// 4. XML anonymous types also have unhelpful names, these are ignored.
-class Abigail {
- public:
-  explicit Abigail(Graph& graph);
-  Id ProcessRoot(xmlNodePtr root);
-
- private:
-  struct SymbolInfo {
-    std::string name;
-    std::optional<ElfSymbol::VersionInfo> version_info;
-    xmlNodePtr node;
-  };
-
-  Graph& graph_;
-
-  // The STG IR uses a distinct node type for the variadic parameter type; if
-  // allocated, this is its STG node id.
-  std::optional<Id> variadic_;
-  // Map from libabigail type ids to STG node ids; except for the type of
-  // variadic parameters.
-  std::unordered_map<std::string, Id> type_ids_;
-
-  // symbol id to symbol information
-  std::unordered_map<std::string, SymbolInfo> symbol_info_map_;
-  // alias symbol id to main symbol id
-  std::unordered_map<std::string, std::string> alias_to_main_;
-  // libabigail decorates certain declarations with symbol ids; this is the
-  // mapping from symbol id to the corresponding type and full name.
-  std::unordered_map<std::string, std::pair<Id, std::string>>
-      symbol_id_and_full_name_;
-
-  // Full name of the current scope.
-  Scope scope_name_;
-
-  Id GetNode(const std::string& type_id);
-  Id GetEdge(xmlNodePtr element);
-  Id GetVariadic();
-  Function MakeFunctionType(xmlNodePtr function);
-
-  void ProcessCorpusGroup(xmlNodePtr group);
-  void ProcessCorpus(xmlNodePtr corpus);
-  void ProcessSymbols(xmlNodePtr symbols);
-  void ProcessSymbol(xmlNodePtr symbol);
-
-  bool ProcessUserDefinedType(std::string_view name, Id id, xmlNodePtr decl);
-  void ProcessScope(xmlNodePtr scope);
-
-  void ProcessInstr(xmlNodePtr instr);
-  void ProcessNamespace(xmlNodePtr scope);
-
-  Id ProcessDecl(bool is_variable, xmlNodePtr decl);
-
-  void ProcessFunctionType(Id id, xmlNodePtr function);
-  void ProcessTypedef(Id id, xmlNodePtr type_definition);
-  void ProcessPointer(Id id, bool is_pointer, xmlNodePtr pointer);
-  void ProcessQualified(Id id, xmlNodePtr qualified);
-  void ProcessArray(Id id, xmlNodePtr array);
-  void ProcessTypeDecl(Id id, xmlNodePtr type_decl);
-  void ProcessStructUnion(Id id, bool is_struct, xmlNodePtr struct_union);
-  void ProcessEnum(Id id, xmlNodePtr enumeration);
-
-  Id ProcessBaseClass(xmlNodePtr base_class);
-  std::optional<Id> ProcessDataMember(bool is_struct, xmlNodePtr data_member);
-  void ProcessMemberFunction(std::vector<Id>& methods, xmlNodePtr method);
-  void ProcessMemberType(xmlNodePtr member_type);
-
-  Id BuildSymbol(const SymbolInfo& info,
-                 std::optional<Id> type_id,
-                 const std::optional<std::string>& name);
-  Id BuildSymbols();
-};
-
+Id ProcessDocument(Graph& graph, xmlDocPtr document);
 Id Read(Runtime& runtime, Graph& graph, const std::string& path);
+Id ReadFromString(Runtime& runtime, Graph& graph, std::string_view xml);
 
 // Exposed for testing.
 void Clean(xmlNodePtr root);
diff --git a/btf_reader.cc b/btf_reader.cc
index 75ec360..ad5248d 100644
--- a/btf_reader.cc
+++ b/btf_reader.cc
@@ -1,7 +1,7 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 // -*- mode: C++ -*-
 //
-// Copyright 2020-2022 Google LLC
+// Copyright 2020-2024 Google LLC
 //
 // Licensed under the Apache License v2.0 with LLVM Exceptions (the
 // "License"); you may not use this file except in compliance with the
@@ -30,6 +30,7 @@
 #include <cstddef>
 #include <cstdint>
 #include <cstring>
+#include <map>
 #include <memory>
 #include <optional>
 #include <sstream>
@@ -39,6 +40,7 @@
 #include <vector>
 
 #include <linux/btf.h>
+#include "elf_dwarf_handle.h"
 #include "elf_loader.h"
 #include "error.h"
 #include "file_descriptor.h"
@@ -49,6 +51,54 @@ namespace stg {
 
 namespace btf {
 
+namespace {
+
+// BTF Specification: https://www.kernel.org/doc/html/latest/bpf/btf.html
+class Structs {
+ public:
+  explicit Structs(Graph& graph);
+  Id Process(std::string_view data);
+
+ private:
+  struct MemoryRange {
+    const char* start;
+    const char* limit;
+    bool Empty() const;
+    template <typename T> const T* Pull(size_t count = 1);
+  };
+
+  MemoryRange string_section_;
+
+  Maker<uint32_t> maker_;
+  std::optional<Id> void_;
+  std::optional<Id> variadic_;
+  std::map<std::string, Id> btf_symbols_;
+
+  Id ProcessAligned(std::string_view data);
+
+  Id GetVoid();
+  Id GetVariadic();
+  Id GetIdRaw(uint32_t btf_index);
+  Id GetId(uint32_t btf_index);
+  Id GetParameterId(uint32_t btf_index);
+  template <typename Node, typename... Args>
+  void Set(uint32_t id, Args&&... args);
+
+  Id BuildTypes(MemoryRange memory);
+  void BuildOneType(const btf_type* t, uint32_t btf_index,
+                    MemoryRange& memory);
+  Id BuildSymbols();
+  std::vector<Id> BuildMembers(
+      bool kflag, const btf_member* members, size_t vlen);
+  Enumeration::Enumerators BuildEnums(
+      bool is_signed, const struct btf_enum* enums, size_t vlen);
+  Enumeration::Enumerators BuildEnums64(
+      bool is_signed, const struct btf_enum64* enums, size_t vlen);
+  std::vector<Id> BuildParams(const struct btf_param* params, size_t vlen);
+  Id BuildEnumUnderlyingType(size_t size, bool is_signed);
+  std::string GetName(uint32_t name_off);
+};
+
 bool Structs::MemoryRange::Empty() const {
   return start == limit;
 }
@@ -62,12 +112,12 @@ const T* Structs::MemoryRange::Pull(size_t count) {
 }
 
 Structs::Structs(Graph& graph)
-    : graph_(graph) {}
+    : maker_(graph) {}
 
 // Get the index of the void type, creating one if needed.
 Id Structs::GetVoid() {
   if (!void_) {
-    void_ = {graph_.Add<Special>(Special::Kind::VOID)};
+    void_ = {maker_.Add<Special>(Special::Kind::VOID)};
   }
   return *void_;
 }
@@ -75,40 +125,47 @@ Id Structs::GetVoid() {
 // Get the index of the variadic parameter type, creating one if needed.
 Id Structs::GetVariadic() {
   if (!variadic_) {
-    variadic_ = {graph_.Add<Special>(Special::Kind::VARIADIC)};
+    variadic_ = {maker_.Add<Special>(Special::Kind::VARIADIC)};
   }
   return *variadic_;
 }
 
-// Map BTF type index to own index.
-//
-// If there is no existing mapping for a BTF type, create one pointing to a new
-// slot at the end of the array.
+// Map BTF type index to node ID.
 Id Structs::GetIdRaw(uint32_t btf_index) {
-  auto [it, inserted] = btf_type_ids_.insert({btf_index, Id(0)});
-  if (inserted) {
-    it->second = graph_.Allocate();
-  }
-  return it->second;
+  return maker_.Get(btf_index);
 }
 
-// Translate BTF type id to own type id, for non-parameters.
+// Translate BTF type index to node ID, for non-parameters.
 Id Structs::GetId(uint32_t btf_index) {
   return btf_index ? GetIdRaw(btf_index) : GetVoid();
 }
 
-// Translate BTF type id to own type id, for parameters.
+// Translate BTF type index to node ID, for parameters.
 Id Structs::GetParameterId(uint32_t btf_index) {
   return btf_index ? GetIdRaw(btf_index) : GetVariadic();
 }
 
+// For a BTF type index, populate the node with the corresponding ID.
+template <typename Node, typename... Args>
+void Structs::Set(uint32_t id, Args&&... args) {
+  maker_.Set<Node>(id, std::forward<Args>(args)...);
+}
+
 Id Structs::Process(std::string_view btf_data) {
+  // TODO: Remove this hack once the upstream binaries have proper
+  // alignment.
+  //
+  // Copy the data to aligned heap-allocated memory, if needed.
+  return reinterpret_cast<uintptr_t>(btf_data.data()) % alignof(btf_header) > 0
+      ? ProcessAligned(std::string(btf_data))
+      : ProcessAligned(btf_data);
+}
+
+Id Structs::ProcessAligned(std::string_view btf_data) {
   Check(sizeof(btf_header) <= btf_data.size())
       << "BTF section too small for header";
   const btf_header* header =
       reinterpret_cast<const btf_header*>(btf_data.data());
-  Check(reinterpret_cast<uintptr_t>(header) % alignof(btf_header) == 0)
-      << "misaligned BTF data";
   Check(header->magic == 0xEB9F) << "Magic field must be 0xEB9F for BTF";
 
   const char* header_limit = btf_data.begin() + header->hdr_len;
@@ -145,7 +202,7 @@ std::vector<Id> Structs::BuildMembers(
     const auto offset = kflag ? BTF_MEMBER_BIT_OFFSET(raw_offset) : raw_offset;
     const auto bitfield_size = kflag ? BTF_MEMBER_BITFIELD_SIZE(raw_offset) : 0;
     result.push_back(
-        graph_.Add<Member>(name, GetId(raw_member.type),
+        maker_.Add<Member>(name, GetId(raw_member.type),
                            static_cast<uint64_t>(offset), bitfield_size));
   }
   return result;
@@ -206,7 +263,7 @@ Id Structs::BuildEnumUnderlyingType(size_t size, bool is_signed) {
      << (8 * size);
   const auto encoding = is_signed ? Primitive::Encoding::SIGNED_INTEGER
                                   : Primitive::Encoding::UNSIGNED_INTEGER;
-  return graph_.Add<Primitive>(os.str(), encoding, size);
+  return maker_.Add<Primitive>(os.str(), encoding, size);
 }
 
 Id Structs::BuildTypes(MemoryRange memory) {
@@ -231,11 +288,6 @@ void Structs::BuildOneType(const btf_type* t, uint32_t btf_index,
   const auto vlen = BTF_INFO_VLEN(t->info);
   Check(kind < NR_BTF_KINDS) << "Unknown BTF kind: " << static_cast<int>(kind);
 
-  // delay allocation of node id as some BTF nodes are skipped
-  auto id = [&]() {
-    return GetIdRaw(btf_index);
-  };
-
   switch (kind) {
     case BTF_KIND_INT: {
       const auto info = *memory.Pull<uint32_t>();
@@ -258,23 +310,23 @@ void Structs::BuildOneType(const btf_type* t, uint32_t btf_index,
       if (bits != 8 * t->size) {
         Die() << "BTF INT bits != 8 * size";
       }
-      graph_.Set<Primitive>(id(), name, encoding, t->size);
+      Set<Primitive>(btf_index, name, encoding, t->size);
       break;
     }
     case BTF_KIND_FLOAT: {
       const auto name = GetName(t->name_off);
       const auto encoding = Primitive::Encoding::REAL_NUMBER;
-      graph_.Set<Primitive>(id(), name, encoding, t->size);
+      Set<Primitive>(btf_index, name, encoding, t->size);
       break;
     }
     case BTF_KIND_PTR: {
-      graph_.Set<PointerReference>(id(), PointerReference::Kind::POINTER,
-                                   GetId(t->type));
+      Set<PointerReference>(btf_index, PointerReference::Kind::POINTER,
+                            GetId(t->type));
       break;
     }
     case BTF_KIND_TYPEDEF: {
       const auto name = GetName(t->name_off);
-      graph_.Set<Typedef>(id(), name, GetId(t->type));
+      Set<Typedef>(btf_index, name, GetId(t->type));
       break;
     }
     case BTF_KIND_VOLATILE:
@@ -285,12 +337,12 @@ void Structs::BuildOneType(const btf_type* t, uint32_t btf_index,
                              : kind == BTF_KIND_VOLATILE
                              ? Qualifier::VOLATILE
                              : Qualifier::RESTRICT;
-      graph_.Set<Qualified>(id(), qualifier, GetId(t->type));
+      Set<Qualified>(btf_index, qualifier, GetId(t->type));
       break;
     }
     case BTF_KIND_ARRAY: {
       const auto* array = memory.Pull<struct btf_array>();
-      graph_.Set<Array>(id(), array->nelems, GetId(array->type));
+      Set<Array>(btf_index, array->nelems, GetId(array->type));
       break;
     }
     case BTF_KIND_STRUCT:
@@ -302,8 +354,8 @@ void Structs::BuildOneType(const btf_type* t, uint32_t btf_index,
       const bool kflag = BTF_INFO_KFLAG(t->info);
       const auto* btf_members = memory.Pull<struct btf_member>(vlen);
       const auto members = BuildMembers(kflag, btf_members, vlen);
-      graph_.Set<StructUnion>(id(), struct_union_kind, name, t->size,
-                              std::vector<Id>(), std::vector<Id>(), members);
+      Set<StructUnion>(btf_index, struct_union_kind, name, t->size,
+                       std::vector<Id>(), std::vector<Id>(), members);
       break;
     }
     case BTF_KIND_ENUM: {
@@ -317,10 +369,10 @@ void Structs::BuildOneType(const btf_type* t, uint32_t btf_index,
       if (vlen) {
         // create a synthetic underlying type
         const Id underlying = BuildEnumUnderlyingType(t->size, is_signed);
-        graph_.Set<Enumeration>(id(), name, underlying, enumerators);
+        Set<Enumeration>(btf_index, name, underlying, enumerators);
       } else {
         // BTF actually provides size (4), but it's meaningless.
-        graph_.Set<Enumeration>(id(), name);
+        Set<Enumeration>(btf_index, name);
       }
       break;
     }
@@ -331,7 +383,7 @@ void Structs::BuildOneType(const btf_type* t, uint32_t btf_index,
       const auto enumerators = BuildEnums64(is_signed, enums, vlen);
       // create a synthetic underlying type
       const Id underlying = BuildEnumUnderlyingType(t->size, is_signed);
-      graph_.Set<Enumeration>(id(), name, underlying, enumerators);
+      Set<Enumeration>(btf_index, name, underlying, enumerators);
       break;
     }
     case BTF_KIND_FWD: {
@@ -339,20 +391,20 @@ void Structs::BuildOneType(const btf_type* t, uint32_t btf_index,
       const auto struct_union_kind = BTF_INFO_KFLAG(t->info)
                                      ? StructUnion::Kind::UNION
                                      : StructUnion::Kind::STRUCT;
-      graph_.Set<StructUnion>(id(), struct_union_kind, name);
+      Set<StructUnion>(btf_index, struct_union_kind, name);
       break;
     }
     case BTF_KIND_FUNC: {
       const auto name = GetName(t->name_off);
       // TODO: map linkage (vlen) to symbol properties
-      graph_.Set<ElfSymbol>(id(), name, std::nullopt, true,
-                            ElfSymbol::SymbolType::FUNCTION,
-                            ElfSymbol::Binding::GLOBAL,
-                            ElfSymbol::Visibility::DEFAULT,
-                            std::nullopt,
-                            std::nullopt,
-                            GetId(t->type),
-                            std::nullopt);
+      Set<ElfSymbol>(btf_index, name, std::nullopt, true,
+                     ElfSymbol::SymbolType::FUNCTION,
+                     ElfSymbol::Binding::GLOBAL,
+                     ElfSymbol::Visibility::DEFAULT,
+                     std::nullopt,
+                     std::nullopt,
+                     GetId(t->type),
+                     std::nullopt);
       const bool inserted =
           btf_symbols_.insert({name, GetIdRaw(btf_index)}).second;
       Check(inserted) << "duplicate symbol " << name;
@@ -361,7 +413,7 @@ void Structs::BuildOneType(const btf_type* t, uint32_t btf_index,
     case BTF_KIND_FUNC_PROTO: {
       const auto* params = memory.Pull<struct btf_param>(vlen);
       const auto parameters = BuildParams(params, vlen);
-      graph_.Set<Function>(id(), GetId(t->type), parameters);
+      Set<Function>(btf_index, GetId(t->type), parameters);
       break;
     }
     case BTF_KIND_VAR: {
@@ -370,14 +422,14 @@ void Structs::BuildOneType(const btf_type* t, uint32_t btf_index,
       const auto name = GetName(t->name_off);
       // TODO: map variable->linkage to symbol properties
       (void) variable;
-      graph_.Set<ElfSymbol>(id(), name, std::nullopt, true,
-                            ElfSymbol::SymbolType::OBJECT,
-                            ElfSymbol::Binding::GLOBAL,
-                            ElfSymbol::Visibility::DEFAULT,
-                            std::nullopt,
-                            std::nullopt,
-                            GetId(t->type),
-                            std::nullopt);
+      Set<ElfSymbol>(btf_index, name, std::nullopt, true,
+                     ElfSymbol::SymbolType::OBJECT,
+                     ElfSymbol::Binding::GLOBAL,
+                     ElfSymbol::Visibility::DEFAULT,
+                     std::nullopt,
+                     std::nullopt,
+                     GetId(t->type),
+                     std::nullopt);
       const bool inserted =
           btf_symbols_.insert({name, GetIdRaw(btf_index)}).second;
       Check(inserted) << "duplicate symbol " << name;
@@ -406,30 +458,19 @@ std::string Structs::GetName(uint32_t name_off) {
 }
 
 Id Structs::BuildSymbols() {
-  return graph_.Add<Interface>(btf_symbols_);
+  return maker_.Add<Interface>(btf_symbols_);
+}
+
+}  // namespace
+
+Id ReadSection(Graph& graph, std::string_view data) {
+  return Structs(graph).Process(data);
 }
 
 Id ReadFile(Graph& graph, const std::string& path, ReadOptions) {
-  Check(elf_version(EV_CURRENT) != EV_NONE) << "ELF version mismatch";
-  struct ElfDeleter {
-    void operator()(Elf* elf) {
-      elf_end(elf);
-    }
-  };
-  const FileDescriptor fd(path.c_str(), O_RDONLY);
-  const std::unique_ptr<Elf, ElfDeleter> elf(
-      elf_begin(fd.Value(), ELF_C_READ, nullptr));
-  if (!elf) {
-    const int error_code = elf_errno();
-    const char* error = elf_errmsg(error_code);
-    if (error != nullptr) {
-      Die() << "elf_begin returned error: " << error;
-    } else {
-      Die() << "elf_begin returned error: " << error_code;
-    }
-  }
-  const elf::ElfLoader loader(elf.get());
-  return Structs(graph).Process(loader.GetBtfRawData());
+  ElfDwarfHandle handle(path);
+  const elf::ElfLoader loader(handle.GetElf());
+  return ReadSection(graph, loader.GetSectionRawData(".BTF"));
 }
 
 }  // namespace btf
diff --git a/btf_reader.h b/btf_reader.h
index 9f52198..74896cf 100644
--- a/btf_reader.h
+++ b/btf_reader.h
@@ -1,7 +1,7 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 // -*- mode: C++ -*-
 //
-// Copyright 2020-2023 Google LLC
+// Copyright 2020-2024 Google LLC
 //
 // Licensed under the Apache License v2.0 with LLVM Exceptions (the
 // "License"); you may not use this file except in compliance with the
@@ -21,66 +21,15 @@
 #ifndef STG_BTF_READER_H_
 #define STG_BTF_READER_H_
 
-#include <cstddef>
-#include <cstdint>
-#include <map>
-#include <optional>
 #include <string>
-#include <string_view>
-#include <unordered_map>
-#include <vector>
 
-#include <linux/btf.h>
 #include "graph.h"
 #include "reader_options.h"
 
 namespace stg {
 namespace btf {
 
-// BTF Specification: https://www.kernel.org/doc/html/latest/bpf/btf.html
-class Structs {
- public:
-  explicit Structs(Graph& graph);
-  Id Process(std::string_view data);
-
- private:
-  struct MemoryRange {
-    const char* start;
-    const char* limit;
-    bool Empty() const;
-    template <typename T> const T* Pull(size_t count = 1);
-  };
-
-  Graph& graph_;
-
-  MemoryRange string_section_;
-
-  std::optional<Id> void_;
-  std::optional<Id> variadic_;
-  std::unordered_map<uint32_t, Id> btf_type_ids_;
-  std::map<std::string, Id> btf_symbols_;
-
-  Id GetVoid();
-  Id GetVariadic();
-  Id GetIdRaw(uint32_t btf_index);
-  Id GetId(uint32_t btf_index);
-  Id GetParameterId(uint32_t btf_index);
-
-  Id BuildTypes(MemoryRange memory);
-  void BuildOneType(const btf_type* t, uint32_t btf_index,
-                    MemoryRange& memory);
-  Id BuildSymbols();
-  std::vector<Id> BuildMembers(
-      bool kflag, const btf_member* members, size_t vlen);
-  Enumeration::Enumerators BuildEnums(
-      bool is_signed, const struct btf_enum* enums, size_t vlen);
-  Enumeration::Enumerators BuildEnums64(
-      bool is_signed, const struct btf_enum64* enums, size_t vlen);
-  std::vector<Id> BuildParams(const struct btf_param* params, size_t vlen);
-  Id BuildEnumUnderlyingType(size_t size, bool is_signed);
-  std::string GetName(uint32_t name_off);
-};
-
+Id ReadSection(Graph& graph, std::string_view data);
 Id ReadFile(Graph& graph, const std::string& path, ReadOptions options);
 
 }  // namespace btf
diff --git a/comparison.cc b/comparison.cc
index 0015fc8..b748de5 100644
--- a/comparison.cc
+++ b/comparison.cc
@@ -38,6 +38,7 @@
 #include "order.h"
 
 namespace stg {
+namespace diff {
 
 struct IgnoreDescriptor {
   std::string_view name;
@@ -590,7 +591,7 @@ Result Compare::operator()(const Function& x1, const Function& x2) {
 
   const auto& parameters1 = x1.parameters;
   const auto& parameters2 = x2.parameters;
-  size_t min = std::min(parameters1.size(), parameters2.size());
+  const size_t min = std::min(parameters1.size(), parameters2.size());
   for (size_t i = 0; i < min; ++i) {
     const Id p1 = parameters1.at(i);
     const Id p2 = parameters2.at(i);
@@ -601,7 +602,7 @@ Result Compare::operator()(const Function& x1, const Function& x2) {
         (*this)(p1, p2));
   }
 
-  bool added = parameters1.size() < parameters2.size();
+  const bool added = parameters1.size() < parameters2.size();
   const auto& which = added ? x2 : x1;
   const auto& parameters = which.parameters;
   for (size_t i = min; i < parameters.size(); ++i) {
@@ -807,4 +808,5 @@ std::string MatchingKey::operator()(const Node&) {
   return {};
 }
 
+}  // namespace diff
 }  // namespace stg
diff --git a/comparison.h b/comparison.h
index 81eccf5..4ccc613 100644
--- a/comparison.h
+++ b/comparison.h
@@ -42,6 +42,7 @@
 #include "scc.h"
 
 namespace stg {
+namespace diff {
 
 struct Ignore {
   enum Value {
@@ -308,6 +309,7 @@ struct Compare {
   Histogram scc_size;
 };
 
+}  // namespace diff
 }  // namespace stg
 
 #endif  // STG_COMPARISON_H_
diff --git a/doc/stgdiff.md b/doc/stgdiff.md
index 62d6dd2..7f0c33b 100644
--- a/doc/stgdiff.md
+++ b/doc/stgdiff.md
@@ -133,11 +133,16 @@ reports the following kinds of fidelity changes:
 *   Loss or gain of type definitions
 *   Loss or gain of type information for symbols
 
-## Output formats
+## Output
 
 All outputs are based on a diff graph which is rooted at the comparison of two
 symbol table nodes.
 
+The `--format` and `--output` options may be repeated to obtain outputs of
+different formats.
+
+### Formats
+
 *   `plain`
 
     Serialise the diff graph via depth first search, avoiding revisiting nodes
diff --git a/dwarf_processor.cc b/dwarf_processor.cc
index 17fd682..beee31f 100644
--- a/dwarf_processor.cc
+++ b/dwarf_processor.cc
@@ -37,6 +37,7 @@
 #include "dwarf_wrappers.h"
 #include "error.h"
 #include "filter.h"
+#include "hex.h"
 #include "graph.h"
 #include "scope.h"
 
@@ -70,14 +71,18 @@ std::string GetName(Entry& entry) {
 std::string GetNameOrEmpty(Entry& entry) {
   auto result = MaybeGetName(entry);
   if (!result.has_value()) {
-    return std::string();
+    return {};
   }
   return std::move(*result);
 }
 
-std::optional<std::string> MaybeGetLinkageName(int version, Entry& entry) {
-  return entry.MaybeGetString(
+std::string GetLinkageName(int version, Entry& entry) {
+  auto linkage_name = entry.MaybeGetString(
       version < 4 ? DW_AT_MIPS_linkage_name : DW_AT_linkage_name);
+  if (linkage_name.has_value()) {
+    return std::move(*linkage_name);
+  }
+  return GetNameOrEmpty(entry);
 }
 
 size_t GetBitSize(Entry& entry) {
@@ -260,7 +265,7 @@ class Processor {
   Processor(Graph& graph, Id void_id, Id variadic_id,
             bool is_little_endian_binary,
             const std::unique_ptr<Filter>& file_filter, Types& result)
-      : graph_(graph),
+      : maker_(graph),
         void_id_(void_id),
         variadic_id_(variadic_id),
         is_little_endian_binary_(is_little_endian_binary),
@@ -275,14 +280,6 @@ class Processor {
     Process(compilation_unit.entry);
   }
 
-  void CheckUnresolvedIds() const {
-    for (const auto& [offset, id] : id_map_) {
-      if (!graph_.Is(id)) {
-        Die() << "unresolved id " << id << ", DWARF offset " << Hex(offset);
-      }
-    }
-  }
-
   void ResolveSymbolSpecifications() {
     std::sort(unresolved_symbol_specifications_.begin(),
               unresolved_symbol_specifications_.end());
@@ -298,7 +295,7 @@ class Processor {
           names_it->first != symbols_it->first) {
         Die() << "Scoped name not found for entry " << Hex(symbols_it->first);
       }
-      result_.symbols[symbols_it->second].name = names_it->second;
+      result_.symbols[symbols_it->second].scoped_name = names_it->second;
       ++symbols_it;
     }
   }
@@ -478,8 +475,7 @@ class Processor {
     if (!file) {
       // Built in types that do not have DW_AT_decl_file should be preserved.
       static constexpr std::string_view kBuiltinPrefix = "__";
-      // TODO: use std::string_view::starts_with
-      if (name.substr(0, kBuiltinPrefix.size()) == kBuiltinPrefix) {
+      if (name.starts_with(kBuiltinPrefix)) {
         return true;
       }
       Die() << "File filter is provided, but " << name << " ("
@@ -641,17 +637,17 @@ class Processor {
 
   void ProcessMethod(std::vector<Id>& methods, Entry& entry) {
     Subprogram subprogram = GetSubprogram(entry);
-    auto id = graph_.Add<Function>(std::move(subprogram.node));
+    auto id = maker_.Add<Function>(std::move(subprogram.node));
     if (subprogram.external && subprogram.address) {
       // Only external functions with address are useful for ABI monitoring
       // TODO: cover virtual methods
       const auto new_symbol_idx = result_.symbols.size();
       result_.symbols.push_back(Types::Symbol{
-          .name = GetScopedNameForSymbol(
+          .scoped_name = GetScopedNameForSymbol(
               new_symbol_idx, subprogram.name_with_context),
           .linkage_name = subprogram.linkage_name,
           .address = *subprogram.address,
-          .id = id});
+          .type_id = id});
     }
     const auto virtuality = entry.MaybeGetUnsignedConstant(DW_AT_virtuality)
                                  .value_or(DW_VIRTUALITY_none);
@@ -665,9 +661,8 @@ class Processor {
               << " shouldn't have specification";
       }
       const auto vtable_offset = entry.MaybeGetVtableOffset().value_or(0);
-      // TODO: proper handling of missing linkage name
       methods.push_back(AddProcessedNode<Method>(
-          entry, subprogram.linkage_name.value_or("{missing}"),
+          entry, subprogram.linkage_name,
           *subprogram.name_with_context.unscoped_name, vtable_offset, id));
     }
   }
@@ -903,10 +898,11 @@ class Processor {
       // Only external variables with address are useful for ABI monitoring
       const auto new_symbol_idx = result_.symbols.size();
       result_.symbols.push_back(Types::Symbol{
-          .name = GetScopedNameForSymbol(new_symbol_idx, name_with_context),
-          .linkage_name = MaybeGetLinkageName(version_, entry),
+          .scoped_name = GetScopedNameForSymbol(
+              new_symbol_idx, name_with_context),
+          .linkage_name = GetLinkageName(version_, entry),
           .address = *address,
-          .id = referred_type_id});
+          .type_id = referred_type_id});
     }
   }
 
@@ -917,18 +913,18 @@ class Processor {
       // Only external functions with address are useful for ABI monitoring
       const auto new_symbol_idx = result_.symbols.size();
       result_.symbols.push_back(Types::Symbol{
-          .name = GetScopedNameForSymbol(
+          .scoped_name = GetScopedNameForSymbol(
               new_symbol_idx, subprogram.name_with_context),
           .linkage_name = std::move(subprogram.linkage_name),
           .address = *subprogram.address,
-          .id = id});
+          .type_id = id});
     }
   }
 
   struct Subprogram {
     Function node;
     NameWithContext name_with_context;
-    std::optional<std::string> linkage_name;
+    std::string linkage_name;
     std::optional<Address> address;
     bool external;
   };
@@ -1011,19 +1007,14 @@ class Processor {
 
     return Subprogram{.node = Function(return_type_id, parameters),
                       .name_with_context = GetNameWithContext(entry),
-                      .linkage_name = MaybeGetLinkageName(version_, entry),
+                      .linkage_name = GetLinkageName(version_, entry),
                       .address = entry.MaybeGetAddress(DW_AT_low_pc),
                       .external = entry.GetFlag(DW_AT_external)};
   }
 
   // Allocate or get already allocated STG Id for Entry.
   Id GetIdForEntry(Entry& entry) {
-    const auto offset = entry.GetOffset();
-    const auto [it, emplaced] = id_map_.emplace(offset, Id(-1));
-    if (emplaced) {
-      it->second = graph_.Allocate();
-    }
-    return it->second;
+    return maker_.Get(Hex(entry.GetOffset()));
   }
 
   // Same as GetIdForEntry, but returns "void_id_" for "unspecified" references,
@@ -1040,22 +1031,20 @@ class Processor {
   // Populate Id from method above with processed Node.
   template <typename Node, typename... Args>
   Id AddProcessedNode(Entry& entry, Args&&... args) {
-    const Id id = GetIdForEntry(entry);
-    graph_.Set<Node>(id, std::forward<Args>(args)...);
-    return id;
+    return maker_.Set<Node>(Hex(entry.GetOffset()),
+                            std::forward<Args>(args)...);
   }
 
   void AddNamedTypeNode(Id id) {
     result_.named_type_ids.push_back(id);
   }
 
-  Graph& graph_;
+  Maker<Hex<Dwarf_Off>> maker_;
   Id void_id_;
   Id variadic_id_;
   bool is_little_endian_binary_;
   const std::unique_ptr<Filter>& file_filter_;
   Types& result_;
-  std::unordered_map<Dwarf_Off, Id> id_map_;
   std::vector<std::pair<Dwarf_Off, std::string>> scoped_names_;
   std::vector<std::pair<Dwarf_Off, size_t>> unresolved_symbol_specifications_;
 
@@ -1066,19 +1055,23 @@ class Processor {
   uint64_t language_;
 };
 
-Types Process(Handler& dwarf, bool is_little_endian_binary,
+Types Process(Dwarf* dwarf, bool is_little_endian_binary,
               const std::unique_ptr<Filter>& file_filter, Graph& graph) {
   Types result;
+
+  if (dwarf == nullptr) {
+    return result;
+  }
+
   const Id void_id = graph.Add<Special>(Special::Kind::VOID);
   const Id variadic_id = graph.Add<Special>(Special::Kind::VARIADIC);
   // TODO: Scope Processor to compilation units?
   Processor processor(graph, void_id, variadic_id, is_little_endian_binary,
                       file_filter, result);
-  for (auto& compilation_unit : dwarf.GetCompilationUnits()) {
+  for (auto& compilation_unit : GetCompilationUnits(*dwarf)) {
     // Could fetch top-level attributes like compiler here.
     processor.ProcessCompilationUnit(compilation_unit);
   }
-  processor.CheckUnresolvedIds();
   processor.ResolveSymbolSpecifications();
 
   return result;
diff --git a/dwarf_processor.h b/dwarf_processor.h
index 8a26c76..7eaa8ed 100644
--- a/dwarf_processor.h
+++ b/dwarf_processor.h
@@ -20,6 +20,8 @@
 #ifndef STG_DWARF_PROCESSOR_H_
 #define STG_DWARF_PROCESSOR_H_
 
+#include <elfutils/libdw.h>
+
 #include <cstddef>
 #include <optional>
 #include <string>
@@ -34,10 +36,10 @@ namespace dwarf {
 
 struct Types {
   struct Symbol {
-    std::string name;
-    std::optional<std::string> linkage_name;
+    std::string scoped_name;
+    std::string linkage_name;
     Address address;
-    Id id;
+    Id type_id;
   };
 
   size_t processed_entries = 0;
@@ -48,7 +50,8 @@ struct Types {
 
 // Process every compilation unit from DWARF and returns processed STG along
 // with information needed for matching to ELF symbols.
-Types Process(Handler& dwarf, bool is_little_endian_binary,
+// If DWARF is missing, returns empty result.
+Types Process(Dwarf* dwarf, bool is_little_endian_binary,
               const std::unique_ptr<Filter>& file_filter, Graph& graph);
 
 }  // namespace dwarf
diff --git a/dwarf_wrappers.cc b/dwarf_wrappers.cc
index 04e5897..9924a43 100644
--- a/dwarf_wrappers.cc
+++ b/dwarf_wrappers.cc
@@ -27,8 +27,6 @@
 
 #include <cstddef>
 #include <cstdint>
-#include <ios>
-#include <memory>
 #include <optional>
 #include <ostream>
 #include <string>
@@ -36,6 +34,7 @@
 #include <vector>
 
 #include "error.h"
+#include "hex.h"
 
 namespace stg {
 namespace dwarf {
@@ -46,12 +45,6 @@ std::ostream& operator<<(std::ostream& os, const Address& address) {
 
 namespace {
 
-static const Dwfl_Callbacks kDwflCallbacks = {
-    .find_elf = nullptr,
-    .find_debuginfo = dwfl_standard_find_debuginfo,
-    .section_address = dwfl_offline_section_address,
-    .debuginfo_path = nullptr};
-
 constexpr int kReturnOk = 0;
 constexpr int kReturnNoEntry = 1;
 
@@ -82,18 +75,6 @@ std::optional<Dwarf_Attribute> GetDirectAttribute(Dwarf_Die* die,
   return result;
 }
 
-void CheckOrDwflError(bool condition, const char* caller) {
-  if (!condition) {
-    int dwfl_error = dwfl_errno();
-    const char* errmsg = dwfl_errmsg(dwfl_error);
-    if (errmsg == nullptr) {
-      // There are some cases when DWFL fails to produce an error message.
-      Die() << caller << " returned error code " << Hex(dwfl_error);
-    }
-    Die() << caller << " returned error: " << errmsg;
-  }
-}
-
 std::optional<uint64_t> MaybeGetUnsignedOperand(const Dwarf_Op& operand) {
   switch (operand.atom) {
     case DW_OP_addr:
@@ -147,56 +128,15 @@ std::optional<Expression> MaybeGetExpression(Dwarf_Attribute& attribute) {
 
 }  // namespace
 
-Handler::Handler(const std::string& path) : dwfl_(dwfl_begin(&kDwflCallbacks)) {
-  CheckOrDwflError(dwfl_.get(), "dwfl_begin");
-  // Add data to process to dwfl
-  dwfl_module_ =
-      dwfl_report_offline(dwfl_.get(), path.c_str(), path.c_str(), -1);
-  InitialiseDwarf();
-}
-
-Handler::Handler(char* data, size_t size) : dwfl_(dwfl_begin(&kDwflCallbacks)) {
-  CheckOrDwflError(dwfl_.get(), "dwfl_begin");
-
-  // Check if ELF can be opened from input data, because DWFL couldn't handle
-  // memory, that is not ELF.
-  // TODO: remove this workaround
-  Elf* elf = elf_memory(data, size);
-  Check(elf != nullptr) << "Input data is not ELF";
-  elf_end(elf);
-
-  // Add data to process to dwfl
-  dwfl_module_ = dwfl_report_offline_memory(dwfl_.get(), "<memory>", "<memory>",
-                                            data, size);
-  InitialiseDwarf();
-}
-
-void Handler::InitialiseDwarf() {
-  CheckOrDwflError(dwfl_.get(), "dwfl_report_offline");
-  // Finish adding files to dwfl and process them
-  CheckOrDwflError(dwfl_report_end(dwfl_.get(), nullptr, nullptr) == kReturnOk,
-                   "dwfl_report_end");
-  GElf_Addr loadbase = 0;  // output argument for dwfl, unused by us
-  dwarf_ = dwfl_module_getdwarf(dwfl_module_, &loadbase);
-  CheckOrDwflError(dwarf_, "dwfl_module_getdwarf");
-}
-
-Elf* Handler::GetElf() {
-  GElf_Addr loadbase = 0;  // output argument for dwfl, unused by us
-  Elf* elf = dwfl_module_getelf(dwfl_module_, &loadbase);
-  CheckOrDwflError(elf, "dwfl_module_getelf");
-  return elf;
-}
-
-std::vector<CompilationUnit> Handler::GetCompilationUnits() {
+std::vector<CompilationUnit> GetCompilationUnits(Dwarf& dwarf) {
   std::vector<CompilationUnit> result;
   Dwarf_Off offset = 0;
   while (true) {
     Dwarf_Off next_offset;
     size_t header_size = 0;
     Dwarf_Half version = 0;
-    int return_code =
-        dwarf_next_unit(dwarf_, offset, &next_offset, &header_size, &version,
+    const int return_code =
+        dwarf_next_unit(&dwarf, offset, &next_offset, &header_size, &version,
                         nullptr, nullptr, nullptr, nullptr, nullptr);
     Check(return_code == kReturnOk || return_code == kReturnNoEntry)
         << "dwarf_next_unit returned error";
@@ -204,7 +144,8 @@ std::vector<CompilationUnit> Handler::GetCompilationUnits() {
       break;
     }
     result.push_back({version, {}});
-    Check(dwarf_offdie(dwarf_, offset + header_size, &result.back().entry.die))
+    Check(dwarf_offdie(&dwarf, offset + header_size,
+                       &result.back().entry.die) != nullptr)
         << "dwarf_offdie returned error";
 
     offset = next_offset;
diff --git a/dwarf_wrappers.h b/dwarf_wrappers.h
index 172489a..ad43413 100644
--- a/dwarf_wrappers.h
+++ b/dwarf_wrappers.h
@@ -22,29 +22,19 @@
 
 #include <elf.h>
 #include <elfutils/libdw.h>
-#include <elfutils/libdwfl.h>
 
 #include <cstddef>
 #include <cstdint>
-#include <memory>
 #include <optional>
 #include <ostream>
 #include <string>
-#include <tuple>
 #include <vector>
 
 namespace stg {
 namespace dwarf {
 
 struct Address {
-  // TODO: use auto operator<=>
-  bool operator<(const Address& other) const {
-    return std::tie(value, is_tls) < std::tie(other.value, other.is_tls);
-  }
-
-  bool operator==(const Address& other) const {
-    return value == other.value && is_tls == other.is_tls;
-  }
+  auto operator<=>(const Address&) const = default;
 
   uint64_t value;
   bool is_tls;
@@ -94,32 +84,7 @@ struct CompilationUnit {
   Entry entry;
 };
 
-// C++ wrapper over libdw (DWARF library).
-//
-// Creates a "Dwarf" object from an ELF file or a memory and controls the life
-// cycle of the created objects.
-class Handler {
- public:
-  explicit Handler(const std::string& path);
-  Handler(char* data, size_t size);
-
-  Elf* GetElf();
-  std::vector<CompilationUnit> GetCompilationUnits();
-
- private:
-  struct DwflDeleter {
-    void operator()(Dwfl* dwfl) {
-      dwfl_end(dwfl);
-    }
-  };
-
-  void InitialiseDwarf();
-
-  std::unique_ptr<Dwfl, DwflDeleter> dwfl_;
-  // Lifetime of Dwfl_Module and Dwarf is controlled by Dwfl.
-  Dwfl_Module* dwfl_module_ = nullptr;
-  Dwarf* dwarf_ = nullptr;
-};
+std::vector<CompilationUnit> GetCompilationUnits(Dwarf& dwarf);
 
 class Files {
  public:
diff --git a/elf_dwarf_handle.cc b/elf_dwarf_handle.cc
new file mode 100644
index 0000000..b03ad06
--- /dev/null
+++ b/elf_dwarf_handle.cc
@@ -0,0 +1,108 @@
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+// -*- mode: C++ -*-
+//
+// Copyright 2022-2024 Google LLC
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
+// Author: Aleksei Vetrov
+
+#include "elf_dwarf_handle.h"
+
+#include <elfutils/libdw.h>
+#include <elfutils/libdwfl.h>
+#include <fcntl.h>
+#include <gelf.h>
+#include <libelf.h>
+
+#include <cstddef>
+#include <functional>
+#include <sstream>
+#include <string>
+
+#include "error.h"
+#include "hex.h"
+
+namespace stg {
+
+namespace {
+
+const Dwfl_Callbacks kDwflCallbacks = {
+    .find_elf = nullptr,
+    .find_debuginfo = dwfl_standard_find_debuginfo,
+    .section_address = dwfl_offline_section_address,
+    .debuginfo_path = nullptr};
+
+constexpr int kReturnOk = 0;
+
+std::string GetDwflError(const char* caller) {
+  std::ostringstream result;
+  const int dwfl_error = dwfl_errno();
+  const char* errmsg = dwfl_errmsg(dwfl_error);
+  if (errmsg == nullptr) {
+    // There are some cases when DWFL fails to produce an error message.
+    result << caller << " returned error code " << Hex(dwfl_error);
+  } else {
+    result << caller << " returned error: " << errmsg;
+  }
+  return result.str();
+}
+
+void CheckOrDwflError(bool condition, const char* caller) {
+  if (!condition) {
+    Die() << GetDwflError(caller);
+  }
+}
+
+}  // namespace
+
+ElfDwarfHandle::ElfDwarfHandle(
+    const char* module_name, const std::function<Dwfl_Module*()>& add_module) {
+  dwfl_ = DwflUniquePtr(dwfl_begin(&kDwflCallbacks));
+  CheckOrDwflError(dwfl_ != nullptr, "dwfl_begin");
+  // Add data to process to dwfl
+  dwfl_module_ = add_module();
+  CheckOrDwflError(dwfl_module_ != nullptr, module_name);
+  // Finish adding files to dwfl and process them
+  CheckOrDwflError(dwfl_report_end(dwfl_.get(), nullptr, nullptr) == kReturnOk,
+                   "dwfl_report_end");
+}
+
+ElfDwarfHandle::ElfDwarfHandle(const std::string& path)
+    : ElfDwarfHandle("dwfl_report_offline", [&] {
+        return dwfl_report_offline(dwfl_.get(), path.c_str(), path.c_str(), -1);
+      }) {}
+
+ElfDwarfHandle::ElfDwarfHandle(char* data, size_t size)
+    : ElfDwarfHandle("dwfl_report_offline_memory", [&] {
+        return dwfl_report_offline_memory(dwfl_.get(), "<memory>", "<memory>",
+                                          data, size);
+      }) {}
+
+Elf& ElfDwarfHandle::GetElf() {
+  GElf_Addr loadbase = 0;  // output argument for dwfl, unused by us
+  Elf* elf = dwfl_module_getelf(dwfl_module_, &loadbase);
+  CheckOrDwflError(elf != nullptr, "dwfl_module_getelf");
+  return *elf;
+}
+
+Dwarf* ElfDwarfHandle::GetDwarf() {
+  GElf_Addr loadbase = 0;  // output argument for dwfl, unused by us
+  Dwarf* dwarf = dwfl_module_getdwarf(dwfl_module_, &loadbase);
+  if (dwarf == nullptr) {
+    Warn() << "No DWARF found: " << GetDwflError("dwfl_module_getdwarf");
+  }
+  return dwarf;
+}
+
+}  // namespace stg
diff --git a/elf_dwarf_handle.h b/elf_dwarf_handle.h
new file mode 100644
index 0000000..cca4a0e
--- /dev/null
+++ b/elf_dwarf_handle.h
@@ -0,0 +1,61 @@
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+// -*- mode: C++ -*-
+//
+// Copyright 2022-2024 Google LLC
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
+// Author: Aleksei Vetrov
+
+#ifndef STG_ELF_DWARF_HANDLE_H_
+#define STG_ELF_DWARF_HANDLE_H_
+
+#include <elf.h>
+#include <elfutils/libdw.h>
+#include <elfutils/libdwfl.h>
+
+#include <cstddef>
+#include <functional>
+#include <memory>
+#include <string>
+
+namespace stg {
+
+class ElfDwarfHandle {
+ public:
+  explicit ElfDwarfHandle(const std::string& path);
+  ElfDwarfHandle(char* data, size_t size);
+
+  Elf& GetElf();
+  Dwarf* GetDwarf();  // Returns nullptr if DWARF is not available.
+
+ private:
+  struct DwflDeleter {
+    void operator()(Dwfl* dwfl) {
+      dwfl_end(dwfl);
+    }
+  };
+  using DwflUniquePtr = std::unique_ptr<Dwfl, DwflDeleter>;
+
+  ElfDwarfHandle(const char* module_name,
+                 const std::function<Dwfl_Module*()>& add_module);
+
+  DwflUniquePtr dwfl_;
+  // Lifetime of Dwfl_Module is controlled by Dwfl.
+  Dwfl_Module* dwfl_module_ = nullptr;
+};
+
+}  // namespace stg
+
+
+#endif  // STG_ELF_DWARF_HANDLE_H_
diff --git a/elf_loader.cc b/elf_loader.cc
index 82d6b4a..cad551d 100644
--- a/elf_loader.cc
+++ b/elf_loader.cc
@@ -245,6 +245,12 @@ size_t GetNumberOfEntries(const GElf_Shdr& section_header) {
   return section_header.sh_size / section_header.sh_entsize;
 }
 
+std::string_view GetRawData(Elf_Scn* section, const char* name) {
+  Elf_Data* data = elf_rawdata(section, nullptr);
+  Check(data != nullptr) << "elf_rawdata failed on section " << name;
+  return {static_cast<char*>(data->d_buf), data->d_size};
+}
+
 std::string_view GetString(Elf* elf, uint32_t section, size_t offset) {
   const auto name = elf_strptr(elf, section, offset);
 
@@ -285,17 +291,14 @@ Elf_Scn* GetSymbolTableSection(Elf* elf, bool is_linux_kernel_binary) {
 constexpr std::string_view kCFISuffix = ".cfi";
 
 bool IsCFISymbolName(std::string_view name) {
-  // Check if symbol name ends with ".cfi"
-  // TODO: use std::string_view::ends_with
-  return (name.size() >= kCFISuffix.size() &&
-          name.substr(name.size() - kCFISuffix.size()) == kCFISuffix);
+  return name.ends_with(kCFISuffix);
 }
 
 }  // namespace
 
 std::string_view UnwrapCFISymbolName(std::string_view cfi_name) {
   Check(IsCFISymbolName(cfi_name))
-      << "CFI symbol " << cfi_name << " doesn't end with .cfi";
+      << "CFI symbol " << cfi_name << " doesn't end with " << kCFISuffix;
   return cfi_name.substr(0, cfi_name.size() - kCFISuffix.size());
 }
 
@@ -422,9 +425,8 @@ std::ostream& operator<<(std::ostream& os,
   }
 }
 
-ElfLoader::ElfLoader(Elf* elf)
-    : elf_(elf) {
-  Check(elf_ != nullptr) << "No ELF was provided";
+ElfLoader::ElfLoader(Elf& elf)
+    : elf_(&elf) {
   InitializeElfInformation();
 }
 
@@ -434,14 +436,8 @@ void ElfLoader::InitializeElfInformation() {
   is_little_endian_binary_ = elf::IsLittleEndianBinary(elf_);
 }
 
-std::string_view ElfLoader::GetBtfRawData() const {
-  Elf_Scn* btf_section = GetSectionByName(elf_, ".BTF");
-  Check(btf_section != nullptr) << ".BTF section is invalid";
-  Elf_Data* elf_data = elf_rawdata(btf_section, nullptr);
-  Check(elf_data != nullptr) << ".BTF section data is invalid";
-  const char* btf_start = static_cast<char*>(elf_data->d_buf);
-  const size_t btf_size = elf_data->d_size;
-  return std::string_view(btf_start, btf_size);
+std::string_view ElfLoader::GetSectionRawData(const char* name) const {
+  return GetRawData(GetSectionByName(elf_, name), name);
 }
 
 std::vector<SymbolTableEntry> ElfLoader::GetElfSymbols() const {
@@ -515,7 +511,7 @@ std::string_view ElfLoader::GetElfSymbolNamespace(
   Check(offset + length < data->d_size)
       << "Namespace string should be null-terminated";
 
-  return std::string_view(begin, length);
+  return {begin, length};
 }
 
 size_t ElfLoader::GetAbsoluteAddress(const SymbolTableEntry& symbol) const {
diff --git a/elf_loader.h b/elf_loader.h
index 39d9fff..561e1dd 100644
--- a/elf_loader.h
+++ b/elf_loader.h
@@ -75,9 +75,9 @@ std::string_view UnwrapCFISymbolName(std::string_view cfi_name);
 
 class ElfLoader final {
  public:
-  explicit ElfLoader(Elf* elf);
+  explicit ElfLoader(Elf& elf);
 
-  std::string_view GetBtfRawData() const;
+  std::string_view GetSectionRawData(const char* name) const;
   std::vector<SymbolTableEntry> GetElfSymbols() const;
   std::vector<SymbolTableEntry> GetCFISymbols() const;
   ElfSymbol::CRC GetElfSymbolCRC(const SymbolTableEntry& symbol) const;
diff --git a/elf_reader.cc b/elf_reader.cc
index 31d39cb..b3def7f 100644
--- a/elf_reader.cc
+++ b/elf_reader.cc
@@ -20,7 +20,6 @@
 #include "elf_reader.h"
 
 #include <cstddef>
-#include <functional>
 #include <map>
 #include <memory>
 #include <optional>
@@ -30,7 +29,7 @@
 #include <vector>
 
 #include "dwarf_processor.h"
-#include "dwarf_wrappers.h"
+#include "elf_dwarf_handle.h"
 #include "elf_loader.h"
 #include "error.h"
 #include "filter.h"
@@ -61,6 +60,8 @@ std::optional<typename M::mapped_type> MaybeGet(const M& map, const K& key) {
 ElfSymbol::SymbolType ConvertSymbolType(
     SymbolTableEntry::SymbolType symbol_type) {
   switch (symbol_type) {
+    case SymbolTableEntry::SymbolType::NOTYPE:
+      return ElfSymbol::SymbolType::NOTYPE;
     case SymbolTableEntry::SymbolType::OBJECT:
       return ElfSymbol::SymbolType::OBJECT;
     case SymbolTableEntry::SymbolType::FUNCTION:
@@ -96,7 +97,7 @@ CRCValuesMap GetCRCValuesMap(const SymbolTable& symbols, const ElfLoader& elf) {
   for (const auto& symbol : symbols) {
     const std::string_view name = symbol.name;
     if (name.substr(0, kCRCPrefix.size()) == kCRCPrefix) {
-      std::string_view name_suffix = name.substr(kCRCPrefix.size());
+      const std::string_view name_suffix = name.substr(kCRCPrefix.size());
       if (!crc_values.emplace(name_suffix, elf.GetElfSymbolCRC(symbol))
                .second) {
         Die() << "Multiple CRC values for symbol '" << name_suffix << '\'';
@@ -187,24 +188,27 @@ bool IsPublicFunctionOrVariable(const SymbolTableEntry& symbol) {
   return true;
 }
 
+bool IsLinuxKernelFunctionOrVariable(const SymbolNameList& ksymtab,
+                                     const SymbolTableEntry& symbol) {
+  // We use symbol name extracted from __ksymtab_ symbols as a proxy for the
+  // real symbol in the ksymtab. Such names can still be duplicated by LOCAL
+  // symbols so drop them to avoid false matches.
+  if (symbol.binding == SymbolTableEntry::Binding::LOCAL) {
+    return false;
+  }
+  // TODO: handle undefined ksymtab symbols
+  return ksymtab.contains(symbol.name);
+}
+
 namespace {
 
 class Reader {
  public:
-  Reader(Runtime& runtime, Graph& graph, const std::string& path,
-         ReadOptions options, const std::unique_ptr<Filter>& file_filter)
-      : graph_(graph),
-        dwarf_(path),
-        elf_(dwarf_.GetElf()),
-        options_(options),
-        file_filter_(file_filter),
-        runtime_(runtime) {}
-
-  Reader(Runtime& runtime, Graph& graph, char* data, size_t size,
+  Reader(Runtime& runtime, Graph& graph, ElfDwarfHandle& elf_dwarf_handle,
          ReadOptions options, const std::unique_ptr<Filter>& file_filter)
       : graph_(graph),
-        dwarf_(data, size),
-        elf_(dwarf_.GetElf()),
+        elf_dwarf_handle_(elf_dwarf_handle),
+        elf_(elf_dwarf_handle_.GetElf()),
         options_(options),
         file_filter_(file_filter),
         runtime_(runtime) {}
@@ -215,6 +219,13 @@ class Reader {
   using SymbolIndex =
       std::map<std::pair<dwarf::Address, std::string>, std::vector<size_t>>;
 
+  void GetLinuxKernelSymbols(
+      const std::vector<SymbolTableEntry>& all_symbols,
+      std::vector<std::pair<ElfSymbol, size_t>>& symbols) const;
+  void GetUserspaceSymbols(
+      const std::vector<SymbolTableEntry>& all_symbols,
+      std::vector<std::pair<ElfSymbol, size_t>>& symbols) const;
+
   Id BuildRoot(const std::vector<std::pair<ElfSymbol, size_t>>& symbols) {
     // On destruction, the unification object will remove or rewrite each graph
     // node for which it has a mapping.
@@ -225,8 +236,9 @@ class Reader {
     // the starting node ID to be the current graph limit.
     Unification unification(runtime_, graph_, graph_.Limit());
 
-    const dwarf::Types types = dwarf::Process(
-        dwarf_, elf_.IsLittleEndianBinary(), file_filter_, graph_);
+    const dwarf::Types types =
+        dwarf::Process(elf_dwarf_handle_.GetDwarf(),
+                       elf_.IsLittleEndianBinary(), file_filter_, graph_);
 
     // A less important optimisation is avoiding copying the mapping array as it
     // is populated. This is done by reserving space to the new graph limit.
@@ -247,10 +259,7 @@ class Reader {
     SymbolIndex address_name_to_index;
     for (size_t i = 0; i < types.symbols.size(); ++i) {
       const auto& symbol = types.symbols[i];
-
-      const auto& name =
-          symbol.linkage_name.has_value() ? *symbol.linkage_name : symbol.name;
-      address_name_to_index[std::make_pair(symbol.address, name)].push_back(i);
+      address_name_to_index[{symbol.address, symbol.linkage_name}].push_back(i);
     }
 
     std::map<std::string, Id> symbols_map;
@@ -282,7 +291,7 @@ class Reader {
     std::vector<Id> roots;
     roots.reserve(types.named_type_ids.size() + types.symbols.size() + 1);
     for (const auto& symbol : types.symbols) {
-      roots.push_back(symbol.id);
+      roots.push_back(symbol.type_id);
     }
     for (const auto id : types.named_type_ids) {
       roots.push_back(id);
@@ -298,14 +307,16 @@ class Reader {
   static bool IsEqual(Unification& unification,
                       const dwarf::Types::Symbol& lhs,
                       const dwarf::Types::Symbol& rhs) {
-    return lhs.name == rhs.name && lhs.linkage_name == rhs.linkage_name
-        && lhs.address == rhs.address && unification.Unify(lhs.id, rhs.id);
+    return lhs.scoped_name == rhs.scoped_name
+        && lhs.linkage_name == rhs.linkage_name
+        && lhs.address == rhs.address
+        && unification.Unify(lhs.type_id, rhs.type_id);
   }
 
   static ElfSymbol SymbolTableEntryToElfSymbol(
       const CRCValuesMap& crc_values, const NamespacesMap& namespaces,
       const SymbolTableEntry& symbol) {
-    return ElfSymbol(
+    return {
         /* symbol_name = */ std::string(symbol.name),
         /* version_info = */ std::nullopt,
         /* is_defined = */
@@ -316,7 +327,7 @@ class Reader {
         /* crc = */ MaybeGet(crc_values, std::string(symbol.name)),
         /* ns = */ MaybeGet(namespaces, std::string(symbol.name)),
         /* type_id = */ std::nullopt,
-        /* full_name = */ std::nullopt);
+        /* full_name = */ std::nullopt};
   }
 
   static void MaybeAddTypeInfo(
@@ -364,87 +375,91 @@ class Reader {
         // "void foo(int bar)" vs "void foo(const int bar)"
         if (!IsEqual(unification, best_symbol, other)) {
           Die() << "Duplicate DWARF symbol: address="
-                << best_symbol.address << ", name=" << best_symbol.name;
+                << best_symbols_it->first.first
+                << ", name=" << best_symbols_it->first.second;
         }
       }
-      if (best_symbol.name.empty()) {
-        Die() << "DWARF symbol (address = " << best_symbol.address
-              << ", linkage_name = "
-              << best_symbol.linkage_name.value_or("{missing}")
-              << " should have a name";
+      if (best_symbol.scoped_name.empty()) {
+        Die() << "Anonymous DWARF symbol: address="
+              << best_symbols_it->first.first
+              << ", name=" << best_symbols_it->first.second;
       }
       // There may be multiple DWARF symbols with same address (zero-length
       // arrays), or ELF symbol has different name from DWARF symbol (aliases).
       // But if we have both situations at once, we can't match ELF to DWARF and
       // it should be fixed in analysed binary source code.
       Check(matched_by_name || candidates == 1)
-          << "multiple candidates without matching names, best_symbol.name="
-          << best_symbol.name;
-      node.type_id = best_symbol.id;
-      node.full_name = best_symbol.name;
+          << "Multiple candidate symbols without matching name: address="
+          << best_symbols_it->first.first
+          << ", name=" << best_symbols_it->first.second;
+      node.type_id = best_symbol.type_id;
+      node.full_name = best_symbol.scoped_name;
     }
   }
 
   Graph& graph_;
-  // The order of the following two fields is important because ElfLoader uses
-  // an Elf* from dwarf::Handler without owning it.
-  dwarf::Handler dwarf_;
-  elf::ElfLoader elf_;
+  ElfDwarfHandle& elf_dwarf_handle_;
+  ElfLoader elf_;
   ReadOptions options_;
   const std::unique_ptr<Filter>& file_filter_;
   Runtime& runtime_;
 };
 
-Id Reader::Read() {
-  const auto all_symbols = elf_.GetElfSymbols();
-  const bool is_linux_kernel = elf_.IsLinuxKernelBinary();
-  const SymbolNameList ksymtab_symbols =
-      is_linux_kernel ? GetKsymtabSymbols(all_symbols) : SymbolNameList();
-
-  CRCValuesMap crc_values;
-  NamespacesMap namespaces;
-  if (is_linux_kernel) {
-    crc_values = GetCRCValuesMap(all_symbols, elf_);
-    namespaces = GetNamespacesMap(all_symbols, elf_);
+void Reader::GetLinuxKernelSymbols(
+    const std::vector<SymbolTableEntry>& all_symbols,
+    std::vector<std::pair<ElfSymbol, size_t>>& symbols) const {
+  const auto crcs = GetCRCValuesMap(all_symbols, elf_);
+  const auto namespaces = GetNamespacesMap(all_symbols, elf_);
+  const auto ksymtab_symbols = GetKsymtabSymbols(all_symbols);
+  for (const auto& symbol : all_symbols) {
+    if (IsLinuxKernelFunctionOrVariable(ksymtab_symbols, symbol)) {
+      const size_t address = elf_.GetAbsoluteAddress(symbol);
+      symbols.emplace_back(
+          SymbolTableEntryToElfSymbol(crcs, namespaces, symbol), address);
+    }
   }
+}
 
+void Reader::GetUserspaceSymbols(
+    const std::vector<SymbolTableEntry>& all_symbols,
+    std::vector<std::pair<ElfSymbol, size_t>>& symbols) const {
   const auto cfi_address_map = GetCFIAddressMap(elf_.GetCFISymbols(), elf_);
-
-  std::vector<std::pair<ElfSymbol, size_t>> symbols;
-  symbols.reserve(all_symbols.size());
   for (const auto& symbol : all_symbols) {
-    if (IsPublicFunctionOrVariable(symbol) &&
-        (!is_linux_kernel || ksymtab_symbols.count(symbol.name))) {
+    if (IsPublicFunctionOrVariable(symbol)) {
       const auto cfi_it = cfi_address_map.find(std::string(symbol.name));
       const size_t address = cfi_it != cfi_address_map.end()
                                  ? cfi_it->second
                                  : elf_.GetAbsoluteAddress(symbol);
       symbols.emplace_back(
-          SymbolTableEntryToElfSymbol(crc_values, namespaces, symbol), address);
+          SymbolTableEntryToElfSymbol({}, {}, symbol), address);
     }
   }
+}
+
+Id Reader::Read() {
+  const auto all_symbols = elf_.GetElfSymbols();
+  const auto get_symbols = elf_.IsLinuxKernelBinary()
+                           ? &Reader::GetLinuxKernelSymbols
+                           : &Reader::GetUserspaceSymbols;
+  std::vector<std::pair<ElfSymbol, size_t>> symbols;
+  symbols.reserve(all_symbols.size());
+  (this->*get_symbols)(all_symbols, symbols);
   symbols.shrink_to_fit();
 
   Id root = BuildRoot(symbols);
 
   // Types produced by ELF/DWARF readers may require removing useless
   // qualifiers.
-  RemoveUselessQualifiers(graph_, root);
-
-  return root;
+  return RemoveUselessQualifiers(graph_, root);
 }
 
 }  // namespace
 }  // namespace internal
 
-Id Read(Runtime& runtime, Graph& graph, const std::string& path,
-        ReadOptions options, const std::unique_ptr<Filter>& file_filter) {
-  return internal::Reader(runtime, graph, path, options, file_filter).Read();
-}
-
-Id Read(Runtime& runtime, Graph& graph, char* data, size_t size,
+Id Read(Runtime& runtime, Graph& graph, ElfDwarfHandle& elf_dwarf_handle,
         ReadOptions options, const std::unique_ptr<Filter>& file_filter) {
-  return internal::Reader(runtime, graph, data, size, options, file_filter)
+  return internal::Reader(runtime, graph, elf_dwarf_handle, options,
+                          file_filter)
       .Read();
 }
 
diff --git a/elf_reader.h b/elf_reader.h
index 159096a..ec7562a 100644
--- a/elf_reader.h
+++ b/elf_reader.h
@@ -28,6 +28,7 @@
 #include <unordered_set>
 #include <vector>
 
+#include "elf_dwarf_handle.h"
 #include "elf_loader.h"
 #include "filter.h"
 #include "graph.h"
@@ -37,9 +38,7 @@
 namespace stg {
 namespace elf {
 
-Id Read(Runtime& runtime, Graph& graph, const std::string& path,
-        ReadOptions options, const std::unique_ptr<Filter>& file_filter);
-Id Read(Runtime& runtime, Graph& graph, char* data, size_t size,
+Id Read(Runtime& runtime, Graph& graph, ElfDwarfHandle& elf_dwarf_handle,
         ReadOptions options, const std::unique_ptr<Filter>& file_filter);
 
 // For unit tests only
@@ -59,6 +58,8 @@ NamespacesMap GetNamespacesMap(const SymbolTable& symbols,
                                const ElfLoader& elf);
 AddressMap GetCFIAddressMap(const SymbolTable& symbols, const ElfLoader& elf);
 bool IsPublicFunctionOrVariable(const SymbolTableEntry& symbol);
+bool IsLinuxKernelFunctionOrVariable(const SymbolNameList& ksymtab,
+                                     const SymbolTableEntry& symbol);
 
 }  // namespace internal
 }  // namespace elf
diff --git a/equality_cache.h b/equality_cache.h
index 9373aa2..c1aa42b 100644
--- a/equality_cache.h
+++ b/equality_cache.h
@@ -240,7 +240,7 @@ struct SimpleEqualityCache {
       ++query_equal_ids;
       return {true};
     }
-    if (known_equalities.count(comparison)) {
+    if (known_equalities.contains(comparison)) {
       ++query_known_equality;
       return {true};
     }
diff --git a/error.h b/error.h
index b72faaf..4680cae 100644
--- a/error.h
+++ b/error.h
@@ -1,7 +1,7 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 // -*- mode: C++ -*-
 //
-// Copyright 2021-2022 Google LLC
+// Copyright 2021-2024 Google LLC
 //
 // Licensed under the Apache License v2.0 with LLVM Exceptions (the
 // "License"); you may not use this file except in compliance with the
@@ -21,7 +21,6 @@
 #define STG_ERROR_H_
 
 #include <exception>
-#include <ios>
 #include <iostream>
 #include <optional>
 #include <ostream>
@@ -48,14 +47,17 @@ class Exception : public std::exception {
   std::string message_;
 };
 
+// Coded to give compilers a chance of making `Check(ok) << foo;` as efficient
+// as `if (!ok) { Die() << foo; }`.
 class Check {
  public:
+  // These functions are all small and inlinable.
   explicit Check(bool ok)
       : os_(ok ? std::optional<std::ostringstream>()
                : std::make_optional<std::ostringstream>()) {}
   ~Check() noexcept(false) {
     if (os_) {
-      throw Exception(os_->str());
+      Throw(*os_);
     }
   }
 
@@ -69,6 +71,11 @@ class Check {
 
  private:
   std::optional<std::ostringstream> os_;
+
+  // This helper is too large to inline.
+  [[noreturn]] static void Throw(const std::ostringstream& os) {
+    throw Exception(os.str());
+  }
 };
 
 class Die {
@@ -112,23 +119,6 @@ inline std::ostream& operator<<(std::ostream& os, Error error) {
   return os << std::system_error(error.number, std::generic_category()).what();
 }
 
-template <typename T>
-struct Hex {
-  explicit Hex(const T& value) : value(value) {}
-  const T& value;
-};
-
-template <typename T> Hex(const T&) -> Hex<T>;
-
-template <typename T>
-std::ostream& operator<<(std::ostream& os, const Hex<T>& hex_value) {
-  // not quite right if an exception is thrown
-  const auto flags = os.flags();
-  os << "0x" << std::hex << hex_value.value;
-  os.flags(flags);
-  return os;
-}
-
 }  // namespace stg
 
 #endif  // STG_ERROR_H_
diff --git a/filter.cc b/filter.cc
index aa6f10a..cff06b3 100644
--- a/filter.cc
+++ b/filter.cc
@@ -71,12 +71,8 @@ Items ReadAbigail(const std::string& filename) {
     }
     // See if we are entering a filter list section.
     if (line[start] == '[' && line[limit - 1] == ']') {
-      std::string_view section(&line[start + 1], limit - start - 2);
-      // TODO: use std::string_view::ends_with
-      const auto section_size = section.size();
-      const auto suffix_size = kSectionSuffix.size();
-      in_filter_section = section_size >= suffix_size &&
-          section.substr(section_size - suffix_size) == kSectionSuffix;
+      const std::string_view section(&line[start + 1], limit - start - 2);
+      in_filter_section = section.ends_with(kSectionSuffix);
       continue;
     }
     // Add item.
@@ -150,7 +146,7 @@ class SetFilter : public Filter {
   explicit SetFilter(Items&& items)
       : items_(std::move(items)) {}
   bool operator()(const std::string& item) const final {
-    return items_.count(item) > 0;
+    return items_.contains(item);
   };
 
  private:
diff --git a/fuzz/abigail_reader_fuzzer.cc b/fuzz/abigail_reader_fuzzer.cc
index 2e01b94..09b6247 100644
--- a/fuzz/abigail_reader_fuzzer.cc
+++ b/fuzz/abigail_reader_fuzzer.cc
@@ -31,27 +31,24 @@ extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
   xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
   // Suppress libxml error messages.
   xmlSetGenericErrorFunc(ctxt, (xmlGenericErrorFunc) DoNothing);
-  xmlDocPtr doc = xmlCtxtReadMemory(
+  xmlDocPtr document = xmlCtxtReadMemory(
       ctxt, data, size, nullptr, nullptr,
       XML_PARSE_NOERROR | XML_PARSE_NONET | XML_PARSE_NOWARNING);
   xmlFreeParserCtxt(ctxt);
 
-  // Bail out if the doc XML is invalid.
-  if (!doc) {
+  // Bail out if the document XML is invalid.
+  if (document == nullptr) {
     return 0;
   }
 
-  xmlNodePtr root = xmlDocGetRootElement(doc);
-  if (root) {
-    try {
-      stg::Graph graph;
-      stg::abixml::Abigail(graph).ProcessRoot(root);
-    } catch (const stg::Exception&) {
-      // Pass as this is us catching invalid XML properly.
-    }
+  try {
+    stg::Graph graph;
+    stg::abixml::ProcessDocument(graph, document);
+  } catch (const stg::Exception&) {
+    // Pass as this is us catching invalid XML properly.
   }
 
-  xmlFreeDoc(doc);
+  xmlFreeDoc(document);
 
   return 0;
 }
diff --git a/fuzz/btf_reader_fuzzer.cc b/fuzz/btf_reader_fuzzer.cc
index 74bbdcc..4ce6de0 100644
--- a/fuzz/btf_reader_fuzzer.cc
+++ b/fuzz/btf_reader_fuzzer.cc
@@ -26,7 +26,7 @@
 extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
   try {
     stg::Graph graph;
-    stg::btf::Structs(graph).Process(std::string_view(data, size));
+    stg::btf::ReadSection(graph, std::string_view(data, size));
   } catch (const stg::Exception&) {
     // Pass as this is us catching invalid BTF properly.
   }
diff --git a/fuzz/elf_reader_fuzzer.cc b/fuzz/elf_reader_fuzzer.cc
index d83b012..ea9af18 100644
--- a/fuzz/elf_reader_fuzzer.cc
+++ b/fuzz/elf_reader_fuzzer.cc
@@ -21,6 +21,7 @@
 #include <sstream>
 #include <vector>
 
+#include "elf_dwarf_handle.h"
 #include "elf_reader.h"
 #include "error.h"
 #include "graph.h"
@@ -36,7 +37,8 @@ extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
     stg::Runtime runtime(os, false);
     stg::Graph graph;
     std::vector<char> data_copy(data, data + size);
-    stg::elf::Read(runtime, graph, data_copy.data(), size, stg::ReadOptions(),
+    stg::ElfDwarfHandle elf_dwarf_handle(data_copy.data(), size);
+    stg::elf::Read(runtime, graph, elf_dwarf_handle, stg::ReadOptions(),
                    nullptr);
   } catch (const stg::Exception&) {
     // Pass as this is us catching invalid ELF properly.
diff --git a/fuzz/proto_reader_fuzzer.cc b/fuzz/proto_reader_fuzzer.cc
index da5e8ba..7a102e0 100644
--- a/fuzz/proto_reader_fuzzer.cc
+++ b/fuzz/proto_reader_fuzzer.cc
@@ -17,16 +17,20 @@
 //
 // Author: Matthias Maennich
 
+#include <sstream>
 #include <string>
 
 #include "error.h"
 #include "graph.h"
 #include "proto_reader.h"
+#include "runtime.h"
 
 extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
   try {
+    std::ostringstream os;
+    stg::Runtime runtime(os, false);
     stg::Graph graph;
-    stg::proto::ReadFromString(graph, std::string_view(data, size));
+    stg::proto::ReadFromString(runtime, graph, std::string_view(data, size));
   } catch (const stg::Exception&) {
     // Pass as this is us catching invalid proto properly.
   }
diff --git a/graph.cc b/graph.cc
index ad402ca..6c5ca05 100644
--- a/graph.cc
+++ b/graph.cc
@@ -27,6 +27,8 @@
 #include <string>
 #include <string_view>
 
+#include "hex.h"
+
 namespace stg {
 
 const Id Id::kInvalid(std::numeric_limits<decltype(Id::ix_)>::max());
@@ -80,6 +82,8 @@ std::ostream& operator<<(std::ostream& os, Qualifier qualifier) {
 
 std::ostream& operator<<(std::ostream& os, ElfSymbol::SymbolType type) {
   switch (type) {
+    case ElfSymbol::SymbolType::NOTYPE:
+      return os << "no-type";
     case ElfSymbol::SymbolType::OBJECT:
       return os << "variable";
     case ElfSymbol::SymbolType::FUNCTION:
diff --git a/graph.h b/graph.h
index 0955675..3a31540 100644
--- a/graph.h
+++ b/graph.h
@@ -22,6 +22,7 @@
 #ifndef STG_GRAPH_H_
 #define STG_GRAPH_H_
 
+#include <compare>
 #include <cstddef>
 #include <cstdint>
 #include <functional>
@@ -43,13 +44,7 @@ struct Id {
   // defined in graph.cc as maximum value for index type
   static const Id kInvalid;
   explicit Id(size_t ix) : ix_(ix) {}
-  // TODO: auto operator<=>(const Id&) const = default;
-  bool operator==(const Id& other) const {
-    return ix_ == other.ix_;
-  }
-  bool operator!=(const Id& other) const {
-    return ix_ != other.ix_;
-  }
+  auto operator<=>(const Id&) const = default;
   size_t ix_;
 };
 
@@ -271,26 +266,17 @@ struct Function {
 };
 
 struct ElfSymbol {
-  enum class SymbolType { OBJECT, FUNCTION, COMMON, TLS, GNU_IFUNC };
+  enum class SymbolType { NOTYPE, OBJECT, FUNCTION, COMMON, TLS, GNU_IFUNC };
   enum class Binding { GLOBAL, LOCAL, WEAK, GNU_UNIQUE };
   enum class Visibility { DEFAULT, PROTECTED, HIDDEN, INTERNAL };
   struct VersionInfo {
-    // TODO: auto operator<=>(const VersionInfo&) const = default;
-    bool operator==(const VersionInfo& other) const {
-      return is_default == other.is_default && name == other.name;
-    }
+    auto operator<=>(const VersionInfo&) const = default;
     bool is_default;
     std::string name;
   };
   struct CRC {
     explicit CRC(uint32_t number) : number(number) {}
-    // TODO: auto operator<=>(const bool&) const = default;
-    bool operator==(const CRC& other) const {
-      return number == other.number;
-    }
-    bool operator!=(const CRC& other) const {
-      return number != other.number;
-    }
+    auto operator<=>(const CRC&) const = default;
     uint32_t number;
   };
   ElfSymbol(const std::string& symbol_name,
@@ -742,6 +728,76 @@ class DenseIdMapping {
   std::vector<Id> ids_;
 };
 
+template <typename ExternalId>
+class Maker {
+ public:
+  explicit Maker(Graph& graph) : graph_(graph) {}
+
+  ~Maker() noexcept(false) {
+    if (std::uncaught_exceptions() == 0) {
+      if (undefined_ > 0) {
+        Die die;
+        die << "undefined nodes:";
+        for (const auto& [external_id, id] : map_) {
+          if (!graph_.Is(id)) {
+            die << ' ' << external_id;
+          }
+        }
+      }
+    }
+  }
+
+  Id Get(const ExternalId& external_id) {
+    auto [it, inserted] = map_.emplace(external_id, 0);
+    if (inserted) {
+      it->second = graph_.Allocate();
+      ++undefined_;
+    }
+    return it->second;
+  }
+
+  template <typename Node, typename... Args>
+  Id Set(const ExternalId& external_id, Args&&... args) {
+    return Set<Node>(DieDuplicate, external_id, std::forward<Args>(args)...);
+  }
+
+  template <typename Node, typename... Args>
+  Id MaybeSet(const ExternalId& external_id, Args&&... args) {
+    return Set<Node>(WarnDuplicate, external_id, std::forward<Args>(args)...);
+  }
+
+  template <typename Node, typename... Args>
+  Id Add(Args&&... args) {
+    return graph_.Add<Node>(std::forward<Args>(args)...);
+  }
+
+ private:
+  Graph& graph_;
+  size_t undefined_ = 0;
+  std::unordered_map<ExternalId, Id> map_;
+
+  template <typename Node, typename... Args>
+  Id Set(void(& fail)(const ExternalId&), const ExternalId& external_id,
+         Args&&... args) {
+    const Id id = Get(external_id);
+    if (graph_.Is(id)) {
+      fail(external_id);
+    } else {
+      graph_.Set<Node>(id, std::forward<Args>(args)...);
+      --undefined_;
+    }
+    return id;
+  }
+
+  // These helpers should probably not be inlined.
+  [[noreturn]] static void DieDuplicate(const ExternalId& external_id) {
+    Die() << "duplicate definition of node: " << external_id;
+  }
+  static void WarnDuplicate(const ExternalId& external_id) {
+    Warn() << "ignoring duplicate definition of node: " << external_id;
+  }
+};
+
 }  // namespace stg
 
 #endif  // STG_GRAPH_H_
diff --git a/hashing.h b/hashing.h
index a1527e4..71fef1e 100644
--- a/hashing.h
+++ b/hashing.h
@@ -21,6 +21,7 @@
 #ifndef STG_HASHING_H_
 #define STG_HASHING_H_
 
+#include <compare>
 #include <cstddef>
 #include <cstdint>
 #include <functional>
@@ -31,14 +32,7 @@ namespace stg {
 
 struct HashValue {
   constexpr explicit HashValue(uint32_t value) : value(value) {}
-  // TODO: bool operator==(const HashValue&) const = default;
-  bool operator==(const HashValue& other) const {
-    return value == other.value;
-  }
-  bool operator!=(const HashValue& other) const {
-    return value != other.value;
-  }
-
+  auto operator<=>(const HashValue&) const = default;
   uint32_t value;
 };
 
diff --git a/hex.h b/hex.h
new file mode 100644
index 0000000..0c174f0
--- /dev/null
+++ b/hex.h
@@ -0,0 +1,57 @@
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+// -*- mode: C++ -*-
+//
+// Copyright 2023-2024 Google LLC
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
+#ifndef STG_HEX_H_
+#define STG_HEX_H_
+
+#include <cstddef>  // for std::size_t
+#include <functional>  // for std::hash
+#include <ios>
+#include <ostream>
+
+namespace stg {
+
+template <typename T>
+struct Hex {
+  explicit Hex(const T& value) : value(value) {}
+  auto operator<=>(const Hex<T>& other) const = default;
+  T value;
+};
+
+template <typename T> Hex(const T&) -> Hex<T>;
+
+template <typename T>
+std::ostream& operator<<(std::ostream& os, const Hex<T>& hex_value) {
+  // not quite right if an exception is thrown
+  const auto flags = os.flags();
+  os << "0x" << std::hex << hex_value.value;
+  os.flags(flags);
+  return os;
+}
+
+}  // namespace stg
+
+template <typename T>
+struct std::hash<stg::Hex<T>> {
+  std::size_t operator()(const stg::Hex<T>& hex) const noexcept {
+    return std::hash<T>{}(hex.value);
+  }
+};
+
+#endif  // STG_HEX_H_
diff --git a/hex_test.cc b/hex_test.cc
new file mode 100644
index 0000000..afa7214
--- /dev/null
+++ b/hex_test.cc
@@ -0,0 +1,69 @@
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
+#include "hex.h"
+
+#include <cstdint>
+#include <sstream>
+#include <string_view>
+
+#include <catch2/catch.hpp>
+
+namespace Test {
+
+struct TestCase {
+  std::string_view name;
+  int value;
+  std::string_view formatted;
+};
+
+TEST_CASE("Hex<uint32_t>") {
+  const auto test = GENERATE(
+      TestCase({"zero", 0, "0x0"}),
+      TestCase({"half width", 0xabcd, "0xabcd"}),
+      TestCase({"full width", 0x12345678, "0x12345678"}));
+
+  INFO("testing with " << test.name << " value");
+  std::ostringstream os;
+  os << stg::Hex<uint32_t>(test.value);
+  CHECK(os.str() == test.formatted);
+}
+
+TEST_CASE("self comparison") {
+  const stg::Hex<uint8_t> a(0);
+  CHECK(a == a);
+  CHECK(!(a != a));
+  CHECK(!(a < a));
+  CHECK(a <= a);
+  CHECK(!(a > a));
+  CHECK(a >= a);
+}
+
+TEST_CASE("distinct comparison") {
+  const stg::Hex<uint8_t> a(0);
+  const stg::Hex<uint8_t> b(1);
+  CHECK(!(a == b));
+  CHECK(a != b);
+  CHECK(a < b);
+  CHECK(a <= b);
+  CHECK(!(a > b));
+  CHECK(!(a >= b));
+}
+
+}  // namespace Test
diff --git a/input.cc b/input.cc
index 239cb07..5757379 100644
--- a/input.cc
+++ b/input.cc
@@ -24,6 +24,7 @@
 
 #include "abigail_reader.h"
 #include "btf_reader.h"
+#include "elf_dwarf_handle.h"
 #include "elf_reader.h"
 #include "error.h"
 #include "filter.h"
@@ -50,11 +51,12 @@ Id ReadInternal(Runtime& runtime, Graph& graph, InputFormat format,
     }
     case InputFormat::ELF: {
       const Time read(runtime, "read ELF");
-      return elf::Read(runtime, graph, input, options, file_filter);
+      ElfDwarfHandle elf_dwarf_handle(input);
+      return elf::Read(runtime, graph, elf_dwarf_handle, options, file_filter);
     }
     case InputFormat::STG: {
       const Time read(runtime, "read STG");
-      return proto::Read(graph, input);
+      return proto::Read(runtime, graph, input);
     }
   }
 }
diff --git a/naming.cc b/naming.cc
index 77548c1..ab1507a 100644
--- a/naming.cc
+++ b/naming.cc
@@ -30,7 +30,7 @@ namespace stg {
 
 Name Name::Add(Side side, Precedence precedence,
                const std::string& text) const {
-  bool bracket = precedence < precedence_;
+  const bool bracket = precedence < precedence_;
   std::ostringstream left;
   std::ostringstream right;
 
diff --git a/post_processing.cc b/post_processing.cc
index 9aafeb4..aec1b24 100644
--- a/post_processing.cc
+++ b/post_processing.cc
@@ -124,7 +124,7 @@ std::vector<std::string> SummariseOffsetChanges(
       const size_t indent3 = match3[1].length();
       if (indent1 + 2 == indent2 && indent1 >= indent3) {
         const auto new_indent = indent1;
-        int64_t new_offset =
+        const int64_t new_offset =
             std::stoll(match2[3].str()) - std::stoll(match2[2].str());
         if (new_indent != indent || new_offset != offset) {
           emit_pending();
diff --git a/proto_reader.cc b/proto_reader.cc
index a83fd10..264a54d 100644
--- a/proto_reader.cc
+++ b/proto_reader.cc
@@ -24,19 +24,24 @@
 #include <cerrno>
 #include <cstdint>
 #include <fstream>
+#include <limits>
 #include <map>
 #include <optional>
 #include <string>
 #include <string_view>
-#include <unordered_map>
 #include <vector>
 
+#include <google/protobuf/io/tokenizer.h>
+#include <google/protobuf/io/zero_copy_stream.h>
 #include <google/protobuf/io/zero_copy_stream_impl.h>
+#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
 #include <google/protobuf/repeated_field.h>
 #include <google/protobuf/repeated_ptr_field.h>
 #include <google/protobuf/text_format.h>
 #include "error.h"
 #include "graph.h"
+#include "hex.h"
+#include "runtime.h"
 #include "stg.pb.h"
 
 namespace stg {
@@ -45,7 +50,7 @@ namespace proto {
 namespace {
 
 struct Transformer {
-  explicit Transformer(Graph& graph) : graph(graph) {}
+  explicit Transformer(Graph& graph) : graph(graph), maker(graph) {}
 
   Id Transform(const proto::STG&);
 
@@ -74,7 +79,7 @@ struct Transformer {
   void AddNode(const Symbols&);
   void AddNode(const Interface&);
   template <typename STGType, typename... Args>
-  void AddNode(Args&&...);
+  void AddNode(uint32_t, Args&&...);
 
   std::vector<Id> Transform(const google::protobuf::RepeatedField<uint32_t>&);
   template <typename GetKey>
@@ -97,7 +102,7 @@ struct Transformer {
   Type Transform(const Type&);
 
   Graph& graph;
-  std::unordered_map<uint32_t, Id> id_map;
+  Maker<Hex<uint32_t>> maker;
 };
 
 Id Transformer::Transform(const proto::STG& x) {
@@ -125,11 +130,7 @@ Id Transformer::Transform(const proto::STG& x) {
 }
 
 Id Transformer::GetId(uint32_t id) {
-  auto [it, inserted] = id_map.emplace(id, 0);
-  if (inserted) {
-    it->second = graph.Allocate();
-  }
-  return it->second;
+  return maker.Get(Hex(id));
 }
 
 template <typename ProtoType>
@@ -140,59 +141,57 @@ void Transformer::AddNodes(const google::protobuf::RepeatedPtrField<ProtoType>&
 }
 
 void Transformer::AddNode(const Void& x) {
-  AddNode<stg::Special>(GetId(x.id()), stg::Special::Kind::VOID);
+  AddNode<stg::Special>(x.id(), stg::Special::Kind::VOID);
 }
 
 void Transformer::AddNode(const Variadic& x) {
-  AddNode<stg::Special>(GetId(x.id()), stg::Special::Kind::VARIADIC);
+  AddNode<stg::Special>(x.id(), stg::Special::Kind::VARIADIC);
 }
 
 void Transformer::AddNode(const Special& x) {
-  AddNode<stg::Special>(GetId(x.id()), x.kind());
+  AddNode<stg::Special>(x.id(), x.kind());
 }
 
 void Transformer::AddNode(const PointerReference& x) {
-  AddNode<stg::PointerReference>(GetId(x.id()), x.kind(),
-                                 GetId(x.pointee_type_id()));
+  AddNode<stg::PointerReference>(x.id(), x.kind(), GetId(x.pointee_type_id()));
 }
 
 void Transformer::AddNode(const PointerToMember& x) {
-  AddNode<stg::PointerToMember>(GetId(x.id()), GetId(x.containing_type_id()),
+  AddNode<stg::PointerToMember>(x.id(), GetId(x.containing_type_id()),
                                 GetId(x.pointee_type_id()));
 }
 
 void Transformer::AddNode(const Typedef& x) {
-  AddNode<stg::Typedef>(GetId(x.id()), x.name(), GetId(x.referred_type_id()));
+  AddNode<stg::Typedef>(x.id(), x.name(), GetId(x.referred_type_id()));
 }
 
 void Transformer::AddNode(const Qualified& x) {
-  AddNode<stg::Qualified>(GetId(x.id()), x.qualifier(),
-                          GetId(x.qualified_type_id()));
+  AddNode<stg::Qualified>(x.id(), x.qualifier(), GetId(x.qualified_type_id()));
 }
 
 void Transformer::AddNode(const Primitive& x) {
   const auto& encoding =
       Transform<stg::Primitive::Encoding>(x.has_encoding(), x.encoding());
-  AddNode<stg::Primitive>(GetId(x.id()), x.name(), encoding, x.bytesize());
+  AddNode<stg::Primitive>(x.id(), x.name(), encoding, x.bytesize());
 }
 
 void Transformer::AddNode(const Array& x) {
-  AddNode<stg::Array>(GetId(x.id()), x.number_of_elements(),
+  AddNode<stg::Array>(x.id(), x.number_of_elements(),
                       GetId(x.element_type_id()));
 }
 
 void Transformer::AddNode(const BaseClass& x) {
-  AddNode<stg::BaseClass>(GetId(x.id()), GetId(x.type_id()), x.offset(),
+  AddNode<stg::BaseClass>(x.id(), GetId(x.type_id()), x.offset(),
                           x.inheritance());
 }
 
 void Transformer::AddNode(const Method& x) {
-  AddNode<stg::Method>(GetId(x.id()), x.mangled_name(), x.name(),
-                       x.vtable_offset(), GetId(x.type_id()));
+  AddNode<stg::Method>(x.id(), x.mangled_name(), x.name(), x.vtable_offset(),
+                       GetId(x.type_id()));
 }
 
 void Transformer::AddNode(const Member& x) {
-  AddNode<stg::Member>(GetId(x.id()), x.name(), GetId(x.type_id()), x.offset(),
+  AddNode<stg::Member>(x.id(), x.name(), GetId(x.type_id()), x.offset(),
                        x.bitsize());
 }
 
@@ -200,29 +199,29 @@ void Transformer::AddNode(const VariantMember& x) {
   const auto& discr_value = x.has_discriminant_value()
                                 ? std::make_optional(x.discriminant_value())
                                 : std::nullopt;
-  AddNode<stg::VariantMember>(GetId(x.id()), x.name(), discr_value,
+  AddNode<stg::VariantMember>(x.id(), x.name(), discr_value,
                               GetId(x.type_id()));
 }
 
 void Transformer::AddNode(const StructUnion& x) {
   if (x.has_definition()) {
     AddNode<stg::StructUnion>(
-        GetId(x.id()), x.kind(), x.name(), x.definition().bytesize(),
+        x.id(), x.kind(), x.name(), x.definition().bytesize(),
         x.definition().base_class_id(), x.definition().method_id(),
         x.definition().member_id());
   } else {
-    AddNode<stg::StructUnion>(GetId(x.id()), x.kind(), x.name());
+    AddNode<stg::StructUnion>(x.id(), x.kind(), x.name());
   }
 }
 
 void Transformer::AddNode(const Enumeration& x) {
   if (x.has_definition()) {
-    AddNode<stg::Enumeration>(GetId(x.id()), x.name(),
+    AddNode<stg::Enumeration>(x.id(), x.name(),
                               GetId(x.definition().underlying_type_id()),
                               x.definition().enumerator());
     return;
   } else {
-    AddNode<stg::Enumeration>(GetId(x.id()), x.name());
+    AddNode<stg::Enumeration>(x.id(), x.name());
   }
 }
 
@@ -230,13 +229,12 @@ void Transformer::AddNode(const Variant& x) {
   const auto& discriminant = x.has_discriminant()
                                  ? std::make_optional(GetId(x.discriminant()))
                                  : std::nullopt;
-  AddNode<stg::Variant>(GetId(x.id()), x.name(), x.bytesize(), discriminant,
+  AddNode<stg::Variant>(x.id(), x.name(), x.bytesize(), discriminant,
                         x.member_id());
 }
 
 void Transformer::AddNode(const Function& x) {
-  AddNode<stg::Function>(GetId(x.id()), GetId(x.return_type_id()),
-                         x.parameter_id());
+  AddNode<stg::Function>(x.id(), GetId(x.return_type_id()), x.parameter_id());
 }
 
 void Transformer::AddNode(const ElfSymbol& x) {
@@ -244,7 +242,7 @@ void Transformer::AddNode(const ElfSymbol& x) {
     return std::make_optional(
         stg::ElfSymbol::VersionInfo{x.is_default(), x.name()});
   };
-  std::optional<stg::ElfSymbol::VersionInfo> version_info =
+  const std::optional<stg::ElfSymbol::VersionInfo> version_info =
       x.has_version_info() ? make_version_info(x.version_info()) : std::nullopt;
   const auto& crc = x.has_crc()
                         ? std::make_optional<stg::ElfSymbol::CRC>(x.crc())
@@ -255,7 +253,7 @@ void Transformer::AddNode(const ElfSymbol& x) {
   const auto& full_name =
       Transform<std::string>(x.has_full_name(), x.full_name());
 
-  AddNode<stg::ElfSymbol>(GetId(x.id()), x.name(), version_info, x.is_defined(),
+  AddNode<stg::ElfSymbol>(x.id(), x.name(), version_info, x.is_defined(),
                           x.symbol_type(), x.binding(), x.visibility(), crc, ns,
                           type_id, full_name);
 }
@@ -265,25 +263,25 @@ void Transformer::AddNode(const Symbols& x) {
   for (const auto& [symbol, id] : x.symbol()) {
     symbols.emplace(symbol, GetId(id));
   }
-  AddNode<stg::Interface>(GetId(x.id()), symbols);
+  AddNode<stg::Interface>(x.id(), symbols);
 }
 
 void Transformer::AddNode(const Interface& x) {
   const InterfaceKey get_key(graph);
-  AddNode<stg::Interface>(GetId(x.id()), Transform(get_key, x.symbol_id()),
+  AddNode<stg::Interface>(x.id(), Transform(get_key, x.symbol_id()),
                           Transform(get_key, x.type_id()));
 }
 
 template <typename STGType, typename... Args>
-void Transformer::AddNode(Args&&... args) {
-  graph.Set<STGType>(Transform(args)...);
+void Transformer::AddNode(uint32_t id, Args&&... args) {
+  maker.Set<STGType>(Hex(id), Transform(args)...);
 }
 
 std::vector<Id> Transformer::Transform(
     const google::protobuf::RepeatedField<uint32_t>& ids) {
   std::vector<Id> result;
   result.reserve(ids.size());
-  for (uint32_t id : ids) {
+  for (const uint32_t id : ids) {
     result.push_back(GetId(id));
   }
   return result;
@@ -391,6 +389,8 @@ stg::StructUnion::Kind Transformer::Transform(StructUnion::Kind x) {
 
 stg::ElfSymbol::SymbolType Transformer::Transform(ElfSymbol::SymbolType x) {
   switch (x) {
+    case ElfSymbol::NOTYPE:
+      return stg::ElfSymbol::SymbolType::NOTYPE;
     case ElfSymbol::OBJECT:
       return stg::ElfSymbol::SymbolType::OBJECT;
     case ElfSymbol::FUNCTION:
@@ -460,41 +460,70 @@ Type Transformer::Transform(const Type& x) {
 
 const std::array<uint32_t, 3> kSupportedFormatVersions = {0, 1, 2};
 
-void CheckFormatVersion(uint32_t version, std::optional<std::string> path) {
-  Check(std::count(kSupportedFormatVersions.begin(),
-                   kSupportedFormatVersions.end(), version) > 0)
+void CheckFormatVersion(uint32_t version) {
+  Check(std::binary_search(kSupportedFormatVersions.begin(),
+                           kSupportedFormatVersions.end(), version))
       << "STG format version " << version
       << " is not supported, minimum supported version: "
       << kSupportedFormatVersions.front();
   if (version != kSupportedFormatVersions.back()) {
-    auto warn = Warn();
-    warn << "STG format version " << version
-         << " is deprecated, consider upgrading stg format to latest version ("
-         << kSupportedFormatVersions.back() << ")";
-    if (path) {
-      warn << " with: stg --stg " << *path << " --output " << *path;
-    }
+    Warn() << "STG format version " << version
+           << " is deprecated, consider upgrading to the latest version ("
+           << kSupportedFormatVersions.back() << ")";
+  }
+}
+
+class ErrorSink : public google::protobuf::io::ErrorCollector {
+ public:
+  void AddError(int line, google::protobuf::io::ColumnNumber column,
+                const std::string& message) final {
+    Moan("error", line, column, message);
+  }
+  void AddWarning(int line, google::protobuf::io::ColumnNumber column,
+                  const std::string& message) final {
+    Moan("warning", line, column, message);
+  }
+
+ private:
+  static void Moan(std::string_view which, int line,
+                   google::protobuf::io::ColumnNumber column,
+                   const std::string& message) {
+    Warn() << "google::protobuf::TextFormat " << which << " at line " << (line + 1)
+           << " column " << (column + 1) << ": " << message;
+  }
+};
+
+Id ReadHelper(Runtime& runtime, Graph& graph,
+              google::protobuf::io::ZeroCopyInputStream& is) {
+  proto::STG stg;
+  {
+    const Time t(runtime, "proto.Parse");
+    ErrorSink error_sink;
+    google::protobuf::TextFormat::Parser parser;
+    parser.RecordErrorsTo(&error_sink);
+    Check(parser.Parse(&is, &stg)) << "failed to parse input as STG";
+  }
+  {
+    const Time t(runtime, "proto.Transform");
+    CheckFormatVersion(stg.version());
+    return Transformer(graph).Transform(stg);
   }
 }
 
 }  // namespace
 
-Id Read(Graph& graph, const std::string& path) {
+Id Read(Runtime& runtime, Graph& graph, const std::string& path) {
   std::ifstream ifs(path);
-  Check(ifs.good()) << "error opening file '" << path
-                    << "' for reading: " << Error(errno);
+  Check(ifs.good()) << "error opening file '" << path << "' for reading: "
+                    << Error(errno);
   google::protobuf::io::IstreamInputStream is(&ifs);
-  proto::STG stg;
-  google::protobuf::TextFormat::Parse(&is, &stg);
-  CheckFormatVersion(stg.version(), path);
-  return Transformer(graph).Transform(stg);
+  return ReadHelper(runtime, graph, is);
 }
 
-Id ReadFromString(Graph& graph, const std::string_view input) {
-  proto::STG stg;
-  google::protobuf::TextFormat::ParseFromString(std::string(input), &stg);
-  CheckFormatVersion(stg.version(), std::nullopt);
-  return Transformer(graph).Transform(stg);
+Id ReadFromString(Runtime& runtime, Graph& graph, std::string_view input) {
+  Check(input.size() <= std::numeric_limits<int>::max()) << "input too big";
+  google::protobuf::io::ArrayInputStream is(input.data(), static_cast<int>(input.size()));
+  return ReadHelper(runtime, graph, is);
 }
 
 }  // namespace proto
diff --git a/proto_reader.h b/proto_reader.h
index 7639bf1..b57f6e8 100644
--- a/proto_reader.h
+++ b/proto_reader.h
@@ -24,12 +24,13 @@
 #include <string_view>
 
 #include "graph.h"
+#include "runtime.h"
 
 namespace stg {
 namespace proto {
 
-Id Read(Graph&, const std::string&);
-Id ReadFromString(Graph&, std::string_view);
+Id Read(Runtime&, Graph&, const std::string&);
+Id ReadFromString(Runtime&, Graph&, std::string_view);
 
 }  // namespace proto
 }  // namespace stg
diff --git a/proto_writer.cc b/proto_writer.cc
index 16b1010..915981f 100644
--- a/proto_writer.cc
+++ b/proto_writer.cc
@@ -27,6 +27,7 @@
 #include <ostream>
 #include <sstream>
 #include <string>
+#include <tuple>
 #include <unordered_map>
 #include <unordered_set>
 
@@ -414,6 +415,8 @@ template <typename MapId>
 ElfSymbol::SymbolType Transform<MapId>::operator()(
     stg::ElfSymbol::SymbolType x) {
   switch (x) {
+    case stg::ElfSymbol::SymbolType::NOTYPE:
+      return ElfSymbol::NOTYPE;
     case stg::ElfSymbol::SymbolType::OBJECT:
       return ElfSymbol::OBJECT;
     case stg::ElfSymbol::SymbolType::FUNCTION:
@@ -458,55 +461,44 @@ ElfSymbol::Visibility Transform<MapId>::operator()(
 
 template <typename ProtoNode>
 void SortNodesById(google::protobuf::RepeatedPtrField<ProtoNode>& nodes) {
-  std::sort(
-      nodes.pointer_begin(), nodes.pointer_end(),
-      [](const auto* lhs, const auto* rhs) { return lhs->id() < rhs->id(); });
+  const auto compare = [](const auto* lhs, const auto* rhs) {
+    return lhs->id() < rhs->id();
+  };
+  std::sort(nodes.pointer_begin(), nodes.pointer_end(), compare);
 }
 
 template <typename ProtoNode>
 void SortNodesByName(google::protobuf::RepeatedPtrField<ProtoNode>& nodes) {
   const auto compare = [](const auto* lhs, const auto* rhs) {
-    const int comparison = lhs->name().compare(rhs->name());
-    return comparison < 0 || (comparison == 0 && lhs->id() < rhs->id());
+    return std::forward_as_tuple(lhs->name(), lhs->id())
+        < std::forward_as_tuple(rhs->name(), rhs->id());
   };
   std::sort(nodes.pointer_begin(), nodes.pointer_end(), compare);
 }
 
 void SortMethodsByMangledName(google::protobuf::RepeatedPtrField<Method>& methods) {
   const auto compare = [](const Method* lhs, const Method* rhs) {
-    const int comparison = lhs->mangled_name().compare(rhs->mangled_name());
-    return comparison < 0 || (comparison == 0 && lhs->id() < rhs->id());
+    return std::forward_as_tuple(lhs->mangled_name(), lhs->id())
+        < std::forward_as_tuple(rhs->mangled_name(), rhs->id());
   };
   std::sort(methods.pointer_begin(), methods.pointer_end(), compare);
 }
 
 void SortElfSymbolsByVersionedName(
     google::protobuf::RepeatedPtrField<ElfSymbol>& elf_symbols) {
-  // TODO: use spaceship operator <=>
   const auto compare = [](const ElfSymbol* lhs, const ElfSymbol* rhs) {
-    if (const int c = lhs->name().compare(rhs->name()); c != 0) {
-      return c < 0;
-    }
-
-    // Put symbols with version info after those without version info.
-    if (lhs->has_version_info() != rhs->has_version_info()) {
-      return rhs->has_version_info();
-    }
-
-    if (lhs->has_version_info()) {
-      const auto& l_version = lhs->version_info();
-      const auto& r_version = rhs->version_info();
-      if (const int c = l_version.name().compare(r_version.name()); c != 0) {
-        return c < 0;
-      }
-
-      // Put symbols with default version before those with non-default version.
-      if (l_version.is_default() != r_version.is_default()) {
-        return r_version.is_default();
-      }
-    }
-
-    return lhs->id() < rhs->id();
+    // Sorting by:
+    //
+    // name
+    // version name
+    // ID as tie-breaker
+    //
+    // Note: symbols without version information will be ordered before
+    // versioned symbols of the same name.
+    return std::forward_as_tuple(lhs->name(), lhs->version_info().name(),
+                                 lhs->id())
+        < std::forward_as_tuple(rhs->name(), rhs->version_info().name(),
+                                rhs->id());
   };
   std::sort(elf_symbols.pointer_begin(), elf_symbols.pointer_end(), compare);
 }
diff --git a/reporting.cc b/reporting.cc
index 5c3c02c..66bd998 100644
--- a/reporting.cc
+++ b/reporting.cc
@@ -78,7 +78,7 @@ namespace {
 std::string GetResolvedDescription(
     const Graph& graph, NameCache& names, Id id) {
   std::ostringstream os;
-  const auto [resolved, typedefs] = ResolveTypedefs(graph, id);
+  const auto [resolved, typedefs] = diff::ResolveTypedefs(graph, id);
   for (const auto& td : typedefs) {
     os << '\'' << td << "' = ";
   }
@@ -92,9 +92,9 @@ std::string GetResolvedDescription(
 // empty.
 //
 // It returns true if the comparison denotes addition or removal of a node.
-bool PrintComparison(const Reporting& reporting, const Comparison& comparison,
-                     std::ostream& os, size_t indent,
-                     const std::string& prefix) {
+bool PrintComparison(const Reporting& reporting,
+                     const diff::Comparison& comparison, std::ostream& os,
+                     size_t indent, const std::string& prefix) {
   os << std::string(indent, ' ');
   if (!prefix.empty()) {
     os << prefix << ' ';
@@ -139,24 +139,24 @@ static constexpr size_t INDENT_INCREMENT = 2;
 
 class Plain {
   // unvisited (absent) -> started (false) -> finished (true)
-  using Seen = std::unordered_map<Comparison, bool, HashComparison>;
+  using Seen = std::unordered_map<diff::Comparison, bool, diff::HashComparison>;
 
  public:
   Plain(const Reporting& reporting, std::ostream& output)
       : reporting_(reporting), output_(output) {}
 
-  void Report(const Comparison&);
+  void Report(const diff::Comparison&);
 
  private:
   const Reporting& reporting_;
   std::ostream& output_;
   Seen seen_;
 
-  void Print(const Comparison&, size_t, const std::string&);
+  void Print(const diff::Comparison&, size_t, const std::string&);
 };
 
-void Plain::Print(const Comparison& comparison, size_t indent,
-           const std::string& prefix) {
+void Plain::Print(const diff::Comparison& comparison, size_t indent,
+                  const std::string& prefix) {
   if (PrintComparison(reporting_, comparison, output_, indent, prefix)) {
     return;
   }
@@ -196,7 +196,7 @@ void Plain::Print(const Comparison& comparison, size_t indent,
   }
 }
 
-void Plain::Report(const Comparison& comparison) {
+void Plain::Report(const diff::Comparison& comparison) {
   // unpack then print - want symbol diff forest rather than symbols diff tree
   const auto& diff = reporting_.outcomes.at(comparison);
   for (const auto& detail : diff.details) {
@@ -216,21 +216,21 @@ class Flat {
   Flat(const Reporting& reporting, bool full, std::ostream& output)
       : reporting_(reporting), full_(full), output_(output) {}
 
-  void Report(const Comparison&);
+  void Report(const diff::Comparison&);
 
  private:
   const Reporting& reporting_;
   const bool full_;
   std::ostream& output_;
-  std::unordered_set<Comparison, HashComparison> seen_;
-  std::deque<Comparison> todo_;
+  std::unordered_set<diff::Comparison, diff::HashComparison> seen_;
+  std::deque<diff::Comparison> todo_;
 
-  bool Print(const Comparison&, bool, std::ostream&, size_t,
+  bool Print(const diff::Comparison&, bool, std::ostream&, size_t,
              const std::string&);
 };
 
-bool Flat::Print(const Comparison& comparison, bool stop, std::ostream& os,
-                 size_t indent, const std::string& prefix) {
+bool Flat::Print(const diff::Comparison& comparison, bool stop,
+                 std::ostream& os, size_t indent, const std::string& prefix) {
   // Nodes that represent additions or removal are always interesting and no
   // recursion is possible.
   if (PrintComparison(reporting_, comparison, os, indent, prefix)) {
@@ -269,7 +269,7 @@ bool Flat::Print(const Comparison& comparison, bool stop, std::ostream& os,
       // Edge changes are interesting if the target diff node is.
       std::ostringstream sub_os;
       // Set the stop flag to prevent recursion past diff-holding nodes.
-      bool sub_interesting =
+      const bool sub_interesting =
           Print(*detail.edge_, true, sub_os, indent, detail.text_);
       // If the sub-tree was interesting, add it.
       if (sub_interesting || full_) {
@@ -281,7 +281,7 @@ bool Flat::Print(const Comparison& comparison, bool stop, std::ostream& os,
   return interesting;
 }
 
-void Flat::Report(const Comparison& comparison) {
+void Flat::Report(const diff::Comparison& comparison) {
   // We want a symbol diff forest rather than a symbol table diff tree, so
   // unpack the symbol table and then print the symbols specially.
   const auto& diff = reporting_.outcomes.at(comparison);
@@ -303,15 +303,17 @@ void Flat::Report(const Comparison& comparison) {
   }
 }
 
-size_t VizId(std::unordered_map<Comparison, size_t, HashComparison>& ids,
-             const Comparison& comparison) {
+size_t VizId(
+    std::unordered_map<diff::Comparison, size_t, diff::HashComparison>& ids,
+    const diff::Comparison& comparison) {
   return ids.insert({comparison, ids.size()}).first->second;
 }
 
-void VizPrint(const Reporting& reporting, const Comparison& comparison,
-              std::unordered_set<Comparison, HashComparison>& seen,
-              std::unordered_map<Comparison, size_t, HashComparison>& ids,
-              std::ostream& os) {
+void VizPrint(
+    const Reporting& reporting, const diff::Comparison& comparison,
+    std::unordered_set<diff::Comparison, diff::HashComparison>& seen,
+    std::unordered_map<diff::Comparison, size_t, diff::HashComparison>& ids,
+    std::ostream& os) {
   if (!seen.insert(comparison).second) {
     return;
   }
@@ -373,11 +375,11 @@ void VizPrint(const Reporting& reporting, const Comparison& comparison,
   }
 }
 
-void ReportViz(const Reporting& reporting, const Comparison& comparison,
+void ReportViz(const Reporting& reporting, const diff::Comparison& comparison,
                std::ostream& output) {
   output << "digraph \"ABI diff\" {\n";
-  std::unordered_set<Comparison, HashComparison> seen;
-  std::unordered_map<Comparison, size_t, HashComparison> ids;
+  std::unordered_set<diff::Comparison, diff::HashComparison> seen;
+  std::unordered_map<diff::Comparison, size_t, diff::HashComparison> ids;
   VizPrint(reporting, comparison, seen, ids, output);
   output << "}\n";
 }
@@ -395,7 +397,7 @@ void PrintFidelityReportBucket(T transition,
 
 }  // namespace
 
-void Report(const Reporting& reporting, const Comparison& comparison,
+void Report(const Reporting& reporting, const diff::Comparison& comparison,
             std::ostream& output) {
   switch (reporting.options.format) {
     case OutputFormat::PLAIN: {
@@ -404,7 +406,7 @@ void Report(const Reporting& reporting, const Comparison& comparison,
     }
     case OutputFormat::FLAT:
     case OutputFormat::SMALL: {
-      bool full = reporting.options.format == OutputFormat::FLAT;
+      const bool full = reporting.options.format == OutputFormat::FLAT;
       Flat(reporting, full, output).Report(comparison);
       break;
     }
diff --git a/reporting.h b/reporting.h
index edee19e..04c3b98 100644
--- a/reporting.h
+++ b/reporting.h
@@ -47,12 +47,12 @@ struct Options {
 
 struct Reporting {
   const Graph& graph;
-  const Outcomes& outcomes;
+  const diff::Outcomes& outcomes;
   const Options& options;
   NameCache& names;
 };
 
-void Report(const Reporting&, const Comparison&, std::ostream&);
+void Report(const Reporting&, const diff::Comparison&, std::ostream&);
 
 bool FidelityDiff(const stg::FidelityDiff&, std::ostream&);
 
diff --git a/scc.h b/scc.h
index ca196b1..3199a53 100644
--- a/scc.h
+++ b/scc.h
@@ -21,8 +21,8 @@
 #define STG_SCC_H_
 
 #include <cstddef>
+#include <exception>
 #include <iterator>
-#include <memory>
 #include <optional>
 #include <unordered_map>
 #include <utility>
@@ -84,8 +84,11 @@ namespace stg {
 template <typename Node, typename Hash = std::hash<Node>>
 class SCC {
  public:
-  bool Empty() const {
-    return open_.empty() && is_open_.empty() && root_index_.empty();
+  ~SCC() noexcept(false) {
+    if (std::uncaught_exceptions() == 0) {
+      Check(open_.empty() && is_open_.empty() && root_index_.empty())
+          << "internal error: SCC state broken";
+    }
   }
 
   std::optional<size_t> Open(const Node& node) {
diff --git a/scc_test.cc b/scc_test.cc
index a82fd6c..47f5de8 100644
--- a/scc_test.cc
+++ b/scc_test.cc
@@ -68,10 +68,10 @@ Graph symmetric_subset_of_reflexive_transitive_closure(Graph g) {
     for (size_t i = 0; i < n; ++i) {
       // since we scan the nodes k in order, it suffices to consider just paths:
       // i -> k -> j
-      if (g[i].count(k)) {
+      if (g[i].contains(k)) {
         // we have i -> k
         for (size_t j = 0; j < n; ++j) {
-          if (g[k].count(j)) {
+          if (g[k].contains(j)) {
             // and k -> j
             g[i].insert(j);
           }
@@ -83,8 +83,8 @@ Graph symmetric_subset_of_reflexive_transitive_closure(Graph g) {
   for (size_t i = 0; i < n; ++i) {
     for (size_t j = i + 1; j < n; ++j) {
       // discard i -> j if not j -> i and vice versa
-      auto ij = g[i].count(j);
-      auto ji = g[j].count(i);
+      auto ij = g[i].contains(j);
+      auto ji = g[j].contains(i);
       if (ij < ji) {
         g[j].erase(i);
       }
@@ -118,7 +118,7 @@ Graph scc_strong_connectivity(const std::vector<std::set<size_t>>& sccs) {
 
 void dfs(std::set<size_t>& visited, SCC<size_t>& scc, const Graph& g,
          size_t node, std::vector<std::set<size_t>>& sccs) {
-  if (visited.count(node)) {
+  if (visited.contains(node)) {
     return;
   }
   auto handle = scc.Open(node);
@@ -149,7 +149,6 @@ void process(const Graph& g) {
     // could reuse a single SCC finder but assert stronger invariants this way
     SCC<size_t> scc;
     dfs(visited, scc, g, o, sccs);
-    CHECK(scc.Empty());
   }
 
   // check partition and topological order properties
@@ -165,7 +164,7 @@ void process(const Graph& g) {
     for (auto node : nodes) {
       for (auto o : g[node]) {
         // edges point to nodes in this or earlier SCCs
-        CHECK(seen.count(o));
+        CHECK(seen.contains(o));
       }
     }
   }
diff --git a/stg.proto b/stg.proto
index 5ba2d6c..ed6c86a 100644
--- a/stg.proto
+++ b/stg.proto
@@ -223,11 +223,12 @@ message ElfSymbol {
 
   enum SymbolType {
     SYMBOL_TYPE_UNSPECIFIED = 0;
-    OBJECT = 1;
-    FUNCTION = 2;
-    COMMON = 3;
-    TLS = 4;
-    GNU_IFUNC = 5;
+    NOTYPE = 1;
+    OBJECT = 2;
+    FUNCTION = 3;
+    COMMON = 4;
+    TLS = 5;
+    GNU_IFUNC = 6;
   }
 
   enum Binding {
diff --git a/stgdiff.cc b/stgdiff.cc
index ecc7fdb..d737767 100644
--- a/stgdiff.cc
+++ b/stgdiff.cc
@@ -76,11 +76,8 @@ int RunFidelity(const char* filename, const stg::Graph& graph,
   return diffs_reported ? kFidelityChange : 0;
 }
 
-int RunExact(stg::Runtime& runtime, const Inputs& inputs,
-             stg::ReadOptions options) {
-  stg::Graph graph;
-  const auto roots = Read(runtime, inputs, graph, options);
-
+int RunExact(stg::Runtime& runtime, const stg::Graph& graph,
+             const std::vector<stg::Id>& roots) {
   struct PairCache {
     std::optional<bool> Query(const stg::Pair& comparison) const {
       return equalities.find(comparison) != equalities.end()
@@ -103,21 +100,16 @@ int RunExact(stg::Runtime& runtime, const Inputs& inputs,
              : kAbiChange;
 }
 
-int Run(stg::Runtime& runtime, const Inputs& inputs, const Outputs& outputs,
-        stg::Ignore ignore, stg::ReadOptions options,
-        std::optional<const char*> fidelity) {
-  // Read inputs.
-  stg::Graph graph;
-  const auto roots = Read(runtime, inputs, graph, options);
-
+int Run(stg::Runtime& runtime, const stg::Graph& graph,
+        const std::vector<stg::Id>& roots, const Outputs& outputs,
+        stg::diff::Ignore ignore, std::optional<const char*> fidelity) {
   // Compute differences.
-  stg::Compare compare{runtime, graph, ignore};
-  std::pair<bool, std::optional<stg::Comparison>> result;
+  stg::diff::Compare compare{runtime, graph, ignore};
+  std::pair<bool, std::optional<stg::diff::Comparison>> result;
   {
     const stg::Time compute(runtime, "compute diffs");
     result = compare(roots[0], roots[1]);
   }
-  stg::Check(compare.scc.Empty()) << "internal error: SCC state broken";
   const auto& [equals, comparison] = result;
   int status = equals ? 0 : kAbiChange;
 
@@ -155,7 +147,7 @@ int main(int argc, char* argv[]) {
   bool opt_exact = false;
   stg::ReadOptions opt_read_options;
   std::optional<const char*> opt_fidelity = std::nullopt;
-  stg::Ignore opt_ignore;
+  stg::diff::Ignore opt_ignore;
   stg::InputFormat opt_input_format = stg::InputFormat::ABI;
   stg::reporting::OutputFormat opt_output_format =
       stg::reporting::OutputFormat::PLAIN;
@@ -189,7 +181,7 @@ int main(int argc, char* argv[]) {
               << "implicit defaults: --abi --format plain\n"
               << "--exact (node equality) cannot be combined with --output\n"
               << stg::reporting::OutputFormatUsage()
-              << stg::IgnoreUsage();
+              << stg::diff::IgnoreUsage();
     return 1;
   };
   while (true) {
@@ -225,11 +217,11 @@ int main(int argc, char* argv[]) {
         inputs.emplace_back(opt_input_format, argument);
         break;
       case 'i':
-        if (const auto ignore = stg::ParseIgnore(argument)) {
+        if (const auto ignore = stg::diff::ParseIgnore(argument)) {
           opt_ignore.Set(ignore.value());
         } else {
           std::cerr << "unknown ignore option: " << argument << '\n'
-                    << stg::IgnoreUsage();
+                    << stg::diff::IgnoreUsage();
           return 1;
         }
         break;
@@ -264,9 +256,11 @@ int main(int argc, char* argv[]) {
 
   try {
     stg::Runtime runtime(std::cerr, opt_metrics);
-    return opt_exact ? RunExact(runtime, inputs, opt_read_options)
-                     : Run(runtime, inputs, outputs, opt_ignore,
-                           opt_read_options, opt_fidelity);
+    stg::Graph graph;
+    const auto roots = Read(runtime, inputs, graph, opt_read_options);
+    return opt_exact ? RunExact(runtime, graph, roots)
+                     : Run(runtime, graph, roots, outputs, opt_ignore,
+                           opt_fidelity);
   } catch (const stg::Exception& e) {
     std::cerr << e.what();
     return 1;
diff --git a/stgdiff_test.cc b/stgdiff_test.cc
index 306ddc3..b0f82cc 100644
--- a/stgdiff_test.cc
+++ b/stgdiff_test.cc
@@ -38,7 +38,7 @@ struct IgnoreTestCase {
   const std::string file0;
   const stg::InputFormat format1;
   const std::string file1;
-  const stg::Ignore ignore;
+  const stg::diff::Ignore ignore;
   const std::string expected_output;
   const bool expected_equals;
 };
@@ -61,7 +61,7 @@ TEST_CASE("ignore") {
            "symbol_type_presence_0.xml",
            stg::InputFormat::ABI,
            "symbol_type_presence_1.xml",
-           stg::Ignore(),
+           stg::diff::Ignore(),
            "symbol_type_presence_small_diff",
            false}),
       IgnoreTestCase(
@@ -70,7 +70,7 @@ TEST_CASE("ignore") {
            "symbol_type_presence_0.xml",
            stg::InputFormat::ABI,
            "symbol_type_presence_1.xml",
-           stg::Ignore(stg::Ignore::SYMBOL_TYPE_PRESENCE),
+           stg::diff::Ignore(stg::diff::Ignore::SYMBOL_TYPE_PRESENCE),
            "empty",
            true}),
       IgnoreTestCase(
@@ -79,7 +79,7 @@ TEST_CASE("ignore") {
            "type_declaration_status_0.xml",
            stg::InputFormat::ABI,
            "type_declaration_status_1.xml",
-           stg::Ignore(),
+           stg::diff::Ignore(),
            "type_declaration_status_small_diff",
            false}),
       IgnoreTestCase(
@@ -88,7 +88,7 @@ TEST_CASE("ignore") {
            "type_declaration_status_0.xml",
            stg::InputFormat::ABI,
            "type_declaration_status_1.xml",
-           stg::Ignore(stg::Ignore::TYPE_DECLARATION_STATUS),
+           stg::diff::Ignore(stg::diff::Ignore::TYPE_DECLARATION_STATUS),
            "empty",
            true}),
       IgnoreTestCase(
@@ -97,7 +97,7 @@ TEST_CASE("ignore") {
            "primitive_type_encoding_0.stg",
            stg::InputFormat::STG,
            "primitive_type_encoding_1.stg",
-           stg::Ignore(),
+           stg::diff::Ignore(),
            "primitive_type_encoding_small_diff",
            false}),
       IgnoreTestCase(
@@ -106,7 +106,7 @@ TEST_CASE("ignore") {
            "primitive_type_encoding_0.stg",
            stg::InputFormat::STG,
            "primitive_type_encoding_1.stg",
-           stg::Ignore(stg::Ignore::PRIMITIVE_TYPE_ENCODING),
+           stg::diff::Ignore(stg::diff::Ignore::PRIMITIVE_TYPE_ENCODING),
            "empty",
            true}),
       IgnoreTestCase(
@@ -115,7 +115,7 @@ TEST_CASE("ignore") {
            "member_size_0.stg",
            stg::InputFormat::STG,
            "member_size_1.stg",
-           stg::Ignore(),
+           stg::diff::Ignore(),
            "member_size_small_diff",
            false}),
       IgnoreTestCase(
@@ -124,7 +124,7 @@ TEST_CASE("ignore") {
            "member_size_0.stg",
            stg::InputFormat::STG,
            "member_size_1.stg",
-           stg::Ignore(stg::Ignore::MEMBER_SIZE),
+           stg::diff::Ignore(stg::diff::Ignore::MEMBER_SIZE),
            "empty",
            true}),
       IgnoreTestCase(
@@ -133,7 +133,7 @@ TEST_CASE("ignore") {
            "enum_underlying_type_0.stg",
            stg::InputFormat::STG,
            "enum_underlying_type_1.stg",
-           stg::Ignore(),
+           stg::diff::Ignore(),
            "enum_underlying_type_small_diff",
            false}),
       IgnoreTestCase(
@@ -142,7 +142,7 @@ TEST_CASE("ignore") {
            "enum_underlying_type_0.stg",
            stg::InputFormat::STG,
            "enum_underlying_type_1.stg",
-           stg::Ignore(stg::Ignore::ENUM_UNDERLYING_TYPE),
+           stg::diff::Ignore(stg::diff::Ignore::ENUM_UNDERLYING_TYPE),
            "empty",
            true}),
       IgnoreTestCase(
@@ -151,7 +151,7 @@ TEST_CASE("ignore") {
            "qualifier_0.stg",
            stg::InputFormat::STG,
            "qualifier_1.stg",
-           stg::Ignore(),
+           stg::diff::Ignore(),
            "qualifier_small_diff",
            false}),
       IgnoreTestCase(
@@ -160,7 +160,7 @@ TEST_CASE("ignore") {
            "qualifier_0.stg",
            stg::InputFormat::STG,
            "qualifier_1.stg",
-           stg::Ignore(stg::Ignore::QUALIFIER),
+           stg::diff::Ignore(stg::diff::Ignore::QUALIFIER),
            "empty",
            true}),
       IgnoreTestCase(
@@ -169,7 +169,7 @@ TEST_CASE("ignore") {
            "crc_change_0.stg",
            stg::InputFormat::STG,
            "crc_change_1.stg",
-           stg::Ignore(),
+           stg::diff::Ignore(),
            "crc_change_small_diff",
            false}),
       IgnoreTestCase(
@@ -178,7 +178,7 @@ TEST_CASE("ignore") {
            "crc_change_0.stg",
            stg::InputFormat::STG,
            "crc_change_1.stg",
-           stg::Ignore(stg::Ignore::SYMBOL_CRC),
+           stg::diff::Ignore(stg::diff::Ignore::SYMBOL_CRC),
            "empty",
            true}),
       IgnoreTestCase(
@@ -187,7 +187,7 @@ TEST_CASE("ignore") {
            "interface_addition_0.stg",
            stg::InputFormat::STG,
            "interface_addition_1.stg",
-           stg::Ignore(),
+           stg::diff::Ignore(),
            "interface_addition_small_diff",
            false}),
       IgnoreTestCase(
@@ -196,7 +196,7 @@ TEST_CASE("ignore") {
            "interface_addition_0.stg",
            stg::InputFormat::STG,
            "interface_addition_1.stg",
-           stg::Ignore(stg::Ignore::INTERFACE_ADDITION),
+           stg::diff::Ignore(stg::diff::Ignore::INTERFACE_ADDITION),
            "empty",
            true}),
       IgnoreTestCase(
@@ -205,7 +205,7 @@ TEST_CASE("ignore") {
            "type_addition_0.stg",
            stg::InputFormat::STG,
            "type_addition_1.stg",
-           stg::Ignore(),
+           stg::diff::Ignore(),
            "type_addition_small_diff",
            false}),
       IgnoreTestCase(
@@ -214,7 +214,7 @@ TEST_CASE("ignore") {
            "type_addition_0.stg",
            stg::InputFormat::STG,
            "type_addition_1.stg",
-           stg::Ignore(stg::Ignore::INTERFACE_ADDITION),
+           stg::diff::Ignore(stg::diff::Ignore::INTERFACE_ADDITION),
            "empty",
            true}),
       IgnoreTestCase(
@@ -223,7 +223,7 @@ TEST_CASE("ignore") {
            "type_addition_1.stg",
            stg::InputFormat::STG,
            "type_addition_2.stg",
-           stg::Ignore(),
+           stg::diff::Ignore(),
            "type_definition_addition_small_diff",
            false}),
       IgnoreTestCase(
@@ -232,7 +232,7 @@ TEST_CASE("ignore") {
            "type_addition_1.stg",
            stg::InputFormat::STG,
            "type_addition_2.stg",
-           stg::Ignore(stg::Ignore::TYPE_DEFINITION_ADDITION),
+           stg::diff::Ignore(stg::diff::Ignore::TYPE_DEFINITION_ADDITION),
            "empty",
            true})
       );
@@ -247,7 +247,7 @@ TEST_CASE("ignore") {
     const auto id1 = Read(runtime, graph, test.format1, test.file1);
 
     // Compute differences.
-    stg::Compare compare{runtime, graph, test.ignore};
+    stg::diff::Compare compare{runtime, graph, test.ignore};
     const auto& [equals, comparison] = compare(id0, id1);
 
     // Write SMALL reports.
@@ -302,7 +302,7 @@ TEST_CASE("short report") {
     const auto id1 = Read(runtime, graph, stg::InputFormat::ABI, test.xml1);
 
     // Compute differences.
-    stg::Compare compare{runtime, graph, {}};
+    stg::diff::Compare compare{runtime, graph, {}};
     const auto& [equals, comparison] = compare(id0, id1);
 
     // Write SHORT reports.
diff --git a/test_cases/diff_tests/describe/types.0.c b/test_cases/diff_tests/describe/types.0.c
index 7c4353b..4435d36 100644
--- a/test_cases/diff_tests/describe/types.0.c
+++ b/test_cases/diff_tests/describe/types.0.c
@@ -28,14 +28,12 @@ struct amusement {
 
 struct amusement * fun() { return 0; }
 
-void tweak(int);
+int M() { return 1; }
+int N() { return 2; }
+int O() { return 3; }
+int P() { return 4; }
 
-int M() { tweak(0); return 0; }
-int N() { tweak(1); return 0; }
-int O() { tweak(2); return 0; }
-int P() { tweak(3); return 0; }
-
-int m() { tweak(4); return 0; }
-int n() { tweak(5); return 0; }
-int o() { tweak(6); return 0; }
-int p() { tweak(7); return 0; }
+int m() { return 5; }
+int n() { return 6; }
+int o() { return 7; }
+int p() { return 8; }
diff --git a/test_cases/diff_tests/describe/types.1.c b/test_cases/diff_tests/describe/types.1.c
index 4411bd8..ff22ac7 100644
--- a/test_cases/diff_tests/describe/types.1.c
+++ b/test_cases/diff_tests/describe/types.1.c
@@ -52,22 +52,20 @@ struct amusement {
 
 struct amusement * fun(void) { return 0; }
 
-void tweak(int);
-
 // declare M as function (void) returning int
-int M(void ) { tweak(0); return 0; }
+int M(void ) { return 1; }
 // declare N as function (void) returning pointer to array 7 of int
-int (*N(void ))[7] { tweak(1); return 0; }
+int (*N(void ))[7] { static int array[7]; return &array; }
 // declare O as function (void) returning pointer to int
-int *O(void ) { tweak(2); return 0; }
+int *O(void ) { static int number; return &number; }
 // declare P as function (void) returning pointer to function (void) returning int
-int (*P(void ))(void ) { tweak(3); return 0; }
+int (*P(void ))(void ) { return &M; }
 
 // declare m as function (void) returning int
-int m(void ) { tweak(4); return 0; }
+int m(void ) { return 5; }
 // declare n as function (void) returning pointer to array 7 of volatile int
-volatile int (*n(void ))[7] { tweak(5); return 0; }
+volatile int (*n(void ))[7] { static volatile int array[7]; return &array; }
 // declare o as function (void) returning pointer to volatile int
-volatile int *o(void ) { tweak(6); return 0; }
+volatile int *o(void ) { static volatile int number; return &number; }
 // declare p as function (void) returning pointer to function (void) returning int
-int (*p(void ))(void ) { tweak(7); return 0; }
+int (*p(void ))(void ) { return &m; }
diff --git a/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_flat b/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_flat
index 63fa50e..a56a281 100644
--- a/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_flat
+++ b/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_flat
@@ -10,13 +10,13 @@ variable symbol '_ZTS15NormalToVirtual' was added
 
 variable symbol '_ZTV15NormalToVirtual' was added
 
-function symbol 'void NormalToVirtual::print(struct NormalToVirtual*)' {_ZN15NormalToVirtual5printEv} changed
-  type 'void(struct NormalToVirtual*)' changed
+function symbol 'int NormalToVirtual::print(struct NormalToVirtual*)' {_ZN15NormalToVirtual5printEv} changed
+  type 'int(struct NormalToVirtual*)' changed
     parameter 1 type 'struct NormalToVirtual*' changed
       pointed-to type 'struct NormalToVirtual' changed
 
-function symbol 'void VirtualToNormal::print(struct VirtualToNormal*)' {_ZN15VirtualToNormal5printEv} changed
-  type 'void(struct VirtualToNormal*)' changed
+function symbol 'int VirtualToNormal::print(struct VirtualToNormal*)' {_ZN15VirtualToNormal5printEv} changed
+  type 'int(struct VirtualToNormal*)' changed
     parameter 1 type 'struct VirtualToNormal*' changed
       pointed-to type 'struct VirtualToNormal' changed
 
@@ -28,12 +28,12 @@ variable symbol 'struct VirtualToNormal virtual_to_normal' changed
 
 type 'struct NormalToVirtual' changed
   byte size changed from 1 to 8
-  method 'void print(struct NormalToVirtual*)' was added
+  method 'int print(struct NormalToVirtual*)' was added
   member 'int(** _vptr$NormalToVirtual)()' was added
 
 type 'struct VirtualToNormal' changed
   byte size changed from 8 to 1
-  method 'void print(struct VirtualToNormal*)' was removed
+  method 'int print(struct VirtualToNormal*)' was removed
   member 'int(** _vptr$VirtualToNormal)()' was removed
 
 exit code 4
diff --git a/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_plain b/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_plain
index 1aabae0..e61d2c7 100644
--- a/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_plain
+++ b/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_plain
@@ -10,20 +10,20 @@ variable symbol '_ZTS15NormalToVirtual' was added
 
 variable symbol '_ZTV15NormalToVirtual' was added
 
-function symbol 'void NormalToVirtual::print(struct NormalToVirtual*)' {_ZN15NormalToVirtual5printEv} changed
-  type 'void(struct NormalToVirtual*)' changed
+function symbol 'int NormalToVirtual::print(struct NormalToVirtual*)' {_ZN15NormalToVirtual5printEv} changed
+  type 'int(struct NormalToVirtual*)' changed
     parameter 1 type 'struct NormalToVirtual*' changed
       pointed-to type 'struct NormalToVirtual' changed
         byte size changed from 1 to 8
-        method 'void print(struct NormalToVirtual*)' was added
+        method 'int print(struct NormalToVirtual*)' was added
         member 'int(** _vptr$NormalToVirtual)()' was added
 
-function symbol 'void VirtualToNormal::print(struct VirtualToNormal*)' {_ZN15VirtualToNormal5printEv} changed
-  type 'void(struct VirtualToNormal*)' changed
+function symbol 'int VirtualToNormal::print(struct VirtualToNormal*)' {_ZN15VirtualToNormal5printEv} changed
+  type 'int(struct VirtualToNormal*)' changed
     parameter 1 type 'struct VirtualToNormal*' changed
       pointed-to type 'struct VirtualToNormal' changed
         byte size changed from 8 to 1
-        method 'void print(struct VirtualToNormal*)' was removed
+        method 'int print(struct VirtualToNormal*)' was removed
         member 'int(** _vptr$VirtualToNormal)()' was removed
 
 variable symbol 'struct NormalToVirtual normal_to_virtual' changed
diff --git a/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_small b/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_small
index d5757f7..4df3199 100644
--- a/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_small
+++ b/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_small
@@ -12,12 +12,12 @@ variable symbol '_ZTV15NormalToVirtual' was added
 
 type 'struct NormalToVirtual' changed
   byte size changed from 1 to 8
-  method 'void print(struct NormalToVirtual*)' was added
+  method 'int print(struct NormalToVirtual*)' was added
   member 'int(** _vptr$NormalToVirtual)()' was added
 
 type 'struct VirtualToNormal' changed
   byte size changed from 8 to 1
-  method 'void print(struct VirtualToNormal*)' was removed
+  method 'int print(struct VirtualToNormal*)' was removed
   member 'int(** _vptr$VirtualToNormal)()' was removed
 
 exit code 4
diff --git a/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_viz b/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_viz
index e315dce..0184d33 100644
--- a/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_viz
+++ b/test_cases/diff_tests/function/expected/virtual_vs_non_virtual_cc.o_o_viz
@@ -12,13 +12,13 @@ digraph "ABI diff" {
   "0" -> "5" [label=""]
   "6" [color=red, label="added(_ZTV15NormalToVirtual)"]
   "0" -> "6" [label=""]
-  "7" [label="'void NormalToVirtual::print(struct NormalToVirtual*)' {_ZN15NormalToVirtual5printEv}"]
-  "8" [label="'void(struct NormalToVirtual*)'"]
+  "7" [label="'int NormalToVirtual::print(struct NormalToVirtual*)' {_ZN15NormalToVirtual5printEv}"]
+  "8" [label="'int(struct NormalToVirtual*)'"]
   "9" [label="'struct NormalToVirtual*'"]
   "10" [color=red, shape=rectangle, label="'struct NormalToVirtual'"]
   "10" -> "10:0"
   "10:0" [color=red, label="byte size changed from 1 to 8"]
-  "11" [color=red, label="added(void print(struct NormalToVirtual*))"]
+  "11" [color=red, label="added(int print(struct NormalToVirtual*))"]
   "10" -> "11" [label=""]
   "12" [color=red, label="added(int(** _vptr$NormalToVirtual)())"]
   "10" -> "12" [label=""]
@@ -26,13 +26,13 @@ digraph "ABI diff" {
   "8" -> "9" [label="parameter 1"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
-  "13" [label="'void VirtualToNormal::print(struct VirtualToNormal*)' {_ZN15VirtualToNormal5printEv}"]
-  "14" [label="'void(struct VirtualToNormal*)'"]
+  "13" [label="'int VirtualToNormal::print(struct VirtualToNormal*)' {_ZN15VirtualToNormal5printEv}"]
+  "14" [label="'int(struct VirtualToNormal*)'"]
   "15" [label="'struct VirtualToNormal*'"]
   "16" [color=red, shape=rectangle, label="'struct VirtualToNormal'"]
   "16" -> "16:0"
   "16:0" [color=red, label="byte size changed from 8 to 1"]
-  "17" [color=red, label="removed(void print(struct VirtualToNormal*))"]
+  "17" [color=red, label="removed(int print(struct VirtualToNormal*))"]
   "16" -> "17" [label=""]
   "18" [color=red, label="removed(int(** _vptr$VirtualToNormal)())"]
   "16" -> "18" [label=""]
diff --git a/test_cases/diff_tests/function/virtual_vs_non_virtual.0.cc b/test_cases/diff_tests/function/virtual_vs_non_virtual.0.cc
index e244040..565eb66 100644
--- a/test_cases/diff_tests/function/virtual_vs_non_virtual.0.cc
+++ b/test_cases/diff_tests/function/virtual_vs_non_virtual.0.cc
@@ -1,11 +1,11 @@
-void tweak(int);
-
 struct VirtualToNormal {
-  virtual void print();
+  virtual int print();
 } virtual_to_normal;
-void VirtualToNormal::print() { tweak(0); }
+
+int VirtualToNormal::print() { return 0; }
 
 struct NormalToVirtual {
-  void print();
+  int print();
 } normal_to_virtual;
-void NormalToVirtual::print() { tweak(1); }
+
+int NormalToVirtual::print() { return 1; }
diff --git a/test_cases/diff_tests/function/virtual_vs_non_virtual.1.cc b/test_cases/diff_tests/function/virtual_vs_non_virtual.1.cc
index a89b6fe..f79a583 100644
--- a/test_cases/diff_tests/function/virtual_vs_non_virtual.1.cc
+++ b/test_cases/diff_tests/function/virtual_vs_non_virtual.1.cc
@@ -1,11 +1,11 @@
-void tweak(int);
-
 struct VirtualToNormal {
-  void print();
+  int print();
 } virtual_to_normal;
-void VirtualToNormal::print() { tweak(0); }
+
+int VirtualToNormal::print() { return 0; }
 
 struct NormalToVirtual {
-  virtual void print();
+  virtual int print();
 } normal_to_virtual;
-void NormalToVirtual::print() { tweak(1); }
+
+int NormalToVirtual::print() { return 1; }
diff --git a/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_flat b/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_flat
index 59e5a0e..27c752f 100644
--- a/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_flat
+++ b/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_flat
@@ -4,6 +4,8 @@ function symbol 'int s10(int struct S::*)' {_Z3s10M1Si} was added
 
 function symbol 'void pmz_fun()' {_Z7pmz_funv} was added
 
+function symbol 'void X::f(struct X*, int)' {_ZN1X1fEi} was added
+
 variable symbol 'char struct Y::* pmc' was added
 
 variable symbol 'int union U::* pmcu' was added
diff --git a/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_plain b/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_plain
index 59e5a0e..27c752f 100644
--- a/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_plain
+++ b/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_plain
@@ -4,6 +4,8 @@ function symbol 'int s10(int struct S::*)' {_Z3s10M1Si} was added
 
 function symbol 'void pmz_fun()' {_Z7pmz_funv} was added
 
+function symbol 'void X::f(struct X*, int)' {_ZN1X1fEi} was added
+
 variable symbol 'char struct Y::* pmc' was added
 
 variable symbol 'int union U::* pmcu' was added
diff --git a/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_small b/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_small
index 59e5a0e..27c752f 100644
--- a/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_small
+++ b/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_small
@@ -4,6 +4,8 @@ function symbol 'int s10(int struct S::*)' {_Z3s10M1Si} was added
 
 function symbol 'void pmz_fun()' {_Z7pmz_funv} was added
 
+function symbol 'void X::f(struct X*, int)' {_ZN1X1fEi} was added
+
 variable symbol 'char struct Y::* pmc' was added
 
 variable symbol 'int union U::* pmcu' was added
diff --git a/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_viz b/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_viz
index 292ca80..b1cbb30 100644
--- a/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_viz
+++ b/test_cases/diff_tests/member/expected/pointer_to_member_cc.o_o_viz
@@ -6,44 +6,46 @@ digraph "ABI diff" {
   "0" -> "2" [label=""]
   "3" [color=red, label="added(void pmz_fun() {_Z7pmz_funv})"]
   "0" -> "3" [label=""]
-  "4" [color=red, label="added(char struct Y::* pmc)"]
+  "4" [color=red, label="added(void X::f(struct X*, int) {_ZN1X1fEi})"]
   "0" -> "4" [label=""]
-  "5" [color=red, label="added(int union U::* pmcu)"]
+  "5" [color=red, label="added(char struct Y::* pmc)"]
   "0" -> "5" [label=""]
-  "6" [color=red, label="added(double struct X::* pmd)"]
+  "6" [color=red, label="added(int union U::* pmcu)"]
   "0" -> "6" [label=""]
-  "7" [color=red, label="added(void(struct X::* pmf)(struct X*, int))"]
+  "7" [color=red, label="added(double struct X::* pmd)"]
   "0" -> "7" [label=""]
-  "8" [color=red, label="added(int struct X::* pmi)"]
+  "8" [color=red, label="added(void(struct X::* pmf)(struct X*, int))"]
   "0" -> "8" [label=""]
-  "9" [color=red, label="added(int union U::* pmu)"]
+  "9" [color=red, label="added(int struct X::* pmi)"]
   "0" -> "9" [label=""]
-  "10" [color=red, label="added(int struct { int t; }::* pmy)"]
+  "10" [color=red, label="added(int union U::* pmu)"]
   "0" -> "10" [label=""]
-  "11" [color=red, label="added(int struct S::* s0)"]
+  "11" [color=red, label="added(int struct { int t; }::* pmy)"]
   "0" -> "11" [label=""]
-  "12" [color=red, label="added(int struct S::** s1)"]
+  "12" [color=red, label="added(int struct S::* s0)"]
   "0" -> "12" [label=""]
-  "13" [color=red, label="added(int struct S::*(* s3)())"]
+  "13" [color=red, label="added(int struct S::** s1)"]
   "0" -> "13" [label=""]
-  "14" [color=red, label="added(int struct S::* s4[7])"]
+  "14" [color=red, label="added(int struct S::*(* s3)())"]
   "0" -> "14" [label=""]
-  "15" [color=red, label="added(int* struct S::* s5)"]
+  "15" [color=red, label="added(int struct S::* s4[7])"]
   "0" -> "15" [label=""]
-  "16" [color=red, label="added(int(* struct S::* s6)())"]
+  "16" [color=red, label="added(int* struct S::* s5)"]
   "0" -> "16" [label=""]
-  "17" [color=red, label="added(int(struct S::* s7)(struct S*))"]
+  "17" [color=red, label="added(int(* struct S::* s6)())"]
   "0" -> "17" [label=""]
-  "18" [color=red, label="added(int(struct S::* s8)[7])"]
+  "18" [color=red, label="added(int(struct S::* s7)(struct S*))"]
   "0" -> "18" [label=""]
-  "19" [color=red, label="added(const int struct S::* volatile s9)"]
+  "19" [color=red, label="added(int(struct S::* s8)[7])"]
   "0" -> "19" [label=""]
-  "20" [label="'char struct A::* diff' -> 'int struct B::* diff'"]
-  "21" [label="'char struct A::*' -> 'int struct B::*'"]
-  "22" [color=red, label="'struct A' -> 'struct B'"]
-  "21" -> "22" [label="containing"]
-  "23" [color=red, label="'char' -> 'int'"]
-  "21" -> "23" [label=""]
-  "20" -> "21" [label=""]
+  "20" [color=red, label="added(const int struct S::* volatile s9)"]
   "0" -> "20" [label=""]
+  "21" [label="'char struct A::* diff' -> 'int struct B::* diff'"]
+  "22" [label="'char struct A::*' -> 'int struct B::*'"]
+  "23" [color=red, label="'struct A' -> 'struct B'"]
+  "22" -> "23" [label="containing"]
+  "24" [color=red, label="'char' -> 'int'"]
+  "22" -> "24" [label=""]
+  "21" -> "22" [label=""]
+  "0" -> "21" [label=""]
 }
diff --git a/test_cases/diff_tests/member/pointer_to_member.1.cc b/test_cases/diff_tests/member/pointer_to_member.1.cc
index 9779061..5034120 100644
--- a/test_cases/diff_tests/member/pointer_to_member.1.cc
+++ b/test_cases/diff_tests/member/pointer_to_member.1.cc
@@ -26,7 +26,7 @@ int s10(int S::*);
 int s10(int S::*) { return 0; }
 
 struct X {
-  void f(int);
+  void f(int) {}
   int a;
 };
 struct Y;
diff --git a/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_flat b/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_flat
index 57d3100..cec1b14 100644
--- a/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_flat
+++ b/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_flat
@@ -1,18 +1,18 @@
-function symbol 'void bar_1(const volatile struct foo*)' was removed
+function symbol 'int bar_1(const volatile struct foo*)' was removed
 
-function symbol 'void bar_2(struct foo*)' was added
+function symbol 'int bar_2(struct foo*)' was added
 
-function symbol changed from 'void bar(struct foo)' to 'void bar(const volatile struct foo*)'
-  type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+function symbol changed from 'int bar(struct foo)' to 'int bar(const volatile struct foo*)'
+  type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
     parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
-function symbol changed from 'void baz(void(*)(struct foo))' to 'void baz(void(* volatile const)(const volatile struct foo*))'
-  type changed from 'void(void(*)(struct foo))' to 'void(void(* volatile const)(const volatile struct foo*))'
-    parameter 1 type changed from 'void(*)(struct foo)' to 'void(* volatile const)(const volatile struct foo*)'
+function symbol changed from 'int baz(int(*)(struct foo))' to 'int baz(int(* volatile const)(const volatile struct foo*))'
+  type changed from 'int(int(*)(struct foo))' to 'int(int(* volatile const)(const volatile struct foo*))'
+    parameter 1 type changed from 'int(*)(struct foo)' to 'int(* volatile const)(const volatile struct foo*)'
       qualifier const added
       qualifier volatile added
-      underlying type changed from 'void(*)(struct foo)' to 'void(*)(const volatile struct foo*)'
-        pointed-to type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+      underlying type changed from 'int(*)(struct foo)' to 'int(*)(const volatile struct foo*)'
+        pointed-to type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
           parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
 exit code 4
diff --git a/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_plain b/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_plain
index 57d3100..cec1b14 100644
--- a/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_plain
+++ b/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_plain
@@ -1,18 +1,18 @@
-function symbol 'void bar_1(const volatile struct foo*)' was removed
+function symbol 'int bar_1(const volatile struct foo*)' was removed
 
-function symbol 'void bar_2(struct foo*)' was added
+function symbol 'int bar_2(struct foo*)' was added
 
-function symbol changed from 'void bar(struct foo)' to 'void bar(const volatile struct foo*)'
-  type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+function symbol changed from 'int bar(struct foo)' to 'int bar(const volatile struct foo*)'
+  type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
     parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
-function symbol changed from 'void baz(void(*)(struct foo))' to 'void baz(void(* volatile const)(const volatile struct foo*))'
-  type changed from 'void(void(*)(struct foo))' to 'void(void(* volatile const)(const volatile struct foo*))'
-    parameter 1 type changed from 'void(*)(struct foo)' to 'void(* volatile const)(const volatile struct foo*)'
+function symbol changed from 'int baz(int(*)(struct foo))' to 'int baz(int(* volatile const)(const volatile struct foo*))'
+  type changed from 'int(int(*)(struct foo))' to 'int(int(* volatile const)(const volatile struct foo*))'
+    parameter 1 type changed from 'int(*)(struct foo)' to 'int(* volatile const)(const volatile struct foo*)'
       qualifier const added
       qualifier volatile added
-      underlying type changed from 'void(*)(struct foo)' to 'void(*)(const volatile struct foo*)'
-        pointed-to type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+      underlying type changed from 'int(*)(struct foo)' to 'int(*)(const volatile struct foo*)'
+        pointed-to type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
           parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
 exit code 4
diff --git a/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_small b/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_small
index 57d3100..cec1b14 100644
--- a/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_small
+++ b/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_small
@@ -1,18 +1,18 @@
-function symbol 'void bar_1(const volatile struct foo*)' was removed
+function symbol 'int bar_1(const volatile struct foo*)' was removed
 
-function symbol 'void bar_2(struct foo*)' was added
+function symbol 'int bar_2(struct foo*)' was added
 
-function symbol changed from 'void bar(struct foo)' to 'void bar(const volatile struct foo*)'
-  type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+function symbol changed from 'int bar(struct foo)' to 'int bar(const volatile struct foo*)'
+  type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
     parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
-function symbol changed from 'void baz(void(*)(struct foo))' to 'void baz(void(* volatile const)(const volatile struct foo*))'
-  type changed from 'void(void(*)(struct foo))' to 'void(void(* volatile const)(const volatile struct foo*))'
-    parameter 1 type changed from 'void(*)(struct foo)' to 'void(* volatile const)(const volatile struct foo*)'
+function symbol changed from 'int baz(int(*)(struct foo))' to 'int baz(int(* volatile const)(const volatile struct foo*))'
+  type changed from 'int(int(*)(struct foo))' to 'int(int(* volatile const)(const volatile struct foo*))'
+    parameter 1 type changed from 'int(*)(struct foo)' to 'int(* volatile const)(const volatile struct foo*)'
       qualifier const added
       qualifier volatile added
-      underlying type changed from 'void(*)(struct foo)' to 'void(*)(const volatile struct foo*)'
-        pointed-to type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+      underlying type changed from 'int(*)(struct foo)' to 'int(*)(const volatile struct foo*)'
+        pointed-to type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
           parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
 exit code 4
diff --git a/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_viz b/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_viz
index ac7228e..96578bf 100644
--- a/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_viz
+++ b/test_cases/diff_tests/qualified/expected/useless_c.btf_btf_viz
@@ -1,24 +1,24 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [color=red, label="removed(void bar_1(const volatile struct foo*))"]
+  "1" [color=red, label="removed(int bar_1(const volatile struct foo*))"]
   "0" -> "1" [label=""]
-  "2" [color=red, label="added(void bar_2(struct foo*))"]
+  "2" [color=red, label="added(int bar_2(struct foo*))"]
   "0" -> "2" [label=""]
-  "3" [label="'void bar(struct foo)' -> 'void bar(const volatile struct foo*)'"]
-  "4" [label="'void(struct foo)' -> 'void(const volatile struct foo*)'"]
+  "3" [label="'int bar(struct foo)' -> 'int bar(const volatile struct foo*)'"]
+  "4" [label="'int(struct foo)' -> 'int(const volatile struct foo*)'"]
   "5" [color=red, label="'struct foo' -> 'const volatile struct foo*'"]
   "4" -> "5" [label="parameter 1"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
-  "6" [label="'void baz(void(*)(struct foo))' -> 'void baz(void(* volatile const)(const volatile struct foo*))'"]
-  "7" [label="'void(void(*)(struct foo))' -> 'void(void(* volatile const)(const volatile struct foo*))'"]
-  "8" [color=red, label="'void(*)(struct foo)' -> 'void(* volatile const)(const volatile struct foo*)'"]
+  "6" [label="'int baz(int(*)(struct foo))' -> 'int baz(int(* volatile const)(const volatile struct foo*))'"]
+  "7" [label="'int(int(*)(struct foo))' -> 'int(int(* volatile const)(const volatile struct foo*))'"]
+  "8" [color=red, label="'int(*)(struct foo)' -> 'int(* volatile const)(const volatile struct foo*)'"]
   "8" -> "8:0"
   "8:0" [color=red, label="qualifier const added"]
   "8" -> "8:1"
   "8:1" [color=red, label="qualifier volatile added"]
-  "9" [label="'void(*)(struct foo)' -> 'void(*)(const volatile struct foo*)'"]
-  "10" [label="'void(struct foo)' -> 'void(const volatile struct foo*)'"]
+  "9" [label="'int(*)(struct foo)' -> 'int(*)(const volatile struct foo*)'"]
+  "10" [label="'int(struct foo)' -> 'int(const volatile struct foo*)'"]
   "10" -> "5" [label="parameter 1"]
   "9" -> "10" [label="pointed-to"]
   "8" -> "9" [label="underlying"]
diff --git a/test_cases/diff_tests/qualified/expected/useless_c.o_o_flat b/test_cases/diff_tests/qualified/expected/useless_c.o_o_flat
index a5c95a6..acfb82a 100644
--- a/test_cases/diff_tests/qualified/expected/useless_c.o_o_flat
+++ b/test_cases/diff_tests/qualified/expected/useless_c.o_o_flat
@@ -1,23 +1,23 @@
-function symbol 'void bar_1(const volatile struct foo*)' was removed
+function symbol 'int bar_1(const volatile struct foo*)' was removed
 
-function symbol 'void bar_2(struct foo*)' was added
+function symbol 'int bar_2(struct foo*)' was added
 
-function symbol changed from 'void bar(struct foo)' to 'void bar(const volatile struct foo*)'
-  type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+function symbol changed from 'int bar(struct foo)' to 'int bar(const volatile struct foo*)'
+  type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
     parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
-function symbol changed from 'void baz(void(*)(struct foo))' to 'void baz(void(*)(const volatile struct foo*))'
-  type changed from 'void(void(*)(struct foo))' to 'void(void(*)(const volatile struct foo*))'
-    parameter 1 type changed from 'void(*)(struct foo)' to 'void(*)(const volatile struct foo*)'
-      pointed-to type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+function symbol changed from 'int baz(int(*)(struct foo))' to 'int baz(int(*)(const volatile struct foo*))'
+  type changed from 'int(int(*)(struct foo))' to 'int(int(*)(const volatile struct foo*))'
+    parameter 1 type changed from 'int(*)(struct foo)' to 'int(*)(const volatile struct foo*)'
+      pointed-to type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
         parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
-variable symbol changed from 'void(* quux)(struct foo)' to 'void(* volatile const quux)(const volatile struct foo*)'
-  type changed from 'void(*)(struct foo)' to 'void(* volatile const)(const volatile struct foo*)'
+variable symbol changed from 'int(* quux)(struct foo)' to 'int(* volatile const quux)(const volatile struct foo*)'
+  type changed from 'int(*)(struct foo)' to 'int(* volatile const)(const volatile struct foo*)'
     qualifier const added
     qualifier volatile added
-    underlying type changed from 'void(*)(struct foo)' to 'void(*)(const volatile struct foo*)'
-      pointed-to type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+    underlying type changed from 'int(*)(struct foo)' to 'int(*)(const volatile struct foo*)'
+      pointed-to type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
         parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
 exit code 4
diff --git a/test_cases/diff_tests/qualified/expected/useless_c.o_o_plain b/test_cases/diff_tests/qualified/expected/useless_c.o_o_plain
index a5c95a6..acfb82a 100644
--- a/test_cases/diff_tests/qualified/expected/useless_c.o_o_plain
+++ b/test_cases/diff_tests/qualified/expected/useless_c.o_o_plain
@@ -1,23 +1,23 @@
-function symbol 'void bar_1(const volatile struct foo*)' was removed
+function symbol 'int bar_1(const volatile struct foo*)' was removed
 
-function symbol 'void bar_2(struct foo*)' was added
+function symbol 'int bar_2(struct foo*)' was added
 
-function symbol changed from 'void bar(struct foo)' to 'void bar(const volatile struct foo*)'
-  type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+function symbol changed from 'int bar(struct foo)' to 'int bar(const volatile struct foo*)'
+  type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
     parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
-function symbol changed from 'void baz(void(*)(struct foo))' to 'void baz(void(*)(const volatile struct foo*))'
-  type changed from 'void(void(*)(struct foo))' to 'void(void(*)(const volatile struct foo*))'
-    parameter 1 type changed from 'void(*)(struct foo)' to 'void(*)(const volatile struct foo*)'
-      pointed-to type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+function symbol changed from 'int baz(int(*)(struct foo))' to 'int baz(int(*)(const volatile struct foo*))'
+  type changed from 'int(int(*)(struct foo))' to 'int(int(*)(const volatile struct foo*))'
+    parameter 1 type changed from 'int(*)(struct foo)' to 'int(*)(const volatile struct foo*)'
+      pointed-to type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
         parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
-variable symbol changed from 'void(* quux)(struct foo)' to 'void(* volatile const quux)(const volatile struct foo*)'
-  type changed from 'void(*)(struct foo)' to 'void(* volatile const)(const volatile struct foo*)'
+variable symbol changed from 'int(* quux)(struct foo)' to 'int(* volatile const quux)(const volatile struct foo*)'
+  type changed from 'int(*)(struct foo)' to 'int(* volatile const)(const volatile struct foo*)'
     qualifier const added
     qualifier volatile added
-    underlying type changed from 'void(*)(struct foo)' to 'void(*)(const volatile struct foo*)'
-      pointed-to type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+    underlying type changed from 'int(*)(struct foo)' to 'int(*)(const volatile struct foo*)'
+      pointed-to type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
         parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
 exit code 4
diff --git a/test_cases/diff_tests/qualified/expected/useless_c.o_o_small b/test_cases/diff_tests/qualified/expected/useless_c.o_o_small
index a5c95a6..acfb82a 100644
--- a/test_cases/diff_tests/qualified/expected/useless_c.o_o_small
+++ b/test_cases/diff_tests/qualified/expected/useless_c.o_o_small
@@ -1,23 +1,23 @@
-function symbol 'void bar_1(const volatile struct foo*)' was removed
+function symbol 'int bar_1(const volatile struct foo*)' was removed
 
-function symbol 'void bar_2(struct foo*)' was added
+function symbol 'int bar_2(struct foo*)' was added
 
-function symbol changed from 'void bar(struct foo)' to 'void bar(const volatile struct foo*)'
-  type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+function symbol changed from 'int bar(struct foo)' to 'int bar(const volatile struct foo*)'
+  type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
     parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
-function symbol changed from 'void baz(void(*)(struct foo))' to 'void baz(void(*)(const volatile struct foo*))'
-  type changed from 'void(void(*)(struct foo))' to 'void(void(*)(const volatile struct foo*))'
-    parameter 1 type changed from 'void(*)(struct foo)' to 'void(*)(const volatile struct foo*)'
-      pointed-to type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+function symbol changed from 'int baz(int(*)(struct foo))' to 'int baz(int(*)(const volatile struct foo*))'
+  type changed from 'int(int(*)(struct foo))' to 'int(int(*)(const volatile struct foo*))'
+    parameter 1 type changed from 'int(*)(struct foo)' to 'int(*)(const volatile struct foo*)'
+      pointed-to type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
         parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
-variable symbol changed from 'void(* quux)(struct foo)' to 'void(* volatile const quux)(const volatile struct foo*)'
-  type changed from 'void(*)(struct foo)' to 'void(* volatile const)(const volatile struct foo*)'
+variable symbol changed from 'int(* quux)(struct foo)' to 'int(* volatile const quux)(const volatile struct foo*)'
+  type changed from 'int(*)(struct foo)' to 'int(* volatile const)(const volatile struct foo*)'
     qualifier const added
     qualifier volatile added
-    underlying type changed from 'void(*)(struct foo)' to 'void(*)(const volatile struct foo*)'
-      pointed-to type changed from 'void(struct foo)' to 'void(const volatile struct foo*)'
+    underlying type changed from 'int(*)(struct foo)' to 'int(*)(const volatile struct foo*)'
+      pointed-to type changed from 'int(struct foo)' to 'int(const volatile struct foo*)'
         parameter 1 type changed from 'struct foo' to 'const volatile struct foo*'
 
 exit code 4
diff --git a/test_cases/diff_tests/qualified/expected/useless_c.o_o_viz b/test_cases/diff_tests/qualified/expected/useless_c.o_o_viz
index e8cf8c8..9b8691d 100644
--- a/test_cases/diff_tests/qualified/expected/useless_c.o_o_viz
+++ b/test_cases/diff_tests/qualified/expected/useless_c.o_o_viz
@@ -1,26 +1,26 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [color=red, label="removed(void bar_1(const volatile struct foo*))"]
+  "1" [color=red, label="removed(int bar_1(const volatile struct foo*))"]
   "0" -> "1" [label=""]
-  "2" [color=red, label="added(void bar_2(struct foo*))"]
+  "2" [color=red, label="added(int bar_2(struct foo*))"]
   "0" -> "2" [label=""]
-  "3" [label="'void bar(struct foo)' -> 'void bar(const volatile struct foo*)'"]
-  "4" [label="'void(struct foo)' -> 'void(const volatile struct foo*)'"]
+  "3" [label="'int bar(struct foo)' -> 'int bar(const volatile struct foo*)'"]
+  "4" [label="'int(struct foo)' -> 'int(const volatile struct foo*)'"]
   "5" [color=red, label="'struct foo' -> 'const volatile struct foo*'"]
   "4" -> "5" [label="parameter 1"]
   "3" -> "4" [label=""]
   "0" -> "3" [label=""]
-  "6" [label="'void baz(void(*)(struct foo))' -> 'void baz(void(*)(const volatile struct foo*))'"]
-  "7" [label="'void(void(*)(struct foo))' -> 'void(void(*)(const volatile struct foo*))'"]
-  "8" [label="'void(*)(struct foo)' -> 'void(*)(const volatile struct foo*)'"]
-  "9" [label="'void(struct foo)' -> 'void(const volatile struct foo*)'"]
+  "6" [label="'int baz(int(*)(struct foo))' -> 'int baz(int(*)(const volatile struct foo*))'"]
+  "7" [label="'int(int(*)(struct foo))' -> 'int(int(*)(const volatile struct foo*))'"]
+  "8" [label="'int(*)(struct foo)' -> 'int(*)(const volatile struct foo*)'"]
+  "9" [label="'int(struct foo)' -> 'int(const volatile struct foo*)'"]
   "9" -> "5" [label="parameter 1"]
   "8" -> "9" [label="pointed-to"]
   "7" -> "8" [label="parameter 1"]
   "6" -> "7" [label=""]
   "0" -> "6" [label=""]
-  "10" [label="'void(* quux)(struct foo)' -> 'void(* volatile const quux)(const volatile struct foo*)'"]
-  "11" [color=red, label="'void(*)(struct foo)' -> 'void(* volatile const)(const volatile struct foo*)'"]
+  "10" [label="'int(* quux)(struct foo)' -> 'int(* volatile const quux)(const volatile struct foo*)'"]
+  "11" [color=red, label="'int(*)(struct foo)' -> 'int(* volatile const)(const volatile struct foo*)'"]
   "11" -> "11:0"
   "11:0" [color=red, label="qualifier const added"]
   "11" -> "11:1"
diff --git a/test_cases/diff_tests/qualified/useless.0.c b/test_cases/diff_tests/qualified/useless.0.c
index 5207883..6450a7a 100644
--- a/test_cases/diff_tests/qualified/useless.0.c
+++ b/test_cases/diff_tests/qualified/useless.0.c
@@ -1,21 +1,19 @@
-void tweak(int);
-
 struct foo {
 };
 
-void bar(struct foo y) {
+int bar(struct foo y) {
   (void) y;
-  tweak(0);
+  return 0;
 }
 
-void bar_1(const volatile struct foo* y) {
+int bar_1(const volatile struct foo* y) {
   (void) y;
-  tweak(1);
+  return 1;
 }
 
-void baz(void(*y)(struct foo)) {
+int baz(int (*y)(struct foo)) {
   (void) y;
-  tweak(2);
+  return 2;
 }
 
-void(*quux)(struct foo) = &bar;
+int (*quux)(struct foo) = &bar;
diff --git a/test_cases/diff_tests/qualified/useless.1.c b/test_cases/diff_tests/qualified/useless.1.c
index a077d5b..53fdc50 100644
--- a/test_cases/diff_tests/qualified/useless.1.c
+++ b/test_cases/diff_tests/qualified/useless.1.c
@@ -1,21 +1,19 @@
-void tweak(int);
-
 struct foo {
 };
 
-void bar_2(struct foo* y) {
+int bar_2(struct foo* y) {
   (void) y;
-  tweak(0);
+  return 0;
 }
 
-void bar(const volatile struct foo* y) {
+int bar(const volatile struct foo* y) {
   (void) y;
-  tweak(1);
+  return 1;
 }
 
-void baz(void(*const volatile y)(const volatile struct foo*)) {
+int baz(int (*const volatile y)(const volatile struct foo*)) {
   (void) y;
-  tweak(2);
+  return 2;
 }
 
-void(*const volatile quux)(const volatile struct foo*) = &bar;
+int (*const volatile quux)(const volatile struct foo*) = &bar;
diff --git a/test_cases/diff_tests/struct/expected/nested_c.btf_btf_flat b/test_cases/diff_tests/struct/expected/nested_c.btf_btf_flat
index 7606cd0..1fd0cff 100644
--- a/test_cases/diff_tests/struct/expected/nested_c.btf_btf_flat
+++ b/test_cases/diff_tests/struct/expected/nested_c.btf_btf_flat
@@ -1,18 +1,18 @@
-function symbol 'void register_ops6(struct containing)' changed
-  type 'void(struct containing)' changed
+function symbol 'int register_ops6(struct containing)' changed
+  type 'int(struct containing)' changed
     parameter 1 type 'struct containing' changed
 
-function symbol 'void register_ops7(struct containing*)' changed
-  type 'void(struct containing*)' changed
+function symbol 'int register_ops7(struct containing*)' changed
+  type 'int(struct containing*)' changed
     parameter 1 type 'struct containing*' changed
       pointed-to type 'struct containing' changed
 
-function symbol 'void register_ops8(struct referring)' changed
-  type 'void(struct referring)' changed
+function symbol 'int register_ops8(struct referring)' changed
+  type 'int(struct referring)' changed
     parameter 1 type 'struct referring' changed
 
-function symbol 'void register_ops9(struct referring*)' changed
-  type 'void(struct referring*)' changed
+function symbol 'int register_ops9(struct referring*)' changed
+  type 'int(struct referring*)' changed
     parameter 1 type 'struct referring*' changed
       pointed-to type 'struct referring' changed
 
diff --git a/test_cases/diff_tests/struct/expected/nested_c.btf_btf_plain b/test_cases/diff_tests/struct/expected/nested_c.btf_btf_plain
index a057172..d783357 100644
--- a/test_cases/diff_tests/struct/expected/nested_c.btf_btf_plain
+++ b/test_cases/diff_tests/struct/expected/nested_c.btf_btf_plain
@@ -1,5 +1,5 @@
-function symbol 'void register_ops6(struct containing)' changed
-  type 'void(struct containing)' changed
+function symbol 'int register_ops6(struct containing)' changed
+  type 'int(struct containing)' changed
     parameter 1 type 'struct containing' changed
       byte size changed from 4 to 8
       member 'struct nested inner' changed
@@ -8,22 +8,22 @@ function symbol 'void register_ops6(struct containing)' changed
           member changed from 'int x' to 'long x'
             type changed from 'int' to 'long'
 
-function symbol 'void register_ops7(struct containing*)' changed
-  type 'void(struct containing*)' changed
+function symbol 'int register_ops7(struct containing*)' changed
+  type 'int(struct containing*)' changed
     parameter 1 type 'struct containing*' changed
       pointed-to type 'struct containing' changed
         (already reported)
 
-function symbol 'void register_ops8(struct referring)' changed
-  type 'void(struct referring)' changed
+function symbol 'int register_ops8(struct referring)' changed
+  type 'int(struct referring)' changed
     parameter 1 type 'struct referring' changed
       member 'struct nested* inner' changed
         type 'struct nested*' changed
           pointed-to type 'struct nested' changed
             (already reported)
 
-function symbol 'void register_ops9(struct referring*)' changed
-  type 'void(struct referring*)' changed
+function symbol 'int register_ops9(struct referring*)' changed
+  type 'int(struct referring*)' changed
     parameter 1 type 'struct referring*' changed
       pointed-to type 'struct referring' changed
         (already reported)
diff --git a/test_cases/diff_tests/struct/expected/nested_c.btf_btf_viz b/test_cases/diff_tests/struct/expected/nested_c.btf_btf_viz
index 6e18086..54aded6 100644
--- a/test_cases/diff_tests/struct/expected/nested_c.btf_btf_viz
+++ b/test_cases/diff_tests/struct/expected/nested_c.btf_btf_viz
@@ -1,7 +1,7 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'void register_ops6(struct containing)'"]
-  "2" [label="'void(struct containing)'"]
+  "1" [label="'int register_ops6(struct containing)'"]
+  "2" [label="'int(struct containing)'"]
   "3" [color=red, shape=rectangle, label="'struct containing'"]
   "3" -> "3:0"
   "3:0" [color=red, label="byte size changed from 4 to 8"]
@@ -18,15 +18,15 @@ digraph "ABI diff" {
   "2" -> "3" [label="parameter 1"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "8" [label="'void register_ops7(struct containing*)'"]
-  "9" [label="'void(struct containing*)'"]
+  "8" [label="'int register_ops7(struct containing*)'"]
+  "9" [label="'int(struct containing*)'"]
   "10" [label="'struct containing*'"]
   "10" -> "3" [label="pointed-to"]
   "9" -> "10" [label="parameter 1"]
   "8" -> "9" [label=""]
   "0" -> "8" [label=""]
-  "11" [label="'void register_ops8(struct referring)'"]
-  "12" [label="'void(struct referring)'"]
+  "11" [label="'int register_ops8(struct referring)'"]
+  "12" [label="'int(struct referring)'"]
   "13" [shape=rectangle, label="'struct referring'"]
   "14" [label="'struct nested* inner'"]
   "15" [label="'struct nested*'"]
@@ -36,8 +36,8 @@ digraph "ABI diff" {
   "12" -> "13" [label="parameter 1"]
   "11" -> "12" [label=""]
   "0" -> "11" [label=""]
-  "16" [label="'void register_ops9(struct referring*)'"]
-  "17" [label="'void(struct referring*)'"]
+  "16" [label="'int register_ops9(struct referring*)'"]
+  "17" [label="'int(struct referring*)'"]
   "18" [label="'struct referring*'"]
   "18" -> "13" [label="pointed-to"]
   "17" -> "18" [label="parameter 1"]
diff --git a/test_cases/diff_tests/struct/expected/nested_c.o_o_flat b/test_cases/diff_tests/struct/expected/nested_c.o_o_flat
index 7606cd0..1fd0cff 100644
--- a/test_cases/diff_tests/struct/expected/nested_c.o_o_flat
+++ b/test_cases/diff_tests/struct/expected/nested_c.o_o_flat
@@ -1,18 +1,18 @@
-function symbol 'void register_ops6(struct containing)' changed
-  type 'void(struct containing)' changed
+function symbol 'int register_ops6(struct containing)' changed
+  type 'int(struct containing)' changed
     parameter 1 type 'struct containing' changed
 
-function symbol 'void register_ops7(struct containing*)' changed
-  type 'void(struct containing*)' changed
+function symbol 'int register_ops7(struct containing*)' changed
+  type 'int(struct containing*)' changed
     parameter 1 type 'struct containing*' changed
       pointed-to type 'struct containing' changed
 
-function symbol 'void register_ops8(struct referring)' changed
-  type 'void(struct referring)' changed
+function symbol 'int register_ops8(struct referring)' changed
+  type 'int(struct referring)' changed
     parameter 1 type 'struct referring' changed
 
-function symbol 'void register_ops9(struct referring*)' changed
-  type 'void(struct referring*)' changed
+function symbol 'int register_ops9(struct referring*)' changed
+  type 'int(struct referring*)' changed
     parameter 1 type 'struct referring*' changed
       pointed-to type 'struct referring' changed
 
diff --git a/test_cases/diff_tests/struct/expected/nested_c.o_o_plain b/test_cases/diff_tests/struct/expected/nested_c.o_o_plain
index a057172..d783357 100644
--- a/test_cases/diff_tests/struct/expected/nested_c.o_o_plain
+++ b/test_cases/diff_tests/struct/expected/nested_c.o_o_plain
@@ -1,5 +1,5 @@
-function symbol 'void register_ops6(struct containing)' changed
-  type 'void(struct containing)' changed
+function symbol 'int register_ops6(struct containing)' changed
+  type 'int(struct containing)' changed
     parameter 1 type 'struct containing' changed
       byte size changed from 4 to 8
       member 'struct nested inner' changed
@@ -8,22 +8,22 @@ function symbol 'void register_ops6(struct containing)' changed
           member changed from 'int x' to 'long x'
             type changed from 'int' to 'long'
 
-function symbol 'void register_ops7(struct containing*)' changed
-  type 'void(struct containing*)' changed
+function symbol 'int register_ops7(struct containing*)' changed
+  type 'int(struct containing*)' changed
     parameter 1 type 'struct containing*' changed
       pointed-to type 'struct containing' changed
         (already reported)
 
-function symbol 'void register_ops8(struct referring)' changed
-  type 'void(struct referring)' changed
+function symbol 'int register_ops8(struct referring)' changed
+  type 'int(struct referring)' changed
     parameter 1 type 'struct referring' changed
       member 'struct nested* inner' changed
         type 'struct nested*' changed
           pointed-to type 'struct nested' changed
             (already reported)
 
-function symbol 'void register_ops9(struct referring*)' changed
-  type 'void(struct referring*)' changed
+function symbol 'int register_ops9(struct referring*)' changed
+  type 'int(struct referring*)' changed
     parameter 1 type 'struct referring*' changed
       pointed-to type 'struct referring' changed
         (already reported)
diff --git a/test_cases/diff_tests/struct/expected/nested_c.o_o_viz b/test_cases/diff_tests/struct/expected/nested_c.o_o_viz
index 6e18086..54aded6 100644
--- a/test_cases/diff_tests/struct/expected/nested_c.o_o_viz
+++ b/test_cases/diff_tests/struct/expected/nested_c.o_o_viz
@@ -1,7 +1,7 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'void register_ops6(struct containing)'"]
-  "2" [label="'void(struct containing)'"]
+  "1" [label="'int register_ops6(struct containing)'"]
+  "2" [label="'int(struct containing)'"]
   "3" [color=red, shape=rectangle, label="'struct containing'"]
   "3" -> "3:0"
   "3:0" [color=red, label="byte size changed from 4 to 8"]
@@ -18,15 +18,15 @@ digraph "ABI diff" {
   "2" -> "3" [label="parameter 1"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "8" [label="'void register_ops7(struct containing*)'"]
-  "9" [label="'void(struct containing*)'"]
+  "8" [label="'int register_ops7(struct containing*)'"]
+  "9" [label="'int(struct containing*)'"]
   "10" [label="'struct containing*'"]
   "10" -> "3" [label="pointed-to"]
   "9" -> "10" [label="parameter 1"]
   "8" -> "9" [label=""]
   "0" -> "8" [label=""]
-  "11" [label="'void register_ops8(struct referring)'"]
-  "12" [label="'void(struct referring)'"]
+  "11" [label="'int register_ops8(struct referring)'"]
+  "12" [label="'int(struct referring)'"]
   "13" [shape=rectangle, label="'struct referring'"]
   "14" [label="'struct nested* inner'"]
   "15" [label="'struct nested*'"]
@@ -36,8 +36,8 @@ digraph "ABI diff" {
   "12" -> "13" [label="parameter 1"]
   "11" -> "12" [label=""]
   "0" -> "11" [label=""]
-  "16" [label="'void register_ops9(struct referring*)'"]
-  "17" [label="'void(struct referring*)'"]
+  "16" [label="'int register_ops9(struct referring*)'"]
+  "17" [label="'int(struct referring*)'"]
   "18" [label="'struct referring*'"]
   "18" -> "13" [label="pointed-to"]
   "17" -> "18" [label="parameter 1"]
diff --git a/test_cases/diff_tests/struct/expected/nested_cc.o_o_flat b/test_cases/diff_tests/struct/expected/nested_cc.o_o_flat
index b936e6d..6719855 100644
--- a/test_cases/diff_tests/struct/expected/nested_cc.o_o_flat
+++ b/test_cases/diff_tests/struct/expected/nested_cc.o_o_flat
@@ -1,18 +1,18 @@
-function symbol 'void register_ops6(struct containing)' {_Z13register_ops610containing} changed
-  type 'void(struct containing)' changed
+function symbol 'int register_ops6(struct containing)' {_Z13register_ops610containing} changed
+  type 'int(struct containing)' changed
     parameter 1 type 'struct containing' changed
 
-function symbol 'void register_ops7(struct containing*)' {_Z13register_ops7P10containing} changed
-  type 'void(struct containing*)' changed
+function symbol 'int register_ops7(struct containing*)' {_Z13register_ops7P10containing} changed
+  type 'int(struct containing*)' changed
     parameter 1 type 'struct containing*' changed
       pointed-to type 'struct containing' changed
 
-function symbol 'void register_ops8(struct referring)' {_Z13register_ops89referring} changed
-  type 'void(struct referring)' changed
+function symbol 'int register_ops8(struct referring)' {_Z13register_ops89referring} changed
+  type 'int(struct referring)' changed
     parameter 1 type 'struct referring' changed
 
-function symbol 'void register_ops9(struct referring*)' {_Z13register_ops9P9referring} changed
-  type 'void(struct referring*)' changed
+function symbol 'int register_ops9(struct referring*)' {_Z13register_ops9P9referring} changed
+  type 'int(struct referring*)' changed
     parameter 1 type 'struct referring*' changed
       pointed-to type 'struct referring' changed
 
diff --git a/test_cases/diff_tests/struct/expected/nested_cc.o_o_plain b/test_cases/diff_tests/struct/expected/nested_cc.o_o_plain
index 20bd034..46a7993 100644
--- a/test_cases/diff_tests/struct/expected/nested_cc.o_o_plain
+++ b/test_cases/diff_tests/struct/expected/nested_cc.o_o_plain
@@ -1,5 +1,5 @@
-function symbol 'void register_ops6(struct containing)' {_Z13register_ops610containing} changed
-  type 'void(struct containing)' changed
+function symbol 'int register_ops6(struct containing)' {_Z13register_ops610containing} changed
+  type 'int(struct containing)' changed
     parameter 1 type 'struct containing' changed
       byte size changed from 4 to 8
       member 'struct nested inner' changed
@@ -8,22 +8,22 @@ function symbol 'void register_ops6(struct containing)' {_Z13register_ops610cont
           member changed from 'int x' to 'long x'
             type changed from 'int' to 'long'
 
-function symbol 'void register_ops7(struct containing*)' {_Z13register_ops7P10containing} changed
-  type 'void(struct containing*)' changed
+function symbol 'int register_ops7(struct containing*)' {_Z13register_ops7P10containing} changed
+  type 'int(struct containing*)' changed
     parameter 1 type 'struct containing*' changed
       pointed-to type 'struct containing' changed
         (already reported)
 
-function symbol 'void register_ops8(struct referring)' {_Z13register_ops89referring} changed
-  type 'void(struct referring)' changed
+function symbol 'int register_ops8(struct referring)' {_Z13register_ops89referring} changed
+  type 'int(struct referring)' changed
     parameter 1 type 'struct referring' changed
       member 'struct nested* inner' changed
         type 'struct nested*' changed
           pointed-to type 'struct nested' changed
             (already reported)
 
-function symbol 'void register_ops9(struct referring*)' {_Z13register_ops9P9referring} changed
-  type 'void(struct referring*)' changed
+function symbol 'int register_ops9(struct referring*)' {_Z13register_ops9P9referring} changed
+  type 'int(struct referring*)' changed
     parameter 1 type 'struct referring*' changed
       pointed-to type 'struct referring' changed
         (already reported)
diff --git a/test_cases/diff_tests/struct/expected/nested_cc.o_o_viz b/test_cases/diff_tests/struct/expected/nested_cc.o_o_viz
index 1b76e07..9e5aaad 100644
--- a/test_cases/diff_tests/struct/expected/nested_cc.o_o_viz
+++ b/test_cases/diff_tests/struct/expected/nested_cc.o_o_viz
@@ -1,7 +1,7 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'void register_ops6(struct containing)' {_Z13register_ops610containing}"]
-  "2" [label="'void(struct containing)'"]
+  "1" [label="'int register_ops6(struct containing)' {_Z13register_ops610containing}"]
+  "2" [label="'int(struct containing)'"]
   "3" [color=red, shape=rectangle, label="'struct containing'"]
   "3" -> "3:0"
   "3:0" [color=red, label="byte size changed from 4 to 8"]
@@ -18,15 +18,15 @@ digraph "ABI diff" {
   "2" -> "3" [label="parameter 1"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "8" [label="'void register_ops7(struct containing*)' {_Z13register_ops7P10containing}"]
-  "9" [label="'void(struct containing*)'"]
+  "8" [label="'int register_ops7(struct containing*)' {_Z13register_ops7P10containing}"]
+  "9" [label="'int(struct containing*)'"]
   "10" [label="'struct containing*'"]
   "10" -> "3" [label="pointed-to"]
   "9" -> "10" [label="parameter 1"]
   "8" -> "9" [label=""]
   "0" -> "8" [label=""]
-  "11" [label="'void register_ops8(struct referring)' {_Z13register_ops89referring}"]
-  "12" [label="'void(struct referring)'"]
+  "11" [label="'int register_ops8(struct referring)' {_Z13register_ops89referring}"]
+  "12" [label="'int(struct referring)'"]
   "13" [shape=rectangle, label="'struct referring'"]
   "14" [label="'struct nested* inner'"]
   "15" [label="'struct nested*'"]
@@ -36,8 +36,8 @@ digraph "ABI diff" {
   "12" -> "13" [label="parameter 1"]
   "11" -> "12" [label=""]
   "0" -> "11" [label=""]
-  "16" [label="'void register_ops9(struct referring*)' {_Z13register_ops9P9referring}"]
-  "17" [label="'void(struct referring*)'"]
+  "16" [label="'int register_ops9(struct referring*)' {_Z13register_ops9P9referring}"]
+  "17" [label="'int(struct referring*)'"]
   "18" [label="'struct referring*'"]
   "18" -> "13" [label="pointed-to"]
   "17" -> "18" [label="parameter 1"]
diff --git a/test_cases/diff_tests/struct/nested.0.c b/test_cases/diff_tests/struct/nested.0.c
index bb693e9..80fb601 100644
--- a/test_cases/diff_tests/struct/nested.0.c
+++ b/test_cases/diff_tests/struct/nested.0.c
@@ -10,8 +10,7 @@ struct referring {
   struct nested * inner;
 };
 
-void tweak(int);
-void register_ops6(struct containing y) { (void) y; tweak(6); }
-void register_ops7(struct containing* y) { (void) y; tweak(7); }
-void register_ops8(struct referring y) { (void) y; tweak(8); }
-void register_ops9(struct referring* y) { (void) y; tweak(9); }
+int register_ops6(struct containing y) { (void) y; return 6; }
+int register_ops7(struct containing* y) { (void) y; return 7; }
+int register_ops8(struct referring y) { (void) y; return 8; }
+int register_ops9(struct referring* y) { (void) y; return 9; }
diff --git a/test_cases/diff_tests/struct/nested.0.cc b/test_cases/diff_tests/struct/nested.0.cc
index 3dfbea8..ce51ef8 100644
--- a/test_cases/diff_tests/struct/nested.0.cc
+++ b/test_cases/diff_tests/struct/nested.0.cc
@@ -10,8 +10,7 @@ struct referring {
   struct nested * inner;
 };
 
-void tweak(int);
-void register_ops6(containing) { tweak(6); }
-void register_ops7(containing*) { tweak(7); }
-void register_ops8(referring) { tweak(8); }
-void register_ops9(referring*) { tweak(9); }
+int register_ops6(containing) { return 6; }
+int register_ops7(containing*) { return 7; }
+int register_ops8(referring) { return 8; }
+int register_ops9(referring*) { return 9; }
diff --git a/test_cases/diff_tests/struct/nested.1.c b/test_cases/diff_tests/struct/nested.1.c
index 003207c..bd30e5f 100644
--- a/test_cases/diff_tests/struct/nested.1.c
+++ b/test_cases/diff_tests/struct/nested.1.c
@@ -10,8 +10,7 @@ struct referring {
   struct nested * inner;
 };
 
-void tweak(int);
-void register_ops6(struct containing y) { (void) y; tweak(6); }
-void register_ops7(struct containing* y) { (void) y; tweak(7); }
-void register_ops8(struct referring y) { (void) y; tweak(8); }
-void register_ops9(struct referring* y) { (void) y; tweak(9); }
+int register_ops6(struct containing y) { (void) y; return 6; }
+int register_ops7(struct containing* y) { (void) y; return 7; }
+int register_ops8(struct referring y) { (void) y; return 8; }
+int register_ops9(struct referring* y) { (void) y; return 9; }
diff --git a/test_cases/diff_tests/struct/nested.1.cc b/test_cases/diff_tests/struct/nested.1.cc
index 7c986de..8c6ff89 100644
--- a/test_cases/diff_tests/struct/nested.1.cc
+++ b/test_cases/diff_tests/struct/nested.1.cc
@@ -10,8 +10,7 @@ struct referring {
   struct nested * inner;
 };
 
-void tweak(int);
-void register_ops6(containing) { tweak(6); }
-void register_ops7(containing*) { tweak(7); }
-void register_ops8(referring) { tweak(8); }
-void register_ops9(referring*) { tweak(9); }
+int register_ops6(containing) { return 6; }
+int register_ops7(containing*) { return 7; }
+int register_ops8(referring) { return 8; }
+int register_ops9(referring*) { return 9; }
diff --git a/test_cases/diff_tests/symbol/expected/visibility_c.o_o_flat b/test_cases/diff_tests/symbol/expected/visibility_c.o_o_flat
index b310d1b..e8339bd 100644
--- a/test_cases/diff_tests/symbol/expected/visibility_c.o_o_flat
+++ b/test_cases/diff_tests/symbol/expected/visibility_c.o_o_flat
@@ -1,8 +1,8 @@
-function symbol 'void c()' was removed
+function symbol 'int c()' was removed
 
-function symbol 'void d()' was removed
+function symbol 'int d()' was removed
 
-function symbol 'void b()' changed
+function symbol 'int b()' changed
   visibility changed from default to protected
 
 exit code 4
diff --git a/test_cases/diff_tests/symbol/expected/visibility_c.o_o_plain b/test_cases/diff_tests/symbol/expected/visibility_c.o_o_plain
index b310d1b..e8339bd 100644
--- a/test_cases/diff_tests/symbol/expected/visibility_c.o_o_plain
+++ b/test_cases/diff_tests/symbol/expected/visibility_c.o_o_plain
@@ -1,8 +1,8 @@
-function symbol 'void c()' was removed
+function symbol 'int c()' was removed
 
-function symbol 'void d()' was removed
+function symbol 'int d()' was removed
 
-function symbol 'void b()' changed
+function symbol 'int b()' changed
   visibility changed from default to protected
 
 exit code 4
diff --git a/test_cases/diff_tests/symbol/expected/visibility_c.o_o_small b/test_cases/diff_tests/symbol/expected/visibility_c.o_o_small
index b310d1b..e8339bd 100644
--- a/test_cases/diff_tests/symbol/expected/visibility_c.o_o_small
+++ b/test_cases/diff_tests/symbol/expected/visibility_c.o_o_small
@@ -1,8 +1,8 @@
-function symbol 'void c()' was removed
+function symbol 'int c()' was removed
 
-function symbol 'void d()' was removed
+function symbol 'int d()' was removed
 
-function symbol 'void b()' changed
+function symbol 'int b()' changed
   visibility changed from default to protected
 
 exit code 4
diff --git a/test_cases/diff_tests/symbol/expected/visibility_c.o_o_viz b/test_cases/diff_tests/symbol/expected/visibility_c.o_o_viz
index cbfa0ad..90bc9ac 100644
--- a/test_cases/diff_tests/symbol/expected/visibility_c.o_o_viz
+++ b/test_cases/diff_tests/symbol/expected/visibility_c.o_o_viz
@@ -1,10 +1,10 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [color=red, label="removed(void c())"]
+  "1" [color=red, label="removed(int c())"]
   "0" -> "1" [label=""]
-  "2" [color=red, label="removed(void d())"]
+  "2" [color=red, label="removed(int d())"]
   "0" -> "2" [label=""]
-  "3" [color=red, label="'void b()'"]
+  "3" [color=red, label="'int b()'"]
   "3" -> "3:0"
   "3:0" [color=red, label="visibility changed from default to protected"]
   "0" -> "3" [label=""]
diff --git a/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_flat b/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_flat
index 329e2bd..7913819 100644
--- a/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_flat
+++ b/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_flat
@@ -1,8 +1,8 @@
-function symbol 'void c()' {_Z1cv} was removed
+function symbol 'int c()' {_Z1cv} was removed
 
-function symbol 'void d()' {_Z1dv} was removed
+function symbol 'int d()' {_Z1dv} was removed
 
-function symbol 'void b()' {_Z1bv} changed
+function symbol 'int b()' {_Z1bv} changed
   visibility changed from default to protected
 
 exit code 4
diff --git a/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_plain b/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_plain
index 329e2bd..7913819 100644
--- a/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_plain
+++ b/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_plain
@@ -1,8 +1,8 @@
-function symbol 'void c()' {_Z1cv} was removed
+function symbol 'int c()' {_Z1cv} was removed
 
-function symbol 'void d()' {_Z1dv} was removed
+function symbol 'int d()' {_Z1dv} was removed
 
-function symbol 'void b()' {_Z1bv} changed
+function symbol 'int b()' {_Z1bv} changed
   visibility changed from default to protected
 
 exit code 4
diff --git a/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_small b/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_small
index 329e2bd..7913819 100644
--- a/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_small
+++ b/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_small
@@ -1,8 +1,8 @@
-function symbol 'void c()' {_Z1cv} was removed
+function symbol 'int c()' {_Z1cv} was removed
 
-function symbol 'void d()' {_Z1dv} was removed
+function symbol 'int d()' {_Z1dv} was removed
 
-function symbol 'void b()' {_Z1bv} changed
+function symbol 'int b()' {_Z1bv} changed
   visibility changed from default to protected
 
 exit code 4
diff --git a/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_viz b/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_viz
index f391ae4..6bc35e3 100644
--- a/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_viz
+++ b/test_cases/diff_tests/symbol/expected/visibility_cc.o_o_viz
@@ -1,10 +1,10 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [color=red, label="removed(void c() {_Z1cv})"]
+  "1" [color=red, label="removed(int c() {_Z1cv})"]
   "0" -> "1" [label=""]
-  "2" [color=red, label="removed(void d() {_Z1dv})"]
+  "2" [color=red, label="removed(int d() {_Z1dv})"]
   "0" -> "2" [label=""]
-  "3" [color=red, label="'void b()' {_Z1bv}"]
+  "3" [color=red, label="'int b()' {_Z1bv}"]
   "3" -> "3:0"
   "3:0" [color=red, label="visibility changed from default to protected"]
   "0" -> "3" [label=""]
diff --git a/test_cases/diff_tests/symbol/version_definition.0.c b/test_cases/diff_tests/symbol/version_definition.0.c
index 6c902b8..2a61728 100644
--- a/test_cases/diff_tests/symbol/version_definition.0.c
+++ b/test_cases/diff_tests/symbol/version_definition.0.c
@@ -4,16 +4,14 @@
 // produce wrong results.
 // TODO: remove statement above after support is implemented
 
-void tweak(int dummy);
-
 __asm__(".symver versioned_foo_v1, versioned_foo@VERS_1");
-void versioned_foo_v1(void) { tweak(1); }
+int versioned_foo_v1(void) { return 1; }
 
 __asm__(".symver versioned_foo_v2, versioned_foo@VERS_2");
-void versioned_foo_v2(void) { tweak(2); }
+int versioned_foo_v2(void) { return 2; }
 
 __asm__(".symver versioned_foo_v3, versioned_foo@@VERS_3");
-void versioned_foo_v3(void) { tweak(3); }
+int versioned_foo_v3(void) { return 3; }
 
 // Using a libc function helps to add the "version needs" section
 // in addition to the "version definitions". This helps to catch
diff --git a/test_cases/diff_tests/symbol/version_definition.1.c b/test_cases/diff_tests/symbol/version_definition.1.c
index 0127d57..289ae19 100644
--- a/test_cases/diff_tests/symbol/version_definition.1.c
+++ b/test_cases/diff_tests/symbol/version_definition.1.c
@@ -4,16 +4,14 @@
 // produce wrong results.
 // TODO: remove statement above after support is implemented
 
-void tweak(int dummy);
-
 __asm__(".symver versioned_foo_v1, versioned_foo@@VERS_1");
-void versioned_foo_v1(void) { tweak(1); }
+int versioned_foo_v1(void) { return 1; }
 
 __asm__(".symver versioned_foo_v2, versioned_foo@VERS_2");
-void versioned_foo_v2(void) { tweak(2); }
+int versioned_foo_v2(void) { return 2; }
 
 __asm__(".symver versioned_foo_v3, versioned_foo@VERS_3");
-void versioned_foo_v3(void) { tweak(3); }
+int versioned_foo_v3(void) { return 3; }
 
 // Using a libc function helps to add the "version needs" section
 // in addition to the "version definitions". This helps to catch
diff --git a/test_cases/diff_tests/symbol/visibility.0.c b/test_cases/diff_tests/symbol/visibility.0.c
index 596b55a..76b3ac6 100644
--- a/test_cases/diff_tests/symbol/visibility.0.c
+++ b/test_cases/diff_tests/symbol/visibility.0.c
@@ -1,5 +1,4 @@
-void tweak(int);
-void a() { tweak(0); }
-void b() { tweak(1); }
-void c() { tweak(2); }
-void d() { tweak(3); }
+int a() { return 0; }
+int b() { return 1; }
+int c() { return 2; }
+int d() { return 3; }
diff --git a/test_cases/diff_tests/symbol/visibility.0.cc b/test_cases/diff_tests/symbol/visibility.0.cc
index 596b55a..76b3ac6 100644
--- a/test_cases/diff_tests/symbol/visibility.0.cc
+++ b/test_cases/diff_tests/symbol/visibility.0.cc
@@ -1,5 +1,4 @@
-void tweak(int);
-void a() { tweak(0); }
-void b() { tweak(1); }
-void c() { tweak(2); }
-void d() { tweak(3); }
+int a() { return 0; }
+int b() { return 1; }
+int c() { return 2; }
+int d() { return 3; }
diff --git a/test_cases/diff_tests/symbol/visibility.1.c b/test_cases/diff_tests/symbol/visibility.1.c
index 45fcbb5..13dfa0c 100644
--- a/test_cases/diff_tests/symbol/visibility.1.c
+++ b/test_cases/diff_tests/symbol/visibility.1.c
@@ -1,5 +1,4 @@
-void tweak(int);
-__attribute__ ((visibility ("default"))) void a() { tweak(0); }
-__attribute__ ((visibility ("protected"))) void b() { tweak(1); }
-__attribute__ ((visibility ("hidden"))) void c() { tweak(2); }
-__attribute__ ((visibility ("internal"))) void d() { tweak(3); }
+__attribute__ ((visibility ("default"))) int a() { return 0; }
+__attribute__ ((visibility ("protected"))) int b() { return 1; }
+__attribute__ ((visibility ("hidden"))) int c() { return 2; }
+__attribute__ ((visibility ("internal"))) int d() { return 3; }
diff --git a/test_cases/diff_tests/symbol/visibility.1.cc b/test_cases/diff_tests/symbol/visibility.1.cc
index 45fcbb5..13dfa0c 100644
--- a/test_cases/diff_tests/symbol/visibility.1.cc
+++ b/test_cases/diff_tests/symbol/visibility.1.cc
@@ -1,5 +1,4 @@
-void tweak(int);
-__attribute__ ((visibility ("default"))) void a() { tweak(0); }
-__attribute__ ((visibility ("protected"))) void b() { tweak(1); }
-__attribute__ ((visibility ("hidden"))) void c() { tweak(2); }
-__attribute__ ((visibility ("internal"))) void d() { tweak(3); }
+__attribute__ ((visibility ("default"))) int a() { return 0; }
+__attribute__ ((visibility ("protected"))) int b() { return 1; }
+__attribute__ ((visibility ("hidden"))) int c() { return 2; }
+__attribute__ ((visibility ("internal"))) int d() { return 3; }
diff --git a/test_cases/diff_tests/types/char.0.c b/test_cases/diff_tests/types/char.0.c
index d24d0ab..8efd700 100644
--- a/test_cases/diff_tests/types/char.0.c
+++ b/test_cases/diff_tests/types/char.0.c
@@ -1,8 +1,7 @@
 // tweaked due to https://gcc.gnu.org/bugzilla/show_bug.cgi?id=112372
-void tweak(int);
-void u(char c) { (void)c; tweak(0); }
-void v(unsigned char c) { (void)c; tweak(1); }
-void w(signed char c) { (void)c; tweak(2); }
-void x(char c) { (void)c; tweak(3); }
-void y(unsigned char c) { (void)c; tweak(4); }
-void z(signed char c) { (void)c; tweak(5); }
+int u(char c) { (void)c; return 0; }
+int v(unsigned char c) { (void)c; return 1; }
+int w(signed char c) { (void)c; return 2; }
+int x(char c) { (void)c; return 3; }
+int y(unsigned char c) { (void)c; return 4; }
+int z(signed char c) { (void)c; return 5; }
diff --git a/test_cases/diff_tests/types/char.1.c b/test_cases/diff_tests/types/char.1.c
index 8ab40a0..7f33ffa 100644
--- a/test_cases/diff_tests/types/char.1.c
+++ b/test_cases/diff_tests/types/char.1.c
@@ -1,8 +1,7 @@
 // tweaked due to https://gcc.gnu.org/bugzilla/show_bug.cgi?id=112372
-void tweak(int);
-void u(unsigned char c) { (void)c; tweak(0); }
-void v(signed char c) { (void)c; tweak(1); }
-void w(char c) { (void)c; tweak(2); }
-void x(signed char c) { (void)c; tweak(3); }
-void y(char c) { (void)c; tweak(4); }
-void z(unsigned char c) { (void)c; tweak(5); }
+int u(unsigned char c) { (void)c; return 0; }
+int v(signed char c) { (void)c; return 1; }
+int w(char c) { (void)c; return 2; }
+int x(signed char c) { (void)c; return 3; }
+int y(char c) { (void)c; return 4; }
+int z(unsigned char c) { (void)c; return 5; }
diff --git a/test_cases/diff_tests/types/expected/char_c.btf_btf_flat b/test_cases/diff_tests/types/expected/char_c.btf_btf_flat
index 719cc42..02eef34 100644
--- a/test_cases/diff_tests/types/expected/char_c.btf_btf_flat
+++ b/test_cases/diff_tests/types/expected/char_c.btf_btf_flat
@@ -1,25 +1,25 @@
-function symbol changed from 'void u(char)' to 'void u(unsigned char)'
-  type changed from 'void(char)' to 'void(unsigned char)'
+function symbol changed from 'int u(char)' to 'int u(unsigned char)'
+  type changed from 'int(char)' to 'int(unsigned char)'
     parameter 1 type changed from 'char' to 'unsigned char'
 
-function symbol changed from 'void v(unsigned char)' to 'void v(signed char)'
-  type changed from 'void(unsigned char)' to 'void(signed char)'
+function symbol changed from 'int v(unsigned char)' to 'int v(signed char)'
+  type changed from 'int(unsigned char)' to 'int(signed char)'
     parameter 1 type changed from 'unsigned char' to 'signed char'
 
-function symbol changed from 'void w(signed char)' to 'void w(char)'
-  type changed from 'void(signed char)' to 'void(char)'
+function symbol changed from 'int w(signed char)' to 'int w(char)'
+  type changed from 'int(signed char)' to 'int(char)'
     parameter 1 type changed from 'signed char' to 'char'
 
-function symbol changed from 'void x(char)' to 'void x(signed char)'
-  type changed from 'void(char)' to 'void(signed char)'
+function symbol changed from 'int x(char)' to 'int x(signed char)'
+  type changed from 'int(char)' to 'int(signed char)'
     parameter 1 type changed from 'char' to 'signed char'
 
-function symbol changed from 'void y(unsigned char)' to 'void y(char)'
-  type changed from 'void(unsigned char)' to 'void(char)'
+function symbol changed from 'int y(unsigned char)' to 'int y(char)'
+  type changed from 'int(unsigned char)' to 'int(char)'
     parameter 1 type changed from 'unsigned char' to 'char'
 
-function symbol changed from 'void z(signed char)' to 'void z(unsigned char)'
-  type changed from 'void(signed char)' to 'void(unsigned char)'
+function symbol changed from 'int z(signed char)' to 'int z(unsigned char)'
+  type changed from 'int(signed char)' to 'int(unsigned char)'
     parameter 1 type changed from 'signed char' to 'unsigned char'
 
 exit code 4
diff --git a/test_cases/diff_tests/types/expected/char_c.btf_btf_plain b/test_cases/diff_tests/types/expected/char_c.btf_btf_plain
index 719cc42..02eef34 100644
--- a/test_cases/diff_tests/types/expected/char_c.btf_btf_plain
+++ b/test_cases/diff_tests/types/expected/char_c.btf_btf_plain
@@ -1,25 +1,25 @@
-function symbol changed from 'void u(char)' to 'void u(unsigned char)'
-  type changed from 'void(char)' to 'void(unsigned char)'
+function symbol changed from 'int u(char)' to 'int u(unsigned char)'
+  type changed from 'int(char)' to 'int(unsigned char)'
     parameter 1 type changed from 'char' to 'unsigned char'
 
-function symbol changed from 'void v(unsigned char)' to 'void v(signed char)'
-  type changed from 'void(unsigned char)' to 'void(signed char)'
+function symbol changed from 'int v(unsigned char)' to 'int v(signed char)'
+  type changed from 'int(unsigned char)' to 'int(signed char)'
     parameter 1 type changed from 'unsigned char' to 'signed char'
 
-function symbol changed from 'void w(signed char)' to 'void w(char)'
-  type changed from 'void(signed char)' to 'void(char)'
+function symbol changed from 'int w(signed char)' to 'int w(char)'
+  type changed from 'int(signed char)' to 'int(char)'
     parameter 1 type changed from 'signed char' to 'char'
 
-function symbol changed from 'void x(char)' to 'void x(signed char)'
-  type changed from 'void(char)' to 'void(signed char)'
+function symbol changed from 'int x(char)' to 'int x(signed char)'
+  type changed from 'int(char)' to 'int(signed char)'
     parameter 1 type changed from 'char' to 'signed char'
 
-function symbol changed from 'void y(unsigned char)' to 'void y(char)'
-  type changed from 'void(unsigned char)' to 'void(char)'
+function symbol changed from 'int y(unsigned char)' to 'int y(char)'
+  type changed from 'int(unsigned char)' to 'int(char)'
     parameter 1 type changed from 'unsigned char' to 'char'
 
-function symbol changed from 'void z(signed char)' to 'void z(unsigned char)'
-  type changed from 'void(signed char)' to 'void(unsigned char)'
+function symbol changed from 'int z(signed char)' to 'int z(unsigned char)'
+  type changed from 'int(signed char)' to 'int(unsigned char)'
     parameter 1 type changed from 'signed char' to 'unsigned char'
 
 exit code 4
diff --git a/test_cases/diff_tests/types/expected/char_c.btf_btf_small b/test_cases/diff_tests/types/expected/char_c.btf_btf_small
index 719cc42..02eef34 100644
--- a/test_cases/diff_tests/types/expected/char_c.btf_btf_small
+++ b/test_cases/diff_tests/types/expected/char_c.btf_btf_small
@@ -1,25 +1,25 @@
-function symbol changed from 'void u(char)' to 'void u(unsigned char)'
-  type changed from 'void(char)' to 'void(unsigned char)'
+function symbol changed from 'int u(char)' to 'int u(unsigned char)'
+  type changed from 'int(char)' to 'int(unsigned char)'
     parameter 1 type changed from 'char' to 'unsigned char'
 
-function symbol changed from 'void v(unsigned char)' to 'void v(signed char)'
-  type changed from 'void(unsigned char)' to 'void(signed char)'
+function symbol changed from 'int v(unsigned char)' to 'int v(signed char)'
+  type changed from 'int(unsigned char)' to 'int(signed char)'
     parameter 1 type changed from 'unsigned char' to 'signed char'
 
-function symbol changed from 'void w(signed char)' to 'void w(char)'
-  type changed from 'void(signed char)' to 'void(char)'
+function symbol changed from 'int w(signed char)' to 'int w(char)'
+  type changed from 'int(signed char)' to 'int(char)'
     parameter 1 type changed from 'signed char' to 'char'
 
-function symbol changed from 'void x(char)' to 'void x(signed char)'
-  type changed from 'void(char)' to 'void(signed char)'
+function symbol changed from 'int x(char)' to 'int x(signed char)'
+  type changed from 'int(char)' to 'int(signed char)'
     parameter 1 type changed from 'char' to 'signed char'
 
-function symbol changed from 'void y(unsigned char)' to 'void y(char)'
-  type changed from 'void(unsigned char)' to 'void(char)'
+function symbol changed from 'int y(unsigned char)' to 'int y(char)'
+  type changed from 'int(unsigned char)' to 'int(char)'
     parameter 1 type changed from 'unsigned char' to 'char'
 
-function symbol changed from 'void z(signed char)' to 'void z(unsigned char)'
-  type changed from 'void(signed char)' to 'void(unsigned char)'
+function symbol changed from 'int z(signed char)' to 'int z(unsigned char)'
+  type changed from 'int(signed char)' to 'int(unsigned char)'
     parameter 1 type changed from 'signed char' to 'unsigned char'
 
 exit code 4
diff --git a/test_cases/diff_tests/types/expected/char_c.btf_btf_viz b/test_cases/diff_tests/types/expected/char_c.btf_btf_viz
index c92c7f3..c68b05c 100644
--- a/test_cases/diff_tests/types/expected/char_c.btf_btf_viz
+++ b/test_cases/diff_tests/types/expected/char_c.btf_btf_viz
@@ -1,37 +1,37 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'void u(char)' -> 'void u(unsigned char)'"]
-  "2" [label="'void(char)' -> 'void(unsigned char)'"]
+  "1" [label="'int u(char)' -> 'int u(unsigned char)'"]
+  "2" [label="'int(char)' -> 'int(unsigned char)'"]
   "3" [color=red, label="'char' -> 'unsigned char'"]
   "2" -> "3" [label="parameter 1"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "4" [label="'void v(unsigned char)' -> 'void v(signed char)'"]
-  "5" [label="'void(unsigned char)' -> 'void(signed char)'"]
+  "4" [label="'int v(unsigned char)' -> 'int v(signed char)'"]
+  "5" [label="'int(unsigned char)' -> 'int(signed char)'"]
   "6" [color=red, label="'unsigned char' -> 'signed char'"]
   "5" -> "6" [label="parameter 1"]
   "4" -> "5" [label=""]
   "0" -> "4" [label=""]
-  "7" [label="'void w(signed char)' -> 'void w(char)'"]
-  "8" [label="'void(signed char)' -> 'void(char)'"]
+  "7" [label="'int w(signed char)' -> 'int w(char)'"]
+  "8" [label="'int(signed char)' -> 'int(char)'"]
   "9" [color=red, label="'signed char' -> 'char'"]
   "8" -> "9" [label="parameter 1"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
-  "10" [label="'void x(char)' -> 'void x(signed char)'"]
-  "11" [label="'void(char)' -> 'void(signed char)'"]
+  "10" [label="'int x(char)' -> 'int x(signed char)'"]
+  "11" [label="'int(char)' -> 'int(signed char)'"]
   "12" [color=red, label="'char' -> 'signed char'"]
   "11" -> "12" [label="parameter 1"]
   "10" -> "11" [label=""]
   "0" -> "10" [label=""]
-  "13" [label="'void y(unsigned char)' -> 'void y(char)'"]
-  "14" [label="'void(unsigned char)' -> 'void(char)'"]
+  "13" [label="'int y(unsigned char)' -> 'int y(char)'"]
+  "14" [label="'int(unsigned char)' -> 'int(char)'"]
   "15" [color=red, label="'unsigned char' -> 'char'"]
   "14" -> "15" [label="parameter 1"]
   "13" -> "14" [label=""]
   "0" -> "13" [label=""]
-  "16" [label="'void z(signed char)' -> 'void z(unsigned char)'"]
-  "17" [label="'void(signed char)' -> 'void(unsigned char)'"]
+  "16" [label="'int z(signed char)' -> 'int z(unsigned char)'"]
+  "17" [label="'int(signed char)' -> 'int(unsigned char)'"]
   "18" [color=red, label="'signed char' -> 'unsigned char'"]
   "17" -> "18" [label="parameter 1"]
   "16" -> "17" [label=""]
diff --git a/test_cases/diff_tests/types/expected/char_c.o_o_flat b/test_cases/diff_tests/types/expected/char_c.o_o_flat
index 719cc42..02eef34 100644
--- a/test_cases/diff_tests/types/expected/char_c.o_o_flat
+++ b/test_cases/diff_tests/types/expected/char_c.o_o_flat
@@ -1,25 +1,25 @@
-function symbol changed from 'void u(char)' to 'void u(unsigned char)'
-  type changed from 'void(char)' to 'void(unsigned char)'
+function symbol changed from 'int u(char)' to 'int u(unsigned char)'
+  type changed from 'int(char)' to 'int(unsigned char)'
     parameter 1 type changed from 'char' to 'unsigned char'
 
-function symbol changed from 'void v(unsigned char)' to 'void v(signed char)'
-  type changed from 'void(unsigned char)' to 'void(signed char)'
+function symbol changed from 'int v(unsigned char)' to 'int v(signed char)'
+  type changed from 'int(unsigned char)' to 'int(signed char)'
     parameter 1 type changed from 'unsigned char' to 'signed char'
 
-function symbol changed from 'void w(signed char)' to 'void w(char)'
-  type changed from 'void(signed char)' to 'void(char)'
+function symbol changed from 'int w(signed char)' to 'int w(char)'
+  type changed from 'int(signed char)' to 'int(char)'
     parameter 1 type changed from 'signed char' to 'char'
 
-function symbol changed from 'void x(char)' to 'void x(signed char)'
-  type changed from 'void(char)' to 'void(signed char)'
+function symbol changed from 'int x(char)' to 'int x(signed char)'
+  type changed from 'int(char)' to 'int(signed char)'
     parameter 1 type changed from 'char' to 'signed char'
 
-function symbol changed from 'void y(unsigned char)' to 'void y(char)'
-  type changed from 'void(unsigned char)' to 'void(char)'
+function symbol changed from 'int y(unsigned char)' to 'int y(char)'
+  type changed from 'int(unsigned char)' to 'int(char)'
     parameter 1 type changed from 'unsigned char' to 'char'
 
-function symbol changed from 'void z(signed char)' to 'void z(unsigned char)'
-  type changed from 'void(signed char)' to 'void(unsigned char)'
+function symbol changed from 'int z(signed char)' to 'int z(unsigned char)'
+  type changed from 'int(signed char)' to 'int(unsigned char)'
     parameter 1 type changed from 'signed char' to 'unsigned char'
 
 exit code 4
diff --git a/test_cases/diff_tests/types/expected/char_c.o_o_plain b/test_cases/diff_tests/types/expected/char_c.o_o_plain
index 719cc42..02eef34 100644
--- a/test_cases/diff_tests/types/expected/char_c.o_o_plain
+++ b/test_cases/diff_tests/types/expected/char_c.o_o_plain
@@ -1,25 +1,25 @@
-function symbol changed from 'void u(char)' to 'void u(unsigned char)'
-  type changed from 'void(char)' to 'void(unsigned char)'
+function symbol changed from 'int u(char)' to 'int u(unsigned char)'
+  type changed from 'int(char)' to 'int(unsigned char)'
     parameter 1 type changed from 'char' to 'unsigned char'
 
-function symbol changed from 'void v(unsigned char)' to 'void v(signed char)'
-  type changed from 'void(unsigned char)' to 'void(signed char)'
+function symbol changed from 'int v(unsigned char)' to 'int v(signed char)'
+  type changed from 'int(unsigned char)' to 'int(signed char)'
     parameter 1 type changed from 'unsigned char' to 'signed char'
 
-function symbol changed from 'void w(signed char)' to 'void w(char)'
-  type changed from 'void(signed char)' to 'void(char)'
+function symbol changed from 'int w(signed char)' to 'int w(char)'
+  type changed from 'int(signed char)' to 'int(char)'
     parameter 1 type changed from 'signed char' to 'char'
 
-function symbol changed from 'void x(char)' to 'void x(signed char)'
-  type changed from 'void(char)' to 'void(signed char)'
+function symbol changed from 'int x(char)' to 'int x(signed char)'
+  type changed from 'int(char)' to 'int(signed char)'
     parameter 1 type changed from 'char' to 'signed char'
 
-function symbol changed from 'void y(unsigned char)' to 'void y(char)'
-  type changed from 'void(unsigned char)' to 'void(char)'
+function symbol changed from 'int y(unsigned char)' to 'int y(char)'
+  type changed from 'int(unsigned char)' to 'int(char)'
     parameter 1 type changed from 'unsigned char' to 'char'
 
-function symbol changed from 'void z(signed char)' to 'void z(unsigned char)'
-  type changed from 'void(signed char)' to 'void(unsigned char)'
+function symbol changed from 'int z(signed char)' to 'int z(unsigned char)'
+  type changed from 'int(signed char)' to 'int(unsigned char)'
     parameter 1 type changed from 'signed char' to 'unsigned char'
 
 exit code 4
diff --git a/test_cases/diff_tests/types/expected/char_c.o_o_small b/test_cases/diff_tests/types/expected/char_c.o_o_small
index 719cc42..02eef34 100644
--- a/test_cases/diff_tests/types/expected/char_c.o_o_small
+++ b/test_cases/diff_tests/types/expected/char_c.o_o_small
@@ -1,25 +1,25 @@
-function symbol changed from 'void u(char)' to 'void u(unsigned char)'
-  type changed from 'void(char)' to 'void(unsigned char)'
+function symbol changed from 'int u(char)' to 'int u(unsigned char)'
+  type changed from 'int(char)' to 'int(unsigned char)'
     parameter 1 type changed from 'char' to 'unsigned char'
 
-function symbol changed from 'void v(unsigned char)' to 'void v(signed char)'
-  type changed from 'void(unsigned char)' to 'void(signed char)'
+function symbol changed from 'int v(unsigned char)' to 'int v(signed char)'
+  type changed from 'int(unsigned char)' to 'int(signed char)'
     parameter 1 type changed from 'unsigned char' to 'signed char'
 
-function symbol changed from 'void w(signed char)' to 'void w(char)'
-  type changed from 'void(signed char)' to 'void(char)'
+function symbol changed from 'int w(signed char)' to 'int w(char)'
+  type changed from 'int(signed char)' to 'int(char)'
     parameter 1 type changed from 'signed char' to 'char'
 
-function symbol changed from 'void x(char)' to 'void x(signed char)'
-  type changed from 'void(char)' to 'void(signed char)'
+function symbol changed from 'int x(char)' to 'int x(signed char)'
+  type changed from 'int(char)' to 'int(signed char)'
     parameter 1 type changed from 'char' to 'signed char'
 
-function symbol changed from 'void y(unsigned char)' to 'void y(char)'
-  type changed from 'void(unsigned char)' to 'void(char)'
+function symbol changed from 'int y(unsigned char)' to 'int y(char)'
+  type changed from 'int(unsigned char)' to 'int(char)'
     parameter 1 type changed from 'unsigned char' to 'char'
 
-function symbol changed from 'void z(signed char)' to 'void z(unsigned char)'
-  type changed from 'void(signed char)' to 'void(unsigned char)'
+function symbol changed from 'int z(signed char)' to 'int z(unsigned char)'
+  type changed from 'int(signed char)' to 'int(unsigned char)'
     parameter 1 type changed from 'signed char' to 'unsigned char'
 
 exit code 4
diff --git a/test_cases/diff_tests/types/expected/char_c.o_o_viz b/test_cases/diff_tests/types/expected/char_c.o_o_viz
index c92c7f3..c68b05c 100644
--- a/test_cases/diff_tests/types/expected/char_c.o_o_viz
+++ b/test_cases/diff_tests/types/expected/char_c.o_o_viz
@@ -1,37 +1,37 @@
 digraph "ABI diff" {
   "0" [shape=rectangle, label="'interface'"]
-  "1" [label="'void u(char)' -> 'void u(unsigned char)'"]
-  "2" [label="'void(char)' -> 'void(unsigned char)'"]
+  "1" [label="'int u(char)' -> 'int u(unsigned char)'"]
+  "2" [label="'int(char)' -> 'int(unsigned char)'"]
   "3" [color=red, label="'char' -> 'unsigned char'"]
   "2" -> "3" [label="parameter 1"]
   "1" -> "2" [label=""]
   "0" -> "1" [label=""]
-  "4" [label="'void v(unsigned char)' -> 'void v(signed char)'"]
-  "5" [label="'void(unsigned char)' -> 'void(signed char)'"]
+  "4" [label="'int v(unsigned char)' -> 'int v(signed char)'"]
+  "5" [label="'int(unsigned char)' -> 'int(signed char)'"]
   "6" [color=red, label="'unsigned char' -> 'signed char'"]
   "5" -> "6" [label="parameter 1"]
   "4" -> "5" [label=""]
   "0" -> "4" [label=""]
-  "7" [label="'void w(signed char)' -> 'void w(char)'"]
-  "8" [label="'void(signed char)' -> 'void(char)'"]
+  "7" [label="'int w(signed char)' -> 'int w(char)'"]
+  "8" [label="'int(signed char)' -> 'int(char)'"]
   "9" [color=red, label="'signed char' -> 'char'"]
   "8" -> "9" [label="parameter 1"]
   "7" -> "8" [label=""]
   "0" -> "7" [label=""]
-  "10" [label="'void x(char)' -> 'void x(signed char)'"]
-  "11" [label="'void(char)' -> 'void(signed char)'"]
+  "10" [label="'int x(char)' -> 'int x(signed char)'"]
+  "11" [label="'int(char)' -> 'int(signed char)'"]
   "12" [color=red, label="'char' -> 'signed char'"]
   "11" -> "12" [label="parameter 1"]
   "10" -> "11" [label=""]
   "0" -> "10" [label=""]
-  "13" [label="'void y(unsigned char)' -> 'void y(char)'"]
-  "14" [label="'void(unsigned char)' -> 'void(char)'"]
+  "13" [label="'int y(unsigned char)' -> 'int y(char)'"]
+  "14" [label="'int(unsigned char)' -> 'int(char)'"]
   "15" [color=red, label="'unsigned char' -> 'char'"]
   "14" -> "15" [label="parameter 1"]
   "13" -> "14" [label=""]
   "0" -> "13" [label=""]
-  "16" [label="'void z(signed char)' -> 'void z(unsigned char)'"]
-  "17" [label="'void(signed char)' -> 'void(unsigned char)'"]
+  "16" [label="'int z(signed char)' -> 'int z(unsigned char)'"]
+  "17" [label="'int(signed char)' -> 'int(unsigned char)'"]
   "18" [color=red, label="'signed char' -> 'unsigned char'"]
   "17" -> "18" [label="parameter 1"]
   "16" -> "17" [label=""]
diff --git a/test_cases/info_tests/array/expected/variable_length_c.btf_stg b/test_cases/info_tests/array/expected/variable_length_c.btf_stg
index a9f6bde..6d73ea7 100644
--- a/test_cases/info_tests/array/expected/variable_length_c.btf_stg
+++ b/test_cases/info_tests/array/expected/variable_length_c.btf_stg
@@ -7,17 +7,18 @@ primitive {
   bytesize: 0x00000004
 }
 function {
-  id: 0x9d80e32f
+  id: 0x8448d7e4
   return_type_id: 0x6720d32f  # int
+  parameter_id: 0x6720d32f  # int
 }
 elf_symbol {
   id: 0xa58ca0b6
   name: "bar"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x9d80e32f  # int()
+  type_id: 0x8448d7e4  # int(int)
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0xa58ca0b6  # int bar()
+  symbol_id: 0xa58ca0b6  # int bar(int)
 }
diff --git a/test_cases/info_tests/array/expected/variable_length_c.elf_stg b/test_cases/info_tests/array/expected/variable_length_c.elf_stg
index 80c4c20..bb33daa 100644
--- a/test_cases/info_tests/array/expected/variable_length_c.elf_stg
+++ b/test_cases/info_tests/array/expected/variable_length_c.elf_stg
@@ -7,18 +7,19 @@ primitive {
   bytesize: 0x00000004
 }
 function {
-  id: 0x9d80e32f
+  id: 0x8448d7e4
   return_type_id: 0x6720d32f  # int
+  parameter_id: 0x6720d32f  # int
 }
 elf_symbol {
   id: 0xa58ca0b6
   name: "bar"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x9d80e32f  # int()
+  type_id: 0x8448d7e4  # int(int)
   full_name: "bar"
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0xa58ca0b6  # int bar()
+  symbol_id: 0xa58ca0b6  # int bar(int)
 }
diff --git a/test_cases/info_tests/array/variable_length.c b/test_cases/info_tests/array/variable_length.c
index fa86172..1dc52df 100644
--- a/test_cases/info_tests/array/variable_length.c
+++ b/test_cases/info_tests/array/variable_length.c
@@ -1,7 +1,4 @@
-int foo(void);
-
-int bar(void) {
-  int n = foo();
+int bar(int n) {
   int a[n];
   return a[n - 1];
 }
diff --git a/test_cases/info_tests/function/expected/virtual_method_cc.elf_stg b/test_cases/info_tests/function/expected/virtual_method_cc.elf_stg
index cbc7e61..19fe631 100644
--- a/test_cases/info_tests/function/expected/virtual_method_cc.elf_stg
+++ b/test_cases/info_tests/function/expected/virtual_method_cc.elf_stg
@@ -1,9 +1,5 @@
 version: 0x00000002
 root_id: 0x84ea5130  # interface
-special {
-  id: 0x48b5725f
-  kind: VOID
-}
 pointer_reference {
   id: 0x01ec39fc
   kind: POINTER
@@ -29,14 +25,14 @@ method {
   id: 0x91a60460
   mangled_name: "_ZN3Foo3barEv"
   name: "bar"
-  type_id: 0x1d536fb5  # void(struct Foo*)
+  type_id: 0x904bdd09  # int(struct Foo*)
 }
 method {
   id: 0x3bae9a68
   mangled_name: "_ZN3Foo3bazEv"
   name: "baz"
   vtable_offset: 1
-  type_id: 0x1d536fb5  # void(struct Foo*)
+  type_id: 0x904bdd09  # int(struct Foo*)
 }
 member {
   id: 0xc9e943fb
@@ -49,14 +45,14 @@ struct_union {
   name: "Foo"
   definition {
     bytesize: 8
-    method_id: 0x91a60460  # void bar(struct Foo*)
-    method_id: 0x3bae9a68  # void baz(struct Foo*)
+    method_id: 0x91a60460  # int bar(struct Foo*)
+    method_id: 0x3bae9a68  # int baz(struct Foo*)
     member_id: 0xc9e943fb  # int(** _vptr$Foo)()
   }
 }
 function {
-  id: 0x1d536fb5
-  return_type_id: 0x48b5725f  # void
+  id: 0x904bdd09
+  return_type_id: 0x6720d32f  # int
   parameter_id: 0x372cf89a  # struct Foo*
 }
 function {
@@ -68,7 +64,7 @@ elf_symbol {
   name: "_ZN3Foo3barEv"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x1d536fb5  # void(struct Foo*)
+  type_id: 0x904bdd09  # int(struct Foo*)
   full_name: "Foo::bar"
 }
 elf_symbol {
@@ -76,7 +72,7 @@ elf_symbol {
   name: "_ZN3Foo3bazEv"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x1d536fb5  # void(struct Foo*)
+  type_id: 0x904bdd09  # int(struct Foo*)
   full_name: "Foo::baz"
 }
 elf_symbol {
@@ -107,8 +103,8 @@ elf_symbol {
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0x043f549e  # void Foo::bar(struct Foo*)
-  symbol_id: 0x39ee62e8  # void Foo::baz(struct Foo*)
+  symbol_id: 0x043f549e  # int Foo::bar(struct Foo*)
+  symbol_id: 0x39ee62e8  # int Foo::baz(struct Foo*)
   symbol_id: 0x263987d0  # _ZTI3Foo
   symbol_id: 0x264c5a0d  # _ZTS3Foo
   symbol_id: 0x9e36cb56  # _ZTV3Foo
diff --git a/test_cases/info_tests/function/virtual_method.cc b/test_cases/info_tests/function/virtual_method.cc
index 0bf3e48..577b16d 100644
--- a/test_cases/info_tests/function/virtual_method.cc
+++ b/test_cases/info_tests/function/virtual_method.cc
@@ -1,8 +1,7 @@
 struct Foo {
-  virtual void bar();
-  virtual void baz();
+  virtual int bar();
+  virtual int baz();
 } foo;
 
-void tweak(int);
-void Foo::bar() { tweak(0); }
-void Foo::baz() { tweak(1); }
+int Foo::bar() { return 0; }
+int Foo::baz() { return 1; }
diff --git a/test_cases/info_tests/qualified/expected/useless_c.btf_stg b/test_cases/info_tests/qualified/expected/useless_c.btf_stg
index d42abf1..3eb718b 100644
--- a/test_cases/info_tests/qualified/expected/useless_c.btf_stg
+++ b/test_cases/info_tests/qualified/expected/useless_c.btf_stg
@@ -1,18 +1,14 @@
 version: 0x00000002
 root_id: 0x84ea5130  # interface
-special {
-  id: 0x48b5725f
-  kind: VOID
-}
 pointer_reference {
-  id: 0x0dd55c4a
+  id: 0x24b3ee1b
   kind: POINTER
-  pointee_type_id: 0x1d1597b4  # void(const volatile struct foo*)
+  pointee_type_id: 0xb88f5ef1  # struct foo
 }
 pointer_reference {
-  id: 0x24b3ee1b
+  id: 0x2e9370e5
   kind: POINTER
-  pointee_type_id: 0xb88f5ef1  # struct foo
+  pointee_type_id: 0x900d2508  # int(const volatile struct foo*)
 }
 pointer_reference {
   id: 0x3637189c
@@ -20,9 +16,9 @@ pointer_reference {
   pointee_type_id: 0xf29c84ee  # const volatile struct foo
 }
 qualified {
-  id: 0x9763259f
+  id: 0x9fb2aeb4
   qualifier: VOLATILE
-  qualified_type_id: 0x0dd55c4a  # void(*)(const volatile struct foo*)
+  qualified_type_id: 0x2e9370e5  # int(*)(const volatile struct foo*)
 }
 qualified {
   id: 0xba35a531
@@ -35,9 +31,15 @@ qualified {
   qualified_type_id: 0xba35a531  # volatile struct foo
 }
 qualified {
-  id: 0xf9c924c5
+  id: 0xfbfd460f
   qualifier: CONST
-  qualified_type_id: 0x9763259f  # void(* volatile)(const volatile struct foo*)
+  qualified_type_id: 0x9fb2aeb4  # int(* volatile)(const volatile struct foo*)
+}
+primitive {
+  id: 0x6720d32f
+  name: "int"
+  encoding: SIGNED_INTEGER
+  bytesize: 0x00000004
 }
 struct_union {
   id: 0xb88f5ef1
@@ -47,44 +49,44 @@ struct_union {
   }
 }
 function {
-  id: 0x19b4aa15
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0x24b3ee1b  # struct foo*
+  id: 0x900d2508
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x3637189c  # const volatile struct foo*
 }
 function {
-  id: 0x1d1597b4
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0x3637189c  # const volatile struct foo*
+  id: 0x94ac18a9
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x24b3ee1b  # struct foo*
 }
 function {
-  id: 0x2eea18a2
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0xf9c924c5  # void(* volatile const)(const volatile struct foo*)
+  id: 0xa37fb2ac
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0xfbfd460f  # int(* volatile const)(const volatile struct foo*)
 }
 elf_symbol {
   id: 0xa58ca0b6
   name: "bar"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x1d1597b4  # void(const volatile struct foo*)
+  type_id: 0x900d2508  # int(const volatile struct foo*)
 }
 elf_symbol {
   id: 0xe89bbaac
   name: "bar_2"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x19b4aa15  # void(struct foo*)
+  type_id: 0x94ac18a9  # int(struct foo*)
 }
 elf_symbol {
   id: 0xbf8fc404
   name: "baz"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x2eea18a2  # void(void(* volatile const)(const volatile struct foo*))
+  type_id: 0xa37fb2ac  # int(int(* volatile const)(const volatile struct foo*))
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0xa58ca0b6  # void bar(const volatile struct foo*)
-  symbol_id: 0xe89bbaac  # void bar_2(struct foo*)
-  symbol_id: 0xbf8fc404  # void baz(void(* volatile const)(const volatile struct foo*))
+  symbol_id: 0xa58ca0b6  # int bar(const volatile struct foo*)
+  symbol_id: 0xe89bbaac  # int bar_2(struct foo*)
+  symbol_id: 0xbf8fc404  # int baz(int(* volatile const)(const volatile struct foo*))
 }
diff --git a/test_cases/info_tests/qualified/expected/useless_c.elf_stg b/test_cases/info_tests/qualified/expected/useless_c.elf_stg
index 2449a6c..360ac52 100644
--- a/test_cases/info_tests/qualified/expected/useless_c.elf_stg
+++ b/test_cases/info_tests/qualified/expected/useless_c.elf_stg
@@ -1,18 +1,14 @@
 version: 0x00000002
 root_id: 0x84ea5130  # interface
-special {
-  id: 0x48b5725f
-  kind: VOID
-}
 pointer_reference {
-  id: 0x0dd55c4a
+  id: 0x24b3ee1b
   kind: POINTER
-  pointee_type_id: 0x1d1597b4  # void(const volatile struct foo*)
+  pointee_type_id: 0xb88f5ef1  # struct foo
 }
 pointer_reference {
-  id: 0x24b3ee1b
+  id: 0x2e9370e5
   kind: POINTER
-  pointee_type_id: 0xb88f5ef1  # struct foo
+  pointee_type_id: 0x900d2508  # int(const volatile struct foo*)
 }
 pointer_reference {
   id: 0x3637189c
@@ -20,9 +16,9 @@ pointer_reference {
   pointee_type_id: 0xf29c84ee  # const volatile struct foo
 }
 qualified {
-  id: 0x9763259f
+  id: 0x9fb2aeb4
   qualifier: VOLATILE
-  qualified_type_id: 0x0dd55c4a  # void(*)(const volatile struct foo*)
+  qualified_type_id: 0x2e9370e5  # int(*)(const volatile struct foo*)
 }
 qualified {
   id: 0xba35a531
@@ -35,9 +31,15 @@ qualified {
   qualified_type_id: 0xba35a531  # volatile struct foo
 }
 qualified {
-  id: 0xf9c924c5
+  id: 0xfbfd460f
   qualifier: CONST
-  qualified_type_id: 0x9763259f  # void(* volatile)(const volatile struct foo*)
+  qualified_type_id: 0x9fb2aeb4  # int(* volatile)(const volatile struct foo*)
+}
+primitive {
+  id: 0x6720d32f
+  name: "int"
+  encoding: SIGNED_INTEGER
+  bytesize: 0x00000004
 }
 struct_union {
   id: 0xb88f5ef1
@@ -47,26 +49,26 @@ struct_union {
   }
 }
 function {
-  id: 0x13ed0681
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0x0dd55c4a  # void(*)(const volatile struct foo*)
+  id: 0x900d2508
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x3637189c  # const volatile struct foo*
 }
 function {
-  id: 0x19b4aa15
-  return_type_id: 0x48b5725f  # void
+  id: 0x94ac18a9
+  return_type_id: 0x6720d32f  # int
   parameter_id: 0x24b3ee1b  # struct foo*
 }
 function {
-  id: 0x1d1597b4
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0x3637189c  # const volatile struct foo*
+  id: 0x96243f16
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x2e9370e5  # int(*)(const volatile struct foo*)
 }
 elf_symbol {
   id: 0xa58ca0b6
   name: "bar"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x1d1597b4  # void(const volatile struct foo*)
+  type_id: 0x900d2508  # int(const volatile struct foo*)
   full_name: "bar"
 }
 elf_symbol {
@@ -74,7 +76,7 @@ elf_symbol {
   name: "bar_2"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x19b4aa15  # void(struct foo*)
+  type_id: 0x94ac18a9  # int(struct foo*)
   full_name: "bar_2"
 }
 elf_symbol {
@@ -82,7 +84,7 @@ elf_symbol {
   name: "baz"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x13ed0681  # void(void(*)(const volatile struct foo*))
+  type_id: 0x96243f16  # int(int(*)(const volatile struct foo*))
   full_name: "baz"
 }
 elf_symbol {
@@ -90,13 +92,13 @@ elf_symbol {
   name: "quux"
   is_defined: true
   symbol_type: OBJECT
-  type_id: 0xf9c924c5  # void(* volatile const)(const volatile struct foo*)
+  type_id: 0xfbfd460f  # int(* volatile const)(const volatile struct foo*)
   full_name: "quux"
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0xa58ca0b6  # void bar(const volatile struct foo*)
-  symbol_id: 0xe89bbaac  # void bar_2(struct foo*)
-  symbol_id: 0xbf8fc404  # void baz(void(*)(const volatile struct foo*))
-  symbol_id: 0x4602d7e1  # void(* volatile const quux)(const volatile struct foo*)
+  symbol_id: 0xa58ca0b6  # int bar(const volatile struct foo*)
+  symbol_id: 0xe89bbaac  # int bar_2(struct foo*)
+  symbol_id: 0xbf8fc404  # int baz(int(*)(const volatile struct foo*))
+  symbol_id: 0x4602d7e1  # int(* volatile const quux)(const volatile struct foo*)
 }
diff --git a/test_cases/info_tests/qualified/useless.c b/test_cases/info_tests/qualified/useless.c
index a077d5b..f044239 100644
--- a/test_cases/info_tests/qualified/useless.c
+++ b/test_cases/info_tests/qualified/useless.c
@@ -1,21 +1,19 @@
-void tweak(int);
-
 struct foo {
 };
 
-void bar_2(struct foo* y) {
+int bar_2(struct foo* y) {
   (void) y;
-  tweak(0);
+  return 0;
 }
 
-void bar(const volatile struct foo* y) {
+int bar(const volatile struct foo* y) {
   (void) y;
-  tweak(1);
+  return 1;
 }
 
-void baz(void(*const volatile y)(const volatile struct foo*)) {
+int baz(int(*const volatile y)(const volatile struct foo*)) {
   (void) y;
-  tweak(2);
+  return 2;
 }
 
-void(*const volatile quux)(const volatile struct foo*) = &bar;
+int(*const volatile quux)(const volatile struct foo*) = &bar;
diff --git a/test_cases/info_tests/struct/expected/nested_c.btf_stg b/test_cases/info_tests/struct/expected/nested_c.btf_stg
index 5c41c48..fc7fd63 100644
--- a/test_cases/info_tests/struct/expected/nested_c.btf_stg
+++ b/test_cases/info_tests/struct/expected/nested_c.btf_stg
@@ -1,9 +1,5 @@
 version: 0x00000002
 root_id: 0x84ea5130  # interface
-special {
-  id: 0x48b5725f
-  kind: VOID
-}
 pointer_reference {
   id: 0x12c83f93
   kind: POINTER
@@ -19,6 +15,12 @@ pointer_reference {
   kind: POINTER
   pointee_type_id: 0xe16078fd  # struct referring
 }
+primitive {
+  id: 0x6720d32f
+  name: "int"
+  encoding: SIGNED_INTEGER
+  bytesize: 0x00000004
+}
 primitive {
   id: 0xfc0e1dbd
   name: "long"
@@ -68,23 +70,23 @@ struct_union {
   }
 }
 function {
-  id: 0x01533705
-  return_type_id: 0x48b5725f  # void
+  id: 0x8c4b85b9
+  return_type_id: 0x6720d32f  # int
   parameter_id: 0x472d9a5b  # struct containing
 }
 function {
-  id: 0x164e865f
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0x1b5b5f31  # struct containing*
+  id: 0x9132eac9
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x32c82798  # struct referring*
 }
 function {
-  id: 0x1c2a5875
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0x32c82798  # struct referring*
+  id: 0x9b5634e3
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x1b5b5f31  # struct containing*
 }
 function {
-  id: 0x28c04fac
-  return_type_id: 0x48b5725f  # void
+  id: 0xa5d8fd10
+  return_type_id: 0x6720d32f  # int
   parameter_id: 0xe16078fd  # struct referring
 }
 elf_symbol {
@@ -92,33 +94,33 @@ elf_symbol {
   name: "register_ops6"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x01533705  # void(struct containing)
+  type_id: 0x8c4b85b9  # int(struct containing)
 }
 elf_symbol {
   id: 0x68a86d39
   name: "register_ops7"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x164e865f  # void(struct containing*)
+  type_id: 0x9b5634e3  # int(struct containing*)
 }
 elf_symbol {
   id: 0x1f6abcc7
   name: "register_ops8"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x28c04fac  # void(struct referring)
+  type_id: 0xa5d8fd10  # int(struct referring)
 }
 elf_symbol {
   id: 0xdc2ac9cf
   name: "register_ops9"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x1c2a5875  # void(struct referring*)
+  type_id: 0x9132eac9  # int(struct referring*)
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0x97e8ca66  # void register_ops6(struct containing)
-  symbol_id: 0x68a86d39  # void register_ops7(struct containing*)
-  symbol_id: 0x1f6abcc7  # void register_ops8(struct referring)
-  symbol_id: 0xdc2ac9cf  # void register_ops9(struct referring*)
+  symbol_id: 0x97e8ca66  # int register_ops6(struct containing)
+  symbol_id: 0x68a86d39  # int register_ops7(struct containing*)
+  symbol_id: 0x1f6abcc7  # int register_ops8(struct referring)
+  symbol_id: 0xdc2ac9cf  # int register_ops9(struct referring*)
 }
diff --git a/test_cases/info_tests/struct/expected/nested_c.elf_stg b/test_cases/info_tests/struct/expected/nested_c.elf_stg
index 28fd1ee..f2c2d35 100644
--- a/test_cases/info_tests/struct/expected/nested_c.elf_stg
+++ b/test_cases/info_tests/struct/expected/nested_c.elf_stg
@@ -1,9 +1,5 @@
 version: 0x00000002
 root_id: 0x84ea5130  # interface
-special {
-  id: 0x48b5725f
-  kind: VOID
-}
 pointer_reference {
   id: 0x12c83f93
   kind: POINTER
@@ -19,6 +15,12 @@ pointer_reference {
   kind: POINTER
   pointee_type_id: 0xe16078fd  # struct referring
 }
+primitive {
+  id: 0x6720d32f
+  name: "int"
+  encoding: SIGNED_INTEGER
+  bytesize: 0x00000004
+}
 primitive {
   id: 0xfc0e1dbd
   name: "long"
@@ -68,23 +70,23 @@ struct_union {
   }
 }
 function {
-  id: 0x01533705
-  return_type_id: 0x48b5725f  # void
+  id: 0x8c4b85b9
+  return_type_id: 0x6720d32f  # int
   parameter_id: 0x472d9a5b  # struct containing
 }
 function {
-  id: 0x164e865f
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0x1b5b5f31  # struct containing*
+  id: 0x9132eac9
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x32c82798  # struct referring*
 }
 function {
-  id: 0x1c2a5875
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0x32c82798  # struct referring*
+  id: 0x9b5634e3
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x1b5b5f31  # struct containing*
 }
 function {
-  id: 0x28c04fac
-  return_type_id: 0x48b5725f  # void
+  id: 0xa5d8fd10
+  return_type_id: 0x6720d32f  # int
   parameter_id: 0xe16078fd  # struct referring
 }
 elf_symbol {
@@ -92,7 +94,7 @@ elf_symbol {
   name: "register_ops6"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x01533705  # void(struct containing)
+  type_id: 0x8c4b85b9  # int(struct containing)
   full_name: "register_ops6"
 }
 elf_symbol {
@@ -100,7 +102,7 @@ elf_symbol {
   name: "register_ops7"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x164e865f  # void(struct containing*)
+  type_id: 0x9b5634e3  # int(struct containing*)
   full_name: "register_ops7"
 }
 elf_symbol {
@@ -108,7 +110,7 @@ elf_symbol {
   name: "register_ops8"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x28c04fac  # void(struct referring)
+  type_id: 0xa5d8fd10  # int(struct referring)
   full_name: "register_ops8"
 }
 elf_symbol {
@@ -116,13 +118,13 @@ elf_symbol {
   name: "register_ops9"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x1c2a5875  # void(struct referring*)
+  type_id: 0x9132eac9  # int(struct referring*)
   full_name: "register_ops9"
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0x97e8ca66  # void register_ops6(struct containing)
-  symbol_id: 0x68a86d39  # void register_ops7(struct containing*)
-  symbol_id: 0x1f6abcc7  # void register_ops8(struct referring)
-  symbol_id: 0xdc2ac9cf  # void register_ops9(struct referring*)
+  symbol_id: 0x97e8ca66  # int register_ops6(struct containing)
+  symbol_id: 0x68a86d39  # int register_ops7(struct containing*)
+  symbol_id: 0x1f6abcc7  # int register_ops8(struct referring)
+  symbol_id: 0xdc2ac9cf  # int register_ops9(struct referring*)
 }
diff --git a/test_cases/info_tests/struct/expected/nested_cc.elf_stg b/test_cases/info_tests/struct/expected/nested_cc.elf_stg
index 6e0fa99..06fd04c 100644
--- a/test_cases/info_tests/struct/expected/nested_cc.elf_stg
+++ b/test_cases/info_tests/struct/expected/nested_cc.elf_stg
@@ -1,9 +1,5 @@
 version: 0x00000002
 root_id: 0x84ea5130  # interface
-special {
-  id: 0x48b5725f
-  kind: VOID
-}
 pointer_reference {
   id: 0x12c83f93
   kind: POINTER
@@ -19,6 +15,12 @@ pointer_reference {
   kind: POINTER
   pointee_type_id: 0xe16078fd  # struct referring
 }
+primitive {
+  id: 0x6720d32f
+  name: "int"
+  encoding: SIGNED_INTEGER
+  bytesize: 0x00000004
+}
 primitive {
   id: 0xfc0e1dbd
   name: "long"
@@ -68,23 +70,23 @@ struct_union {
   }
 }
 function {
-  id: 0x01533705
-  return_type_id: 0x48b5725f  # void
+  id: 0x8c4b85b9
+  return_type_id: 0x6720d32f  # int
   parameter_id: 0x472d9a5b  # struct containing
 }
 function {
-  id: 0x164e865f
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0x1b5b5f31  # struct containing*
+  id: 0x9132eac9
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x32c82798  # struct referring*
 }
 function {
-  id: 0x1c2a5875
-  return_type_id: 0x48b5725f  # void
-  parameter_id: 0x32c82798  # struct referring*
+  id: 0x9b5634e3
+  return_type_id: 0x6720d32f  # int
+  parameter_id: 0x1b5b5f31  # struct containing*
 }
 function {
-  id: 0x28c04fac
-  return_type_id: 0x48b5725f  # void
+  id: 0xa5d8fd10
+  return_type_id: 0x6720d32f  # int
   parameter_id: 0xe16078fd  # struct referring
 }
 elf_symbol {
@@ -92,7 +94,7 @@ elf_symbol {
   name: "_Z13register_ops610containing"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x01533705  # void(struct containing)
+  type_id: 0x8c4b85b9  # int(struct containing)
   full_name: "register_ops6"
 }
 elf_symbol {
@@ -100,7 +102,7 @@ elf_symbol {
   name: "_Z13register_ops7P10containing"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x164e865f  # void(struct containing*)
+  type_id: 0x9b5634e3  # int(struct containing*)
   full_name: "register_ops7"
 }
 elf_symbol {
@@ -108,7 +110,7 @@ elf_symbol {
   name: "_Z13register_ops89referring"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x28c04fac  # void(struct referring)
+  type_id: 0xa5d8fd10  # int(struct referring)
   full_name: "register_ops8"
 }
 elf_symbol {
@@ -116,13 +118,13 @@ elf_symbol {
   name: "_Z13register_ops9P9referring"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x1c2a5875  # void(struct referring*)
+  type_id: 0x9132eac9  # int(struct referring*)
   full_name: "register_ops9"
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0x347b0ec1  # void register_ops6(struct containing)
-  symbol_id: 0xcc14c364  # void register_ops7(struct containing*)
-  symbol_id: 0xe408ab24  # void register_ops8(struct referring)
-  symbol_id: 0x9d450b2c  # void register_ops9(struct referring*)
+  symbol_id: 0x347b0ec1  # int register_ops6(struct containing)
+  symbol_id: 0xcc14c364  # int register_ops7(struct containing*)
+  symbol_id: 0xe408ab24  # int register_ops8(struct referring)
+  symbol_id: 0x9d450b2c  # int register_ops9(struct referring*)
 }
diff --git a/test_cases/info_tests/struct/nested.c b/test_cases/info_tests/struct/nested.c
index 003207c..bd30e5f 100644
--- a/test_cases/info_tests/struct/nested.c
+++ b/test_cases/info_tests/struct/nested.c
@@ -10,8 +10,7 @@ struct referring {
   struct nested * inner;
 };
 
-void tweak(int);
-void register_ops6(struct containing y) { (void) y; tweak(6); }
-void register_ops7(struct containing* y) { (void) y; tweak(7); }
-void register_ops8(struct referring y) { (void) y; tweak(8); }
-void register_ops9(struct referring* y) { (void) y; tweak(9); }
+int register_ops6(struct containing y) { (void) y; return 6; }
+int register_ops7(struct containing* y) { (void) y; return 7; }
+int register_ops8(struct referring y) { (void) y; return 8; }
+int register_ops9(struct referring* y) { (void) y; return 9; }
diff --git a/test_cases/info_tests/struct/nested.cc b/test_cases/info_tests/struct/nested.cc
index 7c986de..8c6ff89 100644
--- a/test_cases/info_tests/struct/nested.cc
+++ b/test_cases/info_tests/struct/nested.cc
@@ -10,8 +10,7 @@ struct referring {
   struct nested * inner;
 };
 
-void tweak(int);
-void register_ops6(containing) { tweak(6); }
-void register_ops7(containing*) { tweak(7); }
-void register_ops8(referring) { tweak(8); }
-void register_ops9(referring*) { tweak(9); }
+int register_ops6(containing) { return 6; }
+int register_ops7(containing*) { return 7; }
+int register_ops8(referring) { return 8; }
+int register_ops9(referring*) { return 9; }
diff --git a/test_cases/info_tests/symbol/expected/version_definition_c.elf_stg b/test_cases/info_tests/symbol/expected/version_definition_c.elf_stg
index 5a80408..2215c46 100644
--- a/test_cases/info_tests/symbol/expected/version_definition_c.elf_stg
+++ b/test_cases/info_tests/symbol/expected/version_definition_c.elf_stg
@@ -1,19 +1,11 @@
 version: 0x00000002
 root_id: 0x84ea5130  # interface
-special {
-  id: 0x48b5725f
-  kind: VOID
-}
 primitive {
   id: 0x6720d32f
   name: "int"
   encoding: SIGNED_INTEGER
   bytesize: 0x00000004
 }
-function {
-  id: 0x10985193
-  return_type_id: 0x48b5725f  # void
-}
 function {
   id: 0x9d80e32f
   return_type_id: 0x6720d32f  # int
@@ -31,7 +23,7 @@ elf_symbol {
   name: "versioned_foo"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
   full_name: "versioned_foo"
 }
 elf_symbol {
@@ -39,7 +31,7 @@ elf_symbol {
   name: "versioned_foo_v1"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
   full_name: "versioned_foo_v1"
 }
 elf_symbol {
@@ -47,7 +39,7 @@ elf_symbol {
   name: "versioned_foo_v2"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
   full_name: "versioned_foo_v2"
 }
 elf_symbol {
@@ -55,14 +47,14 @@ elf_symbol {
   name: "versioned_foo_v3"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
   full_name: "versioned_foo_v3"
 }
 interface {
   id: 0x84ea5130
   symbol_id: 0x886f3c7a  # int test()
-  symbol_id: 0x48a2620a  # void versioned_foo()
-  symbol_id: 0xc828cd97  # void versioned_foo_v1()
-  symbol_id: 0x77e76a1f  # void versioned_foo_v2()
-  symbol_id: 0x36a79a97  # void versioned_foo_v3()
+  symbol_id: 0x48a2620a  # int versioned_foo()
+  symbol_id: 0xc828cd97  # int versioned_foo_v1()
+  symbol_id: 0x77e76a1f  # int versioned_foo_v2()
+  symbol_id: 0x36a79a97  # int versioned_foo_v3()
 }
diff --git a/test_cases/info_tests/symbol/expected/visibility_c.btf_stg b/test_cases/info_tests/symbol/expected/visibility_c.btf_stg
index 0bdc7f0..c1c0aef 100644
--- a/test_cases/info_tests/symbol/expected/visibility_c.btf_stg
+++ b/test_cases/info_tests/symbol/expected/visibility_c.btf_stg
@@ -1,45 +1,47 @@
 version: 0x00000002
 root_id: 0x84ea5130  # interface
-special {
-  id: 0x48b5725f
-  kind: VOID
+primitive {
+  id: 0x6720d32f
+  name: "int"
+  encoding: SIGNED_INTEGER
+  bytesize: 0x00000004
 }
 function {
-  id: 0x10985193
-  return_type_id: 0x48b5725f  # void
+  id: 0x9d80e32f
+  return_type_id: 0x6720d32f  # int
 }
 elf_symbol {
   id: 0xa7b0241d
   name: "a"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
 }
 elf_symbol {
   id: 0xe371117a
   name: "b"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
 }
 elf_symbol {
   id: 0x2230fb28
   name: "c"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
 }
 elf_symbol {
   id: 0x63f6f9b1
   name: "d"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0xa7b0241d  # void a()
-  symbol_id: 0xe371117a  # void b()
-  symbol_id: 0x2230fb28  # void c()
-  symbol_id: 0x63f6f9b1  # void d()
+  symbol_id: 0xa7b0241d  # int a()
+  symbol_id: 0xe371117a  # int b()
+  symbol_id: 0x2230fb28  # int c()
+  symbol_id: 0x63f6f9b1  # int d()
 }
diff --git a/test_cases/info_tests/symbol/expected/visibility_c.elf_stg b/test_cases/info_tests/symbol/expected/visibility_c.elf_stg
index eec44c6..a0a86e7 100644
--- a/test_cases/info_tests/symbol/expected/visibility_c.elf_stg
+++ b/test_cases/info_tests/symbol/expected/visibility_c.elf_stg
@@ -1,19 +1,21 @@
 version: 0x00000002
 root_id: 0x84ea5130  # interface
-special {
-  id: 0x48b5725f
-  kind: VOID
+primitive {
+  id: 0x6720d32f
+  name: "int"
+  encoding: SIGNED_INTEGER
+  bytesize: 0x00000004
 }
 function {
-  id: 0x10985193
-  return_type_id: 0x48b5725f  # void
+  id: 0x9d80e32f
+  return_type_id: 0x6720d32f  # int
 }
 elf_symbol {
   id: 0xa7b0241d
   name: "a"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
   full_name: "a"
 }
 elf_symbol {
@@ -22,11 +24,11 @@ elf_symbol {
   is_defined: true
   symbol_type: FUNCTION
   visibility: PROTECTED
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
   full_name: "b"
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0xa7b0241d  # void a()
-  symbol_id: 0xe371117a  # void b()
+  symbol_id: 0xa7b0241d  # int a()
+  symbol_id: 0xe371117a  # int b()
 }
diff --git a/test_cases/info_tests/symbol/expected/visibility_cc.elf_stg b/test_cases/info_tests/symbol/expected/visibility_cc.elf_stg
index 5b6960d..6b445f5 100644
--- a/test_cases/info_tests/symbol/expected/visibility_cc.elf_stg
+++ b/test_cases/info_tests/symbol/expected/visibility_cc.elf_stg
@@ -1,19 +1,21 @@
 version: 0x00000002
 root_id: 0x84ea5130  # interface
-special {
-  id: 0x48b5725f
-  kind: VOID
+primitive {
+  id: 0x6720d32f
+  name: "int"
+  encoding: SIGNED_INTEGER
+  bytesize: 0x00000004
 }
 function {
-  id: 0x10985193
-  return_type_id: 0x48b5725f  # void
+  id: 0x9d80e32f
+  return_type_id: 0x6720d32f  # int
 }
 elf_symbol {
   id: 0x60468be1
   name: "_Z1av"
   is_defined: true
   symbol_type: FUNCTION
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
   full_name: "a"
 }
 elf_symbol {
@@ -22,11 +24,11 @@ elf_symbol {
   is_defined: true
   symbol_type: FUNCTION
   visibility: PROTECTED
-  type_id: 0x10985193  # void()
+  type_id: 0x9d80e32f  # int()
   full_name: "b"
 }
 interface {
   id: 0x84ea5130
-  symbol_id: 0x60468be1  # void a()
-  symbol_id: 0xfe73b6f7  # void b()
+  symbol_id: 0x60468be1  # int a()
+  symbol_id: 0xfe73b6f7  # int b()
 }
diff --git a/test_cases/info_tests/symbol/version_definition.c b/test_cases/info_tests/symbol/version_definition.c
index af87429..57dc203 100644
--- a/test_cases/info_tests/symbol/version_definition.c
+++ b/test_cases/info_tests/symbol/version_definition.c
@@ -4,18 +4,16 @@
 // produce wrong results.
 // TODO: remove statement above after support is implemented
 
-void tweak(int dummy);
-
-void versioned_foo(void) { tweak(1); }
+int versioned_foo(void) { return 1; }
 
 __asm__(".symver versioned_foo_v1, versioned_foo@@VERS_1");
-void versioned_foo_v1(void) { tweak(2); }
+int versioned_foo_v1(void) { return 2; }
 
 __asm__(".symver versioned_foo_v2, versioned_foo@VERS_2");
-void versioned_foo_v2(void) { tweak(3); }
+int versioned_foo_v2(void) { return 3; }
 
 __asm__(".symver versioned_foo_v3, versioned_foo@VERS_3");
-void versioned_foo_v3(void) { tweak(4); }
+int versioned_foo_v3(void) { return 4; }
 
 // Using a libc function helps to add the "version needs" section
 // in addition to the "version definitions". This helps to catch
diff --git a/test_cases/info_tests/symbol/visibility.c b/test_cases/info_tests/symbol/visibility.c
index 45fcbb5..13dfa0c 100644
--- a/test_cases/info_tests/symbol/visibility.c
+++ b/test_cases/info_tests/symbol/visibility.c
@@ -1,5 +1,4 @@
-void tweak(int);
-__attribute__ ((visibility ("default"))) void a() { tweak(0); }
-__attribute__ ((visibility ("protected"))) void b() { tweak(1); }
-__attribute__ ((visibility ("hidden"))) void c() { tweak(2); }
-__attribute__ ((visibility ("internal"))) void d() { tweak(3); }
+__attribute__ ((visibility ("default"))) int a() { return 0; }
+__attribute__ ((visibility ("protected"))) int b() { return 1; }
+__attribute__ ((visibility ("hidden"))) int c() { return 2; }
+__attribute__ ((visibility ("internal"))) int d() { return 3; }
diff --git a/test_cases/info_tests/symbol/visibility.cc b/test_cases/info_tests/symbol/visibility.cc
index 45fcbb5..13dfa0c 100644
--- a/test_cases/info_tests/symbol/visibility.cc
+++ b/test_cases/info_tests/symbol/visibility.cc
@@ -1,5 +1,4 @@
-void tweak(int);
-__attribute__ ((visibility ("default"))) void a() { tweak(0); }
-__attribute__ ((visibility ("protected"))) void b() { tweak(1); }
-__attribute__ ((visibility ("hidden"))) void c() { tweak(2); }
-__attribute__ ((visibility ("internal"))) void d() { tweak(3); }
+__attribute__ ((visibility ("default"))) int a() { return 0; }
+__attribute__ ((visibility ("protected"))) int b() { return 1; }
+__attribute__ ((visibility ("hidden"))) int c() { return 2; }
+__attribute__ ((visibility ("internal"))) int d() { return 3; }
diff --git a/test_cases/info_tests/variant/optional_empty.rs b/test_cases/info_tests/variant/optional_empty.rs
index 1cda07c..f1552c5 100644
--- a/test_cases/info_tests/variant/optional_empty.rs
+++ b/test_cases/info_tests/variant/optional_empty.rs
@@ -4,6 +4,5 @@ pub enum Empty {}
 pub fn is_none(opt: Option<Empty>) -> bool {
     match opt {
         None => true,
-        _ => false,
     }
 }
diff --git a/type_normalisation.cc b/type_normalisation.cc
index 292957b..e5d4a25 100644
--- a/type_normalisation.cc
+++ b/type_normalisation.cc
@@ -206,7 +206,7 @@ struct RemoveFunctionQualifiers {
     const auto it = resolved.find(id);
     if (it != resolved.end()) {
       id = it->second;
-      Check(!resolved.count(id)) << "qualifier was resolved to qualifier";
+      Check(!resolved.contains(id)) << "qualifier was resolved to qualifier";
     }
   }
 
@@ -216,7 +216,7 @@ struct RemoveFunctionQualifiers {
 
 }  // namespace
 
-void RemoveUselessQualifiers(Graph& graph, Id root) {
+Id RemoveUselessQualifiers(Graph& graph, Id root) {
   std::unordered_map<Id, Id> resolved;
   std::unordered_set<Id> functions;
   FindQualifiedTypesAndFunctions(graph, resolved, functions)(root);
@@ -225,6 +225,7 @@ void RemoveUselessQualifiers(Graph& graph, Id root) {
   for (const auto& id : functions) {
     remove_qualifiers(id);
   }
+  return root;
 }
 
 }  // namespace stg
diff --git a/type_normalisation.h b/type_normalisation.h
index 6bd4362..953b800 100644
--- a/type_normalisation.h
+++ b/type_normalisation.h
@@ -24,7 +24,7 @@
 
 namespace stg {
 
-void RemoveUselessQualifiers(Graph& graph, Id root);
+Id RemoveUselessQualifiers(Graph& graph, Id root);
 
 }  // namespace stg
 
```

