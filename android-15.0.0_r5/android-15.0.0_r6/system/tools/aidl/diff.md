```diff
diff --git a/Android.bp b/Android.bp
index bdd90b13..b69ea472 100644
--- a/Android.bp
+++ b/Android.bp
@@ -311,6 +311,7 @@ cc_library_headers {
     name: "libandroid_aidltrace",
     host_supported: true,
     vendor_available: true,
+    product_available: true,
     export_include_dirs: ["trace"],
     apex_available: [
         "//apex_available:platform",
diff --git a/aidl_language.cpp b/aidl_language.cpp
index 6ebc9fde..18fb290d 100644
--- a/aidl_language.cpp
+++ b/aidl_language.cpp
@@ -1523,7 +1523,8 @@ bool AidlStructuredParcelable::CheckValid(const AidlTypenames& typenames) const
 bool AidlTypeSpecifier::LanguageSpecificCheckValid(Options::Language lang) const {
   if (this->GetName() == "FileDescriptor" &&
       (lang == Options::Language::NDK || lang == Options::Language::RUST)) {
-    AIDL_ERROR(this) << "FileDescriptor isn't supported by the " << to_string(lang) << " backend.";
+    AIDL_ERROR(this) << "FileDescriptor isn't supported by the "
+        << to_string(lang) << " backend. Prefer ParcelFileDescriptor.";
     return false;
   }
 
diff --git a/build/Android.bp b/build/Android.bp
index c5b32177..f0aa60b0 100644
--- a/build/Android.bp
+++ b/build/Android.bp
@@ -314,7 +314,7 @@ aidl_interface {
 
 cc_test_library {
     name: "client-using-test-piece-3",
-    srcs: ["client-using-test-piece-3.cpp"],
+    srcs: ["client-using-test-piece-3/client-using-test-piece-3.cpp"],
     shared_libs: ["test-piece-3-V2-cpp"],
 }
 
@@ -414,7 +414,7 @@ aidl_interface {
 
 cc_library {
     name: "build_test_aidl_always_use_unfrozen",
-    srcs: ["test_unfrozen_iface.cpp"],
+    srcs: ["test_unfrozen_iface/test_unfrozen_iface.cpp"],
     shared_libs: [
         "tests-unfrozen-vendor-V2-cpp",
     ],
diff --git a/build/aidl_api.go b/build/aidl_api.go
index 210c0330..9bf117fd 100644
--- a/build/aidl_api.go
+++ b/build/aidl_api.go
@@ -340,7 +340,7 @@ func (m *aidlApi) makeApiDumpAsVersion(ctx android.ModuleContext, dump apiDump,
 		m.migrateAndAppendVersion(ctx, rb, &version, transitive)
 	} else {
 		actionWord = "Updating"
-		if m.isFrozen() {
+		if !m.isExplicitlyUnFrozen() {
 			rb.Command().BuiltTool("bpmodify").
 				Text("-w -m " + m.properties.BaseName).
 				Text("-parameter frozen -set-bool false").
@@ -354,6 +354,7 @@ func (m *aidlApi) makeApiDumpAsVersion(ctx android.ModuleContext, dump apiDump,
 	}
 
 	timestampFile := android.PathForModuleOut(ctx, "update_or_freeze_api_"+version+".timestamp")
+	rb.SetPhonyOutput()
 	// explicitly don't touch timestamp, so that the command can be run repeatedly
 	rb.Command().Text("true").ImplicitOutput(timestampFile)
 
diff --git a/build/aidl_gen_rule.go b/build/aidl_gen_rule.go
index b9890e34..b0c32631 100644
--- a/build/aidl_gen_rule.go
+++ b/build/aidl_gen_rule.go
@@ -71,6 +71,11 @@ var (
 		Restat:      true,
 		Description: "AIDL Rust ${in}",
 	}, "imports", "nextImports", "outDir", "optionalFlags")
+
+	aidlPhonyRule = pctx.StaticRule("aidlPhonyRule", blueprint.RuleParams{
+		Command:     `touch ${out}`,
+		Description: "create ${out}",
+	})
 )
 
 type aidlGenProperties struct {
@@ -87,6 +92,7 @@ type aidlGenProperties struct {
 	Version             string
 	GenRpc              bool
 	GenTrace            bool
+	GenMockall          bool
 	Unstable            *bool
 	NotFrozen           bool
 	RequireFrozenReason string
@@ -163,7 +169,7 @@ func (g *aidlGenRule) GenerateAndroidBuildActions(ctx android.ModuleContext) {
 
 	// This is to trigger genrule alone
 	ctx.Build(pctx, android.BuildParams{
-		Rule:   android.Phony,
+		Rule:   aidlPhonyRule,
 		Output: android.PathForModuleOut(ctx, "timestamp"), // $out/timestamp
 		Inputs: g.genOutputs.Paths(),
 	})
@@ -222,6 +228,9 @@ func (g *aidlGenRule) generateBuildActionsForSingleAidl(ctx android.ModuleContex
 	if g.properties.GenTrace {
 		optionalFlags = append(optionalFlags, "-t")
 	}
+	if g.properties.GenMockall {
+		optionalFlags = append(optionalFlags, "--mockall")
+	}
 	if g.properties.Stability != nil {
 		optionalFlags = append(optionalFlags, "--stability", *g.properties.Stability)
 	}
diff --git a/build/aidl_interface.go b/build/aidl_interface.go
index 4bb8dc6b..5f5d6685 100644
--- a/build/aidl_interface.go
+++ b/build/aidl_interface.go
@@ -64,14 +64,14 @@ func init() {
 func registerPreArchMutators(ctx android.RegisterMutatorsContext) {
 	ctx.BottomUp("addInterfaceDeps", addInterfaceDeps).Parallel()
 	ctx.BottomUp("checkImports", checkImports).Parallel()
-	ctx.TopDown("createAidlInterface", createAidlInterfaceMutator).Parallel()
+	ctx.BottomUp("createAidlInterface", createAidlInterfaceMutator).Parallel()
 }
 
 func registerPostDepsMutators(ctx android.RegisterMutatorsContext) {
 	ctx.BottomUp("checkAidlGeneratedModules", checkAidlGeneratedModules).Parallel()
 }
 
-func createAidlInterfaceMutator(mctx android.TopDownMutatorContext) {
+func createAidlInterfaceMutator(mctx android.BottomUpMutatorContext) {
 	if g, ok := mctx.Module().(*aidlImplementationGenerator); ok {
 		g.GenerateImplementation(mctx)
 	}
@@ -424,6 +424,9 @@ type aidlInterfaceProperties struct {
 
 			// Rustlibs needed for unstructured parcelables.
 			Additional_rustlibs []string
+
+			// Generate mockall mocks of AIDL interfaces.
+			Gen_mockall *bool
 		}
 	}
 
diff --git a/build/aidl_interface_backends.go b/build/aidl_interface_backends.go
index 59a17f13..ac854f13 100644
--- a/build/aidl_interface_backends.go
+++ b/build/aidl_interface_backends.go
@@ -107,12 +107,6 @@ func addCppLibrary(mctx android.DefaultableHookContext, i *aidlInterface, versio
 		nonAppProps := imageProperties{
 			Cflags: []string{"-DBINDER_STABILITY_SUPPORT"},
 		}
-		if genTrace {
-			sharedLibDependency = append(sharedLibDependency, "libandroid")
-			nonAppProps.Exclude_shared_libs = []string{"libandroid"}
-			nonAppProps.Header_libs = []string{"libandroid_aidltrace"}
-			nonAppProps.Shared_libs = []string{"libcutils"}
-		}
 		targetProp.Platform = nonAppProps
 		targetProp.Vendor = nonAppProps
 		targetProp.Product = nonAppProps
@@ -359,6 +353,7 @@ func addJavaLibrary(mctx android.DefaultableHookContext, i *aidlInterface, versi
 				Apex_available:  i.properties.Backend.Java.Apex_available,
 				Min_sdk_version: i.minSdkVersion(langJava),
 				Static_libs:     i.properties.Backend.Java.Additional_libs,
+				Is_stubs_module: proptools.BoolPtr(true),
 			},
 			&i.properties.Backend.Java.LintProperties,
 		},
@@ -395,6 +390,7 @@ func addRustLibrary(mctx android.DefaultableHookContext, i *aidlInterface, versi
 		RequireFrozenReason: requireFrozenReason,
 		Flags:               i.flagsForAidlGenRule(version),
 		UseUnfrozen:         i.useUnfrozen(mctx),
+		GenMockall:          proptools.Bool(i.properties.Backend.Rust.Gen_mockall),
 	})
 
 	versionedRustName := fixRustName(i.versionedName(version))
@@ -539,7 +535,7 @@ func (g *aidlImplementationGenerator) DepsMutator(ctx android.BottomUpMutatorCon
 func (g *aidlImplementationGenerator) GenerateAndroidBuildActions(ctx android.ModuleContext) {
 }
 
-func (g *aidlImplementationGenerator) GenerateImplementation(ctx android.TopDownMutatorContext) {
+func (g *aidlImplementationGenerator) GenerateImplementation(ctx android.BottomUpMutatorContext) {
 	imports := wrap("", getImportsWithVersion(ctx, g.properties.AidlInterfaceName, g.properties.Version), "-"+g.properties.Lang)
 	if g.properties.Lang == langJava {
 		if p, ok := g.properties.ModuleProperties[0].(*javaProperties); ok {
diff --git a/build/aidl_test.go b/build/aidl_test.go
index 7c126466..9c523581 100644
--- a/build/aidl_test.go
+++ b/build/aidl_test.go
@@ -1141,14 +1141,7 @@ func TestNativeOutputIsAlwaysVersioned(t *testing.T) {
 	var ctx *android.TestContext
 	assertOutput := func(moduleName, variant, outputFilename string) {
 		t.Helper()
-		producer, ok := ctx.ModuleForTests(moduleName, variant).Module().(android.OutputFileProducer)
-		if !ok {
-			t.Errorf("%s(%s): should be OutputFileProducer.", moduleName, variant)
-		}
-		paths, err := producer.OutputFiles("")
-		if err != nil {
-			t.Errorf("%s(%s): failed to get OutputFiles: %v", moduleName, variant, err)
-		}
+		paths := ctx.ModuleForTests(moduleName, variant).OutputFiles(ctx, t, "")
 		if len(paths) != 1 || paths[0].Base() != outputFilename {
 			t.Errorf("%s(%s): expected output %q, but got %v", moduleName, variant, outputFilename, paths)
 		}
diff --git a/build/client-using-test-piece-3.cpp b/build/client-using-test-piece-3/client-using-test-piece-3.cpp
similarity index 100%
rename from build/client-using-test-piece-3.cpp
rename to build/client-using-test-piece-3/client-using-test-piece-3.cpp
diff --git a/build/go.mod b/build/go.mod
index e1cd04e2..accec4a2 100644
--- a/build/go.mod
+++ b/build/go.mod
@@ -1,35 +1,8 @@
 module android/soong/aidl
 
-go 1.21
+go 1.22
 
 require (
 	android/soong v0.0.0
 	github.com/google/blueprint v0.0.0
 )
-
-require (
-	go.starlark.net v0.0.0 // indirect
-	google.golang.org/protobuf v1.25.0 // indirect
-	prebuilts/bazel/common/proto/analysis_v2 v0.0.0 // indirect
-	prebuilts/bazel/common/proto/build v0.0.0 // indirect
-)
-
-replace android/soong v0.0.0 => ../../../../build/soong
-
-replace google.golang.org/protobuf v0.0.0 => ../../../../external/golang-protobuf
-
-replace github.com/google/blueprint v0.0.0 => ../../../../build/blueprint
-
-// Indirect deps from golang-protobuf
-exclude github.com/golang/protobuf v1.5.0
-
-replace github.com/google/go-cmp v0.5.5 => ../../../../external/go-cmp
-
-// Indirect dep from go-cmp
-exclude golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543
-
-replace prebuilts/bazel/common/proto/analysis_v2 v0.0.0 => ../../../../prebuilts/bazel/common/proto/analysis_v2
-
-replace prebuilts/bazel/common/proto/build v0.0.0 => ../../../../prebuilts/bazel/common/proto/build
-
-replace go.starlark.net v0.0.0 => ../../../../external/starlark-go
diff --git a/build/go.work b/build/go.work
new file mode 100644
index 00000000..3d6211f9
--- /dev/null
+++ b/build/go.work
@@ -0,0 +1,14 @@
+go 1.22
+
+use (
+	.
+	../../../../build/soong
+	../../../../build/blueprint
+	../../../../external/golang-protobuf
+)
+
+replace (
+	github.com/golang/protobuf v0.0.0 => ../../../../external/golang-protobuf
+	github.com/google/blueprint v0.0.0 => ../../../../build/blueprint
+    android/soong v0.0.0 => ../../../../build/sooong
+)
diff --git a/build/properties.go b/build/properties.go
index f7301424..5a09b2bc 100644
--- a/build/properties.go
+++ b/build/properties.go
@@ -91,6 +91,7 @@ type javaProperties struct {
 	Static_libs     []string
 	Apex_available  []string
 	Min_sdk_version *string
+	Is_stubs_module *bool
 }
 
 type rustProperties struct {
diff --git a/build/test_unfrozen_iface.cpp b/build/test_unfrozen_iface/test_unfrozen_iface.cpp
similarity index 100%
rename from build/test_unfrozen_iface.cpp
rename to build/test_unfrozen_iface/test_unfrozen_iface.cpp
diff --git a/generate_java_binder.cpp b/generate_java_binder.cpp
index 0c3ca385..343cbd6a 100644
--- a/generate_java_binder.cpp
+++ b/generate_java_binder.cpp
@@ -609,7 +609,11 @@ static void GenerateStubCode(const AidlMethod& method, bool oneway,
           // dynamic array should be created with a passed length.
           string var_length = v->name + "_length";
           (*writer) << "int " << var_length << " = data.readInt();\n";
-          (*writer) << "if (" << var_length << " < 0) {\n";
+          // if impossibly large array requested, return false
+          (*writer) << "if (" << var_length << " > 1000000) {\n";
+          (*writer) << "  throw new android.os.BadParcelableException(\"Array too large: \" + "
+                    << var_length << ");\n";
+          (*writer) << "} else if (" << var_length << " < 0) {\n";
           (*writer) << "  " << v->name << " = null;\n";
           (*writer) << "} else {\n";
           (*writer) << "  " << v->name << " = new " << java_type << "[" << var_length << "];\n";
diff --git a/generate_ndk.cpp b/generate_ndk.cpp
index bee83252..a036eeab 100644
--- a/generate_ndk.cpp
+++ b/generate_ndk.cpp
@@ -297,9 +297,6 @@ void GenerateHeaderIncludes(CodeWriter& out, const AidlTypenames& types,
       // So we need includes for client/server class as well.
       if (interface.GetParentType()) {
         includes.insert("android/binder_ibinder.h");
-        if (options.GenTraces()) {
-          includes.insert("android/trace.h");
-        }
       }
     }
 
@@ -405,19 +402,6 @@ static void GenerateSourceIncludes(CodeWriter& out, const AidlTypenames& types,
     out << "#include <" << inc << ">\n";
   }
   out << "\n";
-
-  // Emit additional definition for gen_traces
-  if (v.has_interface && options.GenTraces()) {
-    out << "namespace {\n";
-    out << "struct ScopedTrace {\n";
-    out.Indent();
-    out << "inline explicit ScopedTrace(const char* name) { ATrace_beginSection(name); }\n";
-    out << "inline ~ScopedTrace() { ATrace_endSection(); }\n";
-    out.Dedent();
-    out << "};\n";
-    out << "}  // namespace\n";
-    out << "\n";
-  }
 }
 
 static void GenerateConstantDeclarations(CodeWriter& out, const AidlTypenames& types,
@@ -510,11 +494,6 @@ static void GenerateClientMethodDefinition(CodeWriter& out, const AidlTypenames&
   if (options.GenLog()) {
     out << cpp::GenLogBeforeExecute(q_name, method, false /* isServer */, true /* isNdk */);
   }
-  if (options.GenTraces()) {
-    out << "ScopedTrace _aidl_trace(\"AIDL::" << to_string(options.TargetLanguage())
-        << "::" << ClassName(defined_type, ClassNames::INTERFACE) << "::" << method.GetName()
-        << "::client\");\n";
-  }
 
   if (method.IsNew() && ShouldForceDowngradeFor(CommunicationSide::WRITE) &&
       method.IsUserDefined()) {
@@ -524,7 +503,8 @@ static void GenerateClientMethodDefinition(CodeWriter& out, const AidlTypenames&
     out << "}\n";
   }
 
-  out << "_aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());\n";
+  out << "_aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), "
+         "_aidl_in.getR());\n";
   if (defined_type.IsSensitiveData()) {
     out << "AParcel_markSensitive(_aidl_in.get());\n";
   }
@@ -547,7 +527,7 @@ static void GenerateClientMethodDefinition(CodeWriter& out, const AidlTypenames&
   }
   out << "_aidl_ret_status = AIBinder_transact(\n";
   out.Indent();
-  out << "asBinder().get(),\n";
+  out << "asBinderReference().get(),\n";
   out << MethodId(method) << ",\n";
   out << "_aidl_in.getR(),\n";
   out << "_aidl_out.getR(),\n";
@@ -558,7 +538,7 @@ static void GenerateClientMethodDefinition(CodeWriter& out, const AidlTypenames&
   out << (flags.empty() ? "0" : base::Join(flags, " | ")) << "\n";
 
   out << "#ifdef BINDER_STABILITY_SUPPORT\n";
-  out << "| FLAG_PRIVATE_LOCAL\n";
+  out << "| static_cast<int>(FLAG_PRIVATE_LOCAL)\n";
   out << "#endif  // BINDER_STABILITY_SUPPORT\n";
   out << ");\n";
   out.Dedent();
@@ -639,11 +619,6 @@ static void GenerateServerCaseDefinition(CodeWriter& out, const AidlTypenames& t
     out << NdkNameOf(types, method.GetType(), StorageMode::STACK) << " _aidl_return;\n";
   }
   out << "\n";
-  if (options.GenTraces()) {
-    out << "ScopedTrace _aidl_trace(\"AIDL::" << to_string(options.TargetLanguage())
-        << "::" << ClassName(defined_type, ClassNames::INTERFACE) << "::" << method.GetName()
-        << "::server\");\n";
-  }
 
   for (const auto& arg : method.GetArguments()) {
     const std::string var_name = cpp::BuildVarName(*arg);
@@ -1018,9 +993,6 @@ void GenerateClientHeader(CodeWriter& out, const AidlTypenames& types,
     out << "#include <chrono>\n";
     out << "#include <sstream>\n";
   }
-  if (options.GenTraces()) {
-    out << "#include <android/trace.h>\n";
-  }
   out << "\n";
   EnterNdkNamespace(out, defined_type);
   GenerateClientClassDecl(out, types, defined_type, options);
diff --git a/generate_rust.cpp b/generate_rust.cpp
index a3211cf7..4146b7fc 100644
--- a/generate_rust.cpp
+++ b/generate_rust.cpp
@@ -638,7 +638,7 @@ void GenerateRustInterface(CodeWriter* code_writer, const AidlInterface* iface,
   }
   code_writer->Dedent();
   *code_writer << "},\n";
-  *code_writer << "async: " << trait_name_async << ",\n";
+  *code_writer << "async: " << trait_name_async << "(try_into_local_async),\n";
   if (iface->IsVintfStability()) {
     *code_writer << "stability: binder::binder_impl::Stability::Vintf,\n";
   }
@@ -649,6 +649,9 @@ void GenerateRustInterface(CodeWriter* code_writer, const AidlInterface* iface,
 
   // Emit the trait.
   GenerateDeprecated(*code_writer, *iface);
+  if (options.GenMockall()) {
+    *code_writer << "#[mockall::automock]\n";
+  }
   *code_writer << "pub trait " << trait_name << ": binder::Interface + Send {\n";
   code_writer->Indent();
   *code_writer << "fn get_descriptor() -> &'static str where Self: Sized { \""
@@ -684,9 +687,18 @@ void GenerateRustInterface(CodeWriter* code_writer, const AidlInterface* iface,
                << " -> " << default_ref_name << " where Self: Sized {\n";
   *code_writer << "  std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)\n";
   *code_writer << "}\n";
+  *code_writer << "fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn "
+               << trait_name_async_server << " + Send + Sync)> {\n";
+  *code_writer << "  None\n";
+  *code_writer << "}\n";
   code_writer->Dedent();
   *code_writer << "}\n";
 
+  // Emit the Interface implementation for the mock, if needed.
+  if (options.GenMockall()) {
+    *code_writer << "impl binder::Interface for Mock" << trait_name << " {}\n";
+  }
+
   // Emit the async trait.
   GenerateDeprecated(*code_writer, *iface);
   *code_writer << "pub trait " << trait_name_async << "<P>: binder::Interface + Send {\n";
@@ -698,13 +710,11 @@ void GenerateRustInterface(CodeWriter* code_writer, const AidlInterface* iface,
     // Generate the method
     GenerateDeprecated(*code_writer, *method);
 
-    MethodKind kind = method->IsOneway() ? MethodKind::READY_FUTURE : MethodKind::BOXED_FUTURE;
-
     if (method->IsUserDefined()) {
-      *code_writer << BuildMethod(*method, typenames, kind) << ";\n";
+      *code_writer << BuildMethod(*method, typenames, MethodKind::BOXED_FUTURE) << ";\n";
     } else {
       // Generate default implementations for meta methods
-      *code_writer << BuildMethod(*method, typenames, kind) << " {\n";
+      *code_writer << BuildMethod(*method, typenames, MethodKind::BOXED_FUTURE) << " {\n";
       code_writer->Indent();
       if (method->GetName() == kGetInterfaceVersion && options.Version() > 0) {
         *code_writer << "Box::pin(async move { Ok(VERSION) })\n";
@@ -796,6 +806,12 @@ void GenerateRustInterface(CodeWriter* code_writer, const AidlInterface* iface,
       *code_writer << "}\n";
     }
   }
+  *code_writer << "fn try_as_async_server(&self) -> Option<&(dyn " << trait_name_async_server
+               << " + Send + Sync)> {\n";
+  code_writer->Indent();
+  *code_writer << "Some(&self._inner)\n";
+  code_writer->Dedent();
+  *code_writer << "}\n";
   code_writer->Dedent();
   *code_writer << "}\n";
 
@@ -804,6 +820,53 @@ void GenerateRustInterface(CodeWriter* code_writer, const AidlInterface* iface,
 
   code_writer->Dedent();
   *code_writer << "}\n";
+
+  // Emit a method for accessing the underlying async implementation of a local server.
+  *code_writer << "pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: "
+                  "binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn "
+               << trait_name_async << "<P>>> {\n";
+  code_writer->Indent();
+
+  *code_writer << "struct Wrapper {\n";
+  code_writer->Indent();
+  *code_writer << "_native: binder::binder_impl::Binder<" << server_name << ">\n";
+  code_writer->Dedent();
+  *code_writer << "}\n";
+  *code_writer << "impl binder::Interface for Wrapper {}\n";
+  *code_writer << "impl<P: binder::BinderAsyncPool> " << trait_name_async << "<P> for Wrapper {\n";
+  code_writer->Indent();
+  for (const auto& method : iface->GetMethods()) {
+    // Generate the method
+    if (method->IsUserDefined()) {
+      string args = "";
+      for (const std::unique_ptr<AidlArgument>& arg : method->GetArguments()) {
+        if (!args.empty()) {
+          args += ", ";
+        }
+        args += kArgumentPrefix;
+        args += arg->GetName();
+      }
+
+      *code_writer << BuildMethod(*method, typenames, MethodKind::BOXED_FUTURE) << " {\n";
+      code_writer->Indent();
+      *code_writer << "Box::pin(self._native.try_as_async_server().unwrap().r#" << method->GetName()
+                   << "(" << args << "))\n";
+      code_writer->Dedent();
+      *code_writer << "}\n";
+    }
+  }
+  code_writer->Dedent();
+  *code_writer << "}\n";
+  *code_writer << "if _native.try_as_async_server().is_some() {\n";
+  *code_writer << "  Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn "
+               << trait_name_async << "<P>>))\n";
+  *code_writer << "} else {\n";
+  *code_writer << "  None\n";
+  *code_writer << "}\n";
+
+  code_writer->Dedent();
+  *code_writer << "}\n";
+
   code_writer->Dedent();
   *code_writer << "}\n";
 
@@ -896,8 +959,8 @@ void GenerateRustInterface(CodeWriter* code_writer, const AidlInterface* iface,
                << client_name << " {\n";
   code_writer->Indent();
   for (const auto& method : iface->GetMethods()) {
-    MethodKind kind = method->IsOneway() ? MethodKind::READY_FUTURE : MethodKind::BOXED_FUTURE;
-    GenerateClientMethod(*code_writer, *iface, *method, typenames, options, kind);
+    GenerateClientMethod(*code_writer, *iface, *method, typenames, options,
+                         MethodKind::BOXED_FUTURE);
   }
   code_writer->Dedent();
   *code_writer << "}\n";
diff --git a/options.cpp b/options.cpp
index 6fb430fc..b8bf9831 100644
--- a/options.cpp
+++ b/options.cpp
@@ -115,6 +115,8 @@ string Options::GetUsage() const {
        << "          Generate dependency file in a format ninja understands." << endl
        << "  --rpc" << endl
        << "          (for Java) whether to generate support for RPC transactions." << endl
+       << "  --mockall" << endl
+       << "          (for Rust) whether to generate mockall mocks of AIDL interfaces." << endl
        << "  --structured" << endl
        << "          Whether this interface is defined exclusively in AIDL." << endl
        << "          It is therefore a candidate for stabilization." << endl
@@ -320,6 +322,7 @@ Options::Options(int argc, const char* const raw_argv[], Options::Language defau
         {"header_out", required_argument, 0, 'h'},
         {"ninja", no_argument, 0, 'n'},
         {"rpc", no_argument, 0, 'r'},
+        {"mockall", no_argument, 0, 'M'},
         {"stability", required_argument, 0, 'Y'},
         {"omit_invocation", no_argument, 0, 'O'},
         {"min_sdk_version", required_argument, 0, 'm'},
@@ -449,6 +452,9 @@ Options::Options(int argc, const char* const raw_argv[], Options::Language defau
       case 'r':
         gen_rpc_ = true;
         break;
+      case 'M':
+        gen_mockall_ = true;
+        break;
       case 't':
         gen_traces_ = true;
         break;
diff --git a/options.h b/options.h
index c3fb79a6..3099c236 100644
--- a/options.h
+++ b/options.h
@@ -179,6 +179,8 @@ class Options final {
 
   bool GenTransactionNames() const { return gen_transaction_names_; }
 
+  bool GenMockall() const { return gen_mockall_; }
+
   bool DependencyFileNinja() const { return dependency_file_ninja_; }
 
   const string& PreviousApiDir() const { return previous_api_dir_; }
@@ -249,6 +251,7 @@ class Options final {
   bool gen_rpc_ = false;
   bool gen_traces_ = false;
   bool gen_transaction_names_ = false;
+  bool gen_mockall_ = false;
   bool dependency_file_ninja_ = false;
   string previous_api_dir_;
   bool structured_ = false;
diff --git a/tests/aidl_integration_test.py b/tests/aidl_integration_test.py
index 6355f84e..6e57d0c8 100755
--- a/tests/aidl_integration_test.py
+++ b/tests/aidl_integration_test.py
@@ -68,7 +68,7 @@ class ShellResult(object):
 class AdbHost(object):
     """Represents a device connected via ADB."""
 
-    def run(self, command, background=False, ignore_status=False):
+    def run(self, command, background=None, ignore_status=False):
         """Run a command on the device via adb shell.
 
         Args:
@@ -83,7 +83,9 @@ class AdbHost(object):
             subprocess.CalledProcessError on command exit != 0.
         """
         if background:
-            command = '( %s ) </dev/null >/dev/null 2>&1 &' % command
+            # outer redirection to /dev/null required to avoid subprocess.Popen blocking
+            # on the FDs being closed
+            command = '(( %s ) </dev/null 2>&1 | log -t %s &) >/dev/null 2>&1' % (command, background)
         return self.adb('shell %s' % pipes.quote(command),
                         ignore_status=ignore_status)
 
@@ -113,7 +115,7 @@ class NativeServer:
     def cleanup(self):
         self.host.run('killall %s' % self.binary, ignore_status=True)
     def run(self):
-        return self.host.run(self.binary, background=True)
+        return self.host.run(self.binary, background=self.binary)
 
 class NativeClient:
     def cleanup(self):
@@ -166,7 +168,7 @@ class JavaServer:
         return self.host.run('CLASSPATH=/data/framework/aidl_test_java_service.jar '
                              + APP_PROCESS_FOR_PRETTY_BITNESS % pretty_bitness(self.bitness) +
                              ' /data/framework android.aidl.service.TestServiceServer',
-                             background=True)
+                             background=self.name)
 
 class JavaClient:
     def __init__(self, host, bitness):
@@ -214,7 +216,7 @@ class JavaVersionTestServer:
         return self.host.run('CLASSPATH=/data/framework/aidl_test_java_service_sdk%d.jar ' % self.ver
                              + APP_PROCESS_FOR_PRETTY_BITNESS % pretty_bitness(self.bitness) +
                              ' /data/framework android.aidl.sdkversion.service.AidlJavaVersionTestService',
-                             background=True)
+                             background=self.name)
 
 class JavaPermissionClient:
     def __init__(self, host, bitness):
@@ -244,7 +246,7 @@ class JavaPermissionServer:
         return self.host.run('CLASSPATH=/data/framework/aidl_test_java_service_permission.jar '
                              + APP_PROCESS_FOR_PRETTY_BITNESS % pretty_bitness(self.bitness) +
                              ' /data/framework android.aidl.permission.service.PermissionTestService',
-                             background=True)
+                             background=self.name)
 
 def getprop(host, prop):
     return host.run('getprop "%s"' % prop).stdout.strip()
@@ -270,7 +272,7 @@ class RustServer:
     def cleanup(self):
         self.host.run('killall %s' % self.binary, ignore_status=True)
     def run(self):
-        return self.host.run(self.binary, background=True)
+        return self.host.run(self.binary, background=self.name)
 
 class RustAsyncServer:
     def __init__(self, host, bitness):
@@ -280,7 +282,7 @@ class RustAsyncServer:
     def cleanup(self):
         self.host.run('killall %s' % self.binary, ignore_status=True)
     def run(self):
-        return self.host.run(self.binary, background=True)
+        return self.host.run(self.binary, background=self.name)
 
 def supported_bitnesses(host):
     bitnesses = []
diff --git a/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BnCppJavaTests.h b/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BnCppJavaTests.h
index 4699bda3..12ad90db 100644
--- a/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BnCppJavaTests.h
+++ b/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BnCppJavaTests.h
@@ -13,7 +13,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnCppJavaTests : public ::android::BnInterface<ICppJavaTests> {
+class LIBBINDER_EXPORTED BnCppJavaTests : public ::android::BnInterface<ICppJavaTests> {
 public:
   static constexpr uint32_t TRANSACTION_RepeatBadParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_RepeatGenericParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -27,7 +27,7 @@ public:
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnCppJavaTests
 
-class ICppJavaTestsDelegator : public BnCppJavaTests {
+class LIBBINDER_EXPORTED ICppJavaTestsDelegator : public BnCppJavaTests {
 public:
   explicit ICppJavaTestsDelegator(const ::android::sp<ICppJavaTests> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BpCppJavaTests.h b/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BpCppJavaTests.h
index 60a44753..bdb85931 100644
--- a/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BpCppJavaTests.h
+++ b/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BpCppJavaTests.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpCppJavaTests : public ::android::BpInterface<ICppJavaTests> {
+class LIBBINDER_EXPORTED BpCppJavaTests : public ::android::BpInterface<ICppJavaTests> {
 public:
   explicit BpCppJavaTests(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpCppJavaTests() = default;
diff --git a/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/ICppJavaTests.h b/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/ICppJavaTests.h
index 68e483b2..3b3a7ac2 100644
--- a/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/ICppJavaTests.h
+++ b/tests/golden_output/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/ICppJavaTests.h
@@ -27,9 +27,9 @@ class StructuredParcelable;
 namespace android {
 namespace aidl {
 namespace tests {
-class ICppJavaTestsDelegator;
+class LIBBINDER_EXPORTED ICppJavaTestsDelegator;
 
-class ICppJavaTests : public ::android::IInterface {
+class LIBBINDER_EXPORTED ICppJavaTests : public ::android::IInterface {
 public:
   typedef ICppJavaTestsDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(CppJavaTests)
@@ -43,7 +43,7 @@ public:
   virtual ::android::binder::Status ReverseFileDescriptorArray(const ::std::vector<::android::base::unique_fd>& input, ::std::vector<::android::base::unique_fd>* repeated, ::std::vector<::android::base::unique_fd>* _aidl_return) = 0;
 };  // class ICppJavaTests
 
-class ICppJavaTestsDefault : public ICppJavaTests {
+class LIBBINDER_EXPORTED ICppJavaTestsDefault : public ICppJavaTests {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-cpp-java-test-interface-java-source/gen/android/aidl/tests/ICppJavaTests.java b/tests/golden_output/aidl-cpp-java-test-interface-java-source/gen/android/aidl/tests/ICppJavaTests.java
index 35f0555d..7ed4f606 100644
--- a/tests/golden_output/aidl-cpp-java-test-interface-java-source/gen/android/aidl/tests/ICppJavaTests.java
+++ b/tests/golden_output/aidl-cpp-java-test-interface-java-source/gen/android/aidl/tests/ICppJavaTests.java
@@ -174,7 +174,9 @@ public interface ICppJavaTests extends android.os.IInterface
           _arg0 = data.createTypedArray(android.os.PersistableBundle.CREATOR);
           android.os.PersistableBundle[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new android.os.PersistableBundle[_arg1_length];
@@ -228,7 +230,9 @@ public interface ICppJavaTests extends android.os.IInterface
           _arg0 = data.createRawFileDescriptorArray();
           java.io.FileDescriptor[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new java.io.FileDescriptor[_arg1_length];
diff --git a/tests/golden_output/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h b/tests/golden_output/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
index c3a623c6..73e5c9bd 100644
--- a/tests/golden_output/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
+++ b/tests/golden_output/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
@@ -25,9 +25,9 @@
 namespace android {
 namespace aidl {
 namespace fixedsizearray {
-class FixedSizeArrayExample : public ::android::Parcelable {
+class LIBBINDER_EXPORTED FixedSizeArrayExample : public ::android::Parcelable {
 public:
-  class IntParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED IntParcelable : public ::android::Parcelable {
   public:
     int32_t value = 0;
     inline bool operator==(const IntParcelable& _rhs) const {
@@ -63,9 +63,9 @@ public:
       return _aidl_os.str();
     }
   };  // class IntParcelable
-  class IRepeatFixedSizeArrayDelegator;
+  class LIBBINDER_EXPORTED IRepeatFixedSizeArrayDelegator;
 
-  class IRepeatFixedSizeArray : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IRepeatFixedSizeArray : public ::android::IInterface {
   public:
     typedef IRepeatFixedSizeArrayDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(RepeatFixedSizeArray)
@@ -79,7 +79,7 @@ public:
     virtual ::android::binder::Status Repeat2dParcelables(const std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>& input, std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>* repeated, std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>* _aidl_return) = 0;
   };  // class IRepeatFixedSizeArray
 
-  class IRepeatFixedSizeArrayDefault : public IRepeatFixedSizeArray {
+  class LIBBINDER_EXPORTED IRepeatFixedSizeArrayDefault : public IRepeatFixedSizeArray {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -109,7 +109,7 @@ public:
       return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
     }
   };  // class IRepeatFixedSizeArrayDefault
-  class BpRepeatFixedSizeArray : public ::android::BpInterface<IRepeatFixedSizeArray> {
+  class LIBBINDER_EXPORTED BpRepeatFixedSizeArray : public ::android::BpInterface<IRepeatFixedSizeArray> {
   public:
     explicit BpRepeatFixedSizeArray(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpRepeatFixedSizeArray() = default;
@@ -122,7 +122,7 @@ public:
     ::android::binder::Status Repeat2dBinders(const std::array<std::array<::android::sp<::android::IBinder>, 3>, 2>& input, std::array<std::array<::android::sp<::android::IBinder>, 3>, 2>* repeated, std::array<std::array<::android::sp<::android::IBinder>, 3>, 2>* _aidl_return) override;
     ::android::binder::Status Repeat2dParcelables(const std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>& input, std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>* repeated, std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>* _aidl_return) override;
   };  // class BpRepeatFixedSizeArray
-  class BnRepeatFixedSizeArray : public ::android::BnInterface<IRepeatFixedSizeArray> {
+  class LIBBINDER_EXPORTED BnRepeatFixedSizeArray : public ::android::BnInterface<IRepeatFixedSizeArray> {
   public:
     static constexpr uint32_t TRANSACTION_RepeatBytes = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     static constexpr uint32_t TRANSACTION_RepeatInts = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -136,7 +136,7 @@ public:
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnRepeatFixedSizeArray
 
-  class IRepeatFixedSizeArrayDelegator : public BnRepeatFixedSizeArray {
+  class LIBBINDER_EXPORTED IRepeatFixedSizeArrayDelegator : public BnRepeatFixedSizeArray {
   public:
     explicit IRepeatFixedSizeArrayDelegator(const ::android::sp<IRepeatFixedSizeArray> &impl) : _aidl_delegate(impl) {}
 
@@ -177,32 +177,32 @@ public:
   enum class LongEnum : int64_t {
     A = 0L,
   };
-  class IEmptyInterfaceDelegator;
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator;
 
-  class IEmptyInterface : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IEmptyInterface : public ::android::IInterface {
   public:
     typedef IEmptyInterfaceDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(EmptyInterface)
   };  // class IEmptyInterface
 
-  class IEmptyInterfaceDefault : public IEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDefault : public IEmptyInterface {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
     }
   };  // class IEmptyInterfaceDefault
-  class BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
   public:
     explicit BpEmptyInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpEmptyInterface() = default;
   };  // class BpEmptyInterface
-  class BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
   public:
     explicit BnEmptyInterface();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnEmptyInterface
 
-  class IEmptyInterfaceDelegator : public BnEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator : public BnEmptyInterface {
   public:
     explicit IEmptyInterfaceDelegator(const ::android::sp<IEmptyInterface> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp b/tests/golden_output/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
index 11e90b53..7b394135 100644
--- a/tests/golden_output/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
+++ b/tests/golden_output/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
@@ -792,20 +792,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*RepeatBytes*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -835,20 +835,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*RepeatInts*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -878,20 +878,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*RepeatBinders*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -921,20 +921,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*RepeatParcelables*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -964,20 +964,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 4 /*Repeat2dBytes*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -1007,20 +1007,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 5 /*Repeat2dInts*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -1050,20 +1050,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 6 /*Repeat2dBinders*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -1093,20 +1093,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 7 /*Repeat2dParcelables*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs b/tests/golden_output/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
index ec33985f..fa103b3a 100644
--- a/tests/golden_output/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
+++ b/tests/golden_output/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
@@ -370,7 +370,7 @@ pub mod r#IRepeatFixedSizeArray {
       native: BnRepeatFixedSizeArray(on_transact),
       proxy: BpRepeatFixedSizeArray {
       },
-      async: IRepeatFixedSizeArrayAsync,
+      async: IRepeatFixedSizeArrayAsync(try_into_local_async),
     }
   }
   pub trait IRepeatFixedSizeArray: binder::Interface + Send {
@@ -389,6 +389,9 @@ pub mod r#IRepeatFixedSizeArray {
     fn setDefaultImpl(d: IRepeatFixedSizeArrayDefaultRef) -> IRepeatFixedSizeArrayDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IRepeatFixedSizeArrayAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IRepeatFixedSizeArrayAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.fixedsizearray.FixedSizeArrayExample.IRepeatFixedSizeArray" }
@@ -457,10 +460,50 @@ pub mod r#IRepeatFixedSizeArray {
         fn r#Repeat2dParcelables(&self, _arg_input: &[[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2], _arg_repeated: &mut [[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]) -> binder::Result<[[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]> {
           self._rt.block_on(self._inner.r#Repeat2dParcelables(_arg_input, _arg_repeated))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn IRepeatFixedSizeArrayAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IRepeatFixedSizeArrayAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnRepeatFixedSizeArray>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IRepeatFixedSizeArrayAsync<P> for Wrapper {
+        fn r#RepeatBytes<'a>(&'a self, _arg_input: &'a [u8; 3], _arg_repeated: &'a mut [u8; 3]) -> binder::BoxFuture<'a, binder::Result<[u8; 3]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#RepeatBytes(_arg_input, _arg_repeated))
+        }
+        fn r#RepeatInts<'a>(&'a self, _arg_input: &'a [i32; 3], _arg_repeated: &'a mut [i32; 3]) -> binder::BoxFuture<'a, binder::Result<[i32; 3]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#RepeatInts(_arg_input, _arg_repeated))
+        }
+        fn r#RepeatBinders<'a>(&'a self, _arg_input: &'a [binder::SpIBinder; 3], _arg_repeated: &'a mut [Option<binder::SpIBinder>; 3]) -> binder::BoxFuture<'a, binder::Result<[binder::SpIBinder; 3]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#RepeatBinders(_arg_input, _arg_repeated))
+        }
+        fn r#RepeatParcelables<'a>(&'a self, _arg_input: &'a [crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3], _arg_repeated: &'a mut [crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]) -> binder::BoxFuture<'a, binder::Result<[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#RepeatParcelables(_arg_input, _arg_repeated))
+        }
+        fn r#Repeat2dBytes<'a>(&'a self, _arg_input: &'a [[u8; 3]; 2], _arg_repeated: &'a mut [[u8; 3]; 2]) -> binder::BoxFuture<'a, binder::Result<[[u8; 3]; 2]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#Repeat2dBytes(_arg_input, _arg_repeated))
+        }
+        fn r#Repeat2dInts<'a>(&'a self, _arg_input: &'a [[i32; 3]; 2], _arg_repeated: &'a mut [[i32; 3]; 2]) -> binder::BoxFuture<'a, binder::Result<[[i32; 3]; 2]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#Repeat2dInts(_arg_input, _arg_repeated))
+        }
+        fn r#Repeat2dBinders<'a>(&'a self, _arg_input: &'a [[binder::SpIBinder; 3]; 2], _arg_repeated: &'a mut [[Option<binder::SpIBinder>; 3]; 2]) -> binder::BoxFuture<'a, binder::Result<[[binder::SpIBinder; 3]; 2]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#Repeat2dBinders(_arg_input, _arg_repeated))
+        }
+        fn r#Repeat2dParcelables<'a>(&'a self, _arg_input: &'a [[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2], _arg_repeated: &'a mut [[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]) -> binder::BoxFuture<'a, binder::Result<[[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#Repeat2dParcelables(_arg_input, _arg_repeated))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IRepeatFixedSizeArrayAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IRepeatFixedSizeArrayDefault: Send + Sync {
     fn r#RepeatBytes(&self, _arg_input: &[u8; 3], _arg_repeated: &mut [u8; 3]) -> binder::Result<[u8; 3]> {
@@ -996,7 +1039,7 @@ pub mod r#IEmptyInterface {
       native: BnEmptyInterface(on_transact),
       proxy: BpEmptyInterface {
       },
-      async: IEmptyInterfaceAsync,
+      async: IEmptyInterfaceAsync(try_into_local_async),
     }
   }
   pub trait IEmptyInterface: binder::Interface + Send {
@@ -1007,6 +1050,9 @@ pub mod r#IEmptyInterface {
     fn setDefaultImpl(d: IEmptyInterfaceDefaultRef) -> IEmptyInterfaceDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IEmptyInterfaceAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.fixedsizearray.FixedSizeArrayExample.IEmptyInterface" }
@@ -1035,10 +1081,26 @@ pub mod r#IEmptyInterface {
         T: IEmptyInterfaceAsyncServer + Send + Sync + 'static,
         R: binder::binder_impl::BinderAsyncRuntime + Send + Sync + 'static,
       {
+        fn try_as_async_server(&self) -> Option<&(dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IEmptyInterfaceAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnEmptyInterface>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IEmptyInterfaceAsync<P> for Wrapper {
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IEmptyInterfaceAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IEmptyInterfaceDefault: Send + Sync {
   }
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
index 374e7b6b..57cebb3e 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
@@ -33,34 +33,34 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class ArrayOfInterfaces : public ::android::Parcelable {
+class LIBBINDER_EXPORTED ArrayOfInterfaces : public ::android::Parcelable {
 public:
-  class IEmptyInterfaceDelegator;
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator;
 
-  class IEmptyInterface : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IEmptyInterface : public ::android::IInterface {
   public:
     typedef IEmptyInterfaceDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(EmptyInterface)
   };  // class IEmptyInterface
 
-  class IEmptyInterfaceDefault : public IEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDefault : public IEmptyInterface {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
     }
   };  // class IEmptyInterfaceDefault
-  class BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
   public:
     explicit BpEmptyInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpEmptyInterface() = default;
   };  // class BpEmptyInterface
-  class BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
   public:
     explicit BnEmptyInterface();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnEmptyInterface
 
-  class IEmptyInterfaceDelegator : public BnEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator : public BnEmptyInterface {
   public:
     explicit IEmptyInterfaceDelegator(const ::android::sp<IEmptyInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -68,16 +68,16 @@ public:
   private:
     ::android::sp<IEmptyInterface> _aidl_delegate;
   };  // class IEmptyInterfaceDelegator
-  class IMyInterfaceDelegator;
+  class LIBBINDER_EXPORTED IMyInterfaceDelegator;
 
-  class IMyInterface : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IMyInterface : public ::android::IInterface {
   public:
     typedef IMyInterfaceDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(MyInterface)
     virtual ::android::binder::Status methodWithInterfaces(const ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>& iface, const ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>& nullable_iface, const ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>& iface_array_in, ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>* iface_array_out, ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>* iface_array_inout, const ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>& nullable_iface_array_in, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* nullable_iface_array_out, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* nullable_iface_array_inout, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* _aidl_return) = 0;
   };  // class IMyInterface
 
-  class IMyInterfaceDefault : public IMyInterface {
+  class LIBBINDER_EXPORTED IMyInterfaceDefault : public IMyInterface {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -86,20 +86,20 @@ public:
       return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
     }
   };  // class IMyInterfaceDefault
-  class BpMyInterface : public ::android::BpInterface<IMyInterface> {
+  class LIBBINDER_EXPORTED BpMyInterface : public ::android::BpInterface<IMyInterface> {
   public:
     explicit BpMyInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpMyInterface() = default;
     ::android::binder::Status methodWithInterfaces(const ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>& iface, const ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>& nullable_iface, const ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>& iface_array_in, ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>* iface_array_out, ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>* iface_array_inout, const ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>& nullable_iface_array_in, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* nullable_iface_array_out, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* nullable_iface_array_inout, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* _aidl_return) override;
   };  // class BpMyInterface
-  class BnMyInterface : public ::android::BnInterface<IMyInterface> {
+  class LIBBINDER_EXPORTED BnMyInterface : public ::android::BnInterface<IMyInterface> {
   public:
     static constexpr uint32_t TRANSACTION_methodWithInterfaces = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     explicit BnMyInterface();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnMyInterface
 
-  class IMyInterfaceDelegator : public BnMyInterface {
+  class LIBBINDER_EXPORTED IMyInterfaceDelegator : public BnMyInterface {
   public:
     explicit IMyInterfaceDelegator(const ::android::sp<IMyInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -118,7 +118,7 @@ public:
   private:
     ::android::sp<IMyInterface> _aidl_delegate;
   };  // class IMyInterfaceDelegator
-  class MyParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyParcelable : public ::android::Parcelable {
   public:
     ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface> iface;
     ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface> nullable_iface;
@@ -160,7 +160,7 @@ public:
       return _aidl_os.str();
     }
   };  // class MyParcelable
-  class MyUnion : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyUnion : public ::android::Parcelable {
   public:
     enum class Tag : int32_t {
       iface = 0,
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnCircular.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnCircular.h
index 6c7a2a87..dd0807e9 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnCircular.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnCircular.h
@@ -14,14 +14,14 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnCircular : public ::android::BnInterface<ICircular> {
+class LIBBINDER_EXPORTED BnCircular : public ::android::BnInterface<ICircular> {
 public:
   static constexpr uint32_t TRANSACTION_GetTestService = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   explicit BnCircular();
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnCircular
 
-class ICircularDelegator : public BnCircular {
+class LIBBINDER_EXPORTED ICircularDelegator : public BnCircular {
 public:
   explicit ICircularDelegator(const ::android::sp<ICircular> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnDeprecated.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnDeprecated.h
index 9effe3d7..78c8d62c 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnDeprecated.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnDeprecated.h
@@ -13,13 +13,13 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class __attribute__((deprecated("test"))) BnDeprecated : public ::android::BnInterface<IDeprecated> {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) BnDeprecated : public ::android::BnInterface<IDeprecated> {
 public:
   explicit BnDeprecated();
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnDeprecated
 
-class __attribute__((deprecated("test"))) IDeprecatedDelegator : public BnDeprecated {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) IDeprecatedDelegator : public BnDeprecated {
 public:
   explicit IDeprecatedDelegator(const ::android::sp<IDeprecated> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNamedCallback.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNamedCallback.h
index fee8d2f4..43a06b11 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNamedCallback.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNamedCallback.h
@@ -13,14 +13,14 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnNamedCallback : public ::android::BnInterface<INamedCallback> {
+class LIBBINDER_EXPORTED BnNamedCallback : public ::android::BnInterface<INamedCallback> {
 public:
   static constexpr uint32_t TRANSACTION_GetName = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   explicit BnNamedCallback();
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnNamedCallback
 
-class INamedCallbackDelegator : public BnNamedCallback {
+class LIBBINDER_EXPORTED INamedCallbackDelegator : public BnNamedCallback {
 public:
   explicit INamedCallbackDelegator(const ::android::sp<INamedCallback> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNewName.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNewName.h
index 7eb72141..447d2346 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNewName.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNewName.h
@@ -13,14 +13,14 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnNewName : public ::android::BnInterface<INewName> {
+class LIBBINDER_EXPORTED BnNewName : public ::android::BnInterface<INewName> {
 public:
   static constexpr uint32_t TRANSACTION_RealName = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   explicit BnNewName();
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnNewName
 
-class INewNameDelegator : public BnNewName {
+class LIBBINDER_EXPORTED INewNameDelegator : public BnNewName {
 public:
   explicit INewNameDelegator(const ::android::sp<INewName> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnOldName.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnOldName.h
index 986a674b..35069b1c 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnOldName.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnOldName.h
@@ -13,14 +13,14 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnOldName : public ::android::BnInterface<IOldName> {
+class LIBBINDER_EXPORTED BnOldName : public ::android::BnInterface<IOldName> {
 public:
   static constexpr uint32_t TRANSACTION_RealName = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   explicit BnOldName();
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnOldName
 
-class IOldNameDelegator : public BnOldName {
+class LIBBINDER_EXPORTED IOldNameDelegator : public BnOldName {
 public:
   explicit IOldNameDelegator(const ::android::sp<IOldName> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnTestService.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnTestService.h
index a7b48284..793baf4a 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnTestService.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnTestService.h
@@ -18,7 +18,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnTestService : public ::android::BnInterface<ITestService> {
+class LIBBINDER_EXPORTED BnTestService : public ::android::BnInterface<ITestService> {
 public:
   static constexpr uint32_t TRANSACTION_UnimplementedMethod = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_Deprecated = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -94,7 +94,7 @@ public:
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnTestService
 
-class ITestServiceDelegator : public BnTestService {
+class LIBBINDER_EXPORTED ITestServiceDelegator : public BnTestService {
 public:
   explicit ITestServiceDelegator(const ::android::sp<ITestService> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpCircular.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpCircular.h
index 53aa76e8..08dc8387 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpCircular.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpCircular.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpCircular : public ::android::BpInterface<ICircular> {
+class LIBBINDER_EXPORTED BpCircular : public ::android::BpInterface<ICircular> {
 public:
   explicit BpCircular(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpCircular() = default;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpDeprecated.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpDeprecated.h
index ff4ef51c..723dd94d 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpDeprecated.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpDeprecated.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class __attribute__((deprecated("test"))) BpDeprecated : public ::android::BpInterface<IDeprecated> {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) BpDeprecated : public ::android::BpInterface<IDeprecated> {
 public:
   explicit BpDeprecated(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpDeprecated() = default;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNamedCallback.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNamedCallback.h
index 4d333ef5..627f1688 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNamedCallback.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNamedCallback.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpNamedCallback : public ::android::BpInterface<INamedCallback> {
+class LIBBINDER_EXPORTED BpNamedCallback : public ::android::BpInterface<INamedCallback> {
 public:
   explicit BpNamedCallback(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpNamedCallback() = default;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNewName.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNewName.h
index 4be360b1..27a50464 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNewName.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNewName.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpNewName : public ::android::BpInterface<INewName> {
+class LIBBINDER_EXPORTED BpNewName : public ::android::BpInterface<INewName> {
 public:
   explicit BpNewName(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpNewName() = default;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpOldName.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpOldName.h
index c8b87dd3..c8d4a14d 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpOldName.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpOldName.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpOldName : public ::android::BpInterface<IOldName> {
+class LIBBINDER_EXPORTED BpOldName : public ::android::BpInterface<IOldName> {
 public:
   explicit BpOldName(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpOldName() = default;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpTestService.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpTestService.h
index c4b4b28f..e1b61d31 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpTestService.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpTestService.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpTestService : public ::android::BpInterface<ITestService> {
+class LIBBINDER_EXPORTED BpTestService : public ::android::BpInterface<ITestService> {
 public:
   explicit BpTestService(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpTestService() = default;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
index cfdc35f9..d3d9668d 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
@@ -18,7 +18,7 @@ class ITestService;
 namespace android {
 namespace aidl {
 namespace tests {
-class CircularParcelable : public ::android::Parcelable {
+class LIBBINDER_EXPORTED CircularParcelable : public ::android::Parcelable {
 public:
   ::android::sp<::android::aidl::tests::ITestService> testService;
   inline bool operator==(const CircularParcelable& _rhs) const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
index e58797c3..ebf07dce 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
@@ -13,7 +13,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class __attribute__((deprecated("test"))) DeprecatedParcelable : public ::android::Parcelable {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) DeprecatedParcelable : public ::android::Parcelable {
 public:
   inline bool operator==(const DeprecatedParcelable&) const {
     return std::tie() == std::tie();
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
index 59e8683a..77c15d57 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
@@ -27,9 +27,9 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class FixedSize : public ::android::Parcelable {
+class LIBBINDER_EXPORTED FixedSize : public ::android::Parcelable {
 public:
-  class FixedUnion : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED FixedUnion : public ::android::Parcelable {
   public:
     enum class Tag : int8_t {
       booleanValue = 0,
@@ -157,7 +157,7 @@ public:
       ::android::aidl::tests::LongEnum enumValue __attribute__((aligned (8)));
     } _value;
   };  // class FixedUnion
-  class EmptyParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED EmptyParcelable : public ::android::Parcelable {
   public:
     inline bool operator==(const EmptyParcelable&) const {
       return std::tie() == std::tie();
@@ -191,7 +191,7 @@ public:
       return _aidl_os.str();
     }
   };  // class EmptyParcelable
-  class FixedParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED FixedParcelable : public ::android::Parcelable {
   public:
     bool booleanValue = false;
     int8_t byteValue = 0;
@@ -251,7 +251,7 @@ public:
       return _aidl_os.str();
     }
   };  // class FixedParcelable
-  class ExplicitPaddingParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED ExplicitPaddingParcelable : public ::android::Parcelable {
   public:
     int8_t byteValue = 0;
     int64_t longValue = 0L;
@@ -297,7 +297,7 @@ public:
       return _aidl_os.str();
     }
   };  // class ExplicitPaddingParcelable
-  class FixedUnionNoPadding : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED FixedUnionNoPadding : public ::android::Parcelable {
   public:
     enum class Tag : int8_t {
       byteValue = 0,
@@ -389,7 +389,7 @@ public:
       int8_t byteValue __attribute__((aligned (1))) = int8_t(0);
     } _value;
   };  // class FixedUnionNoPadding
-  class FixedUnionSmallPadding : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED FixedUnionSmallPadding : public ::android::Parcelable {
   public:
     enum class Tag : int8_t {
       charValue = 0,
@@ -481,7 +481,7 @@ public:
       char16_t charValue __attribute__((aligned (2))) = char16_t('\0');
     } _value;
   };  // class FixedUnionSmallPadding
-  class FixedUnionLongPadding : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED FixedUnionLongPadding : public ::android::Parcelable {
   public:
     enum class Tag : int8_t {
       longValue = 0,
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
index 190c6314..7766bc87 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
@@ -15,7 +15,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 template <typename T, typename U, typename B>
-class GenericStructuredParcelable : public ::android::Parcelable {
+class LIBBINDER_EXPORTED GenericStructuredParcelable : public ::android::Parcelable {
 public:
   int32_t a = 0;
   int32_t b = 0;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ICircular.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ICircular.h
index 22604519..5ab518c7 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ICircular.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ICircular.h
@@ -18,16 +18,16 @@ class ITestService;
 namespace android {
 namespace aidl {
 namespace tests {
-class ICircularDelegator;
+class LIBBINDER_EXPORTED ICircularDelegator;
 
-class ICircular : public ::android::IInterface {
+class LIBBINDER_EXPORTED ICircular : public ::android::IInterface {
 public:
   typedef ICircularDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(Circular)
   virtual ::android::binder::Status GetTestService(::android::sp<::android::aidl::tests::ITestService>* _aidl_return) = 0;
 };  // class ICircular
 
-class ICircularDefault : public ICircular {
+class LIBBINDER_EXPORTED ICircularDefault : public ICircular {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IDeprecated.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IDeprecated.h
index 8ea891d7..dac038e0 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IDeprecated.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IDeprecated.h
@@ -13,15 +13,15 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class IDeprecatedDelegator;
+class LIBBINDER_EXPORTED IDeprecatedDelegator;
 
-class __attribute__((deprecated("test"))) IDeprecated : public ::android::IInterface {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) IDeprecated : public ::android::IInterface {
 public:
   typedef IDeprecatedDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(Deprecated)
 };  // class IDeprecated
 
-class __attribute__((deprecated("test"))) IDeprecatedDefault : public IDeprecated {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) IDeprecatedDefault : public IDeprecated {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INamedCallback.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INamedCallback.h
index ad9110fe..b5313c9e 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INamedCallback.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INamedCallback.h
@@ -14,16 +14,16 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class INamedCallbackDelegator;
+class LIBBINDER_EXPORTED INamedCallbackDelegator;
 
-class INamedCallback : public ::android::IInterface {
+class LIBBINDER_EXPORTED INamedCallback : public ::android::IInterface {
 public:
   typedef INamedCallbackDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(NamedCallback)
   virtual ::android::binder::Status GetName(::android::String16* _aidl_return) = 0;
 };  // class INamedCallback
 
-class INamedCallbackDefault : public INamedCallback {
+class LIBBINDER_EXPORTED INamedCallbackDefault : public INamedCallback {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INewName.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INewName.h
index b2b0d5f6..10eed1d3 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INewName.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INewName.h
@@ -14,16 +14,16 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class INewNameDelegator;
+class LIBBINDER_EXPORTED INewNameDelegator;
 
-class INewName : public ::android::IInterface {
+class LIBBINDER_EXPORTED INewName : public ::android::IInterface {
 public:
   typedef INewNameDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(NewName)
   virtual ::android::binder::Status RealName(::android::String16* _aidl_return) = 0;
 };  // class INewName
 
-class INewNameDefault : public INewName {
+class LIBBINDER_EXPORTED INewNameDefault : public INewName {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IOldName.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IOldName.h
index d4c4e826..7ceed350 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IOldName.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IOldName.h
@@ -14,16 +14,16 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class IOldNameDelegator;
+class LIBBINDER_EXPORTED IOldNameDelegator;
 
-class IOldName : public ::android::IInterface {
+class LIBBINDER_EXPORTED IOldName : public ::android::IInterface {
 public:
   typedef IOldNameDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(OldName)
   virtual ::android::binder::Status RealName(::android::String16* _aidl_return) = 0;
 };  // class IOldName
 
-class IOldNameDefault : public IOldName {
+class LIBBINDER_EXPORTED IOldNameDefault : public IOldName {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
index f532f9cc..22dbb487 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
@@ -60,13 +60,13 @@ class ExtendableParcelable;
 namespace android {
 namespace aidl {
 namespace tests {
-class ITestServiceDelegator;
+class LIBBINDER_EXPORTED ITestServiceDelegator;
 
-class ITestService : public ::android::IInterface {
+class LIBBINDER_EXPORTED ITestService : public ::android::IInterface {
 public:
   typedef ITestServiceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(TestService)
-  class Empty : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED Empty : public ::android::Parcelable {
   public:
     inline bool operator==(const Empty&) const {
       return std::tie() == std::tie();
@@ -100,34 +100,34 @@ public:
       return _aidl_os.str();
     }
   };  // class Empty
-  class CompilerChecks : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED CompilerChecks : public ::android::Parcelable {
   public:
-    class IFooDelegator;
+    class LIBBINDER_EXPORTED IFooDelegator;
 
-    class IFoo : public ::android::IInterface {
+    class LIBBINDER_EXPORTED IFoo : public ::android::IInterface {
     public:
       typedef IFooDelegator DefaultDelegator;
       DECLARE_META_INTERFACE(Foo)
     };  // class IFoo
 
-    class IFooDefault : public IFoo {
+    class LIBBINDER_EXPORTED IFooDefault : public IFoo {
     public:
       ::android::IBinder* onAsBinder() override {
         return nullptr;
       }
     };  // class IFooDefault
-    class BpFoo : public ::android::BpInterface<IFoo> {
+    class LIBBINDER_EXPORTED BpFoo : public ::android::BpInterface<IFoo> {
     public:
       explicit BpFoo(const ::android::sp<::android::IBinder>& _aidl_impl);
       virtual ~BpFoo() = default;
     };  // class BpFoo
-    class BnFoo : public ::android::BnInterface<IFoo> {
+    class LIBBINDER_EXPORTED BnFoo : public ::android::BnInterface<IFoo> {
     public:
       explicit BnFoo();
       ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
     };  // class BnFoo
 
-    class IFooDelegator : public BnFoo {
+    class LIBBINDER_EXPORTED IFooDelegator : public BnFoo {
     public:
       explicit IFooDelegator(const ::android::sp<IFoo> &impl) : _aidl_delegate(impl) {}
 
@@ -137,7 +137,7 @@ public:
     };  // class IFooDelegator
     #pragma clang diagnostic push
     #pragma clang diagnostic ignored "-Wdeprecated-declarations"
-    class HasDeprecated : public ::android::Parcelable {
+    class LIBBINDER_EXPORTED HasDeprecated : public ::android::Parcelable {
     public:
       int32_t __attribute__((deprecated("field"))) deprecated = 0;
       inline bool operator==(const HasDeprecated& _rhs) const {
@@ -174,7 +174,7 @@ public:
       }
     };  // class HasDeprecated
     #pragma clang diagnostic pop
-    class UsingHasDeprecated : public ::android::Parcelable {
+    class LIBBINDER_EXPORTED UsingHasDeprecated : public ::android::Parcelable {
     public:
       enum class Tag : int32_t {
         n = 0,
@@ -267,13 +267,13 @@ public:
     private:
       std::variant<int32_t, ::android::aidl::tests::ITestService::CompilerChecks::HasDeprecated> _value;
     };  // class UsingHasDeprecated
-    class INoPrefixInterfaceDelegator;
+    class LIBBINDER_EXPORTED INoPrefixInterfaceDelegator;
 
-    class INoPrefixInterface : public ::android::IInterface {
+    class LIBBINDER_EXPORTED INoPrefixInterface : public ::android::IInterface {
     public:
       typedef INoPrefixInterfaceDelegator DefaultDelegator;
       DECLARE_META_INTERFACE(NoPrefixInterface)
-      class Nested : public ::android::Parcelable {
+      class LIBBINDER_EXPORTED Nested : public ::android::Parcelable {
       public:
         inline bool operator==(const Nested&) const {
           return std::tie() == std::tie();
@@ -307,16 +307,16 @@ public:
           return _aidl_os.str();
         }
       };  // class Nested
-      class INestedNoPrefixInterfaceDelegator;
+      class LIBBINDER_EXPORTED INestedNoPrefixInterfaceDelegator;
 
-      class INestedNoPrefixInterface : public ::android::IInterface {
+      class LIBBINDER_EXPORTED INestedNoPrefixInterface : public ::android::IInterface {
       public:
         typedef INestedNoPrefixInterfaceDelegator DefaultDelegator;
         DECLARE_META_INTERFACE(NestedNoPrefixInterface)
         virtual ::android::binder::Status foo() = 0;
       };  // class INestedNoPrefixInterface
 
-      class INestedNoPrefixInterfaceDefault : public INestedNoPrefixInterface {
+      class LIBBINDER_EXPORTED INestedNoPrefixInterfaceDefault : public INestedNoPrefixInterface {
       public:
         ::android::IBinder* onAsBinder() override {
           return nullptr;
@@ -325,20 +325,20 @@ public:
           return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
         }
       };  // class INestedNoPrefixInterfaceDefault
-      class BpNestedNoPrefixInterface : public ::android::BpInterface<INestedNoPrefixInterface> {
+      class LIBBINDER_EXPORTED BpNestedNoPrefixInterface : public ::android::BpInterface<INestedNoPrefixInterface> {
       public:
         explicit BpNestedNoPrefixInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
         virtual ~BpNestedNoPrefixInterface() = default;
         ::android::binder::Status foo() override;
       };  // class BpNestedNoPrefixInterface
-      class BnNestedNoPrefixInterface : public ::android::BnInterface<INestedNoPrefixInterface> {
+      class LIBBINDER_EXPORTED BnNestedNoPrefixInterface : public ::android::BnInterface<INestedNoPrefixInterface> {
       public:
         static constexpr uint32_t TRANSACTION_foo = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
         explicit BnNestedNoPrefixInterface();
         ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
       };  // class BnNestedNoPrefixInterface
 
-      class INestedNoPrefixInterfaceDelegator : public BnNestedNoPrefixInterface {
+      class LIBBINDER_EXPORTED INestedNoPrefixInterfaceDelegator : public BnNestedNoPrefixInterface {
       public:
         explicit INestedNoPrefixInterfaceDelegator(const ::android::sp<INestedNoPrefixInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -352,7 +352,7 @@ public:
       virtual ::android::binder::Status foo() = 0;
     };  // class INoPrefixInterface
 
-    class INoPrefixInterfaceDefault : public INoPrefixInterface {
+    class LIBBINDER_EXPORTED INoPrefixInterfaceDefault : public INoPrefixInterface {
     public:
       ::android::IBinder* onAsBinder() override {
         return nullptr;
@@ -361,20 +361,20 @@ public:
         return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
       }
     };  // class INoPrefixInterfaceDefault
-    class BpNoPrefixInterface : public ::android::BpInterface<INoPrefixInterface> {
+    class LIBBINDER_EXPORTED BpNoPrefixInterface : public ::android::BpInterface<INoPrefixInterface> {
     public:
       explicit BpNoPrefixInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
       virtual ~BpNoPrefixInterface() = default;
       ::android::binder::Status foo() override;
     };  // class BpNoPrefixInterface
-    class BnNoPrefixInterface : public ::android::BnInterface<INoPrefixInterface> {
+    class LIBBINDER_EXPORTED BnNoPrefixInterface : public ::android::BnInterface<INoPrefixInterface> {
     public:
       static constexpr uint32_t TRANSACTION_foo = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
       explicit BnNoPrefixInterface();
       ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
     };  // class BnNoPrefixInterface
 
-    class INoPrefixInterfaceDelegator : public BnNoPrefixInterface {
+    class LIBBINDER_EXPORTED INoPrefixInterfaceDelegator : public BnNoPrefixInterface {
     public:
       explicit INoPrefixInterfaceDelegator(const ::android::sp<INoPrefixInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -615,7 +615,7 @@ public:
   virtual ::android::binder::Status GetCircular(::android::aidl::tests::CircularParcelable* cp, ::android::sp<::android::aidl::tests::ICircular>* _aidl_return) = 0;
 };  // class ITestService
 
-class ITestServiceDefault : public ITestService {
+class LIBBINDER_EXPORTED ITestServiceDefault : public ITestService {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
index 922ebf06..ec17e6f0 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
@@ -33,34 +33,34 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class ListOfInterfaces : public ::android::Parcelable {
+class LIBBINDER_EXPORTED ListOfInterfaces : public ::android::Parcelable {
 public:
-  class IEmptyInterfaceDelegator;
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator;
 
-  class IEmptyInterface : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IEmptyInterface : public ::android::IInterface {
   public:
     typedef IEmptyInterfaceDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(EmptyInterface)
   };  // class IEmptyInterface
 
-  class IEmptyInterfaceDefault : public IEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDefault : public IEmptyInterface {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
     }
   };  // class IEmptyInterfaceDefault
-  class BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
   public:
     explicit BpEmptyInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpEmptyInterface() = default;
   };  // class BpEmptyInterface
-  class BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
   public:
     explicit BnEmptyInterface();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnEmptyInterface
 
-  class IEmptyInterfaceDelegator : public BnEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator : public BnEmptyInterface {
   public:
     explicit IEmptyInterfaceDelegator(const ::android::sp<IEmptyInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -68,16 +68,16 @@ public:
   private:
     ::android::sp<IEmptyInterface> _aidl_delegate;
   };  // class IEmptyInterfaceDelegator
-  class IMyInterfaceDelegator;
+  class LIBBINDER_EXPORTED IMyInterfaceDelegator;
 
-  class IMyInterface : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IMyInterface : public ::android::IInterface {
   public:
     typedef IMyInterfaceDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(MyInterface)
     virtual ::android::binder::Status methodWithInterfaces(const ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>& iface, const ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>& nullable_iface, const ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>& iface_list_in, ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>* iface_list_out, ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>* iface_list_inout, const ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>& nullable_iface_list_in, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* nullable_iface_list_out, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* nullable_iface_list_inout, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* _aidl_return) = 0;
   };  // class IMyInterface
 
-  class IMyInterfaceDefault : public IMyInterface {
+  class LIBBINDER_EXPORTED IMyInterfaceDefault : public IMyInterface {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -86,20 +86,20 @@ public:
       return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
     }
   };  // class IMyInterfaceDefault
-  class BpMyInterface : public ::android::BpInterface<IMyInterface> {
+  class LIBBINDER_EXPORTED BpMyInterface : public ::android::BpInterface<IMyInterface> {
   public:
     explicit BpMyInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpMyInterface() = default;
     ::android::binder::Status methodWithInterfaces(const ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>& iface, const ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>& nullable_iface, const ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>& iface_list_in, ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>* iface_list_out, ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>* iface_list_inout, const ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>& nullable_iface_list_in, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* nullable_iface_list_out, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* nullable_iface_list_inout, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* _aidl_return) override;
   };  // class BpMyInterface
-  class BnMyInterface : public ::android::BnInterface<IMyInterface> {
+  class LIBBINDER_EXPORTED BnMyInterface : public ::android::BnInterface<IMyInterface> {
   public:
     static constexpr uint32_t TRANSACTION_methodWithInterfaces = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     explicit BnMyInterface();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnMyInterface
 
-  class IMyInterfaceDelegator : public BnMyInterface {
+  class LIBBINDER_EXPORTED IMyInterfaceDelegator : public BnMyInterface {
   public:
     explicit IMyInterfaceDelegator(const ::android::sp<IMyInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -118,7 +118,7 @@ public:
   private:
     ::android::sp<IMyInterface> _aidl_delegate;
   };  // class IMyInterfaceDelegator
-  class MyParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyParcelable : public ::android::Parcelable {
   public:
     ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface> iface;
     ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface> nullable_iface;
@@ -160,7 +160,7 @@ public:
       return _aidl_os.str();
     }
   };  // class MyParcelable
-  class MyUnion : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyUnion : public ::android::Parcelable {
   public:
     enum class Tag : int32_t {
       iface = 0,
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
index ca6df4c7..ecf4cbd0 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
@@ -13,7 +13,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class OtherParcelableForToString : public ::android::Parcelable {
+class LIBBINDER_EXPORTED OtherParcelableForToString : public ::android::Parcelable {
 public:
   ::android::String16 field;
   inline bool operator==(const OtherParcelableForToString& _rhs) const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
index d4a7d81c..7b7348b2 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
@@ -26,7 +26,7 @@ class StructuredParcelable;
 namespace android {
 namespace aidl {
 namespace tests {
-class ParcelableForToString : public ::android::Parcelable {
+class LIBBINDER_EXPORTED ParcelableForToString : public ::android::Parcelable {
 public:
   int32_t intValue = 0;
   ::std::vector<int32_t> intArray;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
index 9930e1c4..dce103ed 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
@@ -19,7 +19,7 @@ class RecursiveList;
 namespace android {
 namespace aidl {
 namespace tests {
-class RecursiveList : public ::android::Parcelable {
+class LIBBINDER_EXPORTED RecursiveList : public ::android::Parcelable {
 public:
   int32_t value = 0;
   ::std::unique_ptr<::android::aidl::tests::RecursiveList> next;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
index f43cb4ee..81bca09e 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
@@ -24,9 +24,9 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class StructuredParcelable : public ::android::Parcelable {
+class LIBBINDER_EXPORTED StructuredParcelable : public ::android::Parcelable {
 public:
-  class Empty : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED Empty : public ::android::Parcelable {
   public:
     inline bool operator==(const Empty&) const {
       return std::tie() == std::tie();
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
index bad638a8..2cb53af2 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
@@ -27,7 +27,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class Union : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Union : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     ns = 0,
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
index 9091f5a8..c1c8a4fa 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
@@ -25,7 +25,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class UnionWithFd : public ::android::Parcelable {
+class LIBBINDER_EXPORTED UnionWithFd : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     num = 0,
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
index f451ea40..7dd52cec 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
@@ -17,7 +17,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace extension {
-class ExtendableParcelable : public ::android::Parcelable {
+class LIBBINDER_EXPORTED ExtendableParcelable : public ::android::Parcelable {
 public:
   int32_t a = 0;
   ::std::string b;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
index 0273c281..607be428 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
@@ -16,7 +16,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace extension {
-class MyExt : public ::android::Parcelable {
+class LIBBINDER_EXPORTED MyExt : public ::android::Parcelable {
 public:
   int32_t a = 0;
   ::std::string b;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
index e2a8caa3..86e2956f 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
@@ -20,7 +20,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace extension {
-class MyExt2 : public ::android::Parcelable {
+class LIBBINDER_EXPORTED MyExt2 : public ::android::Parcelable {
 public:
   int32_t a = 0;
   ::android::aidl::tests::extension::MyExt b;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
index b8e46b05..c13bc4c4 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
@@ -15,7 +15,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace extension {
-class MyExtLike : public ::android::Parcelable {
+class LIBBINDER_EXPORTED MyExtLike : public ::android::Parcelable {
 public:
   int32_t a = 0;
   ::android::String16 b;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BnNestedService.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BnNestedService.h
index c676ccab..46eaa088 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BnNestedService.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BnNestedService.h
@@ -15,7 +15,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace nested {
-class BnNestedService : public ::android::BnInterface<INestedService> {
+class LIBBINDER_EXPORTED BnNestedService : public ::android::BnInterface<INestedService> {
 public:
   static constexpr uint32_t TRANSACTION_flipStatus = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_flipStatusWithCallback = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -23,7 +23,7 @@ public:
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnNestedService
 
-class INestedServiceDelegator : public BnNestedService {
+class LIBBINDER_EXPORTED INestedServiceDelegator : public BnNestedService {
 public:
   explicit INestedServiceDelegator(const ::android::sp<INestedService> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BpNestedService.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BpNestedService.h
index 640fa530..ae435b81 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BpNestedService.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BpNestedService.h
@@ -13,7 +13,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace nested {
-class BpNestedService : public ::android::BpInterface<INestedService> {
+class LIBBINDER_EXPORTED BpNestedService : public ::android::BpInterface<INestedService> {
 public:
   explicit BpNestedService(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpNestedService() = default;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
index ebb16769..8632532d 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
@@ -19,13 +19,13 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace nested {
-class DeeplyNested : public ::android::Parcelable {
+class LIBBINDER_EXPORTED DeeplyNested : public ::android::Parcelable {
 public:
-  class B : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED B : public ::android::Parcelable {
   public:
-    class C : public ::android::Parcelable {
+    class LIBBINDER_EXPORTED C : public ::android::Parcelable {
     public:
-      class D : public ::android::Parcelable {
+      class LIBBINDER_EXPORTED D : public ::android::Parcelable {
       public:
         enum class E : int8_t {
           OK = 0,
@@ -126,7 +126,7 @@ public:
       return _aidl_os.str();
     }
   };  // class B
-  class A : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED A : public ::android::Parcelable {
   public:
     ::android::aidl::tests::nested::DeeplyNested::B::C::D::E e = ::android::aidl::tests::nested::DeeplyNested::B::C::D::E::OK;
     inline bool operator==(const A& _rhs) const {
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
index 97e65611..0323369d 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
@@ -24,13 +24,13 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace nested {
-class INestedServiceDelegator;
+class LIBBINDER_EXPORTED INestedServiceDelegator;
 
-class INestedService : public ::android::IInterface {
+class LIBBINDER_EXPORTED INestedService : public ::android::IInterface {
 public:
   typedef INestedServiceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(NestedService)
-  class Result : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED Result : public ::android::Parcelable {
   public:
     ::android::aidl::tests::nested::ParcelableWithNested::Status status = ::android::aidl::tests::nested::ParcelableWithNested::Status::OK;
     inline bool operator==(const Result& _rhs) const {
@@ -66,16 +66,16 @@ public:
       return _aidl_os.str();
     }
   };  // class Result
-  class ICallbackDelegator;
+  class LIBBINDER_EXPORTED ICallbackDelegator;
 
-  class ICallback : public ::android::IInterface {
+  class LIBBINDER_EXPORTED ICallback : public ::android::IInterface {
   public:
     typedef ICallbackDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(Callback)
     virtual ::android::binder::Status done(::android::aidl::tests::nested::ParcelableWithNested::Status status) = 0;
   };  // class ICallback
 
-  class ICallbackDefault : public ICallback {
+  class LIBBINDER_EXPORTED ICallbackDefault : public ICallback {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -84,20 +84,20 @@ public:
       return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
     }
   };  // class ICallbackDefault
-  class BpCallback : public ::android::BpInterface<ICallback> {
+  class LIBBINDER_EXPORTED BpCallback : public ::android::BpInterface<ICallback> {
   public:
     explicit BpCallback(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpCallback() = default;
     ::android::binder::Status done(::android::aidl::tests::nested::ParcelableWithNested::Status status) override;
   };  // class BpCallback
-  class BnCallback : public ::android::BnInterface<ICallback> {
+  class LIBBINDER_EXPORTED BnCallback : public ::android::BnInterface<ICallback> {
   public:
     static constexpr uint32_t TRANSACTION_done = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     explicit BnCallback();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnCallback
 
-  class ICallbackDelegator : public BnCallback {
+  class LIBBINDER_EXPORTED ICallbackDelegator : public BnCallback {
   public:
     explicit ICallbackDelegator(const ::android::sp<ICallback> &impl) : _aidl_delegate(impl) {}
 
@@ -112,7 +112,7 @@ public:
   virtual ::android::binder::Status flipStatusWithCallback(::android::aidl::tests::nested::ParcelableWithNested::Status status, const ::android::sp<::android::aidl::tests::nested::INestedService::ICallback>& cb) = 0;
 };  // class INestedService
 
-class INestedServiceDefault : public INestedService {
+class LIBBINDER_EXPORTED INestedServiceDefault : public INestedService {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
index ff884a3c..d01d18c2 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
@@ -19,7 +19,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace nested {
-class ParcelableWithNested : public ::android::Parcelable {
+class LIBBINDER_EXPORTED ParcelableWithNested : public ::android::Parcelable {
 public:
   enum class Status : int8_t {
     OK = 0,
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
index 306c4e05..0b58a4c2 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
@@ -29,7 +29,7 @@ namespace tests {
 namespace unions {
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
-class EnumUnion : public ::android::Parcelable {
+class LIBBINDER_EXPORTED EnumUnion : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     intEnum = 0,
diff --git a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
index 07481840..937cb55a 100644
--- a/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
+++ b/tests/golden_output/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
@@ -26,7 +26,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace unions {
-class UnionInUnion : public ::android::Parcelable {
+class LIBBINDER_EXPORTED UnionInUnion : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     first = 0,
diff --git a/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/ArrayOfInterfaces.java b/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/ArrayOfInterfaces.java
index 978fe3c9..bf3c430b 100644
--- a/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/ArrayOfInterfaces.java
+++ b/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/ArrayOfInterfaces.java
@@ -222,7 +222,9 @@ public class ArrayOfInterfaces implements android.os.Parcelable
             _arg2 = data.createInterfaceArray(android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[]::new, android.aidl.tests.ArrayOfInterfaces.IEmptyInterface.Stub::asInterface);
             android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[] _arg3;
             int _arg3_length = data.readInt();
-            if (_arg3_length < 0) {
+            if (_arg3_length > 1000000) {
+              throw new android.os.BadParcelableException("Array too large: " + _arg3_length);
+            } else if (_arg3_length < 0) {
               _arg3 = null;
             } else {
               _arg3 = new android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[_arg3_length];
@@ -233,7 +235,9 @@ public class ArrayOfInterfaces implements android.os.Parcelable
             _arg5 = data.createInterfaceArray(android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[]::new, android.aidl.tests.ArrayOfInterfaces.IEmptyInterface.Stub::asInterface);
             android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[] _arg6;
             int _arg6_length = data.readInt();
-            if (_arg6_length < 0) {
+            if (_arg6_length > 1000000) {
+              throw new android.os.BadParcelableException("Array too large: " + _arg6_length);
+            } else if (_arg6_length < 0) {
               _arg6 = null;
             } else {
               _arg6 = new android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[_arg6_length];
diff --git a/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/ITestService.java b/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/ITestService.java
index bb1770b8..10284b04 100644
--- a/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/ITestService.java
+++ b/tests/golden_output/aidl-test-interface-java-source/gen/android/aidl/tests/ITestService.java
@@ -1103,7 +1103,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createBooleanArray();
           boolean[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new boolean[_arg1_length];
@@ -1121,7 +1123,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createByteArray();
           byte[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new byte[_arg1_length];
@@ -1139,7 +1143,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createCharArray();
           char[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new char[_arg1_length];
@@ -1157,7 +1163,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createIntArray();
           int[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new int[_arg1_length];
@@ -1175,7 +1183,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createLongArray();
           long[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new long[_arg1_length];
@@ -1193,7 +1203,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createFloatArray();
           float[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new float[_arg1_length];
@@ -1211,7 +1223,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createDoubleArray();
           double[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new double[_arg1_length];
@@ -1229,7 +1243,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createStringArray();
           java.lang.String[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new java.lang.String[_arg1_length];
@@ -1247,7 +1263,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createByteArray();
           byte[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new byte[_arg1_length];
@@ -1265,7 +1283,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createIntArray();
           int[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new int[_arg1_length];
@@ -1283,7 +1303,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createLongArray();
           long[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new long[_arg1_length];
@@ -1424,7 +1446,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createTypedArray(android.os.ParcelFileDescriptor.CREATOR);
           android.os.ParcelFileDescriptor[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new android.os.ParcelFileDescriptor[_arg1_length];
@@ -1597,7 +1621,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createStringArray();
           java.lang.String[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new java.lang.String[_arg1_length];
@@ -1615,7 +1641,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createStringArray();
           java.lang.String[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new java.lang.String[_arg1_length];
@@ -1688,7 +1716,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createBinderArray();
           android.os.IBinder[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new android.os.IBinder[_arg1_length];
@@ -1706,7 +1736,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createBinderArray();
           android.os.IBinder[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new android.os.IBinder[_arg1_length];
@@ -1737,7 +1769,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createTypedArray(android.aidl.tests.SimpleParcelable.CREATOR);
           android.aidl.tests.SimpleParcelable[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new android.aidl.tests.SimpleParcelable[_arg1_length];
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
index 4708a514..bd665b51 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
@@ -211,7 +211,7 @@ ArrayOfInterfaces::BpMyInterface::~BpMyInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_iface);
@@ -239,13 +239,13 @@ ArrayOfInterfaces::BpMyInterface::~BpMyInterface() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*methodWithInterfaces*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
index e8ff5501..3695b2e0 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
@@ -59,17 +59,17 @@ BpCircular::~BpCircular() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*GetTestService*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ICircular::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
index 147cfde4..87712705 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
@@ -47,17 +47,17 @@ BpNamedCallback::~BpNamedCallback() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*GetName*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INamedCallback::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
index 73f954c3..08302539 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
@@ -47,17 +47,17 @@ BpNewName::~BpNewName() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*RealName*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INewName::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
index 284757af..f5fda064 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
@@ -47,17 +47,17 @@ BpOldName::~BpOldName() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*RealName*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IOldName::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
index 0d078b1f..2d5cf145 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
@@ -1402,7 +1402,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1410,13 +1410,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*UnimplementedMethod*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1443,18 +1443,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*Deprecated*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1478,18 +1478,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*TestOneway*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_ONEWAY | FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1509,7 +1509,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1517,13 +1517,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*RepeatBoolean*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1550,7 +1550,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1558,13 +1558,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 4 /*RepeatByte*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1591,7 +1591,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1599,13 +1599,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 5 /*RepeatChar*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1632,7 +1632,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1640,13 +1640,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 6 /*RepeatInt*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1673,7 +1673,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1681,13 +1681,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 7 /*RepeatLong*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1714,7 +1714,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1722,13 +1722,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 8 /*RepeatFloat*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1755,7 +1755,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1763,13 +1763,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 9 /*RepeatDouble*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1796,7 +1796,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1804,13 +1804,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 10 /*RepeatString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1837,7 +1837,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1845,13 +1845,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 11 /*RepeatByteEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1878,7 +1878,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1886,13 +1886,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 12 /*RepeatIntEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1919,7 +1919,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1927,13 +1927,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 13 /*RepeatLongEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1960,7 +1960,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1971,13 +1971,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 14 /*ReverseBoolean*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2007,7 +2007,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2018,13 +2018,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 15 /*ReverseByte*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2054,7 +2054,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2065,13 +2065,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16 /*ReverseChar*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2101,7 +2101,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2112,13 +2112,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 17 /*ReverseInt*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2148,7 +2148,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2159,13 +2159,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 18 /*ReverseLong*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2195,7 +2195,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2206,13 +2206,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 19 /*ReverseFloat*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2242,7 +2242,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2253,13 +2253,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 20 /*ReverseDouble*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2289,7 +2289,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2300,13 +2300,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 21 /*ReverseString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2336,7 +2336,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2347,13 +2347,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 22 /*ReverseByteEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2383,7 +2383,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2394,13 +2394,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 23 /*ReverseIntEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2430,7 +2430,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2441,13 +2441,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 24 /*ReverseLongEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2477,7 +2477,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2485,13 +2485,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 25 /*GetOtherTestService*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2518,7 +2518,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2529,13 +2529,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 26 /*SetOtherTestService*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2562,7 +2562,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2573,13 +2573,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 27 /*VerifyName*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2606,7 +2606,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2614,13 +2614,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 28 /*GetInterfaceArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2647,7 +2647,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2658,13 +2658,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 29 /*VerifyNamesWithInterfaceArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2691,7 +2691,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2699,13 +2699,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 30 /*GetNullableInterfaceArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2732,7 +2732,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2743,13 +2743,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 31 /*VerifyNamesWithNullableInterfaceArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2776,7 +2776,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2784,13 +2784,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 32 /*GetInterfaceList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2817,7 +2817,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2828,13 +2828,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 33 /*VerifyNamesWithInterfaceList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2861,7 +2861,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2869,13 +2869,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 34 /*ReverseStringList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2905,7 +2905,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2913,13 +2913,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 35 /*RepeatParcelFileDescriptor*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2946,7 +2946,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2957,13 +2957,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 36 /*ReverseParcelFileDescriptorArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2993,7 +2993,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3001,13 +3001,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 37 /*ThrowServiceException*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3031,7 +3031,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3039,13 +3039,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 38 /*RepeatNullableIntArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3072,7 +3072,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3080,13 +3080,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 39 /*RepeatNullableByteEnumArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3113,7 +3113,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3121,13 +3121,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 40 /*RepeatNullableIntEnumArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3154,7 +3154,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3162,13 +3162,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 41 /*RepeatNullableLongEnumArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3195,7 +3195,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3203,13 +3203,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 42 /*RepeatNullableString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3236,7 +3236,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3244,13 +3244,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 43 /*RepeatNullableStringList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3277,7 +3277,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3285,13 +3285,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 44 /*RepeatNullableParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3318,7 +3318,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3326,13 +3326,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 45 /*RepeatNullableParcelableArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3359,7 +3359,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3367,13 +3367,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 46 /*RepeatNullableParcelableList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3400,7 +3400,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3408,13 +3408,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 47 /*TakesAnIBinder*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3438,7 +3438,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3446,13 +3446,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 48 /*TakesANullableIBinder*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3476,7 +3476,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3484,13 +3484,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 49 /*TakesAnIBinderList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3514,7 +3514,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3522,13 +3522,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 50 /*TakesANullableIBinderList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3552,7 +3552,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3560,13 +3560,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 51 /*RepeatUtf8CppString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3593,7 +3593,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3601,13 +3601,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 52 /*RepeatNullableUtf8CppString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3634,7 +3634,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3645,13 +3645,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 53 /*ReverseUtf8CppString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3681,7 +3681,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3692,13 +3692,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 54 /*ReverseNullableUtf8CppString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3728,7 +3728,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3736,13 +3736,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 55 /*ReverseUtf8CppStringList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3772,7 +3772,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3780,13 +3780,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 56 /*GetCallback*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3813,7 +3813,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3821,13 +3821,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 57 /*FillOutStructuredParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3854,7 +3854,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3862,13 +3862,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 58 /*RepeatExtendableParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3895,7 +3895,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3903,13 +3903,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 59 /*ReverseList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3936,7 +3936,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3947,13 +3947,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 60 /*ReverseIBinderArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3983,7 +3983,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3994,13 +3994,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 61 /*ReverseNullableIBinderArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4030,7 +4030,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -4038,13 +4038,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 62 /*RepeatSimpleParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4074,7 +4074,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -4085,13 +4085,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 63 /*ReverseSimpleParcelables*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4121,18 +4121,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 64 /*GetOldNameInterface*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4159,18 +4159,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 65 /*GetNewNameInterface*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4197,7 +4197,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -4205,13 +4205,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 66 /*GetUnionTags*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4238,18 +4238,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 67 /*GetCppJavaTests*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4276,18 +4276,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 68 /*getBackendType*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4314,18 +4314,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 69 /*GetCircular*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -5239,17 +5239,17 @@ ITestService::CompilerChecks::BpNoPrefixInterface::~BpNoPrefixInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*foo*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INoPrefixInterface::getDefaultImpl()) {
@@ -5411,17 +5411,17 @@ ITestService::CompilerChecks::INoPrefixInterface::BpNestedNoPrefixInterface::~Bp
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*foo*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INestedNoPrefixInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
index a4702c69..163d622d 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
@@ -205,7 +205,7 @@ ListOfInterfaces::BpMyInterface::~BpMyInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_iface);
@@ -227,13 +227,13 @@ ListOfInterfaces::BpMyInterface::~BpMyInterface() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*methodWithInterfaces*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
index 0ec9154a..67c1d477 100644
--- a/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
+++ b/tests/golden_output/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
@@ -70,20 +70,20 @@ BpNestedService::~BpNestedService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_p);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*flipStatus*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INestedService::getDefaultImpl()) {
@@ -110,7 +110,7 @@ BpNestedService::~BpNestedService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_status);
@@ -120,13 +120,13 @@ BpNestedService::~BpNestedService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*flipStatusWithCallback*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INestedService::getDefaultImpl()) {
@@ -311,20 +311,20 @@ INestedService::BpCallback::~BpCallback() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_status);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*done*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ICallback::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
index 6889bd6b..a6b0615a 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
@@ -40,7 +40,7 @@ pub mod r#IEmptyInterface {
       native: BnEmptyInterface(on_transact),
       proxy: BpEmptyInterface {
       },
-      async: IEmptyInterfaceAsync,
+      async: IEmptyInterfaceAsync(try_into_local_async),
     }
   }
   pub trait IEmptyInterface: binder::Interface + Send {
@@ -51,6 +51,9 @@ pub mod r#IEmptyInterface {
     fn setDefaultImpl(d: IEmptyInterfaceDefaultRef) -> IEmptyInterfaceDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IEmptyInterfaceAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ArrayOfInterfaces.IEmptyInterface" }
@@ -79,10 +82,26 @@ pub mod r#IEmptyInterface {
         T: IEmptyInterfaceAsyncServer + Send + Sync + 'static,
         R: binder::binder_impl::BinderAsyncRuntime + Send + Sync + 'static,
       {
+        fn try_as_async_server(&self) -> Option<&(dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IEmptyInterfaceAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnEmptyInterface>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IEmptyInterfaceAsync<P> for Wrapper {
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IEmptyInterfaceAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IEmptyInterfaceDefault: Send + Sync {
   }
@@ -114,7 +133,7 @@ pub mod r#IMyInterface {
       native: BnMyInterface(on_transact),
       proxy: BpMyInterface {
       },
-      async: IMyInterfaceAsync,
+      async: IMyInterfaceAsync(try_into_local_async),
     }
   }
   pub trait IMyInterface: binder::Interface + Send {
@@ -126,6 +145,9 @@ pub mod r#IMyInterface {
     fn setDefaultImpl(d: IMyInterfaceDefaultRef) -> IMyInterfaceDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IMyInterfaceAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IMyInterfaceAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ArrayOfInterfaces.IMyInterface" }
@@ -159,10 +181,29 @@ pub mod r#IMyInterface {
         fn r#methodWithInterfaces(&self, _arg_iface: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_iface_array_in: &[binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>], _arg_iface_array_out: &mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>, _arg_iface_array_inout: &mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_array_in: Option<&[Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_array_out: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_array_inout: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>> {
           self._rt.block_on(self._inner.r#methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_array_in, _arg_iface_array_out, _arg_iface_array_inout, _arg_nullable_iface_array_in, _arg_nullable_iface_array_out, _arg_nullable_iface_array_inout))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn IMyInterfaceAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IMyInterfaceAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnMyInterface>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IMyInterfaceAsync<P> for Wrapper {
+        fn r#methodWithInterfaces<'a>(&'a self, _arg_iface: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_iface_array_in: &'a [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>], _arg_iface_array_out: &'a mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>, _arg_iface_array_inout: &'a mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_array_in: Option<&'a [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_array_out: &'a mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_array_inout: &'a mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_array_in, _arg_iface_array_out, _arg_iface_array_inout, _arg_nullable_iface_array_in, _arg_nullable_iface_array_out, _arg_nullable_iface_array_inout))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IMyInterfaceAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IMyInterfaceDefault: Send + Sync {
     fn r#methodWithInterfaces(&self, _arg_iface: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_iface_array_in: &[binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>], _arg_iface_array_out: &mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>, _arg_iface_array_inout: &mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_array_in: Option<&[Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_array_out: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_array_inout: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>> {
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
index 9cdfa573..dd8e540e 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnCircular(on_transact),
     proxy: BpCircular {
     },
-    async: ICircularAsync,
+    async: ICircularAsync(try_into_local_async),
   }
 }
 pub trait ICircular: binder::Interface + Send {
@@ -25,6 +25,9 @@ pub trait ICircular: binder::Interface + Send {
   fn setDefaultImpl(d: ICircularDefaultRef) -> ICircularDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn ICircularAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait ICircularAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ICircular" }
@@ -58,10 +61,29 @@ impl BnCircular {
       fn r#GetTestService(&self) -> binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_12_ITestService>>> {
         self._rt.block_on(self._inner.r#GetTestService())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn ICircularAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn ICircularAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnCircular>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> ICircularAsync<P> for Wrapper {
+      fn r#GetTestService<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_12_ITestService>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetTestService())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn ICircularAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait ICircularDefault: Send + Sync {
   fn r#GetTestService(&self) -> binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_12_ITestService>>> {
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
index 59e70ca4..ed30b89b 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnDeprecated(on_transact),
     proxy: BpDeprecated {
     },
-    async: IDeprecatedAsync,
+    async: IDeprecatedAsync(try_into_local_async),
   }
 }
 #[deprecated = "test"]
@@ -25,6 +25,9 @@ pub trait IDeprecated: binder::Interface + Send {
   fn setDefaultImpl(d: IDeprecatedDefaultRef) -> IDeprecatedDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IDeprecatedAsyncServer + Send + Sync)> {
+    None
+  }
 }
 #[deprecated = "test"]
 pub trait IDeprecatedAsync<P>: binder::Interface + Send {
@@ -55,10 +58,26 @@ impl BnDeprecated {
       T: IDeprecatedAsyncServer + Send + Sync + 'static,
       R: binder::binder_impl::BinderAsyncRuntime + Send + Sync + 'static,
     {
+      fn try_as_async_server(&self) -> Option<&(dyn IDeprecatedAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IDeprecatedAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnDeprecated>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> IDeprecatedAsync<P> for Wrapper {
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IDeprecatedAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait IDeprecatedDefault: Send + Sync {
 }
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
index 7b4e3f91..bd0cd82c 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnNamedCallback(on_transact),
     proxy: BpNamedCallback {
     },
-    async: INamedCallbackAsync,
+    async: INamedCallbackAsync(try_into_local_async),
   }
 }
 pub trait INamedCallback: binder::Interface + Send {
@@ -25,6 +25,9 @@ pub trait INamedCallback: binder::Interface + Send {
   fn setDefaultImpl(d: INamedCallbackDefaultRef) -> INamedCallbackDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn INamedCallbackAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait INamedCallbackAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.INamedCallback" }
@@ -58,10 +61,29 @@ impl BnNamedCallback {
       fn r#GetName(&self) -> binder::Result<String> {
         self._rt.block_on(self._inner.r#GetName())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn INamedCallbackAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn INamedCallbackAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnNamedCallback>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> INamedCallbackAsync<P> for Wrapper {
+      fn r#GetName<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetName())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn INamedCallbackAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait INamedCallbackDefault: Send + Sync {
   fn r#GetName(&self) -> binder::Result<String> {
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
index f2a8678c..53b6fe90 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnNewName(on_transact),
     proxy: BpNewName {
     },
-    async: INewNameAsync,
+    async: INewNameAsync(try_into_local_async),
   }
 }
 pub trait INewName: binder::Interface + Send {
@@ -25,6 +25,9 @@ pub trait INewName: binder::Interface + Send {
   fn setDefaultImpl(d: INewNameDefaultRef) -> INewNameDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn INewNameAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait INewNameAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.IOldName" }
@@ -58,10 +61,29 @@ impl BnNewName {
       fn r#RealName(&self) -> binder::Result<String> {
         self._rt.block_on(self._inner.r#RealName())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn INewNameAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn INewNameAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnNewName>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> INewNameAsync<P> for Wrapper {
+      fn r#RealName<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RealName())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn INewNameAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait INewNameDefault: Send + Sync {
   fn r#RealName(&self) -> binder::Result<String> {
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
index 279b6de1..28f8365d 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnOldName(on_transact),
     proxy: BpOldName {
     },
-    async: IOldNameAsync,
+    async: IOldNameAsync(try_into_local_async),
   }
 }
 pub trait IOldName: binder::Interface + Send {
@@ -25,6 +25,9 @@ pub trait IOldName: binder::Interface + Send {
   fn setDefaultImpl(d: IOldNameDefaultRef) -> IOldNameDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IOldNameAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait IOldNameAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.IOldName" }
@@ -58,10 +61,29 @@ impl BnOldName {
       fn r#RealName(&self) -> binder::Result<String> {
         self._rt.block_on(self._inner.r#RealName())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn IOldNameAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IOldNameAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnOldName>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> IOldNameAsync<P> for Wrapper {
+      fn r#RealName<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RealName())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IOldNameAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait IOldNameDefault: Send + Sync {
   fn r#RealName(&self) -> binder::Result<String> {
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
index 9e4cb6a2..7d3d4021 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnTestService(on_transact),
     proxy: BpTestService {
     },
-    async: ITestServiceAsync,
+    async: ITestServiceAsync(try_into_local_async),
   }
 }
 pub trait ITestService: binder::Interface + Send {
@@ -95,13 +95,16 @@ pub trait ITestService: binder::Interface + Send {
   fn setDefaultImpl(d: ITestServiceDefaultRef) -> ITestServiceDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn ITestServiceAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait ITestServiceAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ITestService" }
   fn r#UnimplementedMethod<'a>(&'a self, _arg_arg: i32) -> binder::BoxFuture<'a, binder::Result<i32>>;
   #[deprecated = "to make sure we have something in system/tools/aidl which does a compile check of deprecated and make sure this is reflected in goldens"]
   fn r#Deprecated<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>>;
-  fn r#TestOneway(&self) -> std::future::Ready<binder::Result<()>>;
+  fn r#TestOneway<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>>;
   fn r#RepeatBoolean<'a>(&'a self, _arg_token: bool) -> binder::BoxFuture<'a, binder::Result<bool>>;
   fn r#RepeatByte<'a>(&'a self, _arg_token: i8) -> binder::BoxFuture<'a, binder::Result<i8>>;
   fn r#RepeatChar<'a>(&'a self, _arg_token: u16) -> binder::BoxFuture<'a, binder::Result<u16>>;
@@ -475,10 +478,236 @@ impl BnTestService {
       fn r#GetCircular(&self, _arg_cp: &mut crate::mangled::_7_android_4_aidl_5_tests_18_CircularParcelable) -> binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_9_ICircular>> {
         self._rt.block_on(self._inner.r#GetCircular(_arg_cp))
       }
+      fn try_as_async_server(&self) -> Option<&(dyn ITestServiceAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn ITestServiceAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnTestService>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for Wrapper {
+      fn r#UnimplementedMethod<'a>(&'a self, _arg_arg: i32) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#UnimplementedMethod(_arg_arg))
+      }
+      fn r#Deprecated<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#Deprecated())
+      }
+      fn r#TestOneway<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#TestOneway())
+      }
+      fn r#RepeatBoolean<'a>(&'a self, _arg_token: bool) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatBoolean(_arg_token))
+      }
+      fn r#RepeatByte<'a>(&'a self, _arg_token: i8) -> binder::BoxFuture<'a, binder::Result<i8>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatByte(_arg_token))
+      }
+      fn r#RepeatChar<'a>(&'a self, _arg_token: u16) -> binder::BoxFuture<'a, binder::Result<u16>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatChar(_arg_token))
+      }
+      fn r#RepeatInt<'a>(&'a self, _arg_token: i32) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatInt(_arg_token))
+      }
+      fn r#RepeatLong<'a>(&'a self, _arg_token: i64) -> binder::BoxFuture<'a, binder::Result<i64>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatLong(_arg_token))
+      }
+      fn r#RepeatFloat<'a>(&'a self, _arg_token: f32) -> binder::BoxFuture<'a, binder::Result<f32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatFloat(_arg_token))
+      }
+      fn r#RepeatDouble<'a>(&'a self, _arg_token: f64) -> binder::BoxFuture<'a, binder::Result<f64>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatDouble(_arg_token))
+      }
+      fn r#RepeatString<'a>(&'a self, _arg_token: &'a str) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatString(_arg_token))
+      }
+      fn r#RepeatByteEnum<'a>(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatByteEnum(_arg_token))
+      }
+      fn r#RepeatIntEnum<'a>(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatIntEnum(_arg_token))
+      }
+      fn r#RepeatLongEnum<'a>(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatLongEnum(_arg_token))
+      }
+      fn r#ReverseBoolean<'a>(&'a self, _arg_input: &'a [bool], _arg_repeated: &'a mut Vec<bool>) -> binder::BoxFuture<'a, binder::Result<Vec<bool>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseBoolean(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseByte<'a>(&'a self, _arg_input: &'a [u8], _arg_repeated: &'a mut Vec<u8>) -> binder::BoxFuture<'a, binder::Result<Vec<u8>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseByte(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseChar<'a>(&'a self, _arg_input: &'a [u16], _arg_repeated: &'a mut Vec<u16>) -> binder::BoxFuture<'a, binder::Result<Vec<u16>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseChar(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseInt<'a>(&'a self, _arg_input: &'a [i32], _arg_repeated: &'a mut Vec<i32>) -> binder::BoxFuture<'a, binder::Result<Vec<i32>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseInt(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseLong<'a>(&'a self, _arg_input: &'a [i64], _arg_repeated: &'a mut Vec<i64>) -> binder::BoxFuture<'a, binder::Result<Vec<i64>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseLong(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseFloat<'a>(&'a self, _arg_input: &'a [f32], _arg_repeated: &'a mut Vec<f32>) -> binder::BoxFuture<'a, binder::Result<Vec<f32>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseFloat(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseDouble<'a>(&'a self, _arg_input: &'a [f64], _arg_repeated: &'a mut Vec<f64>) -> binder::BoxFuture<'a, binder::Result<Vec<f64>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseDouble(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseString<'a>(&'a self, _arg_input: &'a [String], _arg_repeated: &'a mut Vec<String>) -> binder::BoxFuture<'a, binder::Result<Vec<String>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseString(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseByteEnum<'a>(&'a self, _arg_input: &'a [crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum], _arg_repeated: &'a mut Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>) -> binder::BoxFuture<'a, binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseByteEnum(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseIntEnum<'a>(&'a self, _arg_input: &'a [crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum], _arg_repeated: &'a mut Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>) -> binder::BoxFuture<'a, binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseIntEnum(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseLongEnum<'a>(&'a self, _arg_input: &'a [crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum], _arg_repeated: &'a mut Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>) -> binder::BoxFuture<'a, binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseLongEnum(_arg_input, _arg_repeated))
+      }
+      fn r#GetOtherTestService<'a>(&'a self, _arg_name: &'a str) -> binder::BoxFuture<'a, binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetOtherTestService(_arg_name))
+      }
+      fn r#SetOtherTestService<'a>(&'a self, _arg_name: &'a str, _arg_service: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#SetOtherTestService(_arg_name, _arg_service))
+      }
+      fn r#VerifyName<'a>(&'a self, _arg_service: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>, _arg_name: &'a str) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#VerifyName(_arg_service, _arg_name))
+      }
+      fn r#GetInterfaceArray<'a>(&'a self, _arg_names: &'a [String]) -> binder::BoxFuture<'a, binder::Result<Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetInterfaceArray(_arg_names))
+      }
+      fn r#VerifyNamesWithInterfaceArray<'a>(&'a self, _arg_services: &'a [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>], _arg_names: &'a [String]) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#VerifyNamesWithInterfaceArray(_arg_services, _arg_names))
+      }
+      fn r#GetNullableInterfaceArray<'a>(&'a self, _arg_names: Option<&'a [Option<String>]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetNullableInterfaceArray(_arg_names))
+      }
+      fn r#VerifyNamesWithNullableInterfaceArray<'a>(&'a self, _arg_services: Option<&'a [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>]>, _arg_names: Option<&'a [Option<String>]>) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#VerifyNamesWithNullableInterfaceArray(_arg_services, _arg_names))
+      }
+      fn r#GetInterfaceList<'a>(&'a self, _arg_names: Option<&'a [Option<String>]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetInterfaceList(_arg_names))
+      }
+      fn r#VerifyNamesWithInterfaceList<'a>(&'a self, _arg_services: Option<&'a [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>]>, _arg_names: Option<&'a [Option<String>]>) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#VerifyNamesWithInterfaceList(_arg_services, _arg_names))
+      }
+      fn r#ReverseStringList<'a>(&'a self, _arg_input: &'a [String], _arg_repeated: &'a mut Vec<String>) -> binder::BoxFuture<'a, binder::Result<Vec<String>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseStringList(_arg_input, _arg_repeated))
+      }
+      fn r#RepeatParcelFileDescriptor<'a>(&'a self, _arg_read: &'a binder::ParcelFileDescriptor) -> binder::BoxFuture<'a, binder::Result<binder::ParcelFileDescriptor>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatParcelFileDescriptor(_arg_read))
+      }
+      fn r#ReverseParcelFileDescriptorArray<'a>(&'a self, _arg_input: &'a [binder::ParcelFileDescriptor], _arg_repeated: &'a mut Vec<Option<binder::ParcelFileDescriptor>>) -> binder::BoxFuture<'a, binder::Result<Vec<binder::ParcelFileDescriptor>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseParcelFileDescriptorArray(_arg_input, _arg_repeated))
+      }
+      fn r#ThrowServiceException<'a>(&'a self, _arg_code: i32) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ThrowServiceException(_arg_code))
+      }
+      fn r#RepeatNullableIntArray<'a>(&'a self, _arg_input: Option<&'a [i32]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<i32>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableIntArray(_arg_input))
+      }
+      fn r#RepeatNullableByteEnumArray<'a>(&'a self, _arg_input: Option<&'a [crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableByteEnumArray(_arg_input))
+      }
+      fn r#RepeatNullableIntEnumArray<'a>(&'a self, _arg_input: Option<&'a [crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableIntEnumArray(_arg_input))
+      }
+      fn r#RepeatNullableLongEnumArray<'a>(&'a self, _arg_input: Option<&'a [crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableLongEnumArray(_arg_input))
+      }
+      fn r#RepeatNullableString<'a>(&'a self, _arg_input: Option<&'a str>) -> binder::BoxFuture<'a, binder::Result<Option<String>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableString(_arg_input))
+      }
+      fn r#RepeatNullableStringList<'a>(&'a self, _arg_input: Option<&'a [Option<String>]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<String>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableStringList(_arg_input))
+      }
+      fn r#RepeatNullableParcelable<'a>(&'a self, _arg_input: Option<&'a crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>) -> binder::BoxFuture<'a, binder::Result<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableParcelable(_arg_input))
+      }
+      fn r#RepeatNullableParcelableArray<'a>(&'a self, _arg_input: Option<&'a [Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableParcelableArray(_arg_input))
+      }
+      fn r#RepeatNullableParcelableList<'a>(&'a self, _arg_input: Option<&'a [Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableParcelableList(_arg_input))
+      }
+      fn r#TakesAnIBinder<'a>(&'a self, _arg_input: &'a binder::SpIBinder) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#TakesAnIBinder(_arg_input))
+      }
+      fn r#TakesANullableIBinder<'a>(&'a self, _arg_input: Option<&'a binder::SpIBinder>) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#TakesANullableIBinder(_arg_input))
+      }
+      fn r#TakesAnIBinderList<'a>(&'a self, _arg_input: &'a [binder::SpIBinder]) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#TakesAnIBinderList(_arg_input))
+      }
+      fn r#TakesANullableIBinderList<'a>(&'a self, _arg_input: Option<&'a [Option<binder::SpIBinder>]>) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#TakesANullableIBinderList(_arg_input))
+      }
+      fn r#RepeatUtf8CppString<'a>(&'a self, _arg_token: &'a str) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatUtf8CppString(_arg_token))
+      }
+      fn r#RepeatNullableUtf8CppString<'a>(&'a self, _arg_token: Option<&'a str>) -> binder::BoxFuture<'a, binder::Result<Option<String>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableUtf8CppString(_arg_token))
+      }
+      fn r#ReverseUtf8CppString<'a>(&'a self, _arg_input: &'a [String], _arg_repeated: &'a mut Vec<String>) -> binder::BoxFuture<'a, binder::Result<Vec<String>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseUtf8CppString(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseNullableUtf8CppString<'a>(&'a self, _arg_input: Option<&'a [Option<String>]>, _arg_repeated: &'a mut Option<Vec<Option<String>>>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<String>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseNullableUtf8CppString(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseUtf8CppStringList<'a>(&'a self, _arg_input: Option<&'a [Option<String>]>, _arg_repeated: &'a mut Option<Vec<Option<String>>>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<String>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseUtf8CppStringList(_arg_input, _arg_repeated))
+      }
+      fn r#GetCallback<'a>(&'a self, _arg_return_null: bool) -> binder::BoxFuture<'a, binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetCallback(_arg_return_null))
+      }
+      fn r#FillOutStructuredParcelable<'a>(&'a self, _arg_parcel: &'a mut crate::mangled::_7_android_4_aidl_5_tests_20_StructuredParcelable) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#FillOutStructuredParcelable(_arg_parcel))
+      }
+      fn r#RepeatExtendableParcelable<'a>(&'a self, _arg_ep: &'a crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable, _arg_ep2: &'a mut crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatExtendableParcelable(_arg_ep, _arg_ep2))
+      }
+      fn r#ReverseList<'a>(&'a self, _arg_list: &'a crate::mangled::_7_android_4_aidl_5_tests_13_RecursiveList) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_13_RecursiveList>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseList(_arg_list))
+      }
+      fn r#ReverseIBinderArray<'a>(&'a self, _arg_input: &'a [binder::SpIBinder], _arg_repeated: &'a mut Vec<Option<binder::SpIBinder>>) -> binder::BoxFuture<'a, binder::Result<Vec<binder::SpIBinder>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseIBinderArray(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseNullableIBinderArray<'a>(&'a self, _arg_input: Option<&'a [Option<binder::SpIBinder>]>, _arg_repeated: &'a mut Option<Vec<Option<binder::SpIBinder>>>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<binder::SpIBinder>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseNullableIBinderArray(_arg_input, _arg_repeated))
+      }
+      fn r#RepeatSimpleParcelable<'a>(&'a self, _arg_input: &'a simple_parcelable::SimpleParcelable, _arg_repeat: &'a mut simple_parcelable::SimpleParcelable) -> binder::BoxFuture<'a, binder::Result<simple_parcelable::SimpleParcelable>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatSimpleParcelable(_arg_input, _arg_repeat))
+      }
+      fn r#ReverseSimpleParcelables<'a>(&'a self, _arg_input: &'a [simple_parcelable::SimpleParcelable], _arg_repeated: &'a mut Vec<simple_parcelable::SimpleParcelable>) -> binder::BoxFuture<'a, binder::Result<Vec<simple_parcelable::SimpleParcelable>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseSimpleParcelables(_arg_input, _arg_repeated))
+      }
+      fn r#GetOldNameInterface<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_8_IOldName>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetOldNameInterface())
+      }
+      fn r#GetNewNameInterface<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_8_INewName>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetNewNameInterface())
+      }
+      fn r#GetUnionTags<'a>(&'a self, _arg_input: &'a [crate::mangled::_7_android_4_aidl_5_tests_5_Union]) -> binder::BoxFuture<'a, binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_5_Union_3_Tag>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetUnionTags(_arg_input))
+      }
+      fn r#GetCppJavaTests<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<Option<binder::SpIBinder>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetCppJavaTests())
+      }
+      fn r#getBackendType<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_11_BackendType>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#getBackendType())
+      }
+      fn r#GetCircular<'a>(&'a self, _arg_cp: &'a mut crate::mangled::_7_android_4_aidl_5_tests_18_CircularParcelable) -> binder::BoxFuture<'a, binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_9_ICircular>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetCircular(_arg_cp))
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn ITestServiceAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait ITestServiceDefault: Send + Sync {
   fn r#UnimplementedMethod(&self, _arg_arg: i32) -> binder::Result<i32> {
@@ -2524,13 +2753,18 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
       }
     )
   }
-  fn r#TestOneway(&self) -> std::future::Ready<binder::Result<()>> {
+  fn r#TestOneway<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
     let _aidl_data = match self.build_parcel_TestOneway() {
       Ok(_aidl_data) => _aidl_data,
-      Err(err) => return std::future::ready(Err(err)),
+      Err(err) => return Box::pin(std::future::ready(Err(err))),
     };
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
-    std::future::ready(self.read_response_TestOneway(_aidl_reply))
+    let binder = self.binder.clone();
+    P::spawn(
+      move || binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move |_aidl_reply| async move {
+        self.read_response_TestOneway(_aidl_reply)
+      }
+    )
   }
   fn r#RepeatBoolean<'a>(&'a self, _arg_token: bool) -> binder::BoxFuture<'a, binder::Result<bool>> {
     let _aidl_data = match self.build_parcel_RepeatBoolean(_arg_token) {
@@ -4542,7 +4776,7 @@ pub mod r#CompilerChecks {
         native: BnFoo(on_transact),
         proxy: BpFoo {
         },
-        async: IFooAsync,
+        async: IFooAsync(try_into_local_async),
       }
     }
     pub trait IFoo: binder::Interface + Send {
@@ -4553,6 +4787,9 @@ pub mod r#CompilerChecks {
       fn setDefaultImpl(d: IFooDefaultRef) -> IFooDefaultRef where Self: Sized {
         std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
       }
+      fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IFooAsyncServer + Send + Sync)> {
+        None
+      }
     }
     pub trait IFooAsync<P>: binder::Interface + Send {
       fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ITestService.CompilerChecks.Foo" }
@@ -4581,10 +4818,26 @@ pub mod r#CompilerChecks {
           T: IFooAsyncServer + Send + Sync + 'static,
           R: binder::binder_impl::BinderAsyncRuntime + Send + Sync + 'static,
         {
+          fn try_as_async_server(&self) -> Option<&(dyn IFooAsyncServer + Send + Sync)> {
+            Some(&self._inner)
+          }
         }
         let wrapped = Wrapper { _inner: inner, _rt: rt };
         Self::new_binder(wrapped, features)
       }
+      pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IFooAsync<P>>> {
+        struct Wrapper {
+          _native: binder::binder_impl::Binder<BnFoo>
+        }
+        impl binder::Interface for Wrapper {}
+        impl<P: binder::BinderAsyncPool> IFooAsync<P> for Wrapper {
+        }
+        if _native.try_as_async_server().is_some() {
+          Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IFooAsync<P>>))
+        } else {
+          None
+        }
+      }
     }
     pub trait IFooDefault: Send + Sync {
     }
@@ -4711,7 +4964,7 @@ pub mod r#CompilerChecks {
         native: BnNoPrefixInterface(on_transact),
         proxy: BpNoPrefixInterface {
         },
-        async: INoPrefixInterfaceAsync,
+        async: INoPrefixInterfaceAsync(try_into_local_async),
       }
     }
     pub trait INoPrefixInterface: binder::Interface + Send {
@@ -4723,6 +4976,9 @@ pub mod r#CompilerChecks {
       fn setDefaultImpl(d: INoPrefixInterfaceDefaultRef) -> INoPrefixInterfaceDefaultRef where Self: Sized {
         std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
       }
+      fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn INoPrefixInterfaceAsyncServer + Send + Sync)> {
+        None
+      }
     }
     pub trait INoPrefixInterfaceAsync<P>: binder::Interface + Send {
       fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface" }
@@ -4756,10 +5012,29 @@ pub mod r#CompilerChecks {
           fn r#foo(&self) -> binder::Result<()> {
             self._rt.block_on(self._inner.r#foo())
           }
+          fn try_as_async_server(&self) -> Option<&(dyn INoPrefixInterfaceAsyncServer + Send + Sync)> {
+            Some(&self._inner)
+          }
         }
         let wrapped = Wrapper { _inner: inner, _rt: rt };
         Self::new_binder(wrapped, features)
       }
+      pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn INoPrefixInterfaceAsync<P>>> {
+        struct Wrapper {
+          _native: binder::binder_impl::Binder<BnNoPrefixInterface>
+        }
+        impl binder::Interface for Wrapper {}
+        impl<P: binder::BinderAsyncPool> INoPrefixInterfaceAsync<P> for Wrapper {
+          fn r#foo<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+            Box::pin(self._native.try_as_async_server().unwrap().r#foo())
+          }
+        }
+        if _native.try_as_async_server().is_some() {
+          Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn INoPrefixInterfaceAsync<P>>))
+        } else {
+          None
+        }
+      }
     }
     pub trait INoPrefixInterfaceDefault: Send + Sync {
       fn r#foo(&self) -> binder::Result<()> {
@@ -4866,7 +5141,7 @@ pub mod r#CompilerChecks {
           native: BnNestedNoPrefixInterface(on_transact),
           proxy: BpNestedNoPrefixInterface {
           },
-          async: INestedNoPrefixInterfaceAsync,
+          async: INestedNoPrefixInterfaceAsync(try_into_local_async),
         }
       }
       pub trait INestedNoPrefixInterface: binder::Interface + Send {
@@ -4878,6 +5153,9 @@ pub mod r#CompilerChecks {
         fn setDefaultImpl(d: INestedNoPrefixInterfaceDefaultRef) -> INestedNoPrefixInterfaceDefaultRef where Self: Sized {
           std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
         }
+        fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn INestedNoPrefixInterfaceAsyncServer + Send + Sync)> {
+          None
+        }
       }
       pub trait INestedNoPrefixInterfaceAsync<P>: binder::Interface + Send {
         fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface.NestedNoPrefixInterface" }
@@ -4911,10 +5189,29 @@ pub mod r#CompilerChecks {
             fn r#foo(&self) -> binder::Result<()> {
               self._rt.block_on(self._inner.r#foo())
             }
+            fn try_as_async_server(&self) -> Option<&(dyn INestedNoPrefixInterfaceAsyncServer + Send + Sync)> {
+              Some(&self._inner)
+            }
           }
           let wrapped = Wrapper { _inner: inner, _rt: rt };
           Self::new_binder(wrapped, features)
         }
+        pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn INestedNoPrefixInterfaceAsync<P>>> {
+          struct Wrapper {
+            _native: binder::binder_impl::Binder<BnNestedNoPrefixInterface>
+          }
+          impl binder::Interface for Wrapper {}
+          impl<P: binder::BinderAsyncPool> INestedNoPrefixInterfaceAsync<P> for Wrapper {
+            fn r#foo<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+              Box::pin(self._native.try_as_async_server().unwrap().r#foo())
+            }
+          }
+          if _native.try_as_async_server().is_some() {
+            Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn INestedNoPrefixInterfaceAsync<P>>))
+          } else {
+            None
+          }
+        }
       }
       pub trait INestedNoPrefixInterfaceDefault: Send + Sync {
         fn r#foo(&self) -> binder::Result<()> {
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
index 452b944b..852491fb 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
@@ -40,7 +40,7 @@ pub mod r#IEmptyInterface {
       native: BnEmptyInterface(on_transact),
       proxy: BpEmptyInterface {
       },
-      async: IEmptyInterfaceAsync,
+      async: IEmptyInterfaceAsync(try_into_local_async),
     }
   }
   pub trait IEmptyInterface: binder::Interface + Send {
@@ -51,6 +51,9 @@ pub mod r#IEmptyInterface {
     fn setDefaultImpl(d: IEmptyInterfaceDefaultRef) -> IEmptyInterfaceDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IEmptyInterfaceAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ListOfInterfaces.IEmptyInterface" }
@@ -79,10 +82,26 @@ pub mod r#IEmptyInterface {
         T: IEmptyInterfaceAsyncServer + Send + Sync + 'static,
         R: binder::binder_impl::BinderAsyncRuntime + Send + Sync + 'static,
       {
+        fn try_as_async_server(&self) -> Option<&(dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IEmptyInterfaceAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnEmptyInterface>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IEmptyInterfaceAsync<P> for Wrapper {
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IEmptyInterfaceAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IEmptyInterfaceDefault: Send + Sync {
   }
@@ -114,7 +133,7 @@ pub mod r#IMyInterface {
       native: BnMyInterface(on_transact),
       proxy: BpMyInterface {
       },
-      async: IMyInterfaceAsync,
+      async: IMyInterfaceAsync(try_into_local_async),
     }
   }
   pub trait IMyInterface: binder::Interface + Send {
@@ -126,6 +145,9 @@ pub mod r#IMyInterface {
     fn setDefaultImpl(d: IMyInterfaceDefaultRef) -> IMyInterfaceDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IMyInterfaceAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IMyInterfaceAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ListOfInterfaces.IMyInterface" }
@@ -159,10 +181,29 @@ pub mod r#IMyInterface {
         fn r#methodWithInterfaces(&self, _arg_iface: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_iface_list_in: &[binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>], _arg_iface_list_out: &mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>, _arg_iface_list_inout: &mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_list_in: Option<&[Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_list_out: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_list_inout: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>> {
           self._rt.block_on(self._inner.r#methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_list_in, _arg_iface_list_out, _arg_iface_list_inout, _arg_nullable_iface_list_in, _arg_nullable_iface_list_out, _arg_nullable_iface_list_inout))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn IMyInterfaceAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IMyInterfaceAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnMyInterface>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IMyInterfaceAsync<P> for Wrapper {
+        fn r#methodWithInterfaces<'a>(&'a self, _arg_iface: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_iface_list_in: &'a [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>], _arg_iface_list_out: &'a mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>, _arg_iface_list_inout: &'a mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_list_in: Option<&'a [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_list_out: &'a mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_list_inout: &'a mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_list_in, _arg_iface_list_out, _arg_iface_list_inout, _arg_nullable_iface_list_in, _arg_nullable_iface_list_out, _arg_nullable_iface_list_inout))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IMyInterfaceAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IMyInterfaceDefault: Send + Sync {
     fn r#methodWithInterfaces(&self, _arg_iface: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_iface_list_in: &[binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>], _arg_iface_list_out: &mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>, _arg_iface_list_inout: &mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_list_in: Option<&[Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_list_out: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_list_inout: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>> {
diff --git a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
index aaebf1cb..c9a3fa71 100644
--- a/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
+++ b/tests/golden_output/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnNestedService(on_transact),
     proxy: BpNestedService {
     },
-    async: INestedServiceAsync,
+    async: INestedServiceAsync(try_into_local_async),
   }
 }
 pub trait INestedService: binder::Interface + Send {
@@ -26,6 +26,9 @@ pub trait INestedService: binder::Interface + Send {
   fn setDefaultImpl(d: INestedServiceDefaultRef) -> INestedServiceDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn INestedServiceAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait INestedServiceAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.nested.INestedService" }
@@ -64,10 +67,32 @@ impl BnNestedService {
       fn r#flipStatusWithCallback(&self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status, _arg_cb: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_9_ICallback>) -> binder::Result<()> {
         self._rt.block_on(self._inner.r#flipStatusWithCallback(_arg_status, _arg_cb))
       }
+      fn try_as_async_server(&self) -> Option<&(dyn INestedServiceAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn INestedServiceAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnNestedService>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> INestedServiceAsync<P> for Wrapper {
+      fn r#flipStatus<'a>(&'a self, _arg_p: &'a crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_6_Result>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#flipStatus(_arg_p))
+      }
+      fn r#flipStatusWithCallback<'a>(&'a self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status, _arg_cb: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_9_ICallback>) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#flipStatusWithCallback(_arg_status, _arg_cb))
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn INestedServiceAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait INestedServiceDefault: Send + Sync {
   fn r#flipStatus(&self, _arg_p: &crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_6_Result> {
@@ -236,7 +261,7 @@ pub mod r#ICallback {
       native: BnCallback(on_transact),
       proxy: BpCallback {
       },
-      async: ICallbackAsync,
+      async: ICallbackAsync(try_into_local_async),
     }
   }
   pub trait ICallback: binder::Interface + Send {
@@ -248,6 +273,9 @@ pub mod r#ICallback {
     fn setDefaultImpl(d: ICallbackDefaultRef) -> ICallbackDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn ICallbackAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait ICallbackAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.nested.INestedService.ICallback" }
@@ -281,10 +309,29 @@ pub mod r#ICallback {
         fn r#done(&self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status) -> binder::Result<()> {
           self._rt.block_on(self._inner.r#done(_arg_status))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn ICallbackAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn ICallbackAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnCallback>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> ICallbackAsync<P> for Wrapper {
+        fn r#done<'a>(&'a self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status) -> binder::BoxFuture<'a, binder::Result<()>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#done(_arg_status))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn ICallbackAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait ICallbackDefault: Send + Sync {
     fn r#done(&self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status) -> binder::Result<()> {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 0707b9bb..acbb2e2e 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -25,7 +25,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BazUnion : public ::android::Parcelable {
+class LIBBINDER_EXPORTED BazUnion : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     intNum = 0,
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
index 22baaa9b..32db1161 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BnFooInterface : public ::android::BnInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BnFooInterface : public ::android::BnInterface<IFooInterface> {
 public:
   static constexpr uint32_t TRANSACTION_originalApi = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_acceptUnionAndReturnString = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -28,7 +28,7 @@ public:
   std::string getInterfaceHash();
 };  // class BnFooInterface
 
-class IFooInterfaceDelegator : public BnFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDelegator : public BnFooInterface {
 public:
   explicit IFooInterfaceDelegator(const ::android::sp<IFooInterface> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
index 409c6f58..73690800 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BpFooInterface : public ::android::BpInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BpFooInterface : public ::android::BpInterface<IFooInterface> {
 public:
   explicit BpFooInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpFooInterface() = default;
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index c7980c52..794737f7 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class Foo : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Foo : public ::android::Parcelable {
 public:
   inline bool operator==(const Foo&) const {
     return std::tie() == std::tie();
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
index e7eb4be8..398ad315 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
@@ -23,9 +23,9 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class IFooInterfaceDelegator;
+class LIBBINDER_EXPORTED IFooInterfaceDelegator;
 
-class IFooInterface : public ::android::IInterface {
+class LIBBINDER_EXPORTED IFooInterface : public ::android::IInterface {
 public:
   typedef IFooInterfaceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(FooInterface)
@@ -39,7 +39,7 @@ public:
   virtual std::string getInterfaceHash() = 0;
 };  // class IFooInterface
 
-class IFooInterfaceDefault : public IFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDefault : public IFooInterface {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index aec8e2cc..7e8f34fd 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -141,17 +141,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*originalApi*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -175,20 +175,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_u);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*acceptUnionAndReturnString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -215,7 +215,7 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_inFoo);
@@ -228,13 +228,13 @@ BpFooInterface::~BpFooInterface() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*ignoreParcelablesAndRepeatInt*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -267,20 +267,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_foos);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*returnsLengthOfFooArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -312,17 +312,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -356,17 +356,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index 9c5b7d0d..d41f0bba 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -15,7 +15,7 @@ declare_binder_interface! {
       cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
       cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
     },
-    async: IFooInterfaceAsync,
+    async: IFooInterfaceAsync(try_into_local_async),
   }
 }
 pub trait IFooInterface: binder::Interface + Send {
@@ -36,6 +36,9 @@ pub trait IFooInterface: binder::Interface + Send {
   fn setDefaultImpl(d: IFooInterfaceDefaultRef) -> IFooInterfaceDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IFooInterfaceAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait IFooInterfaceAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.versioned.tests.IFooInterface" }
@@ -90,10 +93,38 @@ impl BnFooInterface {
       fn r#returnsLengthOfFooArray(&self, _arg_foos: &[crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::Result<i32> {
         self._rt.block_on(self._inner.r#returnsLengthOfFooArray(_arg_foos))
       }
+      fn try_as_async_server(&self) -> Option<&(dyn IFooInterfaceAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IFooInterfaceAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnFooInterface>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for Wrapper {
+      fn r#originalApi<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#originalApi())
+      }
+      fn r#acceptUnionAndReturnString<'a>(&'a self, _arg_u: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#acceptUnionAndReturnString(_arg_u))
+      }
+      fn r#ignoreParcelablesAndRepeatInt<'a>(&'a self, _arg_inFoo: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value))
+      }
+      fn r#returnsLengthOfFooArray<'a>(&'a self, _arg_foos: &'a [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#returnsLengthOfFooArray(_arg_foos))
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IFooInterfaceAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait IFooInterfaceDefault: Send + Sync {
   fn r#originalApi(&self) -> binder::Result<()> {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 79e366b6..cc3b2b4e 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -25,7 +25,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BazUnion : public ::android::Parcelable {
+class LIBBINDER_EXPORTED BazUnion : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     intNum = 0,
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
index 69b229ee..c0632013 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BnFooInterface : public ::android::BnInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BnFooInterface : public ::android::BnInterface<IFooInterface> {
 public:
   static constexpr uint32_t TRANSACTION_originalApi = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_acceptUnionAndReturnString = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -29,7 +29,7 @@ public:
   std::string getInterfaceHash();
 };  // class BnFooInterface
 
-class IFooInterfaceDelegator : public BnFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDelegator : public BnFooInterface {
 public:
   explicit IFooInterfaceDelegator(const ::android::sp<IFooInterface> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
index 0096981a..a5d1605e 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BpFooInterface : public ::android::BpInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BpFooInterface : public ::android::BpInterface<IFooInterface> {
 public:
   explicit BpFooInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpFooInterface() = default;
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index 0a4370dc..6818ce60 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -15,7 +15,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class Foo : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Foo : public ::android::Parcelable {
 public:
   int32_t intDefault42 = 42;
   inline bool operator==(const Foo& _rhs) const {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
index e50a31fe..b3ee1e15 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
@@ -23,9 +23,9 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class IFooInterfaceDelegator;
+class LIBBINDER_EXPORTED IFooInterfaceDelegator;
 
-class IFooInterface : public ::android::IInterface {
+class LIBBINDER_EXPORTED IFooInterface : public ::android::IInterface {
 public:
   typedef IFooInterfaceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(FooInterface)
@@ -40,7 +40,7 @@ public:
   virtual std::string getInterfaceHash() = 0;
 };  // class IFooInterface
 
-class IFooInterfaceDefault : public IFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDefault : public IFooInterface {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index aafb98ee..11fff389 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -151,17 +151,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*originalApi*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -185,20 +185,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_u);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*acceptUnionAndReturnString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -225,7 +225,7 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_inFoo);
@@ -238,13 +238,13 @@ BpFooInterface::~BpFooInterface() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*ignoreParcelablesAndRepeatInt*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -277,20 +277,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_foos);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*returnsLengthOfFooArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -317,17 +317,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 4 /*newApi*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -356,17 +356,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -400,17 +400,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index 3c883b39..1870d515 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -15,7 +15,7 @@ declare_binder_interface! {
       cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
       cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
     },
-    async: IFooInterfaceAsync,
+    async: IFooInterfaceAsync(try_into_local_async),
   }
 }
 pub trait IFooInterface: binder::Interface + Send {
@@ -37,6 +37,9 @@ pub trait IFooInterface: binder::Interface + Send {
   fn setDefaultImpl(d: IFooInterfaceDefaultRef) -> IFooInterfaceDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IFooInterfaceAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait IFooInterfaceAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.versioned.tests.IFooInterface" }
@@ -96,10 +99,41 @@ impl BnFooInterface {
       fn r#newApi(&self) -> binder::Result<()> {
         self._rt.block_on(self._inner.r#newApi())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn IFooInterfaceAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IFooInterfaceAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnFooInterface>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for Wrapper {
+      fn r#originalApi<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#originalApi())
+      }
+      fn r#acceptUnionAndReturnString<'a>(&'a self, _arg_u: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#acceptUnionAndReturnString(_arg_u))
+      }
+      fn r#ignoreParcelablesAndRepeatInt<'a>(&'a self, _arg_inFoo: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value))
+      }
+      fn r#returnsLengthOfFooArray<'a>(&'a self, _arg_foos: &'a [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#returnsLengthOfFooArray(_arg_foos))
+      }
+      fn r#newApi<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#newApi())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IFooInterfaceAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait IFooInterfaceDefault: Send + Sync {
   fn r#originalApi(&self) -> binder::Result<()> {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index a866c6b3..0a5200da 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -25,7 +25,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BazUnion : public ::android::Parcelable {
+class LIBBINDER_EXPORTED BazUnion : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     intNum = 0,
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
index 892b1634..ba837986 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BnFooInterface : public ::android::BnInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BnFooInterface : public ::android::BnInterface<IFooInterface> {
 public:
   static constexpr uint32_t TRANSACTION_originalApi = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_acceptUnionAndReturnString = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -29,7 +29,7 @@ public:
   std::string getInterfaceHash();
 };  // class BnFooInterface
 
-class IFooInterfaceDelegator : public BnFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDelegator : public BnFooInterface {
 public:
   explicit IFooInterfaceDelegator(const ::android::sp<IFooInterface> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
index ffef716a..e59d7af9 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BpFooInterface : public ::android::BpInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BpFooInterface : public ::android::BpInterface<IFooInterface> {
 public:
   explicit BpFooInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpFooInterface() = default;
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index 5e1b926a..378d274d 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -15,7 +15,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class Foo : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Foo : public ::android::Parcelable {
 public:
   int32_t intDefault42 = 42;
   inline bool operator==(const Foo& _rhs) const {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
index aa5add2a..c9b6dcba 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
@@ -23,9 +23,9 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class IFooInterfaceDelegator;
+class LIBBINDER_EXPORTED IFooInterfaceDelegator;
 
-class IFooInterface : public ::android::IInterface {
+class LIBBINDER_EXPORTED IFooInterface : public ::android::IInterface {
 public:
   typedef IFooInterfaceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(FooInterface)
@@ -40,7 +40,7 @@ public:
   virtual std::string getInterfaceHash() = 0;
 };  // class IFooInterface
 
-class IFooInterfaceDefault : public IFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDefault : public IFooInterface {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index ecc887ed..aebb8626 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -151,17 +151,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*originalApi*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -185,20 +185,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_u);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*acceptUnionAndReturnString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -225,7 +225,7 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_inFoo);
@@ -238,13 +238,13 @@ BpFooInterface::~BpFooInterface() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*ignoreParcelablesAndRepeatInt*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -277,20 +277,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_foos);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*returnsLengthOfFooArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -317,17 +317,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 4 /*newApi*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -356,17 +356,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -400,17 +400,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index 17d1406d..24e86517 100644
--- a/tests/golden_output/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -15,7 +15,7 @@ declare_binder_interface! {
       cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
       cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
     },
-    async: IFooInterfaceAsync,
+    async: IFooInterfaceAsync(try_into_local_async),
   }
 }
 pub trait IFooInterface: binder::Interface + Send {
@@ -37,6 +37,9 @@ pub trait IFooInterface: binder::Interface + Send {
   fn setDefaultImpl(d: IFooInterfaceDefaultRef) -> IFooInterfaceDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IFooInterfaceAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait IFooInterfaceAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.versioned.tests.IFooInterface" }
@@ -96,10 +99,41 @@ impl BnFooInterface {
       fn r#newApi(&self) -> binder::Result<()> {
         self._rt.block_on(self._inner.r#newApi())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn IFooInterfaceAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IFooInterfaceAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnFooInterface>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for Wrapper {
+      fn r#originalApi<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#originalApi())
+      }
+      fn r#acceptUnionAndReturnString<'a>(&'a self, _arg_u: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#acceptUnionAndReturnString(_arg_u))
+      }
+      fn r#ignoreParcelablesAndRepeatInt<'a>(&'a self, _arg_inFoo: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value))
+      }
+      fn r#returnsLengthOfFooArray<'a>(&'a self, _arg_foos: &'a [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#returnsLengthOfFooArray(_arg_foos))
+      }
+      fn r#newApi<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#newApi())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IFooInterfaceAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait IFooInterfaceDefault: Send + Sync {
   fn r#originalApi(&self) -> binder::Result<()> {
diff --git a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BnLoggableInterface.h b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BnLoggableInterface.h
index 8aa6cceb..a591a084 100644
--- a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BnLoggableInterface.h
+++ b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BnLoggableInterface.h
@@ -16,7 +16,7 @@
 namespace android {
 namespace aidl {
 namespace loggable {
-class BnLoggableInterface : public ::android::BnInterface<ILoggableInterface> {
+class LIBBINDER_EXPORTED BnLoggableInterface : public ::android::BnInterface<ILoggableInterface> {
 public:
   static constexpr uint32_t TRANSACTION_LogThis = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   explicit BnLoggableInterface();
@@ -38,7 +38,7 @@ public:
   static std::function<void(const TransactionLog&)> logFunc;
 };  // class BnLoggableInterface
 
-class ILoggableInterfaceDelegator : public BnLoggableInterface {
+class LIBBINDER_EXPORTED ILoggableInterfaceDelegator : public BnLoggableInterface {
 public:
   explicit ILoggableInterfaceDelegator(const ::android::sp<ILoggableInterface> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BpLoggableInterface.h b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BpLoggableInterface.h
index 6b8e3703..d85b9400 100644
--- a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BpLoggableInterface.h
+++ b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BpLoggableInterface.h
@@ -14,7 +14,7 @@
 namespace android {
 namespace aidl {
 namespace loggable {
-class BpLoggableInterface : public ::android::BpInterface<ILoggableInterface> {
+class LIBBINDER_EXPORTED BpLoggableInterface : public ::android::BpInterface<ILoggableInterface> {
 public:
   explicit BpLoggableInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpLoggableInterface() = default;
diff --git a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
index 6fa8dccf..e206eb90 100644
--- a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
+++ b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
@@ -17,7 +17,7 @@
 namespace android {
 namespace aidl {
 namespace loggable {
-class Data : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Data : public ::android::Parcelable {
 public:
   int32_t num = 0;
   ::std::string str;
diff --git a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/ILoggableInterface.h b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/ILoggableInterface.h
index 8c766f7c..4309b8b6 100644
--- a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/ILoggableInterface.h
+++ b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/ILoggableInterface.h
@@ -25,22 +25,22 @@ class Data;
 namespace android {
 namespace aidl {
 namespace loggable {
-class ILoggableInterfaceDelegator;
+class LIBBINDER_EXPORTED ILoggableInterfaceDelegator;
 
-class ILoggableInterface : public ::android::IInterface {
+class LIBBINDER_EXPORTED ILoggableInterface : public ::android::IInterface {
 public:
   typedef ILoggableInterfaceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(LoggableInterface)
-  class ISubDelegator;
+  class LIBBINDER_EXPORTED ISubDelegator;
 
-  class ISub : public ::android::IInterface {
+  class LIBBINDER_EXPORTED ISub : public ::android::IInterface {
   public:
     typedef ISubDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(Sub)
     virtual ::android::binder::Status Log(int32_t value) = 0;
   };  // class ISub
 
-  class ISubDefault : public ISub {
+  class LIBBINDER_EXPORTED ISubDefault : public ISub {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -49,7 +49,7 @@ public:
       return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
     }
   };  // class ISubDefault
-  class BpSub : public ::android::BpInterface<ISub> {
+  class LIBBINDER_EXPORTED BpSub : public ::android::BpInterface<ISub> {
   public:
     explicit BpSub(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpSub() = default;
@@ -70,7 +70,7 @@ public:
     };
     static std::function<void(const TransactionLog&)> logFunc;
   };  // class BpSub
-  class BnSub : public ::android::BnInterface<ISub> {
+  class LIBBINDER_EXPORTED BnSub : public ::android::BnInterface<ISub> {
   public:
     static constexpr uint32_t TRANSACTION_Log = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     explicit BnSub();
@@ -92,7 +92,7 @@ public:
     static std::function<void(const TransactionLog&)> logFunc;
   };  // class BnSub
 
-  class ISubDelegator : public BnSub {
+  class LIBBINDER_EXPORTED ISubDelegator : public BnSub {
   public:
     explicit ISubDelegator(const ::android::sp<ISub> &impl) : _aidl_delegate(impl) {}
 
@@ -106,7 +106,7 @@ public:
   virtual ::android::binder::Status LogThis(bool boolValue, ::std::vector<bool>* boolArray, int8_t byteValue, ::std::vector<uint8_t>* byteArray, char16_t charValue, ::std::vector<char16_t>* charArray, int32_t intValue, ::std::vector<int32_t>* intArray, int64_t longValue, ::std::vector<int64_t>* longArray, float floatValue, ::std::vector<float>* floatArray, double doubleValue, ::std::vector<double>* doubleArray, const ::android::String16& stringValue, ::std::vector<::android::String16>* stringArray, ::std::vector<::android::String16>* listValue, const ::android::aidl::loggable::Data& dataValue, const ::android::sp<::android::IBinder>& binderValue, ::std::optional<::android::os::ParcelFileDescriptor>* pfdValue, ::std::vector<::android::os::ParcelFileDescriptor>* pfdArray, ::std::vector<::android::String16>* _aidl_return) = 0;
 };  // class ILoggableInterface
 
-class ILoggableInterfaceDefault : public ILoggableInterface {
+class LIBBINDER_EXPORTED ILoggableInterfaceDefault : public ILoggableInterface {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
index 6c56251f..633dd34a 100644
--- a/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
+++ b/tests/golden_output/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
@@ -24,7 +24,7 @@
 namespace android {
 namespace aidl {
 namespace loggable {
-class Union : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Union : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     num = 0,
diff --git a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
index 0207903e..52a927db 100644
--- a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
+++ b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
@@ -9,13 +9,6 @@
 #include <aidl/android/aidl/loggable/BnLoggableInterface.h>
 #include <aidl/android/aidl/loggable/BpLoggableInterface.h>
 
-namespace {
-struct ScopedTrace {
-  inline explicit ScopedTrace(const char* name) { ATrace_beginSection(name); }
-  inline ~ScopedTrace() { ATrace_endSection(); }
-};
-}  // namespace
-
 namespace aidl {
 namespace android {
 namespace aidl {
@@ -50,7 +43,6 @@ static binder_status_t _aidl_android_aidl_loggable_ILoggableInterface_onTransact
       std::vector<::ndk::ScopedFileDescriptor> in_pfdArray;
       std::vector<std::string> _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ILoggableInterface::LogThis::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_boolValue);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -249,8 +241,7 @@ std::function<void(const BpLoggableInterface::TransactionLog&)> BpLoggableInterf
     _transaction_log.input_args.emplace_back("in_pfdArray", ::android::internal::ToString(*in_pfdArray));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ILoggableInterface::LogThis::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_boolValue);
@@ -317,13 +308,13 @@ std::function<void(const BpLoggableInterface::TransactionLog&)> BpLoggableInterf
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*LogThis*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ILoggableInterface::getDefaultImpl()) {
@@ -490,7 +481,6 @@ static binder_status_t _aidl_android_aidl_loggable_ILoggableInterface_ISub_onTra
     case (FIRST_CALL_TRANSACTION + 0 /*Log*/): {
       int32_t in_value;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ISub::Log::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_value);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -541,21 +531,20 @@ std::function<void(const ILoggableInterface::BpSub::TransactionLog&)> ILoggableI
     _transaction_log.input_args.emplace_back("in_value", ::android::internal::ToString(in_value));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ISub::Log::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_value);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*Log*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ISub::getDefaultImpl()) {
diff --git a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/BpLoggableInterface.h b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/BpLoggableInterface.h
index c86c9073..8b325d55 100644
--- a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/BpLoggableInterface.h
+++ b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/BpLoggableInterface.h
@@ -10,7 +10,6 @@
 #include <functional>
 #include <chrono>
 #include <sstream>
-#include <android/trace.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/ILoggableInterface.h b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/ILoggableInterface.h
index 121100a8..1a7786e8 100644
--- a/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/ILoggableInterface.h
+++ b/tests/golden_output/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/ILoggableInterface.h
@@ -14,7 +14,6 @@
 #include <vector>
 #include <android/binder_ibinder.h>
 #include <android/binder_interface_utils.h>
-#include <android/trace.h>
 #include <aidl/android/aidl/loggable/Data.h>
 #ifdef BINDER_STABILITY_SUPPORT
 #include <android/binder_stability.h>
diff --git a/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BnCppJavaTests.h b/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BnCppJavaTests.h
index 4699bda3..12ad90db 100644
--- a/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BnCppJavaTests.h
+++ b/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BnCppJavaTests.h
@@ -13,7 +13,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnCppJavaTests : public ::android::BnInterface<ICppJavaTests> {
+class LIBBINDER_EXPORTED BnCppJavaTests : public ::android::BnInterface<ICppJavaTests> {
 public:
   static constexpr uint32_t TRANSACTION_RepeatBadParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_RepeatGenericParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -27,7 +27,7 @@ public:
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnCppJavaTests
 
-class ICppJavaTestsDelegator : public BnCppJavaTests {
+class LIBBINDER_EXPORTED ICppJavaTestsDelegator : public BnCppJavaTests {
 public:
   explicit ICppJavaTestsDelegator(const ::android::sp<ICppJavaTests> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BpCppJavaTests.h b/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BpCppJavaTests.h
index 60a44753..bdb85931 100644
--- a/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BpCppJavaTests.h
+++ b/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/BpCppJavaTests.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpCppJavaTests : public ::android::BpInterface<ICppJavaTests> {
+class LIBBINDER_EXPORTED BpCppJavaTests : public ::android::BpInterface<ICppJavaTests> {
 public:
   explicit BpCppJavaTests(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpCppJavaTests() = default;
diff --git a/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/ICppJavaTests.h b/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/ICppJavaTests.h
index 68e483b2..3b3a7ac2 100644
--- a/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/ICppJavaTests.h
+++ b/tests/golden_output/frozen/aidl-cpp-java-test-interface-cpp-source/gen/include/android/aidl/tests/ICppJavaTests.h
@@ -27,9 +27,9 @@ class StructuredParcelable;
 namespace android {
 namespace aidl {
 namespace tests {
-class ICppJavaTestsDelegator;
+class LIBBINDER_EXPORTED ICppJavaTestsDelegator;
 
-class ICppJavaTests : public ::android::IInterface {
+class LIBBINDER_EXPORTED ICppJavaTests : public ::android::IInterface {
 public:
   typedef ICppJavaTestsDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(CppJavaTests)
@@ -43,7 +43,7 @@ public:
   virtual ::android::binder::Status ReverseFileDescriptorArray(const ::std::vector<::android::base::unique_fd>& input, ::std::vector<::android::base::unique_fd>* repeated, ::std::vector<::android::base::unique_fd>* _aidl_return) = 0;
 };  // class ICppJavaTests
 
-class ICppJavaTestsDefault : public ICppJavaTests {
+class LIBBINDER_EXPORTED ICppJavaTestsDefault : public ICppJavaTests {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-cpp-java-test-interface-java-source/gen/android/aidl/tests/ICppJavaTests.java b/tests/golden_output/frozen/aidl-cpp-java-test-interface-java-source/gen/android/aidl/tests/ICppJavaTests.java
index 35f0555d..7ed4f606 100644
--- a/tests/golden_output/frozen/aidl-cpp-java-test-interface-java-source/gen/android/aidl/tests/ICppJavaTests.java
+++ b/tests/golden_output/frozen/aidl-cpp-java-test-interface-java-source/gen/android/aidl/tests/ICppJavaTests.java
@@ -174,7 +174,9 @@ public interface ICppJavaTests extends android.os.IInterface
           _arg0 = data.createTypedArray(android.os.PersistableBundle.CREATOR);
           android.os.PersistableBundle[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new android.os.PersistableBundle[_arg1_length];
@@ -228,7 +230,9 @@ public interface ICppJavaTests extends android.os.IInterface
           _arg0 = data.createRawFileDescriptorArray();
           java.io.FileDescriptor[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new java.io.FileDescriptor[_arg1_length];
diff --git a/tests/golden_output/frozen/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h b/tests/golden_output/frozen/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
index c3a623c6..73e5c9bd 100644
--- a/tests/golden_output/frozen/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
+++ b/tests/golden_output/frozen/aidl-test-fixedsizearray-cpp-source/gen/include/android/aidl/fixedsizearray/FixedSizeArrayExample.h
@@ -25,9 +25,9 @@
 namespace android {
 namespace aidl {
 namespace fixedsizearray {
-class FixedSizeArrayExample : public ::android::Parcelable {
+class LIBBINDER_EXPORTED FixedSizeArrayExample : public ::android::Parcelable {
 public:
-  class IntParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED IntParcelable : public ::android::Parcelable {
   public:
     int32_t value = 0;
     inline bool operator==(const IntParcelable& _rhs) const {
@@ -63,9 +63,9 @@ public:
       return _aidl_os.str();
     }
   };  // class IntParcelable
-  class IRepeatFixedSizeArrayDelegator;
+  class LIBBINDER_EXPORTED IRepeatFixedSizeArrayDelegator;
 
-  class IRepeatFixedSizeArray : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IRepeatFixedSizeArray : public ::android::IInterface {
   public:
     typedef IRepeatFixedSizeArrayDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(RepeatFixedSizeArray)
@@ -79,7 +79,7 @@ public:
     virtual ::android::binder::Status Repeat2dParcelables(const std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>& input, std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>* repeated, std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>* _aidl_return) = 0;
   };  // class IRepeatFixedSizeArray
 
-  class IRepeatFixedSizeArrayDefault : public IRepeatFixedSizeArray {
+  class LIBBINDER_EXPORTED IRepeatFixedSizeArrayDefault : public IRepeatFixedSizeArray {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -109,7 +109,7 @@ public:
       return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
     }
   };  // class IRepeatFixedSizeArrayDefault
-  class BpRepeatFixedSizeArray : public ::android::BpInterface<IRepeatFixedSizeArray> {
+  class LIBBINDER_EXPORTED BpRepeatFixedSizeArray : public ::android::BpInterface<IRepeatFixedSizeArray> {
   public:
     explicit BpRepeatFixedSizeArray(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpRepeatFixedSizeArray() = default;
@@ -122,7 +122,7 @@ public:
     ::android::binder::Status Repeat2dBinders(const std::array<std::array<::android::sp<::android::IBinder>, 3>, 2>& input, std::array<std::array<::android::sp<::android::IBinder>, 3>, 2>* repeated, std::array<std::array<::android::sp<::android::IBinder>, 3>, 2>* _aidl_return) override;
     ::android::binder::Status Repeat2dParcelables(const std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>& input, std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>* repeated, std::array<std::array<::android::aidl::fixedsizearray::FixedSizeArrayExample::IntParcelable, 3>, 2>* _aidl_return) override;
   };  // class BpRepeatFixedSizeArray
-  class BnRepeatFixedSizeArray : public ::android::BnInterface<IRepeatFixedSizeArray> {
+  class LIBBINDER_EXPORTED BnRepeatFixedSizeArray : public ::android::BnInterface<IRepeatFixedSizeArray> {
   public:
     static constexpr uint32_t TRANSACTION_RepeatBytes = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     static constexpr uint32_t TRANSACTION_RepeatInts = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -136,7 +136,7 @@ public:
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnRepeatFixedSizeArray
 
-  class IRepeatFixedSizeArrayDelegator : public BnRepeatFixedSizeArray {
+  class LIBBINDER_EXPORTED IRepeatFixedSizeArrayDelegator : public BnRepeatFixedSizeArray {
   public:
     explicit IRepeatFixedSizeArrayDelegator(const ::android::sp<IRepeatFixedSizeArray> &impl) : _aidl_delegate(impl) {}
 
@@ -177,32 +177,32 @@ public:
   enum class LongEnum : int64_t {
     A = 0L,
   };
-  class IEmptyInterfaceDelegator;
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator;
 
-  class IEmptyInterface : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IEmptyInterface : public ::android::IInterface {
   public:
     typedef IEmptyInterfaceDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(EmptyInterface)
   };  // class IEmptyInterface
 
-  class IEmptyInterfaceDefault : public IEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDefault : public IEmptyInterface {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
     }
   };  // class IEmptyInterfaceDefault
-  class BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
   public:
     explicit BpEmptyInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpEmptyInterface() = default;
   };  // class BpEmptyInterface
-  class BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
   public:
     explicit BnEmptyInterface();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnEmptyInterface
 
-  class IEmptyInterfaceDelegator : public BnEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator : public BnEmptyInterface {
   public:
     explicit IEmptyInterfaceDelegator(const ::android::sp<IEmptyInterface> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp b/tests/golden_output/frozen/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
index 11e90b53..7b394135 100644
--- a/tests/golden_output/frozen/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
+++ b/tests/golden_output/frozen/aidl-test-fixedsizearray-ndk-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.cpp
@@ -792,20 +792,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*RepeatBytes*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -835,20 +835,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*RepeatInts*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -878,20 +878,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*RepeatBinders*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -921,20 +921,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*RepeatParcelables*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -964,20 +964,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 4 /*Repeat2dBytes*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -1007,20 +1007,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 5 /*Repeat2dInts*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -1050,20 +1050,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 6 /*Repeat2dBinders*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
@@ -1093,20 +1093,20 @@ FixedSizeArrayExample::BpRepeatFixedSizeArray::~BpRepeatFixedSizeArray() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 7 /*Repeat2dParcelables*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRepeatFixedSizeArray::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs b/tests/golden_output/frozen/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
index ec33985f..fa103b3a 100644
--- a/tests/golden_output/frozen/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
+++ b/tests/golden_output/frozen/aidl-test-fixedsizearray-rust-source/gen/android/aidl/fixedsizearray/FixedSizeArrayExample.rs
@@ -370,7 +370,7 @@ pub mod r#IRepeatFixedSizeArray {
       native: BnRepeatFixedSizeArray(on_transact),
       proxy: BpRepeatFixedSizeArray {
       },
-      async: IRepeatFixedSizeArrayAsync,
+      async: IRepeatFixedSizeArrayAsync(try_into_local_async),
     }
   }
   pub trait IRepeatFixedSizeArray: binder::Interface + Send {
@@ -389,6 +389,9 @@ pub mod r#IRepeatFixedSizeArray {
     fn setDefaultImpl(d: IRepeatFixedSizeArrayDefaultRef) -> IRepeatFixedSizeArrayDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IRepeatFixedSizeArrayAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IRepeatFixedSizeArrayAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.fixedsizearray.FixedSizeArrayExample.IRepeatFixedSizeArray" }
@@ -457,10 +460,50 @@ pub mod r#IRepeatFixedSizeArray {
         fn r#Repeat2dParcelables(&self, _arg_input: &[[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2], _arg_repeated: &mut [[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]) -> binder::Result<[[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]> {
           self._rt.block_on(self._inner.r#Repeat2dParcelables(_arg_input, _arg_repeated))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn IRepeatFixedSizeArrayAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IRepeatFixedSizeArrayAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnRepeatFixedSizeArray>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IRepeatFixedSizeArrayAsync<P> for Wrapper {
+        fn r#RepeatBytes<'a>(&'a self, _arg_input: &'a [u8; 3], _arg_repeated: &'a mut [u8; 3]) -> binder::BoxFuture<'a, binder::Result<[u8; 3]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#RepeatBytes(_arg_input, _arg_repeated))
+        }
+        fn r#RepeatInts<'a>(&'a self, _arg_input: &'a [i32; 3], _arg_repeated: &'a mut [i32; 3]) -> binder::BoxFuture<'a, binder::Result<[i32; 3]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#RepeatInts(_arg_input, _arg_repeated))
+        }
+        fn r#RepeatBinders<'a>(&'a self, _arg_input: &'a [binder::SpIBinder; 3], _arg_repeated: &'a mut [Option<binder::SpIBinder>; 3]) -> binder::BoxFuture<'a, binder::Result<[binder::SpIBinder; 3]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#RepeatBinders(_arg_input, _arg_repeated))
+        }
+        fn r#RepeatParcelables<'a>(&'a self, _arg_input: &'a [crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3], _arg_repeated: &'a mut [crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]) -> binder::BoxFuture<'a, binder::Result<[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#RepeatParcelables(_arg_input, _arg_repeated))
+        }
+        fn r#Repeat2dBytes<'a>(&'a self, _arg_input: &'a [[u8; 3]; 2], _arg_repeated: &'a mut [[u8; 3]; 2]) -> binder::BoxFuture<'a, binder::Result<[[u8; 3]; 2]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#Repeat2dBytes(_arg_input, _arg_repeated))
+        }
+        fn r#Repeat2dInts<'a>(&'a self, _arg_input: &'a [[i32; 3]; 2], _arg_repeated: &'a mut [[i32; 3]; 2]) -> binder::BoxFuture<'a, binder::Result<[[i32; 3]; 2]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#Repeat2dInts(_arg_input, _arg_repeated))
+        }
+        fn r#Repeat2dBinders<'a>(&'a self, _arg_input: &'a [[binder::SpIBinder; 3]; 2], _arg_repeated: &'a mut [[Option<binder::SpIBinder>; 3]; 2]) -> binder::BoxFuture<'a, binder::Result<[[binder::SpIBinder; 3]; 2]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#Repeat2dBinders(_arg_input, _arg_repeated))
+        }
+        fn r#Repeat2dParcelables<'a>(&'a self, _arg_input: &'a [[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2], _arg_repeated: &'a mut [[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]) -> binder::BoxFuture<'a, binder::Result<[[crate::mangled::_7_android_4_aidl_14_fixedsizearray_21_FixedSizeArrayExample_13_IntParcelable; 3]; 2]>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#Repeat2dParcelables(_arg_input, _arg_repeated))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IRepeatFixedSizeArrayAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IRepeatFixedSizeArrayDefault: Send + Sync {
     fn r#RepeatBytes(&self, _arg_input: &[u8; 3], _arg_repeated: &mut [u8; 3]) -> binder::Result<[u8; 3]> {
@@ -996,7 +1039,7 @@ pub mod r#IEmptyInterface {
       native: BnEmptyInterface(on_transact),
       proxy: BpEmptyInterface {
       },
-      async: IEmptyInterfaceAsync,
+      async: IEmptyInterfaceAsync(try_into_local_async),
     }
   }
   pub trait IEmptyInterface: binder::Interface + Send {
@@ -1007,6 +1050,9 @@ pub mod r#IEmptyInterface {
     fn setDefaultImpl(d: IEmptyInterfaceDefaultRef) -> IEmptyInterfaceDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IEmptyInterfaceAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.fixedsizearray.FixedSizeArrayExample.IEmptyInterface" }
@@ -1035,10 +1081,26 @@ pub mod r#IEmptyInterface {
         T: IEmptyInterfaceAsyncServer + Send + Sync + 'static,
         R: binder::binder_impl::BinderAsyncRuntime + Send + Sync + 'static,
       {
+        fn try_as_async_server(&self) -> Option<&(dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IEmptyInterfaceAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnEmptyInterface>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IEmptyInterfaceAsync<P> for Wrapper {
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IEmptyInterfaceAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IEmptyInterfaceDefault: Send + Sync {
   }
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
index 374e7b6b..57cebb3e 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ArrayOfInterfaces.h
@@ -33,34 +33,34 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class ArrayOfInterfaces : public ::android::Parcelable {
+class LIBBINDER_EXPORTED ArrayOfInterfaces : public ::android::Parcelable {
 public:
-  class IEmptyInterfaceDelegator;
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator;
 
-  class IEmptyInterface : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IEmptyInterface : public ::android::IInterface {
   public:
     typedef IEmptyInterfaceDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(EmptyInterface)
   };  // class IEmptyInterface
 
-  class IEmptyInterfaceDefault : public IEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDefault : public IEmptyInterface {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
     }
   };  // class IEmptyInterfaceDefault
-  class BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
   public:
     explicit BpEmptyInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpEmptyInterface() = default;
   };  // class BpEmptyInterface
-  class BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
   public:
     explicit BnEmptyInterface();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnEmptyInterface
 
-  class IEmptyInterfaceDelegator : public BnEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator : public BnEmptyInterface {
   public:
     explicit IEmptyInterfaceDelegator(const ::android::sp<IEmptyInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -68,16 +68,16 @@ public:
   private:
     ::android::sp<IEmptyInterface> _aidl_delegate;
   };  // class IEmptyInterfaceDelegator
-  class IMyInterfaceDelegator;
+  class LIBBINDER_EXPORTED IMyInterfaceDelegator;
 
-  class IMyInterface : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IMyInterface : public ::android::IInterface {
   public:
     typedef IMyInterfaceDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(MyInterface)
     virtual ::android::binder::Status methodWithInterfaces(const ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>& iface, const ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>& nullable_iface, const ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>& iface_array_in, ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>* iface_array_out, ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>* iface_array_inout, const ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>& nullable_iface_array_in, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* nullable_iface_array_out, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* nullable_iface_array_inout, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* _aidl_return) = 0;
   };  // class IMyInterface
 
-  class IMyInterfaceDefault : public IMyInterface {
+  class LIBBINDER_EXPORTED IMyInterfaceDefault : public IMyInterface {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -86,20 +86,20 @@ public:
       return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
     }
   };  // class IMyInterfaceDefault
-  class BpMyInterface : public ::android::BpInterface<IMyInterface> {
+  class LIBBINDER_EXPORTED BpMyInterface : public ::android::BpInterface<IMyInterface> {
   public:
     explicit BpMyInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpMyInterface() = default;
     ::android::binder::Status methodWithInterfaces(const ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>& iface, const ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>& nullable_iface, const ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>& iface_array_in, ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>* iface_array_out, ::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>* iface_array_inout, const ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>& nullable_iface_array_in, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* nullable_iface_array_out, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* nullable_iface_array_inout, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface>>>* _aidl_return) override;
   };  // class BpMyInterface
-  class BnMyInterface : public ::android::BnInterface<IMyInterface> {
+  class LIBBINDER_EXPORTED BnMyInterface : public ::android::BnInterface<IMyInterface> {
   public:
     static constexpr uint32_t TRANSACTION_methodWithInterfaces = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     explicit BnMyInterface();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnMyInterface
 
-  class IMyInterfaceDelegator : public BnMyInterface {
+  class LIBBINDER_EXPORTED IMyInterfaceDelegator : public BnMyInterface {
   public:
     explicit IMyInterfaceDelegator(const ::android::sp<IMyInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -118,7 +118,7 @@ public:
   private:
     ::android::sp<IMyInterface> _aidl_delegate;
   };  // class IMyInterfaceDelegator
-  class MyParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyParcelable : public ::android::Parcelable {
   public:
     ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface> iface;
     ::android::sp<::android::aidl::tests::ArrayOfInterfaces::IEmptyInterface> nullable_iface;
@@ -160,7 +160,7 @@ public:
       return _aidl_os.str();
     }
   };  // class MyParcelable
-  class MyUnion : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyUnion : public ::android::Parcelable {
   public:
     enum class Tag : int32_t {
       iface = 0,
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnCircular.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnCircular.h
index 6c7a2a87..dd0807e9 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnCircular.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnCircular.h
@@ -14,14 +14,14 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnCircular : public ::android::BnInterface<ICircular> {
+class LIBBINDER_EXPORTED BnCircular : public ::android::BnInterface<ICircular> {
 public:
   static constexpr uint32_t TRANSACTION_GetTestService = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   explicit BnCircular();
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnCircular
 
-class ICircularDelegator : public BnCircular {
+class LIBBINDER_EXPORTED ICircularDelegator : public BnCircular {
 public:
   explicit ICircularDelegator(const ::android::sp<ICircular> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnDeprecated.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnDeprecated.h
index 9effe3d7..78c8d62c 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnDeprecated.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnDeprecated.h
@@ -13,13 +13,13 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class __attribute__((deprecated("test"))) BnDeprecated : public ::android::BnInterface<IDeprecated> {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) BnDeprecated : public ::android::BnInterface<IDeprecated> {
 public:
   explicit BnDeprecated();
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnDeprecated
 
-class __attribute__((deprecated("test"))) IDeprecatedDelegator : public BnDeprecated {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) IDeprecatedDelegator : public BnDeprecated {
 public:
   explicit IDeprecatedDelegator(const ::android::sp<IDeprecated> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNamedCallback.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNamedCallback.h
index fee8d2f4..43a06b11 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNamedCallback.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNamedCallback.h
@@ -13,14 +13,14 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnNamedCallback : public ::android::BnInterface<INamedCallback> {
+class LIBBINDER_EXPORTED BnNamedCallback : public ::android::BnInterface<INamedCallback> {
 public:
   static constexpr uint32_t TRANSACTION_GetName = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   explicit BnNamedCallback();
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnNamedCallback
 
-class INamedCallbackDelegator : public BnNamedCallback {
+class LIBBINDER_EXPORTED INamedCallbackDelegator : public BnNamedCallback {
 public:
   explicit INamedCallbackDelegator(const ::android::sp<INamedCallback> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNewName.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNewName.h
index 7eb72141..447d2346 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNewName.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnNewName.h
@@ -13,14 +13,14 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnNewName : public ::android::BnInterface<INewName> {
+class LIBBINDER_EXPORTED BnNewName : public ::android::BnInterface<INewName> {
 public:
   static constexpr uint32_t TRANSACTION_RealName = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   explicit BnNewName();
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnNewName
 
-class INewNameDelegator : public BnNewName {
+class LIBBINDER_EXPORTED INewNameDelegator : public BnNewName {
 public:
   explicit INewNameDelegator(const ::android::sp<INewName> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnOldName.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnOldName.h
index 986a674b..35069b1c 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnOldName.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnOldName.h
@@ -13,14 +13,14 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnOldName : public ::android::BnInterface<IOldName> {
+class LIBBINDER_EXPORTED BnOldName : public ::android::BnInterface<IOldName> {
 public:
   static constexpr uint32_t TRANSACTION_RealName = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   explicit BnOldName();
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnOldName
 
-class IOldNameDelegator : public BnOldName {
+class LIBBINDER_EXPORTED IOldNameDelegator : public BnOldName {
 public:
   explicit IOldNameDelegator(const ::android::sp<IOldName> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnTestService.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnTestService.h
index a7b48284..793baf4a 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnTestService.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BnTestService.h
@@ -18,7 +18,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BnTestService : public ::android::BnInterface<ITestService> {
+class LIBBINDER_EXPORTED BnTestService : public ::android::BnInterface<ITestService> {
 public:
   static constexpr uint32_t TRANSACTION_UnimplementedMethod = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_Deprecated = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -94,7 +94,7 @@ public:
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnTestService
 
-class ITestServiceDelegator : public BnTestService {
+class LIBBINDER_EXPORTED ITestServiceDelegator : public BnTestService {
 public:
   explicit ITestServiceDelegator(const ::android::sp<ITestService> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpCircular.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpCircular.h
index 53aa76e8..08dc8387 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpCircular.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpCircular.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpCircular : public ::android::BpInterface<ICircular> {
+class LIBBINDER_EXPORTED BpCircular : public ::android::BpInterface<ICircular> {
 public:
   explicit BpCircular(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpCircular() = default;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpDeprecated.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpDeprecated.h
index ff4ef51c..723dd94d 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpDeprecated.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpDeprecated.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class __attribute__((deprecated("test"))) BpDeprecated : public ::android::BpInterface<IDeprecated> {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) BpDeprecated : public ::android::BpInterface<IDeprecated> {
 public:
   explicit BpDeprecated(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpDeprecated() = default;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNamedCallback.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNamedCallback.h
index 4d333ef5..627f1688 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNamedCallback.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNamedCallback.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpNamedCallback : public ::android::BpInterface<INamedCallback> {
+class LIBBINDER_EXPORTED BpNamedCallback : public ::android::BpInterface<INamedCallback> {
 public:
   explicit BpNamedCallback(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpNamedCallback() = default;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNewName.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNewName.h
index 4be360b1..27a50464 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNewName.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpNewName.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpNewName : public ::android::BpInterface<INewName> {
+class LIBBINDER_EXPORTED BpNewName : public ::android::BpInterface<INewName> {
 public:
   explicit BpNewName(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpNewName() = default;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpOldName.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpOldName.h
index c8b87dd3..c8d4a14d 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpOldName.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpOldName.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpOldName : public ::android::BpInterface<IOldName> {
+class LIBBINDER_EXPORTED BpOldName : public ::android::BpInterface<IOldName> {
 public:
   explicit BpOldName(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpOldName() = default;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpTestService.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpTestService.h
index c4b4b28f..e1b61d31 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpTestService.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/BpTestService.h
@@ -12,7 +12,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class BpTestService : public ::android::BpInterface<ITestService> {
+class LIBBINDER_EXPORTED BpTestService : public ::android::BpInterface<ITestService> {
 public:
   explicit BpTestService(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpTestService() = default;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
index cfdc35f9..d3d9668d 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/CircularParcelable.h
@@ -18,7 +18,7 @@ class ITestService;
 namespace android {
 namespace aidl {
 namespace tests {
-class CircularParcelable : public ::android::Parcelable {
+class LIBBINDER_EXPORTED CircularParcelable : public ::android::Parcelable {
 public:
   ::android::sp<::android::aidl::tests::ITestService> testService;
   inline bool operator==(const CircularParcelable& _rhs) const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
index e58797c3..ebf07dce 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/DeprecatedParcelable.h
@@ -13,7 +13,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class __attribute__((deprecated("test"))) DeprecatedParcelable : public ::android::Parcelable {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) DeprecatedParcelable : public ::android::Parcelable {
 public:
   inline bool operator==(const DeprecatedParcelable&) const {
     return std::tie() == std::tie();
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
index 59e8683a..77c15d57 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/FixedSize.h
@@ -27,9 +27,9 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class FixedSize : public ::android::Parcelable {
+class LIBBINDER_EXPORTED FixedSize : public ::android::Parcelable {
 public:
-  class FixedUnion : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED FixedUnion : public ::android::Parcelable {
   public:
     enum class Tag : int8_t {
       booleanValue = 0,
@@ -157,7 +157,7 @@ public:
       ::android::aidl::tests::LongEnum enumValue __attribute__((aligned (8)));
     } _value;
   };  // class FixedUnion
-  class EmptyParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED EmptyParcelable : public ::android::Parcelable {
   public:
     inline bool operator==(const EmptyParcelable&) const {
       return std::tie() == std::tie();
@@ -191,7 +191,7 @@ public:
       return _aidl_os.str();
     }
   };  // class EmptyParcelable
-  class FixedParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED FixedParcelable : public ::android::Parcelable {
   public:
     bool booleanValue = false;
     int8_t byteValue = 0;
@@ -251,7 +251,7 @@ public:
       return _aidl_os.str();
     }
   };  // class FixedParcelable
-  class ExplicitPaddingParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED ExplicitPaddingParcelable : public ::android::Parcelable {
   public:
     int8_t byteValue = 0;
     int64_t longValue = 0L;
@@ -297,7 +297,7 @@ public:
       return _aidl_os.str();
     }
   };  // class ExplicitPaddingParcelable
-  class FixedUnionNoPadding : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED FixedUnionNoPadding : public ::android::Parcelable {
   public:
     enum class Tag : int8_t {
       byteValue = 0,
@@ -389,7 +389,7 @@ public:
       int8_t byteValue __attribute__((aligned (1))) = int8_t(0);
     } _value;
   };  // class FixedUnionNoPadding
-  class FixedUnionSmallPadding : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED FixedUnionSmallPadding : public ::android::Parcelable {
   public:
     enum class Tag : int8_t {
       charValue = 0,
@@ -481,7 +481,7 @@ public:
       char16_t charValue __attribute__((aligned (2))) = char16_t('\0');
     } _value;
   };  // class FixedUnionSmallPadding
-  class FixedUnionLongPadding : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED FixedUnionLongPadding : public ::android::Parcelable {
   public:
     enum class Tag : int8_t {
       longValue = 0,
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
index 190c6314..7766bc87 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/GenericStructuredParcelable.h
@@ -15,7 +15,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 template <typename T, typename U, typename B>
-class GenericStructuredParcelable : public ::android::Parcelable {
+class LIBBINDER_EXPORTED GenericStructuredParcelable : public ::android::Parcelable {
 public:
   int32_t a = 0;
   int32_t b = 0;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ICircular.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ICircular.h
index 22604519..5ab518c7 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ICircular.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ICircular.h
@@ -18,16 +18,16 @@ class ITestService;
 namespace android {
 namespace aidl {
 namespace tests {
-class ICircularDelegator;
+class LIBBINDER_EXPORTED ICircularDelegator;
 
-class ICircular : public ::android::IInterface {
+class LIBBINDER_EXPORTED ICircular : public ::android::IInterface {
 public:
   typedef ICircularDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(Circular)
   virtual ::android::binder::Status GetTestService(::android::sp<::android::aidl::tests::ITestService>* _aidl_return) = 0;
 };  // class ICircular
 
-class ICircularDefault : public ICircular {
+class LIBBINDER_EXPORTED ICircularDefault : public ICircular {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IDeprecated.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IDeprecated.h
index 8ea891d7..dac038e0 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IDeprecated.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IDeprecated.h
@@ -13,15 +13,15 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class IDeprecatedDelegator;
+class LIBBINDER_EXPORTED IDeprecatedDelegator;
 
-class __attribute__((deprecated("test"))) IDeprecated : public ::android::IInterface {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) IDeprecated : public ::android::IInterface {
 public:
   typedef IDeprecatedDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(Deprecated)
 };  // class IDeprecated
 
-class __attribute__((deprecated("test"))) IDeprecatedDefault : public IDeprecated {
+class LIBBINDER_EXPORTED __attribute__((deprecated("test"))) IDeprecatedDefault : public IDeprecated {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INamedCallback.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INamedCallback.h
index ad9110fe..b5313c9e 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INamedCallback.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INamedCallback.h
@@ -14,16 +14,16 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class INamedCallbackDelegator;
+class LIBBINDER_EXPORTED INamedCallbackDelegator;
 
-class INamedCallback : public ::android::IInterface {
+class LIBBINDER_EXPORTED INamedCallback : public ::android::IInterface {
 public:
   typedef INamedCallbackDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(NamedCallback)
   virtual ::android::binder::Status GetName(::android::String16* _aidl_return) = 0;
 };  // class INamedCallback
 
-class INamedCallbackDefault : public INamedCallback {
+class LIBBINDER_EXPORTED INamedCallbackDefault : public INamedCallback {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INewName.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INewName.h
index b2b0d5f6..10eed1d3 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INewName.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/INewName.h
@@ -14,16 +14,16 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class INewNameDelegator;
+class LIBBINDER_EXPORTED INewNameDelegator;
 
-class INewName : public ::android::IInterface {
+class LIBBINDER_EXPORTED INewName : public ::android::IInterface {
 public:
   typedef INewNameDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(NewName)
   virtual ::android::binder::Status RealName(::android::String16* _aidl_return) = 0;
 };  // class INewName
 
-class INewNameDefault : public INewName {
+class LIBBINDER_EXPORTED INewNameDefault : public INewName {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IOldName.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IOldName.h
index d4c4e826..7ceed350 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IOldName.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/IOldName.h
@@ -14,16 +14,16 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class IOldNameDelegator;
+class LIBBINDER_EXPORTED IOldNameDelegator;
 
-class IOldName : public ::android::IInterface {
+class LIBBINDER_EXPORTED IOldName : public ::android::IInterface {
 public:
   typedef IOldNameDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(OldName)
   virtual ::android::binder::Status RealName(::android::String16* _aidl_return) = 0;
 };  // class IOldName
 
-class IOldNameDefault : public IOldName {
+class LIBBINDER_EXPORTED IOldNameDefault : public IOldName {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
index f532f9cc..22dbb487 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ITestService.h
@@ -60,13 +60,13 @@ class ExtendableParcelable;
 namespace android {
 namespace aidl {
 namespace tests {
-class ITestServiceDelegator;
+class LIBBINDER_EXPORTED ITestServiceDelegator;
 
-class ITestService : public ::android::IInterface {
+class LIBBINDER_EXPORTED ITestService : public ::android::IInterface {
 public:
   typedef ITestServiceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(TestService)
-  class Empty : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED Empty : public ::android::Parcelable {
   public:
     inline bool operator==(const Empty&) const {
       return std::tie() == std::tie();
@@ -100,34 +100,34 @@ public:
       return _aidl_os.str();
     }
   };  // class Empty
-  class CompilerChecks : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED CompilerChecks : public ::android::Parcelable {
   public:
-    class IFooDelegator;
+    class LIBBINDER_EXPORTED IFooDelegator;
 
-    class IFoo : public ::android::IInterface {
+    class LIBBINDER_EXPORTED IFoo : public ::android::IInterface {
     public:
       typedef IFooDelegator DefaultDelegator;
       DECLARE_META_INTERFACE(Foo)
     };  // class IFoo
 
-    class IFooDefault : public IFoo {
+    class LIBBINDER_EXPORTED IFooDefault : public IFoo {
     public:
       ::android::IBinder* onAsBinder() override {
         return nullptr;
       }
     };  // class IFooDefault
-    class BpFoo : public ::android::BpInterface<IFoo> {
+    class LIBBINDER_EXPORTED BpFoo : public ::android::BpInterface<IFoo> {
     public:
       explicit BpFoo(const ::android::sp<::android::IBinder>& _aidl_impl);
       virtual ~BpFoo() = default;
     };  // class BpFoo
-    class BnFoo : public ::android::BnInterface<IFoo> {
+    class LIBBINDER_EXPORTED BnFoo : public ::android::BnInterface<IFoo> {
     public:
       explicit BnFoo();
       ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
     };  // class BnFoo
 
-    class IFooDelegator : public BnFoo {
+    class LIBBINDER_EXPORTED IFooDelegator : public BnFoo {
     public:
       explicit IFooDelegator(const ::android::sp<IFoo> &impl) : _aidl_delegate(impl) {}
 
@@ -137,7 +137,7 @@ public:
     };  // class IFooDelegator
     #pragma clang diagnostic push
     #pragma clang diagnostic ignored "-Wdeprecated-declarations"
-    class HasDeprecated : public ::android::Parcelable {
+    class LIBBINDER_EXPORTED HasDeprecated : public ::android::Parcelable {
     public:
       int32_t __attribute__((deprecated("field"))) deprecated = 0;
       inline bool operator==(const HasDeprecated& _rhs) const {
@@ -174,7 +174,7 @@ public:
       }
     };  // class HasDeprecated
     #pragma clang diagnostic pop
-    class UsingHasDeprecated : public ::android::Parcelable {
+    class LIBBINDER_EXPORTED UsingHasDeprecated : public ::android::Parcelable {
     public:
       enum class Tag : int32_t {
         n = 0,
@@ -267,13 +267,13 @@ public:
     private:
       std::variant<int32_t, ::android::aidl::tests::ITestService::CompilerChecks::HasDeprecated> _value;
     };  // class UsingHasDeprecated
-    class INoPrefixInterfaceDelegator;
+    class LIBBINDER_EXPORTED INoPrefixInterfaceDelegator;
 
-    class INoPrefixInterface : public ::android::IInterface {
+    class LIBBINDER_EXPORTED INoPrefixInterface : public ::android::IInterface {
     public:
       typedef INoPrefixInterfaceDelegator DefaultDelegator;
       DECLARE_META_INTERFACE(NoPrefixInterface)
-      class Nested : public ::android::Parcelable {
+      class LIBBINDER_EXPORTED Nested : public ::android::Parcelable {
       public:
         inline bool operator==(const Nested&) const {
           return std::tie() == std::tie();
@@ -307,16 +307,16 @@ public:
           return _aidl_os.str();
         }
       };  // class Nested
-      class INestedNoPrefixInterfaceDelegator;
+      class LIBBINDER_EXPORTED INestedNoPrefixInterfaceDelegator;
 
-      class INestedNoPrefixInterface : public ::android::IInterface {
+      class LIBBINDER_EXPORTED INestedNoPrefixInterface : public ::android::IInterface {
       public:
         typedef INestedNoPrefixInterfaceDelegator DefaultDelegator;
         DECLARE_META_INTERFACE(NestedNoPrefixInterface)
         virtual ::android::binder::Status foo() = 0;
       };  // class INestedNoPrefixInterface
 
-      class INestedNoPrefixInterfaceDefault : public INestedNoPrefixInterface {
+      class LIBBINDER_EXPORTED INestedNoPrefixInterfaceDefault : public INestedNoPrefixInterface {
       public:
         ::android::IBinder* onAsBinder() override {
           return nullptr;
@@ -325,20 +325,20 @@ public:
           return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
         }
       };  // class INestedNoPrefixInterfaceDefault
-      class BpNestedNoPrefixInterface : public ::android::BpInterface<INestedNoPrefixInterface> {
+      class LIBBINDER_EXPORTED BpNestedNoPrefixInterface : public ::android::BpInterface<INestedNoPrefixInterface> {
       public:
         explicit BpNestedNoPrefixInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
         virtual ~BpNestedNoPrefixInterface() = default;
         ::android::binder::Status foo() override;
       };  // class BpNestedNoPrefixInterface
-      class BnNestedNoPrefixInterface : public ::android::BnInterface<INestedNoPrefixInterface> {
+      class LIBBINDER_EXPORTED BnNestedNoPrefixInterface : public ::android::BnInterface<INestedNoPrefixInterface> {
       public:
         static constexpr uint32_t TRANSACTION_foo = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
         explicit BnNestedNoPrefixInterface();
         ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
       };  // class BnNestedNoPrefixInterface
 
-      class INestedNoPrefixInterfaceDelegator : public BnNestedNoPrefixInterface {
+      class LIBBINDER_EXPORTED INestedNoPrefixInterfaceDelegator : public BnNestedNoPrefixInterface {
       public:
         explicit INestedNoPrefixInterfaceDelegator(const ::android::sp<INestedNoPrefixInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -352,7 +352,7 @@ public:
       virtual ::android::binder::Status foo() = 0;
     };  // class INoPrefixInterface
 
-    class INoPrefixInterfaceDefault : public INoPrefixInterface {
+    class LIBBINDER_EXPORTED INoPrefixInterfaceDefault : public INoPrefixInterface {
     public:
       ::android::IBinder* onAsBinder() override {
         return nullptr;
@@ -361,20 +361,20 @@ public:
         return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
       }
     };  // class INoPrefixInterfaceDefault
-    class BpNoPrefixInterface : public ::android::BpInterface<INoPrefixInterface> {
+    class LIBBINDER_EXPORTED BpNoPrefixInterface : public ::android::BpInterface<INoPrefixInterface> {
     public:
       explicit BpNoPrefixInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
       virtual ~BpNoPrefixInterface() = default;
       ::android::binder::Status foo() override;
     };  // class BpNoPrefixInterface
-    class BnNoPrefixInterface : public ::android::BnInterface<INoPrefixInterface> {
+    class LIBBINDER_EXPORTED BnNoPrefixInterface : public ::android::BnInterface<INoPrefixInterface> {
     public:
       static constexpr uint32_t TRANSACTION_foo = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
       explicit BnNoPrefixInterface();
       ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
     };  // class BnNoPrefixInterface
 
-    class INoPrefixInterfaceDelegator : public BnNoPrefixInterface {
+    class LIBBINDER_EXPORTED INoPrefixInterfaceDelegator : public BnNoPrefixInterface {
     public:
       explicit INoPrefixInterfaceDelegator(const ::android::sp<INoPrefixInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -615,7 +615,7 @@ public:
   virtual ::android::binder::Status GetCircular(::android::aidl::tests::CircularParcelable* cp, ::android::sp<::android::aidl::tests::ICircular>* _aidl_return) = 0;
 };  // class ITestService
 
-class ITestServiceDefault : public ITestService {
+class LIBBINDER_EXPORTED ITestServiceDefault : public ITestService {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
index 922ebf06..ec17e6f0 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ListOfInterfaces.h
@@ -33,34 +33,34 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class ListOfInterfaces : public ::android::Parcelable {
+class LIBBINDER_EXPORTED ListOfInterfaces : public ::android::Parcelable {
 public:
-  class IEmptyInterfaceDelegator;
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator;
 
-  class IEmptyInterface : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IEmptyInterface : public ::android::IInterface {
   public:
     typedef IEmptyInterfaceDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(EmptyInterface)
   };  // class IEmptyInterface
 
-  class IEmptyInterfaceDefault : public IEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDefault : public IEmptyInterface {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
     }
   };  // class IEmptyInterfaceDefault
-  class BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BpEmptyInterface : public ::android::BpInterface<IEmptyInterface> {
   public:
     explicit BpEmptyInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpEmptyInterface() = default;
   };  // class BpEmptyInterface
-  class BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
+  class LIBBINDER_EXPORTED BnEmptyInterface : public ::android::BnInterface<IEmptyInterface> {
   public:
     explicit BnEmptyInterface();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnEmptyInterface
 
-  class IEmptyInterfaceDelegator : public BnEmptyInterface {
+  class LIBBINDER_EXPORTED IEmptyInterfaceDelegator : public BnEmptyInterface {
   public:
     explicit IEmptyInterfaceDelegator(const ::android::sp<IEmptyInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -68,16 +68,16 @@ public:
   private:
     ::android::sp<IEmptyInterface> _aidl_delegate;
   };  // class IEmptyInterfaceDelegator
-  class IMyInterfaceDelegator;
+  class LIBBINDER_EXPORTED IMyInterfaceDelegator;
 
-  class IMyInterface : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IMyInterface : public ::android::IInterface {
   public:
     typedef IMyInterfaceDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(MyInterface)
     virtual ::android::binder::Status methodWithInterfaces(const ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>& iface, const ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>& nullable_iface, const ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>& iface_list_in, ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>* iface_list_out, ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>* iface_list_inout, const ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>& nullable_iface_list_in, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* nullable_iface_list_out, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* nullable_iface_list_inout, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* _aidl_return) = 0;
   };  // class IMyInterface
 
-  class IMyInterfaceDefault : public IMyInterface {
+  class LIBBINDER_EXPORTED IMyInterfaceDefault : public IMyInterface {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -86,20 +86,20 @@ public:
       return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
     }
   };  // class IMyInterfaceDefault
-  class BpMyInterface : public ::android::BpInterface<IMyInterface> {
+  class LIBBINDER_EXPORTED BpMyInterface : public ::android::BpInterface<IMyInterface> {
   public:
     explicit BpMyInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpMyInterface() = default;
     ::android::binder::Status methodWithInterfaces(const ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>& iface, const ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>& nullable_iface, const ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>& iface_list_in, ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>* iface_list_out, ::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>* iface_list_inout, const ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>& nullable_iface_list_in, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* nullable_iface_list_out, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* nullable_iface_list_inout, ::std::optional<::std::vector<::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface>>>* _aidl_return) override;
   };  // class BpMyInterface
-  class BnMyInterface : public ::android::BnInterface<IMyInterface> {
+  class LIBBINDER_EXPORTED BnMyInterface : public ::android::BnInterface<IMyInterface> {
   public:
     static constexpr uint32_t TRANSACTION_methodWithInterfaces = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     explicit BnMyInterface();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnMyInterface
 
-  class IMyInterfaceDelegator : public BnMyInterface {
+  class LIBBINDER_EXPORTED IMyInterfaceDelegator : public BnMyInterface {
   public:
     explicit IMyInterfaceDelegator(const ::android::sp<IMyInterface> &impl) : _aidl_delegate(impl) {}
 
@@ -118,7 +118,7 @@ public:
   private:
     ::android::sp<IMyInterface> _aidl_delegate;
   };  // class IMyInterfaceDelegator
-  class MyParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyParcelable : public ::android::Parcelable {
   public:
     ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface> iface;
     ::android::sp<::android::aidl::tests::ListOfInterfaces::IEmptyInterface> nullable_iface;
@@ -160,7 +160,7 @@ public:
       return _aidl_os.str();
     }
   };  // class MyParcelable
-  class MyUnion : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyUnion : public ::android::Parcelable {
   public:
     enum class Tag : int32_t {
       iface = 0,
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
index ca6df4c7..ecf4cbd0 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/OtherParcelableForToString.h
@@ -13,7 +13,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class OtherParcelableForToString : public ::android::Parcelable {
+class LIBBINDER_EXPORTED OtherParcelableForToString : public ::android::Parcelable {
 public:
   ::android::String16 field;
   inline bool operator==(const OtherParcelableForToString& _rhs) const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
index d4a7d81c..7b7348b2 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/ParcelableForToString.h
@@ -26,7 +26,7 @@ class StructuredParcelable;
 namespace android {
 namespace aidl {
 namespace tests {
-class ParcelableForToString : public ::android::Parcelable {
+class LIBBINDER_EXPORTED ParcelableForToString : public ::android::Parcelable {
 public:
   int32_t intValue = 0;
   ::std::vector<int32_t> intArray;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
index 9930e1c4..dce103ed 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/RecursiveList.h
@@ -19,7 +19,7 @@ class RecursiveList;
 namespace android {
 namespace aidl {
 namespace tests {
-class RecursiveList : public ::android::Parcelable {
+class LIBBINDER_EXPORTED RecursiveList : public ::android::Parcelable {
 public:
   int32_t value = 0;
   ::std::unique_ptr<::android::aidl::tests::RecursiveList> next;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
index f43cb4ee..81bca09e 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/StructuredParcelable.h
@@ -24,9 +24,9 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class StructuredParcelable : public ::android::Parcelable {
+class LIBBINDER_EXPORTED StructuredParcelable : public ::android::Parcelable {
 public:
-  class Empty : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED Empty : public ::android::Parcelable {
   public:
     inline bool operator==(const Empty&) const {
       return std::tie() == std::tie();
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
index bad638a8..2cb53af2 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/Union.h
@@ -27,7 +27,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class Union : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Union : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     ns = 0,
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
index 9091f5a8..c1c8a4fa 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/UnionWithFd.h
@@ -25,7 +25,7 @@
 namespace android {
 namespace aidl {
 namespace tests {
-class UnionWithFd : public ::android::Parcelable {
+class LIBBINDER_EXPORTED UnionWithFd : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     num = 0,
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
index f451ea40..7dd52cec 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/ExtendableParcelable.h
@@ -17,7 +17,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace extension {
-class ExtendableParcelable : public ::android::Parcelable {
+class LIBBINDER_EXPORTED ExtendableParcelable : public ::android::Parcelable {
 public:
   int32_t a = 0;
   ::std::string b;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
index 0273c281..607be428 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt.h
@@ -16,7 +16,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace extension {
-class MyExt : public ::android::Parcelable {
+class LIBBINDER_EXPORTED MyExt : public ::android::Parcelable {
 public:
   int32_t a = 0;
   ::std::string b;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
index e2a8caa3..86e2956f 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExt2.h
@@ -20,7 +20,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace extension {
-class MyExt2 : public ::android::Parcelable {
+class LIBBINDER_EXPORTED MyExt2 : public ::android::Parcelable {
 public:
   int32_t a = 0;
   ::android::aidl::tests::extension::MyExt b;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
index b8e46b05..c13bc4c4 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/extension/MyExtLike.h
@@ -15,7 +15,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace extension {
-class MyExtLike : public ::android::Parcelable {
+class LIBBINDER_EXPORTED MyExtLike : public ::android::Parcelable {
 public:
   int32_t a = 0;
   ::android::String16 b;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BnNestedService.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BnNestedService.h
index c676ccab..46eaa088 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BnNestedService.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BnNestedService.h
@@ -15,7 +15,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace nested {
-class BnNestedService : public ::android::BnInterface<INestedService> {
+class LIBBINDER_EXPORTED BnNestedService : public ::android::BnInterface<INestedService> {
 public:
   static constexpr uint32_t TRANSACTION_flipStatus = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_flipStatusWithCallback = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -23,7 +23,7 @@ public:
   ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
 };  // class BnNestedService
 
-class INestedServiceDelegator : public BnNestedService {
+class LIBBINDER_EXPORTED INestedServiceDelegator : public BnNestedService {
 public:
   explicit INestedServiceDelegator(const ::android::sp<INestedService> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BpNestedService.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BpNestedService.h
index 640fa530..ae435b81 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BpNestedService.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/BpNestedService.h
@@ -13,7 +13,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace nested {
-class BpNestedService : public ::android::BpInterface<INestedService> {
+class LIBBINDER_EXPORTED BpNestedService : public ::android::BpInterface<INestedService> {
 public:
   explicit BpNestedService(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpNestedService() = default;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
index ebb16769..8632532d 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/DeeplyNested.h
@@ -19,13 +19,13 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace nested {
-class DeeplyNested : public ::android::Parcelable {
+class LIBBINDER_EXPORTED DeeplyNested : public ::android::Parcelable {
 public:
-  class B : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED B : public ::android::Parcelable {
   public:
-    class C : public ::android::Parcelable {
+    class LIBBINDER_EXPORTED C : public ::android::Parcelable {
     public:
-      class D : public ::android::Parcelable {
+      class LIBBINDER_EXPORTED D : public ::android::Parcelable {
       public:
         enum class E : int8_t {
           OK = 0,
@@ -126,7 +126,7 @@ public:
       return _aidl_os.str();
     }
   };  // class B
-  class A : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED A : public ::android::Parcelable {
   public:
     ::android::aidl::tests::nested::DeeplyNested::B::C::D::E e = ::android::aidl::tests::nested::DeeplyNested::B::C::D::E::OK;
     inline bool operator==(const A& _rhs) const {
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
index 97e65611..0323369d 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/INestedService.h
@@ -24,13 +24,13 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace nested {
-class INestedServiceDelegator;
+class LIBBINDER_EXPORTED INestedServiceDelegator;
 
-class INestedService : public ::android::IInterface {
+class LIBBINDER_EXPORTED INestedService : public ::android::IInterface {
 public:
   typedef INestedServiceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(NestedService)
-  class Result : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED Result : public ::android::Parcelable {
   public:
     ::android::aidl::tests::nested::ParcelableWithNested::Status status = ::android::aidl::tests::nested::ParcelableWithNested::Status::OK;
     inline bool operator==(const Result& _rhs) const {
@@ -66,16 +66,16 @@ public:
       return _aidl_os.str();
     }
   };  // class Result
-  class ICallbackDelegator;
+  class LIBBINDER_EXPORTED ICallbackDelegator;
 
-  class ICallback : public ::android::IInterface {
+  class LIBBINDER_EXPORTED ICallback : public ::android::IInterface {
   public:
     typedef ICallbackDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(Callback)
     virtual ::android::binder::Status done(::android::aidl::tests::nested::ParcelableWithNested::Status status) = 0;
   };  // class ICallback
 
-  class ICallbackDefault : public ICallback {
+  class LIBBINDER_EXPORTED ICallbackDefault : public ICallback {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -84,20 +84,20 @@ public:
       return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
     }
   };  // class ICallbackDefault
-  class BpCallback : public ::android::BpInterface<ICallback> {
+  class LIBBINDER_EXPORTED BpCallback : public ::android::BpInterface<ICallback> {
   public:
     explicit BpCallback(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpCallback() = default;
     ::android::binder::Status done(::android::aidl::tests::nested::ParcelableWithNested::Status status) override;
   };  // class BpCallback
-  class BnCallback : public ::android::BnInterface<ICallback> {
+  class LIBBINDER_EXPORTED BnCallback : public ::android::BnInterface<ICallback> {
   public:
     static constexpr uint32_t TRANSACTION_done = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     explicit BnCallback();
     ::android::status_t onTransact(uint32_t _aidl_code, const ::android::Parcel& _aidl_data, ::android::Parcel* _aidl_reply, uint32_t _aidl_flags) override;
   };  // class BnCallback
 
-  class ICallbackDelegator : public BnCallback {
+  class LIBBINDER_EXPORTED ICallbackDelegator : public BnCallback {
   public:
     explicit ICallbackDelegator(const ::android::sp<ICallback> &impl) : _aidl_delegate(impl) {}
 
@@ -112,7 +112,7 @@ public:
   virtual ::android::binder::Status flipStatusWithCallback(::android::aidl::tests::nested::ParcelableWithNested::Status status, const ::android::sp<::android::aidl::tests::nested::INestedService::ICallback>& cb) = 0;
 };  // class INestedService
 
-class INestedServiceDefault : public INestedService {
+class LIBBINDER_EXPORTED INestedServiceDefault : public INestedService {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
index ff884a3c..d01d18c2 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/nested/ParcelableWithNested.h
@@ -19,7 +19,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace nested {
-class ParcelableWithNested : public ::android::Parcelable {
+class LIBBINDER_EXPORTED ParcelableWithNested : public ::android::Parcelable {
 public:
   enum class Status : int8_t {
     OK = 0,
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
index 306c4e05..0b58a4c2 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/EnumUnion.h
@@ -29,7 +29,7 @@ namespace tests {
 namespace unions {
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
-class EnumUnion : public ::android::Parcelable {
+class LIBBINDER_EXPORTED EnumUnion : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     intEnum = 0,
diff --git a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
index 07481840..937cb55a 100644
--- a/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
+++ b/tests/golden_output/frozen/aidl-test-interface-cpp-source/gen/include/android/aidl/tests/unions/UnionInUnion.h
@@ -26,7 +26,7 @@ namespace android {
 namespace aidl {
 namespace tests {
 namespace unions {
-class UnionInUnion : public ::android::Parcelable {
+class LIBBINDER_EXPORTED UnionInUnion : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     first = 0,
diff --git a/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/ArrayOfInterfaces.java b/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/ArrayOfInterfaces.java
index 978fe3c9..bf3c430b 100644
--- a/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/ArrayOfInterfaces.java
+++ b/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/ArrayOfInterfaces.java
@@ -222,7 +222,9 @@ public class ArrayOfInterfaces implements android.os.Parcelable
             _arg2 = data.createInterfaceArray(android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[]::new, android.aidl.tests.ArrayOfInterfaces.IEmptyInterface.Stub::asInterface);
             android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[] _arg3;
             int _arg3_length = data.readInt();
-            if (_arg3_length < 0) {
+            if (_arg3_length > 1000000) {
+              throw new android.os.BadParcelableException("Array too large: " + _arg3_length);
+            } else if (_arg3_length < 0) {
               _arg3 = null;
             } else {
               _arg3 = new android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[_arg3_length];
@@ -233,7 +235,9 @@ public class ArrayOfInterfaces implements android.os.Parcelable
             _arg5 = data.createInterfaceArray(android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[]::new, android.aidl.tests.ArrayOfInterfaces.IEmptyInterface.Stub::asInterface);
             android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[] _arg6;
             int _arg6_length = data.readInt();
-            if (_arg6_length < 0) {
+            if (_arg6_length > 1000000) {
+              throw new android.os.BadParcelableException("Array too large: " + _arg6_length);
+            } else if (_arg6_length < 0) {
               _arg6 = null;
             } else {
               _arg6 = new android.aidl.tests.ArrayOfInterfaces.IEmptyInterface[_arg6_length];
diff --git a/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/ITestService.java b/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/ITestService.java
index bb1770b8..10284b04 100644
--- a/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/ITestService.java
+++ b/tests/golden_output/frozen/aidl-test-interface-java-source/gen/android/aidl/tests/ITestService.java
@@ -1103,7 +1103,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createBooleanArray();
           boolean[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new boolean[_arg1_length];
@@ -1121,7 +1123,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createByteArray();
           byte[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new byte[_arg1_length];
@@ -1139,7 +1143,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createCharArray();
           char[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new char[_arg1_length];
@@ -1157,7 +1163,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createIntArray();
           int[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new int[_arg1_length];
@@ -1175,7 +1183,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createLongArray();
           long[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new long[_arg1_length];
@@ -1193,7 +1203,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createFloatArray();
           float[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new float[_arg1_length];
@@ -1211,7 +1223,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createDoubleArray();
           double[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new double[_arg1_length];
@@ -1229,7 +1243,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createStringArray();
           java.lang.String[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new java.lang.String[_arg1_length];
@@ -1247,7 +1263,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createByteArray();
           byte[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new byte[_arg1_length];
@@ -1265,7 +1283,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createIntArray();
           int[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new int[_arg1_length];
@@ -1283,7 +1303,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createLongArray();
           long[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new long[_arg1_length];
@@ -1424,7 +1446,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createTypedArray(android.os.ParcelFileDescriptor.CREATOR);
           android.os.ParcelFileDescriptor[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new android.os.ParcelFileDescriptor[_arg1_length];
@@ -1597,7 +1621,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createStringArray();
           java.lang.String[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new java.lang.String[_arg1_length];
@@ -1615,7 +1641,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createStringArray();
           java.lang.String[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new java.lang.String[_arg1_length];
@@ -1688,7 +1716,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createBinderArray();
           android.os.IBinder[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new android.os.IBinder[_arg1_length];
@@ -1706,7 +1736,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createBinderArray();
           android.os.IBinder[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new android.os.IBinder[_arg1_length];
@@ -1737,7 +1769,9 @@ public interface ITestService extends android.os.IInterface
           _arg0 = data.createTypedArray(android.aidl.tests.SimpleParcelable.CREATOR);
           android.aidl.tests.SimpleParcelable[] _arg1;
           int _arg1_length = data.readInt();
-          if (_arg1_length < 0) {
+          if (_arg1_length > 1000000) {
+            throw new android.os.BadParcelableException("Array too large: " + _arg1_length);
+          } else if (_arg1_length < 0) {
             _arg1 = null;
           } else {
             _arg1 = new android.aidl.tests.SimpleParcelable[_arg1_length];
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
index 4708a514..bd665b51 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ArrayOfInterfaces.cpp
@@ -211,7 +211,7 @@ ArrayOfInterfaces::BpMyInterface::~BpMyInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_iface);
@@ -239,13 +239,13 @@ ArrayOfInterfaces::BpMyInterface::~BpMyInterface() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*methodWithInterfaces*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
index e8ff5501..3695b2e0 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ICircular.cpp
@@ -59,17 +59,17 @@ BpCircular::~BpCircular() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*GetTestService*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ICircular::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
index 147cfde4..87712705 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INamedCallback.cpp
@@ -47,17 +47,17 @@ BpNamedCallback::~BpNamedCallback() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*GetName*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INamedCallback::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
index 73f954c3..08302539 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/INewName.cpp
@@ -47,17 +47,17 @@ BpNewName::~BpNewName() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*RealName*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INewName::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
index 284757af..f5fda064 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/IOldName.cpp
@@ -47,17 +47,17 @@ BpOldName::~BpOldName() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*RealName*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IOldName::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
index 0d078b1f..2d5cf145 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ITestService.cpp
@@ -1402,7 +1402,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1410,13 +1410,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*UnimplementedMethod*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1443,18 +1443,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*Deprecated*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1478,18 +1478,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*TestOneway*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_ONEWAY | FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1509,7 +1509,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1517,13 +1517,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*RepeatBoolean*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1550,7 +1550,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1558,13 +1558,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 4 /*RepeatByte*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1591,7 +1591,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1599,13 +1599,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 5 /*RepeatChar*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1632,7 +1632,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1640,13 +1640,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 6 /*RepeatInt*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1673,7 +1673,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1681,13 +1681,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 7 /*RepeatLong*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1714,7 +1714,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1722,13 +1722,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 8 /*RepeatFloat*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1755,7 +1755,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1763,13 +1763,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 9 /*RepeatDouble*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1796,7 +1796,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1804,13 +1804,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 10 /*RepeatString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1837,7 +1837,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1845,13 +1845,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 11 /*RepeatByteEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1878,7 +1878,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1886,13 +1886,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 12 /*RepeatIntEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1919,7 +1919,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1927,13 +1927,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 13 /*RepeatLongEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -1960,7 +1960,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -1971,13 +1971,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 14 /*ReverseBoolean*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2007,7 +2007,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2018,13 +2018,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 15 /*ReverseByte*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2054,7 +2054,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2065,13 +2065,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16 /*ReverseChar*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2101,7 +2101,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2112,13 +2112,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 17 /*ReverseInt*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2148,7 +2148,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2159,13 +2159,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 18 /*ReverseLong*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2195,7 +2195,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2206,13 +2206,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 19 /*ReverseFloat*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2242,7 +2242,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2253,13 +2253,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 20 /*ReverseDouble*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2289,7 +2289,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2300,13 +2300,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 21 /*ReverseString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2336,7 +2336,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2347,13 +2347,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 22 /*ReverseByteEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2383,7 +2383,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2394,13 +2394,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 23 /*ReverseIntEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2430,7 +2430,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2441,13 +2441,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 24 /*ReverseLongEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2477,7 +2477,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2485,13 +2485,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 25 /*GetOtherTestService*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2518,7 +2518,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2529,13 +2529,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 26 /*SetOtherTestService*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2562,7 +2562,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2573,13 +2573,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 27 /*VerifyName*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2606,7 +2606,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2614,13 +2614,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 28 /*GetInterfaceArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2647,7 +2647,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2658,13 +2658,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 29 /*VerifyNamesWithInterfaceArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2691,7 +2691,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2699,13 +2699,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 30 /*GetNullableInterfaceArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2732,7 +2732,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2743,13 +2743,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 31 /*VerifyNamesWithNullableInterfaceArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2776,7 +2776,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2784,13 +2784,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 32 /*GetInterfaceList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2817,7 +2817,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2828,13 +2828,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 33 /*VerifyNamesWithInterfaceList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2861,7 +2861,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2869,13 +2869,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 34 /*ReverseStringList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2905,7 +2905,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2913,13 +2913,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 35 /*RepeatParcelFileDescriptor*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2946,7 +2946,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -2957,13 +2957,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 36 /*ReverseParcelFileDescriptorArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -2993,7 +2993,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3001,13 +3001,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 37 /*ThrowServiceException*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3031,7 +3031,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3039,13 +3039,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 38 /*RepeatNullableIntArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3072,7 +3072,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3080,13 +3080,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 39 /*RepeatNullableByteEnumArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3113,7 +3113,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3121,13 +3121,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 40 /*RepeatNullableIntEnumArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3154,7 +3154,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3162,13 +3162,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 41 /*RepeatNullableLongEnumArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3195,7 +3195,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3203,13 +3203,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 42 /*RepeatNullableString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3236,7 +3236,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3244,13 +3244,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 43 /*RepeatNullableStringList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3277,7 +3277,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3285,13 +3285,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 44 /*RepeatNullableParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3318,7 +3318,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3326,13 +3326,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 45 /*RepeatNullableParcelableArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3359,7 +3359,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3367,13 +3367,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 46 /*RepeatNullableParcelableList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3400,7 +3400,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3408,13 +3408,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 47 /*TakesAnIBinder*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3438,7 +3438,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3446,13 +3446,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 48 /*TakesANullableIBinder*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3476,7 +3476,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3484,13 +3484,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 49 /*TakesAnIBinderList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3514,7 +3514,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3522,13 +3522,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 50 /*TakesANullableIBinderList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3552,7 +3552,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3560,13 +3560,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 51 /*RepeatUtf8CppString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3593,7 +3593,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3601,13 +3601,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 52 /*RepeatNullableUtf8CppString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3634,7 +3634,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3645,13 +3645,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 53 /*ReverseUtf8CppString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3681,7 +3681,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3692,13 +3692,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 54 /*ReverseNullableUtf8CppString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3728,7 +3728,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3736,13 +3736,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 55 /*ReverseUtf8CppStringList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3772,7 +3772,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3780,13 +3780,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 56 /*GetCallback*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3813,7 +3813,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3821,13 +3821,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 57 /*FillOutStructuredParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3854,7 +3854,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3862,13 +3862,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 58 /*RepeatExtendableParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3895,7 +3895,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3903,13 +3903,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 59 /*ReverseList*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3936,7 +3936,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3947,13 +3947,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 60 /*ReverseIBinderArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -3983,7 +3983,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -3994,13 +3994,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 61 /*ReverseNullableIBinderArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4030,7 +4030,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -4038,13 +4038,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 62 /*RepeatSimpleParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4074,7 +4074,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -4085,13 +4085,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 63 /*ReverseSimpleParcelables*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4121,18 +4121,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 64 /*GetOldNameInterface*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4159,18 +4159,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 65 /*GetNewNameInterface*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4197,7 +4197,7 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
@@ -4205,13 +4205,13 @@ BpTestService::~BpTestService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 66 /*GetUnionTags*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4238,18 +4238,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 67 /*GetCppJavaTests*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4276,18 +4276,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 68 /*getBackendType*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -4314,18 +4314,18 @@ BpTestService::~BpTestService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   AParcel_markSensitive(_aidl_in.get());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 69 /*GetCircular*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     FLAG_CLEAR_BUF
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITestService::getDefaultImpl()) {
@@ -5239,17 +5239,17 @@ ITestService::CompilerChecks::BpNoPrefixInterface::~BpNoPrefixInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*foo*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INoPrefixInterface::getDefaultImpl()) {
@@ -5411,17 +5411,17 @@ ITestService::CompilerChecks::INoPrefixInterface::BpNestedNoPrefixInterface::~Bp
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*foo*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INestedNoPrefixInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
index a4702c69..163d622d 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/ListOfInterfaces.cpp
@@ -205,7 +205,7 @@ ListOfInterfaces::BpMyInterface::~BpMyInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_iface);
@@ -227,13 +227,13 @@ ListOfInterfaces::BpMyInterface::~BpMyInterface() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*methodWithInterfaces*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
index 0ec9154a..67c1d477 100644
--- a/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
+++ b/tests/golden_output/frozen/aidl-test-interface-ndk-source/gen/android/aidl/tests/nested/INestedService.cpp
@@ -70,20 +70,20 @@ BpNestedService::~BpNestedService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_p);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*flipStatus*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INestedService::getDefaultImpl()) {
@@ -110,7 +110,7 @@ BpNestedService::~BpNestedService() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_status);
@@ -120,13 +120,13 @@ BpNestedService::~BpNestedService() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*flipStatusWithCallback*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && INestedService::getDefaultImpl()) {
@@ -311,20 +311,20 @@ INestedService::BpCallback::~BpCallback() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_status);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*done*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ICallback::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
index 6889bd6b..a6b0615a 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ArrayOfInterfaces.rs
@@ -40,7 +40,7 @@ pub mod r#IEmptyInterface {
       native: BnEmptyInterface(on_transact),
       proxy: BpEmptyInterface {
       },
-      async: IEmptyInterfaceAsync,
+      async: IEmptyInterfaceAsync(try_into_local_async),
     }
   }
   pub trait IEmptyInterface: binder::Interface + Send {
@@ -51,6 +51,9 @@ pub mod r#IEmptyInterface {
     fn setDefaultImpl(d: IEmptyInterfaceDefaultRef) -> IEmptyInterfaceDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IEmptyInterfaceAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ArrayOfInterfaces.IEmptyInterface" }
@@ -79,10 +82,26 @@ pub mod r#IEmptyInterface {
         T: IEmptyInterfaceAsyncServer + Send + Sync + 'static,
         R: binder::binder_impl::BinderAsyncRuntime + Send + Sync + 'static,
       {
+        fn try_as_async_server(&self) -> Option<&(dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IEmptyInterfaceAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnEmptyInterface>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IEmptyInterfaceAsync<P> for Wrapper {
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IEmptyInterfaceAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IEmptyInterfaceDefault: Send + Sync {
   }
@@ -114,7 +133,7 @@ pub mod r#IMyInterface {
       native: BnMyInterface(on_transact),
       proxy: BpMyInterface {
       },
-      async: IMyInterfaceAsync,
+      async: IMyInterfaceAsync(try_into_local_async),
     }
   }
   pub trait IMyInterface: binder::Interface + Send {
@@ -126,6 +145,9 @@ pub mod r#IMyInterface {
     fn setDefaultImpl(d: IMyInterfaceDefaultRef) -> IMyInterfaceDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IMyInterfaceAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IMyInterfaceAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ArrayOfInterfaces.IMyInterface" }
@@ -159,10 +181,29 @@ pub mod r#IMyInterface {
         fn r#methodWithInterfaces(&self, _arg_iface: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_iface_array_in: &[binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>], _arg_iface_array_out: &mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>, _arg_iface_array_inout: &mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_array_in: Option<&[Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_array_out: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_array_inout: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>> {
           self._rt.block_on(self._inner.r#methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_array_in, _arg_iface_array_out, _arg_iface_array_inout, _arg_nullable_iface_array_in, _arg_nullable_iface_array_out, _arg_nullable_iface_array_inout))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn IMyInterfaceAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IMyInterfaceAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnMyInterface>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IMyInterfaceAsync<P> for Wrapper {
+        fn r#methodWithInterfaces<'a>(&'a self, _arg_iface: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_iface_array_in: &'a [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>], _arg_iface_array_out: &'a mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>, _arg_iface_array_inout: &'a mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_array_in: Option<&'a [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_array_out: &'a mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_array_inout: &'a mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_array_in, _arg_iface_array_out, _arg_iface_array_inout, _arg_nullable_iface_array_in, _arg_nullable_iface_array_out, _arg_nullable_iface_array_inout))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IMyInterfaceAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IMyInterfaceDefault: Send + Sync {
     fn r#methodWithInterfaces(&self, _arg_iface: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_iface_array_in: &[binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>], _arg_iface_array_out: &mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>, _arg_iface_array_inout: &mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_array_in: Option<&[Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_array_out: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_array_inout: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_17_ArrayOfInterfaces_15_IEmptyInterface>>>>> {
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
index 9cdfa573..dd8e540e 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ICircular.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnCircular(on_transact),
     proxy: BpCircular {
     },
-    async: ICircularAsync,
+    async: ICircularAsync(try_into_local_async),
   }
 }
 pub trait ICircular: binder::Interface + Send {
@@ -25,6 +25,9 @@ pub trait ICircular: binder::Interface + Send {
   fn setDefaultImpl(d: ICircularDefaultRef) -> ICircularDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn ICircularAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait ICircularAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ICircular" }
@@ -58,10 +61,29 @@ impl BnCircular {
       fn r#GetTestService(&self) -> binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_12_ITestService>>> {
         self._rt.block_on(self._inner.r#GetTestService())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn ICircularAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn ICircularAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnCircular>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> ICircularAsync<P> for Wrapper {
+      fn r#GetTestService<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_12_ITestService>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetTestService())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn ICircularAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait ICircularDefault: Send + Sync {
   fn r#GetTestService(&self) -> binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_12_ITestService>>> {
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
index 59e70ca4..ed30b89b 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IDeprecated.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnDeprecated(on_transact),
     proxy: BpDeprecated {
     },
-    async: IDeprecatedAsync,
+    async: IDeprecatedAsync(try_into_local_async),
   }
 }
 #[deprecated = "test"]
@@ -25,6 +25,9 @@ pub trait IDeprecated: binder::Interface + Send {
   fn setDefaultImpl(d: IDeprecatedDefaultRef) -> IDeprecatedDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IDeprecatedAsyncServer + Send + Sync)> {
+    None
+  }
 }
 #[deprecated = "test"]
 pub trait IDeprecatedAsync<P>: binder::Interface + Send {
@@ -55,10 +58,26 @@ impl BnDeprecated {
       T: IDeprecatedAsyncServer + Send + Sync + 'static,
       R: binder::binder_impl::BinderAsyncRuntime + Send + Sync + 'static,
     {
+      fn try_as_async_server(&self) -> Option<&(dyn IDeprecatedAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IDeprecatedAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnDeprecated>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> IDeprecatedAsync<P> for Wrapper {
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IDeprecatedAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait IDeprecatedDefault: Send + Sync {
 }
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
index 7b4e3f91..bd0cd82c 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INamedCallback.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnNamedCallback(on_transact),
     proxy: BpNamedCallback {
     },
-    async: INamedCallbackAsync,
+    async: INamedCallbackAsync(try_into_local_async),
   }
 }
 pub trait INamedCallback: binder::Interface + Send {
@@ -25,6 +25,9 @@ pub trait INamedCallback: binder::Interface + Send {
   fn setDefaultImpl(d: INamedCallbackDefaultRef) -> INamedCallbackDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn INamedCallbackAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait INamedCallbackAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.INamedCallback" }
@@ -58,10 +61,29 @@ impl BnNamedCallback {
       fn r#GetName(&self) -> binder::Result<String> {
         self._rt.block_on(self._inner.r#GetName())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn INamedCallbackAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn INamedCallbackAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnNamedCallback>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> INamedCallbackAsync<P> for Wrapper {
+      fn r#GetName<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetName())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn INamedCallbackAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait INamedCallbackDefault: Send + Sync {
   fn r#GetName(&self) -> binder::Result<String> {
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
index f2a8678c..53b6fe90 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/INewName.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnNewName(on_transact),
     proxy: BpNewName {
     },
-    async: INewNameAsync,
+    async: INewNameAsync(try_into_local_async),
   }
 }
 pub trait INewName: binder::Interface + Send {
@@ -25,6 +25,9 @@ pub trait INewName: binder::Interface + Send {
   fn setDefaultImpl(d: INewNameDefaultRef) -> INewNameDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn INewNameAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait INewNameAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.IOldName" }
@@ -58,10 +61,29 @@ impl BnNewName {
       fn r#RealName(&self) -> binder::Result<String> {
         self._rt.block_on(self._inner.r#RealName())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn INewNameAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn INewNameAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnNewName>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> INewNameAsync<P> for Wrapper {
+      fn r#RealName<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RealName())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn INewNameAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait INewNameDefault: Send + Sync {
   fn r#RealName(&self) -> binder::Result<String> {
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
index 279b6de1..28f8365d 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/IOldName.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnOldName(on_transact),
     proxy: BpOldName {
     },
-    async: IOldNameAsync,
+    async: IOldNameAsync(try_into_local_async),
   }
 }
 pub trait IOldName: binder::Interface + Send {
@@ -25,6 +25,9 @@ pub trait IOldName: binder::Interface + Send {
   fn setDefaultImpl(d: IOldNameDefaultRef) -> IOldNameDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IOldNameAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait IOldNameAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.IOldName" }
@@ -58,10 +61,29 @@ impl BnOldName {
       fn r#RealName(&self) -> binder::Result<String> {
         self._rt.block_on(self._inner.r#RealName())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn IOldNameAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IOldNameAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnOldName>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> IOldNameAsync<P> for Wrapper {
+      fn r#RealName<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RealName())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IOldNameAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait IOldNameDefault: Send + Sync {
   fn r#RealName(&self) -> binder::Result<String> {
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
index 9e4cb6a2..7d3d4021 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ITestService.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnTestService(on_transact),
     proxy: BpTestService {
     },
-    async: ITestServiceAsync,
+    async: ITestServiceAsync(try_into_local_async),
   }
 }
 pub trait ITestService: binder::Interface + Send {
@@ -95,13 +95,16 @@ pub trait ITestService: binder::Interface + Send {
   fn setDefaultImpl(d: ITestServiceDefaultRef) -> ITestServiceDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn ITestServiceAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait ITestServiceAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ITestService" }
   fn r#UnimplementedMethod<'a>(&'a self, _arg_arg: i32) -> binder::BoxFuture<'a, binder::Result<i32>>;
   #[deprecated = "to make sure we have something in system/tools/aidl which does a compile check of deprecated and make sure this is reflected in goldens"]
   fn r#Deprecated<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>>;
-  fn r#TestOneway(&self) -> std::future::Ready<binder::Result<()>>;
+  fn r#TestOneway<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>>;
   fn r#RepeatBoolean<'a>(&'a self, _arg_token: bool) -> binder::BoxFuture<'a, binder::Result<bool>>;
   fn r#RepeatByte<'a>(&'a self, _arg_token: i8) -> binder::BoxFuture<'a, binder::Result<i8>>;
   fn r#RepeatChar<'a>(&'a self, _arg_token: u16) -> binder::BoxFuture<'a, binder::Result<u16>>;
@@ -475,10 +478,236 @@ impl BnTestService {
       fn r#GetCircular(&self, _arg_cp: &mut crate::mangled::_7_android_4_aidl_5_tests_18_CircularParcelable) -> binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_9_ICircular>> {
         self._rt.block_on(self._inner.r#GetCircular(_arg_cp))
       }
+      fn try_as_async_server(&self) -> Option<&(dyn ITestServiceAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn ITestServiceAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnTestService>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for Wrapper {
+      fn r#UnimplementedMethod<'a>(&'a self, _arg_arg: i32) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#UnimplementedMethod(_arg_arg))
+      }
+      fn r#Deprecated<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#Deprecated())
+      }
+      fn r#TestOneway<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#TestOneway())
+      }
+      fn r#RepeatBoolean<'a>(&'a self, _arg_token: bool) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatBoolean(_arg_token))
+      }
+      fn r#RepeatByte<'a>(&'a self, _arg_token: i8) -> binder::BoxFuture<'a, binder::Result<i8>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatByte(_arg_token))
+      }
+      fn r#RepeatChar<'a>(&'a self, _arg_token: u16) -> binder::BoxFuture<'a, binder::Result<u16>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatChar(_arg_token))
+      }
+      fn r#RepeatInt<'a>(&'a self, _arg_token: i32) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatInt(_arg_token))
+      }
+      fn r#RepeatLong<'a>(&'a self, _arg_token: i64) -> binder::BoxFuture<'a, binder::Result<i64>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatLong(_arg_token))
+      }
+      fn r#RepeatFloat<'a>(&'a self, _arg_token: f32) -> binder::BoxFuture<'a, binder::Result<f32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatFloat(_arg_token))
+      }
+      fn r#RepeatDouble<'a>(&'a self, _arg_token: f64) -> binder::BoxFuture<'a, binder::Result<f64>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatDouble(_arg_token))
+      }
+      fn r#RepeatString<'a>(&'a self, _arg_token: &'a str) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatString(_arg_token))
+      }
+      fn r#RepeatByteEnum<'a>(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatByteEnum(_arg_token))
+      }
+      fn r#RepeatIntEnum<'a>(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatIntEnum(_arg_token))
+      }
+      fn r#RepeatLongEnum<'a>(&'a self, _arg_token: crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatLongEnum(_arg_token))
+      }
+      fn r#ReverseBoolean<'a>(&'a self, _arg_input: &'a [bool], _arg_repeated: &'a mut Vec<bool>) -> binder::BoxFuture<'a, binder::Result<Vec<bool>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseBoolean(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseByte<'a>(&'a self, _arg_input: &'a [u8], _arg_repeated: &'a mut Vec<u8>) -> binder::BoxFuture<'a, binder::Result<Vec<u8>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseByte(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseChar<'a>(&'a self, _arg_input: &'a [u16], _arg_repeated: &'a mut Vec<u16>) -> binder::BoxFuture<'a, binder::Result<Vec<u16>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseChar(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseInt<'a>(&'a self, _arg_input: &'a [i32], _arg_repeated: &'a mut Vec<i32>) -> binder::BoxFuture<'a, binder::Result<Vec<i32>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseInt(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseLong<'a>(&'a self, _arg_input: &'a [i64], _arg_repeated: &'a mut Vec<i64>) -> binder::BoxFuture<'a, binder::Result<Vec<i64>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseLong(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseFloat<'a>(&'a self, _arg_input: &'a [f32], _arg_repeated: &'a mut Vec<f32>) -> binder::BoxFuture<'a, binder::Result<Vec<f32>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseFloat(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseDouble<'a>(&'a self, _arg_input: &'a [f64], _arg_repeated: &'a mut Vec<f64>) -> binder::BoxFuture<'a, binder::Result<Vec<f64>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseDouble(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseString<'a>(&'a self, _arg_input: &'a [String], _arg_repeated: &'a mut Vec<String>) -> binder::BoxFuture<'a, binder::Result<Vec<String>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseString(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseByteEnum<'a>(&'a self, _arg_input: &'a [crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum], _arg_repeated: &'a mut Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>) -> binder::BoxFuture<'a, binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseByteEnum(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseIntEnum<'a>(&'a self, _arg_input: &'a [crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum], _arg_repeated: &'a mut Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>) -> binder::BoxFuture<'a, binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseIntEnum(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseLongEnum<'a>(&'a self, _arg_input: &'a [crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum], _arg_repeated: &'a mut Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>) -> binder::BoxFuture<'a, binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseLongEnum(_arg_input, _arg_repeated))
+      }
+      fn r#GetOtherTestService<'a>(&'a self, _arg_name: &'a str) -> binder::BoxFuture<'a, binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetOtherTestService(_arg_name))
+      }
+      fn r#SetOtherTestService<'a>(&'a self, _arg_name: &'a str, _arg_service: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#SetOtherTestService(_arg_name, _arg_service))
+      }
+      fn r#VerifyName<'a>(&'a self, _arg_service: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>, _arg_name: &'a str) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#VerifyName(_arg_service, _arg_name))
+      }
+      fn r#GetInterfaceArray<'a>(&'a self, _arg_names: &'a [String]) -> binder::BoxFuture<'a, binder::Result<Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetInterfaceArray(_arg_names))
+      }
+      fn r#VerifyNamesWithInterfaceArray<'a>(&'a self, _arg_services: &'a [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>], _arg_names: &'a [String]) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#VerifyNamesWithInterfaceArray(_arg_services, _arg_names))
+      }
+      fn r#GetNullableInterfaceArray<'a>(&'a self, _arg_names: Option<&'a [Option<String>]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetNullableInterfaceArray(_arg_names))
+      }
+      fn r#VerifyNamesWithNullableInterfaceArray<'a>(&'a self, _arg_services: Option<&'a [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>]>, _arg_names: Option<&'a [Option<String>]>) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#VerifyNamesWithNullableInterfaceArray(_arg_services, _arg_names))
+      }
+      fn r#GetInterfaceList<'a>(&'a self, _arg_names: Option<&'a [Option<String>]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetInterfaceList(_arg_names))
+      }
+      fn r#VerifyNamesWithInterfaceList<'a>(&'a self, _arg_services: Option<&'a [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>]>, _arg_names: Option<&'a [Option<String>]>) -> binder::BoxFuture<'a, binder::Result<bool>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#VerifyNamesWithInterfaceList(_arg_services, _arg_names))
+      }
+      fn r#ReverseStringList<'a>(&'a self, _arg_input: &'a [String], _arg_repeated: &'a mut Vec<String>) -> binder::BoxFuture<'a, binder::Result<Vec<String>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseStringList(_arg_input, _arg_repeated))
+      }
+      fn r#RepeatParcelFileDescriptor<'a>(&'a self, _arg_read: &'a binder::ParcelFileDescriptor) -> binder::BoxFuture<'a, binder::Result<binder::ParcelFileDescriptor>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatParcelFileDescriptor(_arg_read))
+      }
+      fn r#ReverseParcelFileDescriptorArray<'a>(&'a self, _arg_input: &'a [binder::ParcelFileDescriptor], _arg_repeated: &'a mut Vec<Option<binder::ParcelFileDescriptor>>) -> binder::BoxFuture<'a, binder::Result<Vec<binder::ParcelFileDescriptor>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseParcelFileDescriptorArray(_arg_input, _arg_repeated))
+      }
+      fn r#ThrowServiceException<'a>(&'a self, _arg_code: i32) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ThrowServiceException(_arg_code))
+      }
+      fn r#RepeatNullableIntArray<'a>(&'a self, _arg_input: Option<&'a [i32]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<i32>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableIntArray(_arg_input))
+      }
+      fn r#RepeatNullableByteEnumArray<'a>(&'a self, _arg_input: Option<&'a [crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_ByteEnum>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableByteEnumArray(_arg_input))
+      }
+      fn r#RepeatNullableIntEnumArray<'a>(&'a self, _arg_input: Option<&'a [crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_7_IntEnum>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableIntEnumArray(_arg_input))
+      }
+      fn r#RepeatNullableLongEnumArray<'a>(&'a self, _arg_input: Option<&'a [crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<crate::mangled::_7_android_4_aidl_5_tests_8_LongEnum>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableLongEnumArray(_arg_input))
+      }
+      fn r#RepeatNullableString<'a>(&'a self, _arg_input: Option<&'a str>) -> binder::BoxFuture<'a, binder::Result<Option<String>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableString(_arg_input))
+      }
+      fn r#RepeatNullableStringList<'a>(&'a self, _arg_input: Option<&'a [Option<String>]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<String>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableStringList(_arg_input))
+      }
+      fn r#RepeatNullableParcelable<'a>(&'a self, _arg_input: Option<&'a crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>) -> binder::BoxFuture<'a, binder::Result<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableParcelable(_arg_input))
+      }
+      fn r#RepeatNullableParcelableArray<'a>(&'a self, _arg_input: Option<&'a [Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableParcelableArray(_arg_input))
+      }
+      fn r#RepeatNullableParcelableList<'a>(&'a self, _arg_input: Option<&'a [Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>]>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<crate::mangled::_7_android_4_aidl_5_tests_12_ITestService_5_Empty>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableParcelableList(_arg_input))
+      }
+      fn r#TakesAnIBinder<'a>(&'a self, _arg_input: &'a binder::SpIBinder) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#TakesAnIBinder(_arg_input))
+      }
+      fn r#TakesANullableIBinder<'a>(&'a self, _arg_input: Option<&'a binder::SpIBinder>) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#TakesANullableIBinder(_arg_input))
+      }
+      fn r#TakesAnIBinderList<'a>(&'a self, _arg_input: &'a [binder::SpIBinder]) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#TakesAnIBinderList(_arg_input))
+      }
+      fn r#TakesANullableIBinderList<'a>(&'a self, _arg_input: Option<&'a [Option<binder::SpIBinder>]>) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#TakesANullableIBinderList(_arg_input))
+      }
+      fn r#RepeatUtf8CppString<'a>(&'a self, _arg_token: &'a str) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatUtf8CppString(_arg_token))
+      }
+      fn r#RepeatNullableUtf8CppString<'a>(&'a self, _arg_token: Option<&'a str>) -> binder::BoxFuture<'a, binder::Result<Option<String>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatNullableUtf8CppString(_arg_token))
+      }
+      fn r#ReverseUtf8CppString<'a>(&'a self, _arg_input: &'a [String], _arg_repeated: &'a mut Vec<String>) -> binder::BoxFuture<'a, binder::Result<Vec<String>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseUtf8CppString(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseNullableUtf8CppString<'a>(&'a self, _arg_input: Option<&'a [Option<String>]>, _arg_repeated: &'a mut Option<Vec<Option<String>>>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<String>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseNullableUtf8CppString(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseUtf8CppStringList<'a>(&'a self, _arg_input: Option<&'a [Option<String>]>, _arg_repeated: &'a mut Option<Vec<Option<String>>>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<String>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseUtf8CppStringList(_arg_input, _arg_repeated))
+      }
+      fn r#GetCallback<'a>(&'a self, _arg_return_null: bool) -> binder::BoxFuture<'a, binder::Result<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_14_INamedCallback>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetCallback(_arg_return_null))
+      }
+      fn r#FillOutStructuredParcelable<'a>(&'a self, _arg_parcel: &'a mut crate::mangled::_7_android_4_aidl_5_tests_20_StructuredParcelable) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#FillOutStructuredParcelable(_arg_parcel))
+      }
+      fn r#RepeatExtendableParcelable<'a>(&'a self, _arg_ep: &'a crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable, _arg_ep2: &'a mut crate::mangled::_7_android_4_aidl_5_tests_9_extension_20_ExtendableParcelable) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatExtendableParcelable(_arg_ep, _arg_ep2))
+      }
+      fn r#ReverseList<'a>(&'a self, _arg_list: &'a crate::mangled::_7_android_4_aidl_5_tests_13_RecursiveList) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_13_RecursiveList>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseList(_arg_list))
+      }
+      fn r#ReverseIBinderArray<'a>(&'a self, _arg_input: &'a [binder::SpIBinder], _arg_repeated: &'a mut Vec<Option<binder::SpIBinder>>) -> binder::BoxFuture<'a, binder::Result<Vec<binder::SpIBinder>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseIBinderArray(_arg_input, _arg_repeated))
+      }
+      fn r#ReverseNullableIBinderArray<'a>(&'a self, _arg_input: Option<&'a [Option<binder::SpIBinder>]>, _arg_repeated: &'a mut Option<Vec<Option<binder::SpIBinder>>>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<binder::SpIBinder>>>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseNullableIBinderArray(_arg_input, _arg_repeated))
+      }
+      fn r#RepeatSimpleParcelable<'a>(&'a self, _arg_input: &'a simple_parcelable::SimpleParcelable, _arg_repeat: &'a mut simple_parcelable::SimpleParcelable) -> binder::BoxFuture<'a, binder::Result<simple_parcelable::SimpleParcelable>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#RepeatSimpleParcelable(_arg_input, _arg_repeat))
+      }
+      fn r#ReverseSimpleParcelables<'a>(&'a self, _arg_input: &'a [simple_parcelable::SimpleParcelable], _arg_repeated: &'a mut Vec<simple_parcelable::SimpleParcelable>) -> binder::BoxFuture<'a, binder::Result<Vec<simple_parcelable::SimpleParcelable>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ReverseSimpleParcelables(_arg_input, _arg_repeated))
+      }
+      fn r#GetOldNameInterface<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_8_IOldName>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetOldNameInterface())
+      }
+      fn r#GetNewNameInterface<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_8_INewName>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetNewNameInterface())
+      }
+      fn r#GetUnionTags<'a>(&'a self, _arg_input: &'a [crate::mangled::_7_android_4_aidl_5_tests_5_Union]) -> binder::BoxFuture<'a, binder::Result<Vec<crate::mangled::_7_android_4_aidl_5_tests_5_Union_3_Tag>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetUnionTags(_arg_input))
+      }
+      fn r#GetCppJavaTests<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<Option<binder::SpIBinder>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetCppJavaTests())
+      }
+      fn r#getBackendType<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_11_BackendType>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#getBackendType())
+      }
+      fn r#GetCircular<'a>(&'a self, _arg_cp: &'a mut crate::mangled::_7_android_4_aidl_5_tests_18_CircularParcelable) -> binder::BoxFuture<'a, binder::Result<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_9_ICircular>>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#GetCircular(_arg_cp))
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn ITestServiceAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait ITestServiceDefault: Send + Sync {
   fn r#UnimplementedMethod(&self, _arg_arg: i32) -> binder::Result<i32> {
@@ -2524,13 +2753,18 @@ impl<P: binder::BinderAsyncPool> ITestServiceAsync<P> for BpTestService {
       }
     )
   }
-  fn r#TestOneway(&self) -> std::future::Ready<binder::Result<()>> {
+  fn r#TestOneway<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
     let _aidl_data = match self.build_parcel_TestOneway() {
       Ok(_aidl_data) => _aidl_data,
-      Err(err) => return std::future::ready(Err(err)),
+      Err(err) => return Box::pin(std::future::ready(Err(err))),
     };
-    let _aidl_reply = self.binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL);
-    std::future::ready(self.read_response_TestOneway(_aidl_reply))
+    let binder = self.binder.clone();
+    P::spawn(
+      move || binder.submit_transact(transactions::r#TestOneway, _aidl_data, binder::binder_impl::FLAG_ONEWAY | binder::binder_impl::FLAG_CLEAR_BUF | binder::binder_impl::FLAG_PRIVATE_LOCAL),
+      move |_aidl_reply| async move {
+        self.read_response_TestOneway(_aidl_reply)
+      }
+    )
   }
   fn r#RepeatBoolean<'a>(&'a self, _arg_token: bool) -> binder::BoxFuture<'a, binder::Result<bool>> {
     let _aidl_data = match self.build_parcel_RepeatBoolean(_arg_token) {
@@ -4542,7 +4776,7 @@ pub mod r#CompilerChecks {
         native: BnFoo(on_transact),
         proxy: BpFoo {
         },
-        async: IFooAsync,
+        async: IFooAsync(try_into_local_async),
       }
     }
     pub trait IFoo: binder::Interface + Send {
@@ -4553,6 +4787,9 @@ pub mod r#CompilerChecks {
       fn setDefaultImpl(d: IFooDefaultRef) -> IFooDefaultRef where Self: Sized {
         std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
       }
+      fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IFooAsyncServer + Send + Sync)> {
+        None
+      }
     }
     pub trait IFooAsync<P>: binder::Interface + Send {
       fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ITestService.CompilerChecks.Foo" }
@@ -4581,10 +4818,26 @@ pub mod r#CompilerChecks {
           T: IFooAsyncServer + Send + Sync + 'static,
           R: binder::binder_impl::BinderAsyncRuntime + Send + Sync + 'static,
         {
+          fn try_as_async_server(&self) -> Option<&(dyn IFooAsyncServer + Send + Sync)> {
+            Some(&self._inner)
+          }
         }
         let wrapped = Wrapper { _inner: inner, _rt: rt };
         Self::new_binder(wrapped, features)
       }
+      pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IFooAsync<P>>> {
+        struct Wrapper {
+          _native: binder::binder_impl::Binder<BnFoo>
+        }
+        impl binder::Interface for Wrapper {}
+        impl<P: binder::BinderAsyncPool> IFooAsync<P> for Wrapper {
+        }
+        if _native.try_as_async_server().is_some() {
+          Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IFooAsync<P>>))
+        } else {
+          None
+        }
+      }
     }
     pub trait IFooDefault: Send + Sync {
     }
@@ -4711,7 +4964,7 @@ pub mod r#CompilerChecks {
         native: BnNoPrefixInterface(on_transact),
         proxy: BpNoPrefixInterface {
         },
-        async: INoPrefixInterfaceAsync,
+        async: INoPrefixInterfaceAsync(try_into_local_async),
       }
     }
     pub trait INoPrefixInterface: binder::Interface + Send {
@@ -4723,6 +4976,9 @@ pub mod r#CompilerChecks {
       fn setDefaultImpl(d: INoPrefixInterfaceDefaultRef) -> INoPrefixInterfaceDefaultRef where Self: Sized {
         std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
       }
+      fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn INoPrefixInterfaceAsyncServer + Send + Sync)> {
+        None
+      }
     }
     pub trait INoPrefixInterfaceAsync<P>: binder::Interface + Send {
       fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface" }
@@ -4756,10 +5012,29 @@ pub mod r#CompilerChecks {
           fn r#foo(&self) -> binder::Result<()> {
             self._rt.block_on(self._inner.r#foo())
           }
+          fn try_as_async_server(&self) -> Option<&(dyn INoPrefixInterfaceAsyncServer + Send + Sync)> {
+            Some(&self._inner)
+          }
         }
         let wrapped = Wrapper { _inner: inner, _rt: rt };
         Self::new_binder(wrapped, features)
       }
+      pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn INoPrefixInterfaceAsync<P>>> {
+        struct Wrapper {
+          _native: binder::binder_impl::Binder<BnNoPrefixInterface>
+        }
+        impl binder::Interface for Wrapper {}
+        impl<P: binder::BinderAsyncPool> INoPrefixInterfaceAsync<P> for Wrapper {
+          fn r#foo<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+            Box::pin(self._native.try_as_async_server().unwrap().r#foo())
+          }
+        }
+        if _native.try_as_async_server().is_some() {
+          Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn INoPrefixInterfaceAsync<P>>))
+        } else {
+          None
+        }
+      }
     }
     pub trait INoPrefixInterfaceDefault: Send + Sync {
       fn r#foo(&self) -> binder::Result<()> {
@@ -4866,7 +5141,7 @@ pub mod r#CompilerChecks {
           native: BnNestedNoPrefixInterface(on_transact),
           proxy: BpNestedNoPrefixInterface {
           },
-          async: INestedNoPrefixInterfaceAsync,
+          async: INestedNoPrefixInterfaceAsync(try_into_local_async),
         }
       }
       pub trait INestedNoPrefixInterface: binder::Interface + Send {
@@ -4878,6 +5153,9 @@ pub mod r#CompilerChecks {
         fn setDefaultImpl(d: INestedNoPrefixInterfaceDefaultRef) -> INestedNoPrefixInterfaceDefaultRef where Self: Sized {
           std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
         }
+        fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn INestedNoPrefixInterfaceAsyncServer + Send + Sync)> {
+          None
+        }
       }
       pub trait INestedNoPrefixInterfaceAsync<P>: binder::Interface + Send {
         fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ITestService.CompilerChecks.NoPrefixInterface.NestedNoPrefixInterface" }
@@ -4911,10 +5189,29 @@ pub mod r#CompilerChecks {
             fn r#foo(&self) -> binder::Result<()> {
               self._rt.block_on(self._inner.r#foo())
             }
+            fn try_as_async_server(&self) -> Option<&(dyn INestedNoPrefixInterfaceAsyncServer + Send + Sync)> {
+              Some(&self._inner)
+            }
           }
           let wrapped = Wrapper { _inner: inner, _rt: rt };
           Self::new_binder(wrapped, features)
         }
+        pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn INestedNoPrefixInterfaceAsync<P>>> {
+          struct Wrapper {
+            _native: binder::binder_impl::Binder<BnNestedNoPrefixInterface>
+          }
+          impl binder::Interface for Wrapper {}
+          impl<P: binder::BinderAsyncPool> INestedNoPrefixInterfaceAsync<P> for Wrapper {
+            fn r#foo<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+              Box::pin(self._native.try_as_async_server().unwrap().r#foo())
+            }
+          }
+          if _native.try_as_async_server().is_some() {
+            Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn INestedNoPrefixInterfaceAsync<P>>))
+          } else {
+            None
+          }
+        }
       }
       pub trait INestedNoPrefixInterfaceDefault: Send + Sync {
         fn r#foo(&self) -> binder::Result<()> {
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
index 452b944b..852491fb 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/ListOfInterfaces.rs
@@ -40,7 +40,7 @@ pub mod r#IEmptyInterface {
       native: BnEmptyInterface(on_transact),
       proxy: BpEmptyInterface {
       },
-      async: IEmptyInterfaceAsync,
+      async: IEmptyInterfaceAsync(try_into_local_async),
     }
   }
   pub trait IEmptyInterface: binder::Interface + Send {
@@ -51,6 +51,9 @@ pub mod r#IEmptyInterface {
     fn setDefaultImpl(d: IEmptyInterfaceDefaultRef) -> IEmptyInterfaceDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IEmptyInterfaceAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ListOfInterfaces.IEmptyInterface" }
@@ -79,10 +82,26 @@ pub mod r#IEmptyInterface {
         T: IEmptyInterfaceAsyncServer + Send + Sync + 'static,
         R: binder::binder_impl::BinderAsyncRuntime + Send + Sync + 'static,
       {
+        fn try_as_async_server(&self) -> Option<&(dyn IEmptyInterfaceAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IEmptyInterfaceAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnEmptyInterface>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IEmptyInterfaceAsync<P> for Wrapper {
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IEmptyInterfaceAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IEmptyInterfaceDefault: Send + Sync {
   }
@@ -114,7 +133,7 @@ pub mod r#IMyInterface {
       native: BnMyInterface(on_transact),
       proxy: BpMyInterface {
       },
-      async: IMyInterfaceAsync,
+      async: IMyInterfaceAsync(try_into_local_async),
     }
   }
   pub trait IMyInterface: binder::Interface + Send {
@@ -126,6 +145,9 @@ pub mod r#IMyInterface {
     fn setDefaultImpl(d: IMyInterfaceDefaultRef) -> IMyInterfaceDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IMyInterfaceAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IMyInterfaceAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.ListOfInterfaces.IMyInterface" }
@@ -159,10 +181,29 @@ pub mod r#IMyInterface {
         fn r#methodWithInterfaces(&self, _arg_iface: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_iface_list_in: &[binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>], _arg_iface_list_out: &mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>, _arg_iface_list_inout: &mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_list_in: Option<&[Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_list_out: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_list_inout: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>> {
           self._rt.block_on(self._inner.r#methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_list_in, _arg_iface_list_out, _arg_iface_list_inout, _arg_nullable_iface_list_in, _arg_nullable_iface_list_out, _arg_nullable_iface_list_inout))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn IMyInterfaceAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IMyInterfaceAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnMyInterface>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IMyInterfaceAsync<P> for Wrapper {
+        fn r#methodWithInterfaces<'a>(&'a self, _arg_iface: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_iface_list_in: &'a [binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>], _arg_iface_list_out: &'a mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>, _arg_iface_list_inout: &'a mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_list_in: Option<&'a [Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_list_out: &'a mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_list_inout: &'a mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>) -> binder::BoxFuture<'a, binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#methodWithInterfaces(_arg_iface, _arg_nullable_iface, _arg_iface_list_in, _arg_iface_list_out, _arg_iface_list_inout, _arg_nullable_iface_list_in, _arg_nullable_iface_list_out, _arg_nullable_iface_list_inout))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IMyInterfaceAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IMyInterfaceDefault: Send + Sync {
     fn r#methodWithInterfaces(&self, _arg_iface: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>, _arg_nullable_iface: Option<&binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_iface_list_in: &[binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>], _arg_iface_list_out: &mut Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>, _arg_iface_list_inout: &mut Vec<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>, _arg_nullable_iface_list_in: Option<&[Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>]>, _arg_nullable_iface_list_out: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>, _arg_nullable_iface_list_inout: &mut Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>) -> binder::Result<Option<Vec<Option<binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_16_ListOfInterfaces_15_IEmptyInterface>>>>> {
diff --git a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
index aaebf1cb..c9a3fa71 100644
--- a/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
+++ b/tests/golden_output/frozen/aidl-test-interface-rust-source/gen/android/aidl/tests/nested/INestedService.rs
@@ -13,7 +13,7 @@ declare_binder_interface! {
     native: BnNestedService(on_transact),
     proxy: BpNestedService {
     },
-    async: INestedServiceAsync,
+    async: INestedServiceAsync(try_into_local_async),
   }
 }
 pub trait INestedService: binder::Interface + Send {
@@ -26,6 +26,9 @@ pub trait INestedService: binder::Interface + Send {
   fn setDefaultImpl(d: INestedServiceDefaultRef) -> INestedServiceDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn INestedServiceAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait INestedServiceAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.nested.INestedService" }
@@ -64,10 +67,32 @@ impl BnNestedService {
       fn r#flipStatusWithCallback(&self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status, _arg_cb: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_9_ICallback>) -> binder::Result<()> {
         self._rt.block_on(self._inner.r#flipStatusWithCallback(_arg_status, _arg_cb))
       }
+      fn try_as_async_server(&self) -> Option<&(dyn INestedServiceAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn INestedServiceAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnNestedService>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> INestedServiceAsync<P> for Wrapper {
+      fn r#flipStatus<'a>(&'a self, _arg_p: &'a crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_6_Result>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#flipStatus(_arg_p))
+      }
+      fn r#flipStatusWithCallback<'a>(&'a self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status, _arg_cb: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_9_ICallback>) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#flipStatusWithCallback(_arg_status, _arg_cb))
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn INestedServiceAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait INestedServiceDefault: Send + Sync {
   fn r#flipStatus(&self, _arg_p: &crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested) -> binder::Result<crate::mangled::_7_android_4_aidl_5_tests_6_nested_14_INestedService_6_Result> {
@@ -236,7 +261,7 @@ pub mod r#ICallback {
       native: BnCallback(on_transact),
       proxy: BpCallback {
       },
-      async: ICallbackAsync,
+      async: ICallbackAsync(try_into_local_async),
     }
   }
   pub trait ICallback: binder::Interface + Send {
@@ -248,6 +273,9 @@ pub mod r#ICallback {
     fn setDefaultImpl(d: ICallbackDefaultRef) -> ICallbackDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn ICallbackAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait ICallbackAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.tests.nested.INestedService.ICallback" }
@@ -281,10 +309,29 @@ pub mod r#ICallback {
         fn r#done(&self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status) -> binder::Result<()> {
           self._rt.block_on(self._inner.r#done(_arg_status))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn ICallbackAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn ICallbackAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnCallback>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> ICallbackAsync<P> for Wrapper {
+        fn r#done<'a>(&'a self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status) -> binder::BoxFuture<'a, binder::Result<()>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#done(_arg_status))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn ICallbackAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait ICallbackDefault: Send + Sync {
     fn r#done(&self, _arg_status: crate::mangled::_7_android_4_aidl_5_tests_6_nested_20_ParcelableWithNested_6_Status) -> binder::Result<()> {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 0707b9bb..acbb2e2e 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -25,7 +25,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BazUnion : public ::android::Parcelable {
+class LIBBINDER_EXPORTED BazUnion : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     intNum = 0,
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
index 22baaa9b..32db1161 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BnFooInterface : public ::android::BnInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BnFooInterface : public ::android::BnInterface<IFooInterface> {
 public:
   static constexpr uint32_t TRANSACTION_originalApi = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_acceptUnionAndReturnString = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -28,7 +28,7 @@ public:
   std::string getInterfaceHash();
 };  // class BnFooInterface
 
-class IFooInterfaceDelegator : public BnFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDelegator : public BnFooInterface {
 public:
   explicit IFooInterfaceDelegator(const ::android::sp<IFooInterface> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
index 409c6f58..73690800 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BpFooInterface : public ::android::BpInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BpFooInterface : public ::android::BpInterface<IFooInterface> {
 public:
   explicit BpFooInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpFooInterface() = default;
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index c7980c52..794737f7 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class Foo : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Foo : public ::android::Parcelable {
 public:
   inline bool operator==(const Foo&) const {
     return std::tie() == std::tie();
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
index e7eb4be8..398ad315 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
@@ -23,9 +23,9 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class IFooInterfaceDelegator;
+class LIBBINDER_EXPORTED IFooInterfaceDelegator;
 
-class IFooInterface : public ::android::IInterface {
+class LIBBINDER_EXPORTED IFooInterface : public ::android::IInterface {
 public:
   typedef IFooInterfaceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(FooInterface)
@@ -39,7 +39,7 @@ public:
   virtual std::string getInterfaceHash() = 0;
 };  // class IFooInterface
 
-class IFooInterfaceDefault : public IFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDefault : public IFooInterface {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index aec8e2cc..7e8f34fd 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -141,17 +141,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*originalApi*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -175,20 +175,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_u);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*acceptUnionAndReturnString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -215,7 +215,7 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_inFoo);
@@ -228,13 +228,13 @@ BpFooInterface::~BpFooInterface() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*ignoreParcelablesAndRepeatInt*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -267,20 +267,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_foos);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*returnsLengthOfFooArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -312,17 +312,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -356,17 +356,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index 9c5b7d0d..d41f0bba 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V1-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -15,7 +15,7 @@ declare_binder_interface! {
       cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
       cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
     },
-    async: IFooInterfaceAsync,
+    async: IFooInterfaceAsync(try_into_local_async),
   }
 }
 pub trait IFooInterface: binder::Interface + Send {
@@ -36,6 +36,9 @@ pub trait IFooInterface: binder::Interface + Send {
   fn setDefaultImpl(d: IFooInterfaceDefaultRef) -> IFooInterfaceDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IFooInterfaceAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait IFooInterfaceAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.versioned.tests.IFooInterface" }
@@ -90,10 +93,38 @@ impl BnFooInterface {
       fn r#returnsLengthOfFooArray(&self, _arg_foos: &[crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::Result<i32> {
         self._rt.block_on(self._inner.r#returnsLengthOfFooArray(_arg_foos))
       }
+      fn try_as_async_server(&self) -> Option<&(dyn IFooInterfaceAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IFooInterfaceAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnFooInterface>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for Wrapper {
+      fn r#originalApi<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#originalApi())
+      }
+      fn r#acceptUnionAndReturnString<'a>(&'a self, _arg_u: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#acceptUnionAndReturnString(_arg_u))
+      }
+      fn r#ignoreParcelablesAndRepeatInt<'a>(&'a self, _arg_inFoo: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value))
+      }
+      fn r#returnsLengthOfFooArray<'a>(&'a self, _arg_foos: &'a [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#returnsLengthOfFooArray(_arg_foos))
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IFooInterfaceAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait IFooInterfaceDefault: Send + Sync {
   fn r#originalApi(&self) -> binder::Result<()> {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index 79e366b6..cc3b2b4e 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -25,7 +25,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BazUnion : public ::android::Parcelable {
+class LIBBINDER_EXPORTED BazUnion : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     intNum = 0,
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
index 69b229ee..c0632013 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BnFooInterface : public ::android::BnInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BnFooInterface : public ::android::BnInterface<IFooInterface> {
 public:
   static constexpr uint32_t TRANSACTION_originalApi = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_acceptUnionAndReturnString = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -29,7 +29,7 @@ public:
   std::string getInterfaceHash();
 };  // class BnFooInterface
 
-class IFooInterfaceDelegator : public BnFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDelegator : public BnFooInterface {
 public:
   explicit IFooInterfaceDelegator(const ::android::sp<IFooInterface> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
index 0096981a..a5d1605e 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BpFooInterface : public ::android::BpInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BpFooInterface : public ::android::BpInterface<IFooInterface> {
 public:
   explicit BpFooInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpFooInterface() = default;
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index 0a4370dc..6818ce60 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -15,7 +15,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class Foo : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Foo : public ::android::Parcelable {
 public:
   int32_t intDefault42 = 42;
   inline bool operator==(const Foo& _rhs) const {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
index e50a31fe..b3ee1e15 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
@@ -23,9 +23,9 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class IFooInterfaceDelegator;
+class LIBBINDER_EXPORTED IFooInterfaceDelegator;
 
-class IFooInterface : public ::android::IInterface {
+class LIBBINDER_EXPORTED IFooInterface : public ::android::IInterface {
 public:
   typedef IFooInterfaceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(FooInterface)
@@ -40,7 +40,7 @@ public:
   virtual std::string getInterfaceHash() = 0;
 };  // class IFooInterface
 
-class IFooInterfaceDefault : public IFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDefault : public IFooInterface {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index aafb98ee..11fff389 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -151,17 +151,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*originalApi*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -185,20 +185,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_u);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*acceptUnionAndReturnString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -225,7 +225,7 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_inFoo);
@@ -238,13 +238,13 @@ BpFooInterface::~BpFooInterface() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*ignoreParcelablesAndRepeatInt*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -277,20 +277,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_foos);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*returnsLengthOfFooArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -317,17 +317,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 4 /*newApi*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -356,17 +356,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -400,17 +400,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index 3c883b39..1870d515 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V2-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -15,7 +15,7 @@ declare_binder_interface! {
       cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
       cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
     },
-    async: IFooInterfaceAsync,
+    async: IFooInterfaceAsync(try_into_local_async),
   }
 }
 pub trait IFooInterface: binder::Interface + Send {
@@ -37,6 +37,9 @@ pub trait IFooInterface: binder::Interface + Send {
   fn setDefaultImpl(d: IFooInterfaceDefaultRef) -> IFooInterfaceDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IFooInterfaceAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait IFooInterfaceAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.versioned.tests.IFooInterface" }
@@ -96,10 +99,41 @@ impl BnFooInterface {
       fn r#newApi(&self) -> binder::Result<()> {
         self._rt.block_on(self._inner.r#newApi())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn IFooInterfaceAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IFooInterfaceAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnFooInterface>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for Wrapper {
+      fn r#originalApi<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#originalApi())
+      }
+      fn r#acceptUnionAndReturnString<'a>(&'a self, _arg_u: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#acceptUnionAndReturnString(_arg_u))
+      }
+      fn r#ignoreParcelablesAndRepeatInt<'a>(&'a self, _arg_inFoo: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value))
+      }
+      fn r#returnsLengthOfFooArray<'a>(&'a self, _arg_foos: &'a [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#returnsLengthOfFooArray(_arg_foos))
+      }
+      fn r#newApi<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#newApi())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IFooInterfaceAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait IFooInterfaceDefault: Send + Sync {
   fn r#originalApi(&self) -> binder::Result<()> {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
index a866c6b3..0a5200da 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BazUnion.h
@@ -25,7 +25,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BazUnion : public ::android::Parcelable {
+class LIBBINDER_EXPORTED BazUnion : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     intNum = 0,
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
index 892b1634..ba837986 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BnFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BnFooInterface : public ::android::BnInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BnFooInterface : public ::android::BnInterface<IFooInterface> {
 public:
   static constexpr uint32_t TRANSACTION_originalApi = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_acceptUnionAndReturnString = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -29,7 +29,7 @@ public:
   std::string getInterfaceHash();
 };  // class BnFooInterface
 
-class IFooInterfaceDelegator : public BnFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDelegator : public BnFooInterface {
 public:
   explicit IFooInterfaceDelegator(const ::android::sp<IFooInterface> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
index ffef716a..e59d7af9 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/BpFooInterface.h
@@ -14,7 +14,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class BpFooInterface : public ::android::BpInterface<IFooInterface> {
+class LIBBINDER_EXPORTED BpFooInterface : public ::android::BpInterface<IFooInterface> {
 public:
   explicit BpFooInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpFooInterface() = default;
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
index 5e1b926a..378d274d 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/Foo.h
@@ -15,7 +15,7 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class Foo : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Foo : public ::android::Parcelable {
 public:
   int32_t intDefault42 = 42;
   inline bool operator==(const Foo& _rhs) const {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
index aa5add2a..c9b6dcba 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-cpp-source/gen/include/android/aidl/versioned/tests/IFooInterface.h
@@ -23,9 +23,9 @@ namespace android {
 namespace aidl {
 namespace versioned {
 namespace tests {
-class IFooInterfaceDelegator;
+class LIBBINDER_EXPORTED IFooInterfaceDelegator;
 
-class IFooInterface : public ::android::IInterface {
+class LIBBINDER_EXPORTED IFooInterface : public ::android::IInterface {
 public:
   typedef IFooInterfaceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(FooInterface)
@@ -40,7 +40,7 @@ public:
   virtual std::string getInterfaceHash() = 0;
 };  // class IFooInterface
 
-class IFooInterfaceDefault : public IFooInterface {
+class LIBBINDER_EXPORTED IFooInterfaceDefault : public IFooInterface {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
index ecc887ed..aebb8626 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-ndk-source/gen/android/aidl/versioned/tests/IFooInterface.cpp
@@ -151,17 +151,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*originalApi*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -185,20 +185,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_u);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*acceptUnionAndReturnString*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -225,7 +225,7 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_inFoo);
@@ -238,13 +238,13 @@ BpFooInterface::~BpFooInterface() {}
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*ignoreParcelablesAndRepeatInt*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -277,20 +277,20 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_foos);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*returnsLengthOfFooArray*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -317,17 +317,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 4 /*newApi*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -356,17 +356,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
@@ -400,17 +400,17 @@ BpFooInterface::~BpFooInterface() {}
   ::ndk::ScopedAParcel _aidl_in;
   ::ndk::ScopedAParcel _aidl_out;
 
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFooInterface::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
index 17d1406d..24e86517 100644
--- a/tests/golden_output/frozen/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
+++ b/tests/golden_output/frozen/aidl-test-versioned-interface-V3-rust-source/gen/android/aidl/versioned/tests/IFooInterface.rs
@@ -15,7 +15,7 @@ declare_binder_interface! {
       cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
       cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
     },
-    async: IFooInterfaceAsync,
+    async: IFooInterfaceAsync(try_into_local_async),
   }
 }
 pub trait IFooInterface: binder::Interface + Send {
@@ -37,6 +37,9 @@ pub trait IFooInterface: binder::Interface + Send {
   fn setDefaultImpl(d: IFooInterfaceDefaultRef) -> IFooInterfaceDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IFooInterfaceAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait IFooInterfaceAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.versioned.tests.IFooInterface" }
@@ -96,10 +99,41 @@ impl BnFooInterface {
       fn r#newApi(&self) -> binder::Result<()> {
         self._rt.block_on(self._inner.r#newApi())
       }
+      fn try_as_async_server(&self) -> Option<&(dyn IFooInterfaceAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IFooInterfaceAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnFooInterface>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> IFooInterfaceAsync<P> for Wrapper {
+      fn r#originalApi<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#originalApi())
+      }
+      fn r#acceptUnionAndReturnString<'a>(&'a self, _arg_u: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_8_BazUnion) -> binder::BoxFuture<'a, binder::Result<String>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#acceptUnionAndReturnString(_arg_u))
+      }
+      fn r#ignoreParcelablesAndRepeatInt<'a>(&'a self, _arg_inFoo: &'a crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_inoutFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_outFoo: &'a mut crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo, _arg_value: i32) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#ignoreParcelablesAndRepeatInt(_arg_inFoo, _arg_inoutFoo, _arg_outFoo, _arg_value))
+      }
+      fn r#returnsLengthOfFooArray<'a>(&'a self, _arg_foos: &'a [crate::mangled::_7_android_4_aidl_9_versioned_5_tests_3_Foo]) -> binder::BoxFuture<'a, binder::Result<i32>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#returnsLengthOfFooArray(_arg_foos))
+      }
+      fn r#newApi<'a>(&'a self) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#newApi())
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IFooInterfaceAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait IFooInterfaceDefault: Send + Sync {
   fn r#originalApi(&self) -> binder::Result<()> {
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BnLoggableInterface.h b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BnLoggableInterface.h
index 8aa6cceb..a591a084 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BnLoggableInterface.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BnLoggableInterface.h
@@ -16,7 +16,7 @@
 namespace android {
 namespace aidl {
 namespace loggable {
-class BnLoggableInterface : public ::android::BnInterface<ILoggableInterface> {
+class LIBBINDER_EXPORTED BnLoggableInterface : public ::android::BnInterface<ILoggableInterface> {
 public:
   static constexpr uint32_t TRANSACTION_LogThis = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   explicit BnLoggableInterface();
@@ -38,7 +38,7 @@ public:
   static std::function<void(const TransactionLog&)> logFunc;
 };  // class BnLoggableInterface
 
-class ILoggableInterfaceDelegator : public BnLoggableInterface {
+class LIBBINDER_EXPORTED ILoggableInterfaceDelegator : public BnLoggableInterface {
 public:
   explicit ILoggableInterfaceDelegator(const ::android::sp<ILoggableInterface> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BpLoggableInterface.h b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BpLoggableInterface.h
index 6b8e3703..d85b9400 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BpLoggableInterface.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/BpLoggableInterface.h
@@ -14,7 +14,7 @@
 namespace android {
 namespace aidl {
 namespace loggable {
-class BpLoggableInterface : public ::android::BpInterface<ILoggableInterface> {
+class LIBBINDER_EXPORTED BpLoggableInterface : public ::android::BpInterface<ILoggableInterface> {
 public:
   explicit BpLoggableInterface(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpLoggableInterface() = default;
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
index 6fa8dccf..e206eb90 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Data.h
@@ -17,7 +17,7 @@
 namespace android {
 namespace aidl {
 namespace loggable {
-class Data : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Data : public ::android::Parcelable {
 public:
   int32_t num = 0;
   ::std::string str;
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/ILoggableInterface.h b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/ILoggableInterface.h
index 8c766f7c..4309b8b6 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/ILoggableInterface.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/ILoggableInterface.h
@@ -25,22 +25,22 @@ class Data;
 namespace android {
 namespace aidl {
 namespace loggable {
-class ILoggableInterfaceDelegator;
+class LIBBINDER_EXPORTED ILoggableInterfaceDelegator;
 
-class ILoggableInterface : public ::android::IInterface {
+class LIBBINDER_EXPORTED ILoggableInterface : public ::android::IInterface {
 public:
   typedef ILoggableInterfaceDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(LoggableInterface)
-  class ISubDelegator;
+  class LIBBINDER_EXPORTED ISubDelegator;
 
-  class ISub : public ::android::IInterface {
+  class LIBBINDER_EXPORTED ISub : public ::android::IInterface {
   public:
     typedef ISubDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(Sub)
     virtual ::android::binder::Status Log(int32_t value) = 0;
   };  // class ISub
 
-  class ISubDefault : public ISub {
+  class LIBBINDER_EXPORTED ISubDefault : public ISub {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -49,7 +49,7 @@ public:
       return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
     }
   };  // class ISubDefault
-  class BpSub : public ::android::BpInterface<ISub> {
+  class LIBBINDER_EXPORTED BpSub : public ::android::BpInterface<ISub> {
   public:
     explicit BpSub(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpSub() = default;
@@ -70,7 +70,7 @@ public:
     };
     static std::function<void(const TransactionLog&)> logFunc;
   };  // class BpSub
-  class BnSub : public ::android::BnInterface<ISub> {
+  class LIBBINDER_EXPORTED BnSub : public ::android::BnInterface<ISub> {
   public:
     static constexpr uint32_t TRANSACTION_Log = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     explicit BnSub();
@@ -92,7 +92,7 @@ public:
     static std::function<void(const TransactionLog&)> logFunc;
   };  // class BnSub
 
-  class ISubDelegator : public BnSub {
+  class LIBBINDER_EXPORTED ISubDelegator : public BnSub {
   public:
     explicit ISubDelegator(const ::android::sp<ISub> &impl) : _aidl_delegate(impl) {}
 
@@ -106,7 +106,7 @@ public:
   virtual ::android::binder::Status LogThis(bool boolValue, ::std::vector<bool>* boolArray, int8_t byteValue, ::std::vector<uint8_t>* byteArray, char16_t charValue, ::std::vector<char16_t>* charArray, int32_t intValue, ::std::vector<int32_t>* intArray, int64_t longValue, ::std::vector<int64_t>* longArray, float floatValue, ::std::vector<float>* floatArray, double doubleValue, ::std::vector<double>* doubleArray, const ::android::String16& stringValue, ::std::vector<::android::String16>* stringArray, ::std::vector<::android::String16>* listValue, const ::android::aidl::loggable::Data& dataValue, const ::android::sp<::android::IBinder>& binderValue, ::std::optional<::android::os::ParcelFileDescriptor>* pfdValue, ::std::vector<::android::os::ParcelFileDescriptor>* pfdArray, ::std::vector<::android::String16>* _aidl_return) = 0;
 };  // class ILoggableInterface
 
-class ILoggableInterfaceDefault : public ILoggableInterface {
+class LIBBINDER_EXPORTED ILoggableInterfaceDefault : public ILoggableInterface {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
index 6c56251f..633dd34a 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-cpp-source/gen/include/android/aidl/loggable/Union.h
@@ -24,7 +24,7 @@
 namespace android {
 namespace aidl {
 namespace loggable {
-class Union : public ::android::Parcelable {
+class LIBBINDER_EXPORTED Union : public ::android::Parcelable {
 public:
   enum class Tag : int32_t {
     num = 0,
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
index 0207903e..52a927db 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/android/aidl/loggable/ILoggableInterface.cpp
@@ -9,13 +9,6 @@
 #include <aidl/android/aidl/loggable/BnLoggableInterface.h>
 #include <aidl/android/aidl/loggable/BpLoggableInterface.h>
 
-namespace {
-struct ScopedTrace {
-  inline explicit ScopedTrace(const char* name) { ATrace_beginSection(name); }
-  inline ~ScopedTrace() { ATrace_endSection(); }
-};
-}  // namespace
-
 namespace aidl {
 namespace android {
 namespace aidl {
@@ -50,7 +43,6 @@ static binder_status_t _aidl_android_aidl_loggable_ILoggableInterface_onTransact
       std::vector<::ndk::ScopedFileDescriptor> in_pfdArray;
       std::vector<std::string> _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ILoggableInterface::LogThis::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_boolValue);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -249,8 +241,7 @@ std::function<void(const BpLoggableInterface::TransactionLog&)> BpLoggableInterf
     _transaction_log.input_args.emplace_back("in_pfdArray", ::android::internal::ToString(*in_pfdArray));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ILoggableInterface::LogThis::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_boolValue);
@@ -317,13 +308,13 @@ std::function<void(const BpLoggableInterface::TransactionLog&)> BpLoggableInterf
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*LogThis*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ILoggableInterface::getDefaultImpl()) {
@@ -490,7 +481,6 @@ static binder_status_t _aidl_android_aidl_loggable_ILoggableInterface_ISub_onTra
     case (FIRST_CALL_TRANSACTION + 0 /*Log*/): {
       int32_t in_value;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ISub::Log::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_value);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -541,21 +531,20 @@ std::function<void(const ILoggableInterface::BpSub::TransactionLog&)> ILoggableI
     _transaction_log.input_args.emplace_back("in_value", ::android::internal::ToString(in_value));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ISub::Log::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_value);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*Log*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ISub::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/BpLoggableInterface.h b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/BpLoggableInterface.h
index c86c9073..8b325d55 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/BpLoggableInterface.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/BpLoggableInterface.h
@@ -10,7 +10,6 @@
 #include <functional>
 #include <chrono>
 #include <sstream>
-#include <android/trace.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/ILoggableInterface.h b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/ILoggableInterface.h
index 121100a8..1a7786e8 100644
--- a/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/ILoggableInterface.h
+++ b/tests/golden_output/frozen/aidl_test_loggable_interface-ndk-source/gen/include/aidl/android/aidl/loggable/ILoggableInterface.h
@@ -14,7 +14,6 @@
 #include <vector>
 #include <android/binder_ibinder.h>
 #include <android/binder_interface_utils.h>
-#include <android/trace.h>
 #include <aidl/android/aidl/loggable/Data.h>
 #ifdef BINDER_STABILITY_SUPPORT
 #include <android/binder_stability.h>
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
index 44df565d..07c7c487 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
@@ -17,7 +17,7 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class BnTrunkStableTest : public ::android::BnInterface<ITrunkStableTest> {
+class LIBBINDER_EXPORTED BnTrunkStableTest : public ::android::BnInterface<ITrunkStableTest> {
 public:
   static constexpr uint32_t TRANSACTION_repeatParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_repeatEnum = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -46,7 +46,7 @@ public:
   static std::function<void(const TransactionLog&)> logFunc;
 };  // class BnTrunkStableTest
 
-class ITrunkStableTestDelegator : public BnTrunkStableTest {
+class LIBBINDER_EXPORTED ITrunkStableTestDelegator : public BnTrunkStableTest {
 public:
   explicit ITrunkStableTestDelegator(const ::android::sp<ITrunkStableTest> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
index 03bee513..f0e935dd 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
@@ -16,7 +16,7 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class BpTrunkStableTest : public ::android::BpInterface<ITrunkStableTest> {
+class LIBBINDER_EXPORTED BpTrunkStableTest : public ::android::BpInterface<ITrunkStableTest> {
 public:
   explicit BpTrunkStableTest(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpTrunkStableTest() = default;
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index db18c7a6..202274a0 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -33,15 +33,15 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class ITrunkStableTestDelegator;
+class LIBBINDER_EXPORTED ITrunkStableTestDelegator;
 
-class ITrunkStableTest : public ::android::IInterface {
+class LIBBINDER_EXPORTED ITrunkStableTest : public ::android::IInterface {
 public:
   typedef ITrunkStableTestDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(TrunkStableTest)
   static inline const int32_t VERSION = 1;
   static inline const std::string HASH = "88311b9118fb6fe9eff4a2ca19121de0587f6d5f";
-  class MyParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyParcelable : public ::android::Parcelable {
   public:
     int32_t a = 0;
     int32_t b = 0;
@@ -84,7 +84,7 @@ public:
     ONE = 1,
     TWO = 2,
   };
-  class MyUnion : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyUnion : public ::android::Parcelable {
   public:
     enum class Tag : int32_t {
       a = 0,
@@ -177,9 +177,9 @@ public:
   private:
     std::variant<int32_t, int32_t> _value;
   };  // class MyUnion
-  class IMyCallbackDelegator;
+  class LIBBINDER_EXPORTED IMyCallbackDelegator;
 
-  class IMyCallback : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IMyCallback : public ::android::IInterface {
   public:
     typedef IMyCallbackDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(MyCallback)
@@ -192,7 +192,7 @@ public:
     virtual std::string getInterfaceHash() = 0;
   };  // class IMyCallback
 
-  class IMyCallbackDefault : public IMyCallback {
+  class LIBBINDER_EXPORTED IMyCallbackDefault : public IMyCallback {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -213,7 +213,7 @@ public:
       return "";
     }
   };  // class IMyCallbackDefault
-  class BpMyCallback : public ::android::BpInterface<IMyCallback> {
+  class LIBBINDER_EXPORTED BpMyCallback : public ::android::BpInterface<IMyCallback> {
   public:
     explicit BpMyCallback(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpMyCallback() = default;
@@ -242,7 +242,7 @@ public:
     std::string cached_hash_ = "-1";
     std::mutex cached_hash_mutex_;
   };  // class BpMyCallback
-  class BnMyCallback : public ::android::BnInterface<IMyCallback> {
+  class LIBBINDER_EXPORTED BnMyCallback : public ::android::BnInterface<IMyCallback> {
   public:
     static constexpr uint32_t TRANSACTION_repeatParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     static constexpr uint32_t TRANSACTION_repeatEnum = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -270,7 +270,7 @@ public:
     static std::function<void(const TransactionLog&)> logFunc;
   };  // class BnMyCallback
 
-  class IMyCallbackDelegator : public BnMyCallback {
+  class LIBBINDER_EXPORTED IMyCallbackDelegator : public BnMyCallback {
   public:
     explicit IMyCallbackDelegator(const ::android::sp<IMyCallback> &impl) : _aidl_delegate(impl) {}
 
@@ -303,7 +303,7 @@ public:
   virtual std::string getInterfaceHash() = 0;
 };  // class ITrunkStableTest
 
-class ITrunkStableTestDefault : public ITrunkStableTest {
+class LIBBINDER_EXPORTED ITrunkStableTestDefault : public ITrunkStableTest {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
index eac81436..f3b2d063 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
@@ -9,13 +9,6 @@
 #include <aidl/android/aidl/test/trunk/BnTrunkStableTest.h>
 #include <aidl/android/aidl/test/trunk/BpTrunkStableTest.h>
 
-namespace {
-struct ScopedTrace {
-  inline explicit ScopedTrace(const char* name) { ATrace_beginSection(name); }
-  inline ~ScopedTrace() { ATrace_endSection(); }
-};
-}  // namespace
-
 namespace aidl {
 namespace android {
 namespace aidl {
@@ -31,7 +24,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -69,7 +61,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatEnum::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -107,7 +98,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatUnion::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -144,7 +134,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 3 /*callMyCallback*/): {
       std::shared_ptr<::aidl::android::aidl::test::trunk::ITrunkStableTest::IMyCallback> in_cb;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::callMyCallback::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_cb);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -177,7 +166,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
       int32_t _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceVersion::server");
       BnTrunkStableTest::TransactionLog _transaction_log;
       if (BnTrunkStableTest::logFunc != nullptr) {
       }
@@ -210,7 +198,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
       std::string _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceHash::server");
       BnTrunkStableTest::TransactionLog _transaction_log;
       if (BnTrunkStableTest::logFunc != nullptr) {
       }
@@ -261,21 +248,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatParcelable::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*repeatParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -321,21 +307,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatEnum::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*repeatEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -381,21 +366,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatUnion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*repeatUnion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -441,21 +425,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_cb", ::android::internal::ToString(in_cb));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::callMyCallback::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_cb);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*callMyCallback*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -501,18 +484,17 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
   if (BpTrunkStableTest::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceVersion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -564,18 +546,17 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
   if (BpTrunkStableTest::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceHash::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -840,7 +821,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -878,7 +858,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatEnum::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -916,7 +895,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatUnion::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -953,7 +931,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
     case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
       int32_t _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceVersion::server");
       ITrunkStableTest::BnMyCallback::TransactionLog _transaction_log;
       if (ITrunkStableTest::BnMyCallback::logFunc != nullptr) {
       }
@@ -986,7 +963,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
     case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
       std::string _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceHash::server");
       ITrunkStableTest::BnMyCallback::TransactionLog _transaction_log;
       if (ITrunkStableTest::BnMyCallback::logFunc != nullptr) {
       }
@@ -1037,21 +1013,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatParcelable::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*repeatParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1097,21 +1072,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatEnum::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*repeatEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1157,21 +1131,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatUnion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*repeatUnion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1221,18 +1194,17 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
   if (ITrunkStableTest::BpMyCallback::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceVersion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1284,18 +1256,17 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
   if (ITrunkStableTest::BpMyCallback::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceHash::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
index 62bd6ca3..7ab0810b 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
@@ -10,7 +10,6 @@
 #include <functional>
 #include <chrono>
 #include <sstream>
-#include <android/trace.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
index a82c477f..7f355507 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
@@ -22,7 +22,6 @@
 #include <android/binder_interface_utils.h>
 #include <android/binder_parcelable_utils.h>
 #include <android/binder_to_string.h>
-#include <android/trace.h>
 #include <aidl/android/aidl/test/trunk/ITrunkStableTest.h>
 #ifdef BINDER_STABILITY_SUPPORT
 #include <android/binder_stability.h>
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
index d2ec0731..cd894814 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
@@ -15,7 +15,7 @@ declare_binder_interface! {
       cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
       cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
     },
-    async: ITrunkStableTestAsync,
+    async: ITrunkStableTestAsync(try_into_local_async),
   }
 }
 pub trait ITrunkStableTest: binder::Interface + Send {
@@ -36,6 +36,9 @@ pub trait ITrunkStableTest: binder::Interface + Send {
   fn setDefaultImpl(d: ITrunkStableTestDefaultRef) -> ITrunkStableTestDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn ITrunkStableTestAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait ITrunkStableTestAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.test.trunk.ITrunkStableTest" }
@@ -90,10 +93,38 @@ impl BnTrunkStableTest {
       fn r#callMyCallback(&self, _arg_cb: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_11_IMyCallback>) -> binder::Result<()> {
         self._rt.block_on(self._inner.r#callMyCallback(_arg_cb))
       }
+      fn try_as_async_server(&self) -> Option<&(dyn ITrunkStableTestAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn ITrunkStableTestAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnTrunkStableTest>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for Wrapper {
+      fn r#repeatParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatParcelable(_arg_input))
+      }
+      fn r#repeatEnum<'a>(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatEnum(_arg_input))
+      }
+      fn r#repeatUnion<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatUnion(_arg_input))
+      }
+      fn r#callMyCallback<'a>(&'a self, _arg_cb: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_11_IMyCallback>) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#callMyCallback(_arg_cb))
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn ITrunkStableTestAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait ITrunkStableTestDefault: Send + Sync {
   fn r#repeatParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
@@ -548,7 +579,7 @@ pub mod r#IMyCallback {
         cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
         cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
       },
-      async: IMyCallbackAsync,
+      async: IMyCallbackAsync(try_into_local_async),
     }
   }
   pub trait IMyCallback: binder::Interface + Send {
@@ -568,6 +599,9 @@ pub mod r#IMyCallback {
     fn setDefaultImpl(d: IMyCallbackDefaultRef) -> IMyCallbackDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IMyCallbackAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IMyCallbackAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.test.trunk.ITrunkStableTest.IMyCallback" }
@@ -617,10 +651,35 @@ pub mod r#IMyCallback {
         fn r#repeatUnion(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion> {
           self._rt.block_on(self._inner.r#repeatUnion(_arg_input))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn IMyCallbackAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IMyCallbackAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnMyCallback>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IMyCallbackAsync<P> for Wrapper {
+        fn r#repeatParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatParcelable(_arg_input))
+        }
+        fn r#repeatEnum<'a>(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatEnum(_arg_input))
+        }
+        fn r#repeatUnion<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatUnion(_arg_input))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IMyCallbackAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IMyCallbackDefault: Send + Sync {
     fn r#repeatParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
index 8d0d11e7..49d043a4 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
@@ -17,7 +17,7 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class BnTrunkStableTest : public ::android::BnInterface<ITrunkStableTest> {
+class LIBBINDER_EXPORTED BnTrunkStableTest : public ::android::BnInterface<ITrunkStableTest> {
 public:
   static constexpr uint32_t TRANSACTION_repeatParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_repeatEnum = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -47,7 +47,7 @@ public:
   static std::function<void(const TransactionLog&)> logFunc;
 };  // class BnTrunkStableTest
 
-class ITrunkStableTestDelegator : public BnTrunkStableTest {
+class LIBBINDER_EXPORTED ITrunkStableTestDelegator : public BnTrunkStableTest {
 public:
   explicit ITrunkStableTestDelegator(const ::android::sp<ITrunkStableTest> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
index 023e0a70..0e6ddba7 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
@@ -16,7 +16,7 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class BpTrunkStableTest : public ::android::BpInterface<ITrunkStableTest> {
+class LIBBINDER_EXPORTED BpTrunkStableTest : public ::android::BpInterface<ITrunkStableTest> {
 public:
   explicit BpTrunkStableTest(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpTrunkStableTest() = default;
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index c7d6ed34..28a7b361 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -33,15 +33,15 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class ITrunkStableTestDelegator;
+class LIBBINDER_EXPORTED ITrunkStableTestDelegator;
 
-class ITrunkStableTest : public ::android::IInterface {
+class LIBBINDER_EXPORTED ITrunkStableTest : public ::android::IInterface {
 public:
   typedef ITrunkStableTestDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(TrunkStableTest)
   static inline const int32_t VERSION = true ? 1 : 2;
   static inline const std::string HASH = true ? "88311b9118fb6fe9eff4a2ca19121de0587f6d5f" : "notfrozen";
-  class MyParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyParcelable : public ::android::Parcelable {
   public:
     int32_t a = 0;
     int32_t b = 0;
@@ -87,7 +87,7 @@ public:
     TWO = 2,
     THREE = 3,
   };
-  class MyUnion : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyUnion : public ::android::Parcelable {
   public:
     enum class Tag : int32_t {
       a = 0,
@@ -183,7 +183,7 @@ public:
   private:
     std::variant<int32_t, int32_t, int32_t> _value;
   };  // class MyUnion
-  class MyOtherParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyOtherParcelable : public ::android::Parcelable {
   public:
     int32_t a = 0;
     int32_t b = 0;
@@ -221,9 +221,9 @@ public:
       return _aidl_os.str();
     }
   };  // class MyOtherParcelable
-  class IMyCallbackDelegator;
+  class LIBBINDER_EXPORTED IMyCallbackDelegator;
 
-  class IMyCallback : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IMyCallback : public ::android::IInterface {
   public:
     typedef IMyCallbackDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(MyCallback)
@@ -237,7 +237,7 @@ public:
     virtual std::string getInterfaceHash() = 0;
   };  // class IMyCallback
 
-  class IMyCallbackDefault : public IMyCallback {
+  class LIBBINDER_EXPORTED IMyCallbackDefault : public IMyCallback {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -261,7 +261,7 @@ public:
       return "";
     }
   };  // class IMyCallbackDefault
-  class BpMyCallback : public ::android::BpInterface<IMyCallback> {
+  class LIBBINDER_EXPORTED BpMyCallback : public ::android::BpInterface<IMyCallback> {
   public:
     explicit BpMyCallback(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpMyCallback() = default;
@@ -291,7 +291,7 @@ public:
     std::string cached_hash_ = "-1";
     std::mutex cached_hash_mutex_;
   };  // class BpMyCallback
-  class BnMyCallback : public ::android::BnInterface<IMyCallback> {
+  class LIBBINDER_EXPORTED BnMyCallback : public ::android::BnInterface<IMyCallback> {
   public:
     static constexpr uint32_t TRANSACTION_repeatParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     static constexpr uint32_t TRANSACTION_repeatEnum = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -320,7 +320,7 @@ public:
     static std::function<void(const TransactionLog&)> logFunc;
   };  // class BnMyCallback
 
-  class IMyCallbackDelegator : public BnMyCallback {
+  class LIBBINDER_EXPORTED IMyCallbackDelegator : public BnMyCallback {
   public:
     explicit IMyCallbackDelegator(const ::android::sp<IMyCallback> &impl) : _aidl_delegate(impl) {}
 
@@ -357,7 +357,7 @@ public:
   virtual std::string getInterfaceHash() = 0;
 };  // class ITrunkStableTest
 
-class ITrunkStableTestDefault : public ITrunkStableTest {
+class LIBBINDER_EXPORTED ITrunkStableTestDefault : public ITrunkStableTest {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
index d9c62d11..db2e6e5c 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
@@ -9,13 +9,6 @@
 #include <aidl/android/aidl/test/trunk/BnTrunkStableTest.h>
 #include <aidl/android/aidl/test/trunk/BpTrunkStableTest.h>
 
-namespace {
-struct ScopedTrace {
-  inline explicit ScopedTrace(const char* name) { ATrace_beginSection(name); }
-  inline ~ScopedTrace() { ATrace_endSection(); }
-};
-}  // namespace
-
 namespace aidl {
 namespace android {
 namespace aidl {
@@ -31,7 +24,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -69,7 +61,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatEnum::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -107,7 +98,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatUnion::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -144,7 +134,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 3 /*callMyCallback*/): {
       std::shared_ptr<::aidl::android::aidl::test::trunk::ITrunkStableTest::IMyCallback> in_cb;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::callMyCallback::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_cb);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -179,7 +168,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyOtherParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyOtherParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatOtherParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -216,7 +204,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
       int32_t _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceVersion::server");
       BnTrunkStableTest::TransactionLog _transaction_log;
       if (BnTrunkStableTest::logFunc != nullptr) {
       }
@@ -249,7 +236,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
       std::string _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceHash::server");
       BnTrunkStableTest::TransactionLog _transaction_log;
       if (BnTrunkStableTest::logFunc != nullptr) {
       }
@@ -300,21 +286,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatParcelable::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*repeatParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -360,21 +345,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatEnum::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*repeatEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -420,21 +404,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatUnion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*repeatUnion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -480,21 +463,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_cb", ::android::internal::ToString(in_cb));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::callMyCallback::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_cb);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*callMyCallback*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -536,25 +518,24 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatOtherParcelable::client");
   if (true) {
     _aidl_ret_status = STATUS_UNKNOWN_TRANSACTION;
     goto _aidl_error;
   }
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 4 /*repeatOtherParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -604,18 +585,17 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
   if (BpTrunkStableTest::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceVersion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -667,18 +647,17 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
   if (BpTrunkStableTest::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceHash::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -974,7 +953,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -1012,7 +990,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatEnum::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -1050,7 +1027,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatUnion::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -1089,7 +1065,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyOtherParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyOtherParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatOtherParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -1126,7 +1101,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
     case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
       int32_t _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceVersion::server");
       ITrunkStableTest::BnMyCallback::TransactionLog _transaction_log;
       if (ITrunkStableTest::BnMyCallback::logFunc != nullptr) {
       }
@@ -1159,7 +1133,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
     case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
       std::string _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceHash::server");
       ITrunkStableTest::BnMyCallback::TransactionLog _transaction_log;
       if (ITrunkStableTest::BnMyCallback::logFunc != nullptr) {
       }
@@ -1210,21 +1183,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatParcelable::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*repeatParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1270,21 +1242,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatEnum::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*repeatEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1330,21 +1301,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatUnion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*repeatUnion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1390,25 +1360,24 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatOtherParcelable::client");
   if (true) {
     _aidl_ret_status = STATUS_UNKNOWN_TRANSACTION;
     goto _aidl_error;
   }
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*repeatOtherParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1458,18 +1427,17 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
   if (ITrunkStableTest::BpMyCallback::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceVersion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1521,18 +1489,17 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
   if (ITrunkStableTest::BpMyCallback::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceHash::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
index 5d42db5e..cb202ab7 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
@@ -10,7 +10,6 @@
 #include <functional>
 #include <chrono>
 #include <sstream>
-#include <android/trace.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
index 7970009a..8487ca8a 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
@@ -22,7 +22,6 @@
 #include <android/binder_interface_utils.h>
 #include <android/binder_parcelable_utils.h>
 #include <android/binder_to_string.h>
-#include <android/trace.h>
 #include <aidl/android/aidl/test/trunk/ITrunkStableTest.h>
 #ifdef BINDER_STABILITY_SUPPORT
 #include <android/binder_stability.h>
diff --git a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
index 8e64faa7..2be351c9 100644
--- a/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
+++ b/tests/golden_output/frozen/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
@@ -15,7 +15,7 @@ declare_binder_interface! {
       cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
       cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
     },
-    async: ITrunkStableTestAsync,
+    async: ITrunkStableTestAsync(try_into_local_async),
   }
 }
 pub trait ITrunkStableTest: binder::Interface + Send {
@@ -37,6 +37,9 @@ pub trait ITrunkStableTest: binder::Interface + Send {
   fn setDefaultImpl(d: ITrunkStableTestDefaultRef) -> ITrunkStableTestDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn ITrunkStableTestAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait ITrunkStableTestAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.test.trunk.ITrunkStableTest" }
@@ -96,10 +99,41 @@ impl BnTrunkStableTest {
       fn r#repeatOtherParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable> {
         self._rt.block_on(self._inner.r#repeatOtherParcelable(_arg_input))
       }
+      fn try_as_async_server(&self) -> Option<&(dyn ITrunkStableTestAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn ITrunkStableTestAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnTrunkStableTest>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for Wrapper {
+      fn r#repeatParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatParcelable(_arg_input))
+      }
+      fn r#repeatEnum<'a>(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatEnum(_arg_input))
+      }
+      fn r#repeatUnion<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatUnion(_arg_input))
+      }
+      fn r#callMyCallback<'a>(&'a self, _arg_cb: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_11_IMyCallback>) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#callMyCallback(_arg_cb))
+      }
+      fn r#repeatOtherParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatOtherParcelable(_arg_input))
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn ITrunkStableTestAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait ITrunkStableTestDefault: Send + Sync {
   fn r#repeatParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
@@ -648,7 +682,7 @@ pub mod r#IMyCallback {
         cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
         cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
       },
-      async: IMyCallbackAsync,
+      async: IMyCallbackAsync(try_into_local_async),
     }
   }
   pub trait IMyCallback: binder::Interface + Send {
@@ -669,6 +703,9 @@ pub mod r#IMyCallback {
     fn setDefaultImpl(d: IMyCallbackDefaultRef) -> IMyCallbackDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IMyCallbackAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IMyCallbackAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.test.trunk.ITrunkStableTest.IMyCallback" }
@@ -723,10 +760,38 @@ pub mod r#IMyCallback {
         fn r#repeatOtherParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable> {
           self._rt.block_on(self._inner.r#repeatOtherParcelable(_arg_input))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn IMyCallbackAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IMyCallbackAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnMyCallback>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IMyCallbackAsync<P> for Wrapper {
+        fn r#repeatParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatParcelable(_arg_input))
+        }
+        fn r#repeatEnum<'a>(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatEnum(_arg_input))
+        }
+        fn r#repeatUnion<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatUnion(_arg_input))
+        }
+        fn r#repeatOtherParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatOtherParcelable(_arg_input))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IMyCallbackAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IMyCallbackDefault: Send + Sync {
     fn r#repeatParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
index 44df565d..07c7c487 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
@@ -17,7 +17,7 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class BnTrunkStableTest : public ::android::BnInterface<ITrunkStableTest> {
+class LIBBINDER_EXPORTED BnTrunkStableTest : public ::android::BnInterface<ITrunkStableTest> {
 public:
   static constexpr uint32_t TRANSACTION_repeatParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_repeatEnum = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -46,7 +46,7 @@ public:
   static std::function<void(const TransactionLog&)> logFunc;
 };  // class BnTrunkStableTest
 
-class ITrunkStableTestDelegator : public BnTrunkStableTest {
+class LIBBINDER_EXPORTED ITrunkStableTestDelegator : public BnTrunkStableTest {
 public:
   explicit ITrunkStableTestDelegator(const ::android::sp<ITrunkStableTest> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
index 03bee513..f0e935dd 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
@@ -16,7 +16,7 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class BpTrunkStableTest : public ::android::BpInterface<ITrunkStableTest> {
+class LIBBINDER_EXPORTED BpTrunkStableTest : public ::android::BpInterface<ITrunkStableTest> {
 public:
   explicit BpTrunkStableTest(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpTrunkStableTest() = default;
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index db18c7a6..202274a0 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -33,15 +33,15 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class ITrunkStableTestDelegator;
+class LIBBINDER_EXPORTED ITrunkStableTestDelegator;
 
-class ITrunkStableTest : public ::android::IInterface {
+class LIBBINDER_EXPORTED ITrunkStableTest : public ::android::IInterface {
 public:
   typedef ITrunkStableTestDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(TrunkStableTest)
   static inline const int32_t VERSION = 1;
   static inline const std::string HASH = "88311b9118fb6fe9eff4a2ca19121de0587f6d5f";
-  class MyParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyParcelable : public ::android::Parcelable {
   public:
     int32_t a = 0;
     int32_t b = 0;
@@ -84,7 +84,7 @@ public:
     ONE = 1,
     TWO = 2,
   };
-  class MyUnion : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyUnion : public ::android::Parcelable {
   public:
     enum class Tag : int32_t {
       a = 0,
@@ -177,9 +177,9 @@ public:
   private:
     std::variant<int32_t, int32_t> _value;
   };  // class MyUnion
-  class IMyCallbackDelegator;
+  class LIBBINDER_EXPORTED IMyCallbackDelegator;
 
-  class IMyCallback : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IMyCallback : public ::android::IInterface {
   public:
     typedef IMyCallbackDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(MyCallback)
@@ -192,7 +192,7 @@ public:
     virtual std::string getInterfaceHash() = 0;
   };  // class IMyCallback
 
-  class IMyCallbackDefault : public IMyCallback {
+  class LIBBINDER_EXPORTED IMyCallbackDefault : public IMyCallback {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -213,7 +213,7 @@ public:
       return "";
     }
   };  // class IMyCallbackDefault
-  class BpMyCallback : public ::android::BpInterface<IMyCallback> {
+  class LIBBINDER_EXPORTED BpMyCallback : public ::android::BpInterface<IMyCallback> {
   public:
     explicit BpMyCallback(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpMyCallback() = default;
@@ -242,7 +242,7 @@ public:
     std::string cached_hash_ = "-1";
     std::mutex cached_hash_mutex_;
   };  // class BpMyCallback
-  class BnMyCallback : public ::android::BnInterface<IMyCallback> {
+  class LIBBINDER_EXPORTED BnMyCallback : public ::android::BnInterface<IMyCallback> {
   public:
     static constexpr uint32_t TRANSACTION_repeatParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     static constexpr uint32_t TRANSACTION_repeatEnum = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -270,7 +270,7 @@ public:
     static std::function<void(const TransactionLog&)> logFunc;
   };  // class BnMyCallback
 
-  class IMyCallbackDelegator : public BnMyCallback {
+  class LIBBINDER_EXPORTED IMyCallbackDelegator : public BnMyCallback {
   public:
     explicit IMyCallbackDelegator(const ::android::sp<IMyCallback> &impl) : _aidl_delegate(impl) {}
 
@@ -303,7 +303,7 @@ public:
   virtual std::string getInterfaceHash() = 0;
 };  // class ITrunkStableTest
 
-class ITrunkStableTestDefault : public ITrunkStableTest {
+class LIBBINDER_EXPORTED ITrunkStableTestDefault : public ITrunkStableTest {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
index eac81436..f3b2d063 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
@@ -9,13 +9,6 @@
 #include <aidl/android/aidl/test/trunk/BnTrunkStableTest.h>
 #include <aidl/android/aidl/test/trunk/BpTrunkStableTest.h>
 
-namespace {
-struct ScopedTrace {
-  inline explicit ScopedTrace(const char* name) { ATrace_beginSection(name); }
-  inline ~ScopedTrace() { ATrace_endSection(); }
-};
-}  // namespace
-
 namespace aidl {
 namespace android {
 namespace aidl {
@@ -31,7 +24,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -69,7 +61,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatEnum::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -107,7 +98,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatUnion::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -144,7 +134,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 3 /*callMyCallback*/): {
       std::shared_ptr<::aidl::android::aidl::test::trunk::ITrunkStableTest::IMyCallback> in_cb;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::callMyCallback::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_cb);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -177,7 +166,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
       int32_t _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceVersion::server");
       BnTrunkStableTest::TransactionLog _transaction_log;
       if (BnTrunkStableTest::logFunc != nullptr) {
       }
@@ -210,7 +198,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
       std::string _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceHash::server");
       BnTrunkStableTest::TransactionLog _transaction_log;
       if (BnTrunkStableTest::logFunc != nullptr) {
       }
@@ -261,21 +248,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatParcelable::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*repeatParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -321,21 +307,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatEnum::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*repeatEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -381,21 +366,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatUnion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*repeatUnion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -441,21 +425,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_cb", ::android::internal::ToString(in_cb));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::callMyCallback::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_cb);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*callMyCallback*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -501,18 +484,17 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
   if (BpTrunkStableTest::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceVersion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -564,18 +546,17 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
   if (BpTrunkStableTest::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceHash::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -840,7 +821,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -878,7 +858,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatEnum::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -916,7 +895,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatUnion::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -953,7 +931,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
     case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
       int32_t _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceVersion::server");
       ITrunkStableTest::BnMyCallback::TransactionLog _transaction_log;
       if (ITrunkStableTest::BnMyCallback::logFunc != nullptr) {
       }
@@ -986,7 +963,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
     case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
       std::string _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceHash::server");
       ITrunkStableTest::BnMyCallback::TransactionLog _transaction_log;
       if (ITrunkStableTest::BnMyCallback::logFunc != nullptr) {
       }
@@ -1037,21 +1013,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatParcelable::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*repeatParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1097,21 +1072,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatEnum::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*repeatEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1157,21 +1131,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatUnion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*repeatUnion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1221,18 +1194,17 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
   if (ITrunkStableTest::BpMyCallback::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceVersion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1284,18 +1256,17 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
   if (ITrunkStableTest::BpMyCallback::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceHash::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
index 62bd6ca3..7ab0810b 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
@@ -10,7 +10,6 @@
 #include <functional>
 #include <chrono>
 #include <sstream>
-#include <android/trace.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
index a82c477f..7f355507 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
@@ -22,7 +22,6 @@
 #include <android/binder_interface_utils.h>
 #include <android/binder_parcelable_utils.h>
 #include <android/binder_to_string.h>
-#include <android/trace.h>
 #include <aidl/android/aidl/test/trunk/ITrunkStableTest.h>
 #ifdef BINDER_STABILITY_SUPPORT
 #include <android/binder_stability.h>
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
index d2ec0731..cd894814 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V1-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
@@ -15,7 +15,7 @@ declare_binder_interface! {
       cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
       cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
     },
-    async: ITrunkStableTestAsync,
+    async: ITrunkStableTestAsync(try_into_local_async),
   }
 }
 pub trait ITrunkStableTest: binder::Interface + Send {
@@ -36,6 +36,9 @@ pub trait ITrunkStableTest: binder::Interface + Send {
   fn setDefaultImpl(d: ITrunkStableTestDefaultRef) -> ITrunkStableTestDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn ITrunkStableTestAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait ITrunkStableTestAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.test.trunk.ITrunkStableTest" }
@@ -90,10 +93,38 @@ impl BnTrunkStableTest {
       fn r#callMyCallback(&self, _arg_cb: &binder::Strong<dyn crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_11_IMyCallback>) -> binder::Result<()> {
         self._rt.block_on(self._inner.r#callMyCallback(_arg_cb))
       }
+      fn try_as_async_server(&self) -> Option<&(dyn ITrunkStableTestAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn ITrunkStableTestAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnTrunkStableTest>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for Wrapper {
+      fn r#repeatParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatParcelable(_arg_input))
+      }
+      fn r#repeatEnum<'a>(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatEnum(_arg_input))
+      }
+      fn r#repeatUnion<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatUnion(_arg_input))
+      }
+      fn r#callMyCallback<'a>(&'a self, _arg_cb: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_11_IMyCallback>) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#callMyCallback(_arg_cb))
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn ITrunkStableTestAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait ITrunkStableTestDefault: Send + Sync {
   fn r#repeatParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
@@ -548,7 +579,7 @@ pub mod r#IMyCallback {
         cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
         cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
       },
-      async: IMyCallbackAsync,
+      async: IMyCallbackAsync(try_into_local_async),
     }
   }
   pub trait IMyCallback: binder::Interface + Send {
@@ -568,6 +599,9 @@ pub mod r#IMyCallback {
     fn setDefaultImpl(d: IMyCallbackDefaultRef) -> IMyCallbackDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IMyCallbackAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IMyCallbackAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.test.trunk.ITrunkStableTest.IMyCallback" }
@@ -617,10 +651,35 @@ pub mod r#IMyCallback {
         fn r#repeatUnion(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion> {
           self._rt.block_on(self._inner.r#repeatUnion(_arg_input))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn IMyCallbackAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IMyCallbackAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnMyCallback>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IMyCallbackAsync<P> for Wrapper {
+        fn r#repeatParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatParcelable(_arg_input))
+        }
+        fn r#repeatEnum<'a>(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatEnum(_arg_input))
+        }
+        fn r#repeatUnion<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatUnion(_arg_input))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IMyCallbackAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IMyCallbackDefault: Send + Sync {
     fn r#repeatParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
index 5e929de1..fe2567ae 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BnTrunkStableTest.h
@@ -17,7 +17,7 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class BnTrunkStableTest : public ::android::BnInterface<ITrunkStableTest> {
+class LIBBINDER_EXPORTED BnTrunkStableTest : public ::android::BnInterface<ITrunkStableTest> {
 public:
   static constexpr uint32_t TRANSACTION_repeatParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
   static constexpr uint32_t TRANSACTION_repeatEnum = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -47,7 +47,7 @@ public:
   static std::function<void(const TransactionLog&)> logFunc;
 };  // class BnTrunkStableTest
 
-class ITrunkStableTestDelegator : public BnTrunkStableTest {
+class LIBBINDER_EXPORTED ITrunkStableTestDelegator : public BnTrunkStableTest {
 public:
   explicit ITrunkStableTestDelegator(const ::android::sp<ITrunkStableTest> &impl) : _aidl_delegate(impl) {}
 
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
index bd3c966a..26767dd6 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/BpTrunkStableTest.h
@@ -16,7 +16,7 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class BpTrunkStableTest : public ::android::BpInterface<ITrunkStableTest> {
+class LIBBINDER_EXPORTED BpTrunkStableTest : public ::android::BpInterface<ITrunkStableTest> {
 public:
   explicit BpTrunkStableTest(const ::android::sp<::android::IBinder>& _aidl_impl);
   virtual ~BpTrunkStableTest() = default;
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
index 1d585cd7..e0d77f64 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-cpp-source/gen/include/android/aidl/test/trunk/ITrunkStableTest.h
@@ -33,15 +33,15 @@ namespace android {
 namespace aidl {
 namespace test {
 namespace trunk {
-class ITrunkStableTestDelegator;
+class LIBBINDER_EXPORTED ITrunkStableTestDelegator;
 
-class ITrunkStableTest : public ::android::IInterface {
+class LIBBINDER_EXPORTED ITrunkStableTest : public ::android::IInterface {
 public:
   typedef ITrunkStableTestDelegator DefaultDelegator;
   DECLARE_META_INTERFACE(TrunkStableTest)
   static inline const int32_t VERSION = 2;
   static inline const std::string HASH = "notfrozen";
-  class MyParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyParcelable : public ::android::Parcelable {
   public:
     int32_t a = 0;
     int32_t b = 0;
@@ -87,7 +87,7 @@ public:
     TWO = 2,
     THREE = 3,
   };
-  class MyUnion : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyUnion : public ::android::Parcelable {
   public:
     enum class Tag : int32_t {
       a = 0,
@@ -183,7 +183,7 @@ public:
   private:
     std::variant<int32_t, int32_t, int32_t> _value;
   };  // class MyUnion
-  class MyOtherParcelable : public ::android::Parcelable {
+  class LIBBINDER_EXPORTED MyOtherParcelable : public ::android::Parcelable {
   public:
     int32_t a = 0;
     int32_t b = 0;
@@ -221,9 +221,9 @@ public:
       return _aidl_os.str();
     }
   };  // class MyOtherParcelable
-  class IMyCallbackDelegator;
+  class LIBBINDER_EXPORTED IMyCallbackDelegator;
 
-  class IMyCallback : public ::android::IInterface {
+  class LIBBINDER_EXPORTED IMyCallback : public ::android::IInterface {
   public:
     typedef IMyCallbackDelegator DefaultDelegator;
     DECLARE_META_INTERFACE(MyCallback)
@@ -237,7 +237,7 @@ public:
     virtual std::string getInterfaceHash() = 0;
   };  // class IMyCallback
 
-  class IMyCallbackDefault : public IMyCallback {
+  class LIBBINDER_EXPORTED IMyCallbackDefault : public IMyCallback {
   public:
     ::android::IBinder* onAsBinder() override {
       return nullptr;
@@ -261,7 +261,7 @@ public:
       return "";
     }
   };  // class IMyCallbackDefault
-  class BpMyCallback : public ::android::BpInterface<IMyCallback> {
+  class LIBBINDER_EXPORTED BpMyCallback : public ::android::BpInterface<IMyCallback> {
   public:
     explicit BpMyCallback(const ::android::sp<::android::IBinder>& _aidl_impl);
     virtual ~BpMyCallback() = default;
@@ -291,7 +291,7 @@ public:
     std::string cached_hash_ = "-1";
     std::mutex cached_hash_mutex_;
   };  // class BpMyCallback
-  class BnMyCallback : public ::android::BnInterface<IMyCallback> {
+  class LIBBINDER_EXPORTED BnMyCallback : public ::android::BnInterface<IMyCallback> {
   public:
     static constexpr uint32_t TRANSACTION_repeatParcelable = ::android::IBinder::FIRST_CALL_TRANSACTION + 0;
     static constexpr uint32_t TRANSACTION_repeatEnum = ::android::IBinder::FIRST_CALL_TRANSACTION + 1;
@@ -320,7 +320,7 @@ public:
     static std::function<void(const TransactionLog&)> logFunc;
   };  // class BnMyCallback
 
-  class IMyCallbackDelegator : public BnMyCallback {
+  class LIBBINDER_EXPORTED IMyCallbackDelegator : public BnMyCallback {
   public:
     explicit IMyCallbackDelegator(const ::android::sp<IMyCallback> &impl) : _aidl_delegate(impl) {}
 
@@ -357,7 +357,7 @@ public:
   virtual std::string getInterfaceHash() = 0;
 };  // class ITrunkStableTest
 
-class ITrunkStableTestDefault : public ITrunkStableTest {
+class LIBBINDER_EXPORTED ITrunkStableTestDefault : public ITrunkStableTest {
 public:
   ::android::IBinder* onAsBinder() override {
     return nullptr;
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
index 5ee4b25a..8db1fc89 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/android/aidl/test/trunk/ITrunkStableTest.cpp
@@ -9,13 +9,6 @@
 #include <aidl/android/aidl/test/trunk/BnTrunkStableTest.h>
 #include <aidl/android/aidl/test/trunk/BpTrunkStableTest.h>
 
-namespace {
-struct ScopedTrace {
-  inline explicit ScopedTrace(const char* name) { ATrace_beginSection(name); }
-  inline ~ScopedTrace() { ATrace_endSection(); }
-};
-}  // namespace
-
 namespace aidl {
 namespace android {
 namespace aidl {
@@ -31,7 +24,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -69,7 +61,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatEnum::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -107,7 +98,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatUnion::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -144,7 +134,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 3 /*callMyCallback*/): {
       std::shared_ptr<::aidl::android::aidl::test::trunk::ITrunkStableTest::IMyCallback> in_cb;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::callMyCallback::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_cb);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -178,7 +167,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyOtherParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyOtherParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatOtherParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -215,7 +203,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
       int32_t _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceVersion::server");
       BnTrunkStableTest::TransactionLog _transaction_log;
       if (BnTrunkStableTest::logFunc != nullptr) {
       }
@@ -248,7 +235,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_onTransact
     case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
       std::string _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceHash::server");
       BnTrunkStableTest::TransactionLog _transaction_log;
       if (BnTrunkStableTest::logFunc != nullptr) {
       }
@@ -299,21 +285,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatParcelable::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*repeatParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -359,21 +344,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatEnum::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*repeatEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -419,21 +403,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatUnion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*repeatUnion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -479,21 +462,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_cb", ::android::internal::ToString(in_cb));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::callMyCallback::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_cb);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*callMyCallback*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -535,21 +517,20 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::repeatOtherParcelable::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 4 /*repeatOtherParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -599,18 +580,17 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
   if (BpTrunkStableTest::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceVersion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -662,18 +642,17 @@ std::function<void(const BpTrunkStableTest::TransactionLog&)> BpTrunkStableTest:
   if (BpTrunkStableTest::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::ITrunkStableTest::getInterfaceHash::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && ITrunkStableTest::getDefaultImpl()) {
@@ -964,7 +943,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -1002,7 +980,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyEnum _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatEnum::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -1040,7 +1017,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyUnion _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatUnion::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -1078,7 +1054,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyOtherParcelable in_input;
       ::aidl::android::aidl::test::trunk::ITrunkStableTest::MyOtherParcelable _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatOtherParcelable::server");
       _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_input);
       if (_aidl_ret_status != STATUS_OK) break;
 
@@ -1115,7 +1090,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
     case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
       int32_t _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceVersion::server");
       ITrunkStableTest::BnMyCallback::TransactionLog _transaction_log;
       if (ITrunkStableTest::BnMyCallback::logFunc != nullptr) {
       }
@@ -1148,7 +1122,6 @@ static binder_status_t _aidl_android_aidl_test_trunk_ITrunkStableTest_IMyCallbac
     case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
       std::string _aidl_return;
 
-      ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceHash::server");
       ITrunkStableTest::BnMyCallback::TransactionLog _transaction_log;
       if (ITrunkStableTest::BnMyCallback::logFunc != nullptr) {
       }
@@ -1199,21 +1172,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatParcelable::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 0 /*repeatParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1259,21 +1231,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatEnum::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 1 /*repeatEnum*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1319,21 +1290,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatUnion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 2 /*repeatUnion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1379,21 +1349,20 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
     _transaction_log.input_args.emplace_back("in_input", ::android::internal::ToString(in_input));
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::repeatOtherParcelable::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_input);
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 3 /*repeatOtherParcelable*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1443,18 +1412,17 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
   if (ITrunkStableTest::BpMyCallback::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceVersion::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
@@ -1506,18 +1474,17 @@ std::function<void(const ITrunkStableTest::BpMyCallback::TransactionLog&)> ITrun
   if (ITrunkStableTest::BpMyCallback::logFunc != nullptr) {
   }
   auto _log_start = std::chrono::steady_clock::now();
-  ScopedTrace _aidl_trace("AIDL::ndk::IMyCallback::getInterfaceHash::client");
-  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
+  _aidl_ret_status = AIBinder_prepareTransaction(asBinderReference().get(), _aidl_in.getR());
   if (_aidl_ret_status != STATUS_OK) goto _aidl_error;
 
   _aidl_ret_status = AIBinder_transact(
-    asBinder().get(),
+    asBinderReference().get(),
     (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
     _aidl_in.getR(),
     _aidl_out.getR(),
     0
     #ifdef BINDER_STABILITY_SUPPORT
-    | FLAG_PRIVATE_LOCAL
+    | static_cast<int>(FLAG_PRIVATE_LOCAL)
     #endif  // BINDER_STABILITY_SUPPORT
     );
   if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IMyCallback::getDefaultImpl()) {
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
index 5403f995..369287aa 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/BpTrunkStableTest.h
@@ -10,7 +10,6 @@
 #include <functional>
 #include <chrono>
 #include <sstream>
-#include <android/trace.h>
 
 namespace aidl {
 namespace android {
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
index ba5f4004..d7e19a11 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-ndk-source/gen/include/aidl/android/aidl/test/trunk/ITrunkStableTest.h
@@ -22,7 +22,6 @@
 #include <android/binder_interface_utils.h>
 #include <android/binder_parcelable_utils.h>
 #include <android/binder_to_string.h>
-#include <android/trace.h>
 #include <aidl/android/aidl/test/trunk/ITrunkStableTest.h>
 #ifdef BINDER_STABILITY_SUPPORT
 #include <android/binder_stability.h>
diff --git a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
index 6d52d7f1..cdf83e67 100644
--- a/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
+++ b/tests/golden_output/tests/trunk_stable_test/android.aidl.test.trunk-V2-rust-source/gen/android/aidl/test/trunk/ITrunkStableTest.rs
@@ -15,7 +15,7 @@ declare_binder_interface! {
       cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
       cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
     },
-    async: ITrunkStableTestAsync,
+    async: ITrunkStableTestAsync(try_into_local_async),
   }
 }
 pub trait ITrunkStableTest: binder::Interface + Send {
@@ -37,6 +37,9 @@ pub trait ITrunkStableTest: binder::Interface + Send {
   fn setDefaultImpl(d: ITrunkStableTestDefaultRef) -> ITrunkStableTestDefaultRef where Self: Sized {
     std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
   }
+  fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn ITrunkStableTestAsyncServer + Send + Sync)> {
+    None
+  }
 }
 pub trait ITrunkStableTestAsync<P>: binder::Interface + Send {
   fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.test.trunk.ITrunkStableTest" }
@@ -96,10 +99,41 @@ impl BnTrunkStableTest {
       fn r#repeatOtherParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable> {
         self._rt.block_on(self._inner.r#repeatOtherParcelable(_arg_input))
       }
+      fn try_as_async_server(&self) -> Option<&(dyn ITrunkStableTestAsyncServer + Send + Sync)> {
+        Some(&self._inner)
+      }
     }
     let wrapped = Wrapper { _inner: inner, _rt: rt };
     Self::new_binder(wrapped, features)
   }
+  pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn ITrunkStableTestAsync<P>>> {
+    struct Wrapper {
+      _native: binder::binder_impl::Binder<BnTrunkStableTest>
+    }
+    impl binder::Interface for Wrapper {}
+    impl<P: binder::BinderAsyncPool> ITrunkStableTestAsync<P> for Wrapper {
+      fn r#repeatParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatParcelable(_arg_input))
+      }
+      fn r#repeatEnum<'a>(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatEnum(_arg_input))
+      }
+      fn r#repeatUnion<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatUnion(_arg_input))
+      }
+      fn r#callMyCallback<'a>(&'a self, _arg_cb: &'a binder::Strong<dyn crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_11_IMyCallback>) -> binder::BoxFuture<'a, binder::Result<()>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#callMyCallback(_arg_cb))
+      }
+      fn r#repeatOtherParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable>> {
+        Box::pin(self._native.try_as_async_server().unwrap().r#repeatOtherParcelable(_arg_input))
+      }
+    }
+    if _native.try_as_async_server().is_some() {
+      Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn ITrunkStableTestAsync<P>>))
+    } else {
+      None
+    }
+  }
 }
 pub trait ITrunkStableTestDefault: Send + Sync {
   fn r#repeatParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
@@ -624,7 +658,7 @@ pub mod r#IMyCallback {
         cached_version: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1),
         cached_hash: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None)
       },
-      async: IMyCallbackAsync,
+      async: IMyCallbackAsync(try_into_local_async),
     }
   }
   pub trait IMyCallback: binder::Interface + Send {
@@ -645,6 +679,9 @@ pub mod r#IMyCallback {
     fn setDefaultImpl(d: IMyCallbackDefaultRef) -> IMyCallbackDefaultRef where Self: Sized {
       std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
     }
+    fn try_as_async_server<'a>(&'a self) -> Option<&'a (dyn IMyCallbackAsyncServer + Send + Sync)> {
+      None
+    }
   }
   pub trait IMyCallbackAsync<P>: binder::Interface + Send {
     fn get_descriptor() -> &'static str where Self: Sized { "android.aidl.test.trunk.ITrunkStableTest.IMyCallback" }
@@ -699,10 +736,38 @@ pub mod r#IMyCallback {
         fn r#repeatOtherParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable> {
           self._rt.block_on(self._inner.r#repeatOtherParcelable(_arg_input))
         }
+        fn try_as_async_server(&self) -> Option<&(dyn IMyCallbackAsyncServer + Send + Sync)> {
+          Some(&self._inner)
+        }
       }
       let wrapped = Wrapper { _inner: inner, _rt: rt };
       Self::new_binder(wrapped, features)
     }
+    pub fn try_into_local_async<P: binder::BinderAsyncPool + 'static>(_native: binder::binder_impl::Binder<Self>) -> Option<binder::Strong<dyn IMyCallbackAsync<P>>> {
+      struct Wrapper {
+        _native: binder::binder_impl::Binder<BnMyCallback>
+      }
+      impl binder::Interface for Wrapper {}
+      impl<P: binder::BinderAsyncPool> IMyCallbackAsync<P> for Wrapper {
+        fn r#repeatParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatParcelable(_arg_input))
+        }
+        fn r#repeatEnum<'a>(&'a self, _arg_input: crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_6_MyEnum>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatEnum(_arg_input))
+        }
+        fn r#repeatUnion<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_7_MyUnion>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatUnion(_arg_input))
+        }
+        fn r#repeatOtherParcelable<'a>(&'a self, _arg_input: &'a crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable) -> binder::BoxFuture<'a, binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_17_MyOtherParcelable>> {
+          Box::pin(self._native.try_as_async_server().unwrap().r#repeatOtherParcelable(_arg_input))
+        }
+      }
+      if _native.try_as_async_server().is_some() {
+        Some(binder::Strong::new(Box::new(Wrapper { _native }) as Box<dyn IMyCallbackAsync<P>>))
+      } else {
+        None
+      }
+    }
   }
   pub trait IMyCallbackDefault: Send + Sync {
     fn r#repeatParcelable(&self, _arg_input: &crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable) -> binder::Result<crate::mangled::_7_android_4_aidl_4_test_5_trunk_16_ITrunkStableTest_12_MyParcelable> {
```

