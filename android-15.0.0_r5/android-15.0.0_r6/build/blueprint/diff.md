```diff
diff --git a/Android.bp b/Android.bp
index ee0ede0075..04d75fb22a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,5 +1,9 @@
 package {
     default_applicable_licenses: ["build_blueprint_license"],
+    default_visibility: [
+        "//build/blueprint:__subpackages__",
+        "//build/soong:__subpackages__",
+    ],
 }
 
 // Added automatically by a large-scale-change that took the approach of
@@ -39,6 +43,7 @@ bootstrap_go_package {
     pkgPath: "github.com/google/blueprint",
     srcs: [
         "context.go",
+        "incremental.go",
         "levenshtein.go",
         "glob.go",
         "live_tracker.go",
@@ -67,6 +72,10 @@ bootstrap_go_package {
         "transition_test.go",
         "visit_test.go",
     ],
+    visibility: [
+        // used by plugins
+        "//visibility:public",
+    ],
 }
 
 bootstrap_go_package {
@@ -85,12 +94,24 @@ bootstrap_go_package {
         "parser/printer_test.go",
         "parser/sort_test.go",
     ],
+    visibility: [
+        "//build/blueprint:__subpackages__",
+        "//build/soong:__subpackages__",
+        "//development/vndk/tools/elfcheck",
+        "//tools/security/fuzzing/fuzzer_parser",
+        "//vendor:__subpackages__",
+    ],
 }
 
 bootstrap_go_package {
     name: "blueprint-deptools",
     pkgPath: "github.com/google/blueprint/deptools",
     srcs: ["deptools/depfile.go"],
+    visibility: [
+        "//build/blueprint:__subpackages__",
+        "//build/make/tools/compliance",
+        "//build/soong:__subpackages__",
+    ],
 }
 
 bootstrap_go_package {
@@ -109,6 +130,10 @@ bootstrap_go_package {
         "pathtools/glob_test.go",
         "pathtools/lists_test.go",
     ],
+    visibility: [
+        // used by plugins
+        "//visibility:public",
+    ],
 }
 
 bootstrap_go_package {
@@ -133,6 +158,7 @@ bootstrap_go_package {
     ],
     testSrcs: [
         "proptools/clone_test.go",
+        "proptools/configurable_test.go",
         "proptools/escape_test.go",
         "proptools/extend_test.go",
         "proptools/filter_test.go",
@@ -141,6 +167,10 @@ bootstrap_go_package {
         "proptools/typeequal_test.go",
         "proptools/unpack_test.go",
     ],
+    visibility: [
+        // used by plugins
+        "//visibility:public",
+    ],
 }
 
 bootstrap_go_package {
@@ -164,7 +194,6 @@ bootstrap_go_package {
         "bootstrap/bootstrap.go",
         "bootstrap/command.go",
         "bootstrap/config.go",
-        "bootstrap/glob.go",
         "bootstrap/writedocs.go",
     ],
 }
@@ -188,16 +217,13 @@ bootstrap_go_package {
     ],
 }
 
-blueprint_go_binary {
-    name: "bpglob",
-    deps: ["blueprint-pathtools"],
-    srcs: ["bootstrap/bpglob/bpglob.go"],
-}
-
 blueprint_go_binary {
     name: "bpfmt",
     deps: ["blueprint-parser"],
     srcs: ["bpfmt/bpfmt.go"],
+    visibility: [
+        "//tools/external_updater",
+    ],
 }
 
 blueprint_go_binary {
diff --git a/bootstrap/bootstrap.go b/bootstrap/bootstrap.go
index 9872dbbaae..73c8f8bb93 100644
--- a/bootstrap/bootstrap.go
+++ b/bootstrap/bootstrap.go
@@ -97,14 +97,6 @@ var (
 		},
 		"generator")
 
-	bootstrap = pctx.StaticRule("bootstrap",
-		blueprint.RuleParams{
-			Command:     "BUILDDIR=$soongOutDir $bootstrapCmd -i $in",
-			CommandDeps: []string{"$bootstrapCmd"},
-			Description: "bootstrap $in",
-			Generator:   true,
-		})
-
 	touch = pctx.StaticRule("touch",
 		blueprint.RuleParams{
 			Command:     "touch $out",
@@ -149,58 +141,45 @@ var (
 	})
 )
 
-type GoBinaryTool interface {
-	InstallPath() string
+type pluginDependencyTag struct {
+	blueprint.BaseDependencyTag
+}
 
-	// So that other packages can't implement this interface
-	isGoBinary()
+type bootstrapDependencies interface {
+	bootstrapDeps(ctx blueprint.BottomUpMutatorContext)
 }
 
-func pluginDeps(ctx blueprint.BottomUpMutatorContext) {
-	if pkg, ok := ctx.Module().(*GoPackage); ok {
-		if ctx.PrimaryModule() == ctx.Module() {
-			for _, plugin := range pkg.properties.PluginFor {
-				ctx.AddReverseDependency(ctx.Module(), nil, plugin)
-			}
-		}
+var pluginDepTag = pluginDependencyTag{}
+
+func BootstrapDeps(ctx blueprint.BottomUpMutatorContext) {
+	if pkg, ok := ctx.Module().(bootstrapDependencies); ok {
+		pkg.bootstrapDeps(ctx)
 	}
 }
 
-type goPackageProducer interface {
-	GoPkgRoot() string
-	GoPackageTarget() string
-	GoTestTargets() []string
+type PackageInfo struct {
+	PkgPath       string
+	PkgRoot       string
+	PackageTarget string
+	TestTargets   []string
 }
 
-func isGoPackageProducer(module blueprint.Module) bool {
-	_, ok := module.(goPackageProducer)
-	return ok
-}
+var PackageProvider = blueprint.NewProvider[*PackageInfo]()
 
-type goPluginProvider interface {
-	GoPkgPath() string
-	IsPluginFor(string) bool
+type BinaryInfo struct {
+	IntermediatePath string
+	InstallPath      string
+	TestTargets      []string
 }
 
-func isGoPluginFor(name string) func(blueprint.Module) bool {
-	return func(module blueprint.Module) bool {
-		if plugin, ok := module.(goPluginProvider); ok {
-			return plugin.IsPluginFor(name)
-		}
-		return false
-	}
-}
+var BinaryProvider = blueprint.NewProvider[*BinaryInfo]()
 
-func IsBootstrapModule(module blueprint.Module) bool {
-	_, isPackage := module.(*GoPackage)
-	_, isBinary := module.(*GoBinary)
-	return isPackage || isBinary
+type DocsPackageInfo struct {
+	PkgPath string
+	Srcs    []string
 }
 
-func isBootstrapBinaryModule(module blueprint.Module) bool {
-	_, isBinary := module.(*GoBinary)
-	return isBinary
-}
+var DocsPackageProvider = blueprint.NewMutatorProvider[*DocsPackageInfo]("bootstrap_deps")
 
 // A GoPackage is a module for building Go packages.
 type GoPackage struct {
@@ -213,6 +192,9 @@ type GoPackage struct {
 		TestData  []string
 		PluginFor []string
 		EmbedSrcs []string
+		// The visibility property is unused in blueprint, but exists so that soong
+		// can add one and not have the bp files fail to parse during the bootstrap build.
+		Visibility []string
 
 		Darwin struct {
 			Srcs     []string
@@ -223,20 +205,8 @@ type GoPackage struct {
 			TestSrcs []string
 		}
 	}
-
-	// The root dir in which the package .a file is located.  The full .a file
-	// path will be "packageRoot/PkgPath.a"
-	pkgRoot string
-
-	// The path of the .a file that is to be built.
-	archiveFile string
-
-	// The path of the test result file.
-	testResultFile []string
 }
 
-var _ goPackageProducer = (*GoPackage)(nil)
-
 func newGoPackageModuleFactory() func() (blueprint.Module, []interface{}) {
 	return func() (blueprint.Module, []interface{}) {
 		module := &GoPackage{}
@@ -244,6 +214,11 @@ func newGoPackageModuleFactory() func() (blueprint.Module, []interface{}) {
 	}
 }
 
+// Properties returns the list of property structs to be used for registering a wrapped module type.
+func (g *GoPackage) Properties() []interface{} {
+	return []interface{}{&g.properties}
+}
+
 func (g *GoPackage) DynamicDependencies(ctx blueprint.DynamicDependerModuleContext) []string {
 	if ctx.Module() != ctx.PrimaryModule() {
 		return nil
@@ -251,39 +226,25 @@ func (g *GoPackage) DynamicDependencies(ctx blueprint.DynamicDependerModuleConte
 	return g.properties.Deps
 }
 
-func (g *GoPackage) GoPkgPath() string {
-	return g.properties.PkgPath
-}
-
-func (g *GoPackage) GoPkgRoot() string {
-	return g.pkgRoot
-}
-
-func (g *GoPackage) GoPackageTarget() string {
-	return g.archiveFile
-}
-
-func (g *GoPackage) GoTestTargets() []string {
-	return g.testResultFile
-}
-
-func (g *GoPackage) IsPluginFor(name string) bool {
-	for _, plugin := range g.properties.PluginFor {
-		if plugin == name {
-			return true
+func (g *GoPackage) bootstrapDeps(ctx blueprint.BottomUpMutatorContext) {
+	if ctx.PrimaryModule() == ctx.Module() {
+		for _, plugin := range g.properties.PluginFor {
+			ctx.AddReverseDependency(ctx.Module(), pluginDepTag, plugin)
 		}
+		blueprint.SetProvider(ctx, DocsPackageProvider, &DocsPackageInfo{
+			PkgPath: g.properties.PkgPath,
+			Srcs:    g.properties.Srcs,
+		})
 	}
-	return false
 }
 
 func (g *GoPackage) GenerateBuildActions(ctx blueprint.ModuleContext) {
 	// Allow the primary builder to create multiple variants.  Any variants after the first
 	// will copy outputs from the first.
 	if ctx.Module() != ctx.PrimaryModule() {
-		primary := ctx.PrimaryModule().(*GoPackage)
-		g.pkgRoot = primary.pkgRoot
-		g.archiveFile = primary.archiveFile
-		g.testResultFile = primary.testResultFile
+		if info, ok := blueprint.OtherModuleProvider(ctx, ctx.PrimaryModule(), PackageProvider); ok {
+			blueprint.SetProvider(ctx, PackageProvider, info)
+		}
 		return
 	}
 
@@ -299,12 +260,15 @@ func (g *GoPackage) GenerateBuildActions(ctx blueprint.ModuleContext) {
 		return
 	}
 
-	g.pkgRoot = packageRoot(ctx)
-	g.archiveFile = filepath.Join(g.pkgRoot,
+	pkgRoot := packageRoot(ctx)
+	archiveFile := filepath.Join(pkgRoot,
 		filepath.FromSlash(g.properties.PkgPath)+".a")
 
-	ctx.VisitDepsDepthFirstIf(isGoPluginFor(name),
-		func(module blueprint.Module) { hasPlugins = true })
+	ctx.VisitDepsDepthFirst(func(module blueprint.Module) {
+		if ctx.OtherModuleDependencyTag(module) == pluginDepTag {
+			hasPlugins = true
+		}
+	})
 	if hasPlugins {
 		pluginSrc = filepath.Join(moduleGenSrcDir(ctx), "plugin.go")
 		genSrcs = append(genSrcs, pluginSrc)
@@ -325,54 +289,28 @@ func (g *GoPackage) GenerateBuildActions(ctx blueprint.ModuleContext) {
 
 	testArchiveFile := filepath.Join(testRoot(ctx),
 		filepath.FromSlash(g.properties.PkgPath)+".a")
-	g.testResultFile = buildGoTest(ctx, testRoot(ctx), testArchiveFile,
+	testResultFile := buildGoTest(ctx, testRoot(ctx), testArchiveFile,
 		g.properties.PkgPath, srcs, genSrcs, testSrcs, g.properties.EmbedSrcs)
 
 	// Don't build for test-only packages
 	if len(srcs) == 0 && len(genSrcs) == 0 {
 		ctx.Build(pctx, blueprint.BuildParams{
 			Rule:     touch,
-			Outputs:  []string{g.archiveFile},
+			Outputs:  []string{archiveFile},
 			Optional: true,
 		})
 		return
 	}
 
-	buildGoPackage(ctx, g.pkgRoot, g.properties.PkgPath, g.archiveFile,
+	buildGoPackage(ctx, pkgRoot, g.properties.PkgPath, archiveFile,
 		srcs, genSrcs, g.properties.EmbedSrcs)
 	blueprint.SetProvider(ctx, blueprint.SrcsFileProviderKey, blueprint.SrcsFileProviderData{SrcPaths: srcs})
-}
-
-func (g *GoPackage) Srcs() []string {
-	return g.properties.Srcs
-}
-
-func (g *GoPackage) LinuxSrcs() []string {
-	return g.properties.Linux.Srcs
-}
-
-func (g *GoPackage) DarwinSrcs() []string {
-	return g.properties.Darwin.Srcs
-}
-
-func (g *GoPackage) TestSrcs() []string {
-	return g.properties.TestSrcs
-}
-
-func (g *GoPackage) LinuxTestSrcs() []string {
-	return g.properties.Linux.TestSrcs
-}
-
-func (g *GoPackage) DarwinTestSrcs() []string {
-	return g.properties.Darwin.TestSrcs
-}
-
-func (g *GoPackage) Deps() []string {
-	return g.properties.Deps
-}
-
-func (g *GoPackage) TestData() []string {
-	return g.properties.TestData
+	blueprint.SetProvider(ctx, PackageProvider, &PackageInfo{
+		PkgPath:       g.properties.PkgPath,
+		PkgRoot:       pkgRoot,
+		PackageTarget: archiveFile,
+		TestTargets:   testResultFile,
+	})
 }
 
 // A GoBinary is a module for building executable binaries from Go sources.
@@ -386,6 +324,9 @@ type GoBinary struct {
 		EmbedSrcs      []string
 		PrimaryBuilder bool
 		Default        bool
+		// The visibility property is unused in blueprint, but exists so that soong
+		// can add one and not have the bp files fail to parse during the bootstrap build.
+		Visibility []string
 
 		Darwin struct {
 			Srcs     []string
@@ -398,9 +339,14 @@ type GoBinary struct {
 	}
 
 	installPath string
-}
 
-var _ GoBinaryTool = (*GoBinary)(nil)
+	// skipInstall can be set to true by a module type that wraps GoBinary to skip the install rule,
+	// allowing the wrapping module type to create the install rule itself.
+	skipInstall bool
+
+	// outputFile is set to the path to the intermediate output file.
+	outputFile string
+}
 
 func newGoBinaryModuleFactory() func() (blueprint.Module, []interface{}) {
 	return func() (blueprint.Module, []interface{}) {
@@ -416,49 +362,37 @@ func (g *GoBinary) DynamicDependencies(ctx blueprint.DynamicDependerModuleContex
 	return g.properties.Deps
 }
 
-func (g *GoBinary) isGoBinary() {}
-func (g *GoBinary) InstallPath() string {
-	return g.installPath
-}
-
-func (g *GoBinary) Srcs() []string {
-	return g.properties.Srcs
-}
-
-func (g *GoBinary) LinuxSrcs() []string {
-	return g.properties.Linux.Srcs
-}
-
-func (g *GoBinary) DarwinSrcs() []string {
-	return g.properties.Darwin.Srcs
-}
-
-func (g *GoBinary) TestSrcs() []string {
-	return g.properties.TestSrcs
-}
-
-func (g *GoBinary) LinuxTestSrcs() []string {
-	return g.properties.Linux.TestSrcs
+func (g *GoBinary) bootstrapDeps(ctx blueprint.BottomUpMutatorContext) {
+	if g.properties.PrimaryBuilder {
+		blueprint.SetProvider(ctx, PrimaryBuilderProvider, PrimaryBuilderInfo{})
+	}
 }
 
-func (g *GoBinary) DarwinTestSrcs() []string {
-	return g.properties.Darwin.TestSrcs
+// IntermediateFile returns the path to the final linked intermedate file.
+func (g *GoBinary) IntermediateFile() string {
+	return g.outputFile
 }
 
-func (g *GoBinary) Deps() []string {
-	return g.properties.Deps
+// SetSkipInstall is called by module types that wrap GoBinary to skip the install rule,
+// allowing the wrapping module type to create the install rule itself.
+func (g *GoBinary) SetSkipInstall() {
+	g.skipInstall = true
 }
 
-func (g *GoBinary) TestData() []string {
-	return g.properties.TestData
+// Properties returns the list of property structs to be used for registering a wrapped module type.
+func (g *GoBinary) Properties() []interface{} {
+	return []interface{}{&g.properties}
 }
 
 func (g *GoBinary) GenerateBuildActions(ctx blueprint.ModuleContext) {
 	// Allow the primary builder to create multiple variants.  Any variants after the first
 	// will copy outputs from the first.
 	if ctx.Module() != ctx.PrimaryModule() {
-		primary := ctx.PrimaryModule().(*GoBinary)
-		g.installPath = primary.installPath
+		if info, ok := blueprint.OtherModuleProvider(ctx, ctx.PrimaryModule(), BinaryProvider); ok {
+			g.installPath = info.InstallPath
+			g.outputFile = info.IntermediatePath
+			blueprint.SetProvider(ctx, BinaryProvider, info)
+		}
 		return
 	}
 
@@ -467,15 +401,21 @@ func (g *GoBinary) GenerateBuildActions(ctx blueprint.ModuleContext) {
 		objDir          = moduleObjDir(ctx)
 		archiveFile     = filepath.Join(objDir, name+".a")
 		testArchiveFile = filepath.Join(testRoot(ctx), name+".a")
-		aoutFile        = filepath.Join(objDir, "a.out")
+		aoutFile        = filepath.Join(objDir, name)
 		hasPlugins      = false
 		pluginSrc       = ""
 		genSrcs         = []string{}
 	)
 
-	g.installPath = filepath.Join(ctx.Config().(BootstrapConfig).HostToolDir(), name)
-	ctx.VisitDepsDepthFirstIf(isGoPluginFor(name),
-		func(module blueprint.Module) { hasPlugins = true })
+	if !g.skipInstall {
+		g.installPath = filepath.Join(ctx.Config().(BootstrapConfig).HostToolDir(), name)
+	}
+
+	ctx.VisitDirectDeps(func(module blueprint.Module) {
+		if ctx.OtherModuleDependencyTag(module) == pluginDepTag {
+			hasPlugins = true
+		}
+	})
 	if hasPlugins {
 		pluginSrc = filepath.Join(moduleGenSrcDir(ctx), "plugin.go")
 		genSrcs = append(genSrcs, pluginSrc)
@@ -496,21 +436,22 @@ func (g *GoBinary) GenerateBuildActions(ctx blueprint.ModuleContext) {
 		testSrcs = append(g.properties.TestSrcs, g.properties.Linux.TestSrcs...)
 	}
 
-	testDeps = buildGoTest(ctx, testRoot(ctx), testArchiveFile,
+	testResultFile := buildGoTest(ctx, testRoot(ctx), testArchiveFile,
 		name, srcs, genSrcs, testSrcs, g.properties.EmbedSrcs)
+	testDeps = append(testDeps, testResultFile...)
 
 	buildGoPackage(ctx, objDir, "main", archiveFile, srcs, genSrcs, g.properties.EmbedSrcs)
 
 	var linkDeps []string
 	var libDirFlags []string
-	ctx.VisitDepsDepthFirstIf(isGoPackageProducer,
-		func(module blueprint.Module) {
-			dep := module.(goPackageProducer)
-			linkDeps = append(linkDeps, dep.GoPackageTarget())
-			libDir := dep.GoPkgRoot()
+	ctx.VisitDepsDepthFirst(func(module blueprint.Module) {
+		if info, ok := blueprint.OtherModuleProvider(ctx, module, PackageProvider); ok {
+			linkDeps = append(linkDeps, info.PackageTarget)
+			libDir := info.PkgRoot
 			libDirFlags = append(libDirFlags, "-L "+libDir)
-			testDeps = append(testDeps, dep.GoTestTargets()...)
-		})
+			testDeps = append(testDeps, info.TestTargets...)
+		}
+	})
 
 	linkArgs := map[string]string{}
 	if len(libDirFlags) > 0 {
@@ -526,31 +467,42 @@ func (g *GoBinary) GenerateBuildActions(ctx blueprint.ModuleContext) {
 		Optional:  true,
 	})
 
+	g.outputFile = aoutFile
+
 	var validations []string
 	if ctx.Config().(BootstrapConfig).RunGoTests() {
 		validations = testDeps
 	}
 
-	ctx.Build(pctx, blueprint.BuildParams{
-		Rule:        cp,
-		Outputs:     []string{g.installPath},
-		Inputs:      []string{aoutFile},
-		Validations: validations,
-		Optional:    !g.properties.Default,
-	})
+	if !g.skipInstall {
+		ctx.Build(pctx, blueprint.BuildParams{
+			Rule:        cp,
+			Outputs:     []string{g.installPath},
+			Inputs:      []string{aoutFile},
+			Validations: validations,
+			Optional:    !g.properties.Default,
+		})
+	}
+
 	blueprint.SetProvider(ctx, blueprint.SrcsFileProviderKey, blueprint.SrcsFileProviderData{SrcPaths: srcs})
+	blueprint.SetProvider(ctx, BinaryProvider, &BinaryInfo{
+		IntermediatePath: g.outputFile,
+		InstallPath:      g.installPath,
+		TestTargets:      testResultFile,
+	})
 }
 
 func buildGoPluginLoader(ctx blueprint.ModuleContext, pkgPath, pluginSrc string) bool {
 	ret := true
-	name := ctx.ModuleName()
 
 	var pluginPaths []string
-	ctx.VisitDepsDepthFirstIf(isGoPluginFor(name),
-		func(module blueprint.Module) {
-			plugin := module.(goPluginProvider)
-			pluginPaths = append(pluginPaths, plugin.GoPkgPath())
-		})
+	ctx.VisitDirectDeps(func(module blueprint.Module) {
+		if ctx.OtherModuleDependencyTag(module) == pluginDepTag {
+			if info, ok := blueprint.OtherModuleProvider(ctx, module, PackageProvider); ok {
+				pluginPaths = append(pluginPaths, info.PkgPath)
+			}
+		}
+	})
 
 	ctx.Build(pctx, blueprint.BuildParams{
 		Rule:    pluginGenSrc,
@@ -597,14 +549,14 @@ func buildGoPackage(ctx blueprint.ModuleContext, pkgRoot string,
 
 	var incFlags []string
 	var deps []string
-	ctx.VisitDepsDepthFirstIf(isGoPackageProducer,
-		func(module blueprint.Module) {
-			dep := module.(goPackageProducer)
-			incDir := dep.GoPkgRoot()
-			target := dep.GoPackageTarget()
+	ctx.VisitDepsDepthFirst(func(module blueprint.Module) {
+		if info, ok := blueprint.OtherModuleProvider(ctx, module, PackageProvider); ok {
+			incDir := info.PkgRoot
+			target := info.PackageTarget
 			incFlags = append(incFlags, "-I "+incDir)
 			deps = append(deps, target)
-		})
+		}
+	})
 
 	compileArgs := map[string]string{
 		"pkgPath": pkgPath,
@@ -661,14 +613,14 @@ func buildGoTest(ctx blueprint.ModuleContext, testRoot, testPkgArchive,
 	linkDeps := []string{testPkgArchive}
 	libDirFlags := []string{"-L " + testRoot}
 	testDeps := []string{}
-	ctx.VisitDepsDepthFirstIf(isGoPackageProducer,
-		func(module blueprint.Module) {
-			dep := module.(goPackageProducer)
-			linkDeps = append(linkDeps, dep.GoPackageTarget())
-			libDir := dep.GoPkgRoot()
+	ctx.VisitDepsDepthFirst(func(module blueprint.Module) {
+		if info, ok := blueprint.OtherModuleProvider(ctx, module, PackageProvider); ok {
+			linkDeps = append(linkDeps, info.PackageTarget)
+			libDir := info.PkgRoot
 			libDirFlags = append(libDirFlags, "-L "+libDir)
-			testDeps = append(testDeps, dep.GoTestTargets()...)
-		})
+			testDeps = append(testDeps, info.TestTargets...)
+		}
+	})
 
 	ctx.Build(pctx, blueprint.BuildParams{
 		Rule:      compile,
@@ -708,6 +660,10 @@ func buildGoTest(ctx blueprint.ModuleContext, testRoot, testPkgArchive,
 	return []string{testPassed}
 }
 
+var PrimaryBuilderProvider = blueprint.NewMutatorProvider[PrimaryBuilderInfo]("bootstrap_deps")
+
+type PrimaryBuilderInfo struct{}
+
 type singleton struct {
 }
 
@@ -721,50 +677,45 @@ func (s *singleton) GenerateBuildActions(ctx blueprint.SingletonContext) {
 	// Find the module that's marked as the "primary builder", which means it's
 	// creating the binary that we'll use to generate the non-bootstrap
 	// build.ninja file.
-	var primaryBuilders []*GoBinary
+	var primaryBuilders []string
 	// blueprintTools contains blueprint go binaries that will be built in StageMain
 	var blueprintTools []string
 	// blueprintTools contains the test outputs of go tests that can be run in StageMain
 	var blueprintTests []string
 	// blueprintGoPackages contains all blueprint go packages that can be built in StageMain
 	var blueprintGoPackages []string
-	ctx.VisitAllModulesIf(IsBootstrapModule,
-		func(module blueprint.Module) {
-			if ctx.PrimaryModule(module) == module {
-				if binaryModule, ok := module.(*GoBinary); ok {
-					blueprintTools = append(blueprintTools, binaryModule.InstallPath())
-					if binaryModule.properties.PrimaryBuilder {
-						primaryBuilders = append(primaryBuilders, binaryModule)
-					}
+	ctx.VisitAllModules(func(module blueprint.Module) {
+		if ctx.PrimaryModule(module) == module {
+			if binaryInfo, ok := blueprint.SingletonModuleProvider(ctx, module, BinaryProvider); ok {
+				if binaryInfo.InstallPath != "" {
+					blueprintTools = append(blueprintTools, binaryInfo.InstallPath)
 				}
-
-				if packageModule, ok := module.(*GoPackage); ok {
-					blueprintGoPackages = append(blueprintGoPackages,
-						packageModule.GoPackageTarget())
-					blueprintTests = append(blueprintTests,
-						packageModule.GoTestTargets()...)
+				blueprintTests = append(blueprintTests, binaryInfo.TestTargets...)
+				if _, ok := blueprint.SingletonModuleProvider(ctx, module, PrimaryBuilderProvider); ok {
+					primaryBuilders = append(primaryBuilders, binaryInfo.InstallPath)
 				}
 			}
-		})
+
+			if packageInfo, ok := blueprint.SingletonModuleProvider(ctx, module, PackageProvider); ok {
+				blueprintGoPackages = append(blueprintGoPackages, packageInfo.PackageTarget)
+				blueprintTests = append(blueprintTests, packageInfo.TestTargets...)
+			}
+		}
+	})
 
 	var primaryBuilderCmdlinePrefix []string
-	var primaryBuilderName string
+	var primaryBuilderFile string
 
 	if len(primaryBuilders) == 0 {
 		ctx.Errorf("no primary builder module present")
 		return
 	} else if len(primaryBuilders) > 1 {
-		ctx.Errorf("multiple primary builder modules present:")
-		for _, primaryBuilder := range primaryBuilders {
-			ctx.ModuleErrorf(primaryBuilder, "<-- module %s",
-				ctx.ModuleName(primaryBuilder))
-		}
+		ctx.Errorf("multiple primary builder modules present: %q", primaryBuilders)
 		return
 	} else {
-		primaryBuilderName = ctx.ModuleName(primaryBuilders[0])
+		primaryBuilderFile = primaryBuilders[0]
 	}
 
-	primaryBuilderFile := filepath.Join("$ToolDir", primaryBuilderName)
 	ctx.SetOutDir(pctx, "${outDir}")
 
 	for _, subninja := range ctx.Config().(BootstrapConfig).Subninjas() {
@@ -810,11 +761,13 @@ func (s *singleton) GenerateBuildActions(ctx blueprint.SingletonContext) {
 	}
 
 	// Add a phony target for building various tools that are part of blueprint
-	ctx.Build(pctx, blueprint.BuildParams{
-		Rule:    blueprint.Phony,
-		Outputs: []string{"blueprint_tools"},
-		Inputs:  blueprintTools,
-	})
+	if len(blueprintTools) > 0 {
+		ctx.Build(pctx, blueprint.BuildParams{
+			Rule:    blueprint.Phony,
+			Outputs: []string{"blueprint_tools"},
+			Inputs:  blueprintTools,
+		})
+	}
 
 	// Add a phony target for running various tests that are part of blueprint
 	ctx.Build(pctx, blueprint.BuildParams{
diff --git a/bootstrap/bpglob/bpglob.go b/bootstrap/bpglob/bpglob.go
deleted file mode 100644
index 1e6d25bdcb..0000000000
--- a/bootstrap/bpglob/bpglob.go
+++ /dev/null
@@ -1,148 +0,0 @@
-// Copyright 2015 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-// bpglob is the command line tool that checks if the list of files matching a glob has
-// changed, and only updates the output file list if it has changed.  It is used to optimize
-// out build.ninja regenerations when non-matching files are added.  See
-// github.com/google/blueprint/bootstrap/glob.go for a longer description.
-package main
-
-import (
-	"flag"
-	"fmt"
-	"io/ioutil"
-	"os"
-	"time"
-
-	"github.com/google/blueprint/deptools"
-	"github.com/google/blueprint/pathtools"
-)
-
-var (
-	out = flag.String("o", "", "file to write list of files that match glob")
-
-	globs []globArg
-)
-
-func init() {
-	flag.Var((*patternsArgs)(&globs), "p", "pattern to include in results")
-	flag.Var((*excludeArgs)(&globs), "e", "pattern to exclude from results from the most recent pattern")
-}
-
-// A glob arg holds a single -p argument with zero or more following -e arguments.
-type globArg struct {
-	pattern  string
-	excludes []string
-}
-
-// patternsArgs implements flag.Value to handle -p arguments by adding a new globArg to the list.
-type patternsArgs []globArg
-
-func (p *patternsArgs) String() string { return `""` }
-
-func (p *patternsArgs) Set(s string) error {
-	globs = append(globs, globArg{
-		pattern: s,
-	})
-	return nil
-}
-
-// excludeArgs implements flag.Value to handle -e arguments by adding to the last globArg in the
-// list.
-type excludeArgs []globArg
-
-func (e *excludeArgs) String() string { return `""` }
-
-func (e *excludeArgs) Set(s string) error {
-	if len(*e) == 0 {
-		return fmt.Errorf("-p argument is required before the first -e argument")
-	}
-
-	glob := &(*e)[len(*e)-1]
-	glob.excludes = append(glob.excludes, s)
-	return nil
-}
-
-func usage() {
-	fmt.Fprintln(os.Stderr, "usage: bpglob -o out -p glob [-e excludes ...] [-p glob ...]")
-	flag.PrintDefaults()
-	os.Exit(2)
-}
-
-func main() {
-	flag.Parse()
-
-	if *out == "" {
-		fmt.Fprintln(os.Stderr, "error: -o is required")
-		usage()
-	}
-
-	if flag.NArg() > 0 {
-		usage()
-	}
-
-	err := globsWithDepFile(*out, *out+".d", globs)
-	if err != nil {
-		// Globs here were already run in the primary builder without error.  The only errors here should be if the glob
-		// pattern was made invalid by a change in the pathtools glob implementation, in which case the primary builder
-		// needs to be rerun anyways.  Update the output file with something that will always cause the primary builder
-		// to rerun.
-		writeErrorOutput(*out, err)
-	}
-}
-
-// writeErrorOutput writes an error to the output file with a timestamp to ensure that it is
-// considered dirty by ninja.
-func writeErrorOutput(path string, globErr error) {
-	s := fmt.Sprintf("%s: error: %s\n", time.Now().Format(time.StampNano), globErr.Error())
-	err := ioutil.WriteFile(path, []byte(s), 0666)
-	if err != nil {
-		fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
-		os.Exit(1)
-	}
-}
-
-// globsWithDepFile finds all files and directories that match glob.  Directories
-// will have a trailing '/'.  It compares the list of matches against the
-// contents of fileListFile, and rewrites fileListFile if it has changed.  It
-// also writes all of the directories it traversed as dependencies on fileListFile
-// to depFile.
-//
-// The format of glob is either path/*.ext for a single directory glob, or
-// path/**/*.ext for a recursive glob.
-func globsWithDepFile(fileListFile, depFile string, globs []globArg) error {
-	var results pathtools.MultipleGlobResults
-	for _, glob := range globs {
-		result, err := pathtools.Glob(glob.pattern, glob.excludes, pathtools.FollowSymlinks)
-		if err != nil {
-			return err
-		}
-		results = append(results, result)
-	}
-
-	// Only write the output file if it has changed.
-	err := pathtools.WriteFileIfChanged(fileListFile, results.FileList(), 0666)
-	if err != nil {
-		return fmt.Errorf("failed to write file list to %q: %w", fileListFile, err)
-	}
-
-	// The depfile can be written unconditionally as its timestamp doesn't affect ninja's restat
-	// feature.
-	err = deptools.WriteDepFile(depFile, fileListFile, results.Deps())
-	if err != nil {
-		return fmt.Errorf("failed to write dep file to %q: %w", depFile, err)
-	}
-
-	return nil
-}
diff --git a/bootstrap/command.go b/bootstrap/command.go
index 3071e3ee36..8ae6e2487a 100644
--- a/bootstrap/command.go
+++ b/bootstrap/command.go
@@ -42,7 +42,8 @@ type Args struct {
 	TraceFile  string
 
 	// Debug data json file
-	ModuleDebugFile string
+	ModuleDebugFile         string
+	IncrementalBuildActions bool
 }
 
 // RegisterGoModuleTypes adds module types to build tools written in golang
@@ -51,6 +52,14 @@ func RegisterGoModuleTypes(ctx *blueprint.Context) {
 	ctx.RegisterModuleType("blueprint_go_binary", newGoBinaryModuleFactory())
 }
 
+// GoModuleTypesAreWrapped is called by Soong before calling RunBlueprint to provide its own wrapped
+// implementations of bootstrap_go_package and blueprint_go_bianry.
+func GoModuleTypesAreWrapped() {
+	goModuleTypesAreWrapped = true
+}
+
+var goModuleTypesAreWrapped = false
+
 // RunBlueprint emits `args.OutFile` (a Ninja file) and returns the list of
 // its dependencies. These can be written to a `${args.OutFile}.d` file
 // so that it is correctly rebuilt when needed in case Blueprint is itself
@@ -99,9 +108,11 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 	}
 	ctx.EndEvent("list_modules")
 
-	ctx.RegisterBottomUpMutator("bootstrap_plugin_deps", pluginDeps)
+	ctx.RegisterBottomUpMutator("bootstrap_deps", BootstrapDeps)
 	ctx.RegisterSingletonType("bootstrap", newSingletonFactory(), false)
-	RegisterGoModuleTypes(ctx)
+	if !goModuleTypesAreWrapped {
+		RegisterGoModuleTypes(ctx)
+	}
 
 	ctx.BeginEvent("parse_bp")
 	if blueprintFiles, errs := ctx.ParseFileList(".", filesToParse, config); len(errs) > 0 {
@@ -127,6 +138,14 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 		}
 	}
 
+	if ctx.GetIncrementalAnalysis() {
+		var err error = nil
+		err = ctx.RestoreAllBuildActions(config.(BootstrapConfig).SoongOutDir())
+		if err != nil {
+			return nil, fatalErrors([]error{err})
+		}
+	}
+
 	if buildActionsDeps, errs := ctx.PrepareBuildActions(config); len(errs) > 0 {
 		return nil, fatalErrors(errs)
 	} else {
@@ -187,6 +206,13 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 		}
 	}
 
+	// TODO(b/357140398): parallelize this with other ninja file writing work.
+	if ctx.GetIncrementalEnabled() {
+		if err := ctx.CacheAllBuildActions(config.(BootstrapConfig).SoongOutDir()); err != nil {
+			return nil, fmt.Errorf("error cache build actions: %s", err)
+		}
+	}
+
 	providerValidationErrors := <-providersValidationChan
 	if providerValidationErrors != nil {
 		return nil, proptools.MergeErrors(providerValidationErrors)
diff --git a/bootstrap/glob.go b/bootstrap/glob.go
deleted file mode 100644
index 4611cef5f1..0000000000
--- a/bootstrap/glob.go
+++ /dev/null
@@ -1,286 +0,0 @@
-// Copyright 2016 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package bootstrap
-
-import (
-	"bytes"
-	"fmt"
-	"hash/fnv"
-	"io"
-	"io/ioutil"
-	"path/filepath"
-	"strconv"
-	"strings"
-
-	"github.com/google/blueprint"
-	"github.com/google/blueprint/pathtools"
-)
-
-// This file supports globbing source files in Blueprints files.
-//
-// The build.ninja file needs to be regenerated any time a file matching the glob is added
-// or removed.  The naive solution is to have the build.ninja file depend on all the
-// traversed directories, but this will cause the regeneration step to run every time a
-// non-matching file is added to a traversed directory, including backup files created by
-// editors.
-//
-// The solution implemented here optimizes out regenerations when the directory modifications
-// don't match the glob by having the build.ninja file depend on an intermedate file that
-// is only updated when a file matching the glob is added or removed.  The intermediate file
-// depends on the traversed directories via a depfile.  The depfile is used to avoid build
-// errors if a directory is deleted - a direct dependency on the deleted directory would result
-// in a build failure with a "missing and no known rule to make it" error.
-
-var (
-	_ = pctx.VariableFunc("globCmd", func(ctx blueprint.VariableFuncContext, config interface{}) (string, error) {
-		return filepath.Join(config.(BootstrapConfig).SoongOutDir(), "bpglob"), nil
-	})
-
-	// globRule rule traverses directories to produce a list of files that match $glob
-	// and writes it to $out if it has changed, and writes the directories to $out.d
-	GlobRule = pctx.StaticRule("GlobRule",
-		blueprint.RuleParams{
-			Command:     "$globCmd -o $out $args",
-			CommandDeps: []string{"$globCmd"},
-			Description: "glob",
-
-			Restat:  true,
-			Deps:    blueprint.DepsGCC,
-			Depfile: "$out.d",
-		},
-		"args")
-)
-
-// GlobFileContext is the subset of ModuleContext and SingletonContext needed by GlobFile
-type GlobFileContext interface {
-	Config() interface{}
-	Build(pctx blueprint.PackageContext, params blueprint.BuildParams)
-}
-
-// GlobFile creates a rule to write to fileListFile a list of the files that match the specified
-// pattern but do not match any of the patterns specified in excludes.  The file will include
-// appropriate dependencies to regenerate the file if and only if the list of matching files has
-// changed.
-func GlobFile(ctx GlobFileContext, pattern string, excludes []string, fileListFile string) {
-	args := `-p "` + pattern + `"`
-	if len(excludes) > 0 {
-		args += " " + joinWithPrefixAndQuote(excludes, "-e ")
-	}
-	ctx.Build(pctx, blueprint.BuildParams{
-		Rule:    GlobRule,
-		Outputs: []string{fileListFile},
-		Args: map[string]string{
-			"args": args,
-		},
-		Description: "glob " + pattern,
-	})
-}
-
-// multipleGlobFilesRule creates a rule to write to fileListFile a list of the files that match the specified
-// pattern but do not match any of the patterns specified in excludes.  The file will include
-// appropriate dependencies to regenerate the file if and only if the list of matching files has
-// changed.
-func multipleGlobFilesRule(ctx GlobFileContext, fileListFile string, shard int, globs pathtools.MultipleGlobResults) {
-	args := strings.Builder{}
-
-	for i, glob := range globs {
-		if i != 0 {
-			args.WriteString(" ")
-		}
-		args.WriteString(`-p "`)
-		args.WriteString(glob.Pattern)
-		args.WriteString(`"`)
-		for _, exclude := range glob.Excludes {
-			args.WriteString(` -e "`)
-			args.WriteString(exclude)
-			args.WriteString(`"`)
-		}
-	}
-
-	ctx.Build(pctx, blueprint.BuildParams{
-		Rule:    GlobRule,
-		Outputs: []string{fileListFile},
-		Args: map[string]string{
-			"args": args.String(),
-		},
-		Description: fmt.Sprintf("regenerate globs shard %d of %d", shard, numGlobBuckets),
-	})
-}
-
-func joinWithPrefixAndQuote(strs []string, prefix string) string {
-	if len(strs) == 0 {
-		return ""
-	}
-
-	if len(strs) == 1 {
-		return prefix + `"` + strs[0] + `"`
-	}
-
-	n := len(" ") * (len(strs) - 1)
-	for _, s := range strs {
-		n += len(prefix) + len(s) + len(`""`)
-	}
-
-	ret := make([]byte, 0, n)
-	for i, s := range strs {
-		if i != 0 {
-			ret = append(ret, ' ')
-		}
-		ret = append(ret, prefix...)
-		ret = append(ret, '"')
-		ret = append(ret, s...)
-		ret = append(ret, '"')
-	}
-	return string(ret)
-}
-
-// GlobSingleton collects any glob patterns that were seen by Context and writes out rules to
-// re-evaluate them whenever the contents of the searched directories change, and retrigger the
-// primary builder if the results change.
-type GlobSingleton struct {
-	// A function that returns the glob results of individual glob buckets
-	GlobLister func() pathtools.MultipleGlobResults
-
-	// Ninja file that contains instructions for validating the glob list files
-	GlobFile string
-
-	// Directory containing the glob list files
-	GlobDir string
-
-	// The source directory
-	SrcDir string
-}
-
-func globBucketName(globDir string, globBucket int) string {
-	return filepath.Join(globDir, strconv.Itoa(globBucket))
-}
-
-// Returns the directory where glob list files live
-func GlobDirectory(buildDir, globListDir string) string {
-	return filepath.Join(buildDir, "globs", globListDir)
-}
-
-func (s *GlobSingleton) GenerateBuildActions(ctx blueprint.SingletonContext) {
-	// Sort the list of globs into buckets.  A hash function is used instead of sharding so that
-	// adding a new glob doesn't force rerunning all the buckets by shifting them all by 1.
-	globBuckets := make([]pathtools.MultipleGlobResults, numGlobBuckets)
-	for _, g := range s.GlobLister() {
-		bucket := globToBucket(g)
-		globBuckets[bucket] = append(globBuckets[bucket], g)
-	}
-
-	for i, globs := range globBuckets {
-		fileListFile := globBucketName(s.GlobDir, i)
-
-		// Called from generateGlobNinjaFile.  Write out the file list to disk, and add a ninja
-		// rule to run bpglob if any of the dependencies (usually directories that contain
-		// globbed files) have changed.  The file list produced by bpglob should match exactly
-		// with the file written here so that restat can prevent rerunning the primary builder.
-		//
-		// We need to write the file list here so that it has an older modified date
-		// than the build.ninja (otherwise we'd run the primary builder twice on
-		// every new glob)
-		//
-		// We don't need to write the depfile because we're guaranteed that ninja
-		// will run the command at least once (to record it into the ninja_log), so
-		// the depfile will be loaded from that execution.
-		absoluteFileListFile := blueprint.JoinPath(s.SrcDir, fileListFile)
-		err := pathtools.WriteFileIfChanged(absoluteFileListFile, globs.FileList(), 0666)
-		if err != nil {
-			panic(fmt.Errorf("error writing %s: %s", fileListFile, err))
-		}
-
-		// Write out the ninja rule to run bpglob.
-		multipleGlobFilesRule(ctx, fileListFile, i, globs)
-	}
-}
-
-// Writes a .ninja file that contains instructions for regenerating the glob
-// files that contain the results of every glob that was run. The list of files
-// is available as the result of GlobFileListFiles().
-func WriteBuildGlobsNinjaFile(glob *GlobSingleton, config interface{}) error {
-	buffer, errs := generateGlobNinjaFile(glob, config)
-	if len(errs) > 0 {
-		return fatalErrors(errs)
-	}
-
-	const outFilePermissions = 0666
-	err := ioutil.WriteFile(blueprint.JoinPath(glob.SrcDir, glob.GlobFile), buffer, outFilePermissions)
-	if err != nil {
-		return fmt.Errorf("error writing %s: %s", glob.GlobFile, err)
-	}
-
-	return nil
-}
-
-func generateGlobNinjaFile(glob *GlobSingleton, config interface{}) ([]byte, []error) {
-
-	ctx := blueprint.NewContext()
-	ctx.RegisterSingletonType("glob", func() blueprint.Singleton {
-		return glob
-	}, false)
-
-	extraDeps, errs := ctx.ResolveDependencies(config)
-	if len(extraDeps) > 0 {
-		return nil, []error{fmt.Errorf("shouldn't have extra deps")}
-	}
-	if len(errs) > 0 {
-		return nil, errs
-	}
-
-	// PrepareBuildActions() will write $OUTDIR/soong/globs/$m/$i files
-	// where $m=bp2build|build and $i=0..numGlobBuckets
-	extraDeps, errs = ctx.PrepareBuildActions(config)
-	if len(extraDeps) > 0 {
-		return nil, []error{fmt.Errorf("shouldn't have extra deps")}
-	}
-	if len(errs) > 0 {
-		return nil, errs
-	}
-
-	buf := bytes.NewBuffer(nil)
-	err := ctx.WriteBuildFile(buf, false, "")
-	if err != nil {
-		return nil, []error{err}
-	}
-
-	return buf.Bytes(), nil
-}
-
-// GlobFileListFiles returns the list of files that contain the result of globs
-// in the build. It is suitable for inclusion in build.ninja.d (so that
-// build.ninja is regenerated if the globs change). The instructions to
-// regenerate these files are written by WriteBuildGlobsNinjaFile().
-func GlobFileListFiles(globDir string) []string {
-	var fileListFiles []string
-	for i := 0; i < numGlobBuckets; i++ {
-		fileListFile := globBucketName(globDir, i)
-		fileListFiles = append(fileListFiles, fileListFile)
-	}
-	return fileListFiles
-}
-
-const numGlobBuckets = 1024
-
-// globToBucket converts a pathtools.GlobResult into a hashed bucket number in the range
-// [0, numGlobBuckets).
-func globToBucket(g pathtools.GlobResult) int {
-	hash := fnv.New32a()
-	io.WriteString(hash, g.Pattern)
-	for _, e := range g.Excludes {
-		io.WriteString(hash, e)
-	}
-	return int(hash.Sum32() % numGlobBuckets)
-}
diff --git a/bootstrap/writedocs.go b/bootstrap/writedocs.go
index d172f7058f..9b16e50a57 100644
--- a/bootstrap/writedocs.go
+++ b/bootstrap/writedocs.go
@@ -16,16 +16,16 @@ func ModuleTypeDocs(ctx *blueprint.Context, factories map[string]reflect.Value)
 	// Find the module that's marked as the "primary builder", which means it's
 	// creating the binary that we'll use to generate the non-bootstrap
 	// build.ninja file.
-	var primaryBuilders []*GoBinary
-	ctx.VisitAllModulesIf(isBootstrapBinaryModule,
-		func(module blueprint.Module) {
-			binaryModule := module.(*GoBinary)
-			if binaryModule.properties.PrimaryBuilder {
-				primaryBuilders = append(primaryBuilders, binaryModule)
+	var primaryBuilders []blueprint.Module
+	ctx.VisitAllModules(func(module blueprint.Module) {
+		if ctx.PrimaryModule(module) == module {
+			if _, ok := blueprint.SingletonModuleProvider(ctx, module, PrimaryBuilderProvider); ok {
+				primaryBuilders = append(primaryBuilders, module)
 			}
-		})
+		}
+	})
 
-	var primaryBuilder *GoBinary
+	var primaryBuilder blueprint.Module
 	switch len(primaryBuilders) {
 	case 0:
 		return nil, fmt.Errorf("no primary builder module present")
@@ -39,12 +39,9 @@ func ModuleTypeDocs(ctx *blueprint.Context, factories map[string]reflect.Value)
 
 	pkgFiles := make(map[string][]string)
 	ctx.VisitDepsDepthFirst(primaryBuilder, func(module blueprint.Module) {
-		switch m := module.(type) {
-		case (*GoPackage):
-			pkgFiles[m.properties.PkgPath] = pathtools.PrefixPaths(m.properties.Srcs,
-				filepath.Join(ctx.SrcDir(), ctx.ModuleDir(m)))
-		default:
-			panic(fmt.Errorf("unknown dependency type %T", module))
+		if info, ok := blueprint.SingletonModuleProvider(ctx, module, DocsPackageProvider); ok {
+			pkgFiles[info.PkgPath] = pathtools.PrefixPaths(info.Srcs,
+				filepath.Join(ctx.SrcDir(), ctx.ModuleDir(module)))
 		}
 	})
 
diff --git a/bpfmt/bpfmt.go b/bpfmt/bpfmt.go
index df8b87a0cc..e78252df74 100644
--- a/bpfmt/bpfmt.go
+++ b/bpfmt/bpfmt.go
@@ -66,7 +66,7 @@ func processReader(filename string, in io.Reader, out io.Writer) error {
 
 	r := bytes.NewBuffer(src)
 
-	file, errs := parser.Parse(filename, r, parser.NewScope(nil))
+	file, errs := parser.Parse(filename, r)
 	if len(errs) > 0 {
 		for _, err := range errs {
 			fmt.Fprintln(os.Stderr, err)
diff --git a/bpmodify/bpmodify.go b/bpmodify/bpmodify.go
index 1df808e107..98b1bee3a6 100644
--- a/bpmodify/bpmodify.go
+++ b/bpmodify/bpmodify.go
@@ -85,7 +85,7 @@ func processFile(filename string, in io.Reader, out io.Writer) error {
 		return err
 	}
 	r := bytes.NewBuffer(src)
-	file, errs := parser.Parse(filename, r, parser.NewScope(nil))
+	file, errs := parser.Parse(filename, r)
 	if len(errs) > 0 {
 		for _, err := range errs {
 			fmt.Fprintln(os.Stderr, err)
@@ -131,11 +131,13 @@ func findModules(file *parser.File) (modified bool, errs []error) {
 	for _, def := range file.Defs {
 		if module, ok := def.(*parser.Module); ok {
 			for _, prop := range module.Properties {
-				if prop.Name == "name" && prop.Value.Type() == parser.StringType && targetedModule(prop.Value.Eval().(*parser.String).Value) {
-					for _, p := range targetedProperties.properties {
-						m, newErrs := processModuleProperty(module, prop.Name, file, p)
-						errs = append(errs, newErrs...)
-						modified = modified || m
+				if prop.Name == "name" {
+					if stringValue, ok := prop.Value.(*parser.String); ok && targetedModule(stringValue.Value) {
+						for _, p := range targetedProperties.properties {
+							m, newErrs := processModuleProperty(module, prop.Name, file, p)
+							errs = append(errs, newErrs...)
+							modified = modified || m
+						}
 					}
 				}
 			}
@@ -194,7 +196,7 @@ func getOrCreateRecursiveProperty(module *parser.Module, name string, prefixes [
 	m := &module.Map
 	for i, prefix := range prefixes {
 		if prop, found := m.GetProperty(prefix); found {
-			if mm, ok := prop.Value.Eval().(*parser.Map); ok {
+			if mm, ok := prop.Value.(*parser.Map); ok {
 				m = mm
 			} else {
 				// We've found a property in the AST and such property is not of type
@@ -236,9 +238,9 @@ func processParameter(value parser.Expression, paramName, moduleName string,
 	}
 
 	if (*replaceProperty).size() != 0 {
-		if list, ok := value.Eval().(*parser.List); ok {
+		if list, ok := value.(*parser.List); ok {
 			return parser.ReplaceStringsInList(list, (*replaceProperty).oldNameToNewName), nil
-		} else if str, ok := value.Eval().(*parser.String); ok {
+		} else if str, ok := value.(*parser.String); ok {
 			oldVal := str.Value
 			replacementValue := (*replaceProperty).oldNameToNewName[oldVal]
 			if replacementValue != "" {
diff --git a/context.go b/context.go
index 1591b3cdcd..33ad4cd267 100644
--- a/context.go
+++ b/context.go
@@ -19,6 +19,7 @@ import (
 	"bytes"
 	"cmp"
 	"context"
+	"encoding/gob"
 	"encoding/json"
 	"errors"
 	"fmt"
@@ -26,6 +27,7 @@ import (
 	"io"
 	"io/ioutil"
 	"maps"
+	"math"
 	"os"
 	"path/filepath"
 	"reflect"
@@ -53,6 +55,9 @@ const MockModuleListFile = "bplist"
 
 const OutFilePermissions = 0666
 
+const BuildActionsCacheFile = "build_actions.gob"
+const OrderOnlyStringsCacheFile = "order_only_strings.gob"
+
 // A Context contains all the state needed to parse a set of Blueprints files
 // and generate a Ninja file.  The process of generating a Ninja file proceeds
 // through a series of four phases.  Each phase corresponds with a some methods
@@ -94,6 +99,8 @@ type Context struct {
 	mutatorInfo         []*mutatorInfo
 	variantMutatorNames []string
 
+	variantCreatingMutatorOrder []string
+
 	transitionMutators []*transitionMutatorImpl
 
 	depsModified uint32 // positive if a mutator modified the dependencies
@@ -157,6 +164,25 @@ type Context struct {
 	includeTags *IncludeTags
 
 	sourceRootDirs *SourceRootDirs
+
+	// True if an incremental analysis can be attempted, i.e., there is no Soong
+	// code changes, no environmental variable changes and no product config
+	// variable changes.
+	incrementalAnalysis bool
+
+	// True if the flag --incremental-build-actions is set, in which case Soong
+	// will try to do a incremental build. Mainly two tasks will involve here:
+	// caching the providers of all the participating modules, and restoring the
+	// providers and skip the build action generations if there is a cache hit.
+	// Enabling this flag will only guarantee the former task to be performed, the
+	// latter will depend on the flag above.
+	incrementalEnabled bool
+
+	buildActionsToCache       BuildActionCache
+	buildActionsToCacheLock   sync.Mutex
+	buildActionsFromCache     BuildActionCache
+	orderOnlyStringsFromCache OrderOnlyStringsCache
+	orderOnlyStringsToCache   OrderOnlyStringsCache
 }
 
 // A container for String keys. The keys can be used to gate build graph traversal
@@ -372,6 +398,14 @@ type moduleInfo struct {
 
 	startedGenerateBuildActions  bool
 	finishedGenerateBuildActions bool
+
+	incrementalInfo
+}
+
+type incrementalInfo struct {
+	incrementalRestored bool
+	buildActionCacheKey *BuildActionCacheKey
+	orderOnlyStrings    *[]string
 }
 
 type variant struct {
@@ -414,6 +448,16 @@ func (module *moduleInfo) namespace() Namespace {
 	return module.group.namespace
 }
 
+func (module *moduleInfo) ModuleCacheKey() string {
+	variant := module.variant.name
+	if variant == "" {
+		variant = "none"
+	}
+	return fmt.Sprintf("%s-%s-%s-%s",
+		strings.ReplaceAll(filepath.Dir(module.relBlueprintsFile), "/", "."),
+		module.Name(), variant, module.typeName)
+}
+
 // A Variation is a way that a variant of a module differs from other variants of the same module.
 // For example, two variants of the same module might have Variation{"arch","arm"} and
 // Variation{"arch","arm64"}
@@ -426,17 +470,33 @@ type Variation struct {
 }
 
 // A variationMap stores a map of Mutator to Variation to specify a variant of a module.
-type variationMap map[string]string
+type variationMap struct {
+	variations map[string]string
+}
 
 func (vm variationMap) clone() variationMap {
-	return maps.Clone(vm)
+	return variationMap{
+		variations: maps.Clone(vm.variations),
+	}
+}
+
+func (vm variationMap) cloneMatching(mutators []string) variationMap {
+	newVariations := make(map[string]string)
+	for _, mutator := range mutators {
+		if variation, ok := vm.variations[mutator]; ok {
+			newVariations[mutator] = variation
+		}
+	}
+	return variationMap{
+		variations: newVariations,
+	}
 }
 
 // Compare this variationMap to another one.  Returns true if the every entry in this map
 // exists and has the same value in the other map.
 func (vm variationMap) subsetOf(other variationMap) bool {
-	for k, v1 := range vm {
-		if v2, ok := other[k]; !ok || v1 != v2 {
+	for k, v1 := range vm.variations {
+		if v2, ok := other.variations[k]; !ok || v1 != v2 {
 			return false
 		}
 	}
@@ -444,7 +504,44 @@ func (vm variationMap) subsetOf(other variationMap) bool {
 }
 
 func (vm variationMap) equal(other variationMap) bool {
-	return maps.Equal(vm, other)
+	return maps.Equal(vm.variations, other.variations)
+}
+
+func (vm *variationMap) set(mutator, variation string) {
+	if variation == "" {
+		if vm.variations != nil {
+			delete(vm.variations, mutator)
+		}
+	} else {
+		if vm.variations == nil {
+			vm.variations = make(map[string]string)
+		}
+		vm.variations[mutator] = variation
+	}
+}
+
+func (vm variationMap) get(mutator string) string {
+	return vm.variations[mutator]
+}
+
+func (vm variationMap) delete(mutator string) {
+	delete(vm.variations, mutator)
+}
+
+func (vm variationMap) empty() bool {
+	return len(vm.variations) == 0
+}
+
+// differenceKeysCount returns the count of keys that exist in this variationMap that don't exist in the argument.  It
+// ignores the values.
+func (vm variationMap) differenceKeysCount(other variationMap) int {
+	divergence := 0
+	for mutator, _ := range vm.variations {
+		if _, exists := other.variations[mutator]; !exists {
+			divergence += 1
+		}
+	}
+	return divergence
 }
 
 type singletonInfo struct {
@@ -485,6 +582,8 @@ func newContext() *Context {
 		requiredNinjaMinor:          7,
 		requiredNinjaMicro:          0,
 		verifyProvidersAreUnchanged: true,
+		buildActionsToCache:         make(BuildActionCache),
+		orderOnlyStringsToCache:     make(OrderOnlyStringsCache),
 	}
 }
 
@@ -607,6 +706,75 @@ func (c *Context) SetNameInterface(i NameInterface) {
 	c.nameInterface = i
 }
 
+func (c *Context) SetIncrementalAnalysis(incremental bool) {
+	c.incrementalAnalysis = incremental
+}
+
+func (c *Context) GetIncrementalAnalysis() bool {
+	return c.incrementalAnalysis
+}
+
+func (c *Context) SetIncrementalEnabled(incremental bool) {
+	c.incrementalEnabled = incremental
+}
+
+func (c *Context) GetIncrementalEnabled() bool {
+	return c.incrementalEnabled
+}
+
+func (c *Context) updateBuildActionsCache(key *BuildActionCacheKey, data *BuildActionCachedData) {
+	if key != nil {
+		c.buildActionsToCacheLock.Lock()
+		defer c.buildActionsToCacheLock.Unlock()
+		c.buildActionsToCache[*key] = data
+	}
+}
+
+func (c *Context) getBuildActionsFromCache(key *BuildActionCacheKey) *BuildActionCachedData {
+	if c.buildActionsFromCache != nil && key != nil {
+		return c.buildActionsFromCache[*key]
+	}
+	return nil
+}
+
+func (c *Context) CacheAllBuildActions(soongOutDir string) error {
+	return errors.Join(writeToCache(c, soongOutDir, BuildActionsCacheFile, &c.buildActionsToCache),
+		writeToCache(c, soongOutDir, OrderOnlyStringsCacheFile, &c.orderOnlyStringsToCache))
+}
+
+func writeToCache[T any](ctx *Context, soongOutDir string, fileName string, data *T) error {
+	file, err := ctx.fs.OpenFile(filepath.Join(ctx.SrcDir(), soongOutDir, fileName),
+		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, OutFilePermissions)
+	if err != nil {
+		return err
+	}
+	defer file.Close()
+
+	encoder := gob.NewEncoder(file)
+	return encoder.Encode(data)
+}
+
+func (c *Context) RestoreAllBuildActions(soongOutDir string) error {
+	c.buildActionsFromCache = make(BuildActionCache)
+	c.orderOnlyStringsFromCache = make(OrderOnlyStringsCache)
+	return errors.Join(restoreFromCache(c, soongOutDir, BuildActionsCacheFile, &c.buildActionsFromCache),
+		restoreFromCache(c, soongOutDir, OrderOnlyStringsCacheFile, &c.orderOnlyStringsFromCache))
+}
+
+func restoreFromCache[T any](ctx *Context, soongOutDir string, fileName string, data *T) error {
+	file, err := ctx.fs.Open(filepath.Join(ctx.SrcDir(), soongOutDir, fileName))
+	if err != nil {
+		if os.IsNotExist(err) {
+			err = nil
+		}
+		return err
+	}
+	defer file.Close()
+
+	decoder := gob.NewDecoder(file)
+	return decoder.Decode(data)
+}
+
 func (c *Context) SetSrcDir(path string) {
 	c.srcDir = path
 	c.fs = pathtools.NewOsFs(path)
@@ -687,6 +855,18 @@ func (c *Context) RegisterBottomUpMutator(name string, mutator BottomUpMutator)
 	return info
 }
 
+// HasMutatorFinished returns true if the given mutator has finished running.
+// It will panic if given an invalid mutator name.
+func (c *Context) HasMutatorFinished(mutatorName string) bool {
+	for _, mutator := range c.mutatorInfo {
+		if mutator.name == mutatorName {
+			finished, ok := c.finishedMutators[mutator]
+			return ok && finished
+		}
+	}
+	panic(fmt.Sprintf("unknown mutator %q", mutatorName))
+}
+
 type MutatorHandle interface {
 	// Set the mutator to visit modules in parallel while maintaining ordering.  Calling any
 	// method on the mutator context is thread-safe, but the mutator must handle synchronization
@@ -1221,9 +1401,9 @@ func (c *Context) parseOne(rootDir, filename string, reader io.Reader,
 		return nil, nil, []error{err}
 	}
 
-	scope.Remove("subdirs")
-	scope.Remove("optional_subdirs")
-	scope.Remove("build")
+	scope.DontInherit("subdirs")
+	scope.DontInherit("optional_subdirs")
+	scope.DontInherit("build")
 	file, errs = parser.ParseAndEval(filename, reader, scope)
 	if len(errs) > 0 {
 		for i, err := range errs {
@@ -1357,10 +1537,10 @@ func (c *Context) findSubdirBlueprints(dir string, subdirs []string, subdirsPos
 }
 
 func getLocalStringListFromScope(scope *parser.Scope, v string) ([]string, scanner.Position, error) {
-	if assignment, local := scope.Get(v); assignment == nil || !local {
+	if assignment := scope.GetLocal(v); assignment == nil {
 		return nil, scanner.Position{}, nil
 	} else {
-		switch value := assignment.Value.Eval().(type) {
+		switch value := assignment.Value.(type) {
 		case *parser.List:
 			ret := make([]string, 0, len(value.Values))
 
@@ -1386,24 +1566,6 @@ func getLocalStringListFromScope(scope *parser.Scope, v string) ([]string, scann
 	}
 }
 
-func getStringFromScope(scope *parser.Scope, v string) (string, scanner.Position, error) {
-	if assignment, _ := scope.Get(v); assignment == nil {
-		return "", scanner.Position{}, nil
-	} else {
-		switch value := assignment.Value.Eval().(type) {
-		case *parser.String:
-			return value.Value, assignment.EqualsPos, nil
-		case *parser.Bool, *parser.List:
-			return "", scanner.Position{}, &BlueprintError{
-				Err: fmt.Errorf("%q must be a string", v),
-				Pos: assignment.EqualsPos,
-			}
-		default:
-			panic(fmt.Errorf("unknown value type: %d", assignment.Value.Type()))
-		}
-	}
-}
-
 // Clones a build logic module by calling the factory method for its module type, and then cloning
 // property values.  Any values stored in the module object that are not stored in properties
 // structs will be lost.
@@ -1437,17 +1599,11 @@ func newVariant(module *moduleInfo, mutatorName string, variationName string,
 	}
 
 	newVariations := module.variant.variations.clone()
-	if newVariations == nil {
-		newVariations = make(variationMap)
-	}
-	newVariations[mutatorName] = variationName
+	newVariations.set(mutatorName, variationName)
 
 	newDependencyVariations := module.variant.dependencyVariations.clone()
 	if !local {
-		if newDependencyVariations == nil {
-			newDependencyVariations = make(variationMap)
-		}
-		newDependencyVariations[mutatorName] = variationName
+		newDependencyVariations.set(mutatorName, variationName)
 	}
 
 	return variant{newVariantName, newVariations, newDependencyVariations}
@@ -1511,7 +1667,7 @@ type depChooser func(source *moduleInfo, variationIndex, depIndex int, dep depIn
 
 func chooseDep(candidates modulesOrAliases, mutatorName, variationName string, defaultVariationName *string) (*moduleInfo, string) {
 	for _, m := range candidates {
-		if m.moduleOrAliasVariant().variations[mutatorName] == variationName {
+		if m.moduleOrAliasVariant().variations.get(mutatorName) == variationName {
 			return m.moduleOrAliasTarget(), ""
 		}
 	}
@@ -1519,7 +1675,7 @@ func chooseDep(candidates modulesOrAliases, mutatorName, variationName string, d
 	if defaultVariationName != nil {
 		// give it a second chance; match with defaultVariationName
 		for _, m := range candidates {
-			if m.moduleOrAliasVariant().variations[mutatorName] == *defaultVariationName {
+			if m.moduleOrAliasVariant().variations.get(mutatorName) == *defaultVariationName {
 				return m.moduleOrAliasTarget(), ""
 			}
 		}
@@ -1544,7 +1700,7 @@ func chooseDepExplicit(mutatorName string,
 
 func chooseDepInherit(mutatorName string, defaultVariationName *string) depChooser {
 	return func(source *moduleInfo, variationIndex, depIndex int, dep depInfo) (*moduleInfo, string) {
-		sourceVariation := source.variant.variations[mutatorName]
+		sourceVariation := source.variant.variations.get(mutatorName)
 		return chooseDep(dep.module.splitModules, mutatorName, sourceVariation, defaultVariationName)
 	}
 }
@@ -1569,12 +1725,15 @@ func (c *Context) convertDepsToVariation(module *moduleInfo, variationIndex int,
 }
 
 func (c *Context) prettyPrintVariant(variations variationMap) string {
-	names := make([]string, 0, len(variations))
+	var names []string
 	for _, m := range c.variantMutatorNames {
-		if v, ok := variations[m]; ok {
+		if v := variations.get(m); v != "" {
 			names = append(names, m+":"+v)
 		}
 	}
+	if len(names) == 0 {
+		return "<empty variant>"
+	}
 
 	return strings.Join(names, ",")
 }
@@ -1698,8 +1857,6 @@ func (c *Context) resolveDependencies(ctx context.Context, config interface{}) (
 	pprof.Do(ctx, pprof.Labels("blueprint", "ResolveDependencies"), func(ctx context.Context) {
 		c.initProviders()
 
-		c.liveGlobals = newLiveTracker(c, config)
-
 		errs = c.updateDependencies()
 		if len(errs) > 0 {
 			return
@@ -1784,7 +1941,7 @@ func (c *Context) addDependency(module *moduleInfo, config any, tag DependencyTa
 
 	possibleDeps := c.moduleGroupFromName(depName, module.namespace())
 	if possibleDeps == nil {
-		return nil, c.discoveredMissingDependencies(module, depName, nil)
+		return nil, c.discoveredMissingDependencies(module, depName, variationMap{})
 	}
 
 	if m := c.findExactVariantOrSingle(module, config, possibleDeps, false); m != nil {
@@ -1849,42 +2006,70 @@ func (c *Context) findReverseDependency(module *moduleInfo, config any, destName
 func (c *Context) applyTransitions(config any, module *moduleInfo, group *moduleGroup, variant variationMap,
 	requestedVariations []Variation) variationMap {
 	for _, transitionMutator := range c.transitionMutators {
-		// Apply the outgoing transition if it was not explicitly requested.
 		explicitlyRequested := slices.ContainsFunc(requestedVariations, func(variation Variation) bool {
 			return variation.Mutator == transitionMutator.name
 		})
-		sourceVariation := variant[transitionMutator.name]
+
+		sourceVariation := variant.get(transitionMutator.name)
 		outgoingVariation := sourceVariation
+
+		// Apply the outgoing transition if it was not explicitly requested.
 		if !explicitlyRequested {
 			ctx := &outgoingTransitionContextImpl{
-				transitionContextImpl{context: c, source: module, dep: nil, depTag: nil, config: config},
+				transitionContextImpl{context: c, source: module, dep: nil,
+					depTag: nil, postMutator: true, config: config},
 			}
 			outgoingVariation = transitionMutator.mutator.OutgoingTransition(ctx, sourceVariation)
 		}
 
-		// Find an appropriate module to use as the context for the IncomingTransition.
-		appliedIncomingTransition := false
+		earlierVariantCreatingMutators := c.variantCreatingMutatorOrder[:transitionMutator.variantCreatingMutatorIndex]
+		filteredVariant := variant.cloneMatching(earlierVariantCreatingMutators)
+
+		check := func(inputVariant variationMap) bool {
+			filteredInputVariant := inputVariant.cloneMatching(earlierVariantCreatingMutators)
+			return filteredInputVariant.equal(filteredVariant)
+		}
+
+		// Find an appropriate module to use as the context for the IncomingTransition.  First check if any of the
+		// saved inputVariants for the transition mutator match the filtered variant.
+		var matchingInputVariant *moduleInfo
 		for _, inputVariant := range transitionMutator.inputVariants[group] {
-			if inputVariant.variant.variations.subsetOf(variant) {
-				// Apply the incoming transition.
-				ctx := &incomingTransitionContextImpl{
-					transitionContextImpl{context: c, source: nil, dep: inputVariant,
-						depTag: nil, config: config},
-				}
+			if check(inputVariant.variant.variations) {
+				matchingInputVariant = inputVariant
+				break
+			}
+		}
 
-				finalVariation := transitionMutator.mutator.IncomingTransition(ctx, outgoingVariation)
-				if variant == nil {
-					variant = make(variationMap)
+		if matchingInputVariant == nil {
+			// If no inputVariants match, check all the variants of the module for a match.  This can happen if
+			// the mutator only created a single "" variant when it ran on this module.  Matching against all variants
+			// is slightly worse  than checking the input variants, as the selected variant could have been modified
+			// by a later mutator in a way that affects the results of IncomingTransition.
+			for _, moduleOrAlias := range group.modules {
+				if module := moduleOrAlias.module(); module != nil {
+					if check(module.variant.variations) {
+						matchingInputVariant = module
+						break
+					}
 				}
-				variant[transitionMutator.name] = finalVariation
-				appliedIncomingTransition = true
-				break
 			}
 		}
-		if !appliedIncomingTransition && !explicitlyRequested {
+
+		if matchingInputVariant != nil {
+			// Apply the incoming transition.
+			ctx := &incomingTransitionContextImpl{
+				transitionContextImpl{context: c, source: nil, dep: matchingInputVariant,
+					depTag: nil, postMutator: true, config: config},
+			}
+
+			finalVariation := transitionMutator.mutator.IncomingTransition(ctx, outgoingVariation)
+			variant.set(transitionMutator.name, finalVariation)
+		}
+
+		if (matchingInputVariant == nil && !explicitlyRequested) || variant.get(transitionMutator.name) == "" {
 			// The transition mutator didn't apply anything to the target variant, remove the variation unless it
 			// was explicitly requested when adding the dependency.
-			delete(variant, transitionMutator.name)
+			variant.delete(transitionMutator.name)
 		}
 	}
 
@@ -1909,27 +2094,40 @@ func (c *Context) findVariant(module *moduleInfo, config any,
 		}
 	}
 	for _, v := range requestedVariations {
-		if newVariant == nil {
-			newVariant = make(variationMap)
-		}
-		newVariant[v.Mutator] = v.Variation
+		newVariant.set(v.Mutator, v.Variation)
 	}
 
-	newVariant = c.applyTransitions(config, module, possibleDeps, newVariant, requestedVariations)
+	if !reverse {
+		newVariant = c.applyTransitions(config, module, possibleDeps, newVariant, requestedVariations)
+	}
 
-	check := func(variant variationMap) bool {
+	// check returns a bool for whether the requested newVariant matches the given variant from possibleDeps, and a
+	// divergence score.  A score of 0 is best match, and a positive integer is a worse match.
+	// For a non-far search, the score is always 0 as the match must always be exact.  For a far search,
+	// the score is the number of variants that are present in the given variant but not newVariant.
+	check := func(variant variationMap) (bool, int) {
 		if far {
-			return newVariant.subsetOf(variant)
+			if newVariant.subsetOf(variant) {
+				return true, variant.differenceKeysCount(newVariant)
+			}
 		} else {
-			return variant.equal(newVariant)
+			if variant.equal(newVariant) {
+				return true, 0
+			}
 		}
+		return false, math.MaxInt
 	}
 
 	var foundDep *moduleInfo
+	bestDivergence := math.MaxInt
 	for _, m := range possibleDeps.modules {
-		if check(m.moduleOrAliasVariant().variations) {
+		if match, divergence := check(m.moduleOrAliasVariant().variations); match && divergence < bestDivergence {
 			foundDep = m.moduleOrAliasTarget()
-			break
+			bestDivergence = divergence
+			if !far {
+				// non-far dependencies use equality, so only the first match needs to be checked.
+				break
+			}
 		}
 	}
 
@@ -1944,7 +2142,7 @@ func (c *Context) addVariationDependency(module *moduleInfo, config any, variati
 
 	possibleDeps := c.moduleGroupFromName(depName, module.namespace())
 	if possibleDeps == nil {
-		return nil, c.discoveredMissingDependencies(module, depName, nil)
+		return nil, c.discoveredMissingDependencies(module, depName, variationMap{})
 	}
 
 	foundDep, newVariant := c.findVariant(module, config, possibleDeps, variations, far, false)
@@ -2467,10 +2665,8 @@ func (c *Context) updateDependencies() (errs []error) {
 type jsonVariations []Variation
 
 type jsonModuleName struct {
-	Name                 string
-	Variant              string
-	Variations           jsonVariations
-	DependencyVariations jsonVariations
+	Name    string
+	Variant string
 }
 
 type jsonDep struct {
@@ -2487,26 +2683,10 @@ type JsonModule struct {
 	Module    map[string]interface{}
 }
 
-func toJsonVariationMap(vm variationMap) jsonVariations {
-	m := make(jsonVariations, 0, len(vm))
-	for k, v := range vm {
-		m = append(m, Variation{k, v})
-	}
-	sort.Slice(m, func(i, j int) bool {
-		if m[i].Mutator != m[j].Mutator {
-			return m[i].Mutator < m[j].Mutator
-		}
-		return m[i].Variation < m[j].Variation
-	})
-	return m
-}
-
 func jsonModuleNameFromModuleInfo(m *moduleInfo) *jsonModuleName {
 	return &jsonModuleName{
-		Name:                 m.Name(),
-		Variant:              m.variant.name,
-		Variations:           toJsonVariationMap(m.variant.variations),
-		DependencyVariations: toJsonVariationMap(m.variant.dependencyVariations),
+		Name:    m.Name(),
+		Variant: m.variant.name,
 	}
 }
 
@@ -2624,15 +2804,6 @@ func (c *Context) GetWeightedOutputsFromPredicate(predicate func(*JsonModule) (b
 	return outputToWeight
 }
 
-func inList(s string, l []string) bool {
-	for _, element := range l {
-		if s == element {
-			return true
-		}
-	}
-	return false
-}
-
 // PrintJSONGraph prints info of modules in a JSON file.
 func (c *Context) PrintJSONGraphAndActions(wGraph io.Writer, wActions io.Writer) {
 	modulesToGraph := make([]*JsonModule, 0)
@@ -2690,6 +2861,37 @@ func (c *Context) PrepareBuildActions(config interface{}) (deps []string, errs [
 	pprof.Do(c.Context, pprof.Labels("blueprint", "PrepareBuildActions"), func(ctx context.Context) {
 		c.buildActionsReady = false
 
+		c.liveGlobals = newLiveTracker(c, config)
+		// Add all the global rules/variable/pools here because when we restore from
+		// cache we don't have the build defs available to build the globals.
+		// TODO(b/356414070): Revisit this logic once we have a clearer picture about
+		// how the incremental build pieces fit together.
+		if c.GetIncrementalEnabled() {
+			for _, p := range packageContexts {
+				for _, v := range p.scope.variables {
+					err := c.liveGlobals.addVariable(v)
+					if err != nil {
+						errs = []error{err}
+						return
+					}
+				}
+				for _, v := range p.scope.rules {
+					_, err := c.liveGlobals.addRule(v)
+					if err != nil {
+						errs = []error{err}
+						return
+					}
+				}
+				for _, v := range p.scope.pools {
+					err := c.liveGlobals.addPool(v)
+					if err != nil {
+						errs = []error{err}
+						return
+					}
+				}
+			}
+		}
+
 		if !c.dependenciesReady {
 			var extraDeps []string
 			extraDeps, errs = c.resolveDependencies(ctx, config)
@@ -2913,6 +3115,7 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 		return false
 	}
 
+	createdVariations := false
 	var obsoleteLogicModules []Module
 
 	// Process errs and reverseDeps in a single goroutine
@@ -2938,6 +3141,7 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 						newModuleInfo[m.logicModule] = m
 					}
 				}
+				createdVariations = true
 			case <-done:
 				return
 			}
@@ -3012,13 +3216,21 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 			module.newDirectDeps = nil
 		}
 
-		findAliasTarget := func(variant variant) *moduleInfo {
+		findAliasTarget := func(oldVariant variant) *moduleInfo {
 			for _, moduleOrAlias := range group.modules {
+				module := moduleOrAlias.moduleOrAliasTarget()
+				if module.splitModules != nil {
+					// Ignore any old aliases that are pointing to modules that were obsoleted.
+					continue
+				}
 				if alias := moduleOrAlias.alias(); alias != nil {
-					if alias.variant.variations.equal(variant.variations) {
+					if alias.variant.variations.equal(oldVariant.variations) {
 						return alias.target
 					}
 				}
+				if module.variant.variations.equal(oldVariant.variations) {
+					return module
+				}
 			}
 			return nil
 		}
@@ -3044,9 +3256,14 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 
 	if isTransitionMutator {
 		mutator.transitionMutator.inputVariants = transitionMutatorInputVariants
+		mutator.transitionMutator.variantCreatingMutatorIndex = len(c.variantCreatingMutatorOrder)
 		c.transitionMutators = append(c.transitionMutators, mutator.transitionMutator)
 	}
 
+	if createdVariations {
+		c.variantCreatingMutatorOrder = append(c.variantCreatingMutatorOrder, mutator.name)
+	}
+
 	// Add in any new reverse dependencies that were added by the mutator
 	for module, deps := range reverseDeps {
 		sort.Sort(depSorter(deps))
@@ -3213,7 +3430,13 @@ func (c *Context) generateModuleBuildActions(config interface{},
 						}
 					}
 				}()
-				mctx.module.logicModule.GenerateBuildActions(mctx)
+				restored, cacheKey := mctx.restoreModuleBuildActions()
+				if !restored {
+					mctx.module.logicModule.GenerateBuildActions(mctx)
+				}
+				if cacheKey != nil {
+					mctx.cacheModuleBuildActions(cacheKey)
+				}
 			}()
 
 			mctx.module.finishedGenerateBuildActions = true
@@ -3537,7 +3760,7 @@ func (c *Context) handleReplacements(replacements []replace) []error {
 }
 
 func (c *Context) discoveredMissingDependencies(module *moduleInfo, depName string, depVariations variationMap) (errs []error) {
-	if depVariations != nil {
+	if !depVariations.empty() {
 		depName = depName + "{" + c.prettyPrintVariant(depVariations) + "}"
 	}
 	if c.allowMissingDependencies {
@@ -3833,57 +4056,6 @@ func (c *Context) checkForVariableReferenceCycles(
 	}
 }
 
-// AllTargets returns a map all the build target names to the rule used to build
-// them.  This is the same information that is output by running 'ninja -t
-// targets all'.  If this is called before PrepareBuildActions successfully
-// completes then ErrbuildActionsNotReady is returned.
-func (c *Context) AllTargets() (map[string]string, error) {
-	if !c.buildActionsReady {
-		return nil, ErrBuildActionsNotReady
-	}
-
-	targets := map[string]string{}
-	var collectTargets = func(actionDefs localBuildActions) error {
-		for _, buildDef := range actionDefs.buildDefs {
-			ruleName := c.nameTracker.Rule(buildDef.Rule)
-			for _, output := range append(buildDef.Outputs, buildDef.ImplicitOutputs...) {
-				outputValue, err := output.Eval(c.globalVariables)
-				if err != nil {
-					return err
-				}
-				targets[outputValue] = ruleName
-			}
-			for _, output := range append(buildDef.OutputStrings, buildDef.ImplicitOutputStrings...) {
-				targets[output] = ruleName
-			}
-		}
-		return nil
-	}
-	// Collect all the module build targets.
-	for _, module := range c.moduleInfo {
-		if err := collectTargets(module.actionDefs); err != nil {
-			return nil, err
-		}
-	}
-
-	// Collect all the singleton build targets.
-	for _, info := range c.singletonInfo {
-		if err := collectTargets(info.actionDefs); err != nil {
-			return nil, err
-		}
-	}
-
-	return targets, nil
-}
-
-func (c *Context) OutDir() (string, error) {
-	if c.outDir != nil {
-		return c.outDir.Eval(c.globalVariables)
-	} else {
-		return "", nil
-	}
-}
-
 // ModuleTypePropertyStructs returns a mapping from module type name to a list of pointers to
 // property structs returned by the factory for that module type.
 func (c *Context) ModuleTypePropertyStructs() map[string][]interface{} {
@@ -3995,6 +4167,12 @@ func (c *Context) VisitAllModulesIf(pred func(Module) bool,
 }
 
 func (c *Context) VisitDirectDeps(module Module, visit func(Module)) {
+	c.VisitDirectDepsWithTags(module, func(m Module, _ DependencyTag) {
+		visit(m)
+	})
+}
+
+func (c *Context) VisitDirectDepsWithTags(module Module, visit func(Module, DependencyTag)) {
 	topModule := c.moduleInfo[module]
 
 	var visiting *moduleInfo
@@ -4008,7 +4186,7 @@ func (c *Context) VisitDirectDeps(module Module, visit func(Module)) {
 
 	for _, dep := range topModule.directDeps {
 		visiting = dep.module
-		visit(dep.module.logicModule)
+		visit(dep.module.logicModule, dep.tag)
 	}
 }
 
@@ -4471,11 +4649,16 @@ func (s moduleSorter) Swap(i, j int) {
 }
 
 func GetNinjaShardFiles(ninjaFile string) []string {
+	suffix := ".ninja"
+	if !strings.HasSuffix(ninjaFile, suffix) {
+		panic(fmt.Errorf("ninja file name in wrong format : %s", ninjaFile))
+	}
+	base := strings.TrimSuffix(ninjaFile, suffix)
 	ninjaShardCnt := 10
 	fileNames := make([]string, ninjaShardCnt)
 
 	for i := 0; i < ninjaShardCnt; i++ {
-		fileNames[i] = fmt.Sprintf("%s.%d", ninjaFile, i)
+		fileNames[i] = fmt.Sprintf("%s.%d%s", base, i, suffix)
 	}
 	return fileNames
 }
@@ -4485,12 +4668,29 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 	defer c.EndEvent("modules")
 
 	modules := make([]*moduleInfo, 0, len(c.moduleInfo))
+	incrementalModules := make([]*moduleInfo, 0, 200)
+
 	for _, module := range c.moduleInfo {
+		if module.buildActionCacheKey != nil {
+			incrementalModules = append(incrementalModules, module)
+			continue
+		}
 		modules = append(modules, module)
 	}
 	sort.Sort(moduleSorter{modules, c.nameInterface})
 
-	phonys := c.deduplicateOrderOnlyDeps(modules)
+	phonys := c.deduplicateOrderOnlyDeps(append(modules, incrementalModules...))
+	if err := orderOnlyForIncremental(c, incrementalModules, phonys); err != nil {
+		return err
+	}
+
+	c.EventHandler.Do("sort_phony_builddefs", func() {
+		// sorting for determinism, the phony output names are stable
+		sort.Slice(phonys.buildDefs, func(i int, j int) bool {
+			return phonys.buildDefs[i].OutputStrings[0] < phonys.buildDefs[j].OutputStrings[0]
+		})
+	})
+
 	if err := c.writeLocalBuildActions(nw, phonys); err != nil {
 		return err
 	}
@@ -4511,7 +4711,7 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 			wg.Add(1)
 			go func(file string, batchModules []*moduleInfo) {
 				defer wg.Done()
-				f, err := os.OpenFile(JoinPath(c.SrcDir(), file), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, OutFilePermissions)
+				f, err := c.fs.OpenFile(JoinPath(c.SrcDir(), file), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, OutFilePermissions)
 				if err != nil {
 					errorCh <- fmt.Errorf("error opening Ninja file shard: %s", err)
 					return
@@ -4537,6 +4737,20 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 			}(file, batchModules)
 			nw.Subninja(file)
 		}
+
+		if c.GetIncrementalEnabled() {
+			file := fmt.Sprintf("%s.incremental", ninjaFileName)
+			wg.Add(1)
+			go func() {
+				defer wg.Done()
+				err := writeIncrementalModules(c, file, incrementalModules, headerTemplate)
+				if err != nil {
+					errorCh <- err
+				}
+			}()
+			nw.Subninja(file)
+		}
+
 		go func() {
 			wg.Wait()
 			close(errorCh)
@@ -4555,6 +4769,108 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 	}
 }
 
+func orderOnlyForIncremental(c *Context, modules []*moduleInfo, phonys *localBuildActions) error {
+	for _, mod := range modules {
+		// find the order only strings of the incremental module, it can come from
+		// the cache or from buildDefs depending on if the module was skipped or not.
+		var orderOnlyStrings *[]string
+		if mod.incrementalRestored {
+			orderOnlyStrings = mod.orderOnlyStrings
+		} else {
+			orderOnlyStrings = new([]string)
+			for _, b := range mod.actionDefs.buildDefs {
+				// We do similar check when creating phonys in deduplicateOrderOnlyDeps as well
+				if len(b.OrderOnly) > 0 {
+					return fmt.Errorf("order only shouldn't be used: %s", mod.Name())
+				}
+				for _, str := range b.OrderOnlyStrings {
+					if strings.HasPrefix(str, "dedup-") {
+						*orderOnlyStrings = append(*orderOnlyStrings, str)
+					}
+				}
+			}
+		}
+
+		if orderOnlyStrings == nil || len(*orderOnlyStrings) == 0 {
+			continue
+		}
+
+		// update the order only string cache with the info found above.
+		if data, ok := c.buildActionsToCache[*mod.buildActionCacheKey]; ok {
+			data.OrderOnlyStrings = orderOnlyStrings
+		}
+
+		if !mod.incrementalRestored {
+			continue
+		}
+
+		// if the module is skipped, the order only string that we restored from the
+		// cache might not exist anymore. For example, if two modules shared the same
+		// set of order only strings initially, deduplicateOrderOnlyDeps would create
+		// a dedup-* phony and replace the order only string with this phony for these
+		// two modules. If one of the module had its order only strings changed, and
+		// we skip the other module in the next build, the dedup-* phony would not
+		// in the phony list anymore, so we need to add it here in order to avoid
+		// writing the ninja statements for the skipped module, otherwise it would
+		// reference a dedup-* phony that no longer exists.
+		for _, dep := range *orderOnlyStrings {
+			// nothing changed to this phony, the cached value is still valid
+			if _, ok := c.orderOnlyStringsToCache[dep]; ok {
+				continue
+			}
+			orderOnlyStrings, ok := c.orderOnlyStringsFromCache[dep]
+			if !ok {
+				return fmt.Errorf("no cached value found for order only dep: %s", dep)
+			}
+			phony := buildDef{
+				Rule:          Phony,
+				OutputStrings: []string{dep},
+				InputStrings:  orderOnlyStrings,
+				Optional:      true,
+			}
+			phonys.buildDefs = append(phonys.buildDefs, &phony)
+			c.orderOnlyStringsToCache[dep] = orderOnlyStrings
+		}
+	}
+	return nil
+}
+func writeIncrementalModules(c *Context, baseFile string, modules []*moduleInfo, headerTemplate *template.Template) error {
+	bf, err := c.fs.OpenFile(JoinPath(c.SrcDir(), baseFile), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, OutFilePermissions)
+	if err != nil {
+		return err
+	}
+	defer bf.Close()
+	bBuf := bufio.NewWriterSize(bf, 16*1024*1024)
+	defer bBuf.Flush()
+	bWriter := newNinjaWriter(bBuf)
+	ninjaPath := filepath.Join(filepath.Dir(baseFile), strings.ReplaceAll(filepath.Base(baseFile), ".", "_"))
+	err = os.MkdirAll(JoinPath(c.SrcDir(), ninjaPath), 0755)
+	if err != nil {
+		return err
+	}
+	for _, module := range modules {
+		moduleFile := filepath.Join(ninjaPath, module.ModuleCacheKey()+".ninja")
+		if !module.incrementalRestored {
+			err := func() error {
+				mf, err := c.fs.OpenFile(JoinPath(c.SrcDir(), moduleFile), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, OutFilePermissions)
+				if err != nil {
+					return err
+				}
+				defer mf.Close()
+				mBuf := bufio.NewWriterSize(mf, 4*1024*1024)
+				defer mBuf.Flush()
+				mWriter := newNinjaWriter(mBuf)
+				return c.writeModuleAction([]*moduleInfo{module}, mWriter, headerTemplate)
+			}()
+			if err != nil {
+				return err
+			}
+		}
+		bWriter.Subninja(moduleFile)
+	}
+	return nil
+}
+
 func (c *Context) writeModuleAction(modules []*moduleInfo, nw *ninjaWriter, headerTemplate *template.Template) error {
 	buf := bytes.NewBuffer(nil)
 
@@ -4562,7 +4878,6 @@ func (c *Context) writeModuleAction(modules []*moduleInfo, nw *ninjaWriter, head
 		if len(module.actionDefs.variables)+len(module.actionDefs.rules)+len(module.actionDefs.buildDefs) == 0 {
 			continue
 		}
-
 		buf.Reset()
 
 		// In order to make the bootstrap build manifest independent of the
@@ -4682,16 +4997,14 @@ func (c *Context) SetBeforePrepareBuildActionsHook(hookFn func() error) {
 // to be extracted as a phony output
 type phonyCandidate struct {
 	sync.Once
-	phony            *buildDef      // the phony buildDef that wraps the set
-	first            *buildDef      // the first buildDef that uses this set
-	orderOnlyStrings []string       // the original OrderOnlyStrings of the first buildDef that uses this set
-	orderOnly        []*ninjaString // the original OrderOnly of the first buildDef that uses this set
+	phony             *buildDef // the phony buildDef that wraps the set
+	first             *buildDef // the first buildDef that uses this set
+	orderOnlyStrings  []string  // the original OrderOnlyStrings of the first buildDef that uses this set
+	usedByIncremental bool      // if the phony is used by any incremental module
 }
 
 // keyForPhonyCandidate gives a unique identifier for a set of deps.
-// If any of the deps use a variable, we return an empty string to signal
-// that this set of deps is ineligible for extraction.
-func keyForPhonyCandidate(deps []*ninjaString, stringDeps []string) uint64 {
+func keyForPhonyCandidate(stringDeps []string) uint64 {
 	hasher := fnv.New64a()
 	write := func(s string) {
 		// The hasher doesn't retain or modify the input slice, so pass the string data directly to avoid
@@ -4701,12 +5014,6 @@ func keyForPhonyCandidate(deps []*ninjaString, stringDeps []string) uint64 {
 			panic(fmt.Errorf("write failed: %w", err))
 		}
 	}
-	for _, d := range deps {
-		if len(d.Variables()) != 0 {
-			return 0
-		}
-		write(d.Value(nil))
-	}
 	for _, d := range stringDeps {
 		write(d)
 	}
@@ -4717,37 +5024,34 @@ func keyForPhonyCandidate(deps []*ninjaString, stringDeps []string) uint64 {
 // If `b.OrderOnly` is not present in `candidates`, it gets stored.
 // But if `b.OrderOnly` already exists in `candidates`, then `b.OrderOnly`
 // (and phonyCandidate#first.OrderOnly) will be replaced with phonyCandidate#phony.Outputs
-func scanBuildDef(candidates *sync.Map, b *buildDef) {
-	key := keyForPhonyCandidate(b.OrderOnly, b.OrderOnlyStrings)
-	if key == 0 {
-		return
-	}
+func scanBuildDef(candidates *sync.Map, b *buildDef, incremental bool) {
+	key := keyForPhonyCandidate(b.OrderOnlyStrings)
 	if v, loaded := candidates.LoadOrStore(key, &phonyCandidate{
-		first:            b,
-		orderOnly:        b.OrderOnly,
-		orderOnlyStrings: b.OrderOnlyStrings,
+		first:             b,
+		orderOnlyStrings:  b.OrderOnlyStrings,
+		usedByIncremental: incremental,
 	}); loaded {
 		m := v.(*phonyCandidate)
-		if slices.EqualFunc(m.orderOnly, b.OrderOnly, ninjaStringsEqual) &&
-			slices.Equal(m.orderOnlyStrings, b.OrderOnlyStrings) {
+		if slices.Equal(m.orderOnlyStrings, b.OrderOnlyStrings) {
 			m.Do(func() {
 				// this is the second occurrence and hence it makes sense to
 				// extract it as a phony output
 				m.phony = &buildDef{
 					Rule:          Phony,
 					OutputStrings: []string{fmt.Sprintf("dedup-%x", key)},
-					Inputs:        m.first.OrderOnly, //we could also use b.OrderOnly
 					InputStrings:  m.first.OrderOnlyStrings,
 					Optional:      true,
 				}
 				// the previously recorded build-def, which first had these deps as its
 				// order-only deps, should now use this phony output instead
 				m.first.OrderOnlyStrings = m.phony.OutputStrings
-				m.first.OrderOnly = nil
 				m.first = nil
 			})
 			b.OrderOnlyStrings = m.phony.OutputStrings
-			b.OrderOnly = nil
+			// don't override the value with false if it was set to true already
+			if incremental {
+				m.usedByIncremental = incremental
+			}
 		}
 	}
 }
@@ -4763,9 +5067,11 @@ func (c *Context) deduplicateOrderOnlyDeps(modules []*moduleInfo) *localBuildAct
 	candidates := sync.Map{} //used as map[key]*candidate
 	parallelVisit(modules, unorderedVisitorImpl{}, parallelVisitLimit,
 		func(m *moduleInfo, pause chan<- pauseSpec) bool {
+			incremental := m.buildActionCacheKey != nil
 			for _, b := range m.actionDefs.buildDefs {
-				if len(b.OrderOnly) > 0 || len(b.OrderOnlyStrings) > 0 {
-					scanBuildDef(&candidates, b)
+				// The dedup logic doesn't handle the case where OrderOnly is not empty
+				if len(b.OrderOnly) == 0 && len(b.OrderOnlyStrings) > 0 {
+					scanBuildDef(&candidates, b, incremental)
 				}
 			}
 			return false
@@ -4777,17 +5083,14 @@ func (c *Context) deduplicateOrderOnlyDeps(modules []*moduleInfo) *localBuildAct
 		candidate := v.(*phonyCandidate)
 		if candidate.phony != nil {
 			phonys = append(phonys, candidate.phony)
+			if candidate.usedByIncremental {
+				c.orderOnlyStringsToCache[candidate.phony.OutputStrings[0]] =
+					candidate.phony.InputStrings
+			}
 		}
 		return true
 	})
 
-	c.EventHandler.Do("sort_phony_builddefs", func() {
-		// sorting for determinism, the phony output names are stable
-		sort.Slice(phonys, func(i int, j int) bool {
-			return phonys[i].OutputStrings[0] < phonys[j].OutputStrings[0]
-		})
-	})
-
 	return &localBuildActions{buildDefs: phonys}
 }
 
diff --git a/context_test.go b/context_test.go
index d43b243d2c..bccabc5a8b 100644
--- a/context_test.go
+++ b/context_test.go
@@ -19,14 +19,17 @@ import (
 	"errors"
 	"fmt"
 	"hash/fnv"
+	"os"
 	"reflect"
 	"strconv"
 	"strings"
 	"sync"
 	"testing"
+	"text/scanner"
 	"time"
 
 	"github.com/google/blueprint/parser"
+	"github.com/google/blueprint/proptools"
 )
 
 type Walker interface {
@@ -61,33 +64,53 @@ type depsProvider interface {
 	IgnoreDeps() []string
 }
 
-type fooModule struct {
+type IncrementalTestProvider struct {
+	Value string
+}
+
+var IncrementalTestProviderKey = NewProvider[IncrementalTestProvider]()
+
+type baseTestModule struct {
 	SimpleName
 	properties struct {
 		Deps         []string
 		Ignored_deps []string
-		Foo          string
 	}
+	GenerateBuildActionsCalled bool
 }
 
-func newFooModule() (Module, []interface{}) {
-	m := &fooModule{}
-	return m, []interface{}{&m.properties, &m.SimpleName.Properties}
+func (b *baseTestModule) Deps() []string {
+	return b.properties.Deps
 }
 
-func (f *fooModule) GenerateBuildActions(ModuleContext) {
+func (b *baseTestModule) IgnoreDeps() []string {
+	return b.properties.Ignored_deps
 }
 
-func (f *fooModule) Deps() []string {
-	return f.properties.Deps
+var pctx PackageContext
+
+func init() {
+	pctx = NewPackageContext("android/blueprint")
+}
+func (b *baseTestModule) GenerateBuildActions(ctx ModuleContext) {
+	b.GenerateBuildActionsCalled = true
+	outputFile := ctx.ModuleName() + "_phony_output"
+	ctx.Build(pctx, BuildParams{
+		Rule:    Phony,
+		Outputs: []string{outputFile},
+	})
+	SetProvider(ctx, IncrementalTestProviderKey, IncrementalTestProvider{
+		Value: ctx.ModuleName(),
+	})
 }
 
-func (f *fooModule) IgnoreDeps() []string {
-	return f.properties.Ignored_deps
+type fooModule struct {
+	baseTestModule
 }
 
-func (f *fooModule) Foo() string {
-	return f.properties.Foo
+func newFooModule() (Module, []interface{}) {
+	m := &fooModule{}
+	return m, []interface{}{&m.baseTestModule.properties, &m.SimpleName.Properties}
 }
 
 func (f *fooModule) Walk() bool {
@@ -96,35 +119,29 @@ func (f *fooModule) Walk() bool {
 
 type barModule struct {
 	SimpleName
-	properties struct {
-		Deps         []string
-		Ignored_deps []string
-		Bar          bool
-	}
+	baseTestModule
 }
 
 func newBarModule() (Module, []interface{}) {
 	m := &barModule{}
-	return m, []interface{}{&m.properties, &m.SimpleName.Properties}
-}
-
-func (b *barModule) Deps() []string {
-	return b.properties.Deps
+	return m, []interface{}{&m.baseTestModule.properties, &m.SimpleName.Properties}
 }
 
-func (b *barModule) IgnoreDeps() []string {
-	return b.properties.Ignored_deps
+func (b *barModule) Walk() bool {
+	return false
 }
 
-func (b *barModule) GenerateBuildActions(ModuleContext) {
+type incrementalModule struct {
+	SimpleName
+	baseTestModule
+	IncrementalModule
 }
 
-func (b *barModule) Bar() bool {
-	return b.properties.Bar
-}
+var _ Incremental = &incrementalModule{}
 
-func (b *barModule) Walk() bool {
-	return false
+func newIncrementalModule() (Module, []interface{}) {
+	m := &incrementalModule{}
+	return m, []interface{}{&m.baseTestModule.properties, &m.SimpleName.Properties}
 }
 
 type walkerDepsTag struct {
@@ -614,11 +631,15 @@ func Test_findVariant(t *testing.T) {
 		variant: variant{
 			name: "normal_local",
 			variations: variationMap{
-				"normal": "normal",
-				"local":  "local",
+				map[string]string{
+					"normal": "normal",
+					"local":  "local",
+				},
 			},
 			dependencyVariations: variationMap{
-				"normal": "normal",
+				map[string]string{
+					"normal": "normal",
+				},
 			},
 		},
 	}
@@ -679,7 +700,9 @@ func Test_findVariant(t *testing.T) {
 					variant: variant{
 						name: "normal",
 						variations: variationMap{
-							"normal": "normal",
+							map[string]string{
+								"normal": "normal",
+							},
 						},
 					},
 				},
@@ -697,7 +720,9 @@ func Test_findVariant(t *testing.T) {
 					variant: variant{
 						name: "normal",
 						variations: variationMap{
-							"normal": "normal",
+							map[string]string{
+								"normal": "normal",
+							},
 						},
 					},
 					target: 1,
@@ -706,8 +731,10 @@ func Test_findVariant(t *testing.T) {
 					variant: variant{
 						name: "normal_a",
 						variations: variationMap{
-							"normal": "normal",
-							"a":      "a",
+							map[string]string{
+								"normal": "normal",
+								"a":      "a",
+							},
 						},
 					},
 				},
@@ -725,8 +752,10 @@ func Test_findVariant(t *testing.T) {
 					variant: variant{
 						name: "normal_a",
 						variations: variationMap{
-							"normal": "normal",
-							"a":      "a",
+							map[string]string{
+								"normal": "normal",
+								"a":      "a",
+							},
 						},
 					},
 				},
@@ -743,14 +772,16 @@ func Test_findVariant(t *testing.T) {
 				&moduleInfo{
 					variant: variant{
 						name:       "",
-						variations: nil,
+						variations: variationMap{},
 					},
 				},
 				&moduleInfo{
 					variant: variant{
 						name: "far",
 						variations: variationMap{
-							"far": "far",
+							map[string]string{
+								"far": "far",
+							},
 						},
 					},
 				},
@@ -768,7 +799,9 @@ func Test_findVariant(t *testing.T) {
 					variant: variant{
 						name: "far",
 						variations: variationMap{
-							"far": "far",
+							map[string]string{
+								"far": "far",
+							},
 						},
 					},
 					target: 2,
@@ -777,8 +810,10 @@ func Test_findVariant(t *testing.T) {
 					variant: variant{
 						name: "far_a",
 						variations: variationMap{
-							"far": "far",
-							"a":   "a",
+							map[string]string{
+								"far": "far",
+								"a":   "a",
+							},
 						},
 					},
 				},
@@ -786,8 +821,10 @@ func Test_findVariant(t *testing.T) {
 					variant: variant{
 						name: "far_b",
 						variations: variationMap{
-							"far": "far",
-							"b":   "b",
+							map[string]string{
+								"far": "far",
+								"b":   "b",
+							},
 						},
 					},
 				},
@@ -805,7 +842,9 @@ func Test_findVariant(t *testing.T) {
 					variant: variant{
 						name: "far",
 						variations: variationMap{
-							"far": "far",
+							map[string]string{
+								"far": "far",
+							},
 						},
 					},
 					target: 1,
@@ -814,8 +853,10 @@ func Test_findVariant(t *testing.T) {
 					variant: variant{
 						name: "far_a",
 						variations: variationMap{
-							"far": "far",
-							"a":   "a",
+							map[string]string{
+								"far": "far",
+								"a":   "a",
+							},
 						},
 					},
 				},
@@ -1489,3 +1530,337 @@ func TestSourceRootDirs(t *testing.T) {
 		})
 	}
 }
+
+func incrementalSetup(t *testing.T) *Context {
+	ctx := NewContext()
+	fileSystem := map[string][]byte{
+		"Android.bp": []byte(`
+			incremental_module {
+					name: "MyIncrementalModule",
+					deps: ["MyBarModule"],
+			}
+
+			bar_module {
+					name: "MyBarModule",
+			}
+		`),
+	}
+	ctx.MockFileSystem(fileSystem)
+	ctx.RegisterBottomUpMutator("deps", depsMutator)
+	ctx.RegisterModuleType("incremental_module", newIncrementalModule)
+	ctx.RegisterModuleType("bar_module", newBarModule)
+
+	_, errs := ctx.ParseBlueprintsFiles("Android.bp", nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected parse errors:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+
+	_, errs = ctx.ResolveDependencies(nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected dep errors:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+
+	return ctx
+}
+
+func incrementalSetupForRestore(t *testing.T, orderOnlyStrings *[]string) (*Context, any) {
+	ctx := incrementalSetup(t)
+	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
+	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
+
+	providerHashes := make([]uint64, len(providerRegistry))
+	// Use fixed value since SetProvider hasn't been called yet, so we can't go
+	// through the providers of the module.
+	for k, v := range map[providerKey]any{
+		IncrementalTestProviderKey.providerKey: IncrementalTestProvider{
+			Value: barInfo.Name(),
+		},
+	} {
+		hash, err := proptools.CalculateHash(v)
+		if err != nil {
+			panic(fmt.Sprintf("Can't hash value of providers"))
+		}
+		providerHashes[k.id] = hash
+	}
+	cacheKey := calculateHashKey(incInfo, [][]uint64{providerHashes})
+	var providerValue any = IncrementalTestProvider{Value: "MyIncrementalModule"}
+	toCache := BuildActionCache{
+		cacheKey: &BuildActionCachedData{
+			Pos: &scanner.Position{
+				Filename: "Android.bp",
+				Line:     2,
+				Column:   4,
+				Offset:   4,
+			},
+			Providers: []CachedProvider{{
+				Id:    &IncrementalTestProviderKey.providerKey,
+				Value: &providerValue,
+			}},
+			OrderOnlyStrings: orderOnlyStrings,
+		},
+	}
+	ctx.SetIncrementalEnabled(true)
+	ctx.SetIncrementalAnalysis(true)
+	ctx.buildActionsFromCache = toCache
+
+	return ctx, providerValue
+}
+
+func calculateHashKey(m *moduleInfo, providerHashes [][]uint64) BuildActionCacheKey {
+	hash, err := proptools.CalculateHash(m.properties)
+	if err != nil {
+		panic(newPanicErrorf(err, "failed to calculate properties hash"))
+	}
+	cacheInput := new(BuildActionCacheInput)
+	cacheInput.PropertiesHash = hash
+	cacheInput.ProvidersHash = providerHashes
+	hash, err = proptools.CalculateHash(&cacheInput)
+	if err != nil {
+		panic(newPanicErrorf(err, "failed to calculate cache input hash"))
+	}
+	return BuildActionCacheKey{
+		Id:        m.ModuleCacheKey(),
+		InputHash: hash,
+	}
+}
+
+func TestCacheBuildActions(t *testing.T) {
+	ctx := incrementalSetup(t)
+	ctx.SetIncrementalEnabled(true)
+
+	_, errs := ctx.PrepareBuildActions(nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected errors calling generateModuleBuildActions:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+
+	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
+	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
+	if len(ctx.buildActionsToCache) != 1 {
+		t.Errorf("build actions are not cached for the incremental module")
+	}
+	cacheKey := calculateHashKey(incInfo, [][]uint64{barInfo.providerInitialValueHashes})
+	cache := ctx.buildActionsToCache[cacheKey]
+	if cache == nil {
+		t.Errorf("failed to find cached build actions for the incremental module")
+	}
+	var providerValue any = IncrementalTestProvider{Value: "MyIncrementalModule"}
+	expectedCache := BuildActionCachedData{
+		Pos: &scanner.Position{
+			Filename: "Android.bp",
+			Line:     2,
+			Column:   4,
+			Offset:   4,
+		},
+		Providers: []CachedProvider{{
+			Id:    &IncrementalTestProviderKey.providerKey,
+			Value: &providerValue,
+		}},
+	}
+	if !reflect.DeepEqual(expectedCache, *cache) {
+		t.Errorf("expected: %v actual %v", expectedCache, *cache)
+	}
+}
+
+func TestRestoreBuildActions(t *testing.T) {
+	ctx, providerValue := incrementalSetupForRestore(t, nil)
+	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
+	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
+	_, errs := ctx.PrepareBuildActions(nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected errors calling generateModuleBuildActions:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+
+	// Verify that the GenerateBuildActions was skipped for the incremental module
+	incRerun := incInfo.logicModule.(*incrementalModule).GenerateBuildActionsCalled
+	barRerun := barInfo.logicModule.(*barModule).GenerateBuildActionsCalled
+	if incRerun || !barRerun {
+		t.Errorf("failed to skip/rerun GenerateBuildActions: %t %t", incRerun, barRerun)
+	}
+	// Verify that the provider is set correctly for the incremental module
+	if !reflect.DeepEqual(incInfo.providers[IncrementalTestProviderKey.id], providerValue) {
+		t.Errorf("provider is not set correctly when restoring from cache")
+	}
+}
+
+func TestSkipNinjaForCacheHit(t *testing.T) {
+	ctx, _ := incrementalSetupForRestore(t, nil)
+	_, errs := ctx.PrepareBuildActions(nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected errors calling generateModuleBuildActions:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+
+	buf := bytes.NewBuffer(nil)
+	w := newNinjaWriter(buf)
+	ctx.writeAllModuleActions(w, true, "test.ninja")
+	// Verify that soong updated the ninja file for the bar module and skipped the
+	// ninja file writing of the incremental module
+	file, err := ctx.fs.Open("test.0.ninja")
+	if err != nil {
+		t.Errorf("no ninja file for MyBarModule")
+	}
+	content := make([]byte, 1024)
+	file.Read(content)
+	if !strings.Contains(string(content), "build MyBarModule_phony_output: phony") {
+		t.Errorf("ninja file doesn't have build statements for MyBarModule: %s", string(content))
+	}
+
+	file, err = ctx.fs.Open("test_ninja_incremental/.-MyIncrementalModule-none-incremental_module.ninja")
+	if !os.IsNotExist(err) {
+		t.Errorf("shouldn't generate ninja file for MyIncrementalModule: %s", err.Error())
+	}
+}
+
+func TestNotSkipNinjaForCacheMiss(t *testing.T) {
+	ctx := incrementalSetup(t)
+	ctx.SetIncrementalEnabled(true)
+	ctx.SetIncrementalAnalysis(true)
+	_, errs := ctx.PrepareBuildActions(nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected errors calling generateModuleBuildActions:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+
+	buf := bytes.NewBuffer(nil)
+	w := newNinjaWriter(buf)
+	ctx.writeAllModuleActions(w, true, "test.ninja")
+	// Verify that soong updated the ninja files for both the bar module and the
+	// incremental module
+	file, err := ctx.fs.Open("test.0.ninja")
+	if err != nil {
+		t.Errorf("no ninja file for MyBarModule")
+	}
+	content := make([]byte, 1024)
+	file.Read(content)
+	if !strings.Contains(string(content), "build MyBarModule_phony_output: phony") {
+		t.Errorf("ninja file doesn't have build statements for MyBarModule: %s", string(content))
+	}
+
+	file, err = ctx.fs.Open("test_ninja_incremental/.-MyIncrementalModule-none-incremental_module.ninja")
+	if err != nil {
+		t.Errorf("no ninja file for MyIncrementalModule")
+	}
+	file.Read(content)
+	if !strings.Contains(string(content), "build MyIncrementalModule_phony_output: phony") {
+		t.Errorf("ninja file doesn't have build statements for MyIncrementalModule: %s", string(content))
+	}
+}
+
+func TestOrderOnlyStringsCaching(t *testing.T) {
+	ctx := incrementalSetup(t)
+	ctx.SetIncrementalEnabled(true)
+	_, errs := ctx.PrepareBuildActions(nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected errors calling generateModuleBuildActions:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
+	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
+	bDef := buildDef{
+		Rule:             Phony,
+		OrderOnlyStrings: []string{"test.lib"},
+	}
+	incInfo.actionDefs.buildDefs = append(incInfo.actionDefs.buildDefs, &bDef)
+	barInfo.actionDefs.buildDefs = append(barInfo.actionDefs.buildDefs, &bDef)
+
+	buf := bytes.NewBuffer(nil)
+	w := newNinjaWriter(buf)
+	ctx.writeAllModuleActions(w, true, "test.ninja")
+
+	verifyOrderOnlyStringsCache(t, ctx, incInfo, barInfo)
+}
+
+func TestOrderOnlyStringsRestoring(t *testing.T) {
+	phony := "dedup-d479e9a8133ff998"
+	orderOnlyStrings := []string{phony}
+	ctx, _ := incrementalSetupForRestore(t, &orderOnlyStrings)
+	ctx.orderOnlyStringsFromCache = make(OrderOnlyStringsCache)
+	ctx.orderOnlyStringsFromCache[phony] = []string{"test.lib"}
+	_, errs := ctx.PrepareBuildActions(nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected errors calling generateModuleBuildActions:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+
+	buf := bytes.NewBuffer(nil)
+	w := newNinjaWriter(buf)
+	ctx.writeAllModuleActions(w, true, "test.ninja")
+
+	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
+	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
+	verifyOrderOnlyStringsCache(t, ctx, incInfo, barInfo)
+
+	// Verify dedup-d479e9a8133ff998 is still written to the common ninja file even
+	// though MyBarModule no longer uses it.
+	expected := strings.Join([]string{"build", phony + ":", "phony", "test.lib"}, " ")
+	if !strings.Contains(buf.String(), expected) {
+		t.Errorf("phony target not found: %s", buf.String())
+	}
+}
+
+func verifyOrderOnlyStringsCache(t *testing.T, ctx *Context, incInfo, barInfo *moduleInfo) {
+	// Verify that soong cache all the order only strings that are used by the
+	// incremental modules
+	ok, key := mapContainsValue(ctx.orderOnlyStringsToCache, "test.lib")
+	if !ok {
+		t.Errorf("no order only strings used by incremetnal modules cached: %v", ctx.orderOnlyStringsToCache)
+	}
+
+	// Verify that the dedup-* order only strings used by MyIncrementalModule is
+	// cached along with its other cached values
+	cacheKey := calculateHashKey(incInfo, [][]uint64{barInfo.providerInitialValueHashes})
+	cache := ctx.buildActionsToCache[cacheKey]
+	if cache == nil {
+		t.Errorf("failed to find cached build actions for the incremental module")
+	}
+	if !listContainsValue(*cache.OrderOnlyStrings, key) {
+		t.Errorf("no order only strings cached for MyIncrementalModule: %v", *cache.OrderOnlyStrings)
+	}
+}
+
+func listContainsValue[K comparable](l []K, target K) bool {
+	for _, value := range l {
+		if value == target {
+			return true
+		}
+	}
+	return false
+}
+
+func mapContainsValue[K comparable, V comparable](m map[K][]V, target V) (bool, K) {
+	for k, v := range m {
+		if listContainsValue(v, target) {
+			return true, k
+		}
+	}
+	var key K
+	return false, key
+}
diff --git a/incremental.go b/incremental.go
new file mode 100644
index 0000000000..ca899cb6a6
--- /dev/null
+++ b/incremental.go
@@ -0,0 +1,54 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package blueprint
+
+import (
+	"text/scanner"
+)
+
+type BuildActionCacheKey struct {
+	Id        string
+	InputHash uint64
+}
+
+type CachedProvider struct {
+	Id    *providerKey
+	Value *any
+}
+
+type BuildActionCachedData struct {
+	Providers        []CachedProvider
+	Pos              *scanner.Position
+	OrderOnlyStrings *[]string
+}
+
+type BuildActionCache = map[BuildActionCacheKey]*BuildActionCachedData
+
+type OrderOnlyStringsCache map[string][]string
+
+type BuildActionCacheInput struct {
+	PropertiesHash uint64
+	ProvidersHash  [][]uint64
+}
+
+type Incremental interface {
+	IncrementalSupported() bool
+}
+
+type IncrementalModule struct{}
+
+func (m *IncrementalModule) IncrementalSupported() bool {
+	return true
+}
diff --git a/module_ctx.go b/module_ctx.go
index 920b74e76d..8c8e81c66d 100644
--- a/module_ctx.go
+++ b/module_ctx.go
@@ -191,6 +191,7 @@ type EarlyModuleContext interface {
 	AddNinjaFileDeps(deps ...string)
 
 	moduleInfo() *moduleInfo
+
 	error(err error)
 
 	// Namespace returns the Namespace object provided by the NameInterface set by Context.SetNameInterface, or the
@@ -359,6 +360,10 @@ type BaseModuleContext interface {
 	// This method shouldn't be used directly, prefer the type-safe android.SetProvider instead.
 	SetProvider(provider AnyProviderKey, value any)
 
+	// HasMutatorFinished returns true if the given mutator has finished running.
+	// It will panic if given an invalid mutator name.
+	HasMutatorFinished(mutatorName string) bool
+
 	EarlyGetMissingDependencies() []string
 
 	base() *baseModuleContext
@@ -373,6 +378,8 @@ type ModuleContext interface {
 	// to ensure that each variant of a module gets its own intermediates directory to write to.
 	ModuleSubDir() string
 
+	ModuleCacheKey() string
+
 	// Variable creates a new ninja variable scoped to the module.  It can be referenced by calls to Rule and Build
 	// in the same module.
 	Variable(pctx PackageContext, name, value string)
@@ -491,6 +498,10 @@ func (d *baseModuleContext) Namespace() Namespace {
 	return d.context.nameInterface.GetNamespace(newNamespaceContext(d.module))
 }
 
+func (d *baseModuleContext) HasMutatorFinished(mutatorName string) bool {
+	return d.context.HasMutatorFinished(mutatorName)
+}
+
 var _ ModuleContext = (*moduleContext)(nil)
 
 type moduleContext struct {
@@ -535,10 +546,14 @@ func (m *baseModuleContext) OtherModuleErrorf(logicModule Module, format string,
 
 func (m *baseModuleContext) OtherModuleDependencyTag(logicModule Module) DependencyTag {
 	// fast path for calling OtherModuleDependencyTag from inside VisitDirectDeps
-	if logicModule == m.visitingDep.module.logicModule {
+	if m.visitingDep.module != nil && logicModule == m.visitingDep.module.logicModule {
 		return m.visitingDep.tag
 	}
 
+	if m.visitingParent == nil {
+		return nil
+	}
+
 	for _, dep := range m.visitingParent.directDeps {
 		if dep.module.logicModule == logicModule {
 			return dep.tag
@@ -610,6 +625,86 @@ func (m *baseModuleContext) SetProvider(provider AnyProviderKey, value interface
 	m.context.setProvider(m.module, provider.provider(), value)
 }
 
+func (m *moduleContext) cacheModuleBuildActions(key *BuildActionCacheKey) {
+	var providers []CachedProvider
+	for i, p := range m.module.providers {
+		if p != nil && providerRegistry[i].mutator == "" {
+			providers = append(providers,
+				CachedProvider{
+					Id:    providerRegistry[i],
+					Value: &p,
+				})
+		}
+	}
+
+	// These show up in the ninja file, so we need to cache these to ensure we
+	// re-generate ninja file if they changed.
+	relPos := m.module.pos
+	relPos.Filename = m.module.relBlueprintsFile
+	data := BuildActionCachedData{
+		Providers: providers,
+		Pos:       &relPos,
+	}
+
+	m.context.updateBuildActionsCache(key, &data)
+}
+
+func (m *moduleContext) restoreModuleBuildActions() (bool, *BuildActionCacheKey) {
+	// Whether the incremental flag is set and the module type supports
+	// incremental, this will decide weather to cache the data for the module.
+	incrementalEnabled := false
+	// Whether the above conditions are true and we can try to restore from
+	// the cache for this module, i.e., no env, product variables and Soong
+	// code changes.
+	incrementalAnalysis := false
+	var cacheKey *BuildActionCacheKey = nil
+	if m.context.GetIncrementalEnabled() {
+		if im, ok := m.module.logicModule.(Incremental); ok {
+			incrementalEnabled = im.IncrementalSupported()
+			incrementalAnalysis = m.context.GetIncrementalAnalysis() && incrementalEnabled
+		}
+	}
+	if incrementalEnabled {
+		hash, err := proptools.CalculateHash(m.module.properties)
+		if err != nil {
+			panic(newPanicErrorf(err, "failed to calculate properties hash"))
+		}
+		cacheInput := new(BuildActionCacheInput)
+		cacheInput.PropertiesHash = hash
+		m.VisitDirectDeps(func(module Module) {
+			cacheInput.ProvidersHash =
+				append(cacheInput.ProvidersHash, m.context.moduleInfo[module].providerInitialValueHashes)
+		})
+		hash, err = proptools.CalculateHash(&cacheInput)
+		if err != nil {
+			panic(newPanicErrorf(err, "failed to calculate cache input hash"))
+		}
+		cacheKey = &BuildActionCacheKey{
+			Id:        m.ModuleCacheKey(),
+			InputHash: hash,
+		}
+		m.module.buildActionCacheKey = cacheKey
+	}
+
+	restored := false
+	if incrementalAnalysis && cacheKey != nil {
+		// Try to restore from cache if there is a cache hit
+		data := m.context.getBuildActionsFromCache(cacheKey)
+		relPos := m.module.pos
+		relPos.Filename = m.module.relBlueprintsFile
+		if data != nil && data.Pos != nil && relPos == *data.Pos {
+			for _, provider := range data.Providers {
+				m.context.setProvider(m.module, provider.Id, *provider.Value)
+			}
+			m.module.incrementalRestored = true
+			m.module.orderOnlyStrings = data.OrderOnlyStrings
+			restored = true
+		}
+	}
+
+	return restored, cacheKey
+}
+
 func (m *baseModuleContext) GetDirectDep(name string) (Module, DependencyTag) {
 	for _, dep := range m.module.directDeps {
 		if dep.module.Name() == name {
@@ -761,6 +856,10 @@ func (m *moduleContext) ModuleSubDir() string {
 	return m.module.variant.name
 }
 
+func (m *moduleContext) ModuleCacheKey() string {
+	return m.module.ModuleCacheKey()
+}
+
 func (m *moduleContext) Variable(pctx PackageContext, name, value string) {
 	m.scope.ReparentTo(pctx)
 
@@ -832,16 +931,16 @@ type BaseMutatorContext interface {
 
 	// MutatorName returns the name that this mutator was registered with.
 	MutatorName() string
-}
-
-type TopDownMutatorContext interface {
-	BaseMutatorContext
 
 	// CreateModule creates a new module by calling the factory method for the specified moduleType, and applies
 	// the specified property structs to it as if the properties were set in a blueprint file.
 	CreateModule(ModuleFactory, string, ...interface{}) Module
 }
 
+type TopDownMutatorContext interface {
+	BaseMutatorContext
+}
+
 type BottomUpMutatorContext interface {
 	BaseMutatorContext
 
@@ -1049,7 +1148,7 @@ func (mctx *mutatorContext) AliasVariation(variationName string) {
 	}
 
 	for _, variant := range mctx.newVariations {
-		if variant.moduleOrAliasVariant().variations[mctx.mutator.name] == variationName {
+		if variant.moduleOrAliasVariant().variations.get(mctx.mutator.name) == variationName {
 			alias := &moduleAlias{
 				variant: mctx.module.variant,
 				target:  variant.moduleOrAliasTarget(),
@@ -1063,7 +1162,7 @@ func (mctx *mutatorContext) AliasVariation(variationName string) {
 
 	var foundVariations []string
 	for _, variant := range mctx.newVariations {
-		foundVariations = append(foundVariations, variant.moduleOrAliasVariant().variations[mctx.mutator.name])
+		foundVariations = append(foundVariations, variant.moduleOrAliasVariant().variations.get(mctx.mutator.name))
 	}
 	panic(fmt.Errorf("no %q variation in module variations %q", variationName, foundVariations))
 }
@@ -1082,7 +1181,7 @@ func (mctx *mutatorContext) CreateAliasVariation(aliasVariationName, targetVaria
 	}
 
 	for _, variant := range mctx.newVariations {
-		if variant.moduleOrAliasVariant().variations[mctx.mutator.name] == targetVariationName {
+		if variant.moduleOrAliasVariant().variations.get(mctx.mutator.name) == targetVariationName {
 			// Append the alias here so that it comes after any aliases created by AliasVariation.
 			mctx.module.splitModules = append(mctx.module.splitModules, &moduleAlias{
 				variant: newVariant,
@@ -1094,7 +1193,7 @@ func (mctx *mutatorContext) CreateAliasVariation(aliasVariationName, targetVaria
 
 	var foundVariations []string
 	for _, variant := range mctx.newVariations {
-		foundVariations = append(foundVariations, variant.moduleOrAliasVariant().variations[mctx.mutator.name])
+		foundVariations = append(foundVariations, variant.moduleOrAliasVariant().variations.get(mctx.mutator.name))
 	}
 	panic(fmt.Errorf("no %q variation in module variations %q", targetVariationName, foundVariations))
 }
@@ -1392,8 +1491,7 @@ func runAndRemoveLoadHooks(ctx *Context, config interface{}, module *moduleInfo,
 //
 // The filename is only used for reporting errors.
 func CheckBlueprintSyntax(moduleFactories map[string]ModuleFactory, filename string, contents string) []error {
-	scope := parser.NewScope(nil)
-	file, errs := parser.Parse(filename, strings.NewReader(contents), scope)
+	file, errs := parser.Parse(filename, strings.NewReader(contents))
 	if len(errs) != 0 {
 		return errs
 	}
diff --git a/module_ctx_test.go b/module_ctx_test.go
index 7dc7dec02e..b6f7caf125 100644
--- a/module_ctx_test.go
+++ b/module_ctx_test.go
@@ -198,7 +198,7 @@ func TestAliasVariation(t *testing.T) {
 		ctx.RegisterBottomUpMutator("2", noAliasMutator("bar"))
 		ctx.RegisterBottomUpMutator("3", addVariantDepsMutator(nil, nil, "foo", "bar"))
 
-		runWithFailures(ctx, `dependency "bar" of "foo" missing variant:`+"\n  \n"+
+		runWithFailures(ctx, `dependency "bar" of "foo" missing variant:`+"\n  <empty variant>\n"+
 			"available variants:"+
 			"\n  1:a,2:a\n  1:a,2:b\n  1:b,2:a\n  1:b,2:b")
 	})
diff --git a/parser/ast.go b/parser/ast.go
index 7aea5e05ec..67b690283f 100644
--- a/parser/ast.go
+++ b/parser/ast.go
@@ -16,6 +16,7 @@ package parser
 
 import (
 	"fmt"
+	"os"
 	"strings"
 	"text/scanner"
 )
@@ -40,14 +41,13 @@ type Assignment struct {
 	Name       string
 	NamePos    scanner.Position
 	Value      Expression
-	OrigValue  Expression
 	EqualsPos  scanner.Position
 	Assigner   string
 	Referenced bool
 }
 
 func (a *Assignment) String() string {
-	return fmt.Sprintf("%s@%s %s %s (%s) %t", a.Name, a.EqualsPos, a.Assigner, a.Value, a.OrigValue, a.Referenced)
+	return fmt.Sprintf("%s@%s %s %s %t", a.Name, a.EqualsPos, a.Assigner, a.Value, a.Referenced)
 }
 
 func (a *Assignment) Pos() scanner.Position { return a.NamePos }
@@ -131,6 +131,10 @@ func (p *Property) String() string {
 func (p *Property) Pos() scanner.Position { return p.NamePos }
 func (p *Property) End() scanner.Position { return p.Value.End() }
 
+func (p *Property) MarkReferencedVariables(scope *Scope) {
+	p.Value.MarkReferencedVariables(scope)
+}
+
 // An Expression is a Value in a Property or Assignment.  It can be a literal (String or Bool), a
 // Map, a List, an Operator that combines two expressions of the same type, or a Variable that
 // references and Assignment.
@@ -139,11 +143,24 @@ type Expression interface {
 	// Copy returns a copy of the Expression that will not affect the original if mutated
 	Copy() Expression
 	String() string
-	// Type returns the underlying Type enum of the Expression if it were to be evaluated
+	// Type returns the underlying Type enum of the Expression if it were to be evaluated, if it's known.
+	// It's possible that the type isn't known, such as when a select statement with a late-bound variable
+	// is used. For that reason, Type() is mostly for use in error messages, not to make logic decisions
+	// off of.
 	Type() Type
-	// Eval returns an expression that is fully evaluated to a simple type (List, Map, String, or
-	// Bool).  It will return the same object for every call to Eval().
-	Eval() Expression
+	// Eval returns an expression that is fully evaluated to a simple type (List, Map, String,
+	// Bool, or Select).  It will return the origional expression if possible, or allocate a
+	// new one if modifications were necessary.
+	Eval(scope *Scope) (Expression, error)
+	// PrintfInto will substitute any %s's in string literals in the AST with the provided
+	// value. It will modify the AST in-place. This is used to implement soong config value
+	// variables, but should be removed when those have switched to selects.
+	PrintfInto(value string) error
+	// MarkReferencedVariables marks the variables in the given scope referenced if there
+	// is a matching variable reference in this expression. This happens naturally during
+	// Eval as well, but for selects, we need to mark variables as referenced without
+	// actually evaluating the expression yet.
+	MarkReferencedVariables(scope *Scope)
 }
 
 // ExpressionsAreSame tells whether the two values are the same Expression.
@@ -157,9 +174,6 @@ func ExpressionsAreSame(a Expression, b Expression) (equal bool, err error) {
 // TODO(jeffrygaston) once positions are removed from Expression structs,
 // remove this function and have callers use reflect.DeepEqual(a, b)
 func hackyExpressionsAreSame(a Expression, b Expression) (equal bool, err error) {
-	if a.Type() != b.Type() {
-		return false, nil
-	}
 	left, err := hackyFingerprint(a)
 	if err != nil {
 		return false, nil
@@ -173,7 +187,7 @@ func hackyExpressionsAreSame(a Expression, b Expression) (equal bool, err error)
 }
 
 func hackyFingerprint(expression Expression) (fingerprint []byte, err error) {
-	assignment := &Assignment{"a", noPos, expression, expression, noPos, "=", false}
+	assignment := &Assignment{"a", noPos, expression, noPos, "=", false}
 	module := &File{}
 	module.Defs = append(module.Defs, assignment)
 	p := newPrinter(module)
@@ -183,17 +197,19 @@ func hackyFingerprint(expression Expression) (fingerprint []byte, err error) {
 type Type int
 
 const (
-	BoolType Type = iota + 1
+	UnknownType Type = iota
+	BoolType
 	StringType
 	Int64Type
 	ListType
 	MapType
-	NotEvaluatedType
 	UnsetType
 )
 
 func (t Type) String() string {
 	switch t {
+	case UnknownType:
+		return "unknown"
 	case BoolType:
 		return "bool"
 	case StringType:
@@ -204,12 +220,10 @@ func (t Type) String() string {
 		return "list"
 	case MapType:
 		return "map"
-	case NotEvaluatedType:
-		return "notevaluated"
 	case UnsetType:
 		return "unset"
 	default:
-		panic(fmt.Errorf("Unknown type %d", t))
+		panic(fmt.Sprintf("Unknown type %d", t))
 	}
 }
 
@@ -217,7 +231,6 @@ type Operator struct {
 	Args        [2]Expression
 	Operator    rune
 	OperatorPos scanner.Position
-	Value       Expression
 }
 
 func (x *Operator) Copy() Expression {
@@ -227,26 +240,142 @@ func (x *Operator) Copy() Expression {
 	return &ret
 }
 
-func (x *Operator) Eval() Expression {
-	return x.Value.Eval()
+func (x *Operator) Type() Type {
+	t1 := x.Args[0].Type()
+	t2 := x.Args[1].Type()
+	if t1 == UnknownType {
+		return t2
+	}
+	if t2 == UnknownType {
+		return t1
+	}
+	if t1 != t2 {
+		return UnknownType
+	}
+	return t1
+}
+
+func (x *Operator) Eval(scope *Scope) (Expression, error) {
+	return evaluateOperator(scope, x.Operator, x.Args[0], x.Args[1])
 }
 
-func (x *Operator) Type() Type {
-	return x.Args[0].Type()
+func evaluateOperator(scope *Scope, operator rune, left, right Expression) (Expression, error) {
+	if operator != '+' {
+		return nil, fmt.Errorf("unknown operator %c", operator)
+	}
+	l, err := left.Eval(scope)
+	if err != nil {
+		return nil, err
+	}
+	r, err := right.Eval(scope)
+	if err != nil {
+		return nil, err
+	}
+
+	if _, ok := l.(*Select); !ok {
+		if _, ok := r.(*Select); ok {
+			// Promote l to a select so we can add r to it
+			l = &Select{
+				Cases: []*SelectCase{{
+					Value: l,
+				}},
+			}
+		}
+	}
+
+	l = l.Copy()
+
+	switch v := l.(type) {
+	case *String:
+		if _, ok := r.(*String); !ok {
+			fmt.Fprintf(os.Stderr, "not ok")
+		}
+		v.Value += r.(*String).Value
+	case *Int64:
+		v.Value += r.(*Int64).Value
+		v.Token = ""
+	case *List:
+		v.Values = append(v.Values, r.(*List).Values...)
+	case *Map:
+		var err error
+		v.Properties, err = addMaps(scope, v.Properties, r.(*Map).Properties)
+		if err != nil {
+			return nil, err
+		}
+	case *Select:
+		v.Append = r
+	default:
+		return nil, fmt.Errorf("operator %c not supported on %v", operator, v)
+	}
+
+	return l, nil
+}
+
+func addMaps(scope *Scope, map1, map2 []*Property) ([]*Property, error) {
+	ret := make([]*Property, 0, len(map1))
+
+	inMap1 := make(map[string]*Property)
+	inMap2 := make(map[string]*Property)
+	inBoth := make(map[string]*Property)
+
+	for _, prop1 := range map1 {
+		inMap1[prop1.Name] = prop1
+	}
+
+	for _, prop2 := range map2 {
+		inMap2[prop2.Name] = prop2
+		if _, ok := inMap1[prop2.Name]; ok {
+			inBoth[prop2.Name] = prop2
+		}
+	}
+
+	for _, prop1 := range map1 {
+		if prop2, ok := inBoth[prop1.Name]; ok {
+			var err error
+			newProp := *prop1
+			newProp.Value, err = evaluateOperator(scope, '+', prop1.Value, prop2.Value)
+			if err != nil {
+				return nil, err
+			}
+			ret = append(ret, &newProp)
+		} else {
+			ret = append(ret, prop1)
+		}
+	}
+
+	for _, prop2 := range map2 {
+		if _, ok := inBoth[prop2.Name]; !ok {
+			ret = append(ret, prop2)
+		}
+	}
+
+	return ret, nil
+}
+
+func (x *Operator) PrintfInto(value string) error {
+	if err := x.Args[0].PrintfInto(value); err != nil {
+		return err
+	}
+	return x.Args[1].PrintfInto(value)
+}
+
+func (x *Operator) MarkReferencedVariables(scope *Scope) {
+	x.Args[0].MarkReferencedVariables(scope)
+	x.Args[1].MarkReferencedVariables(scope)
 }
 
 func (x *Operator) Pos() scanner.Position { return x.Args[0].Pos() }
 func (x *Operator) End() scanner.Position { return x.Args[1].End() }
 
 func (x *Operator) String() string {
-	return fmt.Sprintf("(%s %c %s = %s)@%s", x.Args[0].String(), x.Operator, x.Args[1].String(),
-		x.Value, x.OperatorPos)
+	return fmt.Sprintf("(%s %c %s)@%s", x.Args[0].String(), x.Operator, x.Args[1].String(),
+		x.OperatorPos)
 }
 
 type Variable struct {
 	Name    string
 	NamePos scanner.Position
-	Value   Expression
+	Type_   Type
 }
 
 func (x *Variable) Pos() scanner.Position { return x.NamePos }
@@ -257,15 +386,33 @@ func (x *Variable) Copy() Expression {
 	return &ret
 }
 
-func (x *Variable) Eval() Expression {
-	return x.Value.Eval()
+func (x *Variable) Eval(scope *Scope) (Expression, error) {
+	if assignment := scope.Get(x.Name); assignment != nil {
+		assignment.Referenced = true
+		return assignment.Value, nil
+	}
+	return nil, fmt.Errorf("undefined variable %s", x.Name)
+}
+
+func (x *Variable) PrintfInto(value string) error {
+	return nil
+}
+
+func (x *Variable) MarkReferencedVariables(scope *Scope) {
+	if assignment := scope.Get(x.Name); assignment != nil {
+		assignment.Referenced = true
+	}
 }
 
 func (x *Variable) String() string {
-	return x.Name + " = " + x.Value.String()
+	return x.Name
 }
 
-func (x *Variable) Type() Type { return x.Value.Type() }
+func (x *Variable) Type() Type {
+	// Variables do not normally have a type associated with them, this is only
+	// filled out in the androidmk tool
+	return x.Type_
+}
 
 type Map struct {
 	LBracePos  scanner.Position
@@ -285,8 +432,36 @@ func (x *Map) Copy() Expression {
 	return &ret
 }
 
-func (x *Map) Eval() Expression {
-	return x
+func (x *Map) Eval(scope *Scope) (Expression, error) {
+	newProps := make([]*Property, len(x.Properties))
+	for i, prop := range x.Properties {
+		newVal, err := prop.Value.Eval(scope)
+		if err != nil {
+			return nil, err
+		}
+		newProps[i] = &Property{
+			Name:     prop.Name,
+			NamePos:  prop.NamePos,
+			ColonPos: prop.ColonPos,
+			Value:    newVal,
+		}
+	}
+	return &Map{
+		LBracePos:  x.LBracePos,
+		RBracePos:  x.RBracePos,
+		Properties: newProps,
+	}, nil
+}
+
+func (x *Map) PrintfInto(value string) error {
+	// We should never reach this because selects cannot hold maps
+	panic("printfinto() is unsupported on maps")
+}
+
+func (x *Map) MarkReferencedVariables(scope *Scope) {
+	for _, prop := range x.Properties {
+		prop.MarkReferencedVariables(scope)
+	}
 }
 
 func (x *Map) String() string {
@@ -379,8 +554,35 @@ func (x *List) Copy() Expression {
 	return &ret
 }
 
-func (x *List) Eval() Expression {
-	return x
+func (x *List) Eval(scope *Scope) (Expression, error) {
+	newValues := make([]Expression, len(x.Values))
+	for i, val := range x.Values {
+		newVal, err := val.Eval(scope)
+		if err != nil {
+			return nil, err
+		}
+		newValues[i] = newVal
+	}
+	return &List{
+		LBracePos: x.LBracePos,
+		RBracePos: x.RBracePos,
+		Values:    newValues,
+	}, nil
+}
+
+func (x *List) PrintfInto(value string) error {
+	for _, val := range x.Values {
+		if err := val.PrintfInto(value); err != nil {
+			return err
+		}
+	}
+	return nil
+}
+
+func (x *List) MarkReferencedVariables(scope *Scope) {
+	for _, val := range x.Values {
+		val.MarkReferencedVariables(scope)
+	}
 }
 
 func (x *List) String() string {
@@ -407,8 +609,29 @@ func (x *String) Copy() Expression {
 	return &ret
 }
 
-func (x *String) Eval() Expression {
-	return x
+func (x *String) Eval(scope *Scope) (Expression, error) {
+	return x, nil
+}
+
+func (x *String) PrintfInto(value string) error {
+	count := strings.Count(x.Value, "%")
+	if count == 0 {
+		return nil
+	}
+
+	if count > 1 {
+		return fmt.Errorf("list/value variable properties only support a single '%%'")
+	}
+
+	if !strings.Contains(x.Value, "%s") {
+		return fmt.Errorf("unsupported %% in value variable property")
+	}
+
+	x.Value = fmt.Sprintf(x.Value, value)
+	return nil
+}
+
+func (x *String) MarkReferencedVariables(scope *Scope) {
 }
 
 func (x *String) String() string {
@@ -433,8 +656,15 @@ func (x *Int64) Copy() Expression {
 	return &ret
 }
 
-func (x *Int64) Eval() Expression {
-	return x
+func (x *Int64) Eval(scope *Scope) (Expression, error) {
+	return x, nil
+}
+
+func (x *Int64) PrintfInto(value string) error {
+	return nil
+}
+
+func (x *Int64) MarkReferencedVariables(scope *Scope) {
 }
 
 func (x *Int64) String() string {
@@ -459,8 +689,15 @@ func (x *Bool) Copy() Expression {
 	return &ret
 }
 
-func (x *Bool) Eval() Expression {
-	return x
+func (x *Bool) Eval(scope *Scope) (Expression, error) {
+	return x, nil
+}
+
+func (x *Bool) PrintfInto(value string) error {
+	return nil
+}
+
+func (x *Bool) MarkReferencedVariables(scope *Scope) {
 }
 
 func (x *Bool) String() string {
@@ -542,29 +779,6 @@ func (c Comment) Text() string {
 	return string(buf)
 }
 
-type NotEvaluated struct {
-	Position scanner.Position
-}
-
-func (n NotEvaluated) Copy() Expression {
-	return NotEvaluated{Position: n.Position}
-}
-
-func (n NotEvaluated) String() string {
-	return "Not Evaluated"
-}
-
-func (n NotEvaluated) Type() Type {
-	return NotEvaluatedType
-}
-
-func (n NotEvaluated) Eval() Expression {
-	return NotEvaluated{Position: n.Position}
-}
-
-func (n NotEvaluated) Pos() scanner.Position { return n.Position }
-func (n NotEvaluated) End() scanner.Position { return n.Position }
-
 func endPos(pos scanner.Position, n int) scanner.Position {
 	pos.Offset += n
 	pos.Column += n
@@ -609,13 +823,13 @@ func (c *ConfigurableCondition) String() string {
 }
 
 type Select struct {
-	KeywordPos     scanner.Position // the keyword "select"
-	Conditions     []ConfigurableCondition
-	LBracePos      scanner.Position
-	RBracePos      scanner.Position
-	Cases          []*SelectCase // the case statements
-	Append         Expression
-	ExpressionType Type
+	Scope      *Scope           // scope used to evaluate the body of the select later on
+	KeywordPos scanner.Position // the keyword "select"
+	Conditions []ConfigurableCondition
+	LBracePos  scanner.Position
+	RBracePos  scanner.Position
+	Cases      []*SelectCase // the case statements
+	Append     Expression
 }
 
 func (s *Select) Pos() scanner.Position { return s.KeywordPos }
@@ -633,8 +847,24 @@ func (s *Select) Copy() Expression {
 	return &ret
 }
 
-func (s *Select) Eval() Expression {
-	return s
+func (s *Select) Eval(scope *Scope) (Expression, error) {
+	s.Scope = scope
+	s.MarkReferencedVariables(scope)
+	return s, nil
+}
+
+func (x *Select) PrintfInto(value string) error {
+	// PrintfInto will be handled at the Configurable object level
+	panic("Cannot call PrintfInto on a select expression")
+}
+
+func (x *Select) MarkReferencedVariables(scope *Scope) {
+	for _, c := range x.Cases {
+		c.MarkReferencedVariables(scope)
+	}
+	if x.Append != nil {
+		x.Append.MarkReferencedVariables(scope)
+	}
 }
 
 func (s *Select) String() string {
@@ -642,18 +872,35 @@ func (s *Select) String() string {
 }
 
 func (s *Select) Type() Type {
-	if s.ExpressionType == UnsetType && s.Append != nil {
-		return s.Append.Type()
+	if len(s.Cases) == 0 {
+		return UnsetType
 	}
-	return s.ExpressionType
+	return UnknownType
+}
+
+type SelectPattern struct {
+	Value   Expression
+	Binding Variable
+}
+
+func (c *SelectPattern) Pos() scanner.Position { return c.Value.Pos() }
+func (c *SelectPattern) End() scanner.Position {
+	if c.Binding.NamePos.IsValid() {
+		return c.Binding.End()
+	}
+	return c.Value.End()
 }
 
 type SelectCase struct {
-	Patterns []Expression
+	Patterns []SelectPattern
 	ColonPos scanner.Position
 	Value    Expression
 }
 
+func (x *SelectCase) MarkReferencedVariables(scope *Scope) {
+	x.Value.MarkReferencedVariables(scope)
+}
+
 func (c *SelectCase) Copy() *SelectCase {
 	ret := *c
 	ret.Value = c.Value.Copy()
@@ -681,21 +928,28 @@ type UnsetProperty struct {
 	Position scanner.Position
 }
 
-func (n UnsetProperty) Copy() Expression {
-	return UnsetProperty{Position: n.Position}
+func (n *UnsetProperty) Copy() Expression {
+	return &UnsetProperty{Position: n.Position}
 }
 
-func (n UnsetProperty) String() string {
+func (n *UnsetProperty) String() string {
 	return "unset"
 }
 
-func (n UnsetProperty) Type() Type {
+func (n *UnsetProperty) Type() Type {
 	return UnsetType
 }
 
-func (n UnsetProperty) Eval() Expression {
-	return UnsetProperty{Position: n.Position}
+func (n *UnsetProperty) Eval(scope *Scope) (Expression, error) {
+	return n, nil
+}
+
+func (x *UnsetProperty) PrintfInto(value string) error {
+	return nil
+}
+
+func (x *UnsetProperty) MarkReferencedVariables(scope *Scope) {
 }
 
-func (n UnsetProperty) Pos() scanner.Position { return n.Position }
-func (n UnsetProperty) End() scanner.Position { return n.Position }
+func (n *UnsetProperty) Pos() scanner.Position { return n.Position }
+func (n *UnsetProperty) End() scanner.Position { return n.Position }
diff --git a/parser/modify.go b/parser/modify.go
index a28fbe6a99..952e618257 100644
--- a/parser/modify.go
+++ b/parser/modify.go
@@ -23,13 +23,11 @@ import (
 
 func AddStringToList(list *List, s string) (modified bool) {
 	for _, v := range list.Values {
-		if v.Type() != StringType {
-			panic(fmt.Errorf("expected string in list, got %s", v.Type()))
-		}
-
 		if sv, ok := v.(*String); ok && sv.Value == s {
 			// string already exists
 			return false
+		} else if !ok {
+			panic(fmt.Errorf("expected string in list, got %s", v.Type()))
 		}
 	}
 
@@ -43,13 +41,11 @@ func AddStringToList(list *List, s string) (modified bool) {
 
 func RemoveStringFromList(list *List, s string) (modified bool) {
 	for i, v := range list.Values {
-		if v.Type() != StringType {
-			panic(fmt.Errorf("expected string in list, got %s", v.Type()))
-		}
-
 		if sv, ok := v.(*String); ok && sv.Value == s {
 			list.Values = append(list.Values[:i], list.Values[i+1:]...)
 			return true
+		} else if !ok {
+			panic(fmt.Errorf("expected string in list, got %s", v.Type()))
 		}
 	}
 
@@ -59,9 +55,6 @@ func RemoveStringFromList(list *List, s string) (modified bool) {
 func ReplaceStringsInList(list *List, replacements map[string]string) (replaced bool) {
 	modified := false
 	for i, v := range list.Values {
-		if v.Type() != StringType {
-			panic(fmt.Errorf("expected string in list, got %s", v.Type()))
-		}
 		if sv, ok := v.(*String); ok && replacements[sv.Value] != "" {
 			pos := list.Values[i].Pos()
 			list.Values[i] = &String{
@@ -69,6 +62,8 @@ func ReplaceStringsInList(list *List, replacements map[string]string) (replaced
 				Value:      replacements[sv.Value],
 			}
 			modified = true
+		} else if !ok {
+			panic(fmt.Errorf("expected string in list, got %s", v.Type()))
 		}
 	}
 	return modified
diff --git a/parser/parser.go b/parser/parser.go
index 81dafc941f..8e5e54390b 100644
--- a/parser/parser.go
+++ b/parser/parser.go
@@ -29,6 +29,7 @@ var errTooManyErrors = errors.New("too many errors")
 const maxErrors = 1
 
 const default_select_branch_name = "__soong_conditions_default__"
+const any_select_branch_name = "__soong_conditions_any__"
 
 type ParseError struct {
 	Err error
@@ -45,22 +46,6 @@ type File struct {
 	Comments []*CommentGroup
 }
 
-func (f *File) Pos() scanner.Position {
-	return scanner.Position{
-		Filename: f.Name,
-		Line:     1,
-		Column:   1,
-		Offset:   0,
-	}
-}
-
-func (f *File) End() scanner.Position {
-	if len(f.Defs) > 0 {
-		return f.Defs[len(f.Defs)-1].End()
-	}
-	return noPos
-}
-
 func parse(p *parser) (file *File, errs []error) {
 	defer func() {
 		if r := recover(); r != nil {
@@ -87,22 +72,54 @@ func parse(p *parser) (file *File, errs []error) {
 }
 
 func ParseAndEval(filename string, r io.Reader, scope *Scope) (file *File, errs []error) {
-	p := newParser(r, scope)
-	p.eval = true
-	p.scanner.Filename = filename
+	file, errs = Parse(filename, r)
+	if len(errs) > 0 {
+		return nil, errs
+	}
+
+	// evaluate all module properties
+	var newDefs []Definition
+	for _, def := range file.Defs {
+		switch d := def.(type) {
+		case *Module:
+			for _, prop := range d.Map.Properties {
+				newval, err := prop.Value.Eval(scope)
+				if err != nil {
+					return nil, []error{err}
+				}
+				switch newval.(type) {
+				case *String, *Bool, *Int64, *Select, *Map, *List:
+					// ok
+				default:
+					panic(fmt.Sprintf("Evaled but got %#v\n", newval))
+				}
+				prop.Value = newval
+			}
+			newDefs = append(newDefs, d)
+		case *Assignment:
+			if err := scope.HandleAssignment(d); err != nil {
+				return nil, []error{err}
+			}
+		}
+	}
 
-	return parse(p)
+	// This is not strictly necessary, but removing the assignments from
+	// the result makes it clearer that this is an evaluated file.
+	// We could also consider adding a "EvaluatedFile" type to return.
+	file.Defs = newDefs
+
+	return file, nil
 }
 
-func Parse(filename string, r io.Reader, scope *Scope) (file *File, errs []error) {
-	p := newParser(r, scope)
+func Parse(filename string, r io.Reader) (file *File, errs []error) {
+	p := newParser(r)
 	p.scanner.Filename = filename
 
 	return parse(p)
 }
 
 func ParseExpression(r io.Reader) (value Expression, errs []error) {
-	p := newParser(r, NewScope(nil))
+	p := newParser(r)
 	p.next()
 	value = p.parseExpression()
 	p.accept(scanner.EOF)
@@ -114,14 +131,11 @@ type parser struct {
 	scanner  scanner.Scanner
 	tok      rune
 	errors   []error
-	scope    *Scope
 	comments []*CommentGroup
-	eval     bool
 }
 
-func newParser(r io.Reader, scope *Scope) *parser {
+func newParser(r io.Reader) *parser {
 	p := &parser{}
-	p.scope = scope
 	p.scanner.Init(r)
 	p.scanner.Error = func(sc *scanner.Scanner, msg string) {
 		p.errorf(msg)
@@ -234,34 +248,9 @@ func (p *parser) parseAssignment(name string, namePos scanner.Position,
 	assignment.Name = name
 	assignment.NamePos = namePos
 	assignment.Value = value
-	assignment.OrigValue = value
 	assignment.EqualsPos = pos
 	assignment.Assigner = assigner
 
-	if p.scope != nil {
-		if assigner == "+=" {
-			if old, local := p.scope.Get(assignment.Name); old == nil {
-				p.errorf("modified non-existent variable %q with +=", assignment.Name)
-			} else if !local {
-				p.errorf("modified non-local variable %q with +=", assignment.Name)
-			} else if old.Referenced {
-				p.errorf("modified variable %q with += after referencing", assignment.Name)
-			} else {
-				val, err := p.evaluateOperator(old.Value, assignment.Value, '+', assignment.EqualsPos)
-				if err != nil {
-					p.error(err)
-				} else {
-					old.Value = val
-				}
-			}
-		} else {
-			err := p.scope.Add(assignment)
-			if err != nil {
-				p.error(err)
-			}
-		}
-	}
-
 	return
 }
 
@@ -297,13 +286,7 @@ func (p *parser) parseModule(typ string, typPos scanner.Position) *Module {
 
 func (p *parser) parsePropertyList(isModule, compat bool) (properties []*Property) {
 	for p.tok == scanner.Ident {
-		property := p.parseProperty(isModule, compat)
-
-		// If a property is set to an empty select or a select where all branches are "unset",
-		// skip emitting the property entirely.
-		if property.Value.Type() != UnsetType {
-			properties = append(properties, property)
-		}
+		properties = append(properties, p.parseProperty(isModule, compat))
 
 		if p.tok != ',' {
 			// There was no comma, so the list is done.
@@ -363,115 +346,6 @@ func (p *parser) parseExpression() (value Expression) {
 	}
 }
 
-func (p *parser) evaluateOperator(value1, value2 Expression, operator rune,
-	pos scanner.Position) (Expression, error) {
-
-	if value1.Type() == UnsetType {
-		return value2, nil
-	}
-	if value2.Type() == UnsetType {
-		return value1, nil
-	}
-
-	value := value1
-
-	if p.eval {
-		e1 := value1.Eval()
-		e2 := value2.Eval()
-		if e1.Type() != e2.Type() {
-			return nil, fmt.Errorf("mismatched type in operator %c: %s != %s", operator,
-				e1.Type(), e2.Type())
-		}
-
-		if _, ok := e1.(*Select); !ok {
-			if _, ok := e2.(*Select); ok {
-				// Promote e1 to a select so we can add e2 to it
-				e1 = &Select{
-					Cases: []*SelectCase{{
-						Value: e1,
-					}},
-					ExpressionType: e1.Type(),
-				}
-			}
-		}
-
-		value = e1.Copy()
-
-		switch operator {
-		case '+':
-			switch v := value.(type) {
-			case *String:
-				v.Value += e2.(*String).Value
-			case *Int64:
-				v.Value += e2.(*Int64).Value
-				v.Token = ""
-			case *List:
-				v.Values = append(v.Values, e2.(*List).Values...)
-			case *Map:
-				var err error
-				v.Properties, err = p.addMaps(v.Properties, e2.(*Map).Properties, pos)
-				if err != nil {
-					return nil, err
-				}
-			case *Select:
-				v.Append = e2
-			default:
-				return nil, fmt.Errorf("operator %c not supported on type %s", operator, v.Type())
-			}
-		default:
-			panic("unknown operator " + string(operator))
-		}
-	}
-
-	return &Operator{
-		Args:        [2]Expression{value1, value2},
-		Operator:    operator,
-		OperatorPos: pos,
-		Value:       value,
-	}, nil
-}
-
-func (p *parser) addMaps(map1, map2 []*Property, pos scanner.Position) ([]*Property, error) {
-	ret := make([]*Property, 0, len(map1))
-
-	inMap1 := make(map[string]*Property)
-	inMap2 := make(map[string]*Property)
-	inBoth := make(map[string]*Property)
-
-	for _, prop1 := range map1 {
-		inMap1[prop1.Name] = prop1
-	}
-
-	for _, prop2 := range map2 {
-		inMap2[prop2.Name] = prop2
-		if _, ok := inMap1[prop2.Name]; ok {
-			inBoth[prop2.Name] = prop2
-		}
-	}
-
-	for _, prop1 := range map1 {
-		if prop2, ok := inBoth[prop1.Name]; ok {
-			var err error
-			newProp := *prop1
-			newProp.Value, err = p.evaluateOperator(prop1.Value, prop2.Value, '+', pos)
-			if err != nil {
-				return nil, err
-			}
-			ret = append(ret, &newProp)
-		} else {
-			ret = append(ret, prop1)
-		}
-	}
-
-	for _, prop2 := range map2 {
-		if _, ok := inBoth[prop2.Name]; !ok {
-			ret = append(ret, prop2)
-		}
-	}
-
-	return ret, nil
-}
-
 func (p *parser) parseOperator(value1 Expression) Expression {
 	operator := p.tok
 	pos := p.scanner.Position
@@ -479,14 +353,11 @@ func (p *parser) parseOperator(value1 Expression) Expression {
 
 	value2 := p.parseExpression()
 
-	value, err := p.evaluateOperator(value1, value2, operator, pos)
-	if err != nil {
-		p.error(err)
-		return nil
+	return &Operator{
+		Args:        [2]Expression{value1, value2},
+		Operator:    operator,
+		OperatorPos: pos,
 	}
-
-	return value
-
 }
 
 func (p *parser) parseValue() (value Expression) {
@@ -535,22 +406,9 @@ func (p *parser) parseVariable() Expression {
 	var value Expression
 
 	text := p.scanner.TokenText()
-	if p.eval {
-		if assignment, local := p.scope.Get(text); assignment == nil {
-			p.errorf("variable %q is not set", text)
-		} else {
-			if local {
-				assignment.Referenced = true
-			}
-			value = assignment.Value
-		}
-	} else {
-		value = &NotEvaluated{}
-	}
 	value = &Variable{
 		Name:    text,
 		NamePos: p.scanner.Position,
-		Value:   value,
 	}
 
 	p.accept(scanner.Ident)
@@ -645,44 +503,72 @@ func (p *parser) parseSelect() Expression {
 		return nil
 	}
 
-	parseOnePattern := func() Expression {
+	maybeParseBinding := func() (Variable, bool) {
+		if p.scanner.TokenText() != "@" {
+			return Variable{}, false
+		}
+		p.next()
+		value := Variable{
+			Name:    p.scanner.TokenText(),
+			NamePos: p.scanner.Position,
+		}
+		p.accept(scanner.Ident)
+		return value, true
+	}
+
+	parseOnePattern := func() SelectPattern {
+		var result SelectPattern
 		switch p.tok {
 		case scanner.Ident:
 			switch p.scanner.TokenText() {
-			case "default":
+			case "any":
+				result.Value = &String{
+					LiteralPos: p.scanner.Position,
+					Value:      any_select_branch_name,
+				}
 				p.next()
-				return &String{
+				if binding, exists := maybeParseBinding(); exists {
+					result.Binding = binding
+				}
+				return result
+			case "default":
+				result.Value = &String{
 					LiteralPos: p.scanner.Position,
 					Value:      default_select_branch_name,
 				}
-			case "true":
 				p.next()
-				return &Bool{
+				return result
+			case "true":
+				result.Value = &Bool{
 					LiteralPos: p.scanner.Position,
 					Value:      true,
 				}
-			case "false":
 				p.next()
-				return &Bool{
+				return result
+			case "false":
+				result.Value = &Bool{
 					LiteralPos: p.scanner.Position,
 					Value:      false,
 				}
+				p.next()
+				return result
 			default:
-				p.errorf("Expted a string, true, false, or default, got %s", p.scanner.TokenText())
+				p.errorf("Expected a string, true, false, or default, got %s", p.scanner.TokenText())
 			}
 		case scanner.String:
 			if s := p.parseStringValue(); s != nil {
 				if strings.HasPrefix(s.Value, "__soong") {
-					p.errorf("select branch conditions starting with __soong are reserved for internal use")
-					return nil
+					p.errorf("select branch patterns starting with __soong are reserved for internal use")
+					return result
 				}
-				return s
+				result.Value = s
+				return result
 			}
 			fallthrough
 		default:
-			p.errorf("Expted a string, true, false, or default, got %s", p.scanner.TokenText())
+			p.errorf("Expected a string, true, false, or default, got %s", p.scanner.TokenText())
 		}
-		return nil
+		return result
 	}
 
 	hasNonUnsetValue := false
@@ -694,11 +580,7 @@ func (p *parser) parseSelect() Expression {
 				return nil
 			}
 			for i := 0; i < len(conditions); i++ {
-				if p := parseOnePattern(); p != nil {
-					c.Patterns = append(c.Patterns, p)
-				} else {
-					return nil
-				}
+				c.Patterns = append(c.Patterns, parseOnePattern())
 				if i < len(conditions)-1 {
 					if !p.accept(',') {
 						return nil
@@ -712,18 +594,14 @@ func (p *parser) parseSelect() Expression {
 				return nil
 			}
 		} else {
-			if p := parseOnePattern(); p != nil {
-				c.Patterns = append(c.Patterns, p)
-			} else {
-				return nil
-			}
+			c.Patterns = append(c.Patterns, parseOnePattern())
 		}
 		c.ColonPos = p.scanner.Position
 		if !p.accept(':') {
 			return nil
 		}
 		if p.tok == scanner.Ident && p.scanner.TokenText() == "unset" {
-			c.Value = UnsetProperty{Position: p.scanner.Position}
+			c.Value = &UnsetProperty{Position: p.scanner.Position}
 			p.accept(scanner.Ident)
 		} else {
 			hasNonUnsetValue = true
@@ -742,16 +620,17 @@ func (p *parser) parseSelect() Expression {
 		return nil
 	}
 
-	patternsEqual := func(a, b Expression) bool {
-		switch a2 := a.(type) {
+	patternsEqual := func(a, b SelectPattern) bool {
+		// We can ignore the bindings, they don't affect which pattern is matched
+		switch a2 := a.Value.(type) {
 		case *String:
-			if b2, ok := b.(*String); ok {
+			if b2, ok := b.Value.(*String); ok {
 				return a2.Value == b2.Value
 			} else {
 				return false
 			}
 		case *Bool:
-			if b2, ok := b.(*Bool); ok {
+			if b2, ok := b.Value.(*Bool); ok {
 				return a2.Value == b2.Value
 			} else {
 				return false
@@ -762,7 +641,7 @@ func (p *parser) parseSelect() Expression {
 		}
 	}
 
-	patternListsEqual := func(a, b []Expression) bool {
+	patternListsEqual := func(a, b []SelectPattern) bool {
 		if len(a) != len(b) {
 			return false
 		}
@@ -775,18 +654,29 @@ func (p *parser) parseSelect() Expression {
 	}
 
 	for i, c := range result.Cases {
-		// Check for duplicates
+		// Check for duplicate patterns across different branches
 		for _, d := range result.Cases[i+1:] {
 			if patternListsEqual(c.Patterns, d.Patterns) {
 				p.errorf("Found duplicate select patterns: %v", c.Patterns)
 				return nil
 			}
 		}
+		// check for duplicate bindings within this branch
+		for i := range c.Patterns {
+			if c.Patterns[i].Binding.Name != "" {
+				for j := i + 1; j < len(c.Patterns); j++ {
+					if c.Patterns[i].Binding.Name == c.Patterns[j].Binding.Name {
+						p.errorf("Found duplicate select pattern binding: %s", c.Patterns[i].Binding.Name)
+						return nil
+					}
+				}
+			}
+		}
 		// Check that the only all-default cases is the last one
 		if i < len(result.Cases)-1 {
 			isAllDefault := true
 			for _, x := range c.Patterns {
-				if x2, ok := x.(*String); !ok || x2.Value != default_select_branch_name {
+				if x2, ok := x.Value.(*String); !ok || x2.Value != default_select_branch_name {
 					isAllDefault = false
 					break
 				}
@@ -798,21 +688,6 @@ func (p *parser) parseSelect() Expression {
 		}
 	}
 
-	ty := UnsetType
-	for _, c := range result.Cases {
-		otherTy := c.Value.Type()
-		// Any other type can override UnsetType
-		if ty == UnsetType {
-			ty = otherTy
-		}
-		if otherTy != UnsetType && otherTy != ty {
-			p.errorf("Found select statement with differing types %q and %q in its cases", ty.String(), otherTy.String())
-			return nil
-		}
-	}
-
-	result.ExpressionType = ty
-
 	result.RBracePos = p.scanner.Position
 	if !p.accept('}') {
 		return nil
@@ -913,79 +788,107 @@ func (p *parser) parseMapValue() *Map {
 }
 
 type Scope struct {
-	vars          map[string]*Assignment
-	inheritedVars map[string]*Assignment
+	vars              map[string]*Assignment
+	preventInheriting map[string]bool
+	parentScope       *Scope
 }
 
 func NewScope(s *Scope) *Scope {
-	newScope := &Scope{
-		vars:          make(map[string]*Assignment),
-		inheritedVars: make(map[string]*Assignment),
+	return &Scope{
+		vars:              make(map[string]*Assignment),
+		preventInheriting: make(map[string]bool),
+		parentScope:       s,
 	}
+}
 
-	if s != nil {
-		for k, v := range s.vars {
-			newScope.inheritedVars[k] = v
+func (s *Scope) HandleAssignment(assignment *Assignment) error {
+	switch assignment.Assigner {
+	case "+=":
+		if !s.preventInheriting[assignment.Name] && s.parentScope.Get(assignment.Name) != nil {
+			return fmt.Errorf("modified non-local variable %q with +=", assignment.Name)
 		}
-		for k, v := range s.inheritedVars {
-			newScope.inheritedVars[k] = v
+		if old, ok := s.vars[assignment.Name]; !ok {
+			return fmt.Errorf("modified non-existent variable %q with +=", assignment.Name)
+		} else if old.Referenced {
+			return fmt.Errorf("modified variable %q with += after referencing", assignment.Name)
+		} else {
+			newValue, err := evaluateOperator(s, '+', old.Value, assignment.Value)
+			if err != nil {
+				return err
+			}
+			old.Value = newValue
+		}
+	case "=":
+		if old, ok := s.vars[assignment.Name]; ok {
+			return fmt.Errorf("variable already set, previous assignment: %s", old)
 		}
-	}
-
-	return newScope
-}
 
-func (s *Scope) Add(assignment *Assignment) error {
-	if old, ok := s.vars[assignment.Name]; ok {
-		return fmt.Errorf("variable already set, previous assignment: %s", old)
-	}
+		if old := s.parentScope.Get(assignment.Name); old != nil && !s.preventInheriting[assignment.Name] {
+			return fmt.Errorf("variable already set in inherited scope, previous assignment: %s", old)
+		}
 
-	if old, ok := s.inheritedVars[assignment.Name]; ok {
-		return fmt.Errorf("variable already set in inherited scope, previous assignment: %s", old)
+		if newValue, err := assignment.Value.Eval(s); err != nil {
+			return err
+		} else {
+			assignment.Value = newValue
+		}
+		s.vars[assignment.Name] = assignment
+	default:
+		return fmt.Errorf("Unknown assigner '%s'", assignment.Assigner)
 	}
-
-	s.vars[assignment.Name] = assignment
-
 	return nil
 }
 
-func (s *Scope) Remove(name string) {
-	delete(s.vars, name)
-	delete(s.inheritedVars, name)
-}
-
-func (s *Scope) Get(name string) (*Assignment, bool) {
+func (s *Scope) Get(name string) *Assignment {
+	if s == nil {
+		return nil
+	}
 	if a, ok := s.vars[name]; ok {
-		return a, true
+		return a
+	}
+	if s.preventInheriting[name] {
+		return nil
 	}
+	return s.parentScope.Get(name)
+}
 
-	if a, ok := s.inheritedVars[name]; ok {
-		return a, false
+func (s *Scope) GetLocal(name string) *Assignment {
+	if s == nil {
+		return nil
+	}
+	if a, ok := s.vars[name]; ok {
+		return a
 	}
+	return nil
+}
 
-	return nil, false
+// DontInherit prevents this scope from inheriting the given variable from its
+// parent scope.
+func (s *Scope) DontInherit(name string) {
+	s.preventInheriting[name] = true
 }
 
 func (s *Scope) String() string {
-	vars := []string{}
+	var sb strings.Builder
+	s.stringInner(&sb)
+	return sb.String()
+}
 
-	for k := range s.vars {
-		vars = append(vars, k)
+func (s *Scope) stringInner(sb *strings.Builder) {
+	if s == nil {
+		return
 	}
-	for k := range s.inheritedVars {
+	vars := make([]string, 0, len(s.vars))
+	for k := range s.vars {
 		vars = append(vars, k)
 	}
 
 	sort.Strings(vars)
 
-	ret := []string{}
 	for _, v := range vars {
-		if assignment, ok := s.vars[v]; ok {
-			ret = append(ret, assignment.String())
-		} else {
-			ret = append(ret, s.inheritedVars[v].String())
-		}
+		sb.WriteString(s.vars[v].String())
+		sb.WriteRune('\n')
 	}
 
-	return strings.Join(ret, "\n")
+	s.parentScope.stringInner(sb)
 }
diff --git a/parser/parser_test.go b/parser/parser_test.go
index 9de69c07c4..b6a1246091 100644
--- a/parser/parser_test.go
+++ b/parser/parser_test.go
@@ -565,12 +565,7 @@ var validParseTestCases = []struct {
 					LiteralPos: mkpos(9, 2, 9),
 					Value:      "stuff",
 				},
-				OrigValue: &String{
-					LiteralPos: mkpos(9, 2, 9),
-					Value:      "stuff",
-				},
-				Assigner:   "=",
-				Referenced: true,
+				Assigner: "=",
 			},
 			&Assignment{
 				Name:      "bar",
@@ -579,21 +574,8 @@ var validParseTestCases = []struct {
 				Value: &Variable{
 					Name:    "foo",
 					NamePos: mkpos(25, 3, 9),
-					Value: &String{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      "stuff",
-					},
-				},
-				OrigValue: &Variable{
-					Name:    "foo",
-					NamePos: mkpos(25, 3, 9),
-					Value: &String{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      "stuff",
-					},
 				},
-				Assigner:   "=",
-				Referenced: true,
+				Assigner: "=",
 			},
 			&Assignment{
 				Name:      "baz",
@@ -602,155 +584,26 @@ var validParseTestCases = []struct {
 				Value: &Operator{
 					OperatorPos: mkpos(41, 4, 13),
 					Operator:    '+',
-					Value: &String{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      "stuffstuff",
-					},
-					Args: [2]Expression{
-						&Variable{
-							Name:    "foo",
-							NamePos: mkpos(37, 4, 9),
-							Value: &String{
-								LiteralPos: mkpos(9, 2, 9),
-								Value:      "stuff",
-							},
-						},
-						&Variable{
-							Name:    "bar",
-							NamePos: mkpos(43, 4, 15),
-							Value: &Variable{
-								Name:    "foo",
-								NamePos: mkpos(25, 3, 9),
-								Value: &String{
-									LiteralPos: mkpos(9, 2, 9),
-									Value:      "stuff",
-								},
-							},
-						},
-					},
-				},
-				OrigValue: &Operator{
-					OperatorPos: mkpos(41, 4, 13),
-					Operator:    '+',
-					Value: &String{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      "stuffstuff",
-					},
 					Args: [2]Expression{
 						&Variable{
 							Name:    "foo",
 							NamePos: mkpos(37, 4, 9),
-							Value: &String{
-								LiteralPos: mkpos(9, 2, 9),
-								Value:      "stuff",
-							},
 						},
 						&Variable{
 							Name:    "bar",
 							NamePos: mkpos(43, 4, 15),
-							Value: &Variable{
-								Name:    "foo",
-								NamePos: mkpos(25, 3, 9),
-								Value: &String{
-									LiteralPos: mkpos(9, 2, 9),
-									Value:      "stuff",
-								},
-							},
 						},
 					},
 				},
-				Assigner:   "=",
-				Referenced: true,
+				Assigner: "=",
 			},
 			&Assignment{
 				Name:      "boo",
 				NamePos:   mkpos(49, 5, 3),
 				EqualsPos: mkpos(53, 5, 7),
-				Value: &Operator{
-					Args: [2]Expression{
-						&Variable{
-							Name:    "baz",
-							NamePos: mkpos(55, 5, 9),
-							Value: &Operator{
-								OperatorPos: mkpos(41, 4, 13),
-								Operator:    '+',
-								Value: &String{
-									LiteralPos: mkpos(9, 2, 9),
-									Value:      "stuffstuff",
-								},
-								Args: [2]Expression{
-									&Variable{
-										Name:    "foo",
-										NamePos: mkpos(37, 4, 9),
-										Value: &String{
-											LiteralPos: mkpos(9, 2, 9),
-											Value:      "stuff",
-										},
-									},
-									&Variable{
-										Name:    "bar",
-										NamePos: mkpos(43, 4, 15),
-										Value: &Variable{
-											Name:    "foo",
-											NamePos: mkpos(25, 3, 9),
-											Value: &String{
-												LiteralPos: mkpos(9, 2, 9),
-												Value:      "stuff",
-											},
-										},
-									},
-								},
-							},
-						},
-						&Variable{
-							Name:    "foo",
-							NamePos: mkpos(68, 6, 10),
-							Value: &String{
-								LiteralPos: mkpos(9, 2, 9),
-								Value:      "stuff",
-							},
-						},
-					},
-					OperatorPos: mkpos(66, 6, 8),
-					Operator:    '+',
-					Value: &String{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      "stuffstuffstuff",
-					},
-				},
-				OrigValue: &Variable{
+				Value: &Variable{
 					Name:    "baz",
 					NamePos: mkpos(55, 5, 9),
-					Value: &Operator{
-						OperatorPos: mkpos(41, 4, 13),
-						Operator:    '+',
-						Value: &String{
-							LiteralPos: mkpos(9, 2, 9),
-							Value:      "stuffstuff",
-						},
-						Args: [2]Expression{
-							&Variable{
-								Name:    "foo",
-								NamePos: mkpos(37, 4, 9),
-								Value: &String{
-									LiteralPos: mkpos(9, 2, 9),
-									Value:      "stuff",
-								},
-							},
-							&Variable{
-								Name:    "bar",
-								NamePos: mkpos(43, 4, 15),
-								Value: &Variable{
-									Name:    "foo",
-									NamePos: mkpos(25, 3, 9),
-									Value: &String{
-										LiteralPos: mkpos(9, 2, 9),
-										Value:      "stuff",
-									},
-								},
-							},
-						},
-					},
 				},
 				Assigner: "=",
 			},
@@ -761,18 +614,6 @@ var validParseTestCases = []struct {
 				Value: &Variable{
 					Name:    "foo",
 					NamePos: mkpos(68, 6, 10),
-					Value: &String{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      "stuff",
-					},
-				},
-				OrigValue: &Variable{
-					Name:    "foo",
-					NamePos: mkpos(68, 6, 10),
-					Value: &String{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      "stuff",
-					},
 				},
 				Assigner: "+=",
 			},
@@ -791,10 +632,6 @@ var validParseTestCases = []struct {
 				Value: &Operator{
 					OperatorPos: mkpos(12, 2, 12),
 					Operator:    '+',
-					Value: &Int64{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      -3,
-					},
 					Args: [2]Expression{
 						&Int64{
 							LiteralPos: mkpos(9, 2, 9),
@@ -804,10 +641,6 @@ var validParseTestCases = []struct {
 						&Operator{
 							OperatorPos: mkpos(17, 2, 17),
 							Operator:    '+',
-							Value: &Int64{
-								LiteralPos: mkpos(14, 2, 14),
-								Value:      1,
-							},
 							Args: [2]Expression{
 								&Int64{
 									LiteralPos: mkpos(14, 2, 14),
@@ -823,43 +656,7 @@ var validParseTestCases = []struct {
 						},
 					},
 				},
-				OrigValue: &Operator{
-					OperatorPos: mkpos(12, 2, 12),
-					Operator:    '+',
-					Value: &Int64{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      -3,
-					},
-					Args: [2]Expression{
-						&Int64{
-							LiteralPos: mkpos(9, 2, 9),
-							Value:      -4,
-							Token:      "-4",
-						},
-						&Operator{
-							OperatorPos: mkpos(17, 2, 17),
-							Operator:    '+',
-							Value: &Int64{
-								LiteralPos: mkpos(14, 2, 14),
-								Value:      1,
-							},
-							Args: [2]Expression{
-								&Int64{
-									LiteralPos: mkpos(14, 2, 14),
-									Value:      -5,
-									Token:      "-5",
-								},
-								&Int64{
-									LiteralPos: mkpos(19, 2, 19),
-									Value:      6,
-									Token:      "6",
-								},
-							},
-						},
-					},
-				},
-				Assigner:   "=",
-				Referenced: false,
+				Assigner: "=",
 			},
 		},
 		nil,
@@ -882,13 +679,7 @@ var validParseTestCases = []struct {
 					Value:      1000000,
 					Token:      "1000000",
 				},
-				OrigValue: &Int64{
-					LiteralPos: mkpos(9, 2, 9),
-					Value:      1000000,
-					Token:      "1000000",
-				},
-				Assigner:   "=",
-				Referenced: true,
+				Assigner: "=",
 			},
 			&Assignment{
 				Name:      "bar",
@@ -897,23 +688,8 @@ var validParseTestCases = []struct {
 				Value: &Variable{
 					Name:    "foo",
 					NamePos: mkpos(25, 3, 9),
-					Value: &Int64{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      1000000,
-						Token:      "1000000",
-					},
 				},
-				OrigValue: &Variable{
-					Name:    "foo",
-					NamePos: mkpos(25, 3, 9),
-					Value: &Int64{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      1000000,
-						Token:      "1000000",
-					},
-				},
-				Assigner:   "=",
-				Referenced: true,
+				Assigner: "=",
 			},
 			&Assignment{
 				Name:      "baz",
@@ -922,164 +698,26 @@ var validParseTestCases = []struct {
 				Value: &Operator{
 					OperatorPos: mkpos(41, 4, 13),
 					Operator:    '+',
-					Value: &Int64{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      2000000,
-					},
 					Args: [2]Expression{
 						&Variable{
 							Name:    "foo",
 							NamePos: mkpos(37, 4, 9),
-							Value: &Int64{
-								LiteralPos: mkpos(9, 2, 9),
-								Value:      1000000,
-								Token:      "1000000",
-							},
 						},
 						&Variable{
 							Name:    "bar",
 							NamePos: mkpos(43, 4, 15),
-							Value: &Variable{
-								Name:    "foo",
-								NamePos: mkpos(25, 3, 9),
-								Value: &Int64{
-									LiteralPos: mkpos(9, 2, 9),
-									Value:      1000000,
-									Token:      "1000000",
-								},
-							},
-						},
-					},
-				},
-				OrigValue: &Operator{
-					OperatorPos: mkpos(41, 4, 13),
-					Operator:    '+',
-					Value: &Int64{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      2000000,
-					},
-					Args: [2]Expression{
-						&Variable{
-							Name:    "foo",
-							NamePos: mkpos(37, 4, 9),
-							Value: &Int64{
-								LiteralPos: mkpos(9, 2, 9),
-								Value:      1000000,
-								Token:      "1000000",
-							},
-						},
-						&Variable{
-							Name:    "bar",
-							NamePos: mkpos(43, 4, 15),
-							Value: &Variable{
-								Name:    "foo",
-								NamePos: mkpos(25, 3, 9),
-								Value: &Int64{
-									LiteralPos: mkpos(9, 2, 9),
-									Value:      1000000,
-									Token:      "1000000",
-								},
-							},
 						},
 					},
 				},
-				Assigner:   "=",
-				Referenced: true,
+				Assigner: "=",
 			},
 			&Assignment{
 				Name:      "boo",
 				NamePos:   mkpos(49, 5, 3),
 				EqualsPos: mkpos(53, 5, 7),
-				Value: &Operator{
-					Args: [2]Expression{
-						&Variable{
-							Name:    "baz",
-							NamePos: mkpos(55, 5, 9),
-							Value: &Operator{
-								OperatorPos: mkpos(41, 4, 13),
-								Operator:    '+',
-								Value: &Int64{
-									LiteralPos: mkpos(9, 2, 9),
-									Value:      2000000,
-								},
-								Args: [2]Expression{
-									&Variable{
-										Name:    "foo",
-										NamePos: mkpos(37, 4, 9),
-										Value: &Int64{
-											LiteralPos: mkpos(9, 2, 9),
-											Value:      1000000,
-											Token:      "1000000",
-										},
-									},
-									&Variable{
-										Name:    "bar",
-										NamePos: mkpos(43, 4, 15),
-										Value: &Variable{
-											Name:    "foo",
-											NamePos: mkpos(25, 3, 9),
-											Value: &Int64{
-												LiteralPos: mkpos(9, 2, 9),
-												Value:      1000000,
-												Token:      "1000000",
-											},
-										},
-									},
-								},
-							},
-						},
-						&Variable{
-							Name:    "foo",
-							NamePos: mkpos(68, 6, 10),
-							Value: &Int64{
-								LiteralPos: mkpos(9, 2, 9),
-								Value:      1000000,
-								Token:      "1000000",
-							},
-						},
-					},
-					OperatorPos: mkpos(66, 6, 8),
-					Operator:    '+',
-					Value: &Int64{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      3000000,
-					},
-				},
-				OrigValue: &Variable{
+				Value: &Variable{
 					Name:    "baz",
 					NamePos: mkpos(55, 5, 9),
-					Value: &Operator{
-						OperatorPos: mkpos(41, 4, 13),
-						Operator:    '+',
-						Value: &Int64{
-							LiteralPos: mkpos(9, 2, 9),
-							Value:      2000000,
-						},
-						Args: [2]Expression{
-							&Variable{
-								Name:    "foo",
-								NamePos: mkpos(37, 4, 9),
-								Value: &Int64{
-									LiteralPos: mkpos(9, 2, 9),
-									Value:      1000000,
-									Token:      "1000000",
-								},
-							},
-							&Variable{
-								Name:    "bar",
-								NamePos: mkpos(43, 4, 15),
-								Value: &Variable{
-									Name:    "foo",
-									NamePos: mkpos(25, 3, 9),
-									Value: &Int64{
-										LiteralPos: mkpos(9, 2, 9),
-										Value:      1000000,
-										Token:      "1000000",
-									},
-								},
-							},
-						},
-					},
 				},
 				Assigner: "=",
 			},
@@ -1090,20 +728,6 @@ var validParseTestCases = []struct {
 				Value: &Variable{
 					Name:    "foo",
 					NamePos: mkpos(68, 6, 10),
-					Value: &Int64{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      1000000,
-						Token:      "1000000",
-					},
-				},
-				OrigValue: &Variable{
-					Name:    "foo",
-					NamePos: mkpos(68, 6, 10),
-					Value: &Int64{
-						LiteralPos: mkpos(9, 2, 9),
-						Value:      1000000,
-						Token:      "1000000",
-					},
 				},
 				Assigner: "+=",
 			},
@@ -1171,7 +795,7 @@ func TestParseValidInput(t *testing.T) {
 	for i, testCase := range validParseTestCases {
 		t.Run(strconv.Itoa(i), func(t *testing.T) {
 			r := bytes.NewBufferString(testCase.input)
-			file, errs := ParseAndEval("", r, NewScope(nil))
+			file, errs := Parse("", r)
 			if len(errs) != 0 {
 				t.Errorf("test case: %s", testCase.input)
 				t.Errorf("unexpected errors:")
@@ -1236,6 +860,17 @@ func TestParserError(t *testing.T) {
 			`,
 			err: "Duplicate select condition found: arch()",
 		},
+		{
+			name: "select with duplicate binding",
+			input: `
+			m {
+				foo: select((arch(), os()), {
+					(any @ bar, any @ bar): true,
+				}),
+			}
+			`,
+			err: "Found duplicate select pattern binding: bar",
+		},
 		// TODO: test more parser errors
 	}
 
@@ -1284,7 +919,7 @@ func TestParserEndPos(t *testing.T) {
 
 	r := bytes.NewBufferString(in)
 
-	file, errs := ParseAndEval("", r, NewScope(nil))
+	file, errs := Parse("", r)
 	if len(errs) != 0 {
 		t.Errorf("unexpected errors:")
 		for _, err := range errs {
@@ -1318,9 +953,8 @@ func TestParserEndPos(t *testing.T) {
 
 func TestParserNotEvaluated(t *testing.T) {
 	// When parsing without evaluation, create variables correctly
-	scope := NewScope(nil)
 	input := "FOO=abc\n"
-	_, errs := Parse("", bytes.NewBufferString(input), scope)
+	file, errs := Parse("", bytes.NewBufferString(input))
 	if errs != nil {
 		t.Errorf("unexpected errors:")
 		for _, err := range errs {
@@ -1328,11 +962,11 @@ func TestParserNotEvaluated(t *testing.T) {
 		}
 		t.FailNow()
 	}
-	assignment, found := scope.Get("FOO")
-	if !found {
+	assignment, ok := file.Defs[0].(*Assignment)
+	if !ok || assignment.Name != "FOO" {
 		t.Fatalf("Expected to find FOO after parsing %s", input)
 	}
-	if s := assignment.String(); strings.Contains(s, "PANIC") {
-		t.Errorf("Attempt to print FOO returned %s", s)
+	if assignment.Value.String() != "abc" {
+		t.Errorf("Attempt to print FOO returned %s", assignment.Value.String())
 	}
 }
diff --git a/parser/printer.go b/parser/printer.go
index c3ecf96d5c..349119f377 100644
--- a/parser/printer.go
+++ b/parser/printer.go
@@ -99,7 +99,7 @@ func (p *printer) printAssignment(assignment *Assignment) {
 	p.requestSpace()
 	p.printToken(assignment.Assigner, assignment.EqualsPos)
 	p.requestSpace()
-	p.printExpression(assignment.OrigValue)
+	p.printExpression(assignment.Value)
 	p.requestNewline()
 }
 
@@ -134,7 +134,7 @@ func (p *printer) printExpression(value Expression) {
 	case *Select:
 		p.printSelect(v)
 	default:
-		panic(fmt.Errorf("bad property type: %s", value.Type()))
+		panic(fmt.Errorf("bad property type: %v", value))
 	}
 }
 
@@ -143,7 +143,7 @@ func (p *printer) printSelect(s *Select) {
 		return
 	}
 	if len(s.Cases) == 1 && len(s.Cases[0].Patterns) == 1 {
-		if str, ok := s.Cases[0].Patterns[0].(*String); ok && str.Value == default_select_branch_name {
+		if str, ok := s.Cases[0].Patterns[0].Value.(*String); ok && str.Value == default_select_branch_name {
 			p.printExpression(s.Cases[0].Value)
 			p.pos = s.RBracePos
 			return
@@ -196,22 +196,7 @@ func (p *printer) printSelect(s *Select) {
 			p.printToken("(", p.pos)
 		}
 		for i, pat := range c.Patterns {
-			switch pat := pat.(type) {
-			case *String:
-				if pat.Value != default_select_branch_name {
-					p.printToken(strconv.Quote(pat.Value), pat.LiteralPos)
-				} else {
-					p.printToken("default", pat.LiteralPos)
-				}
-			case *Bool:
-				s := "false"
-				if pat.Value {
-					s = "true"
-				}
-				p.printToken(s, pat.LiteralPos)
-			default:
-				panic("Unhandled case")
-			}
+			p.printSelectPattern(pat)
 			if i < len(c.Patterns)-1 {
 				p.printToken(",", p.pos)
 				p.requestSpace()
@@ -222,7 +207,7 @@ func (p *printer) printSelect(s *Select) {
 		}
 		p.printToken(":", c.ColonPos)
 		p.requestSpace()
-		if unset, ok := c.Value.(UnsetProperty); ok {
+		if unset, ok := c.Value.(*UnsetProperty); ok {
 			p.printToken(unset.String(), unset.Pos())
 		} else {
 			p.printExpression(c.Value)
@@ -240,6 +225,33 @@ func (p *printer) printSelect(s *Select) {
 	}
 }
 
+func (p *printer) printSelectPattern(pat SelectPattern) {
+	switch pat := pat.Value.(type) {
+	case *String:
+		if pat.Value == default_select_branch_name {
+			p.printToken("default", pat.LiteralPos)
+		} else if pat.Value == any_select_branch_name {
+			p.printToken("any", pat.LiteralPos)
+		} else {
+			p.printToken(strconv.Quote(pat.Value), pat.LiteralPos)
+		}
+	case *Bool:
+		s := "false"
+		if pat.Value {
+			s = "true"
+		}
+		p.printToken(s, pat.LiteralPos)
+	default:
+		panic("Unhandled case")
+	}
+	if pat.Binding.Name != "" {
+		p.requestSpace()
+		p.printToken("@", pat.Binding.Pos())
+		p.requestSpace()
+		p.printExpression(&pat.Binding)
+	}
+}
+
 func (p *printer) printList(list []Expression, pos, endPos scanner.Position) {
 	p.requestSpace()
 	p.printToken("[", pos)
diff --git a/parser/printer_test.go b/parser/printer_test.go
index 60568eb2e1..040c4b5f5b 100644
--- a/parser/printer_test.go
+++ b/parser/printer_test.go
@@ -733,6 +733,26 @@ foo {
         default: [],
     }),
 }
+`,
+	},
+	{
+		name: "Select with bindings",
+		input: `
+foo {
+    stuff: select(arch(), {
+        "x86": "a",
+        any
+          @ baz: "b" + baz,
+    }),
+}
+`,
+		output: `
+foo {
+    stuff: select(arch(), {
+        "x86": "a",
+        any @ baz: "b" + baz,
+    }),
+}
 `,
 	},
 }
@@ -744,7 +764,7 @@ func TestPrinter(t *testing.T) {
 			expected := testCase.output[1:]
 
 			r := bytes.NewBufferString(in)
-			file, errs := Parse("", r, NewScope(nil))
+			file, errs := Parse("", r)
 			if len(errs) != 0 {
 				t.Errorf("test case: %s", in)
 				t.Errorf("unexpected errors:")
diff --git a/parser/sort.go b/parser/sort.go
index 52ff9f5a19..1b8fd8c180 100644
--- a/parser/sort.go
+++ b/parser/sort.go
@@ -282,8 +282,8 @@ func isListOfPrimitives(values []Expression) bool {
 	if len(values) == 0 {
 		return true
 	}
-	switch values[0].Type() {
-	case BoolType, StringType, Int64Type:
+	switch values[0].(type) {
+	case *Bool, *String, *Int64:
 		return true
 	default:
 		return false
diff --git a/pathtools/fs.go b/pathtools/fs.go
index 25e295f7f1..58666cf615 100644
--- a/pathtools/fs.go
+++ b/pathtools/fs.go
@@ -18,11 +18,13 @@ import (
 	"bytes"
 	"fmt"
 	"io"
+	"io/fs"
 	"io/ioutil"
 	"os"
 	"path/filepath"
 	"sort"
 	"strings"
+	"sync"
 	"syscall"
 	"time"
 )
@@ -92,6 +94,10 @@ type FileSystem interface {
 	// Open opens a file for reading. Follows symlinks.
 	Open(name string) (ReaderAtSeekerCloser, error)
 
+	// OpenFile opens a file for read/write, if the file does not exist, and the
+	// O_CREATE flag is passed, it is created with mode perm (before umask).
+	OpenFile(name string, flag int, perm fs.FileMode) (io.WriteCloser, error)
+
 	// Exists returns whether the file exists and whether it is a directory.  Follows symlinks.
 	Exists(name string) (bool, bool, error)
 
@@ -203,6 +209,15 @@ func (fs *osFs) Open(name string) (ReaderAtSeekerCloser, error) {
 	return &OsFile{f, fs}, nil
 }
 
+func (fs *osFs) OpenFile(name string, flag int, perm fs.FileMode) (io.WriteCloser, error) {
+	fs.acquire()
+	f, err := os.OpenFile(fs.toAbs(name), flag, perm)
+	if err != nil {
+		return nil, err
+	}
+	return &OsFile{f, fs}, nil
+}
+
 func (fs *osFs) Exists(name string) (bool, bool, error) {
 	stat, err := os.Stat(fs.toAbs(name))
 	if err == nil {
@@ -282,6 +297,7 @@ type mockFs struct {
 	dirs     map[string]bool
 	symlinks map[string]string
 	all      []string
+	lock     sync.RWMutex
 }
 
 func (m *mockFs) followSymlinks(name string) string {
@@ -310,6 +326,8 @@ func (m *mockFs) followSymlinks(name string) string {
 }
 
 func (m *mockFs) Open(name string) (ReaderAtSeekerCloser, error) {
+	m.lock.RLock()
+	defer m.lock.RUnlock()
 	name = filepath.Clean(name)
 	name = m.followSymlinks(name)
 	if f, ok := m.files[name]; ok {
@@ -329,7 +347,40 @@ func (m *mockFs) Open(name string) (ReaderAtSeekerCloser, error) {
 	}
 }
 
+type MockFileWriter struct {
+	name string
+	fs   *mockFs
+}
+
+func (b *MockFileWriter) Write(p []byte) (n int, err error) {
+	b.fs.lock.Lock()
+	defer b.fs.lock.Unlock()
+	b.fs.files[b.name] = append(b.fs.files[b.name], p...)
+	return n, nil
+}
+func (m *mockFs) OpenFile(name string, flag int, perm fs.FileMode) (io.WriteCloser, error) {
+	// For mockFs we simplify the logic here by just either creating a new file or
+	// truncating an existing one.
+	m.lock.Lock()
+	defer m.lock.Unlock()
+	name = filepath.Clean(name)
+	name = m.followSymlinks(name)
+	m.files[name] = []byte{}
+	return struct {
+		io.Closer
+		io.Writer
+	}{
+		ioutil.NopCloser(nil),
+		&MockFileWriter{
+			name: name,
+			fs:   m,
+		},
+	}, nil
+}
+
 func (m *mockFs) Exists(name string) (bool, bool, error) {
+	m.lock.RLock()
+	defer m.lock.RUnlock()
 	name = filepath.Clean(name)
 	name = m.followSymlinks(name)
 	if _, ok := m.files[name]; ok {
@@ -342,6 +393,8 @@ func (m *mockFs) Exists(name string) (bool, bool, error) {
 }
 
 func (m *mockFs) IsDir(name string) (bool, error) {
+	m.lock.RLock()
+	defer m.lock.RUnlock()
 	dir := filepath.Dir(name)
 	if dir != "." && dir != "/" {
 		isDir, err := m.IsDir(dir)
@@ -370,6 +423,8 @@ func (m *mockFs) IsDir(name string) (bool, error) {
 }
 
 func (m *mockFs) IsSymlink(name string) (bool, error) {
+	m.lock.RLock()
+	defer m.lock.RUnlock()
 	dir, file := quickSplit(name)
 	dir = m.followSymlinks(dir)
 	name = filepath.Join(dir, file)
@@ -442,6 +497,8 @@ func (ms *mockStat) ModTime() time.Time { return time.Time{} }
 func (ms *mockStat) Sys() interface{}   { return nil }
 
 func (m *mockFs) Lstat(name string) (os.FileInfo, error) {
+	m.lock.RLock()
+	defer m.lock.RUnlock()
 	dir, file := quickSplit(name)
 	dir = m.followSymlinks(dir)
 	name = filepath.Join(dir, file)
@@ -466,6 +523,8 @@ func (m *mockFs) Lstat(name string) (os.FileInfo, error) {
 }
 
 func (m *mockFs) Stat(name string) (os.FileInfo, error) {
+	m.lock.RLock()
+	defer m.lock.RUnlock()
 	name = filepath.Clean(name)
 	origName := name
 	name = m.followSymlinks(name)
diff --git a/pathtools/glob.go b/pathtools/glob.go
index 5b2d685282..3de041ea58 100644
--- a/pathtools/glob.go
+++ b/pathtools/glob.go
@@ -21,6 +21,7 @@ import (
 	"io/ioutil"
 	"os"
 	"path/filepath"
+	"slices"
 	"strings"
 )
 
@@ -47,6 +48,15 @@ func (result GlobResult) FileList() []byte {
 	return []byte(strings.Join(result.Matches, "\n") + "\n")
 }
 
+func (result GlobResult) Clone() GlobResult {
+	return GlobResult{
+		Pattern:  result.Pattern,
+		Excludes: slices.Clone(result.Excludes),
+		Matches:  slices.Clone(result.Matches),
+		Deps:     slices.Clone(result.Deps),
+	}
+}
+
 // MultipleGlobResults is a list of GlobResult structs.
 type MultipleGlobResults []GlobResult
 
diff --git a/proptools/configurable.go b/proptools/configurable.go
index 8f101b14ee..e8cc7b728f 100644
--- a/proptools/configurable.go
+++ b/proptools/configurable.go
@@ -21,6 +21,7 @@ import (
 	"strings"
 
 	"github.com/google/blueprint/optional"
+	"github.com/google/blueprint/parser"
 )
 
 // ConfigurableOptional is the same as ShallowOptional, but we use this separate
@@ -150,6 +151,17 @@ type ConfigurableValue struct {
 	boolValue   bool
 }
 
+func (c *ConfigurableValue) toExpression() parser.Expression {
+	switch c.typ {
+	case configurableValueTypeBool:
+		return &parser.Bool{Value: c.boolValue}
+	case configurableValueTypeString:
+		return &parser.String{Value: c.stringValue}
+	default:
+		panic(fmt.Sprintf("Unhandled configurableValueType: %s", c.typ.String()))
+	}
+}
+
 func (c *ConfigurableValue) String() string {
 	switch c.typ {
 	case configurableValueTypeString:
@@ -193,6 +205,7 @@ const (
 	configurablePatternTypeString configurablePatternType = iota
 	configurablePatternTypeBool
 	configurablePatternTypeDefault
+	configurablePatternTypeAny
 )
 
 func (v *configurablePatternType) String() string {
@@ -203,6 +216,8 @@ func (v *configurablePatternType) String() string {
 		return "bool"
 	case configurablePatternTypeDefault:
 		return "default"
+	case configurablePatternTypeAny:
+		return "any"
 	default:
 		panic("unimplemented")
 	}
@@ -222,6 +237,7 @@ type ConfigurablePattern struct {
 	typ         configurablePatternType
 	stringValue string
 	boolValue   bool
+	binding     string
 }
 
 func NewStringConfigurablePattern(s string) ConfigurablePattern {
@@ -251,6 +267,9 @@ func (p *ConfigurablePattern) matchesValue(v ConfigurableValue) bool {
 	if v.typ == configurableValueTypeUndefined {
 		return false
 	}
+	if p.typ == configurablePatternTypeAny {
+		return true
+	}
 	if p.typ != v.typ.patternType() {
 		return false
 	}
@@ -271,6 +290,9 @@ func (p *ConfigurablePattern) matchesValueType(v ConfigurableValue) bool {
 	if v.typ == configurableValueTypeUndefined {
 		return true
 	}
+	if p.typ == configurablePatternTypeAny {
+		return true
+	}
 	return p.typ == v.typ.patternType()
 }
 
@@ -282,27 +304,46 @@ func (p *ConfigurablePattern) matchesValueType(v ConfigurableValue) bool {
 // different configurable properties.
 type ConfigurableCase[T ConfigurableElements] struct {
 	patterns []ConfigurablePattern
-	value    *T
+	value    parser.Expression
 }
 
 type configurableCaseReflection interface {
-	initialize(patterns []ConfigurablePattern, value interface{})
+	initialize(patterns []ConfigurablePattern, value parser.Expression)
 }
 
 var _ configurableCaseReflection = &ConfigurableCase[string]{}
 
 func NewConfigurableCase[T ConfigurableElements](patterns []ConfigurablePattern, value *T) ConfigurableCase[T] {
+	var valueExpr parser.Expression
+	if value == nil {
+		valueExpr = &parser.UnsetProperty{}
+	} else {
+		switch v := any(value).(type) {
+		case *string:
+			valueExpr = &parser.String{Value: *v}
+		case *bool:
+			valueExpr = &parser.Bool{Value: *v}
+		case *[]string:
+			innerValues := make([]parser.Expression, 0, len(*v))
+			for _, x := range *v {
+				innerValues = append(innerValues, &parser.String{Value: x})
+			}
+			valueExpr = &parser.List{Values: innerValues}
+		default:
+			panic(fmt.Sprintf("should be unreachable due to the ConfigurableElements restriction: %#v", value))
+		}
+	}
 	// Clone the values so they can't be modified from soong
 	patterns = slices.Clone(patterns)
 	return ConfigurableCase[T]{
 		patterns: patterns,
-		value:    copyConfiguredValuePtr(value),
+		value:    valueExpr,
 	}
 }
 
-func (c *ConfigurableCase[T]) initialize(patterns []ConfigurablePattern, value interface{}) {
+func (c *ConfigurableCase[T]) initialize(patterns []ConfigurablePattern, value parser.Expression) {
 	c.patterns = patterns
-	c.value = value.(*T)
+	c.value = value
 }
 
 // for the given T, return the reflect.type of configurableCase[T]
@@ -371,6 +412,22 @@ type Configurable[T ConfigurableElements] struct {
 	marker       configurableMarker
 	propertyName string
 	inner        *configurableInner[T]
+	// See Configurable.evaluate for a description of the postProcessor algorithm and
+	// why this is a 2d list
+	postProcessors *[][]postProcessor[T]
+}
+
+type postProcessor[T ConfigurableElements] struct {
+	f func(T) T
+	// start and end represent the range of configurableInners
+	// that this postprocessor is applied to. When appending two configurables
+	// together, the start and end values will stay the same for the left
+	// configurable's postprocessors, but the rights will be rebased by the
+	// number of configurableInners in the left configurable. This way
+	// the postProcessors still only apply to the configurableInners they
+	// origionally applied to before the appending.
+	start int
+	end   int
 }
 
 type configurableInner[T ConfigurableElements] struct {
@@ -384,6 +441,7 @@ type configurableInner[T ConfigurableElements] struct {
 type singleConfigurable[T ConfigurableElements] struct {
 	conditions []ConfigurableCondition
 	cases      []ConfigurableCase[T]
+	scope      *parser.Scope
 }
 
 // Ignore the warning about the unused marker variable, it's used via reflection
@@ -398,6 +456,7 @@ func NewConfigurable[T ConfigurableElements](conditions []ConfigurableCondition,
 	// Clone the slices so they can't be modified from soong
 	conditions = slices.Clone(conditions)
 	cases = slices.Clone(cases)
+	var zeroPostProcessors [][]postProcessor[T]
 	return Configurable[T]{
 		inner: &configurableInner[T]{
 			single: singleConfigurable[T]{
@@ -405,35 +464,87 @@ func NewConfigurable[T ConfigurableElements](conditions []ConfigurableCondition,
 				cases:      cases,
 			},
 		},
+		postProcessors: &zeroPostProcessors,
+	}
+}
+
+func NewSimpleConfigurable[T ConfigurableElements](value T) Configurable[T] {
+	return NewConfigurable(nil, []ConfigurableCase[T]{
+		NewConfigurableCase(nil, &value),
+	})
+}
+
+func newConfigurableWithPropertyName[T ConfigurableElements](propertyName string, conditions []ConfigurableCondition, cases []ConfigurableCase[T], addScope bool) Configurable[T] {
+	result := NewConfigurable(conditions, cases)
+	result.propertyName = propertyName
+	if addScope {
+		for curr := result.inner; curr != nil; curr = curr.next {
+			curr.single.scope = parser.NewScope(nil)
+		}
 	}
+	return result
 }
 
 func (c *Configurable[T]) AppendSimpleValue(value T) {
 	value = copyConfiguredValue(value)
 	// This may be a property that was never initialized from a bp file
 	if c.inner == nil {
-		c.inner = &configurableInner[T]{
-			single: singleConfigurable[T]{
-				cases: []ConfigurableCase[T]{{
-					value: &value,
-				}},
-			},
-		}
+		c.initialize(nil, "", nil, []ConfigurableCase[T]{{
+			value: configuredValueToExpression(value),
+		}})
 		return
 	}
 	c.inner.appendSimpleValue(value)
 }
 
+// AddPostProcessor adds a function that will modify the result of
+// Get() when Get() is called. It operates on all the current contents
+// of the Configurable property, but if other values are appended to
+// the Configurable property afterwards, the postProcessor will not run
+// on them. This can be useful to essentially modify a configurable
+// property without evaluating it.
+func (c *Configurable[T]) AddPostProcessor(p func(T) T) {
+	// Add the new postProcessor on top of the tallest stack of postProcessors.
+	// See Configurable.evaluate for more details on the postProcessors algorithm
+	// and data structure.
+	num_links := c.inner.numLinks()
+	if c.postProcessors == nil {
+		var nilCases []ConfigurableCase[T]
+		c.initialize(nil, "", nil, nilCases)
+	}
+	if len(*c.postProcessors) == 0 {
+		*c.postProcessors = [][]postProcessor[T]{{{
+			f:     p,
+			start: 0,
+			end:   num_links,
+		}}}
+	} else {
+		deepestI := 0
+		deepestDepth := 0
+		for i := 0; i < len(*c.postProcessors); i++ {
+			if len((*c.postProcessors)[i]) > deepestDepth {
+				deepestDepth = len((*c.postProcessors)[i])
+				deepestI = i
+			}
+		}
+		(*c.postProcessors)[deepestI] = append((*c.postProcessors)[deepestI], postProcessor[T]{
+			f:     p,
+			start: 0,
+			end:   num_links,
+		})
+	}
+}
+
 // Get returns the final value for the configurable property.
 // A configurable property may be unset, in which case Get will return nil.
 func (c *Configurable[T]) Get(evaluator ConfigurableEvaluator) ConfigurableOptional[T] {
-	result := c.inner.evaluate(c.propertyName, evaluator)
+	result := c.evaluate(c.propertyName, evaluator)
 	return configuredValuePtrToOptional(result)
 }
 
 // GetOrDefault is the same as Get, but will return the provided default value if the property was unset.
 func (c *Configurable[T]) GetOrDefault(evaluator ConfigurableEvaluator, defaultValue T) T {
-	result := c.inner.evaluate(c.propertyName, evaluator)
+	result := c.evaluate(c.propertyName, evaluator)
 	if result != nil {
 		// Copy the result so that it can't be changed from soong
 		return copyConfiguredValue(*result)
@@ -441,6 +552,127 @@ func (c *Configurable[T]) GetOrDefault(evaluator ConfigurableEvaluator, defaultV
 	return defaultValue
 }
 
+type valueAndIndices[T ConfigurableElements] struct {
+	value   *T
+	replace bool
+	// Similar to start/end in postProcessor, these represent the origional
+	// range or configurableInners that this merged group represents. It's needed
+	// in order to apply recursive postProcessors to only the relevant
+	// configurableInners, even after those configurableInners have been merged
+	// in order to apply an earlier postProcessor.
+	start int
+	end   int
+}
+
+func (c *Configurable[T]) evaluate(propertyName string, evaluator ConfigurableEvaluator) *T {
+	if c.inner == nil {
+		return nil
+	}
+
+	if len(*c.postProcessors) == 0 {
+		// Use a simpler algorithm if there are no postprocessors
+		return c.inner.evaluate(propertyName, evaluator)
+	}
+
+	// The basic idea around evaluating with postprocessors is that each individual
+	// node in the chain (each configurableInner) is first evaluated, and then when
+	// a postprocessor operates on a certain range, that range is merged before passing
+	// it to the postprocessor. We want postProcessors to only accept a final merged
+	// value instead of a linked list, but at the same time, only operate over a portion
+	// of the list. If more configurables are appended onto this one, their values won't
+	// be operated on by the existing postProcessors, but they may have their own
+	// postprocessors.
+	//
+	// _____________________
+	// |         __________|
+	// ______    |    _____|        ___
+	// |    |         |    |        | |
+	// a -> b -> c -> d -> e -> f -> g
+	//
+	// In this diagram, the letters along the bottom is the chain of configurableInners.
+	// The brackets on top represent postprocessors, where higher brackets are processed
+	// after lower ones.
+	//
+	// To evaluate this example, first we evaluate the raw values for all nodes a->g.
+	// Then we merge nodes a/b and d/e and apply the postprocessors to their merged values,
+	// and also to g. Those merged and postprocessed nodes are then reinserted into the
+	// list, and we move on to doing the higher level postprocessors (starting with the c->e one)
+	// in the same way. When all postprocessors are done, a final merge is done on anything
+	// leftover.
+	//
+	// The Configurable.postProcessors field is a 2d array to represent this hierarchy.
+	// The outer index moves right on this graph, the inner index goes up.
+	// When adding a new postProcessor, it will always be the last postProcessor to run
+	// until another is added or another configurable is appended. So in AddPostProcessor(),
+	// we add it to the tallest existing stack.
+
+	var currentValues []valueAndIndices[T]
+	for curr, i := c.inner, 0; curr != nil; curr, i = curr.next, i+1 {
+		value := curr.single.evaluateNonTransitive(propertyName, evaluator)
+		currentValues = append(currentValues, valueAndIndices[T]{
+			value:   value,
+			replace: curr.replace,
+			start:   i,
+			end:     i + 1,
+		})
+	}
+
+	if c.postProcessors == nil || len(*c.postProcessors) == 0 {
+		return mergeValues(currentValues).value
+	}
+
+	foundPostProcessor := true
+	for depth := 0; foundPostProcessor; depth++ {
+		foundPostProcessor = false
+		var newValues []valueAndIndices[T]
+		i := 0
+		for _, postProcessorGroup := range *c.postProcessors {
+			if len(postProcessorGroup) > depth {
+				foundPostProcessor = true
+				postProcessor := postProcessorGroup[depth]
+				startI := 0
+				endI := 0
+				for currentValues[startI].start < postProcessor.start {
+					startI++
+				}
+				for currentValues[endI].end < postProcessor.end {
+					endI++
+				}
+				endI++
+				newValues = append(newValues, currentValues[i:startI]...)
+				merged := mergeValues(currentValues[startI:endI])
+				if merged.value != nil {
+					processed := postProcessor.f(*merged.value)
+					merged.value = &processed
+				}
+				newValues = append(newValues, merged)
+				i = endI
+			}
+		}
+		newValues = append(newValues, currentValues[i:]...)
+		currentValues = newValues
+	}
+
+	return mergeValues(currentValues).value
+}
+
+func mergeValues[T ConfigurableElements](values []valueAndIndices[T]) valueAndIndices[T] {
+	if len(values) < 0 {
+		panic("Expected at least 1 value in mergeValues")
+	}
+	result := values[0]
+	for i := 1; i < len(values); i++ {
+		if result.replace {
+			result.value = replaceConfiguredValues(result.value, values[i].value)
+		} else {
+			result.value = appendConfiguredValues(result.value, values[i].value)
+		}
+		result.end = values[i].end
+		result.replace = values[i].replace
+	}
+	return result
+}
+
 func (c *configurableInner[T]) evaluate(propertyName string, evaluator ConfigurableEvaluator) *T {
 	if c == nil {
 		return nil
@@ -472,7 +704,12 @@ func (c *singleConfigurable[T]) evaluateNonTransitive(propertyName string, evalu
 		if len(c.cases) == 0 {
 			return nil
 		} else if len(c.cases) == 1 {
-			return c.cases[0].value
+			if result, err := expressionToConfiguredValue[T](c.cases[0].value, c.scope); err != nil {
+				evaluator.PropertyErrorf(propertyName, "%s", err.Error())
+				return nil
+			} else {
+				return result
+			}
 		} else {
 			evaluator.PropertyErrorf(propertyName, "Expected 0 or 1 branches in an unconfigured select, found %d", len(c.cases))
 			return nil
@@ -499,7 +736,13 @@ func (c *singleConfigurable[T]) evaluateNonTransitive(propertyName string, evalu
 			}
 		}
 		if allMatch && !foundMatch {
-			result = case_.value
+			newScope := createScopeWithBindings(c.scope, case_.patterns, values)
+			if r, err := expressionToConfiguredValue[T](case_.value, newScope); err != nil {
+				evaluator.PropertyErrorf(propertyName, "%s", err.Error())
+				return nil
+			} else {
+				result = r
+			}
 			foundMatch = true
 		}
 	}
@@ -511,6 +754,27 @@ func (c *singleConfigurable[T]) evaluateNonTransitive(propertyName string, evalu
 	return nil
 }
 
+func createScopeWithBindings(parent *parser.Scope, patterns []ConfigurablePattern, values []ConfigurableValue) *parser.Scope {
+	result := parent
+	for i, pattern := range patterns {
+		if pattern.binding != "" {
+			if result == parent {
+				result = parser.NewScope(parent)
+			}
+			err := result.HandleAssignment(&parser.Assignment{
+				Name:     pattern.binding,
+				Value:    values[i].toExpression(),
+				Assigner: "=",
+			})
+			if err != nil {
+				// This shouldn't happen due to earlier validity checks
+				panic(err.Error())
+			}
+		}
+	}
+	return result
+}
+
 func appendConfiguredValues[T ConfigurableElements](a, b *T) *T {
 	if a == nil && b == nil {
 		return nil
@@ -579,20 +843,27 @@ type configurableReflection interface {
 // Same as configurableReflection, but since initialize needs to take a pointer
 // to a Configurable, it was broken out into a separate interface.
 type configurablePtrReflection interface {
-	initialize(propertyName string, conditions []ConfigurableCondition, cases any)
+	initialize(scope *parser.Scope, propertyName string, conditions []ConfigurableCondition, cases any)
 }
 
 var _ configurableReflection = Configurable[string]{}
 var _ configurablePtrReflection = &Configurable[string]{}
 
-func (c *Configurable[T]) initialize(propertyName string, conditions []ConfigurableCondition, cases any) {
+func (c *Configurable[T]) initialize(scope *parser.Scope, propertyName string, conditions []ConfigurableCondition, cases any) {
 	c.propertyName = propertyName
 	c.inner = &configurableInner[T]{
 		single: singleConfigurable[T]{
 			conditions: conditions,
 			cases:      cases.([]ConfigurableCase[T]),
+			scope:      scope,
 		},
 	}
+	var postProcessors [][]postProcessor[T]
+	c.postProcessors = &postProcessors
+}
+
+func (c *Configurable[T]) Append(other Configurable[T]) {
+	c.setAppend(other, false, false)
 }
 
 func (c Configurable[T]) setAppend(append any, replace bool, prepend bool) {
@@ -600,12 +871,37 @@ func (c Configurable[T]) setAppend(append any, replace bool, prepend bool) {
 	if a.inner.isEmpty() {
 		return
 	}
+
+	if prepend {
+		newBase := a.inner.numLinks()
+		*c.postProcessors = appendPostprocessors(*a.postProcessors, *c.postProcessors, newBase)
+	} else {
+		newBase := c.inner.numLinks()
+		*c.postProcessors = appendPostprocessors(*c.postProcessors, *a.postProcessors, newBase)
+	}
+
 	c.inner.setAppend(a.inner, replace, prepend)
 	if c.inner == c.inner.next {
 		panic("pointer loop")
 	}
 }
 
+func appendPostprocessors[T ConfigurableElements](a, b [][]postProcessor[T], newBase int) [][]postProcessor[T] {
+	var result [][]postProcessor[T]
+	for i := 0; i < len(a); i++ {
+		result = append(result, slices.Clone(a[i]))
+	}
+	for i := 0; i < len(b); i++ {
+		n := slices.Clone(b[i])
+		for j := 0; j < len(n); j++ {
+			n[j].start += newBase
+			n[j].end += newBase
+		}
+		result = append(result, n)
+	}
+	return result
+}
+
 func (c *configurableInner[T]) setAppend(append *configurableInner[T], replace bool, prepend bool) {
 	if c.isEmpty() {
 		*c = *append.clone()
@@ -644,13 +940,21 @@ func (c *configurableInner[T]) setAppend(append *configurableInner[T], replace b
 	}
 }
 
+func (c *configurableInner[T]) numLinks() int {
+	result := 0
+	for curr := c; curr != nil; curr = curr.next {
+		result++
+	}
+	return result
+}
+
 func (c *configurableInner[T]) appendSimpleValue(value T) {
 	if c.next == nil {
 		c.replace = false
 		c.next = &configurableInner[T]{
 			single: singleConfigurable[T]{
 				cases: []ConfigurableCase[T]{{
-					value: &value,
+					value: configuredValueToExpression(value),
 				}},
 			},
 		}
@@ -678,46 +982,28 @@ func (c *singleConfigurable[T]) printfInto(value string) error {
 		if c.value == nil {
 			continue
 		}
-		switch v := any(c.value).(type) {
-		case *string:
-			if err := printfIntoString(v, value); err != nil {
-				return err
-			}
-		case *[]string:
-			for i := range *v {
-				if err := printfIntoString(&((*v)[i]), value); err != nil {
-					return err
-				}
-			}
+		if err := c.value.PrintfInto(value); err != nil {
+			return err
 		}
 	}
 	return nil
 }
 
-func printfIntoString(s *string, configValue string) error {
-	count := strings.Count(*s, "%")
-	if count == 0 {
-		return nil
-	}
-
-	if count > 1 {
-		return fmt.Errorf("list/value variable properties only support a single '%%'")
+func (c Configurable[T]) clone() any {
+	var newPostProcessors *[][]postProcessor[T]
+	if c.postProcessors != nil {
+		x := appendPostprocessors(*c.postProcessors, nil, 0)
+		newPostProcessors = &x
 	}
-
-	if !strings.Contains(*s, "%s") {
-		return fmt.Errorf("unsupported %% in value variable property")
+	return Configurable[T]{
+		propertyName:   c.propertyName,
+		inner:          c.inner.clone(),
+		postProcessors: newPostProcessors,
 	}
-
-	*s = fmt.Sprintf(*s, configValue)
-
-	return nil
 }
 
-func (c Configurable[T]) clone() any {
-	return Configurable[T]{
-		propertyName: c.propertyName,
-		inner:        c.inner.clone(),
-	}
+func (c Configurable[T]) Clone() Configurable[T] {
+	return c.clone().(Configurable[T])
 }
 
 func (c *configurableInner[T]) clone() *configurableInner[T] {
@@ -755,6 +1041,9 @@ func (c *singleConfigurable[T]) isEmpty() bool {
 		return false
 	}
 	if len(c.cases) == 1 && c.cases[0].value != nil {
+		if _, ok := c.cases[0].value.(*parser.UnsetProperty); ok {
+			return true
+		}
 		return false
 	}
 	return true
@@ -774,7 +1063,7 @@ func (c *singleConfigurable[T]) alwaysHasValue() bool {
 		return false
 	}
 	for _, c := range c.cases {
-		if c.value == nil {
+		if _, isUnset := c.value.(*parser.UnsetProperty); isUnset || c.value == nil {
 			return false
 		}
 	}
@@ -785,30 +1074,75 @@ func (c Configurable[T]) configuredType() reflect.Type {
 	return reflect.TypeOf((*T)(nil)).Elem()
 }
 
-func copyConfiguredValuePtr[T ConfigurableElements](t *T) *T {
-	if t == nil {
-		return nil
+func expressionToConfiguredValue[T ConfigurableElements](expr parser.Expression, scope *parser.Scope) (*T, error) {
+	expr, err := expr.Eval(scope)
+	if err != nil {
+		return nil, err
 	}
-	switch t2 := any(*t).(type) {
-	case []string:
-		result := any(slices.Clone(t2)).(T)
-		return &result
+	switch e := expr.(type) {
+	case *parser.UnsetProperty:
+		return nil, nil
+	case *parser.String:
+		if result, ok := any(&e.Value).(*T); ok {
+			return result, nil
+		} else {
+			return nil, fmt.Errorf("can't assign string value to %s property", configuredTypeToString[T]())
+		}
+	case *parser.Bool:
+		if result, ok := any(&e.Value).(*T); ok {
+			return result, nil
+		} else {
+			return nil, fmt.Errorf("can't assign bool value to %s property", configuredTypeToString[T]())
+		}
+	case *parser.List:
+		result := make([]string, 0, len(e.Values))
+		for _, x := range e.Values {
+			if y, ok := x.(*parser.String); ok {
+				result = append(result, y.Value)
+			} else {
+				return nil, fmt.Errorf("expected list of strings but found list of %s", x.Type())
+			}
+		}
+		if result, ok := any(&result).(*T); ok {
+			return result, nil
+		} else {
+			return nil, fmt.Errorf("can't assign list of strings to list of %s property", configuredTypeToString[T]())
+		}
 	default:
-		x := *t
-		return &x
+		// If the expression was not evaluated beforehand we could hit this error even when the types match,
+		// but that's an internal logic error.
+		return nil, fmt.Errorf("expected %s but found %s (%#v)", configuredTypeToString[T](), expr.Type().String(), expr)
 	}
 }
 
-func configuredValuePtrToOptional[T ConfigurableElements](t *T) ConfigurableOptional[T] {
-	if t == nil {
-		return ConfigurableOptional[T]{optional.NewShallowOptional(t)}
+func configuredValueToExpression[T ConfigurableElements](value T) parser.Expression {
+	switch v := any(value).(type) {
+	case string:
+		return &parser.String{Value: v}
+	case bool:
+		return &parser.Bool{Value: v}
+	case []string:
+		values := make([]parser.Expression, 0, len(v))
+		for _, x := range v {
+			values = append(values, &parser.String{Value: x})
+		}
+		return &parser.List{Values: values}
+	default:
+		panic("unhandled type in configuredValueToExpression")
 	}
-	switch t2 := any(*t).(type) {
+}
+
+func configuredTypeToString[T ConfigurableElements]() string {
+	var zero T
+	switch any(zero).(type) {
+	case string:
+		return "string"
+	case bool:
+		return "bool"
 	case []string:
-		result := any(slices.Clone(t2)).(T)
-		return ConfigurableOptional[T]{optional.NewShallowOptional(&result)}
+		return "list of strings"
 	default:
-		return ConfigurableOptional[T]{optional.NewShallowOptional(t)}
+		panic("should be unreachable")
 	}
 }
 
@@ -821,9 +1155,88 @@ func copyConfiguredValue[T ConfigurableElements](t T) T {
 	}
 }
 
+func configuredValuePtrToOptional[T ConfigurableElements](t *T) ConfigurableOptional[T] {
+	if t == nil {
+		return ConfigurableOptional[T]{optional.NewShallowOptional(t)}
+	}
+	switch t2 := any(*t).(type) {
+	case []string:
+		result := any(slices.Clone(t2)).(T)
+		return ConfigurableOptional[T]{optional.NewShallowOptional(&result)}
+	default:
+		return ConfigurableOptional[T]{optional.NewShallowOptional(t)}
+	}
+}
+
 // PrintfIntoConfigurable replaces %s occurrences in strings in Configurable properties
 // with the provided string value. It's intention is to support soong config value variables
 // on Configurable properties.
 func PrintfIntoConfigurable(c any, value string) error {
 	return c.(configurableReflection).printfInto(value)
 }
+
+func promoteValueToConfigurable(origional reflect.Value) reflect.Value {
+	var expr parser.Expression
+	var kind reflect.Kind
+	if origional.Kind() == reflect.Pointer && origional.IsNil() {
+		expr = &parser.UnsetProperty{}
+		kind = origional.Type().Elem().Kind()
+	} else {
+		if origional.Kind() == reflect.Pointer {
+			origional = origional.Elem()
+		}
+		kind = origional.Kind()
+		switch kind {
+		case reflect.String:
+			expr = &parser.String{Value: origional.String()}
+		case reflect.Bool:
+			expr = &parser.Bool{Value: origional.Bool()}
+		case reflect.Slice:
+			strList := origional.Interface().([]string)
+			exprList := make([]parser.Expression, 0, len(strList))
+			for _, x := range strList {
+				exprList = append(exprList, &parser.String{Value: x})
+			}
+			expr = &parser.List{Values: exprList}
+		default:
+			panic("can only convert string/bool/[]string to configurable")
+		}
+	}
+	switch kind {
+	case reflect.String:
+		return reflect.ValueOf(Configurable[string]{
+			inner: &configurableInner[string]{
+				single: singleConfigurable[string]{
+					cases: []ConfigurableCase[string]{{
+						value: expr,
+					}},
+				},
+			},
+			postProcessors: &[][]postProcessor[string]{},
+		})
+	case reflect.Bool:
+		return reflect.ValueOf(Configurable[bool]{
+			inner: &configurableInner[bool]{
+				single: singleConfigurable[bool]{
+					cases: []ConfigurableCase[bool]{{
+						value: expr,
+					}},
+				},
+			},
+			postProcessors: &[][]postProcessor[bool]{},
+		})
+	case reflect.Slice:
+		return reflect.ValueOf(Configurable[[]string]{
+			inner: &configurableInner[[]string]{
+				single: singleConfigurable[[]string]{
+					cases: []ConfigurableCase[[]string]{{
+						value: expr,
+					}},
+				},
+			},
+			postProcessors: &[][]postProcessor[[]string]{},
+		})
+	default:
+		panic(fmt.Sprintf("Can't convert %s property to a configurable", origional.Kind().String()))
+	}
+}
diff --git a/proptools/configurable_test.go b/proptools/configurable_test.go
new file mode 100644
index 0000000000..f608a45b47
--- /dev/null
+++ b/proptools/configurable_test.go
@@ -0,0 +1,95 @@
+package proptools
+
+import (
+	"fmt"
+	"reflect"
+	"testing"
+)
+
+func TestPostProcessor(t *testing.T) {
+	// Same as the ascii art example in Configurable.evaluate()
+	prop := NewConfigurable[[]string](nil, nil)
+	prop.AppendSimpleValue([]string{"a"})
+	prop.AppendSimpleValue([]string{"b"})
+	prop.AddPostProcessor(addToElements("1"))
+
+	prop2 := NewConfigurable[[]string](nil, nil)
+	prop2.AppendSimpleValue([]string{"c"})
+
+	prop3 := NewConfigurable[[]string](nil, nil)
+	prop3.AppendSimpleValue([]string{"d"})
+	prop3.AppendSimpleValue([]string{"e"})
+	prop3.AddPostProcessor(addToElements("2"))
+
+	prop4 := NewConfigurable[[]string](nil, nil)
+	prop4.AppendSimpleValue([]string{"f"})
+
+	prop5 := NewConfigurable[[]string](nil, nil)
+	prop5.AppendSimpleValue([]string{"g"})
+	prop5.AddPostProcessor(addToElements("3"))
+
+	prop2.Append(prop3)
+	prop2.AddPostProcessor(addToElements("z"))
+
+	prop.Append(prop2)
+	prop.AddPostProcessor(addToElements("y"))
+	prop.Append(prop4)
+	prop.Append(prop5)
+
+	expected := []string{"a1y", "b1y", "czy", "d2zy", "e2zy", "f", "g3"}
+	x := prop.Get(&configurableEvalutorForTesting{})
+	if !reflect.DeepEqual(x.Get(), expected) {
+		t.Fatalf("Expected %v, got %v", expected, x.Get())
+	}
+}
+
+func TestPostProcessorWhenPassedToHelperFunction(t *testing.T) {
+	prop := NewConfigurable[[]string](nil, nil)
+	prop.AppendSimpleValue([]string{"a"})
+	prop.AppendSimpleValue([]string{"b"})
+
+	helper := func(p Configurable[[]string]) {
+		p.AddPostProcessor(addToElements("1"))
+	}
+
+	helper(prop)
+
+	expected := []string{"a1", "b1"}
+	x := prop.Get(&configurableEvalutorForTesting{})
+	if !reflect.DeepEqual(x.Get(), expected) {
+		t.Fatalf("Expected %v, got %v", expected, x.Get())
+	}
+}
+
+func addToElements(s string) func([]string) []string {
+	return func(arr []string) []string {
+		for i := range arr {
+			arr[i] = arr[i] + s
+		}
+		return arr
+	}
+}
+
+type configurableEvalutorForTesting struct {
+	vars map[string]string
+}
+
+func (e *configurableEvalutorForTesting) EvaluateConfiguration(condition ConfigurableCondition, property string) ConfigurableValue {
+	if condition.functionName != "f" {
+		panic("Expected functionName to be f")
+	}
+	if len(condition.args) != 1 {
+		panic("Expected exactly 1 arg")
+	}
+	val, ok := e.vars[condition.args[0]]
+	if ok {
+		return ConfigurableValueString(val)
+	}
+	return ConfigurableValueUndefined()
+}
+
+func (e *configurableEvalutorForTesting) PropertyErrorf(property, fmtString string, args ...interface{}) {
+	panic(fmt.Sprintf(fmtString, args...))
+}
+
+var _ ConfigurableEvaluator = (*configurableEvalutorForTesting)(nil)
diff --git a/proptools/extend.go b/proptools/extend.go
index ec25d51af9..1bcb725211 100644
--- a/proptools/extend.go
+++ b/proptools/extend.go
@@ -473,33 +473,7 @@ func ExtendBasicType(dstFieldValue, srcFieldValue reflect.Value, order Order) {
 	// structs when they want to change the default values of properties.
 	srcFieldType := srcFieldValue.Type()
 	if isConfigurable(dstFieldValue.Type()) && !isConfigurable(srcFieldType) {
-		var value reflect.Value
-		if srcFieldType.Kind() == reflect.Pointer {
-			srcFieldType = srcFieldType.Elem()
-			if srcFieldValue.IsNil() {
-				value = srcFieldValue
-			} else {
-				// Copy the pointer
-				value = reflect.New(srcFieldType)
-				value.Elem().Set(srcFieldValue.Elem())
-			}
-		} else {
-			value = reflect.New(srcFieldType)
-			value.Elem().Set(srcFieldValue)
-		}
-		caseType := configurableCaseType(srcFieldType)
-		case_ := reflect.New(caseType)
-		case_.Interface().(configurableCaseReflection).initialize(nil, value.Interface())
-		cases := reflect.MakeSlice(reflect.SliceOf(caseType), 0, 1)
-		cases = reflect.Append(cases, case_.Elem())
-		ct, err := configurableType(srcFieldType)
-		if err != nil {
-			// Should be unreachable due to earlier checks
-			panic(err.Error())
-		}
-		temp := reflect.New(ct)
-		temp.Interface().(configurablePtrReflection).initialize("", nil, cases.Interface())
-		srcFieldValue = temp.Elem()
+		srcFieldValue = promoteValueToConfigurable(srcFieldValue)
 	}
 
 	switch srcFieldValue.Kind() {
diff --git a/proptools/extend_test.go b/proptools/extend_test.go
index 13fd04fd3a..4fabf523e8 100644
--- a/proptools/extend_test.go
+++ b/proptools/extend_test.go
@@ -20,6 +20,8 @@ import (
 	"reflect"
 	"strings"
 	"testing"
+
+	"github.com/google/blueprint/parser"
 )
 
 type appendPropertyTestCase struct {
@@ -1257,172 +1259,166 @@ func appendPropertiesTestCases() []appendPropertyTestCase {
 		{
 			name: "Append configurable",
 			dst: &struct{ S Configurable[[]string] }{
-				S: Configurable[[]string]{
-					inner: &configurableInner[[]string]{
-						single: singleConfigurable[[]string]{
-							conditions: []ConfigurableCondition{{
-								functionName: "soong_config_variable",
-								args: []string{
-									"my_namespace",
-									"foo",
-								},
-							}},
-							cases: []ConfigurableCase[[]string]{{
-								patterns: []ConfigurablePattern{{
-									typ:         configurablePatternTypeString,
-									stringValue: "a",
-								}},
-								value: &[]string{"1", "2"},
-							}},
-						},
+				S: NewConfigurable[[]string]([]ConfigurableCondition{{
+					functionName: "soong_config_variable",
+					args: []string{
+						"my_namespace",
+						"foo",
 					},
-				},
+				}},
+					[]ConfigurableCase[[]string]{{
+						patterns: []ConfigurablePattern{{
+							typ:         configurablePatternTypeString,
+							stringValue: "a",
+						}},
+						value: &parser.List{Values: []parser.Expression{
+							&parser.String{Value: "1"},
+							&parser.String{Value: "2"},
+						}},
+					}},
+				),
 			},
 			src: &struct{ S Configurable[[]string] }{
-				S: Configurable[[]string]{
-					inner: &configurableInner[[]string]{
-						single: singleConfigurable[[]string]{
-							conditions: []ConfigurableCondition{{
-								functionName: "release_variable",
-								args: []string{
-									"bar",
-								},
-							}},
-							cases: []ConfigurableCase[[]string]{{
-								patterns: []ConfigurablePattern{{
-									typ:         configurablePatternTypeString,
-									stringValue: "b",
-								}},
-								value: &[]string{"3", "4"},
-							}},
-						},
+				S: NewConfigurable([]ConfigurableCondition{{
+					functionName: "release_variable",
+					args: []string{
+						"bar",
 					},
-				},
+				}},
+					[]ConfigurableCase[[]string]{{
+						patterns: []ConfigurablePattern{{
+							typ:         configurablePatternTypeString,
+							stringValue: "b",
+						}},
+						value: &parser.List{Values: []parser.Expression{
+							&parser.String{Value: "3"},
+							&parser.String{Value: "4"},
+						}},
+					}},
+				),
 			},
 			out: &struct{ S Configurable[[]string] }{
-				S: Configurable[[]string]{
-					inner: &configurableInner[[]string]{
-						single: singleConfigurable[[]string]{
-							conditions: []ConfigurableCondition{{
-								functionName: "soong_config_variable",
-								args: []string{
-									"my_namespace",
-									"foo",
-								},
+				S: func() Configurable[[]string] {
+					result := NewConfigurable([]ConfigurableCondition{{
+						functionName: "soong_config_variable",
+						args: []string{
+							"my_namespace",
+							"foo",
+						},
+					}},
+						[]ConfigurableCase[[]string]{{
+							patterns: []ConfigurablePattern{{
+								typ:         configurablePatternTypeString,
+								stringValue: "a",
 							}},
-							cases: []ConfigurableCase[[]string]{{
-								patterns: []ConfigurablePattern{{
-									typ:         configurablePatternTypeString,
-									stringValue: "a",
-								}},
-								value: &[]string{"1", "2"},
+							value: &parser.List{Values: []parser.Expression{
+								&parser.String{Value: "1"},
+								&parser.String{Value: "2"},
 							}},
+						}},
+					)
+					result.Append(NewConfigurable([]ConfigurableCondition{{
+						functionName: "release_variable",
+						args: []string{
+							"bar",
 						},
-						next: &configurableInner[[]string]{
-							single: singleConfigurable[[]string]{
-								conditions: []ConfigurableCondition{{
-									functionName: "release_variable",
-									args: []string{
-										"bar",
-									},
-								}},
-								cases: []ConfigurableCase[[]string]{{
-									patterns: []ConfigurablePattern{{
-										typ:         configurablePatternTypeString,
-										stringValue: "b",
-									}},
-									value: &[]string{"3", "4"},
-								}},
-							},
-						},
-					},
-				},
+					}},
+						[]ConfigurableCase[[]string]{{
+							patterns: []ConfigurablePattern{{
+								typ:         configurablePatternTypeString,
+								stringValue: "b",
+							}},
+							value: &parser.List{Values: []parser.Expression{
+								&parser.String{Value: "3"},
+								&parser.String{Value: "4"},
+							}},
+						}}))
+					return result
+				}(),
 			},
 		},
 		{
 			name:  "Prepend configurable",
 			order: Prepend,
 			dst: &struct{ S Configurable[[]string] }{
-				S: Configurable[[]string]{
-					inner: &configurableInner[[]string]{
-						single: singleConfigurable[[]string]{
-							conditions: []ConfigurableCondition{{
-								functionName: "soong_config_variable",
-								args: []string{
-									"my_namespace",
-									"foo",
-								},
-							}},
-							cases: []ConfigurableCase[[]string]{{
-								patterns: []ConfigurablePattern{{
-									typ:         configurablePatternTypeString,
-									stringValue: "a",
-								}},
-								value: &[]string{"1", "2"},
-							}},
-						},
+				S: NewConfigurable([]ConfigurableCondition{{
+					functionName: "soong_config_variable",
+					args: []string{
+						"my_namespace",
+						"foo",
 					},
-				},
+				}},
+					[]ConfigurableCase[[]string]{{
+						patterns: []ConfigurablePattern{{
+							typ:         configurablePatternTypeString,
+							stringValue: "a",
+						}},
+						value: &parser.List{Values: []parser.Expression{
+							&parser.String{Value: "1"},
+							&parser.String{Value: "2"},
+						}},
+					}},
+				),
 			},
 			src: &struct{ S Configurable[[]string] }{
-				S: Configurable[[]string]{
-					inner: &configurableInner[[]string]{
-						single: singleConfigurable[[]string]{
-							conditions: []ConfigurableCondition{{
-								functionName: "release_variable",
-								args: []string{
-									"bar",
-								},
-							}},
-							cases: []ConfigurableCase[[]string]{{
-								patterns: []ConfigurablePattern{{
-									typ:         configurablePatternTypeString,
-									stringValue: "b",
-								}},
-								value: &[]string{"3", "4"},
-							}},
-						},
+				S: NewConfigurable([]ConfigurableCondition{{
+					functionName: "release_variable",
+					args: []string{
+						"bar",
 					},
-				},
+				}},
+					[]ConfigurableCase[[]string]{{
+						patterns: []ConfigurablePattern{{
+							typ:         configurablePatternTypeString,
+							stringValue: "b",
+						}},
+						value: &parser.List{Values: []parser.Expression{
+							&parser.String{Value: "3"},
+							&parser.String{Value: "4"},
+						}},
+					}},
+				),
 			},
 			out: &struct{ S Configurable[[]string] }{
-				S: Configurable[[]string]{
-					inner: &configurableInner[[]string]{
-						single: singleConfigurable[[]string]{
-							conditions: []ConfigurableCondition{{
-								functionName: "release_variable",
-								args: []string{
-									"bar",
-								},
+				S: func() Configurable[[]string] {
+					result := NewConfigurable(
+						[]ConfigurableCondition{{
+							functionName: "release_variable",
+							args: []string{
+								"bar",
+							},
+						}},
+						[]ConfigurableCase[[]string]{{
+							patterns: []ConfigurablePattern{{
+								typ:         configurablePatternTypeString,
+								stringValue: "b",
 							}},
-							cases: []ConfigurableCase[[]string]{{
-								patterns: []ConfigurablePattern{{
-									typ:         configurablePatternTypeString,
-									stringValue: "b",
-								}},
-								value: &[]string{"3", "4"},
+							value: &parser.List{Values: []parser.Expression{
+								&parser.String{Value: "3"},
+								&parser.String{Value: "4"},
 							}},
-						},
-						next: &configurableInner[[]string]{
-							single: singleConfigurable[[]string]{
-								conditions: []ConfigurableCondition{{
-									functionName: "soong_config_variable",
-									args: []string{
-										"my_namespace",
-										"foo",
-									},
-								}},
-								cases: []ConfigurableCase[[]string]{{
-									patterns: []ConfigurablePattern{{
-										typ:         configurablePatternTypeString,
-										stringValue: "a",
-									}},
-									value: &[]string{"1", "2"},
-								}},
+						}},
+					)
+					result.Append(NewConfigurable(
+						[]ConfigurableCondition{{
+							functionName: "soong_config_variable",
+							args: []string{
+								"my_namespace",
+								"foo",
 							},
-						},
-					},
-				},
+						}},
+						[]ConfigurableCase[[]string]{{
+							patterns: []ConfigurablePattern{{
+								typ:         configurablePatternTypeString,
+								stringValue: "a",
+							}},
+							value: &parser.List{Values: []parser.Expression{
+								&parser.String{Value: "1"},
+								&parser.String{Value: "2"},
+							}},
+						}}))
+					return result
+				}(),
 			},
 		},
 	}
@@ -1892,31 +1888,24 @@ func appendMatchingPropertiesTestCases() []appendMatchingPropertiesTestCase {
 			order: Append,
 			dst: []interface{}{
 				&struct{ S Configurable[bool] }{
-					S: Configurable[bool]{
-						inner: &configurableInner[bool]{
-							single: singleConfigurable[bool]{
-								conditions: []ConfigurableCondition{{
-									functionName: "soong_config_variable",
-									args: []string{
-										"my_namespace",
-										"foo",
-									},
-								}},
-								cases: []ConfigurableCase[bool]{{
-									patterns: []ConfigurablePattern{{
-										typ:         configurablePatternTypeString,
-										stringValue: "a",
-									}},
-									value: BoolPtr(true),
-								}, {
-									patterns: []ConfigurablePattern{{
-										typ: configurablePatternTypeDefault,
-									}},
-									value: BoolPtr(false),
-								}},
-							},
+					S: NewConfigurable[bool]([]ConfigurableCondition{{
+						functionName: "soong_config_variable",
+						args: []string{
+							"my_namespace",
+							"foo",
 						},
-					},
+					}}, []ConfigurableCase[bool]{{
+						patterns: []ConfigurablePattern{{
+							typ:         configurablePatternTypeString,
+							stringValue: "a",
+						}},
+						value: &parser.Bool{Value: true},
+					}, {
+						patterns: []ConfigurablePattern{{
+							typ: configurablePatternTypeDefault,
+						}},
+						value: &parser.Bool{Value: false},
+					}}),
 				},
 			},
 			src: &struct{ S *bool }{
@@ -1924,38 +1913,30 @@ func appendMatchingPropertiesTestCases() []appendMatchingPropertiesTestCase {
 			},
 			out: []interface{}{
 				&struct{ S Configurable[bool] }{
-					S: Configurable[bool]{
-						inner: &configurableInner[bool]{
-							single: singleConfigurable[bool]{
-								conditions: []ConfigurableCondition{{
-									functionName: "soong_config_variable",
-									args: []string{
-										"my_namespace",
-										"foo",
-									},
+					S: func() Configurable[bool] {
+						result := NewConfigurable[bool]([]ConfigurableCondition{{
+							functionName: "soong_config_variable",
+							args: []string{
+								"my_namespace",
+								"foo",
+							},
+						}},
+							[]ConfigurableCase[bool]{{
+								patterns: []ConfigurablePattern{{
+									typ:         configurablePatternTypeString,
+									stringValue: "a",
 								}},
-								cases: []ConfigurableCase[bool]{{
-									patterns: []ConfigurablePattern{{
-										typ:         configurablePatternTypeString,
-										stringValue: "a",
-									}},
-									value: BoolPtr(true),
-								}, {
-									patterns: []ConfigurablePattern{{
-										typ: configurablePatternTypeDefault,
-									}},
-									value: BoolPtr(false),
+								value: &parser.Bool{Value: true},
+							}, {
+								patterns: []ConfigurablePattern{{
+									typ: configurablePatternTypeDefault,
 								}},
-							},
-							next: &configurableInner[bool]{
-								single: singleConfigurable[bool]{
-									cases: []ConfigurableCase[bool]{{
-										value: BoolPtr(true),
-									}},
-								},
-							},
-						},
-					},
+								value: &parser.Bool{Value: false},
+							}},
+						)
+						result.AppendSimpleValue(true)
+						return result
+					}(),
 				},
 			},
 		},
@@ -1964,31 +1945,26 @@ func appendMatchingPropertiesTestCases() []appendMatchingPropertiesTestCase {
 			order: Append,
 			dst: []interface{}{
 				&struct{ S Configurable[bool] }{
-					S: Configurable[bool]{
-						inner: &configurableInner[bool]{
-							single: singleConfigurable[bool]{
-								conditions: []ConfigurableCondition{{
-									functionName: "soong_config_variable",
-									args: []string{
-										"my_namespace",
-										"foo",
-									},
-								}},
-								cases: []ConfigurableCase[bool]{{
-									patterns: []ConfigurablePattern{{
-										typ:         configurablePatternTypeString,
-										stringValue: "a",
-									}},
-									value: BoolPtr(true),
-								}, {
-									patterns: []ConfigurablePattern{{
-										typ: configurablePatternTypeDefault,
-									}},
-									value: BoolPtr(false),
-								}},
-							},
+					S: NewConfigurable[bool]([]ConfigurableCondition{{
+						functionName: "soong_config_variable",
+						args: []string{
+							"my_namespace",
+							"foo",
 						},
-					},
+					}},
+						[]ConfigurableCase[bool]{{
+							patterns: []ConfigurablePattern{{
+								typ:         configurablePatternTypeString,
+								stringValue: "a",
+							}},
+							value: &parser.Bool{Value: true},
+						}, {
+							patterns: []ConfigurablePattern{{
+								typ: configurablePatternTypeDefault,
+							}},
+							value: &parser.Bool{Value: false},
+						}},
+					),
 				},
 			},
 			src: &struct{ S bool }{
@@ -1996,38 +1972,31 @@ func appendMatchingPropertiesTestCases() []appendMatchingPropertiesTestCase {
 			},
 			out: []interface{}{
 				&struct{ S Configurable[bool] }{
-					S: Configurable[bool]{
-						inner: &configurableInner[bool]{
-							single: singleConfigurable[bool]{
-								conditions: []ConfigurableCondition{{
-									functionName: "soong_config_variable",
-									args: []string{
-										"my_namespace",
-										"foo",
-									},
+					S: func() Configurable[bool] {
+						result := NewConfigurable[bool](
+							[]ConfigurableCondition{{
+								functionName: "soong_config_variable",
+								args: []string{
+									"my_namespace",
+									"foo",
+								},
+							}},
+							[]ConfigurableCase[bool]{{
+								patterns: []ConfigurablePattern{{
+									typ:         configurablePatternTypeString,
+									stringValue: "a",
 								}},
-								cases: []ConfigurableCase[bool]{{
-									patterns: []ConfigurablePattern{{
-										typ:         configurablePatternTypeString,
-										stringValue: "a",
-									}},
-									value: BoolPtr(true),
-								}, {
-									patterns: []ConfigurablePattern{{
-										typ: configurablePatternTypeDefault,
-									}},
-									value: BoolPtr(false),
+								value: &parser.Bool{Value: true},
+							}, {
+								patterns: []ConfigurablePattern{{
+									typ: configurablePatternTypeDefault,
 								}},
-							},
-							next: &configurableInner[bool]{
-								single: singleConfigurable[bool]{
-									cases: []ConfigurableCase[bool]{{
-										value: BoolPtr(true),
-									}},
-								},
-							},
-						},
-					},
+								value: &parser.Bool{Value: false},
+							}},
+						)
+						result.AppendSimpleValue(true)
+						return result
+					}(),
 				},
 			},
 		},
diff --git a/proptools/unpack.go b/proptools/unpack.go
index 1b48a619c8..712e78c0b7 100644
--- a/proptools/unpack.go
+++ b/proptools/unpack.go
@@ -158,7 +158,7 @@ func (ctx *unpackContext) buildPropertyMap(prefix string, properties []*parser.P
 		}
 
 		ctx.propertyMap[name] = &packedProperty{property, false}
-		switch propValue := property.Value.Eval().(type) {
+		switch propValue := property.Value.(type) {
 		case *parser.Map:
 			ctx.buildPropertyMap(name, propValue.Properties)
 		case *parser.List:
@@ -313,7 +313,7 @@ func (ctx *unpackContext) unpackToStruct(namePrefix string, structValue reflect.
 				return
 			}
 		} else if isStruct(fieldValue.Type()) {
-			if property.Value.Eval().Type() != parser.MapType {
+			if property.Value.Type() != parser.MapType {
 				ctx.addError(&UnpackError{
 					fmt.Errorf("can't assign %s value to map property %q",
 						property.Value.Type(), property.Name),
@@ -354,15 +354,17 @@ func (ctx *unpackContext) unpackToConfigurable(propertyName string, property *pa
 			})
 			return reflect.New(configurableType), false
 		}
+		var postProcessors [][]postProcessor[string]
 		result := Configurable[string]{
 			propertyName: property.Name,
 			inner: &configurableInner[string]{
 				single: singleConfigurable[string]{
 					cases: []ConfigurableCase[string]{{
-						value: &v.Value,
+						value: v,
 					}},
 				},
 			},
+			postProcessors: &postProcessors,
 		}
 		return reflect.ValueOf(&result), true
 	case *parser.Bool:
@@ -374,15 +376,17 @@ func (ctx *unpackContext) unpackToConfigurable(propertyName string, property *pa
 			})
 			return reflect.New(configurableType), false
 		}
+		var postProcessors [][]postProcessor[bool]
 		result := Configurable[bool]{
 			propertyName: property.Name,
 			inner: &configurableInner[bool]{
 				single: singleConfigurable[bool]{
 					cases: []ConfigurableCase[bool]{{
-						value: &v.Value,
+						value: v,
 					}},
 				},
 			},
+			postProcessors: &postProcessors,
 		}
 		return reflect.ValueOf(&result), true
 	case *parser.List:
@@ -411,26 +415,22 @@ func (ctx *unpackContext) unpackToConfigurable(propertyName string, property *pa
 					value[i] = exprUnpacked.Interface().(string)
 				}
 			}
+			var postProcessors [][]postProcessor[[]string]
 			result := Configurable[[]string]{
 				propertyName: property.Name,
 				inner: &configurableInner[[]string]{
 					single: singleConfigurable[[]string]{
 						cases: []ConfigurableCase[[]string]{{
-							value: &value,
+							value: v,
 						}},
 					},
 				},
+				postProcessors: &postProcessors,
 			}
 			return reflect.ValueOf(&result), true
 		default:
 			panic("This should be unreachable because ConfigurableElements only accepts slices of strings")
 		}
-	case *parser.Operator:
-		property.Value = v.Value.Eval()
-		return ctx.unpackToConfigurable(propertyName, property, configurableType, configuredType)
-	case *parser.Variable:
-		property.Value = v.Value.Eval()
-		return ctx.unpackToConfigurable(propertyName, property, configurableType, configuredType)
 	case *parser.Select:
 		resultPtr := reflect.New(configurableType)
 		result := resultPtr.Elem()
@@ -448,19 +448,15 @@ func (ctx *unpackContext) unpackToConfigurable(propertyName string, property *pa
 
 		configurableCaseType := configurableCaseType(configuredType)
 		cases := reflect.MakeSlice(reflect.SliceOf(configurableCaseType), 0, len(v.Cases))
-		for i, c := range v.Cases {
-			p := &parser.Property{
-				Name:    property.Name + "[" + strconv.Itoa(i) + "]",
-				NamePos: c.ColonPos,
-				Value:   c.Value,
-			}
-
+		for _, c := range v.Cases {
 			patterns := make([]ConfigurablePattern, len(c.Patterns))
 			for i, pat := range c.Patterns {
-				switch pat := pat.(type) {
+				switch pat := pat.Value.(type) {
 				case *parser.String:
 					if pat.Value == "__soong_conditions_default__" {
 						patterns[i].typ = configurablePatternTypeDefault
+					} else if pat.Value == "__soong_conditions_any__" {
+						patterns[i].typ = configurablePatternTypeAny
 					} else {
 						patterns[i].typ = configurablePatternTypeString
 						patterns[i].stringValue = pat.Value
@@ -471,42 +467,15 @@ func (ctx *unpackContext) unpackToConfigurable(propertyName string, property *pa
 				default:
 					panic("unimplemented")
 				}
-			}
-
-			var value reflect.Value
-			// Map the "unset" keyword to a nil pointer in the cases map
-			if _, ok := c.Value.(parser.UnsetProperty); ok {
-				value = reflect.Zero(reflect.PointerTo(configuredType))
-			} else {
-				var err error
-				switch configuredType.Kind() {
-				case reflect.String, reflect.Bool:
-					value, err = propertyToValue(reflect.PointerTo(configuredType), p)
-					if err != nil {
-						ctx.addError(&UnpackError{
-							err,
-							c.Value.Pos(),
-						})
-						return reflect.New(configurableType), false
-					}
-				case reflect.Slice:
-					if configuredType.Elem().Kind() != reflect.String {
-						panic("This should be unreachable because ConfigurableElements only accepts slices of strings")
-					}
-					value, ok = ctx.unpackToSlice(p.Name, p, reflect.PointerTo(configuredType))
-					if !ok {
-						return reflect.New(configurableType), false
-					}
-				default:
-					panic("This should be unreachable because ConfigurableElements only accepts strings, boools, or slices of strings")
-				}
+				patterns[i].binding = pat.Binding.Name
 			}
 
 			case_ := reflect.New(configurableCaseType)
-			case_.Interface().(configurableCaseReflection).initialize(patterns, value.Interface())
+			case_.Interface().(configurableCaseReflection).initialize(patterns, c.Value)
 			cases = reflect.Append(cases, case_.Elem())
 		}
 		resultPtr.Interface().(configurablePtrReflection).initialize(
+			v.Scope,
 			property.Name,
 			conditions,
 			cases.Interface(),
@@ -537,7 +506,7 @@ func (ctx *unpackContext) unpackToConfigurable(propertyName string, property *pa
 // If the given property is a select, returns an error saying that you can't assign a select to
 // a non-configurable property. Otherwise returns nil.
 func selectOnNonConfigurablePropertyError(property *parser.Property) error {
-	if _, ok := property.Value.Eval().(*parser.Select); !ok {
+	if _, ok := property.Value.(*parser.Select); !ok {
 		return nil
 	}
 
@@ -570,7 +539,7 @@ func (ctx *unpackContext) unpackToSlice(
 // does.
 func (ctx *unpackContext) unpackToSliceInner(
 	sliceName string, property *parser.Property, sliceType reflect.Type) (reflect.Value, bool) {
-	propValueAsList, ok := property.Value.Eval().(*parser.List)
+	propValueAsList, ok := property.Value.(*parser.List)
 	if !ok {
 		if err := selectOnNonConfigurablePropertyError(property); err != nil {
 			ctx.addError(err)
@@ -590,33 +559,24 @@ func (ctx *unpackContext) unpackToSliceInner(
 	}
 
 	// The function to construct an item value depends on the type of list elements.
-	var getItemFunc func(*parser.Property, reflect.Type) (reflect.Value, bool)
-	switch exprs[0].Type() {
-	case parser.BoolType, parser.StringType, parser.Int64Type:
-		getItemFunc = func(property *parser.Property, t reflect.Type) (reflect.Value, bool) {
+	getItemFunc := func(property *parser.Property, t reflect.Type) (reflect.Value, bool) {
+		switch property.Value.(type) {
+		case *parser.Bool, *parser.String, *parser.Int64:
 			value, err := propertyToValue(t, property)
 			if err != nil {
 				ctx.addError(err)
 				return value, false
 			}
 			return value, true
-		}
-	case parser.ListType:
-		getItemFunc = func(property *parser.Property, t reflect.Type) (reflect.Value, bool) {
+		case *parser.List:
 			return ctx.unpackToSlice(property.Name, property, t)
-		}
-	case parser.MapType:
-		getItemFunc = func(property *parser.Property, t reflect.Type) (reflect.Value, bool) {
+		case *parser.Map:
 			itemValue := reflect.New(t).Elem()
 			ctx.unpackToStruct(property.Name, itemValue)
 			return itemValue, true
+		default:
+			panic(fmt.Errorf("bizarre property expression type: %v, %#v", property.Value.Type(), property.Value))
 		}
-	case parser.NotEvaluatedType:
-		getItemFunc = func(property *parser.Property, t reflect.Type) (reflect.Value, bool) {
-			return reflect.New(t), false
-		}
-	default:
-		panic(fmt.Errorf("bizarre property expression type: %v", exprs[0].Type()))
 	}
 
 	itemProperty := &parser.Property{NamePos: property.NamePos, ColonPos: property.ColonPos}
@@ -657,7 +617,7 @@ func propertyToValue(typ reflect.Type, property *parser.Property) (reflect.Value
 
 	switch kind := baseType.Kind(); kind {
 	case reflect.Bool:
-		b, ok := property.Value.Eval().(*parser.Bool)
+		b, ok := property.Value.(*parser.Bool)
 		if !ok {
 			if err := selectOnNonConfigurablePropertyError(property); err != nil {
 				return value, err
@@ -672,7 +632,7 @@ func propertyToValue(typ reflect.Type, property *parser.Property) (reflect.Value
 		value = reflect.ValueOf(b.Value)
 
 	case reflect.Int64:
-		b, ok := property.Value.Eval().(*parser.Int64)
+		b, ok := property.Value.(*parser.Int64)
 		if !ok {
 			return value, &UnpackError{
 				fmt.Errorf("can't assign %s value to int64 property %q",
@@ -683,7 +643,7 @@ func propertyToValue(typ reflect.Type, property *parser.Property) (reflect.Value
 		value = reflect.ValueOf(b.Value)
 
 	case reflect.String:
-		s, ok := property.Value.Eval().(*parser.String)
+		s, ok := property.Value.(*parser.String)
 		if !ok {
 			if err := selectOnNonConfigurablePropertyError(property); err != nil {
 				return value, err
diff --git a/proptools/unpack_test.go b/proptools/unpack_test.go
index 5e333b66a9..10ac0aa4e1 100644
--- a/proptools/unpack_test.go
+++ b/proptools/unpack_test.go
@@ -18,6 +18,7 @@ import (
 	"bytes"
 	"reflect"
 	"testing"
+	"text/scanner"
 
 	"github.com/google/blueprint/parser"
 )
@@ -732,16 +733,21 @@ var validUnpackTestCases = []struct {
 			&struct {
 				Foo Configurable[string]
 			}{
-				Foo: Configurable[string]{
-					propertyName: "foo",
-					inner: &configurableInner[string]{
-						single: singleConfigurable[string]{
-							cases: []ConfigurableCase[string]{{
-								value: StringPtr("bar"),
-							}},
+				Foo: newConfigurableWithPropertyName(
+					"foo",
+					nil,
+					[]ConfigurableCase[string]{{
+						value: &parser.String{
+							LiteralPos: scanner.Position{
+								Offset: 17,
+								Line:   3,
+								Column: 10,
+							},
+							Value: "bar",
 						},
-					},
-				},
+					}},
+					false,
+				),
 			},
 		},
 	},
@@ -756,16 +762,22 @@ var validUnpackTestCases = []struct {
 			&struct {
 				Foo Configurable[bool]
 			}{
-				Foo: Configurable[bool]{
-					propertyName: "foo",
-					inner: &configurableInner[bool]{
-						single: singleConfigurable[bool]{
-							cases: []ConfigurableCase[bool]{{
-								value: BoolPtr(true),
-							}},
+				Foo: newConfigurableWithPropertyName(
+					"foo",
+					nil,
+					[]ConfigurableCase[bool]{{
+						value: &parser.Bool{
+							LiteralPos: scanner.Position{
+								Offset: 17,
+								Line:   3,
+								Column: 10,
+							},
+							Value: true,
+							Token: "true",
 						},
-					},
-				},
+					}},
+					false,
+				),
 			},
 		},
 	},
@@ -780,16 +792,43 @@ var validUnpackTestCases = []struct {
 			&struct {
 				Foo Configurable[[]string]
 			}{
-				Foo: Configurable[[]string]{
-					propertyName: "foo",
-					inner: &configurableInner[[]string]{
-						single: singleConfigurable[[]string]{
-							cases: []ConfigurableCase[[]string]{{
-								value: &[]string{"a", "b"},
-							}},
+				Foo: newConfigurableWithPropertyName(
+					"foo",
+					nil,
+					[]ConfigurableCase[[]string]{{
+						value: &parser.List{
+							LBracePos: scanner.Position{
+								Offset: 17,
+								Line:   3,
+								Column: 10,
+							},
+							RBracePos: scanner.Position{
+								Offset: 26,
+								Line:   3,
+								Column: 19,
+							},
+							Values: []parser.Expression{
+								&parser.String{
+									LiteralPos: scanner.Position{
+										Offset: 18,
+										Line:   3,
+										Column: 11,
+									},
+									Value: "a",
+								},
+								&parser.String{
+									LiteralPos: scanner.Position{
+										Offset: 23,
+										Line:   3,
+										Column: 16,
+									},
+									Value: "b",
+								},
+							},
 						},
-					},
-				},
+					}},
+					false,
+				),
 			},
 		},
 	},
@@ -808,42 +847,60 @@ var validUnpackTestCases = []struct {
 			&struct {
 				Foo Configurable[string]
 			}{
-				Foo: Configurable[string]{
-					propertyName: "foo",
-					inner: &configurableInner[string]{
-						single: singleConfigurable[string]{
-							conditions: []ConfigurableCondition{{
-								functionName: "soong_config_variable",
-								args: []string{
-									"my_namespace",
-									"my_variable",
-								},
+				Foo: newConfigurableWithPropertyName(
+					"foo",
+					[]ConfigurableCondition{{
+						functionName: "soong_config_variable",
+						args: []string{
+							"my_namespace",
+							"my_variable",
+						},
+					}},
+					[]ConfigurableCase[string]{
+						{
+							patterns: []ConfigurablePattern{{
+								typ:         configurablePatternTypeString,
+								stringValue: "a",
 							}},
-							cases: []ConfigurableCase[string]{
-								{
-									patterns: []ConfigurablePattern{{
-										typ:         configurablePatternTypeString,
-										stringValue: "a",
-									}},
-									value: StringPtr("a2"),
+							value: &parser.String{
+								LiteralPos: scanner.Position{
+									Offset: 90,
+									Line:   4,
+									Column: 11,
 								},
-								{
-									patterns: []ConfigurablePattern{{
-										typ:         configurablePatternTypeString,
-										stringValue: "b",
-									}},
-									value: StringPtr("b2"),
+								Value: "a2",
+							},
+						},
+						{
+							patterns: []ConfigurablePattern{{
+								typ:         configurablePatternTypeString,
+								stringValue: "b",
+							}},
+							value: &parser.String{
+								LiteralPos: scanner.Position{
+									Offset: 106,
+									Line:   5,
+									Column: 11,
 								},
-								{
-									patterns: []ConfigurablePattern{{
-										typ: configurablePatternTypeDefault,
-									}},
-									value: StringPtr("c2"),
+								Value: "b2",
+							},
+						},
+						{
+							patterns: []ConfigurablePattern{{
+								typ: configurablePatternTypeDefault,
+							}},
+							value: &parser.String{
+								LiteralPos: scanner.Position{
+									Offset: 126,
+									Line:   6,
+									Column: 15,
 								},
+								Value: "c2",
 							},
 						},
 					},
-				},
+					true,
+				),
 			},
 		},
 	},
@@ -866,75 +923,117 @@ var validUnpackTestCases = []struct {
 			&struct {
 				Foo Configurable[string]
 			}{
-				Foo: Configurable[string]{
-					propertyName: "foo",
-					inner: &configurableInner[string]{
-						single: singleConfigurable[string]{
-							conditions: []ConfigurableCondition{{
-								functionName: "soong_config_variable",
-								args: []string{
-									"my_namespace",
-									"my_variable",
-								},
-							}},
-							cases: []ConfigurableCase[string]{
-								{
-									patterns: []ConfigurablePattern{{
-										typ:         configurablePatternTypeString,
-										stringValue: "a",
-									}},
-									value: StringPtr("a2"),
+				Foo: func() Configurable[string] {
+					result := newConfigurableWithPropertyName(
+						"foo",
+						[]ConfigurableCondition{{
+							functionName: "soong_config_variable",
+							args: []string{
+								"my_namespace",
+								"my_variable",
+							},
+						}},
+						[]ConfigurableCase[string]{
+							{
+								patterns: []ConfigurablePattern{{
+									typ:         configurablePatternTypeString,
+									stringValue: "a",
+								}},
+								value: &parser.String{
+									LiteralPos: scanner.Position{
+										Offset: 90,
+										Line:   4,
+										Column: 11,
+									},
+									Value: "a2",
 								},
-								{
-									patterns: []ConfigurablePattern{{
-										typ:         configurablePatternTypeString,
-										stringValue: "b",
-									}},
-									value: StringPtr("b2"),
+							},
+							{
+								patterns: []ConfigurablePattern{{
+									typ:         configurablePatternTypeString,
+									stringValue: "b",
+								}},
+								value: &parser.String{
+									LiteralPos: scanner.Position{
+										Offset: 106,
+										Line:   5,
+										Column: 11,
+									},
+									Value: "b2",
 								},
-								{
-									patterns: []ConfigurablePattern{{
-										typ: configurablePatternTypeDefault,
-									}},
-									value: StringPtr("c2"),
+							},
+							{
+								patterns: []ConfigurablePattern{{
+									typ: configurablePatternTypeDefault,
+								}},
+								value: &parser.String{
+									LiteralPos: scanner.Position{
+										Offset: 126,
+										Line:   6,
+										Column: 15,
+									},
+									Value: "c2",
 								},
 							},
 						},
-						next: &configurableInner[string]{
-							single: singleConfigurable[string]{
-								conditions: []ConfigurableCondition{{
-									functionName: "soong_config_variable",
-									args: []string{
-										"my_namespace",
-										"my_2nd_variable",
-									},
+						true,
+					)
+					result.Append(newConfigurableWithPropertyName(
+						"",
+						[]ConfigurableCondition{{
+							functionName: "soong_config_variable",
+							args: []string{
+								"my_namespace",
+								"my_2nd_variable",
+							},
+						}},
+						[]ConfigurableCase[string]{
+							{
+								patterns: []ConfigurablePattern{{
+									typ:         configurablePatternTypeString,
+									stringValue: "d",
 								}},
-								cases: []ConfigurableCase[string]{
-									{
-										patterns: []ConfigurablePattern{{
-											typ:         configurablePatternTypeString,
-											stringValue: "d",
-										}},
-										value: StringPtr("d2"),
+								value: &parser.String{
+									LiteralPos: scanner.Position{
+										Offset: 218,
+										Line:   8,
+										Column: 11,
 									},
-									{
-										patterns: []ConfigurablePattern{{
-											typ:         configurablePatternTypeString,
-											stringValue: "e",
-										}},
-										value: StringPtr("e2"),
+									Value: "d2",
+								},
+							},
+							{
+								patterns: []ConfigurablePattern{{
+									typ:         configurablePatternTypeString,
+									stringValue: "e",
+								}},
+								value: &parser.String{
+									LiteralPos: scanner.Position{
+										Offset: 234,
+										Line:   9,
+										Column: 11,
 									},
-									{
-										patterns: []ConfigurablePattern{{
-											typ: configurablePatternTypeDefault,
-										}},
-										value: StringPtr("f2"),
+									Value: "e2",
+								},
+							},
+							{
+								patterns: []ConfigurablePattern{{
+									typ: configurablePatternTypeDefault,
+								}},
+								value: &parser.String{
+									LiteralPos: scanner.Position{
+										Offset: 254,
+										Line:   10,
+										Column: 15,
 									},
+									Value: "f2",
 								},
 							},
 						},
-					},
-				},
+						true,
+					))
+					return result
+				}(),
 			},
 		},
 	},
@@ -953,26 +1052,37 @@ var validUnpackTestCases = []struct {
 				Foo Configurable[string]
 				Bar Configurable[bool]
 			}{
-				Foo: Configurable[string]{
-					propertyName: "foo",
-					inner: &configurableInner[string]{
-						single: singleConfigurable[string]{
-							cases: []ConfigurableCase[string]{{
-								value: StringPtr("asdf"),
-							}},
+				Foo: newConfigurableWithPropertyName(
+					"foo",
+					nil,
+					[]ConfigurableCase[string]{{
+						value: &parser.String{
+							LiteralPos: scanner.Position{
+								Offset: 25,
+								Line:   2,
+								Column: 25,
+							},
+							Value: "asdf",
 						},
-					},
-				},
-				Bar: Configurable[bool]{
-					propertyName: "bar",
-					inner: &configurableInner[bool]{
-						single: singleConfigurable[bool]{
-							cases: []ConfigurableCase[bool]{{
-								value: BoolPtr(true),
-							}},
+					}},
+					false,
+				),
+				Bar: newConfigurableWithPropertyName(
+					"bar",
+					nil,
+					[]ConfigurableCase[bool]{{
+						value: &parser.Bool{
+							LiteralPos: scanner.Position{
+								Offset: 54,
+								Line:   3,
+								Column: 23,
+							},
+							Value: true,
+							Token: "true",
 						},
-					},
-				},
+					}},
+					false,
+				),
 			},
 		},
 	},
diff --git a/provider.go b/provider.go
index b2e08765e6..5873d10c1a 100644
--- a/provider.go
+++ b/provider.go
@@ -15,6 +15,9 @@
 package blueprint
 
 import (
+	"bytes"
+	"encoding/gob"
+	"errors"
 	"fmt"
 
 	"github.com/google/blueprint/proptools"
@@ -53,6 +56,28 @@ type providerKey struct {
 	mutator string
 }
 
+func (m *providerKey) GobEncode() ([]byte, error) {
+	w := new(bytes.Buffer)
+	encoder := gob.NewEncoder(w)
+	err := errors.Join(encoder.Encode(m.id), encoder.Encode(m.typ), encoder.Encode(m.mutator))
+	if err != nil {
+		return nil, err
+	}
+
+	return w.Bytes(), nil
+}
+
+func (m *providerKey) GobDecode(data []byte) error {
+	r := bytes.NewBuffer(data)
+	decoder := gob.NewDecoder(r)
+	err := errors.Join(decoder.Decode(&m.id), decoder.Decode(&m.typ), decoder.Decode(&m.mutator))
+	if err != nil {
+		return err
+	}
+
+	return nil
+}
+
 func (p *providerKey) provider() *providerKey { return p }
 
 type AnyProviderKey interface {
@@ -73,6 +98,8 @@ var providerRegistry []*providerKey
 // inside GenerateBuildActions for the module, and to get the value from GenerateBuildActions from
 // any module later in the build graph.
 func NewProvider[K any]() ProviderKey[K] {
+	var defaultValue K
+	gob.Register(defaultValue)
 	return NewMutatorProvider[K]("")
 }
 
diff --git a/singleton_ctx.go b/singleton_ctx.go
index fdcf2a91f7..ab44108ea2 100644
--- a/singleton_ctx.go
+++ b/singleton_ctx.go
@@ -161,6 +161,10 @@ type SingletonContext interface {
 	// ModuleVariantsFromName returns the list of module variants named `name` in the same namespace as `referer`.
 	// Allows generating build actions for `referer` based on the metadata for `name` deferred until the singleton context.
 	ModuleVariantsFromName(referer Module, name string) []Module
+
+	// HasMutatorFinished returns true if the given mutator has finished running.
+	// It will panic if given an invalid mutator name.
+	HasMutatorFinished(mutatorName string) bool
 }
 
 var _ SingletonContext = (*singletonContext)(nil)
@@ -400,3 +404,7 @@ func (s *singletonContext) ModuleVariantsFromName(referer Module, name string) [
 	}
 	return result
 }
+
+func (s *singletonContext) HasMutatorFinished(mutatorName string) bool {
+	return s.context.HasMutatorFinished(mutatorName)
+}
diff --git a/transition.go b/transition.go
index 2867c35440..595e9af8f7 100644
--- a/transition.go
+++ b/transition.go
@@ -119,6 +119,12 @@ type IncomingTransitionContext interface {
 	//
 	// This method shouldn't be used directly, prefer the type-safe android.ModuleProvider instead.
 	Provider(provider AnyProviderKey) (any, bool)
+
+	// IsAddingDependency returns true if the transition is being called while adding a dependency
+	// after the transition mutator has already run, or false if it is being called when the transition
+	// mutator is running.  This should be used sparingly, all uses will have to be removed in order
+	// to support creating variants on demand.
+	IsAddingDependency() bool
 }
 
 type OutgoingTransitionContext interface {
@@ -144,9 +150,10 @@ type OutgoingTransitionContext interface {
 }
 
 type transitionMutatorImpl struct {
-	name          string
-	mutator       TransitionMutator
-	inputVariants map[*moduleGroup][]*moduleInfo
+	name                        string
+	mutator                     TransitionMutator
+	variantCreatingMutatorIndex int
+	inputVariants               map[*moduleGroup][]*moduleInfo
 }
 
 // Adds each argument in items to l if it's not already there.
@@ -206,11 +213,12 @@ func (t *transitionMutatorImpl) topDownMutator(mctx TopDownMutatorContext) {
 }
 
 type transitionContextImpl struct {
-	context *Context
-	source  *moduleInfo
-	dep     *moduleInfo
-	depTag  DependencyTag
-	config  interface{}
+	context     *Context
+	source      *moduleInfo
+	dep         *moduleInfo
+	depTag      DependencyTag
+	postMutator bool
+	config      interface{}
 }
 
 func (c *transitionContextImpl) DepTag() DependencyTag {
@@ -221,6 +229,10 @@ func (c *transitionContextImpl) Config() interface{} {
 	return c.config
 }
 
+func (c *transitionContextImpl) IsAddingDependency() bool {
+	return c.postMutator
+}
+
 type outgoingTransitionContextImpl struct {
 	transitionContextImpl
 }
@@ -290,7 +302,7 @@ func (t *transitionMutatorImpl) bottomUpMutator(mctx BottomUpMutatorContext) {
 
 func (t *transitionMutatorImpl) mutateMutator(mctx BottomUpMutatorContext) {
 	module := mctx.(*mutatorContext).module
-	currentVariation := module.variant.variations[t.name]
+	currentVariation := module.variant.variations.get(t.name)
 	t.mutator.Mutate(mctx, currentVariation)
 }
 
diff --git a/transition_test.go b/transition_test.go
index 7c6e1f4d4c..e2d0222d3f 100644
--- a/transition_test.go
+++ b/transition_test.go
@@ -87,6 +87,7 @@ const testTransitionBp = `
 
 			transition_module {
 				name: "F",
+				incoming: "",
 			}
 
 			transition_module {
@@ -112,7 +113,7 @@ func checkTransitionVariants(t *testing.T, ctx *Context, name string, expectedVa
 	group := ctx.moduleGroupFromName(name, nil)
 	var gotVariants []string
 	for _, variant := range group.modules {
-		gotVariants = append(gotVariants, variant.moduleOrAliasVariant().variations["transition"])
+		gotVariants = append(gotVariants, variant.moduleOrAliasVariant().variations.get("transition"))
 	}
 	if !slices.Equal(expectedVariants, gotVariants) {
 		t.Errorf("expected variants of %q to be %q, got %q", name, expectedVariants, gotVariants)
@@ -233,7 +234,7 @@ func TestPostTransitionDeps(t *testing.T) {
 	//  C(c) was added by C and rewritten by OutgoingTransition on B
 	//  D(d) was added by D:late and rewritten by IncomingTransition on D
 	//  E(d) was added by E:d
-	//  F() was added by F, and ignored the existing variation on B
+	//  F() was added by F and rewritten OutgoingTransition on B and then IncomingTransition on F
 	checkTransitionDeps(t, ctx, B_a, "C(c)", "C(c)", "D(d)", "E(d)", "F()")
 	checkTransitionDeps(t, ctx, B_b, "C(c)", "C(c)", "D(d)", "E(d)", "F()")
 	checkTransitionDeps(t, ctx, C_a, "D(d)")
@@ -259,6 +260,30 @@ func TestPostTransitionDeps(t *testing.T) {
 	checkTransitionMutate(t, H_h, "h")
 }
 
+func TestPostTransitionReverseDeps(t *testing.T) {
+	ctx, errs := testTransition(`
+		transition_module {
+			name: "A",
+			split: ["a1", "a2"],
+		}
+
+		transition_module {
+			name: "B",
+			split: ["a1", "a2"],
+			post_transition_reverse_deps: ["A"],
+		}
+	`)
+	assertNoErrors(t, errs)
+
+	checkTransitionVariants(t, ctx, "A", []string{"a1", "a2"})
+	checkTransitionVariants(t, ctx, "B", []string{"a1", "a2"})
+
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "A", "a1"), "B(a1)")
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "A", "a2"), "B(a2)")
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "B", "a1"))
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "B", "a2"))
+}
+
 func TestPostTransitionDepsMissingVariant(t *testing.T) {
 	// TODO: eventually this will create the missing variant on demand
 	_, errs := testTransition(fmt.Sprintf(testTransitionBp,
@@ -266,13 +291,44 @@ func TestPostTransitionDepsMissingVariant(t *testing.T) {
 	expectedError := `Android.bp:8:4: dependency "E" of "B" missing variant:
   transition:missing
 available variants:
-  transition:
+  <empty variant>
   transition:d`
 	if len(errs) != 1 || errs[0].Error() != expectedError {
 		t.Errorf("expected error %q, got %q", expectedError, errs)
 	}
 }
 
+func TestIsAddingDependency(t *testing.T) {
+	ctx, errs := testTransition(`
+		transition_module {
+			name: "A",
+			split: ["a1"],
+			deps: ["C"],
+		}
+
+		transition_module {
+			name: "B",
+			split: ["b1"],
+			post_transition_deps: ["C"],
+		}
+
+		transition_module {
+			name: "C",
+			split: ["c1", "c2"],
+			incoming: "c1",
+			post_transition_incoming: "c2",
+		}
+	`)
+	assertNoErrors(t, errs)
+
+	checkTransitionVariants(t, ctx, "A", []string{"a1"})
+	checkTransitionVariants(t, ctx, "B", []string{"b1"})
+	checkTransitionVariants(t, ctx, "C", []string{"c1", "c2"})
+
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "A", "a1"), "C(c1)")
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "B", "b1"), "C(c2)")
+}
+
 type transitionTestMutator struct{}
 
 func (transitionTestMutator) Split(ctx BaseModuleContext) []string {
@@ -290,6 +346,12 @@ func (transitionTestMutator) OutgoingTransition(ctx OutgoingTransitionContext, s
 }
 
 func (transitionTestMutator) IncomingTransition(ctx IncomingTransitionContext, incomingVariation string) string {
+
+	if ctx.IsAddingDependency() {
+		if incoming := ctx.Module().(*transitionModule).properties.Post_transition_incoming; incoming != nil {
+			return *incoming
+		}
+	}
 	if incoming := ctx.Module().(*transitionModule).properties.Incoming; incoming != nil {
 		return *incoming
 	}
@@ -303,11 +365,13 @@ func (transitionTestMutator) Mutate(ctx BottomUpMutatorContext, variation string
 type transitionModule struct {
 	SimpleName
 	properties struct {
-		Deps                 []string
-		Post_transition_deps []string
-		Split                []string
-		Outgoing             *string
-		Incoming             *string
+		Deps                         []string
+		Post_transition_deps         []string
+		Post_transition_reverse_deps []string
+		Split                        []string
+		Outgoing                     *string
+		Incoming                     *string
+		Post_transition_incoming     *string
 
 		Mutated string `blueprint:"mutated"`
 	}
@@ -339,5 +403,8 @@ func postTransitionDepsMutator(mctx BottomUpMutatorContext) {
 			}
 			mctx.AddVariationDependencies(variations, walkerDepsTag{follow: true}, module)
 		}
+		for _, dep := range m.properties.Post_transition_reverse_deps {
+			mctx.AddReverseDependency(m, walkerDepsTag{follow: true}, dep)
+		}
 	}
 }
```

