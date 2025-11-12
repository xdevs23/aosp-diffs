```diff
diff --git a/Android.bp b/Android.bp
index 051d77c..4e20859 100644
--- a/Android.bp
+++ b/Android.bp
@@ -47,7 +47,9 @@ bootstrap_go_package {
     pkgPath: "github.com/google/blueprint",
     srcs: [
         "context.go",
+        "context_gob_enc.go",
         "incremental.go",
+        "incremental_gob_enc.go",
         "levenshtein.go",
         "glob.go",
         "live_tracker.go",
@@ -59,6 +61,7 @@ bootstrap_go_package {
         "ninja_writer.go",
         "package_ctx.go",
         "provider.go",
+        "provider_gob_enc.go",
         "scope.go",
         "singleton_ctx.go",
         "transition.go",
@@ -151,8 +154,9 @@ bootstrap_go_package {
     name: "blueprint-proptools",
     pkgPath: "github.com/google/blueprint/proptools",
     deps: [
-        "blueprint-parser",
         "blueprint-optional",
+        "blueprint-parser",
+        "blueprint-pool",
     ],
     srcs: [
         "proptools/clone.go",
diff --git a/bootstrap/bootstrap.go b/bootstrap/bootstrap.go
index 14d8cc0..9e6a7e5 100644
--- a/bootstrap/bootstrap.go
+++ b/bootstrap/bootstrap.go
@@ -32,6 +32,7 @@ var (
 	goTestMainCmd   = pctx.StaticVariable("goTestMainCmd", filepath.Join("$ToolDir", "gotestmain"))
 	goTestRunnerCmd = pctx.StaticVariable("goTestRunnerCmd", filepath.Join("$ToolDir", "gotestrunner"))
 	pluginGenSrcCmd = pctx.StaticVariable("pluginGenSrcCmd", filepath.Join("$ToolDir", "loadplugins"))
+	gobGenCmd       = pctx.StaticVariable("gobGenCmd", filepath.Join("$ToolDir", "gob_gen"))
 
 	parallelCompile = pctx.StaticVariable("parallelCompile", func() string {
 		numCpu := runtime.NumCPU()
@@ -82,6 +83,13 @@ var (
 		},
 		"pkg", "plugins")
 
+	verifySerializers = pctx.StaticRule("generateSerializers",
+		blueprint.RuleParams{
+			Command:     "rm -f $out && $gobGenCmd -verify $in && touch $out",
+			CommandDeps: []string{"$gobGenCmd"},
+			Description: "generate serializers $out",
+		})
+
 	test = pctx.StaticRule("test",
 		blueprint.RuleParams{
 			Command:     "$goTestRunnerCmd -p $pkgSrcDir -f $out -- $in -test.short",
@@ -226,11 +234,13 @@ type pluginDependencyTag struct {
 	blueprint.BaseDependencyTag
 }
 
+func (pluginDependencyTag) ExcludeFromVisibilityEnforcement() {}
+
 type bootstrapDependencies interface {
 	bootstrapDeps(ctx blueprint.BottomUpMutatorContext)
 }
 
-var pluginDepTag = pluginDependencyTag{}
+var PluginDepTag = pluginDependencyTag{}
 
 func BootstrapDeps(ctx blueprint.BottomUpMutatorContext) {
 	if pkg, ok := ctx.Module().(bootstrapDependencies); ok {
@@ -264,6 +274,7 @@ var DocsPackageProvider = blueprint.NewMutatorProvider[*DocsPackageInfo]("bootst
 
 // A GoPackage is a module for building Go packages.
 type GoPackage struct {
+	blueprint.ModuleBase
 	blueprint.SimpleName
 	properties struct {
 		Deps      []string
@@ -306,7 +317,7 @@ func (g *GoPackage) DynamicDependencies(ctx blueprint.DynamicDependerModuleConte
 
 func (g *GoPackage) bootstrapDeps(ctx blueprint.BottomUpMutatorContext) {
 	for _, plugin := range g.properties.PluginFor {
-		ctx.AddReverseDependency(ctx.Module(), pluginDepTag, plugin)
+		ctx.AddReverseDependency(ctx.Module(), PluginDepTag, plugin)
 	}
 	blueprint.SetProvider(ctx, DocsPackageProvider, &DocsPackageInfo{
 		PkgPath: g.properties.PkgPath,
@@ -332,7 +343,7 @@ func (g *GoPackage) GenerateBuildActions(ctx blueprint.ModuleContext) {
 		filepath.FromSlash(g.properties.PkgPath)+".a")
 
 	ctx.VisitDepsDepthFirst(func(module blueprint.Module) {
-		if ctx.OtherModuleDependencyTag(module) == pluginDepTag {
+		if ctx.OtherModuleDependencyTag(module) == PluginDepTag {
 			hasPlugins = true
 		}
 	})
@@ -378,8 +389,22 @@ func (g *GoPackage) GenerateBuildActions(ctx blueprint.ModuleContext) {
 	})
 }
 
+func buildVerifySerializers(ctx blueprint.ModuleContext, outputFile string, srcs []string) {
+	var srcPaths []string
+	for _, src := range srcs {
+		srcPaths = append(srcPaths, filepath.Join(moduleSrcDir(ctx), src))
+	}
+
+	ctx.Build(pctx, blueprint.BuildParams{
+		Rule:    verifySerializers,
+		Inputs:  srcPaths,
+		Outputs: []string{outputFile},
+	})
+}
+
 // A GoBinary is a module for building executable binaries from Go sources.
 type GoBinary struct {
+	blueprint.ModuleBase
 	blueprint.SimpleName
 	properties struct {
 		Deps           []string
@@ -463,7 +488,7 @@ func (g *GoBinary) GenerateBuildActions(ctx blueprint.ModuleContext) {
 	}
 
 	ctx.VisitDirectDeps(func(module blueprint.Module) {
-		if ctx.OtherModuleDependencyTag(module) == pluginDepTag {
+		if ctx.OtherModuleDependencyTag(module) == PluginDepTag {
 			hasPlugins = true
 		}
 	})
@@ -546,7 +571,7 @@ func buildGoPluginLoader(ctx blueprint.ModuleContext, pkgPath, pluginSrc string)
 
 	var pluginPaths []string
 	ctx.VisitDirectDeps(func(module blueprint.Module) {
-		if ctx.OtherModuleDependencyTag(module) == pluginDepTag {
+		if ctx.OtherModuleDependencyTag(module) == PluginDepTag {
 			if info, ok := blueprint.OtherModuleProvider(ctx, module, PackageProvider); ok {
 				pluginPaths = append(pluginPaths, info.PkgPath)
 			}
@@ -620,12 +645,21 @@ func buildGoPackage(ctx blueprint.ModuleContext, pkgRoot string,
 		deps = append(deps, embedcfgFile)
 	}
 
+	var validations []string
+
+	if ctx.Config().(BootstrapConfig).IsBootstrap() {
+		verifySerializers := archiveFile + ".verify_serializers"
+		buildVerifySerializers(ctx, verifySerializers, srcs)
+		validations = append(validations, verifySerializers)
+	}
+
 	ctx.Build(pctx, blueprint.BuildParams{
-		Rule:      compile,
-		Outputs:   []string{archiveFile},
-		Inputs:    srcFiles,
-		Implicits: deps,
-		Args:      compileArgs,
+		Rule:        compile,
+		Outputs:     []string{archiveFile},
+		Inputs:      srcFiles,
+		Implicits:   deps,
+		Args:        compileArgs,
+		Validations: validations,
 	})
 }
 
@@ -727,8 +761,8 @@ func (s *singleton) GenerateBuildActions(ctx blueprint.SingletonContext) {
 	var blueprintTests []string
 	// blueprintGoPackages contains all blueprint go packages that can be built in StageMain
 	var blueprintGoPackages []string
-	ctx.VisitAllModules(func(module blueprint.Module) {
-		if ctx.PrimaryModule(module) == module {
+	ctx.VisitAllModuleProxies(func(module blueprint.ModuleProxy) {
+		if ctx.IsPrimaryModule(module) {
 			if binaryInfo, ok := blueprint.SingletonModuleProvider(ctx, module, BinaryProvider); ok {
 				if binaryInfo.InstallPath != "" {
 					blueprintTools = append(blueprintTools, binaryInfo.InstallPath)
diff --git a/bootstrap/command.go b/bootstrap/command.go
index d488f18..b2c2b00 100644
--- a/bootstrap/command.go
+++ b/bootstrap/command.go
@@ -44,6 +44,7 @@ type Args struct {
 	// Debug data json file
 	ModuleDebugFile         string
 	IncrementalBuildActions bool
+	IncrementalDebugFile    string
 }
 
 // RegisterGoModuleTypes adds module types to build tools written in golang
@@ -108,7 +109,7 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 	}
 	ctx.EndEvent("list_modules")
 
-	ctx.RegisterBottomUpMutator("bootstrap_deps", BootstrapDeps).UsesReverseDependencies()
+	ctx.RegisterFirstBottomUpMutator("bootstrap_deps", BootstrapDeps).UsesReverseDependencies()
 	ctx.RegisterSingletonType("bootstrap", newSingletonFactory(), false)
 	if !goModuleTypesAreWrapped {
 		RegisterGoModuleTypes(ctx)
@@ -139,23 +140,25 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 	}
 
 	if ctx.GetIncrementalAnalysis() {
-		var err error = nil
-		err = ctx.RestoreAllBuildActions(config.(BootstrapConfig).SoongOutDir())
+		ctx.BeginEvent("restore_build_actions")
+		err := ctx.RestoreAllBuildActions(config.(BootstrapConfig).SoongOutDir())
+		ctx.EndEvent("restore_build_actions")
 		if err != nil {
 			return nil, colorizeErrs([]error{err})
 		}
 	}
 
+	if args.ModuleDebugFile != "" {
+		finishFunc := ctx.InitializeModuleDebugInfoCollection(args.ModuleDebugFile)
+		defer finishFunc()
+	}
+
 	if buildActionsDeps, errs := ctx.PrepareBuildActions(config); len(errs) > 0 {
 		return nil, colorizeErrs(errs)
 	} else {
 		ninjaDeps = append(ninjaDeps, buildActionsDeps...)
 	}
 
-	if args.ModuleDebugFile != "" {
-		ctx.GenerateModuleDebugInfo(args.ModuleDebugFile)
-	}
-
 	if stopBefore == StopBeforeWriteNinja {
 		return ninjaDeps, nil
 	}
@@ -197,7 +200,10 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 
 	// TODO(b/357140398): parallelize this with other ninja file writing work.
 	if ctx.GetIncrementalEnabled() {
-		if err := ctx.CacheAllBuildActions(config.(BootstrapConfig).SoongOutDir()); err != nil {
+		ctx.BeginEvent("cache_build_actions")
+		err := ctx.CacheAllBuildActions(config.(BootstrapConfig).SoongOutDir())
+		ctx.EndEvent("cache_build_actions")
+		if err != nil {
 			return nil, fmt.Errorf("error cache build actions: %s", err)
 		}
 	}
diff --git a/bootstrap/config.go b/bootstrap/config.go
index 929eac5..0dd99c6 100644
--- a/bootstrap/config.go
+++ b/bootstrap/config.go
@@ -94,6 +94,10 @@ type BootstrapConfig interface {
 
 	Subninjas() []string
 	PrimaryBuilderInvocations() []PrimaryBuilderInvocation
+
+	// IsBootstrap returns true if this is a bootstrap invocation, false if
+	// it is the primary builder.
+	IsBootstrap() bool
 }
 
 type StopBefore int
diff --git a/context.go b/context.go
index 1baefda..875ec98 100644
--- a/context.go
+++ b/context.go
@@ -19,7 +19,6 @@ import (
 	"bytes"
 	"cmp"
 	"context"
-	"encoding/gob"
 	"encoding/json"
 	"errors"
 	"fmt"
@@ -44,6 +43,7 @@ import (
 	"text/template"
 	"unsafe"
 
+	"github.com/google/blueprint/gobtools"
 	"github.com/google/blueprint/metrics"
 	"github.com/google/blueprint/parser"
 	"github.com/google/blueprint/pathtools"
@@ -53,6 +53,8 @@ import (
 	"github.com/google/blueprint/uniquelist"
 )
 
+//go:generate go run gobtools/codegen/gob_gen.go
+
 var ErrBuildActionsNotReady = errors.New("build actions are not ready")
 
 const maxErrors = 10
@@ -98,7 +100,6 @@ type Context struct {
 	moduleFactories     map[string]ModuleFactory
 	nameInterface       NameInterface
 	moduleGroups        []*moduleGroup
-	moduleInfo          map[Module]*moduleInfo
 	singletonInfo       []*singletonInfo
 	mutatorInfo         []*mutatorInfo
 	variantMutatorNames []string
@@ -182,6 +183,9 @@ type Context struct {
 	buildActionsToCacheLock sync.Mutex
 	orderOnlyStringsCache   OrderOnlyStringsCache
 	orderOnlyStrings        syncmap.SyncMap[uniquelist.UniqueList[string], *orderOnlyStringsInfo]
+	incrementalDebugFile    string
+
+	moduleDebugDataChannel chan []byte
 }
 
 type orderOnlyStringsInfo struct {
@@ -360,7 +364,7 @@ type moduleInfo struct {
 	directDeps  []depInfo
 
 	// used by parallelVisit
-	waitingCount int
+	waitingCount atomic.Int32
 
 	// set during each runMutator
 	splitModules           moduleList
@@ -372,8 +376,9 @@ type moduleInfo struct {
 	// requested by reverse dependencies.  It is updated by reverse dependencies and protected by
 	// incomingTransitionInfosLock.  It is invalid after the TransitionMutator top down mutator has run on
 	// this module.
-	incomingTransitionInfos     map[string]TransitionInfo
-	incomingTransitionInfosLock sync.Mutex
+	incomingTransitionInfos      map[string]TransitionInfo
+	incomingTransitionInfoHashes map[string]uint64
+	incomingTransitionInfosLock  sync.Mutex
 	// splitTransitionInfos and splitTransitionVariations stores the list of TransitionInfo objects, and their
 	// corresponding variations, returned by Split or requested by reverse dependencies.  They are valid after the
 	// TransitionMutator top down mutator has run on this module, and invalid after the bottom up mutator has run.
@@ -400,13 +405,31 @@ type moduleInfo struct {
 	startedGenerateBuildActions  bool
 	finishedGenerateBuildActions bool
 
+	// freeAfterGenerateBuildActions is set if the module called ModuleContext.FreeModuleAfterGenerateBuildActions,
+	// allowing the Module to be freed after GenerateBuildActions complete, and requiring all future accesses
+	// to go through ModuleProxy instead of the Module.
+	freeAfterGenerateBuildActions bool
+	// cachedName stores the result of Module.Name() after the end of GenerateBuildActions for use in ModuleProxy.Name()
+	cachedName string
+	// cachedString stores the result of Module.String() after the end of GenerateBuildActions for use in ModuleProxy.String().
+	cachedString string
+
 	incrementalInfo
 }
 
+// @auto-generate: gob
+type globResultCache struct {
+	Pattern  string
+	Excludes []string
+	Result   uint64
+}
+
 type incrementalInfo struct {
-	incrementalRestored bool
-	buildActionCacheKey *BuildActionCacheKey
-	orderOnlyStrings    []string
+	incrementalRestored  bool
+	buildActionCacheKey  *BuildActionCacheKey
+	orderOnlyStrings     []string
+	incrementalDebugInfo []byte
+	globCache            []globResultCache
 }
 
 type variant struct {
@@ -455,7 +478,6 @@ func (module *moduleInfo) ModuleCacheKey() string {
 	}
 	return calculateFileNameHash(fmt.Sprintf("%s-%s-%s-%s",
 		filepath.Dir(module.relBlueprintsFile), module.Name(), variant, module.typeName))
-
 }
 
 func calculateFileNameHash(name string) string {
@@ -476,6 +498,7 @@ func (c *Context) setModuleTransitionInfo(module *moduleInfo, t *transitionMutat
 // A Variation is a way that a variant of a module differs from other variants of the same module.
 // For example, two variants of the same module might have Variation{"arch","arm"} and
 // Variation{"arch","arm64"}
+// @auto-generate: gob
 type Variation struct {
 	// Mutator is the axis on which this variation applies, i.e. "arch" or "link"
 	Mutator string
@@ -593,7 +616,6 @@ func newContext() *Context {
 		EventHandler:          &eventHandler,
 		moduleFactories:       make(map[string]ModuleFactory),
 		nameInterface:         NewSimpleNameInterface(),
-		moduleInfo:            make(map[Module]*moduleInfo),
 		globs:                 make(map[globKey]pathtools.GlobResult),
 		fs:                    pathtools.OsFs,
 		includeTags:           &IncludeTags{},
@@ -743,6 +765,10 @@ func (c *Context) GetIncrementalEnabled() bool {
 	return c.incrementalEnabled
 }
 
+func (c *Context) SetIncrementalDebugFile(file string) {
+	c.incrementalDebugFile = file
+}
+
 func (c *Context) updateBuildActionsCache(key *BuildActionCacheKey, data *BuildActionCachedData) {
 	if key != nil {
 		c.buildActionsToCacheLock.Lock()
@@ -763,7 +789,7 @@ func (c *Context) CacheAllBuildActions(soongOutDir string) error {
 		writeToCache(c, soongOutDir, OrderOnlyStringsCacheFile, &c.orderOnlyStringsCache))
 }
 
-func writeToCache[T any](ctx *Context, soongOutDir string, fileName string, data *T) error {
+func writeToCache(ctx *Context, soongOutDir string, fileName string, data gobtools.CustomEnc) error {
 	file, err := ctx.fs.OpenFile(filepath.Join(ctx.SrcDir(), soongOutDir, fileName),
 		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, OutFilePermissions)
 	if err != nil {
@@ -771,8 +797,12 @@ func writeToCache[T any](ctx *Context, soongOutDir string, fileName string, data
 	}
 	defer file.Close()
 
-	encoder := gob.NewEncoder(file)
-	return encoder.Encode(data)
+	buf := new(bytes.Buffer)
+	if err = data.Encode(buf); err != nil {
+		return err
+	}
+	_, err = file.Write(buf.Bytes())
+	return err
 }
 
 func (c *Context) RestoreAllBuildActions(soongOutDir string) error {
@@ -780,18 +810,18 @@ func (c *Context) RestoreAllBuildActions(soongOutDir string) error {
 		restoreFromCache(c, soongOutDir, OrderOnlyStringsCacheFile, &c.orderOnlyStringsCache))
 }
 
-func restoreFromCache[T any](ctx *Context, soongOutDir string, fileName string, data *T) error {
-	file, err := ctx.fs.Open(filepath.Join(ctx.SrcDir(), soongOutDir, fileName))
-	if err != nil {
-		if os.IsNotExist(err) {
-			err = nil
-		}
-		return err
+func restoreFromCache(ctx *Context, soongOutDir string, fileName string, data gobtools.CustomDec) error {
+	file := filepath.Join(ctx.SrcDir(), soongOutDir, fileName)
+	if _, err := os.Stat(file); os.IsNotExist(err) {
+		return nil
 	}
-	defer file.Close()
 
-	decoder := gob.NewDecoder(file)
-	return decoder.Decode(data)
+	if readBytes, err := os.ReadFile(file); err != nil {
+		return err
+	} else {
+		buf := bytes.NewReader(readBytes)
+		return data.Decode(buf)
+	}
 }
 
 func (c *Context) SetSrcDir(path string) {
@@ -865,6 +895,31 @@ func (c *Context) RegisterBottomUpMutator(name string, mutator BottomUpMutator)
 	return info
 }
 
+// RegisterFirstBottomUpMutator registers a mutator that will be invoked to split Modules into variants.
+// The registered mutator is placed at the front of the list.
+//
+// The mutator type names given here must be unique to all bottom up mutators in the Context.
+func (c *Context) RegisterFirstBottomUpMutator(name string, mutator BottomUpMutator) MutatorHandle {
+	for _, m := range c.variantMutatorNames {
+		if m == name {
+			panic(fmt.Errorf("mutator %q is already registered", name))
+		}
+	}
+
+	info := &mutatorInfo{
+		bottomUpMutator: mutator,
+		name:            name,
+		index:           0,
+	}
+	c.mutatorInfo = append([]*mutatorInfo{info}, c.mutatorInfo...)
+	c.variantMutatorNames = append([]string{name}, c.variantMutatorNames...)
+	for i := range c.mutatorInfo {
+		c.mutatorInfo[i].index = i
+	}
+
+	return info
+}
+
 // HasMutatorFinished returns true if the given mutator has finished running.
 // It will panic if given an invalid mutator name.
 func (c *Context) HasMutatorFinished(mutatorName string) bool {
@@ -1664,7 +1719,7 @@ func (c *Context) createVariations(origModule *moduleInfo, mutator *mutatorInfo,
 		var newLogicModule Module
 		var newProperties []interface{}
 
-		if i == 0 && mutator.transitionMutator == nil {
+		if i == 0 {
 			// Reuse the existing module for the first new variant
 			// This both saves creating a new module, and causes the insertion in c.moduleInfo below
 			// with logicModule as the key to replace the original entry in c.moduleInfo
@@ -1675,6 +1730,7 @@ func (c *Context) createVariations(origModule *moduleInfo, mutator *mutatorInfo,
 
 		m := *origModule
 		newModule := &m
+		newLogicModule.setInfo(newModule)
 		newModule.directDeps = slices.Clone(origModule.directDeps)
 		newModule.reverseDeps = nil
 		newModule.forwardDeps = nil
@@ -1775,11 +1831,15 @@ func (c *Context) prettyPrintGroupVariants(group *moduleGroup) string {
 func newModule(factory ModuleFactory) *moduleInfo {
 	logicModule, properties := factory()
 
-	return &moduleInfo{
-		logicModule: logicModule,
-		factory:     factory,
-		properties:  properties,
+	moduleInfo := &moduleInfo{
+		logicModule:     logicModule,
+		factory:         factory,
+		properties:      properties,
+		startedMutator:  -1,
+		finishedMutator: -1,
 	}
+	logicModule.setInfo(moduleInfo)
+	return moduleInfo
 }
 
 func processModuleDef(moduleDef *parser.Module,
@@ -1840,7 +1900,6 @@ func (c *Context) addModule(module *moduleInfo) []error {
 			},
 		}
 	}
-	c.moduleInfo[module.logicModule] = module
 
 	group := &moduleGroup{
 		name:    name,
@@ -1929,8 +1988,6 @@ func (c *Context) resolveDependencies(ctx context.Context, config interface{}) (
 		}
 		defer c.EndEvent("clone_modules")
 
-		c.clearTransitionMutatorInputVariants()
-
 		c.dependenciesReady = true
 	})
 
@@ -1968,7 +2025,7 @@ func blueprintDepsMutator(ctx BottomUpMutatorContext) {
 // and applies the OutgoingTransition and IncomingTransition methods of each completed TransitionMutator to
 // modify the requested variation.  It finds a variant that existed before the TransitionMutator ran that is
 // a subset of the requested variant to use as the module context for IncomingTransition.
-func (c *Context) applyTransitions(config any, module *moduleInfo, group *moduleGroup, variant variationMap,
+func (c *Context) applyTransitions(config any, module *moduleInfo, depTag DependencyTag, group *moduleGroup, variant variationMap,
 	requestedVariations []Variation, far bool) (variationMap, []error) {
 	for _, transitionMutator := range c.transitionMutators[:c.completedTransitionMutators] {
 		explicitlyRequested := slices.ContainsFunc(requestedVariations, func(variation Variation) bool {
@@ -1988,7 +2045,7 @@ func (c *Context) applyTransitions(config any, module *moduleInfo, group *module
 			ctx := outgoingTransitionContextPool.Get()
 			*ctx = outgoingTransitionContextImpl{
 				transitionContextImpl{context: c, source: module, dep: nil,
-					depTag: nil, postMutator: true, config: config},
+					depTag: depTag, postMutator: true, config: config},
 			}
 			outgoingTransitionInfo = transitionMutator.mutator.OutgoingTransition(ctx, srcTransitionInfo)
 			errs := ctx.errs
@@ -2002,40 +2059,22 @@ func (c *Context) applyTransitions(config any, module *moduleInfo, group *module
 		earlierVariantCreatingMutators := c.transitionMutatorNames[:transitionMutator.index]
 		filteredVariant := variant.cloneMatching(earlierVariantCreatingMutators)
 
-		check := func(inputVariant variationMap) bool {
-			filteredInputVariant := inputVariant.cloneMatching(earlierVariantCreatingMutators)
-			return filteredInputVariant.equal(filteredVariant)
-		}
-
-		// Find an appropriate module to use as the context for the IncomingTransition.  First check if any of the
-		// saved inputVariants for the transition mutator match the filtered variant.
+		// Find an appropriate module to use as the context for the IncomingTransition.
 		var matchingInputVariant *moduleInfo
-		for _, inputVariant := range transitionMutator.inputVariants[group] {
-			if check(inputVariant.variant.variations) {
-				matchingInputVariant = inputVariant
+		for _, module := range group.modules {
+			filteredInputVariant := module.variant.variations.cloneMatching(earlierVariantCreatingMutators)
+			if filteredInputVariant.equal(filteredVariant) {
+				matchingInputVariant = module
 				break
 			}
 		}
 
-		if matchingInputVariant == nil {
-			// If no inputVariants match, check all the variants of the module for a match.  This can happen if
-			// the mutator only created a single "" variant when it ran on this module.  Matching against all variants
-			// is slightly worse  than checking the input variants, as the selected variant could have been modified
-			// by a later mutator in a way that affects the results of IncomingTransition.
-			for _, module := range group.modules {
-				if check(module.variant.variations) {
-					matchingInputVariant = module
-					break
-				}
-			}
-		}
-
 		if matchingInputVariant != nil {
 			// Apply the incoming transition.
 			ctx := incomingTransitionContextPool.Get()
 			*ctx = incomingTransitionContextImpl{
 				transitionContextImpl{context: c, source: nil, dep: matchingInputVariant,
-					depTag: nil, postMutator: true, config: config},
+					depTag: depTag, postMutator: true, config: config},
 			}
 
 			finalTransitionInfo := transitionMutator.mutator.IncomingTransition(ctx, outgoingTransitionInfo)
@@ -2062,7 +2101,7 @@ func (c *Context) applyTransitions(config any, module *moduleInfo, group *module
 	return variant, nil
 }
 
-func (c *Context) findVariant(module *moduleInfo, config any,
+func (c *Context) findVariant(config any, module *moduleInfo, depTag DependencyTag,
 	possibleDeps *moduleGroup, requestedVariations []Variation, far bool, reverse bool) (*moduleInfo, variationMap, []error) {
 
 	// We can't just append variant.Variant to module.dependencyVariant.variantName and
@@ -2084,7 +2123,7 @@ func (c *Context) findVariant(module *moduleInfo, config any,
 
 	if !reverse {
 		var errs []error
-		newVariant, errs = c.applyTransitions(config, module, possibleDeps, newVariant, requestedVariations, far)
+		newVariant, errs = c.applyTransitions(config, module, depTag, possibleDeps, newVariant, requestedVariations, far)
 		if len(errs) > 0 {
 			return nil, variationMap{}, errs
 		}
@@ -2134,7 +2173,7 @@ func (c *Context) addVariationDependency(module *moduleInfo, mutator *mutatorInf
 		return nil, c.discoveredMissingDependencies(module, depName, variationMap{})
 	}
 
-	foundDep, newVariant, errs := c.findVariant(module, config, possibleDeps, variations, far, false)
+	foundDep, newVariant, errs := c.findVariant(config, module, tag, possibleDeps, variations, far, false)
 	if errs != nil {
 		return nil, errs
 	}
@@ -2270,6 +2309,50 @@ var (
 	topDownVisitor  topDownVisitorImpl
 )
 
+// unpause is a channel that will be closed when the paused module should resume.
+type unpause chan struct{}
+
+// pauseFunc is a function a visitor function can call to pause execution until the visitor
+// function on the given module is completed.
+type pauseFunc func(until *moduleInfo)
+
+// parallelVisitWorker is an individual worker that will call visitor functions on behalf of
+// a call to parallelVisit.  It's run method loops until the input queueCh is closed, receiving
+// batches of modules on which to call visit method, and posting responses to the responseCh
+// channel.
+type parallelVisitWorker struct {
+	// queue is the slice of modules that are currently being processed.
+	queue []*moduleInfo
+	// currentQueueIndex is the index into the queue of the module currently being visited.
+	currentQueueIndex int
+
+	// done is the slice of modules that have had the visit method called on them has returned.
+	done []*moduleInfo
+	// remaining is the slice of modules that have not had the visit method called on them.
+	remaining []*moduleInfo
+	// current is the module that is currently running the visit method.
+	current *moduleInfo
+	// unblocked is the slice of modules that are now runnable after visit returned on a module
+	// in this batch.
+	// TODO: can these modules just be handled in this worker?  Use some heuristic to decide
+	//  whether to handle them or send them back to the orchestrator?
+	unblocked []*moduleInfo
+
+	// visit is the method that is called on each module.
+	visit func(module *moduleInfo, pause pauseFunc) bool
+
+	// order is the interface that describes which modules will be ready next once the current module
+	// has had visit called on it.
+	order visitOrderer
+
+	// queueCh is the input channel that provides batches of modules to call visit on.  It is closed
+	// when there is no more work to do.
+	queueCh <-chan []*moduleInfo
+	// responseCh is the output channel where a parallelVisitWorkerResponse is sent after processing
+	// each batch.
+	responseCh chan<- parallelVisitWorkerResponse
+}
+
 // pauseSpec describes a pause that a module needs to occur until another module has been visited,
 // at which point the unpause channel will be closed.
 type pauseSpec struct {
@@ -2278,216 +2361,413 @@ type pauseSpec struct {
 	unpause unpause
 }
 
-type unpause chan struct{}
+// parallelVisitWorkerResponse is sent after a parallelVisitWorker processes a batch of modules.
+type parallelVisitWorkerResponse struct {
+	// done is the slice of modules that have had the visit method called on.
+	done []*moduleInfo
 
-const parallelVisitLimit = 1000
+	// returned is the slice of modules that the worker did not call the visit method on,
+	// either because the visit method returned an error, or because the visit method called
+	// the pause function, which may be waiting (directly or transitively) on a module that
+	// is later in the batch.
+	returned []*moduleInfo
 
-// Calls visit on each module, guaranteeing that visit is not called on a module until visit on all
-// of its dependencies has finished.  A visit function can write a pauseSpec to the pause channel
-// to wait for another dependency to be visited.  If a visit function returns true to cancel
-// while another visitor is paused, the paused visitor will never be resumed and its goroutine
-// will stay paused forever.
-func parallelVisit(moduleIter iter.Seq[*moduleInfo], order visitOrderer, limit int,
-	visit func(module *moduleInfo, pause chan<- pauseSpec) bool) []error {
+	// unblocked is the slice of modules that became ready (i.e. waitingCount is now zero)
+	// after the modules that the worker ran finished.
+	unblocked []*moduleInfo
 
-	doneCh := make(chan *moduleInfo)
-	cancelCh := make(chan bool)
-	pauseCh := make(chan pauseSpec)
-	cancel := false
+	// error is set when a visit method returned an error, signalling that parallelVisit should
+	// abort.
+	error bool
 
-	var backlog []*moduleInfo      // Visitors that are ready to start but backlogged due to limit.
-	var unpauseBacklog []pauseSpec // Visitors that are ready to unpause but backlogged due to limit.
+	// pause is set when the visit method called pause, signalling that the worker is waiting
+	// indefinitely on the unpause channel, which should be closed when the requested module
+	// has completed.
+	pause pauseSpec
+}
 
-	active := 0  // Number of visitors running, not counting paused visitors.
-	visited := 0 // Number of finished visitors.
+// run is the main loop method of a parallelVisitWorker.  It receives batches of modules to
+// call the visit method on from queueCh, and then calls runQueue on them.
+func (worker *parallelVisitWorker) run() {
+	for queued := range worker.queueCh {
+		if len(worker.queue) > 0 {
+			panic(fmt.Errorf("already have queued work"))
+		}
+		errored := worker.runQueue(queued)
+		if errored {
+			return
+		}
+	}
+}
 
-	pauseMap := make(map[*moduleInfo][]pauseSpec)
+// runQueue processes a single batch of modules.
+func (worker *parallelVisitWorker) runQueue(queue []*moduleInfo) bool {
+	worker.queue = queue
+	worker.done = nil
+	worker.unblocked = nil
+	// Use a loop on worker.currentQueueIndex so that the pause method can update it when it sends
+	// the done and remaining modules back to the orchestrator.
+	for worker.currentQueueIndex = 0; worker.currentQueueIndex < len(worker.queue); worker.currentQueueIndex++ {
+		worker.current = worker.queue[worker.currentQueueIndex]
+		worker.remaining = worker.queue[worker.currentQueueIndex+1:]
+		ret := worker.visit(worker.current, worker.pause)
+		worker.done = worker.queue[:worker.currentQueueIndex+1]
+		if ret {
+			// An error occurred.  Send the completed and uncompleted modules back to the orchestrator with
+			// the error flag set.
+			worker.responseCh <- parallelVisitWorkerResponse{
+				done:      worker.done,
+				error:     true,
+				returned:  worker.remaining,
+				unblocked: worker.unblocked,
+			}
+			return true
+		}
 
-	for module := range moduleIter {
-		module.waitingCount = order.waitCount(module)
+		// Decrement waitingCount on the next modules in the tree based
+		// on propagation order, and add them to the queue if they are
+		// ready to start.
+		for _, module := range worker.order.propagate(worker.current) {
+			if module.waitingCount.Add(-1) == 0 {
+				worker.unblocked = append(worker.unblocked, module)
+			}
+		}
 	}
 
-	// Call the visitor on a module if there are fewer active visitors than the parallelism
-	// limit, otherwise add it to the backlog.
-	startOrBacklog := func(module *moduleInfo) {
-		if active < limit {
-			active++
-			go func() {
-				ret := visit(module, pauseCh)
-				if ret {
-					cancelCh <- true
-				}
-				doneCh <- module
-			}()
-		} else {
-			backlog = append(backlog, module)
-		}
+	// The batch is complete.  Send the completed modules back to the orchestrator.
+	worker.responseCh <- parallelVisitWorkerResponse{
+		done:      worker.done,
+		unblocked: worker.unblocked,
 	}
+	worker.queue = nil
+	return false
+}
 
-	// Unpause the already-started but paused  visitor on a module if there are fewer active
-	// visitors than the parallelism limit, otherwise add it to the backlog.
-	unpauseOrBacklog := func(pauseSpec pauseSpec) {
-		if active < limit {
-			active++
-			close(pauseSpec.unpause)
-		} else {
-			unpauseBacklog = append(unpauseBacklog, pauseSpec)
-		}
+// pause is called by visitors (via the function pointer passed into the visit function) in order to
+// signal that the visitor needs to wait until the visitor has completed on the target module.
+func (worker *parallelVisitWorker) pause(until *moduleInfo) {
+	// If the target module is already done there is no need to pause.  This is safe because waitingCount
+	// will never change once it has reached -1.
+	if until.waitingCount.Load() == -1 {
+		return
 	}
+	unpause := make(chan struct{})
+	// This visitor needs to pause.  Send the completed and uncompleted modules back to the orchestrator
+	// with a pauseSpec that describes how and when to unpause this module.  The uncompleted modules are
+	// returned to the orchestrator in case the pause is waiting (directly or transitively) for one of
+	// the uncompleted modules.
+	worker.responseCh <- parallelVisitWorkerResponse{
+		done:      worker.done,
+		returned:  worker.remaining,
+		unblocked: worker.unblocked,
+		pause: pauseSpec{
+			paused:  worker.current,
+			until:   until,
+			unpause: unpause,
+		},
+	}
+	// Reset the queue to contain only the current module, as everything else has already been returned
+	// to the orchestrator.
+	worker.done = nil
+	worker.queue = []*moduleInfo{worker.current}
+	worker.currentQueueIndex = 0
+	worker.remaining = nil
+	worker.unblocked = nil
+
+	// Wait for the orchestrator to close the unpause channel to signal that the requested module has
+	// finished.
+	<-unpause
+}
+
+// parallelVisitLimit is the maximum number of visitors that can be simultaneously active in parallelVisit.
+var parallelVisitLimit = runtime.NumCPU() * 2
+
+// parallelVisitBatchSize is the number of visitors that will be batched together and passed to a single
+// parallelVisitWorker in order to reduce channel communication overhead.  Setting this value higher
+// amortizes the synchronization and coordination costs across more modules, but setting it too high
+// risks having a single worker left processing modules after all the other workers have finished if it
+// has too many long visitors in a single batch.
+const parallelVisitBatchSize = 100
+
+// parallelVisit calls visit on each module, guaranteeing that visit is not called on a module until
+// visit on all of its dependencies (as determined by the visitOrderer) has finished.  A visit function
+// can call the pause function to wait for another dependency to be visited before continuing.
+// If a visit function returns true to cancel while another visitor is paused, the paused visitor will
+// never be resumed and its goroutine will stay paused forever.
+// The limit argument sets the maximum number of workers that can be running visit functions simultaneously.
+// The total number of workers can be higher than limit if some of them are paused, but the paused workers
+// won't be unpaused until the number of active workers drops below the limit.
+func parallelVisit(moduleIter iter.Seq[*moduleInfo], order visitOrderer, limit int,
+	visit func(module *moduleInfo, pause pauseFunc) bool) []error {
 
-	// Start any modules in the backlog up to the parallelism limit.  Unpause paused modules first
-	// since they may already be holding resources.
-	unpauseOrStartFromBacklog := func() {
-		for active < limit && len(unpauseBacklog) > 0 {
-			unpause := unpauseBacklog[0]
-			unpauseBacklog = unpauseBacklog[1:]
-			unpauseOrBacklog(unpause)
-		}
-		for active < limit && len(backlog) > 0 {
-			toVisit := backlog[0]
-			backlog = backlog[1:]
-			startOrBacklog(toVisit)
+	// queueCh sends batches of modules to process from the orchestrator to the workers.
+	queueCh := make(chan []*moduleInfo, limit)
+	// responseCh receives responses from the workers when a batch has finished processing.
+	responseCh := make(chan parallelVisitWorkerResponse, limit)
+
+	// Closing queueCh when parallelVisit finishes signals the workers to exit.
+	defer close(queueCh)
+
+	activeWorkers := 0 // Number of workers running, not counting paused visitors.
+	activeModules := 0 // Number of modules that have been sent to workers.
+	visited := 0       // Number of modules whose visitors have finished.
+	pausedWorkers := 0 // Number of workers that are waiting on an unpause channel
+	workers := 0       // Total number of spawned workers.
+
+	cancel := false // will be set when any worker returns an error.
+
+	var queue []*moduleInfo           // The list of modules that are ready to be sent to workers.
+	var returnedQueue [][]*moduleInfo // The list of modules that were sent to workers and then returned and need to be resent.
+	var unpauseQueue []pauseSpec      // Visitors that are ready to unpause but backlogged due to limit.
+
+	queuedModules := 0 // The number of modules that are queued in queue, returnedQueue or unpauseQueue.
+
+	// pauseMap holds the map from modules that are being waited on to the list of pauseSpecs that are waiting on them.
+	pauseMap := make(map[*moduleInfo][]pauseSpec)
+
+	// newWorker spawns a new worker goroutine.
+	newWorker := func() {
+		worker := &parallelVisitWorker{
+			visit:      visit,
+			order:      order,
+			queueCh:    queueCh,
+			responseCh: responseCh,
 		}
+		workers++
+		go worker.run()
 	}
 
 	toVisit := 0
 
-	// Start or backlog any modules that are not waiting for any other modules.
+	// Initialize waitingCount on each module with the number of modules that need to complete before it can run.
+	// Add any modules whose waitingCount is 0 to the initial queue of ready modules.
 	for module := range moduleIter {
 		toVisit++
-		if module.waitingCount == 0 {
-			startOrBacklog(module)
+		waitingCount := order.waitCount(module)
+		module.waitingCount.Store(int32(waitingCount))
+		if waitingCount == 0 {
+			queue = append(queue, module)
+			queuedModules++
+		}
+	}
+	queue = slices.Grow(queue, toVisit-len(queue))
+
+	// queueWork is called to send work to any available workers, including spawning new workers if there is work
+	// to do and the number of active workers is below the limit.
+	queueWork := func() {
+		for queuedModules > 0 && activeWorkers < limit {
+			// First priority: unpause any paused workers that are ready, as the visitor functions may already
+			// be holding resources.
+			if len(unpauseQueue) > 0 {
+				unpause := unpauseQueue[0]
+				unpauseQueue = unpauseQueue[1:]
+				pausedWorkers--
+				queuedModules--
+				activeModules++
+				close(unpause.unpause)
+			} else {
+				// If there are worker slots available and no idle workers, spawn a new worker.
+				if activeWorkers < limit && activeWorkers+pausedWorkers == workers {
+					newWorker()
+				}
+				var batch []*moduleInfo
+				// Second priority: re-send any returned work back to a worker.
+				if len(returnedQueue) > 0 {
+					batch = returnedQueue[0]
+					returnedQueue = returnedQueue[1:]
+				} else {
+					// Send a batch of work from the queue.  Limit the size of the batch to the size of the queue
+					// divided by the number of available workers to avoid sending a big batch of work to a single
+					// worker when other workers are available and to parallelVisitBatchSize.
+					availableWorkersSlots := limit - activeWorkers
+					queueSizePerAvailableWorker := (len(queue) + availableWorkersSlots - 1) / availableWorkersSlots
+					batchSize := min(parallelVisitBatchSize, queueSizePerAvailableWorker)
+					batch = queue[:batchSize]
+					queue = queue[batchSize:]
+				}
+				activeModules += len(batch)
+				queuedModules -= len(batch)
+				if len(batch) == 0 {
+					panic("zero length batch")
+				}
+				queueCh <- batch
+			}
+			activeWorkers++
 		}
 	}
 
-	for active > 0 {
-		select {
-		case <-cancelCh:
-			cancel = true
-			backlog = nil
-		case doneModule := <-doneCh:
-			active--
-			if !cancel {
-				// Mark this module as done.
-				doneModule.waitingCount = -1
-				visited++
-
-				// Unpause or backlog any modules that were waiting for this one.
-				if unpauses, ok := pauseMap[doneModule]; ok {
-					delete(pauseMap, doneModule)
-					for _, unpause := range unpauses {
-						unpauseOrBacklog(unpause)
-					}
-				}
+	// Call queueWork before starting the loop so that activeModules is nonzero.
+	queueWork()
 
-				// Start any backlogged modules up to limit.
-				unpauseOrStartFromBacklog()
+	// The main orchestrator loop, which runs until there are no workers doing work.
+	for activeModules > 0 {
+		// Wait for a response from a worker.
+		response := <-responseCh
+		activeWorkers--
 
-				// Decrement waitingCount on the next modules in the tree based
-				// on propagation order, and start or backlog them if they are
-				// ready to start.
-				for _, module := range order.propagate(doneModule) {
-					module.waitingCount--
-					if module.waitingCount == 0 {
-						startOrBacklog(module)
-					}
-				}
+		if response.error {
+			// Once cancel is set no more work will be sent to workers.
+			cancel = true
+		}
+
+		// Process finished modules.
+		visited += len(response.done)
+		activeModules -= len(response.done)
+		for _, doneModule := range response.done {
+			// Mark this module as done.  Nothing else should be updating waitingCount, so a single attempt
+			// at CompareAndSwap should always succeed.  This is the only location that will ever update
+			// waitingCount from 0 to -1, and once it is -1 it will never be changed for the rest of this
+			// call to parallelVisit.
+			if !doneModule.waitingCount.CompareAndSwap(0, -1) {
+				panic(fmt.Errorf("failed to atomically mark module %s as done", doneModule))
 			}
-		case pauseSpec := <-pauseCh:
-			if pauseSpec.until.waitingCount == -1 {
+			// Add any modules that were paused on this module to the unpause queue.
+			if unpauses, ok := pauseMap[doneModule]; ok {
+				delete(pauseMap, doneModule)
+				queuedModules += len(unpauses)
+				unpauseQueue = append(unpauseQueue, unpauses...)
+			}
+		}
+
+		if len(response.unblocked) > 0 {
+			// Add any modules that were made ready to the queue.
+			queuedModules += len(response.unblocked)
+			queue = append(queue, response.unblocked...)
+		}
+
+		// Re-queue any returned modules.
+		if len(response.returned) > 0 {
+			queuedModules += len(response.returned)
+			activeModules -= len(response.returned)
+			returnedQueue = append(returnedQueue, response.returned)
+		}
+
+		// Handle a requested pause.
+		if response.pause.paused != nil {
+			// This goroutine is the only one that can set waitingCount to -1, so reading it here does not
+			// race with updating pauseMap if the value is not yet -1.
+			if response.pause.until.waitingCount.Load() == -1 {
 				// Module being paused for is already finished, resume immediately.
-				close(pauseSpec.unpause)
+				// activeWorkers was decremented above when the response was received,
+				// re-increment it as it is going to resume.
+				activeWorkers++
+				close(response.pause.unpause)
 			} else {
 				// Register for unpausing.
-				pauseMap[pauseSpec.until] = append(pauseMap[pauseSpec.until], pauseSpec)
-
-				// Don't count paused visitors as active so that this can't deadlock
-				// if 1000 visitors are paused simultaneously.
-				active--
-				unpauseOrStartFromBacklog()
+				pauseMap[response.pause.until] = append(pauseMap[response.pause.until], response.pause)
+				pausedWorkers++
+				activeModules--
 			}
 		}
+
+		// Each time a response has been handled check if there is work that can now be queued.
+		if !cancel {
+			queueWork()
+		}
 	}
 
+	// The orchestrator loop has finished because there are no modules being processed.  In the normal case all
+	// the modules should have been visited.  If an error occurred there may be queued or paused modules.
+	// If a deadlock occurred and all remaining modules are not ready or paused then there is newly added
+	// cyclic dependency.
 	if !cancel {
-		// Invariant check: no backlogged modules, these weren't waiting on anything except
+		// Invariant checks: no queued, returned or unpaused modules.  These weren't waiting on anything except
 		// the parallelism limit so they should have run.
-		if len(backlog) > 0 {
-			panic(fmt.Errorf("parallelVisit finished with %d backlogged visitors", len(backlog)))
+		if len(queue) > 0 {
+			panic(fmt.Errorf("parallelVisit finished with %d queued visitors", len(queue)))
 		}
-
-		// Invariant check: no backlogged paused modules, these weren't waiting on anything
-		// except the parallelism limit so they should have run.
-		if len(unpauseBacklog) > 0 {
-			panic(fmt.Errorf("parallelVisit finished with %d backlogged unpaused visitors", len(unpauseBacklog)))
+		if len(returnedQueue) > 0 {
+			panic(fmt.Errorf("parallelVisit finished with %d returned queued visitors", len(returnedQueue)))
+		}
+		if len(unpauseQueue) > 0 {
+			panic(fmt.Errorf("parallelVisit finished with %d queued unpaused visitors", len(unpauseQueue)))
 		}
 
-		if len(pauseMap) > 0 {
-			// Probably a deadlock due to a newly added dependency cycle. Start from each module in
-			// the order of the input modules list and perform a depth-first search for the module
-			// it is paused on, ignoring modules that are marked as done.  Note this traverses from
-			// modules to the modules that would have been unblocked when that module finished, i.e
-			// the reverse of the visitOrderer.
+		if visited != toVisit || len(pauseMap) > 0 {
+			// Probably a deadlock due to a dependency cycle. Start from each module in the order
+			// of the input modules list and perform a depth-first search for any module that is
+			// in the walk path twice.  Note this traverses from modules to the modules that would
+			// have been unblocked when that module finished, i.e. the reverse of the visitOrderer.
+			// This search takes into account both the pre-existing dependencies and any newly
+			// added dependencies that are still in the pauseMap.
 
 			// In order to reduce duplicated work, once a module has been checked and determined
 			// not to be part of a cycle add it and everything that depends on it to the checked
 			// map.
-			checked := make(map[*moduleInfo]struct{})
+			checked := make(map[*moduleInfo]bool, toVisit) // modules that were already checked
+			checking := make(map[*moduleInfo]bool)         // modules actively being checked
 
-			var check func(module, end *moduleInfo) []*moduleInfo
-			check = func(module, end *moduleInfo) []*moduleInfo {
-				if module.waitingCount == -1 {
-					// This module was finished, it can't be part of a loop.
-					return nil
-				}
-				if module == end {
-					// This module is the end of the loop, start rolling up the cycle.
+			var errs []error
+			var check func(group *moduleInfo) []*moduleInfo
+
+			check = func(module *moduleInfo) []*moduleInfo {
+				if checking[module] {
+					// This is a cycle.
 					return []*moduleInfo{module}
 				}
-
-				if _, alreadyChecked := checked[module]; alreadyChecked {
+				if checked[module] {
 					return nil
 				}
 
+				checked[module] = true
+				checking[module] = true
+				defer delete(checking, module)
+
+				var cycle []*moduleInfo
 				for _, dep := range order.propagate(module) {
-					cycle := check(dep, end)
+					cycle = check(dep)
 					if cycle != nil {
-						return append([]*moduleInfo{module}, cycle...)
+						break
 					}
 				}
-				for _, depPauseSpec := range pauseMap[module] {
-					cycle := check(depPauseSpec.paused, end)
+				for _, pauseSpec := range pauseMap[module] {
+					cycle = check(pauseSpec.paused)
 					if cycle != nil {
-						return append([]*moduleInfo{module}, cycle...)
+						break
+					}
+				}
+
+				if cycle != nil {
+					if cycle[0] == module {
+						// We are the "start" of the cycle, so we're responsible
+						// for generating the errors.
+						slices.Reverse(cycle)
+						errs = append(errs, cycleError(cycle)...)
+
+						// We can continue processing this module's children to
+						// find more cycles.  Since all the modules that were
+						// part of the found cycle were marked as visited we
+						// won't run into that cycle again.
+					} else {
+						// We're not the "start" of the cycle, so we just append
+						// our module to the list and return it.
+						return append(cycle, module)
 					}
 				}
 
-				checked[module] = struct{}{}
 				return nil
 			}
 
-			// Iterate over the modules list instead of pauseMap to provide deterministic ordering.
 			for module := range moduleIter {
-				for _, pauseSpec := range pauseMap[module] {
-					cycle := check(pauseSpec.paused, pauseSpec.until)
-					if len(cycle) > 0 {
-						return cycleError(cycle)
-					}
-				}
+				check(module)
 			}
-		}
 
-		// Invariant check: if there was no deadlock and no cancellation every module
-		// should have been visited.
-		if visited != toVisit {
-			panic(fmt.Errorf("parallelVisit ran %d visitors, expected %d", visited, toVisit))
+			if len(errs) > 0 {
+				return errs
+			}
 		}
 
-		// Invariant check: if there was no deadlock and no cancellation  every module
+		// Invariant check: if there was no dependency cycle and no cancellation every module
 		// should have been visited, so there is nothing left to be paused on.
 		if len(pauseMap) > 0 {
 			panic(fmt.Errorf("parallelVisit finished with %d paused visitors", len(pauseMap)))
 		}
+
+		// Invariant check: if there was no dependency cycle and no cancellation every module
+		// should have been visited.
+		if visited != toVisit {
+			panic(fmt.Errorf("parallelVisit ran %d visitors, expected %d", visited, toVisit))
+		}
 	}
 
 	return nil
@@ -2524,20 +2804,14 @@ func cycleError(cycle []*moduleInfo) (errs []error) {
 // as well as after any mutator pass has called addDependency
 func (c *Context) updateDependencies() (errs []error) {
 	c.cachedDepsModified = true
-	visited := make(map[*moduleInfo]bool, len(c.moduleInfo)) // modules that were already checked
-	checking := make(map[*moduleInfo]bool)                   // modules actively being checked
-
-	var check func(group *moduleInfo) []*moduleInfo
-
-	check = func(module *moduleInfo) []*moduleInfo {
-		visited[module] = true
-		checking[module] = true
-		defer delete(checking, module)
 
+	for module := range c.iterateAllVariants() {
 		// Reset the forward and reverse deps without reducing their capacity to avoid reallocation.
 		module.reverseDeps = module.reverseDeps[:0]
 		module.forwardDeps = module.forwardDeps[:0]
+	}
 
+	for module := range c.iterateAllVariants() {
 		// Add an implicit dependency ordering on all earlier modules in the same module group
 		selfIndex := slices.Index(module.group.modules, module)
 		module.forwardDeps = slices.Grow(module.forwardDeps, selfIndex+len(module.directDeps))
@@ -2548,165 +2822,13 @@ func (c *Context) updateDependencies() (errs []error) {
 		}
 
 		for _, dep := range module.forwardDeps {
-			if checking[dep] {
-				// This is a cycle.
-				return []*moduleInfo{dep, module}
-			}
-
-			if !visited[dep] {
-				cycle := check(dep)
-				if cycle != nil {
-					if cycle[0] == module {
-						// We are the "start" of the cycle, so we're responsible
-						// for generating the errors.
-						errs = append(errs, cycleError(cycle)...)
-
-						// We can continue processing this module's children to
-						// find more cycles.  Since all the modules that were
-						// part of the found cycle were marked as visited we
-						// won't run into that cycle again.
-					} else {
-						// We're not the "start" of the cycle, so we just append
-						// our module to the list and return it.
-						return append(cycle, module)
-					}
-				}
-			}
-
 			dep.reverseDeps = append(dep.reverseDeps, module)
 		}
-
-		return nil
-	}
-
-	for _, module := range c.moduleInfo {
-		if !visited[module] {
-			cycle := check(module)
-			if cycle != nil {
-				if cycle[len(cycle)-1] != module {
-					panic("inconceivable!")
-				}
-				errs = append(errs, cycleError(cycle)...)
-			}
-		}
 	}
 
 	return
 }
 
-type jsonVariations []Variation
-
-type jsonModuleName struct {
-	Name    string
-	Variant string
-}
-
-type jsonDep struct {
-	jsonModuleName
-	Tag string
-}
-
-type JsonModule struct {
-	jsonModuleName
-	Deps      []jsonDep
-	Type      string
-	Blueprint string
-	CreatedBy *string
-	Module    map[string]interface{}
-}
-
-func jsonModuleNameFromModuleInfo(m *moduleInfo) *jsonModuleName {
-	return &jsonModuleName{
-		Name:    m.Name(),
-		Variant: m.variant.name,
-	}
-}
-
-type JSONDataSupplier interface {
-	AddJSONData(d *map[string]interface{})
-}
-
-// JSONAction contains the action-related info we expose to json module graph
-type JSONAction struct {
-	Inputs  []string
-	Outputs []string
-	Desc    string
-}
-
-// JSONActionSupplier allows JSON representation of additional actions that are not registered in
-// Ninja
-type JSONActionSupplier interface {
-	JSONActions() []JSONAction
-}
-
-func jsonModuleFromModuleInfo(m *moduleInfo) *JsonModule {
-	result := &JsonModule{
-		jsonModuleName: *jsonModuleNameFromModuleInfo(m),
-		Deps:           make([]jsonDep, 0),
-		Type:           m.typeName,
-		Blueprint:      m.relBlueprintsFile,
-		Module:         make(map[string]interface{}),
-	}
-	if m.createdBy != nil {
-		n := m.createdBy.Name()
-		result.CreatedBy = &n
-	}
-	if j, ok := m.logicModule.(JSONDataSupplier); ok {
-		j.AddJSONData(&result.Module)
-	}
-	for _, p := range m.providers {
-		if j, ok := p.(JSONDataSupplier); ok {
-			j.AddJSONData(&result.Module)
-		}
-	}
-	return result
-}
-
-func jsonModuleWithActionsFromModuleInfo(m *moduleInfo, nameTracker *nameTracker) *JsonModule {
-	result := &JsonModule{
-		jsonModuleName: jsonModuleName{
-			Name:    m.Name(),
-			Variant: m.variant.name,
-		},
-		Deps:      make([]jsonDep, 0),
-		Type:      m.typeName,
-		Blueprint: m.relBlueprintsFile,
-		Module:    make(map[string]interface{}),
-	}
-	var actions []JSONAction
-	for _, bDef := range m.actionDefs.buildDefs {
-		a := JSONAction{
-			Inputs: append(append(append(
-				bDef.InputStrings,
-				bDef.ImplicitStrings...),
-				getNinjaStrings(bDef.Inputs, nameTracker)...),
-				getNinjaStrings(bDef.Implicits, nameTracker)...),
-
-			Outputs: append(append(append(
-				bDef.OutputStrings,
-				bDef.ImplicitOutputStrings...),
-				getNinjaStrings(bDef.Outputs, nameTracker)...),
-				getNinjaStrings(bDef.ImplicitOutputs, nameTracker)...),
-		}
-		if d, ok := bDef.Variables["description"]; ok {
-			a.Desc = d.Value(nameTracker)
-		}
-		actions = append(actions, a)
-	}
-
-	if j, ok := m.logicModule.(JSONActionSupplier); ok {
-		actions = append(actions, j.JSONActions()...)
-	}
-	for _, p := range m.providers {
-		if j, ok := p.(JSONActionSupplier); ok {
-			actions = append(actions, j.JSONActions()...)
-		}
-	}
-
-	result.Module["Actions"] = actions
-	return result
-}
-
 // Gets a list of strings from the given list of ninjaStrings by invoking ninjaString.Value on each.
 func getNinjaStrings(nStrs []*ninjaString, nameTracker *nameTracker) []string {
 	var strs []string
@@ -2716,58 +2838,42 @@ func getNinjaStrings(nStrs []*ninjaString, nameTracker *nameTracker) []string {
 	return strs
 }
 
-func (c *Context) GetWeightedOutputsFromPredicate(predicate func(*JsonModule) (bool, int)) map[string]int {
+type WeightedOutputsModuleInfo struct {
+	Type      string
+	DepsCount int
+	SrcsCount int
+	Outputs   []string
+}
+
+func (c *Context) GetWeightedOutputsFromPredicate(predicate func(*WeightedOutputsModuleInfo) (bool, int)) map[string]int {
 	outputToWeight := make(map[string]int)
 	for m := range c.iterateAllVariants() {
-		jmWithActions := jsonModuleWithActionsFromModuleInfo(m, c.nameTracker)
-		if ok, weight := predicate(jmWithActions); ok {
-			for _, a := range jmWithActions.Module["Actions"].([]JSONAction) {
-				for _, o := range a.Outputs {
-					if val, ok := outputToWeight[o]; ok {
-						if val > weight {
-							continue
-						}
+		info := WeightedOutputsModuleInfo{
+			Type:      m.typeName,
+			DepsCount: len(m.directDeps),
+			SrcsCount: 0,
+		}
+		for _, bDef := range m.actionDefs.buildDefs {
+			info.SrcsCount += len(bDef.InputStrings) + len(bDef.Inputs) + len(bDef.ImplicitStrings) + len(bDef.Implicits)
+			info.Outputs = append(info.Outputs, bDef.OutputStrings...)
+			info.Outputs = append(info.Outputs, bDef.ImplicitOutputStrings...)
+			info.Outputs = append(info.Outputs, getNinjaStrings(bDef.Outputs, c.nameTracker)...)
+			info.Outputs = append(info.Outputs, getNinjaStrings(bDef.ImplicitOutputs, c.nameTracker)...)
+		}
+		if ok, weight := predicate(&info); ok {
+			for _, o := range info.Outputs {
+				if val, ok := outputToWeight[o]; ok {
+					if val > weight {
+						continue
 					}
-					outputToWeight[o] = weight
 				}
+				outputToWeight[o] = weight
 			}
 		}
 	}
 	return outputToWeight
 }
 
-// PrintJSONGraph prints info of modules in a JSON file.
-func (c *Context) PrintJSONGraphAndActions(wGraph io.Writer, wActions io.Writer) {
-	modulesToGraph := make([]*JsonModule, 0)
-	modulesToActions := make([]*JsonModule, 0)
-	for m := range c.iterateAllVariants() {
-		jm := jsonModuleFromModuleInfo(m)
-		jmWithActions := jsonModuleWithActionsFromModuleInfo(m, c.nameTracker)
-		for _, d := range m.directDeps {
-			jm.Deps = append(jm.Deps, jsonDep{
-				jsonModuleName: *jsonModuleNameFromModuleInfo(d.module),
-				Tag:            fmt.Sprintf("%T %+v", d.tag, d.tag),
-			})
-			jmWithActions.Deps = append(jmWithActions.Deps, jsonDep{
-				jsonModuleName: jsonModuleName{
-					Name: d.module.Name(),
-				},
-			})
-
-		}
-		modulesToGraph = append(modulesToGraph, jm)
-		modulesToActions = append(modulesToActions, jmWithActions)
-	}
-	writeJson(wGraph, modulesToGraph)
-	writeJson(wActions, modulesToActions)
-}
-
-func writeJson(w io.Writer, modules []*JsonModule) {
-	e := json.NewEncoder(w)
-	e.SetIndent("", "\t")
-	e.Encode(modules)
-}
-
 // PrepareBuildActions generates an internal representation of all the build
 // actions that need to be performed.  This process involves invoking the
 // GenerateBuildActions method on each of the Module objects created during the
@@ -2979,8 +3085,6 @@ var mutatorContextPool = pool.New[mutatorContext]()
 func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 	direction mutatorDirection) (deps []string, errs []error) {
 
-	newModuleInfo := maps.Clone(c.moduleInfo)
-
 	type globalStateChange struct {
 		reverse    []reverseDep
 		rename     []rename
@@ -2989,11 +3093,6 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 		deps       []string
 	}
 
-	type newVariationPair struct {
-		newVariations   moduleList
-		origLogicModule Module
-	}
-
 	reverseDeps := make(map[*moduleInfo][]depInfo)
 	var rename []rename
 	var replace []replace
@@ -3001,12 +3100,11 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 
 	errsCh := make(chan []error)
 	globalStateCh := make(chan globalStateChange)
-	newVariationsCh := make(chan newVariationPair)
 	done := make(chan bool)
 
 	c.needsUpdateDependencies = 0
 
-	visit := func(module *moduleInfo, pause chan<- pauseSpec) bool {
+	visit := func(module *moduleInfo, pause pauseFunc) bool {
 		if module.splitModules != nil {
 			panic("split module found in sorted module list")
 		}
@@ -3018,12 +3116,10 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 				config:  config,
 				module:  module,
 			},
-			mutator: mutatorGroup[0],
-			pauseCh: pause,
+			mutator:   mutatorGroup[0],
+			pauseFunc: pause,
 		}
 
-		origLogicModule := module.logicModule
-
 		module.startedMutator = mutatorGroup[0].index
 
 		func() {
@@ -3048,10 +3144,6 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 			errsCh <- mctx.errs
 			hasErrors = true
 		} else {
-			if len(mctx.newVariations) > 0 {
-				newVariationsCh <- newVariationPair{mctx.newVariations, origLogicModule}
-			}
-
 			if len(mctx.reverseDeps) > 0 || len(mctx.replace) > 0 || len(mctx.rename) > 0 || len(mctx.newModules) > 0 || len(mctx.ninjaFileDeps) > 0 {
 				globalStateCh <- globalStateChange{
 					reverse:    mctx.reverseDeps,
@@ -3068,8 +3160,6 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 		return hasErrors
 	}
 
-	var obsoleteLogicModules []Module
-
 	// Process errs and reverseDeps in a single goroutine
 	go func() {
 		for {
@@ -3084,13 +3174,6 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 				rename = append(rename, globalStateChange.rename...)
 				newModules = append(newModules, globalStateChange.newModules...)
 				deps = append(deps, globalStateChange.deps...)
-			case newVariations := <-newVariationsCh:
-				if newVariations.origLogicModule != newVariations.newVariations[0].logicModule {
-					obsoleteLogicModules = append(obsoleteLogicModules, newVariations.origLogicModule)
-				}
-				for _, module := range newVariations.newVariations {
-					newModuleInfo[module.logicModule] = module
-				}
 			case <-done:
 				return
 			}
@@ -3113,63 +3196,54 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 		return nil, errs
 	}
 
-	for _, obsoleteLogicModule := range obsoleteLogicModules {
-		delete(newModuleInfo, obsoleteLogicModule)
-	}
-
-	c.moduleInfo = newModuleInfo
-
 	transitionMutator := mutatorGroup[0].transitionMutator
 
-	var transitionMutatorInputVariants map[*moduleGroup][]*moduleInfo
 	if transitionMutator != nil {
-		transitionMutatorInputVariants = make(map[*moduleGroup][]*moduleInfo)
-	}
-
-	for _, group := range c.moduleGroups {
-		for i := 0; i < len(group.modules); i++ {
-			module := group.modules[i]
+		for _, group := range c.moduleGroups {
+			for i := 0; i < len(group.modules); i++ {
+				module := group.modules[i]
 
-			// Update module group to contain newly split variants
-			if module.splitModules != nil {
-				if transitionMutator != nil {
-					// For transition mutators, save the pre-split variant for reusing later in applyTransitions.
-					transitionMutatorInputVariants[group] = append(transitionMutatorInputVariants[group], module)
+				// Update module group to contain newly split variants
+				if module.splitModules != nil {
+					group.modules, i = spliceModules(group.modules, i, module.splitModules)
 				}
-				group.modules, i = spliceModules(group.modules, i, module.splitModules)
-			}
 
-			// Fix up any remaining dependencies on modules that were split into variants
-			// by replacing them with the first variant
-			for j, dep := range module.directDeps {
-				if dep.module.obsoletedByNewVariants {
-					module.directDeps[j].module = dep.module.splitModules.firstModule()
+				// Fix up any remaining dependencies on modules that were split into variants
+				// by replacing them with the first variant
+				for j, dep := range module.directDeps {
+					if dep.module.obsoletedByNewVariants {
+						module.directDeps[j].module = dep.module.splitModules.firstModule()
+					}
 				}
-			}
-
-			if module.createdBy != nil && module.createdBy.obsoletedByNewVariants {
-				module.createdBy = module.createdBy.splitModules.firstModule()
-			}
 
-			// Add any new forward dependencies to the reverse dependencies of the dependency to avoid
-			// having to call a full c.updateDependencies().
-			for _, m := range module.newDirectDeps {
-				m.reverseDeps = append(m.reverseDeps, module)
+				if module.createdBy != nil && module.createdBy.obsoletedByNewVariants {
+					module.createdBy = module.createdBy.splitModules.firstModule()
+				}
 			}
-			module.newDirectDeps = nil
 		}
-	}
 
-	if transitionMutator != nil {
-		transitionMutator.inputVariants = transitionMutatorInputVariants
 		c.completedTransitionMutators = transitionMutator.index + 1
+	} else {
+		for _, group := range c.moduleGroups {
+			for _, module := range group.modules {
+				// Add any new forward dependencies to the reverse dependencies of the dependency to avoid
+				// having to call a full c.updateDependencies().
+				for _, m := range module.newDirectDeps {
+					m.reverseDeps = append(m.reverseDeps, module)
+				}
+				module.newDirectDeps = nil
+			}
+		}
 	}
 
 	// Add in any new reverse dependencies that were added by the mutator
 	for module, deps := range reverseDeps {
 		sort.Sort(depSorter(deps))
 		module.directDeps = append(module.directDeps, deps...)
-		c.needsUpdateDependencies++
+		for _, dep := range deps {
+			module.forwardDeps = append(module.forwardDeps, dep.module)
+			dep.module.reverseDeps = append(dep.module.reverseDeps, module)
+		}
 	}
 
 	for _, module := range newModules {
@@ -3177,7 +3251,6 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 		if len(errs) > 0 {
 			return nil, errs
 		}
-		c.needsUpdateDependencies++
 	}
 
 	errs = c.handleRenames(rename)
@@ -3200,47 +3273,18 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 	return deps, errs
 }
 
-// clearTransitionMutatorInputVariants removes the inputVariants field from every
-// TransitionMutator now that all dependencies have been resolved.
-func (c *Context) clearTransitionMutatorInputVariants() {
-	for _, mutator := range c.transitionMutators {
-		mutator.inputVariants = nil
-	}
-}
-
 // Replaces every build logic module with a clone of itself.  Prevents introducing problems where
 // a mutator sets a non-property member variable on a module, which works until a later mutator
 // creates variants of that module.
 func (c *Context) cloneModules() {
-	type update struct {
-		orig  Module
-		clone *moduleInfo
-	}
-	ch := make(chan update)
-	doneCh := make(chan bool)
-	go func() {
-		errs := parallelVisit(c.iterateAllVariants(), unorderedVisitorImpl{}, parallelVisitLimit,
-			func(m *moduleInfo, pause chan<- pauseSpec) bool {
-				origLogicModule := m.logicModule
-				m.logicModule, m.properties = c.cloneLogicModule(m)
-				ch <- update{origLogicModule, m}
-				return false
-			})
-		if len(errs) > 0 {
-			panic(errs)
-		}
-		doneCh <- true
-	}()
-
-	done := false
-	for !done {
-		select {
-		case <-doneCh:
-			done = true
-		case update := <-ch:
-			delete(c.moduleInfo, update.orig)
-			c.moduleInfo[update.clone.logicModule] = update.clone
-		}
+	errs := parallelVisit(c.iterateAllVariants(), unorderedVisitorImpl{}, parallelVisitLimit,
+		func(m *moduleInfo, pause pauseFunc) bool {
+			m.logicModule, m.properties = c.cloneLogicModule(m)
+			m.logicModule.setInfo(m)
+			return false
+		})
+	if len(errs) > 0 {
+		panic(errs)
 	}
 }
 
@@ -3295,7 +3339,7 @@ func (c *Context) generateModuleBuildActions(config interface{},
 	}()
 
 	visitErrs := parallelVisit(c.iterateAllVariants(), bottomUpVisitor, parallelVisitLimit,
-		func(module *moduleInfo, pause chan<- pauseSpec) bool {
+		func(module *moduleInfo, pause pauseFunc) bool {
 			uniqueName := c.nameInterface.UniqueName(newNamespaceContext(module), module.group.name)
 			sanitizedName := toNinjaName(uniqueName)
 			sanitizedVariant := toNinjaName(module.variant.name)
@@ -3317,6 +3361,16 @@ func (c *Context) generateModuleBuildActions(config interface{},
 				handledMissingDeps: module.missingDeps == nil,
 			}
 
+			// Use a deferred call for this, to avoid errors from trying to evaluate the select()
+			// expressions in the configurable values that mctx.evaluator encounters too early.
+			defer func() {
+				if c.moduleDebugDataChannel != nil {
+					c.moduleDebugDataChannel <- getModuleDebugJson(mctx.evaluator, module)
+				}
+				// The evaluator isn't needed anymore. Avoid possibly cyclic ref that may increase gc load.
+				mctx.evaluator = nil
+			}()
+
 			mctx.module.startedGenerateBuildActions = true
 
 			func() {
@@ -3354,6 +3408,17 @@ func (c *Context) generateModuleBuildActions(config interface{},
 
 			depsCh <- mctx.ninjaFileDeps
 
+			if mctx.module.freeAfterGenerateBuildActions {
+				// This module is freed after GenerateBuildActions complete, requiring all future accesses
+				// to go through ModuleProxy instead of the Module.
+				// Cache Module.Name() and Module.String() for future use in ModuleProxy.Name() and ModuleProxy.String()
+				mctx.module.cachedName = mctx.module.logicModule.Name()
+				mctx.module.cachedString = mctx.module.logicModule.String()
+				mctx.module.logicModule = nil
+				mctx.module.properties = nil
+				mctx.module.propertyPos = nil
+			}
+
 			newErrs := c.processLocalBuildActions(&module.actionDefs,
 				&mctx.actionDefs, liveGlobals)
 			if len(newErrs) > 0 {
@@ -3371,6 +3436,33 @@ func (c *Context) generateModuleBuildActions(config interface{},
 	return deps, errs
 }
 
+func (c *Context) WriteIncrementalDebugInfo(filename string, modules []*moduleInfo) {
+	f, err := os.Create(filename)
+	if err != nil {
+		// We expect this to be writable
+		panic(fmt.Sprintf("couldn't create incremental module debug file %s: %s", filename, err))
+	}
+	defer f.Close()
+
+	needComma := false
+	f.WriteString("{\n\"modules\": [\n")
+
+	for _, module := range modules {
+		if module.incrementalDebugInfo == nil {
+			continue
+		}
+		if needComma {
+			f.WriteString(",\n")
+		} else {
+			needComma = true
+		}
+
+		f.Write(module.incrementalDebugInfo)
+	}
+
+	f.WriteString("\n]\n}")
+}
+
 func (c *Context) generateOneSingletonBuildActions(config interface{},
 	info *singletonInfo, liveGlobals *liveTracker) ([]string, []error) {
 
@@ -3697,71 +3789,15 @@ func (c *Context) sortedModuleGroups() []*moduleGroup {
 	return c.cachedSortedModuleGroups
 }
 
-func (c *Context) visitAllModules(visit func(Module)) {
-	var module *moduleInfo
-
-	defer func() {
-		if r := recover(); r != nil {
-			panic(newPanicErrorf(r, "VisitAllModules(%s) for %s",
-				funcName(visit), module))
-		}
-	}()
-
-	for _, moduleGroup := range c.sortedModuleGroups() {
-		for _, module := range moduleGroup.modules {
-			visit(module.logicModule)
-		}
-	}
-}
-
-func (c *Context) visitAllModulesIf(pred func(Module) bool,
-	visit func(Module)) {
-
-	var module *moduleInfo
-
-	defer func() {
-		if r := recover(); r != nil {
-			panic(newPanicErrorf(r, "VisitAllModulesIf(%s, %s) for %s",
-				funcName(pred), funcName(visit), module))
-		}
-	}()
-
-	for _, moduleGroup := range c.sortedModuleGroups() {
-		for _, module := range moduleGroup.modules {
-			if pred(module.logicModule) {
-				visit(module.logicModule)
-			}
-		}
-	}
-}
-
 func (c *Context) visitAllModuleVariants(module *moduleInfo,
-	visit func(Module)) {
-
-	var variant *moduleInfo
-
-	defer func() {
-		if r := recover(); r != nil {
-			panic(newPanicErrorf(r, "VisitAllModuleVariants(%s, %s) for %s",
-				module, funcName(visit), variant))
-		}
-	}()
+	visit func(*moduleInfo)) {
 
 	for _, module := range module.group.modules {
-		visit(module.logicModule)
+		visit(module)
 	}
 }
 
 func (c *Context) visitAllModuleInfos(visit func(*moduleInfo)) {
-	var module *moduleInfo
-
-	defer func() {
-		if r := recover(); r != nil {
-			panic(newPanicErrorf(r, "VisitAllModules(%s) for %s",
-				funcName(visit), module))
-		}
-	}()
-
 	for _, moduleGroup := range c.sortedModuleGroups() {
 		for _, module := range moduleGroup.modules {
 			visit(module)
@@ -3956,37 +3992,32 @@ func (c *Context) ModuleTypeFactories() map[string]ModuleFactory {
 	return maps.Clone(c.moduleFactories)
 }
 
-func (c *Context) ModuleName(logicModule Module) string {
-	module := c.moduleInfo[logicModule]
-	return module.Name()
+func (c *Context) ModuleName(logicModule ModuleOrProxy) string {
+	return logicModule.info().Name()
 }
 
-func (c *Context) ModuleDir(logicModule Module) string {
+func (c *Context) ModuleDir(logicModule ModuleOrProxy) string {
 	return filepath.Dir(c.BlueprintFile(logicModule))
 }
 
-func (c *Context) ModuleSubDir(logicModule Module) string {
-	module := c.moduleInfo[logicModule]
-	return module.variant.name
+func (c *Context) ModuleSubDir(logicModule ModuleOrProxy) string {
+	return logicModule.info().variant.name
 }
 
-func (c *Context) ModuleType(logicModule Module) string {
-	module := c.moduleInfo[logicModule]
-	return module.typeName
+func (c *Context) ModuleType(logicModule ModuleOrProxy) string {
+	return logicModule.info().typeName
 }
 
 // ModuleProvider returns the value, if any, for the provider for a module.  If the value for the
 // provider was not set it returns nil and false.  The return value should always be considered read-only.
 // It panics if called before the appropriate mutator or GenerateBuildActions pass for the provider on the
 // module.  The value returned may be a deep copy of the value originally passed to SetProvider.
-func (c *Context) ModuleProvider(logicModule Module, provider AnyProviderKey) (any, bool) {
-	module := c.moduleInfo[logicModule]
-	return c.provider(module, provider.provider())
+func (c *Context) ModuleProvider(logicModule ModuleOrProxy, provider AnyProviderKey) (any, bool) {
+	return c.provider(logicModule.info(), provider.provider())
 }
 
-func (c *Context) BlueprintFile(logicModule Module) string {
-	module := c.moduleInfo[logicModule]
-	return module.relBlueprintsFile
+func (c *Context) BlueprintFile(logicModule ModuleOrProxy) string {
+	return logicModule.info().relBlueprintsFile
 }
 
 func (c *Context) moduleErrorf(module *moduleInfo, format string,
@@ -4007,15 +4038,15 @@ func (c *Context) moduleErrorf(module *moduleInfo, format string,
 	}
 }
 
-func (c *Context) ModuleErrorf(logicModule Module, format string,
+func (c *Context) ModuleErrorf(logicModule ModuleOrProxy, format string,
 	args ...interface{}) error {
-	return c.moduleErrorf(c.moduleInfo[logicModule], format, args...)
+	return c.moduleErrorf(logicModule.info(), format, args...)
 }
 
-func (c *Context) PropertyErrorf(logicModule Module, property string, format string,
+func (c *Context) PropertyErrorf(logicModule ModuleOrProxy, property string, format string,
 	args ...interface{}) error {
 
-	module := c.moduleInfo[logicModule]
+	module := logicModule.info()
 	if module == nil {
 		// This can happen if PropertyErrorf is called from a load hook
 		return &BlueprintError{
@@ -4041,13 +4072,76 @@ func (c *Context) PropertyErrorf(logicModule Module, property string, format str
 }
 
 func (c *Context) VisitAllModules(visit func(Module)) {
-	c.visitAllModules(visit)
+	var visitingModule *moduleInfo
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitAllModules(%s) for %s",
+				funcName(visit), visitingModule))
+		}
+	}()
+
+	c.visitAllModuleInfos(func(module *moduleInfo) {
+		visitingModule = module
+		if module.logicModule == nil {
+			panic(fmt.Errorf("VisitAllModules visited module %s that called FreeAfterGenerateBuildActions()", module))
+		}
+		visit(module.logicModule)
+	})
 }
 
-func (c *Context) VisitAllModulesIf(pred func(Module) bool,
-	visit func(Module)) {
+func (c *Context) VisitAllModulesIf(pred func(Module) bool, visit func(Module)) {
+	var visitingModule *moduleInfo
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitAllModulesIf(%s, %s) for %s",
+				funcName(pred), funcName(visit), visitingModule))
+		}
+	}()
+
+	c.visitAllModuleInfos(func(module *moduleInfo) {
+		visitingModule = module
+		if module.logicModule == nil {
+			panic(fmt.Errorf("VisitAllModulesIf visited module %s that called FreeAfterGenerateBuildActions()", module))
+		}
+		if pred(module.logicModule) {
+			visit(module.logicModule)
+		}
+	})
+}
+
+func (c *Context) VisitAllModulesProxies(visit func(ModuleProxy)) {
+	var visitingModule *moduleInfo
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitAllModules(%s) for %s",
+				funcName(visit), visitingModule))
+		}
+	}()
+
+	c.visitAllModuleInfos(func(module *moduleInfo) {
+		visitingModule = module
+		visit(ModuleProxy{module})
+	})
+}
+
+func (c *Context) VisitAllModulesOrProxies(visit func(ModuleOrProxy)) {
+	var visitingModule *moduleInfo
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitAllModules(%s) for %s",
+				funcName(visit), visitingModule))
+		}
+	}()
+
+	c.visitAllModuleInfos(func(module *moduleInfo) {
+		visitingModule = module
+		if module.logicModule != nil {
+			visit(module.logicModule)
+		} else {
+			visit(ModuleProxy{module})
+		}
+	})
 
-	c.visitAllModulesIf(pred, visit)
 }
 
 func (c *Context) VisitDirectDeps(module Module, visit func(Module)) {
@@ -4056,8 +4150,26 @@ func (c *Context) VisitDirectDeps(module Module, visit func(Module)) {
 	})
 }
 
+func (c *Context) VisitDirectDepsProxies(module ModuleOrProxy, visit func(ModuleProxy)) {
+	topModule := module.info()
+
+	var visiting *moduleInfo
+
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitDirectDepsProxies(%s, %s) for dependency %s",
+				topModule, funcName(visit), visiting))
+		}
+	}()
+
+	for _, dep := range topModule.directDeps {
+		visiting = dep.module
+		visit(ModuleProxy{dep.module})
+	}
+}
+
 func (c *Context) VisitDirectDepsWithTags(module Module, visit func(Module, DependencyTag)) {
-	topModule := c.moduleInfo[module]
+	topModule := module.info()
 
 	var visiting *moduleInfo
 
@@ -4070,12 +4182,15 @@ func (c *Context) VisitDirectDepsWithTags(module Module, visit func(Module, Depe
 
 	for _, dep := range topModule.directDeps {
 		visiting = dep.module
+		if dep.module.logicModule == nil {
+			panic(fmt.Errorf("VisitDirectDepsWithTags visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+		}
 		visit(dep.module.logicModule, dep.tag)
 	}
 }
 
 func (c *Context) VisitDirectDepsIf(module Module, pred func(Module) bool, visit func(Module)) {
-	topModule := c.moduleInfo[module]
+	topModule := module.info()
 
 	var visiting *moduleInfo
 
@@ -4088,6 +4203,9 @@ func (c *Context) VisitDirectDepsIf(module Module, pred func(Module) bool, visit
 
 	for _, dep := range topModule.directDeps {
 		visiting = dep.module
+		if dep.module.logicModule == nil {
+			panic(fmt.Errorf("VisitDirectDepsIf visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+		}
 		if pred(dep.module.logicModule) {
 			visit(dep.module.logicModule)
 		}
@@ -4095,7 +4213,7 @@ func (c *Context) VisitDirectDepsIf(module Module, pred func(Module) bool, visit
 }
 
 func (c *Context) VisitDepsDepthFirst(module Module, visit func(Module)) {
-	topModule := c.moduleInfo[module]
+	topModule := module.info()
 
 	var visiting *moduleInfo
 
@@ -4108,12 +4226,15 @@ func (c *Context) VisitDepsDepthFirst(module Module, visit func(Module)) {
 
 	c.walkDeps(topModule, false, nil, func(dep depInfo, parent *moduleInfo) {
 		visiting = dep.module
+		if dep.module.logicModule == nil {
+			panic(fmt.Errorf("VisitDepsDepthFirst visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+		}
 		visit(dep.module.logicModule)
 	})
 }
 
 func (c *Context) VisitDepsDepthFirstIf(module Module, pred func(Module) bool, visit func(Module)) {
-	topModule := c.moduleInfo[module]
+	topModule := module.info()
 
 	var visiting *moduleInfo
 
@@ -4125,6 +4246,9 @@ func (c *Context) VisitDepsDepthFirstIf(module Module, pred func(Module) bool, v
 	}()
 
 	c.walkDeps(topModule, false, nil, func(dep depInfo, parent *moduleInfo) {
+		if dep.module.logicModule == nil {
+			panic(fmt.Errorf("VisitDepsDepthFirstIf visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+		}
 		if pred(dep.module.logicModule) {
 			visiting = dep.module
 			visit(dep.module.logicModule)
@@ -4133,17 +4257,57 @@ func (c *Context) VisitDepsDepthFirstIf(module Module, pred func(Module) bool, v
 }
 
 func (c *Context) PrimaryModule(module Module) Module {
-	return c.moduleInfo[module].group.modules.firstModule().logicModule
+	return c.primaryModule(module.info()).logicModule
+}
+
+func (c *Context) primaryModule(moduleInfo *moduleInfo) *moduleInfo {
+	return moduleInfo.group.modules.firstModule()
+}
+
+func (c *Context) IsPrimaryModule(module ModuleOrProxy) bool {
+	return module.info().group.modules.firstModule() == module.info()
 }
 
-func (c *Context) IsFinalModule(module Module) bool {
-	return c.moduleInfo[module].group.modules.lastModule().logicModule == module
+func (c *Context) IsFinalModule(module ModuleOrProxy) bool {
+	return module.info().group.modules.lastModule() == module.info()
+}
+
+func (c *Context) VisitAllModuleVariants(module ModuleOrProxy, visit func(Module)) {
+	var visitingModule *moduleInfo
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitAllModuleVariants(%s) for %s",
+				funcName(visit), visitingModule))
+		}
+	}()
+
+	c.visitAllModuleVariants(module.info(), func(module *moduleInfo) {
+		visitingModule = module
+		if module.logicModule == nil {
+			panic(fmt.Errorf("VisitAllModuleVariants visited module %s that called FreeAfterGenerateBuildActions()", module))
+		}
+
+		visit(module.logicModule)
+	})
 }
 
-func (c *Context) VisitAllModuleVariants(module Module,
-	visit func(Module)) {
+func (c *Context) VisitAllModuleVariantProxies(module ModuleProxy, visit func(ModuleProxy)) {
+	var visitingModule *moduleInfo
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitAllModuleVariantProxies(%s) for %s",
+				funcName(visit), visitingModule))
+		}
+	}()
 
-	c.visitAllModuleVariants(c.moduleInfo[module], visit)
+	c.visitAllModuleVariants(module.info(), func(module *moduleInfo) {
+		visitingModule = module
+		visit(ModuleProxy{module})
+	})
+}
+
+func (c *Context) ModuleToProxy(module ModuleOrProxy) ModuleProxy {
+	return ModuleProxy{module.info()}
 }
 
 // Singletons returns a list of all registered Singletons.
@@ -4554,7 +4718,7 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 	var modules []*moduleInfo
 	var incModules []*moduleInfo
 
-	for _, module := range c.moduleInfo {
+	for module := range c.iterateAllVariants() {
 		if module.buildActionCacheKey != nil {
 			incModules = append(incModules, module)
 			continue
@@ -4640,6 +4804,10 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 			close(errorCh)
 		}()
 
+		if c.incrementalDebugFile != "" {
+			c.WriteIncrementalDebugInfo(c.incrementalDebugFile, incModules)
+		}
+
 		var errors []error
 		for newErrors := range errorCh {
 			errors = append(errors, newErrors)
@@ -4862,7 +5030,7 @@ func (c *Context) deduplicateOrderOnlyDeps(modules []*moduleInfo) *localBuildAct
 	})
 
 	parallelVisit(slices.Values(modules), unorderedVisitorImpl{}, parallelVisitLimit,
-		func(m *moduleInfo, pause chan<- pauseSpec) bool {
+		func(m *moduleInfo, pause pauseFunc) bool {
 			for _, def := range m.actionDefs.buildDefs {
 				if info, loaded := c.orderOnlyStrings.Load(def.OrderOnlyStrings); loaded {
 					if info.dedup {
@@ -4889,14 +5057,10 @@ func (c *Context) cacheModuleBuildActions(module *moduleInfo) {
 		}
 	}
 
-	// These show up in the ninja file, so we need to cache these to ensure we
-	// re-generate ninja file if they changed.
-	relPos := module.pos
-	relPos.Filename = module.relBlueprintsFile
 	data := BuildActionCachedData{
 		Providers:        providers,
-		Pos:              &relPos,
 		OrderOnlyStrings: module.orderOnlyStrings,
+		GlobCache:        module.globCache,
 	}
 
 	c.updateBuildActionsCache(module.buildActionCacheKey, &data)
@@ -5036,20 +5200,20 @@ type Debuggable interface {
 }
 
 // Convert a slice in a reflect.Value to a value suitable for outputting to json
-func debugSlice(value reflect.Value) interface{} {
+func debugSlice(evaluator proptools.ConfigurableEvaluator, value reflect.Value) interface{} {
 	size := value.Len()
 	if size == 0 {
 		return nil
 	}
 	result := make([]interface{}, size)
 	for i := 0; i < size; i++ {
-		result[i] = debugValue(value.Index(i))
+		result[i] = debugValue(evaluator, value.Index(i))
 	}
 	return result
 }
 
 // Convert a map in a reflect.Value to a value suitable for outputting to json
-func debugMap(value reflect.Value) interface{} {
+func debugMap(evaluator proptools.ConfigurableEvaluator, value reflect.Value) interface{} {
 	if value.IsNil() {
 		return nil
 	}
@@ -5059,7 +5223,7 @@ func debugMap(value reflect.Value) interface{} {
 		// In the (hopefully) rare case of a key collision (which will happen when multiple
 		// go-typed keys have the same string representation, we'll just overwrite the last
 		// value.
-		result[debugKey(iter.Key())] = debugValue(iter.Value())
+		result[debugKey(iter.Key())] = debugValue(evaluator, iter.Value())
 	}
 	return result
 }
@@ -5070,7 +5234,30 @@ func debugKey(value reflect.Value) string {
 }
 
 // Convert a single value (possibly a map or slice too) in a reflect.Value to a value suitable for outputting to json
-func debugValue(value reflect.Value) interface{} {
+func debugValue(evaluator proptools.ConfigurableEvaluator, value reflect.Value) interface{} {
+	if proptools.IsConfigurable(value.Type()) {
+		if evaluator == nil {
+			return "<configurable value>"
+		} else {
+			if value.Kind() == reflect.Interface {
+				value = value.Elem() // Get the underlying value in the interface.
+			}
+			if value.Kind() != reflect.Ptr {
+				value = value.Addr() // The method needs a pointer receiver.
+			}
+			// value is now *proptools.Configurable[<something>]
+			value = value.MethodByName("Get").Call([]reflect.Value{reflect.ValueOf(evaluator)})[0]
+			// value is now an unaddressable proptools.ConfigurableOptional[<something>]
+			ptrVal := reflect.New(value.Type())
+			ptrVal.Elem().Set(value)
+			// ptrVal is now *proptools.ConfigurableOptional[<something>]
+			if ptrVal.MethodByName("IsEmpty").Call(nil)[0].Bool() {
+				return nil
+			}
+			value = ptrVal.MethodByName("Get").Call(nil)[0]
+		}
+	}
+
 	// Remember if we originally received a reflect.Interface.
 	wasInterface := value.Kind() == reflect.Interface
 	// Dereference pointers down to the real type
@@ -5082,25 +5269,31 @@ func debugValue(value reflect.Value) interface{} {
 		value = value.Elem()
 	}
 
-	// Skip private fields, maybe other weird corner cases of go's bizarre type system.
-	if !value.CanInterface() {
-		return nil
-	}
-
 	switch kind := value.Kind(); kind {
-	case reflect.Bool, reflect.String, reflect.Int, reflect.Uint:
-		return value.Interface()
+	case reflect.Bool:
+		return value.Bool()
+	case reflect.String:
+		return value.String()
+	case reflect.Int:
+		return value.Int()
+	case reflect.Uint:
+		return value.Uint()
 	case reflect.Slice:
-		return debugSlice(value)
+		return debugSlice(evaluator, value)
 	case reflect.Struct:
+		// At least some of the private struct fields cause stack overflow here.  Do not include them until
+		// we track the recursion down.
+		if !value.CanInterface() {
+			return nil
+		}
 		// If we originally received an interface, and there is a String() method, call that.
 		// TODO: figure out why Path doesn't work correctly otherwise (in aconfigPropagatingDeclarationsInfo)
 		if s, ok := value.Interface().(interface{ String() string }); wasInterface && ok {
 			return s.String()
 		}
-		return debugStruct(value)
+		return debugStruct(evaluator, value)
 	case reflect.Map:
-		return debugMap(value)
+		return debugMap(evaluator, value)
 	default:
 		// TODO: add cases as we find them.
 		return fmt.Sprintf("debugValue(Kind=%v, wasInterface=%v)", kind, wasInterface)
@@ -5110,9 +5303,9 @@ func debugValue(value reflect.Value) interface{} {
 }
 
 // Convert an object in a reflect.Value to a value suitable for outputting to json
-func debugStruct(value reflect.Value) interface{} {
+func debugStruct(evaluator proptools.ConfigurableEvaluator, value reflect.Value) interface{} {
 	result := make(map[string]interface{})
-	debugStructAppend(value, &result)
+	debugStructAppend(evaluator, value, &result)
 	if len(result) == 0 {
 		return nil
 	}
@@ -5120,7 +5313,7 @@ func debugStruct(value reflect.Value) interface{} {
 }
 
 // Convert an object to a value suiable for outputting to json
-func debugStructAppend(value reflect.Value, result *map[string]interface{}) {
+func debugStructAppend(evaluator proptools.ConfigurableEvaluator, value reflect.Value, result *map[string]interface{}) {
 	for value.Kind() == reflect.Ptr {
 		if value.IsNil() {
 			return
@@ -5138,23 +5331,23 @@ func debugStructAppend(value reflect.Value, result *map[string]interface{}) {
 
 	structType := value.Type()
 	for i := 0; i < value.NumField(); i++ {
-		v := debugValue(value.Field(i))
+		v := debugValue(evaluator, value.Field(i))
 		if v != nil {
 			(*result)[structType.Field(i).Name] = v
 		}
 	}
 }
 
-func debugPropertyStruct(props interface{}, result *map[string]interface{}) {
+func debugPropertyStruct(evaluator proptools.ConfigurableEvaluator, props interface{}, result *map[string]interface{}) {
 	if props == nil {
 		return
 	}
-	debugStructAppend(reflect.ValueOf(props), result)
+	debugStructAppend(evaluator, reflect.ValueOf(props), result)
 }
 
 // Get the debug json for a single module. Returns thae data as
 // flattened json text for easy concatenation by GenerateModuleDebugInfo.
-func getModuleDebugJson(module *moduleInfo) []byte {
+func getModuleDebugJson(evaluator proptools.ConfigurableEvaluator, module *moduleInfo) []byte {
 	info := struct {
 		Name       string                 `json:"name"`
 		SourceFile string                 `json:"source_file"`
@@ -5166,7 +5359,7 @@ func getModuleDebugJson(module *moduleInfo) []byte {
 		Debug      string                 `json:"debug"` // from GetDebugString on the module
 		Properties map[string]interface{} `json:"properties"`
 	}{
-		Name:       module.logicModule.Name(),
+		Name:       module.Name(),
 		SourceFile: module.pos.Filename,
 		SourceLine: module.pos.Line,
 		Type:       module.typeName,
@@ -5175,13 +5368,13 @@ func getModuleDebugJson(module *moduleInfo) []byte {
 			result := make([]depJson, len(module.directDeps))
 			for i, dep := range module.directDeps {
 				result[i] = depJson{
-					Name:    dep.module.logicModule.Name(),
+					Name:    dep.module.Name(),
 					Variant: dep.module.variant.name,
 				}
 				t := reflect.TypeOf(dep.tag)
 				if t != nil {
 					result[i].TagType = t.PkgPath() + "." + t.Name()
-					result[i].TagData = debugStruct(reflect.ValueOf(dep.tag))
+					result[i].TagData = debugStruct(nil, reflect.ValueOf(dep.tag))
 				}
 			}
 			return result
@@ -5206,7 +5399,7 @@ func getModuleDebugJson(module *moduleInfo) []byte {
 				}
 
 				if p != nil {
-					pj.Fields = debugValue(reflect.ValueOf(p))
+					pj.Fields = debugValue(nil, reflect.ValueOf(p))
 					include = true
 				}
 
@@ -5226,7 +5419,7 @@ func getModuleDebugJson(module *moduleInfo) []byte {
 		Properties: func() map[string]interface{} {
 			result := make(map[string]interface{})
 			for _, props := range module.properties {
-				debugPropertyStruct(props, &result)
+				debugPropertyStruct(evaluator, props, &result)
 			}
 			return result
 		}(),
@@ -5235,8 +5428,10 @@ func getModuleDebugJson(module *moduleInfo) []byte {
 	return buf
 }
 
-// Generate out/soong/soong-debug-info.json Called if GENERATE_SOONG_DEBUG=true.
-func (this *Context) GenerateModuleDebugInfo(filename string) {
+// InitializeModuleDebugInfoCollection sets up a channel and a receiver to write
+// out/soong/soong-debug-info.json. Called if GENERATE_SOONG_DEBUG=true. Returns a function to be
+// deferred until all modules have been processed.
+func (this *Context) InitializeModuleDebugInfoCollection(filename string) func() {
 	err := os.MkdirAll(filepath.Dir(filename), 0777)
 	if err != nil {
 		// We expect this to be writable
@@ -5248,24 +5443,34 @@ func (this *Context) GenerateModuleDebugInfo(filename string) {
 		// We expect this to be writable
 		panic(fmt.Sprintf("couldn't create soong module debug file %s: %s", filename, err))
 	}
-	defer f.Close()
 
-	needComma := false
-	f.WriteString("{\n\"modules\": [\n")
+	this.moduleDebugDataChannel = make(chan []byte, 10)
+	var wg sync.WaitGroup
+	wg.Add(1)
 
-	// TODO: Optimize this (parallel execution, etc) if it gets slow.
-	this.visitAllModuleInfos(func(module *moduleInfo) {
-		if needComma {
-			f.WriteString(",\n")
-		} else {
-			needComma = true
+	go func() {
+		defer f.Close()
+		defer wg.Done()
+
+		needComma := false
+		f.WriteString("{\n\"modules\": [\n")
+
+		for moduleData := range this.moduleDebugDataChannel {
+			if needComma {
+				f.WriteString(",\n")
+			} else {
+				needComma = true
+			}
+			f.Write(moduleData)
 		}
 
-		moduleData := getModuleDebugJson(module)
-		f.Write(moduleData)
-	})
+		f.WriteString("\n]\n}")
+	}()
 
-	f.WriteString("\n]\n}")
+	return func() {
+		close(this.moduleDebugDataChannel)
+		wg.Wait()
+	}
 }
 
 var fileHeaderTemplate = `******************************************************************************
diff --git a/context_gob_enc.go b/context_gob_enc.go
new file mode 100644
index 0000000..89005a9
--- /dev/null
+++ b/context_gob_enc.go
@@ -0,0 +1,107 @@
+// Code generated by go run gob_gen.go; DO NOT EDIT.
+
+package blueprint
+
+import (
+	"bytes"
+	"github.com/google/blueprint/gobtools"
+)
+
+func init() {
+	globResultCacheGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(globResultCache) })
+	VariationGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(Variation) })
+}
+
+func (r globResultCache) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeString(buf, r.Pattern); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.Excludes))); err != nil {
+		return err
+	}
+	for val1 := 0; val1 < len(r.Excludes); val1++ {
+		if err = gobtools.EncodeString(buf, r.Excludes[val1]); err != nil {
+			return err
+		}
+	}
+
+	if err = gobtools.EncodeSimple(buf, r.Result); err != nil {
+		return err
+	}
+	return err
+}
+
+func (r *globResultCache) Decode(buf *bytes.Reader) error {
+	var err error
+
+	err = gobtools.DecodeString(buf, &r.Pattern)
+	if err != nil {
+		return err
+	}
+
+	var val3 int32
+	err = gobtools.DecodeSimple[int32](buf, &val3)
+	if err != nil {
+		return err
+	}
+	if val3 > 0 {
+		r.Excludes = make([]string, val3)
+		for val4 := 0; val4 < int(val3); val4++ {
+			err = gobtools.DecodeString(buf, &r.Excludes[val4])
+			if err != nil {
+				return err
+			}
+		}
+	}
+
+	err = gobtools.DecodeSimple[uint64](buf, &r.Result)
+	if err != nil {
+		return err
+	}
+
+	return err
+}
+
+var globResultCacheGobRegId int16
+
+func (r globResultCache) GetTypeId() int16 {
+	return globResultCacheGobRegId
+}
+
+func (r Variation) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeString(buf, r.Mutator); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeString(buf, r.Variation); err != nil {
+		return err
+	}
+	return err
+}
+
+func (r *Variation) Decode(buf *bytes.Reader) error {
+	var err error
+
+	err = gobtools.DecodeString(buf, &r.Mutator)
+	if err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeString(buf, &r.Variation)
+	if err != nil {
+		return err
+	}
+
+	return err
+}
+
+var VariationGobRegId int16
+
+func (r Variation) GetTypeId() int16 {
+	return VariationGobRegId
+}
diff --git a/context_test.go b/context_test.go
index 4ab672f..91cdc19 100644
--- a/context_test.go
+++ b/context_test.go
@@ -27,7 +27,6 @@ import (
 	"strings"
 	"sync"
 	"testing"
-	"text/scanner"
 	"time"
 
 	"github.com/google/blueprint/parser"
@@ -74,6 +73,7 @@ type IncrementalTestProvider struct {
 var IncrementalTestProviderKey = NewProvider[IncrementalTestProvider]()
 
 type baseTestModule struct {
+	ModuleBase
 	SimpleName
 	properties struct {
 		Deps             []string
@@ -82,6 +82,8 @@ type baseTestModule struct {
 		Order_only       []string
 		Extra_outputs    []string
 		Extra_order_only []string
+		Srcs             []string
+		Exclude_srcs     []string
 	}
 	GenerateBuildActionsCalled bool
 }
@@ -113,6 +115,9 @@ func (b *baseTestModule) GenerateBuildActions(ctx ModuleContext) {
 			OrderOnly: b.properties.Extra_order_only,
 		})
 	}
+	for _, src := range b.properties.Srcs {
+		ctx.GlobWithDeps(src, b.properties.Exclude_srcs)
+	}
 	SetProvider(ctx, IncrementalTestProviderKey, IncrementalTestProvider{
 		Value: ctx.ModuleName(),
 	})
@@ -650,11 +655,6 @@ func Test_findVariant(t *testing.T) {
 		},
 	}
 
-	type alias struct {
-		variant variant
-		target  int
-	}
-
 	makeDependencyGroup := func(in ...*moduleInfo) *moduleGroup {
 		group := &moduleGroup{
 			name: "dep",
@@ -745,7 +745,7 @@ func Test_findVariant(t *testing.T) {
 	for _, tt := range tests {
 		t.Run(tt.name, func(t *testing.T) {
 			ctx := NewContext()
-			got, _, errs := ctx.findVariant(module, nil, tt.possibleDeps, tt.variations, tt.far, tt.reverse)
+			got, _, errs := ctx.findVariant(nil, module, nil, tt.possibleDeps, tt.variations, tt.far, tt.reverse)
 			if errs != nil {
 				t.Fatal(errs)
 			}
@@ -785,14 +785,21 @@ func Test_parallelVisit(t *testing.T) {
 	moduleF := create("F")
 	moduleG := create("G")
 
+	moduleH := create("H")
+	moduleI := create("I")
+	moduleJ := create("J")
+
 	// A depends on B, B depends on C.  Nothing depends on D through G, and they don't depend on
-	// anything.
+	// anything. H depends on I, and I and J depend on each other.
 	addDep(moduleA, moduleB)
 	addDep(moduleB, moduleC)
+	addDep(moduleH, moduleI)
+	addDep(moduleI, moduleJ)
+	addDep(moduleJ, moduleI)
 
 	t.Run("no modules", func(t *testing.T) {
 		errs := parallelVisit(slices.Values([]*moduleInfo(nil)), bottomUpVisitorImpl{}, 1,
-			func(module *moduleInfo, pause chan<- pauseSpec) bool {
+			func(module *moduleInfo, pause pauseFunc) bool {
 				panic("unexpected call to visitor")
 			})
 		if errs != nil {
@@ -802,7 +809,7 @@ func Test_parallelVisit(t *testing.T) {
 	t.Run("bottom up", func(t *testing.T) {
 		order := ""
 		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC}), bottomUpVisitorImpl{}, 1,
-			func(module *moduleInfo, pause chan<- pauseSpec) bool {
+			func(module *moduleInfo, pause pauseFunc) bool {
 				order += module.group.name
 				return false
 			})
@@ -816,12 +823,10 @@ func Test_parallelVisit(t *testing.T) {
 	t.Run("pause", func(t *testing.T) {
 		order := ""
 		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC, moduleD}), bottomUpVisitorImpl{}, 1,
-			func(module *moduleInfo, pause chan<- pauseSpec) bool {
+			func(module *moduleInfo, pause pauseFunc) bool {
 				if module == moduleC {
 					// Pause module C on module D
-					unpause := make(chan struct{})
-					pause <- pauseSpec{moduleC, moduleD, unpause}
-					<-unpause
+					pause(moduleD)
 				}
 				order += module.group.name
 				return false
@@ -836,7 +841,7 @@ func Test_parallelVisit(t *testing.T) {
 	t.Run("cancel", func(t *testing.T) {
 		order := ""
 		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC}), bottomUpVisitorImpl{}, 1,
-			func(module *moduleInfo, pause chan<- pauseSpec) bool {
+			func(module *moduleInfo, pause pauseFunc) bool {
 				order += module.group.name
 				// Cancel in module B
 				return module == moduleB
@@ -851,12 +856,10 @@ func Test_parallelVisit(t *testing.T) {
 	t.Run("pause and cancel", func(t *testing.T) {
 		order := ""
 		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC, moduleD}), bottomUpVisitorImpl{}, 1,
-			func(module *moduleInfo, pause chan<- pauseSpec) bool {
+			func(module *moduleInfo, pause pauseFunc) bool {
 				if module == moduleC {
 					// Pause module C on module D
-					unpause := make(chan struct{})
-					pause <- pauseSpec{moduleC, moduleD, unpause}
-					<-unpause
+					pause(moduleD)
 				}
 				order += module.group.name
 				// Cancel in module D
@@ -872,7 +875,7 @@ func Test_parallelVisit(t *testing.T) {
 	t.Run("parallel", func(t *testing.T) {
 		order := ""
 		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC}), bottomUpVisitorImpl{}, 3,
-			func(module *moduleInfo, pause chan<- pauseSpec) bool {
+			func(module *moduleInfo, pause pauseFunc) bool {
 				order += module.group.name
 				return false
 			})
@@ -886,12 +889,10 @@ func Test_parallelVisit(t *testing.T) {
 	t.Run("pause existing", func(t *testing.T) {
 		order := ""
 		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC}), bottomUpVisitorImpl{}, 3,
-			func(module *moduleInfo, pause chan<- pauseSpec) bool {
+			func(module *moduleInfo, pause pauseFunc) bool {
 				if module == moduleA {
 					// Pause module A on module B (an existing dependency)
-					unpause := make(chan struct{})
-					pause <- pauseSpec{moduleA, moduleB, unpause}
-					<-unpause
+					pause(moduleB)
 				}
 				order += module.group.name
 				return false
@@ -905,12 +906,10 @@ func Test_parallelVisit(t *testing.T) {
 	})
 	t.Run("cycle", func(t *testing.T) {
 		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC}), bottomUpVisitorImpl{}, 3,
-			func(module *moduleInfo, pause chan<- pauseSpec) bool {
+			func(module *moduleInfo, pause pauseFunc) bool {
 				if module == moduleC {
 					// Pause module C on module A (a dependency cycle)
-					unpause := make(chan struct{})
-					pause <- pauseSpec{moduleC, moduleA, unpause}
-					<-unpause
+					pause(moduleA)
 				}
 				return false
 			})
@@ -935,18 +934,14 @@ func Test_parallelVisit(t *testing.T) {
 	})
 	t.Run("pause cycle", func(t *testing.T) {
 		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC, moduleD}), bottomUpVisitorImpl{}, 3,
-			func(module *moduleInfo, pause chan<- pauseSpec) bool {
+			func(module *moduleInfo, pause pauseFunc) bool {
 				if module == moduleC {
 					// Pause module C on module D
-					unpause := make(chan struct{})
-					pause <- pauseSpec{moduleC, moduleD, unpause}
-					<-unpause
+					pause(moduleD)
 				}
 				if module == moduleD {
 					// Pause module D on module C (a pause cycle)
-					unpause := make(chan struct{})
-					pause <- pauseSpec{moduleD, moduleC, unpause}
-					<-unpause
+					pause(moduleC)
 				}
 				return false
 			})
@@ -979,11 +974,9 @@ func Test_parallelVisit(t *testing.T) {
 			moduleE: moduleF,
 		}
 		errs := parallelVisit(slices.Values([]*moduleInfo{moduleD, moduleE, moduleF, moduleG}), bottomUpVisitorImpl{}, 4,
-			func(module *moduleInfo, pause chan<- pauseSpec) bool {
+			func(module *moduleInfo, pause pauseFunc) bool {
 				if dep, ok := pauseDeps[module]; ok {
-					unpause := make(chan struct{})
-					pause <- pauseSpec{module, dep, unpause}
-					<-unpause
+					pause(dep)
 				}
 				return false
 			})
@@ -1005,6 +998,29 @@ func Test_parallelVisit(t *testing.T) {
 			}
 		}
 	})
+	t.Run("existing cycle", func(t *testing.T) {
+		errs := parallelVisit(slices.Values([]*moduleInfo{moduleH, moduleI, moduleJ}), bottomUpVisitorImpl{}, 3,
+			func(module *moduleInfo, pause pauseFunc) bool {
+				return false
+			})
+		want := []string{
+			`encountered dependency cycle`,
+			`module "J" depends on module "I"`,
+			`module "I" depends on module "J"`,
+		}
+		for i := range want {
+			if len(errs) <= i {
+				t.Errorf("missing error %s", want[i])
+			} else if !strings.Contains(errs[i].Error(), want[i]) {
+				t.Errorf("expected error %s, got %s", want[i], errs[i])
+			}
+		}
+		if len(errs) > len(want) {
+			for _, err := range errs[len(want):] {
+				t.Errorf("unexpected error %s", err.Error())
+			}
+		}
+	})
 }
 
 func TestDeduplicateOrderOnlyDeps(t *testing.T) {
@@ -1121,8 +1137,8 @@ func TestDeduplicateOrderOnlyDeps(t *testing.T) {
 				}
 				t.FailNow()
 			}
-			modules := make([]*moduleInfo, 0, len(ctx.moduleInfo))
-			for _, module := range ctx.moduleInfo {
+			var modules []*moduleInfo
+			for module := range ctx.iterateAllVariants() {
 				modules = append(modules, module)
 			}
 			actualPhonys := ctx.deduplicateOrderOnlyDeps(modules)
@@ -1461,6 +1477,10 @@ func bpSetup(t *testing.T, bp string) *Context {
 	ctx := NewContext()
 	fileSystem := map[string][]byte{
 		"Android.bp": []byte(bp),
+		"file1.cc":   {},
+		"file1.cpp":  {},
+		"file2.cc":   {},
+		"file2.cpp":  {},
 	}
 	ctx.MockFileSystem(fileSystem)
 	ctx.RegisterBottomUpMutator("deps", depsMutator)
@@ -1496,6 +1516,14 @@ func incrementalSetup(t *testing.T) *Context {
 					deps: ["MyBarModule"],
 					outputs: ["MyIncrementalModule_phony_output"],
 					order_only: ["test.lib"],
+					srcs: [
+							"*.cc",
+							"*.cpp",
+					],
+					exclude_srcs: [
+							"file1.cc",
+							"file1.cpp",
+					],
 			}
 			bar_module {
 					name: "MyBarModule",
@@ -1526,7 +1554,7 @@ func incrementalSetupForRestore(ctx *Context, orderOnlyStrings []string) any {
 	} {
 		hash, err := proptools.CalculateHash(v)
 		if err != nil {
-			panic(fmt.Sprintf("Can't hash value of providers"))
+			panic("Can't hash value of providers")
 		}
 		providerHashes[k.id] = hash
 	}
@@ -1534,17 +1562,12 @@ func incrementalSetupForRestore(ctx *Context, orderOnlyStrings []string) any {
 	var providerValue any = IncrementalTestProvider{Value: "MyIncrementalModule"}
 	toCache := BuildActionCache{
 		cacheKey: &BuildActionCachedData{
-			Pos: &scanner.Position{
-				Filename: "Android.bp",
-				Line:     2,
-				Column:   4,
-				Offset:   4,
-			},
 			Providers: []CachedProvider{{
 				Id:    &IncrementalTestProviderKey.providerKey,
 				Value: &providerValue,
 			}},
 			OrderOnlyStrings: orderOnlyStrings,
+			GlobCache:        calculateGlobCache(),
 		},
 	}
 	ctx.SetIncrementalEnabled(true)
@@ -1562,7 +1585,7 @@ func calculateHashKey(m *moduleInfo, providerHashes [][]uint64) BuildActionCache
 	cacheInput := new(BuildActionCacheInput)
 	cacheInput.PropertiesHash = hash
 	cacheInput.ProvidersHash = providerHashes
-	hash, err = proptools.CalculateHash(&cacheInput)
+	hash, err = proptools.CalculateHash(cacheInput)
 	if err != nil {
 		panic(newPanicErrorf(err, "failed to calculate cache input hash"))
 	}
@@ -1572,6 +1595,24 @@ func calculateHashKey(m *moduleInfo, providerHashes [][]uint64) BuildActionCache
 	}
 }
 
+func calculateGlobCache() []globResultCache {
+	globHash1, _ := proptools.CalculateHash([]string{"file2.cc"})
+	globHash2, _ := proptools.CalculateHash([]string{"file2.cpp"})
+
+	return []globResultCache{
+		{
+			Pattern:  "*.cc",
+			Excludes: []string{"file1.cc", "file1.cpp"},
+			Result:   globHash1,
+		},
+		{
+			Pattern:  "*.cpp",
+			Excludes: []string{"file1.cc", "file1.cpp"},
+			Result:   globHash2,
+		},
+	}
+}
+
 func TestCacheBuildActions(t *testing.T) {
 	ctx := incrementalSetup(t)
 	ctx.SetIncrementalEnabled(true)
@@ -1601,17 +1642,12 @@ func TestCacheBuildActions(t *testing.T) {
 	}
 	var providerValue any = IncrementalTestProvider{Value: "MyIncrementalModule"}
 	expectedCache := BuildActionCachedData{
-		Pos: &scanner.Position{
-			Filename: "Android.bp",
-			Line:     2,
-			Column:   4,
-			Offset:   4,
-		},
 		Providers: []CachedProvider{{
 			Id:    &IncrementalTestProviderKey.providerKey,
 			Value: &providerValue,
 		}},
 		OrderOnlyStrings: []string{"dedup-d479e9a8133ff998"},
+		GlobCache:        calculateGlobCache(),
 	}
 	if !reflect.DeepEqual(expectedCache, *cache) {
 		t.Errorf("expected: %v actual %v", expectedCache, *cache)
@@ -1644,6 +1680,35 @@ func TestRestoreBuildActions(t *testing.T) {
 	}
 }
 
+func TestGlobChangeNotRestoreBuildActions(t *testing.T) {
+	ctx := incrementalSetup(t)
+	incrementalSetupForRestore(ctx, nil)
+	// Now change the file system to make the old glob result invalid.
+	fileSystem := map[string][]byte{
+		"Android.bp": {},
+		"file1.cc":   {},
+		"file1.cpp":  {},
+		"file3.cc":   {},
+		"file4.cpp":  {},
+	}
+	ctx.MockFileSystem(fileSystem)
+	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
+	_, errs := ctx.PrepareBuildActions(nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected errors calling generateModuleBuildActions:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+
+	// Verify that the GenerateBuildActions was rerun for the incremental module
+	incRerun := incInfo.logicModule.(*incrementalModule).GenerateBuildActionsCalled
+	if !incRerun {
+		t.Errorf("failed to rerun GenerateBuildActions when glob result changed: %t", incRerun)
+	}
+}
+
 func TestSkipNinjaForCacheHit(t *testing.T) {
 	ctx := incrementalSetup(t)
 	incrementalSetupForRestore(ctx, nil)
@@ -2083,3 +2148,42 @@ func TestDisallowedMutatorMethods(t *testing.T) {
 	}
 
 }
+
+func Benchmark_parallelVisit(b *testing.B) {
+	b.ReportAllocs()
+	create := func(name string) *moduleInfo {
+		m := &moduleInfo{
+			group: &moduleGroup{
+				name: name,
+			},
+		}
+		m.group.modules = moduleList{m}
+		return m
+	}
+
+	addDep := func(from, to *moduleInfo) {
+		from.directDeps = append(from.directDeps, depInfo{to, nil})
+		from.forwardDeps = append(from.forwardDeps, to)
+		to.reverseDeps = append(to.reverseDeps, from)
+	}
+	_ = addDep
+
+	var modules []*moduleInfo
+
+	for i := range b.N {
+		modules = append(modules, create(strconv.Itoa(i)))
+		if i != 0 {
+			//addDep(modules[len(modules)-1], modules[len(modules)-2])
+		}
+	}
+
+	b.ResetTimer()
+	errs := parallelVisit(slices.Values(modules), bottomUpVisitorImpl{}, 1000,
+		func(module *moduleInfo, pause pauseFunc) bool {
+			//fmt.Println(module.group.name)
+			return false
+		})
+	if errs != nil {
+		b.Errorf("expected no errors, got %q", errs)
+	}
+}
diff --git a/depset/depset.go b/depset/depset.go
index a4a73e2..7b744de 100644
--- a/depset/depset.go
+++ b/depset/depset.go
@@ -15,6 +15,8 @@
 package depset
 
 import (
+	"bytes"
+	"errors"
 	"fmt"
 	"iter"
 	"slices"
@@ -91,41 +93,208 @@ func (d DepSet[T]) order() Order {
 	return impl.order
 }
 
-type depSetGob[T depSettableType] struct {
-	Preorder   bool
-	Reverse    bool
-	Order      Order
-	Direct     []T
-	Transitive []DepSet[T]
+var DepSetMapToGob = make(map[any]int32)
+var DepSetMapFromGob = make(map[int32]any)
+var depsetId int32 = 0
+
+// Since the Gob decoding and encoding logic uses these two global maps to store
+// the depsets that have been processed, each time the whole encoding and decoding process
+// runs, these maps need to be cleared.
+func resetGobMaps() {
+	DepSetMapToGob = make(map[any]int32)
+	DepSetMapFromGob = make(map[int32]any)
 }
 
-func (d *DepSet[T]) ToGob() *depSetGob[T] {
-	impl := d.impl()
-	return &depSetGob[T]{
-		Preorder:   impl.preorder,
-		Reverse:    impl.reverse,
-		Order:      impl.order,
-		Direct:     impl.direct.ToSlice(),
-		Transitive: impl.transitive.ToSlice(),
+// This method is required for DepSet to implement CustomEnc
+func (d DepSet[T]) GetTypeId() int16 {
+	return -1
+}
+
+func (d DepSet[T]) GobEncode() ([]byte, error) {
+	buf := new(bytes.Buffer)
+
+	if err := d.Encode(buf); err != nil {
+		return nil, err
 	}
+
+	return buf.Bytes(), nil
 }
 
-func (d *DepSet[T]) FromGob(data *depSetGob[T]) {
-	d.handle = unique.Make(depSet[T]{
-		preorder:   data.Preorder,
-		reverse:    data.Reverse,
-		order:      data.Order,
-		direct:     uniquelist.Make(data.Direct),
-		transitive: uniquelist.Make(data.Transitive),
+func (d DepSet[T]) Encode(buf *bytes.Buffer) error {
+	return d.encodeInternal(buf, func(buffer *bytes.Buffer, data T) error {
+		return gobtools.EncodeStruct(buf, data)
 	})
 }
 
-func (d DepSet[T]) GobEncode() ([]byte, error) {
-	return gobtools.CustomGobEncode[depSetGob[T]](&d)
+func (d DepSet[T]) EncodeInterface(buf *bytes.Buffer) error {
+	return d.encodeInternal(buf, func(buffer *bytes.Buffer, data T) error {
+		return gobtools.EncodeInterface(buf, data)
+	})
+}
+
+func (d DepSet[T]) EncodeString(buf *bytes.Buffer) error {
+	return d.encodeInternal(buf, func(buffer *bytes.Buffer, data T) error {
+		return gobtools.EncodeString(buf, any(data).(string))
+	})
+}
+
+// The Gob encoding and decoding logic below only works in a single thread environment,
+// which is currently the case. When parallel Gob cache processing is necessary the logic
+// needs to be revisited.
+func (d DepSet[T]) encodeInternal(buf *bytes.Buffer, encode func(buffer *bytes.Buffer, data T) error) error {
+	var err error
+	var zeroDepSet DepSet[T]
+	if d == zeroDepSet {
+		return gobtools.EncodeSimple(buf, false)
+	} else {
+		if err = gobtools.EncodeSimple(buf, true); err != nil {
+			return err
+		}
+	}
+	impl := d.impl()
+	// Below we first check if the given depset has been encoded, if no we encode the
+	// actual content of the depset, otherwise we just encode a reference number of it
+	// to avoid duplicating the same depset multiple times.
+	if id, ok := DepSetMapToGob[d]; !ok {
+		depsetId++
+		DepSetMapToGob[d] = depsetId
+		if err = errors.Join(
+			gobtools.EncodeSimple(buf, true),
+			gobtools.EncodeSimple(buf, depsetId),
+			gobtools.EncodeSimple(buf, impl.preorder),
+			gobtools.EncodeSimple(buf, impl.reverse),
+			gobtools.EncodeSimple(buf, int16(impl.order))); err != nil {
+			return err
+		}
+
+		dlist := impl.direct.ToSlice()
+		if err = gobtools.EncodeSimple(buf, int32(len(dlist))); err != nil {
+			return err
+		}
+		for i := 0; i < len(dlist); i++ {
+			if err = encode(buf, dlist[i]); err != nil {
+				return err
+			}
+		}
+
+		tlist := impl.transitive.ToSlice()
+		if err = gobtools.EncodeSimple(buf, int32(len(tlist))); err != nil {
+			return err
+		}
+		for i := 0; i < len(tlist); i++ {
+			if err = tlist[i].encodeInternal(buf, encode); err != nil {
+				return err
+			}
+		}
+	} else {
+		err = errors.Join(
+			gobtools.EncodeSimple(buf, false),
+			gobtools.EncodeSimple(buf, id))
+	}
+
+	return nil
 }
 
 func (d *DepSet[T]) GobDecode(data []byte) error {
-	return gobtools.CustomGobDecode[depSetGob[T]](data, d)
+	buf := bytes.NewReader(data)
+	return d.Decode(buf)
+}
+
+func (d *DepSet[T]) Decode(buf *bytes.Reader) error {
+	return d.decodeInternal(buf, func(reader *bytes.Reader, value *T) error {
+		return gobtools.DecodeStruct(buf, value)
+	})
+}
+
+func (d *DepSet[T]) DecodeInterface(buf *bytes.Reader) error {
+	return d.decodeInternal(buf, func(reader *bytes.Reader, value *T) error {
+		var err error
+		if tmpVal, err := gobtools.DecodeInterface(buf); err == nil {
+			*value = tmpVal.(T)
+		}
+		return err
+	})
+}
+
+func (d *DepSet[T]) DecodeString(buf *bytes.Reader) error {
+	return d.decodeInternal(buf, func(reader *bytes.Reader, value *T) error {
+		var sValue string
+		if err := gobtools.DecodeString(buf, &sValue); err != nil {
+			return err
+		}
+		*value = any(sValue).(T)
+		return nil
+	})
+}
+
+func (d *DepSet[T]) decodeInternal(buf *bytes.Reader, decode func(reader *bytes.Reader, value *T) error) error {
+	var embedded bool
+	var err error
+	var id int32
+	var valueSet bool
+	if err = gobtools.DecodeSimple[bool](buf, &valueSet); err != nil || !valueSet {
+		return err
+	}
+	if err = errors.Join(
+		gobtools.DecodeSimple[bool](buf, &embedded),
+		gobtools.DecodeSimple[int32](buf, &id)); err != nil {
+		return err
+	}
+	if embedded {
+		var fromGob depSet[T]
+		var order int16
+		if err = errors.Join(
+			gobtools.DecodeSimple[bool](buf, &fromGob.preorder),
+			gobtools.DecodeSimple[bool](buf, &fromGob.reverse),
+			gobtools.DecodeSimple[int16](buf, &order)); err != nil {
+			return err
+		}
+		fromGob.order = Order(order)
+
+		var dlist []T
+		var dlen int32
+		err = gobtools.DecodeSimple[int32](buf, &dlen)
+		if err != nil {
+			return err
+		}
+		if dlen > 0 {
+			dlist = make([]T, dlen)
+			for i := 0; i < int(dlen); i++ {
+				if err = decode(buf, &dlist[i]); err != nil {
+					return err
+				}
+			}
+		}
+		fromGob.direct = uniquelist.Make(dlist)
+
+		var tlist []DepSet[T]
+		var tlen int32
+		err = gobtools.DecodeSimple[int32](buf, &tlen)
+		if err != nil {
+			return err
+		}
+		if tlen > 0 {
+			tlist = make([]DepSet[T], tlen)
+			for i := 0; i < int(tlen); i++ {
+				if err = tlist[i].decodeInternal(buf, decode); err != nil {
+					return err
+				}
+			}
+		}
+		fromGob.transitive = uniquelist.Make(tlist)
+
+		d.handle = unique.Make(fromGob)
+		DepSetMapFromGob[id] = d
+	} else {
+		if v, ok := DepSetMapFromGob[id].(*DepSet[T]); ok {
+			d.handle = v.handle
+		} else {
+			// This shouldn't happen in non-parallel processing of the gob cache file.
+			panic("Failed to find the referenced depset during Gob decoding")
+		}
+	}
+
+	return err
 }
 
 // New returns an immutable DepSet with the given order, direct and transitive contents.
diff --git a/depset/depset_test.go b/depset/depset_test.go
index 91ca9e0..0c50b60 100644
--- a/depset/depset_test.go
+++ b/depset/depset_test.go
@@ -15,6 +15,7 @@
 package depset
 
 import (
+	"bytes"
 	"fmt"
 	"reflect"
 	"slices"
@@ -270,6 +271,110 @@ func TestDepSet(t *testing.T) {
 	}
 }
 
+// The following test cases are modifying a global variable, so the test cases can't be run in parallel
+// and the test itself can't be run in parallel with any other tests.
+func TestDepSetGob(t *testing.T) {
+	tests := []struct {
+		name   string
+		depSet func(t *testing.T, order Order) DepSet[string]
+	}{
+		{
+			name: "direct",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				return New[string](order, []string{"c", "a", "b"}, nil)
+			},
+		},
+		{
+			name: "simple",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				subset := New[string](order, []string{"c", "a", "e"}, nil)
+				return New[string](order, []string{"b", "d"}, []DepSet[string]{subset})
+			},
+		},
+		{
+			name: "simpleWithDuplicates",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				subset := New[string](order, []string{"c", "a", "e"}, nil)
+				return New[string](order, []string{"c", "a", "a", "a", "b"}, []DepSet[string]{subset, subset})
+			},
+		},
+		{
+			name: "chain",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				c := NewBuilder[string](order).Direct("c").Build()
+				b := NewBuilder[string](order).Direct("b").Transitive(c).Build()
+				a := NewBuilder[string](order).Direct("a").Transitive(b).Build()
+
+				return a
+			},
+		},
+		{
+			name: "diamond",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				d := NewBuilder[string](order).Direct("d").Build()
+				c := NewBuilder[string](order).Direct("c").Transitive(d).Build()
+				b := NewBuilder[string](order).Direct("b").Transitive(d).Build()
+				a := NewBuilder[string](order).Direct("a").Transitive(b).Transitive(c).Build()
+
+				return a
+			},
+		},
+		{
+			name: "extendedDiamond",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				d := NewBuilder[string](order).Direct("d").Build()
+				e := NewBuilder[string](order).Direct("e").Build()
+				b := NewBuilder[string](order).Direct("b").Transitive(d).Transitive(e).Build()
+				c := NewBuilder[string](order).Direct("c").Transitive(e).Transitive(d).Build()
+				a := NewBuilder[string](order).Direct("a").Transitive(b).Transitive(c).Build()
+				return a
+			},
+		},
+		{
+			name: "extendedDiamondRightArm",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				d := NewBuilder[string](order).Direct("d").Build()
+				e := NewBuilder[string](order).Direct("e").Build()
+				b := NewBuilder[string](order).Direct("b").Transitive(d).Transitive(e).Build()
+				c2 := NewBuilder[string](order).Direct("c2").Transitive(e).Transitive(d).Build()
+				c := NewBuilder[string](order).Direct("c").Transitive(c2).Build()
+				a := NewBuilder[string](order).Direct("a").Transitive(b).Transitive(c).Build()
+				return a
+			},
+		},
+		{
+			name: "zeroDepSet",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				a := NewBuilder[string](order).Build()
+				var b DepSet[string]
+				c := NewBuilder[string](order).Direct("c").Transitive(a, b).Build()
+				return c
+			},
+		},
+	}
+
+	for _, tt := range tests {
+		resetGobMaps()
+		t.Run(tt.name, func(t *testing.T) {
+			toGob := tt.depSet(t, POSTORDER)
+			buf := new(bytes.Buffer)
+			err := toGob.EncodeString(buf)
+			if err != nil {
+				t.Errorf("failed to serialize depset: %s", err)
+			}
+			var fromGob DepSet[string]
+			err = fromGob.DecodeString(bytes.NewReader(buf.Bytes()))
+
+			if err != nil {
+				t.Errorf("failed to deserialize depset: %s", err)
+			}
+			if toGob != fromGob {
+				t.Errorf("depsets are different: %v %v", toGob.ToList(), fromGob.ToList())
+			}
+		})
+	}
+}
+
 func TestDepSetInvalidOrder(t *testing.T) {
 	orders := []Order{POSTORDER, PREORDER, TOPOLOGICAL}
 
diff --git a/gobtools/codegen/Android.bp b/gobtools/codegen/Android.bp
new file mode 100644
index 0000000..efc7112
--- /dev/null
+++ b/gobtools/codegen/Android.bp
@@ -0,0 +1,19 @@
+blueprint_go_binary {
+    name: "gob_gen",
+    srcs: ["gob_gen.go"],
+    testSrcs: [
+        "gob_gen_test.go",
+        "gob_test_data.go",
+        "gob_test_data_gob_enc.go",
+    ],
+    visibility: [
+        // used by plugins
+        "//visibility:private",
+    ],
+    deps: [
+        "blueprint-depset",
+        "blueprint-gobtools",
+        "blueprint-gobtools-test",
+        "blueprint-uniquelist",
+    ],
+}
diff --git a/gobtools/codegen/gob_gen.go b/gobtools/codegen/gob_gen.go
new file mode 100644
index 0000000..c4b18ae
--- /dev/null
+++ b/gobtools/codegen/gob_gen.go
@@ -0,0 +1,743 @@
+// Copyright 2025 Google Inc. All rights reserved.
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
+package main
+
+import (
+	"bytes"
+	"errors"
+	"flag"
+	"fmt"
+	"go/ast"
+	"go/format"
+	"go/parser"
+	"go/scanner"
+	"go/token"
+	"maps"
+	"os"
+	"path"
+	"path/filepath"
+	"slices"
+	"strings"
+)
+
+// This file provides functionality to auto-generate custom Encode and Decode
+// method for Go structs.
+//
+// # Auto-Generation Trigger
+//
+// The generation process is triggered for structs annotated with the comment:
+//   // @auto-generate: gob
+// within a given Go source file.
+//
+// # Generated Methods
+//
+// 1. Encode(buf *bytes.Buffer) error:
+//    Encodes each field within the struct into a stream of bytes.
+//
+// 2. Decode(buf *bytes.Reader) error:
+//    Decodes from a stream of byte and populates each field within the struct.
+//
+// # Supported Data Types
+//
+// The generator can handle the following data types within the annotated structs:
+//   - Most of the primitive types (e.g., int, string, bool)
+//   - Pointers to supported types
+//   - Maps (keys and values must be supported types)
+//   - Slices of supported types
+//   - Type aliases
+//   - Interfaces.
+//   - Other user defined structs (which should have generated Encode and Decode methods)
+
+var verify = flag.Bool("verify", false, "verify existing outputs")
+
+var fieldId int
+
+const genGobAnnotation = "@auto-generate: gob"
+const blueprintPkgPrefix = "github.com/google/blueprint"
+const blueprintPkgPath = "build/blueprint"
+const soongPkgPrefix = "android/soong"
+const soongPkgPath = "build/soong"
+
+type typeDefTypes int
+
+const (
+	Struct typeDefTypes = iota
+	Alias
+	Interface
+	Slice
+	Map
+	Pointer
+	Ident
+	Unknown
+)
+
+type structMap map[string]*ast.TypeSpec
+
+var pkgStructs = make(map[string]structMap)
+var importPkgs = make(map[string]string)
+var curPackage string
+var sourceDir string
+
+func findType(pkgName string, typeName string, imports map[string]bool) typeDefTypes {
+	if _, ok := pkgStructs[pkgName]; !ok {
+		importPackage(pkgName, findPackagePath(pkgName, imports))
+	}
+
+	ts := pkgStructs[pkgName][typeName]
+	if ts == nil {
+		return Unknown
+	}
+
+	// 1. Check for Type Alias
+	if ts.Assign.IsValid() {
+		return Alias
+	}
+
+	// 2. If not an alias, inspect ts.Type
+	switch ts.Type.(type) {
+	case *ast.InterfaceType:
+		return Interface
+	case *ast.StructType:
+		return Struct
+	case *ast.Ident:
+		return Ident
+	case *ast.MapType:
+		return Map
+	case *ast.ArrayType:
+		return Slice
+	case *ast.StarExpr:
+		return Pointer
+	}
+	return Unknown
+}
+
+func findStructName(expr ast.Expr, pkgName string) (string, string, string) {
+	var typeName string
+	var fullName string
+	switch t := expr.(type) {
+	case *ast.Ident:
+		typeName = t.Name
+	case *ast.SelectorExpr:
+		pkgName = t.X.(*ast.Ident).Name
+		typeName = t.Sel.Name
+	case *ast.ArrayType:
+		pkgName, typeName, _ = findStructName(t.Elt, pkgName)
+		typeName = "[]" + typeName
+	case *ast.StarExpr:
+		pkgName, typeName, _ = findStructName(t.X, pkgName)
+		typeName = "*" + typeName
+	default:
+		panic(fmt.Errorf("unknown type to find name: %T", expr))
+	}
+	if pkgName != curPackage {
+		fullName = pkgName + "." + typeName
+	} else {
+		fullName = typeName
+	}
+
+	return pkgName, typeName, fullName
+}
+
+func findStructs(node *ast.File) []*ast.TypeSpec {
+	var ret []*ast.TypeSpec
+	for _, decl := range node.Decls {
+		if genDecl, ok := decl.(*ast.GenDecl); ok && genDecl.Tok == token.TYPE {
+			for _, spec := range genDecl.Specs {
+				if typeSpec, ok := spec.(*ast.TypeSpec); ok {
+					if genDecl.Doc != nil && strings.Contains(genDecl.Doc.Text(), genGobAnnotation) {
+						ret = append(ret, typeSpec)
+					}
+				}
+			}
+		}
+	}
+	return ret
+}
+
+func loadTypes(node *ast.File) {
+	pkgName := node.Name.Name
+	if _, ok := pkgStructs[pkgName]; !ok {
+		pkgStructs[pkgName] = make(map[string]*ast.TypeSpec)
+	}
+	for _, decl := range node.Decls {
+		if genDecl, ok := decl.(*ast.GenDecl); ok && genDecl.Tok == token.TYPE {
+			for _, spec := range genDecl.Specs {
+				if typeSpec, ok := spec.(*ast.TypeSpec); ok {
+					pkgStructs[pkgName][typeSpec.Name.Name] = typeSpec
+				}
+			}
+		}
+	}
+}
+
+func maybeAddImport(structName string, imports map[string]bool) {
+	if parts := strings.Split(structName, "."); len(parts) == 2 {
+		imports[fmt.Sprintf("\"%s\"", importPkgs[parts[0]])] = true
+	}
+}
+
+func nextVar() string {
+	fieldId++
+	return fmt.Sprintf("val%d", fieldId)
+}
+
+func generateEncodeForType(encodeBody *strings.Builder, pkgName string, field ast.Expr, fieldName string, imports map[string]bool) {
+	imports[`"bytes"`] = true
+
+	switch t := field.(type) {
+	// cases such as "name string", "path Path", "basePath".
+	case *ast.Ident:
+		switch t.Name {
+		case "string":
+			encodeBody.WriteString(fmt.Sprintf("\tif err = gobtools.EncodeString(buf, %s); err != nil { return err }\n", fieldName))
+			imports[`"github.com/google/blueprint/gobtools"`] = true
+		case "int":
+			encodeBody.WriteString(fmt.Sprintf("\tif err = gobtools.EncodeSimple(buf, int64(%s)); err != nil { return err }\n", fieldName))
+			imports[`"github.com/google/blueprint/gobtools"`] = true
+		case "bool", "int16", "int32", "int64", "uint16", "uint32", "uint64":
+			encodeBody.WriteString(fmt.Sprintf("\tif err = gobtools.EncodeSimple(buf, %s); err != nil { return err }\n", fieldName))
+			imports[`"github.com/google/blueprint/gobtools"`] = true
+		case "any":
+			encodeBody.WriteString(fmt.Sprintf("\tif err = gobtools.EncodeInterface(buf, %s); err != nil { return err }\n", fieldName))
+			imports[`"github.com/google/blueprint/gobtools"`] = true
+		default:
+			generateEncodeForCustomType(encodeBody, fieldName, pkgName, t.Name, imports)
+		}
+	case *ast.MapType:
+		encodeBody.WriteString(fmt.Sprintf("\tif err = gobtools.EncodeSimple(buf, int32(len(%s))); err != nil { return err }\n", fieldName))
+		encodeBody.WriteString(fmt.Sprintf("\tfor k, v := range %s {\n", fieldName))
+		generateEncodeForType(encodeBody, pkgName, t.Key, "k", imports)
+		generateEncodeForType(encodeBody, pkgName, t.Value, "v", imports)
+		encodeBody.WriteString("\t}\n")
+	case *ast.ArrayType:
+		encodeArray(encodeBody, pkgName, t.Elt, fieldName, imports)
+	// pointers.
+	case *ast.StarExpr:
+		isNil := nextVar()
+		encodeBody.WriteString(fmt.Sprintf("\t%s := %s == nil\n", isNil, fieldName))
+		encodeBody.WriteString(fmt.Sprintf("\tif err = gobtools.EncodeSimple(buf, %s); err != nil { return err }\n", isNil))
+		encodeBody.WriteString(fmt.Sprintf("\tif !%s {\n", isNil))
+		generateEncodeForType(encodeBody, pkgName, t.X, "(*"+fieldName+")", imports)
+		encodeBody.WriteString("\t}\n")
+	// generic types.
+	case *ast.IndexExpr:
+		if typ, ok := t.X.(*ast.SelectorExpr); ok && typ.Sel.Name == "UniqueList" {
+			listName := nextVar()
+			encodeBody.WriteString(fmt.Sprintf("\t%s := %s.ToSlice()\n", listName, fieldName))
+			encodeArray(encodeBody, pkgName, t.Index, listName, imports)
+		} else if typ, ok := t.X.(*ast.SelectorExpr); ok && typ.Sel.Name == "DepSet" {
+			pkgName, typName, _ := findStructName(t.Index, pkgName)
+			if typName == "string" {
+				encodeBody.WriteString(fmt.Sprintf("\tif err = %s.EncodeString(buf); err != nil { return err }\n", fieldName))
+			} else if findType(pkgName, typName, imports) == Interface {
+				encodeBody.WriteString(fmt.Sprintf("\tif err = %s.EncodeInterface(buf); err != nil { return err }\n", fieldName))
+			} else {
+				encodeBody.WriteString(fmt.Sprintf("\tif err = %s.Encode(buf); err != nil { return err }\n", fieldName))
+			}
+		} else {
+			encodeBody.WriteString(fmt.Sprintf("\tif err = %s.Encode(buf); err != nil { return err }\n", fieldName))
+		}
+	// type from other package such as "path android.Path".
+	case *ast.SelectorExpr:
+		pkgName, typName, _ := findStructName(t, pkgName)
+		generateEncodeForCustomType(encodeBody, fieldName, pkgName, typName, imports)
+	// anonymous struct
+	case *ast.StructType:
+		for _, f := range t.Fields.List {
+			encodeBody.WriteString("\n")
+			fName := fieldName + "."
+			if len(f.Names) > 0 {
+				fName += f.Names[0].Name
+			}
+			generateEncodeForType(encodeBody, pkgName, f.Type, fName, imports)
+		}
+	default:
+		panic(fmt.Errorf("unknown data type: %v %T", t, t))
+	}
+}
+
+func generateEncodeForCustomType(encodeBody *strings.Builder, fieldName string, pkgName string, typeName string, imports map[string]bool) {
+	typ := findType(pkgName, typeName, imports)
+	if fieldName[len(fieldName)-1] == '.' {
+		fieldName += typeName
+	}
+	switch typ {
+	case Struct:
+		encodeBody.WriteString(fmt.Sprintf("\tif err = %s.Encode(buf); err != nil { return err }\n", fieldName))
+	case Interface:
+		encodeBody.WriteString(fmt.Sprintf("\tif err = gobtools.EncodeInterface(buf, %s); err != nil { return err }\n", fieldName))
+		imports[`"github.com/google/blueprint/gobtools"`] = true
+	case Ident:
+		// new type declarations such as "type OsClass int".
+		_, _, origType := findStructName(pkgStructs[pkgName][typeName].Type, pkgName)
+		maybeAddImport(origType, imports)
+		newFieldName := fmt.Sprintf("%s(%s)", origType, fieldName)
+		generateEncodeForType(encodeBody, pkgName, pkgStructs[pkgName][typeName].Type, newFieldName, imports)
+	default:
+		generateEncodeForType(encodeBody, pkgName, pkgStructs[pkgName][typeName].Type, fieldName, imports)
+	}
+}
+
+func generateDecodeForCustomType(decodeBody *strings.Builder, fieldName string, pkgName string, typeName string, imports map[string]bool) {
+	typ := findType(pkgName, typeName, imports)
+	if fieldName[len(fieldName)-1] == '.' {
+		fieldName += typeName
+	}
+	fullName := typeName
+	if pkgName != curPackage {
+		fullName = pkgName + "." + typeName
+	}
+
+	switch typ {
+	case Struct:
+		decodeBody.WriteString(fmt.Sprintf("\tif err = %s.Decode(buf); err != nil { return err }\n", fieldName))
+	case Interface:
+		tmpVar := nextVar()
+		decodeBody.WriteString(fmt.Sprintf("\tif %s, err := gobtools.DecodeInterface(buf); err != nil { return err } else if %s == nil {\n", tmpVar, tmpVar))
+		decodeBody.WriteString(fmt.Sprintf("\t%s = nil } else {\n", fieldName))
+		decodeBody.WriteString(fmt.Sprintf("\t%s = %s.(%s) }\n", fieldName, tmpVar, fullName))
+		imports[`"github.com/google/blueprint/gobtools"`] = true
+		maybeAddImport(fullName, imports)
+	case Ident:
+		// new type declarations such as "type OsClass int".
+		_, _, origType := findStructName(pkgStructs[pkgName][typeName].Type, pkgName)
+		tmpVar := nextVar()
+		decodeBody.WriteString(fmt.Sprintf("\tvar %s %s\n", tmpVar, origType))
+		generateDecodeForType(decodeBody, pkgName, pkgStructs[pkgName][typeName].Type, tmpVar, imports)
+		decodeBody.WriteString(fmt.Sprintf("\t%s = %s(%s)\n", fieldName, fullName, tmpVar))
+		maybeAddImport(fullName, imports)
+		maybeAddImport(origType, imports)
+	default:
+		generateDecodeForType(decodeBody, pkgName, pkgStructs[pkgName][typeName].Type, fieldName, imports)
+	}
+}
+
+func generateDecodeForType(decodeBody *strings.Builder, pkgName string, field ast.Expr, fieldName string, imports map[string]bool) {
+	valId := nextVar()
+
+	imports[`"bytes"`] = true
+
+	switch t := field.(type) {
+	case *ast.Ident:
+		switch t.Name {
+		case "string":
+			decodeBody.WriteString(fmt.Sprintf("\terr = gobtools.DecodeString(buf, &%s); if err != nil { return err }\n", fieldName))
+			imports[`"github.com/google/blueprint/gobtools"`] = true
+		case "int":
+			decodeBody.WriteString(fmt.Sprintf("\tvar %s int64\n", valId))
+			decodeBody.WriteString(fmt.Sprintf("\terr = gobtools.DecodeSimple[int64](buf, &%s); if err != nil { return err }\n", valId))
+			decodeBody.WriteString(fmt.Sprintf("\t%s = int(%s)\n", fieldName, valId))
+			imports[`"github.com/google/blueprint/gobtools"`] = true
+		case "bool", "int16", "int32", "int64", "uint16", "uint32", "uint64":
+			decodeBody.WriteString(fmt.Sprintf("\terr = gobtools.DecodeSimple[%s](buf, &%s); if err != nil { return err }\n", t.Name, fieldName))
+			imports[`"github.com/google/blueprint/gobtools"`] = true
+		case "any":
+			tmpVar := nextVar()
+			decodeBody.WriteString(fmt.Sprintf("\tif %s, err := gobtools.DecodeInterface(buf); err != nil { return err } else if %s == nil {\n", tmpVar, tmpVar))
+			decodeBody.WriteString(fmt.Sprintf("\t%s = nil } else {\n", fieldName))
+			decodeBody.WriteString(fmt.Sprintf("\t%s = %s }\n", fieldName, tmpVar))
+			imports[`"github.com/google/blueprint/gobtools"`] = true
+		default:
+			generateDecodeForCustomType(decodeBody, fieldName, pkgName, t.Name, imports)
+		}
+	case *ast.MapType:
+		_, _, kName := findStructName(t.Key, pkgName)
+		_, _, vName := findStructName(t.Value, pkgName)
+		decodeBody.WriteString(fmt.Sprintf("\tvar %s int32\n", valId))
+		decodeBody.WriteString(fmt.Sprintf("\terr = gobtools.DecodeSimple[int32](buf, &%s); if err != nil { return err }\n", valId))
+		decodeBody.WriteString(fmt.Sprintf("\tif %s > 0 {\n", valId))
+		decodeBody.WriteString(fmt.Sprintf("\t%s = make(map[%s]%s, %s)\n", fieldName, kName, vName, valId))
+		maybeAddImport(kName, imports)
+		maybeAddImport(vName, imports)
+		index := nextVar()
+		decodeBody.WriteString(fmt.Sprintf("\tfor %s := 0; %s < int(%s); %s++ {\n", index, index, valId, index))
+		decodeBody.WriteString(fmt.Sprintf("\tvar k %s\n", kName))
+		decodeBody.WriteString(fmt.Sprintf("\tvar v %s\n", vName))
+		maybeAddImport(kName, imports)
+		maybeAddImport(vName, imports)
+		generateDecodeForType(decodeBody, pkgName, t.Key, "k", imports)
+		generateDecodeForType(decodeBody, pkgName, t.Value, "v", imports)
+		decodeBody.WriteString(fmt.Sprintf("\t%s[k] = v\n", fieldName))
+		decodeBody.WriteString("\t}\n")
+		decodeBody.WriteString("\t}\n")
+	case *ast.ArrayType:
+		decodeArray(decodeBody, pkgName, t.Elt, fieldName, imports)
+	case *ast.StarExpr:
+		isNil := nextVar()
+		decodeBody.WriteString(fmt.Sprintf("\tvar %s bool\n", isNil))
+		decodeBody.WriteString(fmt.Sprintf("\tif err = gobtools.DecodeSimple(buf, &%s); err != nil { return err }\n", isNil))
+		decodeBody.WriteString(fmt.Sprintf("\tif !%s {\n", isNil))
+		_, _, typName := findStructName(t.X, pkgName)
+		decodeBody.WriteString(fmt.Sprintf("\tvar %s %s\n", valId, typName))
+		maybeAddImport(typName, imports)
+		generateDecodeForType(decodeBody, pkgName, t.X, valId, imports)
+		decodeBody.WriteString(fmt.Sprintf("\t%s = &%s\n", fieldName, valId))
+		decodeBody.WriteString("\t}\n")
+	case *ast.IndexExpr:
+		if typ, ok := t.X.(*ast.SelectorExpr); ok && typ.Sel.Name == "UniqueList" {
+			listName := nextVar()
+			_, _, typName := findStructName(t.Index, pkgName)
+			decodeBody.WriteString(fmt.Sprintf("\tvar %s []%s\n", listName, typName))
+			maybeAddImport(typName, imports)
+			decodeArray(decodeBody, pkgName, t.Index, listName, imports)
+			decodeBody.WriteString(fmt.Sprintf("\t%s = uniquelist.Make(%s)\n", fieldName, listName))
+			imports[`"github.com/google/blueprint/uniquelist"`] = true
+		} else if typ, ok := t.X.(*ast.SelectorExpr); ok && typ.Sel.Name == "DepSet" {
+			pkgName, typName, _ := findStructName(t.Index, pkgName)
+			if typName == "string" {
+				decodeBody.WriteString(fmt.Sprintf("\tif err = %s.DecodeString(buf); err != nil { return err }\n", fieldName))
+			} else if findType(pkgName, typName, imports) == Interface {
+				decodeBody.WriteString(fmt.Sprintf("\tif err = %s.DecodeInterface(buf); err != nil { return err }\n", fieldName))
+			} else {
+				decodeBody.WriteString(fmt.Sprintf("\tif err = %s.Decode(buf); err != nil { return err }\n", fieldName))
+			}
+		} else {
+			decodeBody.WriteString(fmt.Sprintf("\tif err = %s.Decode(buf); err != nil { return err }\n", fieldName))
+		}
+	case *ast.SelectorExpr:
+		pkgName, typName, _ := findStructName(t, pkgName)
+		generateDecodeForCustomType(decodeBody, fieldName, pkgName, typName, imports)
+	// anonymous struct
+	case *ast.StructType:
+		for _, f := range t.Fields.List {
+			decodeBody.WriteString("\n")
+			fName := fieldName + "."
+			if len(f.Names) > 0 {
+				fName += f.Names[0].Name
+			}
+			generateDecodeForType(decodeBody, pkgName, f.Type, fName, imports)
+		}
+	default:
+		panic(fmt.Errorf("unknown data type: %v %T", t, t))
+	}
+}
+
+func encodeArray(encodeBody *strings.Builder, pkgName string, t ast.Expr, fieldName string, imports map[string]bool) {
+	encodeBody.WriteString(fmt.Sprintf("\tif err = gobtools.EncodeSimple(buf, int32(len(%s))); err != nil { return err }\n", fieldName))
+	index := nextVar()
+	encodeBody.WriteString(fmt.Sprintf("\tfor %s := 0; %s < len(%s); %s++ {\n", index, index, fieldName, index))
+	generateEncodeForType(encodeBody, pkgName, t, fmt.Sprintf("%s[%s]", fieldName, index), imports)
+	encodeBody.WriteString("\t}\n")
+}
+
+func decodeArray(decodeBody *strings.Builder, pkgName string, t ast.Expr, fieldName string, imports map[string]bool) {
+	valId := nextVar()
+	_, _, typName := findStructName(t, pkgName)
+	decodeBody.WriteString(fmt.Sprintf("\tvar %s int32\n", valId))
+	decodeBody.WriteString(fmt.Sprintf("\terr = gobtools.DecodeSimple[int32](buf, &%s); if err != nil { return err }\n", valId))
+	decodeBody.WriteString(fmt.Sprintf("\tif %s > 0 {\n", valId))
+	decodeBody.WriteString(fmt.Sprintf("\t%s = make([]%s, %s)\n", fieldName, typName, valId))
+	maybeAddImport(typName, imports)
+	index := nextVar()
+	decodeBody.WriteString(fmt.Sprintf("\tfor %s := 0; %s < int(%s); %s++ {\n", index, index, valId, index))
+	generateDecodeForType(decodeBody, pkgName, t, fmt.Sprintf("%s[%s]", fieldName, index), imports)
+	decodeBody.WriteString("\t}\n")
+	decodeBody.WriteString("\t}\n")
+}
+
+func generateEncode(pkgName string, structDecl *ast.TypeSpec, encodeBody *strings.Builder, imports map[string]bool) {
+	structType, isStruct := structDecl.Type.(*ast.StructType)
+	structName := structDecl.Name.Name
+
+	encodeBody.WriteString("func (r " + structName + ") Encode(buf *bytes.Buffer) error {\n")
+	encodeBody.WriteString("\tvar err error\n")
+
+	if isStruct {
+		for _, field := range structType.Fields.List {
+			fieldName := "r."
+			if len(field.Names) > 0 {
+				fieldName += field.Names[0].Name
+			}
+			encodeBody.WriteString("\n")
+			generateEncodeForType(encodeBody, pkgName, field.Type, fieldName, imports)
+		}
+	} else {
+		fieldName := "r"
+		encodeBody.WriteString("\n")
+		generateEncodeForType(encodeBody, pkgName, structDecl.Type, fieldName, imports)
+	}
+
+	encodeBody.WriteString("\treturn err\n")
+	encodeBody.WriteString("}\n")
+}
+
+func generateDecode(pkgName string, structDecl *ast.TypeSpec, decodeBody *strings.Builder, imports map[string]bool) {
+	structType, isStruct := structDecl.Type.(*ast.StructType)
+	structName := structDecl.Name.Name
+
+	decodeBody.WriteString("func (r *" + structName + ") Decode(buf *bytes.Reader) error {\n")
+	decodeBody.WriteString("\tvar err error\n")
+
+	if isStruct {
+		for _, field := range structType.Fields.List {
+			fieldName := "r."
+			if len(field.Names) > 0 {
+				fieldName += field.Names[0].Name
+			}
+			decodeBody.WriteString("\n")
+			generateDecodeForType(decodeBody, pkgName, field.Type, fieldName, imports)
+		}
+	} else {
+		fieldName := "(*r)"
+		decodeBody.WriteString("\n")
+		generateDecodeForType(decodeBody, pkgName, structDecl.Type, fieldName, imports)
+	}
+
+	decodeBody.WriteString("\n\treturn err\n")
+	decodeBody.WriteString("}\n")
+}
+
+func main() {
+	flag.Usage = func() {
+		fmt.Fprintf(os.Stderr, "Usage: %s [sources]\n", os.Args[0])
+		flag.PrintDefaults()
+	}
+	flag.Parse()
+	sources := slices.Clone(flag.Args())
+
+	if f := os.Getenv("GOFILE"); f != "" {
+		sources = append(sources, f)
+	}
+
+	if len(sources) == 0 {
+		flag.Usage()
+	}
+
+	curDir, _ := os.Getwd()
+	parts := strings.Split(curDir, blueprintPkgPath)
+	if len(parts) < 2 {
+		parts = strings.Split(curDir, soongPkgPath)
+	}
+	if len(parts) < 2 {
+		// verify mode, the current directory is the base of the source tree.
+		sourceDir = curDir
+	} else {
+		sourceDir = parts[0]
+	}
+
+	for _, s := range sources {
+		out, err := generate(s)
+		if err != nil {
+			fmt.Fprintf(os.Stderr, "failed to generate output for %s: %s\n", s, err)
+			os.Exit(1)
+		}
+
+		outputFile := strings.TrimSuffix(s, ".go") + "_gob_enc.go"
+		if *verify {
+			if len(out) == 0 {
+				err := expectNotExist(outputFile)
+				if err != nil {
+					fmt.Fprintf(os.Stderr, "verification error: %s\n", err)
+					os.Exit(1)
+				}
+			} else {
+				if err := expectContents(outputFile, out); err != nil {
+					fmt.Fprintf(os.Stderr, "verification error: %s\n", err)
+					os.Exit(1)
+				}
+				if !slices.Contains(sources, outputFile) {
+					fmt.Fprintf(os.Stderr, "verification error: generated file %s is not in srcs\n", outputFile)
+					os.Exit(1)
+				}
+			}
+		} else if len(out) > 0 {
+			err = os.WriteFile(outputFile, out, 0666)
+			if err != nil {
+				fmt.Fprintf(os.Stderr, "failed to write output for %s to %s: %s\n", s, outputFile, err)
+				os.Exit(1)
+			}
+		}
+	}
+}
+
+func findPackagePath(pkgName string, imports map[string]bool) string {
+	var pkgDir string
+	baseDir := strings.TrimPrefix(importPkgs[pkgName], blueprintPkgPrefix)
+	if baseDir != importPkgs[pkgName] {
+		pkgDir = filepath.Join(sourceDir, blueprintPkgPath, baseDir)
+	} else {
+		baseDir = strings.TrimPrefix(importPkgs[pkgName], soongPkgPrefix)
+		if baseDir != importPkgs[pkgName] {
+			pkgDir = filepath.Join(sourceDir, soongPkgPath, baseDir)
+		}
+	}
+	if pkgDir == "" {
+		panic(fmt.Errorf("failed to find the package path: %s", importPkgs[pkgName]))
+	}
+
+	return pkgDir
+}
+
+func importPackage(pkgName string, pkgDir string) {
+	if _, ok := pkgStructs[pkgName]; ok {
+		return
+	}
+	includePattern := "*.go"
+	excludePattern := "*_test.go"
+
+	fullPattern := filepath.Join(pkgDir, includePattern)
+
+	matches, err := filepath.Glob(fullPattern)
+	if err != nil {
+		panic(fmt.Errorf("error matching include pattern: %v", err))
+	}
+
+	if len(matches) == 0 {
+		panic(fmt.Errorf("No files found matching pattern '%s' in directory '%s'\n", includePattern, pkgDir))
+		return
+	}
+
+	for _, match := range matches {
+		ok, err := filepath.Match(excludePattern, match)
+		if err != nil {
+			panic(fmt.Errorf("error matching exclude pattern: %v", err))
+		}
+		if ok {
+			continue
+		}
+		node, err := parseFile(match)
+		if err != nil {
+			panic(fmt.Errorf("failed to parse file: %s", match))
+		}
+		loadTypes(node)
+	}
+}
+
+func parseFile(source string) (*ast.File, error) {
+	fset := token.NewFileSet()
+	node, err := parser.ParseFile(fset, source, nil, parser.ParseComments)
+	if err != nil {
+		// ParseFile might return multiple errors in the form of a scanner.ErrorList.  By default printing the error
+		// only shows the first error.  Verification may happen very early during the build, so this may be the first
+		// time syntax errors are reported.  Use scanner.PrintError to convert them into a single error that contains
+		// all the error lines to make the errors more actionable.
+		if errorList, ok := err.(scanner.ErrorList); ok {
+			var buf bytes.Buffer
+			scanner.PrintError(&buf, errorList)
+			err = errors.New(buf.String())
+		}
+		return nil, fmt.Errorf("failed to parse:\n%w", err)
+	}
+	return node, nil
+}
+
+func generateRegistry(structDecl *ast.TypeSpec, codeBody *strings.Builder, initCodeBody *strings.Builder, imports map[string]bool) {
+	structName := structDecl.Name.Name
+	typeId := structName + "GobRegId"
+	codeBody.WriteString(fmt.Sprintf("\tvar %s int16\n", typeId))
+	codeBody.WriteString("func (r " + structName + ") GetTypeId() int16 {\n")
+	codeBody.WriteString(fmt.Sprintf("\treturn %s\n", typeId))
+	codeBody.WriteString("}\n\n")
+
+	initCodeBody.WriteString(fmt.Sprintf("\t%s = gobtools.RegisterType(func() gobtools.CustomDec { return new(%s) })\n", typeId, structName))
+	imports[`"github.com/google/blueprint/gobtools"`] = true
+}
+
+func generate(source string) ([]byte, error) {
+	node, err := parseFile(source) // Find the file containing the struct
+	if err != nil {
+		return nil, err
+	}
+	for _, p := range node.Imports {
+		pkgPath := strings.ReplaceAll(p.Path.Value, "\"", "")
+		if strings.HasPrefix(pkgPath, blueprintPkgPrefix) || strings.HasPrefix(pkgPath, soongPkgPrefix) {
+			pkgName := path.Base(pkgPath)
+			if _, ok := importPkgs[pkgName]; !ok {
+				importPkgs[pkgName] = pkgPath
+			}
+		}
+	}
+	curPackage = node.Name.Name
+	importPackage(curPackage, path.Dir(source))
+
+	var b bytes.Buffer
+	fmt.Fprintf(&b, "// Code generated by go run gob_gen.go; DO NOT EDIT.\n\n")
+	fmt.Fprintf(&b, "package %s\n", curPackage)
+	fmt.Fprintln(&b, "import (")
+
+	var codeBodies []*strings.Builder
+	imports := map[string]bool{}
+	initCodeBody := &strings.Builder{}
+	initCodeBody.WriteString("func init() {\n")
+	structDecls := findStructs(node)
+	for _, structDecl := range structDecls {
+		fieldId = 0
+		codeBody := &strings.Builder{}
+		generateEncode(curPackage, structDecl, codeBody, imports)
+		codeBody.WriteString("\n")
+		fieldId = 0
+		generateDecode(curPackage, structDecl, codeBody, imports)
+		codeBodies = append(codeBodies, codeBody)
+		generateRegistry(structDecl, codeBody, initCodeBody, imports)
+	}
+
+	if len(codeBodies) == 0 {
+		return nil, nil
+	}
+
+	initCodeBody.WriteString("}\n\n")
+
+	fmt.Fprintln(&b, strings.Join(slices.Sorted(maps.Keys(imports)), "\n"))
+	fmt.Fprintln(&b, ")")
+	fmt.Fprintf(&b, initCodeBody.String())
+	for _, codeBody := range codeBodies {
+		fmt.Fprintf(&b, codeBody.String())
+		fmt.Fprintln(&b)
+	}
+
+	out, err := format.Source(b.Bytes())
+	if err != nil {
+		return nil, fmt.Errorf("source format error: %w", err)
+	}
+
+	return out, nil
+}
+
+// expectContents verifies the that file contains the given bytes, returning an error that describes
+// how to fix the problem if it does not.
+func expectContents(file string, expected []byte) error {
+	actual, err := os.ReadFile(file)
+	if os.IsNotExist(err) {
+		return fmt.Errorf("generated file %s does not exist, rerun `go generate` in %s",
+			file, filepath.Dir(file))
+	}
+	if err != nil {
+		return err
+	}
+
+	if len(expected) == 0 {
+		return fmt.Errorf("found unexpected generated file %s, delete it", file)
+	}
+
+	if !bytes.Equal(actual, expected) {
+		return fmt.Errorf("generated file %s has out of date contents, rerun `go generate` in %s",
+			file, filepath.Dir(file))
+	}
+
+	return nil
+}
+
+// expectNotExist verifies that the file does not exist, returning an error that describes how to
+// fix the problem if it does.
+func expectNotExist(file string) error {
+	_, err := os.Stat(file)
+	if os.IsNotExist(err) {
+		return nil
+	}
+	if err != nil {
+		return err
+	}
+	return fmt.Errorf("expected %s to not exist, delete it", file)
+}
diff --git a/gobtools/codegen/gob_gen_test.go b/gobtools/codegen/gob_gen_test.go
new file mode 100644
index 0000000..b741dc9
--- /dev/null
+++ b/gobtools/codegen/gob_gen_test.go
@@ -0,0 +1,150 @@
+// Copyright 2025 Google Inc. All rights reserved.
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
+package main
+
+import (
+	"bytes"
+	"reflect"
+	"testing"
+
+	"github.com/google/blueprint/depset"
+	"github.com/google/blueprint/gobtools"
+	"github.com/google/blueprint/gobtools/test"
+	"github.com/google/blueprint/uniquelist"
+)
+
+func TestPathGobEncDec(t *testing.T) {
+	strValue := "string value for test"
+	defaultEcho := TestEcho{"111111111"}
+	transString := depset.New(depset.PREORDER, []string{"111111111"}, nil)
+	depsetString := depset.New(depset.PREORDER, []string{"222222222"}, []depset.DepSet[string]{transString})
+	transTestEcho := depset.New(depset.PREORDER, []TestEcho{defaultEcho}, nil)
+	depsetTestEcho := depset.New(depset.PREORDER, []TestEcho{defaultEcho}, []depset.DepSet[TestEcho]{transTestEcho})
+	transTestEchoInterface := depset.New(depset.PREORDER, []TestEchoInterface{defaultEcho}, nil)
+	depsetTestEchoInterface := depset.New(depset.PREORDER, []TestEchoInterface{defaultEcho}, []depset.DepSet[TestEchoInterface]{transTestEchoInterface})
+	testCases := []struct {
+		name    string
+		origin  gobtools.CustomEnc
+		decoded gobtools.CustomDec
+	}{
+		{
+			name:    "TestStruct with default values",
+			origin:  &TestStruct{},
+			decoded: &TestStruct{},
+		},
+		{
+			name: "TestStruct with value interface",
+			origin: &TestStruct{
+				f18: TestEcho{"aaaa"},
+				f21: uniquelist.Make([]TestEchoInterface{defaultEcho}),
+				f24: test.TypeStruct{Name: "fffffffff"},
+			},
+			decoded: &TestStruct{},
+		},
+		{
+			name: "TestStruct",
+			origin: &TestStruct{
+				TestEcho: TestEcho{"222222222"},
+				f1:       "333333333",
+				f2:       111,
+				f3:       222,
+				f4:       true,
+				f5:       333,
+				f6:       "444444444",
+				f7:       TestEcho{"444444444"},
+				f8:       444,
+				f9:       555,
+				f10:      666,
+				f11:      []string{"a", "bb", "ccc"},
+				f12: map[string]int{
+					"f12a": 1,
+					"f12b": 2,
+					"f12c": 3,
+				},
+				f13: &strValue,
+				f14: 777,
+				f15: []int{1, 2, 3},
+				f16: []TestEcho{
+					{"555555555"},
+					{"666666666"},
+				},
+				f17: &defaultEcho,
+				f18: &TestEcho{"aaaa"},
+				f19: testStrings{"bbbb", "cccc", "dddd"},
+				f20: uniquelist.Make([]TestEcho{defaultEcho}),
+				f21: uniquelist.Make([]TestEchoInterface{&defaultEcho}),
+				f22: test.TypeStruct{Name: "aaaaaaaaa"},
+				f23: []test.TypeAlias{
+					{
+						{Name: "bbbbbbbbb"},
+						{Name: "ccccccccc"},
+					},
+					{
+						{Name: "ddddddddd"},
+						{Name: "eeeeeeeee"},
+					},
+				},
+				f24: &test.TypeStruct{Name: "fffffffff"},
+				f25: test.TypeIdent{Name: "ggggggggg"},
+				f26: depsetTestEcho,
+				f27: depsetTestEchoInterface,
+				f28: map[int][]string{
+					1: {"aaaaaaaaa", "bbbbbbbbb"},
+					2: {"ccccccccc", "ddddddddd"},
+				},
+				f29: [][]string{
+					{"aaaaaaaaa", "bbbbbbbbb"},
+					{"ccccccccc", "ddddddddd"},
+				},
+				f30: depsetString,
+				f31: &defaultEcho,
+			},
+			decoded: &TestStruct{},
+		},
+		{
+			name:    "testEchos",
+			origin:  &testEchos{defaultEcho},
+			decoded: &testEchos{},
+		},
+		{
+			name: "testStringMap",
+			origin: &testStringMap{
+				"111111111": []string{"222222222", "333333333"},
+				"222222222": []string{"444444444", "555555555"},
+			},
+			decoded: &testStringMap{},
+		},
+		{
+			name: "testEchoMap",
+			origin: &testEchoMap{
+				defaultEcho: &TestEcho{"aaaaaaaaa"},
+			},
+			decoded: &testEchoMap{},
+		},
+	}
+
+	for _, tc := range testCases {
+		buf := new(bytes.Buffer)
+		if err := tc.origin.Encode(buf); err != nil {
+			t.Errorf("failed to encode %s: %v", tc.name, err)
+		}
+		if err := tc.decoded.Decode(bytes.NewReader(buf.Bytes())); err != nil {
+			t.Errorf("failed to decode %s: %v", tc.name, err)
+		}
+		if !reflect.DeepEqual(tc.origin, tc.decoded) {
+			t.Errorf("the decoded data is different from the origin: expected:\n  %#v\n got:\n  %#v", tc.origin, tc.decoded)
+		}
+	}
+}
diff --git a/gobtools/codegen/gob_test_data.go b/gobtools/codegen/gob_test_data.go
new file mode 100644
index 0000000..1b6ab73
--- /dev/null
+++ b/gobtools/codegen/gob_test_data.go
@@ -0,0 +1,83 @@
+// Copyright 2025 Google Inc. All rights reserved.
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
+package main
+
+import (
+	"github.com/google/blueprint/depset"
+	"github.com/google/blueprint/gobtools/test"
+	"github.com/google/blueprint/uniquelist"
+)
+
+//go:generate go run gob_gen.go
+
+type TestEchoInterface interface {
+	EchoTest(string) string
+}
+
+// @auto-generate: gob
+type TestStruct struct {
+	TestEcho
+	f1  string
+	f2  int16
+	f3  int32
+	f4  bool
+	f5  int64
+	f6  string
+	f7  TestEcho
+	f8  uint16
+	f9  uint32
+	f10 uint64
+	f11 []string
+	f12 map[string]int
+	f13 *string
+	f14 int
+	f15 []int
+	f16 []TestEcho
+	f17 *TestEcho
+	f18 TestEchoInterface
+	f19 testStrings
+	f20 uniquelist.UniqueList[TestEcho]
+	f21 uniquelist.UniqueList[TestEchoInterface]
+	f22 test.TypeStruct
+	f23 []test.TypeAlias
+	f24 test.TypeInterface
+	f25 test.TypeIdent
+	f26 depset.DepSet[TestEcho]
+	f27 depset.DepSet[TestEchoInterface]
+	f28 map[int][]string
+	f29 [][]string
+	f30 depset.DepSet[string]
+	f31 any
+}
+
+type testStrings []string
+
+// @auto-generate: gob
+type TestEcho struct {
+	EchoStr string
+}
+
+func (t TestEcho) EchoTest(string) string {
+	return t.EchoStr
+}
+
+// @auto-generate: gob
+type testEchos []TestEchoInterface
+
+// @auto-generate: gob
+type testStringMap map[string][]string
+
+// @auto-generate: gob
+type testEchoMap map[TestEcho]*TestEcho
diff --git a/gobtools/codegen/gob_test_data_gob_enc.go b/gobtools/codegen/gob_test_data_gob_enc.go
new file mode 100644
index 0000000..f20eca4
--- /dev/null
+++ b/gobtools/codegen/gob_test_data_gob_enc.go
@@ -0,0 +1,782 @@
+// Code generated by go run gob_gen.go; DO NOT EDIT.
+
+package main
+
+import (
+	"bytes"
+	"github.com/google/blueprint/gobtools"
+	"github.com/google/blueprint/gobtools/test"
+	"github.com/google/blueprint/uniquelist"
+)
+
+func init() {
+	TestStructGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(TestStruct) })
+	TestEchoGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(TestEcho) })
+	testEchosGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(testEchos) })
+	testStringMapGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(testStringMap) })
+	testEchoMapGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(testEchoMap) })
+}
+
+func (r TestStruct) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = r.TestEcho.Encode(buf); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeString(buf, r.f1); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, r.f2); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, r.f3); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, r.f4); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, r.f5); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeString(buf, r.f6); err != nil {
+		return err
+	}
+
+	if err = r.f7.Encode(buf); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, r.f8); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, r.f9); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, r.f10); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.f11))); err != nil {
+		return err
+	}
+	for val1 := 0; val1 < len(r.f11); val1++ {
+		if err = gobtools.EncodeString(buf, r.f11[val1]); err != nil {
+			return err
+		}
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.f12))); err != nil {
+		return err
+	}
+	for k, v := range r.f12 {
+		if err = gobtools.EncodeString(buf, k); err != nil {
+			return err
+		}
+		if err = gobtools.EncodeSimple(buf, int64(v)); err != nil {
+			return err
+		}
+	}
+
+	val2 := r.f13 == nil
+	if err = gobtools.EncodeSimple(buf, val2); err != nil {
+		return err
+	}
+	if !val2 {
+		if err = gobtools.EncodeString(buf, (*r.f13)); err != nil {
+			return err
+		}
+	}
+
+	if err = gobtools.EncodeSimple(buf, int64(r.f14)); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.f15))); err != nil {
+		return err
+	}
+	for val3 := 0; val3 < len(r.f15); val3++ {
+		if err = gobtools.EncodeSimple(buf, int64(r.f15[val3])); err != nil {
+			return err
+		}
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.f16))); err != nil {
+		return err
+	}
+	for val4 := 0; val4 < len(r.f16); val4++ {
+		if err = r.f16[val4].Encode(buf); err != nil {
+			return err
+		}
+	}
+
+	val5 := r.f17 == nil
+	if err = gobtools.EncodeSimple(buf, val5); err != nil {
+		return err
+	}
+	if !val5 {
+		if err = (*r.f17).Encode(buf); err != nil {
+			return err
+		}
+	}
+
+	if err = gobtools.EncodeInterface(buf, r.f18); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.f19))); err != nil {
+		return err
+	}
+	for val6 := 0; val6 < len(r.f19); val6++ {
+		if err = gobtools.EncodeString(buf, r.f19[val6]); err != nil {
+			return err
+		}
+	}
+
+	val7 := r.f20.ToSlice()
+	if err = gobtools.EncodeSimple(buf, int32(len(val7))); err != nil {
+		return err
+	}
+	for val8 := 0; val8 < len(val7); val8++ {
+		if err = val7[val8].Encode(buf); err != nil {
+			return err
+		}
+	}
+
+	val9 := r.f21.ToSlice()
+	if err = gobtools.EncodeSimple(buf, int32(len(val9))); err != nil {
+		return err
+	}
+	for val10 := 0; val10 < len(val9); val10++ {
+		if err = gobtools.EncodeInterface(buf, val9[val10]); err != nil {
+			return err
+		}
+	}
+
+	if err = r.f22.Encode(buf); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.f23))); err != nil {
+		return err
+	}
+	for val11 := 0; val11 < len(r.f23); val11++ {
+		if err = gobtools.EncodeSimple(buf, int32(len(r.f23[val11]))); err != nil {
+			return err
+		}
+		for val12 := 0; val12 < len(r.f23[val11]); val12++ {
+			if err = r.f23[val11][val12].Encode(buf); err != nil {
+				return err
+			}
+		}
+	}
+
+	if err = gobtools.EncodeInterface(buf, r.f24); err != nil {
+		return err
+	}
+
+	if err = test.TypeStruct(r.f25).Encode(buf); err != nil {
+		return err
+	}
+
+	if err = r.f26.Encode(buf); err != nil {
+		return err
+	}
+
+	if err = r.f27.EncodeInterface(buf); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.f28))); err != nil {
+		return err
+	}
+	for k, v := range r.f28 {
+		if err = gobtools.EncodeSimple(buf, int64(k)); err != nil {
+			return err
+		}
+		if err = gobtools.EncodeSimple(buf, int32(len(v))); err != nil {
+			return err
+		}
+		for val13 := 0; val13 < len(v); val13++ {
+			if err = gobtools.EncodeString(buf, v[val13]); err != nil {
+				return err
+			}
+		}
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.f29))); err != nil {
+		return err
+	}
+	for val14 := 0; val14 < len(r.f29); val14++ {
+		if err = gobtools.EncodeSimple(buf, int32(len(r.f29[val14]))); err != nil {
+			return err
+		}
+		for val15 := 0; val15 < len(r.f29[val14]); val15++ {
+			if err = gobtools.EncodeString(buf, r.f29[val14][val15]); err != nil {
+				return err
+			}
+		}
+	}
+
+	if err = r.f30.EncodeString(buf); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeInterface(buf, r.f31); err != nil {
+		return err
+	}
+	return err
+}
+
+func (r *TestStruct) Decode(buf *bytes.Reader) error {
+	var err error
+
+	if err = r.TestEcho.Decode(buf); err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeString(buf, &r.f1)
+	if err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeSimple[int16](buf, &r.f2)
+	if err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeSimple[int32](buf, &r.f3)
+	if err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeSimple[bool](buf, &r.f4)
+	if err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeSimple[int64](buf, &r.f5)
+	if err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeString(buf, &r.f6)
+	if err != nil {
+		return err
+	}
+
+	if err = r.f7.Decode(buf); err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeSimple[uint16](buf, &r.f8)
+	if err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeSimple[uint32](buf, &r.f9)
+	if err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeSimple[uint64](buf, &r.f10)
+	if err != nil {
+		return err
+	}
+
+	var val13 int32
+	err = gobtools.DecodeSimple[int32](buf, &val13)
+	if err != nil {
+		return err
+	}
+	if val13 > 0 {
+		r.f11 = make([]string, val13)
+		for val14 := 0; val14 < int(val13); val14++ {
+			err = gobtools.DecodeString(buf, &r.f11[val14])
+			if err != nil {
+				return err
+			}
+		}
+	}
+
+	var val16 int32
+	err = gobtools.DecodeSimple[int32](buf, &val16)
+	if err != nil {
+		return err
+	}
+	if val16 > 0 {
+		r.f12 = make(map[string]int, val16)
+		for val17 := 0; val17 < int(val16); val17++ {
+			var k string
+			var v int
+			err = gobtools.DecodeString(buf, &k)
+			if err != nil {
+				return err
+			}
+			var val19 int64
+			err = gobtools.DecodeSimple[int64](buf, &val19)
+			if err != nil {
+				return err
+			}
+			v = int(val19)
+			r.f12[k] = v
+		}
+	}
+
+	var val21 bool
+	if err = gobtools.DecodeSimple(buf, &val21); err != nil {
+		return err
+	}
+	if !val21 {
+		var val20 string
+		err = gobtools.DecodeString(buf, &val20)
+		if err != nil {
+			return err
+		}
+		r.f13 = &val20
+	}
+
+	var val23 int64
+	err = gobtools.DecodeSimple[int64](buf, &val23)
+	if err != nil {
+		return err
+	}
+	r.f14 = int(val23)
+
+	var val25 int32
+	err = gobtools.DecodeSimple[int32](buf, &val25)
+	if err != nil {
+		return err
+	}
+	if val25 > 0 {
+		r.f15 = make([]int, val25)
+		for val26 := 0; val26 < int(val25); val26++ {
+			var val27 int64
+			err = gobtools.DecodeSimple[int64](buf, &val27)
+			if err != nil {
+				return err
+			}
+			r.f15[val26] = int(val27)
+		}
+	}
+
+	var val29 int32
+	err = gobtools.DecodeSimple[int32](buf, &val29)
+	if err != nil {
+		return err
+	}
+	if val29 > 0 {
+		r.f16 = make([]TestEcho, val29)
+		for val30 := 0; val30 < int(val29); val30++ {
+			if err = r.f16[val30].Decode(buf); err != nil {
+				return err
+			}
+		}
+	}
+
+	var val33 bool
+	if err = gobtools.DecodeSimple(buf, &val33); err != nil {
+		return err
+	}
+	if !val33 {
+		var val32 TestEcho
+		if err = val32.Decode(buf); err != nil {
+			return err
+		}
+		r.f17 = &val32
+	}
+
+	if val36, err := gobtools.DecodeInterface(buf); err != nil {
+		return err
+	} else if val36 == nil {
+		r.f18 = nil
+	} else {
+		r.f18 = val36.(TestEchoInterface)
+	}
+
+	var val39 int32
+	err = gobtools.DecodeSimple[int32](buf, &val39)
+	if err != nil {
+		return err
+	}
+	if val39 > 0 {
+		r.f19 = make([]string, val39)
+		for val40 := 0; val40 < int(val39); val40++ {
+			err = gobtools.DecodeString(buf, &r.f19[val40])
+			if err != nil {
+				return err
+			}
+		}
+	}
+
+	var val43 []TestEcho
+	var val44 int32
+	err = gobtools.DecodeSimple[int32](buf, &val44)
+	if err != nil {
+		return err
+	}
+	if val44 > 0 {
+		val43 = make([]TestEcho, val44)
+		for val45 := 0; val45 < int(val44); val45++ {
+			if err = val43[val45].Decode(buf); err != nil {
+				return err
+			}
+		}
+	}
+	r.f20 = uniquelist.Make(val43)
+
+	var val48 []TestEchoInterface
+	var val49 int32
+	err = gobtools.DecodeSimple[int32](buf, &val49)
+	if err != nil {
+		return err
+	}
+	if val49 > 0 {
+		val48 = make([]TestEchoInterface, val49)
+		for val50 := 0; val50 < int(val49); val50++ {
+			if val52, err := gobtools.DecodeInterface(buf); err != nil {
+				return err
+			} else if val52 == nil {
+				val48[val50] = nil
+			} else {
+				val48[val50] = val52.(TestEchoInterface)
+			}
+		}
+	}
+	r.f21 = uniquelist.Make(val48)
+
+	if err = r.f22.Decode(buf); err != nil {
+		return err
+	}
+
+	var val55 int32
+	err = gobtools.DecodeSimple[int32](buf, &val55)
+	if err != nil {
+		return err
+	}
+	if val55 > 0 {
+		r.f23 = make([]test.TypeAlias, val55)
+		for val56 := 0; val56 < int(val55); val56++ {
+			var val59 int32
+			err = gobtools.DecodeSimple[int32](buf, &val59)
+			if err != nil {
+				return err
+			}
+			if val59 > 0 {
+				r.f23[val56] = make([]test.TypeStruct, val59)
+				for val60 := 0; val60 < int(val59); val60++ {
+					if err = r.f23[val56][val60].Decode(buf); err != nil {
+						return err
+					}
+				}
+			}
+		}
+	}
+
+	if val63, err := gobtools.DecodeInterface(buf); err != nil {
+		return err
+	} else if val63 == nil {
+		r.f24 = nil
+	} else {
+		r.f24 = val63.(test.TypeInterface)
+	}
+
+	var val65 test.TypeStruct
+	if err = val65.Decode(buf); err != nil {
+		return err
+	}
+	r.f25 = test.TypeIdent(val65)
+
+	if err = r.f26.Decode(buf); err != nil {
+		return err
+	}
+
+	if err = r.f27.DecodeInterface(buf); err != nil {
+		return err
+	}
+
+	var val69 int32
+	err = gobtools.DecodeSimple[int32](buf, &val69)
+	if err != nil {
+		return err
+	}
+	if val69 > 0 {
+		r.f28 = make(map[int][]string, val69)
+		for val70 := 0; val70 < int(val69); val70++ {
+			var k int
+			var v []string
+			var val71 int64
+			err = gobtools.DecodeSimple[int64](buf, &val71)
+			if err != nil {
+				return err
+			}
+			k = int(val71)
+			var val73 int32
+			err = gobtools.DecodeSimple[int32](buf, &val73)
+			if err != nil {
+				return err
+			}
+			if val73 > 0 {
+				v = make([]string, val73)
+				for val74 := 0; val74 < int(val73); val74++ {
+					err = gobtools.DecodeString(buf, &v[val74])
+					if err != nil {
+						return err
+					}
+				}
+			}
+			r.f28[k] = v
+		}
+	}
+
+	var val77 int32
+	err = gobtools.DecodeSimple[int32](buf, &val77)
+	if err != nil {
+		return err
+	}
+	if val77 > 0 {
+		r.f29 = make([][]string, val77)
+		for val78 := 0; val78 < int(val77); val78++ {
+			var val80 int32
+			err = gobtools.DecodeSimple[int32](buf, &val80)
+			if err != nil {
+				return err
+			}
+			if val80 > 0 {
+				r.f29[val78] = make([]string, val80)
+				for val81 := 0; val81 < int(val80); val81++ {
+					err = gobtools.DecodeString(buf, &r.f29[val78][val81])
+					if err != nil {
+						return err
+					}
+				}
+			}
+		}
+	}
+
+	if err = r.f30.DecodeString(buf); err != nil {
+		return err
+	}
+
+	if val85, err := gobtools.DecodeInterface(buf); err != nil {
+		return err
+	} else if val85 == nil {
+		r.f31 = nil
+	} else {
+		r.f31 = val85
+	}
+
+	return err
+}
+
+var TestStructGobRegId int16
+
+func (r TestStruct) GetTypeId() int16 {
+	return TestStructGobRegId
+}
+
+func (r TestEcho) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeString(buf, r.EchoStr); err != nil {
+		return err
+	}
+	return err
+}
+
+func (r *TestEcho) Decode(buf *bytes.Reader) error {
+	var err error
+
+	err = gobtools.DecodeString(buf, &r.EchoStr)
+	if err != nil {
+		return err
+	}
+
+	return err
+}
+
+var TestEchoGobRegId int16
+
+func (r TestEcho) GetTypeId() int16 {
+	return TestEchoGobRegId
+}
+
+func (r testEchos) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r))); err != nil {
+		return err
+	}
+	for val1 := 0; val1 < len(r); val1++ {
+		if err = gobtools.EncodeInterface(buf, r[val1]); err != nil {
+			return err
+		}
+	}
+	return err
+}
+
+func (r *testEchos) Decode(buf *bytes.Reader) error {
+	var err error
+
+	var val2 int32
+	err = gobtools.DecodeSimple[int32](buf, &val2)
+	if err != nil {
+		return err
+	}
+	if val2 > 0 {
+		(*r) = make([]TestEchoInterface, val2)
+		for val3 := 0; val3 < int(val2); val3++ {
+			if val5, err := gobtools.DecodeInterface(buf); err != nil {
+				return err
+			} else if val5 == nil {
+				(*r)[val3] = nil
+			} else {
+				(*r)[val3] = val5.(TestEchoInterface)
+			}
+		}
+	}
+
+	return err
+}
+
+var testEchosGobRegId int16
+
+func (r testEchos) GetTypeId() int16 {
+	return testEchosGobRegId
+}
+
+func (r testStringMap) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r))); err != nil {
+		return err
+	}
+	for k, v := range r {
+		if err = gobtools.EncodeString(buf, k); err != nil {
+			return err
+		}
+		if err = gobtools.EncodeSimple(buf, int32(len(v))); err != nil {
+			return err
+		}
+		for val1 := 0; val1 < len(v); val1++ {
+			if err = gobtools.EncodeString(buf, v[val1]); err != nil {
+				return err
+			}
+		}
+	}
+	return err
+}
+
+func (r *testStringMap) Decode(buf *bytes.Reader) error {
+	var err error
+
+	var val1 int32
+	err = gobtools.DecodeSimple[int32](buf, &val1)
+	if err != nil {
+		return err
+	}
+	if val1 > 0 {
+		(*r) = make(map[string][]string, val1)
+		for val2 := 0; val2 < int(val1); val2++ {
+			var k string
+			var v []string
+			err = gobtools.DecodeString(buf, &k)
+			if err != nil {
+				return err
+			}
+			var val5 int32
+			err = gobtools.DecodeSimple[int32](buf, &val5)
+			if err != nil {
+				return err
+			}
+			if val5 > 0 {
+				v = make([]string, val5)
+				for val6 := 0; val6 < int(val5); val6++ {
+					err = gobtools.DecodeString(buf, &v[val6])
+					if err != nil {
+						return err
+					}
+				}
+			}
+			(*r)[k] = v
+		}
+	}
+
+	return err
+}
+
+var testStringMapGobRegId int16
+
+func (r testStringMap) GetTypeId() int16 {
+	return testStringMapGobRegId
+}
+
+func (r testEchoMap) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r))); err != nil {
+		return err
+	}
+	for k, v := range r {
+		if err = k.Encode(buf); err != nil {
+			return err
+		}
+		val1 := v == nil
+		if err = gobtools.EncodeSimple(buf, val1); err != nil {
+			return err
+		}
+		if !val1 {
+			if err = (*v).Encode(buf); err != nil {
+				return err
+			}
+		}
+	}
+	return err
+}
+
+func (r *testEchoMap) Decode(buf *bytes.Reader) error {
+	var err error
+
+	var val1 int32
+	err = gobtools.DecodeSimple[int32](buf, &val1)
+	if err != nil {
+		return err
+	}
+	if val1 > 0 {
+		(*r) = make(map[TestEcho]*TestEcho, val1)
+		for val2 := 0; val2 < int(val1); val2++ {
+			var k TestEcho
+			var v *TestEcho
+			if err = k.Decode(buf); err != nil {
+				return err
+			}
+			var val5 bool
+			if err = gobtools.DecodeSimple(buf, &val5); err != nil {
+				return err
+			}
+			if !val5 {
+				var val4 TestEcho
+				if err = val4.Decode(buf); err != nil {
+					return err
+				}
+				v = &val4
+			}
+			(*r)[k] = v
+		}
+	}
+
+	return err
+}
+
+var testEchoMapGobRegId int16
+
+func (r testEchoMap) GetTypeId() int16 {
+	return testEchoMapGobRegId
+}
diff --git a/gobtools/gob_tools.go b/gobtools/gob_tools.go
index f45c364..3d986e9 100644
--- a/gobtools/gob_tools.go
+++ b/gobtools/gob_tools.go
@@ -16,34 +16,171 @@ package gobtools
 
 import (
 	"bytes"
-	"encoding/gob"
+	"encoding/binary"
+	"fmt"
+	"io"
+	"reflect"
 )
 
+// To decode an interface type, we need to store the info about the underlying
+// concreate type of the value during encoding. When decoding we will use that
+// info and the registry map below to recreate a default value of the concrete
+// type and then deserialize the stored data into it.
+var typeRegistry = make(map[int16]func() CustomDec)
+
+// Enum to represent the underlying type of the interface field.
+type interfaceType int16
+
+const (
+	nilInterface interfaceType = iota
+	nilPointerInterface
+	pointerInterface
+	valueInterface
+)
+
+var typeRegId int16 = 0
+
+// RegisterType registers a concrete type with the type registry, this method should
+// be called from an init() function in the package. It incrementally generates an id
+// and return to the caller, when encoding an instance of the struct, the id is stored
+// along with the actual value of the instance. During decoding the stored id is
+// used to look up the function to initiate a default instance of the struct.
+func RegisterType(creator func() CustomDec) int16 {
+	typeRegId++
+	typeRegistry[typeRegId] = creator
+	return typeRegId
+}
+
+// Interface indicates the struct provides custom encoding logic either thru
+// code generation or manual coding.
+type CustomEnc interface {
+	Encode(buf *bytes.Buffer) error
+	GetTypeId() int16
+}
+
+// Interface indicates the struct provides custom decoding logic either thru
+// code generation or manual coding
+type CustomDec interface {
+	Decode(buf *bytes.Reader) error
+}
+
+// Legacy way to provide custom Gob encoding and decoding logic.
 type CustomGob[T any] interface {
 	ToGob() *T
 	FromGob(data *T)
 }
 
-func CustomGobEncode[T any](cg CustomGob[T]) ([]byte, error) {
-	w := new(bytes.Buffer)
-	encoder := gob.NewEncoder(w)
-	err := encoder.Encode(cg.ToGob())
+// Encode a string value.
+func EncodeString(buf *bytes.Buffer, s string) error {
+	b := []byte(s)
+	err := binary.Write(buf, binary.BigEndian, int32(len(b)))
 	if err != nil {
-		return nil, err
+		return err
 	}
-
-	return w.Bytes(), nil
+	_, err = buf.Write(b)
+	return err
 }
 
-func CustomGobDecode[T any](data []byte, cg CustomGob[T]) error {
-	r := bytes.NewBuffer(data)
-	var value T
-	decoder := gob.NewDecoder(r)
-	err := decoder.Decode(&value)
+// Decode a string value.
+func DecodeString(buf *bytes.Reader, s *string) error {
+	var length int32
+	err := binary.Read(buf, binary.BigEndian, &length)
 	if err != nil {
 		return err
 	}
-	cg.FromGob(&value)
+	b := make([]byte, length)
+	_, err = io.ReadFull(buf, b)
+	if err == nil {
+		*s = string(b)
+	}
+
+	return err
+}
+
+// These two methods can be further optimized using primitive specific encoding
+// and decoding methods if it becomes necessary.
 
-	return nil
+// Encode a primitive value.
+func EncodeSimple[T any](buf *bytes.Buffer, b T) error {
+	return binary.Write(buf, binary.BigEndian, b)
+}
+
+// Decode a primitive value.
+func DecodeSimple[T any](buf *bytes.Reader, data *T) error {
+	return binary.Read(buf, binary.BigEndian, data)
+}
+
+// Encode a struct. It uses type assert to leverage Gob to encode the value when
+// the struct hasn't be converted to use codegen to generate encoding logic, this
+// should be removed once all are converted.
+func EncodeStruct(buf *bytes.Buffer, val any) error {
+	// val is pointer to either a struct or an interface{}. If it is the latter the
+	// type assert below will fail even if the underlying concrete type implements
+	// the CustomEnc interface. This is intentional in order for ob to handle the
+	// interface case, where it will store the interface info and is albe to properly
+	// deserialize it later. Otherwise, it will be serialized as a concrete type,
+	// then later it can't be deserialized back to an interface field.
+	if encdec, ok := val.(CustomEnc); ok {
+		return encdec.Encode(buf)
+	} else {
+		panic(fmt.Errorf("encoding type is not supported: %T", val))
+	}
+}
+
+// Encode an interface value.
+func EncodeInterface(buf *bytes.Buffer, data any) error {
+	if data == nil {
+		return EncodeSimple(buf, nilInterface)
+	}
+	intfType := valueInterface
+	if v := reflect.ValueOf(data); v.Kind() == reflect.Ptr {
+		if v.IsNil() {
+			return fmt.Errorf("nil pointer is not supported in EncodeInterface")
+		} else {
+			intfType = pointerInterface
+		}
+	}
+	if err := EncodeSimple(buf, intfType); err != nil {
+		return err
+	}
+	val := data.(CustomEnc)
+	if err := EncodeSimple(buf, val.GetTypeId()); err != nil {
+		return err
+	}
+	return val.Encode(buf)
+}
+
+// Decode a struct. It uses type assert to leverage Gob to decode the value when
+// the struct hasn't be converted to use codegen to generate decoding logic, this
+// should be removed once all are converted
+func DecodeStruct(buf *bytes.Reader, data any) error {
+	if encdec, ok := data.(CustomDec); ok {
+		return encdec.Decode(buf)
+	} else {
+		panic(fmt.Errorf("decoding type is not supported: %T", data))
+	}
+}
+
+// Decode an interface value.
+func DecodeInterface(buf *bytes.Reader) (any, error) {
+	var intfType interfaceType
+	if err := DecodeSimple(buf, &intfType); err != nil || intfType == nilInterface {
+		return nil, err
+	}
+	var typeId int16
+	if err := DecodeSimple(buf, &typeId); err != nil {
+		return nil, err
+	}
+	if f, ok := typeRegistry[typeId]; !ok {
+		return nil, fmt.Errorf("type not registered: %d", typeId)
+	} else {
+		val := f()
+		if err := val.Decode(buf); err != nil {
+			return nil, err
+		} else if intfType == valueInterface {
+			return reflect.ValueOf(val).Elem().Interface(), nil
+		} else {
+			return val, nil
+		}
+	}
 }
diff --git a/gobtools/test/Android.bp b/gobtools/test/Android.bp
new file mode 100644
index 0000000..0f7fab5
--- /dev/null
+++ b/gobtools/test/Android.bp
@@ -0,0 +1,14 @@
+bootstrap_go_package {
+    name: "blueprint-gobtools-test",
+    pkgPath: "github.com/google/blueprint/gobtools/test",
+    srcs: [
+        "test_package.go",
+        "test_package_gob_enc.go",
+    ],
+    visibility: [
+        "//visibility:public",
+    ],
+    deps: [
+        "blueprint-gobtools",
+    ],
+}
diff --git a/gobtools/test/test_package.go b/gobtools/test/test_package.go
new file mode 100644
index 0000000..502d4b8
--- /dev/null
+++ b/gobtools/test/test_package.go
@@ -0,0 +1,20 @@
+package test
+
+//go:generate go run ../codegen/gob_gen.go
+
+type TypeAlias = []TypeStruct
+
+type TypeIdent TypeStruct
+
+type TypeInterface interface {
+	print(value string) string
+}
+
+// @auto-generate: gob
+type TypeStruct struct {
+	Name string
+}
+
+func (t TypeStruct) print(value string) string {
+	return value + t.Name
+}
diff --git a/gobtools/test/test_package_gob_enc.go b/gobtools/test/test_package_gob_enc.go
new file mode 100644
index 0000000..ed76696
--- /dev/null
+++ b/gobtools/test/test_package_gob_enc.go
@@ -0,0 +1,38 @@
+// Code generated by go run gob_gen.go; DO NOT EDIT.
+
+package test
+
+import (
+	"bytes"
+	"github.com/google/blueprint/gobtools"
+)
+
+func init() {
+	TypeStructGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(TypeStruct) })
+}
+
+func (r TypeStruct) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeString(buf, r.Name); err != nil {
+		return err
+	}
+	return err
+}
+
+func (r *TypeStruct) Decode(buf *bytes.Reader) error {
+	var err error
+
+	err = gobtools.DecodeString(buf, &r.Name)
+	if err != nil {
+		return err
+	}
+
+	return err
+}
+
+var TypeStructGobRegId int16
+
+func (r TypeStruct) GetTypeId() int16 {
+	return TypeStructGobRegId
+}
diff --git a/incremental.go b/incremental.go
index e4f8c2a..95ff96d 100644
--- a/incremental.go
+++ b/incremental.go
@@ -14,28 +14,31 @@
 
 package blueprint
 
-import (
-	"text/scanner"
-)
+//go:generate go run gobtools/codegen/gob_gen.go
 
+// @auto-generate: gob
 type BuildActionCacheKey struct {
 	Id        string
 	InputHash uint64
 }
 
+// @auto-generate: gob
 type CachedProvider struct {
 	Id    *providerKey
 	Value *any
 }
 
+// @auto-generate: gob
 type BuildActionCachedData struct {
 	Providers        []CachedProvider
-	Pos              *scanner.Position
 	OrderOnlyStrings []string
+	GlobCache        []globResultCache
 }
 
-type BuildActionCache = map[BuildActionCacheKey]*BuildActionCachedData
+// @auto-generate: gob
+type BuildActionCache map[BuildActionCacheKey]*BuildActionCachedData
 
+// @auto-generate: gob
 type OrderOnlyStringsCache map[string][]string
 
 type BuildActionCacheInput struct {
diff --git a/incremental_gob_enc.go b/incremental_gob_enc.go
new file mode 100644
index 0000000..ab1cbed
--- /dev/null
+++ b/incremental_gob_enc.go
@@ -0,0 +1,332 @@
+// Code generated by go run gob_gen.go; DO NOT EDIT.
+
+package blueprint
+
+import (
+	"bytes"
+	"github.com/google/blueprint/gobtools"
+)
+
+func init() {
+	BuildActionCacheKeyGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(BuildActionCacheKey) })
+	CachedProviderGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(CachedProvider) })
+	BuildActionCachedDataGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(BuildActionCachedData) })
+	BuildActionCacheGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(BuildActionCache) })
+	OrderOnlyStringsCacheGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(OrderOnlyStringsCache) })
+}
+
+func (r BuildActionCacheKey) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeString(buf, r.Id); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeSimple(buf, r.InputHash); err != nil {
+		return err
+	}
+	return err
+}
+
+func (r *BuildActionCacheKey) Decode(buf *bytes.Reader) error {
+	var err error
+
+	err = gobtools.DecodeString(buf, &r.Id)
+	if err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeSimple[uint64](buf, &r.InputHash)
+	if err != nil {
+		return err
+	}
+
+	return err
+}
+
+var BuildActionCacheKeyGobRegId int16
+
+func (r BuildActionCacheKey) GetTypeId() int16 {
+	return BuildActionCacheKeyGobRegId
+}
+
+func (r CachedProvider) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	val1 := r.Id == nil
+	if err = gobtools.EncodeSimple(buf, val1); err != nil {
+		return err
+	}
+	if !val1 {
+		if err = (*r.Id).Encode(buf); err != nil {
+			return err
+		}
+	}
+
+	val2 := r.Value == nil
+	if err = gobtools.EncodeSimple(buf, val2); err != nil {
+		return err
+	}
+	if !val2 {
+		if err = gobtools.EncodeInterface(buf, (*r.Value)); err != nil {
+			return err
+		}
+	}
+	return err
+}
+
+func (r *CachedProvider) Decode(buf *bytes.Reader) error {
+	var err error
+
+	var val2 bool
+	if err = gobtools.DecodeSimple(buf, &val2); err != nil {
+		return err
+	}
+	if !val2 {
+		var val1 providerKey
+		if err = val1.Decode(buf); err != nil {
+			return err
+		}
+		r.Id = &val1
+	}
+
+	var val5 bool
+	if err = gobtools.DecodeSimple(buf, &val5); err != nil {
+		return err
+	}
+	if !val5 {
+		var val4 any
+		if val7, err := gobtools.DecodeInterface(buf); err != nil {
+			return err
+		} else if val7 == nil {
+			val4 = nil
+		} else {
+			val4 = val7
+		}
+		r.Value = &val4
+	}
+
+	return err
+}
+
+var CachedProviderGobRegId int16
+
+func (r CachedProvider) GetTypeId() int16 {
+	return CachedProviderGobRegId
+}
+
+func (r BuildActionCachedData) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.Providers))); err != nil {
+		return err
+	}
+	for val1 := 0; val1 < len(r.Providers); val1++ {
+		if err = r.Providers[val1].Encode(buf); err != nil {
+			return err
+		}
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.OrderOnlyStrings))); err != nil {
+		return err
+	}
+	for val2 := 0; val2 < len(r.OrderOnlyStrings); val2++ {
+		if err = gobtools.EncodeString(buf, r.OrderOnlyStrings[val2]); err != nil {
+			return err
+		}
+	}
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r.GlobCache))); err != nil {
+		return err
+	}
+	for val3 := 0; val3 < len(r.GlobCache); val3++ {
+		if err = r.GlobCache[val3].Encode(buf); err != nil {
+			return err
+		}
+	}
+	return err
+}
+
+func (r *BuildActionCachedData) Decode(buf *bytes.Reader) error {
+	var err error
+
+	var val2 int32
+	err = gobtools.DecodeSimple[int32](buf, &val2)
+	if err != nil {
+		return err
+	}
+	if val2 > 0 {
+		r.Providers = make([]CachedProvider, val2)
+		for val3 := 0; val3 < int(val2); val3++ {
+			if err = r.Providers[val3].Decode(buf); err != nil {
+				return err
+			}
+		}
+	}
+
+	var val6 int32
+	err = gobtools.DecodeSimple[int32](buf, &val6)
+	if err != nil {
+		return err
+	}
+	if val6 > 0 {
+		r.OrderOnlyStrings = make([]string, val6)
+		for val7 := 0; val7 < int(val6); val7++ {
+			err = gobtools.DecodeString(buf, &r.OrderOnlyStrings[val7])
+			if err != nil {
+				return err
+			}
+		}
+	}
+
+	var val10 int32
+	err = gobtools.DecodeSimple[int32](buf, &val10)
+	if err != nil {
+		return err
+	}
+	if val10 > 0 {
+		r.GlobCache = make([]globResultCache, val10)
+		for val11 := 0; val11 < int(val10); val11++ {
+			if err = r.GlobCache[val11].Decode(buf); err != nil {
+				return err
+			}
+		}
+	}
+
+	return err
+}
+
+var BuildActionCachedDataGobRegId int16
+
+func (r BuildActionCachedData) GetTypeId() int16 {
+	return BuildActionCachedDataGobRegId
+}
+
+func (r BuildActionCache) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r))); err != nil {
+		return err
+	}
+	for k, v := range r {
+		if err = k.Encode(buf); err != nil {
+			return err
+		}
+		val1 := v == nil
+		if err = gobtools.EncodeSimple(buf, val1); err != nil {
+			return err
+		}
+		if !val1 {
+			if err = (*v).Encode(buf); err != nil {
+				return err
+			}
+		}
+	}
+	return err
+}
+
+func (r *BuildActionCache) Decode(buf *bytes.Reader) error {
+	var err error
+
+	var val1 int32
+	err = gobtools.DecodeSimple[int32](buf, &val1)
+	if err != nil {
+		return err
+	}
+	if val1 > 0 {
+		(*r) = make(map[BuildActionCacheKey]*BuildActionCachedData, val1)
+		for val2 := 0; val2 < int(val1); val2++ {
+			var k BuildActionCacheKey
+			var v *BuildActionCachedData
+			if err = k.Decode(buf); err != nil {
+				return err
+			}
+			var val5 bool
+			if err = gobtools.DecodeSimple(buf, &val5); err != nil {
+				return err
+			}
+			if !val5 {
+				var val4 BuildActionCachedData
+				if err = val4.Decode(buf); err != nil {
+					return err
+				}
+				v = &val4
+			}
+			(*r)[k] = v
+		}
+	}
+
+	return err
+}
+
+var BuildActionCacheGobRegId int16
+
+func (r BuildActionCache) GetTypeId() int16 {
+	return BuildActionCacheGobRegId
+}
+
+func (r OrderOnlyStringsCache) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeSimple(buf, int32(len(r))); err != nil {
+		return err
+	}
+	for k, v := range r {
+		if err = gobtools.EncodeString(buf, k); err != nil {
+			return err
+		}
+		if err = gobtools.EncodeSimple(buf, int32(len(v))); err != nil {
+			return err
+		}
+		for val1 := 0; val1 < len(v); val1++ {
+			if err = gobtools.EncodeString(buf, v[val1]); err != nil {
+				return err
+			}
+		}
+	}
+	return err
+}
+
+func (r *OrderOnlyStringsCache) Decode(buf *bytes.Reader) error {
+	var err error
+
+	var val1 int32
+	err = gobtools.DecodeSimple[int32](buf, &val1)
+	if err != nil {
+		return err
+	}
+	if val1 > 0 {
+		(*r) = make(map[string][]string, val1)
+		for val2 := 0; val2 < int(val1); val2++ {
+			var k string
+			var v []string
+			err = gobtools.DecodeString(buf, &k)
+			if err != nil {
+				return err
+			}
+			var val5 int32
+			err = gobtools.DecodeSimple[int32](buf, &val5)
+			if err != nil {
+				return err
+			}
+			if val5 > 0 {
+				v = make([]string, val5)
+				for val6 := 0; val6 < int(val5); val6++ {
+					err = gobtools.DecodeString(buf, &v[val6])
+					if err != nil {
+						return err
+					}
+				}
+			}
+			(*r)[k] = v
+		}
+	}
+
+	return err
+}
+
+var OrderOnlyStringsCacheGobRegId int16
+
+func (r OrderOnlyStringsCache) GetTypeId() int16 {
+	return OrderOnlyStringsCacheGobRegId
+}
diff --git a/live_tracker.go b/live_tracker.go
index e62dc59..48a2f72 100644
--- a/live_tracker.go
+++ b/live_tracker.go
@@ -143,7 +143,7 @@ func (l *liveTracker) innerAddRule(r Rule) (def *ruleDef, err error) {
 func (l *liveTracker) addPool(p Pool) error {
 	l.Lock()
 	defer l.Unlock()
-	return l.addPool(p)
+	return l.innerAddPool(p)
 }
 
 func (l *liveTracker) innerAddPool(p Pool) error {
diff --git a/module_ctx.go b/module_ctx.go
index a21b102..dd51441 100644
--- a/module_ctx.go
+++ b/module_ctx.go
@@ -15,12 +15,13 @@
 package blueprint
 
 import (
+	"cmp"
+	"encoding/json"
 	"errors"
 	"fmt"
 	"path/filepath"
-	"sort"
+	"slices"
 	"strings"
-	"sync"
 	"text/scanner"
 
 	"github.com/google/blueprint/parser"
@@ -109,31 +110,76 @@ type Module interface {
 	GenerateBuildActions(ModuleContext)
 
 	String() string
+
+	addLoadHook(hook LoadHookWithPriority)
+	getAndClearloadHooks() []LoadHookWithPriority
+
+	info() *moduleInfo
+	setInfo(*moduleInfo)
+}
+
+type ModuleOrProxy interface {
+	info() *moduleInfo
+	Name() string
+	String() string
+}
+
+var _ ModuleOrProxy = (Module)(nil)
+var _ ModuleOrProxy = ModuleProxy{}
+
+type ModuleBase struct {
+	moduleInfo *moduleInfo
+	loadHooks  []LoadHookWithPriority
+}
+
+func (m ModuleBase) info() *moduleInfo {
+	return m.moduleInfo
+}
+
+func (m *ModuleBase) setInfo(moduleInfo *moduleInfo) {
+	m.moduleInfo = moduleInfo
+}
+
+func (m *ModuleBase) addLoadHook(hook LoadHookWithPriority) {
+	m.loadHooks = append(m.loadHooks, hook)
+}
+
+func (m *ModuleBase) getAndClearloadHooks() []LoadHookWithPriority {
+	hooks := m.loadHooks
+	m.loadHooks = nil
+	return hooks
 }
 
 type ModuleProxy struct {
-	module Module
+	moduleInfo *moduleInfo
+}
+
+func (m ModuleProxy) info() *moduleInfo {
+	return m.moduleInfo
 }
 
 func CreateModuleProxy(module Module) ModuleProxy {
 	return ModuleProxy{
-		module: module,
+		moduleInfo: module.info(),
 	}
 }
 
 func (m ModuleProxy) IsNil() bool {
-	return m.module == nil
+	return m.moduleInfo == nil
 }
 
 func (m ModuleProxy) Name() string {
-	return m.module.Name()
+	if m.moduleInfo.logicModule == nil {
+		return m.moduleInfo.cachedName
+	}
+	return m.moduleInfo.logicModule.Name()
 }
 
 func (m ModuleProxy) String() string {
-	return m.module.String()
-}
-func (m ModuleProxy) GenerateBuildActions(context ModuleContext) {
-	m.module.GenerateBuildActions(context)
+	if m.moduleInfo.logicModule == nil {
+		return m.moduleInfo.cachedString
+	}
+	return m.moduleInfo.logicModule.String()
 }
 
 // A DynamicDependerModule is a Module that may add dependencies that do not
@@ -197,7 +243,7 @@ type EarlyModuleContext interface {
 	PropertyErrorf(property, fmt string, args ...interface{})
 
 	// OtherModulePropertyErrorf reports an error at the line number of a property in the given module definition.
-	OtherModulePropertyErrorf(logicModule Module, property string, format string, args ...interface{})
+	OtherModulePropertyErrorf(logicModule ModuleOrProxy, property string, format string, args ...interface{})
 
 	// Failed returns true if any errors have been reported.  In most cases the module can continue with generating
 	// build rules after an error, allowing it to report additional errors in a single run, but in cases where the error
@@ -227,6 +273,7 @@ type EarlyModuleContext interface {
 	// Namespace returns the Namespace object provided by the NameInterface set by Context.SetNameInterface, or the
 	// default SimpleNameInterface if Context.SetNameInterface was not called.
 	Namespace() Namespace
+	OtherModuleNamespace(ModuleOrProxy) Namespace
 
 	// ModuleFactories returns a map of all of the global ModuleFactories by name.
 	ModuleFactories() map[string]ModuleFactory
@@ -243,7 +290,7 @@ type BaseModuleContext interface {
 	// none exists.  It panics if the dependency does not have the specified tag.
 	GetDirectDepWithTag(name string, tag DependencyTag) Module
 
-	GetDirectDepProxyWithTag(name string, tag DependencyTag) *ModuleProxy
+	GetDirectDepProxyWithTag(name string, tag DependencyTag) ModuleProxy
 
 	// VisitDirectDeps calls visit for each direct dependency.  If there are multiple direct dependencies on the same
 	// module visit will be called multiple times on that module and OtherModuleDependencyTag will return a different
@@ -299,6 +346,12 @@ type BaseModuleContext interface {
 	// only done once for all variants of a module.
 	PrimaryModule() Module
 
+	// IsPrimaryModule returns if the current module is the first variant.  Variants of a module are always visited in
+	// order by mutators and GenerateBuildActions, so the data created by the current mutator can be read from the
+	// Module returned by PrimaryModule without data races.  This can be used to perform singleton actions that are
+	// only done once for all variants of a module.
+	IsPrimaryModule(module ModuleOrProxy) bool
+
 	// FinalModule returns the last variant of the current module.  Variants of a module are always visited in
 	// order by mutators and GenerateBuildActions, so the data created by the current mutator can be read from all
 	// variants using VisitAllModuleVariants if the current module == FinalModule().  This can be used to perform
@@ -309,43 +362,31 @@ type BaseModuleContext interface {
 	// order by mutators and GenerateBuildActions, so the data created by the current mutator can be read from all
 	// variants using VisitAllModuleVariants if the current module is the last one.  This can be used to perform
 	// singleton actions that are only done once for all variants of a module.
-	IsFinalModule(module Module) bool
-
-	// VisitAllModuleVariants calls visit for each variant of the current module.  Variants of a module are always
-	// visited in order by mutators and GenerateBuildActions, so the data created by the current mutator can be read
-	// from all variants if the current module is the last one.  Otherwise, care must be taken to not access any
-	// data modified by the current mutator.
-	VisitAllModuleVariants(visit func(Module))
-
-	// VisitAllModuleVariantProxies calls visit for each variant of the current module.  Variants of a module are always
-	// visited in order by mutators and GenerateBuildActions, so the data created by the current mutator can be read
-	// from all variants if the current module is the last one.  Otherwise, care must be taken to not access any
-	// data modified by the current mutator.
-	VisitAllModuleVariantProxies(visit func(proxy ModuleProxy))
+	IsFinalModule(module ModuleOrProxy) bool
 
 	// OtherModuleName returns the name of another Module.  See BaseModuleContext.ModuleName for more information.
 	// It is intended for use inside the visit functions of Visit* and WalkDeps.
-	OtherModuleName(m Module) string
+	OtherModuleName(m ModuleOrProxy) string
 
 	// OtherModuleDir returns the directory of another Module.  See BaseModuleContext.ModuleDir for more information.
 	// It is intended for use inside the visit functions of Visit* and WalkDeps.
-	OtherModuleDir(m Module) string
+	OtherModuleDir(m ModuleOrProxy) string
 
 	// OtherModuleType returns the type of another Module.  See BaseModuleContext.ModuleType for more information.
 	// It is intended for use inside the visit functions of Visit* and WalkDeps.
-	OtherModuleType(m Module) string
+	OtherModuleType(m ModuleOrProxy) string
 
 	// OtherModuleErrorf reports an error on another Module.  See BaseModuleContext.ModuleErrorf for more information.
 	// It is intended for use inside the visit functions of Visit* and WalkDeps.
-	OtherModuleErrorf(m Module, fmt string, args ...interface{})
+	OtherModuleErrorf(m ModuleOrProxy, fmt string, args ...interface{})
 
 	// OtherModuleDependencyTag returns the dependency tag used to depend on a module, or nil if there is no dependency
 	// on the module.  When called inside a Visit* method with current module being visited, and there are multiple
 	// dependencies on the module being visited, it returns the dependency tag used for the current dependency.
-	OtherModuleDependencyTag(m Module) DependencyTag
+	OtherModuleDependencyTag(m ModuleOrProxy) DependencyTag
 
 	// OtherModuleSubDir returns the string representing the variations of the module.
-	OtherModuleSubDir(m Module) string
+	OtherModuleSubDir(m ModuleOrProxy) string
 
 	// OtherModuleExists returns true if a module with the specified name exists, as determined by the NameInterface
 	// passed to Context.SetNameInterface, or SimpleNameInterface if it was not called.
@@ -383,17 +424,20 @@ type BaseModuleContext interface {
 	OtherModuleReverseDependencyVariantExists(name string) bool
 
 	// OtherModuleProvider returns the value for a provider for the given module.  If the value is
-	// not set it returns nil and false.  The value returned may be a deep copy of the value originally
-	// passed to SetProvider.
+	// not set or the module is nil, it returns nil and false.  The value returned may be a deep
+	// copy of the value originally passed to SetProvider.
 	//
 	// This method shouldn't be used directly, prefer the type-safe android.OtherModuleProvider instead.
-	OtherModuleProvider(m Module, provider AnyProviderKey) (any, bool)
+	OtherModuleProvider(m ModuleOrProxy, provider AnyProviderKey) (any, bool)
 
-	OtherModuleHasProvider(m Module, provider AnyProviderKey) bool
+	OtherModuleHasProvider(m ModuleOrProxy, provider AnyProviderKey) bool
 
 	// OtherModuleIsAutoGenerated returns true if a module has been generated from another module,
 	// instead of being defined in Android.bp file
-	OtherModuleIsAutoGenerated(m Module) bool
+	OtherModuleIsAutoGenerated(m ModuleOrProxy) bool
+
+	// OtherModuleNamespace returns the namespace of the module.
+	OtherModuleNamespace(m ModuleOrProxy) Namespace
 
 	// Provider returns the value for a provider for the current module.  If the value is
 	// not set it returns nil and false.  It panics if called before the appropriate
@@ -413,6 +457,13 @@ type BaseModuleContext interface {
 
 	EarlyGetMissingDependencies() []string
 
+	// RegisterConfigurableEvaluator registers the evaluator used for the proptools.Configurable's in
+	// the module properties. It is used to dump their values in the json debug file
+	// (out/soong/soong-debug-info.json), if it's enabled. This should be called from
+	// GenerateBuildActions, but doing so is optional; if no evaluator has been registered then
+	// configurable values are dumped as placeholder strings.
+	RegisterConfigurableEvaluator(evaluator proptools.ConfigurableEvaluator)
+
 	base() *baseModuleContext
 }
 
@@ -441,6 +492,11 @@ type ModuleContext interface {
 	// but do not exist.  It can be used with Context.SetAllowMissingDependencies to allow the primary builder to
 	// handle missing dependencies on its own instead of having Blueprint treat them as an error.
 	GetMissingDependencies() []string
+
+	// FreeModuleAfterGenerateBuildActions marks this module as no longer necessary after the completion of
+	// GenerateBuildActions, i.e. all later accesses to the module will be via ModuleProxy and not direct access
+	// to the Module.
+	FreeModuleAfterGenerateBuildActions()
 }
 
 var _ BaseModuleContext = (*baseModuleContext)(nil)
@@ -453,6 +509,7 @@ type baseModuleContext struct {
 	visitingParent *moduleInfo
 	visitingDep    depInfo
 	ninjaFileDeps  []string
+	evaluator      proptools.ConfigurableEvaluator
 }
 
 func (d *baseModuleContext) moduleInfo() *moduleInfo {
@@ -522,10 +579,10 @@ func (d *baseModuleContext) PropertyErrorf(property, format string,
 	d.error(d.context.PropertyErrorf(d.module.logicModule, property, format, args...))
 }
 
-func (d *baseModuleContext) OtherModulePropertyErrorf(logicModule Module, property string, format string,
+func (d *baseModuleContext) OtherModulePropertyErrorf(logicModule ModuleOrProxy, property string, format string,
 	args ...interface{}) {
 
-	d.error(d.context.PropertyErrorf(getWrappedModule(logicModule), property, format, args...))
+	d.error(d.context.PropertyErrorf(logicModule, property, format, args...))
 }
 
 func (d *baseModuleContext) Failed() bool {
@@ -534,7 +591,19 @@ func (d *baseModuleContext) Failed() bool {
 
 func (d *baseModuleContext) GlobWithDeps(pattern string,
 	excludes []string) ([]string, error) {
-	return d.context.glob(pattern, excludes)
+	result, err := d.context.glob(pattern, excludes)
+	if err == nil && d.context.incrementalEnabled {
+		hash, err := proptools.CalculateHash(result)
+		if err != nil {
+			panic(newPanicErrorf(err, "failed to calculate hash for glob result: %s", d.ModuleName()))
+		}
+		d.module.globCache = append(d.module.globCache, globResultCache{
+			Pattern:  pattern,
+			Excludes: excludes,
+			Result:   hash,
+		})
+	}
+	return result, err
 }
 
 func (d *baseModuleContext) Fs() pathtools.FileSystem {
@@ -558,29 +627,29 @@ type moduleContext struct {
 	handledMissingDeps bool
 }
 
-func EqualModules(m1, m2 Module) bool {
-	return getWrappedModule(m1) == getWrappedModule(m2)
+func EqualModules(m1, m2 ModuleOrProxy) bool {
+	return m1.info() == m2.info()
 }
 
-func (m *baseModuleContext) OtherModuleName(logicModule Module) string {
-	module := m.context.moduleInfo[getWrappedModule(logicModule)]
+func (m *baseModuleContext) OtherModuleName(logicModule ModuleOrProxy) string {
+	module := logicModule.info()
 	return module.Name()
 }
 
-func (m *baseModuleContext) OtherModuleDir(logicModule Module) string {
-	module := m.context.moduleInfo[getWrappedModule(logicModule)]
+func (m *baseModuleContext) OtherModuleDir(logicModule ModuleOrProxy) string {
+	module := logicModule.info()
 	return filepath.Dir(module.relBlueprintsFile)
 }
 
-func (m *baseModuleContext) OtherModuleType(logicModule Module) string {
-	module := m.context.moduleInfo[getWrappedModule(logicModule)]
+func (m *baseModuleContext) OtherModuleType(logicModule ModuleOrProxy) string {
+	module := logicModule.info()
 	return module.typeName
 }
 
-func (m *baseModuleContext) OtherModuleErrorf(logicModule Module, format string,
+func (m *baseModuleContext) OtherModuleErrorf(logicModule ModuleOrProxy, format string,
 	args ...interface{}) {
 
-	module := m.context.moduleInfo[getWrappedModule(logicModule)]
+	module := logicModule.info()
 	m.errs = append(m.errs, &ModuleError{
 		BlueprintError: BlueprintError{
 			Err: fmt.Errorf(format, args...),
@@ -590,16 +659,9 @@ func (m *baseModuleContext) OtherModuleErrorf(logicModule Module, format string,
 	})
 }
 
-func getWrappedModule(module Module) Module {
-	if mp, isProxy := module.(ModuleProxy); isProxy {
-		return mp.module
-	}
-	return module
-}
-
-func (m *baseModuleContext) OtherModuleDependencyTag(logicModule Module) DependencyTag {
+func (m *baseModuleContext) OtherModuleDependencyTag(logicModule ModuleOrProxy) DependencyTag {
 	// fast path for calling OtherModuleDependencyTag from inside VisitDirectDeps
-	if m.visitingDep.module != nil && getWrappedModule(logicModule) == m.visitingDep.module.logicModule {
+	if m.visitingDep.module != nil && logicModule.info() == m.visitingDep.module {
 		return m.visitingDep.tag
 	}
 
@@ -608,7 +670,7 @@ func (m *baseModuleContext) OtherModuleDependencyTag(logicModule Module) Depende
 	}
 
 	for _, dep := range m.visitingParent.directDeps {
-		if dep.module.logicModule == getWrappedModule(logicModule) {
+		if dep.module == logicModule.info() {
 			return dep.tag
 		}
 	}
@@ -616,8 +678,8 @@ func (m *baseModuleContext) OtherModuleDependencyTag(logicModule Module) Depende
 	return nil
 }
 
-func (m *baseModuleContext) OtherModuleSubDir(logicModule Module) string {
-	return m.context.ModuleSubDir(getWrappedModule(logicModule))
+func (m *baseModuleContext) OtherModuleSubDir(logicModule ModuleOrProxy) string {
+	return m.context.ModuleSubDir(logicModule)
 }
 
 func (m *baseModuleContext) ModuleFromName(name string) (Module, bool) {
@@ -647,7 +709,7 @@ func (m *baseModuleContext) OtherModuleDependencyVariantExists(variations []Vari
 	if possibleDeps == nil {
 		return false
 	}
-	found, _, errs := m.context.findVariant(m.module, m.config, possibleDeps, variations, false, false)
+	found, _, errs := m.context.findVariant(m.config, m.module, nil, possibleDeps, variations, false, false)
 	if errs != nil {
 		panic(errors.Join(errs...))
 	}
@@ -659,7 +721,7 @@ func (m *baseModuleContext) OtherModuleFarDependencyVariantExists(variations []V
 	if possibleDeps == nil {
 		return false
 	}
-	found, _, errs := m.context.findVariant(m.module, m.config, possibleDeps, variations, true, false)
+	found, _, errs := m.context.findVariant(m.config, m.module, nil, possibleDeps, variations, true, false)
 	if errs != nil {
 		panic(errors.Join(errs...))
 	}
@@ -671,21 +733,25 @@ func (m *baseModuleContext) OtherModuleReverseDependencyVariantExists(name strin
 	if possibleDeps == nil {
 		return false
 	}
-	found, _, errs := m.context.findVariant(m.module, m.config, possibleDeps, nil, false, true)
+	found, _, errs := m.context.findVariant(m.config, m.module, nil, possibleDeps, nil, false, true)
 	if errs != nil {
 		panic(errors.Join(errs...))
 	}
 	return found != nil
 }
 
-func (m *baseModuleContext) OtherModuleProvider(logicModule Module, provider AnyProviderKey) (any, bool) {
-	module := m.context.moduleInfo[getWrappedModule(logicModule)]
-	return m.context.provider(module, provider.provider())
+func (m *baseModuleContext) OtherModuleProvider(logicModule ModuleOrProxy, provider AnyProviderKey) (any, bool) {
+	if logicModule == nil {
+		return nil, false
+	}
+	return m.context.provider(logicModule.info(), provider.provider())
 }
 
-func (m *baseModuleContext) OtherModuleHasProvider(logicModule Module, provider AnyProviderKey) bool {
-	module := m.context.moduleInfo[getWrappedModule(logicModule)]
-	return m.context.hasProvider(module, provider.provider())
+func (m *baseModuleContext) OtherModuleHasProvider(logicModule ModuleOrProxy, provider AnyProviderKey) bool {
+	if logicModule == nil {
+		return false
+	}
+	return m.context.hasProvider(logicModule.info(), provider.provider())
 }
 
 func (m *baseModuleContext) Provider(provider AnyProviderKey) (any, bool) {
@@ -718,11 +784,15 @@ func (m *moduleContext) restoreModuleBuildActions() bool {
 		}
 		cacheInput := new(BuildActionCacheInput)
 		cacheInput.PropertiesHash = hash
-		m.VisitDirectDeps(func(module Module) {
+		var deps []ModuleProxy
+		m.VisitDirectDepsProxy(func(module ModuleProxy) {
 			cacheInput.ProvidersHash =
-				append(cacheInput.ProvidersHash, m.context.moduleInfo[module].providerInitialValueHashes)
+				append(cacheInput.ProvidersHash, module.info().providerInitialValueHashes)
+			if m.context.incrementalDebugFile != "" {
+				deps = append(deps, module)
+			}
 		})
-		hash, err = proptools.CalculateHash(&cacheInput)
+		hash, err = proptools.CalculateHash(cacheInput)
 		if err != nil {
 			panic(newPanicErrorf(err, "failed to calculate cache input hash"))
 		}
@@ -731,45 +801,62 @@ func (m *moduleContext) restoreModuleBuildActions() bool {
 			InputHash: hash,
 		}
 		m.module.buildActionCacheKey = cacheKey
+		if m.context.incrementalDebugFile != "" {
+			m.module.incrementalDebugInfo = incrementalDebugData(m, deps, cacheInput)
+		}
 	}
 
 	restored := false
 	if incrementalAnalysis && cacheKey != nil {
 		// Try to restore from cache if there is a cache hit
 		data := m.context.getBuildActionsFromCache(cacheKey)
-		relPos := m.module.pos
-		relPos.Filename = m.module.relBlueprintsFile
-		if data != nil && data.Pos != nil && relPos == *data.Pos {
-			for _, provider := range data.Providers {
-				m.context.setProvider(m.module, provider.Id, *provider.Value)
+		if data == nil {
+			return false
+		}
+		for _, glob := range data.GlobCache {
+			result, err := m.context.glob(glob.Pattern, glob.Excludes)
+			if err != nil {
+				panic(newPanicErrorf(err, "failed to glob for cached module: %s %s %v", m.ModuleName(), glob.Pattern, glob.Excludes))
 			}
-			m.module.incrementalRestored = true
-			m.module.orderOnlyStrings = data.OrderOnlyStrings
-			restored = true
-			for _, str := range data.OrderOnlyStrings {
-				if !strings.HasPrefix(str, "dedup-") {
-					continue
-				}
-				orderOnlyStrings, ok := m.context.orderOnlyStringsCache[str]
-				if !ok {
-					panic(fmt.Errorf("no cached value found for order only dep: %s", str))
-				}
-				key := uniquelist.Make(orderOnlyStrings)
-				if info, loaded := m.context.orderOnlyStrings.LoadOrStore(key, &orderOnlyStringsInfo{
-					dedup:       true,
-					incremental: true,
-				}); loaded {
-					for {
-						cpy := *info
-						cpy.dedup = true
-						cpy.incremental = true
-						if m.context.orderOnlyStrings.CompareAndSwap(key, info, &cpy) {
-							break
-						}
-						if info, loaded = m.context.orderOnlyStrings.Load(key); !loaded {
-							// This shouldn't happen
-							panic("order only string was removed unexpectedly")
-						}
+			hash, err := proptools.CalculateHash(result)
+			if err != nil {
+				panic(newPanicErrorf(err, "failed to calculate hash for cached glob result: %s", m.ModuleName()))
+			}
+			if hash != glob.Result {
+				return false
+			}
+		}
+
+		for _, provider := range data.Providers {
+			m.context.setProvider(m.module, provider.Id, *provider.Value)
+		}
+		m.module.incrementalRestored = true
+		m.module.orderOnlyStrings = data.OrderOnlyStrings
+		m.module.globCache = data.GlobCache
+		restored = true
+		for _, str := range data.OrderOnlyStrings {
+			if !strings.HasPrefix(str, "dedup-") {
+				continue
+			}
+			orderOnlyStrings, ok := m.context.orderOnlyStringsCache[str]
+			if !ok {
+				panic(fmt.Errorf("no cached value found for order only dep: %s", str))
+			}
+			key := uniquelist.Make(orderOnlyStrings)
+			if info, loaded := m.context.orderOnlyStrings.LoadOrStore(key, &orderOnlyStringsInfo{
+				dedup:       true,
+				incremental: true,
+			}); loaded {
+				for {
+					cpy := *info
+					cpy.dedup = true
+					cpy.incremental = true
+					if m.context.orderOnlyStrings.CompareAndSwap(key, info, &cpy) {
+						break
+					}
+					if info, loaded = m.context.orderOnlyStrings.Load(key); !loaded {
+						// This shouldn't happen
+						panic("order only string was removed unexpectedly")
 					}
 				}
 			}
@@ -779,6 +866,52 @@ func (m *moduleContext) restoreModuleBuildActions() bool {
 	return restored
 }
 
+type depProviders struct {
+	Name      string   `json:"dep_name"`
+	Type      string   `json:"dep_type"`
+	Variant   string   `json:"dep_variant"`
+	Providers []string `json:"dep_provider_hash"`
+}
+
+func incrementalDebugData(m *moduleContext, deps []ModuleProxy, inputHash *BuildActionCacheInput) []byte {
+	info := struct {
+		Name      string         `json:"name"`
+		CacheKey  string         `json:"cache_key"`
+		Type      string         `json:"type"`
+		Variant   string         `json:"variant"`
+		PropHash  uint64         `json:"properties_hash"`
+		Providers []depProviders `json:"providers"`
+	}{
+		Name:     m.module.logicModule.Name(),
+		CacheKey: m.ModuleCacheKey(),
+		Type:     m.module.typeName,
+		Variant:  m.module.variant.name,
+		PropHash: inputHash.PropertiesHash,
+		Providers: func() []depProviders {
+			result := make([]depProviders, 0, len(deps))
+			for _, d := range deps {
+				dep := d.info()
+				dp := depProviders{
+					Name:    dep.Name(),
+					Type:    dep.typeName,
+					Variant: dep.variant.name,
+				}
+				for _, p := range providerRegistry {
+					if dep.providerInitialValueHashes[p.id] == 0 {
+						continue
+					}
+					dp.Providers = append(dp.Providers,
+						fmt.Sprintf("%s:%x", p.typ, dep.providerInitialValueHashes[p.id]))
+				}
+				result = append(result, dp)
+			}
+			return result
+		}(),
+	}
+	buf, _ := json.Marshal(info)
+	return buf
+}
+
 func (m *baseModuleContext) GetDirectDepWithTag(name string, tag DependencyTag) Module {
 	var deps []depInfo
 	for _, dep := range m.module.directDeps {
@@ -797,13 +930,13 @@ func (m *baseModuleContext) GetDirectDepWithTag(name string, tag DependencyTag)
 	return nil
 }
 
-func (m *baseModuleContext) GetDirectDepProxyWithTag(name string, tag DependencyTag) *ModuleProxy {
+func (m *baseModuleContext) GetDirectDepProxyWithTag(name string, tag DependencyTag) ModuleProxy {
 	module := m.GetDirectDepWithTag(name, tag)
 	if module != nil {
-		return &ModuleProxy{module}
+		return ModuleProxy{module.info()}
 	}
 
-	return nil
+	return ModuleProxy{}
 }
 
 func (m *baseModuleContext) VisitDirectDeps(visit func(Module)) {
@@ -818,6 +951,9 @@ func (m *baseModuleContext) VisitDirectDeps(visit func(Module)) {
 
 	for _, dep := range m.module.directDeps {
 		m.visitingDep = dep
+		if dep.module.logicModule == nil {
+			panic(fmt.Errorf("VisitDirectDeps visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+		}
 		visit(dep.module.logicModule)
 	}
 
@@ -837,7 +973,7 @@ func (m *baseModuleContext) VisitDirectDepsProxy(visit func(proxy ModuleProxy))
 
 	for _, dep := range m.module.directDeps {
 		m.visitingDep = dep
-		visit(ModuleProxy{dep.module.logicModule})
+		visit(ModuleProxy{dep.module})
 	}
 
 	m.visitingParent = nil
@@ -856,6 +992,9 @@ func (m *baseModuleContext) VisitDirectDepsIf(pred func(Module) bool, visit func
 
 	for _, dep := range m.module.directDeps {
 		m.visitingDep = dep
+		if dep.module.logicModule == nil {
+			panic(fmt.Errorf("VisitDirectDepsIf visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+		}
 		if pred(dep.module.logicModule) {
 			visit(dep.module.logicModule)
 		}
@@ -876,6 +1015,9 @@ func (m *baseModuleContext) VisitDepsDepthFirst(visit func(Module)) {
 	m.context.walkDeps(m.module, false, nil, func(dep depInfo, parent *moduleInfo) {
 		m.visitingParent = parent
 		m.visitingDep = dep
+		if dep.module.logicModule == nil {
+			panic(fmt.Errorf("VisitDepsDepthFirst visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+		}
 		visit(dep.module.logicModule)
 	})
 
@@ -897,6 +1039,9 @@ func (m *baseModuleContext) VisitDepsDepthFirstIf(pred func(Module) bool,
 		if pred(dep.module.logicModule) {
 			m.visitingParent = parent
 			m.visitingDep = dep
+			if dep.module.logicModule == nil {
+				panic(fmt.Errorf("VisitDepsDepthFirstIf visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+			}
 			visit(dep.module.logicModule)
 		}
 	})
@@ -909,6 +1054,9 @@ func (m *baseModuleContext) WalkDeps(visit func(child, parent Module) bool) {
 	m.context.walkDeps(m.module, true, func(dep depInfo, parent *moduleInfo) bool {
 		m.visitingParent = parent
 		m.visitingDep = dep
+		if dep.module.logicModule == nil {
+			panic(fmt.Errorf("WalkDeps visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+		}
 		return visit(dep.module.logicModule, parent.logicModule)
 	}, nil)
 
@@ -920,7 +1068,7 @@ func (m *baseModuleContext) WalkDepsProxy(visit func(child, parent ModuleProxy)
 	m.context.walkDeps(m.module, true, func(dep depInfo, parent *moduleInfo) bool {
 		m.visitingParent = parent
 		m.visitingDep = dep
-		return visit(ModuleProxy{dep.module.logicModule}, ModuleProxy{parent.logicModule})
+		return visit(ModuleProxy{dep.module}, ModuleProxy{parent})
 	}, nil)
 
 	m.visitingParent = nil
@@ -931,20 +1079,16 @@ func (m *baseModuleContext) PrimaryModule() Module {
 	return m.module.group.modules.firstModule().logicModule
 }
 
-func (m *baseModuleContext) FinalModule() Module {
-	return m.module.group.modules.lastModule().logicModule
+func (m *baseModuleContext) IsPrimaryModule(module ModuleOrProxy) bool {
+	return m.module.group.modules.firstModule() == module.info()
 }
 
-func (m *baseModuleContext) IsFinalModule(module Module) bool {
-	return m.module.group.modules.lastModule().logicModule == module
-}
-
-func (m *baseModuleContext) VisitAllModuleVariants(visit func(Module)) {
-	m.context.visitAllModuleVariants(m.module, visit)
+func (m *baseModuleContext) FinalModule() Module {
+	return m.module.group.modules.lastModule().logicModule
 }
 
-func (m *baseModuleContext) VisitAllModuleVariantProxies(visit func(proxy ModuleProxy)) {
-	m.context.visitAllModuleVariants(m.module, visitProxyAdaptor(visit))
+func (m *baseModuleContext) IsFinalModule(module ModuleOrProxy) bool {
+	return m.module.group.modules.lastModule() == module.info()
 }
 
 func (m *baseModuleContext) AddNinjaFileDeps(deps ...string) {
@@ -959,14 +1103,18 @@ func (m *baseModuleContext) base() *baseModuleContext {
 	return m
 }
 
-func (m *baseModuleContext) OtherModuleIsAutoGenerated(logicModule Module) bool {
-	module := m.context.moduleInfo[getWrappedModule(logicModule)]
+func (m *baseModuleContext) OtherModuleIsAutoGenerated(logicModule ModuleOrProxy) bool {
+	module := logicModule.info()
 	if module == nil {
 		panic(fmt.Errorf("Module %s not found in baseModuleContext", logicModule.Name()))
 	}
 	return module.createdBy != nil
 }
 
+func (m *baseModuleContext) OtherModuleNamespace(logicModule ModuleOrProxy) Namespace {
+	return m.context.nameInterface.GetNamespace(newNamespaceContext(logicModule.info()))
+}
+
 func (m *moduleContext) ModuleSubDir() string {
 	return m.module.variant.name
 }
@@ -1036,10 +1184,18 @@ func (m *moduleContext) GetMissingDependencies() []string {
 	return m.module.missingDeps
 }
 
+func (m *moduleContext) FreeModuleAfterGenerateBuildActions() {
+	m.module.freeAfterGenerateBuildActions = true
+}
+
 func (m *baseModuleContext) EarlyGetMissingDependencies() []string {
 	return m.module.missingDeps
 }
 
+func (m *baseModuleContext) RegisterConfigurableEvaluator(evaluator proptools.ConfigurableEvaluator) {
+	m.evaluator = evaluator
+}
+
 //
 // MutatorContext
 //
@@ -1053,7 +1209,7 @@ type mutatorContext struct {
 	newVariations    moduleList    // new variants of existing modules
 	newModules       []*moduleInfo // brand new modules
 	defaultVariation *string
-	pauseCh          chan<- pauseSpec
+	pauseFunc        pauseFunc
 }
 
 type BottomUpMutatorContext interface {
@@ -1181,7 +1337,7 @@ func (mctx *mutatorContext) Module() Module {
 func (mctx *mutatorContext) AddDependency(module Module, tag DependencyTag, deps ...string) []Module {
 	depInfos := make([]Module, 0, len(deps))
 	for _, dep := range deps {
-		modInfo := mctx.context.moduleInfo[module]
+		modInfo := module.info()
 		depInfo, errs := mctx.context.addVariationDependency(modInfo, mctx.mutator, mctx.config, nil, tag, dep, false)
 		if len(errs) > 0 {
 			mctx.errs = append(mctx.errs, errs...)
@@ -1229,7 +1385,7 @@ func (mctx *mutatorContext) AddReverseVariationDependency(variations []Variation
 		return
 	}
 
-	found, newVariant, errs := mctx.context.findVariant(mctx.module, mctx.config, possibleDeps, variations, false, true)
+	found, newVariant, errs := mctx.context.findVariant(mctx.config, mctx.module, tag, possibleDeps, variations, false, true)
 	if errs != nil {
 		mctx.errs = append(mctx.errs, errs...)
 		return
@@ -1356,15 +1512,9 @@ func (mctx *mutatorContext) CreateModule(factory ModuleFactory, typeName string,
 // occur, which will happen when the mutator is not parallelizable.  If the dependency is nil
 // it returns true if pausing is supported or false if it is not.
 func (mctx *mutatorContext) pause(dep *moduleInfo) bool {
-	if mctx.pauseCh != nil {
+	if mctx.pauseFunc != nil {
 		if dep != nil {
-			unpause := make(unpause)
-			mctx.pauseCh <- pauseSpec{
-				paused:  mctx.module,
-				until:   dep,
-				unpause: unpause,
-			}
-			<-unpause
+			mctx.pauseFunc(dep)
 		}
 		return true
 	}
@@ -1473,14 +1623,6 @@ type LoadHookWithPriority struct {
 	loadHook LoadHook
 }
 
-// Load hooks need to be added by module factories, which don't have any parameter to get to the
-// Context, and only produce a Module interface with no base implementation, so the load hooks
-// must be stored in a global map.  The key is a pointer allocated by the module factory, so there
-// is no chance of collisions even if tests are running in parallel with multiple contexts.  The
-// contents should be short-lived, they are added during a module factory and removed immediately
-// after the module factory returns.
-var pendingHooks sync.Map
-
 func AddLoadHook(module Module, hook LoadHook) {
 	// default priority is 0
 	AddLoadHookWithPriority(module, hook, 0)
@@ -1490,26 +1632,18 @@ func AddLoadHook(module Module, hook LoadHook) {
 // Hooks with higher priority run last.
 // Hooks with equal priority run in the order they were registered.
 func AddLoadHookWithPriority(module Module, hook LoadHook, priority int) {
-	// Only one goroutine can be processing a given module, so no additional locking is required
-	// for the slice stored in the sync.Map.
-	v, exists := pendingHooks.Load(module)
-	if !exists {
-		v, _ = pendingHooks.LoadOrStore(module, new([]LoadHookWithPriority))
-	}
-	hooks := v.(*[]LoadHookWithPriority)
-	*hooks = append(*hooks, LoadHookWithPriority{priority, hook})
+	module.addLoadHook(LoadHookWithPriority{priority, hook})
 }
 
 func runAndRemoveLoadHooks(ctx *Context, config interface{}, module *moduleInfo,
 	scopedModuleFactories *map[string]ModuleFactory) (newModules []*moduleInfo, deps []string, errs []error) {
 
-	if v, exists := pendingHooks.Load(module.logicModule); exists {
-		hooks := v.(*[]LoadHookWithPriority)
+	if hooks := module.logicModule.getAndClearloadHooks(); len(hooks) > 0 {
 		// Sort the hooks by priority.
 		// Use SliceStable so that hooks with equal priority run in the order they were registered.
-		sort.SliceStable(*hooks, func(i, j int) bool { return (*hooks)[i].priority < (*hooks)[j].priority })
+		slices.SortStableFunc(hooks, func(i, j LoadHookWithPriority) int { return cmp.Compare(i.priority, j.priority) })
 
-		for _, hook := range *hooks {
+		for _, hook := range hooks {
 			mctx := &loadHookContext{
 				baseModuleContext: baseModuleContext{
 					context: ctx,
@@ -1523,7 +1657,6 @@ func runAndRemoveLoadHooks(ctx *Context, config interface{}, module *moduleInfo,
 			deps = append(deps, mctx.ninjaFileDeps...)
 			errs = append(errs, mctx.errs...)
 		}
-		pendingHooks.Delete(module.logicModule)
 
 		return newModules, deps, errs
 	}
diff --git a/module_ctx_test.go b/module_ctx_test.go
index f319fb6..b6af8eb 100644
--- a/module_ctx_test.go
+++ b/module_ctx_test.go
@@ -21,6 +21,7 @@ import (
 )
 
 type moduleCtxTestModule struct {
+	ModuleBase
 	SimpleName
 }
 
@@ -266,6 +267,7 @@ test2 {
 }
 
 type addNinjaDepsTestModule struct {
+	ModuleBase
 	SimpleName
 }
 
diff --git a/name_interface.go b/name_interface.go
index f018d4b..fc87744 100644
--- a/name_interface.go
+++ b/name_interface.go
@@ -132,7 +132,7 @@ func (s *SimpleNameInterface) NewModule(ctx NamespaceContext, group ModuleGroup,
 		}
 	}
 
-	if !isValidModuleName(name) {
+	if !IsValidModuleName(name) {
 		return nil, []error{
 			// seven characters at the start of the second line to align with the string "error: "
 			fmt.Errorf("module %q should use a valid name.\n"+
@@ -158,7 +158,7 @@ var allowedSpecialCharsInModuleNames = map[rune]bool{
 	'&': true,
 }
 
-func isValidModuleName(name string) bool {
+func IsValidModuleName(name string) bool {
 	for _, c := range name {
 		_, allowedSpecialChar := allowedSpecialCharsInModuleNames[c]
 		valid := unicode.IsLetter(c) || unicode.IsDigit(c) || allowedSpecialChar
diff --git a/proptools/hash_provider.go b/proptools/hash_provider.go
index 04e09b7..ea33dda 100644
--- a/proptools/hash_provider.go
+++ b/proptools/hash_provider.go
@@ -24,6 +24,8 @@ import (
 	"reflect"
 	"slices"
 	"unsafe"
+
+	"github.com/google/blueprint/pool"
 )
 
 // byte to insert between elements of lists, fields of structs/maps, etc in order
@@ -31,11 +33,12 @@ import (
 // elements. 36 is arbitrary, but it's the ascii code for a record separator
 var recordSeparator []byte = []byte{36}
 
+var hasherPool = pool.New[hasher]()
+
 func CalculateHash(value interface{}) (uint64, error) {
-	hasher := hasher{
-		Hash64:   fnv.New64(),
-		int64Buf: make([]byte, 8),
-	}
+	hasher := hasherPool.Get()
+	defer hasherPool.Put(hasher)
+	hasher.reset()
 	v := reflect.ValueOf(value)
 	var err error
 	if v.IsValid() {
@@ -46,20 +49,35 @@ func CalculateHash(value interface{}) (uint64, error) {
 
 type hasher struct {
 	hash.Hash64
-	int64Buf      []byte
+	int64Buf      [8]byte
 	ptrs          map[uintptr]bool
 	mapStateCache *mapState
 }
 
+// Preallocate the ptrs map in the hasher to a value slightly larger than the maximum number of pointers
+// seen in a call to CalculateHash to avoid allocations.  The hasher objects are reused in a pool, so the
+// total number of these maps will be small.
+const ptrsMapSize = 16384
+
 type mapState struct {
 	indexes []int
 	keys    []reflect.Value
 	values  []reflect.Value
 }
 
+func (hasher *hasher) reset() {
+	if hasher.Hash64 == nil {
+		hasher.Hash64 = fnv.New64()
+	} else {
+		hasher.Hash64.Reset()
+	}
+
+	clear(hasher.ptrs)
+}
+
 func (hasher *hasher) writeUint64(i uint64) {
-	binary.LittleEndian.PutUint64(hasher.int64Buf, i)
-	hasher.Write(hasher.int64Buf)
+	binary.LittleEndian.PutUint64(hasher.int64Buf[:], i)
+	hasher.Write(hasher.int64Buf[:])
 }
 
 func (hasher *hasher) writeInt(i int) {
@@ -153,7 +171,7 @@ func (hasher *hasher) calculateHash(v reflect.Value) error {
 		hasher.writeInt(0x55)
 		addr := v.Pointer()
 		if hasher.ptrs == nil {
-			hasher.ptrs = make(map[uintptr]bool)
+			hasher.ptrs = make(map[uintptr]bool, ptrsMapSize)
 		}
 		if _, ok := hasher.ptrs[addr]; ok {
 			// We could make this an error if we want to disallow pointer cycles in the future
diff --git a/proptools/unpack.go b/proptools/unpack.go
index 999d1e9..bf1e8f7 100644
--- a/proptools/unpack.go
+++ b/proptools/unpack.go
@@ -535,6 +535,14 @@ func selectOnNonConfigurablePropertyError(property *parser.Property) error {
 		return nil
 	}
 
+	if property.Name == "defaults" {
+		return &UnpackError{
+			fmt.Errorf("can't assign select statement to non-configurable property %q. We explicitly don't support selects on this property",
+				property.Name),
+			property.Value.Pos(),
+		}
+	}
+
 	return &UnpackError{
 		fmt.Errorf("can't assign select statement to non-configurable property %q. This requires a small soong change to enable in most cases, please file a go/soong-bug if you'd like to use a select statement here",
 			property.Name),
diff --git a/provider.go b/provider.go
index fa3d093..bb956ec 100644
--- a/provider.go
+++ b/provider.go
@@ -15,13 +15,13 @@
 package blueprint
 
 import (
-	"encoding/gob"
 	"fmt"
 
-	"github.com/google/blueprint/gobtools"
 	"github.com/google/blueprint/proptools"
 )
 
+//go:generate go run gobtools/codegen/gob_gen.go
+
 // This file implements Providers, modelled after Bazel
 // (https://docs.bazel.build/versions/master/skylark/rules.html#providers).
 // Each provider can be associated with a mutator, in which case the value for the provider for a
@@ -49,40 +49,13 @@ type typedProviderKey[K any] struct {
 	providerKey
 }
 
+// @auto-generate: gob
 type providerKey struct {
 	id      int
 	typ     string
 	mutator string
 }
 
-type providerKeyGob struct {
-	Id      int
-	Typ     string
-	Mutator string
-}
-
-func (m *providerKey) ToGob() *providerKeyGob {
-	return &providerKeyGob{
-		Id:      m.id,
-		Typ:     m.typ,
-		Mutator: m.mutator,
-	}
-}
-
-func (m *providerKey) FromGob(data *providerKeyGob) {
-	m.id = data.Id
-	m.typ = data.Typ
-	m.mutator = data.Mutator
-}
-
-func (m *providerKey) GobEncode() ([]byte, error) {
-	return gobtools.CustomGobEncode[providerKeyGob](m)
-}
-
-func (m *providerKey) GobDecode(data []byte) error {
-	return gobtools.CustomGobDecode[providerKeyGob](data, m)
-}
-
 func (p *providerKey) provider() *providerKey { return p }
 
 type AnyProviderKey interface {
@@ -103,8 +76,6 @@ var providerRegistry []*providerKey
 // inside GenerateBuildActions for the module, and to get the value from GenerateBuildActions from
 // any module later in the build graph.
 func NewProvider[K any]() ProviderKey[K] {
-	var defaultValue K
-	gob.Register(defaultValue)
 	return NewMutatorProvider[K]("")
 }
 
@@ -269,7 +240,7 @@ func (c *Context) mutatorStartedForModule(mutator *mutatorInfo, m *moduleInfo) b
 // OtherModuleProviderContext is a helper interface that is a subset of ModuleContext or BottomUpMutatorContext
 // for use in OtherModuleProvider.
 type OtherModuleProviderContext interface {
-	OtherModuleProvider(m Module, provider AnyProviderKey) (any, bool)
+	OtherModuleProvider(m ModuleOrProxy, provider AnyProviderKey) (any, bool)
 }
 
 var _ OtherModuleProviderContext = BaseModuleContext(nil)
@@ -277,12 +248,13 @@ var _ OtherModuleProviderContext = ModuleContext(nil)
 var _ OtherModuleProviderContext = BottomUpMutatorContext(nil)
 
 // OtherModuleProvider reads the provider for the given module.  If the provider has been set the value is
-// returned and the boolean is true.  If it has not been set the zero value of the provider's type  is returned
-// and the boolean is false.  The value returned may be a deep copy of the value originally passed to SetProvider.
+// returned and the boolean is true.  If it has not been set or the module is nil, the zero value
+// of the provider's type  is returned and the boolean is false.  The value returned may be a deep
+// copy of the value originally passed to SetProvider.
 //
 // OtherModuleProviderContext is a helper interface that accepts ModuleContext, BottomUpMutatorContext, or
 // TopDownMutatorContext.
-func OtherModuleProvider[K any](ctx OtherModuleProviderContext, module Module, provider ProviderKey[K]) (K, bool) {
+func OtherModuleProvider[K any](ctx OtherModuleProviderContext, module ModuleOrProxy, provider ProviderKey[K]) (K, bool) {
 	value, ok := ctx.OtherModuleProvider(module, provider)
 	if !ok {
 		var k K
@@ -294,7 +266,7 @@ func OtherModuleProvider[K any](ctx OtherModuleProviderContext, module Module, p
 // SingletonModuleProviderContext is a helper interface that is a subset of Context and SingletonContext for use in
 // SingletonModuleProvider.
 type SingletonModuleProviderContext interface {
-	ModuleProvider(m Module, provider AnyProviderKey) (any, bool)
+	ModuleProvider(m ModuleOrProxy, provider AnyProviderKey) (any, bool)
 }
 
 var _ SingletonModuleProviderContext = &Context{}
@@ -305,7 +277,7 @@ var _ SingletonModuleProviderContext = SingletonContext(nil)
 // and the boolean is false.  The value returned may be a deep copy of the value originally passed to SetProvider.
 //
 // SingletonModuleProviderContext is a helper interface that accepts Context or SingletonContext.
-func SingletonModuleProvider[K any](ctx SingletonModuleProviderContext, module Module, provider ProviderKey[K]) (K, bool) {
+func SingletonModuleProvider[K any](ctx SingletonModuleProviderContext, module ModuleOrProxy, provider ProviderKey[K]) (K, bool) {
 	value, ok := ctx.ModuleProvider(module, provider)
 	if !ok {
 		var k K
diff --git a/provider_gob_enc.go b/provider_gob_enc.go
new file mode 100644
index 0000000..5d208ae
--- /dev/null
+++ b/provider_gob_enc.go
@@ -0,0 +1,58 @@
+// Code generated by go run gob_gen.go; DO NOT EDIT.
+
+package blueprint
+
+import (
+	"bytes"
+	"github.com/google/blueprint/gobtools"
+)
+
+func init() {
+	providerKeyGobRegId = gobtools.RegisterType(func() gobtools.CustomDec { return new(providerKey) })
+}
+
+func (r providerKey) Encode(buf *bytes.Buffer) error {
+	var err error
+
+	if err = gobtools.EncodeSimple(buf, int64(r.id)); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeString(buf, r.typ); err != nil {
+		return err
+	}
+
+	if err = gobtools.EncodeString(buf, r.mutator); err != nil {
+		return err
+	}
+	return err
+}
+
+func (r *providerKey) Decode(buf *bytes.Reader) error {
+	var err error
+
+	var val1 int64
+	err = gobtools.DecodeSimple[int64](buf, &val1)
+	if err != nil {
+		return err
+	}
+	r.id = int(val1)
+
+	err = gobtools.DecodeString(buf, &r.typ)
+	if err != nil {
+		return err
+	}
+
+	err = gobtools.DecodeString(buf, &r.mutator)
+	if err != nil {
+		return err
+	}
+
+	return err
+}
+
+var providerKeyGobRegId int16
+
+func (r providerKey) GetTypeId() int16 {
+	return providerKeyGobRegId
+}
diff --git a/provider_test.go b/provider_test.go
index aafe3c3..0d7ad69 100644
--- a/provider_test.go
+++ b/provider_test.go
@@ -22,6 +22,7 @@ import (
 )
 
 type providerTestModule struct {
+	ModuleBase
 	SimpleName
 	properties struct {
 		Deps []string
@@ -176,6 +177,7 @@ var invalidProviderUsageMutatorInfoProvider = NewMutatorProvider[invalidProvider
 var invalidProviderUsageGenerateBuildActionsInfoProvider = NewProvider[invalidProviderUsageGenerateBuildActionsInfo]()
 
 type invalidProviderUsageTestModule struct {
+	ModuleBase
 	SimpleName
 	properties struct {
 		Deps []string
diff --git a/singleton_ctx.go b/singleton_ctx.go
index bcfb45c..947763f 100644
--- a/singleton_ctx.go
+++ b/singleton_ctx.go
@@ -32,36 +32,36 @@ type SingletonContext interface {
 	Name() string
 
 	// ModuleName returns the name of the given Module.  See BaseModuleContext.ModuleName for more information.
-	ModuleName(module Module) string
+	ModuleName(module ModuleOrProxy) string
 
 	// ModuleDir returns the directory of the given Module.  See BaseModuleContext.ModuleDir for more information.
-	ModuleDir(module Module) string
+	ModuleDir(module ModuleOrProxy) string
 
 	// ModuleSubDir returns the unique subdirectory name of the given Module.  See ModuleContext.ModuleSubDir for
 	// more information.
-	ModuleSubDir(module Module) string
+	ModuleSubDir(module ModuleOrProxy) string
 
 	// ModuleType returns the type of the given Module.  See BaseModuleContext.ModuleType for more information.
-	ModuleType(module Module) string
+	ModuleType(module ModuleOrProxy) string
 
 	// BlueprintFile returns the path of the Blueprint file that defined the given module.
-	BlueprintFile(module Module) string
+	BlueprintFile(module ModuleOrProxy) string
 
 	// ModuleProvider returns the value, if any, for the provider for a module.  If the value for the
 	// provider was not set it returns the zero value of the type of the provider, which means the
 	// return value can always be type-asserted to the type of the provider.  The return value should
 	// always be considered read-only.  It panics if called before the appropriate mutator or
 	// GenerateBuildActions pass for the provider on the module.
-	ModuleProvider(module Module, provider AnyProviderKey) (any, bool)
+	ModuleProvider(module ModuleOrProxy, provider AnyProviderKey) (any, bool)
 
 	// ModuleErrorf reports an error at the line number of the module type in the module definition.
-	ModuleErrorf(module Module, format string, args ...interface{})
+	ModuleErrorf(module ModuleOrProxy, format string, args ...interface{})
 
 	// Errorf reports an error at the specified position of the module definition file.
 	Errorf(format string, args ...interface{})
 
 	// OtherModulePropertyErrorf reports an error on the line number of the given property of the given module
-	OtherModulePropertyErrorf(module Module, property string, format string, args ...interface{})
+	OtherModulePropertyErrorf(module ModuleOrProxy, property string, format string, args ...interface{})
 
 	// Failed returns true if any errors have been reported.  In most cases the singleton can continue with generating
 	// build rules after an error, allowing it to report additional errors in a single run, but in cases where the error
@@ -102,6 +102,11 @@ type SingletonContext interface {
 	// VisitAllModuleProxies calls visit for each defined variant of each module in an unspecified order.
 	VisitAllModuleProxies(visit func(proxy ModuleProxy))
 
+	// VisitAllModulesOrProxies calls visit for each defined variant of each module in an unspecified order,
+	// passing a Module if the module did not call FreeModuleAfterGenerateBuildActions, or a ModuleProxy if
+	// it did.
+	VisitAllModulesOrProxies(visit func(ModuleOrProxy))
+
 	// VisitAllModules calls pred for each defined variant of each module in an unspecified order, and if pred returns
 	// true calls visit.
 	VisitAllModulesIf(pred func(Module) bool, visit func(Module))
@@ -123,22 +128,19 @@ type SingletonContext interface {
 	// function, it may be invalidated by future mutators.
 	VisitDirectDepsIf(module Module, pred func(Module) bool, visit func(Module))
 
-	// VisitDepsDepthFirst calls visit for each transitive dependency, traversing the dependency tree in depth first
-	// order. visit will only be called once for any given module, even if there are multiple paths through the
-	// dependency tree to the module or multiple direct dependencies with different tags.
-	VisitDepsDepthFirst(module Module, visit func(Module))
-
-	// VisitDepsDepthFirst calls pred for each transitive dependency, and if pred returns true calls visit, traversing
-	// the dependency tree in depth first order.  visit will only be called once for any given module, even if there are
-	// multiple paths through the dependency tree to the module or multiple direct dependencies with different tags.
-	VisitDepsDepthFirstIf(module Module, pred func(Module) bool,
-		visit func(Module))
+	// VisitDirectDepsProxies calls visit for each direct dependency of the ModuleProxy.  If there are
+	// multiple direct dependencies on the same module visit will be called multiple times on
+	// that module and OtherModuleDependencyTag will return a different tag for each.
+	//
+	// The ModuleProxy passed to the visit function should not be retained outside of the visit
+	// function, it may be invalidated by future mutators.
+	VisitDirectDepsProxies(module ModuleProxy, visit func(ModuleProxy))
 
 	// VisitAllModuleVariants calls visit for each variant of the given module.
 	VisitAllModuleVariants(module Module, visit func(Module))
 
 	// VisitAllModuleVariantProxies calls visit for each variant of the given module.
-	VisitAllModuleVariantProxies(module Module, visit func(proxy ModuleProxy))
+	VisitAllModuleVariantProxies(module ModuleProxy, visit func(proxy ModuleProxy))
 
 	// PrimaryModule returns the first variant of the given module.  This can be used to perform
 	// singleton actions that are only done once for all variants of a module.
@@ -149,9 +151,13 @@ type SingletonContext interface {
 	// all variants of a module.
 	PrimaryModuleProxy(module ModuleProxy) ModuleProxy
 
+	// IsPrimaryModule returns if the given module is the first variant. This can be used to perform
+	// singleton actions that are only done once for all variants of a module.
+	IsPrimaryModule(module ModuleOrProxy) bool
+
 	// IsFinalModule returns if the given module is the last variant. This can be used to perform
 	// singleton actions that are only done once for all variants of a module.
-	IsFinalModule(module Module) bool
+	IsFinalModule(module ModuleOrProxy) bool
 
 	// AddNinjaFileDeps adds dependencies on the specified files to the rule that creates the ninja manifest.  The
 	// primary builder will be rerun whenever the specified files are modified.
@@ -176,6 +182,16 @@ type SingletonContext interface {
 	// HasMutatorFinished returns true if the given mutator has finished running.
 	// It will panic if given an invalid mutator name.
 	HasMutatorFinished(mutatorName string) bool
+
+	// OtherModuleDependencyTag returns the dependency tag used to depend on a module, or nil if there is no dependency
+	// on the module.  When called inside a Visit* method with current module being visited, and there are multiple
+	// dependencies on the module being visited, it returns the dependency tag used for the current dependency.
+	OtherModuleDependencyTag(module ModuleOrProxy) DependencyTag
+
+	GetIncrementalAnalysis() bool
+
+	// OtherModuleNamespace returns the namespace of the module.
+	OtherModuleNamespace(module ModuleOrProxy) Namespace
 }
 
 var _ SingletonContext = (*singletonContext)(nil)
@@ -190,6 +206,8 @@ type singletonContext struct {
 	ninjaFileDeps []string
 	errs          []error
 
+	visitingDep depInfo
+
 	actionDefs localBuildActions
 }
 
@@ -201,28 +219,28 @@ func (s *singletonContext) Name() string {
 	return s.name
 }
 
-func (s *singletonContext) ModuleName(logicModule Module) string {
-	return s.context.ModuleName(getWrappedModule(logicModule))
+func (s *singletonContext) ModuleName(logicModule ModuleOrProxy) string {
+	return s.context.ModuleName(logicModule)
 }
 
-func (s *singletonContext) ModuleDir(logicModule Module) string {
-	return s.context.ModuleDir(getWrappedModule(logicModule))
+func (s *singletonContext) ModuleDir(logicModule ModuleOrProxy) string {
+	return s.context.ModuleDir(logicModule)
 }
 
-func (s *singletonContext) ModuleSubDir(logicModule Module) string {
-	return s.context.ModuleSubDir(getWrappedModule(logicModule))
+func (s *singletonContext) ModuleSubDir(logicModule ModuleOrProxy) string {
+	return s.context.ModuleSubDir(logicModule)
 }
 
-func (s *singletonContext) ModuleType(logicModule Module) string {
-	return s.context.ModuleType(getWrappedModule(logicModule))
+func (s *singletonContext) ModuleType(logicModule ModuleOrProxy) string {
+	return s.context.ModuleType(logicModule)
 }
 
-func (s *singletonContext) ModuleProvider(logicModule Module, provider AnyProviderKey) (any, bool) {
-	return s.context.ModuleProvider(getWrappedModule(logicModule), provider)
+func (s *singletonContext) ModuleProvider(logicModule ModuleOrProxy, provider AnyProviderKey) (any, bool) {
+	return s.context.ModuleProvider(logicModule, provider)
 }
 
-func (s *singletonContext) BlueprintFile(logicModule Module) string {
-	return s.context.BlueprintFile(getWrappedModule(logicModule))
+func (s *singletonContext) BlueprintFile(logicModule ModuleOrProxy) string {
+	return s.context.BlueprintFile(logicModule)
 }
 
 func (s *singletonContext) error(err error) {
@@ -231,7 +249,7 @@ func (s *singletonContext) error(err error) {
 	}
 }
 
-func (s *singletonContext) ModuleErrorf(logicModule Module, format string,
+func (s *singletonContext) ModuleErrorf(logicModule ModuleOrProxy, format string,
 	args ...interface{}) {
 
 	s.error(s.context.ModuleErrorf(logicModule, format, args...))
@@ -242,7 +260,7 @@ func (s *singletonContext) Errorf(format string, args ...interface{}) {
 	s.error(fmt.Errorf(format, args...))
 }
 
-func (s *singletonContext) OtherModulePropertyErrorf(logicModule Module, property string, format string,
+func (s *singletonContext) OtherModulePropertyErrorf(logicModule ModuleOrProxy, property string, format string,
 	args ...interface{}) {
 
 	s.error(s.context.PropertyErrorf(logicModule, property, format, args...))
@@ -328,22 +346,15 @@ func (s *singletonContext) AddSubninja(file string) {
 }
 
 func (s *singletonContext) VisitAllModules(visit func(Module)) {
-	var visitingModule Module
-	defer func() {
-		if r := recover(); r != nil {
-			panic(newPanicErrorf(r, "VisitAllModules(%s) for module %s",
-				funcName(visit), s.context.moduleInfo[visitingModule]))
-		}
-	}()
+	s.context.VisitAllModules(visit)
+}
 
-	s.context.VisitAllModules(func(m Module) {
-		visitingModule = m
-		visit(m)
-	})
+func (s *singletonContext) VisitAllModulesOrProxies(visit func(ModuleOrProxy)) {
+	s.context.VisitAllModulesOrProxies(visit)
 }
 
 func (s *singletonContext) VisitAllModuleProxies(visit func(proxy ModuleProxy)) {
-	s.VisitAllModules(visitProxyAdaptor(visit))
+	s.context.VisitAllModulesProxies(visit)
 }
 
 func (s *singletonContext) VisitAllModulesIf(pred func(Module) bool,
@@ -353,23 +364,66 @@ func (s *singletonContext) VisitAllModulesIf(pred func(Module) bool,
 }
 
 func (s *singletonContext) VisitDirectDeps(module Module, visit func(Module)) {
-	s.context.VisitDirectDeps(module, visit)
+	topModule := module.info()
+
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitDirectDeps(%s, %s) for dependency %s",
+				topModule, funcName(visit), s.visitingDep.module))
+		}
+	}()
+
+	for _, dep := range topModule.directDeps {
+		s.visitingDep = dep
+		if dep.module.logicModule == nil {
+			panic(fmt.Errorf("VisitDirectDeps visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+		}
+		visit(dep.module.logicModule)
+	}
 }
 
 func (s *singletonContext) VisitDirectDepsIf(module Module, pred func(Module) bool, visit func(Module)) {
-	s.context.VisitDirectDepsIf(module, pred, visit)
-}
+	topModule := module.info()
 
-func (s *singletonContext) VisitDepsDepthFirst(module Module,
-	visit func(Module)) {
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitDirectDepsIf(%s, %s, %s) for dependency %s",
+				topModule, funcName(pred), funcName(visit), s.visitingDep.module))
+		}
+	}()
 
-	s.context.VisitDepsDepthFirst(module, visit)
+	for _, dep := range topModule.directDeps {
+		s.visitingDep = dep
+		if dep.module.logicModule == nil {
+			panic(fmt.Errorf("VisitDirectDepsIf visited module %s that called FreeAfterGenerateBuildActions()", dep.module))
+		}
+		if pred(dep.module.logicModule) {
+			visit(dep.module.logicModule)
+		}
+	}
 }
 
-func (s *singletonContext) VisitDepsDepthFirstIf(module Module,
-	pred func(Module) bool, visit func(Module)) {
+func (s *singletonContext) VisitDirectDepsProxies(module ModuleProxy, visit func(ModuleProxy)) {
+	topModule := module.info()
 
-	s.context.VisitDepsDepthFirstIf(module, pred, visit)
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitDirectDepsProxies(%s, %s) for dependency %s",
+				topModule, funcName(visit), s.visitingDep.module))
+		}
+	}()
+
+	for _, dep := range topModule.directDeps {
+		s.visitingDep = dep
+		visit(ModuleProxy{dep.module})
+	}
+}
+
+func (s *singletonContext) OtherModuleDependencyTag(module ModuleOrProxy) DependencyTag {
+	if s.visitingDep.module == module.info() {
+		return s.visitingDep.tag
+	}
+	return nil
 }
 
 func (s *singletonContext) PrimaryModule(module Module) Module {
@@ -377,19 +431,23 @@ func (s *singletonContext) PrimaryModule(module Module) Module {
 }
 
 func (s *singletonContext) PrimaryModuleProxy(module ModuleProxy) ModuleProxy {
-	return ModuleProxy{s.context.PrimaryModule(module.module)}
+	return ModuleProxy{s.context.primaryModule(module.info())}
 }
 
-func (s *singletonContext) IsFinalModule(module Module) bool {
-	return s.context.IsFinalModule(getWrappedModule(module))
+func (s *singletonContext) IsPrimaryModule(module ModuleOrProxy) bool {
+	return s.context.IsPrimaryModule(module)
+}
+
+func (s *singletonContext) IsFinalModule(module ModuleOrProxy) bool {
+	return s.context.IsFinalModule(module)
 }
 
 func (s *singletonContext) VisitAllModuleVariants(module Module, visit func(Module)) {
 	s.context.VisitAllModuleVariants(module, visit)
 }
 
-func (s *singletonContext) VisitAllModuleVariantProxies(module Module, visit func(proxy ModuleProxy)) {
-	s.context.VisitAllModuleVariants(getWrappedModule(module), visitProxyAdaptor(visit))
+func (s *singletonContext) VisitAllModuleVariantProxies(module ModuleProxy, visit func(proxy ModuleProxy)) {
+	s.context.VisitAllModuleVariantProxies(module, visitProxyAdaptor(visit))
 }
 
 func (s *singletonContext) AddNinjaFileDeps(deps ...string) {
@@ -408,7 +466,7 @@ func (s *singletonContext) Fs() pathtools.FileSystem {
 func (s *singletonContext) ModuleVariantsFromName(referer ModuleProxy, name string) []ModuleProxy {
 	c := s.context
 
-	refererInfo := c.moduleInfo[referer.module]
+	refererInfo := referer.info()
 	if refererInfo == nil {
 		s.ModuleErrorf(referer, "could not find module %q", referer.Name())
 		return nil
@@ -421,7 +479,7 @@ func (s *singletonContext) ModuleVariantsFromName(referer ModuleProxy, name stri
 	result := make([]ModuleProxy, 0, len(moduleGroup.modules))
 	for _, moduleInfo := range moduleGroup.modules {
 		if moduleInfo.logicModule != nil {
-			result = append(result, ModuleProxy{moduleInfo.logicModule})
+			result = append(result, ModuleProxy{moduleInfo})
 		}
 	}
 	return result
@@ -431,10 +489,16 @@ func (s *singletonContext) HasMutatorFinished(mutatorName string) bool {
 	return s.context.HasMutatorFinished(mutatorName)
 }
 
-func visitProxyAdaptor(visit func(proxy ModuleProxy)) func(module Module) {
-	return func(module Module) {
-		visit(ModuleProxy{
-			module: module,
-		})
+func visitProxyAdaptor(visit func(proxy ModuleProxy)) func(module ModuleProxy) {
+	return func(module ModuleProxy) {
+		visit(ModuleProxy{module.info()})
 	}
 }
+
+func (s *singletonContext) GetIncrementalAnalysis() bool {
+	return s.context.GetIncrementalAnalysis()
+}
+
+func (s *singletonContext) OtherModuleNamespace(module ModuleOrProxy) Namespace {
+	return s.context.nameInterface.GetNamespace(newNamespaceContext(module.info()))
+}
diff --git a/syncmap/syncmap.go b/syncmap/syncmap.go
index 5d2e3f1..bbd5020 100644
--- a/syncmap/syncmap.go
+++ b/syncmap/syncmap.go
@@ -50,3 +50,7 @@ func (m *SyncMap[K, V]) Range(f func(key K, value V) bool) {
 		return f(k.(K), v.(V))
 	})
 }
+
+func (m *SyncMap[K, V]) Delete(key K) {
+	m.Map.Delete(key)
+}
diff --git a/transition.go b/transition.go
index ee72d8d..884388a 100644
--- a/transition.go
+++ b/transition.go
@@ -20,6 +20,7 @@ import (
 	"slices"
 
 	"github.com/google/blueprint/pool"
+	"github.com/google/blueprint/proptools"
 )
 
 // TransitionMutator implements a top-down mechanism where a module tells its
@@ -221,16 +222,22 @@ func (t *transitionMutatorImpl) addRequiredVariation(m *moduleInfo, variation st
 	}
 
 	m.currentTransitionMutator = t.name
-	if existing, exists := m.incomingTransitionInfos[variation]; exists {
-		if existing != transitionInfo {
-			panic(fmt.Errorf("TransitionInfo %#v and %#v are different but have same variation %q",
-				existing, transitionInfo, variation))
+	hash, err := proptools.CalculateHash(transitionInfo)
+	if err != nil {
+		panic(err)
+	}
+	if existing, exists := m.incomingTransitionInfoHashes[variation]; exists {
+		if existing != hash {
+			panic(fmt.Errorf("TransitionInfo %#v and %#v are different but have same variation %q (hash %x vs %x)",
+				m.incomingTransitionInfos[variation], transitionInfo, variation, existing, hash))
 		}
 	} else {
 		if m.incomingTransitionInfos == nil {
 			m.incomingTransitionInfos = make(map[string]TransitionInfo)
+			m.incomingTransitionInfoHashes = make(map[string]uint64)
 		}
 		m.incomingTransitionInfos[variation] = transitionInfo
+		m.incomingTransitionInfoHashes[variation] = hash
 	}
 }
 
@@ -251,6 +258,7 @@ func (t *transitionMutatorImpl) propagateMutator(mctx BaseModuleContext) {
 	transitionVariations := slices.Sorted(maps.Keys(module.incomingTransitionInfos))
 	transitionInfoMap := module.incomingTransitionInfos
 	module.incomingTransitionInfos = nil
+	module.incomingTransitionInfoHashes = nil
 
 	splitsVariations := make([]string, 0, len(mutatorSplits))
 	for _, splitTransitionInfo := range mutatorSplits {
diff --git a/transition_test.go b/transition_test.go
index ef205e3..4c387b6 100644
--- a/transition_test.go
+++ b/transition_test.go
@@ -576,6 +576,7 @@ func (transitionTestMutator) Mutate(ctx BottomUpMutatorContext, variation Transi
 }
 
 type transitionModule struct {
+	ModuleBase
 	SimpleName
 	properties struct {
 		Deps                                   []string
diff --git a/uniquelist/Android.bp b/uniquelist/Android.bp
index 804d1b6..7a317a0 100644
--- a/uniquelist/Android.bp
+++ b/uniquelist/Android.bp
@@ -7,8 +7,12 @@ bootstrap_go_package {
     testSrcs: [
         "uniquelist_test.go",
     ],
+    deps: [
+        "blueprint-syncmap",
+    ],
     visibility: [
         "//build/blueprint",
         "//build/blueprint/depset",
+        "//build/blueprint/gobtools/codegen",
     ],
 }
diff --git a/uniquelist/uniquelist.go b/uniquelist/uniquelist.go
index d50cea6..f436de1 100644
--- a/uniquelist/uniquelist.go
+++ b/uniquelist/uniquelist.go
@@ -15,104 +15,92 @@
 package uniquelist
 
 import (
+	"hash/maphash"
 	"iter"
+	"reflect"
+	"runtime"
 	"slices"
-	"unique"
+	"sync"
+	"time"
+	"weak"
+
+	"github.com/google/blueprint/syncmap"
 )
 
 // UniqueList is a workaround for Go limitation that slices are not comparable and
-// thus can't be used with unique.Make.  It interns slices by storing them in an
-// unrolled linked list, where each node has a fixed size array, which are comparable
-// and can be stored using the unique package.  A UniqueList is immutable.
+// thus can't be used with unique.Make.  It interns slices by manually hashing the
+// contents of each element and using the result as the key in a sync.Map.
 type UniqueList[T comparable] struct {
-	handle unique.Handle[node[T]]
+	p *[]T
 }
 
-// Len returns the length of the slice that was originally passed to Make.  It returns
-// a stored value and does not require iterating the linked list.
+// uniqueListMapsByType stores a map from the type of list element to the uniqueListMap
+// that stores lists of that type.  The value in the map is always a *uniqueListMap[T]
+// when the key is the reflect.TypeOf(T).
+var uniqueListMapsByType syncmap.SyncMap[reflect.Type, any]
+
+// uniqueListMap stores a map of hash of the contents of a slice to a weak pointer to
+// a canonical slice with that contents.
+type uniqueListMap[T comparable] = syncmap.SyncMap[uint64, weak.Pointer[[]T]]
+
+// freeUnusedList stores a list of functions to call periodically to remove entries
+// in uniqueListMaps whose weak pointer is no longer valid.
+var freeUnusedList []func()
+
+// freeUnusedMutex protects freeUnusedList.
+var freeUnusedMutex sync.Mutex
+
+// initFreeUnused creates a goroutine to call the functions in the freeUnusedList.
+var initFreeUnused = sync.OnceFunc(func() {
+	t := time.Tick(5 * time.Second)
+	go func() {
+		for {
+			<-t
+			freeUnusedMutex.Lock()
+			c := freeUnusedList
+			freeUnusedMutex.Unlock()
+
+			for _, f := range c {
+				f()
+			}
+		}
+	}()
+})
+
+// Len returns the length of the slice that was originally passed to Make.
 func (s UniqueList[T]) Len() int {
-	var zeroList unique.Handle[node[T]]
-	if s.handle == zeroList {
+	if s.p == nil {
 		return 0
 	}
-
-	return s.handle.Value().len
+	return len(*s.p)
 }
 
 // ToSlice returns a slice containing a shallow copy of the list.
 func (s UniqueList[T]) ToSlice() []T {
-	return s.AppendTo(nil)
+	if s.p == nil {
+		return []T(nil)
+	}
+	return slices.Clone(*s.p)
 }
 
 // Iter returns a iter.Seq that iterates the elements of the list.
 func (s UniqueList[T]) Iter() iter.Seq[T] {
-	var zeroSlice unique.Handle[node[T]]
-
-	return func(yield func(T) bool) {
-		cur := s.handle
-		for cur != zeroSlice {
-			impl := cur.Value()
-			for _, v := range impl.elements[:min(nodeSize, impl.len)] {
-				if !yield(v) {
-					return
-				}
-			}
-			cur = impl.next
-		}
-	}
-}
-
-// iterNodes returns an iter.Seq that iterates each node of the
-// unrolled linked list, returning a slice that contains all the
-// elements in a node at once.
-func (s UniqueList[T]) iterNodes() iter.Seq[[]T] {
-	var zeroSlice unique.Handle[node[T]]
-
-	return func(yield func([]T) bool) {
-		cur := s.handle
-		for cur != zeroSlice {
-			impl := cur.Value()
-			l := min(impl.len, len(impl.elements))
-			if !yield(impl.elements[:l]) {
-				return
-			}
-			cur = impl.next
-		}
+	if s.p == nil {
+		return func(yield func(T) bool) {}
 	}
+	return slices.Values(*s.p)
 }
 
 // AppendTo appends the contents of the list to the given slice and returns
 // the results.
 func (s UniqueList[T]) AppendTo(slice []T) []T {
-	// TODO: should this grow by more than s.Len() to amortize reallocation costs?
-	slice = slices.Grow(slice, s.Len())
-	for chunk := range s.iterNodes() {
-		slice = append(slice, chunk...)
+	if s.p == nil {
+		return slice
 	}
+	slice = append(slice, *s.p...)
 	return slice
 }
 
-// node is a node in an unrolled linked list object that holds a group of elements of a
-// list in a fixed size array in order to satisfy the comparable constraint.
-type node[T comparable] struct {
-	// elements is a group of up to nodeSize elements of a list.
-	elements [nodeSize]T
-
-	// len is the length of the list stored in this node and any transitive linked nodes.
-	// If len is less than nodeSize then only the first len values in the elements array
-	// are part of the list.  If len is greater than nodeSize then next will point to the
-	// next node in the unrolled linked list.
-	len int
-
-	// next is the next node in the linked list.  If it is the zero value of unique.Handle
-	// then this is the last node.
-	next unique.Handle[node[T]]
-}
-
-// nodeSize is the number of list elements stored in each node.  The value 6 was chosen to make
-// the size of node 64 bytes to match the cache line size.
-const nodeSize = 6
-
 // Make returns a UniqueList for the given slice.  Two calls to UniqueList with the same slice contents
 // will return identical UniqueList objects.
 func Make[T comparable](slice []T) UniqueList[T] {
@@ -120,42 +108,69 @@ func Make[T comparable](slice []T) UniqueList[T] {
 		return UniqueList[T]{}
 	}
 
-	var last unique.Handle[node[T]]
-	l := 0
-
-	// Iterate backwards through the lists in chunks of nodeSize, with the first chunk visited
-	// being the partial chunk if the length of the slice is not a multiple of nodeSize.
-	//
-	// For each chunk, create an unrolled linked list node with a chunk of slice elements and a
-	// pointer to the previously created node, uniquified through unique.Make.
-	for chunk := range chunkReverse(slice, nodeSize) {
-		var node node[T]
-		copy(node.elements[:], chunk)
-		node.next = last
-		l += len(chunk)
-		node.len = l
-		last = unique.Make(node)
+	uniqueListsForT := getUniqueListMapForType[T]()
+	key := hashSliceContents(slice)
+
+	var p *[]T
+	for {
+		w, ok := uniqueListsForT.Load(key)
+		if !ok {
+			s := slices.Clone(slice)
+			w = weak.Make(&s)
+			w, _ = uniqueListsForT.LoadOrStore(key, w)
+		}
+
+		p = w.Value()
+		if p != nil {
+			break
+		}
+
+		uniqueListsForT.Delete(key)
 	}
+	runtime.KeepAlive(slice)
+	return UniqueList[T]{p}
+}
+
+var seed = maphash.MakeSeed()
 
-	return UniqueList[T]{last}
+// hashSliceContents uses maphash.Hash to hash each element of a slice.
+func hashSliceContents[T comparable](list []T) uint64 {
+	var h maphash.Hash
+	h.SetSeed(seed)
+	for _, e := range list {
+		maphash.WriteComparable(&h, e)
+	}
+	return h.Sum64()
 }
 
-// chunkReverse is similar to slices.Chunk, except that it returns the chunks in reverse
-// order.  If the length of the slice is not a multiple of n then the first chunk returned
-// (which is the last chunk of the input slice) is a partial chunk.
-func chunkReverse[T any](slice []T, n int) iter.Seq[[]T] {
-	return func(yield func([]T) bool) {
-		l := len(slice)
-		lastPartialChunkSize := l % n
-		if lastPartialChunkSize > 0 {
-			if !yield(slice[l-lastPartialChunkSize : l : l]) {
-				return
-			}
-		}
-		for i := l - lastPartialChunkSize - n; i >= 0; i -= n {
-			if !yield(slice[i : i+n : i+n]) {
-				return
-			}
+// getUniqueListMapForType
+func getUniqueListMapForType[T comparable]() *uniqueListMap[T] {
+	var zero T
+	typ := reflect.TypeOf(zero)
+
+	initFreeUnused()
+	uniqueListsForT, ok := uniqueListMapsByType.Load(typ)
+	if !ok {
+		var loaded bool
+		uniqueListsForT = &uniqueListMap[T]{}
+		uniqueListsForT, loaded = uniqueListMapsByType.LoadOrStore(typ, uniqueListsForT)
+		if !loaded {
+			u := uniqueListsForT.(*uniqueListMap[T])
+			freeUnusedMutex.Lock()
+			freeUnusedList = append(freeUnusedList, func() { freeUnused(u) })
+			freeUnusedMutex.Unlock()
 		}
 	}
+	return uniqueListsForT.(*uniqueListMap[T])
+}
+
+// freeUnused walks the entries in a uniqueListMap and removes any whose
+// value is a weak pointer to an object that has been reclaimed.
+func freeUnused[T comparable](u *uniqueListMap[T]) {
+	u.Range(func(key uint64, value weak.Pointer[[]T]) bool {
+		if value.Value() == nil {
+			u.Delete(key)
+		}
+		return true
+	})
 }
diff --git a/uniquelist/uniquelist_test.go b/uniquelist/uniquelist_test.go
index f99f181..20377d3 100644
--- a/uniquelist/uniquelist_test.go
+++ b/uniquelist/uniquelist_test.go
@@ -58,28 +58,8 @@ func TestUniqueList(t *testing.T) {
 			in:   testSlice(1),
 		},
 		{
-			name: "nodeSize_minus_one",
-			in:   testSlice(nodeSize - 1),
-		},
-		{
-			name: "nodeSize",
-			in:   testSlice(nodeSize),
-		},
-		{
-			name: "nodeSize_plus_one",
-			in:   testSlice(nodeSize + 1),
-		},
-		{
-			name: "two_times_nodeSize_minus_one",
-			in:   testSlice(2*nodeSize - 1),
-		},
-		{
-			name: "two_times_nodeSize",
-			in:   testSlice(2 * nodeSize),
-		},
-		{
-			name: "two_times_nodeSize_plus_one",
-			in:   testSlice(2*nodeSize + 1),
+			name: "small",
+			in:   testSlice(8),
 		},
 		{
 			name: "large",
@@ -89,7 +69,12 @@ func TestUniqueList(t *testing.T) {
 
 	for _, testCase := range testCases {
 		t.Run(testCase.name, func(t *testing.T) {
-			uniqueList := Make(testCase.in)
+			uniqueList := Make(slices.Clone(testCase.in))
+			uniqueList2 := Make(slices.Clone(testCase.in))
+
+			if uniqueList != uniqueList2 {
+				t.Errorf("uniqueList != uniqueList2")
+			}
 
 			if g, w := uniqueList.ToSlice(), testCase.in; !slices.Equal(g, w) {
 				t.Errorf("incorrect ToSlice()\nwant: %q\ngot:  %q", w, g)
diff --git a/visit_test.go b/visit_test.go
index f2e22da..d671122 100644
--- a/visit_test.go
+++ b/visit_test.go
@@ -20,6 +20,7 @@ import (
 )
 
 type visitModule struct {
+	ModuleBase
 	SimpleName
 	properties struct {
 		Visit                 []string
```

