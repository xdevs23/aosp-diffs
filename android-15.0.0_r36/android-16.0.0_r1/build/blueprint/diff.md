```diff
diff --git a/Android.bp b/Android.bp
index 8ab0460..051d77c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -39,7 +39,10 @@ bootstrap_go_package {
         "blueprint-metrics",
         "blueprint-parser",
         "blueprint-pathtools",
+        "blueprint-pool",
         "blueprint-proptools",
+        "blueprint-syncmap",
+        "blueprint-uniquelist",
     ],
     pkgPath: "github.com/google/blueprint",
     srcs: [
@@ -58,7 +61,6 @@ bootstrap_go_package {
         "provider.go",
         "scope.go",
         "singleton_ctx.go",
-        "source_file_provider.go",
         "transition.go",
     ],
     testSrcs: [
@@ -137,6 +139,14 @@ bootstrap_go_package {
     ],
 }
 
+bootstrap_go_package {
+    name: "blueprint-pool",
+    pkgPath: "github.com/google/blueprint/pool",
+    srcs: [
+        "pool/pool.go",
+    ],
+}
+
 bootstrap_go_package {
     name: "blueprint-proptools",
     pkgPath: "github.com/google/blueprint/proptools",
diff --git a/bootstrap/bootstrap.go b/bootstrap/bootstrap.go
index 223742e..14d8cc0 100644
--- a/bootstrap/bootstrap.go
+++ b/bootstrap/bootstrap.go
@@ -362,16 +362,14 @@ func (g *GoPackage) GenerateBuildActions(ctx blueprint.ModuleContext) {
 	// Don't build for test-only packages
 	if len(srcs) == 0 && len(genSrcs) == 0 {
 		ctx.Build(pctx, blueprint.BuildParams{
-			Rule:     touch,
-			Outputs:  []string{archiveFile},
-			Optional: true,
+			Rule:    touch,
+			Outputs: []string{archiveFile},
 		})
 		return
 	}
 
 	buildGoPackage(ctx, pkgRoot, g.properties.PkgPath, archiveFile,
 		srcs, genSrcs, g.properties.EmbedSrcs)
-	blueprint.SetProvider(ctx, blueprint.SrcsFileProviderKey, blueprint.SrcsFileProviderData{SrcPaths: srcs})
 	blueprint.SetProvider(ctx, PackageProvider, &PackageInfo{
 		PkgPath:       g.properties.PkgPath,
 		PkgRoot:       pkgRoot,
@@ -517,7 +515,6 @@ func (g *GoBinary) GenerateBuildActions(ctx blueprint.ModuleContext) {
 		Inputs:    []string{archiveFile},
 		Implicits: linkDeps,
 		Args:      linkArgs,
-		Optional:  true,
 	})
 
 	g.outputFile = aoutFile
@@ -533,11 +530,10 @@ func (g *GoBinary) GenerateBuildActions(ctx blueprint.ModuleContext) {
 			Outputs:     []string{g.installPath},
 			Inputs:      []string{aoutFile},
 			Validations: validations,
-			Optional:    !g.properties.Default,
+			Default:     g.properties.Default,
 		})
 	}
 
-	blueprint.SetProvider(ctx, blueprint.SrcsFileProviderKey, blueprint.SrcsFileProviderData{SrcPaths: srcs})
 	blueprint.SetProvider(ctx, BinaryProvider, &BinaryInfo{
 		IntermediatePath: g.outputFile,
 		InstallPath:      g.installPath,
@@ -564,7 +560,6 @@ func buildGoPluginLoader(ctx blueprint.ModuleContext, pkgPath, pluginSrc string)
 			"pkg":     pkgPath,
 			"plugins": strings.Join(pluginPaths, " "),
 		},
-		Optional: true,
 	})
 
 	return ret
@@ -631,7 +626,6 @@ func buildGoPackage(ctx blueprint.ModuleContext, pkgRoot string,
 		Inputs:    srcFiles,
 		Implicits: deps,
 		Args:      compileArgs,
-		Optional:  true,
 	})
 }
 
@@ -660,7 +654,6 @@ func buildGoTest(ctx blueprint.ModuleContext, testRoot, testPkgArchive,
 		Args: map[string]string{
 			"pkg": pkgPath,
 		},
-		Optional: true,
 	})
 
 	linkDeps := []string{testPkgArchive}
@@ -684,7 +677,6 @@ func buildGoTest(ctx blueprint.ModuleContext, testRoot, testPkgArchive,
 			"pkgPath":  "main",
 			"incFlags": "-I " + testRoot,
 		},
-		Optional: true,
 	})
 
 	ctx.Build(pctx, blueprint.BuildParams{
@@ -695,7 +687,6 @@ func buildGoTest(ctx blueprint.ModuleContext, testRoot, testPkgArchive,
 		Args: map[string]string{
 			"libDirFlags": strings.Join(libDirFlags, " "),
 		},
-		Optional: true,
 	})
 
 	ctx.Build(pctx, blueprint.BuildParams{
@@ -707,7 +698,6 @@ func buildGoTest(ctx blueprint.ModuleContext, testRoot, testPkgArchive,
 			"pkg":       pkgPath,
 			"pkgSrcDir": filepath.Dir(testFiles[0]),
 		},
-		Optional: true,
 	})
 
 	return []string{testPassed}
@@ -805,10 +795,6 @@ func (s *singleton) GenerateBuildActions(ctx blueprint.SingletonContext) {
 				"extra":   strings.Join(flags, " "),
 				"pool":    pool,
 			},
-			// soong_ui explicitly requests what it wants to be build. This is
-			// because the same Ninja file contains instructions to run
-			// soong_build, run bp2build and to generate the JSON module graph.
-			Optional:    true,
 			Description: i.Description,
 		})
 	}
@@ -819,6 +805,7 @@ func (s *singleton) GenerateBuildActions(ctx blueprint.SingletonContext) {
 			Rule:    blueprint.Phony,
 			Outputs: []string{"blueprint_tools"},
 			Inputs:  blueprintTools,
+			Default: true,
 		})
 	}
 
@@ -827,14 +814,14 @@ func (s *singleton) GenerateBuildActions(ctx blueprint.SingletonContext) {
 		Rule:    blueprint.Phony,
 		Outputs: []string{"blueprint_tests"},
 		Inputs:  blueprintTests,
+		Default: true,
 	})
 
 	// Add a phony target for running go tests
 	ctx.Build(pctx, blueprint.BuildParams{
-		Rule:     blueprint.Phony,
-		Outputs:  []string{"blueprint_go_packages"},
-		Inputs:   blueprintGoPackages,
-		Optional: true,
+		Rule:    blueprint.Phony,
+		Outputs: []string{"blueprint_go_packages"},
+		Inputs:  blueprintGoPackages,
 	})
 }
 
diff --git a/bootstrap/command.go b/bootstrap/command.go
index 8adaf23..d488f18 100644
--- a/bootstrap/command.go
+++ b/bootstrap/command.go
@@ -166,7 +166,6 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 	}()
 
 	var out blueprint.StringWriterWriter
-	var f *os.File
 	var buf *bufio.Writer
 
 	ctx.BeginEvent("write_files")
@@ -196,12 +195,6 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 		}
 	}
 
-	if f != nil {
-		if err := f.Close(); err != nil {
-			return nil, fmt.Errorf("error closing Ninja file: %s", err)
-		}
-	}
-
 	// TODO(b/357140398): parallelize this with other ninja file writing work.
 	if ctx.GetIncrementalEnabled() {
 		if err := ctx.CacheAllBuildActions(config.(BootstrapConfig).SoongOutDir()); err != nil {
diff --git a/context.go b/context.go
index 2e0d566..1baefda 100644
--- a/context.go
+++ b/context.go
@@ -47,7 +47,10 @@ import (
 	"github.com/google/blueprint/metrics"
 	"github.com/google/blueprint/parser"
 	"github.com/google/blueprint/pathtools"
+	"github.com/google/blueprint/pool"
 	"github.com/google/blueprint/proptools"
+	"github.com/google/blueprint/syncmap"
+	"github.com/google/blueprint/uniquelist"
 )
 
 var ErrBuildActionsNotReady = errors.New("build actions are not ready")
@@ -100,9 +103,9 @@ type Context struct {
 	mutatorInfo         []*mutatorInfo
 	variantMutatorNames []string
 
-	variantCreatingMutatorOrder []string
-
-	transitionMutators []*transitionMutatorImpl
+	completedTransitionMutators int
+	transitionMutators          []*transitionMutatorImpl
+	transitionMutatorNames      []string
 
 	needsUpdateDependencies uint32 // positive if a mutator modified the dependencies
 
@@ -175,11 +178,16 @@ type Context struct {
 	// latter will depend on the flag above.
 	incrementalEnabled bool
 
-	buildActionsToCache       BuildActionCache
-	buildActionsToCacheLock   sync.Mutex
-	buildActionsFromCache     BuildActionCache
-	orderOnlyStringsFromCache OrderOnlyStringsCache
-	orderOnlyStringsToCache   OrderOnlyStringsCache
+	buildActionsCache       BuildActionCache
+	buildActionsToCacheLock sync.Mutex
+	orderOnlyStringsCache   OrderOnlyStringsCache
+	orderOnlyStrings        syncmap.SyncMap[uniquelist.UniqueList[string], *orderOnlyStringsInfo]
+}
+
+type orderOnlyStringsInfo struct {
+	dedup       bool
+	incremental bool
+	dedupName   string
 }
 
 // A container for String keys. The keys can be used to gate build graph traversal
@@ -359,12 +367,25 @@ type moduleInfo struct {
 	obsoletedByNewVariants bool
 
 	// Used by TransitionMutator implementations
-	transitionVariations     []string
-	currentTransitionMutator string
-	requiredVariationsLock   sync.Mutex
+
+	// incomingTransitionInfos stores the map from variation to TransitionInfo object for transitions that were
+	// requested by reverse dependencies.  It is updated by reverse dependencies and protected by
+	// incomingTransitionInfosLock.  It is invalid after the TransitionMutator top down mutator has run on
+	// this module.
+	incomingTransitionInfos     map[string]TransitionInfo
+	incomingTransitionInfosLock sync.Mutex
+	// splitTransitionInfos and splitTransitionVariations stores the list of TransitionInfo objects, and their
+	// corresponding variations, returned by Split or requested by reverse dependencies.  They are valid after the
+	// TransitionMutator top down mutator has run on this module, and invalid after the bottom up mutator has run.
+	splitTransitionInfos      []TransitionInfo
+	splitTransitionVariations []string
+	currentTransitionMutator  string
+
+	// transitionInfos stores the final TransitionInfo for this module indexed by transitionMutatorImpl.index
+	transitionInfos []TransitionInfo
 
 	// outgoingTransitionCache stores the final variation for each dependency, indexed by the source variation
-	// index in transitionVariations and then by the index of the dependency in directDeps
+	// index in splitTransitionInfos and then by the index of the dependency in directDeps
 	outgoingTransitionCache [][]string
 
 	// set during PrepareBuildActions
@@ -432,9 +453,24 @@ func (module *moduleInfo) ModuleCacheKey() string {
 	if variant == "" {
 		variant = "none"
 	}
-	return fmt.Sprintf("%s-%s-%s-%s",
-		strings.ReplaceAll(filepath.Dir(module.relBlueprintsFile), "/", "."),
-		module.Name(), variant, module.typeName)
+	return calculateFileNameHash(fmt.Sprintf("%s-%s-%s-%s",
+		filepath.Dir(module.relBlueprintsFile), module.Name(), variant, module.typeName))
+
+}
+
+func calculateFileNameHash(name string) string {
+	hash, err := proptools.CalculateHash(name)
+	if err != nil {
+		panic(newPanicErrorf(err, "failed to calculate hash for file name: %s", name))
+	}
+	return strconv.FormatUint(hash, 16)
+}
+
+func (c *Context) setModuleTransitionInfo(module *moduleInfo, t *transitionMutatorImpl, info TransitionInfo) {
+	if len(module.transitionInfos) == 0 {
+		module.transitionInfos = make([]TransitionInfo, len(c.transitionMutators))
+	}
+	module.transitionInfos[t.index] = info
 }
 
 // A Variation is a way that a variant of a module differs from other variants of the same module.
@@ -536,11 +572,11 @@ type singletonInfo struct {
 
 type mutatorInfo struct {
 	// set during RegisterMutator
-	topDownMutator    TopDownMutator
-	bottomUpMutator   BottomUpMutator
-	name              string
-	index             int
-	transitionMutator *transitionMutatorImpl
+	transitionPropagateMutator func(BaseModuleContext)
+	bottomUpMutator            BottomUpMutator
+	name                       string
+	index                      int
+	transitionMutator          *transitionMutatorImpl
 
 	usesRename              bool
 	usesReverseDependencies bool
@@ -548,27 +584,27 @@ type mutatorInfo struct {
 	usesCreateModule        bool
 	mutatesDependencies     bool
 	mutatesGlobalState      bool
-	neverFar                bool
 }
 
 func newContext() *Context {
 	eventHandler := metrics.EventHandler{}
 	return &Context{
-		Context:                 context.Background(),
-		EventHandler:            &eventHandler,
-		moduleFactories:         make(map[string]ModuleFactory),
-		nameInterface:           NewSimpleNameInterface(),
-		moduleInfo:              make(map[Module]*moduleInfo),
-		globs:                   make(map[globKey]pathtools.GlobResult),
-		fs:                      pathtools.OsFs,
-		includeTags:             &IncludeTags{},
-		sourceRootDirs:          &SourceRootDirs{},
-		outDir:                  nil,
-		requiredNinjaMajor:      1,
-		requiredNinjaMinor:      7,
-		requiredNinjaMicro:      0,
-		buildActionsToCache:     make(BuildActionCache),
-		orderOnlyStringsToCache: make(OrderOnlyStringsCache),
+		Context:               context.Background(),
+		EventHandler:          &eventHandler,
+		moduleFactories:       make(map[string]ModuleFactory),
+		nameInterface:         NewSimpleNameInterface(),
+		moduleInfo:            make(map[Module]*moduleInfo),
+		globs:                 make(map[globKey]pathtools.GlobResult),
+		fs:                    pathtools.OsFs,
+		includeTags:           &IncludeTags{},
+		sourceRootDirs:        &SourceRootDirs{},
+		outDir:                nil,
+		requiredNinjaMajor:    1,
+		requiredNinjaMinor:    7,
+		requiredNinjaMicro:    0,
+		buildActionsCache:     make(BuildActionCache),
+		orderOnlyStringsCache: make(OrderOnlyStringsCache),
+		orderOnlyStrings:      syncmap.SyncMap[uniquelist.UniqueList[string], *orderOnlyStringsInfo]{},
 	}
 }
 
@@ -711,20 +747,20 @@ func (c *Context) updateBuildActionsCache(key *BuildActionCacheKey, data *BuildA
 	if key != nil {
 		c.buildActionsToCacheLock.Lock()
 		defer c.buildActionsToCacheLock.Unlock()
-		c.buildActionsToCache[*key] = data
+		c.buildActionsCache[*key] = data
 	}
 }
 
 func (c *Context) getBuildActionsFromCache(key *BuildActionCacheKey) *BuildActionCachedData {
-	if c.buildActionsFromCache != nil && key != nil {
-		return c.buildActionsFromCache[*key]
+	if c.buildActionsCache != nil && key != nil {
+		return c.buildActionsCache[*key]
 	}
 	return nil
 }
 
 func (c *Context) CacheAllBuildActions(soongOutDir string) error {
-	return errors.Join(writeToCache(c, soongOutDir, BuildActionsCacheFile, &c.buildActionsToCache),
-		writeToCache(c, soongOutDir, OrderOnlyStringsCacheFile, &c.orderOnlyStringsToCache))
+	return errors.Join(writeToCache(c, soongOutDir, BuildActionsCacheFile, &c.buildActionsCache),
+		writeToCache(c, soongOutDir, OrderOnlyStringsCacheFile, &c.orderOnlyStringsCache))
 }
 
 func writeToCache[T any](ctx *Context, soongOutDir string, fileName string, data *T) error {
@@ -740,10 +776,8 @@ func writeToCache[T any](ctx *Context, soongOutDir string, fileName string, data
 }
 
 func (c *Context) RestoreAllBuildActions(soongOutDir string) error {
-	c.buildActionsFromCache = make(BuildActionCache)
-	c.orderOnlyStringsFromCache = make(OrderOnlyStringsCache)
-	return errors.Join(restoreFromCache(c, soongOutDir, BuildActionsCacheFile, &c.buildActionsFromCache),
-		restoreFromCache(c, soongOutDir, OrderOnlyStringsCacheFile, &c.orderOnlyStringsFromCache))
+	return errors.Join(restoreFromCache(c, soongOutDir, BuildActionsCacheFile, &c.buildActionsCache),
+		restoreFromCache(c, soongOutDir, OrderOnlyStringsCacheFile, &c.orderOnlyStringsCache))
 }
 
 func restoreFromCache[T any](ctx *Context, soongOutDir string, fileName string, data *T) error {
@@ -785,27 +819,20 @@ func singletonTypeName(singleton Singleton) string {
 	return typ.PkgPath() + "." + typ.Name()
 }
 
-// RegisterTopDownMutator registers a mutator that will be invoked to propagate dependency info
-// top-down between Modules.  Each registered mutator is invoked in registration order (mixing
-// TopDownMutators and BottomUpMutators) once per Module, and the invocation on any module will
-// have returned before it is in invoked on any of its dependencies.
-//
-// The mutator type names given here must be unique to all top down mutators in
-// the Context.
-//
-// Returns a MutatorHandle, on which Parallel can be called to set the mutator to visit modules in
-// parallel while maintaining ordering.
-func (c *Context) RegisterTopDownMutator(name string, mutator TopDownMutator) MutatorHandle {
+// registerTransitionPropagateMutator registers a mutator that will be invoked to propagate transition mutator
+// configuration info top-down between Modules.
+func (c *Context) registerTransitionPropagateMutator(name string, mutator func(mctx BaseModuleContext)) MutatorHandle {
 	for _, m := range c.mutatorInfo {
-		if m.name == name && m.topDownMutator != nil {
+		if m.name == name && m.transitionPropagateMutator != nil {
 			panic(fmt.Errorf("mutator %q is already registered", name))
 		}
 	}
 
 	info := &mutatorInfo{
-		topDownMutator: mutator,
-		name:           name,
-		index:          len(c.mutatorInfo),
+		transitionPropagateMutator: mutator,
+
+		name:  name,
+		index: len(c.mutatorInfo),
 	}
 
 	c.mutatorInfo = append(c.mutatorInfo, info)
@@ -814,15 +841,11 @@ func (c *Context) RegisterTopDownMutator(name string, mutator TopDownMutator) Mu
 }
 
 // RegisterBottomUpMutator registers a mutator that will be invoked to split Modules into variants.
-// Each registered mutator is invoked in registration order (mixing TopDownMutators and
-// BottomUpMutators) once per Module, will not be invoked on a module until the invocations on all
-// of the modules dependencies have returned.
+// Each registered mutator is invoked in registration order once per Module, and will not be invoked on a
+// module until the invocations on all of the modules dependencies have returned.
 //
 // The mutator type names given here must be unique to all bottom up or early
 // mutators in the Context.
-//
-// Returns a MutatorHandle, on which Parallel can be called to set the mutator to visit modules in
-// parallel while maintaining ordering.
 func (c *Context) RegisterBottomUpMutator(name string, mutator BottomUpMutator) MutatorHandle {
 	for _, m := range c.variantMutatorNames {
 		if m == name {
@@ -879,7 +902,6 @@ type MutatorHandle interface {
 	MutatesGlobalState() MutatorHandle
 
 	setTransitionMutator(impl *transitionMutatorImpl) MutatorHandle
-	setNeverFar() MutatorHandle
 }
 
 func (mutator *mutatorInfo) UsesRename() MutatorHandle {
@@ -917,11 +939,6 @@ func (mutator *mutatorInfo) setTransitionMutator(impl *transitionMutatorImpl) Mu
 	return mutator
 }
 
-func (mutator *mutatorInfo) setNeverFar() MutatorHandle {
-	mutator.neverFar = true
-	return mutator
-}
-
 // SetIgnoreUnknownModuleTypes sets the behavior of the context in the case
 // where it encounters an unknown module type while parsing Blueprints files. By
 // default, the context will report unknown module types as an error.  If this
@@ -1666,6 +1683,7 @@ func (c *Context) createVariations(origModule *moduleInfo, mutator *mutatorInfo,
 		newModule.properties = newProperties
 		newModule.providers = slices.Clone(origModule.providers)
 		newModule.providerInitialValueHashes = slices.Clone(origModule.providerInitialValueHashes)
+		newModule.transitionInfos = slices.Clone(origModule.transitionInfos)
 
 		newModules = append(newModules, newModule)
 
@@ -1713,20 +1731,6 @@ func chooseDepByIndexes(mutatorName string, variations [][]string) depChooser {
 	}
 }
 
-func chooseDepExplicit(mutatorName string,
-	variationName string, defaultVariationName *string) depChooser {
-	return func(source *moduleInfo, variationIndex, depIndex int, dep depInfo) (*moduleInfo, string) {
-		return chooseDep(dep.module.splitModules, mutatorName, variationName, defaultVariationName)
-	}
-}
-
-func chooseDepInherit(mutatorName string, defaultVariationName *string) depChooser {
-	return func(source *moduleInfo, variationIndex, depIndex int, dep depInfo) (*moduleInfo, string) {
-		sourceVariation := source.variant.variations.get(mutatorName)
-		return chooseDep(dep.module.splitModules, mutatorName, sourceVariation, defaultVariationName)
-	}
-}
-
 func (c *Context) convertDepsToVariation(module *moduleInfo, variationIndex int, depChooser depChooser) (errs []error) {
 	for i, dep := range module.directDeps {
 		if dep.module.obsoletedByNewVariants {
@@ -1960,70 +1964,42 @@ func blueprintDepsMutator(ctx BottomUpMutatorContext) {
 	}
 }
 
-func (c *Context) findReverseDependency(module *moduleInfo, config any, requestedVariations []Variation, destName string) (*moduleInfo, []error) {
-	if destName == module.Name() {
-		return nil, []error{&BlueprintError{
-			Err: fmt.Errorf("%q depends on itself", destName),
-			Pos: module.pos,
-		}}
-	}
-
-	possibleDeps := c.moduleGroupFromName(destName, module.namespace())
-	if possibleDeps == nil {
-		return nil, []error{&BlueprintError{
-			Err: fmt.Errorf("%q has a reverse dependency on undefined module %q",
-				module.Name(), destName),
-			Pos: module.pos,
-		}}
-	}
-
-	if m, _, errs := c.findVariant(module, config, possibleDeps, requestedVariations, false, true); errs != nil {
-		return nil, errs
-	} else if m != nil {
-		return m, nil
-	}
-
-	if c.allowMissingDependencies {
-		// Allow missing variants.
-		return nil, c.discoveredMissingDependencies(module, destName, module.variant.variations)
-	}
-
-	return nil, []error{&BlueprintError{
-		Err: fmt.Errorf("reverse dependency %q of %q missing variant:\n  %s\navailable variants:\n  %s",
-			destName, module.Name(),
-			c.prettyPrintVariant(module.variant.variations),
-			c.prettyPrintGroupVariants(possibleDeps)),
-		Pos: module.pos,
-	}}
-}
-
 // applyTransitions takes a variationMap being used to add a dependency on a module in a moduleGroup
 // and applies the OutgoingTransition and IncomingTransition methods of each completed TransitionMutator to
 // modify the requested variation.  It finds a variant that existed before the TransitionMutator ran that is
 // a subset of the requested variant to use as the module context for IncomingTransition.
 func (c *Context) applyTransitions(config any, module *moduleInfo, group *moduleGroup, variant variationMap,
-	requestedVariations []Variation) (variationMap, []error) {
-	for _, transitionMutator := range c.transitionMutators {
+	requestedVariations []Variation, far bool) (variationMap, []error) {
+	for _, transitionMutator := range c.transitionMutators[:c.completedTransitionMutators] {
 		explicitlyRequested := slices.ContainsFunc(requestedVariations, func(variation Variation) bool {
 			return variation.Mutator == transitionMutator.name
 		})
 
-		sourceVariation := variant.get(transitionMutator.name)
-		outgoingVariation := sourceVariation
-
-		// Apply the outgoing transition if it was not explicitly requested.
-		if !explicitlyRequested {
-			ctx := &outgoingTransitionContextImpl{
+		var outgoingTransitionInfo TransitionInfo
+		if explicitlyRequested {
+			sourceVariation := variant.get(transitionMutator.name)
+			outgoingTransitionInfo = transitionMutator.mutator.TransitionInfoFromVariation(sourceVariation)
+		} else {
+			// Apply the outgoing transition if it was not explicitly requested.
+			var srcTransitionInfo TransitionInfo
+			if (!far || transitionMutator.neverFar) && len(module.transitionInfos) > transitionMutator.index {
+				srcTransitionInfo = module.transitionInfos[transitionMutator.index]
+			}
+			ctx := outgoingTransitionContextPool.Get()
+			*ctx = outgoingTransitionContextImpl{
 				transitionContextImpl{context: c, source: module, dep: nil,
 					depTag: nil, postMutator: true, config: config},
 			}
-			outgoingVariation = transitionMutator.mutator.OutgoingTransition(ctx, sourceVariation)
-			if len(ctx.errs) > 0 {
-				return variationMap{}, ctx.errs
+			outgoingTransitionInfo = transitionMutator.mutator.OutgoingTransition(ctx, srcTransitionInfo)
+			errs := ctx.errs
+			outgoingTransitionContextPool.Put(ctx)
+			ctx = nil
+			if len(errs) > 0 {
+				return variationMap{}, errs
 			}
 		}
 
-		earlierVariantCreatingMutators := c.variantCreatingMutatorOrder[:transitionMutator.variantCreatingMutatorIndex]
+		earlierVariantCreatingMutators := c.transitionMutatorNames[:transitionMutator.index]
 		filteredVariant := variant.cloneMatching(earlierVariantCreatingMutators)
 
 		check := func(inputVariant variationMap) bool {
@@ -2056,16 +2032,24 @@ func (c *Context) applyTransitions(config any, module *moduleInfo, group *module
 
 		if matchingInputVariant != nil {
 			// Apply the incoming transition.
-			ctx := &incomingTransitionContextImpl{
+			ctx := incomingTransitionContextPool.Get()
+			*ctx = incomingTransitionContextImpl{
 				transitionContextImpl{context: c, source: nil, dep: matchingInputVariant,
 					depTag: nil, postMutator: true, config: config},
 			}
 
-			finalVariation := transitionMutator.mutator.IncomingTransition(ctx, outgoingVariation)
-			if len(ctx.errs) > 0 {
-				return variationMap{}, ctx.errs
+			finalTransitionInfo := transitionMutator.mutator.IncomingTransition(ctx, outgoingTransitionInfo)
+			errs := ctx.errs
+			incomingTransitionContextPool.Put(ctx)
+			ctx = nil
+			if len(errs) > 0 {
+				return variationMap{}, errs
 			}
-			variant.set(transitionMutator.name, finalVariation)
+			variation := ""
+			if finalTransitionInfo != nil {
+				variation = finalTransitionInfo.Variation()
+			}
+			variant.set(transitionMutator.name, variation)
 		}
 
 		if (matchingInputVariant == nil && !explicitlyRequested) || variant.get(transitionMutator.name) == "" {
@@ -2088,9 +2072,9 @@ func (c *Context) findVariant(module *moduleInfo, config any,
 	if !far {
 		newVariant = module.variant.variations.clone()
 	} else {
-		for _, mutator := range c.mutatorInfo {
-			if mutator.neverFar {
-				newVariant.set(mutator.name, module.variant.variations.get(mutator.name))
+		for _, transitionMutator := range c.transitionMutators {
+			if transitionMutator.neverFar {
+				newVariant.set(transitionMutator.name, module.variant.variations.get(transitionMutator.name))
 			}
 		}
 	}
@@ -2100,7 +2084,7 @@ func (c *Context) findVariant(module *moduleInfo, config any,
 
 	if !reverse {
 		var errs []error
-		newVariant, errs = c.applyTransitions(config, module, possibleDeps, newVariant, requestedVariations)
+		newVariant, errs = c.applyTransitions(config, module, possibleDeps, newVariant, requestedVariations, far)
 		if len(errs) > 0 {
 			return nil, variationMap{}, errs
 		}
@@ -2855,6 +2839,10 @@ func (c *Context) PrepareBuildActions(config interface{}) (deps []string, errs [
 			return
 		}
 
+		pprof.Do(c.Context, pprof.Labels("blueprint", "GC"), func(ctx context.Context) {
+			runtime.GC()
+		})
+
 		var depsSingletons []string
 		depsSingletons, errs = c.generateSingletonBuildActions(config, c.singletonInfo, c.liveGlobals)
 		if len(errs) > 0 {
@@ -2909,7 +2897,7 @@ func (c *Context) runMutators(ctx context.Context, config interface{}, mutatorGr
 				c.BeginEvent(name)
 				defer c.EndEvent(name)
 				var newDeps []string
-				if mutatorGroup[0].topDownMutator != nil {
+				if mutatorGroup[0].transitionPropagateMutator != nil {
 					newDeps, errs = c.runMutator(config, mutatorGroup, topDownMutator)
 				} else if mutatorGroup[0].bottomUpMutator != nil {
 					newDeps, errs = c.runMutator(config, mutatorGroup, bottomUpMutator)
@@ -2965,7 +2953,7 @@ func (topDownMutatorImpl) run(mutatorGroup []*mutatorInfo, ctx *mutatorContext)
 	if len(mutatorGroup) > 1 {
 		panic(fmt.Errorf("top down mutator group %s must only have 1 mutator, found %d", mutatorGroup[0].name, len(mutatorGroup)))
 	}
-	mutatorGroup[0].topDownMutator(ctx)
+	mutatorGroup[0].transitionPropagateMutator(ctx)
 }
 
 func (topDownMutatorImpl) orderer() visitOrderer {
@@ -2986,6 +2974,8 @@ type reverseDep struct {
 	dep    depInfo
 }
 
+var mutatorContextPool = pool.New[mutatorContext]()
+
 func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 	direction mutatorDirection) (deps []string, errs []error) {
 
@@ -3021,7 +3011,8 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 			panic("split module found in sorted module list")
 		}
 
-		mctx := &mutatorContext{
+		mctx := mutatorContextPool.Get()
+		*mctx = mutatorContext{
 			baseModuleContext: baseModuleContext{
 				context: c,
 				config:  config,
@@ -3052,29 +3043,31 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 
 		module.finishedMutator = mutatorGroup[len(mutatorGroup)-1].index
 
+		hasErrors := false
 		if len(mctx.errs) > 0 {
 			errsCh <- mctx.errs
-			return true
-		}
-
-		if len(mctx.newVariations) > 0 {
-			newVariationsCh <- newVariationPair{mctx.newVariations, origLogicModule}
-		}
+			hasErrors = true
+		} else {
+			if len(mctx.newVariations) > 0 {
+				newVariationsCh <- newVariationPair{mctx.newVariations, origLogicModule}
+			}
 
-		if len(mctx.reverseDeps) > 0 || len(mctx.replace) > 0 || len(mctx.rename) > 0 || len(mctx.newModules) > 0 || len(mctx.ninjaFileDeps) > 0 {
-			globalStateCh <- globalStateChange{
-				reverse:    mctx.reverseDeps,
-				replace:    mctx.replace,
-				rename:     mctx.rename,
-				newModules: mctx.newModules,
-				deps:       mctx.ninjaFileDeps,
+			if len(mctx.reverseDeps) > 0 || len(mctx.replace) > 0 || len(mctx.rename) > 0 || len(mctx.newModules) > 0 || len(mctx.ninjaFileDeps) > 0 {
+				globalStateCh <- globalStateChange{
+					reverse:    mctx.reverseDeps,
+					replace:    mctx.replace,
+					rename:     mctx.rename,
+					newModules: mctx.newModules,
+					deps:       mctx.ninjaFileDeps,
+				}
 			}
 		}
+		mutatorContextPool.Put(mctx)
+		mctx = nil
 
-		return false
+		return hasErrors
 	}
 
-	createdVariations := false
 	var obsoleteLogicModules []Module
 
 	// Process errs and reverseDeps in a single goroutine
@@ -3098,7 +3091,6 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 				for _, module := range newVariations.newVariations {
 					newModuleInfo[module.logicModule] = module
 				}
-				createdVariations = true
 			case <-done:
 				return
 			}
@@ -3127,10 +3119,10 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 
 	c.moduleInfo = newModuleInfo
 
-	isTransitionMutator := mutatorGroup[0].transitionMutator != nil
+	transitionMutator := mutatorGroup[0].transitionMutator
 
 	var transitionMutatorInputVariants map[*moduleGroup][]*moduleInfo
-	if isTransitionMutator {
+	if transitionMutator != nil {
 		transitionMutatorInputVariants = make(map[*moduleGroup][]*moduleInfo)
 	}
 
@@ -3140,7 +3132,7 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 
 			// Update module group to contain newly split variants
 			if module.splitModules != nil {
-				if isTransitionMutator {
+				if transitionMutator != nil {
 					// For transition mutators, save the pre-split variant for reusing later in applyTransitions.
 					transitionMutatorInputVariants[group] = append(transitionMutatorInputVariants[group], module)
 				}
@@ -3168,14 +3160,9 @@ func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 		}
 	}
 
-	if isTransitionMutator {
-		mutatorGroup[0].transitionMutator.inputVariants = transitionMutatorInputVariants
-		mutatorGroup[0].transitionMutator.variantCreatingMutatorIndex = len(c.variantCreatingMutatorOrder)
-		c.transitionMutators = append(c.transitionMutators, mutatorGroup[0].transitionMutator)
-	}
-
-	if createdVariations {
-		c.variantCreatingMutatorOrder = append(c.variantCreatingMutatorOrder, mutatorGroup[0].name)
+	if transitionMutator != nil {
+		transitionMutator.inputVariants = transitionMutatorInputVariants
+		c.completedTransitionMutators = transitionMutator.index + 1
 	}
 
 	// Add in any new reverse dependencies that were added by the mutator
@@ -3344,13 +3331,9 @@ func (c *Context) generateModuleBuildActions(config interface{},
 						}
 					}
 				}()
-				restored, cacheKey := mctx.restoreModuleBuildActions()
-				if !restored {
+				if !mctx.restoreModuleBuildActions() {
 					mctx.module.logicModule.GenerateBuildActions(mctx)
 				}
-				if cacheKey != nil {
-					mctx.cacheModuleBuildActions(cacheKey)
-				}
 			}()
 
 			mctx.module.finishedGenerateBuildActions = true
@@ -4568,23 +4551,20 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 	c.BeginEvent("modules")
 	defer c.EndEvent("modules")
 
-	modules := make([]*moduleInfo, 0, len(c.moduleInfo))
-	incrementalModules := make([]*moduleInfo, 0, 200)
+	var modules []*moduleInfo
+	var incModules []*moduleInfo
 
 	for _, module := range c.moduleInfo {
 		if module.buildActionCacheKey != nil {
-			incrementalModules = append(incrementalModules, module)
+			incModules = append(incModules, module)
 			continue
 		}
 		modules = append(modules, module)
 	}
 	sort.Sort(moduleSorter{modules, c.nameInterface})
-	sort.Sort(moduleSorter{incrementalModules, c.nameInterface})
+	sort.Sort(moduleSorter{incModules, c.nameInterface})
 
-	phonys := c.deduplicateOrderOnlyDeps(append(modules, incrementalModules...))
-	if err := orderOnlyForIncremental(c, incrementalModules, phonys); err != nil {
-		return err
-	}
+	phonys := c.deduplicateOrderOnlyDeps(append(modules, incModules...))
 
 	c.EventHandler.Do("sort_phony_builddefs", func() {
 		// sorting for determinism, the phony output names are stable
@@ -4647,7 +4627,7 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 			wg.Add(1)
 			go func() {
 				defer wg.Done()
-				err := writeIncrementalModules(c, file, incrementalModules, headerTemplate)
+				err := writeIncrementalModules(c, file, incModules, headerTemplate)
 				if err != nil {
 					errorCh <- err
 				}
@@ -4673,70 +4653,6 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 	}
 }
 
-func orderOnlyForIncremental(c *Context, modules []*moduleInfo, phonys *localBuildActions) error {
-	for _, mod := range modules {
-		// find the order only strings of the incremental module, it can come from
-		// the cache or from buildDefs depending on if the module was skipped or not.
-		var orderOnlyStrings []string
-		if mod.incrementalRestored {
-			orderOnlyStrings = mod.orderOnlyStrings
-		} else {
-			for _, b := range mod.actionDefs.buildDefs {
-				// We do similar check when creating phonys in deduplicateOrderOnlyDeps as well
-				if len(b.OrderOnly) > 0 {
-					return fmt.Errorf("order only shouldn't be used: %s", mod.Name())
-				}
-				for _, str := range b.OrderOnlyStrings {
-					if strings.HasPrefix(str, "dedup-") {
-						orderOnlyStrings = append(orderOnlyStrings, str)
-					}
-				}
-			}
-		}
-
-		if len(orderOnlyStrings) == 0 {
-			continue
-		}
-
-		// update the order only string cache with the info found above.
-		if data, ok := c.buildActionsToCache[*mod.buildActionCacheKey]; ok {
-			data.OrderOnlyStrings = orderOnlyStrings
-		}
-
-		if !mod.incrementalRestored {
-			continue
-		}
-
-		// if the module is skipped, the order only string that we restored from the
-		// cache might not exist anymore. For example, if two modules shared the same
-		// set of order only strings initially, deduplicateOrderOnlyDeps would create
-		// a dedup-* phony and replace the order only string with this phony for these
-		// two modules. If one of the module had its order only strings changed, and
-		// we skip the other module in the next build, the dedup-* phony would not
-		// in the phony list anymore, so we need to add it here in order to avoid
-		// writing the ninja statements for the skipped module, otherwise it would
-		// reference a dedup-* phony that no longer exists.
-		for _, dep := range orderOnlyStrings {
-			// nothing changed to this phony, the cached value is still valid
-			if _, ok := c.orderOnlyStringsToCache[dep]; ok {
-				continue
-			}
-			orderOnlyStrings, ok := c.orderOnlyStringsFromCache[dep]
-			if !ok {
-				return fmt.Errorf("no cached value found for order only dep: %s", dep)
-			}
-			phony := buildDef{
-				Rule:          Phony,
-				OutputStrings: []string{dep},
-				InputStrings:  orderOnlyStrings,
-				Optional:      true,
-			}
-			phonys.buildDefs = append(phonys.buildDefs, &phony)
-			c.orderOnlyStringsToCache[dep] = orderOnlyStrings
-		}
-	}
-	return nil
-}
 func writeIncrementalModules(c *Context, baseFile string, modules []*moduleInfo, headerTemplate *template.Template) error {
 	bf, err := c.fs.OpenFile(JoinPath(c.SrcDir(), baseFile), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, OutFilePermissions)
 	if err != nil {
@@ -4751,6 +4667,8 @@ func writeIncrementalModules(c *Context, baseFile string, modules []*moduleInfo,
 	if err != nil {
 		return err
 	}
+
+	c.buildActionsCache = make(BuildActionCache)
 	for _, module := range modules {
 		moduleFile := filepath.Join(ninjaPath, module.ModuleCacheKey()+".ninja")
 		if !module.incrementalRestored {
@@ -4769,6 +4687,9 @@ func writeIncrementalModules(c *Context, baseFile string, modules []*moduleInfo,
 				return err
 			}
 		}
+		if module.buildActionCacheKey != nil {
+			c.cacheModuleBuildActions(module)
+		}
 		bWriter.Subninja(moduleFile)
 	}
 	return nil
@@ -4896,16 +4817,6 @@ func (c *Context) SetBeforePrepareBuildActionsHook(hookFn func() error) {
 	c.BeforePrepareBuildActionsHook = hookFn
 }
 
-// phonyCandidate represents the state of a set of deps that decides its eligibility
-// to be extracted as a phony output
-type phonyCandidate struct {
-	sync.Once
-	phony             *buildDef // the phony buildDef that wraps the set
-	first             *buildDef // the first buildDef that uses this set
-	orderOnlyStrings  []string  // the original OrderOnlyStrings of the first buildDef that uses this set
-	usedByIncremental bool      // if the phony is used by any incremental module
-}
-
 // keyForPhonyCandidate gives a unique identifier for a set of deps.
 func keyForPhonyCandidate(stringDeps []string) uint64 {
 	hasher := fnv.New64a()
@@ -4923,42 +4834,6 @@ func keyForPhonyCandidate(stringDeps []string) uint64 {
 	return hasher.Sum64()
 }
 
-// scanBuildDef is called for every known buildDef `b` that has a non-empty `b.OrderOnly`.
-// If `b.OrderOnly` is not present in `candidates`, it gets stored.
-// But if `b.OrderOnly` already exists in `candidates`, then `b.OrderOnly`
-// (and phonyCandidate#first.OrderOnly) will be replaced with phonyCandidate#phony.Outputs
-func scanBuildDef(candidates *sync.Map, b *buildDef, incremental bool) {
-	key := keyForPhonyCandidate(b.OrderOnlyStrings)
-	if v, loaded := candidates.LoadOrStore(key, &phonyCandidate{
-		first:             b,
-		orderOnlyStrings:  b.OrderOnlyStrings,
-		usedByIncremental: incremental,
-	}); loaded {
-		m := v.(*phonyCandidate)
-		if slices.Equal(m.orderOnlyStrings, b.OrderOnlyStrings) {
-			m.Do(func() {
-				// this is the second occurrence and hence it makes sense to
-				// extract it as a phony output
-				m.phony = &buildDef{
-					Rule:          Phony,
-					OutputStrings: []string{fmt.Sprintf("dedup-%x", key)},
-					InputStrings:  m.first.OrderOnlyStrings,
-					Optional:      true,
-				}
-				// the previously recorded build-def, which first had these deps as its
-				// order-only deps, should now use this phony output instead
-				m.first.OrderOnlyStrings = m.phony.OutputStrings
-				m.first = nil
-			})
-			b.OrderOnlyStrings = m.phony.OutputStrings
-			// don't override the value with false if it was set to true already
-			if incremental {
-				m.usedByIncremental = incremental
-			}
-		}
-	}
-}
-
 // deduplicateOrderOnlyDeps searches for common sets of order-only dependencies across all
 // buildDef instances in the provided moduleInfo instances. Each such
 // common set forms a new buildDef representing a phony output that then becomes
@@ -4967,34 +4842,64 @@ func (c *Context) deduplicateOrderOnlyDeps(modules []*moduleInfo) *localBuildAct
 	c.BeginEvent("deduplicate_order_only_deps")
 	defer c.EndEvent("deduplicate_order_only_deps")
 
-	candidates := sync.Map{} //used as map[key]*candidate
+	var phonys []*buildDef
+	c.orderOnlyStringsCache = make(OrderOnlyStringsCache)
+	c.orderOnlyStrings.Range(func(key uniquelist.UniqueList[string], info *orderOnlyStringsInfo) bool {
+		if info.dedup {
+			dedup := fmt.Sprintf("dedup-%x", keyForPhonyCandidate(key.ToSlice()))
+			phony := &buildDef{
+				Rule:          Phony,
+				OutputStrings: []string{dedup},
+				InputStrings:  key.ToSlice(),
+			}
+			info.dedupName = dedup
+			phonys = append(phonys, phony)
+			if info.incremental {
+				c.orderOnlyStringsCache[phony.OutputStrings[0]] = phony.InputStrings
+			}
+		}
+		return true
+	})
+
 	parallelVisit(slices.Values(modules), unorderedVisitorImpl{}, parallelVisitLimit,
 		func(m *moduleInfo, pause chan<- pauseSpec) bool {
-			incremental := m.buildActionCacheKey != nil
-			for _, b := range m.actionDefs.buildDefs {
-				// The dedup logic doesn't handle the case where OrderOnly is not empty
-				if len(b.OrderOnly) == 0 && len(b.OrderOnlyStrings) > 0 {
-					scanBuildDef(&candidates, b, incremental)
+			for _, def := range m.actionDefs.buildDefs {
+				if info, loaded := c.orderOnlyStrings.Load(def.OrderOnlyStrings); loaded {
+					if info.dedup {
+						def.OrderOnlyStrings = uniquelist.Make([]string{info.dedupName})
+						m.orderOnlyStrings = append(m.orderOnlyStrings, info.dedupName)
+					}
 				}
 			}
 			return false
 		})
 
-	// now collect all created phonys to return
-	var phonys []*buildDef
-	candidates.Range(func(_ any, v any) bool {
-		candidate := v.(*phonyCandidate)
-		if candidate.phony != nil {
-			phonys = append(phonys, candidate.phony)
-			if candidate.usedByIncremental {
-				c.orderOnlyStringsToCache[candidate.phony.OutputStrings[0]] =
-					candidate.phony.InputStrings
-			}
+	return &localBuildActions{buildDefs: phonys}
+}
+
+func (c *Context) cacheModuleBuildActions(module *moduleInfo) {
+	var providers []CachedProvider
+	for i, p := range module.providers {
+		if p != nil && providerRegistry[i].mutator == "" {
+			providers = append(providers,
+				CachedProvider{
+					Id:    providerRegistry[i],
+					Value: &p,
+				})
 		}
-		return true
-	})
+	}
 
-	return &localBuildActions{buildDefs: phonys}
+	// These show up in the ninja file, so we need to cache these to ensure we
+	// re-generate ninja file if they changed.
+	relPos := module.pos
+	relPos.Filename = module.relBlueprintsFile
+	data := BuildActionCachedData{
+		Providers:        providers,
+		Pos:              &relPos,
+		OrderOnlyStrings: module.orderOnlyStrings,
+	}
+
+	c.updateBuildActionsCache(module.buildActionCacheKey, &data)
 }
 
 func (c *Context) writeLocalBuildActions(nw *ninjaWriter,
diff --git a/context_test.go b/context_test.go
index 1a5f8c0..4ab672f 100644
--- a/context_test.go
+++ b/context_test.go
@@ -20,6 +20,7 @@ import (
 	"fmt"
 	"hash/fnv"
 	"os"
+	"path"
 	"reflect"
 	"slices"
 	"strconv"
@@ -31,6 +32,7 @@ import (
 
 	"github.com/google/blueprint/parser"
 	"github.com/google/blueprint/proptools"
+	"github.com/google/blueprint/uniquelist"
 )
 
 type Walker interface {
@@ -74,8 +76,12 @@ var IncrementalTestProviderKey = NewProvider[IncrementalTestProvider]()
 type baseTestModule struct {
 	SimpleName
 	properties struct {
-		Deps         []string
-		Ignored_deps []string
+		Deps             []string
+		Ignored_deps     []string
+		Outputs          []string
+		Order_only       []string
+		Extra_outputs    []string
+		Extra_order_only []string
 	}
 	GenerateBuildActionsCalled bool
 }
@@ -95,11 +101,18 @@ func init() {
 }
 func (b *baseTestModule) GenerateBuildActions(ctx ModuleContext) {
 	b.GenerateBuildActionsCalled = true
-	outputFile := ctx.ModuleName() + "_phony_output"
 	ctx.Build(pctx, BuildParams{
-		Rule:    Phony,
-		Outputs: []string{outputFile},
+		Rule:      Phony,
+		Outputs:   b.properties.Outputs,
+		OrderOnly: b.properties.Order_only,
 	})
+	if len(b.properties.Extra_outputs) > 0 {
+		ctx.Build(pctx, BuildParams{
+			Rule:      Phony,
+			Outputs:   b.properties.Extra_outputs,
+			OrderOnly: b.properties.Extra_order_only,
+		})
+	}
 	SetProvider(ctx, IncrementalTestProviderKey, IncrementalTestProvider{
 		Value: ctx.ModuleName(),
 	})
@@ -119,7 +132,6 @@ func (f *fooModule) Walk() bool {
 }
 
 type barModule struct {
-	SimpleName
 	baseTestModule
 }
 
@@ -133,7 +145,6 @@ func (b *barModule) Walk() bool {
 }
 
 type incrementalModule struct {
-	SimpleName
 	baseTestModule
 	IncrementalModule
 }
@@ -1001,14 +1012,12 @@ func TestDeduplicateOrderOnlyDeps(t *testing.T) {
 		return &buildDef{
 			OutputStrings:    []string{output},
 			InputStrings:     inputs,
-			OrderOnlyStrings: orderOnlyDeps,
+			OrderOnlyStrings: uniquelist.Make(orderOnlyDeps),
 		}
 	}
-	m := func(bs ...*buildDef) *moduleInfo {
-		return &moduleInfo{actionDefs: localBuildActions{buildDefs: bs}}
-	}
+
 	type testcase struct {
-		modules        []*moduleInfo
+		bp             string
 		expectedPhonys []*buildDef
 		conversions    map[string][]string
 	}
@@ -1018,10 +1027,18 @@ func TestDeduplicateOrderOnlyDeps(t *testing.T) {
 		return strconv.FormatUint(hash.Sum64(), 16)
 	}
 	testCases := []testcase{{
-		modules: []*moduleInfo{
-			m(b("A", nil, []string{"d"})),
-			m(b("B", nil, []string{"d"})),
-		},
+		bp: `
+			foo_module {
+					name: "A",
+					outputs: ["A"],
+					order_only: ["d"],
+			}
+			foo_module {
+					name: "B",
+					outputs: ["B"],
+					order_only: ["d"],
+			}
+		`,
 		expectedPhonys: []*buildDef{
 			b("dedup-"+fnvHash("d"), []string{"d"}, nil),
 		},
@@ -1030,16 +1047,36 @@ func TestDeduplicateOrderOnlyDeps(t *testing.T) {
 			"B": []string{"dedup-" + fnvHash("d")},
 		},
 	}, {
-		modules: []*moduleInfo{
-			m(b("A", nil, []string{"a"})),
-			m(b("B", nil, []string{"b"})),
-		},
+		bp: `
+			foo_module {
+					name: "A",
+					outputs: ["A"],
+					order_only: ["a"],
+			}
+			foo_module {
+					name: "B",
+					outputs: ["B"],
+					order_only: ["b"],
+			}
+		`,
 	}, {
-		modules: []*moduleInfo{
-			m(b("A", nil, []string{"a"})),
-			m(b("B", nil, []string{"b"})),
-			m(b("C", nil, []string{"a"})),
-		},
+		bp: `
+			foo_module {
+					name: "A",
+					outputs: ["A"],
+					order_only: ["a"],
+			}
+			foo_module {
+					name: "B",
+					outputs: ["B"],
+					order_only: ["b"],
+			}
+			foo_module {
+					name: "C",
+					outputs: ["C"],
+					order_only: ["a"],
+			}
+		`,
 		expectedPhonys: []*buildDef{b("dedup-"+fnvHash("a"), []string{"a"}, nil)},
 		conversions: map[string][]string{
 			"A": []string{"dedup-" + fnvHash("a")},
@@ -1047,12 +1084,22 @@ func TestDeduplicateOrderOnlyDeps(t *testing.T) {
 			"C": []string{"dedup-" + fnvHash("a")},
 		},
 	}, {
-		modules: []*moduleInfo{
-			m(b("A", nil, []string{"a", "b"}),
-				b("B", nil, []string{"a", "b"})),
-			m(b("C", nil, []string{"a", "c"}),
-				b("D", nil, []string{"a", "c"})),
-		},
+		bp: `
+			foo_module {
+					name: "A",
+					outputs: ["A"],
+					order_only: ["a", "b"],
+					extra_outputs: ["B"],
+					extra_order_only: ["a", "b"],
+			}
+			foo_module {
+					name: "C",
+					outputs: ["C"],
+					order_only: ["a", "c"],
+					extra_outputs: ["D"],
+					extra_order_only: ["a", "c"],
+			}
+		`,
 		expectedPhonys: []*buildDef{
 			b("dedup-"+fnvHash("ab"), []string{"a", "b"}, nil),
 			b("dedup-"+fnvHash("ac"), []string{"a", "c"}, nil)},
@@ -1065,8 +1112,20 @@ func TestDeduplicateOrderOnlyDeps(t *testing.T) {
 	}}
 	for index, tc := range testCases {
 		t.Run(fmt.Sprintf("TestCase-%d", index), func(t *testing.T) {
-			ctx := NewContext()
-			actualPhonys := ctx.deduplicateOrderOnlyDeps(tc.modules)
+			ctx := bpSetup(t, tc.bp)
+			_, errs := ctx.PrepareBuildActions(nil)
+			if len(errs) > 0 {
+				t.Errorf("unexpected errors calling generateModuleBuildActions:")
+				for _, err := range errs {
+					t.Errorf("  %s", err)
+				}
+				t.FailNow()
+			}
+			modules := make([]*moduleInfo, 0, len(ctx.moduleInfo))
+			for _, module := range ctx.moduleInfo {
+				modules = append(modules, module)
+			}
+			actualPhonys := ctx.deduplicateOrderOnlyDeps(modules)
 			if len(actualPhonys.variables) != 0 {
 				t.Errorf("No variables expected but found %v", actualPhonys.variables)
 			}
@@ -1087,7 +1146,7 @@ func TestDeduplicateOrderOnlyDeps(t *testing.T) {
 				}
 			}
 			find := func(k string) *buildDef {
-				for _, m := range tc.modules {
+				for _, m := range modules {
 					for _, b := range m.actionDefs.buildDefs {
 						if reflect.DeepEqual(b.OutputStrings, []string{k}) {
 							return b
@@ -1101,7 +1160,7 @@ func TestDeduplicateOrderOnlyDeps(t *testing.T) {
 				if actual == nil {
 					t.Errorf("Couldn't find %s", k)
 				}
-				if !reflect.DeepEqual(actual.OrderOnlyStrings, conversion) {
+				if !reflect.DeepEqual(actual.OrderOnlyStrings.ToSlice(), conversion) {
 					t.Errorf("expected %s.OrderOnly = %v but got %v", k, conversion, actual.OrderOnly)
 				}
 			}
@@ -1398,23 +1457,15 @@ func TestSourceRootDirs(t *testing.T) {
 	}
 }
 
-func incrementalSetup(t *testing.T) *Context {
+func bpSetup(t *testing.T, bp string) *Context {
 	ctx := NewContext()
 	fileSystem := map[string][]byte{
-		"Android.bp": []byte(`
-			incremental_module {
-					name: "MyIncrementalModule",
-					deps: ["MyBarModule"],
-			}
-
-			bar_module {
-					name: "MyBarModule",
-			}
-		`),
+		"Android.bp": []byte(bp),
 	}
 	ctx.MockFileSystem(fileSystem)
 	ctx.RegisterBottomUpMutator("deps", depsMutator)
 	ctx.RegisterModuleType("incremental_module", newIncrementalModule)
+	ctx.RegisterModuleType("foo_module", newFooModule)
 	ctx.RegisterModuleType("bar_module", newBarModule)
 
 	_, errs := ctx.ParseBlueprintsFiles("Android.bp", nil)
@@ -1438,8 +1489,30 @@ func incrementalSetup(t *testing.T) *Context {
 	return ctx
 }
 
-func incrementalSetupForRestore(t *testing.T, orderOnlyStrings []string) (*Context, any) {
-	ctx := incrementalSetup(t)
+func incrementalSetup(t *testing.T) *Context {
+	bp := `
+			incremental_module {
+					name: "MyIncrementalModule",
+					deps: ["MyBarModule"],
+					outputs: ["MyIncrementalModule_phony_output"],
+					order_only: ["test.lib"],
+			}
+			bar_module {
+					name: "MyBarModule",
+					outputs: ["MyBarModule_phony_output"],
+					order_only: ["test.lib"],
+			}
+			foo_module {
+					name: "MyFooModule",
+					outputs: ["MyFooModule_phony_output"],
+					order_only: ["test.lib"],
+			}
+		`
+
+	return bpSetup(t, bp)
+}
+
+func incrementalSetupForRestore(ctx *Context, orderOnlyStrings []string) any {
 	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
 	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
 
@@ -1476,9 +1549,9 @@ func incrementalSetupForRestore(t *testing.T, orderOnlyStrings []string) (*Conte
 	}
 	ctx.SetIncrementalEnabled(true)
 	ctx.SetIncrementalAnalysis(true)
-	ctx.buildActionsFromCache = toCache
+	ctx.buildActionsCache = toCache
 
-	return ctx, providerValue
+	return providerValue
 }
 
 func calculateHashKey(m *moduleInfo, providerHashes [][]uint64) BuildActionCacheKey {
@@ -1512,13 +1585,17 @@ func TestCacheBuildActions(t *testing.T) {
 		t.FailNow()
 	}
 
+	buf := bytes.NewBuffer(nil)
+	w := newNinjaWriter(buf)
+	ctx.writeAllModuleActions(w, true, "test.ninja")
+
 	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
 	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
-	if len(ctx.buildActionsToCache) != 1 {
+	if len(ctx.buildActionsCache) != 1 {
 		t.Errorf("build actions are not cached for the incremental module")
 	}
 	cacheKey := calculateHashKey(incInfo, [][]uint64{barInfo.providerInitialValueHashes})
-	cache := ctx.buildActionsToCache[cacheKey]
+	cache := ctx.buildActionsCache[cacheKey]
 	if cache == nil {
 		t.Errorf("failed to find cached build actions for the incremental module")
 	}
@@ -1534,6 +1611,7 @@ func TestCacheBuildActions(t *testing.T) {
 			Id:    &IncrementalTestProviderKey.providerKey,
 			Value: &providerValue,
 		}},
+		OrderOnlyStrings: []string{"dedup-d479e9a8133ff998"},
 	}
 	if !reflect.DeepEqual(expectedCache, *cache) {
 		t.Errorf("expected: %v actual %v", expectedCache, *cache)
@@ -1541,7 +1619,8 @@ func TestCacheBuildActions(t *testing.T) {
 }
 
 func TestRestoreBuildActions(t *testing.T) {
-	ctx, providerValue := incrementalSetupForRestore(t, nil)
+	ctx := incrementalSetup(t)
+	providerValue := incrementalSetupForRestore(ctx, nil)
 	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
 	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
 	_, errs := ctx.PrepareBuildActions(nil)
@@ -1566,7 +1645,8 @@ func TestRestoreBuildActions(t *testing.T) {
 }
 
 func TestSkipNinjaForCacheHit(t *testing.T) {
-	ctx, _ := incrementalSetupForRestore(t, nil)
+	ctx := incrementalSetup(t)
+	incrementalSetupForRestore(ctx, nil)
 	_, errs := ctx.PrepareBuildActions(nil)
 	if len(errs) > 0 {
 		t.Errorf("unexpected errors calling generateModuleBuildActions:")
@@ -1591,7 +1671,8 @@ func TestSkipNinjaForCacheHit(t *testing.T) {
 		t.Errorf("ninja file doesn't have build statements for MyBarModule: %s", string(content))
 	}
 
-	file, err = ctx.fs.Open("test_incremental_ninja/.-MyIncrementalModule-none-incremental_module.ninja")
+	file, err = ctx.fs.Open(path.Join("test_incremental_ninja",
+		calculateFileNameHash(".-MyIncrementalModule-none-incremental_module")+".ninja"))
 	if !os.IsNotExist(err) {
 		t.Errorf("shouldn't generate ninja file for MyIncrementalModule: %s", err.Error())
 	}
@@ -1625,7 +1706,8 @@ func TestNotSkipNinjaForCacheMiss(t *testing.T) {
 		t.Errorf("ninja file doesn't have build statements for MyBarModule: %s", string(content))
 	}
 
-	file, err = ctx.fs.Open("test_incremental_ninja/.-MyIncrementalModule-none-incremental_module.ninja")
+	file, err = ctx.fs.Open(path.Join("test_incremental_ninja",
+		calculateFileNameHash(".-MyIncrementalModule-none-incremental_module")+".ninja"))
 	if err != nil {
 		t.Errorf("no ninja file for MyIncrementalModule")
 	}
@@ -1636,6 +1718,7 @@ func TestNotSkipNinjaForCacheMiss(t *testing.T) {
 }
 
 func TestOrderOnlyStringsCaching(t *testing.T) {
+	phony := "dedup-d479e9a8133ff998"
 	ctx := incrementalSetup(t)
 	ctx.SetIncrementalEnabled(true)
 	_, errs := ctx.PrepareBuildActions(nil)
@@ -1648,26 +1731,27 @@ func TestOrderOnlyStringsCaching(t *testing.T) {
 	}
 	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
 	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
-	bDef := buildDef{
-		Rule:             Phony,
-		OrderOnlyStrings: []string{"test.lib"},
-	}
-	incInfo.actionDefs.buildDefs = append(incInfo.actionDefs.buildDefs, &bDef)
-	barInfo.actionDefs.buildDefs = append(barInfo.actionDefs.buildDefs, &bDef)
 
 	buf := bytes.NewBuffer(nil)
 	w := newNinjaWriter(buf)
 	ctx.writeAllModuleActions(w, true, "test.ninja")
 
 	verifyOrderOnlyStringsCache(t, ctx, incInfo, barInfo)
+
+	// Verify dedup-d479e9a8133ff998 is written to the common ninja file.
+	expected := strings.Join([]string{"build", phony + ":", "phony", "test.lib"}, " ")
+	if strings.Count(buf.String(), expected) != 1 {
+		t.Errorf("only one phony target should be found: %s", buf.String())
+	}
 }
 
 func TestOrderOnlyStringsRestoring(t *testing.T) {
 	phony := "dedup-d479e9a8133ff998"
 	orderOnlyStrings := []string{phony}
-	ctx, _ := incrementalSetupForRestore(t, orderOnlyStrings)
-	ctx.orderOnlyStringsFromCache = make(OrderOnlyStringsCache)
-	ctx.orderOnlyStringsFromCache[phony] = []string{"test.lib"}
+	ctx := incrementalSetup(t)
+	incrementalSetupForRestore(ctx, orderOnlyStrings)
+	ctx.orderOnlyStringsCache = make(OrderOnlyStringsCache)
+	ctx.orderOnlyStringsCache[phony] = []string{"test.lib"}
 	_, errs := ctx.PrepareBuildActions(nil)
 	if len(errs) > 0 {
 		t.Errorf("unexpected errors calling generateModuleBuildActions:")
@@ -1677,34 +1761,187 @@ func TestOrderOnlyStringsRestoring(t *testing.T) {
 		t.FailNow()
 	}
 
+	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
+
 	buf := bytes.NewBuffer(nil)
 	w := newNinjaWriter(buf)
 	ctx.writeAllModuleActions(w, true, "test.ninja")
 
 	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
+	verifyOrderOnlyStringsCache(t, ctx, incInfo, barInfo)
+
+	verifyBuildDefsShouldContain(t, barInfo, phony)
+	// Verify dedup-d479e9a8133ff998 is written to the common ninja file.
+	expected := strings.Join([]string{"build", phony + ":", "phony", "test.lib"}, " ")
+	if strings.Count(buf.String(), expected) != 1 {
+		t.Errorf("only one phony target should be found: %s", buf.String())
+	}
+
+	if len(ctx.orderOnlyStringsCache) != 1 {
+		t.Errorf("Phony target should be cached: %s", buf.String())
+	}
+}
+
+func TestOrderOnlyStringsValidWhenOnlyRestoredModuleUseIt(t *testing.T) {
+	phony := "dedup-d479e9a8133ff998"
+	orderOnlyStrings := []string{phony}
+	bp := `
+			incremental_module {
+					name: "MyIncrementalModule",
+					deps: ["MyBarModule"],
+					outputs: ["MyIncrementalModule_phony_output"],
+					order_only: ["test.lib"],
+			}
+			bar_module {
+					name: "MyBarModule",
+					outputs: ["MyBarModule_phony_output"],
+			}
+		`
+
+	ctx := bpSetup(t, bp)
+	incrementalSetupForRestore(ctx, orderOnlyStrings)
+	ctx.orderOnlyStringsCache = make(OrderOnlyStringsCache)
+	ctx.orderOnlyStringsCache[phony] = []string{"test.lib"}
+	_, errs := ctx.PrepareBuildActions(nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected errors calling generateModuleBuildActions:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+
 	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
+
+	buf := bytes.NewBuffer(nil)
+	w := newNinjaWriter(buf)
+	ctx.writeAllModuleActions(w, true, "test.ninja")
+
+	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
 	verifyOrderOnlyStringsCache(t, ctx, incInfo, barInfo)
 
 	// Verify dedup-d479e9a8133ff998 is still written to the common ninja file even
 	// though MyBarModule no longer uses it.
 	expected := strings.Join([]string{"build", phony + ":", "phony", "test.lib"}, " ")
-	if !strings.Contains(buf.String(), expected) {
-		t.Errorf("phony target not found: %s", buf.String())
+	if strings.Count(buf.String(), expected) != 1 {
+		t.Errorf("only one phony target should be found: %s", buf.String())
+	}
+
+	if len(ctx.orderOnlyStringsCache) != 1 {
+		t.Errorf("Phony target should be cached: %s", buf.String())
+	}
+}
+
+func TestCachedModuleRemoved(t *testing.T) {
+	phony := "dedup-d479e9a8133ff998"
+	orderOnlyStrings := []string{phony}
+	ctx := incrementalSetup(t)
+	incrementalSetupForRestore(ctx, orderOnlyStrings)
+	bp := `
+			bar_module {
+					name: "MyBarModule",
+					outputs: ["MyBarModule_phony_output"],
+					order_only: ["test.lib"],
+			}
+		`
+	ctx = bpSetup(t, bp)
+	ctx.orderOnlyStringsCache = make(OrderOnlyStringsCache)
+	ctx.orderOnlyStringsCache[phony] = []string{"test.lib"}
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
+	// Verify dedup-d479e9a8133ff998 is no longer written to the common ninja file
+	// because MyIncrementalModule was removed so only MyBarModule still use it.
+	expected := strings.Join([]string{"build", phony + ":", "phony", "test.lib"}, " ")
+	if strings.Count(buf.String(), expected) != 0 {
+		t.Errorf("Phony target should not be present in ninja file: %s", buf.String())
+	}
+	if len(ctx.orderOnlyStringsCache) != 0 {
+		t.Errorf("Phony target should not be cached: %s", buf.String())
+	}
+	if len(ctx.buildActionsCache) != 0 {
+		t.Errorf("No module should be cached: %v", ctx.buildActionsCache)
+	}
+}
+
+// This tests the scenario where one restored module and two non-restored modules
+// share the same set of order only strings. The two non-restored modules will
+// contribute a dedup phony target in this case, and the restored module shouldn't
+// add a duplicate one.
+func TestSharedOrderOnlyStringsRestoringNoDuplicates(t *testing.T) {
+	phony := "dedup-d479e9a8133ff998"
+	orderOnlyStrings := []string{phony}
+	ctx := incrementalSetup(t)
+	incrementalSetupForRestore(ctx, orderOnlyStrings)
+	ctx.orderOnlyStringsCache = make(OrderOnlyStringsCache)
+	ctx.orderOnlyStringsCache[phony] = []string{"test.lib"}
+
+	_, errs := ctx.PrepareBuildActions(nil)
+	if len(errs) > 0 {
+		t.Errorf("unexpected errors calling generateModuleBuildActions:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
+	fooInfo := ctx.moduleGroupFromName("MyFooModule", nil).modules.firstModule()
+	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
+
+	buf := bytes.NewBuffer(nil)
+	w := newNinjaWriter(buf)
+	ctx.writeAllModuleActions(w, true, "test.ninja")
+
+	verifyOrderOnlyStringsCache(t, ctx, incInfo, barInfo)
+	verifyBuildDefsShouldContain(t, fooInfo, phony)
+	verifyBuildDefsShouldContain(t, barInfo, phony)
+
+	// Verify dedup-d479e9a8133ff998 is written to the common ninja file.
+	expected := strings.Join([]string{"build", phony + ":", "phony", "test.lib"}, " ")
+	if strings.Count(buf.String(), expected) != 1 {
+		t.Errorf("only one phony target should be found: %s", buf.String())
+	}
+
+	if len(ctx.orderOnlyStringsCache) != 1 {
+		t.Errorf("Phony target should be cached: %s", buf.String())
+	}
+}
+
+func verifyBuildDefsShouldContain(t *testing.T, module *moduleInfo, expected string) {
+	found := false
+	for _, def := range module.actionDefs.buildDefs {
+		found = listContainsValue(def.OrderOnlyStrings.ToSlice(), expected)
+		if found {
+			break
+		}
+	}
+	if !found {
+		t.Errorf("%s should have dedup phony target: %v", module.Name(), module.actionDefs.buildDefs)
 	}
 }
 
 func verifyOrderOnlyStringsCache(t *testing.T, ctx *Context, incInfo, barInfo *moduleInfo) {
 	// Verify that soong cache all the order only strings that are used by the
 	// incremental modules
-	ok, key := mapContainsValue(ctx.orderOnlyStringsToCache, "test.lib")
+	ok, key := mapContainsValue(ctx.orderOnlyStringsCache, "test.lib")
 	if !ok {
-		t.Errorf("no order only strings used by incremetnal modules cached: %v", ctx.orderOnlyStringsToCache)
+		t.Errorf("no order only strings used by incremetnal modules cached: %v", ctx.orderOnlyStringsCache)
 	}
 
 	// Verify that the dedup-* order only strings used by MyIncrementalModule is
 	// cached along with its other cached values
 	cacheKey := calculateHashKey(incInfo, [][]uint64{barInfo.providerInitialValueHashes})
-	cache := ctx.buildActionsToCache[cacheKey]
+	cache := ctx.buildActionsCache[cacheKey]
 	if cache == nil {
 		t.Errorf("failed to find cached build actions for the incremental module")
 	}
diff --git a/depset/Android.bp b/depset/Android.bp
index 3f76663..b4e9f2a 100644
--- a/depset/Android.bp
+++ b/depset/Android.bp
@@ -3,6 +3,7 @@ bootstrap_go_package {
     pkgPath: "github.com/google/blueprint/depset",
     deps: [
         "blueprint-gobtools",
+        "blueprint-uniquelist",
     ],
     srcs: [
         "depset.go",
diff --git a/depset/depset.go b/depset/depset.go
index ff4ad8a..a4a73e2 100644
--- a/depset/depset.go
+++ b/depset/depset.go
@@ -18,8 +18,10 @@ import (
 	"fmt"
 	"iter"
 	"slices"
+	"unique"
 
 	"github.com/google/blueprint/gobtools"
+	"github.com/google/blueprint/uniquelist"
 )
 
 // DepSet is designed to be conceptually compatible with Bazel's depsets:
@@ -60,21 +62,28 @@ type depSettableType comparable
 // duplicated element is not guaranteed).
 //
 // A DepSet is created by New or NewBuilder.Build from the slice for direct contents
-// and the *DepSets of dependencies. A DepSet is immutable once created.
+// and the DepSets of dependencies. A DepSet is immutable once created.
+//
+// DepSets are stored using UniqueList which uses the unique package to intern them, which ensures
+// that the graph semantics of the DepSet are maintained even after serializing/deserializing or
+// when mixing newly created and deserialized DepSets.
 type DepSet[T depSettableType] struct {
-	handle *depSet[T]
+	// handle is a unique.Handle to an internal depSet object, which makes DepSets effectively a
+	// single pointer.
+	handle unique.Handle[depSet[T]]
 }
 
 type depSet[T depSettableType] struct {
 	preorder   bool
 	reverse    bool
 	order      Order
-	direct     []T
-	transitive []DepSet[T]
+	direct     uniquelist.UniqueList[T]
+	transitive uniquelist.UniqueList[DepSet[T]]
 }
 
-func (d DepSet[T]) impl() *depSet[T] {
-	return d.handle
+// impl returns a copy of the uniquified  depSet for a DepSet.
+func (d DepSet[T]) impl() depSet[T] {
+	return d.handle.Value()
 }
 
 func (d DepSet[T]) order() Order {
@@ -96,19 +105,19 @@ func (d *DepSet[T]) ToGob() *depSetGob[T] {
 		Preorder:   impl.preorder,
 		Reverse:    impl.reverse,
 		Order:      impl.order,
-		Direct:     impl.direct,
-		Transitive: impl.transitive,
+		Direct:     impl.direct.ToSlice(),
+		Transitive: impl.transitive.ToSlice(),
 	}
 }
 
 func (d *DepSet[T]) FromGob(data *depSetGob[T]) {
-	d.handle = &depSet[T]{
+	d.handle = unique.Make(depSet[T]{
 		preorder:   data.Preorder,
 		reverse:    data.Reverse,
 		order:      data.Order,
-		direct:     data.Direct,
-		transitive: data.Transitive,
-	}
+		direct:     uniquelist.Make(data.Direct),
+		transitive: uniquelist.Make(data.Transitive),
+	})
 }
 
 func (d DepSet[T]) GobEncode() ([]byte, error) {
@@ -123,12 +132,18 @@ func (d *DepSet[T]) GobDecode(data []byte) error {
 func New[T depSettableType](order Order, direct []T, transitive []DepSet[T]) DepSet[T] {
 	var directCopy []T
 	var transitiveCopy []DepSet[T]
+
+	// Create a zero value of DepSet, which will be used to check if the unique.Handle is the zero value.
+	var zeroDepSet DepSet[T]
+
 	nonEmptyTransitiveCount := 0
 	for _, t := range transitive {
-		if t.handle != nil {
-			if t.order() != order {
+		// A zero valued DepSet has no associated unique.Handle for a depSet.  It has no contents, so it can
+		// be skipped.
+		if t != zeroDepSet {
+			if t.handle.Value().order != order {
 				panic(fmt.Errorf("incompatible order, new DepSet is %s but transitive DepSet is %s",
-					order, t.order()))
+					order, t.handle.Value().order))
 			}
 			nonEmptyTransitiveCount++
 		}
@@ -147,25 +162,34 @@ func New[T depSettableType](order Order, direct []T, transitive []DepSet[T]) Dep
 	} else {
 		transitiveIter = slices.All(transitive)
 	}
+
+	// Copy only the non-zero-valued elements in the transitive list.  transitiveIter may be a forwards
+	// or backards iterator.
 	for _, t := range transitiveIter {
-		if t.handle != nil {
+		if t != zeroDepSet {
 			transitiveCopy = append(transitiveCopy, t)
 		}
 	}
 
+	// Optimization:  If both the direct and transitive lists are empty then this DepSet is semantically
+	// equivalent to the zero valued DepSet (effectively a nil pointer).  Returning the zero value will
+	// allow this DepSet to be skipped in DepSets that reference this one as a transitive input, saving
+	// memory.
 	if len(directCopy) == 0 && len(transitive) == 0 {
-		return DepSet[T]{nil}
+		return DepSet[T]{}
 	}
 
-	depSet := &depSet[T]{
+	// Create a depSet to hold the contents.
+	depSet := depSet[T]{
 		preorder:   order == PREORDER,
 		reverse:    order == TOPOLOGICAL,
 		order:      order,
-		direct:     directCopy,
-		transitive: transitiveCopy,
+		direct:     uniquelist.Make(directCopy),
+		transitive: uniquelist.Make(transitiveCopy),
 	}
 
-	return DepSet[T]{depSet}
+	// Uniquify the depSet and store it in a DepSet.
+	return DepSet[T]{unique.Make(depSet)}
 }
 
 // Builder is used to create an immutable DepSet.
@@ -200,8 +224,9 @@ func (b *Builder[T]) Direct(direct ...T) *Builder[T] {
 // Transitive adds transitive contents to the DepSet being built by a Builder. Newly added
 // transitive contents are to the right of any existing transitive contents.
 func (b *Builder[T]) Transitive(transitive ...DepSet[T]) *Builder[T] {
+	var zeroDepSet DepSet[T]
 	for _, t := range transitive {
-		if t.handle != nil && t.order() != b.order {
+		if t != zeroDepSet && t.order() != b.order {
 			panic(fmt.Errorf("incompatible order, new DepSet is %s but transitive DepSet is %s",
 				b.order, t.order()))
 		}
@@ -216,30 +241,33 @@ func (b *Builder[T]) Build() DepSet[T] {
 	return New(b.order, b.direct, b.transitive)
 }
 
-// walk calls the visit method in depth-first order on a DepSet, preordered if d.preorder is set,
+// collect collects the contents of the DepSet in depth-first order, preordered if d.preorder is set,
 // otherwise postordered.
-func (d DepSet[T]) walk(visit func([]T)) {
+func (d DepSet[T]) collect() []T {
 	visited := make(map[DepSet[T]]bool)
+	var list []T
 
 	var dfs func(d DepSet[T])
 	dfs = func(d DepSet[T]) {
 		impl := d.impl()
 		visited[d] = true
 		if impl.preorder {
-			visit(impl.direct)
+			list = impl.direct.AppendTo(list)
 		}
-		for _, dep := range impl.transitive {
+		for dep := range impl.transitive.Iter() {
 			if !visited[dep] {
 				dfs(dep)
 			}
 		}
 
 		if !impl.preorder {
-			visit(impl.direct)
+			list = impl.direct.AppendTo(list)
 		}
 	}
 
 	dfs(d)
+
+	return list
 }
 
 // ToList returns the DepSet flattened to a list.  The order in the list is based on the order
@@ -249,14 +277,12 @@ func (d DepSet[T]) walk(visit func([]T)) {
 // its transitive dependencies, in which case the ordering of the duplicated element is not
 // guaranteed).
 func (d DepSet[T]) ToList() []T {
-	if d.handle == nil {
+	var zeroDepSet unique.Handle[depSet[T]]
+	if d.handle == zeroDepSet {
 		return nil
 	}
 	impl := d.impl()
-	var list []T
-	d.walk(func(paths []T) {
-		list = append(list, paths...)
-	})
+	list := d.collect()
 	list = firstUniqueInPlace(list)
 	if impl.reverse {
 		slices.Reverse(list)
diff --git a/module_ctx.go b/module_ctx.go
index 22c24a5..a21b102 100644
--- a/module_ctx.go
+++ b/module_ctx.go
@@ -26,6 +26,7 @@ import (
 	"github.com/google/blueprint/parser"
 	"github.com/google/blueprint/pathtools"
 	"github.com/google/blueprint/proptools"
+	"github.com/google/blueprint/uniquelist"
 )
 
 // A Module handles generating all of the Ninja build actions needed to build a
@@ -106,6 +107,8 @@ type Module interface {
 	// during its generate phase.  This call should generate all Ninja build
 	// actions (rules, pools, and build statements) needed to build the module.
 	GenerateBuildActions(ModuleContext)
+
+	String() string
 }
 
 type ModuleProxy struct {
@@ -118,10 +121,17 @@ func CreateModuleProxy(module Module) ModuleProxy {
 	}
 }
 
+func (m ModuleProxy) IsNil() bool {
+	return m.module == nil
+}
+
 func (m ModuleProxy) Name() string {
 	return m.module.Name()
 }
 
+func (m ModuleProxy) String() string {
+	return m.module.String()
+}
 func (m ModuleProxy) GenerateBuildActions(context ModuleContext) {
 	m.module.GenerateBuildActions(context)
 }
@@ -233,10 +243,7 @@ type BaseModuleContext interface {
 	// none exists.  It panics if the dependency does not have the specified tag.
 	GetDirectDepWithTag(name string, tag DependencyTag) Module
 
-	// GetDirectDep returns the Module and DependencyTag for the  direct dependency with the specified
-	// name, or nil if none exists.  If there are multiple dependencies on the same module it returns
-	// the first DependencyTag.
-	GetDirectDep(name string) (Module, DependencyTag)
+	GetDirectDepProxyWithTag(name string, tag DependencyTag) *ModuleProxy
 
 	// VisitDirectDeps calls visit for each direct dependency.  If there are multiple direct dependencies on the same
 	// module visit will be called multiple times on that module and OtherModuleDependencyTag will return a different
@@ -337,6 +344,9 @@ type BaseModuleContext interface {
 	// dependencies on the module being visited, it returns the dependency tag used for the current dependency.
 	OtherModuleDependencyTag(m Module) DependencyTag
 
+	// OtherModuleSubDir returns the string representing the variations of the module.
+	OtherModuleSubDir(m Module) string
+
 	// OtherModuleExists returns true if a module with the specified name exists, as determined by the NameInterface
 	// passed to Context.SetNameInterface, or SimpleNameInterface if it was not called.
 	OtherModuleExists(name string) bool
@@ -379,6 +389,8 @@ type BaseModuleContext interface {
 	// This method shouldn't be used directly, prefer the type-safe android.OtherModuleProvider instead.
 	OtherModuleProvider(m Module, provider AnyProviderKey) (any, bool)
 
+	OtherModuleHasProvider(m Module, provider AnyProviderKey) bool
+
 	// OtherModuleIsAutoGenerated returns true if a module has been generated from another module,
 	// instead of being defined in Android.bp file
 	OtherModuleIsAutoGenerated(m Module) bool
@@ -401,8 +413,6 @@ type BaseModuleContext interface {
 
 	EarlyGetMissingDependencies() []string
 
-	EqualModules(m1, m2 Module) bool
-
 	base() *baseModuleContext
 }
 
@@ -515,7 +525,7 @@ func (d *baseModuleContext) PropertyErrorf(property, format string,
 func (d *baseModuleContext) OtherModulePropertyErrorf(logicModule Module, property string, format string,
 	args ...interface{}) {
 
-	d.error(d.context.PropertyErrorf(logicModule, property, format, args...))
+	d.error(d.context.PropertyErrorf(getWrappedModule(logicModule), property, format, args...))
 }
 
 func (d *baseModuleContext) Failed() bool {
@@ -548,7 +558,7 @@ type moduleContext struct {
 	handledMissingDeps bool
 }
 
-func (m *baseModuleContext) EqualModules(m1, m2 Module) bool {
+func EqualModules(m1, m2 Module) bool {
 	return getWrappedModule(m1) == getWrappedModule(m2)
 }
 
@@ -606,6 +616,10 @@ func (m *baseModuleContext) OtherModuleDependencyTag(logicModule Module) Depende
 	return nil
 }
 
+func (m *baseModuleContext) OtherModuleSubDir(logicModule Module) string {
+	return m.context.ModuleSubDir(getWrappedModule(logicModule))
+}
+
 func (m *baseModuleContext) ModuleFromName(name string) (Module, bool) {
 	moduleGroup, exists := m.context.nameInterface.ModuleFromName(name, m.module.namespace())
 	if exists {
@@ -669,6 +683,11 @@ func (m *baseModuleContext) OtherModuleProvider(logicModule Module, provider Any
 	return m.context.provider(module, provider.provider())
 }
 
+func (m *baseModuleContext) OtherModuleHasProvider(logicModule Module, provider AnyProviderKey) bool {
+	module := m.context.moduleInfo[getWrappedModule(logicModule)]
+	return m.context.hasProvider(module, provider.provider())
+}
+
 func (m *baseModuleContext) Provider(provider AnyProviderKey) (any, bool) {
 	return m.context.provider(m.module, provider.provider())
 }
@@ -677,31 +696,7 @@ func (m *baseModuleContext) SetProvider(provider AnyProviderKey, value interface
 	m.context.setProvider(m.module, provider.provider(), value)
 }
 
-func (m *moduleContext) cacheModuleBuildActions(key *BuildActionCacheKey) {
-	var providers []CachedProvider
-	for i, p := range m.module.providers {
-		if p != nil && providerRegistry[i].mutator == "" {
-			providers = append(providers,
-				CachedProvider{
-					Id:    providerRegistry[i],
-					Value: &p,
-				})
-		}
-	}
-
-	// These show up in the ninja file, so we need to cache these to ensure we
-	// re-generate ninja file if they changed.
-	relPos := m.module.pos
-	relPos.Filename = m.module.relBlueprintsFile
-	data := BuildActionCachedData{
-		Providers: providers,
-		Pos:       &relPos,
-	}
-
-	m.context.updateBuildActionsCache(key, &data)
-}
-
-func (m *moduleContext) restoreModuleBuildActions() (bool, *BuildActionCacheKey) {
+func (m *moduleContext) restoreModuleBuildActions() bool {
 	// Whether the incremental flag is set and the module type supports
 	// incremental, this will decide weather to cache the data for the module.
 	incrementalEnabled := false
@@ -751,20 +746,37 @@ func (m *moduleContext) restoreModuleBuildActions() (bool, *BuildActionCacheKey)
 			m.module.incrementalRestored = true
 			m.module.orderOnlyStrings = data.OrderOnlyStrings
 			restored = true
+			for _, str := range data.OrderOnlyStrings {
+				if !strings.HasPrefix(str, "dedup-") {
+					continue
+				}
+				orderOnlyStrings, ok := m.context.orderOnlyStringsCache[str]
+				if !ok {
+					panic(fmt.Errorf("no cached value found for order only dep: %s", str))
+				}
+				key := uniquelist.Make(orderOnlyStrings)
+				if info, loaded := m.context.orderOnlyStrings.LoadOrStore(key, &orderOnlyStringsInfo{
+					dedup:       true,
+					incremental: true,
+				}); loaded {
+					for {
+						cpy := *info
+						cpy.dedup = true
+						cpy.incremental = true
+						if m.context.orderOnlyStrings.CompareAndSwap(key, info, &cpy) {
+							break
+						}
+						if info, loaded = m.context.orderOnlyStrings.Load(key); !loaded {
+							// This shouldn't happen
+							panic("order only string was removed unexpectedly")
+						}
+					}
+				}
+			}
 		}
 	}
 
-	return restored, cacheKey
-}
-
-func (m *baseModuleContext) GetDirectDep(name string) (Module, DependencyTag) {
-	for _, dep := range m.module.directDeps {
-		if dep.module.Name() == name {
-			return dep.module.logicModule, dep.tag
-		}
-	}
-
-	return nil, nil
+	return restored
 }
 
 func (m *baseModuleContext) GetDirectDepWithTag(name string, tag DependencyTag) Module {
@@ -785,6 +797,15 @@ func (m *baseModuleContext) GetDirectDepWithTag(name string, tag DependencyTag)
 	return nil
 }
 
+func (m *baseModuleContext) GetDirectDepProxyWithTag(name string, tag DependencyTag) *ModuleProxy {
+	module := m.GetDirectDepWithTag(name, tag)
+	if module != nil {
+		return &ModuleProxy{module}
+	}
+
+	return nil
+}
+
 func (m *baseModuleContext) VisitDirectDeps(visit func(Module)) {
 	defer func() {
 		if r := recover(); r != nil {
@@ -989,6 +1010,25 @@ func (m *moduleContext) Build(pctx PackageContext, params BuildParams) {
 	}
 
 	m.actionDefs.buildDefs = append(m.actionDefs.buildDefs, def)
+	if def.OrderOnlyStrings.Len() > 0 {
+		if info, loaded := m.context.orderOnlyStrings.LoadOrStore(def.OrderOnlyStrings, &orderOnlyStringsInfo{
+			dedup:       false,
+			incremental: m.module.buildActionCacheKey != nil,
+		}); loaded {
+			for {
+				cpy := *info
+				cpy.dedup = true
+				cpy.incremental = cpy.incremental || m.module.buildActionCacheKey != nil
+				if m.context.orderOnlyStrings.CompareAndSwap(def.OrderOnlyStrings, info, &cpy) {
+					break
+				}
+				if info, loaded = m.context.orderOnlyStrings.Load(def.OrderOnlyStrings); !loaded {
+					// This shouldn't happen
+					panic("order only string was removed unexpectedly")
+				}
+			}
+		}
+	}
 }
 
 func (m *moduleContext) GetMissingDependencies() []string {
@@ -1016,10 +1056,6 @@ type mutatorContext struct {
 	pauseCh          chan<- pauseSpec
 }
 
-type TopDownMutatorContext interface {
-	BaseModuleContext
-}
-
 type BottomUpMutatorContext interface {
 	BaseModuleContext
 
@@ -1102,7 +1138,6 @@ type BottomUpMutatorContext interface {
 // The Mutator function should only modify members of properties structs, and not
 // members of the module struct itself, to ensure the modified values are copied
 // if a second Mutator chooses to split the module a second time.
-type TopDownMutator func(mctx TopDownMutatorContext)
 type BottomUpMutator func(mctx BottomUpMutatorContext)
 
 // DependencyTag is an interface to an arbitrary object that embeds BaseDependencyTag.  It can be
@@ -1120,31 +1155,23 @@ func (BaseDependencyTag) dependencyTag(DependencyTag) {
 
 var _ DependencyTag = BaseDependencyTag{}
 
-func (mctx *mutatorContext) createVariationsWithTransition(variationNames []string, outgoingTransitions [][]string) []Module {
-	return mctx.createVariations(variationNames, chooseDepByIndexes(mctx.mutator.name, outgoingTransitions))
-}
-
-func (mctx *mutatorContext) createVariations(variationNames []string, depChooser depChooser) []Module {
-	var ret []Module
+func (mctx *mutatorContext) createVariationsWithTransition(variationNames []string, outgoingTransitions [][]string) []*moduleInfo {
+	depChooser := chooseDepByIndexes(mctx.mutator.name, outgoingTransitions)
 	modules, errs := mctx.context.createVariations(mctx.module, mctx.mutator, depChooser, variationNames)
 	if len(errs) > 0 {
 		mctx.errs = append(mctx.errs, errs...)
 	}
 
-	for _, module := range modules {
-		ret = append(ret, module.logicModule)
-	}
-
 	if mctx.newVariations != nil {
 		panic("module already has variations from this mutator")
 	}
 	mctx.newVariations = modules
 
-	if len(ret) != len(variationNames) {
+	if len(modules) != len(variationNames) {
 		panic("oops!")
 	}
 
-	return ret
+	return modules
 }
 
 func (mctx *mutatorContext) Module() Module {
@@ -1168,8 +1195,8 @@ func (mctx *mutatorContext) AddDependency(module Module, tag DependencyTag, deps
 	return depInfos
 }
 
-func (mctx *mutatorContext) AddReverseDependency(module Module, tag DependencyTag, destName string) {
-	if !mctx.mutator.usesReverseDependencies {
+func (m *mutatorContext) AddReverseDependency(module Module, tag DependencyTag, name string) {
+	if !m.mutator.usesReverseDependencies {
 		panic(fmt.Errorf("method AddReverseDependency called from mutator that was not marked UsesReverseDependencies"))
 	}
 
@@ -1177,24 +1204,13 @@ func (mctx *mutatorContext) AddReverseDependency(module Module, tag DependencyTa
 		panic("BaseDependencyTag is not allowed to be used directly!")
 	}
 
-	destModule, errs := mctx.context.findReverseDependency(mctx.context.moduleInfo[module], mctx.config, nil, destName)
-	if len(errs) > 0 {
-		mctx.errs = append(mctx.errs, errs...)
-		return
-	}
-
-	if destModule == nil {
-		// allowMissingDependencies is true and the module wasn't found
-		return
+	if module != m.module.logicModule {
+		panic(fmt.Errorf("AddReverseDependency called with module that is not the current module"))
 	}
-
-	mctx.reverseDeps = append(mctx.reverseDeps, reverseDep{
-		destModule,
-		depInfo{mctx.context.moduleInfo[module], tag},
-	})
+	m.AddReverseVariationDependency(nil, tag, name)
 }
 
-func (mctx *mutatorContext) AddReverseVariationDependency(variations []Variation, tag DependencyTag, destName string) {
+func (mctx *mutatorContext) AddReverseVariationDependency(variations []Variation, tag DependencyTag, name string) {
 	if !mctx.mutator.usesReverseDependencies {
 		panic(fmt.Errorf("method AddReverseVariationDependency called from mutator that was not marked UsesReverseDependencies"))
 	}
@@ -1203,19 +1219,40 @@ func (mctx *mutatorContext) AddReverseVariationDependency(variations []Variation
 		panic("BaseDependencyTag is not allowed to be used directly!")
 	}
 
-	destModule, errs := mctx.context.findReverseDependency(mctx.module, mctx.config, variations, destName)
-	if len(errs) > 0 {
+	possibleDeps := mctx.context.moduleGroupFromName(name, mctx.module.namespace())
+	if possibleDeps == nil {
+		mctx.errs = append(mctx.errs, &BlueprintError{
+			Err: fmt.Errorf("%q has a reverse dependency on undefined module %q",
+				mctx.module.Name(), name),
+			Pos: mctx.module.pos,
+		})
+		return
+	}
+
+	found, newVariant, errs := mctx.context.findVariant(mctx.module, mctx.config, possibleDeps, variations, false, true)
+	if errs != nil {
 		mctx.errs = append(mctx.errs, errs...)
 		return
 	}
 
-	if destModule == nil {
-		// allowMissingDependencies is true and the module wasn't found
+	if found == nil {
+		if mctx.context.allowMissingDependencies {
+			// Allow missing variants.
+			mctx.errs = append(mctx.errs, mctx.context.discoveredMissingDependencies(mctx.module, name, newVariant)...)
+		} else {
+			mctx.errs = append(mctx.errs, &BlueprintError{
+				Err: fmt.Errorf("reverse dependency %q of %q missing variant:\n  %s\navailable variants:\n  %s",
+					name, mctx.module.Name(),
+					mctx.context.prettyPrintVariant(newVariant),
+					mctx.context.prettyPrintGroupVariants(possibleDeps)),
+				Pos: mctx.module.pos,
+			})
+		}
 		return
 	}
 
 	mctx.reverseDeps = append(mctx.reverseDeps, reverseDep{
-		destModule,
+		found,
 		depInfo{mctx.module, tag},
 	})
 }
@@ -1270,11 +1307,11 @@ func (mctx *mutatorContext) ReplaceDependenciesIf(name string, predicate Replace
 	targets := mctx.context.moduleVariantsThatDependOn(name, mctx.module)
 
 	if len(targets) == 0 {
-		panic(fmt.Errorf("ReplaceDependencies could not find identical variant {%s} for module %s\n"+
-			"available variants:\n  %s",
-			mctx.context.prettyPrintVariant(mctx.module.variant.variations),
+		panic(fmt.Errorf("ReplaceDependenciesIf could not find variant of %s that depends on %s variant %s",
 			name,
-			mctx.context.prettyPrintGroupVariants(mctx.context.moduleGroupFromName(name, mctx.module.namespace()))))
+			mctx.module.group.name,
+			mctx.context.prettyPrintVariant(mctx.module.variant.variations),
+		))
 	}
 
 	for _, target := range targets {
@@ -1347,6 +1384,10 @@ func (s *SimpleName) Name() string {
 	return s.Properties.Name
 }
 
+func (s *SimpleName) String() string {
+	return s.Name()
+}
+
 // Load Hooks
 
 type LoadHookContext interface {
diff --git a/module_ctx_test.go b/module_ctx_test.go
index 9b7727d..f319fb6 100644
--- a/module_ctx_test.go
+++ b/module_ctx_test.go
@@ -170,6 +170,29 @@ func TestAddVariationDependencies(t *testing.T) {
 
 }
 
+func TestInvalidModuleNames(t *testing.T) {
+	t.Helper()
+	bp := `
+		test {
+			name: "fo o", // contains space
+		}
+	`
+
+	mockFS := map[string][]byte{
+		"Android.bp": []byte(bp),
+	}
+
+	ctx := NewContext()
+	ctx.RegisterModuleType("test", newModuleCtxTestModule)
+
+	ctx.MockFileSystem(mockFS)
+	_, errs := ctx.ParseFileList(".", []string{"Android.bp"}, nil)
+
+	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "should use a valid name") {
+		t.Errorf("Expected invalid name exception, found %s", errs)
+	}
+}
+
 func TestCheckBlueprintSyntax(t *testing.T) {
 	factories := map[string]ModuleFactory{
 		"test": newModuleCtxTestModule,
@@ -262,10 +285,6 @@ func addNinjaDepsTestBottomUpMutator(ctx BottomUpMutatorContext) {
 	ctx.AddNinjaFileDeps("BottomUpMutator")
 }
 
-func addNinjaDepsTestTopDownMutator(ctx TopDownMutatorContext) {
-	ctx.AddNinjaFileDeps("TopDownMutator")
-}
-
 type addNinjaDepsTestSingleton struct{}
 
 func addNinjaDepsTestSingletonFactory() Singleton {
@@ -288,7 +307,6 @@ func TestAddNinjaFileDeps(t *testing.T) {
 
 	ctx.RegisterModuleType("test", addNinjaDepsTestModuleFactory)
 	ctx.RegisterBottomUpMutator("testBottomUpMutator", addNinjaDepsTestBottomUpMutator)
-	ctx.RegisterTopDownMutator("testTopDownMutator", addNinjaDepsTestTopDownMutator)
 	ctx.RegisterSingletonType("testSingleton", addNinjaDepsTestSingletonFactory, false)
 	parseDeps, errs := ctx.ParseBlueprintsFiles("Android.bp", nil)
 	if len(errs) > 0 {
@@ -321,7 +339,7 @@ func TestAddNinjaFileDeps(t *testing.T) {
 		t.Errorf("ParseBlueprintsFiles: wanted deps %q, got %q", w, g)
 	}
 
-	if g, w := resolveDeps, []string{"BottomUpMutator", "TopDownMutator"}; !reflect.DeepEqual(g, w) {
+	if g, w := resolveDeps, []string{"BottomUpMutator"}; !reflect.DeepEqual(g, w) {
 		t.Errorf("ResolveDependencies: wanted deps %q, got %q", w, g)
 	}
 
diff --git a/name_interface.go b/name_interface.go
index db82453..f018d4b 100644
--- a/name_interface.go
+++ b/name_interface.go
@@ -18,6 +18,7 @@ import (
 	"fmt"
 	"sort"
 	"strings"
+	"unicode"
 )
 
 // This file exposes the logic of locating a module via a query string, to enable
@@ -131,11 +132,43 @@ func (s *SimpleNameInterface) NewModule(ctx NamespaceContext, group ModuleGroup,
 		}
 	}
 
+	if !isValidModuleName(name) {
+		return nil, []error{
+			// seven characters at the start of the second line to align with the string "error: "
+			fmt.Errorf("module %q should use a valid name.\n"+
+				"       Special chars like spaces are not allowed.", name),
+		}
+	}
+
 	s.modules[name] = group
 
 	return nil, []error{}
 }
 
+// Leters, Digits, Underscore, `+` (libc++), `.` are valid chars for module names.
+// Additional chars like `-` were added to the list to account for module names
+// that predate the enforcement of this check.
+var allowedSpecialCharsInModuleNames = map[rune]bool{
+	'_': true,
+	'-': true,
+	'.': true,
+	'/': true,
+	'@': true,
+	'+': true,
+	'&': true,
+}
+
+func isValidModuleName(name string) bool {
+	for _, c := range name {
+		_, allowedSpecialChar := allowedSpecialCharsInModuleNames[c]
+		valid := unicode.IsLetter(c) || unicode.IsDigit(c) || allowedSpecialChar
+		if !valid {
+			return false
+		}
+	}
+	return len(name) > 0
+}
+
 func (s *SimpleNameInterface) NewSkippedModule(ctx NamespaceContext, name string, info SkippedModuleInfo) {
 	if name == "" {
 		return
diff --git a/ninja_defs.go b/ninja_defs.go
index c640311..ef0c4b4 100644
--- a/ninja_defs.go
+++ b/ninja_defs.go
@@ -20,6 +20,8 @@ import (
 	"sort"
 	"strconv"
 	"strings"
+
+	"github.com/google/blueprint/uniquelist"
 )
 
 // A Deps value indicates the dependency file format that Ninja should expect to
@@ -89,7 +91,8 @@ type BuildParams struct {
 	OrderOnly       []string          // The list of order-only dependencies.
 	Validations     []string          // The list of validations to run when this rule runs.
 	Args            map[string]string // The variable/value pairs to set.
-	Optional        bool              // Skip outputting a default statement
+	Default         bool              // Output a ninja default statement
+	PhonyOutput     bool              // This is a phony_output
 }
 
 // A poolDef describes a pool definition.  It does not include the name of the
@@ -261,12 +264,12 @@ type buildDef struct {
 	Implicits             []*ninjaString
 	ImplicitStrings       []string
 	OrderOnly             []*ninjaString
-	OrderOnlyStrings      []string
+	OrderOnlyStrings      uniquelist.UniqueList[string]
 	Validations           []*ninjaString
 	ValidationStrings     []string
 	Args                  map[Variable]*ninjaString
 	Variables             map[string]*ninjaString
-	Optional              bool
+	Default               bool
 }
 
 func formatTags(tags map[string]string, rule Rule) string {
@@ -333,17 +336,20 @@ func parseBuildParams(scope scope, params *BuildParams,
 		return nil, fmt.Errorf("error parsing Implicits param: %s", err)
 	}
 
-	b.OrderOnly, b.OrderOnlyStrings, err = parseNinjaOrSimpleStrings(scope, params.OrderOnly)
+	var orderOnlyStrings []string
+	b.OrderOnly, orderOnlyStrings, err = parseNinjaOrSimpleStrings(scope, params.OrderOnly)
 	if err != nil {
 		return nil, fmt.Errorf("error parsing OrderOnly param: %s", err)
 	}
 
+	b.OrderOnlyStrings = uniquelist.Make(orderOnlyStrings)
+
 	b.Validations, b.ValidationStrings, err = parseNinjaOrSimpleStrings(scope, params.Validations)
 	if err != nil {
 		return nil, fmt.Errorf("error parsing Validations param: %s", err)
 	}
 
-	b.Optional = params.Optional
+	b.Default = params.Default
 
 	if params.Depfile != "" {
 		value, err := parseNinjaString(scope, params.Depfile)
@@ -394,6 +400,10 @@ func parseBuildParams(scope scope, params *BuildParams,
 		}
 	}
 
+	if params.PhonyOutput {
+		setVariable("phony_output", simpleNinjaString("true"))
+	}
+
 	return b, nil
 }
 
@@ -422,7 +432,7 @@ func (b *buildDef) WriteTo(nw *ninjaWriter, nameTracker *nameTracker) error {
 
 	err := nw.Build(comment, rule, outputs, implicitOuts, explicitDeps, implicitDeps, orderOnlyDeps, validations,
 		outputStrings, implicitOutStrings, explicitDepStrings,
-		implicitDepStrings, orderOnlyDepStrings, validationStrings,
+		implicitDepStrings, orderOnlyDepStrings.ToSlice(), validationStrings,
 		nameTracker)
 	if err != nil {
 		return err
@@ -452,7 +462,7 @@ func (b *buildDef) WriteTo(nw *ninjaWriter, nameTracker *nameTracker) error {
 		}
 	}
 
-	if !b.Optional {
+	if b.Default {
 		err = nw.Default(nameTracker, outputs, outputStrings)
 		if err != nil {
 			return err
diff --git a/ninja_strings.go b/ninja_strings.go
index c351b93..0513bea 100644
--- a/ninja_strings.go
+++ b/ninja_strings.go
@@ -437,7 +437,7 @@ func toNinjaName(name string) string {
 	return ret.String()
 }
 
-var builtinRuleArgs = []string{"out", "in"}
+var builtinRuleArgs = []string{"out", "in", "in_newline"}
 
 func validateArgName(argName string) error {
 	err := validateNinjaName(argName)
diff --git a/parser/parser.go b/parser/parser.go
index 8d36e53..a54eb46 100644
--- a/parser/parser.go
+++ b/parser/parser.go
@@ -555,6 +555,12 @@ func (p *parser) parseSelect() Expression {
 			default:
 				p.errorf("Expected a string, true, false, or default, got %s", p.scanner.TokenText())
 			}
+		case scanner.Int:
+			if i := p.parseIntValue(); i != nil {
+				result.Value = i
+				return result
+			}
+			p.errorf("Expected a string, int, true, false, or default, got %s", p.scanner.TokenText())
 		case scanner.String:
 			if s := p.parseStringValue(); s != nil {
 				if strings.HasPrefix(s.Value, "__soong") {
@@ -566,7 +572,7 @@ func (p *parser) parseSelect() Expression {
 			}
 			fallthrough
 		default:
-			p.errorf("Expected a string, true, false, or default, got %s", p.scanner.TokenText())
+			p.errorf("Expected a string, int, true, false, or default, got %s", p.scanner.TokenText())
 		}
 		return result
 	}
@@ -638,6 +644,12 @@ func (p *parser) parseSelect() Expression {
 			} else {
 				return false
 			}
+		case *Int64:
+			if b2, ok := b.Value.(*Int64); ok {
+				return a2.Value == b2.Value
+			} else {
+				return false
+			}
 		default:
 			// true so that we produce an error in this unexpected scenario
 			return true
diff --git a/pool/pool.go b/pool/pool.go
new file mode 100644
index 0000000..d257ec8
--- /dev/null
+++ b/pool/pool.go
@@ -0,0 +1,42 @@
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
+package pool
+
+import (
+	"sync"
+)
+
+type Pool[T any] struct {
+	pool sync.Pool
+}
+
+func New[T any]() Pool[T] {
+	return Pool[T]{
+		pool: sync.Pool{
+			New: func() any {
+				var zero T
+				return &zero
+			},
+		},
+	}
+}
+
+func (p *Pool[T]) Get() *T {
+	return p.pool.Get().(*T)
+}
+
+func (p *Pool[T]) Put(t *T) {
+	p.pool.Put(t)
+}
diff --git a/proptools/configurable.go b/proptools/configurable.go
index a97328d..0d45134 100644
--- a/proptools/configurable.go
+++ b/proptools/configurable.go
@@ -52,7 +52,7 @@ func (o *ConfigurableOptional[T]) GetOrDefault(other T) T {
 }
 
 type ConfigurableElements interface {
-	string | bool | []string
+	string | bool | []string | int64
 }
 
 type ConfigurableEvaluator interface {
@@ -127,6 +127,7 @@ type configurableValueType int
 const (
 	configurableValueTypeString configurableValueType = iota
 	configurableValueTypeBool
+	configurableValueTypeInt64
 	configurableValueTypeUndefined
 	configurableValueTypeStringList
 )
@@ -137,6 +138,8 @@ func (v *configurableValueType) patternType() configurablePatternType {
 		return configurablePatternTypeString
 	case configurableValueTypeBool:
 		return configurablePatternTypeBool
+	case configurableValueTypeInt64:
+		return configurablePatternTypeInt64
 	case configurableValueTypeStringList:
 		return configurablePatternTypeStringList
 	default:
@@ -150,6 +153,8 @@ func (v *configurableValueType) String() string {
 		return "string"
 	case configurableValueTypeBool:
 		return "bool"
+	case configurableValueTypeInt64:
+		return "int"
 	case configurableValueTypeStringList:
 		return "string_list"
 	case configurableValueTypeUndefined:
@@ -165,6 +170,7 @@ type ConfigurableValue struct {
 	typ             configurableValueType
 	stringValue     string
 	boolValue       bool
+	int64Value      int64
 	stringListValue []string
 }
 
@@ -174,6 +180,8 @@ func (c *ConfigurableValue) toExpression() parser.Expression {
 		return &parser.Bool{Value: c.boolValue}
 	case configurableValueTypeString:
 		return &parser.String{Value: c.stringValue}
+	case configurableValueTypeInt64:
+		return &parser.Int64{Value: c.int64Value}
 	case configurableValueTypeStringList:
 		result := &parser.List{}
 		for _, s := range c.stringListValue {
@@ -195,6 +203,8 @@ func (c *ConfigurableValue) String() string {
 		} else {
 			return "false"
 		}
+	case configurableValueTypeInt64:
+		return strconv.FormatInt(c.int64Value, 10)
 	case configurableValueTypeUndefined:
 		return "undefined"
 	default:
@@ -216,6 +226,13 @@ func ConfigurableValueBool(b bool) ConfigurableValue {
 	}
 }
 
+func ConfigurableValueInt(i int64) ConfigurableValue {
+	return ConfigurableValue{
+		typ:        configurableValueTypeInt64,
+		int64Value: i,
+	}
+}
+
 func ConfigurableValueStringList(l []string) ConfigurableValue {
 	return ConfigurableValue{
 		typ:             configurableValueTypeStringList,
@@ -234,6 +251,7 @@ type configurablePatternType int
 const (
 	configurablePatternTypeString configurablePatternType = iota
 	configurablePatternTypeBool
+	configurablePatternTypeInt64
 	configurablePatternTypeStringList
 	configurablePatternTypeDefault
 	configurablePatternTypeAny
@@ -245,6 +263,8 @@ func (v *configurablePatternType) String() string {
 		return "string"
 	case configurablePatternTypeBool:
 		return "bool"
+	case configurablePatternTypeInt64:
+		return "int64"
 	case configurablePatternTypeStringList:
 		return "string_list"
 	case configurablePatternTypeDefault:
@@ -270,6 +290,7 @@ type ConfigurablePattern struct {
 	typ         configurablePatternType
 	stringValue string
 	boolValue   bool
+	int64Value  int64
 	binding     string
 }
 
@@ -285,6 +306,11 @@ func (c ConfigurablePattern) toParserSelectPattern() parser.SelectPattern {
 			Value:   &parser.Bool{Value: c.boolValue},
 			Binding: parser.Variable{Name: c.binding},
 		}
+	case configurablePatternTypeInt64:
+		return parser.SelectPattern{
+			Value:   &parser.Int64{Value: c.int64Value},
+			Binding: parser.Variable{Name: c.binding},
+		}
 	case configurablePatternTypeDefault:
 		return parser.SelectPattern{
 			Value:   &parser.String{Value: "__soong_conditions_default__"},
@@ -338,6 +364,8 @@ func (p *ConfigurablePattern) matchesValue(v ConfigurableValue) bool {
 		return p.stringValue == v.stringValue
 	case configurablePatternTypeBool:
 		return p.boolValue == v.boolValue
+	case configurablePatternTypeInt64:
+		return p.int64Value == v.int64Value
 	default:
 		panic("unimplemented")
 	}
@@ -426,6 +454,8 @@ func configurableCaseType(configuredType reflect.Type) reflect.Type {
 		return reflect.TypeOf(ConfigurableCase[string]{})
 	case reflect.Bool:
 		return reflect.TypeOf(ConfigurableCase[bool]{})
+	case reflect.Int64:
+		return reflect.TypeOf(ConfigurableCase[int64]{})
 	case reflect.Slice:
 		switch configuredType.Elem().Kind() {
 		case reflect.String:
@@ -1218,6 +1248,12 @@ func expressionToConfiguredValue[T ConfigurableElements](expr parser.Expression,
 		} else {
 			return nil, fmt.Errorf("can't assign bool value to %s property", configuredTypeToString[T]())
 		}
+	case *parser.Int64:
+		if result, ok := any(&e.Value).(*T); ok {
+			return result, nil
+		} else {
+			return nil, fmt.Errorf("can't assign int64 value to %s property", configuredTypeToString[T]())
+		}
 	case *parser.List:
 		result := make([]string, 0, len(e.Values))
 		for _, x := range e.Values {
@@ -1263,6 +1299,8 @@ func configuredTypeToString[T ConfigurableElements]() string {
 		return "string"
 	case bool:
 		return "bool"
+	case int64:
+		return "int64"
 	case []string:
 		return "list of strings"
 	default:
diff --git a/proptools/hash_provider.go b/proptools/hash_provider.go
index c75bb7f..04e09b7 100644
--- a/proptools/hash_provider.go
+++ b/proptools/hash_provider.go
@@ -22,7 +22,7 @@ import (
 	"hash/fnv"
 	"math"
 	"reflect"
-	"sort"
+	"slices"
 	"unsafe"
 )
 
@@ -32,97 +32,145 @@ import (
 var recordSeparator []byte = []byte{36}
 
 func CalculateHash(value interface{}) (uint64, error) {
-	hasher := fnv.New64()
-	ptrs := make(map[uintptr]bool)
+	hasher := hasher{
+		Hash64:   fnv.New64(),
+		int64Buf: make([]byte, 8),
+	}
 	v := reflect.ValueOf(value)
 	var err error
 	if v.IsValid() {
-		err = calculateHashInternal(hasher, v, ptrs)
+		err = hasher.calculateHash(v)
 	}
 	return hasher.Sum64(), err
 }
 
-func calculateHashInternal(hasher hash.Hash64, v reflect.Value, ptrs map[uintptr]bool) error {
-	var int64Array [8]byte
-	int64Buf := int64Array[:]
-	binary.LittleEndian.PutUint64(int64Buf, uint64(v.Kind()))
-	hasher.Write(int64Buf)
+type hasher struct {
+	hash.Hash64
+	int64Buf      []byte
+	ptrs          map[uintptr]bool
+	mapStateCache *mapState
+}
+
+type mapState struct {
+	indexes []int
+	keys    []reflect.Value
+	values  []reflect.Value
+}
+
+func (hasher *hasher) writeUint64(i uint64) {
+	binary.LittleEndian.PutUint64(hasher.int64Buf, i)
+	hasher.Write(hasher.int64Buf)
+}
+
+func (hasher *hasher) writeInt(i int) {
+	hasher.writeUint64(uint64(i))
+}
+
+func (hasher *hasher) writeByte(i byte) {
+	hasher.int64Buf[0] = i
+	hasher.Write(hasher.int64Buf[:1])
+}
+
+func (hasher *hasher) getMapState(size int) *mapState {
+	s := hasher.mapStateCache
+	// Clear hasher.mapStateCache so that any recursive uses don't collide with this frame.
+	hasher.mapStateCache = nil
+
+	if s == nil {
+		s = &mapState{}
+	}
+
+	// Reset the slices to length `size` and capacity at least `size`
+	s.indexes = slices.Grow(s.indexes[:0], size)[0:size]
+	s.keys = slices.Grow(s.keys[:0], size)[0:size]
+	s.values = slices.Grow(s.values[:0], size)[0:size]
+
+	return s
+}
+
+func (hasher *hasher) putMapState(s *mapState) {
+	if hasher.mapStateCache == nil || cap(hasher.mapStateCache.indexes) < cap(s.indexes) {
+		hasher.mapStateCache = s
+	}
+}
+
+func (hasher *hasher) calculateHash(v reflect.Value) error {
+	hasher.writeUint64(uint64(v.Kind()))
 	v.IsValid()
 	switch v.Kind() {
 	case reflect.Struct:
-		binary.LittleEndian.PutUint64(int64Buf, uint64(v.NumField()))
-		hasher.Write(int64Buf)
-		for i := 0; i < v.NumField(); i++ {
+		l := v.NumField()
+		hasher.writeInt(l)
+		for i := 0; i < l; i++ {
 			hasher.Write(recordSeparator)
-			err := calculateHashInternal(hasher, v.Field(i), ptrs)
+			err := hasher.calculateHash(v.Field(i))
 			if err != nil {
 				return fmt.Errorf("in field %s: %s", v.Type().Field(i).Name, err.Error())
 			}
 		}
 	case reflect.Map:
-		binary.LittleEndian.PutUint64(int64Buf, uint64(v.Len()))
-		hasher.Write(int64Buf)
-		indexes := make([]int, v.Len())
-		keys := make([]reflect.Value, v.Len())
-		values := make([]reflect.Value, v.Len())
+		l := v.Len()
+		hasher.writeInt(l)
 		iter := v.MapRange()
+		s := hasher.getMapState(l)
 		for i := 0; iter.Next(); i++ {
-			indexes[i] = i
-			keys[i] = iter.Key()
-			values[i] = iter.Value()
+			s.indexes[i] = i
+			s.keys[i] = iter.Key()
+			s.values[i] = iter.Value()
 		}
-		sort.SliceStable(indexes, func(i, j int) bool {
-			return compare_values(keys[indexes[i]], keys[indexes[j]]) < 0
+		slices.SortFunc(s.indexes, func(i, j int) int {
+			return compare_values(s.keys[i], s.keys[j])
 		})
-		for i := 0; i < v.Len(); i++ {
+		for i := 0; i < l; i++ {
 			hasher.Write(recordSeparator)
-			err := calculateHashInternal(hasher, keys[indexes[i]], ptrs)
+			err := hasher.calculateHash(s.keys[s.indexes[i]])
 			if err != nil {
 				return fmt.Errorf("in map: %s", err.Error())
 			}
 			hasher.Write(recordSeparator)
-			err = calculateHashInternal(hasher, keys[indexes[i]], ptrs)
+			err = hasher.calculateHash(s.keys[s.indexes[i]])
 			if err != nil {
 				return fmt.Errorf("in map: %s", err.Error())
 			}
 		}
+		hasher.putMapState(s)
 	case reflect.Slice, reflect.Array:
-		binary.LittleEndian.PutUint64(int64Buf, uint64(v.Len()))
-		hasher.Write(int64Buf)
-		for i := 0; i < v.Len(); i++ {
+		l := v.Len()
+		hasher.writeInt(l)
+		for i := 0; i < l; i++ {
 			hasher.Write(recordSeparator)
-			err := calculateHashInternal(hasher, v.Index(i), ptrs)
+			err := hasher.calculateHash(v.Index(i))
 			if err != nil {
 				return fmt.Errorf("in %s at index %d: %s", v.Kind().String(), i, err.Error())
 			}
 		}
 	case reflect.Pointer:
 		if v.IsNil() {
-			int64Buf[0] = 0
-			hasher.Write(int64Buf[:1])
+			hasher.writeByte(0)
 			return nil
 		}
 		// Hardcoded value to indicate it is a pointer
-		binary.LittleEndian.PutUint64(int64Buf, uint64(0x55))
-		hasher.Write(int64Buf)
+		hasher.writeInt(0x55)
 		addr := v.Pointer()
-		if _, ok := ptrs[addr]; ok {
+		if hasher.ptrs == nil {
+			hasher.ptrs = make(map[uintptr]bool)
+		}
+		if _, ok := hasher.ptrs[addr]; ok {
 			// We could make this an error if we want to disallow pointer cycles in the future
 			return nil
 		}
-		ptrs[addr] = true
-		err := calculateHashInternal(hasher, v.Elem(), ptrs)
+		hasher.ptrs[addr] = true
+		err := hasher.calculateHash(v.Elem())
 		if err != nil {
 			return fmt.Errorf("in pointer: %s", err.Error())
 		}
 	case reflect.Interface:
 		if v.IsNil() {
-			int64Buf[0] = 0
-			hasher.Write(int64Buf[:1])
+			hasher.writeByte(0)
 		} else {
 			// The only way get the pointer out of an interface to hash it or check for cycles
 			// would be InterfaceData(), but that's deprecated and seems like it has undefined behavior.
-			err := calculateHashInternal(hasher, v.Elem(), ptrs)
+			err := hasher.calculateHash(v.Elem())
 			if err != nil {
 				return fmt.Errorf("in interface: %s", err.Error())
 			}
@@ -131,27 +179,22 @@ func calculateHashInternal(hasher hash.Hash64, v reflect.Value, ptrs map[uintptr
 		strLen := len(v.String())
 		if strLen == 0 {
 			// unsafe.StringData is unspecified in this case
-			int64Buf[0] = 0
-			hasher.Write(int64Buf[:1])
+			hasher.writeByte(0)
 			return nil
 		}
 		hasher.Write(unsafe.Slice(unsafe.StringData(v.String()), strLen))
 	case reflect.Bool:
 		if v.Bool() {
-			int64Buf[0] = 1
+			hasher.writeByte(1)
 		} else {
-			int64Buf[0] = 0
+			hasher.writeByte(0)
 		}
-		hasher.Write(int64Buf[:1])
 	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
-		binary.LittleEndian.PutUint64(int64Buf, v.Uint())
-		hasher.Write(int64Buf)
+		hasher.writeUint64(v.Uint())
 	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
-		binary.LittleEndian.PutUint64(int64Buf, uint64(v.Int()))
-		hasher.Write(int64Buf)
+		hasher.writeUint64(uint64(v.Int()))
 	case reflect.Float32, reflect.Float64:
-		binary.LittleEndian.PutUint64(int64Buf, math.Float64bits(v.Float()))
-		hasher.Write(int64Buf)
+		hasher.writeUint64(math.Float64bits(v.Float()))
 	default:
 		return fmt.Errorf("data may only contain primitives, strings, arrays, slices, structs, maps, and pointers, found: %s", v.Kind().String())
 	}
@@ -183,14 +226,16 @@ func compare_values(x, y reflect.Value) int {
 	case reflect.Pointer:
 		return cmp.Compare(x.Pointer(), y.Pointer())
 	case reflect.Array:
-		for i := 0; i < x.Len(); i++ {
+		l := x.Len()
+		for i := 0; i < l; i++ {
 			if result := compare_values(x.Index(i), y.Index(i)); result != 0 {
 				return result
 			}
 		}
 		return 0
 	case reflect.Struct:
-		for i := 0; i < x.NumField(); i++ {
+		l := x.NumField()
+		for i := 0; i < l; i++ {
 			if result := compare_values(x.Field(i), y.Field(i)); result != 0 {
 				return result
 			}
@@ -209,3 +254,76 @@ func compare_values(x, y reflect.Value) int {
 		panic(fmt.Sprintf("Could not compare types %s and %s", x.Type().String(), y.Type().String()))
 	}
 }
+
+func ContainsConfigurable(value interface{}) bool {
+	ptrs := make(map[uintptr]bool)
+	v := reflect.ValueOf(value)
+	if v.IsValid() {
+		return containsConfigurableInternal(v, ptrs)
+	}
+	return false
+}
+
+func containsConfigurableInternal(v reflect.Value, ptrs map[uintptr]bool) bool {
+	switch v.Kind() {
+	case reflect.Struct:
+		t := v.Type()
+		if IsConfigurable(t) {
+			return true
+		}
+		typeFields := typeFields(t)
+		for i := 0; i < v.NumField(); i++ {
+			if HasTag(typeFields[i], "blueprint", "allow_configurable_in_provider") {
+				continue
+			}
+			if containsConfigurableInternal(v.Field(i), ptrs) {
+				return true
+			}
+		}
+	case reflect.Map:
+		iter := v.MapRange()
+		for iter.Next() {
+			key := iter.Key()
+			value := iter.Value()
+			if containsConfigurableInternal(key, ptrs) {
+				return true
+			}
+			if containsConfigurableInternal(value, ptrs) {
+				return true
+			}
+		}
+	case reflect.Slice, reflect.Array:
+		l := v.Len()
+		for i := 0; i < l; i++ {
+			if containsConfigurableInternal(v.Index(i), ptrs) {
+				return true
+			}
+		}
+	case reflect.Pointer:
+		if v.IsNil() {
+			return false
+		}
+		addr := v.Pointer()
+		if _, ok := ptrs[addr]; ok {
+			// pointer cycle
+			return false
+		}
+		ptrs[addr] = true
+		if containsConfigurableInternal(v.Elem(), ptrs) {
+			return true
+		}
+	case reflect.Interface:
+		if v.IsNil() {
+			return false
+		} else {
+			// The only way get the pointer out of an interface to hash it or check for cycles
+			// would be InterfaceData(), but that's deprecated and seems like it has undefined behavior.
+			if containsConfigurableInternal(v.Elem(), ptrs) {
+				return true
+			}
+		}
+	default:
+		return false
+	}
+	return false
+}
diff --git a/proptools/hash_provider_test.go b/proptools/hash_provider_test.go
index 338c6e4..f7ccd3b 100644
--- a/proptools/hash_provider_test.go
+++ b/proptools/hash_provider_test.go
@@ -57,54 +57,91 @@ func TestHashingNonSerializableTypesFails(t *testing.T) {
 	}
 }
 
-func TestHashSuccessful(t *testing.T) {
-	testCases := []struct {
-		name string
-		data interface{}
-	}{
-		{
-			name: "int",
-			data: 5,
+var hashTestCases = []struct {
+	name string
+	data interface{}
+}{
+	{
+		name: "int",
+		data: 5,
+	},
+	{
+		name: "string",
+		data: "foo",
+	},
+	{
+		name: "*string",
+		data: StringPtr("foo"),
+	},
+	{
+		name: "array",
+		data: [3]string{"foo", "bar", "baz"},
+	},
+	{
+		name: "slice",
+		data: []string{"foo", "bar", "baz"},
+	},
+	{
+		name: "struct",
+		data: struct {
+			foo string
+			bar int
+		}{
+			foo: "foo",
+			bar: 3,
 		},
-		{
-			name: "string",
-			data: "foo",
-		},
-		{
-			name: "*string",
-			data: StringPtr("foo"),
+	},
+	{
+		name: "map",
+		data: map[string]int{
+			"foo": 3,
+			"bar": 4,
 		},
-		{
-			name: "array",
-			data: [3]string{"foo", "bar", "baz"},
+	},
+	{
+		name: "list of interfaces with different types",
+		data: []interface{}{"foo", 3, []string{"bar", "baz"}},
+	},
+	{
+		name: "nested maps",
+		data: map[string]map[string]map[string]map[string]map[string]int{
+			"foo": {"foo": {"foo": {"foo": {"foo": 5}}}},
 		},
-		{
-			name: "slice",
-			data: []string{"foo", "bar", "baz"},
+	},
+	{
+		name: "multiple maps",
+		data: struct {
+			foo  map[string]int
+			bar  map[string]int
+			baz  map[string]int
+			qux  map[string]int
+			quux map[string]int
+		}{
+			foo:  map[string]int{"foo": 1, "bar": 2},
+			bar:  map[string]int{"bar": 2},
+			baz:  map[string]int{"baz": 3, "foo": 1},
+			qux:  map[string]int{"qux": 4},
+			quux: map[string]int{"quux": 5},
 		},
-		{
-			name: "struct",
-			data: struct {
-				foo string
-				bar int
-			}{
-				foo: "foo",
-				bar: 3,
+	},
+	{
+		name: "nested structs",
+		data: nestableStruct{
+			foo: nestableStruct{
+				foo: nestableStruct{
+					foo: nestableStruct{
+						foo: nestableStruct{
+							foo: "foo",
+						},
+					},
+				},
 			},
 		},
-		{
-			name: "map",
-			data: map[string]int{
-				"foo": 3,
-				"bar": 4,
-			},
-		},
-		{
-			name: "list of interfaces with different types",
-			data: []interface{}{"foo", 3, []string{"bar", "baz"}},
-		},
-	}
-	for _, testCase := range testCases {
+	},
+}
+
+func TestHashSuccessful(t *testing.T) {
+	for _, testCase := range hashTestCases {
 		t.Run(testCase.name, func(t *testing.T) {
 			mustHash(t, testCase.data)
 		})
@@ -126,3 +163,60 @@ func TestHashingDereferencePointers(t *testing.T) {
 		t.Fatal("Got different results for the same string")
 	}
 }
+
+type nestableStruct struct {
+	foo interface{}
+}
+
+func TestContainsConfigurable(t *testing.T) {
+	testCases := []struct {
+		name   string
+		value  any
+		result bool
+	}{
+		{
+			name: "struct without configurable",
+			value: struct {
+				S string
+			}{},
+			result: false,
+		},
+		{
+			name: "struct with configurable",
+			value: struct {
+				S Configurable[string]
+			}{},
+			result: true,
+		},
+		{
+			name: "struct with allowed configurable",
+			value: struct {
+				S Configurable[string] `blueprint:"allow_configurable_in_provider"`
+			}{},
+			result: false,
+		},
+	}
+
+	for _, testCase := range testCases {
+		t.Run(testCase.name, func(t *testing.T) {
+			got := ContainsConfigurable(testCase.value)
+			if got != testCase.result {
+				t.Errorf("expected %v, got %v", testCase.value, got)
+			}
+		})
+	}
+}
+
+func BenchmarkCalculateHash(b *testing.B) {
+	for _, testCase := range hashTestCases {
+		b.Run(testCase.name, func(b *testing.B) {
+			b.ReportAllocs()
+			for i := 0; i < b.N; i++ {
+				_, err := CalculateHash(testCase.data)
+				if err != nil {
+					panic(err)
+				}
+			}
+		})
+	}
+}
diff --git a/proptools/unpack.go b/proptools/unpack.go
index 712e78c..999d1e9 100644
--- a/proptools/unpack.go
+++ b/proptools/unpack.go
@@ -389,6 +389,28 @@ func (ctx *unpackContext) unpackToConfigurable(propertyName string, property *pa
 			postProcessors: &postProcessors,
 		}
 		return reflect.ValueOf(&result), true
+	case *parser.Int64:
+		if configuredType.Kind() != reflect.Int64 {
+			ctx.addError(&UnpackError{
+				fmt.Errorf("can't assign int64 value to configurable %s property %q",
+					configuredType.String(), property.Name),
+				property.Value.Pos(),
+			})
+			return reflect.New(configurableType), false
+		}
+		var postProcessors [][]postProcessor[int64]
+		result := Configurable[int64]{
+			propertyName: property.Name,
+			inner: &configurableInner[int64]{
+				single: singleConfigurable[int64]{
+					cases: []ConfigurableCase[int64]{{
+						value: v,
+					}},
+				},
+			},
+			postProcessors: &postProcessors,
+		}
+		return reflect.ValueOf(&result), true
 	case *parser.List:
 		if configuredType.Kind() != reflect.Slice {
 			ctx.addError(&UnpackError{
@@ -464,6 +486,9 @@ func (ctx *unpackContext) unpackToConfigurable(propertyName string, property *pa
 				case *parser.Bool:
 					patterns[i].typ = configurablePatternTypeBool
 					patterns[i].boolValue = pat.Value
+				case *parser.Int64:
+					patterns[i].typ = configurablePatternTypeInt64
+					patterns[i].int64Value = pat.Value
 				default:
 					panic("unimplemented")
 				}
diff --git a/provider.go b/provider.go
index 8f9120d..fa3d093 100644
--- a/provider.go
+++ b/provider.go
@@ -186,6 +186,11 @@ func (c *Context) setProvider(m *moduleInfo, provider *providerKey, value any) {
 
 	m.providers[provider.id] = value
 
+	containsConfigurableChan := make(chan bool)
+	go func() {
+		containsConfigurableChan <- proptools.ContainsConfigurable(value)
+	}()
+
 	if m.providerInitialValueHashes == nil {
 		m.providerInitialValueHashes = make([]uint64, len(providerRegistry))
 	}
@@ -194,6 +199,10 @@ func (c *Context) setProvider(m *moduleInfo, provider *providerKey, value any) {
 		panic(fmt.Sprintf("Can't set value of provider %s: %s", provider.typ, err.Error()))
 	}
 	m.providerInitialValueHashes[provider.id] = hash
+
+	if <-containsConfigurableChan {
+		panic(fmt.Sprintf("Providers can't contain Configurable objects: %s", provider.typ))
+	}
 }
 
 // provider returns the value, if any, for a given provider for a module.  Verifies that it is
@@ -203,6 +212,28 @@ func (c *Context) setProvider(m *moduleInfo, provider *providerKey, value any) {
 // Once Go has generics the return value can be typed and the type assert by callers can be dropped:
 // provider(type T)(m *moduleInfo, provider ProviderKey(T)) T
 func (c *Context) provider(m *moduleInfo, provider *providerKey) (any, bool) {
+	validateProvider(c, m, provider)
+	if len(m.providers) > provider.id {
+		if p := m.providers[provider.id]; p != nil {
+			return p, true
+		}
+	}
+
+	return nil, false
+}
+
+func (c *Context) hasProvider(m *moduleInfo, provider *providerKey) bool {
+	validateProvider(c, m, provider)
+	if len(m.providers) > provider.id {
+		if p := m.providers[provider.id]; p != nil {
+			return true
+		}
+	}
+
+	return false
+}
+
+func validateProvider(c *Context, m *moduleInfo, provider *providerKey) {
 	if provider.mutator == "" {
 		if !m.finishedGenerateBuildActions {
 			panic(fmt.Sprintf("Can't get value of provider %s before GenerateBuildActions finished",
@@ -215,14 +246,6 @@ func (c *Context) provider(m *moduleInfo, provider *providerKey) (any, bool) {
 				provider.typ, provider.mutator))
 		}
 	}
-
-	if len(m.providers) > provider.id {
-		if p := m.providers[provider.id]; p != nil {
-			return p, true
-		}
-	}
-
-	return nil, false
 }
 
 func (c *Context) mutatorFinishedForModule(mutator *mutatorInfo, m *moduleInfo) bool {
@@ -243,8 +266,8 @@ func (c *Context) mutatorStartedForModule(mutator *mutatorInfo, m *moduleInfo) b
 	return m.startedMutator >= mutator.index
 }
 
-// OtherModuleProviderContext is a helper interface that is a subset of ModuleContext, BottomUpMutatorContext, or
-// TopDownMutatorContext for use in OtherModuleProvider.
+// OtherModuleProviderContext is a helper interface that is a subset of ModuleContext or BottomUpMutatorContext
+// for use in OtherModuleProvider.
 type OtherModuleProviderContext interface {
 	OtherModuleProvider(m Module, provider AnyProviderKey) (any, bool)
 }
@@ -252,7 +275,6 @@ type OtherModuleProviderContext interface {
 var _ OtherModuleProviderContext = BaseModuleContext(nil)
 var _ OtherModuleProviderContext = ModuleContext(nil)
 var _ OtherModuleProviderContext = BottomUpMutatorContext(nil)
-var _ OtherModuleProviderContext = TopDownMutatorContext(nil)
 
 // OtherModuleProvider reads the provider for the given module.  If the provider has been set the value is
 // returned and the boolean is true.  If it has not been set the zero value of the provider's type  is returned
@@ -292,8 +314,8 @@ func SingletonModuleProvider[K any](ctx SingletonModuleProviderContext, module M
 	return value.(K), ok
 }
 
-// ModuleProviderContext is a helper interface that is a subset of ModuleContext, BottomUpMutatorContext, or
-// TopDownMutatorContext for use in ModuleProvider.
+// ModuleProviderContext is a helper interface that is a subset of ModuleContext or BottomUpMutatorContext
+// for use in ModuleProvider.
 type ModuleProviderContext interface {
 	Provider(provider AnyProviderKey) (any, bool)
 }
@@ -301,7 +323,6 @@ type ModuleProviderContext interface {
 var _ ModuleProviderContext = BaseModuleContext(nil)
 var _ ModuleProviderContext = ModuleContext(nil)
 var _ ModuleProviderContext = BottomUpMutatorContext(nil)
-var _ ModuleProviderContext = TopDownMutatorContext(nil)
 
 // ModuleProvider reads the provider for the current module.  If the provider has been set the value is
 // returned and the boolean is true.  If it has not been set the zero value of the provider's type  is returned
@@ -318,8 +339,8 @@ func ModuleProvider[K any](ctx ModuleProviderContext, provider ProviderKey[K]) (
 	return value.(K), ok
 }
 
-// SetProviderContext is a helper interface that is a subset of ModuleContext, BottomUpMutatorContext, or
-// TopDownMutatorContext for use in SetProvider.
+// SetProviderContext is a helper interface that is a subset of ModuleContext or BottomUpMutatorContext
+// for use in SetProvider.
 type SetProviderContext interface {
 	SetProvider(provider AnyProviderKey, value any)
 }
@@ -327,7 +348,6 @@ type SetProviderContext interface {
 var _ SetProviderContext = BaseModuleContext(nil)
 var _ SetProviderContext = ModuleContext(nil)
 var _ SetProviderContext = BottomUpMutatorContext(nil)
-var _ SetProviderContext = TopDownMutatorContext(nil)
 
 // SetProvider sets the value for a provider for the current module.  It panics if not called
 // during the appropriate mutator or GenerateBuildActions pass for the provider, if the value
diff --git a/provider_test.go b/provider_test.go
index 8c02a75..aafe3c3 100644
--- a/provider_test.go
+++ b/provider_test.go
@@ -176,8 +176,6 @@ var invalidProviderUsageMutatorInfoProvider = NewMutatorProvider[invalidProvider
 var invalidProviderUsageGenerateBuildActionsInfoProvider = NewProvider[invalidProviderUsageGenerateBuildActionsInfo]()
 
 type invalidProviderUsageTestModule struct {
-	parent *invalidProviderUsageTestModule
-
 	SimpleName
 	properties struct {
 		Deps []string
@@ -188,9 +186,7 @@ type invalidProviderUsageTestModule struct {
 		Early_mutator_set_of_build_actions_provider bool
 
 		Early_mutator_get_of_mutator_provider       bool
-		Early_module_get_of_mutator_provider        bool
 		Early_mutator_get_of_build_actions_provider bool
-		Early_module_get_of_build_actions_provider  bool
 
 		Duplicate_set bool
 	}
@@ -202,14 +198,6 @@ func invalidProviderUsageDepsMutator(ctx BottomUpMutatorContext) {
 	}
 }
 
-func invalidProviderUsageParentMutator(ctx TopDownMutatorContext) {
-	if i, ok := ctx.Module().(*invalidProviderUsageTestModule); ok {
-		ctx.VisitDirectDeps(func(module Module) {
-			module.(*invalidProviderUsageTestModule).parent = i
-		})
-	}
-}
-
 func invalidProviderUsageBeforeMutator(ctx BottomUpMutatorContext) {
 	if i, ok := ctx.Module().(*invalidProviderUsageTestModule); ok {
 		if i.properties.Early_mutator_set_of_mutator_provider {
@@ -223,7 +211,7 @@ func invalidProviderUsageBeforeMutator(ctx BottomUpMutatorContext) {
 	}
 }
 
-func invalidProviderUsageMutatorUnderTest(ctx TopDownMutatorContext) {
+func invalidProviderUsageMutatorUnderTest(ctx BottomUpMutatorContext) {
 	if i, ok := ctx.Module().(*invalidProviderUsageTestModule); ok {
 		if i.properties.Early_mutator_set_of_build_actions_provider {
 			// A mutator attempting to set the value of a non-mutator provider.
@@ -233,14 +221,6 @@ func invalidProviderUsageMutatorUnderTest(ctx TopDownMutatorContext) {
 			// A mutator attempting to get the value of a non-mutator provider.
 			_, _ = ModuleProvider(ctx, invalidProviderUsageGenerateBuildActionsInfoProvider)
 		}
-		if i.properties.Early_module_get_of_mutator_provider {
-			// A mutator attempting to get the value of a provider associated with this mutator on
-			// a module for which this mutator hasn't run.  This is a top down mutator so
-			// dependencies haven't run yet.
-			ctx.VisitDirectDeps(func(module Module) {
-				_, _ = OtherModuleProvider(ctx, module, invalidProviderUsageMutatorInfoProvider)
-			})
-		}
 	}
 }
 
@@ -262,11 +242,6 @@ func (i *invalidProviderUsageTestModule) GenerateBuildActions(ctx ModuleContext)
 		// A GenerateBuildActions trying to set the value of a provider associated with a mutator.
 		SetProvider(ctx, invalidProviderUsageMutatorInfoProvider, invalidProviderUsageMutatorInfo(""))
 	}
-	if i.properties.Early_module_get_of_build_actions_provider {
-		// A GenerateBuildActions trying to get the value of a provider on a module for which
-		// GenerateBuildActions hasn't run.
-		_, _ = OtherModuleProvider(ctx, i.parent, invalidProviderUsageGenerateBuildActionsInfoProvider)
-	}
 	if i.properties.Duplicate_set {
 		SetProvider(ctx, invalidProviderUsageGenerateBuildActionsInfoProvider, invalidProviderUsageGenerateBuildActionsInfo(""))
 		SetProvider(ctx, invalidProviderUsageGenerateBuildActionsInfoProvider, invalidProviderUsageGenerateBuildActionsInfo(""))
@@ -283,9 +258,8 @@ func TestInvalidProvidersUsage(t *testing.T) {
 		})
 		ctx.RegisterBottomUpMutator("deps", invalidProviderUsageDepsMutator)
 		ctx.RegisterBottomUpMutator("before", invalidProviderUsageBeforeMutator)
-		ctx.RegisterTopDownMutator("mutator_under_test", invalidProviderUsageMutatorUnderTest)
+		ctx.RegisterBottomUpMutator("mutator_under_test", invalidProviderUsageMutatorUnderTest)
 		ctx.RegisterBottomUpMutator("after", invalidProviderUsageAfterMutator)
-		ctx.RegisterTopDownMutator("parent", invalidProviderUsageParentMutator)
 
 		// Don't invalidate the parent pointer and before GenerateBuildActions.
 		ctx.SkipCloneModulesAfterMutators = true
@@ -395,21 +369,11 @@ func TestInvalidProvidersUsage(t *testing.T) {
 			module:   "module_under_test",
 			panicMsg: "Can't get value of provider blueprint.invalidProviderUsageMutatorInfo before mutator mutator_under_test finished",
 		},
-		{
-			prop:     "early_module_get_of_mutator_provider",
-			module:   "module_under_test",
-			panicMsg: "Can't get value of provider blueprint.invalidProviderUsageMutatorInfo before mutator mutator_under_test finished",
-		},
 		{
 			prop:     "early_mutator_get_of_build_actions_provider",
 			module:   "module_under_test",
 			panicMsg: "Can't get value of provider blueprint.invalidProviderUsageGenerateBuildActionsInfo before GenerateBuildActions finished",
 		},
-		{
-			prop:     "early_module_get_of_build_actions_provider",
-			module:   "module_under_test",
-			panicMsg: "Can't get value of provider blueprint.invalidProviderUsageGenerateBuildActionsInfo before GenerateBuildActions finished",
-		},
 		{
 			prop:     "duplicate_set",
 			module:   "module_under_test",
diff --git a/singleton_ctx.go b/singleton_ctx.go
index 91db313..bcfb45c 100644
--- a/singleton_ctx.go
+++ b/singleton_ctx.go
@@ -141,9 +141,14 @@ type SingletonContext interface {
 	VisitAllModuleVariantProxies(module Module, visit func(proxy ModuleProxy))
 
 	// PrimaryModule returns the first variant of the given module.  This can be used to perform
-	//	// singleton actions that are only done once for all variants of a module.
+	// singleton actions that are only done once for all variants of a module.
 	PrimaryModule(module Module) Module
 
+	// PrimaryModuleProxy returns the proxy of the first variant of the given module.
+	// This can be used to perform singleton actions that are only done once for
+	// all variants of a module.
+	PrimaryModuleProxy(module ModuleProxy) ModuleProxy
+
 	// IsFinalModule returns if the given module is the last variant. This can be used to perform
 	// singleton actions that are only done once for all variants of a module.
 	IsFinalModule(module Module) bool
@@ -166,7 +171,7 @@ type SingletonContext interface {
 
 	// ModuleVariantsFromName returns the list of module variants named `name` in the same namespace as `referer`.
 	// Allows generating build actions for `referer` based on the metadata for `name` deferred until the singleton context.
-	ModuleVariantsFromName(referer Module, name string) []Module
+	ModuleVariantsFromName(referer ModuleProxy, name string) []ModuleProxy
 
 	// HasMutatorFinished returns true if the given mutator has finished running.
 	// It will panic if given an invalid mutator name.
@@ -217,7 +222,7 @@ func (s *singletonContext) ModuleProvider(logicModule Module, provider AnyProvid
 }
 
 func (s *singletonContext) BlueprintFile(logicModule Module) string {
-	return s.context.BlueprintFile(logicModule)
+	return s.context.BlueprintFile(getWrappedModule(logicModule))
 }
 
 func (s *singletonContext) error(err error) {
@@ -371,8 +376,12 @@ func (s *singletonContext) PrimaryModule(module Module) Module {
 	return s.context.PrimaryModule(module)
 }
 
+func (s *singletonContext) PrimaryModuleProxy(module ModuleProxy) ModuleProxy {
+	return ModuleProxy{s.context.PrimaryModule(module.module)}
+}
+
 func (s *singletonContext) IsFinalModule(module Module) bool {
-	return s.context.IsFinalModule(module)
+	return s.context.IsFinalModule(getWrappedModule(module))
 }
 
 func (s *singletonContext) VisitAllModuleVariants(module Module, visit func(Module)) {
@@ -380,7 +389,7 @@ func (s *singletonContext) VisitAllModuleVariants(module Module, visit func(Modu
 }
 
 func (s *singletonContext) VisitAllModuleVariantProxies(module Module, visit func(proxy ModuleProxy)) {
-	s.context.VisitAllModuleVariants(module, visitProxyAdaptor(visit))
+	s.context.VisitAllModuleVariants(getWrappedModule(module), visitProxyAdaptor(visit))
 }
 
 func (s *singletonContext) AddNinjaFileDeps(deps ...string) {
@@ -396,10 +405,10 @@ func (s *singletonContext) Fs() pathtools.FileSystem {
 	return s.context.fs
 }
 
-func (s *singletonContext) ModuleVariantsFromName(referer Module, name string) []Module {
+func (s *singletonContext) ModuleVariantsFromName(referer ModuleProxy, name string) []ModuleProxy {
 	c := s.context
 
-	refererInfo := c.moduleInfo[referer]
+	refererInfo := c.moduleInfo[referer.module]
 	if refererInfo == nil {
 		s.ModuleErrorf(referer, "could not find module %q", referer.Name())
 		return nil
@@ -409,9 +418,11 @@ func (s *singletonContext) ModuleVariantsFromName(referer Module, name string) [
 	if !exists {
 		return nil
 	}
-	result := make([]Module, 0, len(moduleGroup.modules))
+	result := make([]ModuleProxy, 0, len(moduleGroup.modules))
 	for _, moduleInfo := range moduleGroup.modules {
-		result = append(result, moduleInfo.logicModule)
+		if moduleInfo.logicModule != nil {
+			result = append(result, ModuleProxy{moduleInfo.logicModule})
+		}
 	}
 	return result
 }
diff --git a/source_file_provider.go b/source_file_provider.go
deleted file mode 100644
index bf48dc6..0000000
--- a/source_file_provider.go
+++ /dev/null
@@ -1,7 +0,0 @@
-package blueprint
-
-type SrcsFileProviderData struct {
-	SrcPaths []string
-}
-
-var SrcsFileProviderKey = NewProvider[SrcsFileProviderData]()
diff --git a/syncmap/Android.bp b/syncmap/Android.bp
new file mode 100644
index 0000000..337ea4c
--- /dev/null
+++ b/syncmap/Android.bp
@@ -0,0 +1,9 @@
+bootstrap_go_package {
+    name: "blueprint-syncmap",
+    pkgPath: "github.com/google/blueprint/syncmap",
+    srcs: ["syncmap.go"],
+    visibility: [
+        "//build/blueprint:__subpackages__",
+        "//build/soong:__subpackages__",
+    ],
+}
diff --git a/syncmap/syncmap.go b/syncmap/syncmap.go
new file mode 100644
index 0000000..5d2e3f1
--- /dev/null
+++ b/syncmap/syncmap.go
@@ -0,0 +1,52 @@
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
+package syncmap
+
+import "sync"
+
+// SyncMap is a wrapper around sync.Map that provides type safety via generics.
+type SyncMap[K comparable, V any] struct {
+	sync.Map
+}
+
+// Load returns the value stored in the map for a key, or the zero value if no
+// value is present.
+// The ok result indicates whether value was found in the map.
+func (m *SyncMap[K, V]) Load(key K) (value V, ok bool) {
+	v, ok := m.Map.Load(key)
+	if !ok {
+		return *new(V), false
+	}
+	return v.(V), true
+}
+
+// Store sets the value for a key.
+func (m *SyncMap[K, V]) Store(key K, value V) {
+	m.Map.Store(key, value)
+}
+
+// LoadOrStore returns the existing value for the key if present.
+// Otherwise, it stores and returns the given value.
+// The loaded result is true if the value was loaded, false if stored.
+func (m *SyncMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
+	v, loaded := m.Map.LoadOrStore(key, value)
+	return v.(V), loaded
+}
+
+func (m *SyncMap[K, V]) Range(f func(key K, value V) bool) {
+	m.Map.Range(func(k, v any) bool {
+		return f(k.(K), v.(V))
+	})
+}
diff --git a/transition.go b/transition.go
index afd3661..ee72d8d 100644
--- a/transition.go
+++ b/transition.go
@@ -16,8 +16,10 @@ package blueprint
 
 import (
 	"fmt"
+	"maps"
 	"slices"
-	"sort"
+
+	"github.com/google/blueprint/pool"
 )
 
 // TransitionMutator implements a top-down mechanism where a module tells its
@@ -83,24 +85,32 @@ type TransitionMutator interface {
 	// the module knows its variations just based on information given to it in
 	// the Blueprint file. This method should not mutate the module it is called
 	// on.
-	Split(ctx BaseModuleContext) []string
+	Split(ctx BaseModuleContext) []TransitionInfo
 
 	// OutgoingTransition is called on a module to determine which variation it wants
 	// from its direct dependencies. The dependency itself can override this decision.
 	// This method should not mutate the module itself.
-	OutgoingTransition(ctx OutgoingTransitionContext, sourceVariation string) string
+	OutgoingTransition(ctx OutgoingTransitionContext, sourceTransitionInfo TransitionInfo) TransitionInfo
 
 	// IncomingTransition is called on a module to determine which variation it should
 	// be in based on the variation modules that depend on it want. This gives the module
 	// a final say about its own variations. This method should not mutate the module
 	// itself.
-	IncomingTransition(ctx IncomingTransitionContext, incomingVariation string) string
+	IncomingTransition(ctx IncomingTransitionContext, incomingTransitionInfo TransitionInfo) TransitionInfo
 
 	// Mutate is called after a module was split into multiple variations on each
 	// variation.  It should not split the module any further but adding new dependencies
 	// is fine. Unlike all the other methods on TransitionMutator, this method is
 	// allowed to mutate the module.
-	Mutate(ctx BottomUpMutatorContext, variation string)
+	Mutate(ctx BottomUpMutatorContext, transitionInfo TransitionInfo)
+
+	// TransitionInfoFromVariation is called when adding dependencies with an explicit variation after the
+	// TransitionMutator has already run.  It takes a variation name and returns a TransitionInfo for that
+	// variation.  It may not be possible for some TransitionMutators to generate an appropriate TransitionInfo
+	// if the variation does not contain all the information from the TransitionInfo, in which case the
+	// TransitionMutator can panic in TransitionInfoFromVariation, and adding dependencies with explicit variations
+	// for this TransitionMutator is not supported.
+	TransitionInfoFromVariation(string) TransitionInfo
 }
 
 type IncomingTransitionContext interface {
@@ -108,6 +118,14 @@ type IncomingTransitionContext interface {
 	// is being computed
 	Module() Module
 
+	// ModuleName returns the name of the module.  This is generally the value that was returned by Module.Name() when
+	// the module was created, but may have been modified by calls to BottomUpMutatorContext.Rename.
+	ModuleName() string
+
+	// DepTag() Returns the dependency tag through which this dependency is
+	// reached
+	DepTag() DependencyTag
+
 	// Config returns the config object that was passed to
 	// Context.PrepareBuildActions.
 	Config() interface{}
@@ -138,6 +156,10 @@ type OutgoingTransitionContext interface {
 	// is being computed
 	Module() Module
 
+	// ModuleName returns the name of the module.  This is generally the value that was returned by Module.Name() when
+	// the module was created, but may have been modified by calls to BottomUpMutatorContext.Rename.
+	ModuleName() string
+
 	// DepTag() Returns the dependency tag through which this dependency is
 	// reached
 	DepTag() DependencyTag
@@ -161,11 +183,19 @@ type OutgoingTransitionContext interface {
 	PropertyErrorf(property, fmt string, args ...interface{})
 }
 
+type TransitionInfo interface {
+	// Variation returns a string that will be used as the variation name for modules that use this TransitionInfo
+	// as their configuration.  It must return a unique value for each valid TransitionInfo in order to avoid
+	// conflicts, and all identical TransitionInfos must return the same value.
+	Variation() string
+}
+
 type transitionMutatorImpl struct {
-	name                        string
-	mutator                     TransitionMutator
-	variantCreatingMutatorIndex int
-	inputVariants               map[*moduleGroup][]*moduleInfo
+	name          string
+	mutator       TransitionMutator
+	index         int
+	inputVariants map[*moduleGroup][]*moduleInfo
+	neverFar      bool
 }
 
 // Adds each argument in items to l if it's not already there.
@@ -179,9 +209,9 @@ func addToStringListIfNotPresent(l []string, items ...string) []string {
 	return l
 }
 
-func (t *transitionMutatorImpl) addRequiredVariation(m *moduleInfo, variation string) {
-	m.requiredVariationsLock.Lock()
-	defer m.requiredVariationsLock.Unlock()
+func (t *transitionMutatorImpl) addRequiredVariation(m *moduleInfo, variation string, transitionInfo TransitionInfo) {
+	m.incomingTransitionInfosLock.Lock()
+	defer m.incomingTransitionInfosLock.Unlock()
 
 	// This is only a consistency check. Leaking the variations of a transition
 	// mutator to another one could well lead to issues that are difficult to
@@ -191,10 +221,20 @@ func (t *transitionMutatorImpl) addRequiredVariation(m *moduleInfo, variation st
 	}
 
 	m.currentTransitionMutator = t.name
-	m.transitionVariations = addToStringListIfNotPresent(m.transitionVariations, variation)
+	if existing, exists := m.incomingTransitionInfos[variation]; exists {
+		if existing != transitionInfo {
+			panic(fmt.Errorf("TransitionInfo %#v and %#v are different but have same variation %q",
+				existing, transitionInfo, variation))
+		}
+	} else {
+		if m.incomingTransitionInfos == nil {
+			m.incomingTransitionInfos = make(map[string]TransitionInfo)
+		}
+		m.incomingTransitionInfos[variation] = transitionInfo
+	}
 }
 
-func (t *transitionMutatorImpl) topDownMutator(mctx TopDownMutatorContext) {
+func (t *transitionMutatorImpl) propagateMutator(mctx BaseModuleContext) {
 	module := mctx.(*mutatorContext).module
 	mutatorSplits := t.mutator.Split(mctx)
 	if mutatorSplits == nil || len(mutatorSplits) == 0 {
@@ -208,22 +248,45 @@ func (t *transitionMutatorImpl) topDownMutator(mctx TopDownMutatorContext) {
 	// Sort the module transitions, but keep the mutatorSplits in the order returned
 	// by Split, as the order can be significant when inter-variant dependencies are
 	// used.
-	sort.Strings(module.transitionVariations)
-	module.transitionVariations = addToStringListIfNotPresent(mutatorSplits, module.transitionVariations...)
+	transitionVariations := slices.Sorted(maps.Keys(module.incomingTransitionInfos))
+	transitionInfoMap := module.incomingTransitionInfos
+	module.incomingTransitionInfos = nil
+
+	splitsVariations := make([]string, 0, len(mutatorSplits))
+	for _, splitTransitionInfo := range mutatorSplits {
+		splitVariation := splitTransitionInfo.Variation()
+		splitsVariations = append(splitsVariations, splitVariation)
+		if transitionInfoMap == nil {
+			transitionInfoMap = make(map[string]TransitionInfo, len(mutatorSplits))
+		}
+		transitionInfoMap[splitVariation] = splitTransitionInfo
+	}
+
+	transitionVariations = addToStringListIfNotPresent(splitsVariations, transitionVariations...)
 
-	outgoingTransitionCache := make([][]string, len(module.transitionVariations))
-	for srcVariationIndex, srcVariation := range module.transitionVariations {
+	outgoingTransitionVariationCache := make([][]string, len(transitionVariations))
+	transitionInfos := make([]TransitionInfo, 0, len(transitionVariations))
+	for srcVariationIndex, srcVariation := range transitionVariations {
 		srcVariationTransitionCache := make([]string, len(module.directDeps))
 		for depIndex, dep := range module.directDeps {
-			finalVariation := t.transition(mctx)(mctx.moduleInfo(), srcVariation, dep.module, dep.tag)
-			srcVariationTransitionCache[depIndex] = finalVariation
-			t.addRequiredVariation(dep.module, finalVariation)
+			transitionInfo := t.transition(mctx)(mctx.moduleInfo(), transitionInfoMap[srcVariation], dep.module, dep.tag)
+			variation := transitionInfo.Variation()
+			srcVariationTransitionCache[depIndex] = variation
+			t.addRequiredVariation(dep.module, variation, transitionInfo)
 		}
-		outgoingTransitionCache[srcVariationIndex] = srcVariationTransitionCache
+		outgoingTransitionVariationCache[srcVariationIndex] = srcVariationTransitionCache
+		transitionInfos = append(transitionInfos, transitionInfoMap[srcVariation])
 	}
-	module.outgoingTransitionCache = outgoingTransitionCache
+	module.outgoingTransitionCache = outgoingTransitionVariationCache
+	module.splitTransitionVariations = transitionVariations
+	module.splitTransitionInfos = transitionInfos
 }
 
+var (
+	outgoingTransitionContextPool = pool.New[outgoingTransitionContextImpl]()
+	incomingTransitionContextPool = pool.New[incomingTransitionContextImpl]()
+)
+
 type transitionContextImpl struct {
 	context     *Context
 	source      *moduleInfo
@@ -268,6 +331,10 @@ func (c *outgoingTransitionContextImpl) Module() Module {
 	return c.source.logicModule
 }
 
+func (c *outgoingTransitionContextImpl) ModuleName() string {
+	return c.source.group.name
+}
+
 func (c *outgoingTransitionContextImpl) Provider(provider AnyProviderKey) (any, bool) {
 	return c.context.provider(c.source, provider.provider())
 }
@@ -280,12 +347,16 @@ func (c *incomingTransitionContextImpl) Module() Module {
 	return c.dep.logicModule
 }
 
+func (c *incomingTransitionContextImpl) ModuleName() string {
+	return c.dep.group.name
+}
+
 func (c *incomingTransitionContextImpl) Provider(provider AnyProviderKey) (any, bool) {
 	return c.context.provider(c.dep, provider.provider())
 }
 
 func (t *transitionMutatorImpl) transition(mctx BaseModuleContext) Transition {
-	return func(source *moduleInfo, sourceVariation string, dep *moduleInfo, depTag DependencyTag) string {
+	return func(source *moduleInfo, sourceTransitionInfo TransitionInfo, dep *moduleInfo, depTag DependencyTag) TransitionInfo {
 		tc := transitionContextImpl{
 			context: mctx.base().context,
 			source:  source,
@@ -293,20 +364,26 @@ func (t *transitionMutatorImpl) transition(mctx BaseModuleContext) Transition {
 			depTag:  depTag,
 			config:  mctx.Config(),
 		}
-		outCtx := &outgoingTransitionContextImpl{tc}
-		outgoingVariation := t.mutator.OutgoingTransition(outCtx, sourceVariation)
+		outCtx := outgoingTransitionContextPool.Get()
+		*outCtx = outgoingTransitionContextImpl{tc}
+		outgoingTransitionInfo := t.mutator.OutgoingTransition(outCtx, sourceTransitionInfo)
 		for _, err := range outCtx.errs {
 			mctx.error(err)
 		}
+		outgoingTransitionContextPool.Put(outCtx)
+		outCtx = nil
 		if mctx.Failed() {
-			return outgoingVariation
+			return outgoingTransitionInfo
 		}
-		inCtx := &incomingTransitionContextImpl{tc}
-		finalVariation := t.mutator.IncomingTransition(inCtx, outgoingVariation)
+		inCtx := incomingTransitionContextPool.Get()
+		*inCtx = incomingTransitionContextImpl{tc}
+		finalTransitionInfo := t.mutator.IncomingTransition(inCtx, outgoingTransitionInfo)
 		for _, err := range inCtx.errs {
 			mctx.error(err)
 		}
-		return finalVariation
+		incomingTransitionContextPool.Put(inCtx)
+		inCtx = nil
+		return finalTransitionInfo
 	}
 }
 
@@ -315,9 +392,11 @@ func (t *transitionMutatorImpl) bottomUpMutator(mctx BottomUpMutatorContext) {
 	// Fetch and clean up transition mutator state. No locking needed since the
 	// only time interaction between multiple modules is required is during the
 	// computation of the variations required by a given module.
-	variations := mc.module.transitionVariations
+	variations := mc.module.splitTransitionVariations
+	transitionInfos := mc.module.splitTransitionInfos
 	outgoingTransitionCache := mc.module.outgoingTransitionCache
-	mc.module.transitionVariations = nil
+	mc.module.splitTransitionInfos = nil
+	mc.module.splitTransitionVariations = nil
 	mc.module.outgoingTransitionCache = nil
 	mc.module.currentTransitionMutator = ""
 
@@ -330,15 +409,18 @@ func (t *transitionMutatorImpl) bottomUpMutator(mctx BottomUpMutatorContext) {
 		// Module is not split, just apply the transition
 		mc.context.convertDepsToVariation(mc.module, 0,
 			chooseDepByIndexes(mc.mutator.name, outgoingTransitionCache))
+		mc.context.setModuleTransitionInfo(mc.module, t, transitionInfos[0])
 	} else {
-		mc.createVariationsWithTransition(variations, outgoingTransitionCache)
+		modules := mc.createVariationsWithTransition(variations, outgoingTransitionCache)
+		for i, module := range modules {
+			mc.context.setModuleTransitionInfo(module, t, transitionInfos[i])
+		}
 	}
 }
 
 func (t *transitionMutatorImpl) mutateMutator(mctx BottomUpMutatorContext) {
 	module := mctx.(*mutatorContext).module
-	currentVariation := module.variant.variations.get(t.name)
-	t.mutator.Mutate(mctx, currentVariation)
+	t.mutator.Mutate(mctx, module.transitionInfos[t.index])
 }
 
 type TransitionMutatorHandle interface {
@@ -351,25 +433,31 @@ type TransitionMutatorHandle interface {
 
 type transitionMutatorHandle struct {
 	inner MutatorHandle
+	impl  *transitionMutatorImpl
 }
 
 var _ TransitionMutatorHandle = (*transitionMutatorHandle)(nil)
 
 func (h *transitionMutatorHandle) NeverFar() TransitionMutatorHandle {
-	h.inner.setNeverFar()
+	h.impl.neverFar = true
 	return h
 }
 
 func (c *Context) RegisterTransitionMutator(name string, mutator TransitionMutator) TransitionMutatorHandle {
 	impl := &transitionMutatorImpl{name: name, mutator: mutator}
 
-	c.RegisterTopDownMutator(name+"_propagate", impl.topDownMutator)
+	c.registerTransitionPropagateMutator(name+"_propagate", impl.propagateMutator)
 	bottomUpHandle := c.RegisterBottomUpMutator(name, impl.bottomUpMutator).setTransitionMutator(impl)
 	c.RegisterBottomUpMutator(name+"_mutate", impl.mutateMutator)
-	return &transitionMutatorHandle{inner: bottomUpHandle}
+
+	impl.index = len(c.transitionMutators)
+	c.transitionMutators = append(c.transitionMutators, impl)
+	c.transitionMutatorNames = append(c.transitionMutatorNames, name)
+
+	return &transitionMutatorHandle{inner: bottomUpHandle, impl: impl}
 }
 
 // This function is called for every dependency edge to determine which
 // variation of the dependency is needed. Its inputs are the depending module,
 // its variation, the dependency and the dependency tag.
-type Transition func(source *moduleInfo, sourceVariation string, dep *moduleInfo, depTag DependencyTag) string
+type Transition func(source *moduleInfo, sourceTransitionInfo TransitionInfo, dep *moduleInfo, depTag DependencyTag) TransitionInfo
diff --git a/transition_test.go b/transition_test.go
index c84c288..ef205e3 100644
--- a/transition_test.go
+++ b/transition_test.go
@@ -523,40 +523,56 @@ func TestIsAddingDependency(t *testing.T) {
 
 type transitionTestMutator struct{}
 
-func (transitionTestMutator) Split(ctx BaseModuleContext) []string {
+func (transitionTestMutator) TransitionInfoFromVariation(s string) TransitionInfo {
+	return testTransitionInfo(s)
+}
+
+type testTransitionInfo string
+
+func (t testTransitionInfo) Variation() string {
+	return string(t)
+}
+
+func (transitionTestMutator) Split(ctx BaseModuleContext) []TransitionInfo {
 	if split := ctx.Module().(*transitionModule).properties.Split; len(split) > 0 {
-		return split
+		var transitionInfos []TransitionInfo
+		for _, s := range split {
+			transitionInfos = append(transitionInfos, testTransitionInfo(s))
+		}
+		return transitionInfos
 	}
-	return []string{""}
+	return []TransitionInfo{testTransitionInfo("")}
 }
 
-func (transitionTestMutator) OutgoingTransition(ctx OutgoingTransitionContext, sourceVariation string) string {
+func (transitionTestMutator) OutgoingTransition(ctx OutgoingTransitionContext, sourceVariation TransitionInfo) TransitionInfo {
 	if err := ctx.Module().(*transitionModule).properties.Outgoing_transition_error; err != nil {
 		ctx.ModuleErrorf("Error: %s", *err)
 	}
 	if outgoing := ctx.Module().(*transitionModule).properties.Outgoing; outgoing != nil {
-		return *outgoing
+		return testTransitionInfo(*outgoing)
 	}
 	return sourceVariation
 }
 
-func (transitionTestMutator) IncomingTransition(ctx IncomingTransitionContext, incomingVariation string) string {
+func (transitionTestMutator) IncomingTransition(ctx IncomingTransitionContext, incomingVariation TransitionInfo) TransitionInfo {
 	if err := ctx.Module().(*transitionModule).properties.Incoming_transition_error; err != nil {
 		ctx.ModuleErrorf("Error: %s", *err)
 	}
 	if ctx.IsAddingDependency() {
 		if incoming := ctx.Module().(*transitionModule).properties.Post_transition_incoming; incoming != nil {
-			return *incoming
+			return testTransitionInfo(*incoming)
 		}
 	}
 	if incoming := ctx.Module().(*transitionModule).properties.Incoming; incoming != nil {
-		return *incoming
+		return testTransitionInfo(*incoming)
 	}
 	return incomingVariation
 }
 
-func (transitionTestMutator) Mutate(ctx BottomUpMutatorContext, variation string) {
-	ctx.Module().(*transitionModule).properties.Mutated = variation
+func (transitionTestMutator) Mutate(ctx BottomUpMutatorContext, variation TransitionInfo) {
+	if variation != nil {
+		ctx.Module().(*transitionModule).properties.Mutated = variation.Variation()
+	}
 }
 
 type transitionModule struct {
diff --git a/uniquelist/Android.bp b/uniquelist/Android.bp
new file mode 100644
index 0000000..804d1b6
--- /dev/null
+++ b/uniquelist/Android.bp
@@ -0,0 +1,14 @@
+bootstrap_go_package {
+    name: "blueprint-uniquelist",
+    pkgPath: "github.com/google/blueprint/uniquelist",
+    srcs: [
+        "uniquelist.go",
+    ],
+    testSrcs: [
+        "uniquelist_test.go",
+    ],
+    visibility: [
+        "//build/blueprint",
+        "//build/blueprint/depset",
+    ],
+}
diff --git a/uniquelist/uniquelist.go b/uniquelist/uniquelist.go
new file mode 100644
index 0000000..d50cea6
--- /dev/null
+++ b/uniquelist/uniquelist.go
@@ -0,0 +1,161 @@
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
+package uniquelist
+
+import (
+	"iter"
+	"slices"
+	"unique"
+)
+
+// UniqueList is a workaround for Go limitation that slices are not comparable and
+// thus can't be used with unique.Make.  It interns slices by storing them in an
+// unrolled linked list, where each node has a fixed size array, which are comparable
+// and can be stored using the unique package.  A UniqueList is immutable.
+type UniqueList[T comparable] struct {
+	handle unique.Handle[node[T]]
+}
+
+// Len returns the length of the slice that was originally passed to Make.  It returns
+// a stored value and does not require iterating the linked list.
+func (s UniqueList[T]) Len() int {
+	var zeroList unique.Handle[node[T]]
+	if s.handle == zeroList {
+		return 0
+	}
+
+	return s.handle.Value().len
+}
+
+// ToSlice returns a slice containing a shallow copy of the list.
+func (s UniqueList[T]) ToSlice() []T {
+	return s.AppendTo(nil)
+}
+
+// Iter returns a iter.Seq that iterates the elements of the list.
+func (s UniqueList[T]) Iter() iter.Seq[T] {
+	var zeroSlice unique.Handle[node[T]]
+
+	return func(yield func(T) bool) {
+		cur := s.handle
+		for cur != zeroSlice {
+			impl := cur.Value()
+			for _, v := range impl.elements[:min(nodeSize, impl.len)] {
+				if !yield(v) {
+					return
+				}
+			}
+			cur = impl.next
+		}
+	}
+}
+
+// iterNodes returns an iter.Seq that iterates each node of the
+// unrolled linked list, returning a slice that contains all the
+// elements in a node at once.
+func (s UniqueList[T]) iterNodes() iter.Seq[[]T] {
+	var zeroSlice unique.Handle[node[T]]
+
+	return func(yield func([]T) bool) {
+		cur := s.handle
+		for cur != zeroSlice {
+			impl := cur.Value()
+			l := min(impl.len, len(impl.elements))
+			if !yield(impl.elements[:l]) {
+				return
+			}
+			cur = impl.next
+		}
+	}
+}
+
+// AppendTo appends the contents of the list to the given slice and returns
+// the results.
+func (s UniqueList[T]) AppendTo(slice []T) []T {
+	// TODO: should this grow by more than s.Len() to amortize reallocation costs?
+	slice = slices.Grow(slice, s.Len())
+	for chunk := range s.iterNodes() {
+		slice = append(slice, chunk...)
+	}
+	return slice
+}
+
+// node is a node in an unrolled linked list object that holds a group of elements of a
+// list in a fixed size array in order to satisfy the comparable constraint.
+type node[T comparable] struct {
+	// elements is a group of up to nodeSize elements of a list.
+	elements [nodeSize]T
+
+	// len is the length of the list stored in this node and any transitive linked nodes.
+	// If len is less than nodeSize then only the first len values in the elements array
+	// are part of the list.  If len is greater than nodeSize then next will point to the
+	// next node in the unrolled linked list.
+	len int
+
+	// next is the next node in the linked list.  If it is the zero value of unique.Handle
+	// then this is the last node.
+	next unique.Handle[node[T]]
+}
+
+// nodeSize is the number of list elements stored in each node.  The value 6 was chosen to make
+// the size of node 64 bytes to match the cache line size.
+const nodeSize = 6
+
+// Make returns a UniqueList for the given slice.  Two calls to UniqueList with the same slice contents
+// will return identical UniqueList objects.
+func Make[T comparable](slice []T) UniqueList[T] {
+	if len(slice) == 0 {
+		return UniqueList[T]{}
+	}
+
+	var last unique.Handle[node[T]]
+	l := 0
+
+	// Iterate backwards through the lists in chunks of nodeSize, with the first chunk visited
+	// being the partial chunk if the length of the slice is not a multiple of nodeSize.
+	//
+	// For each chunk, create an unrolled linked list node with a chunk of slice elements and a
+	// pointer to the previously created node, uniquified through unique.Make.
+	for chunk := range chunkReverse(slice, nodeSize) {
+		var node node[T]
+		copy(node.elements[:], chunk)
+		node.next = last
+		l += len(chunk)
+		node.len = l
+		last = unique.Make(node)
+	}
+
+	return UniqueList[T]{last}
+}
+
+// chunkReverse is similar to slices.Chunk, except that it returns the chunks in reverse
+// order.  If the length of the slice is not a multiple of n then the first chunk returned
+// (which is the last chunk of the input slice) is a partial chunk.
+func chunkReverse[T any](slice []T, n int) iter.Seq[[]T] {
+	return func(yield func([]T) bool) {
+		l := len(slice)
+		lastPartialChunkSize := l % n
+		if lastPartialChunkSize > 0 {
+			if !yield(slice[l-lastPartialChunkSize : l : l]) {
+				return
+			}
+		}
+		for i := l - lastPartialChunkSize - n; i >= 0; i -= n {
+			if !yield(slice[i : i+n : i+n]) {
+				return
+			}
+		}
+	}
+}
diff --git a/uniquelist/uniquelist_test.go b/uniquelist/uniquelist_test.go
new file mode 100644
index 0000000..f99f181
--- /dev/null
+++ b/uniquelist/uniquelist_test.go
@@ -0,0 +1,111 @@
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
+package uniquelist
+
+import (
+	"fmt"
+	"slices"
+	"testing"
+)
+
+func ExampleUniqueList() {
+	a := []string{"a", "b", "c", "d"}
+	uniqueA := Make(a)
+	b := slices.Clone(a)
+	uniqueB := Make(b)
+	fmt.Println(uniqueA == uniqueB)
+	fmt.Println(uniqueA.ToSlice())
+
+	// Output: true
+	// [a b c d]
+}
+
+func testSlice(n int) []int {
+	var slice []int
+	for i := 0; i < n; i++ {
+		slice = append(slice, i)
+	}
+	return slice
+}
+
+func TestUniqueList(t *testing.T) {
+	testCases := []struct {
+		name string
+		in   []int
+	}{
+		{
+			name: "nil",
+			in:   nil,
+		},
+		{
+			name: "zero",
+			in:   []int{},
+		},
+		{
+			name: "one",
+			in:   testSlice(1),
+		},
+		{
+			name: "nodeSize_minus_one",
+			in:   testSlice(nodeSize - 1),
+		},
+		{
+			name: "nodeSize",
+			in:   testSlice(nodeSize),
+		},
+		{
+			name: "nodeSize_plus_one",
+			in:   testSlice(nodeSize + 1),
+		},
+		{
+			name: "two_times_nodeSize_minus_one",
+			in:   testSlice(2*nodeSize - 1),
+		},
+		{
+			name: "two_times_nodeSize",
+			in:   testSlice(2 * nodeSize),
+		},
+		{
+			name: "two_times_nodeSize_plus_one",
+			in:   testSlice(2*nodeSize + 1),
+		},
+		{
+			name: "large",
+			in:   testSlice(1000),
+		},
+	}
+
+	for _, testCase := range testCases {
+		t.Run(testCase.name, func(t *testing.T) {
+			uniqueList := Make(testCase.in)
+
+			if g, w := uniqueList.ToSlice(), testCase.in; !slices.Equal(g, w) {
+				t.Errorf("incorrect ToSlice()\nwant: %q\ngot:  %q", w, g)
+			}
+
+			if g, w := slices.Collect(uniqueList.Iter()), testCase.in; !slices.Equal(g, w) {
+				t.Errorf("incorrect Iter()\nwant: %q\ngot:  %q", w, g)
+			}
+
+			if g, w := uniqueList.AppendTo([]int{-1}), append([]int{-1}, testCase.in...); !slices.Equal(g, w) {
+				t.Errorf("incorrect Iter()\nwant: %q\ngot:  %q", w, g)
+			}
+
+			if g, w := uniqueList.Len(), len(testCase.in); g != w {
+				t.Errorf("incorrect Len(), want %v, got %v", w, g)
+			}
+		})
+	}
+}
diff --git a/visit_test.go b/visit_test.go
index 34e67d1..f2e22da 100644
--- a/visit_test.go
+++ b/visit_test.go
@@ -50,7 +50,7 @@ func visitDepsMutator(ctx BottomUpMutatorContext) {
 	}
 }
 
-func visitMutator(ctx TopDownMutatorContext) {
+func visitMutator(ctx BottomUpMutatorContext) {
 	if m, ok := ctx.Module().(*visitModule); ok {
 		ctx.VisitDepsDepthFirst(func(dep Module) {
 			if ctx.OtherModuleDependencyTag(dep) != visitTagDep {
@@ -90,7 +90,7 @@ func setupVisitTest(t *testing.T) *Context {
 	ctx := NewContext()
 	ctx.RegisterModuleType("visit_module", newVisitModule)
 	ctx.RegisterBottomUpMutator("visit_deps", visitDepsMutator)
-	ctx.RegisterTopDownMutator("visit", visitMutator)
+	ctx.RegisterBottomUpMutator("visit", visitMutator)
 
 	ctx.MockFileSystem(map[string][]byte{
 		"Android.bp": []byte(`
```

