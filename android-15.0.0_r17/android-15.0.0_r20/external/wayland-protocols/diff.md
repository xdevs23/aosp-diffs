```diff
diff --git a/wayland_protocol_codegen.go b/wayland_protocol_codegen.go
index 9b94a82..bb93af6 100644
--- a/wayland_protocol_codegen.go
+++ b/wayland_protocol_codegen.go
@@ -88,7 +88,7 @@ func registerCodeGenBuildComponents(ctx android.RegistrationContext) {
 	ctx.RegisterModuleType("wayland_protocol_codegen", codegenFactory)
 
 	ctx.FinalDepsMutators(func(ctx android.RegisterMutatorsContext) {
-		ctx.BottomUp("wayland_protocol_codegen_tool_deps", toolDepsMutator).Parallel()
+		ctx.BottomUp("wayland_protocol_codegen_tool_deps", toolDepsMutator)
 	})
 }
 
@@ -125,6 +125,12 @@ func (t hostToolDependencyTag) AllowDisabledModuleDependency(target android.Modu
 	return target.IsReplacedByPrebuilt()
 }
 
+func (t hostToolDependencyTag) AllowDisabledModuleDependencyProxy(
+	ctx android.OtherModuleProviderContext, target android.ModuleProxy) bool {
+	return android.OtherModuleProviderOrDefault(
+		ctx, target, android.CommonModuleInfoKey).ReplacedByPrebuilt
+}
+
 var _ android.AllowDisabledModuleDependency = (*hostToolDependencyTag)(nil)
 
 type generatorProperties struct {
@@ -293,22 +299,18 @@ func (g *Module) generateCommonBuildActions(ctx android.ModuleContext) {
 	if len(g.properties.Tools) > 0 {
 		seenTools := make(map[string]bool)
 
-		ctx.VisitDirectDepsBlueprint(func(module blueprint.Module) {
-			switch tag := ctx.OtherModuleDependencyTag(module).(type) {
+		ctx.VisitDirectDepsProxyAllowDisabled(func(proxy android.ModuleProxy) {
+			switch tag := ctx.OtherModuleDependencyTag(proxy).(type) {
 			case hostToolDependencyTag:
+				// Necessary to retrieve any prebuilt replacement for the tool, since
+				// toolDepsMutator runs too late for the prebuilt mutators to have
+				// replaced the dependency.
+				module := android.PrebuiltGetPreferred(ctx, proxy)
 				tool := ctx.OtherModuleName(module)
-				if m, ok := module.(android.Module); ok {
-					// Necessary to retrieve any prebuilt replacement for the tool, since
-					// toolDepsMutator runs too late for the prebuilt mutators to have
-					// replaced the dependency.
-					module = android.PrebuiltGetPreferred(ctx, m)
-				}
-
-				switch t := module.(type) {
-				case android.HostToolProvider:
+				if h, ok := android.OtherModuleProvider(ctx, module, android.HostToolProviderKey); ok {
 					// A HostToolProvider provides the path to a tool, which will be copied
 					// into the sandbox.
-					if !t.(android.Module).Enabled(ctx) {
+					if !android.OtherModuleProviderOrDefault(ctx, module, android.CommonModuleInfoKey).Enabled {
 						if ctx.Config().AllowMissingDependencies() {
 							ctx.AddMissingDependencies([]string{tool})
 						} else {
@@ -316,25 +318,35 @@ func (g *Module) generateCommonBuildActions(ctx android.ModuleContext) {
 						}
 						return
 					}
-					path := t.HostToolPath()
+					path := h.HostToolPath
 					if !path.Valid() {
 						ctx.ModuleErrorf("host tool %q missing output file", tool)
 						return
 					}
 					if specs := android.OtherModuleProviderOrDefault(
-						ctx, t, android.InstallFilesProvider).TransitivePackagingSpecs.ToList(); specs != nil {
+						ctx, module, android.InstallFilesProvider).TransitivePackagingSpecs.ToList(); specs != nil {
 						// If the HostToolProvider has PackgingSpecs, which are definitions of the
 						// required relative locations of the tool and its dependencies, use those
 						// instead.  They will be copied to those relative locations in the sbox
 						// sandbox.
-						packagedTools = append(packagedTools, specs...)
+						// Care must be taken since TransitivePackagingSpec may return device-side
+						// paths via the required property. Filter them out.
+						for i, ps := range specs {
+							if ps.Partition() != "" {
+								if i == 0 {
+									panic("first PackagingSpec is assumed to be the host-side tool")
+								}
+								continue
+							}
+							packagedTools = append(packagedTools, ps)
+						}
 						// Assume that the first PackagingSpec of the module is the tool.
 						addLocationLabel(tag.label, packagedToolLocation{specs[0]})
 					} else {
 						tools = append(tools, path.Path())
 						addLocationLabel(tag.label, toolLocation{android.Paths{path.Path()}})
 					}
-				default:
+				} else {
 					ctx.ModuleErrorf("%q is not a host tool provider", tool)
 					return
 				}
@@ -624,16 +636,16 @@ func generatorFactory(taskGenerator taskFunc, props ...interface{}) *Module {
 
 type noopImageInterface struct{}
 
-func (x noopImageInterface) ImageMutatorBegin(android.BaseModuleContext)                 {}
-func (x noopImageInterface) VendorVariantNeeded(android.BaseModuleContext) bool          { return false }
-func (x noopImageInterface) ProductVariantNeeded(android.BaseModuleContext) bool         { return false }
-func (x noopImageInterface) CoreVariantNeeded(android.BaseModuleContext) bool            { return false }
-func (x noopImageInterface) RamdiskVariantNeeded(android.BaseModuleContext) bool         { return false }
-func (x noopImageInterface) VendorRamdiskVariantNeeded(android.BaseModuleContext) bool   { return false }
-func (x noopImageInterface) DebugRamdiskVariantNeeded(android.BaseModuleContext) bool    { return false }
-func (x noopImageInterface) RecoveryVariantNeeded(android.BaseModuleContext) bool        { return false }
-func (x noopImageInterface) ExtraImageVariations(ctx android.BaseModuleContext) []string { return nil }
-func (x noopImageInterface) SetImageVariation(ctx android.BaseModuleContext, variation string) {
+func (x noopImageInterface) ImageMutatorBegin(android.ImageInterfaceContext)                 {}
+func (x noopImageInterface) VendorVariantNeeded(android.ImageInterfaceContext) bool          { return false }
+func (x noopImageInterface) ProductVariantNeeded(android.ImageInterfaceContext) bool         { return false }
+func (x noopImageInterface) CoreVariantNeeded(android.ImageInterfaceContext) bool            { return false }
+func (x noopImageInterface) RamdiskVariantNeeded(android.ImageInterfaceContext) bool         { return false }
+func (x noopImageInterface) VendorRamdiskVariantNeeded(android.ImageInterfaceContext) bool   { return false }
+func (x noopImageInterface) DebugRamdiskVariantNeeded(android.ImageInterfaceContext) bool    { return false }
+func (x noopImageInterface) RecoveryVariantNeeded(android.ImageInterfaceContext) bool        { return false }
+func (x noopImageInterface) ExtraImageVariations(ctx android.ImageInterfaceContext) []string { return nil }
+func (x noopImageInterface) SetImageVariation(ctx android.ImageInterfaceContext, variation string) {
 }
 
 // Constructs a Module for handling the code generation.
```

