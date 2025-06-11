```diff
diff --git a/OWNERS b/OWNERS
index 899c9a6..c3a0434 100644
--- a/OWNERS
+++ b/OWNERS
@@ -12,3 +12,4 @@ xutan@google.com #{LAST_RESORT_SUGGESTION}
 
 # Allow Soong team to make build changes
 per-file bazel/*,Android.bp,*.go,go.mod,go.work,go.work.sum = file:platform/build/soong:/OWNERS #{LAST_RESORT_SUGGESTION}
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/wayland_protocol_codegen.go b/wayland_protocol_codegen.go
index bb93af6..43f99cf 100644
--- a/wayland_protocol_codegen.go
+++ b/wayland_protocol_codegen.go
@@ -127,8 +127,8 @@ func (t hostToolDependencyTag) AllowDisabledModuleDependency(target android.Modu
 
 func (t hostToolDependencyTag) AllowDisabledModuleDependencyProxy(
 	ctx android.OtherModuleProviderContext, target android.ModuleProxy) bool {
-	return android.OtherModuleProviderOrDefault(
-		ctx, target, android.CommonModuleInfoKey).ReplacedByPrebuilt
+	return android.OtherModulePointerProviderOrDefault(
+		ctx, target, android.CommonModuleInfoProvider).ReplacedByPrebuilt
 }
 
 var _ android.AllowDisabledModuleDependency = (*hostToolDependencyTag)(nil)
@@ -307,10 +307,10 @@ func (g *Module) generateCommonBuildActions(ctx android.ModuleContext) {
 				// replaced the dependency.
 				module := android.PrebuiltGetPreferred(ctx, proxy)
 				tool := ctx.OtherModuleName(module)
-				if h, ok := android.OtherModuleProvider(ctx, module, android.HostToolProviderKey); ok {
+				if h, ok := android.OtherModuleProvider(ctx, module, android.HostToolProviderInfoProvider); ok {
 					// A HostToolProvider provides the path to a tool, which will be copied
 					// into the sandbox.
-					if !android.OtherModuleProviderOrDefault(ctx, module, android.CommonModuleInfoKey).Enabled {
+					if !android.OtherModulePointerProviderOrDefault(ctx, module, android.CommonModuleInfoProvider).Enabled {
 						if ctx.Config().AllowMissingDependencies() {
 							ctx.AddMissingDependencies([]string{tool})
 						} else {
@@ -614,11 +614,8 @@ var _ android.IDEInfo = (*Module)(nil)
 var _ android.ApexModule = (*Module)(nil)
 
 // Part of android.ApexModule.
-func (g *Module) ShouldSupportSdkVersion(ctx android.BaseModuleContext,
-	sdkVersion android.ApiLevel) error {
-	// Because generated outputs are checked by client modules(e.g. cc_library, ...)
-	// we can safely ignore the check here.
-	return nil
+func (g *Module) MinSdkVersionSupported(ctx android.BaseModuleContext) android.ApiLevel {
+	return android.MinApiLevel
 }
 
 func generatorFactory(taskGenerator taskFunc, props ...interface{}) *Module {
```

