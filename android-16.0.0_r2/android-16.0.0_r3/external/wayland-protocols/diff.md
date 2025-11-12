```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
deleted file mode 100644
index 3591c7f..0000000
--- a/PREUPLOAD.cfg
+++ /dev/null
@@ -1,3 +0,0 @@
-[Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
-
diff --git a/wayland_protocol_codegen.go b/wayland_protocol_codegen.go
index 43f99cf..2294c53 100644
--- a/wayland_protocol_codegen.go
+++ b/wayland_protocol_codegen.go
@@ -127,8 +127,8 @@ func (t hostToolDependencyTag) AllowDisabledModuleDependency(target android.Modu
 
 func (t hostToolDependencyTag) AllowDisabledModuleDependencyProxy(
 	ctx android.OtherModuleProviderContext, target android.ModuleProxy) bool {
-	return android.OtherModulePointerProviderOrDefault(
-		ctx, target, android.CommonModuleInfoProvider).ReplacedByPrebuilt
+	return android.OtherModuleProviderOrDefault(
+		ctx, target, android.PrebuiltInfoProvider).ReplacedByPrebuilt
 }
 
 var _ android.AllowDisabledModuleDependency = (*hostToolDependencyTag)(nil)
@@ -633,15 +633,21 @@ func generatorFactory(taskGenerator taskFunc, props ...interface{}) *Module {
 
 type noopImageInterface struct{}
 
-func (x noopImageInterface) ImageMutatorBegin(android.ImageInterfaceContext)                 {}
-func (x noopImageInterface) VendorVariantNeeded(android.ImageInterfaceContext) bool          { return false }
-func (x noopImageInterface) ProductVariantNeeded(android.ImageInterfaceContext) bool         { return false }
-func (x noopImageInterface) CoreVariantNeeded(android.ImageInterfaceContext) bool            { return false }
-func (x noopImageInterface) RamdiskVariantNeeded(android.ImageInterfaceContext) bool         { return false }
-func (x noopImageInterface) VendorRamdiskVariantNeeded(android.ImageInterfaceContext) bool   { return false }
-func (x noopImageInterface) DebugRamdiskVariantNeeded(android.ImageInterfaceContext) bool    { return false }
-func (x noopImageInterface) RecoveryVariantNeeded(android.ImageInterfaceContext) bool        { return false }
-func (x noopImageInterface) ExtraImageVariations(ctx android.ImageInterfaceContext) []string { return nil }
+func (x noopImageInterface) ImageMutatorBegin(android.ImageInterfaceContext)         {}
+func (x noopImageInterface) VendorVariantNeeded(android.ImageInterfaceContext) bool  { return false }
+func (x noopImageInterface) ProductVariantNeeded(android.ImageInterfaceContext) bool { return false }
+func (x noopImageInterface) CoreVariantNeeded(android.ImageInterfaceContext) bool    { return false }
+func (x noopImageInterface) RamdiskVariantNeeded(android.ImageInterfaceContext) bool { return false }
+func (x noopImageInterface) VendorRamdiskVariantNeeded(android.ImageInterfaceContext) bool {
+	return false
+}
+func (x noopImageInterface) DebugRamdiskVariantNeeded(android.ImageInterfaceContext) bool {
+	return false
+}
+func (x noopImageInterface) RecoveryVariantNeeded(android.ImageInterfaceContext) bool { return false }
+func (x noopImageInterface) ExtraImageVariations(ctx android.ImageInterfaceContext) []string {
+	return nil
+}
 func (x noopImageInterface) SetImageVariation(ctx android.ImageInterfaceContext, variation string) {
 }
 
```

