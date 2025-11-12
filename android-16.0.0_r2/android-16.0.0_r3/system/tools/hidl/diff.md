```diff
diff --git a/build/hidl_interface.go b/build/hidl_interface.go
index 93d82758..4770b708 100644
--- a/build/hidl_interface.go
+++ b/build/hidl_interface.go
@@ -314,7 +314,7 @@ func (g *hidlGenRule) GenerateAndroidBuildActions(ctx android.ModuleContext) {
 		return
 	}
 
-	ctx.ModuleBuild(pctx, android.ModuleBuildParams{
+	ctx.Build(pctx, android.BuildParams{
 		Rule:            rule,
 		Inputs:          inputs,
 		Output:          g.genOutputs[0],
@@ -866,7 +866,6 @@ var allAospHidlInterfaces = map[string]bool{
 	"android.frameworks.cameraservice.service@2.1": true,
 	"android.frameworks.cameraservice.service@2.2": true,
 	"android.frameworks.displayservice@1.0":        true,
-	"android.frameworks.schedulerservice@1.0":      true,
 	"android.frameworks.sensorservice@1.0":         true,
 	"android.frameworks.stats@1.0":                 true,
 	"android.frameworks.vr.composer@1.0":           true,
diff --git a/build/hidl_package_root.go b/build/hidl_package_root.go
index 628c210d..14ddb890 100644
--- a/build/hidl_package_root.go
+++ b/build/hidl_package_root.go
@@ -79,7 +79,7 @@ func (r *hidlPackageRoot) generateCurrentFile(ctx android.ModuleContext) {
 	output := android.PathForModuleGen(ctx, r.Name()+".txt")
 	r.genOutputs = append(r.genOutputs, output)
 
-	ctx.ModuleBuild(pctx, android.ModuleBuildParams{
+	ctx.Build(pctx, android.BuildParams{
 		Rule:   currentTxtRule,
 		Input:  r.currentPath.Path(),
 		Output: output,
```

