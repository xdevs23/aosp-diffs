```diff
diff --git a/build/xsdc.go b/build/xsdc.go
index 57c59e7..e02ed21 100644
--- a/build/xsdc.go
+++ b/build/xsdc.go
@@ -30,7 +30,7 @@ func init() {
 	android.RegisterModuleType("xsd_config", xsdConfigFactory)
 
 	android.PreArchMutators(func(ctx android.RegisterMutatorsContext) {
-		ctx.TopDown("xsd_config", xsdConfigMutator).Parallel()
+		ctx.BottomUp("xsd_config", xsdConfigMutator).Parallel()
 	})
 }
 
@@ -319,7 +319,7 @@ func (module *xsdConfig) setOutputFiles(ctx android.ModuleContext) {
 	ctx.SetOutputFiles(module.genOutputs_h.Paths(), "h")
 }
 
-func xsdConfigMutator(mctx android.TopDownMutatorContext) {
+func xsdConfigMutator(mctx android.BottomUpMutatorContext) {
 	if module, ok := mctx.Module().(*xsdConfig); ok {
 		name := module.BaseModuleName()
 
```

