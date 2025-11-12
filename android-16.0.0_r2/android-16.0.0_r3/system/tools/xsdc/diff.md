```diff
diff --git a/build/xsdc.go b/build/xsdc.go
index b64fe89..57d56c4 100644
--- a/build/xsdc.go
+++ b/build/xsdc.go
@@ -144,7 +144,7 @@ func (module *xsdConfig) generateXsdConfig(ctx android.ModuleContext) {
 	output := android.PathForModuleGen(ctx, module.Name()+".xsd")
 	module.genOutputs = append(module.genOutputs, output)
 
-	ctx.ModuleBuild(pctx, android.ModuleBuildParams{
+	ctx.Build(pctx, android.BuildParams{
 		Rule:   xsdConfigRule,
 		Input:  module.xsdConfigPath,
 		Output: output,
@@ -231,7 +231,7 @@ func (module *xsdConfig) GenerateAndroidBuildActions(ctx android.ModuleContext)
 		}
 	})
 
-	srcFiles := ctx.ExpandSources(module.properties.Srcs, nil)
+	srcFiles := android.PathsForModuleSrc(ctx, module.properties.Srcs)
 	module.xsdConfigPath = srcFiles[0]
 	module.xsdIncludeConfigPaths = android.PathsForModuleSrc(ctx, module.properties.Include_files)
 
```

