```diff
diff --git a/soong/bindings_generator.go b/soong/bindings_generator.go
index 98a27a278..e5f6e52cd 100644
--- a/soong/bindings_generator.go
+++ b/soong/bindings_generator.go
@@ -105,7 +105,7 @@ func (m *mojomDowngradedFiles) GenerateAndroidBuildActions(ctx android.ModuleCon
 		out := android.PathForModuleGen(ctx, in.Rel())
 		m.generatedSrcs = append(m.generatedSrcs, out)
 
-		ctx.ModuleBuild(pctx, android.ModuleBuildParams{
+		ctx.Build(pctx, android.BuildParams{
 			Rule:   downgradeMojomTypesRule,
 			Input:  in,
 			Output: out,
@@ -171,7 +171,7 @@ func (m *mojomPickles) GenerateAndroidBuildActions(ctx android.ModuleContext) {
 		out := android.PathForModuleGen(ctx, relStem+".p")
 		m.generatedSrcs = append(m.generatedSrcs, out)
 
-		ctx.ModuleBuild(pctx, android.ModuleBuildParams{
+		ctx.Build(pctx, android.BuildParams{
 			Rule:   generateMojomPicklesRule,
 			Input:  in,
 			Output: out,
@@ -317,7 +317,7 @@ func (p *mojomGenerationProperties) generateBuildActions(
 				outs = append(outs, out)
 				generatedSrcs = append(generatedSrcs, out)
 			}
-			ctx.ModuleBuild(pctx, android.ModuleBuildParams{
+			ctx.Build(pctx, android.BuildParams{
 				Rule:      generateMojomSrcsRule,
 				Input:     in,
 				Implicits: implicitDeps,
@@ -469,7 +469,7 @@ func (m *mojomSrcjar) GenerateAndroidBuildActions(ctx android.ModuleContext) {
 	)
 
 	out := android.PathForModuleGen(ctx, m.properties.Srcjar)
-	ctx.ModuleBuild(pctx, android.ModuleBuildParams{
+	ctx.Build(pctx, android.BuildParams{
 		Rule:   mergeSrcjarsRule,
 		Inputs: srcjars,
 		Output: out,
```

