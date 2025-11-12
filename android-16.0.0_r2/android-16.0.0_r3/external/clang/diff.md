```diff
diff --git a/soong/tblgen.go b/soong/tblgen.go
index aa14b42168..32c451d89b 100644
--- a/soong/tblgen.go
+++ b/soong/tblgen.go
@@ -74,7 +74,7 @@ func (t *tblgen) GenerateAndroidBuildActions(ctx android.ModuleContext) {
 		out := android.PathForModuleGen(ctx, o)
 		generator := outToGenerator(ctx, o)
 
-		ctx.ModuleBuild(pctx, android.ModuleBuildParams{
+		ctx.Build(pctx, android.BuildParams{
 			Rule:   tblgenRule,
 			Input:  in,
 			Output: out,
```

