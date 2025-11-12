```diff
diff --git a/soong/tblgen.go b/soong/tblgen.go
index f1565a4065..60107ce4a8 100644
--- a/soong/tblgen.go
+++ b/soong/tblgen.go
@@ -73,7 +73,7 @@ func (t *tblgen) GenerateAndroidBuildActions(ctx android.ModuleContext) {
 		out := android.PathForModuleGen(ctx, o)
 		generator := outToGenerator(ctx, o)
 
-		ctx.ModuleBuild(pctx, android.ModuleBuildParams{
+		ctx.Build(pctx, android.BuildParams{
 			Rule:   tblgenRule,
 			Input:  in,
 			Output: out,
```

