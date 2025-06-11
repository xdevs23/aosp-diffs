```diff
diff --git a/ConstantExpression.cpp b/ConstantExpression.cpp
index 6930c0f4..a0019be8 100644
--- a/ConstantExpression.cpp
+++ b/ConstantExpression.cpp
@@ -487,7 +487,7 @@ std::string ConstantExpression::rawValue(ScalarType::Kind castKind) const {
 
 #define CASE_STR(__type__) return std::to_string(this->cast<__type__>());
 
-    SWITCH_KIND(castKind, CASE_STR, SHOULD_NOT_REACH(); return nullptr; );
+    SWITCH_KIND(castKind, CASE_STR, SHOULD_NOT_REACH(); return ""; );
 }
 
 template<typename T>
diff --git a/build/hidl_interface.go b/build/hidl_interface.go
index 6250604b..93d82758 100644
--- a/build/hidl_interface.go
+++ b/build/hidl_interface.go
@@ -10,7 +10,7 @@
 // distributed under the License is distributed on an "AS IS" BASIS,
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
-// limitations under the License.
+// limitations under the License.f
 
 package hidl
 
@@ -158,11 +158,11 @@ type allHidlLintsSingleton struct {
 
 func (m *allHidlLintsSingleton) GenerateBuildActions(ctx android.SingletonContext) {
 	var hidlLintOutputs android.Paths
-	ctx.VisitAllModules(func(m android.Module) {
-		if t, ok := m.(*hidlGenRule); ok {
-			if t.properties.Language == "lint" {
-				if len(t.genOutputs) == 1 {
-					hidlLintOutputs = append(hidlLintOutputs, t.genOutputs[0])
+	ctx.VisitAllModuleProxies(func(m android.ModuleProxy) {
+		if t, ok := android.OtherModuleProvider(ctx, m, HidlGenRuleInfoProvider); ok {
+			if t.Language == "lint" {
+				if len(t.GenOutputs) == 1 {
+					hidlLintOutputs = append(hidlLintOutputs, t.GenOutputs[0])
 				} else {
 					panic("-hidl-lint target was not configured correctly")
 				}
@@ -182,11 +182,12 @@ func (m *allHidlLintsSingleton) GenerateBuildActions(ctx android.SingletonContex
 			"files":  strings.Join(hidlLintOutputs.Strings(), " "),
 		},
 	})
+
+	ctx.DistForGoal("dist_files", outPath)
 }
 
 func (m *allHidlLintsSingleton) MakeVars(ctx android.MakeVarsContext) {
 	ctx.Strict("ALL_HIDL_LINTS_ZIP", m.outPath.String())
-	ctx.DistForGoal("dist_files", m.outPath)
 }
 
 type hidlGenProperties struct {
@@ -209,6 +210,13 @@ type hidlGenRule struct {
 	genOutputs   android.WritablePaths
 }
 
+type HidlGenRuleInfo struct {
+	Language   string
+	GenOutputs android.WritablePaths
+}
+
+var HidlGenRuleInfoProvider = blueprint.NewProvider[HidlGenRuleInfo]()
+
 var _ android.SourceFileProducer = (*hidlGenRule)(nil)
 var _ genrule.SourceFileGenerator = (*hidlGenRule)(nil)
 
@@ -270,6 +278,11 @@ func (g *hidlGenRule) GenerateAndroidBuildActions(ctx android.ModuleContext) {
 		rule = hidlSrcJarRule
 	}
 
+	android.SetProvider(ctx, HidlGenRuleInfoProvider, HidlGenRuleInfo{
+		Language:   g.properties.Language,
+		GenOutputs: g.genOutputs,
+	})
+
 	if g.properties.Language == "lint" {
 		ctx.Build(pctx, android.BuildParams{
 			Rule:   lintRule,
diff --git a/test/hidl_test/static_test.cpp b/test/hidl_test/static_test.cpp
index 3d9f3f01..906755d6 100644
--- a/test/hidl_test/static_test.cpp
+++ b/test/hidl_test/static_test.cpp
@@ -144,8 +144,7 @@ static_assert(IExpression::UInt64BitShifting::uint64BitShift1 == 1LL << 63, "1l
 
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wconstant-logical-operand"
-#pragma clang diagnostic ignored "-Wlogical-op-parentheses"
-#pragma clang diagnostic ignored "-Wbitwise-op-parentheses"
+#pragma clang diagnostic ignored "-Wparentheses"
 
 static_assert(IExpression::Precedence::literal == (4), "");
 static_assert(IExpression::Precedence::neg == (-4), "");
```

