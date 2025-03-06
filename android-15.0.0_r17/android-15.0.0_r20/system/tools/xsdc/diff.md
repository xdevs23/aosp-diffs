```diff
diff --git a/build/xsdc.go b/build/xsdc.go
index e02ed21..b64fe89 100644
--- a/build/xsdc.go
+++ b/build/xsdc.go
@@ -28,10 +28,6 @@ import (
 func init() {
 	pctx.Import("android/soong/java/config")
 	android.RegisterModuleType("xsd_config", xsdConfigFactory)
-
-	android.PreArchMutators(func(ctx android.RegisterMutatorsContext) {
-		ctx.BottomUp("xsd_config", xsdConfigMutator).Parallel()
-	})
 }
 
 var (
@@ -319,47 +315,47 @@ func (module *xsdConfig) setOutputFiles(ctx android.ModuleContext) {
 	ctx.SetOutputFiles(module.genOutputs_h.Paths(), "h")
 }
 
-func xsdConfigMutator(mctx android.BottomUpMutatorContext) {
-	if module, ok := mctx.Module().(*xsdConfig); ok {
-		name := module.BaseModuleName()
+func xsdConfigLoadHook(mctx android.LoadHookContext) {
+	module := mctx.Module().(*xsdConfig)
+	name := module.BaseModuleName()
 
-		args := " --stub-packages " + *module.properties.Package_name +
-			" --hide MissingPermission --hide BroadcastBehavior" +
-			" --hide HiddenSuperclass --hide DeprecationMismatch --hide UnavailableSymbol" +
-			" --hide SdkConstant --hide HiddenTypeParameter --hide Todo"
+	args := " --stub-packages " + *module.properties.Package_name +
+		" --hide MissingPermission --hide BroadcastBehavior" +
+		" --hide HiddenSuperclass --hide DeprecationMismatch --hide UnavailableSymbol" +
+		" --hide SdkConstant --hide HiddenTypeParameter --hide Todo"
 
-		api_dir := proptools.StringDefault(module.properties.Api_dir, "api")
+	api_dir := proptools.StringDefault(module.properties.Api_dir, "api")
 
-		currentApiFileName := filepath.Join(api_dir, "current.txt")
-		removedApiFileName := filepath.Join(api_dir, "removed.txt")
+	currentApiFileName := filepath.Join(api_dir, "current.txt")
+	removedApiFileName := filepath.Join(api_dir, "removed.txt")
 
-		check_api := CheckApi{}
+	check_api := CheckApi{}
 
-		check_api.Current.Api_file = proptools.StringPtr(currentApiFileName)
-		check_api.Current.Removed_api_file = proptools.StringPtr(removedApiFileName)
+	check_api.Current.Api_file = proptools.StringPtr(currentApiFileName)
+	check_api.Current.Removed_api_file = proptools.StringPtr(removedApiFileName)
 
-		check_api.Last_released.Api_file = proptools.StringPtr(
-			filepath.Join(api_dir, "last_current.txt"))
-		check_api.Last_released.Removed_api_file = proptools.StringPtr(
-			filepath.Join(api_dir, "last_removed.txt"))
+	check_api.Last_released.Api_file = proptools.StringPtr(
+		filepath.Join(api_dir, "last_current.txt"))
+	check_api.Last_released.Removed_api_file = proptools.StringPtr(
+		filepath.Join(api_dir, "last_removed.txt"))
 
-		mctx.CreateModule(java.DroidstubsFactory, &DroidstubsProperties{
-			Name:                 proptools.StringPtr(name + ".docs"),
-			Srcs:                 []string{":" + name},
-			Args:                 proptools.StringPtr(args),
-			Api_filename:         proptools.StringPtr(currentApiFileName),
-			Removed_api_filename: proptools.StringPtr(removedApiFileName),
-			Check_api:            check_api,
-			Installable:          proptools.BoolPtr(false),
-			Sdk_version:          proptools.StringPtr("core_platform"),
-		})
-	}
+	mctx.CreateModule(java.DroidstubsFactory, &DroidstubsProperties{
+		Name:                 proptools.StringPtr(name + ".docs"),
+		Srcs:                 []string{":" + name},
+		Args:                 proptools.StringPtr(args),
+		Api_filename:         proptools.StringPtr(currentApiFileName),
+		Removed_api_filename: proptools.StringPtr(removedApiFileName),
+		Check_api:            check_api,
+		Installable:          proptools.BoolPtr(false),
+		Sdk_version:          proptools.StringPtr("core_platform"),
+	})
 }
 
 func xsdConfigFactory() android.Module {
 	module := &xsdConfig{}
 	module.AddProperties(&module.properties)
 	android.InitAndroidModule(module)
+	android.AddLoadHook(module, xsdConfigLoadHook)
 
 	return module
 }
diff --git a/src/main/java/com/android/xsdc/XsdHandler.java b/src/main/java/com/android/xsdc/XsdHandler.java
index f6a9492..2f0a072 100644
--- a/src/main/java/com/android/xsdc/XsdHandler.java
+++ b/src/main/java/com/android/xsdc/XsdHandler.java
@@ -206,11 +206,11 @@ public class XsdHandler extends DefaultHandler {
                     // Tags under simpleType <restriction>. They are ignored.
                     break;
                 case "annotation":
-                    stateStack.peek().deprecated = isDeprecated(state.attributeMap, state.tags,
+                    stateStack.peek().deprecated = isDeprecated(state.attributeMap,
                             stateStack.peek().deprecated);
-                    stateStack.peek().finalValue = isFinalValue(state.attributeMap, state.tags,
+                    stateStack.peek().finalValue = isFinalValue(state.attributeMap,
                             stateStack.peek().finalValue);
-                    stateStack.peek().nullability = getNullability(state.attributeMap, state.tags,
+                    stateStack.peek().nullability = getNullability(state.attributeMap,
                             stateStack.peek().nullability);
                     break;
                 case "appinfo":
@@ -311,7 +311,6 @@ public class XsdHandler extends DefaultHandler {
         String name = state.attributeMap.get("name");
         QName typename = parseQName(state.attributeMap.get("type"));
         QName ref = parseQName(state.attributeMap.get("ref"));
-        String defVal = state.attributeMap.get("default");
         String use = state.attributeMap.get("use");
 
         if (use != null && use.equals("prohibited")) return null;
@@ -673,8 +672,7 @@ public class XsdHandler extends DefaultHandler {
         includeList.add(fileName);
     }
 
-    private boolean isDeprecated(Map<String, String> attributeMap,List<XsdTag> tags,
-            boolean deprecated) throws XsdParserException {
+    private boolean isDeprecated(Map<String, String> attributeMap, boolean deprecated) throws XsdParserException {
         String name = attributeMap.get("name");
         if ("Deprecated".equals(name)) {
             return true;
@@ -682,8 +680,7 @@ public class XsdHandler extends DefaultHandler {
         return deprecated;
     }
 
-    private boolean isFinalValue(Map<String, String> attributeMap,List<XsdTag> tags,
-            boolean finalValue) throws XsdParserException {
+    private boolean isFinalValue(Map<String, String> attributeMap, boolean finalValue) throws XsdParserException {
         String name = attributeMap.get("name");
         if ("final".equals(name)) {
             return true;
@@ -691,8 +688,7 @@ public class XsdHandler extends DefaultHandler {
         return finalValue;
     }
 
-    private Nullability getNullability(Map<String, String> attributeMap,List<XsdTag> tags,
-            Nullability nullability) throws XsdParserException {
+    private Nullability getNullability(Map<String, String> attributeMap, Nullability nullability) throws XsdParserException {
         String name = attributeMap.get("name");
         if ("nullable".equals(name)) {
             return Nullability.NULLABLE;
diff --git a/src/main/java/com/android/xsdc/cpp/CppCodeGenerator.java b/src/main/java/com/android/xsdc/cpp/CppCodeGenerator.java
index a58647d..a74319f 100644
--- a/src/main/java/com/android/xsdc/cpp/CppCodeGenerator.java
+++ b/src/main/java/com/android/xsdc/cpp/CppCodeGenerator.java
@@ -163,9 +163,9 @@ public class CppCodeGenerator {
         }
         parserHeaderFile.printf("\n");
         if (useTinyXml) {
-            printGuardedIncludes(parserHeaderFile, "libtinyxml2", "tinyxml2.h");
+            printGuardedIncludes("libtinyxml2", "tinyxml2.h");
         } else {
-            printGuardedIncludes(parserHeaderFile, "libxml2", "libxml/parser.h",
+            printGuardedIncludes("libxml2", "libxml/parser.h",
                     Arrays.asList("libxml/xinclude.h"));
         }
         if (hasEnums) {
@@ -266,11 +266,11 @@ public class CppCodeGenerator {
         enumsHeaderFile.close();
     }
 
-    private void printGuardedIncludes(CodeWriter file, String libName, String mainHeader) {
-        printGuardedIncludes(file, libName, mainHeader, Collections.emptyList());
+    private void printGuardedIncludes(String libName, String mainHeader) {
+        printGuardedIncludes(libName, mainHeader, Collections.emptyList());
     }
 
-    private void printGuardedIncludes(CodeWriter file, String libName, String mainHeader,
+    private void printGuardedIncludes(String libName, String mainHeader,
             Collection<String> additionalHeaders) {
         parserHeaderFile.printf("#if __has_include(<%s>)\n", mainHeader);
         parserHeaderFile.printf("#include <%s>\n", mainHeader);
@@ -908,7 +908,6 @@ public class CppCodeGenerator {
                 getValueType((XsdSimpleContent) complexType, false) : null;
         if (valueType != null) {
             constructorArgs.append(String.format(", %s %s", valueType.getName(), "value"));
-            boolean isMultipleType = (valueType.isList() ? true : false);
             constructor.append(String.format(", %s_(%s)", "value", "value"));
             // getParsingExpression prepends with underscore, so set args for instantiation
             args.append(String.format(", %s", "_value"));
diff --git a/src/main/java/com/android/xsdc/java/JavaCodeGenerator.java b/src/main/java/com/android/xsdc/java/JavaCodeGenerator.java
index 0fc2b7c..8be3253 100644
--- a/src/main/java/com/android/xsdc/java/JavaCodeGenerator.java
+++ b/src/main/java/com/android/xsdc/java/JavaCodeGenerator.java
@@ -283,7 +283,7 @@ public class JavaCodeGenerator {
         out.println();
         printParser(out, nameScope + name, complexType);
         if (writer) {
-            printWriter(out, name, complexType);
+            printWriter(out, complexType);
         }
 
         out.println("}");
@@ -376,10 +376,8 @@ public class JavaCodeGenerator {
                 + "}\n");
     }
 
-    private void printWriter(CodeWriter out, String name, XsdComplexType complexType)
+    private void printWriter(CodeWriter out, XsdComplexType complexType)
             throws JavaCodeGeneratorException {
-        JavaSimpleType baseValueType = (complexType instanceof XsdSimpleContent) ?
-                getValueType((XsdSimpleContent) complexType, true) : null;
         List<XsdElement> allElements = new ArrayList<>();
         List<XsdAttribute> allAttributes = new ArrayList<>();
         stackComponents(complexType, allElements, allAttributes);
@@ -404,7 +402,6 @@ public class JavaCodeGenerator {
         out.print("_out.print(\"<\" + _name);\n");
         for (int i = 0; i < allAttributes.size(); ++i) {
             JavaType type = allAttributeTypes.get(i);
-            boolean isList = allAttributeTypes.get(i).isList();
             XsdAttribute attribute = resolveAttribute(allAttributes.get(i));
             String variableName = Utils.toVariableName(attribute.getName());
             out.printf("if (has%s()) {\n", Utils.capitalize(variableName));
```

