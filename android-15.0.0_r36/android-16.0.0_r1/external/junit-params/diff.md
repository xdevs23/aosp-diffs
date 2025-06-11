```diff
diff --git a/OWNERS b/OWNERS
index 851c64c..667b369 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
 paulduffin@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.google b/README.google
index a1ef97e..b840fed 100644
--- a/README.google
+++ b/README.google
@@ -21,3 +21,4 @@ Local Modifications:
       36541809 - Partially revert 36541809 to allow @TestCaseName to be
                  used as long as it generates a name that is compatible
                  with CTS and AJUR.
+      394914027- Preserve annotations when method is parameterized.
diff --git a/src/main/java/junitparams/internal/TestMethod.java b/src/main/java/junitparams/internal/TestMethod.java
index d0188ef..8b16a8f 100644
--- a/src/main/java/junitparams/internal/TestMethod.java
+++ b/src/main/java/junitparams/internal/TestMethod.java
@@ -4,6 +4,7 @@ import java.lang.annotation.Annotation;
 import java.lang.reflect.Method;
 import java.util.ArrayList;
 import java.util.Arrays;
+import java.util.Collection;
 import java.util.List;
 
 import org.junit.Ignore;
@@ -101,12 +102,13 @@ public class TestMethod {
         return frameworkMethodAnnotations.getAnnotation(annotationType);
     }
 
-    private Description getDescription(Object[] params, int i) {
+    private Description getDescription(Object[] params, int i, Collection<Annotation> parentAnnotations) {
         Object paramSet = params[i];
         String name = namingStrategy.getTestCaseName(i, paramSet);
+        name = String.format("%s(%s)", name, testClass().getName());
         String uniqueMethodId = Utils.uniqueMethodId(i, paramSet, name());
 
-        return Description.createTestDescription(testClass().getName(), name, uniqueMethodId);
+        return Description.createSuiteDescription(name, uniqueMethodId, parentAnnotations.toArray(new Annotation[0]));
     }
 
     DescribableFrameworkMethod describableFrameworkMethod() {
@@ -135,7 +137,7 @@ public class TestMethod {
                         = new ArrayList<InstanceFrameworkMethod>();
                 for (int i = 0; i < parametersSets.length; i++) {
                     Object parametersSet = parametersSets[i];
-                    Description description = getDescription(parametersSets, i);
+                    Description description = getDescription(parametersSets, i, baseDescription.getAnnotations());
                     methods.add(new InstanceFrameworkMethod(
                             method, baseDescription.childlessCopy(),
                             description, parametersSet));
```

