```diff
diff --git a/Android.bp b/Android.bp
index b939bff..852b910 100644
--- a/Android.bp
+++ b/Android.bp
@@ -252,6 +252,8 @@ java_library_static {
 // Stubbing static methods is not an official mockito API.
 // Project depending on this also need to depend on the static JNI libraries libstaticjvmtiagent and
 // libdexmakerjvmtiagent
+// This library as known leaks that can lead to a crash. Local workaround is to
+// call Mockito.framework().clearInlineMocks()
 java_library_static {
     name: "mockito-target-extended",
     static_libs: [
diff --git a/OWNERS b/OWNERS
index 5119321..13872f3 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 paulduffin@google.com
 xutan@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.version b/README.version
index 00257de..76ae771 100644
--- a/README.version
+++ b/README.version
@@ -16,3 +16,4 @@ Local Modifications:
         Exclude Stress#mockALot from presubmit (Ic9a2927ffa07924bd759429e31c56dc1b71a826c)
         Extend timeout of Stress#mockALot() for CTS. (Iad30a8cb07b38054b490b7006d11908fc752a024)
         Minor change: Remove empty statement in DexMaker (Ide74cc51907912883e658db7f049bcce3675fc01)
+        Mock: Add multidimensional type class (I52ff53c9eab51bc91539ba54bc509a30fef501d1)
diff --git a/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/MockStatic.java b/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/MockStatic.java
index 95a9baa..25a8789 100644
--- a/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/MockStatic.java
+++ b/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/MockStatic.java
@@ -25,7 +25,7 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockingDeta
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.reset;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.staticMockMarker;
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.verifyZeroInteractions;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verifyNoMoreInteractions;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.when;
 
 import static org.junit.Assert.assertEquals;
@@ -401,7 +401,7 @@ public class MockStatic {
         try {
             SuperClass.returnB();
             clearInvocations(staticMockMarker(SuperClass.class));
-            verifyZeroInteractions(staticMockMarker(SuperClass.class));
+            verifyNoMoreInteractions(staticMockMarker(SuperClass.class));
         } finally {
             session.finishMocking();
         }
diff --git a/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/StaticMockitoSession.java b/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/StaticMockitoSession.java
index eff42ab..3b14d43 100644
--- a/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/StaticMockitoSession.java
+++ b/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/StaticMockitoSession.java
@@ -81,4 +81,19 @@ public class StaticMockitoSession {
             .startMocking()
             .finishMocking();
     }
+
+    @Test
+    public void invalidMockitoUsage_stillFinishesSessionCleanly() {
+        MockitoSession session = mockitoSession().mockStatic(A.class).startMocking();
+
+        // Intentionally invalid usage
+        doReturn(1);
+        session.finishMocking(new Throwable());
+
+        // Assert that A can be mocked again
+        mockitoSession().mockStatic(A.class).startMocking().finishMocking();
+    }
+
+    static class A {
+    }
 }
diff --git a/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/VerifyStatic.java b/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/VerifyStatic.java
index afb1439..ccd667b 100644
--- a/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/VerifyStatic.java
+++ b/dexmaker-mockito-inline-extended-tests/src/main/java/com/android/dx/mockito/inline/extended/tests/VerifyStatic.java
@@ -30,7 +30,6 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSess
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.staticMockMarker;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verifyNoMoreInteractions;
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.verifyZeroInteractions;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.when;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNull;
@@ -180,7 +179,7 @@ public class VerifyStatic {
         MockitoSession session = mockitoSession().mockStatic(EchoClass.class).startMocking();
         try {
             EchoClass.echo("marco!");
-            verifyZeroInteractions(staticMockMarker(EchoClass.class));
+            verifyNoMoreInteractions(staticMockMarker(EchoClass.class));
             fail();
         } finally {
             session.finishMocking();
diff --git a/dexmaker-mockito-inline-extended/src/main/java/com/android/dx/mockito/inline/extended/StaticMockitoSession.java b/dexmaker-mockito-inline-extended/src/main/java/com/android/dx/mockito/inline/extended/StaticMockitoSession.java
index 851d4a4..ed063f2 100644
--- a/dexmaker-mockito-inline-extended/src/main/java/com/android/dx/mockito/inline/extended/StaticMockitoSession.java
+++ b/dexmaker-mockito-inline-extended/src/main/java/com/android/dx/mockito/inline/extended/StaticMockitoSession.java
@@ -16,6 +16,7 @@
 
 package com.android.dx.mockito.inline.extended;
 
+import org.mockito.exceptions.base.MockitoException;
 import org.mockito.Mockito;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
@@ -68,6 +69,17 @@ public class StaticMockitoSession implements MockitoSession {
         try {
             instanceSession.finishMocking(failure);
         } finally {
+            if (failure != null) {
+                try {
+                    Mockito.validateMockitoUsage();
+                } catch (MockitoException e) {
+                    // The delegate finishMocking would normally validate,
+                    // except it doesn't if there's a failure passed in.
+                    // We trigger and clear it here to ensure Mockit.reset
+                    // works below.
+                    failure.addSuppressed(e);
+                }
+            }
             for (Class<?> clazz : staticMocks) {
                 mockingInProgressClass.set(clazz);
                 try {
diff --git a/dexmaker-mockito-inline/src/main/java/com/android/dx/mockito/inline/MockMethodAdvice.java b/dexmaker-mockito-inline/src/main/java/com/android/dx/mockito/inline/MockMethodAdvice.java
index 74e24b0..f440f84 100644
--- a/dexmaker-mockito-inline/src/main/java/com/android/dx/mockito/inline/MockMethodAdvice.java
+++ b/dexmaker-mockito-inline/src/main/java/com/android/dx/mockito/inline/MockMethodAdvice.java
@@ -11,6 +11,7 @@ import java.lang.reflect.Method;
 import java.lang.reflect.Modifier;
 import java.util.ArrayList;
 import java.util.Map;
+import java.util.Optional;
 import java.util.concurrent.Callable;
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
@@ -25,6 +26,9 @@ class MockMethodAdvice {
     /** Pattern to decompose a instrumentedMethodWithTypeAndSignature */
     private final Pattern methodPattern = Pattern.compile("(.*)#(.*)\\((.*)\\)");
 
+    /** Pattern to verifies types description is ending only with array type */
+    private static final Pattern ARRAY_PATTERN = Pattern.compile("(\\[\\])+");
+
     @SuppressWarnings("ThreadLocalUsage")
     private final SelfCallInfo selfCallInfo = new SelfCallInfo();
 
@@ -86,6 +90,59 @@ class MockMethodAdvice {
         }
     }
 
+    private static final Map<String, String> PRIMITIVE_CLASS_TO_SIGNATURE =
+            Map.of(
+                    "byte", "B",
+                    "short", "S",
+                    "int", "I",
+                    "long", "J",
+                    "char", "C",
+                    "float", "F",
+                    "double", "D",
+                    "boolean", "Z");
+
+    /**
+     * Convert a type signature of an array to the corresponding class
+     *
+     * <p>It parse "foo[][][][]" into a jni signature "[[[[Lfoo;" and rely on Class.forName to do
+     * the conversion. Primivite type are converted using {@code PRIMITIVE_CLASS_TO_SIGNATURE}.
+     *
+     * @param argTypeName the type description (e.g: byte[])
+     * @return the class wrapped in Optional on success, or empty if the conversion failed
+     */
+    private static Optional<Class<?>> parseTypeName(String argTypeName) {
+        int index = argTypeName.indexOf("[");
+        if (index == -1) {
+            // not an Array type
+            return Optional.empty();
+        }
+
+        String typeName = argTypeName.substring(0, index);
+        String rest = argTypeName.substring(index, argTypeName.length());
+
+        if (!ARRAY_PATTERN.matcher(rest).matches()) {
+            return Optional.empty();
+        }
+        int dimensionCount = (int) argTypeName.chars().filter(ch -> ch == '[').count();
+
+        String classSignature =
+                PRIMITIVE_CLASS_TO_SIGNATURE.getOrDefault(typeName, "L" + typeName + ";");
+
+        StringBuilder sb = new StringBuilder();
+        // "[".repeat(dimensionCount) would be a shorter alternative but this is not available on
+        // all android test target. See b/396768441
+        for (int i = 0; i < dimensionCount; i++) {
+            sb.append("[");
+        }
+        sb.append(classSignature);
+        String fullTypeSignature = sb.toString();
+        try {
+            return Optional.of(Class.forName(fullTypeSignature));
+        } catch (ClassNotFoundException e) {
+            return Optional.empty();
+        }
+    }
+
     /**
      * Get the method of {@code instance} specified by {@code methodWithTypeAndSignature}.
      *
@@ -135,34 +192,10 @@ class MockMethodAdvice {
                     case "boolean":
                         argTypes.add(Boolean.TYPE);
                         break;
-                    case "byte[]":
-                        argTypes.add(byte[].class);
-                        break;
-                    case "short[]":
-                        argTypes.add(short[].class);
-                        break;
-                    case "int[]":
-                        argTypes.add(int[].class);
-                        break;
-                    case "long[]":
-                        argTypes.add(long[].class);
-                        break;
-                    case "char[]":
-                        argTypes.add(char[].class);
-                        break;
-                    case "float[]":
-                        argTypes.add(float[].class);
-                        break;
-                    case "double[]":
-                        argTypes.add(double[].class);
-                        break;
-                    case "boolean[]":
-                        argTypes.add(boolean[].class);
-                        break;
                     default:
-                        if (argTypeName.endsWith("[]")) {
-                            argTypes.add(Class.forName("[L" + argTypeName.substring(0,
-                                    argTypeName.length() - 2) + ";"));
+                        Optional<Class<?>> arrayClass = parseTypeName(argTypeName);
+                        if (arrayClass.isPresent()) {
+                            argTypes.add(arrayClass.get());
                         } else {
                             argTypes.add(Class.forName(argTypeName));
                         }
```

