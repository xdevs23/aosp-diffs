```diff
diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml
index a278e12f..5d7242b1 100644
--- a/.gitlab-ci.yml
+++ b/.gitlab-ci.yml
@@ -12,10 +12,24 @@ cache:
     # Cache the downloaded dependencies and plugins between builds.
     - '$GRADLE_USER_HOME'
 
-build:
+build-job:
+  stage: build
   script:
     - $GRADLE build
+
+test-job:
+  stage: test
+  script:
     - $GRADLE test jacocoTestCoverageVerification
+
+deploy-job:
+  stage: deploy
+  script:
     - if [ $NEXUS_USER_NAME ]; then $GRADLE publish; fi
     - if [ !$NEXUS_USER_NAME ]; then $GRADLE publishToMavenLocal; fi
+
+sonar-job:
+  stage: deploy
+  allow_failure: true
+  script:
     - if [ $SONAR_LOGIN ]; then $GRADLE -Dorg.gradle.jvmargs='-XX:MetaspaceSize=1024M -XX:MaxMetaspaceSize=1024M' jacocoTestReport sonar -Dsonar.host.url=$SONAR -Dsonar.login=${SONAR_LOGIN}; fi
diff --git a/METADATA b/METADATA
index 16691c2e..7f5811af 100644
--- a/METADATA
+++ b/METADATA
@@ -11,7 +11,7 @@ third_party {
     type: GIT
     value: "https://gitlab.ow2.org/asm/asm.git"
   }
-  version: "9.6"
-  last_upgrade_date { year: 2024 month: 7 day: 15 }
+  version: "9.8"
+  last_upgrade_date { year: 2025 month: 6 day: 6 }
   license_type: NOTICE
 }
diff --git a/README.md b/README.md
new file mode 100644
index 00000000..890fc6a8
--- /dev/null
+++ b/README.md
@@ -0,0 +1,58 @@
+# ASM
+
+ASM is an all purpose Java bytecode manipulation and analysis framework. It can
+be used to modify existing classes or to dynamically generate classes, directly
+in binary form. ASM provides some common bytecode transformations and analysis
+algorithms from which custom complex transformations and code analysis tools can
+be built. ASM offers similar functionality as other Java bytecode frameworks,
+but is focused on [performance](https://asm.ow2.io/performance.html). Because it
+was designed and implemented to be as small and as fast as possible, it is well
+suited for use in dynamic systems (but can of course be used in a static way
+too, e.g. in compilers).
+
+## Building the Project
+
+To build the project, you need to have [Java 11+](https://openjdk.java.net)
+installed on your system. You can build the project by running the following
+command:
+
+```shell
+./gradle/gradlew clean build
+```
+
+After the build is complete, you can find the compiled JAR files in the
+corresponding `build/libs` directory of each submodule.
+
+To run only the project tests, you can use the following command:
+
+```shell
+./gradle/gradlew test
+```
+
+## How to Contribute
+
+To contribute to the ASM project fork this repository
+on [GitLab](https://gitlab.ow2.org/asm/asm), make changes,
+then send us
+a [merge request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html).
+We will review your changes and apply them to the `master` branch.
+To avoid frustration, before sending us your merge request, please run a full
+Gradle build to ensure that your changes do not violate our quality standards:
+
+```shell
+./gradle/gradlew clean build
+```
+
+All submodules are checked
+with [googleJavaFormat](https://github.com/google/google-java-format),
+[Checkstyle](https://checkstyle.sourceforge.io)
+and [PMD](https://pmd.github.io).
+
+## Reporting Issues
+
+If you encounter any issues with the ASM project, please create a new issue
+on the [GitLab issue tracker](https://gitlab.ow2.org/asm/asm/-/issues).
+
+## License
+
+ASM is licensed under the [BSD 3-Clause License](LICENSE.txt).
\ No newline at end of file
diff --git a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Analyzer.java b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Analyzer.java
index ab875b88..668a81ef 100644
--- a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Analyzer.java
+++ b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Analyzer.java
@@ -123,7 +123,7 @@ public class Analyzer<V extends Value> implements Opcodes {
       TryCatchBlockNode tryCatchBlock = method.tryCatchBlocks.get(i);
       int startIndex = insnList.indexOf(tryCatchBlock.start);
       int endIndex = insnList.indexOf(tryCatchBlock.end);
-      for (int j = startIndex; j <= endIndex; ++j) {
+      for (int j = startIndex; j < endIndex; ++j) {
         List<TryCatchBlockNode> insnHandlers = handlers[j];
         if (insnHandlers == null) {
           insnHandlers = new ArrayList<>();
@@ -165,6 +165,8 @@ public class Analyzer<V extends Value> implements Opcodes {
         if (insnType == AbstractInsnNode.LABEL
             || insnType == AbstractInsnNode.LINE
             || insnType == AbstractInsnNode.FRAME) {
+          // Update the current frame, so it can be used during processing for this instruction
+          currentFrame.init(oldFrame);
           merge(insnIndex + 1, oldFrame, subroutine);
           newControlFlowEdge(insnIndex, insnIndex + 1);
         } else {
@@ -174,7 +176,7 @@ public class Analyzer<V extends Value> implements Opcodes {
           if (insnNode instanceof JumpInsnNode) {
             JumpInsnNode jumpInsn = (JumpInsnNode) insnNode;
             if (insnOpcode != GOTO && insnOpcode != JSR) {
-              currentFrame.initJumpTarget(insnOpcode, /* target = */ null);
+              currentFrame.initJumpTarget(insnOpcode, /* target= */ null);
               merge(insnIndex + 1, currentFrame, subroutine);
               newControlFlowEdge(insnIndex, insnIndex + 1);
             }
@@ -263,9 +265,18 @@ public class Analyzer<V extends Value> implements Opcodes {
               catchType = Type.getObjectType(tryCatchBlock.type);
             }
             if (newControlFlowExceptionEdge(insnIndex, tryCatchBlock)) {
+              // Merge the frame *before* this instruction, with its stack cleared and an exception
+              // pushed, with the handler's frame.
               Frame<V> handler = newFrame(oldFrame);
               handler.clearStack();
-              handler.push(interpreter.newExceptionValue(tryCatchBlock, handler, catchType));
+              V exceptionValue = interpreter.newExceptionValue(tryCatchBlock, handler, catchType);
+              handler.push(exceptionValue);
+              merge(insnList.indexOf(tryCatchBlock.handler), handler, subroutine);
+              // Merge the frame *after* this instruction, with its stack cleared and an exception
+              // pushed, with the handler's frame.
+              handler = newFrame(currentFrame);
+              handler.clearStack();
+              handler.push(exceptionValue);
               merge(insnList.indexOf(tryCatchBlock.handler), handler, subroutine);
             }
           }
diff --git a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Frame.java b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Frame.java
index ac3600c7..97c71cac 100644
--- a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Frame.java
+++ b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Frame.java
@@ -371,7 +371,7 @@ public class Frame<V extends Value> {
         if (value1.getSize() != 1) {
           throw new AnalyzerException(insn, "Illegal use of DUP");
         }
-        push(value1);
+        push(interpreter.copyOperation(insn, value1));
         push(interpreter.copyOperation(insn, value1));
         break;
       case Opcodes.DUP_X1:
@@ -381,8 +381,8 @@ public class Frame<V extends Value> {
           throw new AnalyzerException(insn, "Illegal use of DUP_X1");
         }
         push(interpreter.copyOperation(insn, value1));
-        push(value2);
-        push(value1);
+        push(interpreter.copyOperation(insn, value2));
+        push(interpreter.copyOperation(insn, value1));
         break;
       case Opcodes.DUP_X2:
         value1 = pop();
@@ -395,14 +395,14 @@ public class Frame<V extends Value> {
         if (value1.getSize() == 1) {
           value2 = pop();
           if (value2.getSize() == 1) {
-            push(value2);
-            push(value1);
+            push(interpreter.copyOperation(insn, value2));
+            push(interpreter.copyOperation(insn, value1));
             push(interpreter.copyOperation(insn, value2));
             push(interpreter.copyOperation(insn, value1));
             break;
           }
         } else {
-          push(value1);
+          push(interpreter.copyOperation(insn, value1));
           push(interpreter.copyOperation(insn, value1));
           break;
         }
@@ -416,9 +416,9 @@ public class Frame<V extends Value> {
             if (value3.getSize() == 1) {
               push(interpreter.copyOperation(insn, value2));
               push(interpreter.copyOperation(insn, value1));
-              push(value3);
-              push(value2);
-              push(value1);
+              push(interpreter.copyOperation(insn, value3));
+              push(interpreter.copyOperation(insn, value2));
+              push(interpreter.copyOperation(insn, value1));
               break;
             }
           }
@@ -426,8 +426,8 @@ public class Frame<V extends Value> {
           value2 = pop();
           if (value2.getSize() == 1) {
             push(interpreter.copyOperation(insn, value1));
-            push(value2);
-            push(value1);
+            push(interpreter.copyOperation(insn, value2));
+            push(interpreter.copyOperation(insn, value1));
             break;
           }
         }
@@ -443,18 +443,18 @@ public class Frame<V extends Value> {
               if (value4.getSize() == 1) {
                 push(interpreter.copyOperation(insn, value2));
                 push(interpreter.copyOperation(insn, value1));
-                push(value4);
-                push(value3);
-                push(value2);
-                push(value1);
+                push(interpreter.copyOperation(insn, value4));
+                push(interpreter.copyOperation(insn, value3));
+                push(interpreter.copyOperation(insn, value2));
+                push(interpreter.copyOperation(insn, value1));
                 break;
               }
             } else {
               push(interpreter.copyOperation(insn, value2));
               push(interpreter.copyOperation(insn, value1));
-              push(value3);
-              push(value2);
-              push(value1);
+              push(interpreter.copyOperation(insn, value3));
+              push(interpreter.copyOperation(insn, value2));
+              push(interpreter.copyOperation(insn, value1));
               break;
             }
           }
@@ -654,15 +654,15 @@ public class Frame<V extends Value> {
       V value3 = pop();
       if (value3.getSize() == 1) {
         push(interpreter.copyOperation(insn, value1));
-        push(value3);
-        push(value2);
-        push(value1);
+        push(interpreter.copyOperation(insn, value3));
+        push(interpreter.copyOperation(insn, value2));
+        push(interpreter.copyOperation(insn, value1));
         return true;
       }
     } else {
       push(interpreter.copyOperation(insn, value1));
-      push(value2);
-      push(value1);
+      push(interpreter.copyOperation(insn, value2));
+      push(interpreter.copyOperation(insn, value1));
       return true;
     }
     return false;
diff --git a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/SimpleVerifier.java b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/SimpleVerifier.java
index a623bd09..3e7a0c70 100644
--- a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/SimpleVerifier.java
+++ b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/SimpleVerifier.java
@@ -41,6 +41,9 @@ import org.objectweb.asm.Type;
  */
 public class SimpleVerifier extends BasicVerifier {
 
+  /** The type of the Object class. */
+  private static final Type OBJECT_TYPE = Type.getObjectType("java/lang/Object");
+
   /** The type of the class that is verified. */
   private final Type currentClass;
 
@@ -196,30 +199,70 @@ public class SimpleVerifier extends BasicVerifier {
 
   @Override
   protected boolean isSubTypeOf(final BasicValue value, final BasicValue expected) {
-    Type expectedType = expected.getType();
     Type type = value.getType();
+    Type expectedType = expected.getType();
+    // Null types correspond to BasicValue.UNINITIALIZED_VALUE.
+    if (type == null || expectedType == null) {
+      return type == null && expectedType == null;
+    }
+    if (type.equals(expectedType)) {
+      return true;
+    }
     switch (expectedType.getSort()) {
       case Type.INT:
       case Type.FLOAT:
       case Type.LONG:
       case Type.DOUBLE:
-        return type.equals(expectedType);
+        return false;
       case Type.ARRAY:
       case Type.OBJECT:
         if (type.equals(NULL_TYPE)) {
           return true;
-        } else if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) {
-          if (isAssignableFrom(expectedType, type)) {
-            return true;
-          } else if (getClass(expectedType).isInterface()) {
-            // The merge of class or interface types can only yield class types (because it is not
-            // possible in general to find an unambiguous common super interface, due to multiple
-            // inheritance). Because of this limitation, we need to relax the subtyping check here
-            // if 'value' is an interface.
-            return Object.class.isAssignableFrom(getClass(type));
-          } else {
+        }
+        // Convert 'type' to its element type and array dimension. Arrays of primitive values are
+        // seen as Object arrays with one dimension less. Hence the element type is always of
+        // Type.OBJECT sort.
+        int dim = 0;
+        if (type.getSort() == Type.ARRAY) {
+          dim = type.getDimensions();
+          type = type.getElementType();
+          if (type.getSort() != Type.OBJECT) {
+            dim = dim - 1;
+            type = OBJECT_TYPE;
+          }
+        }
+        // Do the same for expectedType.
+        int expectedDim = 0;
+        if (expectedType.getSort() == Type.ARRAY) {
+          expectedDim = expectedType.getDimensions();
+          expectedType = expectedType.getElementType();
+          if (expectedType.getSort() != Type.OBJECT) {
+            // If the expected type is an array of some primitive type, it does not have any subtype
+            // other than itself. And 'type' is different by hypothesis.
             return false;
           }
+        }
+        // A type with less dimensions than expected can't be a subtype of the expected type.
+        if (dim < expectedDim) {
+          return false;
+        }
+        // A type with more dimensions than expected is seen as an array with the expected
+        // dimensions but with an Object element type. For instance an array of arrays of Integer is
+        // seen as an array of Object if the expected type is an array of Serializable.
+        if (dim > expectedDim) {
+          type = OBJECT_TYPE;
+        }
+        // type and expectedType have a Type.OBJECT sort by construction (see above),
+        // as expected by isAssignableFrom.
+        if (isAssignableFrom(expectedType, type)) {
+          return true;
+        }
+        if (getClass(expectedType).isInterface()) {
+          // The merge of class or interface types can only yield class types (because it is not
+          // possible in general to find an unambiguous common super interface, due to multiple
+          // inheritance). Because of this limitation, we need to relax the subtyping check here
+          // if 'value' is an interface.
+          return Object.class.isAssignableFrom(getClass(type));
         } else {
           return false;
         }
@@ -230,48 +273,71 @@ public class SimpleVerifier extends BasicVerifier {
 
   @Override
   public BasicValue merge(final BasicValue value1, final BasicValue value2) {
-    if (!value1.equals(value2)) {
-      Type type1 = value1.getType();
-      Type type2 = value2.getType();
-      if (type1 != null
-          && (type1.getSort() == Type.OBJECT || type1.getSort() == Type.ARRAY)
-          && type2 != null
-          && (type2.getSort() == Type.OBJECT || type2.getSort() == Type.ARRAY)) {
-        if (type1.equals(NULL_TYPE)) {
-          return value2;
-        }
-        if (type2.equals(NULL_TYPE)) {
-          return value1;
-        }
+    Type type1 = value1.getType();
+    Type type2 = value2.getType();
+    // Null types correspond to BasicValue.UNINITIALIZED_VALUE.
+    if (type1 == null || type2 == null) {
+      return BasicValue.UNINITIALIZED_VALUE;
+    }
+    if (type1.equals(type2)) {
+      return value1;
+    }
+    // The merge of a primitive type with a different type is the type of uninitialized values.
+    if (type1.getSort() != Type.OBJECT && type1.getSort() != Type.ARRAY) {
+      return BasicValue.UNINITIALIZED_VALUE;
+    }
+    if (type2.getSort() != Type.OBJECT && type2.getSort() != Type.ARRAY) {
+      return BasicValue.UNINITIALIZED_VALUE;
+    }
+    // Special case for the type of the "null" literal.
+    if (type1.equals(NULL_TYPE)) {
+      return value2;
+    }
+    if (type2.equals(NULL_TYPE)) {
+      return value1;
+    }
+    // Convert type1 to its element type and array dimension. Arrays of primitive values are seen as
+    // Object arrays with one dimension less. Hence the element type is always of Type.OBJECT sort.
+    int dim1 = 0;
+    if (type1.getSort() == Type.ARRAY) {
+      dim1 = type1.getDimensions();
+      type1 = type1.getElementType();
+      if (type1.getSort() != Type.OBJECT) {
+        dim1 = dim1 - 1;
+        type1 = OBJECT_TYPE;
+      }
+    }
+    // Do the same for type2.
+    int dim2 = 0;
+    if (type2.getSort() == Type.ARRAY) {
+      dim2 = type2.getDimensions();
+      type2 = type2.getElementType();
+      if (type2.getSort() != Type.OBJECT) {
+        dim2 = dim2 - 1;
+        type2 = OBJECT_TYPE;
+      }
+    }
+    // The merge of array types of different dimensions is an Object array type.
+    if (dim1 != dim2) {
+      return newArrayValue(OBJECT_TYPE, Math.min(dim1, dim2));
+    }
+    // Type1 and type2 have a Type.OBJECT sort by construction (see above),
+    // as expected by isAssignableFrom.
+    if (isAssignableFrom(type1, type2)) {
+      return newArrayValue(type1, dim1);
+    }
+    if (isAssignableFrom(type2, type1)) {
+      return newArrayValue(type2, dim1);
+    }
+    if (!isInterface(type1)) {
+      while (!type1.equals(OBJECT_TYPE)) {
+        type1 = getSuperClass(type1);
         if (isAssignableFrom(type1, type2)) {
-          return value1;
-        }
-        if (isAssignableFrom(type2, type1)) {
-          return value2;
-        }
-        int numDimensions = 0;
-        if (type1.getSort() == Type.ARRAY
-            && type2.getSort() == Type.ARRAY
-            && type1.getDimensions() == type2.getDimensions()
-            && type1.getElementType().getSort() == Type.OBJECT
-            && type2.getElementType().getSort() == Type.OBJECT) {
-          numDimensions = type1.getDimensions();
-          type1 = type1.getElementType();
-          type2 = type2.getElementType();
-        }
-        while (true) {
-          if (type1 == null || isInterface(type1)) {
-            return newArrayValue(Type.getObjectType("java/lang/Object"), numDimensions);
-          }
-          type1 = getSuperClass(type1);
-          if (isAssignableFrom(type1, type2)) {
-            return newArrayValue(type1, numDimensions);
-          }
+          return newArrayValue(type1, dim1);
         }
       }
-      return BasicValue.UNINITIALIZED_VALUE;
     }
-    return value1;
+    return newArrayValue(OBJECT_TYPE, dim1);
   }
 
   private BasicValue newArrayValue(final Type type, final int dimensions) {
@@ -292,7 +358,7 @@ public class SimpleVerifier extends BasicVerifier {
    * implementation of this method loads the class and uses the reflection API to return its result
    * (unless the given type corresponds to the class being verified).
    *
-   * @param type a type.
+   * @param type an object reference type (i.e., with Type.OBJECT sort).
    * @return whether 'type' corresponds to an interface.
    */
   protected boolean isInterface(final Type type) {
@@ -307,8 +373,9 @@ public class SimpleVerifier extends BasicVerifier {
    * of this method loads the class and uses the reflection API to return its result (unless the
    * given type corresponds to the class being verified).
    *
-   * @param type a type.
-   * @return the type corresponding to the super class of 'type'.
+   * @param type an object reference type (i.e., with Type.OBJECT sort).
+   * @return the type corresponding to the super class of 'type', or {@literal null} if 'type' is
+   *     the type of the Object class.
    */
   protected Type getSuperClass(final Type type) {
     if (currentClass != null && currentClass.equals(type)) {
@@ -325,8 +392,8 @@ public class SimpleVerifier extends BasicVerifier {
    * result (unless the result can be computed from the class being verified, and the types of its
    * super classes and implemented interfaces).
    *
-   * @param type1 a type.
-   * @param type2 another type.
+   * @param type1 an object reference type (i.e., with Type.OBJECT sort).
+   * @param type2 another object reference type (i.e., with Type.OBJECT sort).
    * @return whether the class corresponding to 'type1' is either the same as, or is a superclass or
    *     superinterface of the class corresponding to 'type2'.
    */
@@ -335,14 +402,16 @@ public class SimpleVerifier extends BasicVerifier {
       return true;
     }
     if (currentClass != null && currentClass.equals(type1)) {
-      if (getSuperClass(type2) == null) {
+      Type superType2 = getSuperClass(type2);
+      if (superType2 == null) {
         return false;
-      } else {
-        if (isInterface) {
-          return type2.getSort() == Type.OBJECT || type2.getSort() == Type.ARRAY;
-        }
-        return isAssignableFrom(type1, getSuperClass(type2));
       }
+      if (isInterface) {
+        // This should always be true, given the preconditions of this method, but is kept for
+        // backward compatibility.
+        return type2.getSort() == Type.OBJECT || type2.getSort() == Type.ARRAY;
+      }
+      return isAssignableFrom(type1, superType2);
     }
     if (currentClass != null && currentClass.equals(type2)) {
       if (isAssignableFrom(type1, currentSuperClass)) {
@@ -365,12 +434,14 @@ public class SimpleVerifier extends BasicVerifier {
    * specified with {@link #setClassLoader}, or with the class loader of this class if no class
    * loader was specified.
    *
-   * @param type a type.
+   * @param type an object reference type (i.e., with Type.OBJECT sort).
    * @return the class corresponding to 'type'.
    */
   protected Class<?> getClass(final Type type) {
     try {
       if (type.getSort() == Type.ARRAY) {
+        // This should never happen, given the preconditions of this method, but is kept for
+        // backward compatibility.
         return Class.forName(type.getDescriptor().replace('/', '.'), false, loader);
       }
       return Class.forName(type.getClassName(), false, loader);
diff --git a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/SourceInterpreter.java b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/SourceInterpreter.java
index 961ef9f2..a2d36a88 100644
--- a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/SourceInterpreter.java
+++ b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/SourceInterpreter.java
@@ -30,6 +30,7 @@ package org.objectweb.asm.tree.analysis;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
+import org.objectweb.asm.ConstantDynamic;
 import org.objectweb.asm.Opcodes;
 import org.objectweb.asm.Type;
 import org.objectweb.asm.tree.AbstractInsnNode;
@@ -86,8 +87,22 @@ public class SourceInterpreter extends Interpreter<SourceValue> implements Opcod
         size = 2;
         break;
       case LDC:
+        // Values able to be pushed by LDC:
+        //   - int, float, string (object), type (Class, object), type (MethodType, object),
+        //       handle (MethodHandle, object): one word
+        //   - long, double, ConstantDynamic (can produce either single word values, or double word
+        //       values): (up to) two words
         Object value = ((LdcInsnNode) insn).cst;
-        size = value instanceof Long || value instanceof Double ? 2 : 1;
+        if (value instanceof Long || value instanceof Double) {
+          // two words guaranteed
+          size = 2;
+        } else if (value instanceof ConstantDynamic) {
+          // might yield two words
+          size = ((ConstantDynamic) value).getSize();
+        } else {
+          // one word guaranteed
+          size = 1;
+        }
         break;
       case GETSTATIC:
         size = Type.getType(((FieldInsnNode) insn).desc).getSize();
diff --git a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicInterpreterTest.java b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicInterpreterTest.java
index fc199934..3719d7fa 100644
--- a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicInterpreterTest.java
+++ b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicInterpreterTest.java
@@ -102,13 +102,13 @@ class AnalyzerWithBasicInterpreterTest extends AsmTest {
           }
         };
 
-    ArrayList<Frame<? extends BasicValue>[]> methodFrames = new ArrayList<>();
+    ArrayList<Frame<BasicValue>[]> methodFrames = new ArrayList<>();
     for (MethodNode methodNode : classNode.methods) {
       methodFrames.add(analyzer.analyze(classNode.name, methodNode));
     }
 
-    for (Frame<? extends BasicValue>[] frames : methodFrames) {
-      for (Frame<? extends BasicValue> frame : frames) {
+    for (Frame<BasicValue>[] frames : methodFrames) {
+      for (Frame<BasicValue> frame : frames) {
         assertTrue(frame == null || frame instanceof CustomFrame);
       }
     }
@@ -156,7 +156,7 @@ class AnalyzerWithBasicInterpreterTest extends AsmTest {
   @Test
   void testAnalyzeAndComputeMaxs_staticMethod() throws AnalyzerException {
     MethodNode methodNode =
-        new MethodNodeBuilder("(I)V", /* maxStack = */ 0, /* maxLocals = */ 0).vreturn().build();
+        new MethodNodeBuilder("(I)V", /* maxStack= */ 0, /* maxLocals= */ 0).vreturn().build();
     methodNode.access |= Opcodes.ACC_STATIC;
     Analyzer<BasicValue> analyzer = new Analyzer<BasicValue>(new BasicInterpreter());
 
diff --git a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicVerifierTest.java b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicVerifierTest.java
index 905b09b4..dc13c845 100644
--- a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicVerifierTest.java
+++ b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicVerifierTest.java
@@ -247,6 +247,52 @@ class AnalyzerWithBasicVerifierTest extends AsmTest {
     assertEquals("Error at instruction 2: Expected I, but found F", message);
   }
 
+  @Test
+  void testAnalyze_validMethodWithExceptionHandlers() {
+    Label label0 = new Label();
+    Label label1 = new Label();
+    Label label2 = new Label();
+    Label label3 = new Label();
+    Label label4 = new Label();
+    Label label5 = new Label();
+    Label label6 = new Label();
+    MethodNode methodNode =
+        new MethodNodeBuilder("(Ljava/lang/Object;)V", 3, 3)
+            .trycatch(label0, label1, label2, "java/lang/Exception")
+            .trycatch(label1, label3, label4, null)
+            .trycatch(label5, label6, label4, null)
+            .trycatch(label6, label2, label2, "java/lang/Exception")
+            .aload(0)
+            .ifnonnull(label0)
+            .aconst_null()
+            .athrow()
+            .label(label0)
+            .aload(0)
+            .astore(2)
+            .label(label1)
+            .nop()
+            .aload(2)
+            .pop()
+            .label(label3)
+            .vreturn()
+            .label(label4)
+            .astore(1)
+            .label(label5)
+            .aload(2)
+            .pop()
+            .label(label6)
+            .aload(1)
+            .athrow()
+            .label(label2)
+            .astore(1)
+            .go(label3)
+            .build();
+
+    Executable analyze = () -> newAnalyzer().analyze(CLASS_NAME, methodNode);
+
+    assertDoesNotThrow(analyze);
+  }
+
   /**
    * Tests that the precompiled classes can be successfully analyzed with a BasicVerifier.
    *
diff --git a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithSimpleVerifierTest.java b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithSimpleVerifierTest.java
index 99505a9f..97789abe 100644
--- a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithSimpleVerifierTest.java
+++ b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithSimpleVerifierTest.java
@@ -54,6 +54,88 @@ class AnalyzerWithSimpleVerifierTest extends AsmTest {
 
   private static final String CLASS_NAME = "C";
 
+  @Test
+  void testAnalyze_differentDimensions() {
+    Label otherwise = new Label();
+    Label finish = new Label();
+    MethodNode methodNode =
+        new MethodNodeBuilder("()[Ljava/io/Serializable;", 3, 1)
+            .insn(Opcodes.ICONST_0)
+            .ifne(otherwise)
+            .iconst_0()
+            .iconst_0()
+            .multiANewArrayInsn("[[I", 2)
+            .go(finish)
+            .label(otherwise)
+            .iconst_0()
+            .iconst_0()
+            .iconst_0()
+            .multiANewArrayInsn("[[[Ljava/lang/System;", 3)
+            .label(finish)
+            .areturn()
+            .build();
+
+    Executable analyze = () -> newAnalyzer().analyze(CLASS_NAME, methodNode);
+
+    assertDoesNotThrow(analyze);
+    assertDoesNotThrow(() -> MethodNodeBuilder.buildClassWithMethod(methodNode).newInstance());
+  }
+
+  @Test
+  void testAnalyze_arrayOfCurrentClass() {
+    Label label0 = new Label();
+    Label label1 = new Label();
+    Label label2 = new Label();
+    Label label3 = new Label();
+    MethodNode methodNode =
+        new MethodNodeBuilder()
+            .iconst_0()
+            .typeInsn(Opcodes.ANEWARRAY, CLASS_NAME)
+            .astore(1)
+            .iconst_0()
+            .istore(2)
+            .label(label0)
+            .iload(2)
+            .ifne(label1)
+            .aload(1)
+            .iload(2)
+            .insn(Opcodes.AALOAD)
+            .pop()
+            .go(label0)
+            .label(label1)
+            .label(label2)
+            .iload(2)
+            .ifne(label3)
+            .aload(1)
+            .iload(2)
+            .insn(Opcodes.AALOAD)
+            .pop()
+            .go(label2)
+            .label(label3)
+            .vreturn()
+            .build();
+
+    Executable analyze = () -> newAnalyzer().analyze(CLASS_NAME, methodNode);
+
+    assertDoesNotThrow(analyze);
+    assertDoesNotThrow(() -> MethodNodeBuilder.buildClassWithMethod(methodNode).newInstance());
+  }
+
+  @Test
+  void testAnalyze_primitiveArrayReturnType() {
+    MethodNode methodNode =
+        new MethodNodeBuilder("()[I", 1, 1)
+            .iconst_0()
+            .typeInsn(Opcodes.ANEWARRAY, CLASS_NAME)
+            .areturn()
+            .build();
+
+    Executable analyze = () -> newAnalyzer().analyze(CLASS_NAME, methodNode);
+
+    String message = assertThrows(AnalyzerException.class, analyze).getMessage();
+    assertTrue(message.contains("Incompatible return type: expected [I, but found [LC;"));
+  }
+
   @Test
   void testAnalyze_invalidInvokevirtual() {
     MethodNode methodNode =
@@ -140,6 +222,73 @@ class AnalyzerWithSimpleVerifierTest extends AsmTest {
     assertDoesNotThrow(() -> MethodNodeBuilder.buildClassWithMethod(methodNode).newInstance());
   }
 
+  @Test
+  void testAnalyze_mergeStackFramesWithExceptionHandlers() throws AnalyzerException {
+    Label startTry0Label = new Label();
+    Label endTry0Label = new Label();
+    Label catch0Label = new Label();
+    Label startTry1Label = new Label();
+    Label endTry1Label = new Label();
+    Label catch1Label = new Label();
+    Label startTry2Label = new Label();
+    Label endTry2Label = new Label();
+    Label catch2Label = new Label();
+    Label label0 = new Label();
+    Label labelReturn = new Label();
+    MethodNode methodNode =
+        new MethodNodeBuilder(2, 6)
+            .trycatch(startTry0Label, endTry0Label, catch0Label, "java/lang/Throwable")
+            .trycatch(startTry1Label, endTry1Label, catch1Label, "java/lang/Throwable")
+            .trycatch(startTry2Label, endTry2Label, catch2Label)
+            .iconst_0()
+            .istore(2)
+            .typeInsn(Opcodes.NEW, "java/lang/String")
+            .astore(3)
+            .typeInsn(Opcodes.NEW, "java/nio/file/Path")
+            .astore(1)
+            .label(startTry2Label)
+            .typeInsn(Opcodes.NEW, "java/io/PrintWriter")
+            .astore(2)
+            .label(startTry0Label)
+            .label(endTry0Label)
+            .aload(2)
+            .methodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintWriter", "close", "()V", false)
+            .go(endTry2Label)
+            .label(catch0Label)
+            .astore(3)
+            .label(startTry1Label)
+            .aload(2)
+            .methodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintWriter", "close", "()V", false)
+            .label(endTry1Label)
+            .go(label0)
+            .label(catch1Label)
+            .astore(4)
+            .aload(3)
+            .aload(4)
+            .methodInsn(
+                Opcodes.INVOKEVIRTUAL,
+                "java/lang/Throwable",
+                "addSuppressed",
+                "(Ljava/lang/Throwable;)V",
+                false)
+            .label(label0)
+            .aload(3)
+            .athrow()
+            .label(endTry2Label)
+            .go(labelReturn)
+            .label(catch2Label)
+            .astore(5)
+            .aload(5)
+            .athrow()
+            .label(labelReturn)
+            .vreturn()
+            .build();
+
+    Executable analyze = () -> newAnalyzer().analyze(CLASS_NAME, methodNode);
+
+    assertDoesNotThrow(analyze);
+  }
+
   /**
    * Tests that the precompiled classes can be successfully analyzed with a SimpleVerifier.
    *
diff --git a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithSourceInterpreterTest.java b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithSourceInterpreterTest.java
index 5d4a205e..c4d7f670 100644
--- a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithSourceInterpreterTest.java
+++ b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithSourceInterpreterTest.java
@@ -28,13 +28,18 @@
 package org.objectweb.asm.tree.analysis;
 
 import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
+import static org.junit.jupiter.api.Assertions.assertEquals;
 import static org.junit.jupiter.api.Assertions.assertThrows;
 
+import java.util.Arrays;
 import org.junit.jupiter.api.Test;
 import org.junit.jupiter.params.ParameterizedTest;
 import org.junit.jupiter.params.provider.MethodSource;
 import org.objectweb.asm.ClassReader;
+import org.objectweb.asm.Label;
+import org.objectweb.asm.Opcodes;
 import org.objectweb.asm.test.AsmTest;
+import org.objectweb.asm.tree.AbstractInsnNode;
 import org.objectweb.asm.tree.ClassNode;
 import org.objectweb.asm.tree.MethodNode;
 
@@ -68,4 +73,56 @@ class AnalyzerWithSourceInterpreterTest extends AsmTest {
       assertDoesNotThrow(() -> analyzer.analyze(classNode.name, methodNode));
     }
   }
+
+  /** Checks if DUP_X2 producers are correct. */
+  @Test
+  void testAnalyze_dupx2Producers() throws AnalyzerException {
+    Label label0 = new Label();
+    Label label1 = new Label();
+    MethodNode methodNode =
+        new MethodNodeBuilder(4, 1)
+            .push()
+            .push()
+            .iconst_0()
+            .ifne(label0)
+            // First case
+            .insn(Opcodes.ICONST_M1)
+            .go(label1)
+            // Second case
+            .label(label0)
+            .iconst_0()
+            // DUP_X2 value
+            .label(label1)
+            .insn(Opcodes.DUP_X2)
+            .pop() // Point where the frame is checked
+            .pop()
+            .pop()
+            .pop()
+            .vreturn()
+            .build();
+
+    Analyzer<SourceValue> analyzer = new Analyzer<>(new SourceInterpreter());
+    analyzer.analyze("C", methodNode);
+
+    AbstractInsnNode firstPop =
+        Arrays.stream(methodNode.instructions.toArray())
+            .filter(insn -> insn.getOpcode() == Opcodes.POP)
+            .findFirst()
+            .get();
+    AbstractInsnNode dupx2 =
+        Arrays.stream(methodNode.instructions.toArray())
+            .filter(insn -> insn.getOpcode() == Opcodes.DUP_X2)
+            .findFirst()
+            .get();
+    Frame<SourceValue> frame = analyzer.getFrames()[methodNode.instructions.indexOf(firstPop)];
+    // Check if all source values have the DUP_X2 as a producer
+    SourceValue sourceValue1 = frame.getStack(frame.getStackSize() - 4);
+    SourceValue sourceValue2 = frame.getStack(frame.getStackSize() - 3);
+    SourceValue sourceValue3 = frame.getStack(frame.getStackSize() - 2);
+    SourceValue sourceValue4 = frame.getStack(frame.getStackSize() - 1);
+    assertEquals(sourceValue1.insns.iterator().next(), dupx2);
+    assertEquals(sourceValue2.insns.iterator().next(), dupx2);
+    assertEquals(sourceValue3.insns.iterator().next(), dupx2);
+    assertEquals(sourceValue4.insns.iterator().next(), dupx2);
+  }
 }
diff --git a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/SimpleVerifierTest.java b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/SimpleVerifierTest.java
index 4faa857e..034ade19 100644
--- a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/SimpleVerifierTest.java
+++ b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/SimpleVerifierTest.java
@@ -33,7 +33,7 @@ import static org.junit.jupiter.api.Assertions.assertFalse;
 import static org.junit.jupiter.api.Assertions.assertThrows;
 import static org.junit.jupiter.api.Assertions.assertTrue;
 
-import java.util.Arrays;
+import java.util.List;
 import org.junit.jupiter.api.Test;
 import org.junit.jupiter.params.ParameterizedTest;
 import org.junit.jupiter.params.provider.CsvSource;
@@ -85,7 +85,7 @@ class SimpleVerifierTest {
             /* latest */ Opcodes.ASM10_EXPERIMENTAL,
             baseType,
             superType,
-            Arrays.asList(interfaceType),
+            List.of(interfaceType),
             false) {
 
           @Override
diff --git a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/SmallSetTest.java b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/SmallSetTest.java
index 12691fbf..818b0040 100644
--- a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/SmallSetTest.java
+++ b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/SmallSetTest.java
@@ -32,8 +32,6 @@ import static org.junit.jupiter.api.Assertions.assertFalse;
 import static org.junit.jupiter.api.Assertions.assertThrows;
 import static org.junit.jupiter.api.Assertions.assertTrue;
 
-import java.util.Arrays;
-import java.util.HashSet;
 import java.util.Iterator;
 import java.util.NoSuchElementException;
 import java.util.Set;
@@ -73,7 +71,7 @@ class SmallSetTest {
     Set<Object> union2 = set2.union(set1);
 
     assertEquals(union1, union2);
-    assertEquals(union1, new HashSet<Object>(Arrays.asList(ELEMENT1)));
+    assertEquals(union1, Set.of(ELEMENT1));
   }
 
   @Test
@@ -85,7 +83,7 @@ class SmallSetTest {
     Set<Object> union2 = set2.union(set1);
 
     assertEquals(union1, union2);
-    assertEquals(union1, new HashSet<Object>(Arrays.asList(ELEMENT1, ELEMENT2)));
+    assertEquals(union1, Set.of(ELEMENT1, ELEMENT2));
   }
 
   @Test
@@ -97,7 +95,7 @@ class SmallSetTest {
     Set<Object> union2 = set2.union(set1);
 
     assertEquals(union1, union2);
-    assertEquals(union1, new HashSet<Object>(Arrays.asList(ELEMENT1, ELEMENT2)));
+    assertEquals(union1, Set.of(ELEMENT1, ELEMENT2));
   }
 
   @Test
@@ -109,7 +107,7 @@ class SmallSetTest {
     Set<Object> union2 = set2.union(set1);
 
     assertEquals(union1, union2);
-    assertEquals(union1, new HashSet<Object>(Arrays.asList(ELEMENT1, ELEMENT2, ELEMENT3)));
+    assertEquals(union1, Set.of(ELEMENT1, ELEMENT2, ELEMENT3));
   }
 
   @Test
@@ -121,8 +119,7 @@ class SmallSetTest {
     Set<Object> union2 = set2.union(set1);
 
     assertEquals(union1, union2);
-    assertEquals(
-        union1, new HashSet<Object>(Arrays.asList(ELEMENT1, ELEMENT2, ELEMENT3, ELEMENT4)));
+    assertEquals(union1, Set.of(ELEMENT1, ELEMENT2, ELEMENT3, ELEMENT4));
   }
 
   @Test
@@ -166,6 +163,6 @@ class SmallSetTest {
   }
 
   private static SmallSet<Object> newSmallSet(final Object element1, final Object element2) {
-    return (SmallSet<Object>) new SmallSet<Object>(element1).union(new SmallSet<Object>(element2));
+    return (SmallSet<Object>) new SmallSet<>(element1).union(new SmallSet<>(element2));
   }
 }
diff --git a/asm-commons/src/main/java/org/objectweb/asm/commons/AnnotationRemapper.java b/asm-commons/src/main/java/org/objectweb/asm/commons/AnnotationRemapper.java
index 3eeaf0f6..fa41dc69 100644
--- a/asm-commons/src/main/java/org/objectweb/asm/commons/AnnotationRemapper.java
+++ b/asm-commons/src/main/java/org/objectweb/asm/commons/AnnotationRemapper.java
@@ -57,7 +57,7 @@ public class AnnotationRemapper extends AnnotationVisitor {
    */
   @Deprecated
   public AnnotationRemapper(final AnnotationVisitor annotationVisitor, final Remapper remapper) {
-    this(/* descriptor = */ null, annotationVisitor, remapper);
+    this(/* descriptor= */ null, annotationVisitor, remapper);
   }
 
   /**
@@ -86,7 +86,7 @@ public class AnnotationRemapper extends AnnotationVisitor {
   @Deprecated
   protected AnnotationRemapper(
       final int api, final AnnotationVisitor annotationVisitor, final Remapper remapper) {
-    this(api, /* descriptor = */ null, annotationVisitor, remapper);
+    this(api, /* descriptor= */ null, annotationVisitor, remapper);
   }
 
   /**
@@ -139,7 +139,7 @@ public class AnnotationRemapper extends AnnotationVisitor {
     } else {
       return annotationVisitor == av
           ? this
-          : createAnnotationRemapper(/* descriptor = */ null, annotationVisitor);
+          : createAnnotationRemapper(/* descriptor= */ null, annotationVisitor);
     }
   }
 
@@ -153,7 +153,7 @@ public class AnnotationRemapper extends AnnotationVisitor {
    */
   @Deprecated
   protected AnnotationVisitor createAnnotationRemapper(final AnnotationVisitor annotationVisitor) {
-    return new AnnotationRemapper(api, /* descriptor = */ null, annotationVisitor, remapper);
+    return new AnnotationRemapper(api, /* descriptor= */ null, annotationVisitor, remapper);
   }
 
   /**
diff --git a/asm-commons/src/main/java/org/objectweb/asm/commons/ClassRemapper.java b/asm-commons/src/main/java/org/objectweb/asm/commons/ClassRemapper.java
index 4ce62395..baea2c81 100644
--- a/asm-commons/src/main/java/org/objectweb/asm/commons/ClassRemapper.java
+++ b/asm-commons/src/main/java/org/objectweb/asm/commons/ClassRemapper.java
@@ -258,7 +258,7 @@ public class ClassRemapper extends ClassVisitor {
    */
   @Deprecated
   protected AnnotationVisitor createAnnotationRemapper(final AnnotationVisitor annotationVisitor) {
-    return new AnnotationRemapper(api, /* descriptor = */ null, annotationVisitor, remapper);
+    return new AnnotationRemapper(api, /* descriptor= */ null, annotationVisitor, remapper);
   }
 
   /**
diff --git a/asm-commons/src/main/java/org/objectweb/asm/commons/FieldRemapper.java b/asm-commons/src/main/java/org/objectweb/asm/commons/FieldRemapper.java
index dc180224..e65650c7 100644
--- a/asm-commons/src/main/java/org/objectweb/asm/commons/FieldRemapper.java
+++ b/asm-commons/src/main/java/org/objectweb/asm/commons/FieldRemapper.java
@@ -96,7 +96,7 @@ public class FieldRemapper extends FieldVisitor {
    */
   @Deprecated
   protected AnnotationVisitor createAnnotationRemapper(final AnnotationVisitor annotationVisitor) {
-    return new AnnotationRemapper(api, /* descriptor = */ null, annotationVisitor, remapper);
+    return new AnnotationRemapper(api, /* descriptor= */ null, annotationVisitor, remapper);
   }
 
   /**
diff --git a/asm-commons/src/main/java/org/objectweb/asm/commons/GeneratorAdapter.java b/asm-commons/src/main/java/org/objectweb/asm/commons/GeneratorAdapter.java
index 97f832b1..1b90115c 100644
--- a/asm-commons/src/main/java/org/objectweb/asm/commons/GeneratorAdapter.java
+++ b/asm-commons/src/main/java/org/objectweb/asm/commons/GeneratorAdapter.java
@@ -396,6 +396,9 @@ public class GeneratorAdapter extends LocalVariablesSorter {
       mv.visitInsn(Opcodes.ACONST_NULL);
     } else {
       switch (value.getSort()) {
+        case Type.VOID:
+          mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Void", "TYPE", CLASS_DESCRIPTOR);
+          break;
         case Type.BOOLEAN:
           mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Boolean", "TYPE", CLASS_DESCRIPTOR);
           break;
diff --git a/asm-commons/src/main/java/org/objectweb/asm/commons/MethodRemapper.java b/asm-commons/src/main/java/org/objectweb/asm/commons/MethodRemapper.java
index 7bc9f7a9..c889d47d 100644
--- a/asm-commons/src/main/java/org/objectweb/asm/commons/MethodRemapper.java
+++ b/asm-commons/src/main/java/org/objectweb/asm/commons/MethodRemapper.java
@@ -75,7 +75,7 @@ public class MethodRemapper extends MethodVisitor {
     AnnotationVisitor annotationVisitor = super.visitAnnotationDefault();
     return annotationVisitor == null
         ? annotationVisitor
-        : createAnnotationRemapper(/* descriptor = */ null, annotationVisitor);
+        : createAnnotationRemapper(/* descriptor= */ null, annotationVisitor);
   }
 
   @Override
@@ -271,7 +271,7 @@ public class MethodRemapper extends MethodVisitor {
    */
   @Deprecated
   protected AnnotationVisitor createAnnotationRemapper(final AnnotationVisitor annotationVisitor) {
-    return new AnnotationRemapper(api, /* descriptor = */ null, annotationVisitor, remapper);
+    return new AnnotationRemapper(api, /* descriptor= */ null, annotationVisitor, remapper);
   }
 
   /**
diff --git a/asm-commons/src/main/java/org/objectweb/asm/commons/RecordComponentRemapper.java b/asm-commons/src/main/java/org/objectweb/asm/commons/RecordComponentRemapper.java
index 2f1e5ae2..0fa5055e 100644
--- a/asm-commons/src/main/java/org/objectweb/asm/commons/RecordComponentRemapper.java
+++ b/asm-commons/src/main/java/org/objectweb/asm/commons/RecordComponentRemapper.java
@@ -99,7 +99,7 @@ public class RecordComponentRemapper extends RecordComponentVisitor {
    */
   @Deprecated
   protected AnnotationVisitor createAnnotationRemapper(final AnnotationVisitor annotationVisitor) {
-    return new AnnotationRemapper(api, /* descriptor = */ null, annotationVisitor, remapper);
+    return new AnnotationRemapper(api, /* descriptor= */ null, annotationVisitor, remapper);
   }
 
   /**
diff --git a/asm-commons/src/main/java/org/objectweb/asm/commons/SimpleRemapper.java b/asm-commons/src/main/java/org/objectweb/asm/commons/SimpleRemapper.java
index 6803d948..44f3442d 100644
--- a/asm-commons/src/main/java/org/objectweb/asm/commons/SimpleRemapper.java
+++ b/asm-commons/src/main/java/org/objectweb/asm/commons/SimpleRemapper.java
@@ -50,9 +50,11 @@ public class SimpleRemapper extends Remapper {
    *           name.
    *       <li>for invokedynamic method names, the key is the name and descriptor of the method (in
    *           the form .&lt;name&gt;&lt;descriptor&gt;), and the value is the new method name.
-   *       <li>for field and attribute names, the key is the owner and name of the field or
-   *           attribute (in the form &lt;owner&gt;.&lt;name&gt;), and the value is the new field
-   *           name.
+   *       <li>for field names, the key is the owner and name of the field or attribute (in the form
+   *           &lt;owner&gt;.&lt;name&gt;), and the value is the new field name.
+   *       <li>for attribute names, the key is the annotation descriptor and the name of the
+   *           attribute (in the form &lt;descriptor&gt;.&lt;name&gt;), and the value is the new
+   *           attribute name.
    *       <li>for internal names, the key is the old internal name, and the value is the new
    *           internal name (see {@link org.objectweb.asm.Type#getInternalName()}).
    *     </ul>
diff --git a/asm-commons/src/test/java/org/objectweb/asm/commons/AdviceAdapterTest.java b/asm-commons/src/test/java/org/objectweb/asm/commons/AdviceAdapterTest.java
index 0b676c08..dcf7625d 100644
--- a/asm-commons/src/test/java/org/objectweb/asm/commons/AdviceAdapterTest.java
+++ b/asm-commons/src/test/java/org/objectweb/asm/commons/AdviceAdapterTest.java
@@ -577,7 +577,7 @@ class AdviceAdapterTest extends AsmTest {
             .label(label1)
             .iconst_0()
             .iconst_0()
-            .switchto(label3, label3, /*useTableSwitch=*/ parameter.equals("tableswitch"))
+            .switchto(label3, label3, /* useTableSwitch= */ parameter.equals("tableswitch"))
             .label(label2)
             // After instrumentation, expect an after advice here, before instruction #7.
             .athrow()
diff --git a/asm-commons/src/test/java/org/objectweb/asm/commons/ClassRemapperTest.java b/asm-commons/src/test/java/org/objectweb/asm/commons/ClassRemapperTest.java
index 697125f3..97686d77 100644
--- a/asm-commons/src/test/java/org/objectweb/asm/commons/ClassRemapperTest.java
+++ b/asm-commons/src/test/java/org/objectweb/asm/commons/ClassRemapperTest.java
@@ -34,11 +34,13 @@ import static org.junit.jupiter.api.Assertions.assertTrue;
 
 import java.util.Arrays;
 import java.util.Locale;
+import java.util.Map;
 import org.junit.jupiter.api.Test;
 import org.junit.jupiter.api.function.Executable;
 import org.junit.jupiter.params.ParameterizedTest;
 import org.junit.jupiter.params.provider.MethodSource;
 import org.objectweb.asm.AnnotationVisitor;
+import org.objectweb.asm.Attribute;
 import org.objectweb.asm.ClassReader;
 import org.objectweb.asm.ClassVisitor;
 import org.objectweb.asm.ClassWriter;
@@ -189,6 +191,7 @@ class ClassRemapperTest extends AsmTest {
             });
     classRemapper.visit(Opcodes.V1_5, Opcodes.ACC_PUBLIC, "C", null, "java/lang/Object", null);
 
+    // The ClassRemapper change the modules and the hashes so the lists have to be mutable.
     classRemapper.visitAttribute(
         new ModuleHashesAttribute("algorithm", Arrays.asList("pkg.C"), Arrays.asList(new byte[0])));
 
@@ -269,6 +272,56 @@ class ClassRemapperTest extends AsmTest {
     assertEquals("demo", invokeDynamic.bsm.getName());
   }
 
+  /** Tests that classes transformed with an empty ClassRemapper are unchanged. */
+  @ParameterizedTest
+  @MethodSource(ALL_CLASSES_AND_ALL_APIS)
+  void testEmptyClassRemapper_precompiledClass(
+      final PrecompiledClass classParameter, final Api apiParameter) {
+    byte[] classFile = classParameter.getBytes();
+    ClassReader classReader = new ClassReader(classFile);
+    ClassWriter classWriter = new ClassWriter(0);
+    ClassRemapper classRemapper =
+        newClassRemapper(apiParameter.value(), classWriter, new SimpleRemapper(Map.of()));
+
+    Executable accept =
+        () -> classReader.accept(classRemapper, new Attribute[] {new CodeComment()}, 0);
+
+    if (classParameter.isMoreRecentThan(apiParameter)) {
+      Exception exception = assertThrows(UnsupportedOperationException.class, accept);
+      assertTrue(exception.getMessage().matches(UNSUPPORTED_OPERATION_MESSAGE_PATTERN));
+    } else {
+      assertDoesNotThrow(accept);
+      assertEquals(new ClassFile(classFile), new ClassFile(classWriter.toByteArray()));
+    }
+  }
+
+  /** Tests that inner class names are unchanged with by an empty ClassRemapper. */
+  @Test
+  void testEmptyClassRemapper_innerClassNames() {
+    ClassWriter classFileWriter = new ClassWriter(0);
+    classFileWriter.visit(
+        Opcodes.V1_8,
+        Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE,
+        "Outer",
+        null,
+        "java/lang/Object",
+        null);
+    classFileWriter.visitInnerClass(
+        "Outer$$Inner",
+        "Outer",
+        "$Inner",
+        Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE);
+    classFileWriter.visitEnd();
+    byte[] classFile = classFileWriter.toByteArray();
+    ClassReader classReader = new ClassReader(classFile);
+    ClassWriter classWriter = new ClassWriter(0);
+    ClassRemapper classRemapper = new ClassRemapper(classWriter, new SimpleRemapper(Map.of()));
+
+    classReader.accept(classRemapper, new Attribute[] {new CodeComment()}, 0);
+
+    assertEquals(new ClassFile(classFile), new ClassFile(classWriter.toByteArray()));
+  }
+
   /** Tests that classes transformed with a ClassRemapper can be loaded and instantiated. */
   @ParameterizedTest
   @MethodSource(ALL_CLASSES_AND_ALL_APIS)
diff --git a/asm-commons/src/test/java/org/objectweb/asm/commons/GeneratorAdapterTest.java b/asm-commons/src/test/java/org/objectweb/asm/commons/GeneratorAdapterTest.java
index c5ca9134..6b551dc0 100644
--- a/asm-commons/src/test/java/org/objectweb/asm/commons/GeneratorAdapterTest.java
+++ b/asm-commons/src/test/java/org/objectweb/asm/commons/GeneratorAdapterTest.java
@@ -37,10 +37,11 @@ import static org.objectweb.asm.commons.GeneratorAdapter.LE;
 import static org.objectweb.asm.commons.GeneratorAdapter.LT;
 import static org.objectweb.asm.commons.GeneratorAdapter.NE;
 
-import java.util.Arrays;
+import java.util.List;
 import java.util.stream.Collectors;
 import org.junit.jupiter.api.Test;
 import org.junit.jupiter.api.function.Executable;
+import org.objectweb.asm.ConstantDynamic;
 import org.objectweb.asm.Handle;
 import org.objectweb.asm.Label;
 import org.objectweb.asm.Opcodes;
@@ -109,7 +110,7 @@ class GeneratorAdapterTest {
     assertEquals(Opcodes.ACC_PUBLIC, methodNode.access);
     assertEquals("name", methodNode.name);
     assertEquals("()V", methodNode.desc);
-    assertEquals(Arrays.asList("java/lang/Exception"), methodNode.exceptions);
+    assertEquals(List.of("java/lang/Exception"), methodNode.exceptions);
   }
 
   @Test
@@ -127,7 +128,7 @@ class GeneratorAdapterTest {
     assertEquals(Opcodes.ACC_PUBLIC, methodNode.access);
     assertEquals("name", methodNode.name);
     assertEquals("()V", methodNode.desc);
-    assertEquals(Arrays.asList(), methodNode.exceptions);
+    assertEquals(List.of(), methodNode.exceptions);
   }
 
   @Test
@@ -159,7 +160,7 @@ class GeneratorAdapterTest {
   void testPush_long() {
     assertEquals("LCONST_0", new Generator().push(0L));
     assertEquals("LCONST_1", new Generator().push(1L));
-    assertEquals("LDC 2", new Generator().push(2L));
+    assertEquals("LDC 2L", new Generator().push(2L));
   }
 
   @Test
@@ -167,14 +168,14 @@ class GeneratorAdapterTest {
     assertEquals("FCONST_0", new Generator().push(0.0f));
     assertEquals("FCONST_1", new Generator().push(1.0f));
     assertEquals("FCONST_2", new Generator().push(2.0f));
-    assertEquals("LDC 3.0", new Generator().push(3.0f));
+    assertEquals("LDC 3.0F", new Generator().push(3.0f));
   }
 
   @Test
   void testPush_double() {
     assertEquals("DCONST_0", new Generator().push(0.0));
     assertEquals("DCONST_1", new Generator().push(1.0));
-    assertEquals("LDC 2.0", new Generator().push(2.0));
+    assertEquals("LDC 2.0D", new Generator().push(2.0));
   }
 
   @Test
@@ -186,6 +187,8 @@ class GeneratorAdapterTest {
   @Test
   void testPush_type() {
     assertEquals("ACONST_NULL", new Generator().push((Type) null));
+    assertEquals(
+        "GETSTATIC java/lang/Void.TYPE : Ljava/lang/Class;", new Generator().push(Type.VOID_TYPE));
     assertEquals(
         "GETSTATIC java/lang/Boolean.TYPE : Ljava/lang/Class;",
         new Generator().push(Type.BOOLEAN_TYPE));
@@ -216,7 +219,7 @@ class GeneratorAdapterTest {
   void testPush_handle() {
     assertEquals("ACONST_NULL", new Generator().push((Handle) null));
     assertEquals(
-        "LDC pkg/Owner.nameI (2)",
+        "// handle kind 0x2 : GETSTATIC\n" + "    LDC pkg/Owner.name(I)",
         new Generator().push(new Handle(Opcodes.H_GETSTATIC, "pkg/Owner", "name", "I", false)));
   }
 
@@ -762,6 +765,28 @@ class GeneratorAdapterTest {
                 3));
   }
 
+  @Test
+  void testConstantDynamic() {
+    assertEquals(
+        "LDC name : Ljava/lang/Object; [\n"
+            + "      // handle kind 0x2 : GETSTATIC\n"
+            + "      pkg/Owner.name(I)\n"
+            + "      // arguments:\n"
+            + "      1, \n"
+            + "      2, \n"
+            + "      3\n"
+            + "    ]",
+        new Generator()
+            .push(
+                new ConstantDynamic(
+                    "name",
+                    "Ljava/lang/Object;",
+                    new Handle(Opcodes.H_GETSTATIC, "pkg/Owner", "name", "I", false),
+                    1,
+                    2,
+                    3)));
+  }
+
   @Test
   void testNewInstance() {
     assertEquals("NEW pkg/Class", new Generator().newInstance(Type.getObjectType("pkg/Class")));
@@ -902,6 +927,11 @@ class GeneratorAdapterTest {
       return toString();
     }
 
+    public String push(final ConstantDynamic constantDynamic) {
+      generatorAdapter.push(constantDynamic);
+      return toString();
+    }
+
     public String loadThis() {
       generatorAdapter.loadThis();
       return toString();
diff --git a/asm-commons/src/test/java/org/objectweb/asm/commons/InstructionAdapterTest.java b/asm-commons/src/test/java/org/objectweb/asm/commons/InstructionAdapterTest.java
index 65476eef..8141359d 100644
--- a/asm-commons/src/test/java/org/objectweb/asm/commons/InstructionAdapterTest.java
+++ b/asm-commons/src/test/java/org/objectweb/asm/commons/InstructionAdapterTest.java
@@ -174,8 +174,9 @@ class InstructionAdapterTest extends AsmTest {
         new Handle(Opcodes.H_GETFIELD, "pkg/Class", "name", "I", /* isInterface= */ false));
 
     assertEquals(
-        "ICONST_0 ICONST_1 ICONST_2 BIPUSH 51 ICONST_4 ICONST_5 LDC 6 LDC 7.0 LDC 8.0 LDC \"9\" "
-            + "LDC Lpkg/Class;.class LDC pkg/Class.nameI (1)",
+        "ICONST_0 ICONST_1 ICONST_2 BIPUSH 51 ICONST_4 ICONST_5 LDC 6L LDC 7.0F LDC 8.0D LDC \"9\" "
+            + "LDC Lpkg/Class;.class // handle kind 0x1 : GETFIELD\n"
+            + "    LDC pkg/Class.name(I)",
         textifier.text.stream()
             .map(text -> text.toString().trim())
             .collect(Collectors.joining(" ")));
diff --git a/asm-commons/src/test/java/org/objectweb/asm/commons/ModuleHashesAttributeTest.java b/asm-commons/src/test/java/org/objectweb/asm/commons/ModuleHashesAttributeTest.java
index 40a45c06..5e5f0e65 100644
--- a/asm-commons/src/test/java/org/objectweb/asm/commons/ModuleHashesAttributeTest.java
+++ b/asm-commons/src/test/java/org/objectweb/asm/commons/ModuleHashesAttributeTest.java
@@ -30,7 +30,7 @@ package org.objectweb.asm.commons;
 import static org.junit.jupiter.api.Assertions.assertArrayEquals;
 import static org.junit.jupiter.api.Assertions.assertEquals;
 
-import java.util.Arrays;
+import java.util.List;
 import org.junit.jupiter.api.Test;
 import org.objectweb.asm.Attribute;
 import org.objectweb.asm.ClassReader;
@@ -53,9 +53,7 @@ class ModuleHashesAttributeTest {
     ClassWriter classWriter = new ClassWriter(0);
     classWriter.visitAttribute(
         new ModuleHashesAttribute(
-            "algorithm",
-            Arrays.asList(new String[] {"module1", "module2"}),
-            Arrays.asList(new byte[][] {HASH1, HASH2})));
+            "algorithm", List.of("module1", "module2"), List.of(HASH1, HASH2)));
 
     ModuleHashesAttribute moduleHashesAttribute = new ModuleHashesAttribute();
     new ClassReader(classWriter.toByteArray())
diff --git a/asm-commons/src/test/java/org/objectweb/asm/commons/SimpleRemapperTest.java b/asm-commons/src/test/java/org/objectweb/asm/commons/SimpleRemapperTest.java
index edba97c8..50497e13 100644
--- a/asm-commons/src/test/java/org/objectweb/asm/commons/SimpleRemapperTest.java
+++ b/asm-commons/src/test/java/org/objectweb/asm/commons/SimpleRemapperTest.java
@@ -29,8 +29,6 @@ package org.objectweb.asm.commons;
 
 import static org.junit.jupiter.api.Assertions.assertEquals;
 
-import java.util.Collections;
-import java.util.HashMap;
 import java.util.Map;
 import org.junit.jupiter.api.Test;
 
@@ -44,7 +42,7 @@ class SimpleRemapperTest {
   @Test
   void testMapSignature_remapParentOnly_nestedClassExtends() {
     String inputSignature = "LOuter<Ljava/lang/Object;>.Inner;";
-    Remapper remapper = new SimpleRemapper(Collections.singletonMap("Outer", "RenamedOuter"));
+    Remapper remapper = new SimpleRemapper(Map.of("Outer", "RenamedOuter"));
 
     String remappedSignature = remapper.mapSignature(inputSignature, false);
 
@@ -54,8 +52,7 @@ class SimpleRemapperTest {
   @Test
   void testMapSignature_remapChildOnly_nestedClassExtends() {
     String inputSignature = "LOuter<Ljava/lang/Object;>.Inner;";
-    Remapper remapper =
-        new SimpleRemapper(Collections.singletonMap("Outer$Inner", "Outer$RenamedInner"));
+    Remapper remapper = new SimpleRemapper(Map.of("Outer$Inner", "Outer$RenamedInner"));
 
     String remappedSignature = remapper.mapSignature(inputSignature, false);
 
@@ -65,8 +62,7 @@ class SimpleRemapperTest {
   @Test
   void testMapSignature_remapChildOnly_nestedClassExtends_identifiersWithDollarSign() {
     String inputSignature = "LOuter<Ljava/lang/Object;>.Inner$1;";
-    Remapper remapper =
-        new SimpleRemapper(Collections.singletonMap("Outer$Inner$1", "Outer$RenamedInner$1"));
+    Remapper remapper = new SimpleRemapper(Map.of("Outer$Inner$1", "Outer$RenamedInner$1"));
 
     String remappedSignature = remapper.mapSignature(inputSignature, false);
 
@@ -76,9 +72,8 @@ class SimpleRemapperTest {
   @Test
   void testMapSignature_remapBothParentAndChild_nestedClassExtends() {
     String inputSignature = "LOuter<Ljava/lang/Object;>.Inner;";
-    Map<String, String> mapping = new HashMap<>();
-    mapping.put("Outer", "RenamedOuter");
-    mapping.put("Outer$Inner", "RenamedOuter$RenamedInner");
+    Map<String, String> mapping =
+        Map.of("Outer", "RenamedOuter", "Outer$Inner", "RenamedOuter$RenamedInner");
     Remapper remapper = new SimpleRemapper(mapping);
 
     String remappedSignature = remapper.mapSignature(inputSignature, false);
diff --git a/asm-test/src/main/java/org/objectweb/asm/test/ClassFile.java b/asm-test/src/main/java/org/objectweb/asm/test/ClassFile.java
index c4fc9aba..fc9eb11f 100644
--- a/asm-test/src/main/java/org/objectweb/asm/test/ClassFile.java
+++ b/asm-test/src/main/java/org/objectweb/asm/test/ClassFile.java
@@ -255,8 +255,8 @@ public class ClassFile {
    */
   private void computeNameAndDumps() {
     try {
-      Builder builder = new Builder("ClassFile", /* parent = */ null);
-      Builder constantPoolBuilder = new Builder("ConstantPool", /* parent = */ null);
+      Builder builder = new Builder("ClassFile", /* parent= */ null);
+      Builder constantPoolBuilder = new Builder("ConstantPool", /* parent= */ null);
       ConstantClassInfo classInfo =
           dumpClassFile(new Parser(classBytes), builder, constantPoolBuilder);
       className = classInfo.dump().replace('/', '.');
@@ -288,7 +288,7 @@ public class ClassFile {
     builder.add("magic: ", parser.u4());
     builder.add("minor_version: ", parser.u2());
     int majorVersion = parser.u2();
-    if (majorVersion > /* V15 = */ 59) {
+    if (majorVersion > /* V15= */ 59) {
       throw new ClassFormatException("Unsupported class version");
     }
     builder.add("major_version: ", majorVersion);
@@ -1753,6 +1753,7 @@ public class ClassFile {
   private abstract static class CpInfo {
     /** The dump of this item. */
     private String dump;
+
     /** The context to use to get the referenced constant pool items. */
     private final ClassContext classContext;
 
@@ -2284,6 +2285,7 @@ public class ClassFile {
   private static class InstructionIndex {
     /** An offset in bytes from the start of the bytecode of a method. */
     private final int bytecodeOffset;
+
     /** The context to use to find the index from the bytecode offset. */
     private final MethodContext methodContext;
 
@@ -2378,10 +2380,13 @@ public class ClassFile {
   private abstract static class AbstractBuilder<T> implements ClassContext, MethodContext {
     /** Flag used to distinguish CpInfo keys in {@link #context}. */
     private static final int CP_INFO_KEY = 0xF0000000;
+
     /** The parent node of this node. May be {@literal null}. */
     private final AbstractBuilder<?> parent;
+
     /** The children of this builder. */
     final ArrayList<T> children;
+
     /** The map used to implement the Context interfaces. */
     private final HashMap<Integer, Object> context;
 
diff --git a/asm-test/src/main/resources/jdk11/AllInstructions.class b/asm-test/src/main/resources/jdk11/AllInstructions.class
index 69aa4447..2f34bc32 100644
Binary files a/asm-test/src/main/resources/jdk11/AllInstructions.class and b/asm-test/src/main/resources/jdk11/AllInstructions.class differ
diff --git a/asm-test/src/resources/java/jdk11/AllInstructions.jasm b/asm-test/src/resources/java/jdk11/AllInstructions.jasm
index 007142f9..62708879 100644
--- a/asm-test/src/resources/java/jdk11/AllInstructions.jasm
+++ b/asm-test/src/resources/java/jdk11/AllInstructions.jasm
@@ -85,6 +85,31 @@ private static Method bsm:"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/St
   lreturn;
 }
 
+// Needed to make two since asmtools' jasm doesnt optimize bsm entries the same way we do.
+// -> asmtools would generate two bsm methods, ClassWriter would generate one with the input from asmtools.
+// -> test fails while technically being correct
+private static Method anotherBsm:"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;)J"
+  stack 2 locals 3
+{
+  bipush 42;
+  i2l;
+  lreturn;
+}
+
+public static Method gnarlyCondyPop:"()V"
+  stack 2 locals 0
+{
+    ldc2_w  Dynamic REF_invokeStatic
+        :jdk11/AllInstructions.anotherBsm
+        :"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;)J"
+        :test
+        :"J";
+    // Test that a condy ldc (interpreted as an ldc of a ConstantDynamic object) yields
+    //  a value with the proper size, as indicated by its descriptor (long in this case, 2 words)
+    pop2;
+    return;
+}
+
 public static Method main:"([Ljava/lang/String;)V"
   stack 1 locals 2
 {
diff --git a/asm-test/src/test/java/org/objectweb/asm/test/AsmTestTest.java b/asm-test/src/test/java/org/objectweb/asm/test/AsmTestTest.java
index d8645487..89f59e19 100644
--- a/asm-test/src/test/java/org/objectweb/asm/test/AsmTestTest.java
+++ b/asm-test/src/test/java/org/objectweb/asm/test/AsmTestTest.java
@@ -32,9 +32,8 @@ import static org.junit.jupiter.api.Assertions.assertFalse;
 import static org.junit.jupiter.api.Assertions.assertNotNull;
 import static org.junit.jupiter.api.Assertions.assertTrue;
 
-import java.util.Arrays;
-import java.util.HashSet;
 import java.util.List;
+import java.util.Set;
 import java.util.stream.Collectors;
 import org.junit.jupiter.api.Test;
 import org.junit.jupiter.params.provider.Arguments;
@@ -89,10 +88,10 @@ class AsmTestTest extends AsmTest {
     List<Arguments> allArguments = allClassesAndAllApis().collect(Collectors.toList());
 
     assertEquals(
-        new HashSet<Object>(Arrays.asList(PrecompiledClass.values())),
+        Set.of(PrecompiledClass.values()),
         allArguments.stream().map(arg -> arg.get()[0]).collect(Collectors.toSet()));
     assertEquals(
-        new HashSet<Object>(Arrays.asList(Api.values())),
+        Set.of(Api.values()),
         allArguments.stream().map(arg -> arg.get()[1]).collect(Collectors.toSet()));
   }
 
@@ -101,10 +100,10 @@ class AsmTestTest extends AsmTest {
     List<Arguments> allArguments = allClassesAndLatestApi().collect(Collectors.toList());
 
     assertEquals(
-        new HashSet<Object>(Arrays.asList(PrecompiledClass.values())),
+        Set.of(PrecompiledClass.values()),
         allArguments.stream().map(arg -> arg.get()[0]).collect(Collectors.toSet()));
     assertEquals(
-        new HashSet<Object>(Arrays.asList(Api.ASM9)),
+        Set.of(Api.ASM9),
         allArguments.stream().map(arg -> arg.get()[1]).collect(Collectors.toSet()));
   }
 }
diff --git a/asm-tree/src/main/java/org/objectweb/asm/tree/ClassNode.java b/asm-tree/src/main/java/org/objectweb/asm/tree/ClassNode.java
index bd43dc71..3cbd221d 100644
--- a/asm-tree/src/main/java/org/objectweb/asm/tree/ClassNode.java
+++ b/asm-tree/src/main/java/org/objectweb/asm/tree/ClassNode.java
@@ -90,8 +90,8 @@ public class ClassNode extends ClassVisitor {
 
   /**
    * The internal name of the enclosing class of this class (see {@link
-   * org.objectweb.asm.Type#getInternalName()}). Must be {@literal null} if this class has no
-   * enclosing class, or if it is a local or anonymous class.
+   * org.objectweb.asm.Type#getInternalName()}). Must be {@literal null} if this class is not a
+   * local or anonymous class.
    */
   public String outerClass;
 
diff --git a/asm-tree/src/test/java/org/objectweb/asm/tree/AnnotationNodeTest.java b/asm-tree/src/test/java/org/objectweb/asm/tree/AnnotationNodeTest.java
index e926dbcc..20b0bae0 100644
--- a/asm-tree/src/test/java/org/objectweb/asm/tree/AnnotationNodeTest.java
+++ b/asm-tree/src/test/java/org/objectweb/asm/tree/AnnotationNodeTest.java
@@ -31,7 +31,7 @@ import static org.junit.jupiter.api.Assertions.assertEquals;
 import static org.junit.jupiter.api.Assertions.assertNull;
 import static org.junit.jupiter.api.Assertions.assertThrows;
 
-import java.util.Arrays;
+import java.util.List;
 import org.junit.jupiter.api.Test;
 import org.junit.jupiter.api.function.Executable;
 import org.objectweb.asm.AnnotationVisitor;
@@ -75,21 +75,21 @@ class AnnotationNodeTest extends AsmTest {
     annotationNode.visitAnnotation("annotation", "Lpkg/Annotation;");
 
     assertEquals("bytes", annotationNode.values.get(0));
-    assertEquals(Arrays.asList(new Byte[] {0, 1}), annotationNode.values.get(1));
+    assertEquals(List.of((byte) 0, (byte) 1), annotationNode.values.get(1));
     assertEquals("booleans", annotationNode.values.get(2));
-    assertEquals(Arrays.asList(new Boolean[] {false, true}), annotationNode.values.get(3));
+    assertEquals(List.of(false, true), annotationNode.values.get(3));
     assertEquals("shorts", annotationNode.values.get(4));
-    assertEquals(Arrays.asList(new Short[] {0, 1}), annotationNode.values.get(5));
+    assertEquals(List.of((short) 0, (short) 1), annotationNode.values.get(5));
     assertEquals("chars", annotationNode.values.get(6));
-    assertEquals(Arrays.asList(new Character[] {'0', '1'}), annotationNode.values.get(7));
+    assertEquals(List.of('0', '1'), annotationNode.values.get(7));
     assertEquals("ints", annotationNode.values.get(8));
-    assertEquals(Arrays.asList(new Integer[] {0, 1}), annotationNode.values.get(9));
+    assertEquals(List.of(0, 1), annotationNode.values.get(9));
     assertEquals("longs", annotationNode.values.get(10));
-    assertEquals(Arrays.asList(new Long[] {0L, 1L}), annotationNode.values.get(11));
+    assertEquals(List.of(0L, 1L), annotationNode.values.get(11));
     assertEquals("floats", annotationNode.values.get(12));
-    assertEquals(Arrays.asList(new Float[] {0.0f, 1.0f}), annotationNode.values.get(13));
+    assertEquals(List.of(0.0f, 1.0f), annotationNode.values.get(13));
     assertEquals("doubles", annotationNode.values.get(14));
-    assertEquals(Arrays.asList(new Double[] {0.0, 1.0}), annotationNode.values.get(15));
+    assertEquals(List.of(0.0, 1.0), annotationNode.values.get(15));
     assertEquals("string", annotationNode.values.get(16));
     assertEquals("value", annotationNode.values.get(17));
     assertEquals("annotation", annotationNode.values.get(18));
diff --git a/asm-tree/src/test/java/org/objectweb/asm/tree/FrameNodeTest.java b/asm-tree/src/test/java/org/objectweb/asm/tree/FrameNodeTest.java
index b00024cf..1a158776 100644
--- a/asm-tree/src/test/java/org/objectweb/asm/tree/FrameNodeTest.java
+++ b/asm-tree/src/test/java/org/objectweb/asm/tree/FrameNodeTest.java
@@ -30,7 +30,7 @@ package org.objectweb.asm.tree;
 import static org.junit.jupiter.api.Assertions.assertEquals;
 import static org.junit.jupiter.api.Assertions.assertThrows;
 
-import java.util.Arrays;
+import java.util.List;
 import org.junit.jupiter.api.Test;
 import org.junit.jupiter.api.function.Executable;
 import org.objectweb.asm.Opcodes;
@@ -52,8 +52,8 @@ class FrameNodeTest extends AsmTest {
 
     assertEquals(AbstractInsnNode.FRAME, frameNode.getType());
     assertEquals(Opcodes.F_FULL, frameNode.type);
-    assertEquals(Arrays.asList(locals), frameNode.local);
-    assertEquals(Arrays.asList(stack), frameNode.stack);
+    assertEquals(List.of(locals), frameNode.local);
+    assertEquals(List.of(stack), frameNode.stack);
   }
 
   @Test
diff --git a/asm-tree/src/test/java/org/objectweb/asm/tree/LookupSwitchInsnNodeTest.java b/asm-tree/src/test/java/org/objectweb/asm/tree/LookupSwitchInsnNodeTest.java
index 4313ea56..9e933031 100644
--- a/asm-tree/src/test/java/org/objectweb/asm/tree/LookupSwitchInsnNodeTest.java
+++ b/asm-tree/src/test/java/org/objectweb/asm/tree/LookupSwitchInsnNodeTest.java
@@ -29,7 +29,7 @@ package org.objectweb.asm.tree;
 
 import static org.junit.jupiter.api.Assertions.assertEquals;
 
-import java.util.Arrays;
+import java.util.List;
 import org.junit.jupiter.api.Test;
 import org.objectweb.asm.test.AsmTest;
 
@@ -50,7 +50,7 @@ class LookupSwitchInsnNodeTest extends AsmTest {
 
     assertEquals(AbstractInsnNode.LOOKUPSWITCH_INSN, lookupSwitchInsnNode.getType());
     assertEquals(dflt, lookupSwitchInsnNode.dflt);
-    assertEquals(Arrays.asList(new Integer[] {1}), lookupSwitchInsnNode.keys);
-    assertEquals(Arrays.asList(labels), lookupSwitchInsnNode.labels);
+    assertEquals(List.of(1), lookupSwitchInsnNode.keys);
+    assertEquals(List.of(labels), lookupSwitchInsnNode.labels);
   }
 }
diff --git a/asm-tree/src/test/java/org/objectweb/asm/tree/MethodNodeTest.java b/asm-tree/src/test/java/org/objectweb/asm/tree/MethodNodeTest.java
index d59e5875..7aff0a02 100644
--- a/asm-tree/src/test/java/org/objectweb/asm/tree/MethodNodeTest.java
+++ b/asm-tree/src/test/java/org/objectweb/asm/tree/MethodNodeTest.java
@@ -30,7 +30,7 @@ package org.objectweb.asm.tree;
 import static org.junit.jupiter.api.Assertions.assertEquals;
 import static org.junit.jupiter.api.Assertions.assertThrows;
 
-import java.util.Arrays;
+import java.util.List;
 import org.junit.jupiter.api.Test;
 import org.junit.jupiter.api.function.Executable;
 import org.junit.jupiter.params.ParameterizedTest;
@@ -89,7 +89,7 @@ class MethodNodeTest extends AsmTest {
             method.name = name;
             method.desc = descriptor;
             method.signature = signature;
-            method.exceptions = exceptions == null ? null : Arrays.asList(exceptions);
+            method.exceptions = exceptions == null ? null : List.of(exceptions);
             methods.add(method);
             return method;
           }
diff --git a/asm-tree/src/test/java/org/objectweb/asm/tree/TableSwitchInsnNodeTest.java b/asm-tree/src/test/java/org/objectweb/asm/tree/TableSwitchInsnNodeTest.java
index 54e659de..cd83ef48 100644
--- a/asm-tree/src/test/java/org/objectweb/asm/tree/TableSwitchInsnNodeTest.java
+++ b/asm-tree/src/test/java/org/objectweb/asm/tree/TableSwitchInsnNodeTest.java
@@ -29,7 +29,7 @@ package org.objectweb.asm.tree;
 
 import static org.junit.jupiter.api.Assertions.assertEquals;
 
-import java.util.Arrays;
+import java.util.List;
 import org.junit.jupiter.api.Test;
 import org.objectweb.asm.test.AsmTest;
 
@@ -51,6 +51,6 @@ class TableSwitchInsnNodeTest extends AsmTest {
     assertEquals(0, tableSwitchInsnNode.min);
     assertEquals(1, tableSwitchInsnNode.max);
     assertEquals(dflt, tableSwitchInsnNode.dflt);
-    assertEquals(Arrays.asList(labels), tableSwitchInsnNode.labels);
+    assertEquals(List.of(labels), tableSwitchInsnNode.labels);
   }
 }
diff --git a/asm-util/src/main/java/org/objectweb/asm/util/ASMifier.java b/asm-util/src/main/java/org/objectweb/asm/util/ASMifier.java
index b779a190..99e2bc0d 100644
--- a/asm-util/src/main/java/org/objectweb/asm/util/ASMifier.java
+++ b/asm-util/src/main/java/org/objectweb/asm/util/ASMifier.java
@@ -112,6 +112,9 @@ public class ASMifier extends Printer {
     classVersions.put(Opcodes.V20, "V20");
     classVersions.put(Opcodes.V21, "V21");
     classVersions.put(Opcodes.V22, "V22");
+    classVersions.put(Opcodes.V23, "V23");
+    classVersions.put(Opcodes.V24, "V24");
+    classVersions.put(Opcodes.V25, "V25");
     CLASS_VERSIONS = Collections.unmodifiableMap(classVersions);
   }
 
@@ -670,7 +673,11 @@ public class ASMifier extends Printer {
   public void visitParameter(final String parameterName, final int access) {
     stringBuilder.setLength(0);
     stringBuilder.append(name).append(".visitParameter(");
-    appendString(stringBuilder, parameterName);
+    if (parameterName == null) {
+      stringBuilder.append("null");
+    } else {
+      appendString(stringBuilder, parameterName);
+    }
     stringBuilder.append(", ");
     appendAccessFlags(access);
     text.add(stringBuilder.append(");\n").toString());
@@ -1468,24 +1475,24 @@ public class ASMifier extends Printer {
       }
       stringBuilder.append("})");
     } else if (value instanceof Byte) {
-      stringBuilder.append("new Byte((byte)").append(value).append(')');
+      stringBuilder.append("Byte.valueOf((byte)").append(value).append(')');
     } else if (value instanceof Boolean) {
       stringBuilder.append(((Boolean) value).booleanValue() ? "Boolean.TRUE" : "Boolean.FALSE");
     } else if (value instanceof Short) {
-      stringBuilder.append("new Short((short)").append(value).append(')');
+      stringBuilder.append("Short.valueOf((short)").append(value).append(')');
     } else if (value instanceof Character) {
       stringBuilder
-          .append("new Character((char)")
+          .append("Character.valueOf((char)")
           .append((int) ((Character) value).charValue())
           .append(')');
     } else if (value instanceof Integer) {
-      stringBuilder.append("new Integer(").append(value).append(')');
+      stringBuilder.append("Integer.valueOf(").append(value).append(')');
     } else if (value instanceof Float) {
-      stringBuilder.append("new Float(\"").append(value).append("\")");
+      stringBuilder.append("Float.valueOf(\"").append(value).append("\")");
     } else if (value instanceof Long) {
-      stringBuilder.append("new Long(").append(value).append("L)");
+      stringBuilder.append("Long.valueOf(").append(value).append("L)");
     } else if (value instanceof Double) {
-      stringBuilder.append("new Double(\"").append(value).append("\")");
+      stringBuilder.append("Double.valueOf(\"").append(value).append("\")");
     } else if (value instanceof byte[]) {
       byte[] byteArray = (byte[]) value;
       stringBuilder.append("new byte[] {");
diff --git a/asm-util/src/main/java/org/objectweb/asm/util/CheckClassAdapter.java b/asm-util/src/main/java/org/objectweb/asm/util/CheckClassAdapter.java
index 4b12b240..80ada1a9 100644
--- a/asm-util/src/main/java/org/objectweb/asm/util/CheckClassAdapter.java
+++ b/asm-util/src/main/java/org/objectweb/asm/util/CheckClassAdapter.java
@@ -162,7 +162,7 @@ public class CheckClassAdapter extends ClassVisitor {
    * @param classVisitor the class visitor to which this adapter must delegate calls.
    */
   public CheckClassAdapter(final ClassVisitor classVisitor) {
-    this(classVisitor, /* checkDataFlow = */ true);
+    this(classVisitor, /* checkDataFlow= */ true);
   }
 
   /**
@@ -380,7 +380,7 @@ public class CheckClassAdapter extends ClassVisitor {
       final String name, final String descriptor, final String signature) {
     checkState();
     CheckMethodAdapter.checkUnqualifiedName(version, name, "record component name");
-    CheckMethodAdapter.checkDescriptor(version, descriptor, /* canBeVoid = */ false);
+    CheckMethodAdapter.checkDescriptor(version, descriptor, /* canBeVoid= */ false);
     if (signature != null) {
       checkFieldSignature(signature);
     }
@@ -410,7 +410,7 @@ public class CheckClassAdapter extends ClassVisitor {
             | Opcodes.ACC_MANDATED
             | Opcodes.ACC_DEPRECATED);
     CheckMethodAdapter.checkUnqualifiedName(version, name, "field name");
-    CheckMethodAdapter.checkDescriptor(version, descriptor, /* canBeVoid = */ false);
+    CheckMethodAdapter.checkDescriptor(version, descriptor, /* canBeVoid= */ false);
     if (signature != null) {
       checkFieldSignature(signature);
     }
@@ -1048,7 +1048,7 @@ public class CheckClassAdapter extends ClassVisitor {
       final PrintWriter printWriter) {
     ClassNode classNode = new ClassNode();
     classReader.accept(
-        new CheckClassAdapter(/*latest*/ Opcodes.ASM10_EXPERIMENTAL, classNode, false) {},
+        new CheckClassAdapter(/*latest*/ Opcodes.ASM9, classNode, false) {},
         ClassReader.SKIP_DEBUG);
 
     Type syperType = classNode.superName == null ? null : Type.getObjectType(classNode.superName);
diff --git a/asm-util/src/main/java/org/objectweb/asm/util/CheckFrameAnalyzer.java b/asm-util/src/main/java/org/objectweb/asm/util/CheckFrameAnalyzer.java
index 5be17b2a..b58398c2 100644
--- a/asm-util/src/main/java/org/objectweb/asm/util/CheckFrameAnalyzer.java
+++ b/asm-util/src/main/java/org/objectweb/asm/util/CheckFrameAnalyzer.java
@@ -123,7 +123,7 @@ class CheckFrameAnalyzer<V extends Value> extends Analyzer<V> {
     }
 
     Frame<V>[] frames = getFrames();
-    Frame<V> currentFrame = frames[0];
+    Frame<V> currentFrame = newFrame(frames[0]);
     expandFrames(owner, method, currentFrame);
     for (int insnIndex = 0; insnIndex < insnList.size(); ++insnIndex) {
       Frame<V> oldFrame = frames[insnIndex];
@@ -138,7 +138,7 @@ class CheckFrameAnalyzer<V extends Value> extends Analyzer<V> {
         if (insnType == AbstractInsnNode.LABEL
             || insnType == AbstractInsnNode.LINE
             || insnType == AbstractInsnNode.FRAME) {
-          checkFrame(insnIndex + 1, oldFrame, /* requireFrame = */ false);
+          checkFrame(insnIndex + 1, oldFrame, /* requireFrame= */ false);
         } else {
           currentFrame.init(oldFrame).execute(insnNode, interpreter);
 
@@ -148,40 +148,40 @@ class CheckFrameAnalyzer<V extends Value> extends Analyzer<V> {
             }
             JumpInsnNode jumpInsn = (JumpInsnNode) insnNode;
             int targetInsnIndex = insnList.indexOf(jumpInsn.label);
-            checkFrame(targetInsnIndex, currentFrame, /* requireFrame = */ true);
+            checkFrame(targetInsnIndex, currentFrame, /* requireFrame= */ true);
             if (insnOpcode == GOTO) {
               endControlFlow(insnIndex);
             } else {
-              checkFrame(insnIndex + 1, currentFrame, /* requireFrame = */ false);
+              checkFrame(insnIndex + 1, currentFrame, /* requireFrame= */ false);
             }
           } else if (insnNode instanceof LookupSwitchInsnNode) {
             LookupSwitchInsnNode lookupSwitchInsn = (LookupSwitchInsnNode) insnNode;
             int targetInsnIndex = insnList.indexOf(lookupSwitchInsn.dflt);
-            checkFrame(targetInsnIndex, currentFrame, /* requireFrame = */ true);
+            checkFrame(targetInsnIndex, currentFrame, /* requireFrame= */ true);
             for (int i = 0; i < lookupSwitchInsn.labels.size(); ++i) {
               LabelNode label = lookupSwitchInsn.labels.get(i);
               targetInsnIndex = insnList.indexOf(label);
               currentFrame.initJumpTarget(insnOpcode, label);
-              checkFrame(targetInsnIndex, currentFrame, /* requireFrame = */ true);
+              checkFrame(targetInsnIndex, currentFrame, /* requireFrame= */ true);
             }
             endControlFlow(insnIndex);
           } else if (insnNode instanceof TableSwitchInsnNode) {
             TableSwitchInsnNode tableSwitchInsn = (TableSwitchInsnNode) insnNode;
             int targetInsnIndex = insnList.indexOf(tableSwitchInsn.dflt);
             currentFrame.initJumpTarget(insnOpcode, tableSwitchInsn.dflt);
-            checkFrame(targetInsnIndex, currentFrame, /* requireFrame = */ true);
+            checkFrame(targetInsnIndex, currentFrame, /* requireFrame= */ true);
             newControlFlowEdge(insnIndex, targetInsnIndex);
             for (int i = 0; i < tableSwitchInsn.labels.size(); ++i) {
               LabelNode label = tableSwitchInsn.labels.get(i);
               currentFrame.initJumpTarget(insnOpcode, label);
               targetInsnIndex = insnList.indexOf(label);
-              checkFrame(targetInsnIndex, currentFrame, /* requireFrame = */ true);
+              checkFrame(targetInsnIndex, currentFrame, /* requireFrame= */ true);
             }
             endControlFlow(insnIndex);
           } else if (insnOpcode == RET) {
             throw new AnalyzerException(insnNode, "RET instructions are unsupported");
           } else if (insnOpcode != ATHROW && (insnOpcode < IRETURN || insnOpcode > RETURN)) {
-            checkFrame(insnIndex + 1, currentFrame, /* requireFrame = */ false);
+            checkFrame(insnIndex + 1, currentFrame, /* requireFrame= */ false);
           } else {
             endControlFlow(insnIndex);
           }
@@ -199,7 +199,7 @@ class CheckFrameAnalyzer<V extends Value> extends Analyzer<V> {
             Frame<V> handler = newFrame(oldFrame);
             handler.clearStack();
             handler.push(interpreter.newExceptionValue(tryCatchBlock, handler, catchType));
-            checkFrame(insnList.indexOf(tryCatchBlock.handler), handler, /* requireFrame = */ true);
+            checkFrame(insnList.indexOf(tryCatchBlock.handler), handler, /* requireFrame= */ true);
           }
         }
 
diff --git a/asm-util/src/main/java/org/objectweb/asm/util/CheckMethodAdapter.java b/asm-util/src/main/java/org/objectweb/asm/util/CheckMethodAdapter.java
index 339af5d1..ed18dc00 100644
--- a/asm-util/src/main/java/org/objectweb/asm/util/CheckMethodAdapter.java
+++ b/asm-util/src/main/java/org/objectweb/asm/util/CheckMethodAdapter.java
@@ -787,7 +787,7 @@ public class CheckMethodAdapter extends MethodVisitor {
     checkVisitCodeCalled();
     checkVisitMaxsNotCalled();
     checkOpcodeMethod(opcode, Method.VISIT_JUMP_INSN);
-    checkLabel(label, /* checkVisited = */ false, "label");
+    checkLabel(label, /* checkVisited= */ false, "label");
     super.visitJumpInsn(opcode, label);
     ++insnCount;
   }
@@ -796,7 +796,7 @@ public class CheckMethodAdapter extends MethodVisitor {
   public void visitLabel(final Label label) {
     checkVisitCodeCalled();
     checkVisitMaxsNotCalled();
-    checkLabel(label, /* checkVisited = */ false, "label");
+    checkLabel(label, /* checkVisited= */ false, "label");
     if (labelInsnIndices.get(label) != null) {
       throw new IllegalStateException("Already visited label");
     }
@@ -832,12 +832,12 @@ public class CheckMethodAdapter extends MethodVisitor {
       throw new IllegalArgumentException(
           "Max = " + max + " must be greater than or equal to min = " + min);
     }
-    checkLabel(dflt, /* checkVisited = */ false, "default label");
+    checkLabel(dflt, /* checkVisited= */ false, "default label");
     if (labels == null || labels.length != max - min + 1) {
       throw new IllegalArgumentException("There must be max - min + 1 labels");
     }
     for (int i = 0; i < labels.length; ++i) {
-      checkLabel(labels[i], /* checkVisited = */ false, "label at index " + i);
+      checkLabel(labels[i], /* checkVisited= */ false, "label at index " + i);
     }
     super.visitTableSwitchInsn(min, max, dflt, labels);
     ++insnCount;
@@ -847,12 +847,17 @@ public class CheckMethodAdapter extends MethodVisitor {
   public void visitLookupSwitchInsn(final Label dflt, final int[] keys, final Label[] labels) {
     checkVisitMaxsNotCalled();
     checkVisitCodeCalled();
-    checkLabel(dflt, /* checkVisited = */ false, "default label");
+    checkLabel(dflt, /* checkVisited= */ false, "default label");
     if (keys == null || labels == null || keys.length != labels.length) {
       throw new IllegalArgumentException("There must be the same number of keys and labels");
     }
+    for (int i = 1; i < keys.length; ++i) {
+      if (keys[i] < keys[i - 1]) {
+        throw new IllegalArgumentException("The keys must be sorted in increasing order");
+      }
+    }
     for (int i = 0; i < labels.length; ++i) {
-      checkLabel(labels[i], /* checkVisited = */ false, "label at index " + i);
+      checkLabel(labels[i], /* checkVisited= */ false, "label at index " + i);
     }
     super.visitLookupSwitchInsn(dflt, keys, labels);
     ++insnCount;
@@ -908,9 +913,9 @@ public class CheckMethodAdapter extends MethodVisitor {
       final Label start, final Label end, final Label handler, final String type) {
     checkVisitCodeCalled();
     checkVisitMaxsNotCalled();
-    checkLabel(start, /* checkVisited = */ false, START_LABEL);
-    checkLabel(end, /* checkVisited = */ false, END_LABEL);
-    checkLabel(handler, /* checkVisited = */ false, "handler label");
+    checkLabel(start, /* checkVisited= */ false, START_LABEL);
+    checkLabel(end, /* checkVisited= */ false, END_LABEL);
+    checkLabel(handler, /* checkVisited= */ false, "handler label");
     if (labelInsnIndices.get(start) != null
         || labelInsnIndices.get(end) != null
         || labelInsnIndices.get(handler) != null) {
@@ -954,8 +959,8 @@ public class CheckMethodAdapter extends MethodVisitor {
     if (signature != null) {
       CheckClassAdapter.checkFieldSignature(signature);
     }
-    checkLabel(start, /* checkVisited = */ true, START_LABEL);
-    checkLabel(end, /* checkVisited = */ true, END_LABEL);
+    checkLabel(start, /* checkVisited= */ true, START_LABEL);
+    checkLabel(end, /* checkVisited= */ true, END_LABEL);
     checkUnsignedShort(index, INVALID_LOCAL_VARIABLE_INDEX);
     int startInsnIndex = labelInsnIndices.get(start).intValue();
     int endInsnIndex = labelInsnIndices.get(end).intValue();
@@ -992,8 +997,8 @@ public class CheckMethodAdapter extends MethodVisitor {
           "Invalid start, end and index arrays (must be non null and of identical length");
     }
     for (int i = 0; i < start.length; ++i) {
-      checkLabel(start[i], /* checkVisited = */ true, START_LABEL);
-      checkLabel(end[i], /* checkVisited = */ true, END_LABEL);
+      checkLabel(start[i], /* checkVisited= */ true, START_LABEL);
+      checkLabel(end[i], /* checkVisited= */ true, END_LABEL);
       checkUnsignedShort(index[i], INVALID_LOCAL_VARIABLE_INDEX);
       int startInsnIndex = labelInsnIndices.get(start[i]).intValue();
       int endInsnIndex = labelInsnIndices.get(end[i]).intValue();
@@ -1011,7 +1016,7 @@ public class CheckMethodAdapter extends MethodVisitor {
     checkVisitCodeCalled();
     checkVisitMaxsNotCalled();
     checkUnsignedShort(line, "Invalid line number");
-    checkLabel(start, /* checkVisited = */ true, START_LABEL);
+    checkLabel(start, /* checkVisited= */ true, START_LABEL);
     super.visitLineNumber(line, start);
   }
 
@@ -1088,7 +1093,7 @@ public class CheckMethodAdapter extends MethodVisitor {
     if (value instanceof String) {
       checkInternalName(version, (String) value, "Invalid stack frame value");
     } else if (value instanceof Label) {
-      checkLabel((Label) value, /* checkVisited = */ false, "label");
+      checkLabel((Label) value, /* checkVisited= */ false, "label");
     } else {
       throw new IllegalArgumentException("Invalid stack frame value: " + value);
     }
diff --git a/asm-util/src/main/java/org/objectweb/asm/util/Textifier.java b/asm-util/src/main/java/org/objectweb/asm/util/Textifier.java
index 0049d357..17dbcbf3 100644
--- a/asm-util/src/main/java/org/objectweb/asm/util/Textifier.java
+++ b/asm-util/src/main/java/org/objectweb/asm/util/Textifier.java
@@ -35,6 +35,7 @@ import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
 import org.objectweb.asm.Attribute;
+import org.objectweb.asm.ConstantDynamic;
 import org.objectweb.asm.Handle;
 import org.objectweb.asm.Label;
 import org.objectweb.asm.Opcodes;
@@ -384,11 +385,7 @@ public class Textifier extends Printer {
     stringBuilder.append(' ').append(name);
     if (value != null) {
       stringBuilder.append(" = ");
-      if (value instanceof String) {
-        stringBuilder.append('\"').append(value).append('\"');
-      } else {
-        stringBuilder.append(value);
-      }
+      appendConstant(value);
     }
 
     stringBuilder.append('\n');
@@ -437,10 +434,10 @@ public class Textifier extends Printer {
     stringBuilder.append(name);
     appendDescriptor(METHOD_DESCRIPTOR, descriptor);
     if (exceptions != null && exceptions.length > 0) {
-      stringBuilder.append(" throws ");
+      stringBuilder.append(" throws");
       for (String exception : exceptions) {
-        appendDescriptor(INTERNAL_NAME, exception);
         stringBuilder.append(' ');
+        appendDescriptor(INTERNAL_NAME, exception);
       }
     }
 
@@ -948,33 +945,9 @@ public class Textifier extends Printer {
     stringBuilder.append(" [");
     stringBuilder.append('\n');
     stringBuilder.append(tab3);
-    appendHandle(bootstrapMethodHandle);
-    stringBuilder.append('\n');
-    stringBuilder.append(tab3).append("// arguments:");
-    if (bootstrapMethodArguments.length == 0) {
-      stringBuilder.append(" none");
-    } else {
-      stringBuilder.append('\n');
-      for (Object value : bootstrapMethodArguments) {
-        stringBuilder.append(tab3);
-        if (value instanceof String) {
-          Printer.appendString(stringBuilder, (String) value);
-        } else if (value instanceof Type) {
-          Type type = (Type) value;
-          if (type.getSort() == Type.METHOD) {
-            appendDescriptor(METHOD_DESCRIPTOR, type.getDescriptor());
-          } else {
-            visitType(type);
-          }
-        } else if (value instanceof Handle) {
-          appendHandle((Handle) value);
-        } else {
-          stringBuilder.append(value);
-        }
-        stringBuilder.append(", \n");
-      }
-      stringBuilder.setLength(stringBuilder.length() - 3);
-    }
+    appendHandle(bootstrapMethodHandle, tab3);
+    stringBuilder.append('\n').append(tab3);
+    appendBoostrapMethodArgs(bootstrapMethodArguments, tab3);
     stringBuilder.append('\n');
     stringBuilder.append(tab2).append("]\n");
     text.add(stringBuilder.toString());
@@ -1001,13 +974,15 @@ public class Textifier extends Printer {
   @Override
   public void visitLdcInsn(final Object value) {
     stringBuilder.setLength(0);
-    stringBuilder.append(tab2).append("LDC ");
-    if (value instanceof String) {
-      Printer.appendString(stringBuilder, (String) value);
-    } else if (value instanceof Type) {
-      stringBuilder.append(((Type) value).getDescriptor()).append(CLASS_SUFFIX);
+    if (value instanceof ConstantDynamic) {
+      stringBuilder.append(tab2).append("LDC ");
+      appendConstantDynamic((ConstantDynamic) value, tab2);
+    } else if (value instanceof Handle) {
+      stringBuilder.append(tab2);
+      appendHandle((Handle) value, tab2 + "LDC ");
     } else {
-      stringBuilder.append(value);
+      stringBuilder.append(tab2).append("LDC ");
+      appendConstant(value);
     }
     stringBuilder.append('\n');
     text.add(stringBuilder.toString());
@@ -1307,6 +1282,96 @@ public class Textifier extends Printer {
     }
   }
 
+  /**
+   * Appends a constant value. This method can be used for {@link Integer}, {@link Float}, {@link
+   * Long}, {@link Double}, {@link Boolean}, {@link String}, and {@link Type}. Attempting to use any
+   * other type will result in its {@link Object#toString()} representation.
+   *
+   * @param constant the constant to be appended.
+   */
+  private void appendConstant(final Object constant) {
+    if (constant instanceof Number) {
+      if (constant instanceof Double) {
+        stringBuilder.append(constant).append('D');
+      } else if (constant instanceof Float) {
+        stringBuilder.append(constant).append('F');
+      } else if (constant instanceof Long) {
+        stringBuilder.append(constant).append('L');
+      } else {
+        // Integer (or other "unsupported" Number subclass)
+        stringBuilder.append(constant);
+      }
+    } else {
+      if (constant instanceof Type) {
+        stringBuilder.append(((Type) constant).getDescriptor()).append(CLASS_SUFFIX);
+      } else if (constant instanceof String) {
+        Printer.appendString(stringBuilder, constant.toString());
+      } else {
+        // Boolean or other "unsupported" constant
+        stringBuilder.append(constant);
+      }
+    }
+  }
+
+  /**
+   * Append the contents of a {@link ConstantDynamic}.
+   *
+   * @param condy the constant dynamic to append
+   * @param condyIndent the indent to use for newlines.
+   */
+  private void appendConstantDynamic(final ConstantDynamic condy, final String condyIndent) {
+    stringBuilder
+        .append(condy.getName())
+        .append(" : ")
+        .append(condy.getDescriptor())
+        .append(" [\n");
+    stringBuilder.append(condyIndent).append(tab);
+    appendHandle(condy.getBootstrapMethod(), condyIndent + tab);
+    stringBuilder.append('\n').append(condyIndent).append(tab);
+    Object[] bsmArgs = new Object[condy.getBootstrapMethodArgumentCount()];
+    for (int i = 0; i < bsmArgs.length; i++) {
+      bsmArgs[i] = condy.getBootstrapMethodArgument(i);
+    }
+    appendBoostrapMethodArgs(bsmArgs, condyIndent + tab);
+    stringBuilder.append('\n').append(condyIndent).append(']');
+  }
+
+  /**
+   * Appends bootstrap method args for {@link ConstantDynamic} and {@link #visitInvokeDynamicInsn}.
+   *
+   * @param bsmArgs the bootstrap method arguments.
+   * @param argIndent the indent to use for newlines.
+   */
+  private void appendBoostrapMethodArgs(final Object[] bsmArgs, final String argIndent) {
+    stringBuilder.append("// arguments:");
+    if (bsmArgs.length == 0) {
+      stringBuilder.append(" none");
+    } else {
+      for (int i = 0; i < bsmArgs.length; i++) {
+        Object arg = bsmArgs[i];
+        if (i != 0) {
+          stringBuilder.append(", ");
+        }
+        stringBuilder.append('\n').append(argIndent);
+        if (arg instanceof Type) {
+          Type type = (Type) arg;
+          if (type.getSort() == Type.METHOD) {
+            appendDescriptor(METHOD_DESCRIPTOR, type.getDescriptor());
+          } else {
+            visitType(type);
+          }
+        } else if (arg instanceof Handle) {
+          appendHandle((Handle) arg, argIndent);
+        } else if (arg instanceof ConstantDynamic) {
+          stringBuilder.append("// constant dynamic: ").append('\n').append(argIndent);
+          appendConstantDynamic((ConstantDynamic) arg, argIndent);
+        } else {
+          appendConstant(arg);
+        }
+      }
+    }
+  }
+
   /**
    * Appends the hexadecimal value of the given access flags to {@link #stringBuilder}.
    *
@@ -1378,12 +1443,18 @@ public class Textifier extends Printer {
     stringBuilder.append(name);
   }
 
+  @Deprecated
+  protected void appendHandle(final Handle handle) {
+    appendHandle(handle, tab3);
+  }
+
   /**
    * Appends a string representation of the given handle to {@link #stringBuilder}.
    *
    * @param handle a handle.
+   * @param afterComment this is the prefix of the line after the handle kind.
    */
-  protected void appendHandle(final Handle handle) {
+  protected void appendHandle(final Handle handle, final String afterComment) {
     int tag = handle.getTag();
     stringBuilder.append("// handle kind 0x").append(Integer.toHexString(tag)).append(" : ");
     boolean isMethodHandle = false;
@@ -1424,7 +1495,7 @@ public class Textifier extends Printer {
         throw new IllegalArgumentException();
     }
     stringBuilder.append('\n');
-    stringBuilder.append(tab3);
+    stringBuilder.append(afterComment);
     appendDescriptor(INTERNAL_NAME, handle.getOwner());
     stringBuilder.append('.');
     stringBuilder.append(handle.getName());
diff --git a/asm-util/src/main/java/org/objectweb/asm/util/TraceClassVisitor.java b/asm-util/src/main/java/org/objectweb/asm/util/TraceClassVisitor.java
index 953e1149..b7859766 100644
--- a/asm-util/src/main/java/org/objectweb/asm/util/TraceClassVisitor.java
+++ b/asm-util/src/main/java/org/objectweb/asm/util/TraceClassVisitor.java
@@ -119,7 +119,7 @@ public final class TraceClassVisitor extends ClassVisitor {
    */
   public TraceClassVisitor(
       final ClassVisitor classVisitor, final Printer printer, final PrintWriter printWriter) {
-    super(/* latest api = */ Opcodes.ASM10_EXPERIMENTAL, classVisitor);
+    super(/* latest api = */ Opcodes.ASM9, classVisitor);
     this.printWriter = printWriter;
     this.p = printer;
   }
diff --git a/asm-util/src/test/java/org/objectweb/asm/util/CheckClassAdapterTest.java b/asm-util/src/test/java/org/objectweb/asm/util/CheckClassAdapterTest.java
index 280ec628..3b00a498 100644
--- a/asm-util/src/test/java/org/objectweb/asm/util/CheckClassAdapterTest.java
+++ b/asm-util/src/test/java/org/objectweb/asm/util/CheckClassAdapterTest.java
@@ -414,7 +414,7 @@ class CheckClassAdapterTest extends AsmTest implements Opcodes {
 
   @Test
   void testVisitMethod_noDataFlowCheckIfDisabled() {
-    CheckClassAdapter checkClassAdapter = new CheckClassAdapter(null, /* checkDataFlow = */ false);
+    CheckClassAdapter checkClassAdapter = new CheckClassAdapter(null, /* checkDataFlow= */ false);
     checkClassAdapter.visit(V1_1, ACC_PUBLIC, "C", null, "java/lang/Object", null);
     MethodVisitor methodVisitor = checkClassAdapter.visitMethod(ACC_PUBLIC, "m", "()V", null, null);
     methodVisitor.visitCode();
@@ -547,8 +547,7 @@ class CheckClassAdapterTest extends AsmTest implements Opcodes {
     ClassReader classReader = new ClassReader(classParameter.getBytes());
     StringWriter logger = new StringWriter();
 
-    CheckClassAdapter.verify(
-        classReader, /* printResults = */ false, new PrintWriter(logger, true));
+    CheckClassAdapter.verify(classReader, /* printResults= */ false, new PrintWriter(logger, true));
 
     assertEquals("", logger.toString());
   }
diff --git a/asm-util/src/test/java/org/objectweb/asm/util/CheckFrameAnalyzerTest.java b/asm-util/src/test/java/org/objectweb/asm/util/CheckFrameAnalyzerTest.java
index 2edd75f7..bc8aa0db 100644
--- a/asm-util/src/test/java/org/objectweb/asm/util/CheckFrameAnalyzerTest.java
+++ b/asm-util/src/test/java/org/objectweb/asm/util/CheckFrameAnalyzerTest.java
@@ -27,6 +27,7 @@
 // THE POSSIBILITY OF SUCH DAMAGE.
 package org.objectweb.asm.util;
 
+import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
 import static org.junit.jupiter.api.Assertions.assertNotNull;
 import static org.junit.jupiter.api.Assertions.assertThrows;
 import static org.junit.jupiter.api.Assertions.assertTrue;
@@ -63,6 +64,22 @@ class CheckFrameAnalyzerTest extends AsmTest {
   // Labels used to generate test cases.
   private final Label label0 = new Label();
 
+  @Test
+  void testAnalyze_validBytecode() {
+    MethodNode methodNode =
+        new MethodNodeBuilder("(Ljava/lang/Object;)V", 1, 2)
+            .aload(0)
+            .astore(1)
+            .iconst_0()
+            .istore(0)
+            .vreturn()
+            .build();
+
+    Executable analyze = () -> newAnalyzer().analyze(CLASS_NAME, methodNode);
+
+    assertDoesNotThrow(analyze);
+  }
+
   @Test
   void testAnalyze_invalidJsr() {
     MethodNode methodNode = new MethodNodeBuilder().jsr(label0).label(label0).vreturn().build();
@@ -135,7 +152,7 @@ class CheckFrameAnalyzerTest extends AsmTest {
   @Test
   void testAnalyze_invalidAppendFrame() {
     MethodNode methodNode =
-        new MethodNodeBuilder(/* maxStack = */ 0, /* maxLocals = */ 1)
+        new MethodNodeBuilder(/* maxStack= */ 0, /* maxLocals= */ 1)
             .nop()
             .frame(Opcodes.F_APPEND, new Object[] {Opcodes.INTEGER}, null)
             .vreturn()
@@ -151,7 +168,7 @@ class CheckFrameAnalyzerTest extends AsmTest {
   @Test
   void testAnalyze_invalidChopFrame() {
     MethodNode methodNode =
-        new MethodNodeBuilder(/* maxStack = */ 0, /* maxLocals = */ 1)
+        new MethodNodeBuilder(/* maxStack= */ 0, /* maxLocals= */ 1)
             .nop()
             .frame(Opcodes.F_CHOP, new Object[] {null, null}, null)
             .vreturn()
@@ -166,7 +183,7 @@ class CheckFrameAnalyzerTest extends AsmTest {
   @Test
   void testAnalyze_illegalStackMapFrameValue() {
     MethodNode methodNode =
-        new MethodNodeBuilder(/* maxStack = */ 0, /* maxLocals = */ 2)
+        new MethodNodeBuilder(/* maxStack= */ 0, /* maxLocals= */ 2)
             .nop()
             .frame(Opcodes.F_APPEND, new Object[] {new Object()}, null)
             .vreturn()
@@ -182,7 +199,7 @@ class CheckFrameAnalyzerTest extends AsmTest {
   @Test
   void testAnalyze_illegalLabelNodeStackMapFrameValue() {
     MethodNode methodNode =
-        new MethodNodeBuilder(/* maxStack = */ 0, /* maxLocals = */ 2)
+        new MethodNodeBuilder(/* maxStack= */ 0, /* maxLocals= */ 2)
             .nop()
             .frame(Opcodes.F_APPEND, new Object[] {new LabelNode(label0)}, null)
             .label(label0)
diff --git a/asm-util/src/test/java/org/objectweb/asm/util/CheckMethodAdapterTest.java b/asm-util/src/test/java/org/objectweb/asm/util/CheckMethodAdapterTest.java
index 817d3d65..37567c0c 100644
--- a/asm-util/src/test/java/org/objectweb/asm/util/CheckMethodAdapterTest.java
+++ b/asm-util/src/test/java/org/objectweb/asm/util/CheckMethodAdapterTest.java
@@ -33,6 +33,7 @@ import static org.junit.jupiter.api.Assertions.assertThrows;
 import static org.junit.jupiter.api.Assertions.assertTrue;
 
 import java.util.HashMap;
+import java.util.Map;
 import org.junit.jupiter.api.Test;
 import org.junit.jupiter.api.function.Executable;
 import org.objectweb.asm.ClassWriter;
@@ -122,7 +123,7 @@ class CheckMethodAdapterTest extends AsmTest implements Opcodes {
   @Test
   void testVisitCode_abstractMethod() {
     CheckMethodAdapter checkAbstractMethodAdapter =
-        new CheckMethodAdapter(Opcodes.ACC_ABSTRACT, "m", "()V", null, new HashMap<>());
+        new CheckMethodAdapter(Opcodes.ACC_ABSTRACT, "m", "()V", null, Map.of());
 
     Executable visitCode = () -> checkAbstractMethodAdapter.visitCode();
 
@@ -775,6 +776,21 @@ class CheckMethodAdapterTest extends AsmTest implements Opcodes {
     assertEquals("There must be the same number of keys and labels", exception.getMessage());
   }
 
+  @Test
+  void testVisitLookupSwitchInsn_nonSortedKeys() {
+    Label label0 = new Label();
+    Label label1 = new Label();
+    checkMethodAdapter.visitCode();
+
+    Executable visitLookupSwitchInsn =
+        () ->
+            checkMethodAdapter.visitLookupSwitchInsn(
+                new Label(), new int[] {2, 1}, new Label[] {label0, label1});
+
+    Exception exception = assertThrows(IllegalArgumentException.class, visitLookupSwitchInsn);
+    assertEquals("The keys must be sorted in increasing order", exception.getMessage());
+  }
+
   @Test
   void testVisitMultiANewArrayInsn_invalidDescriptor() {
     checkMethodAdapter.visitCode();
@@ -1086,7 +1102,7 @@ class CheckMethodAdapterTest extends AsmTest implements Opcodes {
   @Test
   void testVisitEnd_invalidDataFlow() {
     MethodVisitor dataFlowCheckMethodAdapter =
-        new CheckMethodAdapter(ACC_PUBLIC, "m", "(I)I", null, new HashMap<>());
+        new CheckMethodAdapter(ACC_PUBLIC, "m", "(I)I", null, Map.of());
     dataFlowCheckMethodAdapter.visitCode();
     dataFlowCheckMethodAdapter.visitVarInsn(ILOAD, 1);
     dataFlowCheckMethodAdapter.visitVarInsn(ASTORE, 0);
@@ -1110,11 +1126,11 @@ class CheckMethodAdapterTest extends AsmTest implements Opcodes {
     MethodVisitor methodVisitor =
         new CheckMethodAdapter.MethodWriterWrapper(
             /* latest api = */ Opcodes.ASM9,
-            /* version = */ Opcodes.V1_5,
+            /* version= */ Opcodes.V1_5,
             classWriter,
             new MethodVisitor(/* latest api = */ Opcodes.ASM9) {});
     MethodVisitor dataFlowCheckMethodAdapter =
-        new CheckMethodAdapter(ACC_PUBLIC, "m", "(I)I", methodVisitor, new HashMap<>());
+        new CheckMethodAdapter(ACC_PUBLIC, "m", "(I)I", methodVisitor, Map.of());
     dataFlowCheckMethodAdapter.visitCode();
     dataFlowCheckMethodAdapter.visitVarInsn(ILOAD, 1);
     dataFlowCheckMethodAdapter.visitInsn(IRETURN);
@@ -1131,11 +1147,11 @@ class CheckMethodAdapterTest extends AsmTest implements Opcodes {
     MethodVisitor methodVisitor =
         new CheckMethodAdapter.MethodWriterWrapper(
             /* latest api = */ Opcodes.ASM9,
-            /* version = */ Opcodes.V1_5,
+            /* version= */ Opcodes.V1_5,
             classWriter,
             new MethodVisitor(/* latest api = */ Opcodes.ASM9) {});
     MethodVisitor dataFlowCheckMethodAdapter =
-        new CheckMethodAdapter(ACC_PUBLIC, "m", "(I)I", methodVisitor, new HashMap<>());
+        new CheckMethodAdapter(ACC_PUBLIC, "m", "(I)I", methodVisitor, Map.of());
     dataFlowCheckMethodAdapter.visitCode();
     dataFlowCheckMethodAdapter.visitVarInsn(ILOAD, 1);
     dataFlowCheckMethodAdapter.visitInsn(IRETURN);
@@ -1152,11 +1168,11 @@ class CheckMethodAdapterTest extends AsmTest implements Opcodes {
     MethodVisitor methodVisitor =
         new CheckMethodAdapter.MethodWriterWrapper(
             /* latest api = */ Opcodes.ASM9,
-            /* version = */ Opcodes.V1_5,
+            /* version= */ Opcodes.V1_5,
             classWriter,
             new MethodVisitor(/* latest api = */ Opcodes.ASM9) {});
     MethodVisitor dataFlowCheckMethodAdapter =
-        new CheckMethodAdapter(ACC_PUBLIC, "m", "(I)I", methodVisitor, new HashMap<>());
+        new CheckMethodAdapter(ACC_PUBLIC, "m", "(I)I", methodVisitor, Map.of());
     dataFlowCheckMethodAdapter.visitCode();
     dataFlowCheckMethodAdapter.visitVarInsn(ILOAD, 1);
     dataFlowCheckMethodAdapter.visitInsn(IRETURN);
@@ -1177,7 +1193,7 @@ class CheckMethodAdapterTest extends AsmTest implements Opcodes {
     MethodVisitor methodVisitor =
         new CheckMethodAdapter.MethodWriterWrapper(
             /* latest api = */ Opcodes.ASM9,
-            /* version = */ Opcodes.V1_7,
+            /* version= */ Opcodes.V1_7,
             classWriter,
             new MethodVisitor(/* latest api = */ Opcodes.ASM9) {});
     MethodVisitor dataFlowCheckMethodAdapter =
@@ -1202,7 +1218,7 @@ class CheckMethodAdapterTest extends AsmTest implements Opcodes {
     MethodVisitor methodVisitor =
         new CheckMethodAdapter.MethodWriterWrapper(
             /* latest api = */ Opcodes.ASM9,
-            /* version = */ Opcodes.V1_7,
+            /* version= */ Opcodes.V1_7,
             classWriter,
             new MethodVisitor(/* latest api = */ Opcodes.ASM9) {});
     MethodVisitor dataFlowCheckMethodAdapter =
@@ -1228,7 +1244,7 @@ class CheckMethodAdapterTest extends AsmTest implements Opcodes {
   @Test
   void testVisitEnd_invalidReturnType() {
     MethodVisitor dataFlowCheckMethodAdapter =
-        new CheckMethodAdapter(ACC_PUBLIC, "m", "(I)V", null, new HashMap<>());
+        new CheckMethodAdapter(ACC_PUBLIC, "m", "(I)V", null, Map.of());
     dataFlowCheckMethodAdapter.visitCode();
     dataFlowCheckMethodAdapter.visitVarInsn(ILOAD, 1);
     dataFlowCheckMethodAdapter.visitInsn(IRETURN);
diff --git a/asm-util/src/test/java/org/objectweb/asm/util/CheckModuleAdapterTest.java b/asm-util/src/test/java/org/objectweb/asm/util/CheckModuleAdapterTest.java
index 61b985da..e524c1e0 100644
--- a/asm-util/src/test/java/org/objectweb/asm/util/CheckModuleAdapterTest.java
+++ b/asm-util/src/test/java/org/objectweb/asm/util/CheckModuleAdapterTest.java
@@ -44,14 +44,14 @@ class CheckModuleAdapterTest {
 
   @Test
   void testConstructor() {
-    assertDoesNotThrow(() -> new CheckModuleAdapter(null, /* open = */ false));
+    assertDoesNotThrow(() -> new CheckModuleAdapter(null, /* open= */ false));
     assertThrows(
-        IllegalStateException.class, () -> new CheckModuleAdapter(null, /* open = */ false) {});
+        IllegalStateException.class, () -> new CheckModuleAdapter(null, /* open= */ false) {});
   }
 
   @Test // see issue #317804
   void testVisitRequire_javaBaseTransitive() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ false);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ false);
     checkModuleAdapter.classVersion = Opcodes.V10;
 
     Executable visitRequire =
@@ -65,7 +65,7 @@ class CheckModuleAdapterTest {
 
   @Test // see issue #317804
   void testVisitRequire_javaBaseStaticPhase() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ false);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ false);
     checkModuleAdapter.classVersion = Opcodes.V10;
 
     Executable visitRequire =
@@ -79,7 +79,7 @@ class CheckModuleAdapterTest {
 
   @Test // see issue #317804
   void testVisitRequire_javaBaseTransitiveAndStaticPhase() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ false);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ false);
     checkModuleAdapter.classVersion = Opcodes.V10;
 
     Executable visitRequire =
@@ -95,7 +95,7 @@ class CheckModuleAdapterTest {
 
   @Test // see issue #317804
   void testVisitRequire_javaBaseTransitiveOrStaticPhaseAreIgnoredUnderJvms9() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ false);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ false);
     checkModuleAdapter.classVersion = Opcodes.V9;
 
     Executable visitRequire =
@@ -108,7 +108,7 @@ class CheckModuleAdapterTest {
 
   @Test
   void testVisitExport_nullArray() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ false);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ false);
 
     Executable visitExport = () -> checkModuleAdapter.visitExport("package", 0, (String[]) null);
 
@@ -117,7 +117,7 @@ class CheckModuleAdapterTest {
 
   @Test
   void testVisitOpen_nullArray() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ false);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ false);
 
     Executable visitOpen = () -> checkModuleAdapter.visitOpen("package", 0, (String[]) null);
 
@@ -126,7 +126,7 @@ class CheckModuleAdapterTest {
 
   @Test
   void testVisitOpen_openModule() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ true);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ true);
 
     Executable visitOpen = () -> checkModuleAdapter.visitOpen("package", 0, (String[]) null);
 
@@ -136,7 +136,7 @@ class CheckModuleAdapterTest {
 
   @Test
   void testVisitUse_nameAlreadyDeclared() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ false);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ false);
     checkModuleAdapter.visitUse("service");
 
     Executable visitUse = () -> checkModuleAdapter.visitUse("service");
@@ -147,7 +147,7 @@ class CheckModuleAdapterTest {
 
   @Test
   void testVisitUse_afterEnd() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ false);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ false);
     checkModuleAdapter.visitEnd();
 
     Executable visitUse = () -> checkModuleAdapter.visitUse("service");
@@ -159,7 +159,7 @@ class CheckModuleAdapterTest {
 
   @Test
   void testVisitProvide_nullProviderList() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ false);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ false);
 
     Executable visitProvide = () -> checkModuleAdapter.visitProvide("service2", (String[]) null);
 
@@ -169,7 +169,7 @@ class CheckModuleAdapterTest {
 
   @Test
   void testVisitProvide_emptyProviderList() {
-    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open = */ false);
+    CheckModuleAdapter checkModuleAdapter = new CheckModuleAdapter(null, /* open= */ false);
 
     Executable visitProvide = () -> checkModuleAdapter.visitProvide("service1");
 
diff --git a/asm-util/src/test/java/org/objectweb/asm/util/MethodNodeBuilder.java b/asm-util/src/test/java/org/objectweb/asm/util/MethodNodeBuilder.java
index 936d4ce9..1d2b6eec 100644
--- a/asm-util/src/test/java/org/objectweb/asm/util/MethodNodeBuilder.java
+++ b/asm-util/src/test/java/org/objectweb/asm/util/MethodNodeBuilder.java
@@ -43,11 +43,15 @@ final class MethodNodeBuilder {
   private final MethodNode methodNode;
 
   MethodNodeBuilder() {
-    this(/* maxStack = */ 10, /* maxLocals = */ 10);
+    this(/* maxStack= */ 10, /* maxLocals= */ 10);
   }
 
   MethodNodeBuilder(final int maxStack, final int maxLocals) {
-    methodNode = new MethodNode(Opcodes.ACC_PUBLIC, "m", "()V", null, null);
+    this("()V", maxStack, maxLocals);
+  }
+
+  MethodNodeBuilder(final String descriptor, final int maxStack, final int maxLocals) {
+    methodNode = new MethodNode(Opcodes.ACC_PUBLIC, "m", descriptor, null, null);
     methodNode.maxStack = maxStack;
     methodNode.maxLocals = maxLocals;
     methodNode.visitCode();
@@ -63,6 +67,21 @@ final class MethodNodeBuilder {
     return this;
   }
 
+  MethodNodeBuilder istore(final int variable) {
+    methodNode.visitVarInsn(Opcodes.ISTORE, variable);
+    return this;
+  }
+
+  MethodNodeBuilder aload(final int variable) {
+    methodNode.visitVarInsn(Opcodes.ALOAD, variable);
+    return this;
+  }
+
+  MethodNodeBuilder astore(final int variable) {
+    methodNode.visitVarInsn(Opcodes.ASTORE, variable);
+    return this;
+  }
+
   MethodNodeBuilder vreturn() {
     methodNode.visitInsn(Opcodes.RETURN);
     return this;
diff --git a/asm-util/src/test/java/org/objectweb/asm/util/TextifierTest.java b/asm-util/src/test/java/org/objectweb/asm/util/TextifierTest.java
index bfbfb92e..1c72d7cd 100644
--- a/asm-util/src/test/java/org/objectweb/asm/util/TextifierTest.java
+++ b/asm-util/src/test/java/org/objectweb/asm/util/TextifierTest.java
@@ -37,7 +37,6 @@ import static org.junit.jupiter.api.Assumptions.assumeTrue;
 import java.io.IOException;
 import java.io.PrintWriter;
 import java.io.StringWriter;
-import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Paths;
 import org.junit.jupiter.api.Test;
@@ -85,10 +84,7 @@ class TextifierTest extends AsmTest {
             0);
 
     String expectedText =
-        new String(
-                Files.readAllBytes(
-                    Paths.get("src/test/resources/" + classParameter.getName() + ".txt")),
-                StandardCharsets.UTF_8)
+        Files.readString(Paths.get("src/test/resources/" + classParameter.getName() + ".txt"))
             .replace("\r", "");
 
     assertEquals(expectedText, output.toString());
diff --git a/asm-util/src/test/resources/jdk11.AllInstructions.txt b/asm-util/src/test/resources/jdk11.AllInstructions.txt
index e9a961be..3161527f 100644
--- a/asm-util/src/test/resources/jdk11.AllInstructions.txt
+++ b/asm-util/src/test/resources/jdk11.AllInstructions.txt
@@ -16,14 +16,28 @@ public class jdk11/AllInstructions {
 
   // access flags 0x1
   public m()Ljava/lang/Object;
-    LDC name : Ljava/lang/Object; jdk11/HandleOwner.handleField(Ljava/lang/Object;)Ljava/lang/Object; (6) [argumentName : Ljava/lang/Object; jdk11/ArgumentHandleOwner.argumentHandleNameLjava/lang/Object; (2) []]
+    LDC name : Ljava/lang/Object; [
+      // handle kind 0x6 : INVOKESTATIC
+      jdk11/HandleOwner.handleField(Ljava/lang/Object;)Ljava/lang/Object;
+      // arguments:
+      // constant dynamic: 
+      argumentName : Ljava/lang/Object; [
+        // handle kind 0x2 : GETSTATIC
+        jdk11/ArgumentHandleOwner.argumentHandleName(Ljava/lang/Object;)
+        // arguments: none
+      ]
+    ]
     ARETURN
     MAXSTACK = 1
     MAXLOCALS = 1
 
   // access flags 0x9
   public static primitiveExample()J
-    LDC test : J jdk11/AllInstructions.bsm(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;)J (6) []
+    LDC test : J [
+      // handle kind 0x6 : INVOKESTATIC
+      jdk11/AllInstructions.bsm(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;)J
+      // arguments: none
+    ]
     LRETURN
     MAXSTACK = 2
     MAXLOCALS = 0
@@ -36,9 +50,37 @@ public class jdk11/AllInstructions {
     MAXSTACK = 2
     MAXLOCALS = 3
 
+  // access flags 0xA
+  private static anotherBsm(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;)J
+    BIPUSH 42
+    I2L
+    LRETURN
+    MAXSTACK = 2
+    MAXLOCALS = 3
+
+  // access flags 0x9
+  public static gnarlyCondyPop()V
+    LDC test : J [
+      // handle kind 0x6 : INVOKESTATIC
+      jdk11/AllInstructions.anotherBsm(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;)J
+      // arguments: none
+    ]
+    POP2
+    RETURN
+    MAXSTACK = 2
+    MAXLOCALS = 0
+
   // access flags 0x9
   public static main([Ljava/lang/String;)V
-    LDC run : Ljava/lang/Runnable; java/lang/invoke/LambdaMetafactory.metafactory(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/Object; (6) [()V, jdk11/AllInstructions.lambda$main$0()V (6), ()V]
+    LDC run : Ljava/lang/Runnable; [
+      // handle kind 0x6 : INVOKESTATIC
+      java/lang/invoke/LambdaMetafactory.metafactory(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/Object;
+      // arguments:
+      ()V, 
+      // handle kind 0x6 : INVOKESTATIC
+      jdk11/AllInstructions.lambda$main$0()V, 
+      ()V
+    ]
     ASTORE 1
     ALOAD 1
     INVOKEINTERFACE java/lang/Runnable.run ()V (itf)
diff --git a/asm-util/src/test/resources/jdk3.AllInstructions.txt b/asm-util/src/test/resources/jdk3.AllInstructions.txt
index 6abf2a12..260f10b5 100644
--- a/asm-util/src/test/resources/jdk3.AllInstructions.txt
+++ b/asm-util/src/test/resources/jdk3.AllInstructions.txt
@@ -315,7 +315,7 @@ class jdk3/AllInstructions {
    L0
     LINENUMBER 72 L0
     LLOAD 0
-    LDC -1
+    LDC -1L
     LCMP
     IFGE L1
     ICONST_1
@@ -339,7 +339,7 @@ class jdk3/AllInstructions {
    L6
     LINENUMBER 74 L6
     LLOAD 4
-    LDC 2
+    LDC 2L
     LCMP
     IFGT L7
     ICONST_1
@@ -351,7 +351,7 @@ class jdk3/AllInstructions {
    L9
     LINENUMBER 75 L9
     LLOAD 6
-    LDC 3
+    LDC 3L
     LCMP
     IFLT L10
     ICONST_1
@@ -363,7 +363,7 @@ class jdk3/AllInstructions {
    L12
     LINENUMBER 76 L12
     LLOAD 8
-    LDC 4
+    LDC 4L
     LCMP
     IFNE L13
     ICONST_1
@@ -375,7 +375,7 @@ class jdk3/AllInstructions {
    L15
     LINENUMBER 77 L15
     LLOAD 10
-    LDC 5
+    LDC 5L
     LCMP
     IFEQ L16
     ICONST_1
@@ -389,12 +389,12 @@ class jdk3/AllInstructions {
     ILOAD 18
     IFEQ L19
     LLOAD 12
-    LDC 5
+    LDC 5L
     LADD
     GOTO L20
    L19
     LLOAD 12
-    LDC 5
+    LDC 5L
     LSUB
    L20
     LSTORE 0
@@ -403,12 +403,12 @@ class jdk3/AllInstructions {
     ILOAD 19
     IFEQ L22
     LLOAD 14
-    LDC 100
+    LDC 100L
     LMUL
     GOTO L23
    L22
     LLOAD 14
-    LDC 100
+    LDC 100L
     LDIV
    L23
     LSTORE 2
@@ -417,12 +417,12 @@ class jdk3/AllInstructions {
     ILOAD 20
     IFEQ L25
     LLOAD 16
-    LDC 10000
+    LDC 10000L
     LREM
     GOTO L26
    L25
     LLOAD 16
-    LDC -1
+    LDC -1L
     LXOR
    L26
     LSTORE 4
@@ -431,12 +431,12 @@ class jdk3/AllInstructions {
     ILOAD 21
     IFEQ L28
     LLOAD 0
-    LDC 1000000
+    LDC 1000000L
     LAND
     GOTO L29
    L28
     LLOAD 0
-    LDC 1000000
+    LDC 1000000L
     LOR
    L29
     LSTORE 6
@@ -534,7 +534,7 @@ class jdk3/AllInstructions {
    L0
     LINENUMBER 91 L0
     FLOAD 0
-    LDC -1.0
+    LDC -1.0F
     FCMPG
     IFGE L1
     ICONST_1
@@ -570,7 +570,7 @@ class jdk3/AllInstructions {
    L9
     LINENUMBER 94 L9
     FLOAD 3
-    LDC 3.0
+    LDC 3.0F
     FCMPL
     IFLT L10
     ICONST_1
@@ -582,7 +582,7 @@ class jdk3/AllInstructions {
    L12
     LINENUMBER 95 L12
     FLOAD 4
-    LDC 4.0
+    LDC 4.0F
     FCMPL
     IFNE L13
     ICONST_1
@@ -594,7 +594,7 @@ class jdk3/AllInstructions {
    L15
     LINENUMBER 96 L15
     FLOAD 5
-    LDC 5.0
+    LDC 5.0F
     FCMPL
     IFEQ L16
     ICONST_1
@@ -608,12 +608,12 @@ class jdk3/AllInstructions {
     ILOAD 9
     IFEQ L19
     FLOAD 6
-    LDC 5.0
+    LDC 5.0F
     FADD
     GOTO L20
    L19
     FLOAD 6
-    LDC 5.0
+    LDC 5.0F
     FSUB
    L20
     FSTORE 0
@@ -622,12 +622,12 @@ class jdk3/AllInstructions {
     ILOAD 10
     IFEQ L22
     FLOAD 7
-    LDC 100.0
+    LDC 100.0F
     FMUL
     GOTO L23
    L22
     FLOAD 7
-    LDC 100.0
+    LDC 100.0F
     FDIV
    L23
     FSTORE 1
@@ -636,7 +636,7 @@ class jdk3/AllInstructions {
     ILOAD 11
     IFEQ L25
     FLOAD 8
-    LDC 10000.0
+    LDC 10000.0F
     FREM
     GOTO L26
    L25
@@ -743,7 +743,7 @@ class jdk3/AllInstructions {
    L0
     LINENUMBER 119 L0
     DLOAD 0
-    LDC -1.0
+    LDC -1.0D
     DCMPG
     IFGE L1
     ICONST_1
@@ -767,7 +767,7 @@ class jdk3/AllInstructions {
    L6
     LINENUMBER 121 L6
     DLOAD 4
-    LDC 2.0
+    LDC 2.0D
     DCMPG
     IFGT L7
     ICONST_1
@@ -779,7 +779,7 @@ class jdk3/AllInstructions {
    L9
     LINENUMBER 122 L9
     DLOAD 6
-    LDC 3.0
+    LDC 3.0D
     DCMPL
     IFLT L10
     ICONST_1
@@ -791,7 +791,7 @@ class jdk3/AllInstructions {
    L12
     LINENUMBER 123 L12
     DLOAD 8
-    LDC 4.0
+    LDC 4.0D
     DCMPL
     IFNE L13
     ICONST_1
@@ -803,7 +803,7 @@ class jdk3/AllInstructions {
    L15
     LINENUMBER 124 L15
     DLOAD 10
-    LDC 5.0
+    LDC 5.0D
     DCMPL
     IFEQ L16
     ICONST_1
@@ -817,12 +817,12 @@ class jdk3/AllInstructions {
     ILOAD 18
     IFEQ L19
     DLOAD 12
-    LDC 5.0
+    LDC 5.0D
     DADD
     GOTO L20
    L19
     DLOAD 12
-    LDC 5.0
+    LDC 5.0D
     DSUB
    L20
     DSTORE 0
@@ -831,12 +831,12 @@ class jdk3/AllInstructions {
     ILOAD 19
     IFEQ L22
     DLOAD 14
-    LDC 100.0
+    LDC 100.0D
     DMUL
     GOTO L23
    L22
     DLOAD 14
-    LDC 100.0
+    LDC 100.0D
     DDIV
    L23
     DSTORE 2
@@ -845,7 +845,7 @@ class jdk3/AllInstructions {
     ILOAD 20
     IFEQ L25
     DLOAD 16
-    LDC 10000.0
+    LDC 10000.0D
     DREM
     GOTO L26
    L25
@@ -1639,7 +1639,7 @@ class jdk3/AllInstructions {
     MAXLOCALS = 1
 
   // access flags 0x1
-  public jsrAndRetInstructions(I)I throws java/lang/Exception 
+  public jsrAndRetInstructions(I)I throws java/lang/Exception
     TRYCATCHBLOCK L0 L1 L2 java/lang/Throwable
     TRYCATCHBLOCK L0 L3 L3 null
    L4
diff --git a/asm-util/src/test/resources/jdk3.AllStructures.txt b/asm-util/src/test/resources/jdk3.AllStructures.txt
index cd8cf5d5..d3b699eb 100644
--- a/asm-util/src/test/resources/jdk3.AllStructures.txt
+++ b/asm-util/src/test/resources/jdk3.AllStructures.txt
@@ -9,10 +9,10 @@ abstract class jdk3/AllStructures implements java/lang/Runnable java/lang/Clonea
   INNERCLASS jdk3/AllStructures$1 null null
 
   // access flags 0x1A
-  private final static Ljava/lang/String; UTF8 = "ࠀ耀"
+  private final static Ljava/lang/String; UTF8 = "\u0008\u0080\u0800\u8000"
 
   // access flags 0x1A
-  private final static J serialVersionUID = 123456
+  private final static J serialVersionUID = 123456L
 
   // access flags 0x1
   public I f0
@@ -190,7 +190,7 @@ abstract class jdk3/AllStructures implements java/lang/Runnable java/lang/Clonea
   private native nativeMethod()V
 
   // access flags 0x2
-  private anonymousInnerClass()Ljava/lang/Runnable; throws java/lang/Exception 
+  private anonymousInnerClass()Ljava/lang/Runnable; throws java/lang/Exception
    L0
     LINENUMBER 71 L0
     ALOAD 0
diff --git a/asm-util/src/test/resources/jdk5.AllInstructions.txt b/asm-util/src/test/resources/jdk5.AllInstructions.txt
index 94cb8a04..08447a52 100644
--- a/asm-util/src/test/resources/jdk5.AllInstructions.txt
+++ b/asm-util/src/test/resources/jdk5.AllInstructions.txt
@@ -341,7 +341,7 @@ class jdk5/AllInstructions {
    L0
     LINENUMBER 82 L0
     LLOAD 0
-    LDC -1
+    LDC -1L
     LCMP
     IFGE L1
     ICONST_1
@@ -365,7 +365,7 @@ class jdk5/AllInstructions {
    L6
     LINENUMBER 84 L6
     LLOAD 4
-    LDC 2
+    LDC 2L
     LCMP
     IFGT L7
     ICONST_1
@@ -377,7 +377,7 @@ class jdk5/AllInstructions {
    L9
     LINENUMBER 85 L9
     LLOAD 6
-    LDC 3
+    LDC 3L
     LCMP
     IFLT L10
     ICONST_1
@@ -389,7 +389,7 @@ class jdk5/AllInstructions {
    L12
     LINENUMBER 86 L12
     LLOAD 8
-    LDC 4
+    LDC 4L
     LCMP
     IFNE L13
     ICONST_1
@@ -401,7 +401,7 @@ class jdk5/AllInstructions {
    L15
     LINENUMBER 87 L15
     LLOAD 10
-    LDC 5
+    LDC 5L
     LCMP
     IFEQ L16
     ICONST_1
@@ -415,12 +415,12 @@ class jdk5/AllInstructions {
     ILOAD 18
     IFEQ L19
     LLOAD 12
-    LDC 5
+    LDC 5L
     LADD
     GOTO L20
    L19
     LLOAD 12
-    LDC 5
+    LDC 5L
     LSUB
    L20
     LSTORE 0
@@ -429,12 +429,12 @@ class jdk5/AllInstructions {
     ILOAD 19
     IFEQ L22
     LLOAD 14
-    LDC 100
+    LDC 100L
     LMUL
     GOTO L23
    L22
     LLOAD 14
-    LDC 100
+    LDC 100L
     LDIV
    L23
     LSTORE 2
@@ -443,12 +443,12 @@ class jdk5/AllInstructions {
     ILOAD 20
     IFEQ L25
     LLOAD 16
-    LDC 10000
+    LDC 10000L
     LREM
     GOTO L26
    L25
     LLOAD 16
-    LDC -1
+    LDC -1L
     LXOR
    L26
     LSTORE 4
@@ -457,12 +457,12 @@ class jdk5/AllInstructions {
     ILOAD 21
     IFEQ L28
     LLOAD 0
-    LDC 1000000
+    LDC 1000000L
     LAND
     GOTO L29
    L28
     LLOAD 0
-    LDC 1000000
+    LDC 1000000L
     LOR
    L29
     LSTORE 6
@@ -560,7 +560,7 @@ class jdk5/AllInstructions {
    L0
     LINENUMBER 101 L0
     FLOAD 0
-    LDC -1.0
+    LDC -1.0F
     FCMPG
     IFGE L1
     ICONST_1
@@ -596,7 +596,7 @@ class jdk5/AllInstructions {
    L9
     LINENUMBER 104 L9
     FLOAD 3
-    LDC 3.0
+    LDC 3.0F
     FCMPL
     IFLT L10
     ICONST_1
@@ -608,7 +608,7 @@ class jdk5/AllInstructions {
    L12
     LINENUMBER 105 L12
     FLOAD 4
-    LDC 4.0
+    LDC 4.0F
     FCMPL
     IFNE L13
     ICONST_1
@@ -620,7 +620,7 @@ class jdk5/AllInstructions {
    L15
     LINENUMBER 106 L15
     FLOAD 5
-    LDC 5.0
+    LDC 5.0F
     FCMPL
     IFEQ L16
     ICONST_1
@@ -634,12 +634,12 @@ class jdk5/AllInstructions {
     ILOAD 9
     IFEQ L19
     FLOAD 6
-    LDC 5.0
+    LDC 5.0F
     FADD
     GOTO L20
    L19
     FLOAD 6
-    LDC 5.0
+    LDC 5.0F
     FSUB
    L20
     FSTORE 0
@@ -648,12 +648,12 @@ class jdk5/AllInstructions {
     ILOAD 10
     IFEQ L22
     FLOAD 7
-    LDC 100.0
+    LDC 100.0F
     FMUL
     GOTO L23
    L22
     FLOAD 7
-    LDC 100.0
+    LDC 100.0F
     FDIV
    L23
     FSTORE 1
@@ -662,7 +662,7 @@ class jdk5/AllInstructions {
     ILOAD 11
     IFEQ L25
     FLOAD 8
-    LDC 10000.0
+    LDC 10000.0F
     FREM
     GOTO L26
    L25
@@ -769,7 +769,7 @@ class jdk5/AllInstructions {
    L0
     LINENUMBER 129 L0
     DLOAD 0
-    LDC -1.0
+    LDC -1.0D
     DCMPG
     IFGE L1
     ICONST_1
@@ -793,7 +793,7 @@ class jdk5/AllInstructions {
    L6
     LINENUMBER 131 L6
     DLOAD 4
-    LDC 2.0
+    LDC 2.0D
     DCMPG
     IFGT L7
     ICONST_1
@@ -805,7 +805,7 @@ class jdk5/AllInstructions {
    L9
     LINENUMBER 132 L9
     DLOAD 6
-    LDC 3.0
+    LDC 3.0D
     DCMPL
     IFLT L10
     ICONST_1
@@ -817,7 +817,7 @@ class jdk5/AllInstructions {
    L12
     LINENUMBER 133 L12
     DLOAD 8
-    LDC 4.0
+    LDC 4.0D
     DCMPL
     IFNE L13
     ICONST_1
@@ -829,7 +829,7 @@ class jdk5/AllInstructions {
    L15
     LINENUMBER 134 L15
     DLOAD 10
-    LDC 5.0
+    LDC 5.0D
     DCMPL
     IFEQ L16
     ICONST_1
@@ -843,12 +843,12 @@ class jdk5/AllInstructions {
     ILOAD 18
     IFEQ L19
     DLOAD 12
-    LDC 5.0
+    LDC 5.0D
     DADD
     GOTO L20
    L19
     DLOAD 12
-    LDC 5.0
+    LDC 5.0D
     DSUB
    L20
     DSTORE 0
@@ -857,12 +857,12 @@ class jdk5/AllInstructions {
     ILOAD 19
     IFEQ L22
     DLOAD 14
-    LDC 100.0
+    LDC 100.0D
     DMUL
     GOTO L23
    L22
     DLOAD 14
-    LDC 100.0
+    LDC 100.0D
     DDIV
    L23
     DSTORE 2
@@ -871,7 +871,7 @@ class jdk5/AllInstructions {
     ILOAD 20
     IFEQ L25
     DLOAD 16
-    LDC 10000.0
+    LDC 10000.0D
     DREM
     GOTO L26
    L25
@@ -1612,7 +1612,7 @@ class jdk5/AllInstructions {
     MAXLOCALS = 1
 
   // access flags 0x1
-  public jsrAndRetInstructions(I)I throws java/lang/Exception 
+  public jsrAndRetInstructions(I)I throws java/lang/Exception
     TRYCATCHBLOCK L0 L1 L2 java/lang/Throwable
     TRYCATCHBLOCK L0 L1 L3 null
     TRYCATCHBLOCK L2 L4 L3 null
diff --git a/asm-util/src/test/resources/jdk5.AllStructures.txt b/asm-util/src/test/resources/jdk5.AllStructures.txt
index 24387ab1..fe23e3bc 100644
--- a/asm-util/src/test/resources/jdk5.AllStructures.txt
+++ b/asm-util/src/test/resources/jdk5.AllStructures.txt
@@ -139,7 +139,7 @@ class jdk5/AllStructures implements java/util/Comparator {
   // access flags 0x0
   // signature <U0:Ljava/lang/Object;U1:Ljava/lang/Number;U2::Ljava/util/List<Ljava/lang/String;>;U3::Ljava/util/List<*>;U4::Ljava/util/List<+Ljava/lang/Number;>;U5::Ljava/util/List<-Ljava/lang/Number;>;U6:Ljava/lang/Number;:Ljava/lang/Runnable;:Ljava/lang/Cloneable;U7:Ljava/lang/Exception;U8:Ljava/io/IOException;>(Ljava/util/List<TU0;>;Ljava/util/List<[TU1;>;Ljava/util/List<[[TU2;>;Ljava/util/List<TU3;>;Ljava/util/List<TU4;>;Ljava/util/List<TU5;>;Ljava/util/List<TU6;>;Ljdk5/AllStructures<TU0;TU1;TU2;TU3;TU4;TU5;TU6;>.InnerClass;Ljdk5/AllStructures<TU0;TU1;TU2;TU3;TU4;TU5;TU6;>.GenericInnerClass<TU1;>;)V^TU7;^TU8;
   // declaration: void genericMethod<U0, U1 extends java.lang.Number, U2 extends java.util.List<java.lang.String>, U3 extends java.util.List<?>, U4 extends java.util.List<? extends java.lang.Number>, U5 extends java.util.List<? super java.lang.Number>, U6 extends java.lang.Number extends java.lang.Runnable, java.lang.Cloneable, U7 extends java.lang.Exception, U8 extends java.io.IOException>(java.util.List<U0>, java.util.List<U1[]>, java.util.List<U2[][]>, java.util.List<U3>, java.util.List<U4>, java.util.List<U5>, java.util.List<U6>, jdk5.AllStructures<U0, U1, U2, U3, U4, U5, U6>.InnerClass, jdk5.AllStructures<U0, U1, U2, U3, U4, U5, U6>.GenericInnerClass<U1>) throws U7, U8
-  genericMethod(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljdk5/AllStructures$InnerClass;Ljdk5/AllStructures$GenericInnerClass;)V throws java/lang/Exception java/io/IOException 
+  genericMethod(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljdk5/AllStructures$InnerClass;Ljdk5/AllStructures$GenericInnerClass;)V throws java/lang/Exception java/io/IOException
    L0
     LINENUMBER 130 L0
     RETURN
diff --git a/asm-util/src/test/resources/jdk8.AllStructures.txt b/asm-util/src/test/resources/jdk8.AllStructures.txt
index a6a11ed2..d4dd6cf7 100644
--- a/asm-util/src/test/resources/jdk8.AllStructures.txt
+++ b/asm-util/src/test/resources/jdk8.AllStructures.txt
@@ -101,7 +101,7 @@ public abstract class jdk8/AllStructures extends java/util/HashMap implements ja
   // access flags 0x1
   // signature <V0:TU0;V1:TU1;>(TV0;TV1;Ljava/util/Map<+TV0;+TV1;>;)Ljava/util/Map<+TV0;+TV1;>;
   // declaration: java.util.Map<? extends V0, ? extends V1> m<V0 extends U0, V1 extends U1>(V0, V1, java.util.Map<? extends V0, ? extends V1>)
-  public m(Ljava/lang/Object;Ljava/util/List;Ljava/util/Map;)Ljava/util/Map; throws java/lang/IllegalStateException java/lang/IllegalArgumentException 
+  public m(Ljava/lang/Object;Ljava/util/List;Ljava/util/Map;)Ljava/util/Map; throws java/lang/IllegalStateException java/lang/IllegalArgumentException
     // parameter  p0
     // parameter  p1
     // parameter  p2
@@ -253,7 +253,7 @@ public abstract class jdk8/AllStructures extends java/util/HashMap implements ja
     MAXLOCALS = 1
 
   // access flags 0x2
-  private anonymousInnerClass()Ljava/lang/Runnable; throws java/lang/Exception 
+  private anonymousInnerClass()Ljava/lang/Runnable; throws java/lang/Exception
    L0
     LINENUMBER 130 L0
     NEW jdk8/AllStructures$1
diff --git a/asm/src/main/java/org/objectweb/asm/AnnotationWriter.java b/asm/src/main/java/org/objectweb/asm/AnnotationWriter.java
index b4538488..38693032 100644
--- a/asm/src/main/java/org/objectweb/asm/AnnotationWriter.java
+++ b/asm/src/main/java/org/objectweb/asm/AnnotationWriter.java
@@ -144,7 +144,7 @@ final class AnnotationWriter extends AnnotationVisitor {
     // Write type_index and reserve space for num_element_value_pairs.
     annotation.putShort(symbolTable.addConstantUtf8(descriptor)).putShort(0);
     return new AnnotationWriter(
-        symbolTable, /* useNamedValues = */ true, annotation, previousAnnotation);
+        symbolTable, /* useNamedValues= */ true, annotation, previousAnnotation);
   }
 
   /**
@@ -179,7 +179,7 @@ final class AnnotationWriter extends AnnotationVisitor {
     // Write type_index and reserve space for num_element_value_pairs.
     typeAnnotation.putShort(symbolTable.addConstantUtf8(descriptor)).putShort(0);
     return new AnnotationWriter(
-        symbolTable, /* useNamedValues = */ true, typeAnnotation, previousAnnotation);
+        symbolTable, /* useNamedValues= */ true, typeAnnotation, previousAnnotation);
   }
 
   // -----------------------------------------------------------------------------------------------
@@ -284,7 +284,7 @@ final class AnnotationWriter extends AnnotationVisitor {
     }
     // Write tag and type_index, and reserve 2 bytes for num_element_value_pairs.
     annotation.put12('@', symbolTable.addConstantUtf8(descriptor)).putShort(0);
-    return new AnnotationWriter(symbolTable, /* useNamedValues = */ true, annotation, null);
+    return new AnnotationWriter(symbolTable, /* useNamedValues= */ true, annotation, null);
   }
 
   @Override
@@ -303,7 +303,7 @@ final class AnnotationWriter extends AnnotationVisitor {
     // visit the array elements. Its num_element_value_pairs will correspond to the number of array
     // elements and will be stored in what is in fact num_values.
     annotation.put12('[', 0);
-    return new AnnotationWriter(symbolTable, /* useNamedValues = */ false, annotation, null);
+    return new AnnotationWriter(symbolTable, /* useNamedValues= */ false, annotation, null);
   }
 
   @Override
diff --git a/asm/src/main/java/org/objectweb/asm/Attribute.java b/asm/src/main/java/org/objectweb/asm/Attribute.java
index 3d73dc68..aa34a57c 100644
--- a/asm/src/main/java/org/objectweb/asm/Attribute.java
+++ b/asm/src/main/java/org/objectweb/asm/Attribute.java
@@ -44,11 +44,11 @@ public class Attribute {
   public final String type;
 
   /**
-   * The raw content of this attribute, only used for unknown attributes (see {@link #isUnknown()}).
-   * The 6 header bytes of the attribute (attribute_name_index and attribute_length) are <i>not</i>
-   * included.
+   * The raw content of this attribute, as returned by {@link
+   * #write(ClassWriter,byte[],int,int,int)}. The 6 header bytes of the attribute
+   * (attribute_name_index and attribute_length) are <i>not</i> included.
    */
-  private byte[] content;
+  private ByteVector cachedContent;
 
   /**
    * The next attribute in this attribute list (Attribute instances can be linked via this field to
@@ -93,7 +93,9 @@ public class Attribute {
    *
    * @return the labels corresponding to this attribute, or {@literal null} if this attribute is not
    *     a Code attribute that contains labels.
+   * @deprecated no longer used by ASM.
    */
+  @Deprecated
   protected Label[] getLabels() {
     return new Label[0];
   }
@@ -115,7 +117,9 @@ public class Attribute {
    *     attribute header bytes (attribute_name_index and attribute_length) are not taken into
    *     account here.
    * @param labels the labels of the method's code, or {@literal null} if the attribute to be read
-   *     is not a Code attribute.
+   *     is not a Code attribute. Labels defined in the attribute must be created and added to this
+   *     array, if not already present, by calling the {@link #readLabel} method (do not create
+   *     {@link Label} instances directly).
    * @return a <i>new</i> {@link Attribute} object corresponding to the specified bytes.
    */
   protected Attribute read(
@@ -126,16 +130,99 @@ public class Attribute {
       final int codeAttributeOffset,
       final Label[] labels) {
     Attribute attribute = new Attribute(type);
-    attribute.content = new byte[length];
-    System.arraycopy(classReader.classFileBuffer, offset, attribute.content, 0, length);
+    attribute.cachedContent = new ByteVector(classReader.readBytes(offset, length));
     return attribute;
   }
 
+  /**
+   * Reads an attribute with the same {@link #type} as the given attribute. This method returns a
+   * new {@link Attribute} object, corresponding to the 'length' bytes starting at 'offset', in the
+   * given ClassReader.
+   *
+   * @param attribute The attribute prototype that is used for reading.
+   * @param classReader the class that contains the attribute to be read.
+   * @param offset index of the first byte of the attribute's content in {@link ClassReader}. The 6
+   *     attribute header bytes (attribute_name_index and attribute_length) are not taken into
+   *     account here.
+   * @param length the length of the attribute's content (excluding the 6 attribute header bytes).
+   * @param charBuffer the buffer to be used to call the ClassReader methods requiring a
+   *     'charBuffer' parameter.
+   * @param codeAttributeOffset index of the first byte of content of the enclosing Code attribute
+   *     in {@link ClassReader}, or -1 if the attribute to be read is not a Code attribute. The 6
+   *     attribute header bytes (attribute_name_index and attribute_length) are not taken into
+   *     account here.
+   * @param labels the labels of the method's code, or {@literal null} if the attribute to be read
+   *     is not a Code attribute. Labels defined in the attribute are added to this array, if not
+   *     already present.
+   * @return a new {@link Attribute} object corresponding to the specified bytes.
+   */
+  public static Attribute read(
+      final Attribute attribute,
+      final ClassReader classReader,
+      final int offset,
+      final int length,
+      final char[] charBuffer,
+      final int codeAttributeOffset,
+      final Label[] labels) {
+    return attribute.read(classReader, offset, length, charBuffer, codeAttributeOffset, labels);
+  }
+
+  /**
+   * Returns the label corresponding to the given bytecode offset by calling {@link
+   * ClassReader#readLabel}. This creates and adds the label to the given array if it is not already
+   * present. Note that this created label may be a {@link Label} subclass instance, if the given
+   * ClassReader overrides {@link ClassReader#readLabel}. Hence {@link #read(ClassReader, int, int,
+   * char[], int, Label[])} must not manually create {@link Label} instances.
+   *
+   * @param bytecodeOffset a bytecode offset in a method.
+   * @param labels the already created labels, indexed by their offset. If a label already exists
+   *     for bytecodeOffset this method does not create a new one. Otherwise it stores the new label
+   *     in this array.
+   * @return a label for the given bytecode offset.
+   */
+  public static Label readLabel(
+      final ClassReader classReader, final int bytecodeOffset, final Label[] labels) {
+    return classReader.readLabel(bytecodeOffset, labels);
+  }
+
+  /**
+   * Calls {@link #write(ClassWriter,byte[],int,int,int)} if it has not already been called and
+   * returns its result or its (cached) previous result.
+   *
+   * @param classWriter the class to which this attribute must be added. This parameter can be used
+   *     to add the items that corresponds to this attribute to the constant pool of this class.
+   * @param code the bytecode of the method corresponding to this Code attribute, or {@literal null}
+   *     if this attribute is not a Code attribute. Corresponds to the 'code' field of the Code
+   *     attribute.
+   * @param codeLength the length of the bytecode of the method corresponding to this code
+   *     attribute, or 0 if this attribute is not a Code attribute. Corresponds to the 'code_length'
+   *     field of the Code attribute.
+   * @param maxStack the maximum stack size of the method corresponding to this Code attribute, or
+   *     -1 if this attribute is not a Code attribute.
+   * @param maxLocals the maximum number of local variables of the method corresponding to this code
+   *     attribute, or -1 if this attribute is not a Code attribute.
+   * @return the byte array form of this attribute.
+   */
+  private ByteVector maybeWrite(
+      final ClassWriter classWriter,
+      final byte[] code,
+      final int codeLength,
+      final int maxStack,
+      final int maxLocals) {
+    if (cachedContent == null) {
+      cachedContent = write(classWriter, code, codeLength, maxStack, maxLocals);
+    }
+    return cachedContent;
+  }
+
   /**
    * Returns the byte array form of the content of this attribute. The 6 header bytes
    * (attribute_name_index and attribute_length) must <i>not</i> be added in the returned
    * ByteVector.
    *
+   * <p>This method is only invoked once to compute the binary form of this attribute. Subsequent
+   * changes to the attribute after it was written for the first time will not be considered.
+   *
    * @param classWriter the class to which this attribute must be added. This parameter can be used
    *     to add the items that corresponds to this attribute to the constant pool of this class.
    * @param code the bytecode of the method corresponding to this Code attribute, or {@literal null}
@@ -156,7 +243,39 @@ public class Attribute {
       final int codeLength,
       final int maxStack,
       final int maxLocals) {
-    return new ByteVector(content);
+    return cachedContent;
+  }
+
+  /**
+   * Returns the byte array form of the content of the given attribute. The 6 header bytes
+   * (attribute_name_index and attribute_length) are <i>not</i> added in the returned byte array.
+   *
+   * @param attribute The attribute that should be written.
+   * @param classWriter the class to which this attribute must be added. This parameter can be used
+   *     to add the items that corresponds to this attribute to the constant pool of this class.
+   * @param code the bytecode of the method corresponding to this Code attribute, or {@literal null}
+   *     if this attribute is not a Code attribute. Corresponds to the 'code' field of the Code
+   *     attribute.
+   * @param codeLength the length of the bytecode of the method corresponding to this code
+   *     attribute, or 0 if this attribute is not a Code attribute. Corresponds to the 'code_length'
+   *     field of the Code attribute.
+   * @param maxStack the maximum stack size of the method corresponding to this Code attribute, or
+   *     -1 if this attribute is not a Code attribute.
+   * @param maxLocals the maximum number of local variables of the method corresponding to this code
+   *     attribute, or -1 if this attribute is not a Code attribute.
+   * @return the byte array form of this attribute.
+   */
+  public static byte[] write(
+      final Attribute attribute,
+      final ClassWriter classWriter,
+      final byte[] code,
+      final int codeLength,
+      final int maxStack,
+      final int maxLocals) {
+    ByteVector content = attribute.maybeWrite(classWriter, code, codeLength, maxStack, maxLocals);
+    byte[] result = new byte[content.length];
+    System.arraycopy(content.data, 0, result, 0, content.length);
+    return result;
   }
 
   /**
@@ -221,7 +340,7 @@ public class Attribute {
     Attribute attribute = this;
     while (attribute != null) {
       symbolTable.addConstantUtf8(attribute.type);
-      size += 6 + attribute.write(classWriter, code, codeLength, maxStack, maxLocals).length;
+      size += 6 + attribute.maybeWrite(classWriter, code, codeLength, maxStack, maxLocals).length;
       attribute = attribute.nextAttribute;
     }
     return size;
@@ -308,7 +427,7 @@ public class Attribute {
     Attribute attribute = this;
     while (attribute != null) {
       ByteVector attributeContent =
-          attribute.write(classWriter, code, codeLength, maxStack, maxLocals);
+          attribute.maybeWrite(classWriter, code, codeLength, maxStack, maxLocals);
       // Put attribute_name_index and attribute_length.
       output.putShort(symbolTable.addConstantUtf8(attribute.type)).putInt(attributeContent.length);
       output.putByteArray(attributeContent.data, 0, attributeContent.length);
diff --git a/asm/src/main/java/org/objectweb/asm/ClassReader.java b/asm/src/main/java/org/objectweb/asm/ClassReader.java
index 8c8e7180..5f66ed2b 100644
--- a/asm/src/main/java/org/objectweb/asm/ClassReader.java
+++ b/asm/src/main/java/org/objectweb/asm/ClassReader.java
@@ -177,7 +177,7 @@ public class ClassReader {
       final byte[] classFileBuffer,
       final int classFileOffset,
       final int classFileLength) { // NOPMD(UnusedFormalParameter) used for backward compatibility.
-    this(classFileBuffer, classFileOffset, /* checkClassVersion = */ true);
+    this(classFileBuffer, classFileOffset, /* checkClassVersion= */ true);
   }
 
   /**
@@ -195,7 +195,7 @@ public class ClassReader {
     this.b = classFileBuffer;
     // Check the class' major_version. This field is after the magic and minor_version fields, which
     // use 4 and 2 bytes respectively.
-    if (checkClassVersion && readShort(classFileOffset + 6) > Opcodes.V22) {
+    if (checkClassVersion && readShort(classFileOffset + 6) > Opcodes.V25) {
       throw new IllegalArgumentException(
           "Unsupported class file major version " + readShort(classFileOffset + 6));
     }
@@ -607,9 +607,9 @@ public class ClassReader {
         // Parse num_element_value_pairs and element_value_pairs and visit these values.
         currentAnnotationOffset =
             readElementValues(
-                classVisitor.visitAnnotation(annotationDescriptor, /* visible = */ true),
+                classVisitor.visitAnnotation(annotationDescriptor, /* visible= */ true),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -625,9 +625,9 @@ public class ClassReader {
         // Parse num_element_value_pairs and element_value_pairs and visit these values.
         currentAnnotationOffset =
             readElementValues(
-                classVisitor.visitAnnotation(annotationDescriptor, /* visible = */ false),
+                classVisitor.visitAnnotation(annotationDescriptor, /* visible= */ false),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -649,9 +649,9 @@ public class ClassReader {
                     context.currentTypeAnnotationTarget,
                     context.currentTypeAnnotationTargetPath,
                     annotationDescriptor,
-                    /* visible = */ true),
+                    /* visible= */ true),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -673,9 +673,9 @@ public class ClassReader {
                     context.currentTypeAnnotationTarget,
                     context.currentTypeAnnotationTargetPath,
                     annotationDescriptor,
-                    /* visible = */ false),
+                    /* visible= */ false),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -967,9 +967,9 @@ public class ClassReader {
         // Parse num_element_value_pairs and element_value_pairs and visit these values.
         currentAnnotationOffset =
             readElementValues(
-                recordComponentVisitor.visitAnnotation(annotationDescriptor, /* visible = */ true),
+                recordComponentVisitor.visitAnnotation(annotationDescriptor, /* visible= */ true),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -985,9 +985,9 @@ public class ClassReader {
         // Parse num_element_value_pairs and element_value_pairs and visit these values.
         currentAnnotationOffset =
             readElementValues(
-                recordComponentVisitor.visitAnnotation(annotationDescriptor, /* visible = */ false),
+                recordComponentVisitor.visitAnnotation(annotationDescriptor, /* visible= */ false),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1009,9 +1009,9 @@ public class ClassReader {
                     context.currentTypeAnnotationTarget,
                     context.currentTypeAnnotationTargetPath,
                     annotationDescriptor,
-                    /* visible = */ true),
+                    /* visible= */ true),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1033,9 +1033,9 @@ public class ClassReader {
                     context.currentTypeAnnotationTarget,
                     context.currentTypeAnnotationTargetPath,
                     annotationDescriptor,
-                    /* visible = */ false),
+                    /* visible= */ false),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1151,9 +1151,9 @@ public class ClassReader {
         // Parse num_element_value_pairs and element_value_pairs and visit these values.
         currentAnnotationOffset =
             readElementValues(
-                fieldVisitor.visitAnnotation(annotationDescriptor, /* visible = */ true),
+                fieldVisitor.visitAnnotation(annotationDescriptor, /* visible= */ true),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1169,9 +1169,9 @@ public class ClassReader {
         // Parse num_element_value_pairs and element_value_pairs and visit these values.
         currentAnnotationOffset =
             readElementValues(
-                fieldVisitor.visitAnnotation(annotationDescriptor, /* visible = */ false),
+                fieldVisitor.visitAnnotation(annotationDescriptor, /* visible= */ false),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1193,9 +1193,9 @@ public class ClassReader {
                     context.currentTypeAnnotationTarget,
                     context.currentTypeAnnotationTargetPath,
                     annotationDescriptor,
-                    /* visible = */ true),
+                    /* visible= */ true),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1217,9 +1217,9 @@ public class ClassReader {
                     context.currentTypeAnnotationTarget,
                     context.currentTypeAnnotationTargetPath,
                     annotationDescriptor,
-                    /* visible = */ false),
+                    /* visible= */ false),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1412,9 +1412,9 @@ public class ClassReader {
         // Parse num_element_value_pairs and element_value_pairs and visit these values.
         currentAnnotationOffset =
             readElementValues(
-                methodVisitor.visitAnnotation(annotationDescriptor, /* visible = */ true),
+                methodVisitor.visitAnnotation(annotationDescriptor, /* visible= */ true),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1430,9 +1430,9 @@ public class ClassReader {
         // Parse num_element_value_pairs and element_value_pairs and visit these values.
         currentAnnotationOffset =
             readElementValues(
-                methodVisitor.visitAnnotation(annotationDescriptor, /* visible = */ false),
+                methodVisitor.visitAnnotation(annotationDescriptor, /* visible= */ false),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1454,9 +1454,9 @@ public class ClassReader {
                     context.currentTypeAnnotationTarget,
                     context.currentTypeAnnotationTargetPath,
                     annotationDescriptor,
-                    /* visible = */ true),
+                    /* visible= */ true),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1478,9 +1478,9 @@ public class ClassReader {
                     context.currentTypeAnnotationTarget,
                     context.currentTypeAnnotationTargetPath,
                     annotationDescriptor,
-                    /* visible = */ false),
+                    /* visible= */ false),
                 currentAnnotationOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -1488,16 +1488,13 @@ public class ClassReader {
     // Visit the RuntimeVisibleParameterAnnotations attribute.
     if (runtimeVisibleParameterAnnotationsOffset != 0) {
       readParameterAnnotations(
-          methodVisitor, context, runtimeVisibleParameterAnnotationsOffset, /* visible = */ true);
+          methodVisitor, context, runtimeVisibleParameterAnnotationsOffset, /* visible= */ true);
     }
 
     // Visit the RuntimeInvisibleParameterAnnotations attribute.
     if (runtimeInvisibleParameterAnnotationsOffset != 0) {
       readParameterAnnotations(
-          methodVisitor,
-          context,
-          runtimeInvisibleParameterAnnotationsOffset,
-          /* visible = */ false);
+          methodVisitor, context, runtimeInvisibleParameterAnnotationsOffset, /* visible= */ false);
     }
 
     // Visit the non standard attributes.
@@ -1926,7 +1923,7 @@ public class ClassReader {
         }
       } else if (Constants.RUNTIME_VISIBLE_TYPE_ANNOTATIONS.equals(attributeName)) {
         visibleTypeAnnotationOffsets =
-            readTypeAnnotations(methodVisitor, context, currentOffset, /* visible = */ true);
+            readTypeAnnotations(methodVisitor, context, currentOffset, /* visible= */ true);
         // Here we do not extract the labels corresponding to the attribute content. This would
         // require a full parsing of the attribute, which would need to be repeated when parsing
         // the bytecode instructions (see below). Instead, the content of the attribute is read one
@@ -1935,7 +1932,7 @@ public class ClassReader {
         // time. This assumes that type annotations are ordered by increasing bytecode offset.
       } else if (Constants.RUNTIME_INVISIBLE_TYPE_ANNOTATIONS.equals(attributeName)) {
         invisibleTypeAnnotationOffsets =
-            readTypeAnnotations(methodVisitor, context, currentOffset, /* visible = */ false);
+            readTypeAnnotations(methodVisitor, context, currentOffset, /* visible= */ false);
         // Same comment as above for the RuntimeVisibleTypeAnnotations attribute.
       } else if (Constants.STACK_MAP_TABLE.equals(attributeName)) {
         if ((context.parsingOptions & SKIP_FRAMES) == 0) {
@@ -2517,9 +2514,9 @@ public class ClassReader {
                   context.currentTypeAnnotationTarget,
                   context.currentTypeAnnotationTargetPath,
                   annotationDescriptor,
-                  /* visible = */ true),
+                  /* visible= */ true),
               currentAnnotationOffset,
-              /* named = */ true,
+              /* named= */ true,
               charBuffer);
         }
         currentVisibleTypeAnnotationBytecodeOffset =
@@ -2545,9 +2542,9 @@ public class ClassReader {
                   context.currentTypeAnnotationTarget,
                   context.currentTypeAnnotationTargetPath,
                   annotationDescriptor,
-                  /* visible = */ false),
+                  /* visible= */ false),
               currentAnnotationOffset,
-              /* named = */ true,
+              /* named= */ true,
               charBuffer);
         }
         currentInvisibleTypeAnnotationBytecodeOffset =
@@ -2618,9 +2615,9 @@ public class ClassReader {
                   context.currentLocalVariableAnnotationRangeEnds,
                   context.currentLocalVariableAnnotationRangeIndices,
                   annotationDescriptor,
-                  /* visible = */ true),
+                  /* visible= */ true),
               currentOffset,
-              /* named = */ true,
+              /* named= */ true,
               charBuffer);
         }
       }
@@ -2646,9 +2643,9 @@ public class ClassReader {
                   context.currentLocalVariableAnnotationRangeEnds,
                   context.currentLocalVariableAnnotationRangeIndices,
                   annotationDescriptor,
-                  /* visible = */ false),
+                  /* visible= */ false),
               currentOffset,
-              /* named = */ true,
+              /* named= */ true,
               charBuffer);
         }
       }
@@ -2821,7 +2818,7 @@ public class ClassReader {
                 methodVisitor.visitTryCatchAnnotation(
                     targetType & 0xFFFFFF00, path, annotationDescriptor, visible),
                 currentOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       } else {
         // We don't want to visit the other target_type annotations, so we just skip them (which
@@ -2832,7 +2829,7 @@ public class ClassReader {
         // with a null AnnotationVisitor).
         currentOffset =
             readElementValues(
-                /* annotationVisitor = */ null, currentOffset, /* named = */ true, charBuffer);
+                /* annotationVisitor= */ null, currentOffset, /* named= */ true, charBuffer);
       }
     }
     return typeAnnotationsOffsets;
@@ -2972,7 +2969,7 @@ public class ClassReader {
             readElementValues(
                 methodVisitor.visitParameterAnnotation(i, annotationDescriptor, visible),
                 currentOffset,
-                /* named = */ true,
+                /* named= */ true,
                 charBuffer);
       }
     }
@@ -3042,9 +3039,9 @@ public class ClassReader {
         case 'e': // enum_const_value
           return currentOffset + 5;
         case '@': // annotation_value
-          return readElementValues(null, currentOffset + 3, /* named = */ true, charBuffer);
+          return readElementValues(null, currentOffset + 3, /* named= */ true, charBuffer);
         case '[': // array_value
-          return readElementValues(null, currentOffset + 1, /* named = */ false, charBuffer);
+          return readElementValues(null, currentOffset + 1, /* named= */ false, charBuffer);
         default:
           return currentOffset + 3;
       }
@@ -3112,7 +3109,7 @@ public class ClassReader {
           return readElementValues(
               annotationVisitor.visitArray(elementName),
               currentOffset - 2,
-              /* named = */ false,
+              /* named= */ false,
               charBuffer);
         }
         switch (classFileBuffer[currentOffset] & 0xFF) {
@@ -3189,7 +3186,7 @@ public class ClassReader {
                 readElementValues(
                     annotationVisitor.visitArray(elementName),
                     currentOffset - 2,
-                    /* named = */ false,
+                    /* named= */ false,
                     charBuffer);
             break;
         }
@@ -3600,6 +3597,20 @@ public class ClassReader {
     return classFileBuffer[offset] & 0xFF;
   }
 
+  /**
+   * Reads several bytes in this {@link ClassReader}. <i>This method is intended for {@link
+   * Attribute} sub classes, and is normally not needed by class generators or adapters.</i>
+   *
+   * @param offset the start offset of the bytes to be read in this {@link ClassReader}.
+   * @param length the number of bytes to read.
+   * @return the read bytes.
+   */
+  public byte[] readBytes(final int offset, final int length) {
+    byte[] result = new byte[length];
+    System.arraycopy(classFileBuffer, offset, result, 0, length);
+    return result;
+  }
+
   /**
    * Reads an unsigned short value in this {@link ClassReader}. <i>This method is intended for
    * {@link Attribute} sub classes, and is normally not needed by class generators or adapters.</i>
diff --git a/asm/src/main/java/org/objectweb/asm/ClassWriter.java b/asm/src/main/java/org/objectweb/asm/ClassWriter.java
index fcc42a2b..eeff8130 100644
--- a/asm/src/main/java/org/objectweb/asm/ClassWriter.java
+++ b/asm/src/main/java/org/objectweb/asm/ClassWriter.java
@@ -264,13 +264,7 @@ public class ClassWriter extends ClassVisitor {
     super(/* latest api = */ Opcodes.ASM9);
     this.flags = flags;
     symbolTable = classReader == null ? new SymbolTable(this) : new SymbolTable(this, classReader);
-    if ((flags & COMPUTE_FRAMES) != 0) {
-      compute = MethodWriter.COMPUTE_ALL_FRAMES;
-    } else if ((flags & COMPUTE_MAXS) != 0) {
-      compute = MethodWriter.COMPUTE_MAX_STACK_AND_LOCAL;
-    } else {
-      compute = MethodWriter.COMPUTE_NOTHING;
-    }
+    setFlags(flags);
   }
 
   // -----------------------------------------------------------------------------------------------
@@ -774,7 +768,7 @@ public class ClassWriter extends ClassVisitor {
     lastRecordComponent = null;
     firstAttribute = null;
     compute = hasFrames ? MethodWriter.COMPUTE_INSERTED_FRAMES : MethodWriter.COMPUTE_NOTHING;
-    new ClassReader(classFile, 0, /* checkClassVersion = */ false)
+    new ClassReader(classFile, 0, /* checkClassVersion= */ false)
         .accept(
             this,
             attributes,
@@ -1020,6 +1014,28 @@ public class ClassWriter extends ClassVisitor {
     return symbolTable.addConstantNameAndType(name, descriptor);
   }
 
+  /**
+   * Changes the computation strategy of method properties like max stack size, max number of local
+   * variables, and frames.
+   *
+   * <p><b>WARNING</b>: {@link #setFlags(int)} method changes the behavior of new method visitors
+   * returned from {@link #visitMethod(int, String, String, String, String[])}. The behavior will be
+   * changed only after the next method visitor is returned. All the previously returned method
+   * visitors keep their previous behavior.
+   *
+   * @param flags option flags that can be used to modify the default behavior of this class. Must
+   *     be zero or more of {@link #COMPUTE_MAXS} and {@link #COMPUTE_FRAMES}.
+   */
+  public final void setFlags(final int flags) {
+    if ((flags & ClassWriter.COMPUTE_FRAMES) != 0) {
+      compute = MethodWriter.COMPUTE_ALL_FRAMES;
+    } else if ((flags & ClassWriter.COMPUTE_MAXS) != 0) {
+      compute = MethodWriter.COMPUTE_MAX_STACK_AND_LOCAL;
+    } else {
+      compute = MethodWriter.COMPUTE_NOTHING;
+    }
+  }
+
   // -----------------------------------------------------------------------------------------------
   // Default method to compute common super classes when computing stack map frames
   // -----------------------------------------------------------------------------------------------
diff --git a/asm/src/main/java/org/objectweb/asm/Constants.java b/asm/src/main/java/org/objectweb/asm/Constants.java
index ff32798d..98684e2a 100644
--- a/asm/src/main/java/org/objectweb/asm/Constants.java
+++ b/asm/src/main/java/org/objectweb/asm/Constants.java
@@ -215,7 +215,7 @@ final class Constants {
     }
     if (minorVersion != 0xFFFF) {
       throw new IllegalStateException(
-          "ASM9_EXPERIMENTAL can only be used by classes compiled with --enable-preview");
+          "ASM10_EXPERIMENTAL can only be used by classes compiled with --enable-preview");
     }
   }
 }
diff --git a/asm/src/main/java/org/objectweb/asm/MethodVisitor.java b/asm/src/main/java/org/objectweb/asm/MethodVisitor.java
index 529f4667..751bc7f5 100644
--- a/asm/src/main/java/org/objectweb/asm/MethodVisitor.java
+++ b/asm/src/main/java/org/objectweb/asm/MethodVisitor.java
@@ -34,15 +34,16 @@ package org.objectweb.asm;
  * visitTypeAnnotation} | {@code visitAttribute} )* [ {@code visitCode} ( {@code visitFrame} |
  * {@code visit<i>X</i>Insn} | {@code visitLabel} | {@code visitInsnAnnotation} | {@code
  * visitTryCatchBlock} | {@code visitTryCatchAnnotation} | {@code visitLocalVariable} | {@code
- * visitLocalVariableAnnotation} | {@code visitLineNumber} )* {@code visitMaxs} ] {@code visitEnd}.
- * In addition, the {@code visit<i>X</i>Insn} and {@code visitLabel} methods must be called in the
- * sequential order of the bytecode instructions of the visited code, {@code visitInsnAnnotation}
- * must be called <i>after</i> the annotated instruction, {@code visitTryCatchBlock} must be called
- * <i>before</i> the labels passed as arguments have been visited, {@code
- * visitTryCatchBlockAnnotation} must be called <i>after</i> the corresponding try catch block has
- * been visited, and the {@code visitLocalVariable}, {@code visitLocalVariableAnnotation} and {@code
- * visitLineNumber} methods must be called <i>after</i> the labels passed as arguments have been
- * visited.
+ * visitLocalVariableAnnotation} | {@code visitLineNumber} | {@code visitAttribute} )* {@code
+ * visitMaxs} ] {@code visitEnd}. In addition, the {@code visit<i>X</i>Insn} and {@code visitLabel}
+ * methods must be called in the sequential order of the bytecode instructions of the visited code,
+ * {@code visitInsnAnnotation} must be called <i>after</i> the annotated instruction, {@code
+ * visitTryCatchBlock} must be called <i>before</i> the labels passed as arguments have been
+ * visited, {@code visitTryCatchBlockAnnotation} must be called <i>after</i> the corresponding try
+ * catch block has been visited, and the {@code visitLocalVariable}, {@code
+ * visitLocalVariableAnnotation} and {@code visitLineNumber} methods must be called <i>after</i> the
+ * labels passed as arguments have been visited. Finally, the {@code visitAttribute} method must be
+ * called before {@code visitCode} for non-code attributes, and after it for code attributes.
  *
  * @author Eric Bruneton
  */
@@ -595,7 +596,7 @@ public abstract class MethodVisitor {
    * Visits a LOOKUPSWITCH instruction.
    *
    * @param dflt beginning of the default handler block.
-   * @param keys the values of the keys.
+   * @param keys the values of the keys. Keys must be sorted in increasing order.
    * @param labels beginnings of the handler blocks. {@code labels[i]} is the beginning of the
    *     handler block for the {@code keys[i]} key.
    */
diff --git a/asm/src/main/java/org/objectweb/asm/MethodWriter.java b/asm/src/main/java/org/objectweb/asm/MethodWriter.java
index 8cdeec47..65f20251 100644
--- a/asm/src/main/java/org/objectweb/asm/MethodWriter.java
+++ b/asm/src/main/java/org/objectweb/asm/MethodWriter.java
@@ -651,7 +651,7 @@ final class MethodWriter extends MethodVisitor {
   @Override
   public AnnotationVisitor visitAnnotationDefault() {
     defaultValue = new ByteVector();
-    return new AnnotationWriter(symbolTable, /* useNamedValues = */ false, defaultValue, null);
+    return new AnnotationWriter(symbolTable, /* useNamedValues= */ false, defaultValue, null);
   }
 
   @Override
@@ -1519,14 +1519,14 @@ final class MethodWriter extends MethodVisitor {
       return lastCodeRuntimeVisibleTypeAnnotation =
           new AnnotationWriter(
               symbolTable,
-              /* useNamedValues = */ true,
+              /* useNamedValues= */ true,
               typeAnnotation,
               lastCodeRuntimeVisibleTypeAnnotation);
     } else {
       return lastCodeRuntimeInvisibleTypeAnnotation =
           new AnnotationWriter(
               symbolTable,
-              /* useNamedValues = */ true,
+              /* useNamedValues= */ true,
               typeAnnotation,
               lastCodeRuntimeInvisibleTypeAnnotation);
     }
@@ -1642,7 +1642,7 @@ final class MethodWriter extends MethodVisitor {
           code.data[endOffset] = (byte) Opcodes.ATHROW;
           // Emit a frame for this unreachable block, with no local and a Throwable on the stack
           // (so that the ATHROW could consume this Throwable if it were reachable).
-          int frameIndex = visitFrameStart(startOffset, /* numLocal = */ 0, /* numStack = */ 1);
+          int frameIndex = visitFrameStart(startOffset, /* numLocal= */ 0, /* numStack= */ 1);
           currentFrame[frameIndex] =
               Frame.getAbstractTypeFromInternalName(symbolTable, "java/lang/Throwable");
           visitFrameEnd();
diff --git a/asm/src/main/java/org/objectweb/asm/Opcodes.java b/asm/src/main/java/org/objectweb/asm/Opcodes.java
index 9f32e10b..4ed95869 100644
--- a/asm/src/main/java/org/objectweb/asm/Opcodes.java
+++ b/asm/src/main/java/org/objectweb/asm/Opcodes.java
@@ -288,6 +288,9 @@ public interface Opcodes {
   int V20 = 0 << 16 | 64;
   int V21 = 0 << 16 | 65;
   int V22 = 0 << 16 | 66;
+  int V23 = 0 << 16 | 67;
+  int V24 = 0 << 16 | 68;
+  int V25 = 0 << 16 | 69;
 
   /**
    * Version flag indicating that the class is using 'preview' features.
diff --git a/asm/src/main/java/org/objectweb/asm/Symbol.java b/asm/src/main/java/org/objectweb/asm/Symbol.java
index fcc4e10f..8d3d3169 100644
--- a/asm/src/main/java/org/objectweb/asm/Symbol.java
+++ b/asm/src/main/java/org/objectweb/asm/Symbol.java
@@ -178,7 +178,9 @@ abstract class Symbol {
    *   <li>the symbol's value for {@link #CONSTANT_INTEGER_TAG},{@link #CONSTANT_FLOAT_TAG}, {@link
    *       #CONSTANT_LONG_TAG}, {@link #CONSTANT_DOUBLE_TAG},
    *   <li>the CONSTANT_MethodHandle_info reference_kind field value for {@link
-   *       #CONSTANT_METHOD_HANDLE_TAG} symbols,
+   *       #CONSTANT_METHOD_HANDLE_TAG} symbols (or this value left shifted by 8 bits for
+   *       reference_kind values larger than or equal to H_INVOKEVIRTUAL and if the method owner is
+   *       an interface),
    *   <li>the CONSTANT_InvokeDynamic_info bootstrap_method_attr_index field value for {@link
    *       #CONSTANT_INVOKE_DYNAMIC_TAG} symbols,
    *   <li>the offset of a bootstrap method in the BootstrapMethods boostrap_methods array, for
diff --git a/asm/src/main/java/org/objectweb/asm/SymbolTable.java b/asm/src/main/java/org/objectweb/asm/SymbolTable.java
index a4cbb486..c3b17957 100644
--- a/asm/src/main/java/org/objectweb/asm/SymbolTable.java
+++ b/asm/src/main/java/org/objectweb/asm/SymbolTable.java
@@ -221,7 +221,9 @@ final class SymbolTable {
               classReader.readByte(itemOffset),
               classReader.readClass(memberRefItemOffset, charBuffer),
               classReader.readUTF8(nameAndTypeItemOffset, charBuffer),
-              classReader.readUTF8(nameAndTypeItemOffset + 2, charBuffer));
+              classReader.readUTF8(nameAndTypeItemOffset + 2, charBuffer),
+              classReader.readByte(memberRefItemOffset - 1)
+                  == Symbol.CONSTANT_INTERFACE_METHODREF_TAG);
           break;
         case Symbol.CONSTANT_DYNAMIC_TAG:
         case Symbol.CONSTANT_INVOKE_DYNAMIC_TAG:
@@ -830,14 +832,15 @@ final class SymbolTable {
       final String descriptor,
       final boolean isInterface) {
     final int tag = Symbol.CONSTANT_METHOD_HANDLE_TAG;
+    final int data = getConstantMethodHandleSymbolData(referenceKind, isInterface);
     // Note that we don't need to include isInterface in the hash computation, because it is
     // redundant with owner (we can't have the same owner with different isInterface values).
-    int hashCode = hash(tag, owner, name, descriptor, referenceKind);
+    int hashCode = hash(tag, owner, name, descriptor, data);
     Entry entry = get(hashCode);
     while (entry != null) {
       if (entry.tag == tag
           && entry.hashCode == hashCode
-          && entry.data == referenceKind
+          && entry.data == data
           && entry.owner.equals(owner)
           && entry.name.equals(name)
           && entry.value.equals(descriptor)) {
@@ -851,8 +854,7 @@ final class SymbolTable {
       constantPool.put112(
           tag, referenceKind, addConstantMethodref(owner, name, descriptor, isInterface).index);
     }
-    return put(
-        new Entry(constantPoolCount++, tag, owner, name, descriptor, referenceKind, hashCode));
+    return put(new Entry(constantPoolCount++, tag, owner, name, descriptor, data, hashCode));
   }
 
   /**
@@ -866,16 +868,36 @@ final class SymbolTable {
    * @param owner the internal name of a class of interface.
    * @param name a field or method name.
    * @param descriptor a field or method descriptor.
+   * @param isInterface whether owner is an interface or not.
    */
   private void addConstantMethodHandle(
       final int index,
       final int referenceKind,
       final String owner,
       final String name,
-      final String descriptor) {
+      final String descriptor,
+      final boolean isInterface) {
     final int tag = Symbol.CONSTANT_METHOD_HANDLE_TAG;
-    int hashCode = hash(tag, owner, name, descriptor, referenceKind);
-    add(new Entry(index, tag, owner, name, descriptor, referenceKind, hashCode));
+    final int data = getConstantMethodHandleSymbolData(referenceKind, isInterface);
+    int hashCode = hash(tag, owner, name, descriptor, data);
+    add(new Entry(index, tag, owner, name, descriptor, data, hashCode));
+  }
+
+  /**
+   * Returns the {@link Symbol#data} field for a CONSTANT_MethodHandle_info Symbol.
+   *
+   * @param referenceKind one of {@link Opcodes#H_GETFIELD}, {@link Opcodes#H_GETSTATIC}, {@link
+   *     Opcodes#H_PUTFIELD}, {@link Opcodes#H_PUTSTATIC}, {@link Opcodes#H_INVOKEVIRTUAL}, {@link
+   *     Opcodes#H_INVOKESTATIC}, {@link Opcodes#H_INVOKESPECIAL}, {@link
+   *     Opcodes#H_NEWINVOKESPECIAL} or {@link Opcodes#H_INVOKEINTERFACE}.
+   * @param isInterface whether owner is an interface or not.
+   */
+  private static int getConstantMethodHandleSymbolData(
+      final int referenceKind, final boolean isInterface) {
+    if (referenceKind > Opcodes.H_PUTSTATIC && isInterface) {
+      return referenceKind << 8;
+    }
+    return referenceKind;
   }
 
   /**
@@ -1414,23 +1436,23 @@ final class SymbolTable {
     }
 
     Entry(final int index, final int tag, final String value, final int hashCode) {
-      super(index, tag, /* owner = */ null, /* name = */ null, value, /* data = */ 0);
+      super(index, tag, /* owner= */ null, /* name= */ null, value, /* data= */ 0);
       this.hashCode = hashCode;
     }
 
     Entry(final int index, final int tag, final String value, final long data, final int hashCode) {
-      super(index, tag, /* owner = */ null, /* name = */ null, value, data);
+      super(index, tag, /* owner= */ null, /* name= */ null, value, data);
       this.hashCode = hashCode;
     }
 
     Entry(
         final int index, final int tag, final String name, final String value, final int hashCode) {
-      super(index, tag, /* owner = */ null, name, value, /* data = */ 0);
+      super(index, tag, /* owner= */ null, name, value, /* data= */ 0);
       this.hashCode = hashCode;
     }
 
     Entry(final int index, final int tag, final long data, final int hashCode) {
-      super(index, tag, /* owner = */ null, /* name = */ null, /* value = */ null, data);
+      super(index, tag, /* owner= */ null, /* name= */ null, /* value= */ null, data);
       this.hashCode = hashCode;
     }
   }
diff --git a/asm/src/test/java/org/objectweb/asm/AttributeTest.java b/asm/src/test/java/org/objectweb/asm/AttributeTest.java
index d137d621..dd5f1b2f 100644
--- a/asm/src/test/java/org/objectweb/asm/AttributeTest.java
+++ b/asm/src/test/java/org/objectweb/asm/AttributeTest.java
@@ -28,6 +28,7 @@
 package org.objectweb.asm;
 
 import static org.junit.jupiter.api.Assertions.assertArrayEquals;
+import static org.junit.jupiter.api.Assertions.assertEquals;
 import static org.junit.jupiter.api.Assertions.assertTrue;
 
 import org.junit.jupiter.api.Test;
@@ -48,4 +49,51 @@ class AttributeTest {
   void testGetLabels() {
     assertArrayEquals(new Label[0], new Attribute("Comment").getLabels());
   }
+
+  @Test
+  void testStaticWrite() {
+    ClassWriter classWriter = new ClassWriter(0);
+    ByteAttribute attribute = new ByteAttribute((byte) 42);
+    byte[] content0 = Attribute.write(attribute, classWriter, null, -1, -1, -1);
+    byte[] content1 = Attribute.write(attribute, classWriter, null, -1, -1, -1);
+
+    assertEquals(42, content0[0]);
+    assertEquals(42, content1[0]);
+  }
+
+  @Test
+  void testCachedContent() {
+    SymbolTable table = new SymbolTable(new ClassWriter(0));
+    ByteAttribute attributes = new ByteAttribute((byte) 42);
+    attributes.nextAttribute = new ByteAttribute((byte) 123);
+    int size = attributes.computeAttributesSize(table, null, -1, -1, -1);
+    ByteVector result = new ByteVector();
+    attributes.putAttributes(table, result);
+
+    assertEquals(14, size);
+    assertEquals(42, result.data[6]);
+    assertEquals(123, result.data[13]);
+  }
+
+  static class ByteAttribute extends Attribute {
+
+    private byte value;
+
+    ByteAttribute(final byte value) {
+      super("Byte");
+      this.value = value;
+    }
+
+    @Override
+    protected ByteVector write(
+        final ClassWriter classWriter,
+        final byte[] code,
+        final int codeLength,
+        final int maxStack,
+        final int maxLocals) {
+      ByteVector result = new ByteVector();
+      result.putByte(value++);
+      return result;
+    }
+  }
 }
diff --git a/asm/src/test/java/org/objectweb/asm/ClassReaderTest.java b/asm/src/test/java/org/objectweb/asm/ClassReaderTest.java
index 95a968f8..10d39b4c 100644
--- a/asm/src/test/java/org/objectweb/asm/ClassReaderTest.java
+++ b/asm/src/test/java/org/objectweb/asm/ClassReaderTest.java
@@ -216,8 +216,6 @@ class ClassReaderTest extends AsmTest implements Opcodes {
         ClassLoader.getSystemResourceAsStream(
             classParameter.getName().replace('.', '/') + ".class")) {
       classReader = new ClassReader(inputStream);
-    } catch (IOException ioe) {
-      throw ioe;
     }
 
     assertNotEquals(0, classReader.getAccess());
@@ -259,8 +257,6 @@ class ClassReaderTest extends AsmTest implements Opcodes {
       assertTimeoutPreemptively(
           Duration.ofMillis(100),
           () -> assertThrows(ArrayIndexOutOfBoundsException.class, streamConstructor));
-    } catch (IOException ioe) {
-      throw ioe;
     }
   }
 
@@ -452,7 +448,7 @@ class ClassReaderTest extends AsmTest implements Opcodes {
         || invalidClass == InvalidClass.INVALID_BYTECODE_OFFSET) {
       Exception exception = assertThrows(ArrayIndexOutOfBoundsException.class, accept);
       Matcher matcher = Pattern.compile("\\d+").matcher(exception.getMessage());
-      assertTrue(matcher.find() && Integer.valueOf(matcher.group()) > 0);
+      assertTrue(matcher.find() && Integer.parseInt(matcher.group()) > 0);
     } else {
       assertThrows(IllegalArgumentException.class, accept);
     }
diff --git a/asm/src/test/java/org/objectweb/asm/ClassWriterFlagsTest.java b/asm/src/test/java/org/objectweb/asm/ClassWriterFlagsTest.java
new file mode 100644
index 00000000..f0726d6d
--- /dev/null
+++ b/asm/src/test/java/org/objectweb/asm/ClassWriterFlagsTest.java
@@ -0,0 +1,187 @@
+// ASM: a very small and fast Java bytecode manipulation framework
+// Copyright (c) 2000-2011 INRIA, France Telecom
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+// 1. Redistributions of source code must retain the above copyright
+//    notice, this list of conditions and the following disclaimer.
+// 2. Redistributions in binary form must reproduce the above copyright
+//    notice, this list of conditions and the following disclaimer in the
+//    documentation and/or other materials provided with the distribution.
+// 3. Neither the name of the copyright holders nor the names of its
+//    contributors may be used to endorse or promote products derived from
+//    this software without specific prior written permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
+// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
+// THE POSSIBILITY OF SUCH DAMAGE.
+package org.objectweb.asm;
+
+import java.util.concurrent.atomic.AtomicReference;
+import org.junit.jupiter.api.Assertions;
+import org.junit.jupiter.api.Test;
+
+/**
+ * Tests for {@link ClassWriter}. Checks that {@link ClassWriter} can be configured to compute maxs
+ * and frames for each method.
+ *
+ * @author Volodya Lombrozo.
+ */
+class ClassWriterFlagsTest {
+
+  @Test
+  void switchesModesThreeTimes() {
+    final ClassWriter writer = new ClassWriter(0);
+    final DummyClass clazz = new DummyClass(writer);
+    final String computeMaxs = "computeMaxs";
+    final String computeNothing = "computeNothing";
+    final String computeFrames = "computeFrames";
+    writer.setFlags(ClassWriter.COMPUTE_MAXS);
+    clazz.withDummyMethod(computeMaxs);
+    writer.setFlags(0);
+    clazz.withDummyMethod(computeNothing);
+    writer.setFlags(ClassWriter.COMPUTE_FRAMES);
+    clazz.withDummyMethod(computeFrames);
+    final CompiledClass compiled = clazz.compile();
+    final Maxs maxs = compiled.maxs(computeMaxs);
+    Assertions.assertEquals(3, maxs.stack, "Max stack is not 3");
+    Assertions.assertEquals(1, maxs.locals, "Max locals is not 1");
+    final Maxs nothing = compiled.maxs(computeNothing);
+    Assertions.assertEquals(1, nothing.stack, "Max stack is not 1");
+    Assertions.assertEquals(0, nothing.locals, "Max locals is not 0");
+    final Maxs frames = compiled.maxs(computeFrames);
+    Assertions.assertEquals(3, frames.stack, "Max stack is not 3");
+    Assertions.assertEquals(1, frames.locals, "Max locals is not 1");
+  }
+
+  @Test
+  void computesFramesAsUsual() {
+    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
+    final String method = "frames";
+    final Maxs maxs = new DummyClass(writer).withDummyMethod(method).compile().maxs(method);
+    Assertions.assertEquals(3, maxs.stack, "Max stack is not 3");
+    Assertions.assertEquals(1, maxs.locals, "Max locals is not 1");
+  }
+
+  @Test
+  void computesMaxsAsUsual() {
+    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
+    final String method = "maxs";
+    final Maxs maxs = new DummyClass(writer).withDummyMethod(method).compile().maxs(method);
+    Assertions.assertEquals(3, maxs.stack, "Max stack is not 3");
+    Assertions.assertEquals(1, maxs.locals, "Max locals is not 1");
+  }
+
+  @Test
+  void computesNothingAsUsual() {
+    final ClassWriter writer = new ClassWriter(0);
+    final String method = "nothing";
+    final Maxs maxs = new DummyClass(writer).withDummyMethod(method).compile().maxs(method);
+    Assertions.assertEquals(1, maxs.stack, "Max stack is not 3");
+    Assertions.assertEquals(0, maxs.locals, "Max locals is not 1");
+  }
+
+  private static final class CompiledClass {
+
+    private final byte[] clazz;
+
+    private CompiledClass(final byte[] clazz) {
+      this.clazz = clazz;
+    }
+
+    /**
+     * Get max stack and locals for a method.
+     *
+     * @param method Method name.
+     * @return Max stack and locals.
+     */
+    Maxs maxs(final String method) {
+      final AtomicReference<Maxs> maxs = new AtomicReference<>();
+      new ClassReader(clazz)
+          .accept(
+              new ClassVisitor(Opcodes.ASM5) {
+                @Override
+                public MethodVisitor visitMethod(
+                    final int access,
+                    final String name,
+                    final String descriptor,
+                    final String signature,
+                    final String[] exceptions) {
+                  if (name.equals(method)) {
+                    return new MethodVisitor(Opcodes.ASM5) {
+                      @Override
+                      public void visitMaxs(final int stack, final int locals) {
+                        maxs.set(new Maxs(stack, locals));
+                      }
+                    };
+                  } else {
+                    return super.visitMethod(access, name, descriptor, signature, exceptions);
+                  }
+                }
+              },
+              0);
+      return maxs.get();
+    }
+  }
+
+  private static final class DummyClass {
+
+    /** Class writer to use in a test. */
+    private final ClassWriter writer;
+
+    /**
+     * Constructor.
+     *
+     * @param writer Class writer to use in a test.
+     */
+    private DummyClass(final ClassWriter writer) {
+      this.writer = writer;
+      this.writer.visit(
+          Opcodes.V1_7, Opcodes.ACC_PUBLIC, "SomeClass", null, "java/lang/Object", null);
+    }
+
+    CompiledClass compile() {
+      writer.visitEnd();
+      return new CompiledClass(writer.toByteArray());
+    }
+
+    DummyClass withDummyMethod(final String method) {
+      final Label start = new Label();
+      final MethodVisitor mvisitor =
+          writer.visitMethod(Opcodes.ACC_PUBLIC, method, "()V", null, null);
+      mvisitor.visitCode();
+      mvisitor.visitLabel(start);
+      mvisitor.visitInsn(Opcodes.LCONST_0);
+      final Label label = new Label();
+      mvisitor.visitJumpInsn(Opcodes.GOTO, label);
+      mvisitor.visitLabel(label);
+      mvisitor.visitFrame(Opcodes.F_NEW, 0, null, 1, new Object[] {Opcodes.LONG});
+      mvisitor.visitInsn(Opcodes.ACONST_NULL);
+      mvisitor.visitInsn(Opcodes.RETURN);
+      mvisitor.visitMaxs(1, 0);
+      mvisitor.visitEnd();
+      return this;
+    }
+  }
+
+  private static final class Maxs {
+
+    final int stack;
+    final int locals;
+
+    private Maxs(final int stack, final int locals) {
+      this.stack = stack;
+      this.locals = locals;
+    }
+  }
+}
diff --git a/asm/src/test/java/org/objectweb/asm/ClassWriterTest.java b/asm/src/test/java/org/objectweb/asm/ClassWriterTest.java
index df146d3c..bb9e095f 100644
--- a/asm/src/test/java/org/objectweb/asm/ClassWriterTest.java
+++ b/asm/src/test/java/org/objectweb/asm/ClassWriterTest.java
@@ -31,6 +31,7 @@ import static java.util.stream.Collectors.toSet;
 import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
 import static org.junit.jupiter.api.Assertions.assertEquals;
 import static org.junit.jupiter.api.Assertions.assertFalse;
+import static org.junit.jupiter.api.Assertions.assertNotEquals;
 import static org.junit.jupiter.api.Assertions.assertThrows;
 import static org.junit.jupiter.api.Assertions.assertTrue;
 import static org.junit.jupiter.api.Assertions.fail;
@@ -66,8 +67,8 @@ class ClassWriterTest extends AsmTest {
   /**
    * Tests that the non-static fields of ClassWriter are the expected ones. This test is designed to
    * fail each time new fields are added to ClassWriter, and serves as a reminder to update the
-   * field reset logic in {@link ClassWriter#replaceAsmInstructions()}, if needed, each time a new
-   * field is added.
+   * field reset logic in {@link ClassWriter#replaceAsmInstructions(byte[], boolean)}, if needed,
+   * each time a new field is added.
    */
   @Test
   void testInstanceFields() {
@@ -78,41 +79,40 @@ class ClassWriterTest extends AsmTest {
             .collect(toSet());
 
     Set<String> expectedFields =
-        new HashSet<String>(
-            Arrays.asList(
-                "flags",
-                "version",
-                "symbolTable",
-                "accessFlags",
-                "thisClass",
-                "superClass",
-                "interfaceCount",
-                "interfaces",
-                "firstField",
-                "lastField",
-                "firstMethod",
-                "lastMethod",
-                "numberOfInnerClasses",
-                "innerClasses",
-                "enclosingClassIndex",
-                "enclosingMethodIndex",
-                "signatureIndex",
-                "sourceFileIndex",
-                "debugExtension",
-                "lastRuntimeVisibleAnnotation",
-                "lastRuntimeInvisibleAnnotation",
-                "lastRuntimeVisibleTypeAnnotation",
-                "lastRuntimeInvisibleTypeAnnotation",
-                "moduleWriter",
-                "nestHostClassIndex",
-                "numberOfNestMemberClasses",
-                "nestMemberClasses",
-                "numberOfPermittedSubclasses",
-                "permittedSubclasses",
-                "firstRecordComponent",
-                "lastRecordComponent",
-                "firstAttribute",
-                "compute"));
+        Set.of(
+            "flags",
+            "version",
+            "symbolTable",
+            "accessFlags",
+            "thisClass",
+            "superClass",
+            "interfaceCount",
+            "interfaces",
+            "firstField",
+            "lastField",
+            "firstMethod",
+            "lastMethod",
+            "numberOfInnerClasses",
+            "innerClasses",
+            "enclosingClassIndex",
+            "enclosingMethodIndex",
+            "signatureIndex",
+            "sourceFileIndex",
+            "debugExtension",
+            "lastRuntimeVisibleAnnotation",
+            "lastRuntimeInvisibleAnnotation",
+            "lastRuntimeVisibleTypeAnnotation",
+            "lastRuntimeInvisibleTypeAnnotation",
+            "moduleWriter",
+            "nestHostClassIndex",
+            "numberOfNestMemberClasses",
+            "nestMemberClasses",
+            "numberOfPermittedSubclasses",
+            "permittedSubclasses",
+            "firstRecordComponent",
+            "lastRecordComponent",
+            "firstAttribute",
+            "compute");
     // IMPORTANT: if this fails, update the string list AND update the logic that resets the
     // ClassWriter fields in ClassWriter.toByteArray(), if needed (this logic is used to do a
     // ClassReader->ClassWriter round trip to remove the ASM specific instructions due to large
@@ -246,6 +246,16 @@ class ClassWriterTest extends AsmTest {
             .contains("constant_pool: ConstantMethodHandleInfo 1.ConstantFieldRefInfo A.hI"));
   }
 
+  @Test
+  void testNewHandleIsInterface() {
+    ClassWriter classWriter = newEmptyClassWriter();
+
+    int index1 = classWriter.newHandle(Opcodes.H_INVOKEVIRTUAL, "A", "m", "()V", false);
+    int index2 = classWriter.newHandle(Opcodes.H_INVOKEVIRTUAL, "A", "m", "()V", true);
+
+    assertNotEquals(index1, index2);
+  }
+
   @Test
   void testNewConstantDynamic() {
     ClassWriter classWriter = newEmptyClassWriter();
diff --git a/asm/src/test/java/org/objectweb/asm/ConstantsTest.java b/asm/src/test/java/org/objectweb/asm/ConstantsTest.java
index 12630ebd..543ba044 100644
--- a/asm/src/test/java/org/objectweb/asm/ConstantsTest.java
+++ b/asm/src/test/java/org/objectweb/asm/ConstantsTest.java
@@ -255,6 +255,9 @@ class ConstantsTest {
       case "V20":
       case "V21":
       case "V22":
+      case "V23":
+      case "V24":
+      case "V25":
         return ConstantType.CLASS_VERSION;
       case "ACC_PUBLIC":
       case "ACC_PRIVATE":
@@ -563,7 +566,7 @@ class ConstantsTest {
 
   private static int getIntegerValue(final Field field) {
     try {
-      return ((Integer) field.get(null)).intValue();
+      return (int) field.get(null);
     } catch (IllegalAccessException e) {
       throw new IllegalArgumentException(e);
     }
diff --git a/asm/src/test/java/org/objectweb/asm/MethodWriterTest.java b/asm/src/test/java/org/objectweb/asm/MethodWriterTest.java
index 60ead10a..b45bc763 100644
--- a/asm/src/test/java/org/objectweb/asm/MethodWriterTest.java
+++ b/asm/src/test/java/org/objectweb/asm/MethodWriterTest.java
@@ -33,7 +33,6 @@ import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
 
 import java.time.Duration;
 import java.util.Arrays;
-import java.util.HashSet;
 import java.util.Set;
 import org.junit.jupiter.api.Test;
 
@@ -64,39 +63,38 @@ class MethodWriterTest {
                 })
             .collect(toSet());
 
-    HashSet<String> expectedAttributes =
-        new HashSet<String>(
-            Arrays.asList(
-                Constants.CONSTANT_VALUE,
-                Constants.CODE,
-                Constants.STACK_MAP_TABLE,
-                Constants.EXCEPTIONS,
-                Constants.INNER_CLASSES,
-                Constants.ENCLOSING_METHOD,
-                Constants.SYNTHETIC,
-                Constants.SIGNATURE,
-                Constants.SOURCE_FILE,
-                Constants.SOURCE_DEBUG_EXTENSION,
-                Constants.LINE_NUMBER_TABLE,
-                Constants.LOCAL_VARIABLE_TABLE,
-                Constants.LOCAL_VARIABLE_TYPE_TABLE,
-                Constants.DEPRECATED,
-                Constants.RUNTIME_VISIBLE_ANNOTATIONS,
-                Constants.RUNTIME_INVISIBLE_ANNOTATIONS,
-                Constants.RUNTIME_VISIBLE_PARAMETER_ANNOTATIONS,
-                Constants.RUNTIME_INVISIBLE_PARAMETER_ANNOTATIONS,
-                Constants.RUNTIME_VISIBLE_TYPE_ANNOTATIONS,
-                Constants.RUNTIME_INVISIBLE_TYPE_ANNOTATIONS,
-                Constants.ANNOTATION_DEFAULT,
-                Constants.BOOTSTRAP_METHODS,
-                Constants.METHOD_PARAMETERS,
-                Constants.MODULE,
-                Constants.MODULE_PACKAGES,
-                Constants.MODULE_MAIN_CLASS,
-                Constants.NEST_HOST,
-                Constants.NEST_MEMBERS,
-                Constants.PERMITTED_SUBCLASSES,
-                Constants.RECORD));
+    Set<String> expectedAttributes =
+        Set.of(
+            Constants.CONSTANT_VALUE,
+            Constants.CODE,
+            Constants.STACK_MAP_TABLE,
+            Constants.EXCEPTIONS,
+            Constants.INNER_CLASSES,
+            Constants.ENCLOSING_METHOD,
+            Constants.SYNTHETIC,
+            Constants.SIGNATURE,
+            Constants.SOURCE_FILE,
+            Constants.SOURCE_DEBUG_EXTENSION,
+            Constants.LINE_NUMBER_TABLE,
+            Constants.LOCAL_VARIABLE_TABLE,
+            Constants.LOCAL_VARIABLE_TYPE_TABLE,
+            Constants.DEPRECATED,
+            Constants.RUNTIME_VISIBLE_ANNOTATIONS,
+            Constants.RUNTIME_INVISIBLE_ANNOTATIONS,
+            Constants.RUNTIME_VISIBLE_PARAMETER_ANNOTATIONS,
+            Constants.RUNTIME_INVISIBLE_PARAMETER_ANNOTATIONS,
+            Constants.RUNTIME_VISIBLE_TYPE_ANNOTATIONS,
+            Constants.RUNTIME_INVISIBLE_TYPE_ANNOTATIONS,
+            Constants.ANNOTATION_DEFAULT,
+            Constants.BOOTSTRAP_METHODS,
+            Constants.METHOD_PARAMETERS,
+            Constants.MODULE,
+            Constants.MODULE_PACKAGES,
+            Constants.MODULE_MAIN_CLASS,
+            Constants.NEST_HOST,
+            Constants.NEST_MEMBERS,
+            Constants.PERMITTED_SUBCLASSES,
+            Constants.RECORD);
     // IMPORTANT: if this fails, update the list AND update MethodWriter.canCopyMethodAttributes(),
     // if needed.
     assertEquals(expectedAttributes, actualAttributes);
diff --git a/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/AdapterBenchmark.java b/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/AdapterBenchmark.java
index 5fbaba34..007f7dff 100644
--- a/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/AdapterBenchmark.java
+++ b/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/AdapterBenchmark.java
@@ -249,77 +249,77 @@ public class AdapterBenchmark extends AbstractBenchmark {
   @Benchmark
   public void readAndWrite_asm4_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm4dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm4dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asm5_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm5dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm5dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asm6_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm6dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm6dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asm7_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm7dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm7dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asm8_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm8dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm8dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asm9_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm9dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm9dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asmCurrent(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asmCurrent.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asmCurrent.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_aspectJBcel(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(aspectJBcel.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(aspectJBcel.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_bcel(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(bcel.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(bcel.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_javassist(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(javassist.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(javassist.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_serp(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(serp.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(serp.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
@@ -375,70 +375,70 @@ public class AdapterBenchmark extends AbstractBenchmark {
   @Benchmark
   public void readAndWriteWithComputeMaxs_asm4_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm4dot0.readAndWrite(classFile, /* computeMaxs = */ true));
+      blackhole.consume(asm4dot0.readAndWrite(classFile, /* computeMaxs= */ true));
     }
   }
 
   @Benchmark
   public void readAndWriteWithComputeMaxs_asm5_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm5dot0.readAndWrite(classFile, /* computeMaxs = */ true));
+      blackhole.consume(asm5dot0.readAndWrite(classFile, /* computeMaxs= */ true));
     }
   }
 
   @Benchmark
   public void readAndWriteWithComputeMaxs_asm6_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm6dot0.readAndWrite(classFile, /* computeMaxs = */ true));
+      blackhole.consume(asm6dot0.readAndWrite(classFile, /* computeMaxs= */ true));
     }
   }
 
   @Benchmark
   public void readAndWriteWithComputeMaxs_asm7_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm7dot0.readAndWrite(classFile, /* computeMaxs = */ true));
+      blackhole.consume(asm7dot0.readAndWrite(classFile, /* computeMaxs= */ true));
     }
   }
 
   @Benchmark
   public void readAndWriteWithComputeMaxs_asm8_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm8dot0.readAndWrite(classFile, /* computeMaxs = */ true));
+      blackhole.consume(asm8dot0.readAndWrite(classFile, /* computeMaxs= */ true));
     }
   }
 
   @Benchmark
   public void readAndWriteWithComputeMaxs_asm9_0(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asm9dot0.readAndWrite(classFile, /* computeMaxs = */ true));
+      blackhole.consume(asm9dot0.readAndWrite(classFile, /* computeMaxs= */ true));
     }
   }
 
   @Benchmark
   public void readAndWriteWithComputeMaxs_asmCurrent(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(asmCurrent.readAndWrite(classFile, /* computeMaxs = */ true));
+      blackhole.consume(asmCurrent.readAndWrite(classFile, /* computeMaxs= */ true));
     }
   }
 
   @Benchmark
   public void readAndWriteWithComputeMaxs_aspectJBcel(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(aspectJBcel.readAndWrite(classFile, /* computeMaxs = */ true));
+      blackhole.consume(aspectJBcel.readAndWrite(classFile, /* computeMaxs= */ true));
     }
   }
 
   @Benchmark
   public void readAndWriteWithComputeMaxs_bcel(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(bcel.readAndWrite(classFile, /* computeMaxs = */ true));
+      blackhole.consume(bcel.readAndWrite(classFile, /* computeMaxs= */ true));
     }
   }
 
   @Benchmark
   public void readAndWriteWithComputeMaxs_serp(final Blackhole blackhole) {
     for (byte[] classFile : classFiles) {
-      blackhole.consume(serp.readAndWrite(classFile, /* computeMaxs = */ true));
+      blackhole.consume(serp.readAndWrite(classFile, /* computeMaxs= */ true));
     }
   }
 
diff --git a/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/AdapterBenchmarkJava8.java b/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/AdapterBenchmarkJava8.java
index 2e0f9d72..4049655c 100644
--- a/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/AdapterBenchmarkJava8.java
+++ b/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/AdapterBenchmarkJava8.java
@@ -175,42 +175,42 @@ public class AdapterBenchmarkJava8 extends AbstractBenchmark {
   @Benchmark
   public void readAndWrite_asm5_0(final Blackhole blackhole) {
     for (byte[] classFile : java8classFiles) {
-      blackhole.consume(asm5dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm5dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asm6_0(final Blackhole blackhole) {
     for (byte[] classFile : java8classFiles) {
-      blackhole.consume(asm6dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm6dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asm7_0(final Blackhole blackhole) {
     for (byte[] classFile : java8classFiles) {
-      blackhole.consume(asm7dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm7dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asm8_0(final Blackhole blackhole) {
     for (byte[] classFile : java8classFiles) {
-      blackhole.consume(asm8dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm8dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asm9_0(final Blackhole blackhole) {
     for (byte[] classFile : java8classFiles) {
-      blackhole.consume(asm9dot0.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asm9dot0.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
   @Benchmark
   public void readAndWrite_asmCurrent(final Blackhole blackhole) {
     for (byte[] classFile : java8classFiles) {
-      blackhole.consume(asmCurrent.readAndWrite(classFile, /* computeMaxs = */ false));
+      blackhole.consume(asmCurrent.readAndWrite(classFile, /* computeMaxs= */ false));
     }
   }
 
diff --git a/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/JClassLibGenerator.java b/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/JClassLibGenerator.java
index fc2b0a73..1ecc06d5 100644
--- a/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/JClassLibGenerator.java
+++ b/benchmarks/src/jmh/java/org/objectweb/asm/benchmarks/JClassLibGenerator.java
@@ -30,7 +30,7 @@ package org.objectweb.asm.benchmarks;
 import java.io.ByteArrayOutputStream;
 import java.io.DataOutputStream;
 import java.io.IOException;
-import java.util.Arrays;
+import java.util.List;
 import org.gjt.jclasslib.bytecode.ImmediateByteInstruction;
 import org.gjt.jclasslib.bytecode.ImmediateShortInstruction;
 import org.gjt.jclasslib.bytecode.Opcodes;
@@ -82,7 +82,7 @@ public class JClassLibGenerator extends Generator {
           ConstantPoolUtil.addConstantUTF8Info(classFile, CodeAttribute.ATTRIBUTE_NAME, 0));
       codeAttribute1.setCode(
           ByteCodeWriter.writeByteCode(
-              Arrays.asList(
+              List.of(
                   new SimpleInstruction(Opcodes.OPCODE_ALOAD_0),
                   new ImmediateShortInstruction(
                       Opcodes.OPCODE_INVOKESPECIAL,
@@ -107,7 +107,7 @@ public class JClassLibGenerator extends Generator {
           ConstantPoolUtil.addConstantUTF8Info(classFile, CodeAttribute.ATTRIBUTE_NAME, 0));
       codeAttribute2.setCode(
           ByteCodeWriter.writeByteCode(
-              Arrays.asList(
+              List.of(
                   new ImmediateShortInstruction(
                       Opcodes.OPCODE_GETSTATIC,
                       ConstantPoolUtil.addConstantFieldrefInfo(
diff --git a/build.gradle b/build.gradle
index 181ed398..9dd034a3 100644
--- a/build.gradle
+++ b/build.gradle
@@ -31,8 +31,8 @@ buildscript {
   dependencies { classpath 'org.netbeans.tools:sigtest-maven-plugin:1.5' }
 }
 
-plugins { id 'com.github.sherter.google-java-format' version '0.9' apply false }
-plugins { id 'me.champeau.jmh' version '0.6.8' apply false }
+plugins { id 'com.diffplug.spotless' version "6.23.3" apply false }
+plugins { id 'me.champeau.jmh' version '0.7.2' apply false }
 plugins { id 'org.sonarqube' version '4.3.1.3277' apply false }
 
 description = 'ASM, a very small and fast Java bytecode manipulation framework'
@@ -47,15 +47,17 @@ dependencies {
 
 allprojects {
   group = 'org.ow2.asm'
-  version = '9.6' + (rootProject.hasProperty('release') ? '' : '-SNAPSHOT')
+  version = '9.8' + (rootProject.hasProperty('release') ? '' : '-SNAPSHOT')
 }
 
 subprojects {
   repositories { mavenCentral() }
   apply plugin: 'java-library'
   apply plugin: 'jacoco'
-  sourceCompatibility = '1.8'
-  targetCompatibility = '1.8'
+  java {
+    sourceCompatibility = '11'
+    targetCompatibility = '11'
+  }
   test { useJUnitPlatform() }
   ext.provides = []  // The provided java packages, e.g. ['org.objectweb.asm']
   ext.requires = []  // The required Gradle projects, e.g. [':asm-test']
@@ -99,8 +101,8 @@ project(':asm-commons') {
 project(':asm-test') {
   description = "Utilities for testing ${parent.description}"
   provides = ['org.objectweb.asm.test']
-  depends = ['org.junit.jupiter:junit-jupiter-api:5.9.1',
-      'org.junit.jupiter:junit-jupiter-params:5.9.1']
+  depends = ['org.junit.jupiter:junit-jupiter-api:5.10.1',
+      'org.junit.jupiter:junit-jupiter-params:5.10.1']
 }
 
 project(':asm-tree') {
@@ -145,11 +147,11 @@ project(':benchmarks') {
     }
     classes.dependsOn "asm${version}"
   }
-  configurations.create('input-classes-java8')
-  dependencies.add('input-classes-java8', 'io.vavr:vavr:0.10.0@jar')
+  configurations.create('input-classes-java11')
+  dependencies.add('input-classes-java11', 'io.vavr:vavr:0.10.0@jar')
   task copyInputClasses(type: Copy) {
-    from configurations.'input-classes-java8'.collect{zipTree(it)}
-    into "${buildDir}/input-classes-java8"
+    from configurations.'input-classes-java11'.collect{zipTree(it)}
+    into "${buildDir}/input-classes-java11"
   }
   classes.dependsOn copyInputClasses
   jmh {
@@ -168,8 +170,10 @@ project(':tools') {
 
 project(':tools:retrofitter') {
   description = "JDK 1.5 class retrofitter based on ${rootProject.description}"
-  sourceCompatibility = '1.9'
-  targetCompatibility = '1.9'
+  java {
+    sourceCompatibility = '11'
+    targetCompatibility = '11'
+  }
   // TODO: this compiles asm twice (here and in :asm).
   sourceSets.main.java.srcDirs += project(':asm').sourceSets.main.java.srcDirs
 }
@@ -181,9 +185,14 @@ project(':tools:retrofitter') {
 // All projects are checked with googleJavaFormat, Checkstyle and PMD, 
 // and tested with :asm-test and JUnit.
 subprojects {
-  apply plugin: 'com.github.sherter.google-java-format'
-  googleJavaFormat.toolVersion = '1.15.0'
-  googleJavaFormat.exclude 'src/resources/java/**/*'
+  apply plugin: 'com.diffplug.spotless'
+  spotless {
+    java {
+      target '**/*.java'
+      targetExclude 'src/resources/java/**/*'
+      googleJavaFormat('1.18.1')
+    }
+  }
   
   // Check the coding style with Checkstyle. Fail in case of error or warning.
   apply plugin: 'checkstyle'
@@ -202,9 +211,9 @@ subprojects {
   dependencies {
     requires.each { projectName -> api project(projectName) }
     depends.each { artifactName -> api artifactName }
-    testImplementation 'org.junit.jupiter:junit-jupiter-api:5.9.1',
-        'org.junit.jupiter:junit-jupiter-params:5.9.1'
-    testRuntimeOnly 'org.junit.jupiter:junit-jupiter-engine:5.9.1'
+    testImplementation 'org.junit.jupiter:junit-jupiter-api:5.10.1',
+        'org.junit.jupiter:junit-jupiter-params:5.10.1'
+    testRuntimeOnly 'org.junit.jupiter:junit-jupiter-engine:5.10.1'
     testImplementation project(':asm-test')
   }
 
@@ -218,11 +227,11 @@ subprojects {
 }
 
 // Configure the projects with a non-empty 'provides' property. They must be
-// checked for code coverage and backward compatibility, retrofited to Java 1.5,
+// checked for code coverage and backward compatibility, retrofitted to Java 1.5,
 // and packaged with generated module-info classes.
 configure(subprojects.findAll{it.provides}) {
   // Code coverage configuration.
-  jacoco.toolVersion = '0.8.10'
+  jacoco.toolVersion = '0.8.12'
   jacocoTestReport {
     reports { xml.required = true }
     classDirectories.setFrom(sourceSets.main.output.classesDirs)
@@ -245,7 +254,7 @@ configure(subprojects.findAll{it.provides}) {
       def loader = new URLClassLoader(path.collect {f -> f.toURL()} as URL[])
       def retrofitter =
           loader.loadClass('org.objectweb.asm.tools.Retrofitter').newInstance()
-      def classes = sourceSets.main.output.classesDirs.singleFile
+      def classes = sourceSets.main.output.classesDirs.singleFile.toPath()
       def requires = transitiveRequires() as List
       retrofitter.retrofit(classes, "${version}")
       retrofitter.verify(classes, "${version}", provides, requires)
@@ -384,7 +393,7 @@ configure([rootProject] + subprojects.findAll { it.provides }) {
         pom {
           name = artifactId
           description = project.description
-          packaging 'jar'
+          packaging = isRoot ? 'pom' : 'jar'
           inceptionYear = '2000'
           licenses {
             license {
diff --git a/tools/retrofitter/src/main/java/org/objectweb/asm/tools/Retrofitter.java b/tools/retrofitter/src/main/java/org/objectweb/asm/tools/Retrofitter.java
index 43002cea..53f26281 100644
--- a/tools/retrofitter/src/main/java/org/objectweb/asm/tools/Retrofitter.java
+++ b/tools/retrofitter/src/main/java/org/objectweb/asm/tools/Retrofitter.java
@@ -28,17 +28,29 @@
 package org.objectweb.asm.tools;
 
 import static java.lang.String.format;
+import static java.util.stream.Collectors.toList;
 import static java.util.stream.Collectors.toSet;
+import static org.objectweb.asm.Opcodes.ACC_PRIVATE;
+import static org.objectweb.asm.Opcodes.ACC_STATIC;
+import static org.objectweb.asm.Opcodes.ACC_SYNTHETIC;
+import static org.objectweb.asm.Opcodes.ARETURN;
+import static org.objectweb.asm.Opcodes.DUP;
+import static org.objectweb.asm.Opcodes.ILOAD;
+import static org.objectweb.asm.Opcodes.INVOKESPECIAL;
+import static org.objectweb.asm.Opcodes.INVOKESTATIC;
+import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;
+import static org.objectweb.asm.Opcodes.NEW;
 
 import java.io.BufferedReader;
-import java.io.File;
 import java.io.IOException;
 import java.io.InputStream;
 import java.io.InputStreamReader;
 import java.io.LineNumberReader;
 import java.lang.module.ModuleDescriptor;
+import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
+import java.nio.file.Paths;
 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.HashSet;
@@ -66,7 +78,7 @@ import org.objectweb.asm.Type;
  * @author Eric Bruneton
  * @author Eugene Kuleshov
  */
-public class Retrofitter {
+public final class Retrofitter {
 
   /** The name of the module-info file. */
   private static final String MODULE_INFO = "module-info.class";
@@ -74,6 +86,15 @@ public class Retrofitter {
   /** The name of the java.base module. */
   private static final String JAVA_BASE_MODULE = "java.base";
 
+  /** Bootstrap method for the string concatenation using indy. */
+  private static final Handle STRING_CONCAT_FACTORY_HANDLE =
+      new Handle(
+          Opcodes.H_INVOKESTATIC,
+          "java/lang/invoke/StringConcatFactory",
+          "makeConcatWithConstants",
+          "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
+          false);
+
   /**
    * The fields and methods of the JDK 1.5 API. Each string has the form
    * "&lt;owner&gt;&lt;name&gt;&lt;descriptor&gt;".
@@ -101,7 +122,7 @@ public class Retrofitter {
    */
   public static void main(final String[] args) throws IOException {
     if (args.length == 2) {
-      new Retrofitter().retrofit(new File(args[0]), args[1]);
+      new Retrofitter().retrofit(Paths.get(args[0]), args[1]);
     } else {
       System.err.println("Usage: Retrofitter <classes directory> <ASM release version>"); // NOPMD
     }
@@ -116,12 +137,12 @@ public class Retrofitter {
    * @param version the module-info version.
    * @throws IOException if a file can't be read or written.
    */
-  public void retrofit(final File classesDir, final String version) throws IOException {
-    for (File classFile : getAllClasses(classesDir, new ArrayList<File>())) {
-      ClassReader classReader = new ClassReader(Files.newInputStream(classFile.toPath()));
+  public void retrofit(final Path classesDir, final String version) throws IOException {
+    for (Path classFile : getAllClasses(classesDir, /* includeModuleInfo= */ true)) {
+      ClassReader classReader = new ClassReader(Files.readAllBytes(classFile));
       ClassWriter classWriter = new ClassWriter(0);
       classReader.accept(new ClassRetrofitter(classWriter), ClassReader.SKIP_FRAMES);
-      Files.write(classFile.toPath(), classWriter.toByteArray());
+      Files.write(classFile, classWriter.toByteArray());
     }
     generateModuleInfoClass(classesDir, version);
   }
@@ -138,7 +159,7 @@ public class Retrofitter {
    * @throws IllegalArgumentException if the module-info class does not have the expected content.
    */
   public void verify(
-      final File classesDir,
+      final Path classesDir,
       final String expectedVersion,
       final List<String> expectedExports,
       final List<String> expectedRequires)
@@ -146,35 +167,175 @@ public class Retrofitter {
     if (jdkApi.isEmpty()) {
       readJdkApi();
     }
-    for (File classFile : getAllClasses(classesDir, new ArrayList<File>())) {
-      if (!classFile.getName().equals(MODULE_INFO)) {
-        new ClassReader(Files.newInputStream(classFile.toPath())).accept(new ClassVerifier(), 0);
-      }
+
+    List<Path> classFiles = getAllClasses(classesDir, /* includeModuleInfo= */ false);
+    List<ClassReader> classReaders = getClassReaders(classFiles);
+    for (ClassReader classReader : classReaders) {
+      classReader.accept(new ClassVerifier(), 0);
     }
+    checkPrivateMemberAccess(classReaders);
     verifyModuleInfoClass(
         classesDir,
         expectedVersion,
-        new HashSet<String>(expectedExports),
+        new HashSet<>(expectedExports),
         Stream.concat(expectedRequires.stream(), Stream.of(JAVA_BASE_MODULE)).collect(toSet()));
   }
 
-  private List<File> getAllClasses(final File file, final List<File> allClasses)
+  private List<ClassReader> getClassReaders(final List<Path> classFiles) throws IOException {
+    ArrayList<ClassReader> classReaders = new ArrayList<>();
+    for (Path classFile : classFiles) {
+      classReaders.add(new ClassReader(Files.readAllBytes(classFile)));
+    }
+    return classReaders;
+  }
+
+  private List<Path> getAllClasses(final Path path, final boolean includeModuleInfo)
       throws IOException {
-    if (file.isDirectory()) {
-      File[] children = file.listFiles();
-      if (children == null) {
-        throw new IOException("Unable to read files of " + file);
-      }
-      for (File child : children) {
-        getAllClasses(child, allClasses);
-      }
-    } else if (file.getName().endsWith(".class")) {
-      allClasses.add(file);
+    try (Stream<Path> stream = Files.walk(path)) {
+      return stream
+          .filter(
+              child -> {
+                String filename = child.getFileName().toString();
+                return filename.endsWith(".class")
+                    && (includeModuleInfo || !filename.equals("module-info.class"));
+              })
+          .collect(toList());
     }
-    return allClasses;
   }
 
-  private void generateModuleInfoClass(final File dstDir, final String version) throws IOException {
+  /**
+   * Checks that no code accesses to a private member from another class. If there is a private
+   * access, removing the nestmate attributes is not a legal transformation.
+   */
+  private static void checkPrivateMemberAccess(final List<ClassReader> readers) {
+    // Compute all private members.
+    HashMap<String, HashSet<String>> privateMemberMap = new HashMap<>();
+    for (ClassReader reader : readers) {
+      HashSet<String> privateMembers = new HashSet<>();
+      reader.accept(
+          new ClassVisitor(/* latest api =*/ Opcodes.ASM9) {
+            @Override
+            public void visit(
+                final int version,
+                final int access,
+                final String name,
+                final String signature,
+                final String superName,
+                final String[] interfaces) {
+              privateMemberMap.put(name, privateMembers);
+            }
+
+            @Override
+            public FieldVisitor visitField(
+                final int access,
+                final String name,
+                final String descriptor,
+                final String signature,
+                final Object value) {
+              if ((access & ACC_PRIVATE) != 0) {
+                privateMembers.add(name + '/' + descriptor);
+              }
+              return null;
+            }
+
+            @Override
+            public MethodVisitor visitMethod(
+                final int access,
+                final String name,
+                final String descriptor,
+                final String signature,
+                final String[] exceptions) {
+              if ((access & ACC_PRIVATE) != 0) {
+                privateMembers.add(name + '/' + descriptor);
+              }
+              return null;
+            }
+          },
+          0);
+    }
+
+    // Verify that there is no access to a private member of another class.
+    for (ClassReader reader : readers) {
+      reader.accept(
+          new ClassVisitor(/* latest api =*/ Opcodes.ASM9) {
+            /** The internal name of the visited class. */
+            String className;
+
+            /** The name and descriptor of the currently visited method. */
+            String currentMethodName;
+
+            @Override
+            public void visit(
+                final int version,
+                final int access,
+                final String name,
+                final String signature,
+                final String superName,
+                final String[] interfaces) {
+              className = name;
+            }
+
+            @Override
+            public MethodVisitor visitMethod(
+                final int access,
+                final String name,
+                final String descriptor,
+                final String signature,
+                final String[] exceptions) {
+              currentMethodName = name + descriptor;
+              return new MethodVisitor(/* latest api =*/ Opcodes.ASM9) {
+
+                private void checkAccess(
+                    final String owner, final String name, final String descriptor) {
+                  if (owner.equals(className)) { // same class access
+                    return;
+                  }
+                  HashSet<String> members = privateMemberMap.get(owner);
+                  if (members == null) { // not a known class
+                    return;
+                  }
+                  if (members.contains(name + '/' + descriptor)) {
+                    throw new IllegalArgumentException(
+                        format(
+                            "ERROR: illegal access to a private member %s.%s called in %s %s",
+                            owner, name + " " + descriptor, className, currentMethodName));
+                  }
+                }
+
+                @Override
+                public void visitFieldInsn(
+                    final int opcode,
+                    final String owner,
+                    final String name,
+                    final String descriptor) {
+                  checkAccess(owner, name, descriptor);
+                }
+
+                @Override
+                public void visitMethodInsn(
+                    final int opcode,
+                    final String owner,
+                    final String name,
+                    final String descriptor,
+                    final boolean isInterface) {
+                  checkAccess(owner, name, descriptor);
+                }
+
+                @Override
+                public void visitLdcInsn(final Object value) {
+                  if (value instanceof Handle) {
+                    Handle handle = (Handle) value;
+                    checkAccess(handle.getOwner(), handle.getName(), handle.getDesc());
+                  }
+                }
+              };
+            }
+          },
+          0);
+    }
+  }
+
+  private void generateModuleInfoClass(final Path dstDir, final String version) throws IOException {
     ClassWriter classWriter = new ClassWriter(0);
     classWriter.visit(Opcodes.V9, Opcodes.ACC_MODULE, "module-info", null, null, null);
     ArrayList<String> moduleNames = new ArrayList<>();
@@ -201,17 +362,17 @@ public class Retrofitter {
     }
     moduleVisitor.visitEnd();
     classWriter.visitEnd();
-    Files.write(Path.of(dstDir.getAbsolutePath(), MODULE_INFO), classWriter.toByteArray());
+    Files.write(dstDir.toAbsolutePath().resolve(MODULE_INFO), classWriter.toByteArray());
   }
 
   private void verifyModuleInfoClass(
-      final File dstDir,
+      final Path dstDir,
       final String expectedVersion,
       final Set<String> expectedExports,
       final Set<String> expectedRequires)
       throws IOException {
     ModuleDescriptor module =
-        ModuleDescriptor.read(Files.newInputStream(Path.of(dstDir.getAbsolutePath(), MODULE_INFO)));
+        ModuleDescriptor.read(Files.newInputStream(dstDir.toAbsolutePath().resolve(MODULE_INFO)));
     String version = module.version().map(ModuleDescriptor.Version::toString).orElse("");
     if (!version.equals(expectedVersion)) {
       throw new IllegalArgumentException(
@@ -240,31 +401,32 @@ public class Retrofitter {
     try (InputStream inputStream =
             new GZIPInputStream(
                 Retrofitter.class.getClassLoader().getResourceAsStream("jdk1.5.0.12.txt.gz"));
-        BufferedReader reader = new LineNumberReader(new InputStreamReader(inputStream))) {
-      while (true) {
-        String line = reader.readLine();
-        if (line != null) {
-          if (line.startsWith("class")) {
-            String className = line.substring(6, line.lastIndexOf(' '));
-            String superClassName = line.substring(line.lastIndexOf(' ') + 1);
-            jdkHierarchy.put(className, superClassName);
-          } else {
-            jdkApi.add(line);
-          }
+        InputStreamReader inputStreamReader =
+            new InputStreamReader(inputStream, StandardCharsets.UTF_8);
+        BufferedReader reader = new LineNumberReader(inputStreamReader)) {
+      String line;
+      while ((line = reader.readLine()) != null) {
+        if (line.startsWith("class")) {
+          String className = line.substring(6, line.lastIndexOf(' '));
+          String superClassName = line.substring(line.lastIndexOf(' ') + 1);
+          jdkHierarchy.put(className, superClassName);
         } else {
-          break;
+          jdkApi.add(line);
         }
       }
-    } catch (IOException ioe) {
-      throw ioe;
     }
   }
 
   /** A ClassVisitor that retrofits classes to 1.5 version. */
-  class ClassRetrofitter extends ClassVisitor {
+  final class ClassRetrofitter extends ClassVisitor {
+    /** The internal name of the visited class. */
+    String owner;
+
+    /** An id used to generate the name of the synthetic string concatenation methods. */
+    int concatMethodId;
 
     public ClassRetrofitter(final ClassVisitor classVisitor) {
-      super(/* latest api =*/ Opcodes.ASM8, classVisitor);
+      super(/* latest api =*/ Opcodes.ASM9, classVisitor);
     }
 
     @Override
@@ -275,10 +437,22 @@ public class Retrofitter {
         final String signature,
         final String superName,
         final String[] interfaces) {
-      addPackageReferences(Type.getObjectType(name), /* export = */ true);
+      owner = name;
+      concatMethodId = 0;
+      addPackageReferences(Type.getObjectType(name), /* export= */ true);
       super.visit(Opcodes.V1_5, access, name, signature, superName, interfaces);
     }
 
+    @Override
+    public void visitNestHost(final String nestHost) {
+      // Remove the NestHost attribute.
+    }
+
+    @Override
+    public void visitNestMember(final String nestMember) {
+      // Remove the NestMembers attribute.
+    }
+
     @Override
     public FieldVisitor visitField(
         final int access,
@@ -286,7 +460,7 @@ public class Retrofitter {
         final String descriptor,
         final String signature,
         final Object value) {
-      addPackageReferences(Type.getType(descriptor), /* export = */ false);
+      addPackageReferences(Type.getType(descriptor), /* export= */ false);
       return super.visitField(access, name, descriptor, signature, value);
     }
 
@@ -297,14 +471,20 @@ public class Retrofitter {
         final String descriptor,
         final String signature,
         final String[] exceptions) {
-      addPackageReferences(Type.getType(descriptor), /* export = */ false);
+      addPackageReferences(Type.getType(descriptor), /* export= */ false);
       return new MethodVisitor(
           api, super.visitMethod(access, name, descriptor, signature, exceptions)) {
 
+        @Override
+        public void visitParameter(final String name, final int access) {
+          // Javac 21 generates a Parameter attribute for the synthetic/mandated parameters.
+          // Remove the Parameter attribute.
+        }
+
         @Override
         public void visitFieldInsn(
             final int opcode, final String owner, final String name, final String descriptor) {
-          addPackageReferences(Type.getType(descriptor), /* export = */ false);
+          addPackageReferences(Type.getType(descriptor), /* export= */ false);
           super.visitFieldInsn(opcode, owner, name, descriptor);
         }
 
@@ -315,7 +495,7 @@ public class Retrofitter {
             final String name,
             final String descriptor,
             final boolean isInterface) {
-          addPackageReferences(Type.getType(descriptor), /* export = */ false);
+          addPackageReferences(Type.getType(descriptor), /* export= */ false);
           // Remove the addSuppressed() method calls generated for try-with-resources statements.
           // This method is not defined in JDK1.5.
           if (owner.equals("java/lang/Throwable")
@@ -327,15 +507,101 @@ public class Retrofitter {
           }
         }
 
+        @Override
+        public void visitInvokeDynamicInsn(
+            final String name,
+            final String descriptor,
+            final Handle bootstrapMethodHandle,
+            final Object... bootstrapMethodArguments) {
+          // For simple recipe, (if there is no constant pool constants used), rewrite the
+          // concatenation using a StringBuilder instead.
+          if (STRING_CONCAT_FACTORY_HANDLE.equals(bootstrapMethodHandle)
+              && bootstrapMethodArguments.length == 1) {
+            String recipe = (String) bootstrapMethodArguments[0];
+            String methodName = "stringConcat$" + concatMethodId++;
+            generateConcatMethod(methodName, descriptor, recipe);
+            super.visitMethodInsn(INVOKESTATIC, owner, methodName, descriptor, false);
+            return;
+          }
+          super.visitInvokeDynamicInsn(
+              name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments);
+        }
+
+        private void generateConcatMethod(
+            final String methodName, final String descriptor, final String recipe) {
+          MethodVisitor mv =
+              visitMethod(
+                  ACC_STATIC | ACC_PRIVATE | ACC_SYNTHETIC, methodName, descriptor, null, null);
+          mv.visitCode();
+          mv.visitTypeInsn(NEW, "java/lang/StringBuilder");
+          mv.visitInsn(DUP);
+          mv.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
+          int nexLocal = 0;
+          int typeIndex = 0;
+          int maxStack = 2;
+          Type[] types = Type.getArgumentTypes(descriptor);
+          StringBuilder text = new StringBuilder();
+          for (int i = 0; i < recipe.length(); i++) {
+            char c = recipe.charAt(i);
+            if (c == '\1') {
+              if (text.length() != 0) {
+                generateConstantTextAppend(mv, text.toString());
+                text.setLength(0);
+              }
+              Type type = types[typeIndex++];
+              mv.visitVarInsn(type.getOpcode(ILOAD), nexLocal);
+              maxStack = Math.max(maxStack, 1 + type.getSize());
+              String desc = stringBuilderAppendDescriptor(type);
+              mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", desc, false);
+              nexLocal += type.getSize();
+            } else {
+              text.append(c);
+            }
+          }
+          if (text.length() != 0) {
+            generateConstantTextAppend(mv, text.toString());
+          }
+          mv.visitMethodInsn(
+              INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
+          mv.visitInsn(ARETURN);
+          mv.visitMaxs(maxStack, nexLocal);
+          mv.visitEnd();
+        }
+
+        private void generateConstantTextAppend(final MethodVisitor mv, final String text) {
+          mv.visitLdcInsn(text);
+          mv.visitMethodInsn(
+              INVOKEVIRTUAL,
+              "java/lang/StringBuilder",
+              "append",
+              "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
+              false);
+        }
+
+        private String stringBuilderAppendDescriptor(final Type type) {
+          switch (type.getSort()) {
+            case Type.BYTE:
+            case Type.SHORT:
+            case Type.INT:
+              return "(I)Ljava/lang/StringBuilder;";
+            case Type.OBJECT:
+              return type.getDescriptor().equals("Ljava/lang/String;")
+                  ? "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
+                  : "(Ljava/lang/Object;)Ljava/lang/StringBuilder;";
+            default:
+              return '(' + type.getDescriptor() + ")Ljava/lang/StringBuilder;";
+          }
+        }
+
         @Override
         public void visitTypeInsn(final int opcode, final String type) {
-          addPackageReferences(Type.getObjectType(type), /* export = */ false);
+          addPackageReferences(Type.getObjectType(type), /* export= */ false);
           super.visitTypeInsn(opcode, type);
         }
 
         @Override
         public void visitMultiANewArrayInsn(final String descriptor, final int numDimensions) {
-          addPackageReferences(Type.getType(descriptor), /* export = */ false);
+          addPackageReferences(Type.getType(descriptor), /* export= */ false);
           super.visitMultiANewArrayInsn(descriptor, numDimensions);
         }
 
@@ -343,7 +609,7 @@ public class Retrofitter {
         public void visitTryCatchBlock(
             final Label start, final Label end, final Label handler, final String type) {
           if (type != null) {
-            addPackageReferences(Type.getObjectType(type), /* export = */ false);
+            addPackageReferences(Type.getObjectType(type), /* export= */ false);
           }
           super.visitTryCatchBlock(start, end, handler, type);
         }
@@ -377,12 +643,12 @@ public class Retrofitter {
   /**
    * A ClassVisitor checking that a class uses only JDK 1.5 class file features and the JDK 1.5 API.
    */
-  class ClassVerifier extends ClassVisitor {
+  final class ClassVerifier extends ClassVisitor {
 
     /** The internal name of the visited class. */
     String className;
 
-    /** The name of the currently visited method. */
+    /** The name and descriptor of the currently visited method. */
     String currentMethodName;
 
     public ClassVerifier() {
```

