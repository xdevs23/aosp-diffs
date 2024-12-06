```diff
diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml
index fa32f617..a278e12f 100644
--- a/.gitlab-ci.yml
+++ b/.gitlab-ci.yml
@@ -1,10 +1,10 @@
-image: gradle:7.6-jdk11
+image: gradle:8.3-jdk11
 
 variables:
   # Set the location of the dependency cache to a local directory, so that it
   # can be cached between GitLab Continous Integration Jobs.
   GRADLE_USER_HOME: '.gradle'
-  GRADLE: 'gradle -Dorg.gradle.jvmargs=-XX:MaxMetaspaceSize=512m'
+  GRADLE: 'gradle'
   SONAR: 'https://sonarqube.ow2.org'
 
 cache:
@@ -18,4 +18,4 @@ build:
     - $GRADLE test jacocoTestCoverageVerification
     - if [ $NEXUS_USER_NAME ]; then $GRADLE publish; fi
     - if [ !$NEXUS_USER_NAME ]; then $GRADLE publishToMavenLocal; fi
-    - if [ $SONAR_LOGIN ]; then $GRADLE jacocoTestReport sonarqube -Dsonar.host.url=$SONAR -Dsonar.login=${SONAR_LOGIN}; fi
+    - if [ $SONAR_LOGIN ]; then $GRADLE -Dorg.gradle.jvmargs='-XX:MetaspaceSize=1024M -XX:MaxMetaspaceSize=1024M' jacocoTestReport sonar -Dsonar.host.url=$SONAR -Dsonar.login=${SONAR_LOGIN}; fi
diff --git a/METADATA b/METADATA
index ecd75791..16691c2e 100644
--- a/METADATA
+++ b/METADATA
@@ -11,7 +11,7 @@ third_party {
     type: GIT
     value: "https://gitlab.ow2.org/asm/asm.git"
   }
-  version: "9.4"
-  last_upgrade_date { year: 2022 month: 11 day: 14 }
+  version: "9.6"
+  last_upgrade_date { year: 2024 month: 7 day: 15 }
   license_type: NOTICE
 }
diff --git a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Analyzer.java b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Analyzer.java
index 40432a5b..ab875b88 100644
--- a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Analyzer.java
+++ b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Analyzer.java
@@ -123,7 +123,7 @@ public class Analyzer<V extends Value> implements Opcodes {
       TryCatchBlockNode tryCatchBlock = method.tryCatchBlocks.get(i);
       int startIndex = insnList.indexOf(tryCatchBlock.start);
       int endIndex = insnList.indexOf(tryCatchBlock.end);
-      for (int j = startIndex; j < endIndex; ++j) {
+      for (int j = startIndex; j <= endIndex; ++j) {
         List<TryCatchBlockNode> insnHandlers = handlers[j];
         if (insnHandlers == null) {
           insnHandlers = new ArrayList<>();
@@ -137,9 +137,15 @@ public class Analyzer<V extends Value> implements Opcodes {
     findSubroutines(method.maxLocals);
 
     // Initializes the data structures for the control flow analysis.
-    Frame<V> currentFrame = computeInitialFrame(owner, method);
-    merge(0, currentFrame, null);
-    init(owner, method);
+    Frame<V> currentFrame;
+    try {
+      currentFrame = computeInitialFrame(owner, method);
+      merge(0, currentFrame, null);
+      init(owner, method);
+    } catch (RuntimeException e) {
+      // DontCheck(IllegalCatch): can't be fixed, for backward compatibility.
+      throw new AnalyzerException(insnList.get(0), "Error at instruction 0: " + e.getMessage(), e);
+    }
 
     // Control flow analysis.
     while (numInstructionsToProcess > 0) {
diff --git a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Frame.java b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Frame.java
index 2776fb30..ac3600c7 100644
--- a/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Frame.java
+++ b/asm-analysis/src/main/java/org/objectweb/asm/tree/analysis/Frame.java
@@ -672,7 +672,7 @@ public class Frame<V extends Value> {
       final AbstractInsnNode insn, final String methodDescriptor, final Interpreter<V> interpreter)
       throws AnalyzerException {
     ArrayList<V> valueList = new ArrayList<>();
-    for (int i = Type.getArgumentTypes(methodDescriptor).length; i > 0; --i) {
+    for (int i = Type.getArgumentCount(methodDescriptor); i > 0; --i) {
       valueList.add(0, pop());
     }
     if (insn.getOpcode() != Opcodes.INVOKESTATIC && insn.getOpcode() != Opcodes.INVOKEDYNAMIC) {
diff --git a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerTest.java b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerTest.java
index e0ff13bf..1f8a8f1b 100644
--- a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerTest.java
+++ b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerTest.java
@@ -74,6 +74,24 @@ class AnalyzerTest extends AsmTest {
   private final Label label11 = new Label();
   private final Label label12 = new Label();
 
+  @Test
+  void testAnalyze_runtimeExceptions() {
+    MethodNode methodNode = new MethodNodeBuilder().insn(Opcodes.NOP).vreturn().build();
+
+    Executable analyze =
+        () ->
+            new Analyzer<MockValue>(new MockInterpreter()) {
+
+              @Override
+              protected Frame<MockValue> newFrame(final int numLocals, final int numStack) {
+                throw new RuntimeException("newFrame error");
+              }
+            }.analyze(CLASS_NAME, methodNode);
+
+    String message = assertThrows(AnalyzerException.class, analyze).getMessage();
+    assertTrue(message.contains("newFrame error"));
+  }
+
   @Test
   void testAnalyze_invalidOpcode() {
     MethodNode methodNode = new MethodNodeBuilder().insn(-1).vreturn().build();
diff --git a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicVerifierTest.java b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicVerifierTest.java
index 8a09544f..905b09b4 100644
--- a/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicVerifierTest.java
+++ b/asm-analysis/src/test/java/org/objectweb/asm/tree/analysis/AnalyzerWithBasicVerifierTest.java
@@ -37,6 +37,7 @@ import org.junit.jupiter.api.function.Executable;
 import org.junit.jupiter.params.ParameterizedTest;
 import org.junit.jupiter.params.provider.MethodSource;
 import org.objectweb.asm.ClassReader;
+import org.objectweb.asm.Label;
 import org.objectweb.asm.Opcodes;
 import org.objectweb.asm.test.AsmTest;
 import org.objectweb.asm.tree.ClassNode;
@@ -77,6 +78,32 @@ class AnalyzerWithBasicVerifierTest extends AsmTest {
     assertTrue(message.contains("Expected an object reference or a return address, but found I"));
   }
 
+  @Test
+  void testAnalyze_invalidIloadDueToLastInstructionOfExceptionHandler() {
+    Label startTryLabel = new Label();
+    Label endTryLabel = new Label();
+    Label catchLabel = new Label();
+    MethodNode methodNode =
+        new MethodNodeBuilder()
+            .trycatch(startTryLabel, endTryLabel, catchLabel)
+            .iconst_0()
+            .istore(1)
+            .label(startTryLabel)
+            .aconst_null()
+            .astore(1)
+            .label(endTryLabel)
+            .vreturn()
+            .label(catchLabel)
+            .iload(1)
+            .vreturn()
+            .build();
+
+    Executable analyze = () -> newAnalyzer().analyze(CLASS_NAME, methodNode);
+
+    String message = assertThrows(AnalyzerException.class, analyze).getMessage();
+    assertTrue(message.contains("Error at instruction 8: Expected I, but found ."));
+  }
+
   @Test
   void testAnalyze_invalidIstore() {
     MethodNode methodNode = new MethodNodeBuilder().aconst_null().istore(1).vreturn().build();
diff --git a/asm-commons/src/main/java/org/objectweb/asm/commons/AnalyzerAdapter.java b/asm-commons/src/main/java/org/objectweb/asm/commons/AnalyzerAdapter.java
index c31533ec..c97a79e2 100644
--- a/asm-commons/src/main/java/org/objectweb/asm/commons/AnalyzerAdapter.java
+++ b/asm-commons/src/main/java/org/objectweb/asm/commons/AnalyzerAdapter.java
@@ -308,7 +308,7 @@ public class AnalyzerAdapter extends MethodVisitor {
         if (value == Opcodes.UNINITIALIZED_THIS) {
           initializedValue = this.owner;
         } else {
-          initializedValue = uninitializedTypes.get(value);
+          initializedValue = owner;
         }
         for (int i = 0; i < locals.size(); ++i) {
           if (locals.get(i) == value) {
diff --git a/asm-commons/src/main/java/org/objectweb/asm/commons/JSRInlinerAdapter.java b/asm-commons/src/main/java/org/objectweb/asm/commons/JSRInlinerAdapter.java
index e1beedfc..cdcbd9fc 100644
--- a/asm-commons/src/main/java/org/objectweb/asm/commons/JSRInlinerAdapter.java
+++ b/asm-commons/src/main/java/org/objectweb/asm/commons/JSRInlinerAdapter.java
@@ -425,7 +425,7 @@ public class JSRInlinerAdapter extends MethodNode implements Opcodes {
   }
 
   /** An instantiation of a subroutine. */
-  private class Instantiation extends AbstractMap<LabelNode, LabelNode> {
+  private final class Instantiation extends AbstractMap<LabelNode, LabelNode> {
 
     /**
      * The instantiation from which this one was created (or {@literal null} for the instantiation
diff --git a/asm-test/src/main/resources/jdk8/AllFrames.class b/asm-test/src/main/resources/jdk8/AllFrames.class
index 90d79b8c..bcba7988 100644
Binary files a/asm-test/src/main/resources/jdk8/AllFrames.class and b/asm-test/src/main/resources/jdk8/AllFrames.class differ
diff --git a/asm-test/src/main/resources/jdk8/Artificial$()$Structures.class b/asm-test/src/main/resources/jdk8/Artificial$()$Structures.class
index 1cc843ec..4846df9e 100644
Binary files a/asm-test/src/main/resources/jdk8/Artificial$()$Structures.class and b/asm-test/src/main/resources/jdk8/Artificial$()$Structures.class differ
diff --git a/asm-test/src/resources/java/jdk8/AllFrames.java b/asm-test/src/resources/java/jdk8/AllFrames.java
old mode 100755
new mode 100644
index 44be5d1b..7f1a9b7a
--- a/asm-test/src/resources/java/jdk8/AllFrames.java
+++ b/asm-test/src/resources/java/jdk8/AllFrames.java
@@ -75,6 +75,25 @@ public class AllFrames {
         : m0(!b, y, c, s, i + 1, f + 1f, l + 1l, d + 1d, o, p, q);
   }
 
+  // Frame types: same, same_locals_1_stack_item.
+  // Element types: primitive types and object.
+  public static int m0Static(
+      boolean b,
+      byte y,
+      char c,
+      short s,
+      int i,
+      float f,
+      long l,
+      double d,
+      Object o,
+      Object[] p,
+      Object[][] q) {
+    return b
+        ? m0Static(!b, y, c, s, i - 1, f - 1f, l - 1l, d - 1d, o, p, q)
+        : m0Static(!b, y, c, s, i + 1, f + 1f, l + 1l, d + 1d, o, p, q);
+  }
+
   // Element types: uninitialized (multiple per frame).
   public String m0(byte[] bytes, boolean b) {
     try {
@@ -94,6 +113,16 @@ public class AllFrames {
     }
   }
 
+  // Frame types: append.
+  // Element types: top.
+  public static void m1Static(int i, int j) {
+    int k;
+    int l = j;
+    if (i < 0) {
+      i = -i;
+    }
+  }
+
   // Frame types: chop.
   public long m2(int n, boolean b) {
     long total = 0;
@@ -111,6 +140,23 @@ public class AllFrames {
     return total;
   }
 
+  // Frame types: chop.
+  public static long m2Static(int n, boolean b) {
+    long total = 0;
+    if (b) {
+      int i = 0;
+      do {
+        total += i++;
+      } while (i < n);
+    } else {
+      long i = 0;
+      do {
+        total += i++;
+      } while (i < n);
+    }
+    return total;
+  }
+
   // Frame types: same_frame_extended.
   public int m3(int i) {
     if (i < 0) {
@@ -120,6 +166,15 @@ public class AllFrames {
     return i;
   }
 
+  // Frame types: same_frame_extended.
+  public static int m3Static(int i) {
+    if (i < 0) {
+      i = i + i + i + i + i + i + i + i + i + i + i + i + i + i + i + i;
+      i = i + i + i + i + i + i + i + i + i + i + i + i + i + i + i + i;
+    }
+    return i;
+  }
+
   // Frame types: same_locals_1_stack_item_frame_extended.
   public void m4(int i) {
     i = i + i + i + i + i + i + i + i + i + i + i + i + i + i + i + i;
diff --git a/asm-test/src/resources/java/jdk8/DumpArtificialStructures.java b/asm-test/src/resources/java/jdk8/DumpArtificialStructures.java
index 99e45a10..81f5012a 100644
--- a/asm-test/src/resources/java/jdk8/DumpArtificialStructures.java
+++ b/asm-test/src/resources/java/jdk8/DumpArtificialStructures.java
@@ -57,10 +57,11 @@ public class DumpArtificialStructures implements Opcodes {
     ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
     MethodVisitor methodVisitor;
 
+    final String INTERNAL_NAME = "jdk8/Artificial$()$Structures";
     classWriter.visit(
         V1_8,
         ACC_PUBLIC + ACC_SUPER,
-        "jdk8/Artificial$()$Structures",
+        INTERNAL_NAME,
         null,
         "java/lang/Object",
         null);
@@ -73,7 +74,7 @@ public class DumpArtificialStructures implements Opcodes {
     methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
     methodVisitor.visitVarInsn(ALOAD, 0);
     methodVisitor.visitVarInsn(ILOAD, 1);
-    methodVisitor.visitFieldInsn(PUTFIELD, "jdk8/Artificial$()$Structures", "value", "I");
+    methodVisitor.visitFieldInsn(PUTFIELD, INTERNAL_NAME, "value", "I");
     methodVisitor.visitInsn(RETURN);
     methodVisitor.visitMaxs(0, 0);
     methodVisitor.visitEnd();
@@ -89,13 +90,13 @@ public class DumpArtificialStructures implements Opcodes {
     Label elseLabel = new Label();
     methodVisitor.visitJumpInsn(IFNULL, elseLabel);
     methodVisitor.visitVarInsn(ALOAD, 1);
-    methodVisitor.visitFieldInsn(GETFIELD, "jdk8/Artificial$()$Structures", "value", "I");
+    methodVisitor.visitFieldInsn(GETFIELD, INTERNAL_NAME, "value", "I");
     Label endIfLabel = new Label();
     methodVisitor.visitJumpInsn(GOTO, endIfLabel);
     methodVisitor.visitLabel(elseLabel);
     methodVisitor.visitInsn(ICONST_0);
     methodVisitor.visitLabel(endIfLabel);
-    methodVisitor.visitFieldInsn(PUTFIELD, "jdk8/Artificial$()$Structures", "value", "I");
+    methodVisitor.visitFieldInsn(PUTFIELD, INTERNAL_NAME, "value", "I");
     methodVisitor.visitInsn(RETURN);
     methodVisitor.visitMaxs(0, 0);
     methodVisitor.visitEnd();
@@ -104,12 +105,12 @@ public class DumpArtificialStructures implements Opcodes {
         classWriter.visitMethod(
             ACC_PUBLIC, "clone", "()Ljdk8/Artificial$()$Structures;", null, null);
     methodVisitor.visitCode();
-    methodVisitor.visitTypeInsn(NEW, "jdk8/Artificial$()$Structures");
+    methodVisitor.visitTypeInsn(NEW, INTERNAL_NAME);
     methodVisitor.visitInsn(DUP);
     methodVisitor.visitVarInsn(ALOAD, 0);
     methodVisitor.visitMethodInsn(
         INVOKESPECIAL,
-        "jdk8/Artificial$()$Structures",
+        INTERNAL_NAME,
         "<init>",
         "(Ljdk8/Artificial$()$Structures;)V",
         false);
@@ -126,6 +127,50 @@ public class DumpArtificialStructures implements Opcodes {
     methodVisitor.visitMaxs(0, 0);
     methodVisitor.visitEnd();
 
+    methodVisitor =
+        classWriter.visitMethod(
+            ACC_PUBLIC | ACC_STATIC, "frameWithForwardLabelReferences", "([Ljava/lang/String;)V", null, null);
+    methodVisitor.visitCode();
+    methodVisitor.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
+    Label labelNew = new Label();
+    methodVisitor.visitJumpInsn(GOTO, labelNew);
+
+    Label labelInit = new Label();
+    methodVisitor.visitLabel(labelInit);
+    methodVisitor.visitFrame(
+        Opcodes.F_NEW,
+        1,
+        new Object[] {"[Ljava/lang/String;"},
+        3,
+        new Object[] {"java/io/PrintStream", labelNew, labelNew});
+    methodVisitor.visitMethodInsn(INVOKESPECIAL, INTERNAL_NAME, "<init>", "()V", false);
+    Label labelAfterInit = new Label();
+    methodVisitor.visitJumpInsn(GOTO, labelAfterInit);
+
+    methodVisitor.visitLabel(labelNew);
+    methodVisitor.visitFrame(
+        Opcodes.F_NEW,
+        1,
+        new Object[] {"[Ljava/lang/String;"},
+        1,
+        new Object[] {"java/io/PrintStream"});
+    methodVisitor.visitTypeInsn(NEW, INTERNAL_NAME);
+    methodVisitor.visitInsn(DUP);
+    methodVisitor.visitJumpInsn(GOTO, labelInit);
+
+    methodVisitor.visitLabel(labelAfterInit);
+    methodVisitor.visitFrame(
+        Opcodes.F_NEW,
+        1,
+        new Object[] {"[Ljava/lang/String;"},
+        2,
+        new Object[] {"java/io/PrintStream", INTERNAL_NAME});
+    methodVisitor.visitMethodInsn(
+        INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
+    methodVisitor.visitInsn(RETURN);
+    methodVisitor.visitMaxs(3, 1);
+    methodVisitor.visitEnd();
+
     classWriter.visitEnd();
     return classWriter.toByteArray();
   }
diff --git a/asm-tree/src/main/java/org/objectweb/asm/tree/MethodNode.java b/asm-tree/src/main/java/org/objectweb/asm/tree/MethodNode.java
index 23e3e4c5..8b529a52 100644
--- a/asm-tree/src/main/java/org/objectweb/asm/tree/MethodNode.java
+++ b/asm-tree/src/main/java/org/objectweb/asm/tree/MethodNode.java
@@ -294,14 +294,14 @@ public class MethodNode extends MethodVisitor {
     AnnotationNode annotation = new AnnotationNode(descriptor);
     if (visible) {
       if (visibleParameterAnnotations == null) {
-        int params = Type.getArgumentTypes(desc).length;
+        int params = Type.getArgumentCount(desc);
         visibleParameterAnnotations = (List<AnnotationNode>[]) new List<?>[params];
       }
       visibleParameterAnnotations[parameter] =
           Util.add(visibleParameterAnnotations[parameter], annotation);
     } else {
       if (invisibleParameterAnnotations == null) {
-        int params = Type.getArgumentTypes(desc).length;
+        int params = Type.getArgumentCount(desc);
         invisibleParameterAnnotations = (List<AnnotationNode>[]) new List<?>[params];
       }
       invisibleParameterAnnotations[parameter] =
diff --git a/asm-util/src/main/java/org/objectweb/asm/util/ASMifier.java b/asm-util/src/main/java/org/objectweb/asm/util/ASMifier.java
index 82e2b15e..b779a190 100644
--- a/asm-util/src/main/java/org/objectweb/asm/util/ASMifier.java
+++ b/asm-util/src/main/java/org/objectweb/asm/util/ASMifier.java
@@ -111,6 +111,7 @@ public class ASMifier extends Printer {
     classVersions.put(Opcodes.V19, "V19");
     classVersions.put(Opcodes.V20, "V20");
     classVersions.put(Opcodes.V21, "V21");
+    classVersions.put(Opcodes.V22, "V22");
     CLASS_VERSIONS = Collections.unmodifiableMap(classVersions);
   }
 
diff --git a/asm-util/src/main/java/org/objectweb/asm/util/CheckFrameAnalyzer.java b/asm-util/src/main/java/org/objectweb/asm/util/CheckFrameAnalyzer.java
index 6a5b1de6..5be17b2a 100644
--- a/asm-util/src/main/java/org/objectweb/asm/util/CheckFrameAnalyzer.java
+++ b/asm-util/src/main/java/org/objectweb/asm/util/CheckFrameAnalyzer.java
@@ -118,6 +118,9 @@ class CheckFrameAnalyzer<V extends Value> extends Analyzer<V> {
   protected void init(final String owner, final MethodNode method) throws AnalyzerException {
     insnList = method.instructions;
     currentLocals = Type.getArgumentsAndReturnSizes(method.desc) >> 2;
+    if ((method.access & Opcodes.ACC_STATIC) != 0) {
+      currentLocals -= 1;
+    }
 
     Frame<V>[] frames = getFrames();
     Frame<V> currentFrame = frames[0];
diff --git a/asm-util/src/test/resources/jdk8.AllFrames.txt b/asm-util/src/test/resources/jdk8.AllFrames.txt
index 8dea110f..5179fd51 100644
--- a/asm-util/src/test/resources/jdk8.AllFrames.txt
+++ b/asm-util/src/test/resources/jdk8.AllFrames.txt
@@ -108,15 +108,17 @@ public class jdk8/AllFrames {
     LINENUMBER 73 L0
     ILOAD 1
     IFEQ L1
+   L2
+    LINENUMBER 74 L2
     ALOAD 0
     ILOAD 1
-    IFNE L2
+    IFNE L3
     ICONST_1
-    GOTO L3
-   L2
+    GOTO L4
+   L3
    FRAME SAME1 jdk8/AllFrames
     ICONST_0
-   L3
+   L4
    FRAME FULL [jdk8/AllFrames I I I I I F J D java/lang/Object [Ljava/lang/Object; [[Ljava/lang/Object;] [jdk8/AllFrames I]
     ILOAD 2
     ILOAD 3
@@ -136,11 +138,10 @@ public class jdk8/AllFrames {
     ALOAD 11
     ALOAD 12
     ALOAD 13
-   L4
-    LINENUMBER 74 L4
     INVOKEVIRTUAL jdk8/AllFrames.m0 (ZBCSIFJDLjava/lang/Object;[Ljava/lang/Object;[[Ljava/lang/Object;)I
     GOTO L5
    L1
+    LINENUMBER 75 L1
    FRAME SAME
     ALOAD 0
     ILOAD 1
@@ -170,36 +171,132 @@ public class jdk8/AllFrames {
     ALOAD 11
     ALOAD 12
     ALOAD 13
-   L8
-    LINENUMBER 75 L8
     INVOKEVIRTUAL jdk8/AllFrames.m0 (ZBCSIFJDLjava/lang/Object;[Ljava/lang/Object;[[Ljava/lang/Object;)I
    L5
     LINENUMBER 73 L5
    FRAME SAME1 I
     IRETURN
-   L9
-    LOCALVARIABLE this Ljdk8/AllFrames; L0 L9 0
-    LOCALVARIABLE b Z L0 L9 1
-    LOCALVARIABLE y B L0 L9 2
-    LOCALVARIABLE c C L0 L9 3
-    LOCALVARIABLE s S L0 L9 4
-    LOCALVARIABLE i I L0 L9 5
-    LOCALVARIABLE f F L0 L9 6
-    LOCALVARIABLE l J L0 L9 7
-    LOCALVARIABLE d D L0 L9 9
-    LOCALVARIABLE o Ljava/lang/Object; L0 L9 11
-    LOCALVARIABLE p [Ljava/lang/Object; L0 L9 12
-    LOCALVARIABLE q [[Ljava/lang/Object; L0 L9 13
+   L8
+    LOCALVARIABLE this Ljdk8/AllFrames; L0 L8 0
+    LOCALVARIABLE b Z L0 L8 1
+    LOCALVARIABLE y B L0 L8 2
+    LOCALVARIABLE c C L0 L8 3
+    LOCALVARIABLE s S L0 L8 4
+    LOCALVARIABLE i I L0 L8 5
+    LOCALVARIABLE f F L0 L8 6
+    LOCALVARIABLE l J L0 L8 7
+    LOCALVARIABLE d D L0 L8 9
+    LOCALVARIABLE o Ljava/lang/Object; L0 L8 11
+    LOCALVARIABLE p [Ljava/lang/Object; L0 L8 12
+    LOCALVARIABLE q [[Ljava/lang/Object; L0 L8 13
     MAXSTACK = 14
     MAXLOCALS = 14
 
+  // access flags 0x9
+  public static m0Static(ZBCSIFJDLjava/lang/Object;[Ljava/lang/Object;[[Ljava/lang/Object;)I
+    // parameter  b
+    // parameter  y
+    // parameter  c
+    // parameter  s
+    // parameter  i
+    // parameter  f
+    // parameter  l
+    // parameter  d
+    // parameter  o
+    // parameter  p
+    // parameter  q
+   L0
+    LINENUMBER 92 L0
+    ILOAD 0
+    IFEQ L1
+   L2
+    LINENUMBER 93 L2
+    ILOAD 0
+    IFNE L3
+    ICONST_1
+    GOTO L4
+   L3
+   FRAME SAME
+    ICONST_0
+   L4
+   FRAME SAME1 I
+    ILOAD 1
+    ILOAD 2
+    ILOAD 3
+    ILOAD 4
+    ICONST_1
+    ISUB
+    FLOAD 5
+    FCONST_1
+    FSUB
+    LLOAD 6
+    LCONST_1
+    LSUB
+    DLOAD 8
+    DCONST_1
+    DSUB
+    ALOAD 10
+    ALOAD 11
+    ALOAD 12
+    INVOKESTATIC jdk8/AllFrames.m0Static (ZBCSIFJDLjava/lang/Object;[Ljava/lang/Object;[[Ljava/lang/Object;)I
+    GOTO L5
+   L1
+    LINENUMBER 94 L1
+   FRAME SAME
+    ILOAD 0
+    IFNE L6
+    ICONST_1
+    GOTO L7
+   L6
+   FRAME SAME
+    ICONST_0
+   L7
+   FRAME SAME1 I
+    ILOAD 1
+    ILOAD 2
+    ILOAD 3
+    ILOAD 4
+    ICONST_1
+    IADD
+    FLOAD 5
+    FCONST_1
+    FADD
+    LLOAD 6
+    LCONST_1
+    LADD
+    DLOAD 8
+    DCONST_1
+    DADD
+    ALOAD 10
+    ALOAD 11
+    ALOAD 12
+    INVOKESTATIC jdk8/AllFrames.m0Static (ZBCSIFJDLjava/lang/Object;[Ljava/lang/Object;[[Ljava/lang/Object;)I
+   L5
+    LINENUMBER 92 L5
+   FRAME SAME1 I
+    IRETURN
+   L8
+    LOCALVARIABLE b Z L0 L8 0
+    LOCALVARIABLE y B L0 L8 1
+    LOCALVARIABLE c C L0 L8 2
+    LOCALVARIABLE s S L0 L8 3
+    LOCALVARIABLE i I L0 L8 4
+    LOCALVARIABLE f F L0 L8 5
+    LOCALVARIABLE l J L0 L8 6
+    LOCALVARIABLE d D L0 L8 8
+    LOCALVARIABLE o Ljava/lang/Object; L0 L8 10
+    LOCALVARIABLE p [Ljava/lang/Object; L0 L8 11
+    LOCALVARIABLE q [[Ljava/lang/Object; L0 L8 12
+    MAXSTACK = 13
+    MAXLOCALS = 13
+
   // access flags 0x1
   public m0([BZ)Ljava/lang/String;
     // parameter  bytes
     // parameter  b
     TRYCATCHBLOCK L0 L1 L2 java/io/UnsupportedEncodingException
    L0
-    LINENUMBER 81 L0
+    LINENUMBER 100 L0
     ALOAD 1
     IFNONNULL L3
     ACONST_NULL
@@ -223,11 +320,11 @@ public class jdk8/AllFrames {
    FRAME SAME1 java/lang/String
     ARETURN
    L2
-    LINENUMBER 82 L2
+    LINENUMBER 101 L2
    FRAME SAME1 java/io/UnsupportedEncodingException
     ASTORE 3
    L6
-    LINENUMBER 83 L6
+    LINENUMBER 102 L6
     ACONST_NULL
     ARETURN
    L7
@@ -243,20 +340,20 @@ public class jdk8/AllFrames {
     // parameter  i
     // parameter  j
    L0
-    LINENUMBER 91 L0
+    LINENUMBER 110 L0
     ILOAD 2
     ISTORE 4
    L1
-    LINENUMBER 92 L1
+    LINENUMBER 111 L1
     ILOAD 1
     IFGE L2
    L3
-    LINENUMBER 93 L3
+    LINENUMBER 112 L3
     ILOAD 1
     INEG
     ISTORE 1
    L2
-    LINENUMBER 95 L2
+    LINENUMBER 114 L2
    FRAME APPEND [T I]
     RETURN
    L4
@@ -267,24 +364,52 @@ public class jdk8/AllFrames {
     MAXSTACK = 1
     MAXLOCALS = 5
 
+  // access flags 0x9
+  public static m1Static(II)V
+    // parameter  i
+    // parameter  j
+   L0
+    LINENUMBER 120 L0
+    ILOAD 1
+    ISTORE 3
+   L1
+    LINENUMBER 121 L1
+    ILOAD 0
+    IFGE L2
+   L3
+    LINENUMBER 122 L3
+    ILOAD 0
+    INEG
+    ISTORE 0
+   L2
+    LINENUMBER 124 L2
+   FRAME APPEND [T I]
+    RETURN
+   L4
+    LOCALVARIABLE i I L0 L4 0
+    LOCALVARIABLE j I L0 L4 1
+    LOCALVARIABLE l I L1 L4 3
+    MAXSTACK = 1
+    MAXLOCALS = 4
+
   // access flags 0x1
   public m2(IZ)J
     // parameter  n
     // parameter  b
    L0
-    LINENUMBER 99 L0
+    LINENUMBER 128 L0
     LCONST_0
     LSTORE 3
    L1
-    LINENUMBER 100 L1
+    LINENUMBER 129 L1
     ILOAD 2
     IFEQ L2
    L3
-    LINENUMBER 101 L3
+    LINENUMBER 130 L3
     ICONST_0
     ISTORE 5
    L4
-    LINENUMBER 103 L4
+    LINENUMBER 132 L4
    FRAME APPEND [J I]
     LLOAD 3
     ILOAD 5
@@ -293,20 +418,20 @@ public class jdk8/AllFrames {
     LADD
     LSTORE 3
    L5
-    LINENUMBER 104 L5
+    LINENUMBER 133 L5
     ILOAD 5
     ILOAD 1
     IF_ICMPLT L4
    L6
-    LINENUMBER 105 L6
+    LINENUMBER 134 L6
     GOTO L7
    L2
-    LINENUMBER 106 L2
+    LINENUMBER 135 L2
    FRAME CHOP 1
     LCONST_0
     LSTORE 5
    L8
-    LINENUMBER 108 L8
+    LINENUMBER 137 L8
    FRAME APPEND [J]
     LLOAD 3
     LLOAD 5
@@ -317,14 +442,14 @@ public class jdk8/AllFrames {
     LADD
     LSTORE 3
    L9
-    LINENUMBER 109 L9
+    LINENUMBER 138 L9
     LLOAD 5
     ILOAD 1
     I2L
     LCMP
     IFLT L8
    L7
-    LINENUMBER 111 L7
+    LINENUMBER 140 L7
    FRAME CHOP 1
     LLOAD 3
     LRETURN
@@ -338,15 +463,85 @@ public class jdk8/AllFrames {
     MAXSTACK = 8
     MAXLOCALS = 7
 
+  // access flags 0x9
+  public static m2Static(IZ)J
+    // parameter  n
+    // parameter  b
+   L0
+    LINENUMBER 145 L0
+    LCONST_0
+    LSTORE 2
+   L1
+    LINENUMBER 146 L1
+    ILOAD 1
+    IFEQ L2
+   L3
+    LINENUMBER 147 L3
+    ICONST_0
+    ISTORE 4
+   L4
+    LINENUMBER 149 L4
+   FRAME APPEND [J I]
+    LLOAD 2
+    ILOAD 4
+    IINC 4 1
+    I2L
+    LADD
+    LSTORE 2
+   L5
+    LINENUMBER 150 L5
+    ILOAD 4
+    ILOAD 0
+    IF_ICMPLT L4
+   L6
+    LINENUMBER 151 L6
+    GOTO L7
+   L2
+    LINENUMBER 152 L2
+   FRAME CHOP 1
+    LCONST_0
+    LSTORE 4
+   L8
+    LINENUMBER 154 L8
+   FRAME APPEND [J]
+    LLOAD 2
+    LLOAD 4
+    DUP2
+    LCONST_1
+    LADD
+    LSTORE 4
+    LADD
+    LSTORE 2
+   L9
+    LINENUMBER 155 L9
+    LLOAD 4
+    ILOAD 0
+    I2L
+    LCMP
+    IFLT L8
+   L7
+    LINENUMBER 157 L7
+   FRAME CHOP 1
+    LLOAD 2
+    LRETURN
+   L10
+    LOCALVARIABLE i I L4 L6 4
+    LOCALVARIABLE i J L8 L7 4
+    LOCALVARIABLE n I L0 L10 0
+    LOCALVARIABLE b Z L0 L10 1
+    LOCALVARIABLE total J L1 L10 2
+    MAXSTACK = 8
+    MAXLOCALS = 6
+
   // access flags 0x1
   public m3(I)I
     // parameter  i
    L0
-    LINENUMBER 116 L0
+    LINENUMBER 162 L0
     ILOAD 1
     IFGE L1
    L2
-    LINENUMBER 117 L2
+    LINENUMBER 163 L2
     ILOAD 1
     ILOAD 1
     IADD
@@ -380,7 +575,7 @@ public class jdk8/AllFrames {
     IADD
     ISTORE 1
    L3
-    LINENUMBER 118 L3
+    LINENUMBER 164 L3
     ILOAD 1
     ILOAD 1
     IADD
@@ -414,7 +609,7 @@ public class jdk8/AllFrames {
     IADD
     ISTORE 1
    L1
-    LINENUMBER 120 L1
+    LINENUMBER 166 L1
    FRAME SAME
     ILOAD 1
     IRETURN
@@ -424,11 +619,96 @@ public class jdk8/AllFrames {
     MAXSTACK = 2
     MAXLOCALS = 2
 
+  // access flags 0x9
+  public static m3Static(I)I
+    // parameter  i
+   L0
+    LINENUMBER 171 L0
+    ILOAD 0
+    IFGE L1
+   L2
+    LINENUMBER 172 L2
+    ILOAD 0
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ISTORE 0
+   L3
+    LINENUMBER 173 L3
+    ILOAD 0
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ILOAD 0
+    IADD
+    ISTORE 0
+   L1
+    LINENUMBER 175 L1
+   FRAME SAME
+    ILOAD 0
+    IRETURN
+   L4
+    LOCALVARIABLE i I L0 L4 0
+    MAXSTACK = 2
+    MAXLOCALS = 1
+
   // access flags 0x1
   public m4(I)V
     // parameter  i
    L0
-    LINENUMBER 125 L0
+    LINENUMBER 180 L0
     ILOAD 1
     ILOAD 1
     IADD
@@ -462,7 +742,7 @@ public class jdk8/AllFrames {
     IADD
     ISTORE 1
    L1
-    LINENUMBER 126 L1
+    LINENUMBER 181 L1
     ILOAD 1
     ILOAD 1
     IADD
@@ -496,7 +776,7 @@ public class jdk8/AllFrames {
     IADD
     ISTORE 1
    L2
-    LINENUMBER 127 L2
+    LINENUMBER 182 L2
     ALOAD 0
     ILOAD 1
     IFNE L3
@@ -509,7 +789,7 @@ public class jdk8/AllFrames {
    FRAME FULL [jdk8/AllFrames I] [jdk8/AllFrames java/lang/String]
     PUTFIELD jdk8/AllFrames.s : Ljava/lang/String;
    L5
-    LINENUMBER 128 L5
+    LINENUMBER 183 L5
     RETURN
    L6
     LOCALVARIABLE this Ljdk8/AllFrames; L0 L6 0
@@ -521,7 +801,7 @@ public class jdk8/AllFrames {
   public static m5(Z)Ljava/lang/Number;
     // parameter  b
    L0
-    LINENUMBER 132 L0
+    LINENUMBER 187 L0
     ILOAD 0
     IFEQ L1
     NEW java/lang/Integer
@@ -551,7 +831,7 @@ public class jdk8/AllFrames {
   public static m6(Z)[Ljava/lang/Number;
     // parameter  b
    L0
-    LINENUMBER 137 L0
+    LINENUMBER 192 L0
     ILOAD 0
     IFEQ L1
     ICONST_1
@@ -573,7 +853,7 @@ public class jdk8/AllFrames {
   public static m7(Z)[[Ljava/lang/Number;
     // parameter  b
    L0
-    LINENUMBER 142 L0
+    LINENUMBER 197 L0
     ILOAD 0
     IFEQ L1
     ICONST_1
@@ -597,7 +877,7 @@ public class jdk8/AllFrames {
   public static m8(Z)[Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 147 L0
+    LINENUMBER 202 L0
     ILOAD 0
     IFEQ L1
     ICONST_1
@@ -623,7 +903,7 @@ public class jdk8/AllFrames {
   public static m9(Z)Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 152 L0
+    LINENUMBER 207 L0
     ILOAD 0
     IFEQ L1
     ICONST_1
@@ -645,7 +925,7 @@ public class jdk8/AllFrames {
   public static m10(Z)[Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 157 L0
+    LINENUMBER 212 L0
     ILOAD 0
     IFEQ L1
     ICONST_1
@@ -670,7 +950,7 @@ public class jdk8/AllFrames {
   public static m11(Z)Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 162 L0
+    LINENUMBER 217 L0
     ILOAD 0
     IFEQ L1
     ICONST_1
@@ -693,7 +973,7 @@ public class jdk8/AllFrames {
   public static m12(Z)[Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 167 L0
+    LINENUMBER 222 L0
     ILOAD 0
     IFEQ L1
     ICONST_1
@@ -716,7 +996,7 @@ public class jdk8/AllFrames {
   public static m13(Z)[Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 172 L0
+    LINENUMBER 227 L0
     ILOAD 0
     IFEQ L1
     ICONST_1
@@ -743,7 +1023,7 @@ public class jdk8/AllFrames {
   public static m14(Z)[[Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 177 L0
+    LINENUMBER 232 L0
     ILOAD 0
     IFEQ L1
     ICONST_1
@@ -772,7 +1052,7 @@ public class jdk8/AllFrames {
   public static m15(Z)Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 182 L0
+    LINENUMBER 237 L0
     ILOAD 0
     IFEQ L1
     NEW java/lang/Integer
@@ -796,7 +1076,7 @@ public class jdk8/AllFrames {
   public static m16(Z)Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 187 L0
+    LINENUMBER 242 L0
     ILOAD 0
     IFEQ L1
     NEW java/lang/Integer
@@ -820,7 +1100,7 @@ public class jdk8/AllFrames {
   public m17(Z)Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 192 L0
+    LINENUMBER 247 L0
     ILOAD 1
     IFEQ L1
     ICONST_0
@@ -843,7 +1123,7 @@ public class jdk8/AllFrames {
   public m18(Z)Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 197 L0
+    LINENUMBER 252 L0
     ILOAD 1
     IFEQ L1
     ICONST_0
@@ -866,7 +1146,7 @@ public class jdk8/AllFrames {
   public m19(Z)Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 202 L0
+    LINENUMBER 257 L0
     ILOAD 1
     IFEQ L1
     ICONST_0
@@ -889,7 +1169,7 @@ public class jdk8/AllFrames {
   public static m20(Z)Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 207 L0
+    LINENUMBER 262 L0
     ILOAD 0
     IFEQ L1
     ACONST_NULL
@@ -912,7 +1192,7 @@ public class jdk8/AllFrames {
   public static m21(Z)Ljava/lang/Object;
     // parameter  b
    L0
-    LINENUMBER 212 L0
+    LINENUMBER 267 L0
     ILOAD 0
     IFEQ L1
     NEW java/lang/Integer
@@ -934,11 +1214,11 @@ public class jdk8/AllFrames {
   // access flags 0x9
   public static m23()I
    L0
-    LINENUMBER 218 L0
+    LINENUMBER 273 L0
     ACONST_NULL
     ASTORE 0
    L1
-    LINENUMBER 219 L1
+    LINENUMBER 274 L1
     ALOAD 0
     ICONST_0
     AALOAD
diff --git a/asm-util/src/test/resources/jdk8.Artificial$()$Structures.txt b/asm-util/src/test/resources/jdk8.Artificial$()$Structures.txt
index 3bcfda7c..f7dd76ce 100644
--- a/asm-util/src/test/resources/jdk8.Artificial$()$Structures.txt
+++ b/asm-util/src/test/resources/jdk8.Artificial$()$Structures.txt
@@ -53,4 +53,24 @@ public class jdk8/Artificial$()$Structures {
     ARETURN
     MAXSTACK = 1
     MAXLOCALS = 0
+
+  // access flags 0x9
+  public static frameWithForwardLabelReferences([Ljava/lang/String;)V
+    GETSTATIC java/lang/System.out : Ljava/io/PrintStream;
+    GOTO L0
+   L1
+   FRAME FULL [[Ljava/lang/String;] [java/io/PrintStream L0 L0]
+    INVOKESPECIAL jdk8/Artificial$()$Structures.<init> ()V
+    GOTO L2
+   L0
+   FRAME SAME1 java/io/PrintStream
+    NEW jdk8/Artificial$()$Structures
+    DUP
+    GOTO L1
+   L2
+   FRAME FULL [[Ljava/lang/String;] [java/io/PrintStream jdk8/Artificial$()$Structures]
+    INVOKEVIRTUAL java/io/PrintStream.println (Ljava/lang/Object;)V
+    RETURN
+    MAXSTACK = 3
+    MAXLOCALS = 1
 }
diff --git a/asm/src/main/java/org/objectweb/asm/ClassReader.java b/asm/src/main/java/org/objectweb/asm/ClassReader.java
index 2cfef457..8c8e7180 100644
--- a/asm/src/main/java/org/objectweb/asm/ClassReader.java
+++ b/asm/src/main/java/org/objectweb/asm/ClassReader.java
@@ -188,13 +188,14 @@ public class ClassReader {
    * @param classFileOffset the offset in byteBuffer of the first byte of the ClassFile to be read.
    * @param checkClassVersion whether to check the class version or not.
    */
+  @SuppressWarnings("PMD.ConstructorCallsOverridableMethod")
   ClassReader(
       final byte[] classFileBuffer, final int classFileOffset, final boolean checkClassVersion) {
     this.classFileBuffer = classFileBuffer;
     this.b = classFileBuffer;
     // Check the class' major_version. This field is after the magic and minor_version fields, which
     // use 4 and 2 bytes respectively.
-    if (checkClassVersion && readShort(classFileOffset + 6) > Opcodes.V21) {
+    if (checkClassVersion && readShort(classFileOffset + 6) > Opcodes.V22) {
       throw new IllegalArgumentException(
           "Unsupported class file major version " + readShort(classFileOffset + 6));
     }
diff --git a/asm/src/main/java/org/objectweb/asm/ClassWriter.java b/asm/src/main/java/org/objectweb/asm/ClassWriter.java
index 078efa20..fcc42a2b 100644
--- a/asm/src/main/java/org/objectweb/asm/ClassWriter.java
+++ b/asm/src/main/java/org/objectweb/asm/ClassWriter.java
@@ -217,6 +217,7 @@ public class ClassWriter extends ClassVisitor {
   /**
    * Indicates what must be automatically computed in {@link MethodWriter}. Must be one of {@link
    * MethodWriter#COMPUTE_NOTHING}, {@link MethodWriter#COMPUTE_MAX_STACK_AND_LOCAL}, {@link
+   * MethodWriter#COMPUTE_MAX_STACK_AND_LOCAL_FROM_FRAMES}, {@link
    * MethodWriter#COMPUTE_INSERTED_FRAMES}, or {@link MethodWriter#COMPUTE_ALL_FRAMES}.
    */
   private int compute;
diff --git a/asm/src/main/java/org/objectweb/asm/Frame.java b/asm/src/main/java/org/objectweb/asm/Frame.java
index 89195006..5047d41e 100644
--- a/asm/src/main/java/org/objectweb/asm/Frame.java
+++ b/asm/src/main/java/org/objectweb/asm/Frame.java
@@ -64,8 +64,8 @@ package org.objectweb.asm;
  *       right shift of {@link #DIM_SHIFT}.
  *   <li>the KIND field, stored in 4 bits, indicates the kind of VALUE used. These 4 bits can be
  *       retrieved with {@link #KIND_MASK} and, without any shift, must be equal to {@link
- *       #CONSTANT_KIND}, {@link #REFERENCE_KIND}, {@link #UNINITIALIZED_KIND}, {@link #LOCAL_KIND}
- *       or {@link #STACK_KIND}.
+ *       #CONSTANT_KIND}, {@link #REFERENCE_KIND}, {@link #UNINITIALIZED_KIND}, {@link
+ *       #FORWARD_UNINITIALIZED_KIND},{@link #LOCAL_KIND} or {@link #STACK_KIND}.
  *   <li>the FLAGS field, stored in 2 bits, contains up to 2 boolean flags. Currently only one flag
  *       is defined, namely {@link #TOP_IF_LONG_OR_DOUBLE_FLAG}.
  *   <li>the VALUE field, stored in the remaining 20 bits, contains either
@@ -78,7 +78,10 @@ package org.objectweb.asm;
  *         <li>the index of a {@link Symbol#TYPE_TAG} {@link Symbol} in the type table of a {@link
  *             SymbolTable}, if KIND is equal to {@link #REFERENCE_KIND}.
  *         <li>the index of an {@link Symbol#UNINITIALIZED_TYPE_TAG} {@link Symbol} in the type
- *             table of a SymbolTable, if KIND is equal to {@link #UNINITIALIZED_KIND}.
+ *             table of a {@link SymbolTable}, if KIND is equal to {@link #UNINITIALIZED_KIND}.
+ *         <li>the index of a {@link Symbol#FORWARD_UNINITIALIZED_TYPE_TAG} {@link Symbol} in the
+ *             type table of a {@link SymbolTable}, if KIND is equal to {@link
+ *             #FORWARD_UNINITIALIZED_KIND}.
  *         <li>the index of a local variable in the input stack frame, if KIND is equal to {@link
  *             #LOCAL_KIND}.
  *         <li>a position relatively to the top of the stack of the input stack frame, if KIND is
@@ -88,10 +91,10 @@ package org.objectweb.asm;
  *
  * <p>Output frames can contain abstract types of any kind and with a positive or negative array
  * dimension (and even unassigned types, represented by 0 - which does not correspond to any valid
- * abstract type value). Input frames can only contain CONSTANT_KIND, REFERENCE_KIND or
- * UNINITIALIZED_KIND abstract types of positive or {@literal null} array dimension. In all cases
- * the type table contains only internal type names (array type descriptors are forbidden - array
- * dimensions must be represented through the DIM field).
+ * abstract type value). Input frames can only contain CONSTANT_KIND, REFERENCE_KIND,
+ * UNINITIALIZED_KIND or FORWARD_UNINITIALIZED_KIND abstract types of positive or {@literal null}
+ * array dimension. In all cases the type table contains only internal type names (array type
+ * descriptors are forbidden - array dimensions must be represented through the DIM field).
  *
  * <p>The LONG and DOUBLE types are always represented by using two slots (LONG + TOP or DOUBLE +
  * TOP), for local variables as well as in the operand stack. This is necessary to be able to
@@ -159,8 +162,9 @@ class Frame {
   private static final int CONSTANT_KIND = 1 << KIND_SHIFT;
   private static final int REFERENCE_KIND = 2 << KIND_SHIFT;
   private static final int UNINITIALIZED_KIND = 3 << KIND_SHIFT;
-  private static final int LOCAL_KIND = 4 << KIND_SHIFT;
-  private static final int STACK_KIND = 5 << KIND_SHIFT;
+  private static final int FORWARD_UNINITIALIZED_KIND = 4 << KIND_SHIFT;
+  private static final int LOCAL_KIND = 5 << KIND_SHIFT;
+  private static final int STACK_KIND = 6 << KIND_SHIFT;
 
   // Possible flags for the FLAGS field of an abstract type.
 
@@ -220,13 +224,13 @@ class Frame {
 
   /**
    * The abstract types that are initialized in the basic block. A constructor invocation on an
-   * UNINITIALIZED or UNINITIALIZED_THIS abstract type must replace <i>every occurrence</i> of this
-   * type in the local variables and in the operand stack. This cannot be done during the first step
-   * of the algorithm since, during this step, the local variables and the operand stack types are
-   * still abstract. It is therefore necessary to store the abstract types of the constructors which
-   * are invoked in the basic block, in order to do this replacement during the second step of the
-   * algorithm, where the frames are fully computed. Note that this array can contain abstract types
-   * that are relative to the input locals or to the input stack.
+   * UNINITIALIZED, FORWARD_UNINITIALIZED or UNINITIALIZED_THIS abstract type must replace <i>every
+   * occurrence</i> of this type in the local variables and in the operand stack. This cannot be
+   * done during the first step of the algorithm since, during this step, the local variables and
+   * the operand stack types are still abstract. It is therefore necessary to store the abstract
+   * types of the constructors which are invoked in the basic block, in order to do this replacement
+   * during the second step of the algorithm, where the frames are fully computed. Note that this
+   * array can contain abstract types that are relative to the input locals or to the input stack.
    */
   private int[] initializations;
 
@@ -284,8 +288,12 @@ class Frame {
       String descriptor = Type.getObjectType((String) type).getDescriptor();
       return getAbstractTypeFromDescriptor(symbolTable, descriptor, 0);
     } else {
-      return UNINITIALIZED_KIND
-          | symbolTable.addUninitializedType("", ((Label) type).bytecodeOffset);
+      Label label = (Label) type;
+      if ((label.flags & Label.FLAG_RESOLVED) != 0) {
+        return UNINITIALIZED_KIND | symbolTable.addUninitializedType("", label.bytecodeOffset);
+      } else {
+        return FORWARD_UNINITIALIZED_KIND | symbolTable.addForwardUninitializedType("", label);
+      }
     }
   }
 
@@ -637,12 +645,14 @@ class Frame {
    * @param symbolTable the type table to use to lookup and store type {@link Symbol}.
    * @param abstractType an abstract type.
    * @return the REFERENCE_KIND abstract type corresponding to abstractType if it is
-   *     UNINITIALIZED_THIS or an UNINITIALIZED_KIND abstract type for one of the types on which a
-   *     constructor is invoked in the basic block. Otherwise returns abstractType.
+   *     UNINITIALIZED_THIS or an UNINITIALIZED_KIND or FORWARD_UNINITIALIZED_KIND abstract type for
+   *     one of the types on which a constructor is invoked in the basic block. Otherwise returns
+   *     abstractType.
    */
   private int getInitializedType(final SymbolTable symbolTable, final int abstractType) {
     if (abstractType == UNINITIALIZED_THIS
-        || (abstractType & (DIM_MASK | KIND_MASK)) == UNINITIALIZED_KIND) {
+        || (abstractType & (DIM_MASK | KIND_MASK)) == UNINITIALIZED_KIND
+        || (abstractType & (DIM_MASK | KIND_MASK)) == FORWARD_UNINITIALIZED_KIND) {
       for (int i = 0; i < initializationCount; ++i) {
         int initializedType = initializations[i];
         int dim = initializedType & DIM_MASK;
@@ -1253,11 +1263,12 @@ class Frame {
    *
    * @param symbolTable the type table to use to lookup and store type {@link Symbol}.
    * @param sourceType the abstract type with which the abstract type array element must be merged.
-   *     This type should be of {@link #CONSTANT_KIND}, {@link #REFERENCE_KIND} or {@link
-   *     #UNINITIALIZED_KIND} kind, with positive or {@literal null} array dimensions.
+   *     This type should be of {@link #CONSTANT_KIND}, {@link #REFERENCE_KIND}, {@link
+   *     #UNINITIALIZED_KIND} or {@link #FORWARD_UNINITIALIZED_KIND} kind, with positive or
+   *     {@literal null} array dimensions.
    * @param dstTypes an array of abstract types. These types should be of {@link #CONSTANT_KIND},
-   *     {@link #REFERENCE_KIND} or {@link #UNINITIALIZED_KIND} kind, with positive or {@literal
-   *     null} array dimensions.
+   *     {@link #REFERENCE_KIND}, {@link #UNINITIALIZED_KIND} or {@link #FORWARD_UNINITIALIZED_KIND}
+   *     kind, with positive or {@literal null} array dimensions.
    * @param dstIndex the index of the type that must be merged in dstTypes.
    * @return {@literal true} if the type array has been modified by this operation.
    */
@@ -1400,7 +1411,8 @@ class Frame {
    *
    * @param symbolTable the type table to use to lookup and store type {@link Symbol}.
    * @param abstractType an abstract type, restricted to {@link Frame#CONSTANT_KIND}, {@link
-   *     Frame#REFERENCE_KIND} or {@link Frame#UNINITIALIZED_KIND} types.
+   *     Frame#REFERENCE_KIND}, {@link Frame#UNINITIALIZED_KIND} or {@link
+   *     Frame#FORWARD_UNINITIALIZED_KIND} types.
    * @param output where the abstract type must be put.
    * @see <a href="https://docs.oracle.com/javase/specs/jvms/se9/html/jvms-4.html#jvms-4.7.4">JVMS
    *     4.7.4</a>
@@ -1422,6 +1434,10 @@ class Frame {
         case UNINITIALIZED_KIND:
           output.putByte(ITEM_UNINITIALIZED).putShort((int) symbolTable.getType(typeValue).data);
           break;
+        case FORWARD_UNINITIALIZED_KIND:
+          output.putByte(ITEM_UNINITIALIZED);
+          symbolTable.getForwardUninitializedLabel(typeValue).put(output);
+          break;
         default:
           throw new AssertionError();
       }
diff --git a/asm/src/main/java/org/objectweb/asm/Label.java b/asm/src/main/java/org/objectweb/asm/Label.java
index 4bcf7c56..5189e1f6 100644
--- a/asm/src/main/java/org/objectweb/asm/Label.java
+++ b/asm/src/main/java/org/objectweb/asm/Label.java
@@ -116,6 +116,13 @@ public class Label {
    */
   static final int FORWARD_REFERENCE_TYPE_WIDE = 0x20000000;
 
+  /**
+   * The type of forward references stored in two bytes in the <i>stack map table</i>. This is the
+   * case of the labels of {@link Frame#ITEM_UNINITIALIZED} stack map frame elements, when the NEW
+   * instruction is after the &lt;init&gt; constructor call (in bytecode offset order).
+   */
+  static final int FORWARD_REFERENCE_TYPE_STACK_MAP = 0x30000000;
+
   /**
    * The bit mask to extract the 'handle' of a forward reference to this label. The extracted handle
    * is the bytecode offset where the forward reference value is stored (using either 2 or 4 bytes,
@@ -404,6 +411,20 @@ public class Label {
     }
   }
 
+  /**
+   * Puts a reference to this label in the <i>stack map table</i> of a method. If the bytecode
+   * offset of the label is known, it is written directly. Otherwise, a null relative offset is
+   * written and a new forward reference is declared for this label.
+   *
+   * @param stackMapTableEntries the stack map table where the label offset must be added.
+   */
+  final void put(final ByteVector stackMapTableEntries) {
+    if ((flags & FLAG_RESOLVED) == 0) {
+      addForwardReference(0, FORWARD_REFERENCE_TYPE_STACK_MAP, stackMapTableEntries.length);
+    }
+    stackMapTableEntries.putShort(bytecodeOffset);
+  }
+
   /**
    * Adds a forward reference to this label. This method must be called only for a true forward
    * reference, i.e. only if this label is not resolved yet. For backward references, the relative
@@ -436,9 +457,12 @@ public class Label {
    * Sets the bytecode offset of this label to the given value and resolves the forward references
    * to this label, if any. This method must be called when this label is added to the bytecode of
    * the method, i.e. when its bytecode offset becomes known. This method fills in the blanks that
-   * where left in the bytecode by each forward reference previously added to this label.
+   * where left in the bytecode (and optionally in the stack map table) by each forward reference
+   * previously added to this label.
    *
    * @param code the bytecode of the method.
+   * @param stackMapTableEntries the 'entries' array of the StackMapTable code attribute of the
+   *     method. Maybe {@literal null}.
    * @param bytecodeOffset the bytecode offset of this label.
    * @return {@literal true} if a blank that was left for this label was too small to store the
    *     offset. In such a case the corresponding jump instruction is replaced with an equivalent
@@ -446,7 +470,8 @@ public class Label {
    *     instructions are later replaced with standard bytecode instructions with wider offsets (4
    *     bytes instead of 2), in ClassReader.
    */
-  final boolean resolve(final byte[] code, final int bytecodeOffset) {
+  final boolean resolve(
+      final byte[] code, final ByteVector stackMapTableEntries, final int bytecodeOffset) {
     this.flags |= FLAG_RESOLVED;
     this.bytecodeOffset = bytecodeOffset;
     if (forwardReferences == null) {
@@ -476,11 +501,14 @@ public class Label {
         }
         code[handle++] = (byte) (relativeOffset >>> 8);
         code[handle] = (byte) relativeOffset;
-      } else {
+      } else if ((reference & FORWARD_REFERENCE_TYPE_MASK) == FORWARD_REFERENCE_TYPE_WIDE) {
         code[handle++] = (byte) (relativeOffset >>> 24);
         code[handle++] = (byte) (relativeOffset >>> 16);
         code[handle++] = (byte) (relativeOffset >>> 8);
         code[handle] = (byte) relativeOffset;
+      } else {
+        stackMapTableEntries.data[handle++] = (byte) (bytecodeOffset >>> 8);
+        stackMapTableEntries.data[handle] = (byte) bytecodeOffset;
       }
     }
     return hasAsmInstructions;
diff --git a/asm/src/main/java/org/objectweb/asm/MethodWriter.java b/asm/src/main/java/org/objectweb/asm/MethodWriter.java
index d238d391..8cdeec47 100644
--- a/asm/src/main/java/org/objectweb/asm/MethodWriter.java
+++ b/asm/src/main/java/org/objectweb/asm/MethodWriter.java
@@ -534,8 +534,9 @@ final class MethodWriter extends MethodVisitor {
    * the number of stack elements. The local variables start at index 3 and are followed by the
    * operand stack elements. In summary frame[0] = offset, frame[1] = numLocal, frame[2] = numStack.
    * Local variables and operand stack entries contain abstract types, as defined in {@link Frame},
-   * but restricted to {@link Frame#CONSTANT_KIND}, {@link Frame#REFERENCE_KIND} or {@link
-   * Frame#UNINITIALIZED_KIND} abstract types. Long and double types use only one array entry.
+   * but restricted to {@link Frame#CONSTANT_KIND}, {@link Frame#REFERENCE_KIND}, {@link
+   * Frame#UNINITIALIZED_KIND} or {@link Frame#FORWARD_UNINITIALIZED_KIND} abstract types. Long and
+   * double types use only one array entry.
    */
   private int[] currentFrame;
 
@@ -693,7 +694,7 @@ final class MethodWriter extends MethodVisitor {
     if (visible) {
       if (lastRuntimeVisibleParameterAnnotations == null) {
         lastRuntimeVisibleParameterAnnotations =
-            new AnnotationWriter[Type.getArgumentTypes(descriptor).length];
+            new AnnotationWriter[Type.getArgumentCount(descriptor)];
       }
       return lastRuntimeVisibleParameterAnnotations[parameter] =
           AnnotationWriter.create(
@@ -701,7 +702,7 @@ final class MethodWriter extends MethodVisitor {
     } else {
       if (lastRuntimeInvisibleParameterAnnotations == null) {
         lastRuntimeInvisibleParameterAnnotations =
-            new AnnotationWriter[Type.getArgumentTypes(descriptor).length];
+            new AnnotationWriter[Type.getArgumentCount(descriptor)];
       }
       return lastRuntimeInvisibleParameterAnnotations[parameter] =
           AnnotationWriter.create(
@@ -1199,7 +1200,7 @@ final class MethodWriter extends MethodVisitor {
   @Override
   public void visitLabel(final Label label) {
     // Resolve the forward references to this label, if any.
-    hasAsmInstructions |= label.resolve(code.data, code.length);
+    hasAsmInstructions |= label.resolve(code.data, stackMapTableEntries, code.length);
     // visitLabel starts a new basic block (except for debug only labels), so we need to update the
     // previous and current block references and list of successors.
     if ((label.flags & Label.FLAG_DEBUG_ONLY) != 0) {
@@ -1795,7 +1796,7 @@ final class MethodWriter extends MethodVisitor {
     if (compute == COMPUTE_ALL_FRAMES) {
       Label nextBasicBlock = new Label();
       nextBasicBlock.frame = new Frame(nextBasicBlock);
-      nextBasicBlock.resolve(code.data, code.length);
+      nextBasicBlock.resolve(code.data, stackMapTableEntries, code.length);
       lastBasicBlock.nextBasicBlock = nextBasicBlock;
       lastBasicBlock = nextBasicBlock;
       currentBasicBlock = null;
@@ -1979,9 +1980,8 @@ final class MethodWriter extends MethodVisitor {
           .putByte(Frame.ITEM_OBJECT)
           .putShort(symbolTable.addConstantClass((String) type).index);
     } else {
-      stackMapTableEntries
-          .putByte(Frame.ITEM_UNINITIALIZED)
-          .putShort(((Label) type).bytecodeOffset);
+      stackMapTableEntries.putByte(Frame.ITEM_UNINITIALIZED);
+      ((Label) type).put(stackMapTableEntries);
     }
   }
 
diff --git a/asm/src/main/java/org/objectweb/asm/Opcodes.java b/asm/src/main/java/org/objectweb/asm/Opcodes.java
index 7202784f..9f32e10b 100644
--- a/asm/src/main/java/org/objectweb/asm/Opcodes.java
+++ b/asm/src/main/java/org/objectweb/asm/Opcodes.java
@@ -287,6 +287,7 @@ public interface Opcodes {
   int V19 = 0 << 16 | 63;
   int V20 = 0 << 16 | 64;
   int V21 = 0 << 16 | 65;
+  int V22 = 0 << 16 | 66;
 
   /**
    * Version flag indicating that the class is using 'preview' features.
diff --git a/asm/src/main/java/org/objectweb/asm/Symbol.java b/asm/src/main/java/org/objectweb/asm/Symbol.java
index b1dd5eb0..fcc4e10f 100644
--- a/asm/src/main/java/org/objectweb/asm/Symbol.java
+++ b/asm/src/main/java/org/objectweb/asm/Symbol.java
@@ -103,12 +103,25 @@ abstract class Symbol {
   static final int TYPE_TAG = 128;
 
   /**
-   * The tag value of an {@link Frame#ITEM_UNINITIALIZED} type entry in the type table of a class.
+   * The tag value of an uninitialized type entry in the type table of a class. This type is used
+   * for the normal case where the NEW instruction is before the &lt;init&gt; constructor call (in
+   * bytecode offset order), i.e. when the label of the NEW instruction is resolved when the
+   * constructor call is visited. If the NEW instruction is after the constructor call, use the
+   * {@link #FORWARD_UNINITIALIZED_TYPE_TAG} tag value instead.
    */
   static final int UNINITIALIZED_TYPE_TAG = 129;
 
+  /**
+   * The tag value of an uninitialized type entry in the type table of a class. This type is used
+   * for the unusual case where the NEW instruction is after the &lt;init&gt; constructor call (in
+   * bytecode offset order), i.e. when the label of the NEW instruction is not resolved when the
+   * constructor call is visited. If the NEW instruction is before the constructor call, use the
+   * {@link #UNINITIALIZED_TYPE_TAG} tag value instead.
+   */
+  static final int FORWARD_UNINITIALIZED_TYPE_TAG = 130;
+
   /** The tag value of a merged type entry in the (ASM specific) type table of a class. */
-  static final int MERGED_TYPE_TAG = 130;
+  static final int MERGED_TYPE_TAG = 131;
 
   // Instance fields.
 
@@ -151,8 +164,8 @@ abstract class Symbol {
    *       #CONSTANT_INVOKE_DYNAMIC_TAG} symbols,
    *   <li>an arbitrary string for {@link #CONSTANT_UTF8_TAG} and {@link #CONSTANT_STRING_TAG}
    *       symbols,
-   *   <li>an internal class name for {@link #CONSTANT_CLASS_TAG}, {@link #TYPE_TAG} and {@link
-   *       #UNINITIALIZED_TYPE_TAG} symbols,
+   *   <li>an internal class name for {@link #CONSTANT_CLASS_TAG}, {@link #TYPE_TAG}, {@link
+   *       #UNINITIALIZED_TYPE_TAG} and {@link #FORWARD_UNINITIALIZED_TYPE_TAG} symbols,
    *   <li>{@literal null} for the other types of symbol.
    * </ul>
    */
@@ -172,6 +185,9 @@ abstract class Symbol {
    *       {@link #CONSTANT_DYNAMIC_TAG} or {@link #BOOTSTRAP_METHOD_TAG} symbols,
    *   <li>the bytecode offset of the NEW instruction that created an {@link
    *       Frame#ITEM_UNINITIALIZED} type for {@link #UNINITIALIZED_TYPE_TAG} symbols,
+   *   <li>the index of the {@link Label} (in the {@link SymbolTable#labelTable} table) of the NEW
+   *       instruction that created an {@link Frame#ITEM_UNINITIALIZED} type for {@link
+   *       #FORWARD_UNINITIALIZED_TYPE_TAG} symbols,
    *   <li>the indices (in the class' type table) of two {@link #TYPE_TAG} source types for {@link
    *       #MERGED_TYPE_TAG} symbols,
    *   <li>0 for the other types of symbol.
diff --git a/asm/src/main/java/org/objectweb/asm/SymbolTable.java b/asm/src/main/java/org/objectweb/asm/SymbolTable.java
index a2f26f18..a4cbb486 100644
--- a/asm/src/main/java/org/objectweb/asm/SymbolTable.java
+++ b/asm/src/main/java/org/objectweb/asm/SymbolTable.java
@@ -108,11 +108,35 @@ final class SymbolTable {
    * An ASM specific type table used to temporarily store internal names that will not necessarily
    * be stored in the constant pool. This type table is used by the control flow and data flow
    * analysis algorithm used to compute stack map frames from scratch. This array stores {@link
-   * Symbol#TYPE_TAG} and {@link Symbol#UNINITIALIZED_TYPE_TAG}) Symbol. The type symbol at index
-   * {@code i} has its {@link Symbol#index} equal to {@code i} (and vice versa).
+   * Symbol#TYPE_TAG}, {@link Symbol#UNINITIALIZED_TYPE_TAG},{@link
+   * Symbol#FORWARD_UNINITIALIZED_TYPE_TAG} and {@link Symbol#MERGED_TYPE_TAG} entries. The type
+   * symbol at index {@code i} has its {@link Symbol#index} equal to {@code i} (and vice versa).
    */
   private Entry[] typeTable;
 
+  /**
+   * The actual number of {@link LabelEntry} in {@link #labelTable}. These elements are stored from
+   * index 0 to labelCount (excluded). The other array entries are empty. These label entries are
+   * also stored in the {@link #labelEntries} hash set.
+   */
+  private int labelCount;
+
+  /**
+   * The labels corresponding to the "forward uninitialized" types in the ASM specific {@link
+   * typeTable} (see {@link Symbol#FORWARD_UNINITIALIZED_TYPE_TAG}). The label entry at index {@code
+   * i} has its {@link LabelEntry#index} equal to {@code i} (and vice versa).
+   */
+  private LabelEntry[] labelTable;
+
+  /**
+   * A hash set of all the {@link LabelEntry} elements in the {@link #labelTable}. Each {@link
+   * LabelEntry} instance is stored at the array index given by its hash code modulo the array size.
+   * If several entries must be stored at the same array index, they are linked together via their
+   * {@link LabelEntry#next} field. The {@link #getOrAddLabelEntry(Label)} method ensures that this
+   * table does not contain duplicated entries.
+   */
+  private LabelEntry[] labelEntries;
+
   /**
    * Constructs a new, empty SymbolTable for the given ClassWriter.
    *
@@ -1129,6 +1153,18 @@ final class SymbolTable {
     return typeTable[typeIndex];
   }
 
+  /**
+   * Returns the label corresponding to the "forward uninitialized" type table element whose index
+   * is given.
+   *
+   * @param typeIndex the type table index of a "forward uninitialized" type table element.
+   * @return the label corresponding of the NEW instruction which created this "forward
+   *     uninitialized" type.
+   */
+  Label getForwardUninitializedLabel(final int typeIndex) {
+    return labelTable[(int) typeTable[typeIndex].data].label;
+  }
+
   /**
    * Adds a type in the type table of this symbol table. Does nothing if the type table already
    * contains a similar type.
@@ -1149,13 +1185,13 @@ final class SymbolTable {
   }
 
   /**
-   * Adds an {@link Frame#ITEM_UNINITIALIZED} type in the type table of this symbol table. Does
-   * nothing if the type table already contains a similar type.
+   * Adds an uninitialized type in the type table of this symbol table. Does nothing if the type
+   * table already contains a similar type.
    *
    * @param value an internal class name.
-   * @param bytecodeOffset the bytecode offset of the NEW instruction that created this {@link
-   *     Frame#ITEM_UNINITIALIZED} type value.
-   * @return the index of a new or already existing type Symbol with the given value.
+   * @param bytecodeOffset the bytecode offset of the NEW instruction that created this
+   *     uninitialized type value.
+   * @return the index of a new or already existing type #@link Symbol} with the given value.
    */
   int addUninitializedType(final String value, final int bytecodeOffset) {
     int hashCode = hash(Symbol.UNINITIALIZED_TYPE_TAG, value, bytecodeOffset);
@@ -1173,6 +1209,32 @@ final class SymbolTable {
         new Entry(typeCount, Symbol.UNINITIALIZED_TYPE_TAG, value, bytecodeOffset, hashCode));
   }
 
+  /**
+   * Adds a "forward uninitialized" type in the type table of this symbol table. Does nothing if the
+   * type table already contains a similar type.
+   *
+   * @param value an internal class name.
+   * @param label the label of the NEW instruction that created this uninitialized type value. If
+   *     the label is resolved, use the {@link #addUninitializedType} method instead.
+   * @return the index of a new or already existing type {@link Symbol} with the given value.
+   */
+  int addForwardUninitializedType(final String value, final Label label) {
+    int labelIndex = getOrAddLabelEntry(label).index;
+    int hashCode = hash(Symbol.FORWARD_UNINITIALIZED_TYPE_TAG, value, labelIndex);
+    Entry entry = get(hashCode);
+    while (entry != null) {
+      if (entry.tag == Symbol.FORWARD_UNINITIALIZED_TYPE_TAG
+          && entry.hashCode == hashCode
+          && entry.data == labelIndex
+          && entry.value.equals(value)) {
+        return entry.index;
+      }
+      entry = entry.next;
+    }
+    return addTypeInternal(
+        new Entry(typeCount, Symbol.FORWARD_UNINITIALIZED_TYPE_TAG, value, labelIndex, hashCode));
+  }
+
   /**
    * Adds a merged type in the type table of this symbol table. Does nothing if the type table
    * already contains a similar type.
@@ -1225,6 +1287,59 @@ final class SymbolTable {
     return put(entry).index;
   }
 
+  /**
+   * Returns the {@link LabelEntry} corresponding to the given label. Creates a new one if there is
+   * no such entry.
+   *
+   * @param label the {@link Label} of a NEW instruction which created an uninitialized type, in the
+   *     case where this NEW instruction is after the &lt;init&gt; constructor call (in bytecode
+   *     offset order). See {@link Symbol#FORWARD_UNINITIALIZED_TYPE_TAG}.
+   * @return the {@link LabelEntry} corresponding to {@code label}.
+   */
+  private LabelEntry getOrAddLabelEntry(final Label label) {
+    if (labelEntries == null) {
+      labelEntries = new LabelEntry[16];
+      labelTable = new LabelEntry[16];
+    }
+    int hashCode = System.identityHashCode(label);
+    LabelEntry labelEntry = labelEntries[hashCode % labelEntries.length];
+    while (labelEntry != null && labelEntry.label != label) {
+      labelEntry = labelEntry.next;
+    }
+    if (labelEntry != null) {
+      return labelEntry;
+    }
+
+    if (labelCount > (labelEntries.length * 3) / 4) {
+      int currentCapacity = labelEntries.length;
+      int newCapacity = currentCapacity * 2 + 1;
+      LabelEntry[] newLabelEntries = new LabelEntry[newCapacity];
+      for (int i = currentCapacity - 1; i >= 0; --i) {
+        LabelEntry currentEntry = labelEntries[i];
+        while (currentEntry != null) {
+          int newCurrentEntryIndex = System.identityHashCode(currentEntry.label) % newCapacity;
+          LabelEntry nextEntry = currentEntry.next;
+          currentEntry.next = newLabelEntries[newCurrentEntryIndex];
+          newLabelEntries[newCurrentEntryIndex] = currentEntry;
+          currentEntry = nextEntry;
+        }
+      }
+      labelEntries = newLabelEntries;
+    }
+    if (labelCount == labelTable.length) {
+      LabelEntry[] newLabelTable = new LabelEntry[2 * labelTable.length];
+      System.arraycopy(labelTable, 0, newLabelTable, 0, labelTable.length);
+      labelTable = newLabelTable;
+    }
+
+    labelEntry = new LabelEntry(labelCount, label);
+    int index = hashCode % labelEntries.length;
+    labelEntry.next = labelEntries[index];
+    labelEntries[index] = labelEntry;
+    labelTable[labelCount++] = labelEntry;
+    return labelEntry;
+  }
+
   // -----------------------------------------------------------------------------------------------
   // Static helper methods to compute hash codes.
   // -----------------------------------------------------------------------------------------------
@@ -1275,7 +1390,7 @@ final class SymbolTable {
    *
    * @author Eric Bruneton
    */
-  private static class Entry extends Symbol {
+  private static final class Entry extends Symbol {
 
     /** The hash code of this entry. */
     final int hashCode;
@@ -1319,4 +1434,30 @@ final class SymbolTable {
       this.hashCode = hashCode;
     }
   }
+
+  /**
+   * A label corresponding to a "forward uninitialized" type in the ASM specific {@link
+   * SymbolTable#typeTable} (see {@link Symbol#FORWARD_UNINITIALIZED_TYPE_TAG}).
+   *
+   * @author Eric Bruneton
+   */
+  private static final class LabelEntry {
+
+    /** The index of this label entry in the {@link SymbolTable#labelTable} array. */
+    final int index;
+
+    /** The value of this label entry. */
+    final Label label;
+
+    /**
+     * Another entry (and so on recursively) having the same hash code (modulo the size of {@link
+     * SymbolTable#labelEntries}}) as this one.
+     */
+    LabelEntry next;
+
+    LabelEntry(final int index, final Label label) {
+      this.index = index;
+      this.label = label;
+    }
+  }
 }
diff --git a/asm/src/main/java/org/objectweb/asm/Type.java b/asm/src/main/java/org/objectweb/asm/Type.java
index 85aab7ea..c60a4233 100644
--- a/asm/src/main/java/org/objectweb/asm/Type.java
+++ b/asm/src/main/java/org/objectweb/asm/Type.java
@@ -295,26 +295,12 @@ public final class Type {
    */
   public static Type[] getArgumentTypes(final String methodDescriptor) {
     // First step: compute the number of argument types in methodDescriptor.
-    int numArgumentTypes = 0;
-    // Skip the first character, which is always a '('.
-    int currentOffset = 1;
-    // Parse the argument types, one at a each loop iteration.
-    while (methodDescriptor.charAt(currentOffset) != ')') {
-      while (methodDescriptor.charAt(currentOffset) == '[') {
-        currentOffset++;
-      }
-      if (methodDescriptor.charAt(currentOffset++) == 'L') {
-        // Skip the argument descriptor content.
-        int semiColumnOffset = methodDescriptor.indexOf(';', currentOffset);
-        currentOffset = Math.max(currentOffset, semiColumnOffset + 1);
-      }
-      ++numArgumentTypes;
-    }
+    int numArgumentTypes = getArgumentCount(methodDescriptor);
 
     // Second step: create a Type instance for each argument type.
     Type[] argumentTypes = new Type[numArgumentTypes];
     // Skip the first character, which is always a '('.
-    currentOffset = 1;
+    int currentOffset = 1;
     // Parse and create the argument types, one at each loop iteration.
     int currentArgumentTypeIndex = 0;
     while (methodDescriptor.charAt(currentOffset) != ')') {
@@ -702,6 +688,43 @@ public final class Type {
     }
   }
 
+  /**
+   * Returns the number of arguments of this method type. This method should only be used for method
+   * types.
+   *
+   * @return the number of arguments of this method type. Each argument counts for 1, even long and
+   *     double ones. The implicit @literal{this} argument is not counted.
+   */
+  public int getArgumentCount() {
+    return getArgumentCount(getDescriptor());
+  }
+
+  /**
+   * Returns the number of arguments in the given method descriptor.
+   *
+   * @param methodDescriptor a method descriptor.
+   * @return the number of arguments in the given method descriptor. Each argument counts for 1,
+   *     even long and double ones. The implicit @literal{this} argument is not counted.
+   */
+  public static int getArgumentCount(final String methodDescriptor) {
+    int argumentCount = 0;
+    // Skip the first character, which is always a '('.
+    int currentOffset = 1;
+    // Parse the argument types, one at a each loop iteration.
+    while (methodDescriptor.charAt(currentOffset) != ')') {
+      while (methodDescriptor.charAt(currentOffset) == '[') {
+        currentOffset++;
+      }
+      if (methodDescriptor.charAt(currentOffset++) == 'L') {
+        // Skip the argument descriptor content.
+        int semiColumnOffset = methodDescriptor.indexOf(';', currentOffset);
+        currentOffset = Math.max(currentOffset, semiColumnOffset + 1);
+      }
+      ++argumentCount;
+    }
+    return argumentCount;
+  }
+
   /**
    * Returns the size of the arguments and of the return value of methods of this type. This method
    * should only be used for method types.
@@ -709,7 +732,8 @@ public final class Type {
    * @return the size of the arguments of the method (plus one for the implicit this argument),
    *     argumentsSize, and the size of its return value, returnSize, packed into a single int i =
    *     {@code (argumentsSize &lt;&lt; 2) | returnSize} (argumentsSize is therefore equal to {@code
-   *     i &gt;&gt; 2}, and returnSize to {@code i &amp; 0x03}).
+   *     i &gt;&gt; 2}, and returnSize to {@code i &amp; 0x03}). Long and double values have size 2,
+   *     the others have size 1.
    */
   public int getArgumentsAndReturnSizes() {
     return getArgumentsAndReturnSizes(getDescriptor());
@@ -722,7 +746,8 @@ public final class Type {
    * @return the size of the arguments of the method (plus one for the implicit this argument),
    *     argumentsSize, and the size of its return value, returnSize, packed into a single int i =
    *     {@code (argumentsSize &lt;&lt; 2) | returnSize} (argumentsSize is therefore equal to {@code
-   *     i &gt;&gt; 2}, and returnSize to {@code i &amp; 0x03}).
+   *     i &gt;&gt; 2}, and returnSize to {@code i &amp; 0x03}). Long and double values have size 2,
+   *     the others have size 1.
    */
   public static int getArgumentsAndReturnSizes(final String methodDescriptor) {
     int argumentsSize = 1;
diff --git a/asm/src/test/java/org/objectweb/asm/ClassWriterComputeMaxsTest.java b/asm/src/test/java/org/objectweb/asm/ClassWriterComputeMaxsTest.java
index 7e92d457..363ff000 100644
--- a/asm/src/test/java/org/objectweb/asm/ClassWriterComputeMaxsTest.java
+++ b/asm/src/test/java/org/objectweb/asm/ClassWriterComputeMaxsTest.java
@@ -1008,7 +1008,7 @@ class ClassWriterComputeMaxsTest {
     }
   }
 
-  private static final class TestCaseBuilder {
+  private static final class TestCaseBuilder { // NOPMD(TestClassWithoutTestCases)
 
     private final ClassWriter classWriter;
     private final MethodVisitor methodVisitor;
diff --git a/asm/src/test/java/org/objectweb/asm/ClassWriterTest.java b/asm/src/test/java/org/objectweb/asm/ClassWriterTest.java
index fb9034ed..df146d3c 100644
--- a/asm/src/test/java/org/objectweb/asm/ClassWriterTest.java
+++ b/asm/src/test/java/org/objectweb/asm/ClassWriterTest.java
@@ -456,6 +456,64 @@ class ClassWriterTest extends AsmTest {
     assertTrue(new ClassFile(classFile).toString().contains("[[[[[[[[Ljava/lang/Number;"));
   }
 
+  @Test
+  void testToByteArray_manyFramesWithForwardLabelReferences() {
+    ClassWriter classWriter = new ClassWriter(0);
+    classWriter.visit(Opcodes.V1_7, Opcodes.ACC_PUBLIC, "A", null, "java/lang/Object", null);
+    MethodVisitor constructor =
+        classWriter.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
+    constructor.visitCode();
+    constructor.visitVarInsn(Opcodes.ALOAD, 0);
+    constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
+    constructor.visitInsn(Opcodes.RETURN);
+    constructor.visitMaxs(1, 1);
+    constructor.visitEnd();
+    MethodVisitor methodVisitor =
+        classWriter.visitMethod(Opcodes.ACC_STATIC, "m", "()V", null, null);
+    methodVisitor.visitCode();
+    Label label0 = new Label();
+    methodVisitor.visitJumpInsn(Opcodes.GOTO, label0);
+    Label label1 = new Label();
+    methodVisitor.visitLabel(label1);
+    Label[] newLabels = new Label[24];
+    for (int i = 0; i < newLabels.length; ++i) {
+      newLabels[i] = new Label();
+    }
+    methodVisitor.visitFrame(Opcodes.F_NEW, newLabels.length, newLabels, 0, null);
+    for (int i = 0; i < newLabels.length; ++i) {
+      methodVisitor.visitVarInsn(Opcodes.ALOAD, i);
+      methodVisitor.visitMethodInsn(Opcodes.INVOKESPECIAL, "A", "<init>", "()V", false);
+    }
+    Label label2 = new Label();
+    methodVisitor.visitJumpInsn(Opcodes.GOTO, label2);
+    methodVisitor.visitLabel(label0);
+    Object[] topTypes = new Object[newLabels.length];
+    for (int i = 0; i < topTypes.length; ++i) {
+      topTypes[i] = Opcodes.TOP;
+    }
+    methodVisitor.visitFrame(Opcodes.F_NEW, topTypes.length, topTypes, 0, null);
+    for (int i = 0; i < newLabels.length; ++i) {
+      methodVisitor.visitLabel(newLabels[i]);
+      methodVisitor.visitTypeInsn(Opcodes.NEW, "A");
+      methodVisitor.visitVarInsn(Opcodes.ASTORE, i);
+    }
+    methodVisitor.visitJumpInsn(Opcodes.GOTO, label1);
+    methodVisitor.visitLabel(label2);
+    String[] newTypes = new String[newLabels.length];
+    for (int i = 0; i < newTypes.length; ++i) {
+      newTypes[i] = "A";
+    }
+    methodVisitor.visitFrame(Opcodes.F_NEW, newTypes.length, newTypes, 0, null);
+    methodVisitor.visitInsn(Opcodes.RETURN);
+    methodVisitor.visitMaxs(1, newLabels.length);
+    methodVisitor.visitEnd();
+    classWriter.visitEnd();
+
+    byte[] classFile = classWriter.toByteArray();
+
+    assertDoesNotThrow(() -> new ClassFile(classFile).newInstance());
+  }
+
   @Test
   void testGetCommonSuperClass() {
     ClassWriter classWriter = new ClassWriter(0);
diff --git a/asm/src/test/java/org/objectweb/asm/ConstantsTest.java b/asm/src/test/java/org/objectweb/asm/ConstantsTest.java
index 54955c54..12630ebd 100644
--- a/asm/src/test/java/org/objectweb/asm/ConstantsTest.java
+++ b/asm/src/test/java/org/objectweb/asm/ConstantsTest.java
@@ -254,6 +254,7 @@ class ConstantsTest {
       case "V19":
       case "V20":
       case "V21":
+      case "V22":
         return ConstantType.CLASS_VERSION;
       case "ACC_PUBLIC":
       case "ACC_PRIVATE":
diff --git a/asm/src/test/java/org/objectweb/asm/TypeTest.java b/asm/src/test/java/org/objectweb/asm/TypeTest.java
index bf52bcd2..ccefc808 100644
--- a/asm/src/test/java/org/objectweb/asm/TypeTest.java
+++ b/asm/src/test/java/org/objectweb/asm/TypeTest.java
@@ -248,6 +248,34 @@ class TypeTest implements Opcodes {
     assertEquals(Type.INT_TYPE, returnType);
   }
 
+  @Test
+  void testGetArgumentCountFromType() {
+    assertEquals(
+        14,
+        Type.getMethodType("(IZBCSDFJLI;LV;Ljava/lang/Object;[I[LI;[[Ljava/lang/Object;)V")
+            .getArgumentCount());
+  }
+
+  @Test
+  void testGetArgumentCountFromDescriptor() {
+    assertEquals(
+        14, Type.getArgumentCount("(IZBCSDFJLI;LV;Ljava/lang/Object;[I[LI;[[Ljava/lang/Object;)V"));
+    assertEquals(0, Type.getArgumentCount("()I"));
+  }
+
+  @Test
+  void testGetArgumentsAndReturnSizeFromType() {
+    assertEquals(
+        17 << 2,
+        Type.getMethodType("(IZBCSDFJLI;LV;Ljava/lang/Object;[I[LI;[[Ljava/lang/Object;)V")
+            .getArgumentsAndReturnSizes());
+    assertEquals(1 << 2 | 1, Type.getMethodType("()I").getArgumentsAndReturnSizes());
+    assertEquals(1 << 2 | 1, Type.getMethodType("()F").getArgumentsAndReturnSizes());
+    assertEquals(1 << 2 | 2, Type.getMethodType("()J").getArgumentsAndReturnSizes());
+    assertEquals(1 << 2 | 2, Type.getMethodType("()D").getArgumentsAndReturnSizes());
+    assertEquals(1 << 2 | 1, Type.getMethodType("()LD;").getArgumentsAndReturnSizes());
+  }
+
   @Test
   void testGetArgumentsAndReturnSizeFromDescriptor() {
     assertEquals(
diff --git a/build.gradle b/build.gradle
index ec26c104..181ed398 100644
--- a/build.gradle
+++ b/build.gradle
@@ -33,7 +33,7 @@ buildscript {
 
 plugins { id 'com.github.sherter.google-java-format' version '0.9' apply false }
 plugins { id 'me.champeau.jmh' version '0.6.8' apply false }
-plugins { id 'org.sonarqube' version '3.5.0.2730' apply false }
+plugins { id 'org.sonarqube' version '4.3.1.3277' apply false }
 
 description = 'ASM, a very small and fast Java bytecode manipulation framework'
 
@@ -47,7 +47,7 @@ dependencies {
 
 allprojects {
   group = 'org.ow2.asm'
-  version = '9.5' + (rootProject.hasProperty('release') ? '' : '-SNAPSHOT')
+  version = '9.6' + (rootProject.hasProperty('release') ? '' : '-SNAPSHOT')
 }
 
 subprojects {
@@ -196,6 +196,8 @@ subprojects {
   pmd.ruleSets = []
   pmd.ruleSetFiles = files("${rootDir}/tools/pmd.xml")
   pmd.consoleOutput = true
+  pmdMain.dependsOn ':asm:jar'
+  pmdTest.dependsOn ':asm:jar'
 
   dependencies {
     requires.each { projectName -> api project(projectName) }
@@ -220,7 +222,7 @@ subprojects {
 // and packaged with generated module-info classes.
 configure(subprojects.findAll{it.provides}) {
   // Code coverage configuration.
-  jacoco.toolVersion = '0.8.8'
+  jacoco.toolVersion = '0.8.10'
   jacocoTestReport {
     reports { xml.required = true }
     classDirectories.setFrom(sourceSets.main.output.classesDirs)
@@ -228,6 +230,9 @@ configure(subprojects.findAll{it.provides}) {
   jacocoTestCoverageVerification {
     classDirectories.setFrom(sourceSets.main.output.classesDirs)
     violationRules.rule { limit { minimum = 0.95; counter = 'INSTRUCTION' } }
+    dependsOn ':asm:jar'
+    dependsOn ':asm-tree:jar'
+    dependsOn ':asm-commons:jar'
   }
   check.dependsOn jacocoTestCoverageVerification
 
@@ -313,9 +318,9 @@ configure(subprojects.findAll{it.provides}) {
   }
 
   // Apply the SonarQube plugin to monitor the code quality of the project.
-  // Use with 'gradlew sonarqube -Dsonar.host.url=https://sonarqube.ow2.org'.
+  // Use with 'gradlew sonar -Dsonar.host.url=https://sonarqube.ow2.org'.
   apply plugin: 'org.sonarqube'
-  sonarqube {
+  sonar {
     properties { property 'sonar.projectKey', "ASM:${project.name}" }
   }
 
@@ -334,11 +339,11 @@ configure(subprojects.findAll{it.provides}) {
   // together with the main jar (containing the compiled code).
   task javadocJar(type: Jar, dependsOn: 'javadoc') {
     from javadoc.destinationDir
-    classifier 'javadoc'
+    archiveClassifier = 'javadoc'
   }
   task sourcesJar(type: Jar, dependsOn: 'classes') {
     from sourceSets.main.allSource
-    classifier 'sources'
+    archiveClassifier = 'sources'
   }
   java {
     withJavadocJar()
diff --git a/gradle/wrapper/gradle-wrapper.properties b/gradle/wrapper/gradle-wrapper.properties
index 565bc3a9..f97a8cf5 100644
--- a/gradle/wrapper/gradle-wrapper.properties
+++ b/gradle/wrapper/gradle-wrapper.properties
@@ -3,4 +3,4 @@ distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-7.6-bin.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.3-bin.zip
diff --git a/tools/pmd.xml b/tools/pmd.xml
index a4d73723..c271809b 100644
--- a/tools/pmd.xml
+++ b/tools/pmd.xml
@@ -75,8 +75,6 @@
     <exclude name="AvoidDuplicateLiterals" />
     <exclude name="AvoidFieldNameMatchingMethodName" />
     <exclude name="AvoidLiteralsInIfCondition" />
-    <!-- Not relevant for ASM (no Java Beans). -->
-    <exclude name="BeanMembersShouldSerialize" />
     <!-- Too many false positives. -->
     <exclude name="CompareObjectsWithEquals" />
     <!-- Does not work, too  many false positives. -->
```

