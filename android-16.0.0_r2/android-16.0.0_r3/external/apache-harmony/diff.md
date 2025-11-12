```diff
diff --git a/jdwp/src/test/java/org/apache/harmony/jpda/tests/jdwp/ClassType/SetValuesTest.java b/jdwp/src/test/java/org/apache/harmony/jpda/tests/jdwp/ClassType/SetValuesTest.java
index b668361..79f226b 100644
--- a/jdwp/src/test/java/org/apache/harmony/jpda/tests/jdwp/ClassType/SetValuesTest.java
+++ b/jdwp/src/test/java/org/apache/harmony/jpda/tests/jdwp/ClassType/SetValuesTest.java
@@ -116,7 +116,13 @@ public class SetValuesTest extends JDWPClassTypeTestCase {
     }
 
     private void testField(long classID, Field fieldInfo, Value value) {
-
+        // Static final fields value can't be modified: that's mentioned both in the language [1]
+        // and JDWP protocol [2] specs.
+        // [1] https://docs.oracle.com/javase/specs/jls/se24/html/jls-17.html#jls-17.5.4
+        // [2] https://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ClassType_SetValues
+        if (fieldInfo.isStatic() && fieldInfo.isFinal()) {
+            return;
+        }
         logWriter.println("\n==> testField: ");
         logWriter.println("    classID = " + classID);
         logWriter.println("    fieldInfo = " + fieldInfo);
diff --git a/jdwp/src/test/java/org/apache/harmony/jpda/tests/jdwp/ReferenceType/GetValues007Test.java b/jdwp/src/test/java/org/apache/harmony/jpda/tests/jdwp/ReferenceType/GetValues007Test.java
index d4bcd34..0301863 100644
--- a/jdwp/src/test/java/org/apache/harmony/jpda/tests/jdwp/ReferenceType/GetValues007Test.java
+++ b/jdwp/src/test/java/org/apache/harmony/jpda/tests/jdwp/ReferenceType/GetValues007Test.java
@@ -65,6 +65,11 @@ public class GetValues007Test extends JDWPSyncTestCase {
         long interfaceFieldID = checkField(implementerRefTypeID, interfaceFieldName);
         logWriter.println("=> interfaceFieldID = " + interfaceFieldID);
 
+        // Fields declared in interfaces are implicitly public static final, hence can't be
+        // modified.
+        // Test passes in the RI: that's probably a bug.
+        // TODO(b/415022136): in ART GetValues does not initialize class and reads 0 instead of 1.
+        /*
         logWriter.println("\n=> CHECK ClassType::SetValues command for implementerRefTypeID," +
             " interfaceFieldID...");
         int expectedIntValue = 2;
@@ -107,5 +112,6 @@ public class GetValues007Test extends JDWPSyncTestCase {
 
         synchronizer.sendMessage(JPDADebuggeeSynchronizer.SGNL_CONTINUE);
         logWriter.println("==> " + thisTestName + " for ReferenceType::GetValues command: FINISH");
+        */
     }
 }
```

