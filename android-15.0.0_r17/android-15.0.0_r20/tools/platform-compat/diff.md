```diff
diff --git a/java/android/processor/compat/changeid/ChangeIdProcessor.java b/java/android/processor/compat/changeid/ChangeIdProcessor.java
index a3d3025..97b5f31 100644
--- a/java/android/processor/compat/changeid/ChangeIdProcessor.java
+++ b/java/android/processor/compat/changeid/ChangeIdProcessor.java
@@ -204,15 +204,6 @@ public class ChangeIdProcessor extends SingleAnnotationProcessor {
             }
         }
 
-        String comment =
-                elements.getDocComment(element);
-        if (comment != null) {
-            comment = HIDE_TAG_MATCHER.matcher(comment).replaceAll("");
-            comment = JAVADOC_SANITIZER.matcher(comment).replaceAll("");
-            comment = comment.replaceAll("\\n", " ");
-            builder.description(comment.trim());
-        }
-
         return verifyChange(element,
                 builder.javaClass(enclosingElementName)
                         .javaPackage(packageName)
diff --git a/java/com/android/class2nonsdklist/ApiComponents.java b/java/com/android/class2nonsdklist/ApiComponents.java
index f1f42f0..6ccde53 100644
--- a/java/com/android/class2nonsdklist/ApiComponents.java
+++ b/java/com/android/class2nonsdklist/ApiComponents.java
@@ -250,10 +250,6 @@ public class ApiComponents {
         }
         StringCursor sc = new StringCursor(linkTag);
         try {
-
-            String memberName = "";
-            String methodParameterTypes = "";
-
             int tagPos = sc.find('#');
             String fullyQualifiedClassName = sc.next(tagPos);
 
@@ -279,7 +275,8 @@ public class ApiComponents {
             }
 
             int leftParenPos = sc.find('(');
-            memberName = sc.next(leftParenPos);
+            String memberName = sc.next(leftParenPos);
+            String methodParameterTypes = "";
             if (leftParenPos != -1) {
                 // Consume the '('.
                 sc.next();
diff --git a/javatest/android/processor/compat/changeid/ChangeIdProcessorTest.java b/javatest/android/processor/compat/changeid/ChangeIdProcessorTest.java
index 13647c7..18a6e8b 100644
--- a/javatest/android/processor/compat/changeid/ChangeIdProcessorTest.java
+++ b/javatest/android/processor/compat/changeid/ChangeIdProcessorTest.java
@@ -138,18 +138,18 @@ public class ChangeIdProcessorTest {
                         "}")
         };
         String expectedFile = HEADER + "<config>" +
-                "<compat-change description=\"description of MY_CHANGE_ID\" "
+                "<compat-change "
                 + "enableAfterTargetSdk=\"29\" id=\"123456789\" name=\"MY_CHANGE_ID\">"
                 + "<meta-data definedIn=\"libcore.util.Compat\" "
                 + "sourcePosition=\"libcore/util/Compat.java:13\"/></compat-change>"
-                + "<compat-change description=\"description of ANOTHER_CHANGE\" disabled=\"true\" "
+                + "<compat-change disabled=\"true\" "
                 + "id=\"23456700\" name=\"ANOTHER_CHANGE\"><meta-data definedIn=\"libcore.util"
                 + ".Compat\" sourcePosition=\"libcore/util/Compat.java:16\"/></compat-change>"
-                + "<compat-change description=\"description of LAST_CHANGE\" "
+                + "<compat-change "
                 + "enableSinceTargetSdk=\"30\" id=\"23456701\" name=\"LAST_CHANGE\">"
                 + "<meta-data definedIn=\"libcore.util.Compat\" "
                 + "sourcePosition=\"libcore/util/Compat.java:20\"/></compat-change>"
-                + "<compat-change description=\"description of OVERRIDABLE_CHANGE\" "
+                + "<compat-change "
                 + "id=\"23456702\" name=\"OVERRIDABLE_CHANGE\" overridable=\"true\">"
                 + "<meta-data definedIn=\"libcore.util.Compat\" "
                 + "sourcePosition=\"libcore/util/Compat.java:24\"/></compat-change>"
@@ -192,13 +192,13 @@ public class ChangeIdProcessorTest {
                         "}")
         };
         String libcoreExpectedFile = HEADER + "<config>" +
-                "<compat-change description=\"description of MY_CHANGE_ID\" "
+                "<compat-change "
                 + "id=\"123456789\" name=\"MY_CHANGE_ID\">"
                 + "<meta-data definedIn=\"libcore.util.Compat\" "
                 + "sourcePosition=\"libcore/util/Compat.java:10\"/></compat-change>"
                 + "</config>";
         String androidExpectedFile = HEADER + "<config>" +
-                "<compat-change description=\"description of ANOTHER_CHANGE\" "
+                "<compat-change "
                 + "id=\"23456700\" name=\"ANOTHER_CHANGE\"><meta-data definedIn=\"android.util"
                 + ".SomeClass\" sourcePosition=\"android/util/SomeClass.java:7\"/></compat-change>"
                 + "</config>";
@@ -235,7 +235,7 @@ public class ChangeIdProcessorTest {
                         "}"),
         };
         String expectedFile = HEADER + "<config>" +
-                "<compat-change description=\"description of MY_CHANGE_ID\" "
+                "<compat-change "
                 + "id=\"123456789\" name=\"MY_CHANGE_ID\"><meta-data definedIn=\"libcore.util"
                 + ".Compat.Inner\" sourcePosition=\"libcore/util/Compat.java:11\"/>"
                 + "</compat-change></config>";
@@ -267,7 +267,7 @@ public class ChangeIdProcessorTest {
                         "}"),
         };
         String expectedFile = HEADER + "<config>" +
-                "<compat-change description=\"description of MY_CHANGE_ID\" "
+                "<compat-change "
                 + "id=\"123456789\" name=\"MY_CHANGE_ID\"><meta-data definedIn=\"libcore.util"
                 + ".Compat\" sourcePosition=\"libcore/util/Compat.java:10\"/>"
                 + "</compat-change></config>";
@@ -300,7 +300,7 @@ public class ChangeIdProcessorTest {
                         "}"),
         };
         String expectedFile = HEADER + "<config>" +
-                "<compat-change description=\"description of MY_CHANGE_ID\" "
+                "<compat-change "
                 + "id=\"123456789\" name=\"MY_CHANGE_ID\"><meta-data definedIn=\"libcore.util"
                 + ".Compat\" sourcePosition=\"libcore/util/Compat.java:11\"/>"
                 + "</compat-change></config>";
@@ -638,7 +638,7 @@ public class ChangeIdProcessorTest {
                         "}"),
         };
         String expectedFile = HEADER + "<config>" +
-                "<compat-change description=\"description of MY_CHANGE_ID.\" "
+                "<compat-change "
                 + "id=\"123456789\" name=\"MY_CHANGE_ID\"><meta-data definedIn=\"libcore.util"
                 + ".Compat.Inner\" sourcePosition=\"libcore/util/Compat.java:11\"/>"
                 + "</compat-change></config>";
```

