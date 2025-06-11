```diff
diff --git a/OWNERS b/OWNERS
index 56b1b53..bf9f7f0 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,11 +1,10 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
-jsharkey@android.com
 ddougherty@google.com
-tiem@google.com
 tnorbye@google.com
 
 # [temporary] some of libcore members involved in
 # Doclava migration to Java 17.
 # See http://b/260694901
 sorinbasca@google.com #{LAST_RESORT_SUGGESTION}
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/src/com/google/doclava/AndroidAuxSource.java b/src/com/google/doclava/AndroidAuxSource.java
index ca1fbd0..9686520 100644
--- a/src/com/google/doclava/AndroidAuxSource.java
+++ b/src/com/google/doclava/AndroidAuxSource.java
@@ -187,25 +187,35 @@ public class AndroidAuxSource implements AuxSource {
       // Document required features
       if ((type == TYPE_CLASS || type == TYPE_METHOD || type == TYPE_FIELD)
           && annotation.type().qualifiedNameMatches("android", "annotation.RequiresFeature")) {
-        AnnotationValueInfo value = null;
+        ArrayList<AnnotationValueInfo> values = new ArrayList<>();
+        boolean any = false;
         for (AnnotationValueInfo val : annotation.elementValues()) {
           switch (val.element().name()) {
             case "value":
-              value = val;
+              values.add(val);
+              break;
+            case "allOf":
+              values = (ArrayList<AnnotationValueInfo>) val.value();
+              break;
+            case "anyOf":
+              any = true;
+              values = (ArrayList<AnnotationValueInfo>) val.value();
               break;
           }
         }
-        if (value == null) continue;
+        if (values.isEmpty()) continue;
 
         ClassInfo pmClass = annotation.type().findClass("android.content.pm.PackageManager");
         ArrayList<TagInfo> valueTags = new ArrayList<>();
-        final String expected = String.valueOf(value.value());
-        for (FieldInfo field : pmClass.fields()) {
-          if (field.isHiddenOrRemoved()) continue;
-          if (String.valueOf(field.constantValue()).equals(expected)) {
-            valueTags.add(new ParsedTagInfo("", "",
-                "{@link " + pmClass.qualifiedName() + "#" + field.name() + "}", null,
-                SourcePositionInfo.UNKNOWN));
+        for (AnnotationValueInfo value : values) {
+          final String expected = String.valueOf(value.value());
+          for (FieldInfo field : pmClass.fields()) {
+            if (field.isHiddenOrRemoved()) continue;
+            if (String.valueOf(field.constantValue()).equals(expected)) {
+              valueTags.add(new ParsedTagInfo("", "",
+                  "{@link " + pmClass.qualifiedName() + "#" + field.name() + "}", null,
+                  SourcePositionInfo.UNKNOWN));
+            }
           }
         }
 
@@ -215,6 +225,7 @@ public class AndroidAuxSource implements AuxSource {
             null, SourcePositionInfo.UNKNOWN));
 
         Map<String, String> args = new HashMap<>();
+        if (any) args.put("any", "true");
         tags.add(new AuxTagInfo("@feature", "@feature", SourcePositionInfo.UNKNOWN, args,
             valueTags.toArray(TagInfo.getArray(valueTags.size()))));
       }
```

