```diff
diff --git a/src/com/google/doclava/CompatInfo.java b/src/com/google/doclava/CompatInfo.java
index 1999818..150b5a3 100644
--- a/src/com/google/doclava/CompatInfo.java
+++ b/src/com/google/doclava/CompatInfo.java
@@ -252,10 +252,10 @@ public class CompatInfo {
         // via compat_config.xml, so we can resolve links properly here?
         definedInContainer = Converter.obtainPackage("android");
       }
-      if (change.description == null) {
-        throw new RuntimeException("No description found for @ChangeId " + change.name);
+      if (change.name == null) {
+        throw new RuntimeException("No name found for @ChangeId " + change.name);
       }
-      Comment comment = new Comment(change.description, definedInContainer, new SourcePositionInfo(
+      Comment comment = new Comment(change.name, definedInContainer, new SourcePositionInfo(
           change.sourceFile, change.sourceLine, 1));
       String path = "change." + i;
       hdf.setValue(path + ".id", Long.toString(change.id));
```

