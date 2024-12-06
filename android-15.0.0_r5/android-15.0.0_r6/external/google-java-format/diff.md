```diff
diff --git a/Android.bp b/Android.bp
index 0c267f9..8df1c08 100644
--- a/Android.bp
+++ b/Android.bp
@@ -50,7 +50,6 @@ java_library_host {
     exclude_srcs: [
         ":google_java_format_main_srcs",
         "core/src/main/java/com/google/googlejavaformat/java/GoogleJavaFormatToolProvider.java",
-        "core/src/main/java/com/google/googlejavaformat/java/java21/Java21InputAstVisitor.java",
     ],
     libs: [
         "error_prone_annotations",
```

