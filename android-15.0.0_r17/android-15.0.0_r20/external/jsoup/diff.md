```diff
diff --git a/Android.bp b/Android.bp
index f4227e9c..538219ce 100644
--- a/Android.bp
+++ b/Android.bp
@@ -2,6 +2,6 @@
 java_library_static {
     name: "jsoup",
     srcs: ["src/main/java/**/*.java"],
-    static_libs: ["jsoup_annotation_stubs"],
+    static_libs: ["jspecify"],
     visibility: ["//external/accessibility-test-framework"],
 }
```

