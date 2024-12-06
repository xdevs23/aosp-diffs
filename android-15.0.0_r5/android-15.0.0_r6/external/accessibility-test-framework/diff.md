```diff
diff --git a/Android.bp b/Android.bp
index 78f497a..c38a05a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -3,20 +3,18 @@ android_library {
     srcs: [
         "src/main/java/**/*.java",
     ],
+    exclude_srcs: ["src/main/java/com/google/android/apps/common/testing/accessibility/framework/integrations/espresso/*"],
     resource_dirs: ["src/main/resources/*/"],
     visibility: ["//visibility:public"],
     static_libs: [
         "aatf-java-proto-lite",
-        "androidx.core_core",
-        "androidx.test.espresso.core",
-        "androidx.test.rules",
-        "androidx.test.runner",
-        "androidx.test.services.storage",
+        "guava",
+    ],
+    libs: [
         "auto_value_annotations",
         "checker-qual",
         "com.google.android.material_material",
         "error_prone_annotations",
-        "guava",
         "guava-android-annotation-stubs",
         "hamcrest",
         "hamcrest-library",
```

