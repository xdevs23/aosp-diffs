```diff
diff --git a/Android.bp b/Android.bp
index baa6ff7..7ea6396 100644
--- a/Android.bp
+++ b/Android.bp
@@ -66,7 +66,7 @@ android_library {
         "androidx.test.ext.truth",
         "androidx.test.rules",
         "androidx.annotation_annotation",
-        "org.apache.http.legacy",
+        "org.apache.http.legacy.stubs.system",
         "mobile_data_downloader_lib",
         "auto_value_annotations",
         "framework-annotations-lib",
diff --git a/javatests/Android.bp b/javatests/Android.bp
index 52dfda6..1b52f4c 100644
--- a/javatests/Android.bp
+++ b/javatests/Android.bp
@@ -25,7 +25,7 @@ android_app {
     manifest: "com/google/android/libraries/mobiledatadownload/internal/AndroidManifest.xml",
     platform_apis: true,
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
     ]
 }
 
```

