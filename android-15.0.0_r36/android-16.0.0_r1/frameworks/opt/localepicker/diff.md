```diff
diff --git a/tests/Android.bp b/tests/Android.bp
index 925f99c..1bcf811 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -36,7 +36,7 @@ android_app {
 
     static_libs: [
         "localepicker",
-        "Robolectric_all-target_upstream",
+        "Robolectric_all-target",
         "mockito-robolectric-prebuilt",
         "truth",
     ],
@@ -49,5 +49,4 @@ android_robolectric_test {
     name: "LocalePickerRoboTests",
     srcs: ["src/**/*.java"],
     instrumentation_for: "LocalePickerTest",
-    upstream: true,
 }
```

