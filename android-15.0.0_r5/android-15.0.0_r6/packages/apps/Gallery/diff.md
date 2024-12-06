```diff
diff --git a/tests/Android.bp b/tests/Android.bp
index 53bde64..a14cd25 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -11,8 +11,8 @@ android_test {
     name: "GalleryTests",
     certificate: "media",
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
     ],
     static_libs: ["junit"],
     // Include all test java files.
```

