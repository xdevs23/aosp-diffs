```diff
diff --git a/rcs/presencepolling/tests/Android.bp b/rcs/presencepolling/tests/Android.bp
index c792111..cdaa0af 100644
--- a/rcs/presencepolling/tests/Android.bp
+++ b/rcs/presencepolling/tests/Android.bp
@@ -28,8 +28,8 @@ android_test {
     srcs: ["src/**/*.java"],
     libs: [
         "mockito-target",
-        "android.test.base",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.runner.stubs.system",
     ],
     static_libs: [
         "androidx.test.rules",
```

