```diff
diff --git a/tests/Android.bp b/tests/Android.bp
index d2cc677a..8b49b47b 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -8,8 +8,8 @@ android_test {
     name: "LegacyCameraTests",
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
     ],
     static_libs: [
         "junit",
```

