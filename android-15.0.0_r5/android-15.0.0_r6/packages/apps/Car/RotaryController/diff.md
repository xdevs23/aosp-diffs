```diff
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index 46f8719..eef91fb 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -12,9 +12,9 @@ android_test {
 
     libs: [
         "android.car-system-stubs",
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
 
     static_libs: [
```

