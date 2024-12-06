```diff
diff --git a/tests/Android.bp b/tests/Android.bp
index 5126c86..7690eef 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -29,9 +29,9 @@ android_test {
 
     libs: [
         "ims-common",
-        "android.test.runner",
-        "android.test.mock",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.mock.stubs.system",
+        "android.test.base.stubs.system",
     ],
 
     static_libs: [
```

