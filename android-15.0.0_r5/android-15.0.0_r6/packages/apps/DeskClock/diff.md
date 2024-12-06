```diff
diff --git a/tests/Android.bp b/tests/Android.bp
index 8b21729c5..441ca63d0 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -7,8 +7,8 @@ package {
 android_test {
     name: "DeskClockTests",
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
     ],
     static_libs: [
         "junit",
```

