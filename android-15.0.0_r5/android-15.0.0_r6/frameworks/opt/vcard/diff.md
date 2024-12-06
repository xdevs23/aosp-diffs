```diff
diff --git a/tests/Android.bp b/tests/Android.bp
index 0b277fd..89f2bc5 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -25,9 +25,9 @@ android_test {
     test_suites: ["device-tests"],
     srcs: ["src/**/*.java"],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
     static_libs: [
         "com.android.vcard",
```

