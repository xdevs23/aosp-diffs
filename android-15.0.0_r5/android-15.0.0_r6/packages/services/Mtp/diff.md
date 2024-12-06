```diff
diff --git a/tests/Android.bp b/tests/Android.bp
index f069707..9dfd7f2 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -7,9 +7,9 @@ android_test {
     name: "MtpServiceTests",
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
         "junit",
```

