```diff
diff --git a/tests/Android.bp b/tests/Android.bp
index cdde6f7..2cc5d06 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -7,8 +7,8 @@ package {
 android_test {
     name: "CallLogBackupTests",
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
     ],
     // Only compile source java files in this apk.
     srcs: ["src/**/*.java"],
```

