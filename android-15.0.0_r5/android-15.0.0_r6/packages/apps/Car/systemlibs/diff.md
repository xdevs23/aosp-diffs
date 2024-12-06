```diff
diff --git a/car-qc-lib/tests/unit/Android.bp b/car-qc-lib/tests/unit/Android.bp
index 3af82b4..2dc78e3 100644
--- a/car-qc-lib/tests/unit/Android.bp
+++ b/car-qc-lib/tests/unit/Android.bp
@@ -27,9 +27,9 @@ android_test {
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
```

