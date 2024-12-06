```diff
diff --git a/tests/Android.bp b/tests/Android.bp
index 3ff2bf8..b79114e 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -13,9 +13,9 @@ android_test {
         "android.content.pm.flags-aconfig-java",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
 
     // Only compile source java files in this apk.
```

