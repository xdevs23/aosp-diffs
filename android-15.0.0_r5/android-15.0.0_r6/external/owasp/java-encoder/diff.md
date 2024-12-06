```diff
diff --git a/Android.bp b/Android.bp
index 7223c96..96b16e2 100644
--- a/Android.bp
+++ b/Android.bp
@@ -53,7 +53,7 @@ android_test {
         "owasp-java-encoder",
     ],
     libs: [
-        "android.test.base",
+        "android.test.base.stubs.test",
     ],
     min_sdk_version: "33",
     sdk_version: "test_current",
```

