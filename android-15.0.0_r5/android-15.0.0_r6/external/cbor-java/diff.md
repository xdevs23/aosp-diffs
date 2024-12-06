```diff
diff --git a/Android.bp b/Android.bp
index b12b3d5..e467114 100644
--- a/Android.bp
+++ b/Android.bp
@@ -56,7 +56,7 @@ android_test {
         "cbor-java",
     ],
     libs: [
-        "android.test.base",
+        "android.test.base.stubs.test",
     ],
     min_sdk_version: "30",
     sdk_version: "test_current",
```

