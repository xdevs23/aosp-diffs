```diff
diff --git a/robotests/Android.bp b/robotests/Android.bp
index 61be339..328b225 100644
--- a/robotests/Android.bp
+++ b/robotests/Android.bp
@@ -23,7 +23,6 @@ android_robolectric_test {
     test_options: {
         timeout: 36000,
     },
-    upstream: true,
 
     strict_mode: false,
 }
```

