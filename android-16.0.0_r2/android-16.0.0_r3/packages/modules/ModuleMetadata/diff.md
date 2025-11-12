```diff
diff --git a/Android.bp b/Android.bp
index c0453ac..3ba255d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -30,4 +30,8 @@ android_app {
     dex_preopt: {
         enabled: false,
     },
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
```

