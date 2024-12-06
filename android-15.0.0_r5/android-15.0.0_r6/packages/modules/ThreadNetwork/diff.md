```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index e4ab29f..d74b1b8 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -26,6 +26,7 @@ apex_defaults {
     key: "com.android.threadnetwork.key",
     certificate: ":com.android.threadnetwork.certificate",
     compressible: true,
+    updatable: false,
 }
 
 apex {
```

