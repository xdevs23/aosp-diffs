```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index dcacec9..4163aaf 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -84,6 +84,11 @@ apex {
     androidManifest: "AndroidManifest.xml",
     file_contexts: ":com.android.scheduling-file_contexts",
     key: "com.android.scheduling.key",
+    certificate: ":com.android.scheduling.certificate",
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 sdk {
```

