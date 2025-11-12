```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index d74b1b8..09905c2 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -25,7 +25,7 @@ apex_defaults {
     manifest: "apex_manifest.json",
     key: "com.android.threadnetwork.key",
     certificate: ":com.android.threadnetwork.certificate",
-    compressible: true,
+    compressible: false, // do not compress non-updatable apex
     updatable: false,
 }
 
```

