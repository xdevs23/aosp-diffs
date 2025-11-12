```diff
diff --git a/Android.bp b/Android.bp
index fa52dec..d8a3b48 100644
--- a/Android.bp
+++ b/Android.bp
@@ -69,7 +69,7 @@ cc_library {
 
     export_include_dirs: ["."],
 
-    min_sdk_version: "S",
+    min_sdk_version: "apex_inherit",
 
     apex_available: [
         "com.android.art",
```

