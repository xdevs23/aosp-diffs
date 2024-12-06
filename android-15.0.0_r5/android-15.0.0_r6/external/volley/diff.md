```diff
diff --git a/Android.bp b/Android.bp
index d6c9764..c32ced9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -45,7 +45,7 @@ java_library {
         // Only needed at compile-time.
         "androidx.annotation_annotation",
 
-        "org.apache.http.legacy",
+        "sdk_public_28_org.apache.http.legacy",
     ],
     optional_uses_libs: [
         "org.apache.http.legacy",
```

