```diff
diff --git a/Android.bp b/Android.bp
index 575ca5a6b..e754c5751 100644
--- a/Android.bp
+++ b/Android.bp
@@ -315,7 +315,7 @@ android_app {
     ],
     libs: [
         "auto_value_annotations",
-        "org.apache.http.legacy",
+        "org.apache.http.legacy.stubs.system",
     ],
     // LOCAL_ANNOTATION_PROCESSORS
     plugins: [
```

