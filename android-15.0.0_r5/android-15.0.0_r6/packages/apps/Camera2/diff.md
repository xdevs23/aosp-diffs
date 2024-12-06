```diff
diff --git a/Android.bp b/Android.bp
index 5cf37d569..8487fd4e7 100644
--- a/Android.bp
+++ b/Android.bp
@@ -53,7 +53,7 @@ android_app {
     },
 
     // Guava uses deprecated org.apache.http.legacy classes.
-    libs: ["org.apache.http.legacy"],
+    libs: ["org.apache.http.legacy.stubs.system"],
 
     jni_libs: [
         "libjni_tinyplanet",
```

