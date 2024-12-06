```diff
diff --git a/Android.bp b/Android.bp
index 77e895020..a864ec33f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -44,7 +44,7 @@ android_app {
         proguard_flags_files: ["proguard.flags"],
     },
 
-    libs: ["org.apache.http.legacy"],
+    libs: ["org.apache.http.legacy.stubs"],
 
     optional_uses_libs: [
         "com.google.android.media.effects",
```

