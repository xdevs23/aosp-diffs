```diff
diff --git a/Android.bp b/Android.bp
index 00d342b3..0625012e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -117,6 +117,7 @@ cc_library_static {
     stl: "c++_static",
     apex_available: [
         "//apex_available:platform",
+        "com.android.media",
         "com.android.mediaprovider",
     ],
 }
```

