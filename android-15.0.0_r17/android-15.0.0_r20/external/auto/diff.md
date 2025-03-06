```diff
diff --git a/value/Android.bp b/value/Android.bp
index 4936f9f8..3a9df7bf 100644
--- a/value/Android.bp
+++ b/value/Android.bp
@@ -58,6 +58,8 @@ java_library {
         "//apex_available:platform",
         "com.android.extservices",
         "com.android.adservices",
+        "com.android.tethering",
+        "com.android.uwb",
     ],
     target: {
         windows: {
```

