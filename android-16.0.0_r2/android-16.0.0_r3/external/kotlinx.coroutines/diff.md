```diff
diff --git a/Android.bp b/Android.bp
index 90ea70b9..72b3dc60 100644
--- a/Android.bp
+++ b/Android.bp
@@ -83,6 +83,7 @@ java_library_host {
         "//apex_available:anyapex",
     ],
     kotlin_lang_version: "2",
+    kotlin_incremental: false,
 }
 
 // Expose the host library to Android targets. This is generally an unsafe operation; in using
@@ -112,6 +113,7 @@ java_library {
         "//apex_available:anyapex",
     ],
     visibility: ["//visibility:public"],
+    kotlin_incremental: false,
 }
 
 java_library {
```

