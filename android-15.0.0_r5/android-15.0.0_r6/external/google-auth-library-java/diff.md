```diff
diff --git a/oauth2_http/Android.bp b/oauth2_http/Android.bp
index 5227e19..78ec3cc 100644
--- a/oauth2_http/Android.bp
+++ b/oauth2_http/Android.bp
@@ -17,6 +17,11 @@ java_library_host {
         "//external/sdk-platform-java:__subpackages__",
         "//tools/apksig",
     ],
+    errorprone: {
+        javacflags: [
+            "-Xep:DoubleBraceInitialization:WARN",
+        ],
+    },
     target: {
         windows: {
             enabled: true,
```

