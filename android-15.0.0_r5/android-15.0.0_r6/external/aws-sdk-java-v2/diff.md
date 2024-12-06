```diff
diff --git a/core/sdk-core/Android.bp b/core/sdk-core/Android.bp
index c74d0573d95..a902c0b3b3b 100644
--- a/core/sdk-core/Android.bp
+++ b/core/sdk-core/Android.bp
@@ -23,6 +23,11 @@ java_library_host {
         "awssdk-utils",
         "awssdk-profiles",
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

