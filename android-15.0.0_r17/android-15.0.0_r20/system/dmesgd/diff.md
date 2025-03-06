```diff
diff --git a/Android.bp b/Android.bp
index ccd2e95..2dca647 100644
--- a/Android.bp
+++ b/Android.bp
@@ -28,8 +28,9 @@ cc_defaults {
         "-Wno-unused-argument",
         "-Wno-unused-function",
         "-Wno-nullability-completeness",
-        "-Os",
     ],
+
+    optimize_for_size: true,
 }
 
 cc_binary {
```

