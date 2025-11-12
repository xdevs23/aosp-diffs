```diff
diff --git a/Android.bp b/Android.bp
index 50a6a2f7..5852dc34 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,7 +42,7 @@ java_library {
 java_library_static {
     name: "tink-java",
 
-    visibility: ["//vendor:__subpackages__"],
+    visibility: ["//packages/apps/Car/SensitiveAppLock:__pkg__"],
 
     srcs: [
         "src_android/main/**/*.java",
```

