```diff
diff --git a/Android.bp b/Android.bp
index b3c8e91..67ecf42 100644
--- a/Android.bp
+++ b/Android.bp
@@ -56,9 +56,6 @@ cc_library_static {
     host_supported: true,
     target: {
         host: {
-            include_dirs: [
-                "bionic/libc/kernel/uapi",
-            ],
             cflags: [
                 "-D__ANDROID_HOST__",
             ],
@@ -98,9 +95,6 @@ cc_test {
     host_supported: true,
     target: {
         host: {
-            include_dirs: [
-                "bionic/libc/kernel/uapi",
-            ],
             cflags: [
                 "-D__ANDROID_HOST__",
             ],
```

