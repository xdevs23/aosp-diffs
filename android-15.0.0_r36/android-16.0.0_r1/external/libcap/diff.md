```diff
diff --git a/Android.bp b/Android.bp
index b247e95..c7480fe 100644
--- a/Android.bp
+++ b/Android.bp
@@ -74,7 +74,7 @@ cc_library {
         linux_bionic: {
             enabled: true,
         },
-        linux_glibc: {
+        host_linux: {
             local_include_dirs: ["libcap/include/uapi"],
         },
     },
```

