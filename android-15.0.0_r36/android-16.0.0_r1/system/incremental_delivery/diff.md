```diff
diff --git a/incfs/Android.bp b/incfs/Android.bp
index a534674..a475528 100644
--- a/incfs/Android.bp
+++ b/incfs/Android.bp
@@ -203,7 +203,7 @@ cc_binary {
         "incfsdump/dump.cpp",
     ],
     target: {
-        linux_glibc: {
+        host_linux: {
             enabled: true,
         },
     },
```

