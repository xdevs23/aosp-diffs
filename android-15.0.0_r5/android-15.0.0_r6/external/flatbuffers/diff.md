```diff
diff --git a/Android.bp b/Android.bp
index 2e603bb5..d857b801 100644
--- a/Android.bp
+++ b/Android.bp
@@ -79,6 +79,8 @@ cc_binary_host {
         "-Wno-implicit-fallthrough", // in reflection.cpp
     ],
 
+    rtti: true,
+
     local_include_dirs: [
         "grpc",
         "include",
```

