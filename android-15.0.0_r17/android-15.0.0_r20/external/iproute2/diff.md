```diff
diff --git a/ip/Android.bp b/ip/Android.bp
index 329f7fa1..ca527f21 100644
--- a/ip/Android.bp
+++ b/ip/Android.bp
@@ -105,7 +105,6 @@ cc_binary {
     ],
 
     cflags: [
-        "-Wno-implicit-function-declaration",
         "-Wno-int-conversion",
         "-Wno-missing-field-initializers",
         "-D_GNU_SOURCE",
```

