```diff
diff --git a/src/Android.bp b/src/Android.bp
index 052e3e6..d7ec9d8 100644
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -50,6 +50,10 @@ cc_binary {
         "util.c",
     ],
 
+    // This project is massively out of date,
+    // and even upstream 2.90 doesn't compile as C23,
+    // so pin to C17.
+    c_std: "gnu17",
     cflags: [
         "-O2",
         "-g",
```

