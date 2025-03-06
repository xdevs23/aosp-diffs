```diff
diff --git a/Android.bp b/Android.bp
index 4f31f99..b9b0198 100644
--- a/Android.bp
+++ b/Android.bp
@@ -32,6 +32,10 @@ license {
 
 cc_defaults {
     name: "iputils_defaults",
+
+    // This code uses K&R prototypes, which are invalid in C23 or later.
+    c_std: "gnu17",
+
     cflags: [
         "-fno-strict-aliasing",
         "-D_GNU_SOURCE",
```

