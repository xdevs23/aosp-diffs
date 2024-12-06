```diff
diff --git a/Android.bp b/Android.bp
index ff6a1231..fa6177a8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -135,6 +135,7 @@ cc_binary {
 // =================================================
 cc_binary_host {
     name: "dump_syms",
+    rtti: true,
     target: {
         darwin: {
             enabled: false,
```

