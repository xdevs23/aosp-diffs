```diff
diff --git a/Android.bp b/Android.bp
index 629fa75..a91768f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -65,7 +65,7 @@ cc_binary {
             enabled: false,
         },
         x86_64: {
-            enabled: false,
+            cflags: ["-DSTRESSAPPTEST_CPU_X86_64"],
         },
     },
 
```

