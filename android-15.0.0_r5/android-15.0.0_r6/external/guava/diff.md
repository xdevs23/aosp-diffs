```diff
diff --git a/Android.bp b/Android.bp
index 26e65a3c6..e6d0bed91 100644
--- a/Android.bp
+++ b/Android.bp
@@ -197,6 +197,7 @@ java_library {
             enabled: true,
         },
     },
+    is_stubs_module: true,
 }
 
 // Compile guava testlib
```

