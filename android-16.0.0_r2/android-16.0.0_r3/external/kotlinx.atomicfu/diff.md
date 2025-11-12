```diff
diff --git a/Android.bp b/Android.bp
index 2c80b65..18b40f6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -39,4 +39,7 @@ java_library {
         "//apex_available:platform",
         "//apex_available:anyapex",
     ],
+    // atomicfu is used during compilation of the kotlin-incremental-client.
+    // It therefore can not itself be incremental.
+    kotlin_incremental: false,
 }
```

