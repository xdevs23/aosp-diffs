```diff
diff --git a/Android.bp b/Android.bp
index ec75947..0b9291a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -200,6 +200,7 @@ cc_library {
     static: {
         apex_available: [
             "com.android.runtime",
+            "com.android.appsearch",
         ],
     },
 
@@ -216,6 +217,8 @@ cc_library {
     },
 
     afdo: true,
+    // TODO(b/390639586): Remove this line once the blocker is resolved.
+    min_sdk_version: "apex_inherit",
 }
 
 // A build of libz with identical behavior between architectures.
```

