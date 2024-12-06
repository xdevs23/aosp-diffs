```diff
diff --git a/Android.bp b/Android.bp
index 58a8af8..cb5c79b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -106,6 +106,7 @@ java_sdk_library {
         "--subtract-api $(location :frameworks-base-api-current.txt)",
     ],
     dist_group: "android",
+    default_to_stubs: true,
 }
 
 // Make the current.txt available for use by the cts/tests/signature and /vendor tests.
```

