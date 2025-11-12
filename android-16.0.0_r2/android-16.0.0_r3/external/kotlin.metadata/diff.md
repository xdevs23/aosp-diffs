```diff
diff --git a/Android.bp b/Android.bp
index 3c2398d..e402c7d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -22,5 +22,6 @@ java_import_host {
         "//external/dagger2",
         "//external/kotlinx.atomicfu",
         "//prebuilts/sdk/current/androidx:__subpackages__",
+        "//tools/metalava:__subpackages__",
     ],
 }
```

