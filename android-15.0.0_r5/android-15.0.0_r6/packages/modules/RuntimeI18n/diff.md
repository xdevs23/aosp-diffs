```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index 1fab799..a79f050 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -48,8 +48,6 @@ apex_defaults {
         "i18n-bootclasspath-fragment",
     ],
     updatable: false,
-    // Need hash tree so that CompOS can use dm-verity to verify the image in the Protected VM.
-    generate_hashtree: true,
 }
 
 apex_key {
@@ -134,7 +132,7 @@ sdk {
     },
     native_shared_libs: [
         "libandroidicu",
-	"libicu",
+        "libicu",
     ],
 }
 
```

