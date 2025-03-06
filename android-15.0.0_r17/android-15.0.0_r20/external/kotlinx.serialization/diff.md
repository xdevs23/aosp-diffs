```diff
diff --git a/Android.bp b/Android.bp
index d6c6f8d9..51b86357 100644
--- a/Android.bp
+++ b/Android.bp
@@ -13,6 +13,10 @@ java_library {
         "-opt-in=kotlinx.serialization.ExperimentalSerializationApi",
         "-opt-in=kotlinx.serialization.InternalSerializationApi",
     ],
+    optimize: {
+        proguard_flags_files: ["rules/*"],
+        export_proguard_flags_files: true,
+    },
     apex_available: [
         "//apex_available:platform",
         "//apex_available:anyapex",
```

