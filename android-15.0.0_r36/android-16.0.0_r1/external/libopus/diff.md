```diff
diff --git a/Android.bp b/Android.bp
index 7c2ff7b4..0fe42a28 100644
--- a/Android.bp
+++ b/Android.bp
@@ -372,7 +372,7 @@ cc_library {
     apex_available: [
         "//apex_available:platform", // used by libstagefright_soft_opusdec
         "com.android.media.swcodec",
-        "com.android.btservices",
+        "com.android.bt",
     ],
     min_sdk_version: "29",
 }
```

