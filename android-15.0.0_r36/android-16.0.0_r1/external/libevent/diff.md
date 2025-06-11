```diff
diff --git a/Android.bp b/Android.bp
index 51aca8f..6288113 100644
--- a/Android.bp
+++ b/Android.bp
@@ -65,6 +65,7 @@ cc_library {
         "-O3",
         "-Wno-strict-aliasing",
         "-Wno-unused-parameter",
+        "-Wno-tautological-compare",
         "-Werror",
     ],
     export_include_dirs: ["include"],
@@ -116,7 +117,7 @@ cc_library {
     min_sdk_version: "30",
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.nfcservices",
     ],
 }
```

