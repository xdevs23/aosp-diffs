```diff
diff --git a/Android.bp b/Android.bp
index 477ae1d..ee68753 100644
--- a/Android.bp
+++ b/Android.bp
@@ -46,7 +46,7 @@ cc_library_static {
     min_sdk_version: "30",
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.nfcservices",
     ],
     target: {
diff --git a/OWNERS b/OWNERS
index b5b5d5f..6b6b52c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -4,3 +4,4 @@
 include platform/external/libchrome:/OWNERS
 # previous importer
 armansito@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

