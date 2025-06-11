```diff
diff --git a/Android.bp b/Android.bp
index e273be0..4e5c011 100644
--- a/Android.bp
+++ b/Android.bp
@@ -56,7 +56,6 @@ cc_library_headers {
     export_include_dirs: ["."],
     apex_available: [
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
         "//apex_available:platform",
     ],
     sdk_version: "current",
diff --git a/METADATA b/METADATA
index d97975c..dedc25d 100644
--- a/METADATA
+++ b/METADATA
@@ -1,3 +1,15 @@
+name: "gemmlowp"
+description: "Low-precision matrix multiplication"
 third_party {
   license_type: NOTICE
+  last_upgrade_date {
+    year: 2021
+    month: 2
+    day: 26
+  }
+  identifier {
+    type: "Archive"
+    value: "https://github.com/google/gemmlowp/archive/13d57703abca3005d97b19df1f2db731607a7dc2.zip"
+    version: "13d57703abca3005d97b19df1f2db731607a7dc2"
+  }
 }
diff --git a/OWNERS b/OWNERS
index e5412e2..8ed008c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 miaowang@google.com
 ianhua@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

