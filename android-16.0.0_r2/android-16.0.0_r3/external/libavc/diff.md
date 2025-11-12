```diff
diff --git a/examples/Android.bp b/examples/Android.bp
index 36a45ec..0015273 100644
--- a/examples/Android.bp
+++ b/examples/Android.bp
@@ -46,7 +46,7 @@ cc_defaults {
     static_libs: ["libavcenc"],
 }
 
-cc_test {
+cc_binary {
     name: "avcdec",
     defaults: ["avcdec_defaults"],
     local_include_dirs: [
@@ -56,7 +56,7 @@ cc_test {
     static_libs: ["libavcdec"],
 }
 
-cc_test {
+cc_binary {
     name: "mvcdec",
     defaults: ["avcdec_defaults"],
     local_include_dirs: [
@@ -68,7 +68,7 @@ cc_test {
     ],
 }
 
-cc_test {
+cc_binary {
     name: "avcenc",
     defaults: ["avcenc_defaults"],
 
@@ -81,7 +81,7 @@ cc_test {
     ],
 }
 
-cc_test {
+cc_binary {
     name: "svcenc",
     defaults: ["avcenc_defaults"],
 
@@ -102,7 +102,7 @@ cc_test {
     ],
 }
 
-cc_test {
+cc_binary {
     name: "svcdec",
     defaults: ["avcdec_defaults"],
 
```

