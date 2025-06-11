```diff
diff --git a/apex/testing/Android.bp b/apex/testing/Android.bp
index 6e31d40f0..f12a039d2 100644
--- a/apex/testing/Android.bp
+++ b/apex/testing/Android.bp
@@ -27,6 +27,7 @@ apex_test {
     defaults: ["com.android.neuralnetworks-defaults"],
     manifest: "test_apex_manifest.json",
     file_contexts: ":com.android.neuralnetworks-file_contexts",
+    apex_available_name: "com.android.neuralnetworks",
     // Test APEX, should never be installed
     installable: false,
 }
diff --git a/common/Android.bp b/common/Android.bp
index 8f3e1188f..34e5458b5 100644
--- a/common/Android.bp
+++ b/common/Android.bp
@@ -120,7 +120,6 @@ cc_defaults {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
     ],
     vendor_available: true,
     // b/109953668, disable OpenMP
@@ -271,7 +270,6 @@ cc_defaults {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
     ],
     // b/109953668, disable OpenMP
     // openmp: true,
diff --git a/common/random/Android.bp b/common/random/Android.bp
index a05b8336c..0ea1405fc 100644
--- a/common/random/Android.bp
+++ b/common/random/Android.bp
@@ -29,7 +29,6 @@ cc_library_headers {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
     ],
     min_sdk_version: "30",
     sdk_version: "current",
@@ -43,7 +42,6 @@ cc_library_static {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
     ],
     srcs: [
         "guarded_philox_random.cc",
@@ -68,7 +66,6 @@ cc_library_static {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
     ],
     srcs: [
         "guarded_philox_random.cc",
diff --git a/common/types/Android.bp b/common/types/Android.bp
index 48342e5a7..6a35c1b70 100644
--- a/common/types/Android.bp
+++ b/common/types/Android.bp
@@ -29,7 +29,6 @@ cc_defaults {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
     ],
     min_sdk_version: "30",
     target: {
diff --git a/runtime/Android.bp b/runtime/Android.bp
index 46063d82d..66a79eb8a 100644
--- a/runtime/Android.bp
+++ b/runtime/Android.bp
@@ -57,9 +57,9 @@ cc_library_headers {
     min_sdk_version: "30",
     apex_available: [
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks", // Due to the dependency from libneuralnetworks_common
-        // that is available to the platform
 
+        // Due to the dependency from libneuralnetworks_common
+        // that is available to the platform
         "//apex_available:platform",
     ],
 }
@@ -141,10 +141,8 @@ cc_defaults {
         "libfmq",
         "libhidlbase",
         "libhidlmemory",
-        "libjsoncpp",
         "libmath",
         "libneuralnetworks_common",
-        "libprocessgroup",
         "libtextclassifier_hash_static",
         "libutils",
         "neuralnetworks_types",
@@ -210,10 +208,7 @@ cc_library_shared {
         "neuralnetworks_defaults",
     ],
     min_sdk_version: "30",
-    apex_available: [
-        "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
-    ],
+    apex_available: ["com.android.neuralnetworks"],
     stubs: {
         versions: [
             "30",
diff --git a/shim_and_sl/Android.bp b/shim_and_sl/Android.bp
index 5508c6ed2..cdb45ae23 100644
--- a/shim_and_sl/Android.bp
+++ b/shim_and_sl/Android.bp
@@ -46,7 +46,6 @@ cc_library_static {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
     ],
     srcs: [
         "NeuralNetworksShim.cpp",
@@ -116,7 +115,6 @@ cc_library_static {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
     ],
     export_include_dirs: [
         "include",
```

