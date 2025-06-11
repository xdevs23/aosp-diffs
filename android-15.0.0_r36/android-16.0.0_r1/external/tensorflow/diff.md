```diff
diff --git a/Android.bp b/Android.bp
index 98b9aef34b6..414d7a84139 100644
--- a/Android.bp
+++ b/Android.bp
@@ -65,7 +65,6 @@ cc_library_headers {
         "//apex_available:platform",
         "com.android.extservices",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
         "com.android.adservices",
         "com.android.ondevicepersonalization",
     ],
@@ -206,6 +205,10 @@ cc_library_static {
         "-DTF_ANDROID_ENABLE_LOG_EVERY_N_SECONDS",
         // Used to support int64, string type in //tensorflow/core/framework/register_types.h.
         "-D__ANDROID_TYPES_FULL__",
+        // This code uses malloc_usable_size(),
+        // and thus can't be built with _FORTIFY_SOURCE=3.
+        "-U_FORTIFY_SOURCE",
+        "-D_FORTIFY_SOURCE=2",
         "-Wno-defaulted-function-deleted",
         "-Wno-deprecated-builtins",
         "-Wno-deprecated-declarations",
diff --git a/OWNERS b/OWNERS
index 023662674b7..b748756f510 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,3 +3,5 @@
 # Please update this list if you find better owner candidates.
 miaowang@google.com
 ianhua@google.com
+jdduke@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/tensorflow/lite/Android.bp b/tensorflow/lite/Android.bp
index 256869da128..dfbbbb7758d 100644
--- a/tensorflow/lite/Android.bp
+++ b/tensorflow/lite/Android.bp
@@ -141,13 +141,15 @@ cc_library_static {
 cc_library_shared {
     name: "libtflite",
     defaults: ["tflite_defaults"],
-    shared_libs: [
+    static_libs: [
+        "libfft2d",
         "libflatbuffers-cpp",
-        "libruy",
+        "libruy_static",
+    ],
+    shared_libs: [
         "libtextclassifier_hash",
     ],
     whole_static_libs: [
-        "libfft2d",
         "libtflite_context",
         "libtflite_framework",
         "libtflite_kernels",
diff --git a/tensorflow/lite/java/Android.bp b/tensorflow/lite/java/Android.bp
index dd59b4fe7bb..eec5091a01f 100644
--- a/tensorflow/lite/java/Android.bp
+++ b/tensorflow/lite/java/Android.bp
@@ -41,4 +41,7 @@ java_library_static {
         "com.android.extservices",
         "com.android.ondevicepersonalization",
     ],
-}
\ No newline at end of file
+    optimize: {
+        proguard_flags_files: ["proguard.flags"],
+    },
+}
diff --git a/tensorflow/lite/java/src/main/java/org/tensorflow/lite/InterpreterFactoryImpl.java b/tensorflow/lite/java/src/main/java/org/tensorflow/lite/InterpreterFactoryImpl.java
index 77fdfd6754c..00eacfa42d7 100644
--- a/tensorflow/lite/java/src/main/java/org/tensorflow/lite/InterpreterFactoryImpl.java
+++ b/tensorflow/lite/java/src/main/java/org/tensorflow/lite/InterpreterFactoryImpl.java
@@ -26,6 +26,7 @@ import org.tensorflow.lite.nnapi.NnApiDelegateImpl;
 @UsedByReflection("InterpreterFactory.java")
 class InterpreterFactoryImpl implements InterpreterFactoryApi {
 
+  @UsedByReflection("InterpreterFactory.java")
   public InterpreterFactoryImpl() {}
 
   @Override
diff --git a/tensorflow/lite/kernels/Android.bp b/tensorflow/lite/kernels/Android.bp
index 5d5198c0bec..538c4e46cda 100644
--- a/tensorflow/lite/kernels/Android.bp
+++ b/tensorflow/lite/kernels/Android.bp
@@ -29,7 +29,6 @@ cc_library_static {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
     ],
     srcs: [
         "internal/optimized/neon_tensor_utils.cc",
```

