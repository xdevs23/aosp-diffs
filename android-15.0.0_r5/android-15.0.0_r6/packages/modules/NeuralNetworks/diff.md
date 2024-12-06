```diff
diff --git a/runtime/Android.bp b/runtime/Android.bp
index 21ec0b9af..81f4f9617 100644
--- a/runtime/Android.bp
+++ b/runtime/Android.bp
@@ -156,7 +156,6 @@ cc_defaults {
 
     shared_libs: [
         "libbinder_ndk",
-        "libcgrouprc",
         "liblog",
         "libneuralnetworks_packageinfo",
     ],
@@ -332,9 +331,6 @@ ndk_library {
     symbol_file: "libneuralnetworks.map.txt",
     // Android O-MR1
     first_version: "27",
-    export_header_libs: [
-        "libneuralnetworks_ndk_headers",
-    ],
 }
 
 genrule {
diff --git a/runtime/include/NeuralNetworks.h b/runtime/include/NeuralNetworks.h
index b986e09e9..4e570e176 100644
--- a/runtime/include/NeuralNetworks.h
+++ b/runtime/include/NeuralNetworks.h
@@ -55,7 +55,7 @@
 #endif  // __ANDROID__
 
 #if !defined(__DEPRECATED_IN)
-#define __DEPRECATED_IN(api_level) __attribute__((annotate("deprecated_in=" #api_level)))
+#define __DEPRECATED_IN(api_level, msg) __attribute__((annotate("deprecated_in=" #api_level)))
 #endif
 
 // This is required for building libneuralnetworks_cl,
@@ -66,7 +66,8 @@
 #define __NNAPI_DEPRECATED_IN(x)
 #else
 #define __NNAPI_INTRODUCED_IN(x) __INTRODUCED_IN(x)
-#define __NNAPI_DEPRECATED_IN(x) __DEPRECATED_IN(x)
+#define __NNAPI_DEPRECATED_IN(x) \
+    __DEPRECATED_IN(x, "NN API is deprecated. Users should migrate to TFlite.")
 #endif
 
 #ifndef __NNAPI_FL5_MIN_ANDROID_API__
```

