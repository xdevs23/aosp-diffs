```diff
diff --git a/Android.bp b/Android.bp
index 630bd26..e5add5e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -274,9 +274,6 @@ java_library {
     srcs: [
         "tensorflow_lite_support/java/src/java/org/tensorflow/lite/task/core/*.java",
     ],
-    optimize: {
-        proguard_flags_files: ["proguard.flags"],
-    },
     apex_available: [
         "//apex_available:platform",
         "com.android.adservices",
diff --git a/proguard.flags b/proguard.flags
deleted file mode 100644
index 566e53f..0000000
--- a/proguard.flags
+++ /dev/null
@@ -1,10 +0,0 @@
-# Stop proguard from stripping away code used by tensorflow JNI library.
--keepclassmembers class org.tensorflow.lite.NativeInterpreterWrapper {
-    private long inferenceDurationNanoseconds;
-}
-
--keep class org.tensorflow.lite.annotations.UsedByReflection
--keep @org.tensorflow.lite.annotations.UsedByReflection class *
--keepclassmembers class * {
-    @org.tensorflow.lite.annotations.UsedByReflection *;
-}
\ No newline at end of file
```

