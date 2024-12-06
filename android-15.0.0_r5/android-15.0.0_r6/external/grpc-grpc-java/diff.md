```diff
diff --git a/annotation-stubs/Android.bp b/annotation-stubs/Android.bp
index 929eb598c..472fd823e 100644
--- a/annotation-stubs/Android.bp
+++ b/annotation-stubs/Android.bp
@@ -43,6 +43,7 @@ java_library {
             enabled: true,
         },
     },
+    is_stubs_module: true,
 }
 
 python_binary_host {
diff --git a/core/Android.bp b/core/Android.bp
index 68c2d6f34..347a99dac 100644
--- a/core/Android.bp
+++ b/core/Android.bp
@@ -97,9 +97,7 @@ java_library {
         "gson",
         "error_prone_annotations",
         "guava",
-        "opencensus-java-api",
-        "opencensus-java-contrib-grpc-metrics",
-        "perfmark-api-lib",
+        "perfmark",
     ],
     target: {
         // For the Android variant, ignore this class since it is optional,
```

