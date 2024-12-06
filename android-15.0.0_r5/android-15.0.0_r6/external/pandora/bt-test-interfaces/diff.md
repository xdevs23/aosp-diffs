```diff
diff --git a/Android.bp b/Android.bp
index dd2f953..34d6c63 100644
--- a/Android.bp
+++ b/Android.bp
@@ -18,7 +18,7 @@ license {
 }
 
 java_library {
-    name: "pandora-grpc-java",
+    name: "pandora_stable-grpc-java",
     visibility: ["//packages/modules/Bluetooth/android/pandora/server"],
     srcs: [":pandora-protos"],
     static_libs: [
@@ -27,7 +27,7 @@ java_library {
         "javax_annotation-api_1.3.2",
         "libprotobuf-java-lite",
         "opencensus-java-api",
-        "pandora-proto-java",
+        "pandora_stable-proto-java",
     ],
     proto: {
         include_dirs: [
@@ -36,13 +36,13 @@ java_library {
         ],
         plugin: "grpc-java-plugin",
         output_params: [
-           "lite",
+            "lite",
         ],
     },
 }
 
 java_library {
-    name: "pandora-proto-java",
+    name: "pandora_stable-proto-java",
     visibility: [
         "//packages/modules/Bluetooth/android/pandora/server",
         "//packages/modules/Bluetooth/pandora/interfaces",
diff --git a/OWNERS b/OWNERS
index d4db030..20a7f4a 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,2 @@
 girardier@google.com
-licorne@google.com
 charliebout@google.com
```

