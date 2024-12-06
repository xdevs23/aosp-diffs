```diff
diff --git a/Android.bp b/Android.bp
index 9413549f..7dd2dbdd 100644
--- a/Android.bp
+++ b/Android.bp
@@ -35,6 +35,7 @@ java_library {
         ":GsonBuildConfig.java",
     ],
     sdk_version: "current",
+    min_sdk_version: "30",
     // b/267831518: Pin tradefed and dependencies to Java 11.
     java_version: "11",
     target: {
@@ -42,6 +43,10 @@ java_library {
             enabled: true,
         },
     },
+    apex_available: [
+        "//apex_available:platform",
+        "//apex_available:anyapex",
+    ],
 }
 
 python_binary_host {
```

