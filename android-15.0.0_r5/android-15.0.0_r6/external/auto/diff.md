```diff
diff --git a/service/Android.bp b/service/Android.bp
index b7327ea7..052b4b15 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -12,6 +12,10 @@ java_library {
     host_supported: true,
     srcs: ["annotations/src/main/java/**/*.java"],
     sdk_version: "core_current",
+    apex_available: [
+        "//apex_available:platform",
+        "//apex_available:anyapex",
+    ],
     visibility: ["//visibility:public"],
 }
 
```

