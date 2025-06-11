```diff
diff --git a/Android.bp b/Android.bp
index 2bc0f5d..0684c54 100644
--- a/Android.bp
+++ b/Android.bp
@@ -39,6 +39,7 @@ java_library_static {
         "//cts/common/device-side/device-info",
         "//packages/apps/DeviceDiagnostics/app/src/main",
         "//packages/apps/DeviceDiagnostics/DeviceDiagnosticsLib/src/main",
+        "//packages/apps/DeviceDiagnostics/tradeinmode",
     ],
     min_sdk_version: "31",
     dxflags: ["--multi-dex"],
@@ -53,4 +54,5 @@ java_library_static {
     libs: [
         "gson",
     ],
+    host_supported: true,
 }
```

