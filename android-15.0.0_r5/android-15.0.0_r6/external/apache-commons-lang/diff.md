```diff
diff --git a/Android.bp b/Android.bp
index 883e3e361..04d3e4edb 100644
--- a/Android.bp
+++ b/Android.bp
@@ -46,4 +46,9 @@ java_library {
         "//external/apache-velocity-engine",
         "//packages/modules/OnDevicePersonalization:__subpackages__",
     ],
+    errorprone: {
+        javacflags: [
+            "-Xep:ReturnValueIgnored:WARN",
+        ],
+    },
 }
```

