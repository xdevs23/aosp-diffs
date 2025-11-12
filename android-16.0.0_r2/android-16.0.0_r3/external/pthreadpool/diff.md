```diff
diff --git a/Android.bp b/Android.bp
index 42fff11..0f1c159 100644
--- a/Android.bp
+++ b/Android.bp
@@ -57,6 +57,10 @@ cc_library_static {
         "libcpuinfo",
         "libclog",
     ],
+    visibility: [
+        "//external/XNNPACK",
+        "//packages/modules/NeuralNetworks/driver/sample_hidl",
+    ],
 }
 
 cc_test {
```

