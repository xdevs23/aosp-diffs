```diff
diff --git a/shim/Android.bp b/shim/Android.bp
index 6ae4ef27f..effa36cbf 100644
--- a/shim/Android.bp
+++ b/shim/Android.bp
@@ -175,11 +175,17 @@ cc_defaults {
     proprietary: true,
 }
 
+vintf_fragment {
+    name: "android.hardware.neuralnetworks-shim-service-armnn.xml",
+    src: "config/android.hardware.neuralnetworks-shim-service-armnn.xml",
+    proprietary: true,
+}
+
 cc_binary {
     name: "android.hardware.neuralnetworks-shim-service-armnn",
     srcs: ["shimservice.cpp"],
     defaults: ["NeuralNetworksShimArmnnDriverAidl_server_defaults"],
     stl: "libc++_static",
     init_rc: ["config/android.hardware.neuralnetworks-shim-service-armnn.rc"],
-    vintf_fragments: ["config/android.hardware.neuralnetworks-shim-service-armnn.xml"],
+    vintf_fragment_modules: ["android.hardware.neuralnetworks-shim-service-armnn.xml"],
 }
```

