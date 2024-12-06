```diff
diff --git a/Android.bp b/Android.bp
index 504ba94..9dfa015 100644
--- a/Android.bp
+++ b/Android.bp
@@ -36,8 +36,10 @@ java_library {
         "//frameworks/base/services/tests/displayservicetests",
         "//frameworks/base/services/tests/powerservicetests",
         "//frameworks/base/services/tests/uiservicestests",
+        "//frameworks/base/services/tests/vibrator",
         "//frameworks/base/tests/UsbManagerTests",
         "//packages/modules/Bluetooth/framework/tests/bumble",
+        "//packages/modules/HealthFitness/tests/unittests",
         "//vendor:__subpackages__",
     ],
 }
```

