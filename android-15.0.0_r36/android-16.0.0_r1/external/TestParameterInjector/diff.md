```diff
diff --git a/Android.bp b/Android.bp
index 16ee275..3a2736c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -10,6 +10,7 @@ package {
 
 java_library {
     name: "TestParameterInjector",
+    sdk_version: "current",
     srcs: [
         "junit4/src/main/java/**/*.java",
     ],
@@ -32,6 +33,8 @@ java_library {
         "//cts/tests/tests/app",
         "//cts/tests/tests/car",
         "//cts/tests/tests/content",
+        "//cts/tests/tests/packageinstaller/criticaluserjourney",
+        "//cts/tests/tests/packageinstaller/install",
         "//external/robolectric:__subpackages__",
         "//frameworks/base/core/tests/coretests",
         "//frameworks/base/libs/WindowManager/Shell/tests/unittest",
@@ -41,8 +44,9 @@ java_library {
         "//frameworks/base/services/tests/uiservicestests",
         "//frameworks/base/services/tests/vibrator",
         "//frameworks/base/tests/UsbManagerTests",
-        "//packages/modules/Bluetooth/framework/tests/bumble",
-        "//packages/modules/HealthFitness/tests/unittests",
+        "//frameworks/proto_logging/stats/stats_log_api_gen/test_java",
+        "//packages/modules/Bluetooth:__subpackages__",
+        "//packages/modules/HealthFitness:__subpackages__",
         "//vendor:__subpackages__",
     ],
 }
diff --git a/OWNERS b/OWNERS
index 14099dc..6df97ba 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 okamil@google.com
 wescande@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

