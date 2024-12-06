```diff
diff --git a/service/Android.bp b/service/Android.bp
index 3ba2551..fcb89ca 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -56,7 +56,7 @@ java_library {
     ],
     sdk_version: "system_server_current",
     libs: [
-        "framework-configinfrastructure",
+        "framework-configinfrastructure.stubs.module_lib",
         "framework-scheduling.impl",
         "framework-tethering.stubs.module_lib",
         "unsupportedappusage",
diff --git a/tests/unittests/Android.bp b/tests/unittests/Android.bp
index 78ea03b..0e01922 100644
--- a/tests/unittests/Android.bp
+++ b/tests/unittests/Android.bp
@@ -28,9 +28,9 @@ android_test {
         "truth",
     ],
     libs: [
-        "android.test.mock",
-        "android.test.base",
-        "android.test.runner",
+        "android.test.mock.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.runner.stubs.system",
     ],
     jni_libs: [
         // Required for ExtendedMockito
```

