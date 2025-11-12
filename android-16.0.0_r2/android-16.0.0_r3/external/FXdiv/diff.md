```diff
diff --git a/Android.bp b/Android.bp
index e4e0bc8..a110347 100644
--- a/Android.bp
+++ b/Android.bp
@@ -34,6 +34,10 @@ cc_library_headers {
     export_include_dirs: ["include"],
     vendor_available: true,
     sdk_version: "current",
+    visibility: [
+        "//external/XNNPACK",
+        "//external/pthreadpool",
+    ],
 }
 
 cc_defaults {
@@ -48,7 +52,7 @@ cc_defaults {
     stl: "libc++_static",
     static_libs: [
         "libgmock_ndk",
-    ]
+    ],
 }
 
 cc_test {
diff --git a/METADATA b/METADATA
index 7e1712f..fc69c2f 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,20 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/FXdiv
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "FXdiv"
 description: "Header-only library for division via fixed-point multiplication by inverse  On modern CPUs and GPUs integer division is several times slower than multiplication. FXdiv implements an algorithm to replace an integer division with a multiplication and two shifts. This algorithm improves performance when an application performs repeated divisions by the same divisor."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/Maratyszcza/FXdiv"
-  }
-  url {
-    type: GIT
-    value: "https://github.com/Maratyszcza/FXdiv"
-  }
-  version: "63058eff77e11aa15bf531df5dd34395ec3017c8"
   license_type: NOTICE
   last_upgrade_date {
     year: 2020
     month: 12
     day: 9
   }
+  homepage: "https://github.com/Maratyszcza/FXdiv"
+  identifier {
+    type: "Git"
+    value: "https://github.com/Maratyszcza/FXdiv"
+    version: "63058eff77e11aa15bf531df5dd34395ec3017c8"
+  }
 }
diff --git a/OWNERS b/OWNERS
index dc0d96b..70d0603 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,2 @@
 include platform/packages/modules/NeuralNetworks:/NNAPI_OWNERS
-include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
+include platform/system/core:main:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

