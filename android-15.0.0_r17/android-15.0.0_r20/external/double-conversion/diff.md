```diff
diff --git a/Android.bp b/Android.bp
index 49b0b0c..307a17e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -16,6 +16,10 @@ license {
 
 cc_library_static {
     name: "libdoubleconversion",
+    host_supported: true,
+    ramdisk_available: true,
+    recovery_available: true,
+    vendor_available: true,
     export_include_dirs: ["."],
     srcs: [
         "double-conversion/bignum.cc",
@@ -31,7 +35,16 @@ cc_library_static {
     min_sdk_version: "30",
     stl: "libc++_static",
     visibility: [
+        "//external/libchrome:__subpackages__",
         "//external/tensorflow:__subpackages__",
+        "//external/zucchini:__subpackages__",
+        "//packages/modules/Bluetooth:__subpackages__",
+        "//system/update_engine",
+        "//vendor:__subpackages__",
+    ],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.btservices",
+        "com.android.ondevicepersonalization",
     ],
-    apex_available: ["com.android.ondevicepersonalization"],
 }
```

