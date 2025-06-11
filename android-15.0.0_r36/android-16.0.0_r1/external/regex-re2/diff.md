```diff
diff --git a/Android.bp b/Android.bp
index 15b8abf..c782321 100644
--- a/Android.bp
+++ b/Android.bp
@@ -14,6 +14,7 @@ cc_library_static {
     host_supported: true,
     product_available: true,
     vendor_available: true,
+    recovery_available: true,
     stl: "libc++",
     apex_available: [
         "//apex_available:platform",
@@ -51,6 +52,7 @@ cc_library_static {
         "//external/grpc-grpc:__subpackages__",
         "//external/kythe:__subpackages__",
     ],
+    min_sdk_version: "apex_inherit",
 }
 
 // This test uses a minimal fork of GTest that is incompatible with Android
```

