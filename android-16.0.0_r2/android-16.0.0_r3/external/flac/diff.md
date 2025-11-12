```diff
diff --git a/src/libFLAC/Android.bp b/src/libFLAC/Android.bp
index a08fae0d..5e2f84e7 100644
--- a/src/libFLAC/Android.bp
+++ b/src/libFLAC/Android.bp
@@ -8,7 +8,7 @@ package {
     default_applicable_licenses: ["external_flac_license"],
 }
 
-cc_library_static {
+cc_library {
     name: "libFLAC",
     vendor_available: true,
     host_supported: true,
```

