```diff
diff --git a/Android.bp b/Android.bp
index 30df5cb..5cbb5e9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -278,6 +278,7 @@ cc_defaults {
 // Build as a shared library.
 cc_library {
     name: "libjpeg",
+    afdo: true,
     host_supported: true,
     vendor_available: true,
     product_available: true,
diff --git a/OWNERS.android b/OWNERS.android
index 3fbf06e..7529cb9 100644
--- a/OWNERS.android
+++ b/OWNERS.android
@@ -1,4 +1 @@
-# Upstream maintainer who should review any functional changes:
-scroggo@google.com
-# AOSP maintainers:
 include platform/system/core:/janitors/OWNERS
```

