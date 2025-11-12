```diff
diff --git a/Android.bp b/Android.bp
index c7d29331c..1d5bbfdf6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -251,8 +251,6 @@ cc_library {
     recovery_available: true,
     vendor_available: true,
     product_available: true,
-    // TODO(b/153609531): remove when no longer needed.
-    native_bridge_supported: true,
     target: {
         android: {
             static: {
diff --git a/OWNERS b/OWNERS
index 7c51a12a1..a1edd8888 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,2 @@
-# Default code reviewers picked from top 3 or more developers.
-# Please update this list if you find better candidates.
 ccross@google.com
-joeo@google.com
+colefaust@google.com
```

