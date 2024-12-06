```diff
diff --git a/Android.bp b/Android.bp
index 8e7b887..c972cb5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -62,12 +62,8 @@ cc_defaults {
     ],
 
     cflags: [
-        "-Wall",
-        "-Werror",
         "-std=c++11",
-
         "-D__DISABLE_ASSERTS",
-
         "-DTARGET_BUILD_VARIANT=user",
     ],
 
@@ -75,7 +71,6 @@ cc_defaults {
         debuggable: {
             cflags: [
                 "-U__DISABLE_ASSERTS",
-
                 "-UTARGET_BUILD_VARIANT",
                 "-DTARGET_BUILD_VARIANT=userdebug",
             ],
@@ -84,7 +79,6 @@ cc_defaults {
             cflags: [
                 "-O0",
                 "-D__ENABLE_INTERNAL_OPTIONS",
-
                 "-UTARGET_BUILD_VARIANT",
                 "-DTARGET_BUILD_VARIANT=eng",
             ],
@@ -109,8 +103,8 @@ cc_library_headers {
     native_bridge_supported: true,
     target: {
         windows: {
-	    enabled: true,
-	},
+            enabled: true,
+        },
     },
 }
 
```

