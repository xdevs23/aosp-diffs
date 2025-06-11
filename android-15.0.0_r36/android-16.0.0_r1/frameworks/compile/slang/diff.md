```diff
diff --git a/Android.bp b/Android.bp
index c972cb5..6cad2a5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -65,6 +65,7 @@ cc_defaults {
         "-std=c++11",
         "-D__DISABLE_ASSERTS",
         "-DTARGET_BUILD_VARIANT=user",
+        "-Wno-cast-function-type-mismatch",
     ],
 
     product_variables: {
```

