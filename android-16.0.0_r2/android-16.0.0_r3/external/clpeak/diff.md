```diff
diff --git a/Android.bp b/Android.bp
index c8422d3..98978d1 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,6 +42,7 @@ cc_benchmark {
         "include",
         "src/kernels",
     ],
+    test_suites: ["dts"],
     header_libs: ["OpenCL-CLHPP"],
     soc_specific: true,
 }
```

