```diff
diff --git a/Android.bp b/Android.bp
index 66d0956..629fa75 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,8 +55,12 @@ cc_binary {
     ],
 
     arch: {
-        arm: { cflags: ["-DSTRESSAPPTEST_CPU_ARMV7A"] },
-        arm64: { cflags: ["-DSTRESSAPPTEST_CPU_AARCH64"] },
+        arm: {
+            cflags: ["-DSTRESSAPPTEST_CPU_ARMV7A"],
+        },
+        arm64: {
+            cflags: ["-DSTRESSAPPTEST_CPU_AARCH64"],
+        },
         x86: {
             enabled: false,
         },
```

