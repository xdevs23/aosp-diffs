```diff
diff --git a/Android.bp b/Android.bp
index c64200c..ec75947 100644
--- a/Android.bp
+++ b/Android.bp
@@ -45,9 +45,11 @@ cflags_arm = [
 cflags_arm64 = cflags_arm + ["-DINFLATE_CHUNK_READ_64LE"]
 
 cflags_riscv64 = [
-    // TODO: test and enable these.
-    // "-DRISCV_RVV",
-    // "-DADLER32_SIMD_RVV",
+    "-DRISCV_RVV",
+    "-DADLER32_SIMD_RVV",
+    "-DDEFLATE_SLIDE_HASH_RVV",
+    "-DINFLATE_CHUNK_GENERIC",
+    "-DINFLATE_CHUNK_READ_64LE",
 ]
 
 // The *host* x86 configuration (with *lower* CPU feature requirements).
```

