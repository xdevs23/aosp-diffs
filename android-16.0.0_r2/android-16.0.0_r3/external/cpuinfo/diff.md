```diff
diff --git a/Android.bp b/Android.bp
index 010bf1d..87602a8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -104,10 +104,13 @@ cc_library_static {
         "-std=c99",
         "-Oz",
         "-D_GNU_SOURCE=1",
+        "-DCPUINFO_LOG_LEVEL=2",
         "-Wno-unused-function",
         "-Wno-unused-parameter",
         "-Wno-missing-field-initializers",
-        "-DCPUINFO_LOG_LEVEL=2",
+        // __riscv_hwprobe() changed from unsigned long* to cpu_set_t*,
+        // but upstream hasn't updated yet.
+        "-Wno-incompatible-pointer-types",
     ],
     whole_static_libs: [
         "libclog",
```

