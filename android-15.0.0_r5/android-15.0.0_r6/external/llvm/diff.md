```diff
diff --git a/Android.bp b/Android.bp
index 7e46bb4a58..dba0bece94 100644
--- a/Android.bp
+++ b/Android.bp
@@ -82,8 +82,6 @@ llvm_defaults {
         "-D__STDC_CONSTANT_MACROS",
         "-D__STDC_FORMAT_MACROS",
         "-fomit-frame-pointer",
-        "-Wall",
-        "-W",
         "-Wno-cast-qual",
         "-Wno-sign-compare",
         "-Wno-unused-parameter",
@@ -92,7 +90,6 @@ llvm_defaults {
         "-Wno-implicit-fallthrough",
         "-Wno-deprecated-declarations",
         "-Wwrite-strings",
-        "-Werror",
         "-Dsprintf=sprintf",
     ],
 
@@ -314,7 +311,7 @@ cc_library {
     target: {
         host: {
             // Host build pulls in all ARM, Mips, X86 components.
-           whole_static_libs: llvm_arm_static_libraries +
+            whole_static_libs: llvm_arm_static_libraries +
                 llvm_aarch64_static_libraries +
                 llvm_mips_static_libraries +
                 llvm_x86_static_libraries,
```

