```diff
diff --git a/Android.bp b/Android.bp
index 30cf1f39..89432fb4 100644
--- a/Android.bp
+++ b/Android.bp
@@ -113,13 +113,10 @@ cc_library {
     export_header_lib_headers: ["libbpf_bcc_headers"],
     local_include_dirs: ["src/cc"],
 
-    defaults: ["bpf_defaults"],
+    defaults: ["bpf_cc_defaults"],
     cflags: [
         "-DHAVE_EXTERNAL_LIBBPF",
         "-DMINIMAL_LIBBPF",
-        "-Werror",
-        "-Wall",
-        "-Wextra",
         "-Wno-sign-compare",
         "-Wno-typedef-redefinition",
         "-Wno-unused-parameter",
diff --git a/libbpf-tools/Android.bp b/libbpf-tools/Android.bp
index e24b2c0f..a7b02905 100644
--- a/libbpf-tools/Android.bp
+++ b/libbpf-tools/Android.bp
@@ -39,9 +39,6 @@ cc_defaults {
         "-mllvm -bpf-stack-size=1024",
         "-g",
     ],
-    header_libs: [
-        "bpf_prog_headers",
-    ],
     generated_headers: ["libbpf_headers"],
     arch: {
         arm: {
diff --git a/libbpf-tools/blazesym b/libbpf-tools/blazesym
deleted file mode 160000
index d954f738..00000000
--- a/libbpf-tools/blazesym
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit d954f73867527dc75025802160c759d0b6a0641f
diff --git a/libbpf-tools/bpftool b/libbpf-tools/bpftool
deleted file mode 160000
index 6eb3e205..00000000
--- a/libbpf-tools/bpftool
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 6eb3e20583da834da18ea3011dcefd08b3493f8d
```

