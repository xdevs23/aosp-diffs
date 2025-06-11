```diff
diff --git a/Android.bp b/Android.bp
index 49f66dda..f8ed9cff 100644
--- a/Android.bp
+++ b/Android.bp
@@ -125,6 +125,7 @@ cc_defaults {
 
         // disable warnings:
         "-Wno-bitwise-op-parentheses",
+        "-Wno-cast-function-type-mismatch",
         "-Wno-dangling-else",
         "-Wno-ignored-attributes",
         "-Wno-logical-op-parentheses",
@@ -370,6 +371,12 @@ cc_defaults {
     ldflags: [
         "-Wl,--no-gc-sections",
     ],
+    // Cmake snapshots are not supported when building for musl, but
+    // all host modules depend on the musl CRT objects when building
+    // the host for musl, so mark the CRT objects as supported to avoid
+    // "CMake snapshots not supported, despite being a dependency for ..."
+    // errors.
+    cmake_snapshot_supported: true,
 
     // The headers below are the same as the header_libs in
     // libc_musl_defaults, but bazel considers the crt depending
@@ -599,7 +606,6 @@ cc_genrule {
 // configure scripts from external projects to generate necessary files to build against musl.
 //
 
-
 // An empty static library that will be copied to libdl.a, etc. in the sysroot.
 // Shouldn't be used by anything else besides the sysroot cc_genrule.
 cc_library_static {
@@ -813,4 +819,4 @@ cc_genrule {
         " $(genDir)/libs_renamed.zip",
 }
 
-build=["sources.bp"]
+build = ["sources.bp"]
diff --git a/OWNERS b/OWNERS
index 1db06a62..284398c7 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 ccross@google.com
 enh@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/android/include/linux/udp.h b/android/include/linux/udp.h
new file mode 100644
index 00000000..cfc749fb
--- /dev/null
+++ b/android/include/linux/udp.h
@@ -0,0 +1,8 @@
+#pragma once
+
+// Bionic(bionic/libc/kernel/tools/defaults.py) replaces udphdr
+// with __kernel_udphdr and because of that including linux/udp.h
+// is insufficient. Undo the renaming performed by the script.
+#define __kernel_udphdr udphdr
+
+#include_next <linux/udp.h>
```

