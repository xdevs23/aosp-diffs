```diff
diff --git a/Android.bp b/Android.bp
index 573255aa..7d0771e3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -65,7 +65,7 @@ cc_defaults {
         "-Wno-typedef-redefinition",
     ],
     header_libs: [
-         "elfutils_headers",
+        "elfutils_headers",
     ],
     export_header_lib_headers: ["elfutils_headers"],
 
@@ -85,7 +85,7 @@ cc_library {
     vendor_available: true,
     defaults: ["elfutils_defaults"],
 
-    srcs:  ["libelf/*.c",],
+    srcs: ["libelf/*.c"],
 
     export_include_dirs: ["libelf"],
 
@@ -140,8 +140,10 @@ cc_library_headers {
     visibility: [":__subpackages__"],
 }
 
-cc_library_host_static {
+cc_library {
     name: "libdw",
+    host_supported: true,
+    device_supported: false,
     defaults: ["elfutils_defaults"],
     target: {
         darwin: {
@@ -171,12 +173,6 @@ cc_library_host_static {
         // Do not enabled compression support
         "libdwfl/bzip2.c",
         "libdwfl/lzma.c",
-        // Those headers are incompatible with clang due to nested function
-        // definitions.
-        "libdwfl/dwfl_segment_report_module.c",
-        "libdwfl/debuginfod-client.c",
-        "libdwfl/elf-from-memory.c",
-        "libdwfl/link_map.c",
         // These depend on argp which doesn't exist in musl
         "libdwfl/argp-std.c",
         // Those are common source files actually used as headers and not
@@ -196,7 +192,7 @@ cc_library_host_static {
         "libdw",
     ],
     static_libs: [
-        "libelf"
+        "libelf",
     ],
     whole_static_libs: [
         "libeu",
```

