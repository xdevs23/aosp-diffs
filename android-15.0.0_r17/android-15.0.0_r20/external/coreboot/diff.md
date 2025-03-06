```diff
diff --git a/Android.bp b/Android.bp
index ee617dc7d1..504e843cfc 100644
--- a/Android.bp
+++ b/Android.bp
@@ -64,9 +64,12 @@ cc_defaults {
         "src",
         "src/vendorcode/intel/edk2/uefi_2.4/MdePkg/Include",
     ],
+}
 
+cc_defaults {
+    name: "coreboot-tools-with-vboot-defaults",
+    defaults: [ "coreboot-tools-defaults" ],
     include_dirs: ["external/vboot_reference/host/lib/include"],
-
     static_libs: ["libvboot_host"],
 }
 
@@ -98,8 +101,9 @@ genrule {
 
 cc_binary {
     name: "cbfstool",
-    defaults: ["coreboot-tools-defaults"],
+    defaults: [ "coreboot-tools-with-vboot-defaults" ],
     host_supported: true,
+    vendor: true,
     cflags: [
         "-Wno-error=missing-prototypes",
         "-Wno-error=strict-prototypes",
@@ -144,7 +148,8 @@ cc_binary {
 
 cc_binary {
     name: "elogtool",
-    defaults: ["coreboot-tools-defaults"],
+    defaults: [ "coreboot-tools-with-vboot-defaults" ],
+    vendor: true,
     srcs: [
         "util/cbfstool/common.c",
         "util/cbfstool/elogtool.c",
@@ -158,6 +163,7 @@ cc_binary {
 cc_binary {
     name: "ifdtool",
     defaults: ["coreboot-tools-defaults"],
+    vendor: true,
     cflags: [
         "-Wno-error=incompatible-pointer-types-discards-qualifiers",
         "-Wno-error=shadow",
@@ -170,14 +176,12 @@ cc_binary {
     ],
 }
 
-/* TODO(czapiga): Remove cbmem from vendor/google/desktop
 cc_binary {
   name: "cbmem",
-  defaults: ["cooreboot-tools-defaults"],
+  defaults: ["coreboot-tools-defaults"],
   vendor: true,
   srcs: [
     "util/cbmem/cbmem.c",
     "src/commonlib/bsd/ipchksum.c",
   ],
 }
-*/
```

