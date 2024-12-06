```diff
diff --git a/Android.bp b/Android.bp
index 56676ff..c64200c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -104,6 +104,9 @@ libz_srcs = [
 
 cc_defaults {
     name: "libz_defaults",
+    defaults: [
+        "bug_24465209_workaround",
+    ],
 
     cflags: cflags_shared,
     stl: "none",
@@ -120,11 +123,6 @@ cc_defaults {
 
     arch: {
         arm: {
-            // TODO: This is to work around b/24465209. Remove after root cause
-            // is fixed.
-            pack_relocations: false,
-            ldflags: ["-Wl,--hash-style=both"],
-
             cflags: cflags_arm,
         },
         arm64: {
@@ -177,28 +175,11 @@ cc_defaults {
     },
 }
 
-// TODO: Remove this when b/328163089 is fixed.
-// Thin lto will be enabled by default in the future.
-cc_defaults {
-    name: "libz_thin_lto_defaults",
-
-    target: {
-        android_arm64: {
-            lto: {
-                thin: true,
-            },
-        },
-    },
-}
-
 cc_library {
     name: "libz",
-    defaults: [
-        "libz_defaults",
-        "libz_thin_lto_defaults",
-    ],
+    defaults: ["libz_defaults"],
 
-    whole_static_libs: ["libz_static"],
+    srcs: libz_srcs,
 
     unique_host_soname: true,
     static_ndk_lib: true,
@@ -213,6 +194,13 @@ cc_library {
         symbol_file: "libz.map.txt",
     },
 
+    // linker/linker64 statically link zlib.
+    static: {
+        apex_available: [
+            "com.android.runtime",
+        ],
+    },
+
     // When used by Vendor/Product APEX,
     // libz should be treated like non-stable module.
     // (Hence, should be bundled in APEX).
@@ -224,24 +212,8 @@ cc_library {
             no_stubs: true,
         },
     },
-}
-
-cc_library {
-    name: "libz_static",
-    defaults: ["libz_defaults"],
-    visibility: ["//visibility:private"],
-
-    srcs: libz_srcs,
-
-    sdk_version: "minimum",
-    min_sdk_version: "apex_inherit",
 
-    apex_available: [
-        "com.android.art",
-        "com.android.art.debug",
-        "com.android.runtime",
-        "//apex_available:platform",
-    ],
+    afdo: true,
 }
 
 // A build of libz with identical behavior between architectures.
@@ -252,7 +224,6 @@ cc_library {
 // can and do differ over time.
 cc_library {
     name: "libz_stable",
-    defaults: ["libz_thin_lto_defaults"],
     visibility: [
         "//bootable/recovery/applypatch",
         "//bootable/recovery/tests",
@@ -312,6 +283,23 @@ cc_library {
     ],
 }
 
+cc_library_static {
+    name: "tflite_support_libz",
+    defaults: ["libz_defaults"],
+    srcs: [
+        "contrib/minizip/ioapi.c",
+        "contrib/minizip/unzip.c",
+    ],
+    sdk_version: "current",
+    // TODO: switch this to "apex_inherit".
+    min_sdk_version: "30",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.adservices",
+        "com.android.extservices",
+    ],
+}
+
 cc_test {
     name: "zlib_tests",
     srcs: [
@@ -348,9 +336,6 @@ ndk_library {
     symbol_file: "libz.map.txt",
     first_version: "9",
     unversioned_until: "current",
-    export_header_libs: [
-        "libz_headers",
-    ],
 }
 
 // Export zlib headers for inclusion in the musl sysroot.
```

