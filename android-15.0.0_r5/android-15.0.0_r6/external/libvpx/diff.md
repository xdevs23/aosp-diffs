```diff
diff --git a/Android.bp b/Android.bp
index 573fdaffc..b211e02a0 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1164,11 +1164,18 @@ license {
     ],
 }
 
-cc_library {
-    name: "libvpx",
-    vendor_available: true,
-    host_supported: true,
-    version_script: "exports.lds",
+cc_defaults {
+    name: "libvpx_defaults",
+
+    cflags: [
+        "-O3",
+    ],
+
+    min_sdk_version: "29",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.media.swcodec",
+    ],
 
     target: {
         darwin: {
@@ -1184,6 +1191,37 @@ cc_library {
         },
     },
 
+    arch: {
+        // configured to require the neon unit
+        arm: {
+            local_include_dirs: ["config/arm-neon"],
+        },
+
+        arm64: {
+            local_include_dirs: ["config/arm64"],
+        },
+
+        riscv64: {
+            local_include_dirs: ["config/generic"],
+        },
+
+        x86: {
+            local_include_dirs: ["config/x86"],
+        },
+
+        x86_64: {
+            local_include_dirs: ["config/x86_64"],
+        },
+    },
+}
+
+cc_library {
+    name: "libvpx",
+    defaults: ["libvpx_defaults"],
+    vendor_available: true,
+    host_supported: true,
+    version_script: "exports.lds",
+
     arch: {
         // configured to require the neon unit
         arm: {
@@ -1191,22 +1229,18 @@ cc_library {
             instruction_set: "arm",
 
             srcs: libvpx_arm_neon_c_srcs + libvpx_arm_neon_asm_srcs,
-            local_include_dirs: ["config/arm-neon"],
         },
 
         arm64: {
             srcs: libvpx_arm64_c_srcs,
-            local_include_dirs: ["config/arm64"],
         },
 
         riscv64: {
             srcs: libvpx_generic_c_srcs,
-            local_include_dirs: ["config/generic"],
         },
 
         x86: {
             srcs: libvpx_x86_c_srcs + libvpx_x86_asm_srcs,
-            local_include_dirs: ["config/x86"],
             cflags: [
                 "-mssse3",
             ],
@@ -1214,7 +1248,6 @@ cc_library {
 
         x86_64: {
             srcs: libvpx_x86_64_c_srcs + libvpx_x86_64_asm_srcs,
-            local_include_dirs: ["config/x86_64"],
             cflags: [
                 "-mssse3",
             ],
@@ -1222,7 +1255,6 @@ cc_library {
     },
 
     cflags: [
-        "-O3",
         "-Wno-unused-parameter",
     ],
 
@@ -1233,11 +1265,6 @@ cc_library {
         misc_undefined: ["bounds"],
         blocklist: "libvpx_blocklist.txt",
     },
-    min_sdk_version: "29",
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.media.swcodec",
-    ],
 }
 
 cc_library_headers {
@@ -1250,32 +1277,12 @@ cc_library_headers {
 
 cc_fuzz {
     name: "vp9_dec_fuzzer",
+    defaults: ["libvpx_defaults"],
     host_supported: true,
     srcs: [
         "examples/vpx_dec_fuzzer.cc",
     ],
-    target: {
-        darwin: {
-            enabled: false,
-        },
-    },
-    arch: {
-        arm: {
-            local_include_dirs: ["config/arm-neon"],
-        },
-
-        arm64: {
-            local_include_dirs: ["config/arm64"],
-        },
 
-        x86: {
-            local_include_dirs: ["config/x86"],
-        },
-
-        x86_64: {
-            local_include_dirs: ["config/x86_64"],
-        },
-    },
     cflags: ["-DDECODER=vp9"],
     static_libs: [
         "libvpx",
@@ -1284,32 +1291,11 @@ cc_fuzz {
 
 cc_fuzz {
     name: "vp8_dec_fuzzer",
+    defaults: ["libvpx_defaults"],
     host_supported: true,
     srcs: [
         "examples/vpx_dec_fuzzer.cc",
     ],
-    target: {
-        darwin: {
-            enabled: false,
-        },
-    },
-    arch: {
-        arm: {
-            local_include_dirs: ["config/arm-neon"],
-        },
-
-        arm64: {
-            local_include_dirs: ["config/arm64"],
-        },
-
-        x86: {
-            local_include_dirs: ["config/x86"],
-        },
-
-        x86_64: {
-            local_include_dirs: ["config/x86_64"],
-        },
-    },
 
     cflags: ["-DDECODER=vp8"],
     static_libs: [
diff --git a/Android.bp.in b/Android.bp.in
index c88d8a5da..ac7a2717b 100644
--- a/Android.bp.in
+++ b/Android.bp.in
@@ -29,11 +29,18 @@ license {
     ],
 }
 
-cc_library {
-    name: "libvpx",
-    vendor_available: true,
-    host_supported: true,
-    version_script: "exports.lds",
+cc_defaults {
+    name: "libvpx_defaults",
+
+    cflags: [
+        "-O3",
+    ],
+
+    min_sdk_version: "29",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.media.swcodec",
+    ],
 
     target: {
         darwin: {
@@ -49,6 +56,37 @@ cc_library {
         },
     },
 
+    arch: {
+        // configured to require the neon unit
+        arm: {
+            local_include_dirs: ["config/arm-neon"],
+        },
+
+        arm64: {
+            local_include_dirs: ["config/arm64"],
+        },
+
+        riscv64: {
+            local_include_dirs: ["config/generic"],
+        },
+
+        x86: {
+            local_include_dirs: ["config/x86"],
+        },
+
+        x86_64: {
+            local_include_dirs: ["config/x86_64"],
+        },
+    },
+}
+
+cc_library {
+    name: "libvpx",
+    defaults: [ "libvpx_defaults" ],
+    vendor_available: true,
+    host_supported: true,
+    version_script: "exports.lds",
+
     arch: {
         // configured to require the neon unit
         arm: {
@@ -56,22 +94,18 @@ cc_library {
             instruction_set: "arm",
 
             srcs: libvpx_arm_neon_c_srcs + libvpx_arm_neon_asm_srcs,
-            local_include_dirs: ["config/arm-neon"],
         },
 
         arm64: {
             srcs: libvpx_arm64_c_srcs,
-            local_include_dirs: ["config/arm64"],
         },
 
         riscv64: {
             srcs: libvpx_generic_c_srcs,
-            local_include_dirs: ["config/generic"],
         },
 
         x86: {
             srcs: libvpx_x86_c_srcs + libvpx_x86_asm_srcs,
-            local_include_dirs: ["config/x86"],
             cflags: [
                 "-mssse3",
             ],
@@ -79,7 +113,6 @@ cc_library {
 
         x86_64: {
             srcs: libvpx_x86_64_c_srcs + libvpx_x86_64_asm_srcs,
-            local_include_dirs: ["config/x86_64"],
             cflags: [
                 "-mssse3",
             ],
@@ -87,7 +120,6 @@ cc_library {
     },
 
     cflags: [
-        "-O3",
         "-Wno-unused-parameter",
     ],
 
@@ -98,11 +130,6 @@ cc_library {
         misc_undefined: ["bounds"],
         blocklist: "libvpx_blocklist.txt",
     },
-    min_sdk_version: "29",
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.media.swcodec",
-    ],
 }
 
 cc_library_headers {
@@ -115,32 +142,12 @@ cc_library_headers {
 
 cc_fuzz {
     name: "vp9_dec_fuzzer",
+    defaults: [ "libvpx_defaults" ],
     host_supported: true,
     srcs: [
         "examples/vpx_dec_fuzzer.cc",
     ],
-    target: {
-        darwin: {
-            enabled: false,
-        },
-    },
-    arch: {
-        arm: {
-            local_include_dirs: ["config/arm-neon"],
-        },
-
-        arm64: {
-            local_include_dirs: ["config/arm64"],
-        },
 
-        x86: {
-            local_include_dirs: ["config/x86"],
-        },
-
-        x86_64: {
-            local_include_dirs: ["config/x86_64"],
-        },
-    },
     cflags: ["-DDECODER=vp9"],
     static_libs: [
         "libvpx",
@@ -149,32 +156,11 @@ cc_fuzz {
 
 cc_fuzz {
     name: "vp8_dec_fuzzer",
+    defaults: [ "libvpx_defaults" ],
     host_supported: true,
     srcs: [
         "examples/vpx_dec_fuzzer.cc",
     ],
-    target: {
-        darwin: {
-            enabled: false,
-        },
-    },
-    arch: {
-        arm: {
-            local_include_dirs: ["config/arm-neon"],
-        },
-
-        arm64: {
-            local_include_dirs: ["config/arm64"],
-        },
-
-        x86: {
-            local_include_dirs: ["config/x86"],
-        },
-
-        x86_64: {
-            local_include_dirs: ["config/x86_64"],
-        },
-    },
 
     cflags: ["-DDECODER=vp8"],
     static_libs: [
diff --git a/config/arm64/vpx_config.asm b/config/arm64/vpx_config.asm
index f23e27fe7..abc909617 100644
--- a/config/arm64/vpx_config.asm
+++ b/config/arm64/vpx_config.asm
@@ -51,7 +51,7 @@
 .equ CONFIG_DEBUG_LIBS ,  0
 .equ CONFIG_DEQUANT_TOKENS ,  0
 .equ CONFIG_DC_RECON ,  0
-.equ CONFIG_RUNTIME_CPU_DETECT ,  0
+.equ CONFIG_RUNTIME_CPU_DETECT ,  1
 .equ CONFIG_POSTPROC ,  0
 .equ CONFIG_VP9_POSTPROC ,  0
 .equ CONFIG_MULTITHREAD ,  1
diff --git a/config/arm64/vpx_config.c b/config/arm64/vpx_config.c
index d9a44071c..776aa5d50 100644
--- a/config/arm64/vpx_config.c
+++ b/config/arm64/vpx_config.c
@@ -6,5 +6,5 @@
 /* in the file PATENTS.  All contributing project authors may */
 /* be found in the AUTHORS file in the root of the source tree. */
 #include "vpx/vpx_codec.h"
-static const char* const cfg = "--target=armv8-linux-gcc --disable-neon_dotprod --disable-neon_i8mm --enable-external-build --enable-realtime-only --enable-pic --disable-runtime-cpu-detect --disable-install-docs --size-limit=4096x3072 --enable-vp9-highbitdepth";
+static const char* const cfg = "--target=armv8-linux-gcc --disable-neon_dotprod --disable-neon_i8mm --enable-external-build --enable-realtime-only --enable-pic --disable-runtime-cpu-detect --disable-install-docs --size-limit=4096x3072 --enable-vp9-highbitdepth --enable-runtime-cpu-detect";
 const char *vpx_codec_build_config(void) {return cfg;}
diff --git a/config/arm64/vpx_config.h b/config/arm64/vpx_config.h
index 03f681712..3c8fb9193 100644
--- a/config/arm64/vpx_config.h
+++ b/config/arm64/vpx_config.h
@@ -60,7 +60,7 @@
 #define CONFIG_DEBUG_LIBS 0
 #define CONFIG_DEQUANT_TOKENS 0
 #define CONFIG_DC_RECON 0
-#define CONFIG_RUNTIME_CPU_DETECT 0
+#define CONFIG_RUNTIME_CPU_DETECT 1
 #define CONFIG_POSTPROC 0
 #define CONFIG_VP9_POSTPROC 0
 #define CONFIG_MULTITHREAD 1
diff --git a/generate_config.sh b/generate_config.sh
index a8a43e149..570782f38 100755
--- a/generate_config.sh
+++ b/generate_config.sh
@@ -211,7 +211,8 @@ gen_config_files x86 "--target=x86-linux-gcc ${intel} ${all_platforms}"
 gen_config_files x86_64 "--target=x86_64-linux-gcc ${intel} ${all_platforms}"
 gen_config_files arm-neon "--target=armv7-linux-gcc ${all_platforms}"
 arm64="--disable-neon_dotprod --disable-neon_i8mm"
-gen_config_files arm64 "--target=armv8-linux-gcc ${arm64} ${all_platforms}"
+gen_config_files arm64 "--target=armv8-linux-gcc ${arm64} ${all_platforms} \
+  --enable-runtime-cpu-detect"
 gen_config_files generic "--target=generic-gnu ${all_platforms}"
 
 echo "Remove temporary directory."
```

