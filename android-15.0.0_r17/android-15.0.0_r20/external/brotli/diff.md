```diff
diff --git a/Android.bp b/Android.bp
index f8593f9..3c965c7 100755
--- a/Android.bp
+++ b/Android.bp
@@ -113,8 +113,8 @@ cc_library_shared {
         "java/org/brotli/wrapper/enc/encoder_jni.cc",
     ],
     static_libs: [
-      "libnativehelper_lazy",
-      "libbrotli",
+        "libnativehelper_lazy",
+        "libbrotli",
     ],
     cflags: [
         "-Wno-unused-parameter",
@@ -136,6 +136,10 @@ java_library {
     min_sdk_version: "29",
     // b/267831518: Pin tradefed and dependencies to Java 11.
     java_version: "11",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.virt",
+    ],
 }
 
 // TODO(b/171429704): Remove this genrule and use the fuzz_data.zip
@@ -144,7 +148,7 @@ genrule {
     name: "brotli-fuzzer-corpus",
     srcs: ["java/org/brotli/integration/fuzz_data.zip"],
     cmd: "mkdir -p $(genDir)/c/fuzz && " +
-         "unzip -q $(in) -d $(genDir)/c/fuzz",
+        "unzip -q $(in) -d $(genDir)/c/fuzz",
     out: [
         "c/fuzz/04bdd9f35a2881027adddb039026623cd2e86664",
         "c/fuzz/04dc2c1dc1f4612d4dc4892f4444983f2064c252",
@@ -214,6 +218,6 @@ cc_fuzz {
     srcs: ["c/fuzz/decode_fuzzer.c"],
     corpus: [":brotli-fuzzer-corpus"],
     fuzz_config: {
-        componentid: 128577
+        componentid: 128577,
     },
 }
```

