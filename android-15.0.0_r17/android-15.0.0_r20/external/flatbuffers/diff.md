```diff
diff --git a/Android.bp b/Android.bp
index d857b801..5f63853a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -141,22 +141,22 @@ cc_defaults {
     ],
     shared_libs: [
         "liblog",
-        "libflatbuffers-cpp"
+        "libflatbuffers-cpp",
     ],
     local_include_dirs: [
         "tests",
         "tests/fuzzer",
     ],
     fuzz_config: {
-        componentid: 87896
-    }
+        componentid: 87896,
+    },
 }
 
 cc_fuzz {
     name: "flatbuffers_parser_fuzzer",
     defaults: ["flatbuffers_fuzzer_defaults"],
     srcs: [
-        "tests/fuzzer/flatbuffers_parser_fuzzer.cc"
+        "tests/fuzzer/flatbuffers_parser_fuzzer.cc",
     ],
 }
 
@@ -164,7 +164,7 @@ cc_fuzz {
     name: "flatbuffers_scalar_fuzzer",
     defaults: ["flatbuffers_fuzzer_defaults"],
     srcs: [
-        "tests/fuzzer/flatbuffers_scalar_fuzzer.cc"
+        "tests/fuzzer/flatbuffers_scalar_fuzzer.cc",
     ],
 }
 
@@ -172,6 +172,6 @@ cc_fuzz {
     name: "flatbuffers_verifier_fuzzer",
     defaults: ["flatbuffers_fuzzer_defaults"],
     srcs: [
-        "tests/fuzzer/flatbuffers_verifier_fuzzer.cc"
+        "tests/fuzzer/flatbuffers_verifier_fuzzer.cc",
     ],
 }
```

