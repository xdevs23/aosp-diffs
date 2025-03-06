```diff
diff --git a/Android.bp b/Android.bp
index 8cc9ea5..ca7c1d9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -61,7 +61,6 @@ cc_library_static {
     ],
     cflags: [
         "-Wno-unused-parameter",
-        "-Wno-implicit-function-declaration",
         "-DHAVE_CONFIG_H",
     ],
     export_include_dirs: [
@@ -93,9 +92,9 @@ cc_fuzz {
     // are used.
     corpus: ["fuzzer/corpus/0*"],
     fuzzing_frameworks: {
-      afl: false,
+        afl: false,
     },
     fuzz_config: {
-        componentid: 87896
-    }
+        componentid: 87896,
+    },
 }
diff --git a/METADATA b/METADATA
index d97975c..3916b0d 100644
--- a/METADATA
+++ b/METADATA
@@ -1,3 +1,15 @@
+name: "libsrtp2"
+description: "Library for SRTP (Secure Realtime Transport Protocol)"
 third_party {
   license_type: NOTICE
+  last_upgrade_date {
+    year: 2019
+    month: 12
+    day: 11
+  }
+  identifier {
+    type: "Git"
+    value: "https://github.com/cisco/libsrtp"
+    version: "46755e2aa15b618854b1ab502b4787e584aa590d"
+  }
 }
diff --git a/OWNERS b/OWNERS
new file mode 100644
index 0000000..7529cb9
--- /dev/null
+++ b/OWNERS
@@ -0,0 +1 @@
+include platform/system/core:/janitors/OWNERS
```

