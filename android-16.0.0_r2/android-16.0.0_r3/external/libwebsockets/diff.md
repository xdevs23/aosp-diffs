```diff
diff --git a/Android.bp b/Android.bp
index 2f5ea2ba..0c562b1a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -168,7 +168,7 @@ libwebsocketsIncludePath = [
     "lib",
 ]
 
-cc_library_static {
+cc_library_host_static {
     name: "libwebsockets",
     srcs: libwebsocketsSrcFiles,
     local_include_dirs: libwebsocketsIncludePath,
@@ -176,48 +176,30 @@ cc_library_static {
     static_libs: [
         "libssl",
         "libcap",
+        "libcrypto",
+    ],
+    cflags: [
+        "-UNDEBUG",
+        "-Wall",
+        "-Wsign-compare",
+        "-Wstrict-aliasing",
+        "-Wuninitialized",
+        "-Werror",
+        "-fvisibility=hidden",
+        "-Wundef",
+        "-Wtype-limits",
+        "-Wignored-qualifiers",
+        "-Wno-deprecated-declarations",
+        "-pthread",
+        "-Wno-unused-command-line-argument",
+        "-Wno-unused-parameter",
     ],
-    host_supported: true,
-    product_variables: {
-        debuggable: {
-            cflags: [
-                "-UNDEBUG",
-            ],
-        },
-    },
     target: {
         darwin: {
             enabled: false,
         },
-        android: {
-            shared_libs: [
-                "libcrypto",
-            ],
-            cflags: [
-                "-Wno-unused-parameter",
-                "-Wno-missing-field-initializers",
-            ],
-        },
-        host: {
-            static_libs: [
-                "libcrypto",
-            ],
-            cflags: [
-                "-UNDEBUG",
-                "-Wall",
-                "-Wsign-compare",
-                "-Wstrict-aliasing",
-                "-Wuninitialized",
-                "-Werror",
-                "-fvisibility=hidden",
-                "-Wundef",
-                "-Wtype-limits",
-                "-Wignored-qualifiers",
-                "-Wno-deprecated-declarations",
-                "-pthread",
-                "-Wno-unused-command-line-argument",
-                "-Wno-unused-parameter",
-            ],
-        },
     },
+    visibility: [
+        "//device/google/cuttlefish:__subpackages__",
+    ],
 }
```

