```diff
diff --git a/Android.bp b/Android.bp
index b68d2dd..04074ee 100644
--- a/Android.bp
+++ b/Android.bp
@@ -82,3 +82,30 @@ cc_library_static {
         },
     },
 }
+
+// A static library to support examples/test code with CFI assembly support.
+cc_library_static {
+    name: "libwebm_mkvreader",
+    host_supported: true,
+    export_include_dirs: ["."],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    srcs: [
+        "mkvparser/mkvparser.cc",
+        "mkvparser/mkvreader.cc",
+    ],
+    sanitize: {
+        cfi: true,
+        config: {
+            cfi_assembly_support: true,
+        },
+    },
+    min_sdk_version: "29",
+    target: {
+        darwin: {
+            enabled: false,
+        },
+    },
+}
```

