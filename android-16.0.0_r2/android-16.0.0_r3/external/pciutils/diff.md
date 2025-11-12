```diff
diff --git a/Android.bp b/Android.bp
index eb6d344..1725a16 100644
--- a/Android.bp
+++ b/Android.bp
@@ -62,20 +62,22 @@ cc_genrule {
     cmd: "mkdir -p $(genDir)/pciutils && cp $(in) $(genDir)/pciutils/",
 }
 
+pciutils_cflags = [
+    "-O2",
+    "-Wall",
+    "-W",
+    "-Wno-parentheses",
+    "-Wstrict-prototypes",
+    "-Wmissing-prototypes",
+]
+
 cc_library_static {
     name: "libpci",
     host_supported: true,
     vendor_available: true,
     visibility: ["//external/flashrom"],
 
-    cflags: [
-        "-O2",
-        "-Wall",
-        "-W",
-        "-Wno-parentheses",
-        "-Wstrict-prototypes",
-        "-Wmissing-prototypes",
-    ],
+    cflags: pciutils_cflags,
 
     srcs: [
         "lib/init.c",
@@ -119,3 +121,26 @@ cc_library_static {
         "libz",
     ],
 }
+
+cc_binary {
+    name: "lspci_pciutils",
+    vendor: true,
+
+    cflags: pciutils_cflags,
+
+    srcs: [
+        "ls*.c",
+        "common.c",
+    ],
+
+    static_libs: [
+        "libkmod",
+        "libpci",
+        "libz",
+    ],
+
+    generated_headers: [
+        "libpci_config",
+        "libpci_includes",
+    ],
+}
```

