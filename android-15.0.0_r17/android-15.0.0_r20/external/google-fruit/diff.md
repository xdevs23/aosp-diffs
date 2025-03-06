```diff
diff --git a/Android.bp b/Android.bp
index 444c19c..f68b771 100644
--- a/Android.bp
+++ b/Android.bp
@@ -41,8 +41,11 @@ cc_library {
     name: "libfruit",
     host_supported: true,
     vendor_available: true,
-    export_include_dirs: ["include", "configuration/android"],
-    srcs: ["src/**/*.cpp", ],
+    export_include_dirs: [
+        "include",
+        "configuration/android",
+    ],
+    srcs: ["src/**/*.cpp"],
     apex_available: [
         "//apex_available:platform",
         "//apex_available:anyapex",
@@ -52,15 +55,15 @@ cc_library {
 // TODO: tests written in python+pytest that calls back into compiler. unclear how to best proceed.
 
 cc_defaults {
-  name: "libfruit-example-defaults",
-  host_supported: true,
-  gtest: false,
-  shared_libs: ["libfruit"],
-  cflags: ["-Wno-non-virtual-dtor"],
+    name: "libfruit-example-defaults",
+    host_supported: true,
+    gtest: false,
+    shared_libs: ["libfruit"],
+    cflags: ["-Wno-non-virtual-dtor"],
 }
 
 cc_test {
-  defaults: ["libfruit-example-defaults"],
-  name: "libfruit-example-hello-world",
-  srcs: ["examples/hello_world/**/*.cpp"],
+    defaults: ["libfruit-example-defaults"],
+    name: "libfruit-example-hello-world",
+    srcs: ["examples/hello_world/**/*.cpp"],
 }
```

