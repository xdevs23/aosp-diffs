```diff
diff --git a/Android.bp b/Android.bp
index 4045030..debe3f0 100644
--- a/Android.bp
+++ b/Android.bp
@@ -56,9 +56,12 @@ cc_library {
         "-Wno-implicit-fallthrough",
     ],
     stl: "libc++_static",
-    export_include_dirs: ["include", "lib"],
+    export_include_dirs: [
+        "include",
+        "lib",
+    ],
     srcs: [
-        "lib/**/*.cc"
+        "lib/**/*.cc",
     ],
     apex_available: [
         "//apex_available:platform",
diff --git a/OWNERS b/OWNERS
new file mode 100644
index 0000000..7529cb9
--- /dev/null
+++ b/OWNERS
@@ -0,0 +1 @@
+include platform/system/core:/janitors/OWNERS
```

