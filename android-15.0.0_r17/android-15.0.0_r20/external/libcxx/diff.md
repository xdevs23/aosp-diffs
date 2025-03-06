```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 000000000..ca94140e6
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,16 @@
+filegroup {
+    name: "trusty_filegroup_external_libcxx",
+    srcs: ["LICENSE.TXT"],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
+
+dirgroup {
+    name: "trusty_dirgroup_external_libcxx",
+    dirs: [
+        "include",
+        "lib",
+        "src",
+        "utils",
+    ],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

