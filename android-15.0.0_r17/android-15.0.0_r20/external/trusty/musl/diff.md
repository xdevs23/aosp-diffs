```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 00000000..5d7fb026
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_external_trusty_musl",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

