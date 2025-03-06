```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..01d82b3
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_external_trusty_headers",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

