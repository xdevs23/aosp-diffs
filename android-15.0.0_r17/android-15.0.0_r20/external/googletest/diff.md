```diff
diff --git a/Android.bp b/Android.bp
index 2e77afda..bd969b42 100644
--- a/Android.bp
+++ b/Android.bp
@@ -48,3 +48,9 @@ cc_library_host_static {
     name: "googletest_cmake",
     cmake_snapshot_supported: true,
 }
+
+dirgroup {
+    name: "trusty_dirgroup_external_googletest",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

