```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..f33a8bc
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_user_app_secretkeeper",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

