```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..8e29600
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_user_app_confirmationui",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

