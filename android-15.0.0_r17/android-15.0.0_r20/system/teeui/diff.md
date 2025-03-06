```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..ef4505f
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_system_teeui",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/tools/framebufferizer/Android.bp b/tools/framebufferizer/Android.bp
index 489f4ce..5d08687 100644
--- a/tools/framebufferizer/Android.bp
+++ b/tools/framebufferizer/Android.bp
@@ -13,7 +13,7 @@ java_binary_host {
         "json-prebuilt",
         "gson",
     ],
-    required: [
+    jni_libs: [
         "libteeui_jni",
     ]
 }
```

