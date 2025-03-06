```diff
diff --git a/Android.bp b/Android.bp
index 6bfae8d..c8cbb46 100644
--- a/Android.bp
+++ b/Android.bp
@@ -14,3 +14,9 @@ license {
         "LICENSE.rst",
     ],
 }
+
+dirgroup {
+    name: "trusty_dirgroup_external_python_jinja",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

