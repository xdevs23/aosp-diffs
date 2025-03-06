```diff
diff --git a/Android.bp b/Android.bp
index fd63546..3fd466b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -22,3 +22,9 @@ python_library {
         "six.py",
     ],
 }
+
+dirgroup {
+    name: "trusty_dirgroup_external_python_six",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

