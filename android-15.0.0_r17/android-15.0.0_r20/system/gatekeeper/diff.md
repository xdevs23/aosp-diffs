```diff
diff --git a/Android.bp b/Android.bp
index 6f95e18..23b2015 100644
--- a/Android.bp
+++ b/Android.bp
@@ -56,3 +56,9 @@ cc_library_static {
         "include",
     ],
 }
+
+dirgroup {
+    name: "trusty_dirgroup_system_gatekeeper",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

