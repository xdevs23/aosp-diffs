```diff
diff --git a/Android.bp b/Android.bp
index 162c230b6..142865a06 100644
--- a/Android.bp
+++ b/Android.bp
@@ -278,3 +278,8 @@ filegroup {
     ],
 }
 
+dirgroup {
+    name: "trusty_dirgroup_external_freetype",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

