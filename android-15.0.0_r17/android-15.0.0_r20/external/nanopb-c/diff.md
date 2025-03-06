```diff
diff --git a/Android.bp b/Android.bp
index 4515e03..ecc380b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -115,3 +115,9 @@ cc_library_static {
 
     cflags: ["-DPB_ENABLE_MALLOC", "-DPB_FIELD_32BIT"],
 }
+
+dirgroup {
+    name: "trusty_dirgroup_external_nanopb-c",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
```

