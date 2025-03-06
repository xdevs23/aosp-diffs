```diff
diff --git a/Android.bp b/Android.bp
index ab54390..689f35a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -18,6 +18,8 @@ cc_library_host_static {
     srcs: [
         "lib/*.c"
     ],
+    // Upstream explicitly chooses C99.
+    c_std: "gnu99",
     cflags: [
         "-Wno-unused-parameter",
         "-DHAVE_USELOCALE",
```

