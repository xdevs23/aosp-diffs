```diff
diff --git a/libfdt/Android.bp b/libfdt/Android.bp
index 0bf631a..c30bfa5 100644
--- a/libfdt/Android.bp
+++ b/libfdt/Android.bp
@@ -26,4 +26,10 @@ cc_library {
         "//apex_available:platform",
         "com.android.virt",
     ],
+
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
```

