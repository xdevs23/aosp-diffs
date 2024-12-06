```diff
diff --git a/Android.bp b/Android.bp
index 00a3134..f6e3870 100644
--- a/Android.bp
+++ b/Android.bp
@@ -27,5 +27,6 @@ cc_library_host_static {
     ],
     visibility: [
         "//external/elfutils:__subpackages__",
+        "//external/dwarves:__subpackages__",
     ],
 }
```

