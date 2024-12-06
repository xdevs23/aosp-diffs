```diff
diff --git a/Android.bp b/Android.bp
index 52130d8..9741ae2 100644
--- a/Android.bp
+++ b/Android.bp
@@ -86,7 +86,7 @@ cc_library {
         // Exception: composd calls PaletteCreateOdrefreshStagingDirectory, but
         // that function doesn't depend on any unstable internal APIs (only libc
         // and libselinux).
-        "//packages/modules/Virtualization/compos/composd/native",
+        "//packages/modules/Virtualization/android/composd/native",
 
         // Microdroid needs this library to be able to run odrefresh and dex2oat
         // in the pVM, but it doesn't make any calls to it itself.
```

