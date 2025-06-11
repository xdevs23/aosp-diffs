```diff
diff --git a/KM200/Android.bp b/KM200/Android.bp
index 75684c8..b419bee 100644
--- a/KM200/Android.bp
+++ b/KM200/Android.bp
@@ -54,7 +54,6 @@ cc_library {
     cflags: [
         "-O0",
         "-DNXP_EXTNS",
-        "-Wno-enum-constexpr-conversion",
     ],
     shared_libs: [
         "android.hardware.security.secureclock-V1-ndk",
```

