```diff
diff --git a/Android.bp b/Android.bp
index 6d59c063cb..fd36b23e70 100644
--- a/Android.bp
+++ b/Android.bp
@@ -77,6 +77,7 @@ cc_defaults {
         "-Wno-null-pointer-arithmetic",
         "-Wno-register",
         "-Wno-shift-count-overflow",
+        "-Wno-single-bit-bitfield-constant-conversion",
         "-Wno-sign-compare",
         "-Wno-strict-prototypes",
         "-Wno-tautological-compare",
```

