```diff
diff --git a/Android.bp b/Android.bp
index c38ede4..9c87f87 100644
--- a/Android.bp
+++ b/Android.bp
@@ -68,11 +68,12 @@ cc_defaults {
         "-DDEBUG=YES",
         "-DUSE_DEBUG_RNG=NO",
         "-DALG_CAMELLIA=ALG_NO",
-        "-Wno-logical-op-parentheses",
+        "-Wno-cast-function-type-mismatch",
         "-Wno-empty-body",
+        "-Wno-logical-op-parentheses",
         "-Wno-missing-field-initializers",
-        "-Wno-unused-parameter",
         "-Wno-typedef-redefinition",
+        "-Wno-unused-parameter",
     ],
     target: {
         darwin: {
diff --git a/OWNERS b/OWNERS
index a65e9bf..aa3057e 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 schuffelen@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

