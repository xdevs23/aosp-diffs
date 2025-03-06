```diff
diff --git a/Android.bp b/Android.bp
index 9dad71555..3bf543148 100644
--- a/Android.bp
+++ b/Android.bp
@@ -8571,7 +8571,6 @@ cc_defaults {
         "-Wno-unused-parameter",
         "-Wno-missing-field-initializers",
         "-Wno-pointer-arith",
-        "-Wno-implicit-function-declaration",
         "-Wno-ignored-qualifiers",
     ],
     stl: "libc++_static",
```

