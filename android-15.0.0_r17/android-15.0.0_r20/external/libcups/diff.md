```diff
diff --git a/Android.bp b/Android.bp
index 1bdccae0..a3852441 100644
--- a/Android.bp
+++ b/Android.bp
@@ -118,7 +118,6 @@ cc_library_shared {
         "-Wno-unused-value",
         "-Wno-sign-compare",
         "-Wno-missing-field-initializers",
-        "-Wno-implicit-function-declaration",
         "-Wno-deprecated-declarations",
         "-Werror",
     ],
diff --git a/OWNERS b/OWNERS
index 6f85dcb6..b3140efe 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 kumarashishg@google.com
 anothermark@google.com
 aprasath@google.com
+bmgordon@google.com
```

