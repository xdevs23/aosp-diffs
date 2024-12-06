```diff
diff --git a/Android.bp b/Android.bp
index 7eb6183..718450c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -33,16 +33,6 @@ cc_defaults {
     name: "mcld-defaults",
     defaults: ["llvm-defaults"],
 
-    cppflags: [
-        "-Wall",
-        "-Wno-unused",
-        "-Werror",
-
-        //To enable asserts:
-        //"-D_DEBUG",
-        //"-UNDEBUG",
-    ],
-
     target: {
         arm_on_x86: {
             cflags: [
```

