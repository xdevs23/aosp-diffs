```diff
diff --git a/Android.bp b/Android.bp
index 04d3e4edb..f8dc7c452 100644
--- a/Android.bp
+++ b/Android.bp
@@ -49,6 +49,7 @@ java_library {
     errorprone: {
         javacflags: [
             "-Xep:ReturnValueIgnored:WARN",
+            "-Xep:BoxedPrimitiveEquality:WARN",
         ],
     },
 }
```

