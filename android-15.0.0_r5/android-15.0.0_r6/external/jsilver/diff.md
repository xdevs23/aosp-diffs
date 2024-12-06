```diff
diff --git a/Android.bp b/Android.bp
index ee82683..7580e28 100644
--- a/Android.bp
+++ b/Android.bp
@@ -38,6 +38,7 @@ java_library_host {
     errorprone: {
         javacflags: [
             "-Xep:PreconditionsInvalidPlaceholder:WARN",
+            "-Xep:LenientFormatStringValidation:WARN",
         ],
     },
 }
```

