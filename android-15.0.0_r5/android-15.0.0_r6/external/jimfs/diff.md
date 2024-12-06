```diff
diff --git a/jimfs/Android.bp b/jimfs/Android.bp
index afa7cd6..8e1d4d7 100644
--- a/jimfs/Android.bp
+++ b/jimfs/Android.bp
@@ -37,6 +37,11 @@ java_library_host {
     plugins: [
         "auto_service_plugin",
     ],
+    errorprone: {
+        javacflags: [
+            "-Xep:LenientFormatStringValidation:WARN",
+        ],
+    },
 }
 
 java_genrule_host {
@@ -48,8 +53,8 @@ java_genrule_host {
         "soong_zip",
     ],
     cmd: "$(location gen_annotations.py) $(genDir)/java && " +
-         "$(location soong_zip) -jar -o $(out) -C $(genDir)/java -D $(genDir)/java",
+        "$(location soong_zip) -jar -o $(out) -C $(genDir)/java -D $(genDir)/java",
     out: [
-        "jimfs-annotation-stubs.srcjar"
+        "jimfs-annotation-stubs.srcjar",
     ],
 }
```

