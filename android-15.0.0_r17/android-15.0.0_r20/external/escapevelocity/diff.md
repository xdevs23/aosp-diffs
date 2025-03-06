```diff
diff --git a/Android.bp b/Android.bp
index 15d5993..2e13f62 100644
--- a/Android.bp
+++ b/Android.bp
@@ -21,8 +21,9 @@ license {
     ],
 }
 
-java_library_host {
+java_library {
     name: "escapevelocity",
     srcs: ["src/main/**/*.java"],
     libs: ["guava"],
+    host_supported: true,
 }
```

