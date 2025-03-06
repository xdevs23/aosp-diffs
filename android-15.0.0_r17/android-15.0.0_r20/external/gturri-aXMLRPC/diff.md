```diff
diff --git a/Android.bp b/Android.bp
index ac4b491..411eb59 100644
--- a/Android.bp
+++ b/Android.bp
@@ -37,7 +37,7 @@ java_library_host {
     ],
     visibility: [
         ":__subpackages__",
-        "//test/dts/libs/servo",
+        "//test/dts/libs/hostside/servo",
     ],
 }
 
```

