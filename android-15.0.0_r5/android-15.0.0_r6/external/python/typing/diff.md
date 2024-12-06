```diff
diff --git a/typing_extensions/Android.bp b/typing_extensions/Android.bp
index 2769575..b994c06 100644
--- a/typing_extensions/Android.bp
+++ b/typing_extensions/Android.bp
@@ -16,7 +16,7 @@ package {
 }
 
 python_library {
-    name: "typing_extensions",
+    name: "typing_extensions_legacy",
     host_supported: true,
     srcs: [
        "__init__.py",
```

