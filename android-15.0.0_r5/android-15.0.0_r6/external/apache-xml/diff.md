```diff
diff --git a/Android.bp b/Android.bp
index 09bfe28..84739c5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -59,6 +59,8 @@ java_library {
     visibility: [
         "//art/build/apex",
         "//art/build/sdk",
+        "//art/tools/ahat",
+        "//art/tools/fuzzer",
         "//libcore",
         "//packages/modules/ArtPrebuilt",
     ],
```

