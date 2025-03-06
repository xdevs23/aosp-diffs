```diff
diff --git a/Android.bp b/Android.bp
index 6e5ef80..484ac91 100644
--- a/Android.bp
+++ b/Android.bp
@@ -80,6 +80,7 @@ java_library_host {
         "--add-exports jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED",
         "--add-exports jdk.compiler/com.sun.tools.javac.model=ALL-UNNAMED",
         "--add-exports jdk.compiler/com.sun.tools.javac.parser=ALL-UNNAMED",
+        "--add-exports=jdk.compiler/com.sun.tools.javac.processing=ALL-UNNAMED",
         "--add-exports jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED",
         "--add-exports jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED",
     ],
```

