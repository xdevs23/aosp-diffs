```diff
diff --git a/Android.bp b/Android.bp
index be86538..2558c68 100644
--- a/Android.bp
+++ b/Android.bp
@@ -122,6 +122,15 @@ java_library {
     hostdex: true,
     installable: true,
 
+    optimize: {
+        enabled: true,
+        shrink: false,
+        optimize: false,
+        obfuscate: false,
+        proguard_compatibility: false,
+        ignore_warnings: false,
+    },
+
     sdk_version: "none",
     system_modules: "core-all-system-modules",
     libs: [
diff --git a/OWNERS b/OWNERS
index dc99a81..8a472fd 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 # Bug component: 24949
 ngeoffray@google.com
 include platform/libcore:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

