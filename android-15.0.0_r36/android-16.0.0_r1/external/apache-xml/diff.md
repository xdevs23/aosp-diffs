```diff
diff --git a/Android.bp b/Android.bp
index 84739c5..71dde7e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -70,6 +70,7 @@ java_library {
     ],
     srcs: ["src/main/java/**/*.java"],
     java_resource_dirs: ["src/main/java"],
+    exclude_java_resources: ["src/main/java/**/*.src"],
 
     installable: true,
     hostdex: true,
@@ -83,6 +84,15 @@ java_library {
         warning_checks: ["SuspiciousIndentation"],
     },
 
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
     min_sdk_version: "31",
diff --git a/OWNERS b/OWNERS
index 87a5dbe..41bd4fe 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/libcore:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

