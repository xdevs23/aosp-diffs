```diff
diff --git a/Android.bp b/Android.bp
index 7c301ce..5ecbe35 100644
--- a/Android.bp
+++ b/Android.bp
@@ -27,7 +27,7 @@ python_library {
     ],
     data: [
         ":vndk_lib_lists",
-        ":vndk_lib_extra_lists"
+        ":vndk_lib_extra_lists",
     ],
 }
 
@@ -37,11 +37,6 @@ python_defaults {
         "vndk_utils",
         "vts_vndk_utils",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        }
-    }
 }
 
 // TODO(b/243602514): Python data should not be put in testcases dir.
diff --git a/golden/Android.bp b/golden/Android.bp
index 232cb0c..1b779ed 100644
--- a/golden/Android.bp
+++ b/golden/Android.bp
@@ -20,11 +20,6 @@ python_binary_host {
     name: "extract_lsdump",
     main: "extract_lsdump.py",
     srcs: ["extract_lsdump.py"],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    }
 }
 
 // TODO(b/150663999): Replace with gensrcs when the build system is able to
```

