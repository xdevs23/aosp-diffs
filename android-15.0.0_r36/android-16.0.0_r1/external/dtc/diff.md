```diff
diff --git a/OWNERS b/OWNERS
index 62b9704..abf779f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,3 +3,4 @@ ptosi@google.com
 # Default code reviewers picked from top 3 or more developers.
 szuweilin@google.com
 bowgotsai@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/libfdt/Android.bp b/libfdt/Android.bp
index 32b3b39..7bfb055 100644
--- a/libfdt/Android.bp
+++ b/libfdt/Android.bp
@@ -21,6 +21,11 @@ cc_defaults {
         "acpi.c",
     ],
     export_include_dirs: ["."],
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
 
 cc_library {
@@ -39,9 +44,4 @@ cc_library {
         "cc_baremetal_defaults",
         "libfdt_defaults",
     ],
-    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
-    // until cross-language lto is supported.
-    lto: {
-        never: true,
-    },
 }
```

