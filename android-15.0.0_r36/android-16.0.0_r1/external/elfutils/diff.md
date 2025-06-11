```diff
diff --git a/Android.bp b/Android.bp
index 7d0771e3..dd5aaf37 100644
--- a/Android.bp
+++ b/Android.bp
@@ -44,10 +44,22 @@ license {
 // and this have to be included explicitly by elfutils users.
 cc_defaults {
     name: "elfutils_transitive_defaults",
-    static_libs: [
-        "libz",
-        "libzstd",
-    ],
+    target: {
+        android: {
+            static_libs: [
+                "libzstd",
+            ],
+            shared_libs: [
+                "libz",
+            ],
+        },
+        host: {
+            static_libs: [
+                "libz",
+                "libzstd",
+            ],
+        },
+    },
 }
 
 cc_defaults {
@@ -117,6 +129,11 @@ cc_library {
         "//external/igt-gpu-tools",
         "//external/mesa3d",
     ],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.tethering", // For standalone bpf loader binary that depends on libbpf.
+    ],
+    min_sdk_version: "apex_inherit",
 }
 
 cc_library_headers {
@@ -138,6 +155,11 @@ cc_library_headers {
         },
     },
     visibility: [":__subpackages__"],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.tethering", // For standalone bpf loader binary that depends on libbpf.
+    ],
+    min_sdk_version: "apex_inherit",
 }
 
 cc_library {
diff --git a/OWNERS b/OWNERS
index 80b73257..f5225a06 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 maennich@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

