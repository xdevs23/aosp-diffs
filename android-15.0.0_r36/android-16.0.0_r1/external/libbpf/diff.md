```diff
diff --git a/Android.bp b/Android.bp
index c538d71..46954cf 100644
--- a/Android.bp
+++ b/Android.bp
@@ -88,10 +88,6 @@ cc_library {
         "-Wno-unused-parameter",
         "-Wno-user-defined-warnings",
     ],
-    static_libs: [
-        "libelf",
-        "libz",
-    ],
     visibility: [
         "//external/bpftool",
         "//external/bcc/libbpf-tools",
@@ -100,10 +96,30 @@ cc_library {
         "//external/rust/android-crates-io/crates/libbpf-sys",
         "//external/stg",
         "//hardware/interfaces/health/utils/libhealthloop", // For use in tests only.
+        // Because libbpf depends on the GPL-licensed libelf, its use should be restricted to the
+        // standalone bpf loader binary. This visibility must not be widened.
+        "//packages/modules/Connectivity/bpf/loader",
     ],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.tethering",
+    ],
+    min_sdk_version: "apex_inherit",
     target: {
+        android: {
+            static_libs: [
+                "libelf",
+            ],
+            shared_libs: [
+                "libz",
+            ],
+        },
         host: {
             compile_multilib: "64",
+            static_libs: [
+                "libelf",
+                "libz",
+            ],
         },
     },
 }
diff --git a/OWNERS b/OWNERS
index fba0a5c..3b45524 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,3 +3,4 @@ file:platform/system/bpf:main:/OWNERS_bpf
 
 maennich@google.com
 gprocida@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

