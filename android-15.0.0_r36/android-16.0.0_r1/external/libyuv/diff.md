```diff
diff --git a/Android.bp b/Android.bp
index 506184e0..e93b4b1e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -94,6 +94,11 @@ cc_library {
         "com.android.virt",
     ],
     min_sdk_version: "29",
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
 
 // compatibilty static library until all uses of libyuv_static are replaced
diff --git a/OWNERS b/OWNERS
index f11a7bfd..5c40170c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -9,3 +9,4 @@ per-file .gitignore=*
 per-file AUTHORS=*
 per-file DEPS=*
 per-file PRESUBMIT.py=mbonadei@chromium.org,jansson@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

