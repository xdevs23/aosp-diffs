```diff
diff --git a/Android.bp b/Android.bp
index ecc380b..7522edb 100644
--- a/Android.bp
+++ b/Android.bp
@@ -76,7 +76,7 @@ cc_library_static {
     defaults: ["libprotobuf-c-nano-defaults"],
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
     ],
     min_sdk_version: "30",
 }
@@ -99,7 +99,10 @@ cc_library_static {
     name: "libprotobuf-c-nano-enable_malloc-16bit",
     defaults: ["libprotobuf-c-nano-defaults"],
 
-    cflags: ["-DPB_ENABLE_MALLOC", "-DPB_FIELD_16BIT"],
+    cflags: [
+        "-DPB_ENABLE_MALLOC",
+        "-DPB_FIELD_16BIT",
+    ],
 }
 
 cc_library_static {
@@ -113,7 +116,10 @@ cc_library_static {
     name: "libprotobuf-c-nano-enable_malloc-32bit",
     defaults: ["libprotobuf-c-nano-defaults"],
 
-    cflags: ["-DPB_ENABLE_MALLOC", "-DPB_FIELD_32BIT"],
+    cflags: [
+        "-DPB_ENABLE_MALLOC",
+        "-DPB_FIELD_32BIT",
+    ],
 }
 
 dirgroup {
diff --git a/OWNERS b/OWNERS
index bf734b3..516734d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 shanyu@google.com
 rtenneti@google.com
 krzysio@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

