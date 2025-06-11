```diff
diff --git a/Android.bp b/Android.bp
index dbf2886..c1894e9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -58,7 +58,10 @@ cc_binary {
 
     shared_libs: ["libext2_uuid"],
     static_libs: ["libgptf"],
-    visibility: ["//visibility:any_system_partition"],
+    visibility: [
+        "//build/make/tools/otatools_package",
+        "//visibility:any_system_partition",
+    ],
 }
 
 lib_common_srcs = [
diff --git a/OWNERS b/OWNERS
index 552c47c..fad822e 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/system/vold:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

