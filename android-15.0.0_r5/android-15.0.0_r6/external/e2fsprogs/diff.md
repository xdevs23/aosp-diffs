```diff
diff --git a/e2fsck/Android.bp b/e2fsck/Android.bp
index b42de9d7..3662152c 100644
--- a/e2fsck/Android.bp
+++ b/e2fsck/Android.bp
@@ -66,6 +66,7 @@ cc_binary {
 
     shared_libs: e2fsck_libs,
     required: ["badblocks"],
+    bootstrap: true,
 }
 
 cc_binary {
diff --git a/misc/Android.bp b/misc/Android.bp
index 4edac23e..c89d1212 100644
--- a/misc/Android.bp
+++ b/misc/Android.bp
@@ -130,7 +130,7 @@ cc_binary {
     },
     no_full_install: true,
     stem: "mke2fs",
-    visibility: ["//packages/modules/Virtualization/microdroid"],
+    visibility: ["//packages/modules/Virtualization/build/microdroid"],
 }
 
 //##########################################################################
```

