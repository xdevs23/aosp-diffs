```diff
diff --git a/OWNERS b/OWNERS
index 40e8d5aa..e406e847 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 tytso@google.com
 dvander@google.com
 ebiggers@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/e2fsck/Android.bp b/e2fsck/Android.bp
index 3662152c..4bb94668 100644
--- a/e2fsck/Android.bp
+++ b/e2fsck/Android.bp
@@ -69,6 +69,20 @@ cc_binary {
     bootstrap: true,
 }
 
+cc_binary {
+    name: "e2fsck.microdroid",
+    defaults: ["e2fsck-defaults"],
+    target: {
+        android: {
+            required: ["badblocks"],
+            shared_libs: e2fsck_libs,
+        },
+    },
+    no_full_install: true,
+    stem: "e2fsck",
+    visibility: ["//packages/modules/Virtualization/build/microdroid"],
+}
+
 cc_binary {
     name: "e2fsck_static",
     static_executable: true,
diff --git a/misc/Android.bp b/misc/Android.bp
index 8b84058c..48876511 100644
--- a/misc/Android.bp
+++ b/misc/Android.bp
@@ -88,6 +88,12 @@ cc_binary {
     defaults: ["mke2fs_device_defaults"],
     target: {
         host: {
+            dist: {
+                targets: [
+                    "dist_files",
+                    "sdk",
+                ],
+            },
             static_libs: [
                 "libext2_blkid",
                 "libext2_misc",
diff --git a/resize/Android.bp b/resize/Android.bp
index ea6cf1e4..947874dc 100644
--- a/resize/Android.bp
+++ b/resize/Android.bp
@@ -48,6 +48,19 @@ cc_binary {
     },
 }
 
+cc_binary {
+    name: "resize2fs.microdroid",
+    defaults: ["resize2fs-defaults"],
+    target: {
+        android: {
+            shared_libs: resize2fs_libs,
+        },
+    },
+    no_full_install: true,
+    stem: "resize2fs",
+    visibility: ["//packages/modules/Virtualization/build/microdroid"],
+}
+
 cc_binary {
     name: "resize2fs_ramdisk",
     stem: "resize2fs",
```

