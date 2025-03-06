```diff
diff --git a/contrib/android/Android.bp b/contrib/android/Android.bp
index d38e0626..7032a2a0 100644
--- a/contrib/android/Android.bp
+++ b/contrib/android/Android.bp
@@ -12,11 +12,8 @@ package {
     default_applicable_licenses: ["external_e2fsprogs_license"],
 }
 
-cc_binary {
-    name: "e2fsdroid",
-    host_supported: true,
-    recovery_available: true,
-    vendor_available: true,
+cc_defaults {
+    name: "e2fsdroid_defaults",
     defaults: ["e2fsprogs-defaults"],
 
     srcs: [
@@ -61,6 +58,24 @@ cc_binary {
     },
 }
 
+cc_binary {
+    name: "e2fsdroid",
+    defaults: [
+        "e2fsdroid_defaults",
+    ],
+    host_supported: true,
+    vendor_available: true,
+}
+
+cc_binary {
+    name: "e2fsdroid.recovery",
+    defaults: [
+        "e2fsdroid_defaults",
+    ],
+    recovery: true,
+    stem: "e2fsdroid",
+}
+
 //##########################################################################
 // Build ext2simg
 
diff --git a/misc/Android.bp b/misc/Android.bp
index c89d1212..8b84058c 100644
--- a/misc/Android.bp
+++ b/misc/Android.bp
@@ -43,7 +43,6 @@ cc_library {
 
 cc_defaults {
     name: "mke2fs_defaults",
-    recovery_available: true,
     defaults: ["e2fsprogs-defaults"],
 
     srcs: [
@@ -56,11 +55,37 @@ cc_defaults {
     include_dirs: ["external/e2fsprogs/e2fsck"],
 }
 
+cc_defaults {
+    name: "mke2fs_device_defaults",
+    defaults: ["mke2fs_defaults"],
+    target: {
+        android: {
+            required: [
+                "mke2fs.conf",
+            ],
+            shared_libs: [
+                "libext2fs",
+                "libext2_blkid",
+                "libext2_misc",
+                "libext2_uuid",
+                "libext2_quota",
+                "libext2_com_err",
+                "libext2_e2p",
+            ],
+            symlinks: [
+                "mkfs.ext2",
+                "mkfs.ext3",
+                "mkfs.ext4",
+            ],
+        },
+    },
+}
+
 cc_binary {
     name: "mke2fs",
     host_supported: true,
     vendor_available: true,
-    defaults: ["mke2fs_defaults"],
+    defaults: ["mke2fs_device_defaults"],
     target: {
         host: {
             static_libs: [
@@ -85,31 +110,20 @@ cc_binary {
             ldflags: ["-static"],
             enabled: true,
         },
-        android: {
-            required: [
-                "mke2fs.conf",
-            ],
-            shared_libs: [
-                "libext2fs",
-                "libext2_blkid",
-                "libext2_misc",
-                "libext2_uuid",
-                "libext2_quota",
-                "libext2_com_err",
-                "libext2_e2p",
-            ],
-            symlinks: [
-                "mkfs.ext2",
-                "mkfs.ext3",
-                "mkfs.ext4",
-            ],
-        },
     },
 }
 
+cc_binary {
+    name: "mke2fs.recovery",
+    defaults: ["mke2fs_device_defaults"],
+    recovery: true,
+    stem: "mke2fs",
+}
+
 cc_binary {
     name: "mke2fs.microdroid",
     defaults: ["mke2fs_defaults"],
+    recovery_available: true,
     bootstrap: true,
     target: {
         android: {
```

