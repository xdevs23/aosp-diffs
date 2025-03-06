```diff
diff --git a/Android.bp b/Android.bp
index 9d1518d..ac930f4 100644
--- a/Android.bp
+++ b/Android.bp
@@ -75,6 +75,7 @@ cc_defaults {
         "-DHAVE_LGETXATTR",
         "-D_FILE_OFFSET_BITS=64",
         "-DEROFS_MAX_BLOCK_SIZE=16384",
+        "-DHAVE_UTIMENSAT",
     ],
 }
 
@@ -162,7 +163,13 @@ cc_binary {
 
     defaults: ["mkfs-erofs_defaults"],
     host_supported: true,
-    recovery_available: true,
+}
+
+cc_binary {
+    name: "mkfs.erofs.recovery",
+    defaults: ["mkfs-erofs_defaults"],
+    recovery: true,
+    stem: "mkfs.erofs",
 }
 
 cc_binary_host {
@@ -172,17 +179,21 @@ cc_binary_host {
     stl: "libc++_static"
 }
 
-cc_binary {
-    name: "dump.erofs",
+cc_defaults {
+    name: "dump.erofs_defaults",
     defaults: ["erofs-utils_defaults"],
-    host_supported: true,
-    recovery_available: true,
     srcs: [
         "dump/*.c",
     ],
     static_libs: [
         "liberofs",
     ],
+}
+
+cc_binary {
+    name: "dump.erofs",
+    defaults: ["dump.erofs_defaults"],
+    host_supported: true,
     target: {
         darwin: {
             enabled: false,
@@ -191,19 +202,37 @@ cc_binary {
 }
 
 cc_binary {
-    name: "fsck.erofs",
+    name: "dump.erofs.recovery",
+    defaults: ["dump.erofs_defaults"],
+    recovery: true,
+    stem: "dump.erofs",
+}
+
+cc_defaults {
+    name: "fsck.erofs_defaults",
     defaults: ["erofs-utils_defaults"],
-    host_supported: true,
-    recovery_available: true,
     srcs: [
         "fsck/*.c",
     ],
     static_libs: [
         "liberofs",
     ],
+}
+
+cc_binary {
+    name: "fsck.erofs",
+    defaults: ["fsck.erofs_defaults"],
+    host_supported: true,
     target: {
         darwin: {
             enabled: false,
         },
     },
 }
+
+cc_binary {
+    name: "fsck.erofs.recovery",
+    defaults: ["fsck.erofs_defaults"],
+    recovery: true,
+    stem: "fsck.erofs",
+}
\ No newline at end of file
diff --git a/OWNERS b/OWNERS
index e281cd2..78e2649 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 dvander@google.com
 jaegeuk@google.com
 daehojeong@google.com
+dhavale@google.com
```

