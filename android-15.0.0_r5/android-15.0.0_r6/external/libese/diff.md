```diff
diff --git a/libese-hw/nxp/Android.bp b/libese-hw/nxp/Android.bp
index 6ff143e..34e1756 100644
--- a/libese-hw/nxp/Android.bp
+++ b/libese-hw/nxp/Android.bp
@@ -40,6 +40,7 @@ cc_library {
         "-Werror",
         "-Wno-error=unused-variable",
         "-Wno-format",
+        "-Wno-single-bit-bitfield-constant-conversion",
     ],
     target: {
         darwin: {
@@ -72,6 +73,7 @@ cc_library {
     srcs: ["pn80t/linux_spidev.c"],
     cflags: [
         "-Wno-format",
+        "-Wno-single-bit-bitfield-constant-conversion",
     ],
     export_include_dirs: ["include"],
 }
@@ -85,6 +87,7 @@ cc_library {
         "-Werror",
         "-Wno-error=unused-variable",
         "-Wno-format",
+        "-Wno-single-bit-bitfield-constant-conversion",
     ],
     export_include_dirs: ["include"],
 }
diff --git a/libese-teq1/Android.bp b/libese-teq1/Android.bp
index 1bb2e6b..ce318dc 100644
--- a/libese-teq1/Android.bp
+++ b/libese-teq1/Android.bp
@@ -28,7 +28,7 @@ cc_library {
     defaults: ["libese-api-defaults"],
     host_supported: true,
     srcs: ["teq1.c"],
-    cflags: ["-Wall", "-Werror"],
+    cflags: ["-Wall", "-Wno-single-bit-bitfield-constant-conversion", "-Werror"],
     shared_libs: ["liblog", "libese", "libese-sysdeps"],
     export_include_dirs: ["include"],
 }
@@ -40,7 +40,7 @@ cc_library {
     host_supported: true,
 
     srcs: ["teq1.c"],
-    cflags: ["-Wall", "-Werror"],
+    cflags: ["-Wall", "-Wno-single-bit-bitfield-constant-conversion", "-Werror"],
 
     // Ensure that only explicitly exported symbols are visible.
     shared_libs: ["liblog", "libese", "libese-sysdeps"],
diff --git a/libese-teq1/tests/Android.bp b/libese-teq1/tests/Android.bp
index 7ca30ae..a7167f5 100644
--- a/libese-teq1/tests/Android.bp
+++ b/libese-teq1/tests/Android.bp
@@ -27,7 +27,7 @@ cc_test {
     name: "ese_teq1_unittests",
     proprietary: true,
     srcs: ["teq1_unittests.cpp", "ese_operations_wrapper.cpp" ],
-    cflags: ["-Wall", "-Werror"],
+    cflags: ["-Wall", "-Wno-single-bit-bitfield-constant-conversion", "-Werror"],
     host_supported: true,
     shared_libs: [
         "libese",
diff --git a/ready_se/google/keymint/KM200/Applet/src/com/android/javacard/keymaster/KMKeymintDataStore.java b/ready_se/google/keymint/KM200/Applet/src/com/android/javacard/keymaster/KMKeymintDataStore.java
index efd7ae5..e9a704b 100644
--- a/ready_se/google/keymint/KM200/Applet/src/com/android/javacard/keymaster/KMKeymintDataStore.java
+++ b/ready_se/google/keymint/KM200/Applet/src/com/android/javacard/keymaster/KMKeymintDataStore.java
@@ -547,6 +547,8 @@ public class KMKeymintDataStore implements KMUpgradable {
     }
     if (preSharedKey == null) {
       preSharedKey = seProvider.createPreSharedKey(preSharedKey, keyData, offset, length);
+    } else {
+      seProvider.createPreSharedKey(preSharedKey, keyData, offset, length);
     }
   }
 
diff --git a/ready_se/google/keymint/KM300/HAL/JavacardKeyMintOperation.cpp b/ready_se/google/keymint/KM300/HAL/JavacardKeyMintOperation.cpp
index a46f066..02dc2f0 100644
--- a/ready_se/google/keymint/KM300/HAL/JavacardKeyMintOperation.cpp
+++ b/ready_se/google/keymint/KM300/HAL/JavacardKeyMintOperation.cpp
@@ -217,9 +217,6 @@ keymaster_error_t JavacardKeyMintOperation::updateInChunks(DataView& view,
         if (sendError != KM_ERROR_OK) {
             return sendError;
         }
-        // Clear tokens
-        if (!authToken.mac.empty()) authToken = HardwareAuthToken();
-        if (!timestampToken.mac.empty()) timestampToken = TimeStampToken();
     }
     return KM_ERROR_OK;
 }
```

