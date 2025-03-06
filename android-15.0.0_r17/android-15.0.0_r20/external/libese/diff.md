```diff
diff --git a/ready_se/google/keymint/KM200/HAL/Android.bp b/ready_se/google/keymint/KM200/HAL/Android.bp
index 11a32f9..a6bacb1 100644
--- a/ready_se/google/keymint/KM200/HAL/Android.bp
+++ b/ready_se/google/keymint/KM200/HAL/Android.bp
@@ -36,7 +36,6 @@ cc_library {
     name: "libjc_keymint",
     defaults: [
         "keymaster_defaults",
-        "keymint_use_latest_hal_aidl_ndk_shared",
     ],
     srcs: [
         "CborConverter.cpp",
@@ -49,10 +48,11 @@ cc_library {
     ],
     cflags: ["-O0"],
     shared_libs: [
+        "android.hardware.security.keymint-V2-ndk",
         "android.hardware.security.secureclock-V1-ndk",
         "android.hardware.security.sharedsecret-V1-ndk",
         "android.hardware.security.rkp-V3-ndk",
-        "lib_android_keymaster_keymint_utils",
+        "lib_android_keymaster_keymint_utils_V2",
         "libbase",
         "libcppbor",
         "libkeymaster_portable",
@@ -73,9 +73,27 @@ cc_library {
 cc_library {
     name: "libjc_keymint_transport",
     vendor_available: true,
-    defaults: [
-        "keymint_use_latest_hal_aidl_ndk_shared",
+    srcs: [
+        "SocketTransport.cpp",
+        "OmapiTransport.cpp",
     ],
+    export_include_dirs: [
+        ".",
+    ],
+    shared_libs: [
+        "android.hardware.security.keymint-V2-ndk",
+        "libbinder",
+        "libbase",
+        "liblog",
+        "libbinder_ndk",
+        "android.se.omapi-V1-ndk",
+        "libhardware",
+    ],
+}
+
+cc_library {
+    name: "libjc_keymint_transport_V3",
+    vendor_available: true,
     srcs: [
         "SocketTransport.cpp",
         "OmapiTransport.cpp",
@@ -84,6 +102,7 @@ cc_library {
         ".",
     ],
     shared_libs: [
+        "android.hardware.security.keymint-V3-ndk",
         "libbinder",
         "libbase",
         "liblog",
@@ -106,12 +125,10 @@ cc_binary {
         "-Wall",
         "-Wextra",
     ],
-    defaults: [
-        "keymint_use_latest_hal_aidl_ndk_shared",
-    ],
     shared_libs: [
+        "android.hardware.security.keymint-V2-ndk",
         "android.hardware.security.sharedsecret-V1-ndk",
-        "lib_android_keymaster_keymint_utils",
+        "lib_android_keymaster_keymint_utils_V2",
         "android.hardware.security.rkp-V3-ndk",
         "libbase",
         "libbinder_ndk",
diff --git a/ready_se/google/keymint/KM300/HAL/Android.bp b/ready_se/google/keymint/KM300/HAL/Android.bp
index 732ad1b..c514c6e 100644
--- a/ready_se/google/keymint/KM300/HAL/Android.bp
+++ b/ready_se/google/keymint/KM300/HAL/Android.bp
@@ -36,7 +36,6 @@ cc_library {
     name: "libjc_keymint3",
     defaults: [
         "keymaster_defaults",
-        "keymint_use_latest_hal_aidl_ndk_shared",
     ],
     srcs: [
         "CborConverter.cpp",
@@ -49,10 +48,11 @@ cc_library {
     ],
     cflags: ["-O0"],
     shared_libs: [
+        "android.hardware.security.keymint-V3-ndk",
         "android.hardware.security.secureclock-V1-ndk",
         "android.hardware.security.sharedsecret-V1-ndk",
         "android.hardware.security.rkp-V3-ndk",
-        "lib_android_keymaster_keymint_utils",
+        "lib_android_keymaster_keymint_utils_V3",
         "libbase",
         "libcppbor",
         "libkeymaster_portable",
@@ -61,7 +61,7 @@ cc_library {
         "liblog",
         "libcrypto",
         "libcutils",
-        "libjc_keymint_transport",
+        "libjc_keymint_transport_V3",
         "libbinder_ndk",
     ],
     export_include_dirs: [
@@ -83,12 +83,10 @@ cc_binary {
         "-Wall",
         "-Wextra",
     ],
-    defaults: [
-        "keymint_use_latest_hal_aidl_ndk_shared",
-    ],
     shared_libs: [
+        "android.hardware.security.keymint-V3-ndk",
         "android.hardware.security.sharedsecret-V1-ndk",
-        "lib_android_keymaster_keymint_utils",
+        "lib_android_keymaster_keymint_utils_V3",
         "android.hardware.security.rkp-V3-ndk",
         "libbase",
         "libbinder_ndk",
@@ -96,7 +94,7 @@ cc_binary {
         "libcrypto",
         "libkeymaster_portable",
         "libjc_keymint3",
-        "libjc_keymint_transport",
+        "libjc_keymint_transport_V3",
         "liblog",
         "libutils",
         "android.se.omapi-V1-ndk",
```

