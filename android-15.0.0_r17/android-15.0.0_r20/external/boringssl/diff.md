```diff
diff --git a/Android.bp b/Android.bp
index 2ca7f604..0e23064d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -79,7 +79,10 @@ cc_defaults {
         "-DBORINGSSL_NO_STATIC_INITIALIZER",
         "-DANDROID_BAREMETAL",
     ],
-    defaults: ["boringssl_flags_common"],
+    defaults: [
+        "boringssl_flags_common",
+        "cc_baremetal_defaults",
+    ],
     apex_available: [
         "com.android.virt",
     ],
@@ -182,11 +185,13 @@ cc_object {
         "com.android.adservices",
         "com.android.btservices",
         "com.android.compos",
+        "com.android.configinfrastructure",
         "com.android.conscrypt",
         "com.android.extservices",
         "com.android.ondevicepersonalization",
         "com.android.resolv",
         "com.android.virt",
+        "com.android.wifi",
     ],
 }
 
@@ -284,11 +289,13 @@ cc_library {
         "com.android.adservices",
         "com.android.btservices",
         "com.android.compos",
+        "com.android.configinfrastructure",
         "com.android.conscrypt",
         "com.android.extservices",
-        "com.android.resolv",
         "com.android.ondevicepersonalization",
+        "com.android.resolv",
         "com.android.virt",
+        "com.android.wifi",
     ],
     min_sdk_version: "29",
     afdo: true,
@@ -348,7 +355,7 @@ cc_library_static {
         "//bootable/deprecated-ota/updater",
         "//external/conscrypt",
         "//external/python/cpython2",
-        "//external/rust/crates/quiche",
+        "//external/rust/android-crates-io/crates/quiche",
         // Strictly, only the *static* toybox for legacy devices should have
         // access to libcrypto_static, but we can't express that.
         "//external/toybox",
@@ -511,11 +518,13 @@ cc_library {
 
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
         "com.android.adbd",
+        "com.android.btservices",
+        "com.android.configinfrastructure",
         "com.android.conscrypt",
         "com.android.resolv",
         "com.android.virt",
+        "com.android.wifi",
     ],
     min_sdk_version: "29",
 }
@@ -746,6 +755,9 @@ cc_binary {
     defaults: [
         "boringssl_flags",
     ],
+    cflags: [
+        "-DBORINGSSL_FIPS",
+    ],
     shared_libs: [
         "libcrypto",
     ],
@@ -787,8 +799,10 @@ rust_bindgen {
         "libcrypto",
         "libssl",
     ],
+    min_sdk_version: "29",
     apex_available: [
         "//apex_available:platform",
+        "com.android.configinfrastructure",
         "com.android.virt",
     ],
 }
@@ -834,8 +848,10 @@ cc_library_static {
         "libcrypto",
         "libssl",
     ],
+    min_sdk_version: "29",
     apex_available: [
         "//apex_available:platform",
+        "com.android.configinfrastructure",
         "com.android.virt",
     ],
 
@@ -878,6 +894,7 @@ rust_defaults {
     crate_name: "bssl_sys",
     visibility: [
         "//external/rust/crates/openssl",
+        "//external/rust/android-crates-io/crates/tokio-openssl",
         "//system/keymint/boringssl",
         "//system/security/prng_seeder",
     ],
@@ -899,8 +916,10 @@ rust_library {
     whole_static_libs: [
         "libbssl_rust_support",
     ],
+    min_sdk_version: "29",
     apex_available: [
         "//apex_available:platform",
+        "com.android.configinfrastructure",
         "com.android.virt",
     ],
     cfgs: ["unsupported_inline_wrappers"],
@@ -973,3 +992,9 @@ rust_test {
     test_suites: ["general-tests"],
     auto_gen_config: true,
 }
+
+dirgroup {
+    name: "trusty_dirgroup_external_boringssl",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/src/crypto/bio/connect.c b/src/crypto/bio/connect.c
index 900e659b..50d89836 100644
--- a/src/crypto/bio/connect.c
+++ b/src/crypto/bio/connect.c
@@ -487,7 +487,11 @@ static long conn_callback_ctrl(BIO *bio, int cmd, bio_info_cb fp) {
       // convention.
       OPENSSL_MSVC_PRAGMA(warning(push))
       OPENSSL_MSVC_PRAGMA(warning(disable : 4191))
+      OPENSSL_CLANG_PRAGMA("clang diagnostic push")
+      OPENSSL_CLANG_PRAGMA("clang diagnostic ignored \"-Wunknown-warning-option\"")
+      OPENSSL_CLANG_PRAGMA("clang diagnostic ignored \"-Wcast-function-type\"")
       data->info_callback = (int (*)(const struct bio_st *, int, int))fp;
+      OPENSSL_CLANG_PRAGMA("clang diagnostic pop")
       OPENSSL_MSVC_PRAGMA(warning(pop))
       break;
     default:
```

