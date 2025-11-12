```diff
diff --git a/nearby/Android.bp b/nearby/Android.bp
index 4c70f79..01b8eac 100644
--- a/nearby/Android.bp
+++ b/nearby/Android.bp
@@ -23,7 +23,7 @@ rust_library_rlib {
     ],
     rustlibs: [
         "libhex",
-        "librand",
+        "librand-0.8",
         "libtinyvec",
     ],
 }
@@ -61,7 +61,7 @@ rust_library_rlib {
         "libcrypto_provider",
         "libcrypto_provider_stubs",
         "libbssl_crypto",
-        "librand",
+        "librand-0.8",
     ],
 }
 
@@ -81,8 +81,8 @@ rust_ffi_shared {
         "liblazy_static",
         "liblock_adapter",
         "liblog_rust",
-        "librand",
-        "librand_chacha",
+        "librand-0.8",
+        "librand_chacha-0.3",
         "libukey2_connections",
         "libukey2_rs",
     ],
@@ -97,7 +97,7 @@ rust_library_rlib {
         "libbytes",
         "libcrypto_provider",
         "libnom",
-        "librand",
+        "librand-0.8",
         "libukey2_proto",
         "libukey2_rs",
     ],
@@ -124,8 +124,8 @@ rust_ffi_shared {
         "libjni",
         "liblazy_static",
         "liblock_adapter",
-        "librand",
-        "librand_chacha",
+        "librand-0.8",
+        "librand_chacha-0.3",
         "libukey2_connections",
         "libukey2_rs",
     ],
@@ -155,7 +155,7 @@ rust_library_rlib {
         "libcrypto_provider",
         "libnum_bigint",
         "liblog_rust",
-        "librand",
+        "librand-0.8",
         "libukey2_proto",
     ],
 }
```

