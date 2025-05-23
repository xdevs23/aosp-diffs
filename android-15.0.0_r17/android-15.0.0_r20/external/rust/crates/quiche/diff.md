```diff
diff --git a/Android.bp b/Android.bp
index 1b4784b..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,219 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_quiche_license"],
-}
-
-// Added automatically by a large-scale-change that took the approach of
-// 'apply every license found to every target'. While this makes sure we respect
-// every license restriction, it may not be entirely correct.
-//
-// e.g. GPL in an MIT project might only apply to the contrib/ directory.
-//
-// Please consider splitting the single license below into multiple licenses,
-// taking care not to lose any license_kind information, and overriding the
-// default license using the 'licenses: [...]' property on targets as needed.
-//
-// For unused files, consider creating a 'fileGroup' with "//visibility:private"
-// to attach the license to, and including a comment whether the files may be
-// used in the current project.
-// See: http://go/android-license-faq
-license {
-    name: "external_rust_crates_quiche_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-BSD",
-        "SPDX-license-identifier-ISC",
-        "SPDX-license-identifier-OpenSSL",
-        "legacy_unencumbered",
-    ],
-    license_text: [
-        "COPYING",
-    ],
-}
-
-cc_library_headers {
-    name: "libquiche_ffi_headers",
-    export_include_dirs: ["include"],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.resolv",
-    ],
-    min_sdk_version: "29",
-}
-
-rust_library {
-    name: "libquiche",
-    host_supported: true,
-    crate_name: "quiche",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.17.1",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    rlibs: [
-        "liblazy_static",
-        "liblibc",
-        "liblibm",
-        "liblog_rust",
-        "liboctets",
-        "libring",
-        "libslab",
-        "libsmallvec",
-    ],
-    prefer_rlib: true,
-    shared_libs: [
-        "libcrypto",
-        "libssl",
-    ],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.resolv",
-    ],
-    product_available: true,
-    vendor_available: true,
-    min_sdk_version: "29",
-}
-
-rust_ffi {
-    name: "libquiche_ffi",
-    host_supported: true,
-    crate_name: "quiche",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.17.1",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    rlibs: [
-        "liblazy_static",
-        "liblibc",
-        "liblibm",
-        "liblog_rust",
-        "liboctets",
-        "libring",
-        "libslab",
-        "libsmallvec",
-    ],
-    prefer_rlib: true,
-    shared_libs: [
-        "libcrypto",
-        "libssl",
-    ],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.resolv",
-    ],
-    product_available: true,
-    vendor_available: true,
-    min_sdk_version: "29",
-}
-
-rust_test_host {
-    name: "quiche_host_test_src_lib",
-    crate_name: "quiche",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.17.1",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "boringssl-vendored",
-        "default",
-    ],
-    rustlibs: [
-        "liblazy_static",
-        "liblibc",
-        "liblibm",
-        "liblog_rust",
-        "libmio",
-        "liboctets",
-        "libring",
-        "libslab",
-        "libsmallvec",
-        "liburl",
-    ],
-    shared_libs: [
-        "libcrypto",
-        "libssl",
-    ],
-    data: [
-        "examples/cert.crt",
-        "examples/cert.key",
-        "examples/cert-big.crt",
-        "examples/rootca.crt",
-    ],
-}
-
-rust_test {
-    name: "quiche_device_test_src_lib",
-    crate_name: "quiche",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.17.1",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    edition: "2018",
-    features: [
-        "boringssl-vendored",
-        "default",
-    ],
-    rustlibs: [
-        "liblazy_static",
-        "liblibc",
-        "liblibm",
-        "liblog_rust",
-        "libmio",
-        "liboctets",
-        "libring",
-        "libslab",
-        "libsmallvec",
-        "liburl",
-    ],
-    static_libs: [
-        "libcrypto_static",
-        "libssl",
-    ],
-    data: [
-        "examples/cert.crt",
-        "examples/cert.key",
-        "examples/cert-big.crt",
-        "examples/rootca.crt",
-    ],
-    shared_libs: ["libc++"],
-}
-
-rust_library_rlib {
-    name: "libquiche_static",
-    host_supported: true,
-    crate_name: "quiche",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.17.1",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    rustlibs: [
-        "liblazy_static",
-        "liblibc",
-        "liblibm",
-        "liblog_rust",
-        "liboctets",
-        "libring",
-        "libslab",
-        "libsmallvec",
-    ],
-    static_libs: [
-        "libcrypto_static",
-        "libssl",
-    ],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.resolv",
-    ],
-    product_available: true,
-    vendor_available: true,
-    min_sdk_version: "29",
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index d394a8a..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,18 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "packages/modules/DnsResolver"
-    }
-  ],
-  "presubmit": [
-    {
-      "name": "quiche_device_test_src_lib"
-    }
-  ],
-  "presubmit-rust": [
-    {
-      "name": "quiche_device_test_src_lib"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index e589563..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,78 +0,0 @@
-{
-  "apex_available": [
-    "//apex_available:platform",
-    "com.android.resolv"
-  ],
-  "min_sdk_version": "29",
-  "package": {
-    "quiche": {
-      "patch": "patches/Android.bp.patch",
-      "test_data": {
-        "src/lib.rs": [
-          "examples/cert.crt",
-          "examples/cert.key",
-          "examples/cert-big.crt",
-          "examples/rootca.crt"
-        ]
-      }
-    }
-  },
-  "variants": [
-    {
-      "module_blocklist": [
-        "libquiche_static"
-      ],
-      "module_name_overrides": {
-        "libquiche_shared": "libquiche_ffi"
-      }
-    },
-    {
-      "module_blocklist": [
-        "libquiche",
-        "libquiche_shared",
-        "libquiche_static"
-      ],
-      "module_name_overrides": {
-        "quiche_test_src_lib": "quiche_host_test_src_lib"
-      },
-      "tests": true,
-      "package": {
-        "quiche": {
-          "device_supported": false
-        }
-      }
-    },
-    {
-      "module_blocklist": [
-        "libquiche",
-        "libquiche_shared",
-        "libquiche_static"
-      ],
-      "module_name_overrides": {
-        "libcrypto": "libcrypto_static",
-        "quiche_test_src_lib": "quiche_device_test_src_lib"
-      },
-      "tests": true,
-      "package": {
-        "quiche": {
-          "host_supported": false
-        }
-      }
-    },
-    {
-      "module_blocklist": [
-        "libquiche_shared",
-        "libquiche_static"
-      ],
-      "module_name_overrides": {
-        "libcrypto": "libcrypto_static",
-        "libquiche": "libquiche_static"
-      },
-      "package": {
-        "quiche": {
-          "force_rlib": true
-        }
-      }
-    }
-  ]
-}
diff --git a/ffi_headers.bp.fragment b/ffi_headers.bp.fragment
new file mode 100644
index 0000000..25ef953
--- /dev/null
+++ b/ffi_headers.bp.fragment
@@ -0,0 +1,9 @@
+cc_library_headers {
+    name: "libquiche_ffi_headers",
+    export_include_dirs: ["include"],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.resolv",
+    ],
+    min_sdk_version: "29",
+}
diff --git a/patches/Android.bp.patch b/patches/Android.bp.patch
index 4beeec7..9b434ab 100644
--- a/patches/Android.bp.patch
+++ b/patches/Android.bp.patch
@@ -2,6 +2,19 @@ diff --git a/Android.bp b/Android.bp
 index a1a223b..1b4784b 100644
 --- a/Android.bp
 +++ b/Android.bp
+@@ -9,7 +9,11 @@ package {
+ license {
+     name: "external_rust_crates_quiche_license",
+     visibility: [":__subpackages__"],
+-    license_kinds: ["SPDX-license-identifier-BSD-2-Clause"],
++    license_kinds: [
++        "SPDX-license-identifier-BSD-2-Clause",
++        "SPDX-license-identifier-ISC",
++        "SPDX-license-identifier-OpenSSL",
++    ],
+     license_text: ["LICENSE"],
+ }
+
 @@ -46,70 +46,64 @@ cc_library_headers {
  }
  
diff --git a/src/ffi.rs b/src/ffi.rs
index 38e82c4..36cb40d 100644
--- a/src/ffi.rs
+++ b/src/ffi.rs
@@ -102,10 +102,7 @@ use crate::*;
 
 #[no_mangle]
 pub extern fn quiche_version() -> *const u8 {
-    //static VERSION: &str = concat!("0.17.1", "\0");
-    // ANDROID's build system doesn't support environment variables
-    // so we hardcode the package version here.
-    static VERSION: &str = concat!("0.6.0", "\0");
+    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
     VERSION.as_ptr()
 }
 
```

