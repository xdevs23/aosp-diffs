```diff
diff --git a/Android.bp b/Android.bp
index ccac5a9..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,51 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_zip_license"],
-}
-
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
-license {
-    name: "external_rust_crates_zip_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-MIT",
-    ],
-    license_text: [
-        "LICENSE",
-    ],
-}
-
-rust_library {
-    name: "libzip",
-    host_supported: true,
-    crate_name: "zip",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.6.6",
-    crate_root: "src/lib.rs",
-    edition: "2021",
-    features: [
-        "deflate-zlib",
-        "flate2",
-    ],
-    rustlibs: [
-        "libbyteorder",
-        "libcrc32fast",
-        "libflate2",
-    ],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.virt",
-    ],
-    product_available: true,
-    vendor_available: true,
-    arch: {
-        arm: {
-            rustlibs: ["libcrossbeam_utils"],
-        },
-    },
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index bbc8a7f..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,29 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "packages/modules/Virtualization/apkdmverity"
-    },
-    {
-      "path": "packages/modules/Virtualization/avmd"
-    },
-    {
-      "path": "packages/modules/Virtualization/libs/apexutil"
-    },
-    {
-      "path": "packages/modules/Virtualization/libs/apkverify"
-    },
-    {
-      "path": "packages/modules/Virtualization/microdroid_manager"
-    },
-    {
-      "path": "packages/modules/Virtualization/virtualizationmanager"
-    },
-    {
-      "path": "packages/modules/Virtualization/vm"
-    },
-    {
-      "path": "packages/modules/Virtualization/zipfuse"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index 0fdd156..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,15 +0,0 @@
-{
-  "apex_available": [
-    "//apex_available:platform",
-    "com.android.virt"
-  ],
-  "features": [
-    "deflate-zlib"
-  ],
-  "package": {
-    "zip": {
-      "patch": "patches/Android.bp.diff"
-    }
-  },
-  "run_cargo": false
-}
```
