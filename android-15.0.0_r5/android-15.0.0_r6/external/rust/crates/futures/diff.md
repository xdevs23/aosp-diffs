```diff
diff --git a/Android.bp b/Android.bp
index ab3485a..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,76 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_futures_license"],
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
-//
-// large-scale-change included anything that looked like it might be a license
-// text as a license_text. e.g. LICENSE, NOTICE, COPYING etc.
-//
-// Please consider removing redundant or irrelevant files from 'license_text:'.
-// See: http://go/android-license-faq
-license {
-    name: "external_rust_crates_futures_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-Apache-2.0",
-        "SPDX-license-identifier-MIT",
-    ],
-    license_text: [
-        "LICENSE-APACHE",
-        "LICENSE-MIT",
-    ],
-}
-
-rust_library {
-    name: "libfutures",
-    host_supported: true,
-    crate_name: "futures",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.3.30",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: [
-        "alloc",
-        "async-await",
-        "default",
-        "executor",
-        "futures-executor",
-        "std",
-    ],
-    rustlibs: [
-        "libfutures_channel",
-        "libfutures_core",
-        "libfutures_executor",
-        "libfutures_io",
-        "libfutures_sink",
-        "libfutures_task",
-        "libfutures_util",
-    ],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.btservices",
-        "com.android.resolv",
-        "com.android.virt",
-    ],
-    product_available: true,
-    vendor_available: true,
-    min_sdk_version: "29",
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index f20282b..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,35 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "external/rust/crates/anyhow"
-    },
-    {
-      "path": "external/rust/crates/futures-channel"
-    },
-    {
-      "path": "external/rust/crates/futures-executor"
-    },
-    {
-      "path": "external/rust/crates/tokio"
-    },
-    {
-      "path": "packages/modules/DnsResolver"
-    },
-    {
-      "path": "packages/modules/Virtualization/authfs"
-    },
-    {
-      "path": "packages/modules/Virtualization/virtualizationmanager"
-    },
-    {
-      "path": "packages/modules/Virtualization/zipfuse"
-    },
-    {
-      "path": "system/security/keystore2"
-    },
-    {
-      "path": "system/security/keystore2/legacykeystore"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index 76e999c..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,10 +0,0 @@
-{
-  "apex_available": [
-    "//apex_available:platform",
-    "com.android.btservices",
-    "com.android.resolv",
-    "com.android.virt"
-  ],
-  "min_sdk_version": "29",
-  "run_cargo": false
-}
```
