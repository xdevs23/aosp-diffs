```diff
diff --git a/Android.bp b/Android.bp
index 26dd152..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,77 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_num_cpus_license"],
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
-// For unused files, consider creating a 'filegroup' with "//visibility:private"
-// to attach the license to, and including a comment whether the files may be
-// used in the current project.
-//
-// large-scale-change included anything that looked like it might be a license
-// text as a license_text. e.g. LICENSE, NOTICE, COPYING etc.
-//
-// Please consider removing redundant or irrelevant files from 'license_text:'.
-// http://go/android-license-faq
-license {
-    name: "external_rust_crates_num_cpus_license",
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
-    name: "libnum_cpus",
-    host_supported: true,
-    crate_name: "num_cpus",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.16.0",
-    crate_root: "src/lib.rs",
-    edition: "2015",
-    rustlibs: ["liblibc"],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.btservices",
-        "com.android.compos",
-        "com.android.resolv",
-        "com.android.uwb",
-        "com.android.virt",
-    ],
-    product_available: true,
-    vendor_available: true,
-    min_sdk_version: "29",
-}
-
-rust_test {
-    name: "num_cpus_test_src_lib",
-    crate_name: "num_cpus",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.16.0",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: false,
-    },
-    edition: "2015",
-    rustlibs: ["liblibc"],
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index e6f36fd..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,78 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "external/rust/crates/anyhow"
-    },
-    {
-      "path": "external/rust/crates/async-stream"
-    },
-    {
-      "path": "external/rust/crates/base64"
-    },
-    {
-      "path": "external/rust/crates/futures-channel"
-    },
-    {
-      "path": "external/rust/crates/futures-executor"
-    },
-    {
-      "path": "external/rust/crates/futures-test"
-    },
-    {
-      "path": "external/rust/crates/futures-util"
-    },
-    {
-      "path": "external/rust/crates/hashbrown"
-    },
-    {
-      "path": "external/rust/crates/ryu"
-    },
-    {
-      "path": "external/rust/crates/tinytemplate"
-    },
-    {
-      "path": "external/rust/crates/tinyvec"
-    },
-    {
-      "path": "external/rust/crates/tokio"
-    },
-    {
-      "path": "external/rust/crates/tokio-test"
-    },
-    {
-      "path": "external/rust/crates/unicode-xid"
-    },
-    {
-      "path": "external/uwb/src"
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
-  ],
-  "presubmit": [
-    {
-      "name": "num_cpus_test_src_lib"
-    }
-  ],
-  "presubmit-rust": [
-    {
-      "name": "num_cpus_test_src_lib"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index ca7d422..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,19 +0,0 @@
-{
-  "apex_available": [
-    "//apex_available:platform",
-    "com.android.btservices",
-    "com.android.compos",
-    "com.android.resolv",
-    "com.android.uwb",
-    "com.android.virt"
-  ],
-  "min_sdk_version": "29",
-  "package": {
-    "num_cpus": {
-      "no_presubmit": true,
-      "patch": "patches/Android.bp.patch"
-    }
-  },
-  "run_cargo": false,
-  "tests": true
-}
```
