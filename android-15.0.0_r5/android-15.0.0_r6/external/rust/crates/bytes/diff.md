```diff
diff --git a/Android.bp b/Android.bp
index 03f0272..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,319 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_bytes_license"],
-}
-
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
-license {
-    name: "external_rust_crates_bytes_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-MIT",
-    ],
-    license_text: [
-        "LICENSE",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_buf",
-    host_supported: true,
-    crate_name: "test_buf",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_buf.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_buf_mut",
-    host_supported: true,
-    crate_name: "test_buf_mut",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_buf_mut.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_bytes",
-    host_supported: true,
-    crate_name: "test_bytes",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_bytes.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_bytes_odd_alloc",
-    host_supported: true,
-    crate_name: "test_bytes_odd_alloc",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_bytes_odd_alloc.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_bytes_vec_alloc",
-    host_supported: true,
-    crate_name: "test_bytes_vec_alloc",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_bytes_vec_alloc.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_chain",
-    host_supported: true,
-    crate_name: "test_chain",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_chain.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_debug",
-    host_supported: true,
-    crate_name: "test_debug",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_debug.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_iter",
-    host_supported: true,
-    crate_name: "test_iter",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_iter.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_reader",
-    host_supported: true,
-    crate_name: "test_reader",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_reader.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_serde",
-    host_supported: true,
-    crate_name: "test_serde",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_serde.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_test {
-    name: "bytes_test_tests_test_take",
-    host_supported: true,
-    crate_name: "test_take",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "tests/test_take.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: [
-        "libbytes",
-        "libserde",
-        "libserde_test",
-    ],
-}
-
-rust_library {
-    name: "libbytes",
-    host_supported: true,
-    crate_name: "bytes",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.5.0",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: [
-        "default",
-        "serde",
-        "std",
-    ],
-    rustlibs: ["libserde"],
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
-    product_available: true,
-    vendor_available: true,
-    min_sdk_version: "29",
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index 0e8ed79..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,108 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "external/rust/crates/async-stream"
-    },
-    {
-      "path": "external/rust/crates/futures-util"
-    },
-    {
-      "path": "external/rust/crates/jni"
-    },
-    {
-      "path": "external/rust/crates/tokio"
-    },
-    {
-      "path": "external/rust/crates/tokio-test"
-    },
-    {
-      "path": "external/uwb/src"
-    },
-    {
-      "path": "packages/modules/DnsResolver"
-    },
-    {
-      "path": "packages/modules/Virtualization/apkdmverity"
-    },
-    {
-      "path": "packages/modules/Virtualization/authfs"
-    },
-    {
-      "path": "packages/modules/Virtualization/avmd"
-    },
-    {
-      "path": "packages/modules/Virtualization/libs/apkverify"
-    },
-    {
-      "path": "packages/modules/Virtualization/microdroid_manager"
-    },
-    {
-      "path": "packages/modules/Virtualization/virtualizationmanager"
-    }
-  ],
-  "presubmit": [
-    {
-      "name": "bytes_test_tests_test_buf"
-    },
-    {
-      "name": "bytes_test_tests_test_buf_mut"
-    },
-    {
-      "name": "bytes_test_tests_test_bytes"
-    },
-    {
-      "name": "bytes_test_tests_test_bytes_odd_alloc"
-    },
-    {
-      "name": "bytes_test_tests_test_bytes_vec_alloc"
-    },
-    {
-      "name": "bytes_test_tests_test_chain"
-    },
-    {
-      "name": "bytes_test_tests_test_debug"
-    },
-    {
-      "name": "bytes_test_tests_test_iter"
-    },
-    {
-      "name": "bytes_test_tests_test_reader"
-    },
-    {
-      "name": "bytes_test_tests_test_take"
-    }
-  ],
-  "presubmit-rust": [
-    {
-      "name": "bytes_test_tests_test_buf"
-    },
-    {
-      "name": "bytes_test_tests_test_buf_mut"
-    },
-    {
-      "name": "bytes_test_tests_test_bytes"
-    },
-    {
-      "name": "bytes_test_tests_test_bytes_odd_alloc"
-    },
-    {
-      "name": "bytes_test_tests_test_bytes_vec_alloc"
-    },
-    {
-      "name": "bytes_test_tests_test_chain"
-    },
-    {
-      "name": "bytes_test_tests_test_debug"
-    },
-    {
-      "name": "bytes_test_tests_test_iter"
-    },
-    {
-      "name": "bytes_test_tests_test_reader"
-    },
-    {
-      "name": "bytes_test_tests_test_take"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index 57a41b3..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,12 +0,0 @@
-{
-  "apex_available": [
-    "//apex_available:platform",
-    "//apex_available:anyapex"
-  ],
-  "features": [
-    "default",
-    "serde"
-  ],
-  "min_sdk_version": "29",
-  "tests": true
-}
```
