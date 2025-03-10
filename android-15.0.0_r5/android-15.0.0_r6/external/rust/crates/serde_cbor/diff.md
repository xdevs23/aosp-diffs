```diff
diff --git a/Android.bp b/Android.bp
index c812596..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,273 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_serde_cbor_license"],
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
-    name: "external_rust_crates_serde_cbor_license",
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
-    name: "libserde_cbor",
-    host_supported: true,
-    crate_name: "serde_cbor",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.11.2",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-        "tags",
-    ],
-    rustlibs: [
-        "libhalf",
-        "libserde",
-    ],
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
-    product_available: true,
-    vendor_available: true,
-}
-
-rust_test {
-    name: "serde_cbor_test_tests_bennofs",
-    host_supported: true,
-    crate_name: "bennofs",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.11.2",
-    crate_root: "tests/bennofs.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-        "tags",
-    ],
-    rustlibs: [
-        "libhalf",
-        "libserde",
-        "libserde_cbor",
-    ],
-    proc_macros: ["libserde_derive"],
-}
-
-rust_test {
-    name: "serde_cbor_test_tests_canonical",
-    host_supported: true,
-    crate_name: "canonical",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.11.2",
-    crate_root: "tests/canonical.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-        "tags",
-    ],
-    rustlibs: [
-        "libhalf",
-        "libserde",
-        "libserde_cbor",
-    ],
-    proc_macros: ["libserde_derive"],
-}
-
-rust_test {
-    name: "serde_cbor_test_tests_de",
-    host_supported: true,
-    crate_name: "de",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.11.2",
-    crate_root: "tests/de.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-        "tags",
-    ],
-    rustlibs: [
-        "libhalf",
-        "libserde",
-        "libserde_cbor",
-    ],
-    proc_macros: ["libserde_derive"],
-}
-
-rust_test {
-    name: "serde_cbor_test_tests_enum",
-    host_supported: true,
-    crate_name: "enum",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.11.2",
-    crate_root: "tests/enum.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-        "tags",
-    ],
-    rustlibs: [
-        "libhalf",
-        "libserde",
-        "libserde_cbor",
-    ],
-    proc_macros: ["libserde_derive"],
-}
-
-rust_test {
-    name: "serde_cbor_test_tests_ser",
-    host_supported: true,
-    crate_name: "ser",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.11.2",
-    crate_root: "tests/ser.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-        "tags",
-    ],
-    rustlibs: [
-        "libhalf",
-        "libserde",
-        "libserde_cbor",
-    ],
-    proc_macros: ["libserde_derive"],
-}
-
-rust_test {
-    name: "serde_cbor_test_tests_std_types",
-    host_supported: true,
-    crate_name: "std_types",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.11.2",
-    crate_root: "tests/std_types.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-        "tags",
-    ],
-    rustlibs: [
-        "libhalf",
-        "libserde",
-        "libserde_cbor",
-    ],
-    proc_macros: ["libserde_derive"],
-}
-
-rust_test {
-    name: "serde_cbor_test_tests_tags",
-    host_supported: true,
-    crate_name: "tags",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.11.2",
-    crate_root: "tests/tags.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-        "tags",
-    ],
-    rustlibs: [
-        "libhalf",
-        "libserde",
-        "libserde_cbor",
-    ],
-    proc_macros: ["libserde_derive"],
-}
-
-rust_test {
-    name: "serde_cbor_test_tests_value",
-    host_supported: true,
-    crate_name: "value",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.11.2",
-    crate_root: "tests/value.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-        "tags",
-    ],
-    rustlibs: [
-        "libhalf",
-        "libserde",
-        "libserde_cbor",
-    ],
-    proc_macros: ["libserde_derive"],
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index a757518..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,84 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "external/rust/crates/base64"
-    },
-    {
-      "path": "external/rust/crates/tinytemplate"
-    },
-    {
-      "path": "external/rust/crates/tinyvec"
-    },
-    {
-      "path": "external/rust/crates/unicode-xid"
-    },
-    {
-      "path": "packages/modules/Virtualization/avmd"
-    },
-    {
-      "path": "packages/modules/Virtualization/microdroid_manager"
-    },
-    {
-      "path": "system/security/diced"
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
-      "name": "serde_cbor_test_tests_bennofs"
-    },
-    {
-      "name": "serde_cbor_test_tests_canonical"
-    },
-    {
-      "name": "serde_cbor_test_tests_de"
-    },
-    {
-      "name": "serde_cbor_test_tests_enum"
-    },
-    {
-      "name": "serde_cbor_test_tests_ser"
-    },
-    {
-      "name": "serde_cbor_test_tests_std_types"
-    },
-    {
-      "name": "serde_cbor_test_tests_tags"
-    },
-    {
-      "name": "serde_cbor_test_tests_value"
-    }
-  ],
-  "presubmit-rust": [
-    {
-      "name": "serde_cbor_test_tests_bennofs"
-    },
-    {
-      "name": "serde_cbor_test_tests_canonical"
-    },
-    {
-      "name": "serde_cbor_test_tests_de"
-    },
-    {
-      "name": "serde_cbor_test_tests_enum"
-    },
-    {
-      "name": "serde_cbor_test_tests_ser"
-    },
-    {
-      "name": "serde_cbor_test_tests_std_types"
-    },
-    {
-      "name": "serde_cbor_test_tests_tags"
-    },
-    {
-      "name": "serde_cbor_test_tests_value"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index abdd3d0..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "features": [
-    "default",
-    "tags"
-  ],
-  "tests": true
-}
```

