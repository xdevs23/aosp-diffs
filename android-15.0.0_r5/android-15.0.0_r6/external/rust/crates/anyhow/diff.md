```diff
diff --git a/Android.bp b/Android.bp
index 24c88cd..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,324 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_anyhow_license"],
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
-    name: "external_rust_crates_anyhow_license",
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
-rust_test {
-    name: "anyhow_test_src_lib",
-    host_supported: true,
-    crate_name: "anyhow",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_test {
-    name: "anyhow_test_tests_test_autotrait",
-    host_supported: true,
-    crate_name: "test_autotrait",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "tests/test_autotrait.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libanyhow",
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_test {
-    name: "anyhow_test_tests_test_boxed",
-    host_supported: true,
-    crate_name: "test_boxed",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "tests/test_boxed.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libanyhow",
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_test {
-    name: "anyhow_test_tests_test_chain",
-    host_supported: true,
-    crate_name: "test_chain",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "tests/test_chain.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libanyhow",
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_test {
-    name: "anyhow_test_tests_test_context",
-    host_supported: true,
-    crate_name: "test_context",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "tests/test_context.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libanyhow",
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_test {
-    name: "anyhow_test_tests_test_convert",
-    host_supported: true,
-    crate_name: "test_convert",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "tests/test_convert.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libanyhow",
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_test {
-    name: "anyhow_test_tests_test_downcast",
-    host_supported: true,
-    crate_name: "test_downcast",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "tests/test_downcast.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libanyhow",
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_test {
-    name: "anyhow_test_tests_test_fmt",
-    host_supported: true,
-    crate_name: "test_fmt",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "tests/test_fmt.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libanyhow",
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_test {
-    name: "anyhow_test_tests_test_macros",
-    host_supported: true,
-    crate_name: "test_macros",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "tests/test_macros.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libanyhow",
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_test {
-    name: "anyhow_test_tests_test_repr",
-    host_supported: true,
-    crate_name: "test_repr",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "tests/test_repr.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libanyhow",
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_test {
-    name: "anyhow_test_tests_test_source",
-    host_supported: true,
-    crate_name: "test_source",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "tests/test_source.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: [
-        "libanyhow",
-        "libfutures",
-        "libthiserror",
-    ],
-}
-
-rust_library {
-    name: "libanyhow",
-    host_supported: true,
-    crate_name: "anyhow",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.79",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
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
index f983c0e..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,126 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
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
-      "path": "packages/modules/Virtualization/encryptedstore"
-    },
-    {
-      "path": "packages/modules/Virtualization/libs/apkverify"
-    },
-    {
-      "path": "packages/modules/Virtualization/libs/capabilities"
-    },
-    {
-      "path": "packages/modules/Virtualization/libs/devicemapper"
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
-    },
-    {
-      "path": "system/keymint/hal"
-    },
-    {
-      "path": "system/security/diced"
-    },
-    {
-      "path": "system/security/keystore2"
-    },
-    {
-      "path": "system/security/keystore2/legacykeystore"
-    },
-    {
-      "path": "system/security/keystore2/selinux"
-    }
-  ],
-  "presubmit": [
-    {
-      "name": "anyhow_test_src_lib"
-    },
-    {
-      "name": "anyhow_test_tests_test_autotrait"
-    },
-    {
-      "name": "anyhow_test_tests_test_boxed"
-    },
-    {
-      "name": "anyhow_test_tests_test_chain"
-    },
-    {
-      "name": "anyhow_test_tests_test_context"
-    },
-    {
-      "name": "anyhow_test_tests_test_convert"
-    },
-    {
-      "name": "anyhow_test_tests_test_downcast"
-    },
-    {
-      "name": "anyhow_test_tests_test_fmt"
-    },
-    {
-      "name": "anyhow_test_tests_test_macros"
-    },
-    {
-      "name": "anyhow_test_tests_test_repr"
-    },
-    {
-      "name": "anyhow_test_tests_test_source"
-    }
-  ],
-  "presubmit-rust": [
-    {
-      "name": "anyhow_test_src_lib"
-    },
-    {
-      "name": "anyhow_test_tests_test_autotrait"
-    },
-    {
-      "name": "anyhow_test_tests_test_boxed"
-    },
-    {
-      "name": "anyhow_test_tests_test_chain"
-    },
-    {
-      "name": "anyhow_test_tests_test_context"
-    },
-    {
-      "name": "anyhow_test_tests_test_convert"
-    },
-    {
-      "name": "anyhow_test_tests_test_downcast"
-    },
-    {
-      "name": "anyhow_test_tests_test_fmt"
-    },
-    {
-      "name": "anyhow_test_tests_test_macros"
-    },
-    {
-      "name": "anyhow_test_tests_test_repr"
-    },
-    {
-      "name": "anyhow_test_tests_test_source"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index a7b61c5..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,24 +0,0 @@
-{
-  "tests": true,
-  "min_sdk_version": "29",
-  "package": {
-    "anyhow": {
-      "dep_blocklist": [
-        "libbacktrace_rust",
-        "librustversion",
-        "libsyn",
-        "libtrybuild"
-      ]
-    }
-  },
-  "cfg_blocklist": [
-    "backtrace"
-  ],
-  "module_blocklist": [
-    "anyhow_test_tests_compiletest",
-    "anyhow_test_tests_test_backtrace",
-    "anyhow_test_tests_test_ensure",
-    "anyhow_test_tests_test_ffi"
-  ],
-  "run_cargo": false
-}
```
