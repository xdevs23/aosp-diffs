```diff
diff --git a/Android.bp b/Android.bp
index 7a57758..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,95 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_regex-syntax_license"],
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
-    name: "external_rust_crates_regex-syntax_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-Apache-2.0",
-        "SPDX-license-identifier-MIT",
-        "SPDX-license-identifier-Unicode-DFS",
-    ],
-    license_text: [
-        "LICENSE-APACHE",
-        "LICENSE-MIT",
-    ],
-}
-
-rust_library {
-    name: "libregex_syntax",
-    host_supported: true,
-    crate_name: "regex_syntax",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.6.29",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: [
-        "default",
-        "unicode",
-        "unicode-age",
-        "unicode-bool",
-        "unicode-case",
-        "unicode-gencat",
-        "unicode-perl",
-        "unicode-script",
-        "unicode-segment",
-    ],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.compos",
-        "com.android.virt",
-    ],
-    product_available: true,
-    vendor_available: true,
-}
-
-rust_test {
-    name: "regex-syntax_test_src_lib",
-    host_supported: true,
-    crate_name: "regex_syntax",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.6.29",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "unicode",
-        "unicode-age",
-        "unicode-bool",
-        "unicode-case",
-        "unicode-gencat",
-        "unicode-perl",
-        "unicode-script",
-        "unicode-segment",
-    ],
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index afa287b..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,51 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "external/rust/crates/base64"
-    },
-    {
-      "path": "external/rust/crates/clap/2.33.3"
-    },
-    {
-      "path": "external/rust/crates/libsqlite3-sys"
-    },
-    {
-      "path": "external/rust/crates/once_cell"
-    },
-    {
-      "path": "external/rust/crates/regex"
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
-      "path": "packages/modules/Virtualization/virtualizationmanager"
-    },
-    {
-      "path": "system/keymint/hal"
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
-      "name": "regex-syntax_test_src_lib"
-    }
-  ],
-  "presubmit-rust": [
-    {
-      "name": "regex-syntax_test_src_lib"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index a76efe6..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,9 +0,0 @@
-{
-  "apex_available": [
-    "//apex_available:platform",
-    "com.android.compos",
-    "com.android.virt"
-  ],
-  "run_cargo": false,
-  "tests": true
-}
```

