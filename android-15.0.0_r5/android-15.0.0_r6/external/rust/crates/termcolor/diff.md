```diff
diff --git a/Android.bp b/Android.bp
index e909d2e..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,72 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_termcolor_license"],
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
-    name: "external_rust_crates_termcolor_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-MIT",
-        "SPDX-license-identifier-Unlicense",
-    ],
-    license_text: [
-        "COPYING",
-        "LICENSE-MIT",
-        "UNLICENSE",
-    ],
-}
-
-rust_library {
-    name: "libtermcolor",
-    host_supported: true,
-    crate_name: "termcolor",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.4.1",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
-    product_available: true,
-    vendor_available: true,
-}
-
-rust_test {
-    name: "termcolor_test_src_lib",
-    host_supported: true,
-    crate_name: "termcolor",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.4.1",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index ea6c5d1..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,27 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "packages/modules/Virtualization/virtualizationmanager"
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
-      "name": "termcolor_test_src_lib"
-    }
-  ],
-  "presubmit-rust": [
-    {
-      "name": "termcolor_test_src_lib"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index c8842d1..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-  "run_cargo": false,
-  "tests": true
-}
```

