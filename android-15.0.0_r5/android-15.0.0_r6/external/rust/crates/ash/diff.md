```diff
diff --git a/Android.bp b/Android.bp
index ecbc34e..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,135 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_ash_license"],
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
-    name: "external_rust_crates_ash_license",
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
-    name: "ash_test_src_lib",
-    host_supported: true,
-    crate_name: "ash",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.37.3+1.3.251",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2021",
-    features: [
-        "debug",
-        "default",
-        "libloading",
-        "loaded",
-    ],
-    rustlibs: ["liblibloading"],
-}
-
-rust_test {
-    name: "ash_test_tests_constant_size_arrays",
-    host_supported: true,
-    crate_name: "constant_size_arrays",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.37.3+1.3.251",
-    crate_root: "tests/constant_size_arrays.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2021",
-    features: [
-        "debug",
-        "default",
-        "libloading",
-        "loaded",
-    ],
-    rustlibs: [
-        "libash_rust",
-        "liblibloading",
-    ],
-}
-
-rust_test {
-    name: "ash_test_tests_display",
-    host_supported: true,
-    crate_name: "display",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.37.3+1.3.251",
-    crate_root: "tests/display.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2021",
-    features: [
-        "debug",
-        "default",
-        "libloading",
-        "loaded",
-    ],
-    rustlibs: [
-        "libash_rust",
-        "liblibloading",
-    ],
-}
-
-rust_library {
-    name: "libash_rust",
-    host_supported: true,
-    crate_name: "ash",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.37.3+1.3.251",
-    crate_root: "src/lib.rs",
-    edition: "2021",
-    features: [
-        "debug",
-        "default",
-        "libloading",
-        "loaded",
-    ],
-    rustlibs: ["liblibloading"],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.virt",
-    ],
-    product_available: true,
-    vendor_available: true,
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index f439cf8..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,8 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "external/rust/crates/vulkano"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index 15db1a5..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,8 +0,0 @@
-{
-  "tests": true,
-  "apex_available": [
-    "//apex_available:platform",
-    "com.android.virt"
-  ],
-  "run_cargo": false
-}
```

