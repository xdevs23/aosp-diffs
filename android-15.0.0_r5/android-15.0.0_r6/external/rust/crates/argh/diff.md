```diff
diff --git a/Android.bp b/Android.bp
index 6e8219f..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,101 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_argh_license"],
-}
-
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
-license {
-    name: "external_rust_crates_argh_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-BSD",
-    ],
-    license_text: [
-        "LICENSE",
-    ],
-}
-
-rust_test {
-    name: "argh_test_src_lib",
-    host_supported: true,
-    crate_name: "argh",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.1.12",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    rustlibs: [
-        "libargh_shared",
-        "libonce_cell",
-    ],
-    proc_macros: ["libargh_derive"],
-}
-
-rust_test {
-    name: "argh_test_tests_args_info_tests",
-    host_supported: true,
-    crate_name: "args_info_tests",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.1.12",
-    crate_root: "tests/args_info_tests.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    rustlibs: [
-        "libargh",
-        "libargh_shared",
-        "libonce_cell",
-    ],
-    proc_macros: ["libargh_derive"],
-}
-
-rust_test {
-    name: "argh_test_tests_lib",
-    host_supported: true,
-    crate_name: "lib",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.1.12",
-    crate_root: "tests/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    rustlibs: [
-        "libargh",
-        "libargh_shared",
-        "libonce_cell",
-    ],
-    proc_macros: ["libargh_derive"],
-}
-
-rust_library {
-    name: "libargh",
-    host_supported: true,
-    crate_name: "argh",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.1.12",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    rustlibs: ["libargh_shared"],
-    proc_macros: ["libargh_derive"],
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
index c04829d..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,24 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "packages/modules/Virtualization/virtualizationmanager"
-    }
-  ],
-  "presubmit": [
-    {
-      "name": "argh_test_src_lib"
-    },
-    {
-      "name": "argh_test_tests_lib"
-    }
-  ],
-  "presubmit-rust": [
-    {
-      "name": "argh_test_src_lib"
-    },
-    {
-      "name": "argh_test_tests_lib"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index 51eae9d..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,17 +0,0 @@
-{
-  "tests": true,
-  "apex_available": [
-    "//apex_available:platform",
-    "com.android.virt"
-  ],
-  "package": {
-    "argh": {
-      "dep_blocklist": [
-        "libtrybuild"
-      ]
-    }
-  },
-  "module_blocklist": [
-    "argh_test_tests_compiletest"
-  ]
-}
```
