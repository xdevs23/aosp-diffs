```diff
diff --git a/Android.bp b/Android.bp
index bd6095f..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,72 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_team: "trendy_team_android_rust",
-    default_applicable_licenses: ["external_rust_crates_twox-hash_license"],
-}
-
-license {
-    name: "external_rust_crates_twox-hash_license",
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
-    name: "libtwox_hash",
-    host_supported: true,
-    crate_name: "twox_hash",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.6.3",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: [
-        "default",
-        "rand",
-        "std",
-    ],
-    rustlibs: [
-        "libcfg_if",
-        "librand",
-        "libstatic_assertions",
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
-    name: "twox-hash_test_src_lib",
-    host_supported: true,
-    crate_name: "twox_hash",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.6.3",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "rand",
-        "std",
-    ],
-    rustlibs: [
-        "libcfg_if",
-        "librand",
-        "libserde_json",
-        "libstatic_assertions",
-    ],
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index abeede5..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-  "tests": true,
-  "module_blocklist": ["hash_file"]
-}
```

