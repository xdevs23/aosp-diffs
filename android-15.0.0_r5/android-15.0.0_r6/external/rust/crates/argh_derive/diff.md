```diff
diff --git a/Android.bp b/Android.bp
index 00b448e..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,38 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_argh_derive_license"],
-}
-
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
-license {
-    name: "external_rust_crates_argh_derive_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-BSD",
-    ],
-    license_text: [
-        "LICENSE",
-    ],
-}
-
-rust_proc_macro {
-    name: "libargh_derive",
-    crate_name: "argh_derive",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.1.12",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    rustlibs: [
-        "libargh_shared",
-        "libproc_macro2",
-        "libquote",
-        "libsyn",
-    ],
-    product_available: true,
-    vendor_available: true,
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index 9f55024..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,11 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "external/rust/crates/argh"
-    },
-    {
-      "path": "packages/modules/Virtualization/virtualizationmanager"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index cb908d7..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,3 +0,0 @@
-{
-  "run_cargo": false
-}
```
