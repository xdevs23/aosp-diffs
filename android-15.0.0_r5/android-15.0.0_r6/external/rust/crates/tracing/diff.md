```diff
diff --git a/Android.bp b/Android.bp
index e06f035..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,72 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_tracing_license"],
-}
-
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
-license {
-    name: "external_rust_crates_tracing_license",
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
-    name: "libtracing",
-    host_supported: true,
-    crate_name: "tracing",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.1.40",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: [
-        "attributes",
-        "default",
-        "std",
-        "tracing-attributes",
-    ],
-    rustlibs: [
-        "libpin_project_lite",
-        "libtracing_core",
-    ],
-    proc_macros: ["libtracing_attributes"],
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
-    product_available: true,
-    vendor_available: true,
-}
-
-rust_library {
-    name: "libtracing_max_level_off",
-    host_supported: true,
-    crate_name: "tracing",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.1.40",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: [
-        "max_level_off",
-        "release_max_level_off",
-    ],
-    rustlibs: [
-        "libpin_project_lite",
-        "libtracing_core",
-    ],
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
-    product_available: true,
-    vendor_available: true,
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index 33fc981..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,15 +0,0 @@
-{
-  "run_cargo": false,
-  "variants": [
-    {},
-    {
-      "features": [
-        "max_level_off",
-        "release_max_level_off"
-      ],
-      "module_name_overrides": {
-        "libtracing": "libtracing_max_level_off"
-      }
-    }
-  ]
-}
```

