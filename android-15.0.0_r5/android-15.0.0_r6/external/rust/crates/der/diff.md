```diff
diff --git a/Android.bp b/Android.bp
index 2112d76..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,118 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_der_license"],
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
-// See: http://go/android-license-faq
-license {
-    name: "external_rust_crates_der_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-Apache-2.0",
-        "SPDX-license-identifier-MIT",
-    ],
-    license_text: [
-        "LICENSE-APACHE",
-    ],
-}
-
-rust_library {
-    name: "libder",
-    host_supported: true,
-    crate_name: "der",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.7.8",
-    crate_root: "src/lib.rs",
-    edition: "2021",
-    features: [
-        "alloc",
-        "derive",
-        "flagset",
-        "oid",
-        "zeroize",
-    ],
-    rustlibs: [
-        "libconst_oid",
-        "libflagset",
-        "libzeroize",
-    ],
-    proc_macros: ["libder_derive"],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.virt",
-    ],
-    product_available: true,
-    vendor_available: true,
-    visibility: [
-        "//external/rust/crates/sec1:__subpackages__",
-        "//external/rust/crates/spki:__subpackages__",
-        "//external/rust/crates/pkcs1:__subpackages__",
-        "//external/rust/crates/pkcs8:__subpackages__",
-        "//external/rust/crates/x509-cert:__subpackages__",
-        "//packages/modules/Virtualization:__subpackages__",
-        "//system/keymint:__subpackages__",
-    ],
-
-}
-
-rust_library_rlib {
-    name: "libder_nostd",
-    crate_name: "der",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.7.8",
-    crate_root: "src/lib.rs",
-    edition: "2021",
-    features: [
-        "alloc",
-        "derive",
-        "flagset",
-        "oid",
-        "zeroize",
-    ],
-    rustlibs: [
-        "libconst_oid_nostd",
-        "libflagset_nostd",
-        "libzeroize_nostd",
-    ],
-    proc_macros: ["libder_derive"],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.virt",
-    ],
-    prefer_rlib: true,
-    no_stdlibs: true,
-    stdlibs: [
-        "liballoc.rust_sysroot",
-        "libcompiler_builtins.rust_sysroot",
-        "libcore.rust_sysroot",
-    ],
-    product_available: true,
-    vendor_available: true,
-    visibility: [
-        "//external/rust/crates/sec1:__subpackages__",
-        "//external/rust/crates/spki:__subpackages__",
-        "//external/rust/crates/pkcs1:__subpackages__",
-        "//external/rust/crates/pkcs8:__subpackages__",
-        "//external/rust/crates/x509-cert:__subpackages__",
-        "//packages/modules/Virtualization:__subpackages__",
-        "//system/keymint:__subpackages__",
-    ],
-
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/cargo2android_viz.bp b/cargo2android_viz.bp
deleted file mode 100644
index 02cda1f..0000000
--- a/cargo2android_viz.bp
+++ /dev/null
@@ -1,9 +0,0 @@
-visibility: [
-     "//external/rust/crates/sec1:__subpackages__",
-     "//external/rust/crates/spki:__subpackages__",
-     "//external/rust/crates/pkcs1:__subpackages__",
-     "//external/rust/crates/pkcs8:__subpackages__",
-     "//external/rust/crates/x509-cert:__subpackages__",
-     "//packages/modules/Virtualization:__subpackages__",
-     "//system/keymint:__subpackages__",
-]
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index ca989f0..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,41 +0,0 @@
-{
-  "apex_available": [
-    "//apex_available:platform",
-    "com.android.virt"
-  ],
-  "features": [
-    "alloc",
-    "derive",
-    "flagset",
-    "oid",
-    "zeroize"
-  ],
-  "vendor_available": true,
-  "run_cargo": false,
-  "variants": [
-    {
-      "package": {
-        "der": {
-          "add_module_block": "cargo2android_viz.bp"
-        }
-      }
-    },
-    {
-      "module_name_overrides": {
-        "libconst_oid": "libconst_oid_nostd",
-        "libder": "libder_nostd",
-        "libflagset": "libflagset_nostd",
-        "libzeroize": "libzeroize_nostd"
-      },
-      "package": {
-        "der": {
-          "add_module_block": "cargo2android_viz.bp",
-          "alloc": true,
-          "force_rlib": true,
-          "host_supported": false,
-          "no_std": true
-        }
-      }
-    }
-  ]
-}
```

