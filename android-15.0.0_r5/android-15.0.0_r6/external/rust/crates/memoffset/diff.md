```diff
diff --git a/Android.bp b/Android.bp
index 0e2b0de..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,104 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_memoffset_license"],
-}
-
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
-license {
-    name: "external_rust_crates_memoffset_license",
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
-    name: "libmemoffset",
-    host_supported: true,
-    crate_name: "memoffset",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.9.0",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: ["default"],
-    cfgs: [
-        "allow_clippy",
-        "aosp_force_use_std",
-        "doctests",
-        "maybe_uninit",
-        "raw_ref_macros",
-        "stable_const",
-        "tuple_ty",
-    ],
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
-    product_available: true,
-    vendor_available: true,
-    min_sdk_version: "29",
-}
-
-rust_test {
-    name: "memoffset_test_src_lib",
-    host_supported: true,
-    crate_name: "memoffset",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.9.0",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: ["default"],
-    cfgs: [
-        "allow_clippy",
-        "aosp_force_use_std",
-        "doctests",
-        "maybe_uninit",
-        "raw_ref_macros",
-        "stable_const",
-        "tuple_ty",
-    ],
-}
-
-rust_library_rlib {
-    name: "libmemoffset_nostd",
-    crate_name: "memoffset",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.9.0",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: ["default"],
-    cfgs: [
-        "allow_clippy",
-        "doctests",
-        "maybe_uninit",
-        "raw_ref_macros",
-        "stable_const",
-        "tuple_ty",
-    ],
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
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
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index 448ea8a..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,78 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "external/rust/crates/base64"
-    },
-    {
-      "path": "external/rust/crates/crossbeam-deque"
-    },
-    {
-      "path": "external/rust/crates/crossbeam-epoch"
-    },
-    {
-      "path": "external/rust/crates/hashbrown"
-    },
-    {
-      "path": "external/rust/crates/tinytemplate"
-    },
-    {
-      "path": "external/rust/crates/tinyvec"
-    },
-    {
-      "path": "external/rust/crates/tokio"
-    },
-    {
-      "path": "external/rust/crates/unicode-xid"
-    },
-    {
-      "path": "packages/modules/Virtualization/apkdmverity"
-    },
-    {
-      "path": "packages/modules/Virtualization/authfs"
-    },
-    {
-      "path": "packages/modules/Virtualization/encryptedstore"
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
-      "path": "system/security/diced"
-    },
-    {
-      "path": "system/security/keystore2"
-    },
-    {
-      "path": "system/security/keystore2/legacykeystore"
-    },
-    {
-      "path": "system/security/keystore2/src/crypto"
-    }
-  ],
-  "presubmit": [
-    {
-      "name": "memoffset_test_src_lib"
-    }
-  ],
-  "presubmit-rust": [
-    {
-      "name": "memoffset_test_src_lib"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index a503b0a..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,31 +0,0 @@
-{
-  "package": {
-    "memoffset": {
-      "dep_blocklist": [
-        "libdoc_comment"
-      ]
-    }
-  },
-  "variants": [
-    {
-      "min_sdk_version": "29",
-      "extra_cfg": [
-        "aosp_force_use_std"
-      ],
-      "tests": true
-    },
-    {
-      "module_name_overrides": {
-        "libmemoffset": "libmemoffset_nostd"
-      },
-      "package": {
-        "memoffset": {
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
