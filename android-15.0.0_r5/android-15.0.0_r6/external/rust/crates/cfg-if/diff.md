```diff
diff --git a/Android.bp b/Android.bp
index dd16711..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,88 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_cfg-if_license"],
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
-    name: "external_rust_crates_cfg-if_license",
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
-    name: "cfg-if_test_src_lib",
-    host_supported: true,
-    crate_name: "cfg_if",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.0",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-}
-
-rust_test {
-    name: "cfg-if_test_tests_xcrate",
-    host_supported: true,
-    crate_name: "xcrate",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.0",
-    crate_root: "tests/xcrate.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    rustlibs: ["libcfg_if"],
-}
-
-rust_library {
-    name: "libcfg_if",
-    host_supported: true,
-    crate_name: "cfg_if",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.0",
-    crate_root: "src/lib.rs",
-    edition: "2018",
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
index 1f7fb90..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,201 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "external/rust/crates/android_logger"
-    },
-    {
-      "path": "external/rust/crates/ash"
-    },
-    {
-      "path": "external/rust/crates/async-stream"
-    },
-    {
-      "path": "external/rust/crates/base64"
-    },
-    {
-      "path": "external/rust/crates/cast"
-    },
-    {
-      "path": "external/rust/crates/crc32fast"
-    },
-    {
-      "path": "external/rust/crates/crossbeam-deque"
-    },
-    {
-      "path": "external/rust/crates/crossbeam-epoch"
-    },
-    {
-      "path": "external/rust/crates/crossbeam-queue"
-    },
-    {
-      "path": "external/rust/crates/crossbeam-utils"
-    },
-    {
-      "path": "external/rust/crates/env_logger"
-    },
-    {
-      "path": "external/rust/crates/flate2"
-    },
-    {
-      "path": "external/rust/crates/futures-util"
-    },
-    {
-      "path": "external/rust/crates/gdbstub_arch"
-    },
-    {
-      "path": "external/rust/crates/getrandom"
-    },
-    {
-      "path": "external/rust/crates/hashbrown"
-    },
-    {
-      "path": "external/rust/crates/hashlink"
-    },
-    {
-      "path": "external/rust/crates/jni"
-    },
-    {
-      "path": "external/rust/crates/libsqlite3-sys"
-    },
-    {
-      "path": "external/rust/crates/mio"
-    },
-    {
-      "path": "external/rust/crates/once_cell"
-    },
-    {
-      "path": "external/rust/crates/parking_lot_core"
-    },
-    {
-      "path": "external/rust/crates/quiche"
-    },
-    {
-      "path": "external/rust/crates/quickcheck"
-    },
-    {
-      "path": "external/rust/crates/rand_chacha"
-    },
-    {
-      "path": "external/rust/crates/rand_core"
-    },
-    {
-      "path": "external/rust/crates/rand_xorshift"
-    },
-    {
-      "path": "external/rust/crates/regex"
-    },
-    {
-      "path": "external/rust/crates/ryu"
-    },
-    {
-      "path": "external/rust/crates/serde-xml-rs"
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
-      "path": "external/rust/crates/tokio-test"
-    },
-    {
-      "path": "external/rust/crates/unicode-xid"
-    },
-    {
-      "path": "external/rust/crates/virtio-drivers"
-    },
-    {
-      "path": "external/rust/crates/vulkano"
-    },
-    {
-      "path": "external/rust/crates/zerocopy"
-    },
-    {
-      "path": "external/uwb/src"
-    },
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
-      "path": "packages/modules/Virtualization/libs/apexutil"
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
-      "path": "system/keymint/derive"
-    },
-    {
-      "path": "system/keymint/hal"
-    },
-    {
-      "path": "system/logging/rust"
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
-    },
-    {
-      "path": "system/security/keystore2/src/crypto"
-    }
-  ],
-  "presubmit": [
-    {
-      "name": "cfg-if_test_src_lib"
-    },
-    {
-      "name": "cfg-if_test_tests_xcrate"
-    }
-  ],
-  "presubmit-rust": [
-    {
-      "name": "cfg-if_test_src_lib"
-    },
-    {
-      "name": "cfg-if_test_tests_xcrate"
-    }
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index 16616e0..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,5 +0,0 @@
-{
-  "min_sdk_version": "29",
-  "run_cargo": false,
-  "tests": true
-}
```
