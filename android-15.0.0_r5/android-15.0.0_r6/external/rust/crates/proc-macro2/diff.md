```diff
diff --git a/Android.bp b/Android.bp
index e3d6582..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,241 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_applicable_licenses: ["external_rust_crates_proc-macro2_license"],
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
-    name: "external_rust_crates_proc-macro2_license",
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
-rust_library_host {
-    name: "libproc_macro2",
-    crate_name: "proc_macro2",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.69",
-    crate_root: "src/lib.rs",
-    edition: "2021",
-    features: [
-        "default",
-        "proc-macro",
-        "span-locations",
-    ],
-    cfgs: [
-        "proc_macro_span",
-        "span_locations",
-        "wrap_proc_macro",
-    ],
-    rustlibs: ["libunicode_ident"],
-    compile_multilib: "first",
-}
-
-rust_test_host {
-    name: "proc-macro2_test_tests_comments",
-    crate_name: "comments",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.69",
-    crate_root: "tests/comments.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2021",
-    features: [
-        "default",
-        "proc-macro",
-        "span-locations",
-    ],
-    cfgs: [
-        "proc_macro_span",
-        "span_locations",
-        "wrap_proc_macro",
-    ],
-    rustlibs: [
-        "libproc_macro2",
-        "libquote",
-        "libunicode_ident",
-    ],
-    proc_macros: ["librustversion"],
-}
-
-rust_test_host {
-    name: "proc-macro2_test_tests_features",
-    crate_name: "features",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.69",
-    crate_root: "tests/features.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2021",
-    features: [
-        "default",
-        "proc-macro",
-        "span-locations",
-    ],
-    cfgs: [
-        "proc_macro_span",
-        "span_locations",
-        "wrap_proc_macro",
-    ],
-    rustlibs: [
-        "libproc_macro2",
-        "libquote",
-        "libunicode_ident",
-    ],
-    proc_macros: ["librustversion"],
-}
-
-rust_test_host {
-    name: "proc-macro2_test_tests_marker",
-    crate_name: "marker",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.69",
-    crate_root: "tests/marker.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2021",
-    features: [
-        "default",
-        "proc-macro",
-        "span-locations",
-    ],
-    cfgs: [
-        "proc_macro_span",
-        "span_locations",
-        "wrap_proc_macro",
-    ],
-    rustlibs: [
-        "libproc_macro2",
-        "libquote",
-        "libunicode_ident",
-    ],
-    proc_macros: ["librustversion"],
-}
-
-rust_test_host {
-    name: "proc-macro2_test_tests_test",
-    crate_name: "test",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.69",
-    crate_root: "tests/test.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2021",
-    features: [
-        "default",
-        "proc-macro",
-        "span-locations",
-    ],
-    cfgs: [
-        "proc_macro_span",
-        "span_locations",
-        "wrap_proc_macro",
-    ],
-    rustlibs: [
-        "libproc_macro2",
-        "libquote",
-        "libunicode_ident",
-    ],
-    proc_macros: ["librustversion"],
-}
-
-rust_test_host {
-    name: "proc-macro2_test_tests_test_fmt",
-    crate_name: "test_fmt",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.69",
-    crate_root: "tests/test_fmt.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2021",
-    features: [
-        "default",
-        "proc-macro",
-        "span-locations",
-    ],
-    cfgs: [
-        "proc_macro_span",
-        "span_locations",
-        "wrap_proc_macro",
-    ],
-    rustlibs: [
-        "libproc_macro2",
-        "libquote",
-        "libunicode_ident",
-    ],
-    proc_macros: ["librustversion"],
-}
-
-rust_test_host {
-    name: "proc-macro2_test_tests_test_size",
-    crate_name: "test_size",
-    cargo_env_compat: true,
-    cargo_pkg_version: "1.0.69",
-    crate_root: "tests/test_size.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2021",
-    features: [
-        "default",
-        "proc-macro",
-        "span-locations",
-    ],
-    cfgs: [
-        "proc_macro_span",
-        "span_locations",
-        "wrap_proc_macro",
-    ],
-    rustlibs: [
-        "libproc_macro2",
-        "libquote",
-        "libunicode_ident",
-    ],
-    proc_macros: ["librustversion"],
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index 7c46892..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,167 +0,0 @@
-// Generated by update_crate_tests.py for tests that depend on this crate.
-{
-  "imports": [
-    {
-      "path": "external/rust/crates/anyhow"
-    },
-    {
-      "path": "external/rust/crates/arbitrary"
-    },
-    {
-      "path": "external/rust/crates/argh"
-    },
-    {
-      "path": "external/rust/crates/async-stream"
-    },
-    {
-      "path": "external/rust/crates/base64"
-    },
-    {
-      "path": "external/rust/crates/bitflags"
-    },
-    {
-      "path": "external/rust/crates/bytes"
-    },
-    {
-      "path": "external/rust/crates/coset"
-    },
-    {
-      "path": "external/rust/crates/either"
-    },
-    {
-      "path": "external/rust/crates/futures-channel"
-    },
-    {
-      "path": "external/rust/crates/futures-executor"
-    },
-    {
-      "path": "external/rust/crates/futures-test"
-    },
-    {
-      "path": "external/rust/crates/futures-util"
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
-      "path": "external/rust/crates/libm"
-    },
-    {
-      "path": "external/rust/crates/libsqlite3-sys"
-    },
-    {
-      "path": "external/rust/crates/oid-registry"
-    },
-    {
-      "path": "external/rust/crates/rand_chacha"
-    },
-    {
-      "path": "external/rust/crates/serde"
-    },
-    {
-      "path": "external/rust/crates/serde-xml-rs"
-    },
-    {
-      "path": "external/rust/crates/serde_cbor"
-    },
-    {
-      "path": "external/rust/crates/slab"
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
-      "path": "external/rust/crates/unicode-bidi"
-    },
-    {
-      "path": "external/rust/crates/unicode-xid"
-    },
-    {
-      "path": "external/rust/crates/url"
-    },
-    {
-      "path": "external/rust/crates/virtio-drivers"
-    },
-    {
-      "path": "external/rust/crates/zerocopy"
-    },
-    {
-      "path": "external/rust/crates/zeroize"
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
-  ]
-}
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index a64c9e4..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,13 +0,0 @@
-{
-  "features": [
-    "default",
-    "span-locations"
-  ],
-  "package": {
-    "proc-macro2": {
-      "device_supported": false,
-      "host_first_multilib": true
-    }
-  },
-  "tests": true
-}
```

