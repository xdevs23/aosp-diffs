```diff
diff --git a/Android.bp b/Android.bp
index 431d96e..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,39 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-package {
-    default_team: "trendy_team_android_rust",
-}
-
-rust_library {
-    name: "libtermtree",
-    host_supported: true,
-    crate_name: "termtree",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.4.1",
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
-    name: "termtree_test_src_lib",
-    host_supported: true,
-    crate_name: "termtree",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.4.1",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index d40889a..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-    "run_cargo": false,
-    "tests": true
-}
```

