```diff
diff --git a/Android.bp b/Android.bp
index ab2d598..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,22 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-// TODO: Add license.
-rust_library {
-    name: "libfs_err",
-    host_supported: true,
-    crate_name: "fs_err",
-    cargo_env_compat: true,
-    cargo_pkg_version: "2.11.0",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    cfgs: ["rustc_1_63"],
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
index 0967ef4..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1 +0,0 @@
-{}
```

