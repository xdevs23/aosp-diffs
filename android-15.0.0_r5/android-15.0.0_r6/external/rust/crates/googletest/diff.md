```diff
diff --git a/Android.bp b/Android.bp
index 3afe244..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,28 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-rust_library {
-    name: "libgoogletest_rust",
-    host_supported: true,
-    crate_name: "googletest",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.11.0",
-    crate_root: "src/lib.rs",
-    edition: "2021",
-    rustlibs: [
-        "libnum_traits",
-        "libregex",
-    ],
-    proc_macros: [
-        "libgoogletest_macro",
-        "librustversion",
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
index bccaabe..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,6 +0,0 @@
-{
-  "module_name_overrides": {
-    "libgoogletest": "libgoogletest_rust"
-  },
-  "run_cargo": false
-}
```
