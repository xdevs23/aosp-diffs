```diff
diff --git a/Android.bp b/Android.bp
index 7daf998..96beb97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,46 +1 @@
-// This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
-
-// TODO: Add license.
-rust_test {
-    name: "errno_test_src_lib",
-    host_supported: true,
-    crate_name: "errno",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.3.8",
-    crate_root: "src/lib.rs",
-    test_suites: ["general-tests"],
-    auto_gen_config: true,
-    test_options: {
-        unit_test: true,
-    },
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: ["liblibc"],
-}
-
-rust_library {
-    name: "liberrno",
-    host_supported: true,
-    crate_name: "errno",
-    cargo_env_compat: true,
-    cargo_pkg_version: "0.3.8",
-    crate_root: "src/lib.rs",
-    edition: "2018",
-    features: [
-        "default",
-        "std",
-    ],
-    rustlibs: ["liblibc"],
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
-    product_available: true,
-    vendor_available: true,
-}
+// This crate has been migrated to external/rust/android-crates-io.
diff --git a/OWNERS b/OWNERS
index 697f117..37be8d1 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,5 +3,4 @@ include platform/prebuilts/rust:main:/OWNERS
 
 dextero@google.com
 vill@google.com
-nputikhin@google.com
 istvannador@google.com
diff --git a/cargo_embargo.json b/cargo_embargo.json
deleted file mode 100644
index c8842d1..0000000
--- a/cargo_embargo.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-  "run_cargo": false,
-  "tests": true
-}
```

