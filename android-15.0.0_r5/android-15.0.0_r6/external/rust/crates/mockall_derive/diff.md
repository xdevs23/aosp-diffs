```diff
diff --git a/Android.bp b/Android.bp
index 8b13c83..3b8d4ee 100644
--- a/Android.bp
+++ b/Android.bp
@@ -24,6 +24,7 @@ rust_proc_macro {
 
 rust_test_host {
     name: "mockall_derive_test_src_lib",
+    host_cross_supported: false,
     crate_name: "mockall_derive",
     cargo_env_compat: true,
     cargo_pkg_version: "0.12.1",
```

