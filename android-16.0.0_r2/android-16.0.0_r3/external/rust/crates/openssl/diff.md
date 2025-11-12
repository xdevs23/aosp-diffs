```diff
diff --git a/Android.bp b/Android.bp
index e358a0f..5d8c2f2 100644
--- a/Android.bp
+++ b/Android.bp
@@ -58,6 +58,7 @@ rust_library {
         "//system/authgraph/boringssl",
         "//system/keymint/boringssl",
         "//system/security/keystore2/tests",
+        "//system/security/keystore2/tests/keystore-engine",
         "//system/software_defined_vehicle/core_services/crypto_rpc",
         "//system/software_defined_vehicle/core_services/sdv_comms/sdk",
         "//system/software_defined_vehicle/core_services/service_discovery/sdv_sd_agent",
diff --git a/cargo_embargo.json b/cargo_embargo.json
index 27830fc..d9a36c0 100644
--- a/cargo_embargo.json
+++ b/cargo_embargo.json
@@ -33,6 +33,7 @@
         "//system/authgraph/boringssl",
         "//system/keymint/boringssl",
         "//system/security/keystore2/tests",
+        "//system/security/keystore2/tests/keystore-engine",
         "//system/software_defined_vehicle/core_services/crypto_rpc",
         "//system/software_defined_vehicle/core_services/sdv_comms/sdk",
         "//system/software_defined_vehicle/core_services/service_discovery/sdv_sd_agent",
```

