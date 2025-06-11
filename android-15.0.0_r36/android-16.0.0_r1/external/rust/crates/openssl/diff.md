```diff
diff --git a/Android.bp b/Android.bp
index 4219f0b..e358a0f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -60,10 +60,11 @@ rust_library {
         "//system/security/keystore2/tests",
         "//system/software_defined_vehicle/core_services/crypto_rpc",
         "//system/software_defined_vehicle/core_services/sdv_comms/sdk",
-        "//system/software_defined_vehicle/core_services/service_authn",
         "//system/software_defined_vehicle/core_services/service_discovery/sdv_sd_agent",
         "//system/software_defined_vehicle/core_services/service_discovery/vvmtruststore",
+        "//system/software_defined_vehicle/core_services/third_party/hwtrust_private_key",
         "//system/software_defined_vehicle/core_services/vsidl/middleware/rpc/transport/grpc",
+        "//system/software_defined_vehicle/platform/init_open_dice",
         "//tools/netsim",
         "//tools/security/remote_provisioning/hwtrust",
         "//vendor:__subpackages__",
diff --git a/cargo_embargo.json b/cargo_embargo.json
index f34c11b..27830fc 100644
--- a/cargo_embargo.json
+++ b/cargo_embargo.json
@@ -35,10 +35,10 @@
         "//system/security/keystore2/tests",
         "//system/software_defined_vehicle/core_services/crypto_rpc",
         "//system/software_defined_vehicle/core_services/sdv_comms/sdk",
-        "//system/software_defined_vehicle/core_services/service_authn",
         "//system/software_defined_vehicle/core_services/service_discovery/sdv_sd_agent",
         "//system/software_defined_vehicle/core_services/service_discovery/vvmtruststore",
         "//system/software_defined_vehicle/core_services/vsidl/middleware/rpc/transport/grpc",
+        "//system/software_defined_vehicle/platform/init_open_dice",
         "//tools/netsim",
         "//tools/security/remote_provisioning/hwtrust",
         "//vendor:__subpackages__"
```

