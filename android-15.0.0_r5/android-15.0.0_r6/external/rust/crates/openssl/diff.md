```diff
diff --git a/Android.bp b/Android.bp
index 7cf2f35..7cf38a3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -51,23 +51,24 @@ rust_library {
     name: "libopenssl",
     visibility: [
         ":__subpackages__",
+        "//packages/modules/Virtualization/android/virtualizationservice",
+        "//packages/modules/Virtualization/guest/authfs",
+        "//packages/modules/Virtualization/guest/authfs/src/fsverity/metadata",
+        "//packages/modules/Virtualization/guest/microdroid_manager",
+        "//packages/modules/Virtualization/guest/pvmfw/avb",
         "//packages/modules/Virtualization/libs/apkverify",
-        "//packages/modules/Virtualization/authfs",
-        "//packages/modules/Virtualization/service_vm/client_vm_csr",
-        "//packages/modules/Virtualization/virtualizationservice",
-        "//system/security/keystore2/tests",
-        "//system/authgraph/boringssl",
         "//packages/modules/Virtualization/libs/dice/driver",
-        "//packages/modules/Virtualization/authfs/src/fsverity/metadata",
-        "//tools/security/remote_provisioning/hwtrust",
-        "//packages/modules/Virtualization/pvmfw/avb",
-        "//packages/modules/Virtualization/microdroid_manager",
+        "//packages/modules/Virtualization/libs/libclient_vm_csr",
+        "//packages/modules/Virtualization/libs/libvm_payload",
+        "//packages/modules/Virtualization/tests/authfs",
+        "//system/authgraph/boringssl",
         "//system/keymint/boringssl",
-        "//tools/netsim",
-        "//packages/modules/Virtualization/vm_payload",
+        "//system/security/keystore2/tests",
+        "//system/software_defined_vehicle/core_services/service_authn",
         "//system/software_defined_vehicle/core_services/service_discovery/sdv_sd_agent",
         "//system/software_defined_vehicle/core_services/vsidl/middleware/rpc/transport/grpc",
-        "//system/software_defined_vehicle/core_services/service_authn",
+        "//tools/netsim",
+        "//tools/security/remote_provisioning/hwtrust",
         "//vendor:__subpackages__",
     ],
     host_supported: true,
diff --git a/cargo_embargo.json b/cargo_embargo.json
index c2f3caa..0505b35 100644
--- a/cargo_embargo.json
+++ b/cargo_embargo.json
@@ -13,6 +13,29 @@
     }
   },
   "run_cargo": false,
+  "module_visibility": {
+    "libopenssl": [
+        ":__subpackages__",
+        "//packages/modules/Virtualization/libs/apkverify",
+        "//packages/modules/Virtualization/authfs",
+        "//packages/modules/Virtualization/service_vm/client_vm_csr",
+        "//packages/modules/Virtualization/virtualizationservice",
+        "//system/security/keystore2/tests",
+        "//system/authgraph/boringssl",
+        "//packages/modules/Virtualization/libs/dice/driver",
+        "//packages/modules/Virtualization/authfs/src/fsverity/metadata",
+        "//tools/security/remote_provisioning/hwtrust",
+        "//packages/modules/Virtualization/pvmfw/avb",
+        "//packages/modules/Virtualization/microdroid_manager",
+        "//system/keymint/boringssl",
+        "//tools/netsim",
+        "//packages/modules/Virtualization/vm_payload",
+        "//system/software_defined_vehicle/core_services/service_discovery/sdv_sd_agent",
+        "//system/software_defined_vehicle/core_services/vsidl/middleware/rpc/transport/grpc",
+        "//system/software_defined_vehicle/core_services/service_authn",
+        "//vendor:__subpackages__"
+    ]
+  },
   "variants": [
     {
       "module_name_overrides": {
```

