```diff
diff --git a/OWNERS b/OWNERS
index efe940c..a2600b4 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,2 @@
 mewan@google.com
 cey@google.com
-akaustubh@google.com
diff --git a/proto/carrier_settings.proto b/proto/carrier_settings.proto
index 5a18c24..45aa13b 100644
--- a/proto/carrier_settings.proto
+++ b/proto/carrier_settings.proto
@@ -147,6 +147,29 @@ message ApnItem {
     SKIP_464XLAT_ENABLE = 2;
   }
   optional Xlat skip_464xlat = 26 [default = SKIP_464XLAT_DEFAULT];
+
+  // Lingering network types for this APN, separated by "|". A network type
+  // is represented as an integer defined in TelephonyManager.NETWORK_TYPE_*.
+  optional string lingering_network_type_bitmask = 27;
+
+  // Whether the PDU session brought up by this APN should always be on.
+  optional bool always_on = 28 [default = false];
+
+  // IPv6 MTU for the connections.
+  // This is a backup value when network doesn't specify one.
+  optional int32 mtu_v6 = 29 [default = 0];
+
+  // The infrastructure bitmask which the APN can be used on. For example,
+  // some APNs can only be used when the device is on cellular, on satellite,
+  // or both. The default value is 3 (INFRASTRUCTURE_CELLULAR |
+  // INFRASTRUCTURE_SATELLITE).
+  optional int32 infrastructure_bitmask = 30 [default = 3];
+
+  // Indicates if the APN is used for eSIM bootsrap provisioning.
+  // Valid values are:
+  // 0: Not used for eSIM bootstrap provisioning (default).
+  // 1: Used for eSIM bootstrap provisioning.
+  optional int32 esim_bootstrap_provisioning = 31 [default = 0];
 }
 
 // A collection of all APNs for a carrier
```

