```diff
diff --git a/srcs/android/sysprop/BluetoothProperties.sysprop b/srcs/android/sysprop/BluetoothProperties.sysprop
index 93ec6d0..56c8c7c 100644
--- a/srcs/android/sysprop/BluetoothProperties.sysprop
+++ b/srcs/android/sysprop/BluetoothProperties.sysprop
@@ -117,6 +117,15 @@ prop {
     prop_name: "persist.bluetooth.leaudio_dynamic_switcher.mode"
 }
 
+# Used to disable the HID device role at runtime
+prop {
+    api_name: "isProfileHidDeviceRuntimeDisabled"
+    type: Boolean
+    scope: Public
+    access: ReadWrite
+    prop_name: "persist.bluetooth.hid.device.disabled"
+}
+
 ######## Bluetooth configurations
 
 # Whether GAP BLE Privacy (RPA) is enabled on this device.
@@ -139,16 +148,6 @@ prop {
     prop_name: "bluetooth.core.gap.le.conn.min.limit"
 }
 
-# Whether LE Connection with initiating with only LE 1M PHY.
-# Set by vendors overlay, read at Bluetooth initialization
-prop {
-    api_name: "isGapLeConnOnlyInit1mPhyEnabled"
-    type: Boolean
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.gap.le.conn.only_init_1m_phy.enabled"
-}
-
 # Whether Inband ringtone for LeAudio is supported.
 # Set by vendors overlay, read at Bluetooth initialization
 prop {
@@ -582,74 +581,6 @@ prop {
     prop_name: "bluetooth.profile.vcp.controller.enabled"
 }
 
-# ACL Link supervision timeout
-prop {
-    api_name: "getLinkSupervisionTimeout"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.acl.link_supervision_timeout"
-}
-
-# The following values are used to load default adapter parameters for BR/EDR.
-# The Bluetooth Core Specification should be consulted for the meaning and valid
-# domain of each of these values.
-
-# BR/EDR Page scan activity configuration
-prop {
-    api_name: "getClassicPageScanType"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.classic.page_scan_type"
-}
-prop {
-    api_name: "getClassicPageScanInterval"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.classic.page_scan_interval"
-}
-prop {
-    api_name: "getClassicPageScanWindow"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.classic.page_scan_window"
-}
-
-# BR/EDR Inquiry scan activity configuration
-prop {
-    api_name: "getClassicInquiryScanType"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.classic.inq_scan_type"
-}
-prop {
-    api_name: "getClassicInquiryScanInterval"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.classic.inq_scan_interval"
-}
-prop {
-    api_name: "getClassicInquiryScanWindow"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.classic.inq_scan_window"
-}
-
-# BR/EDR Page Timeout
-prop {
-    api_name: "getClassicPageTimeout"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.classic.page_timeout"
-}
-
 # BR/EDR Sniff Parameters
 # Please refer to BTA_DM_PM_PARK_IDX in bta_api.h to determine how many
 # entries are currently being supported.
@@ -756,84 +687,6 @@ prop {
     prop_name: "bluetooth.core.le.aggressive_connection_threshold"
 }
 
-# Direct connection timeout in ms
-prop {
-    api_name: "getLeDirectConnectionTimeout"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.direct_connection_timeout"
-}
-
-# LE connection scan interval/window
-prop {
-    api_name: "getLeConnectionScanIntervalFast"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.connection_scan_interval_fast"
-}
-prop {
-    api_name: "getLeConnectionScanWindowFast"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.connection_scan_window_fast"
-}
-prop {
-    api_name: "getLeConnectionScanWindow2mFast"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.connection_scan_window_2m_fast"
-}
-prop {
-    api_name: "getLeConnectionScanWindowCodedFast"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.connection_scan_window_coded_fast"
-}
-prop {
-    api_name: "getLeConnectionScanIntervalSlow"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.connection_scan_interval_slow"
-}
-prop {
-    api_name: "getLeConnectionScanWindowSlow"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.connection_scan_window_slow"
-}
-
-# LE scanning parameters used during BTM inquiry
-prop {
-    api_name: "getLeInquiryScanInterval"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.inquiry_scan_interval"
-}
-prop {
-    api_name: "getLeInquiryScanWindow"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.inquiry_scan_window"
-}
-
-# Used to disable LeGetVendorCapabilities.
-prop {
-    api_name: "getLeVendorCapabilitiesEnabled"
-    type: Boolean
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.vendor_capabilities.enabled"
-}
-
 # Maximum number of number of allowed concurrent LE Connections
 prop {
     api_name: "getLeMaxNumberOfConcurrentConnections"
@@ -856,15 +709,6 @@ prop {
     prop_name: "bluetooth.core.le.dsa_transport_preference"
 }
 
-# Used to disable enhanced SCO connection
-prop {
-    api_name: "getDisableEnchancedConnection"
-    type: Boolean
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.sco.disable_enhanced_connection"
-}
-
 # Whether Bluetooth HFP SCO managed by Audio.
 # Set by vendors overlay, read at Bluetooth initialization
 prop {
@@ -884,21 +728,3 @@ prop {
     prop_name: "persist.bluetooth.sniff_offload.enabled"
     integer_as_bool: true
 }
-
-# Determines if MSFT HCI ext should be used for LE Scanning
-prop {
-    api_name: "isMsftHciExtEnabled"
-    type: Boolean
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.core.le.use_msft_hci_ext"
-}
-
-# MSFT HCI ext vendor opcode
-prop {
-    api_name: "getMsftVendorOpcode"
-    type: UInt
-    scope: Internal
-    access: Readonly
-    prop_name: "bluetooth.hci.msft_vendor_opcode"
-}
diff --git a/srcs/android/sysprop/NfcProperties.sysprop b/srcs/android/sysprop/NfcProperties.sysprop
index 52c9920..e90c6b9 100644
--- a/srcs/android/sysprop/NfcProperties.sysprop
+++ b/srcs/android/sysprop/NfcProperties.sysprop
@@ -112,3 +112,19 @@ prop {
     access: Readonly
     prop_name: "ro.nfc.get_caps_supported"
 }
+
+prop {
+    api_name: "fw_version"
+    type: String
+    scope: Public
+    access: ReadWrite
+    prop_name: "nfc.fw.ver"
+}
+
+prop {
+    api_name: "verbose_debug_enabled"
+    type: Boolean
+    scope: Public
+    access: ReadWrite
+    prop_name: "persist.nfc.verbose_debug_enabled"
+}
diff --git a/srcs/android/sysprop/OWNERS b/srcs/android/sysprop/OWNERS
index a8f2e4a..ad53604 100644
--- a/srcs/android/sysprop/OWNERS
+++ b/srcs/android/sysprop/OWNERS
@@ -1,2 +1,3 @@
 per-file CarProperties.sysprop = file:/CAR_OWNERS
 per-file InputProperties.sysprop = file:platform/frameworks/base:/INPUT_OWNERS
+per-file BluetoothProperties.sysprop = file:platform/packages/modules/Bluetooth:/sysprop/OWNERS
diff --git a/srcs/api/PlatformProperties-current.txt b/srcs/api/PlatformProperties-current.txt
index b6a8bc3..c186b2a 100644
--- a/srcs/api/PlatformProperties-current.txt
+++ b/srcs/api/PlatformProperties-current.txt
@@ -165,6 +165,11 @@ props {
     api_name: "isProfileHidDeviceEnabled"
     prop_name: "bluetooth.profile.hid.device.enabled"
   }
+  prop {
+    api_name: "isProfileHidDeviceRuntimeDisabled"
+    access: ReadWrite
+    prop_name: "persist.bluetooth.hid.device.disabled"
+  }
   prop {
     api_name: "isProfileHidHostEnabled"
     prop_name: "bluetooth.profile.hid.host.enabled"
@@ -416,6 +421,12 @@ props {
     access: ReadWrite
     prop_name: "persist.nfc.debug_enabled"
   }
+  prop {
+    api_name: "fw_version"
+    type: String
+    access: ReadWrite
+    prop_name: "nfc.fw.ver"
+  }
   prop {
     api_name: "get_caps_supported"
     prop_name: "ro.nfc.get_caps_supported"
@@ -470,6 +481,11 @@ props {
     access: ReadWrite
     prop_name: "persist.nfc.vendor_debug_enabled"
   }
+  prop {
+    api_name: "verbose_debug_enabled"
+    access: ReadWrite
+    prop_name: "persist.nfc.verbose_debug_enabled"
+  }
 }
 props {
   module: "android.sysprop.OtaProperties"
```

