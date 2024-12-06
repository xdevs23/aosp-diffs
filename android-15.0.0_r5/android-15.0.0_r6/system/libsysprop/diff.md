```diff
diff --git a/srcs/android/sysprop/BluetoothProperties.sysprop b/srcs/android/sysprop/BluetoothProperties.sysprop
index c1daafd..e307b79 100644
--- a/srcs/android/sysprop/BluetoothProperties.sysprop
+++ b/srcs/android/sysprop/BluetoothProperties.sysprop
@@ -410,6 +410,16 @@ prop {
     prop_name: "bluetooth.profile.hfp.hf.enabled"
 }
 
+# Whether Bluetooth HFP software datapath is enabled.
+# Set by vendors overlay, read at Bluetooth initialization
+prop {
+    api_name: "isHfpSoftwareDatapathEnabled"
+    type: Boolean
+    scope: Public
+    access: Readonly
+    prop_name: "bluetooth.hfp.software_datapath.enabled"
+}
+
 # Whether the Human Interface Device Profile (HID) device role is enabled on this device.
 # Set by vendors overlay, read at Bluetooth initialization
 prop {
@@ -805,3 +815,22 @@ prop {
     access: Readonly
     prop_name: "bluetooth.sco.managed_by_audio"
 }
+
+# Determine if sniff mode is handled in AP or MCU
+prop {
+    api_name: "enable_sniff_offload"
+    type: Boolean
+    scope: Public
+    access: Readonly
+    prop_name: "persist.bluetooth.sniff_offload.enabled"
+    integer_as_bool: true
+}
+
+# Determines if MSFT HCI ext should be used for LE Scanning
+prop {
+    api_name: "isMsftHciExtEnabled"
+    type: Boolean
+    scope: Internal
+    access: Readonly
+    prop_name: "bluetooth.core.le.use_msft_hci_ext"
+}
diff --git a/srcs/android/sysprop/NfcProperties.sysprop b/srcs/android/sysprop/NfcProperties.sysprop
index e4db344..52c9920 100644
--- a/srcs/android/sysprop/NfcProperties.sysprop
+++ b/srcs/android/sysprop/NfcProperties.sysprop
@@ -56,3 +56,59 @@ prop {
     access: ReadWrite
     prop_name: "nfc.initialized"
 }
+
+prop {
+    api_name: "info_antpos_X"
+    type: IntegerList
+    scope: Public
+    access: Readonly
+    prop_name: "ro.nfc.info.antpos.X"
+}
+
+prop {
+    api_name: "info_antpos_Y"
+    type: IntegerList
+    scope: Public
+    access: Readonly
+    prop_name: "ro.nfc.info.antpos.Y"
+}
+
+prop {
+    api_name: "info_antpos_device_width"
+    type: Integer
+    scope: Public
+    access: Readonly
+    prop_name: "ro.nfc.info.antpos.device_width"
+}
+
+prop {
+    api_name: "info_antpos_device_height"
+    type: Integer
+    scope: Public
+    access: Readonly
+    prop_name: "ro.nfc.info.antpos.device_height"
+}
+
+prop {
+    api_name: "info_antpos_device_foldable"
+    type: Boolean
+    scope: Public
+    access: Readonly
+    prop_name: "ro.nfc.info.antpos.device_foldable"
+}
+
+prop {
+    api_name: "observe_mode_supported"
+    type: Boolean
+    scope: Public
+    access: Readonly
+    prop_name: "ro.nfc.observe_mode_supported"
+}
+
+prop {
+    api_name: "get_caps_supported"
+    type: Boolean
+    scope: Public
+    access: Readonly
+    prop_name: "ro.nfc.get_caps_supported"
+}
diff --git a/srcs/android/sysprop/SensorProperties.sysprop b/srcs/android/sysprop/SensorProperties.sysprop
new file mode 100644
index 0000000..fe739a9
--- /dev/null
+++ b/srcs/android/sysprop/SensorProperties.sysprop
@@ -0,0 +1,26 @@
+# Copyright (C) 2018 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+module: "android.sysprop.SensorProperties"
+owner: Platform
+
+# Whether the device has a high quality barometer as defined on the CDD.
+# Set by OEMs, read for xTS verifier tests
+prop {
+    api_name: "isHighQualityBarometerImplemented"
+    type: Boolean
+    scope: Internal
+    access: Readonly
+    prop_name: "sensor.barometer.high_quality.implemented"
+}
diff --git a/srcs/android/sysprop/TelephonyProperties.sysprop b/srcs/android/sysprop/TelephonyProperties.sysprop
index 15999e7..e74f450 100644
--- a/srcs/android/sysprop/TelephonyProperties.sysprop
+++ b/srcs/android/sysprop/TelephonyProperties.sysprop
@@ -312,7 +312,7 @@ prop {
 
 #
 # Set to false to disable SMS receiving, default is
-# the value of config_sms_capable
+# the value of TelephonyManager.isDeviceSmsCapable()
 # Indexed by phone ID
 #
 prop {
@@ -325,7 +325,7 @@ prop {
 
 #
 # Set to false to disable SMS sending, default is
-# the value of config_sms_capable
+# the value of TelephonyManager.isDeviceSmsCapable()
 # Indexed by phone ID
 #
 prop {
diff --git a/srcs/api/PlatformProperties-current.txt b/srcs/api/PlatformProperties-current.txt
index d6a2e7c..e54d05c 100644
--- a/srcs/api/PlatformProperties-current.txt
+++ b/srcs/api/PlatformProperties-current.txt
@@ -14,6 +14,11 @@ props {
     type: StringList
     prop_name: "bluetooth.core.le.dsa_transport_preference"
   }
+  prop {
+    api_name: "enable_sniff_offload"
+    prop_name: "persist.bluetooth.sniff_offload.enabled"
+    integer_as_bool: true
+  }
   prop {
     api_name: "factory_reset"
     access: ReadWrite
@@ -77,6 +82,10 @@ props {
     api_name: "isGapLePrivacyEnabled"
     prop_name: "bluetooth.core.gap.le.privacy.enabled"
   }
+  prop {
+    api_name: "isHfpSoftwareDatapathEnabled"
+    prop_name: "bluetooth.hfp.software_datapath.enabled"
+  }
   prop {
     api_name: "isLeAudioCodecExtensionAidlEnabled"
     prop_name: "bluetooth.core.le_audio.codec_extension_aidl.enabled"
@@ -346,11 +355,43 @@ props {
     access: ReadWrite
     prop_name: "persist.nfc.debug_enabled"
   }
+  prop {
+    api_name: "get_caps_supported"
+    prop_name: "ro.nfc.get_caps_supported"
+  }
+  prop {
+    api_name: "info_antpos_X"
+    type: IntegerList
+    prop_name: "ro.nfc.info.antpos.X"
+  }
+  prop {
+    api_name: "info_antpos_Y"
+    type: IntegerList
+    prop_name: "ro.nfc.info.antpos.Y"
+  }
+  prop {
+    api_name: "info_antpos_device_foldable"
+    prop_name: "ro.nfc.info.antpos.device_foldable"
+  }
+  prop {
+    api_name: "info_antpos_device_height"
+    type: Integer
+    prop_name: "ro.nfc.info.antpos.device_height"
+  }
+  prop {
+    api_name: "info_antpos_device_width"
+    type: Integer
+    prop_name: "ro.nfc.info.antpos.device_width"
+  }
   prop {
     api_name: "initialized"
     access: ReadWrite
     prop_name: "nfc.initialized"
   }
+  prop {
+    api_name: "observe_mode_supported"
+    prop_name: "ro.nfc.observe_mode_supported"
+  }
   prop {
     api_name: "skipNdefRead"
     prop_name: "nfc.dta.skip_ndef_read"
```

