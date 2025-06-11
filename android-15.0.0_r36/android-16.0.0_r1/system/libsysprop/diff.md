```diff
diff --git a/srcs/Android.bp b/srcs/Android.bp
index e584604..1ac55ab 100644
--- a/srcs/Android.bp
+++ b/srcs/Android.bp
@@ -27,7 +27,7 @@ sysprop_library {
         "//apex_available:platform",
         "com.android.art",
         "com.android.art.debug",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.compos",
         "com.android.crashrecovery",
         "com.android.nfcservices",
diff --git a/srcs/android/sysprop/ApkVerityProperties.sysprop b/srcs/android/sysprop/ApkVerityProperties.sysprop
deleted file mode 100644
index ab7795c..0000000
--- a/srcs/android/sysprop/ApkVerityProperties.sysprop
+++ /dev/null
@@ -1,24 +0,0 @@
-# Copyright (C) 2019 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-owner: Platform
-module: "android.sysprop.ApkVerityProperties"
-
-prop {
-    api_name: "apk_verity_mode"
-    type: Integer
-    prop_name: "ro.apk_verity.mode"
-    scope: Public
-    access: Writeonce
-}
diff --git a/srcs/android/sysprop/BluetoothProperties.sysprop b/srcs/android/sysprop/BluetoothProperties.sysprop
index d6b8e4f..93ec6d0 100644
--- a/srcs/android/sysprop/BluetoothProperties.sysprop
+++ b/srcs/android/sysprop/BluetoothProperties.sysprop
@@ -105,6 +105,18 @@ prop {
     prop_name: "persist.bluetooth.leaudio.allow_list"
 }
 
+# LE audio modes
+# - "disabled"  - All LE audio feature off.
+# - "unicast"   - Unicast enabled only.
+# - "broadcast" - Unicast + broadcast enabled.
+prop {
+    api_name: "le_audio_dynamic_switcher_mode"
+    type: String
+    scope: Internal
+    access: ReadWrite
+    prop_name: "persist.bluetooth.leaudio_dynamic_switcher.mode"
+}
+
 ######## Bluetooth configurations
 
 # Whether GAP BLE Privacy (RPA) is enabled on this device.
@@ -707,6 +719,43 @@ prop {
     prop_name: "bluetooth.core.le.connection_supervision_timeout"
 }
 
+# LE connection intervals which replace the above (min/max)_connection_interval
+prop {
+    api_name: "getLeMinConnectionIntervalRelaxed"
+    type: UInt
+    scope: Internal
+    access: Readonly
+    prop_name: "bluetooth.core.le.min_connection_interval_relaxed"
+}
+prop {
+    api_name: "getLeMaxConnectionIntervalRelaxed"
+    type: UInt
+    scope: Internal
+    access: Readonly
+    prop_name: "bluetooth.core.le.max_connection_interval_relaxed"
+}
+prop {
+    api_name: "getLeMinConnectionIntervalAggressive"
+    type: UInt
+    scope: Internal
+    access: Readonly
+    prop_name: "bluetooth.core.le.min_connection_interval_aggressive"
+}
+prop {
+    api_name: "getLeMaxConnectionIntervalAggressive"
+    type: UInt
+    scope: Internal
+    access: Readonly
+    prop_name: "bluetooth.core.le.max_connection_interval_aggressive"
+}
+prop {
+    api_name: "getLeAggressiveConnectionThreshold"
+    type: UInt
+    scope: Internal
+    access: Readonly
+    prop_name: "bluetooth.core.le.aggressive_connection_threshold"
+}
+
 # Direct connection timeout in ms
 prop {
     api_name: "getLeDirectConnectionTimeout"
@@ -844,3 +893,12 @@ prop {
     access: Readonly
     prop_name: "bluetooth.core.le.use_msft_hci_ext"
 }
+
+# MSFT HCI ext vendor opcode
+prop {
+    api_name: "getMsftVendorOpcode"
+    type: UInt
+    scope: Internal
+    access: Readonly
+    prop_name: "bluetooth.hci.msft_vendor_opcode"
+}
diff --git a/srcs/api/PlatformProperties-current.txt b/srcs/api/PlatformProperties-current.txt
index ddd908b..b6a8bc3 100644
--- a/srcs/api/PlatformProperties-current.txt
+++ b/srcs/api/PlatformProperties-current.txt
@@ -1,12 +1,3 @@
-props {
-  module: "android.sysprop.ApkVerityProperties"
-  prop {
-    api_name: "apk_verity_mode"
-    type: Integer
-    access: Writeonce
-    prop_name: "ro.apk_verity.mode"
-  }
-}
 props {
   module: "android.sysprop.BackportedFixesProperties"
   prop {
diff --git a/srcs/api/PlatformProperties-latest.txt b/srcs/api/PlatformProperties-latest.txt
index 7ecf960..e19f4d2 100644
--- a/srcs/api/PlatformProperties-latest.txt
+++ b/srcs/api/PlatformProperties-latest.txt
@@ -7,15 +7,6 @@ props {
     prop_name: "ro.adb.secure"
   }
 }
-props {
-  module: "android.sysprop.ApkVerityProperties"
-  prop {
-    api_name: "apk_verity_mode"
-    type: Integer
-    access: Writeonce
-    prop_name: "ro.apk_verity.mode"
-  }
-}
 props {
   module: "android.sysprop.CarProperties"
   prop {
```

