```diff
diff --git a/synadhd/config/Android.bp b/synadhd/config/Android.bp
new file mode 100644
index 0000000..064fe58
--- /dev/null
+++ b/synadhd/config/Android.bp
@@ -0,0 +1,29 @@
+// Copyright (C) 2008 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+soong_namespace {
+}
+
+prebuilt_etc {
+    name: "wpa_supplicant.conf",
+    src: ":wpa_supplicant_conf_gen",
+    sub_dir: "wifi",
+    vendor: true,
+    enabled: select(soong_config_variable("wpa_supplicant_8", "board_wlan_device"), {
+        "synadhd": true,
+        default: false,
+    }),
+    licenses: [
+        "external_wpa_supplicant_8_license",
+    ],
+}
diff --git a/synadhd/config/Android.mk b/synadhd/config/Android.mk
deleted file mode 100644
index 8c3b13f..0000000
--- a/synadhd/config/Android.mk
+++ /dev/null
@@ -1,30 +0,0 @@
-#
-# Copyright (C) 2008 The Android Open Source Project
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
-#
-LOCAL_PATH := $(call my-dir)
-
-########################
-
-WIFI_DRIVER_SOCKET_IFACE := wlan0
-ifeq ($(strip $(WPA_SUPPLICANT_VERSION)),VER_0_8_X)
-  include external/wpa_supplicant_8/wpa_supplicant/wpa_supplicant_conf.mk
-else
-ifeq ($(strip $(WPA_SUPPLICANT_VERSION)),VER_0_6_X)
-  include external/wpa_supplicant_6/wpa_supplicant/wpa_supplicant_conf.mk
-else
-  include external/wpa_supplicant/wpa_supplicant_conf.mk
-endif
-endif
-#######################
```

