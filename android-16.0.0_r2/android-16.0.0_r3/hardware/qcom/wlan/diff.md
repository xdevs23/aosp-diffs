```diff
diff --git a/Android.bp b/Android.bp
index 559b223..66ed742 100644
--- a/Android.bp
+++ b/Android.bp
@@ -48,6 +48,7 @@ soong_config_string_variable {
     values: [
         "wcn6740",
         "wcn3990",
+        "wcn7850",
     ],
 }
 
@@ -77,6 +78,15 @@ wifihal_qcom_defaults {
                     ],
                 }),
             },
+            wcn7850: {
+                whole_static_libs: [
+                    "//hardware/qcom/ar1-la3/wlan/qcwcn/wifi_hal:libwifi-hal-qcom",
+                ],
+                shared_libs: [
+                    "//hardware/qcom/ar1-la3/wlan/cld80211-lib:libcld80211",
+                    "libcrypto",
+                ],
+            },
             conditions_default: {
                 whole_static_libs: [
                     "//hardware/qcom/wlan/legacy:libwifi-hal-qcom",
diff --git a/wcn6740/qcwcn/config/Android.bp b/wcn6740/qcwcn/config/Android.bp
new file mode 100644
index 0000000..a0f4eb5
--- /dev/null
+++ b/wcn6740/qcwcn/config/Android.bp
@@ -0,0 +1,23 @@
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
+
+prebuilt_etc {
+    name: "wpa_supplicant.conf",
+    src: ":wpa_supplicant_conf_gen",
+    sub_dir: "wifi",
+    vendor: true,
+    licenses: [
+        "external_wpa_supplicant_8_license",
+    ],
+}
diff --git a/wcn6740/qcwcn/config/Android.mk b/wcn6740/qcwcn/config/Android.mk
deleted file mode 100644
index 1c1622d..0000000
--- a/wcn6740/qcwcn/config/Android.mk
+++ /dev/null
@@ -1,24 +0,0 @@
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
-#########################
-
-WIFI_DRIVER_SOCKET_IFACE := wlan0
-ifeq ($(strip $(WPA_SUPPLICANT_VERSION)),VER_0_8_X)
-  include external/wpa_supplicant_8/wpa_supplicant/wpa_supplicant_conf.mk
-endif
-#######################
```

