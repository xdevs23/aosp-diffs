```diff
diff --git a/Android.bp b/Android.bp
index 21ec9df..559b223 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,4 +1,3 @@
-
 package {
     default_applicable_licenses: ["hardware_qcom_wlan_license"],
 }
@@ -66,13 +65,17 @@ wifihal_qcom_defaults {
                 ],
             },
             wcn3990: {
-                whole_static_libs: [
-                    "//hardware/qcom/sw5100/wlan/qcwcn/wifi_hal:libwifi-hal-qcom",
-                ],
-                shared_libs: [
-                    "//hardware/qcom/sw5100/wlan/cld80211-lib:libcld80211",
-                    "libcrypto",
-                ],
+                whole_static_libs: select(soong_config_variable("pixel_watch", "bsp_dir"), {
+                    any @ bsp_dir: [
+                        "//hardware/qcom/" + bsp_dir + "/wlan/qcwcn/wifi_hal:libwifi-hal-qcom",
+                    ],
+                }),
+                shared_libs: select(soong_config_variable("pixel_watch", "bsp_dir"), {
+                    any @ bsp_dir: [
+                        "//hardware/qcom/" + bsp_dir + "/wlan/cld80211-lib:libcld80211",
+                        "libcrypto",
+                    ],
+                }),
             },
             conditions_default: {
                 whole_static_libs: [
diff --git a/wcn6740/qcwcn/wpa_supplicant_8_lib/Android.bp b/wcn6740/qcwcn/wpa_supplicant_8_lib/Android.bp
new file mode 100644
index 0000000..75e0eea
--- /dev/null
+++ b/wcn6740/qcwcn/wpa_supplicant_8_lib/Android.bp
@@ -0,0 +1,74 @@
+//
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
+//
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "hardware_qcom_wlan_wcn6740_qcwcn_wpa_supplicant_8_lib_license",
+    ],
+}
+
+license {
+    name: "hardware_qcom_wlan_wcn6740_qcwcn_wpa_supplicant_8_lib_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-BSD",
+    ],
+    license_text: [
+        "NOTICE",
+    ],
+}
+
+cc_library_static {
+    name: "lib_driver_cmd_qcwcn",
+    shared_libs: [
+        "libc",
+        "libcutils",
+        "libdl",
+        "libnl",
+    ],
+    cflags: [
+        "-DCONFIG_ANDROID_LOG",
+        "-DCONFIG_P2P",
+        "-Wall",
+        "-Werror",
+    ],
+    srcs: [
+        "driver_cmd_nl80211.c",
+        "driver_cmd_nl80211_extn.c",
+    ],
+    include_dirs: [
+        "external/libnl/include",
+        "external/wpa_supplicant_8/src",
+        "external/wpa_supplicant_8/src/ap",
+        "external/wpa_supplicant_8/src/common",
+        "external/wpa_supplicant_8/src/drivers",
+        "external/wpa_supplicant_8/src/l2_packet",
+        "external/wpa_supplicant_8/src/utils",
+        "external/wpa_supplicant_8/src/wps",
+        "external/wpa_supplicant_8/wpa_supplicant",
+    ],
+    vendor: true,
+    arch: {
+        arm: {
+            cflags: [
+                "-mabi=aapcs-linux",
+            ],
+        },
+    },
+    defaults: [
+        "wpa_supplicant_cflags_default",
+    ],
+}
diff --git a/wcn6740/qcwcn/wpa_supplicant_8_lib/Android.mk b/wcn6740/qcwcn/wpa_supplicant_8_lib/Android.mk
deleted file mode 100644
index 8e2ab2d..0000000
--- a/wcn6740/qcwcn/wpa_supplicant_8_lib/Android.mk
+++ /dev/null
@@ -1,79 +0,0 @@
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
-ifeq ($(WPA_SUPPLICANT_VERSION),VER_0_8_X)
-
-ifneq ($(BOARD_WPA_SUPPLICANT_DRIVER),)
-  CONFIG_DRIVER_$(BOARD_WPA_SUPPLICANT_DRIVER) := y
-endif
-
-WPA_SUPPL_DIR := external/wpa_supplicant_8
-WPA_SRC_FILE :=
-
-include $(WPA_SUPPL_DIR)/wpa_supplicant/android.config
-
-WPA_SUPPL_DIR_INCLUDE := $(WPA_SUPPL_DIR)/src \
-	$(WPA_SUPPL_DIR)/src/common \
-	$(WPA_SUPPL_DIR)/src/drivers \
-	$(WPA_SUPPL_DIR)/src/l2_packet \
-	$(WPA_SUPPL_DIR)/src/utils \
-	$(WPA_SUPPL_DIR)/src/wps \
-	$(WPA_SUPPL_DIR)/src/ap \
-	$(WPA_SUPPL_DIR)/wpa_supplicant
-
-ifdef CONFIG_DRIVER_NL80211
-WPA_SUPPL_DIR_INCLUDE += external/libnl/include
-WPA_SRC_FILE += driver_cmd_nl80211_extn.c \
-		driver_cmd_nl80211.c
-endif
-
-ifeq ($(TARGET_ARCH),arm)
-# To force sizeof(enum) = 4
-L_CFLAGS += -mabi=aapcs-linux
-endif
-
-ifdef CONFIG_ANDROID_LOG
-L_CFLAGS += -DCONFIG_ANDROID_LOG
-endif
-
-ifdef CONFIG_P2P
-L_CFLAGS += -DCONFIG_P2P
-endif
-
-L_CFLAGS += -Werror
-
-########################
-
-include $(CLEAR_VARS)
-LOCAL_MODULE := lib_driver_cmd_qcwcn
-LOCAL_SHARED_LIBRARIES := libc libcutils
-ifneq ($(wildcard external/libnl),)
-LOCAL_SHARED_LIBRARIES += libnl
-endif
-LOCAL_SHARED_LIBRARIES += libdl
-LOCAL_CFLAGS := $(L_CFLAGS) -Wall
-LOCAL_SRC_FILES := $(WPA_SRC_FILE)
-LOCAL_C_INCLUDES := $(WPA_SUPPL_DIR_INCLUDE)
-LOCAL_VENDOR_MODULE := true
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-BSD
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-include $(BUILD_STATIC_LIBRARY)
-
-########################
-
-endif
```

