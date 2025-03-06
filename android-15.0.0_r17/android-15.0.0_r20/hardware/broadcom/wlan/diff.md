```diff
diff --git a/bcmdhd/dhdutil/include/typedefs.h b/bcmdhd/dhdutil/include/typedefs.h
index 314bf80..711b1dd 100644
--- a/bcmdhd/dhdutil/include/typedefs.h
+++ b/bcmdhd/dhdutil/include/typedefs.h
@@ -165,9 +165,7 @@ typedef long unsigned int size_t;
 #ifdef USE_TYPEDEF_DEFAULTS
 #undef USE_TYPEDEF_DEFAULTS
 
-#ifndef TYPEDEF_BOOL
-typedef	/* @abstract@ */ unsigned char	bool;
-#endif
+#include <stdbool.h>
 
 /* define uchar, ushort, uint, ulong */
 
diff --git a/bcmdhd/wifi_hal/common.h b/bcmdhd/wifi_hal/common.h
index 21bdafd..8223051 100644
--- a/bcmdhd/wifi_hal/common.h
+++ b/bcmdhd/wifi_hal/common.h
@@ -71,7 +71,7 @@ const uint32_t BRCM_OUI =  0x001018;
  * 11ax/HE:  OFDM(12) + HE(12) x 2 nss = 36 (MCS0 ~ MCS11)
  * 11be/EHT:  OFDM(12) + EHT(16) x 2 nss = 44 (MCS0 ~ MCS15)
  */
-#define NUM_RATE                        44u
+#define MAX_NUM_RATE                        44u
 #define NUM_RATE_NON_BE                 36u
 
 #define NL_MSG_MAX_LEN                  5120u
diff --git a/bcmdhd/wifi_hal/link_layer_stats.cpp b/bcmdhd/wifi_hal/link_layer_stats.cpp
index 580fc9c..695a900 100644
--- a/bcmdhd/wifi_hal/link_layer_stats.cpp
+++ b/bcmdhd/wifi_hal/link_layer_stats.cpp
@@ -414,7 +414,8 @@ private:
             }
 
             num_rate = peer_info_ptr->num_rate;
-            if ((num_rate == NUM_RATE) || (num_rate == NUM_RATE_NON_BE)) {
+            /* boundary check as per max supported num rate */
+            if (num_rate <= MAX_NUM_RATE) {
                 all_rate_stats_per_peer_per_link_size = num_rate * sizeof(wifi_rate_stat);
                 if (num_rate && (*data_rem_len >= all_rate_stats_per_peer_per_link_size)) {
                     ret = convertToExternalRatestatsStructure(data, offset, outbuf, data_rem_len,
diff --git a/bcmdhd/wpa_supplicant_8_lib/Android.bp b/bcmdhd/wpa_supplicant_8_lib/Android.bp
new file mode 100644
index 0000000..b4e5318
--- /dev/null
+++ b/bcmdhd/wpa_supplicant_8_lib/Android.bp
@@ -0,0 +1,66 @@
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
+
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "hardware_broadcom_wlan_bcmdhd_wpa_supplicant_8_lib_license",
+    ],
+}
+
+license {
+    name: "hardware_broadcom_wlan_bcmdhd_wpa_supplicant_8_lib_license",
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
+    name: "lib_driver_cmd_bcmdhd",
+    shared_libs: [
+        "libc",
+        "libcutils",
+    ],
+    cflags: [
+        "-DCONFIG_ANDROID_LOG",
+        "-DCONFIG_P2P",
+        "-Wall",
+        "-Werror",
+        "-Wno-unused-parameter",
+        "-Wno-macro-redefined",
+    ],
+    srcs: [
+        "driver_cmd_nl80211.c",
+    ],
+    include_dirs: [
+        "external/libnl/include",
+        "external/wpa_supplicant_8/src",
+        "external/wpa_supplicant_8/src/common",
+        "external/wpa_supplicant_8/src/drivers",
+        "external/wpa_supplicant_8/src/l2_packet",
+        "external/wpa_supplicant_8/src/utils",
+        "external/wpa_supplicant_8/src/wps",
+        "external/wpa_supplicant_8/wpa_supplicant",
+    ],
+    vendor: true,
+    defaults: [
+        "wpa_supplicant_cflags_default",
+    ],
+}
diff --git a/bcmdhd/wpa_supplicant_8_lib/Android.mk b/bcmdhd/wpa_supplicant_8_lib/Android.mk
deleted file mode 100644
index 448a7ca..0000000
--- a/bcmdhd/wpa_supplicant_8_lib/Android.mk
+++ /dev/null
@@ -1,81 +0,0 @@
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
-WPA_SUPPL_DIR = external/wpa_supplicant_8
-WPA_SRC_FILE :=
-
-include $(WPA_SUPPL_DIR)/wpa_supplicant/android.config
-
-WPA_SUPPL_DIR_INCLUDE = $(WPA_SUPPL_DIR)/src \
-	$(WPA_SUPPL_DIR)/src/common \
-	$(WPA_SUPPL_DIR)/src/drivers \
-	$(WPA_SUPPL_DIR)/src/l2_packet \
-	$(WPA_SUPPL_DIR)/src/utils \
-	$(WPA_SUPPL_DIR)/src/wps \
-	$(WPA_SUPPL_DIR)/wpa_supplicant
-
-ifdef CONFIG_DRIVER_NL80211
-WPA_SUPPL_DIR_INCLUDE += external/libnl/include
-WPA_SRC_FILE += driver_cmd_nl80211.c
-endif
-
-ifdef CONFIG_DRIVER_WEXT
-WPA_SRC_FILE += driver_cmd_wext.c
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
-ifeq ($(TARGET_USES_64_BIT_BCMDHD),true)
-L_CFLAGS += -DBCMDHD_64_BIT_IPC
-endif
-
-L_CFLAGS += -Wall -Werror -Wno-unused-parameter -Wno-macro-redefined
-
-########################
-
-include $(CLEAR_VARS)
-LOCAL_MODULE := lib_driver_cmd_bcmdhd
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-BSD
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-LOCAL_SHARED_LIBRARIES := libc libcutils
-LOCAL_CFLAGS := $(L_CFLAGS)
-LOCAL_SRC_FILES := $(WPA_SRC_FILE)
-LOCAL_C_INCLUDES := $(WPA_SUPPL_DIR_INCLUDE)
-LOCAL_VENDOR_MODULE := true
-include $(BUILD_STATIC_LIBRARY)
-
-########################
-
-endif
diff --git a/bcmdhd/wpa_supplicant_8_lib/driver_cmd_nl80211.c b/bcmdhd/wpa_supplicant_8_lib/driver_cmd_nl80211.c
index f9dbb95..56504f6 100644
--- a/bcmdhd/wpa_supplicant_8_lib/driver_cmd_nl80211.c
+++ b/bcmdhd/wpa_supplicant_8_lib/driver_cmd_nl80211.c
@@ -125,12 +125,7 @@ int wpa_driver_nl80211_driver_cmd(void *priv, char *cmd, char *buf,
 			wpa_driver_send_hang_msg(drv);
 		} else {
 			drv_errors = 0;
-			ret = 0;
-			if ((os_strcasecmp(cmd, "LINKSPEED") == 0) ||
-			    (os_strcasecmp(cmd, "RSSI") == 0) ||
-			    (os_strcasecmp(cmd, "GETBAND") == 0) ||
-			    (os_strncasecmp(cmd, "WLS_BATCHING", 12) == 0))
-				ret = strlen(buf);
+			ret = strlen(buf);
 			wpa_driver_notify_country_change(drv->ctx, cmd);
 			wpa_printf(MSG_DEBUG, "%s %s len = %d, %zu", __func__, buf, ret, strlen(buf));
 		}
```

