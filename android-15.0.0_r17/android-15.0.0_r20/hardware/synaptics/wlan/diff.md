```diff
diff --git a/synadhd/wifi_hal/common.h b/synadhd/wifi_hal/common.h
index 248ba1f..1c7b7a8 100755
--- a/synadhd/wifi_hal/common.h
+++ b/synadhd/wifi_hal/common.h
@@ -60,6 +60,17 @@ const uint32_t BRCM_OUI =  0x001018;
 #define MAX_NUM_RADIOS 3
 #define MAX_CMD_RESP_BUF_LEN 8192
 
+#define NL_MSG_MAX_LEN                  5120u
+
+/* nl_msg->nm_nlh->nlmsg_len is added by data len of the attributes
+ * NL80211_ATTR_VENDOR_ID, NL80211_ATTR_VENDOR_SUBCMD,
+ * NL80211_ATTR_IFINDEX, APF_PROGRAM_LEN by 56u
+ * To keep the additioanl room and aligned,
+ * keeping the overhead of 128u
+ */
+#define NL_MSG_HDR_OVERHEAD_LEN		128u
+#define NL_MSG_DEFAULT_LEN		(getpagesize() - NL_MSG_HDR_OVERHEAD_LEN)
+
 /*
  This enum defines ranges for various commands; commands themselves
  can be defined in respective feature headers; i.e. find gscan command
diff --git a/synadhd/wifi_hal/cpp_bindings.cpp b/synadhd/wifi_hal/cpp_bindings.cpp
index de0c27c..be0e870 100755
--- a/synadhd/wifi_hal/cpp_bindings.cpp
+++ b/synadhd/wifi_hal/cpp_bindings.cpp
@@ -565,14 +565,23 @@ int WifiEvent::parse() {
     return result;
 }
 
-int WifiRequest::create(int family, uint8_t cmd, int flags, int hdrlen) {
+int WifiRequest::create(int family, uint8_t cmd, int flags, int data_len) {
 
     destroy();
 
-    mMsg = nlmsg_alloc();
+    /* If data_len is 0, default msg size will be used
+     * (nlmsg_alloc uses PAGE_SIZE by default).
+     * data_len is requested specifically for cases where len needs
+     * to be greater than default_size.
+     */
+    if (data_len) {
+        mMsg = nlmsg_alloc_size(data_len);
+    } else {
+        mMsg = nlmsg_alloc();
+    }
     if (mMsg != NULL) {
         genlmsg_put(mMsg, /* pid = */ 0, /* seq = */ 0, family,
-                hdrlen, flags, cmd, /* version = */ 0);
+                0, flags, cmd, /* version = */ 0);
         return WIFI_SUCCESS;
     } else {
         return WIFI_ERROR_OUT_OF_MEMORY;
@@ -608,6 +617,29 @@ static int mapErrorCodes(int err)
     return ret;
 }
 
+int WifiRequest::create_custom_len(uint32_t id, int subcmd, int data_len) {
+    int res = create_custom_len(NL80211_CMD_VENDOR, data_len);
+    if (res < 0) {
+        return mapErrorCodes(res);
+    }
+
+    res = put_u32(NL80211_ATTR_VENDOR_ID, id);
+    if (res < 0) {
+        return mapErrorCodes(res);
+    }
+
+    res = put_u32(NL80211_ATTR_VENDOR_SUBCMD, subcmd);
+    if (res < 0) {
+        return mapErrorCodes(res);
+    }
+
+    if (mIface != -1) {
+        res = set_iface_id(mIface);
+    }
+
+    return mapErrorCodes(res);
+}
+
 int WifiRequest::create(uint32_t id, int subcmd) {
     int res = create(NL80211_CMD_VENDOR);
     if (res < 0) {
diff --git a/synadhd/wifi_hal/cpp_bindings.h b/synadhd/wifi_hal/cpp_bindings.h
index cc1c662..f2d096f 100755
--- a/synadhd/wifi_hal/cpp_bindings.h
+++ b/synadhd/wifi_hal/cpp_bindings.h
@@ -189,12 +189,16 @@ public:
     }
 
     /* Command assembly helpers */
-    int create(int family, uint8_t cmd, int flags, int hdrlen);
+    int create(int family, uint8_t cmd, int flags, int data_len);
     int create(uint8_t cmd) {
         return create(mFamily, cmd, 0, 0);
     }
 
+    int create_custom_len(uint8_t cmd, int data_len) {
+        return create(mFamily, cmd, 0, data_len);
+    }
     int create(uint32_t id, int subcmd);
+    int create_custom_len(uint32_t id, int subcmd, int data_len);
 
     int put(int attribute, void *ptr, unsigned len) {
         return nla_put(mMsg, attribute, len, ptr);
diff --git a/synadhd/wifi_hal/wifi_hal.cpp b/synadhd/wifi_hal/wifi_hal.cpp
index 0506257..d13ac05 100755
--- a/synadhd/wifi_hal/wifi_hal.cpp
+++ b/synadhd/wifi_hal/wifi_hal.cpp
@@ -1205,6 +1205,7 @@ class AndroidPktFilterCommand : public WifiCommand {
         {
             mProgram = NULL;
             mProgramLen = 0;
+            mReadProgram = NULL;
         }
 
         AndroidPktFilterCommand(wifi_interface_handle handle,
@@ -1215,6 +1216,7 @@ class AndroidPktFilterCommand : public WifiCommand {
         {
             mVersion = NULL;
             mMaxLen = NULL;
+            mReadProgram = NULL;
         }
 
         AndroidPktFilterCommand(wifi_interface_handle handle,
@@ -1223,20 +1225,23 @@ class AndroidPktFilterCommand : public WifiCommand {
                 mReadProgram(host_dst), mProgramLen(length),
                 mReqType(READ_APF_PROGRAM)
         {
+            mProgram = NULL;
+            mVersion = NULL;
+            mMaxLen = NULL;
         }
 
     int createRequest(WifiRequest& request) {
         if (mReqType == SET_APF_PROGRAM) {
-            ALOGI("\n%s: APF set program request\n", __FUNCTION__);
+            ALOGI("%s: APF set program request\n", __FUNCTION__);
             return createSetPktFilterRequest(request);
         } else if (mReqType == GET_APF_CAPABILITIES) {
-            ALOGI("\n%s: APF get capabilities request\n", __FUNCTION__);
+            ALOGI("%s: APF get capabilities request\n", __FUNCTION__);
 	    return createGetPktFilterCapabilitesRequest(request);
         } else if (mReqType == READ_APF_PROGRAM) {
-            ALOGI("\n%s: APF read packet filter request\n", __FUNCTION__);
+            ALOGI("%s: APF read packet filter request\n", __FUNCTION__);
             return createReadPktFilterRequest(request);
         } else {
-            ALOGE("\n%s Unknown APF request\n", __FUNCTION__);
+            ALOGE("%s Unknown APF request\n", __FUNCTION__);
             return WIFI_ERROR_NOT_SUPPORTED;
         }
         return WIFI_SUCCESS;
@@ -1244,9 +1249,19 @@ class AndroidPktFilterCommand : public WifiCommand {
 
     int createSetPktFilterRequest(WifiRequest& request) {
         u8 *program = new u8[mProgramLen];
+        int result;
+
         NULL_CHECK_RETURN(program, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
-        int result = request.create(GOOGLE_OUI, APF_SUBCMD_SET_FILTER);
+
+        ALOGI("mProgramLen : %d\n", mProgramLen);
+        if (mProgramLen > NL_MSG_DEFAULT_LEN) {
+            result = request.create_custom_len(GOOGLE_OUI, APF_SUBCMD_SET_FILTER,
+                    NL_MSG_MAX_LEN);
+        } else {
+            result = request.create(GOOGLE_OUI, APF_SUBCMD_SET_FILTER);
+        }
         if (result < 0) {
+            ALOGE("Failed to create cmd: %d, err %d\n", APF_SUBCMD_SET_FILTER, result);
             delete[] program;
             return result;
         }
@@ -1254,11 +1269,13 @@ class AndroidPktFilterCommand : public WifiCommand {
         nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
         result = request.put_u32(APF_ATTRIBUTE_PROGRAM_LEN, mProgramLen);
         if (result < 0) {
+            ALOGE("Failed to put the program_len %d, err %d\n", mProgramLen, result);
             goto exit;
         }
         memcpy(program, mProgram, mProgramLen);
         result = request.put(APF_ATTRIBUTE_PROGRAM, program, mProgramLen);
         if (result < 0) {
+            ALOGE("Failed to copy program_ptr %d, err %d\n", mProgramLen, result);
             goto exit;
         }
 exit:   request.attr_end(data);
@@ -1291,6 +1308,7 @@ exit:   request.attr_end(data);
         WifiRequest request(familyId(), ifaceId());
         int result = createRequest(request);
         if (result < 0) {
+            ALOGI("CreateRequest failed for APF, result = %d", result);
             return result;
         }
         result = requestResponse(request);
@@ -1298,7 +1316,6 @@ exit:   request.attr_end(data);
             ALOGI("Request Response failed for APF, result = %d", result);
             return result;
         }
-        ALOGI("Done!");
         return result;
     }
 
@@ -1307,7 +1324,7 @@ exit:   request.attr_end(data);
     }
 
     int handleResponse(WifiEvent& reply) {
-        ALOGD("In SetAPFCommand::handleResponse");
+        ALOGE("In SetAPFCommand::handleResponse mReqType %d\n", mReqType);
 
         if (reply.get_cmd() != NL80211_CMD_VENDOR) {
             ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
@@ -1320,13 +1337,13 @@ exit:   request.attr_end(data);
         nlattr *vendor_data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
         int len = reply.get_vendor_data_len();
 
-        ALOGD("Id = %0x, subcmd = %d, len = %d", id, subcmd, len);
+        ALOGI("Id = %0x, subcmd = %d, len = %d", id, subcmd, len);
         if (vendor_data == NULL || len == 0) {
             ALOGE("no vendor data in SetAPFCommand response; ignoring it");
             return NL_SKIP;
         }
-        if( mReqType == SET_APF_PROGRAM) {
-            ALOGD("Response received for set packet filter command\n");
+        if (mReqType == SET_APF_PROGRAM) {
+            ALOGE("Response received for set packet filter command\n");
         } else if (mReqType == GET_APF_CAPABILITIES) {
             *mVersion = 0;
             *mMaxLen = 0;
diff --git a/synadhd/wifi_hal/wifi_logger.cpp b/synadhd/wifi_hal/wifi_logger.cpp
index a2be05f..37f0204 100755
--- a/synadhd/wifi_hal/wifi_logger.cpp
+++ b/synadhd/wifi_hal/wifi_logger.cpp
@@ -1647,8 +1647,12 @@ public:
     }
     RingDump(wifi_interface_handle iface, int id)
         : WifiCommand("RingDump", iface, id), mLargestBuffSize(0), mBuff(NULL),
-        mErrCode(0)
+        mErrCode(0), mMap(NULL), mNumMaps(0)
     {
+        memset(&mHandle, 0, sizeof(wifi_ring_buffer_data_handler));
+        for (int i = 0; i < DUMP_BUF_ATTR_MAX; i++) {
+            ring_name[i] = NULL;
+        }
     }
 
     int start() {
diff --git a/synadhd/wpa_supplicant_8_lib/Android.bp b/synadhd/wpa_supplicant_8_lib/Android.bp
new file mode 100644
index 0000000..e87db01
--- /dev/null
+++ b/synadhd/wpa_supplicant_8_lib/Android.bp
@@ -0,0 +1,72 @@
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
+        "hardware_synaptics_wlan_synadhd_wpa_supplicant_8_lib_license",
+    ],
+}
+
+license {
+    name: "hardware_synaptics_wlan_synadhd_wpa_supplicant_8_lib_license",
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
+    name: "lib_driver_cmd_synadhd",
+    shared_libs: [
+        "libc",
+        "libcutils",
+    ],
+    cflags: [
+        "-DBCMDHD_64_BIT_IPC", // It is always set for r11
+        "-DCONFIG_ANDROID_LOG",
+        "-DCONFIG_P2P",
+        "-Wall",
+        "-Werror",
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
diff --git a/synadhd/wpa_supplicant_8_lib/Android.mk b/synadhd/wpa_supplicant_8_lib/Android.mk
deleted file mode 100644
index d1f8e55..0000000
--- a/synadhd/wpa_supplicant_8_lib/Android.mk
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
-LOCAL_MODULE := lib_driver_cmd_synadhd
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
```

