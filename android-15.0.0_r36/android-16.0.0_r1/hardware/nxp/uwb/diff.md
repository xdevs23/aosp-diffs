```diff
diff --git a/Android.bp b/Android.bp
index af11258..04f89b8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -6,7 +6,7 @@ package {
 // See: http://go/android-license-faq
 license {
     name: "hardware_nxp_uwb_license",
-    visibility: [":__subpackages__"],
+    visibility: ["//visibility:public"],
     license_kinds: [
         "SPDX-license-identifier-Apache-2.0",
     ],
@@ -82,11 +82,6 @@ cc_library_shared {
         "halimpl/utils",
         "extns/inc",
     ],
-    required: [
-        "libuwb-uci.conf",
-        "libuwb-nxp.conf",
-        "libuwb-countrycode.conf",
-    ],
     cflags: [
         "-DGENERIC",
         "-DBUILDCFG=1",
diff --git a/aidl/uwb_chip.cpp b/aidl/uwb_chip.cpp
index 040e411..ace1ed9 100644
--- a/aidl/uwb_chip.cpp
+++ b/aidl/uwb_chip.cpp
@@ -110,7 +110,6 @@ void onServiceDied(void *cookie) {
 
 ::ndk::ScopedAStatus UwbChip::sessionInit(int32_t sessionId) {
       LOG(INFO) << "AIDL-SessionInitialization Enter";
-      phNxpUciHal_sessionInitialization(sessionId);
       return ndk::ScopedAStatus::ok();
 }
 }  // namespace impl
diff --git a/extns/inc/uci_defs.h b/extns/inc/uci_defs.h
index b6e7394..7ce7c16 100644
--- a/extns/inc/uci_defs.h
+++ b/extns/inc/uci_defs.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2018-2024 NXP
+ * Copyright 2018-2025 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -29,6 +29,7 @@
 #define UCI_MSG_HDR_SIZE 4 /* per UCI spec */
 #define UCI_RESPONSE_STATUS_OFFSET 4
 #define UCI_CMD_SESSION_ID_OFFSET 4
+#define UCI_RESPONSE_PAYLOAD_OFFSET 5
 
 /* UCI Command and Notification Format:
  * 4 byte message header:
@@ -116,6 +117,7 @@
 constexpr uint8_t kSessionType_Ranging = 0x00;
 constexpr uint8_t kSessionType_RangingAndData = 0x01;
 constexpr uint8_t kSessionType_CCCRanging = 0xA0;
+constexpr uint8_t kSessionType_AliroRanging = 0xA2;
 
 /*********************************************************
  * UCI session config Group-2: Opcodes and size of command
@@ -187,6 +189,7 @@ constexpr uint8_t kSessionType_CCCRanging = 0xA0;
 #define UCI_STATUS_BUFFER_UNDERFLOW 0x58
 #define UCI_STATUS_LOW_VBAT 0x59
 #define UCI_STATUS_HW_RESET 0xFE
+#define UWBS_STATUS_ERROR 0xFF /* error occurred in UWBS*/
 
 /* Status code for feature not supported */
 #define UCI_STATUS_FEATURE_NOT_SUPPORTED 0x55
diff --git a/halimpl/config/Android.bp b/halimpl/config/Android.bp
deleted file mode 100644
index 2e40092..0000000
--- a/halimpl/config/Android.bp
+++ /dev/null
@@ -1,17 +0,0 @@
-prebuilt_etc {
-    name: "libuwb-uci.conf",
-    src: "SR1XX/libuwb-uci.conf",
-    vendor: true,
-}
-
-prebuilt_etc {
-    name: "libuwb-nxp.conf",
-    src: "SR1XX/libuwb-nxp.conf",
-    vendor: true,
-}
-
-prebuilt_etc {
-    name: "libuwb-countrycode.conf",
-    src: "libuwb-countrycode.conf",
-    vendor: true,
-}
diff --git a/halimpl/config/README.md b/halimpl/example_config/README.md
similarity index 100%
rename from halimpl/config/README.md
rename to halimpl/example_config/README.md
diff --git a/halimpl/config/SR1XX/libuwb-nxp-SR100S.conf b/halimpl/example_config/SR1XX/libuwb-nxp-SR100S.conf
similarity index 97%
rename from halimpl/config/SR1XX/libuwb-nxp-SR100S.conf
rename to halimpl/example_config/SR1XX/libuwb-nxp-SR100S.conf
index 97742ce..85f1c7f 100644
--- a/halimpl/config/SR1XX/libuwb-nxp-SR100S.conf
+++ b/halimpl/example_config/SR1XX/libuwb-nxp-SR100S.conf
@@ -119,9 +119,11 @@ UWB_FW_DOWNLOAD_LOG=0x00
 ###############################################################################
 
 ###############################################################################
-#enable or disable delete ursk for ccc session
+# Enable or disable delete ursk for ccc session
 DELETE_URSK_FOR_CCC_SESSION=0x00
-###############################################################################
+
+# Enable or disable delete ursk for aliro session
+DELETE_URSK_FOR_ALIRO_SESSION=0x00
 
 ###############################################################################
 #enable or disable sts index overriding for ccc session
diff --git a/halimpl/config/SR1XX/libuwb-nxp.conf b/halimpl/example_config/SR1XX/libuwb-nxp.conf
similarity index 91%
rename from halimpl/config/SR1XX/libuwb-nxp.conf
rename to halimpl/example_config/SR1XX/libuwb-nxp.conf
index d4bd45d..4f65e65 100644
--- a/halimpl/config/SR1XX/libuwb-nxp.conf
+++ b/halimpl/example_config/SR1XX/libuwb-nxp.conf
@@ -120,8 +120,11 @@ UWB_FW_DOWNLOAD_LOG=0x00
 ###############################################################################
 
 ###############################################################################
-#enable or disable delete ursk for ccc session
+# Enable or disable delete ursk for ccc session
 DELETE_URSK_FOR_CCC_SESSION=0x00
+
+# Enable or disable delete ursk for aliro session
+DELETE_URSK_FOR_ALIRO_SESSION=0x00
 ###############################################################################
 
 ###############################################################################
@@ -193,3 +196,16 @@ COUNTRY_CODE_CAP_FILE_LOCATION={"vendor/etc/"}
 # binding and locking during uwb init [not allowed = 0x00, allowed = 0x01]
 ###############################################################################
 UWB_BINDING_LOCKING_ALLOWED=0x00
+###############################################################################
+
+###############################################################################
+#enable or disable uwb uci debug logging to file
+#0x00 - Disables writing log to file
+#0x01 - Enable log
+UWB_UCIX_UCIR_ERROR_LOG=0x00
+###############################################################################
+#Size of uwb uci debug log file
+#Max value is 1MB
+#Less than 100kb restricted data printed in file
+#Define values in bytes 50kb - 50000
+UWB_DEBUG_LOG_FILE_SIZE=1000000
diff --git a/halimpl/config/SR1XX/libuwb-uci-SR160.conf b/halimpl/example_config/SR1XX/libuwb-uci-SR160.conf
similarity index 100%
rename from halimpl/config/SR1XX/libuwb-uci-SR160.conf
rename to halimpl/example_config/SR1XX/libuwb-uci-SR160.conf
diff --git a/halimpl/config/SR1XX/libuwb-uci.conf b/halimpl/example_config/SR1XX/libuwb-uci.conf
similarity index 100%
rename from halimpl/config/SR1XX/libuwb-uci.conf
rename to halimpl/example_config/SR1XX/libuwb-uci.conf
diff --git a/halimpl/config/libuwb-countrycode.conf b/halimpl/example_config/libuwb-countrycode.conf
similarity index 100%
rename from halimpl/config/libuwb-countrycode.conf
rename to halimpl/example_config/libuwb-countrycode.conf
diff --git a/halimpl/hal/hbci/NxpUwbChipHbciModule.cc b/halimpl/hal/hbci/NxpUwbChipHbciModule.cc
index 4e80b85..e2f1680 100644
--- a/halimpl/hal/hbci/NxpUwbChipHbciModule.cc
+++ b/halimpl/hal/hbci/NxpUwbChipHbciModule.cc
@@ -1,3 +1,5 @@
+#include <optional>
+#include <string_view>
 #include <vector>
 
 #include "NxpUwbChip.h"
@@ -42,7 +44,7 @@ static void report_binding_status(uint8_t binding_status)
 static bool otp_read_data(const uint8_t channel, const uint8_t param_id, uint8_t *buffer, size_t len)
 {
   phNxpUciHal_Sem_t calib_data_ntf_wait;
-  phNxpUciHal_init_cb_data(&calib_data_ntf_wait, NULL);
+  phNxpUciHal_init_cb_data(&calib_data_ntf_wait);
 
   // NXP_READ_CALIB_DATA_NTF
   bool received = false;
@@ -168,7 +170,7 @@ static tHAL_UWB_STATUS sr1xx_do_bind(uint8_t *binding_status, uint8_t *remain_co
 
   // register rx handler for UWB_ESE_BINDING_NTF
   phNxpUciHal_Sem_t binding_ntf_wait;
-  phNxpUciHal_init_cb_data(&binding_ntf_wait, NULL);
+  phNxpUciHal_init_cb_data(&binding_ntf_wait);
 
   auto binding_ntf_cb =
     [&](size_t packet_len, const uint8_t *packet) mutable -> bool
@@ -230,7 +232,7 @@ static tHAL_UWB_STATUS sr1xx_check_binding_status(uint8_t *binding_status)
   // register rx handler for UWB_ESE_BINDING_CHECK_NTF
   uint8_t binding_status_got = UWB_DEVICE_UNKNOWN;
   phNxpUciHal_Sem_t binding_check_ntf_wait;
-  phNxpUciHal_init_cb_data(&binding_check_ntf_wait, NULL);
+  phNxpUciHal_init_cb_data(&binding_check_ntf_wait);
   auto binding_check_ntf_cb = [&](size_t packet_len, const uint8_t *packet) mutable -> bool {
     if (packet_len >= UCI_RESPONSE_STATUS_OFFSET) {
       binding_status_got = packet[UCI_RESPONSE_STATUS_OFFSET];
@@ -271,20 +273,17 @@ exit_check_binding_status:
 static int16_t sr1xx_extra_group_delay(const uint8_t ch)
 {
   int16_t required_compensation = 0;
-  char calibrated_with_fw[15] = {0};
 
   /* Calibrated with D4X and we are on D5X or later */
   bool is_calibrated_with_d4x = false;
 
-  int has_calibrated_with_fw_config = NxpConfig_GetStr(
-      "cal.fw_version", calibrated_with_fw, sizeof(calibrated_with_fw) - 1);
+  std::optional<std::string_view> res = NxpConfig_GetStr("cal.fw_version");
 
-  if (has_calibrated_with_fw_config) {
+  if (res.has_value()) {
+    std::string_view fw_version = *res;
     // Conf file has entry of `cal.fw_version`
-    if ( ( 0 == memcmp("48.", calibrated_with_fw, 3)) ||
-         ( 0 == memcmp("49.", calibrated_with_fw, 3))) {
-      is_calibrated_with_d4x = true;
-    }
+    is_calibrated_with_d4x =
+      fw_version.starts_with("48.") || fw_version.starts_with("49.");
   }
   else
   {
@@ -303,15 +302,10 @@ static int16_t sr1xx_extra_group_delay(const uint8_t ch)
 
     // Calibrated with D49
     // Required extra negative offset, Channel specific, but antenna agnostic.
-    unsigned short cal_chx_extra_d49_offset_n = 0;
     char key[32];
     std::snprintf(key, sizeof(key), "cal.ch%u.extra_d49_offset_n", ch);
-    int has_extra_d49_offset_n = NxpConfig_GetNum(
-      key, &cal_chx_extra_d49_offset_n, sizeof(cal_chx_extra_d49_offset_n));
-
-    if (has_extra_d49_offset_n) { /*< Extra correction from conf file ... */
-      required_compensation -= cal_chx_extra_d49_offset_n;
-    }
+    uint16_t cal_chx_extra_d49_offset_n = NxpConfig_GetNum<uint16_t>(key).value_or(0);
+    required_compensation -= cal_chx_extra_d49_offset_n;
   }
   else
   {
@@ -335,6 +329,9 @@ public:
   tHAL_UWB_STATUS apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len);
   tHAL_UWB_STATUS get_supported_channels(const uint8_t **cal_channels, uint8_t *nr);
 
+  void suspend() override;
+  void resume() override;
+
 private:
   tHAL_UWB_STATUS check_binding();
   bool onDeviceStatusNtf(size_t packet_len, const uint8_t* packet);
@@ -408,9 +405,8 @@ tHAL_UWB_STATUS NxpUwbChipHbciModule::check_binding()
       return UWBSTATUS_SUCCESS;
   }
 
-  unsigned long val = 0;
-  NxpConfig_GetNum(NAME_UWB_BINDING_LOCKING_ALLOWED, &val, sizeof(val));
-  bool isBindingLockingAllowed = (val != 0);
+  bool isBindingLockingAllowed =
+    NxpConfig_GetBool(NAME_UWB_BINDING_LOCKING_ALLOWED).value_or(false);
   if (!isBindingLockingAllowed) {
     return UWBSTATUS_SUCCESS;
   }
@@ -589,6 +585,16 @@ NxpUwbChipHbciModule::get_supported_channels(const uint8_t **cal_channels, uint8
   return UWBSTATUS_SUCCESS;
 }
 
+void NxpUwbChipHbciModule::suspend()
+{
+  phTmlUwb_Suspend();
+}
+
+void NxpUwbChipHbciModule::resume()
+{
+  phTmlUwb_Resume();
+}
+
 std::unique_ptr<NxpUwbChip> GetUwbChip()
 {
   return std::make_unique<NxpUwbChipHbciModule>();
diff --git a/halimpl/hal/hbci/phNxpUciHal_hbci_fwd.cc b/halimpl/hal/hbci/phNxpUciHal_hbci_fwd.cc
index ee56a7f..08fbb4f 100644
--- a/halimpl/hal/hbci/phNxpUciHal_hbci_fwd.cc
+++ b/halimpl/hal/hbci/phNxpUciHal_hbci_fwd.cc
@@ -23,7 +23,9 @@
 #include <stdlib.h>
 #include <sys/ioctl.h>
 
+#include <optional>
 #include <string>
+#include <string_view>
 
 #include "phNxpConfig.h"
 #include "phNxpLog.h"
@@ -34,13 +36,17 @@
 using namespace std;
 #define FILEPATH_MAXLEN 500
 
-static uint8_t chip_id = 0x00;
-static uint8_t deviceLcInfo = 0x00;
-static uint8_t is_fw_download_log_enabled = 0x00;
-static const char* default_prod_fw = "libsr100t_prod_fw.bin";
-static const char* default_dev_fw = "libsr100t_dev_fw.bin";
-static const char* default_fw_dir = "/vendor/firmware/uwb/";
-static string default_fw_path;
+namespace {
+
+uint8_t chip_id = 0x00;
+uint8_t deviceLcInfo = 0x00;
+uint8_t is_fw_download_log_enabled = 0x00;
+constexpr std::string_view default_prod_fw = "libsr100t_prod_fw.bin";
+constexpr std::string_view default_dev_fw = "libsr100t_dev_fw.bin";
+constexpr std::string_view default_fw_dir = "/vendor/firmware/uwb/";
+string default_fw_path;
+
+}   // namespace
 
 /*************************************************************************************/
 /*   LOCAL FUNCTIONS                                                                 */
@@ -58,37 +64,22 @@ static void setOpts(void)
     gOpts.fMiso         = NULL;
 }
 
-
+// TODO: change function name & return type
 static int init(void)
 {
-  const char *pDefaultFwFileName = NULL;
-  char configured_fw_name[FILEPATH_MAXLEN];
   default_fw_path = default_fw_dir;
 
   if((deviceLcInfo == PHHBCI_HELIOS_PROD_KEY_1) || (deviceLcInfo == PHHBCI_HELIOS_PROD_KEY_2)) {
-    pDefaultFwFileName = default_prod_fw;
-    if (!NxpConfig_GetStr(NAME_NXP_UWB_PROD_FW_FILENAME, configured_fw_name, sizeof(configured_fw_name))) {
-      ALOGD("Invalid Prod Fw  name keeping the default name: %s", pDefaultFwFileName);
-      default_fw_path += pDefaultFwFileName;
-    } else{
-      ALOGD("configured_fw_name : %s", configured_fw_name);
-      default_fw_path += configured_fw_name;
-    }
+    default_fw_path += NxpConfig_GetStr(NAME_NXP_UWB_PROD_FW_FILENAME).value_or(default_prod_fw);
   } else if (deviceLcInfo == PHHBCI_HELIOS_DEV_KEY) {
-    pDefaultFwFileName = default_dev_fw;
-    if (!NxpConfig_GetStr(NAME_NXP_UWB_DEV_FW_FILENAME, configured_fw_name, sizeof(configured_fw_name))) {
-      ALOGD("Invalid Dev Fw  name keeping the default name: %s", pDefaultFwFileName);
-      default_fw_path += pDefaultFwFileName;
-    } else{
-      ALOGD("configured_fw_name : %s", configured_fw_name);
-      default_fw_path += configured_fw_name;
-    }
+    default_fw_path += NxpConfig_GetStr(NAME_NXP_UWB_DEV_FW_FILENAME).value_or(default_dev_fw);
   } else {
     ALOGD("Invalid DeviceLCInfo : 0x%x\n", deviceLcInfo);
     return 1;
   }
-
   ALOGD("Referring FW path..........: %s", default_fw_path.c_str());
+
+  // TODO: remove these out.
   // gOpts.capture = Capture_Apdu_With_Dummy_Miso;
 
   if (Capture_Off != gOpts.capture) {
@@ -941,14 +932,9 @@ int phNxpUciHal_fw_download()
         ALOGD("phHbci_GetChipIdInfo Failure!\n");
         return 1;
     }
-    is_fw_download_log_enabled = false;
+    is_fw_download_log_enabled = NxpConfig_GetBool(NAME_UWB_FW_DOWNLOAD_LOG).value_or(false);
+    ALOGD("NAME_UWB_FW_DOWNLOAD_LOG: 0x%02x\n",is_fw_download_log_enabled);
 
-    if(NxpConfig_GetNum(NAME_UWB_FW_DOWNLOAD_LOG, &num, sizeof(num))){
-        is_fw_download_log_enabled = (uint8_t)num;
-        ALOGD("NAME_UWB_FW_DOWNLOAD_LOG: 0x%02x\n",is_fw_download_log_enabled);
-    } else {
-        ALOGD("NAME_UWB_FW_DOWNLOAD_LOG: failed 0x%02x\n",is_fw_download_log_enabled);
-    }
     if (init())
     {
         ALOGD("INIT Failed.....\n");
diff --git a/halimpl/hal/phNxpUciHal.cc b/halimpl/hal/phNxpUciHal.cc
index 5f648c0..a38c395 100644
--- a/halimpl/hal/phNxpUciHal.cc
+++ b/halimpl/hal/phNxpUciHal.cc
@@ -17,10 +17,14 @@
 
 #include <array>
 #include <functional>
-#include <string.h>
 #include <list>
 #include <map>
+#include <memory>
 #include <mutex>
+#include <optional>
+#include <span>
+#include <string>
+#include <thread>
 #include <unordered_set>
 #include <vector>
 
@@ -46,7 +50,6 @@ using android::base::StringPrintf;
 /* UCI HAL Control structure */
 phNxpUciHal_Control_t nxpucihal_ctrl;
 
-bool uwb_device_initialized = false;
 bool uwb_get_platform_id = false;
 uint32_t timeoutTimerId = 0;
 char persistant_log_path[120];
@@ -134,6 +137,53 @@ static void phNxpUciHal_rx_handler_destroy(void)
   rx_handlers.clear();
 }
 
+
+bool  nxp_properitory_ntf_skip_cb(size_t data_len, const uint8_t *p_data) {
+  bool is_handled = false;
+  const uint8_t mt = (p_data[0] & UCI_MT_MASK) >> UCI_MT_SHIFT;
+  const uint8_t gid = p_data[0] & UCI_GID_MASK;
+  const uint8_t oid = p_data[1] & UCI_OID_MASK;
+  if (mt == UCI_MT_NTF) { // must be true.
+    if (gid == UCI_GID_PROPRIETARY
+      && oid == EXT_UCI_PROP_GEN_DEBUG_NTF_0x18
+      && data_len == 9
+      && p_data[4] == 0x07
+      && p_data[5] == 0x29
+      && p_data[6] == 0x01
+    ) {
+      //  0  1  2  3  4  5  6  7  8
+      // 6E 18 00 05 07 29 01 00 64.
+      // b/381330041
+      NXPLOG_UCIHAL_D("%s: Skip 6E180015072901.... packet", __FUNCTION__);
+      is_handled = true;
+    }
+  }
+  else
+  {
+    // Not possible. We registered only for NTF
+    NXPLOG_UCIHAL_E("%s: Wrong MT: %d", __FUNCTION__, mt);
+  }
+  return is_handled;
+};
+
+bool phNxpUciHal_handle_dev_error_ntf(size_t packet_len,
+                                      const uint8_t *packet) {
+  if (packet_len > UCI_RESPONSE_STATUS_OFFSET) {
+    if (UWBS_STATUS_ERROR == packet[UCI_RESPONSE_STATUS_OFFSET]) {
+      if (nxpucihal_ctrl.recovery_ongoing == true) {
+        NXPLOG_UCIHAL_D("Fw crashed during recovery, ignore packet");
+      } else {
+        nxpucihal_ctrl.recovery_ongoing = true;
+        phNxpUciHalProp_trigger_fw_crash_log_dump();
+      }
+      return true;
+    }
+  } else {
+    NXPLOG_UCIHAL_E("[%s] Invalid packet length: %d", __func__, packet_len);
+  }
+  return false;
+}
+
 /******************************************************************************
  * Function         phNxpUciHal_client_thread
  *
@@ -151,7 +201,7 @@ static void phNxpUciHal_client_thread(phNxpUciHal_Control_t* p_nxpucihal_ctrl)
 
   while (thread_running) {
     /* Fetch next message from the UWB stack message queue */
-    auto msg = p_nxpucihal_ctrl->gDrvCfg.pClientMq->recv();
+    auto msg = p_nxpucihal_ctrl->pClientMq->recv();
 
     if (!thread_running) {
       break;
@@ -285,7 +335,6 @@ bool phNxpUciHal_parse(size_t* cmdlen, uint8_t* cmd)
  ******************************************************************************/
 tHAL_UWB_STATUS phNxpUciHal_open(uwb_stack_callback_t* p_cback, uwb_stack_data_callback_t* p_data_cback)
 {
-  static const char uwb_dev_node[256] = "/dev/srxxx";
   tHAL_UWB_STATUS wConfigStatus = UWBSTATUS_SUCCESS;
 
   if (nxpucihal_ctrl.halStatus == HAL_STATUS_OPEN) {
@@ -297,6 +346,7 @@ tHAL_UWB_STATUS phNxpUciHal_open(uwb_stack_callback_t* p_cback, uwb_stack_data_c
 
   /* initialize trace level */
   phNxpLog_InitializeLogLevel();
+  phNxpUciLog_initialize();
 
   /*Create the timer for extns write response*/
   timeoutTimerId = phOsalUwb_Timer_Create();
@@ -308,7 +358,7 @@ tHAL_UWB_STATUS phNxpUciHal_open(uwb_stack_callback_t* p_cback, uwb_stack_data_c
 
   CONCURRENCY_LOCK();
 
-  NXPLOG_UCIHAL_E("Assigning the default helios Node: %s", uwb_dev_node);
+  NXPLOG_UCIHAL_D("Assigning the default helios Node: %s", uwb_dev_node);
   /* By default HAL status is HAL_STATUS_OPEN */
   nxpucihal_ctrl.halStatus = HAL_STATUS_OPEN;
 
@@ -316,21 +366,13 @@ tHAL_UWB_STATUS phNxpUciHal_open(uwb_stack_callback_t* p_cback, uwb_stack_data_c
   nxpucihal_ctrl.p_uwb_stack_data_cback = p_data_cback;
   nxpucihal_ctrl.fw_dwnld_mode = false;
 
-  /* Configure hardware link */
-  nxpucihal_ctrl.gDrvCfg.pClientMq = std::make_shared<MessageQueue<phLibUwb_Message>>("Client");
-  nxpucihal_ctrl.gDrvCfg.nLinkType = ENUM_LINK_TYPE_SPI;
+  // Create a main message queue.
+  nxpucihal_ctrl.pClientMq = std::make_shared<MessageQueue<phLibUwb_Message>>("Client");
 
   // Default country code = '00'
   nxpucihal_ctrl.country_code[0] = '0';
   nxpucihal_ctrl.country_code[1] = '0';
 
-  /* Initialize TML layer */
-  wConfigStatus = phTmlUwb_Init(uwb_dev_node, nxpucihal_ctrl.gDrvCfg.pClientMq);
-  if (wConfigStatus != UWBSTATUS_SUCCESS) {
-    NXPLOG_UCIHAL_E("phTmlUwb_Init Failed");
-    goto clean_and_return;
-  }
-
   /* Create the client thread */
   nxpucihal_ctrl.client_thread =
     std::thread{ &phNxpUciHal_client_thread, &nxpucihal_ctrl };
@@ -346,22 +388,18 @@ tHAL_UWB_STATUS phNxpUciHal_open(uwb_stack_callback_t* p_cback, uwb_stack_data_c
   phNxpUciHal_rx_handler_add(UCI_MT_RSP, UCI_GID_CORE, UCI_MSG_CORE_GET_CAPS_INFO,
     false, phNxpUciHal_handle_get_caps_info);
 
-  /* Call open complete */
-  phTmlUwb_DeferredCall(std::make_shared<phLibUwb_Message>(UCI_HAL_OPEN_CPLT_MSG));
 
-  return UWBSTATUS_SUCCESS;
+  phNxpUciHal_rx_handler_add(UCI_MT_NTF, UCI_GID_PROPRIETARY, EXT_UCI_PROP_GEN_DEBUG_NTF_0x18, false,
+                                      nxp_properitory_ntf_skip_cb);
 
-clean_and_return:
-  CONCURRENCY_UNLOCK();
+  phNxpUciHal_rx_handler_add(UCI_MT_NTF, UCI_GID_CORE,
+                             UCI_MSG_CORE_DEVICE_STATUS_NTF, false,
+                             phNxpUciHal_handle_dev_error_ntf);
 
-  /* Report error status */
-  (*nxpucihal_ctrl.p_uwb_stack_cback)(HAL_UWB_OPEN_CPLT_EVT, HAL_UWB_ERROR_EVT);
+  /* Call open complete */
+  nxpucihal_ctrl.pClientMq->send(std::make_shared<phLibUwb_Message>(UCI_HAL_OPEN_CPLT_MSG));
 
-  nxpucihal_ctrl.p_uwb_stack_cback = NULL;
-  nxpucihal_ctrl.p_uwb_stack_data_cback = NULL;
-  phNxpUciHal_cleanup_monitor();
-  nxpucihal_ctrl.halStatus = HAL_STATUS_CLOSE;
-  return wConfigStatus;
+  return UWBSTATUS_SUCCESS;
 }
 
 /******************************************************************************
@@ -499,7 +537,7 @@ static void handle_rx_packet(uint8_t *buffer, size_t length)
     }
     // End of UCI_MT_NTF
   } else if (mt == UCI_MT_RSP) {
-    if (nxpucihal_ctrl.hal_ext_enabled) {
+    if (nxpucihal_ctrl.hal_ext_enabled && !isSkipPacket) {
       isSkipPacket = true;
 
       if (pbf) {
@@ -606,25 +644,23 @@ tHAL_UWB_STATUS phNxpUciHal_close() {
     return UWBSTATUS_FAILED;
   }
 
-  uwb_device_initialized = false;
-
   CONCURRENCY_LOCK();
 
   SessionTrack_deinit();
 
   NXPLOG_UCIHAL_D("Terminating phNxpUciHal client thread...");
-  phTmlUwb_DeferredCall(std::make_shared<phLibUwb_Message>(UCI_HAL_CLOSE_CPLT_MSG));
+  nxpucihal_ctrl.pClientMq->send(std::make_shared<phLibUwb_Message>(UCI_HAL_CLOSE_CPLT_MSG));
   nxpucihal_ctrl.client_thread.join();
 
-  status = phTmlUwb_Shutdown();
-
-  phNxpUciHal_rx_handler_destroy();
-
   nxpucihal_ctrl.halStatus = HAL_STATUS_CLOSE;
 
   CONCURRENCY_UNLOCK();
 
-  nxpucihal_ctrl.uwb_chip.reset();
+  phNxpUciHal_hw_deinit();
+
+  phNxpUciHal_rx_handler_destroy();
+
+  nxpucihal_ctrl.uwb_chip = nullptr;
 
   phOsalUwb_Timer_Cleanup();
 
@@ -632,6 +668,8 @@ tHAL_UWB_STATUS phNxpUciHal_close() {
 
   NxpConfig_Deinit();
 
+  phNxpUciLog_deinitialize();
+
   NXPLOG_UCIHAL_D("phNxpUciHal_close completed");
 
   /* Return success always */
@@ -649,31 +687,26 @@ tHAL_UWB_STATUS phNxpUciHal_close() {
  ******************************************************************************/
 static void parseAntennaConfig(const char *configName)
 {
-  std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
-  size_t retlen = 0;
-  int gotConfig = NxpConfig_GetByteArray(configName, buffer.data(), buffer.size(), &retlen);
-  if (gotConfig) {
-    if (retlen <= UCI_MSG_HDR_SIZE) {
-      NXPLOG_UCIHAL_E("parseAntennaConfig: %s is too short. Aborting.", configName);
-      return;
-    }
+  auto res = NxpConfig_GetByteArray(configName);
+  if (!res.has_value()) {
+    NXPLOG_UCIHAL_D("No antenna pair info found, %s is missing.", configName);
+    return;
   }
-  else
-  {
-    NXPLOG_UCIHAL_E("parseAntennaConfig: Failed to get '%s'. Aborting.", configName);
+  std::span<const uint8_t> data = *res;
+  if (data.size() <= UCI_MSG_HDR_SIZE) {
+    NXPLOG_UCIHAL_D("No antenna pair info found, %s is too short.", configName);
     return;
   }
 
-  const uint16_t dataLength = retlen;
-  const uint8_t *data = buffer.data();
+  int index = 1;  // Excluding number of params
+  while (index < data.size()) {
+    if ((index + 3) > data.size()) {
+      break;
+    }
+    uint8_t tagId = data[index++];
+    uint8_t subTagId = data[index++];
+    uint8_t length = data[index++];
 
-  uint8_t index = 1; // Excluding number of params
-  uint8_t tagId, subTagId;
-  int length;
-  while (index < dataLength) {
-    tagId = data[index++];
-    subTagId = data[index++];
-    length = data[index++];
     if ((ANTENNA_RX_PAIR_DEFINE_TAG_ID == tagId) &&
         (ANTENNA_RX_PAIR_DEFINE_SUB_TAG_ID == subTagId)) {
       nxpucihal_ctrl.numberOfAntennaPairs = data[index];
@@ -683,6 +716,7 @@ static void parseAntennaConfig(const char *configName)
       index = index + length;
     }
   }
+  NXPLOG_UCIHAL_D("No antenna pair info found in from %s.", configName)
 }
 
 /******************************************************************************
@@ -693,12 +727,9 @@ static void parseAntennaConfig(const char *configName)
  * Returns          status
  *
  ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_applyVendorConfig()
+static tHAL_UWB_STATUS phNxpUciHal_applyVendorConfig()
 {
   std::vector<const char *> vendorParamNames;
-  std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
-  size_t retlen = 0;
-  tHAL_UWB_STATUS status = UWBSTATUS_FAILED;
 
   // Base parameter names
   if (nxpucihal_ctrl.fw_boot_mode == USER_FW_BOOT_MODE) {
@@ -714,15 +745,15 @@ tHAL_UWB_STATUS phNxpUciHal_applyVendorConfig()
     per_chip_param = NAME_UWB_CORE_EXT_DEVICE_SR1XX_S_CONFIG;
   }
 
-  if (NxpConfig_GetByteArray(per_chip_param, buffer.data(), buffer.size(),
-                             &retlen)) {
-    if (retlen > 0 && retlen < UCI_MAX_DATA_LEN) {
-      NXPLOG_UCIHAL_D("VendorConfig: apply %s", per_chip_param);
-      status = phNxpUciHal_sendCoreConfig(buffer.data(), retlen);
-      if (status != UWBSTATUS_SUCCESS) {
-        NXPLOG_UCIHAL_E("VendorConfig: failed to apply %s", per_chip_param);
-        return status;
-      }
+  // TODO: split this into a function.
+  auto chip_pkt = NxpConfig_GetByteArray(per_chip_param);
+  if (chip_pkt.has_value()) {
+    NXPLOG_UCIHAL_D("VendorConfig: apply %s", per_chip_param);
+    tHAL_UWB_STATUS status =
+      phNxpUciHal_sendCoreConfig((*chip_pkt).data(), (*chip_pkt).size());
+    if (status != UWBSTATUS_SUCCESS) {
+      NXPLOG_UCIHAL_E("VendorConfig: failed to apply %s", per_chip_param);
+      return status;
     }
   }
 
@@ -744,29 +775,28 @@ tHAL_UWB_STATUS phNxpUciHal_applyVendorConfig()
 
   // Execute
   for (const auto paramName : vendorParamNames) {
-    if (NxpConfig_GetByteArray(paramName, buffer.data(), buffer.size(), &retlen)) {
-      if (retlen > 0 && retlen < UCI_MAX_DATA_LEN) {
-        NXPLOG_UCIHAL_D("VendorConfig: apply %s", paramName);
-        status = phNxpUciHal_send_ext_cmd(retlen, buffer.data());
-        if (status != UWBSTATUS_SUCCESS) {
-          NXPLOG_UCIHAL_E("VendorConfig: failed to apply %s", paramName);
-          return status;
-        }
+    auto extra_pkt = NxpConfig_GetByteArray(paramName);
+    if (extra_pkt.has_value()) {
+      NXPLOG_UCIHAL_D("VendorConfig: apply %s", paramName);
+      tHAL_UWB_STATUS status =
+        phNxpUciHal_send_ext_cmd((*extra_pkt).size(), (*extra_pkt).data());
+      if (status != UWBSTATUS_SUCCESS) {
+        NXPLOG_UCIHAL_E("VendorConfig: failed to apply %s", paramName);
+        return status;
       }
     }
   }
 
   // Low Power Mode
   // TODO: remove this out, this can be move to Chip parameter names
-  uint8_t lowPowerMode = 0;
-  if (NxpConfig_GetNum(NAME_NXP_UWB_LOW_POWER_MODE, &lowPowerMode, sizeof(lowPowerMode))) {
-    NXPLOG_UCIHAL_D("VendorConfig: apply %s", NAME_NXP_UWB_LOW_POWER_MODE);
+  bool lowPowerMode =  NxpConfig_GetBool(NAME_NXP_UWB_LOW_POWER_MODE).value_or(false);
+  NXPLOG_UCIHAL_D("VendorConfig: apply %s", NAME_NXP_UWB_LOW_POWER_MODE);
 
+  if (lowPowerMode) {
     // Core set config packet: GID=0x00 OID=0x04
     const std::vector<uint8_t> packet(
         {((UCI_MT_CMD << UCI_MT_SHIFT) | UCI_GID_CORE), UCI_MSG_CORE_SET_CONFIG,
-         0x00, 0x04, 0x01, LOW_POWER_MODE_TAG_ID, LOW_POWER_MODE_LENGTH,
-         lowPowerMode});
+         0x00, 0x04, 0x01, LOW_POWER_MODE_TAG_ID, LOW_POWER_MODE_LENGTH, 0x01 });
 
     if (phNxpUciHal_send_ext_cmd(packet.size(), packet.data()) != UWBSTATUS_SUCCESS) {
       NXPLOG_UCIHAL_E("VendorConfig: failed to apply NAME_NXP_UWB_LOW_POWER_MODE");
@@ -857,14 +887,14 @@ static bool cacheDevInfoRsp()
 }
 
 /******************************************************************************
- * Function         phNxpUciHal_init_hw
+ * Function         phNxpUciHal_hw_init
  *
  * Description      Init the chip.
  *
  * Returns          status
  *
  ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_init_hw()
+tHAL_UWB_STATUS phNxpUciHal_hw_init()
 {
   tHAL_UWB_STATUS status;
 
@@ -872,8 +902,14 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
     NXPLOG_UCIHAL_E("HAL not initialized");
     return UWBSTATUS_FAILED;
   }
+  nxpucihal_ctrl.uwb_device_initialized = false;
 
-  uwb_device_initialized = false;
+  // Initiates TML.
+  status = phTmlUwb_Init(uwb_dev_node, nxpucihal_ctrl.pClientMq);
+  if (status != UWBSTATUS_SUCCESS) {
+    NXPLOG_UCIHAL_E("phTmlUwb_Init Failed");
+    return status;
+  }
 
   // Device Status Notification
   UciHalSemaphore devStatusNtfWait;
@@ -895,7 +931,6 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
     return status;
   }
 
-  // Initiate UCI packet read
   status = phTmlUwb_StartRead(&phNxpUciHal_read_complete, NULL);
   if (status != UWBSTATUS_SUCCESS) {
     NXPLOG_UCIHAL_E("read status error status = %x", status);
@@ -948,13 +983,29 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
     return status;
   }
   phNxpUciHal_extcal_handle_coreinit();
+  nxpucihal_ctrl.uwb_device_initialized = true;
+  nxpucihal_ctrl.recovery_ongoing = false;
 
-  uwb_device_initialized = true;
   phNxpUciHal_getVersionInfo();
 
   return UWBSTATUS_SUCCESS;
 }
 
+void phNxpUciHal_hw_deinit()
+{
+  phTmlUwb_Shutdown();
+}
+
+void phNxpUciHal_hw_suspend()
+{
+  nxpucihal_ctrl.uwb_chip->suspend();
+}
+
+void phNxpUciHal_hw_resume()
+{
+  nxpucihal_ctrl.uwb_chip->resume();
+}
+
 /******************************************************************************
  * Function         phNxpUciHal_coreInitialization
  *
@@ -965,16 +1016,16 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
  ******************************************************************************/
 tHAL_UWB_STATUS phNxpUciHal_coreInitialization()
 {
-  tHAL_UWB_STATUS status = phNxpUciHal_init_hw();
+  tHAL_UWB_STATUS status = phNxpUciHal_hw_init();
   if (status != UWBSTATUS_SUCCESS) {
-    phTmlUwb_DeferredCall(std::make_shared<phLibUwb_Message>(UCI_HAL_ERROR_MSG));
+    nxpucihal_ctrl.pClientMq->send(std::make_shared<phLibUwb_Message>(UCI_HAL_ERROR_MSG));
     return status;
   }
 
   SessionTrack_init();
 
   // report to upper-layer
-  phTmlUwb_DeferredCall(std::make_shared<phLibUwb_Message>(UCI_HAL_INIT_CPLT_MSG));
+  nxpucihal_ctrl.pClientMq->send(std::make_shared<phLibUwb_Message>(UCI_HAL_INIT_CPLT_MSG));
 
   constexpr uint8_t dev_ready_ntf[] = {0x60, 0x01, 0x00, 0x01, 0x01};
   report_uci_message(dev_ready_ntf, sizeof(dev_ready_ntf));
@@ -982,25 +1033,6 @@ tHAL_UWB_STATUS phNxpUciHal_coreInitialization()
   return UWBSTATUS_SUCCESS;
 }
 
-/******************************************************************************
- * Function         phNxpUciHal_sessionInitialization
- *
- * Description      This function performs session initialization
- *
- * Returns          status
- *
- ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_sessionInitialization(uint32_t sessionId) {
-  NXPLOG_UCIHAL_D(" %s: Enter", __func__);
-  tHAL_UWB_STATUS status = UWBSTATUS_SUCCESS;
-
-  if (nxpucihal_ctrl.halStatus != HAL_STATUS_OPEN) {
-    NXPLOG_UCIHAL_E("HAL not initialized");
-    return UWBSTATUS_FAILED;
-  }
-  return status;
-}
-
 /******************************************************************************
  * Function         phNxpUciHal_GetMwVersion
  *
diff --git a/halimpl/hal/phNxpUciHal.h b/halimpl/hal/phNxpUciHal.h
index e7c0f7b..e16f668 100644
--- a/halimpl/hal/phNxpUciHal.h
+++ b/halimpl/hal/phNxpUciHal.h
@@ -97,7 +97,10 @@
 #define UCI_CMD_PAYLOAD_BYTE_LENGTH 1
 
 /* FW debug and crash log path */
-const char debug_log_path[] = "/data/vendor/uwb/";
+inline constexpr const char debug_log_path[] = "/data/vendor/uwb/";
+
+// Device file
+inline constexpr const char uwb_dev_node[] = "/dev/srxxx";
 
 /* UCI Data */
 #define NXP_MAX_CONFIG_STRING_LEN 2052
@@ -237,7 +240,9 @@ private:
 typedef struct phNxpUciHal_Control {
   phNxpUci_HalStatus halStatus; /* Indicate if hal is open or closed */
   std::thread client_thread;    /* Integration thread handle */
-  phLibUwb_sConfig_t gDrvCfg;   /* Driver config data */
+
+  // a main message queue on the "client" thread.
+  std::shared_ptr<MessageQueue<phLibUwb_Message>> pClientMq;
 
   std::unique_ptr<NxpUwbChip> uwb_chip;
 
@@ -271,6 +276,9 @@ typedef struct phNxpUciHal_Control {
   uint8_t cal_rx_antenna_mask;
   uint8_t cal_tx_antenna_mask;
 
+  bool_t recovery_ongoing;
+  bool_t uwb_device_initialized;
+
   // Current country code
   uint8_t country_code[2];
 } phNxpUciHal_Control_t;
@@ -296,7 +304,12 @@ struct phNxpUciHal_RxHandler;
 #define UWB_NXP_ANDROID_MW_RC_VERSION (0x02)   /* Android MW RC Version */
 #define UWB_NXP_ANDROID_MW_DROP_VERSION (0x07) /* Android MW early drops */
 /******************** UCI HAL exposed functions *******************************/
-tHAL_UWB_STATUS phNxpUciHal_init_hw();
+tHAL_UWB_STATUS phNxpUciHal_hw_init();
+void phNxpUciHal_hw_deinit();
+
+void phNxpUciHal_hw_suspend();
+void phNxpUciHal_hw_resume();
+
 tHAL_UWB_STATUS phNxpUciHal_write_unlocked(size_t cmd_len, const uint8_t* p_cmd);
 void phNxpUciHal_read_complete(void* pContext, phTmlUwb_ReadTransactInfo* pInfo);
 
@@ -304,7 +317,6 @@ void phNxpUciHal_read_complete(void* pContext, phTmlUwb_ReadTransactInfo* pInfo)
 void report_uci_message(const uint8_t* buffer, size_t len);
 
 tHAL_UWB_STATUS phNxpUciHal_uwb_reset();
-tHAL_UWB_STATUS phNxpUciHal_applyVendorConfig();
 tHAL_UWB_STATUS phNxpUciHal_process_ext_cmd_rsp(size_t cmd_len, const uint8_t *p_cmd);
 void phNxpUciHal_send_dev_error_status_ntf();
 bool phNxpUciHal_parse(size_t* data_len, uint8_t *p_data);
@@ -326,23 +338,30 @@ void phNxpUciHal_rx_handler_del(std::shared_ptr<phNxpUciHal_RxHandler> handler);
 
 class UciHalRxHandler {
 public:
-  UciHalRxHandler() {
-  }
+  UciHalRxHandler() {}
   UciHalRxHandler(uint8_t mt, uint8_t gid, uint8_t oid,
                   RxHandlerCallback callback) {
     handler_ = phNxpUciHal_rx_handler_add(mt, gid, oid, false, callback);
   }
   UciHalRxHandler& operator=(UciHalRxHandler &&handler) {
+    Unregister();
     handler_ = std::move(handler.handler_);
     return *this;
   }
-  virtual ~UciHalRxHandler() {
+
+  UciHalRxHandler(const UciHalRxHandler&) = delete;
+  UciHalRxHandler& operator=(const UciHalRxHandler& handler) = delete;
+
+  ~UciHalRxHandler() {
+    Unregister();
+  }
+private:
+  void Unregister() {
     if (handler_) {
       phNxpUciHal_rx_handler_del(handler_);
       handler_.reset();
     }
   }
-private:
   std::shared_ptr<phNxpUciHal_RxHandler> handler_;
 };
 
diff --git a/halimpl/hal/phNxpUciHal_ext.cc b/halimpl/hal/phNxpUciHal_ext.cc
index 6b8975f..3cb0502 100644
--- a/halimpl/hal/phNxpUciHal_ext.cc
+++ b/halimpl/hal/phNxpUciHal_ext.cc
@@ -13,12 +13,14 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-#include <string.h>
 #include <sys/stat.h>
 
 #include <atomic>
 #include <bitset>
+#include <limits>
 #include <map>
+#include <optional>
+#include <span>
 #include <vector>
 
 #include <cutils/properties.h>
@@ -163,32 +165,18 @@ tHAL_UWB_STATUS phNxpUciHal_send_ext_cmd(size_t cmd_len, const uint8_t* p_cmd) {
  *                  update the acutual state of operation in arg pointer
  *
  ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_set_board_config(){
-  tHAL_UWB_STATUS status;
-  uint8_t buffer[] = {0x2E,0x00,0x00,0x02,0x01,0x01};
-  /* Set the board variant configurations */
-  unsigned long num = 0;
-  NXPLOG_UCIHAL_D("%s: enter; ", __func__);
-  uint8_t boardConfig = 0, boardVersion = 0;
-
-  if(NxpConfig_GetNum(NAME_UWB_BOARD_VARIANT_CONFIG, &num, sizeof(num))){
-    boardConfig = (uint8_t)num;
-    NXPLOG_UCIHAL_D("%s: NAME_UWB_BOARD_VARIANT_CONFIG: %x", __func__,boardConfig);
-  } else {
-    NXPLOG_UCIHAL_D("%s: NAME_UWB_BOARD_VARIANT_CONFIG: failed %x", __func__,boardConfig);
-  }
-  if(NxpConfig_GetNum(NAME_UWB_BOARD_VARIANT_VERSION, &num, sizeof(num))){
-    boardVersion = (uint8_t)num;
-    NXPLOG_UCIHAL_D("%s: NAME_UWB_BOARD_VARIANT_VERSION: %x", __func__,boardVersion);
-  } else{
-    NXPLOG_UCIHAL_D("%s: NAME_UWB_BOARD_VARIANT_VERSION: failed %lx", __func__,num);
-  }
+tHAL_UWB_STATUS phNxpUciHal_set_board_config() {
+  uint8_t buffer[6] = {0x2E,0x00,0x00,0x02,0x01,0x01};
+
+  uint8_t boardConfig = NxpConfig_GetNum<uint8_t>(NAME_UWB_BOARD_VARIANT_CONFIG).value_or(0);
+  uint8_t boardVersion = NxpConfig_GetNum<uint8_t>(NAME_UWB_BOARD_VARIANT_VERSION).value_or(0);
+
+  NXPLOG_UCIHAL_D("Board variant config: config=0x%x, version=0x%x", boardConfig, boardVersion);
+
   buffer[4] = boardConfig;
   buffer[5] = boardVersion;
 
-  status = phNxpUciHal_send_ext_cmd(sizeof(buffer), buffer);
-
-  return status;
+  return phNxpUciHal_send_ext_cmd(sizeof(buffer), buffer);
 }
 
 /*******************************************************************************
@@ -484,104 +472,152 @@ static bool CountryCodeCapsApplyTxPower(void)
 
 static void extcal_do_xtal(void)
 {
-  int ret;
-
   // RF_CLK_ACCURACY_CALIB (otp supported)
   // parameters: cal.otp.xtal=0|1, cal.xtal=X
-  uint8_t otp_xtal_flag = 0;
+  constexpr std::string_view kConfKeyOtp = "cal.otp.xtal";  // as-if, safe to use data() for c-string.
+  constexpr std::string_view kConfKeyXtal = "cal.xtal";
+
   uint8_t xtal_data[32];
   size_t xtal_data_len = 0;
-
-  if (NxpConfig_GetNum("cal.otp.xtal", &otp_xtal_flag, 1) && otp_xtal_flag) {
-    nxpucihal_ctrl.uwb_chip->read_otp(EXTCAL_PARAM_CLK_ACCURACY, xtal_data, sizeof(xtal_data), &xtal_data_len);
+  bool xtal_otp_provided = false;
+
+  // Reads xtal calibration from OTP.
+  bool use_otp_xtal = NxpConfig_GetBool(kConfKeyOtp).value_or(false);
+  if (use_otp_xtal) {
+    tHAL_UWB_STATUS status = nxpucihal_ctrl.uwb_chip->read_otp(
+      EXTCAL_PARAM_CLK_ACCURACY, xtal_data, sizeof(xtal_data), &xtal_data_len);
+    xtal_otp_provided = status == UWBSTATUS_SUCCESS && xtal_data_len > 0;
   }
-  if (!xtal_data_len) {
+
+  // Reads xtal calibration from configuration file.
+  if (!xtal_otp_provided) {
+    if (use_otp_xtal) {
+      NXPLOG_UCIHAL_W("%s is set but cannot read it from otp, fallback to config.", kConfKeyOtp.data());
+    }
     size_t retlen = 0;
-    if (NxpConfig_GetByteArray("cal.xtal", xtal_data, sizeof(xtal_data), &retlen)) {
-      xtal_data_len = retlen;
+    auto res = NxpConfig_GetByteArray(kConfKeyXtal);
+    if (!res.has_value()) {
+      NXPLOG_UCIHAL_E("Failed to get clock calibration data: %s is not provided.", kConfKeyXtal.data());
+      return;
+    }
+    std::span<const uint8_t> data = *res;
+    if (data.empty() || data.size() > sizeof(xtal_data)) {
+      NXPLOG_UCIHAL_E("Failed to get clock calibration data: cannot parse %s", kConfKeyXtal.data());
+      return;
     }
+    memcpy(xtal_data, data.data(), data.size());
+    xtal_data_len = data.size();
   }
 
-  if (xtal_data_len) {
-    NXPLOG_UCIHAL_D("Apply CLK_ACCURARY (len=%zu, from-otp=%c)", xtal_data_len, otp_xtal_flag ? 'y' : 'n');
+  NXPLOG_UCIHAL_D("Apply CLK_ACCURARY (len=%zu, from-otp=%c)", xtal_data_len, xtal_otp_provided ? 'y' : 'n');
 
-    ret = nxpucihal_ctrl.uwb_chip->apply_calibration(EXTCAL_PARAM_CLK_ACCURACY, 0, xtal_data, xtal_data_len);
-
-    if (ret != UWBSTATUS_SUCCESS) {
-      NXPLOG_UCIHAL_E("Failed to apply CLK_ACCURACY (len=%zu, from-otp=%c)",
-          xtal_data_len, otp_xtal_flag ? 'y' : 'n');
-    }
+  tHAL_UWB_STATUS ret =
+    nxpucihal_ctrl.uwb_chip->apply_calibration(
+      EXTCAL_PARAM_CLK_ACCURACY, 0, xtal_data, xtal_data_len);
+  if (ret != UWBSTATUS_SUCCESS) {
+    NXPLOG_UCIHAL_E("Failed to apply CLK_ACCURACY.");
   }
 }
 
-static void extcal_do_ant_delay(void)
+// Returns a pair of limit values <lower limit, upper limit>
+static std::pair<uint16_t, uint16_t> extcal_get_ant_delay_limits(uint8_t ant_id, uint8_t ch)
 {
-  std::bitset<8> rx_antenna_mask(nxpucihal_ctrl.cal_rx_antenna_mask);
-  const uint8_t n_rx_antennas = rx_antenna_mask.size();
+  constexpr uint16_t def_lower_limit = std::numeric_limits<uint16_t>::min();
+  constexpr uint16_t def_upper_limit = std::numeric_limits<uint16_t>::max();
 
-  const uint8_t *cal_channels = NULL;
-  uint8_t nr_cal_channels = 0;
-  nxpucihal_ctrl.uwb_chip->get_supported_channels(&cal_channels, &nr_cal_channels);
+  const std::string key_lower_limit = std::format("cal.ant{}.ch{}.ant_delay.lower_limit", ant_id, ch);
+  const std::string key_upper_limit = std::format("cal.ant{}.ch{}.ant_delay.upper_limit", ant_id, ch);
 
-  // RX_ANT_DELAY_CALIB
-  // parameter: cal.ant<N>.ch<N>.ant_delay=X
-  // N(1) + N * {AntennaID(1), Rxdelay(Q14.2)}
-  if (n_rx_antennas) {
-    for (int i = 0; i < nr_cal_channels; i++) {
-      uint8_t ch = cal_channels[i];
-      std::vector<uint8_t> entries;
-      uint8_t n_entries = 0;
+  uint16_t lower_limit = NxpConfig_GetNum<uint16_t>(
+    key_lower_limit, /*include_factory=*/false).value_or(def_lower_limit);
+  uint16_t upper_limit = NxpConfig_GetNum<uint16_t>(
+    key_upper_limit, /*include_factory=*/false).value_or(def_upper_limit);
 
-      for (auto i = 0; i < n_rx_antennas; i++) {
-        if (!rx_antenna_mask[i])
-          continue;
+  return std::make_pair(lower_limit, upper_limit);
+}
 
-        const uint8_t ant_id = i + 1;
+static void extcal_do_ant_delay_ch(const std::bitset<8> rx_antenna_mask, uint8_t ch)
+{
+  std::vector<uint8_t> entries;
+  uint8_t n_entries = 0;
 
-        uint16_t delay_value, version_value;
-        bool value_provided = false;
+  for (auto i = 0; i < rx_antenna_mask.size(); i++) {
+    if (!rx_antenna_mask.test(i)) { continue; }
 
-        const std::string key_ant_delay = std::format("cal.ant{}.ch{}.ant_delay", ant_id, ch);
-        const std::string key_force_version = key_ant_delay + std::format(".force_version", ant_id, ch);
+    const uint8_t ant_id = i + 1;
 
-        // 1) try cal.ant{N}.ch{N}.ant_delay.force_value.{N}
-        if (NxpConfig_GetNum(key_force_version.c_str(), &version_value, 2)) {
-          const std::string key_force_value = key_ant_delay + std::format(".force_value.{}", ant_id, ch, version_value);
-          if (NxpConfig_GetNum(key_force_value.c_str(), &delay_value, 2)) {
-            value_provided = true;
-            NXPLOG_UCIHAL_D("Apply RX_ANT_DELAY_CALIB %s = %u", key_force_value.c_str(), delay_value);
-          }
-        }
+    const std::string key_ant_delay = std::format("cal.ant{}.ch{}.ant_delay", ant_id, ch);
+    const std::string key_force_version = key_ant_delay + ".force_version";
 
-        // 2) try cal.ant{N}.ch{N}.ant_delay
-        if (!value_provided) {
-          if (NxpConfig_GetNum(key_ant_delay.c_str(), &delay_value, 2)) {
-            value_provided = true;
-            NXPLOG_UCIHAL_D("Apply RX_ANT_DELAY_CALIB: %s = %u", key_ant_delay.c_str(), delay_value);
-          }
-        }
+    std::optional<uint16_t> delay_value;
 
-        if (!value_provided) {
-          NXPLOG_UCIHAL_V("%s was not provided from configuration files.", key_ant_delay.c_str());
-          continue;
-        }
+    // 1) try cal.ant{N}.ch{N}.ant_delay.force_value.{N}
+    std::optional<uint16_t> force_version = NxpConfig_GetNum<uint16_t>(key_force_version);
+    if (force_version.has_value()) {
+      const std::string key_force_value = key_ant_delay + std::format(".force_value.{}", *force_version);
+      delay_value = NxpConfig_GetNum<uint16_t>(key_force_value);
+      if (delay_value.has_value()) {
+        NXPLOG_UCIHAL_D("Apply RX_ANT_DELAY_CALIB %s = %u", key_force_value.c_str(), *delay_value);
+      }
+    }
 
-        entries.push_back(ant_id);
-        // Little Endian
-        entries.push_back(delay_value & 0xff);
-        entries.push_back(delay_value >> 8);
-        n_entries++;
+    // 2) try cal.ant{N}.ch{N}.ant_delay
+    if (!delay_value.has_value()) {
+      delay_value = NxpConfig_GetNum<uint16_t>(key_ant_delay);
+      if (delay_value.has_value()) {
+        NXPLOG_UCIHAL_D("Apply RX_ANT_DELAY_CALIB: %s = %u", key_ant_delay.c_str(), *delay_value);
       }
+    }
 
-      if (!n_entries)
-        continue;
+    if (!delay_value.has_value()) {
+      NXPLOG_UCIHAL_V("%s was not provided from configuration files.", key_ant_delay.c_str());
+      return;
+    }
 
-      entries.insert(entries.begin(), n_entries);
-      tHAL_UWB_STATUS ret = nxpucihal_ctrl.uwb_chip->apply_calibration(EXTCAL_PARAM_RX_ANT_DELAY, ch, entries.data(), entries.size());
-      if (ret != UWBSTATUS_SUCCESS) {
-        NXPLOG_UCIHAL_E("Failed to apply RX_ANT_DELAY for channel %u", ch);
-      }
+    // clamping
+    uint16_t clamped_delay = *delay_value;
+    std::pair<uint16_t, uint16_t> limits = extcal_get_ant_delay_limits(ant_id, ch);
+    if (clamped_delay < limits.first) { clamped_delay = limits.first; }
+    if (clamped_delay > limits.second) { clamped_delay = limits.second; }
+
+    if (clamped_delay != delay_value) {
+      NXPLOG_UCIHAL_W("Clamping %s to %u", key_ant_delay.c_str(), clamped_delay);
     }
+
+    entries.push_back(ant_id);
+    // Little Endian
+    entries.push_back(clamped_delay & 0xff);
+    entries.push_back(clamped_delay >> 8);
+    n_entries++;
+  }
+
+  if (!n_entries) { return; }
+
+  entries.insert(entries.begin(), n_entries);
+  tHAL_UWB_STATUS ret = nxpucihal_ctrl.uwb_chip->apply_calibration(EXTCAL_PARAM_RX_ANT_DELAY, ch, entries.data(), entries.size());
+  if (ret != UWBSTATUS_SUCCESS) {
+    // TODO: halt the chip when this failed.
+    NXPLOG_UCIHAL_E("Failed to apply RX_ANT_DELAY for channel %u", ch);
+  }
+}
+
+static void extcal_do_ant_delay(void)
+{
+  const std::bitset<8> rx_antenna_mask(nxpucihal_ctrl.cal_rx_antenna_mask);
+  if (rx_antenna_mask.none()) {
+    NXPLOG_UCIHAL_E("No rx_antenna_mask defined by configuration file. Please check your configurations files (and HAL codes).")
+    return;
+  }
+
+  const uint8_t *cal_channels = NULL;
+  uint8_t nr_cal_channels = 0;
+  nxpucihal_ctrl.uwb_chip->get_supported_channels(&cal_channels, &nr_cal_channels);
+
+  // RX_ANT_DELAY_CALIB
+  // parameter: cal.ant<N>.ch<N>.ant_delay=X
+  // N(1) + N * {AntennaID(1), Rxdelay(Q14.2)}
+  for (int i = 0; i < nr_cal_channels; i++) {
+    extcal_do_ant_delay_ch(rx_antenna_mask, cal_channels[i]);
   }
 }
 
@@ -606,19 +642,17 @@ static void extcal_do_tx_power(void)
         if (!tx_antenna_mask[i])
           continue;
 
-        char key[32];
         const uint8_t ant_id = i + 1;
-        std::snprintf(key, sizeof(key), "cal.ant%u.ch%u.tx_power", ant_id, ch);
 
-        uint8_t power_value[32];
-        size_t retlen = 0;
-        if (!NxpConfig_GetByteArray(key, power_value, sizeof(power_value), &retlen)) {
+        std::string key = std::format("cal.ant{}.ch{}.tx_power", ant_id, ch);
+        std::optional<std::span<const uint8_t>> res = NxpConfig_GetByteArray(key);
+        if (!res.has_value()) {
           continue;
         }
-
-        NXPLOG_UCIHAL_D("Apply TX_POWER: %s = { %zu bytes }", key, retlen);
+        std::span<const uint8_t> pkt = *res;
+        NXPLOG_UCIHAL_D("Apply TX_POWER: %s = { %zu bytes }", key.c_str(), (*res).size());
         entries.push_back(ant_id);
-        entries.insert(entries.end(), power_value, power_value + retlen);
+        entries.insert(entries.end(), pkt.begin(), pkt.end());
         n_entries++;
       }
 
@@ -636,14 +670,12 @@ static void extcal_do_tx_power(void)
 
 static void extcal_do_tx_pulse_shape(void)
 {
-  // parameters: cal.tx_pulse_shape={...}
-  size_t retlen = 0;
-  uint8_t data[64];
-
-  if (NxpConfig_GetByteArray("cal.tx_pulse_shape", data, sizeof(data), &retlen) && retlen) {
-      NXPLOG_UCIHAL_D("Apply TX_PULSE_SHAPE: data = { %zu bytes }", retlen);
+  std::optional<std::span<const uint8_t>> res = NxpConfig_GetByteArray("cal.tx_pulse_shape");
+  if (res.has_value()) {
+      NXPLOG_UCIHAL_D("Apply TX_PULSE_SHAPE: data = { %zu bytes }", (*res).size());
 
-      tHAL_UWB_STATUS ret = nxpucihal_ctrl.uwb_chip->apply_calibration(EXTCAL_PARAM_TX_PULSE_SHAPE, 0, data, (size_t)retlen);
+      tHAL_UWB_STATUS ret = nxpucihal_ctrl.uwb_chip->apply_calibration(
+        EXTCAL_PARAM_TX_PULSE_SHAPE, /*ch=*/0, (*res).data(), (*res).size());
       if (ret != UWBSTATUS_SUCCESS) {
         NXPLOG_UCIHAL_E("Failed to apply TX_PULSE_SHAPE.");
       }
@@ -654,27 +686,20 @@ static void extcal_do_tx_base_band(void)
 {
   // TX_BASE_BAND_CONTROL, DDFS_TONE_CONFIG
   // parameters: cal.ddfs_enable=1|0, cal.dc_suppress=1|0, ddfs_tone_config={...}
-  uint8_t ddfs_enable = 0, dc_suppress = 0;
-  uint8_t ddfs_tone[256];
-  size_t retlen = 0;
-  tHAL_UWB_STATUS ret;
-
-  if (NxpConfig_GetNum("cal.ddfs_enable", &ddfs_enable, 1)) {
-    NXPLOG_UCIHAL_D("Apply TX_BASE_BAND_CONTROL: ddfs_enable=%u", ddfs_enable);
-  }
-  if (NxpConfig_GetNum("cal.dc_suppress", &dc_suppress, 1)) {
-    NXPLOG_UCIHAL_D("Apply TX_BASE_BAND_CONTROL: dc_suppress=%u", dc_suppress);
-  }
+  bool ddfs_enable = NxpConfig_GetBool("cal.ddfs_enable").value_or(false);
+  bool dc_suppress = NxpConfig_GetBool("cal.dc_suppress").value_or(false);
 
   // DDFS_TONE_CONFIG
   if (ddfs_enable) {
-    if (!NxpConfig_GetByteArray("cal.ddfs_tone_config", ddfs_tone, sizeof(ddfs_tone), &retlen) || !retlen) {
+    std::optional<std::span<const uint8_t>> ddfs_tone = NxpConfig_GetByteArray("cal.ddfs_tone_config");
+    if (!ddfs_tone.has_value()) {
       NXPLOG_UCIHAL_E("cal.ddfs_tone_config is not supplied while cal.ddfs_enable=1, ddfs was not enabled.");
       ddfs_enable = 0;
     } else {
-      NXPLOG_UCIHAL_D("Apply DDFS_TONE_CONFIG: ddfs_tone_config = { %zu bytes }", retlen);
+      NXPLOG_UCIHAL_D("Apply DDFS_TONE_CONFIG: ddfs_tone_config = { %zu bytes }", (*ddfs_tone).size());
 
-      ret = nxpucihal_ctrl.uwb_chip->apply_calibration(EXTCAL_PARAM_DDFS_TONE_CONFIG, 0, ddfs_tone, (size_t)retlen);
+      tHAL_UWB_STATUS ret = nxpucihal_ctrl.uwb_chip->apply_calibration(EXTCAL_PARAM_DDFS_TONE_CONFIG,
+        /*ch=*/0, (*ddfs_tone).data(), (*ddfs_tone).size());
       if (ret != UWBSTATUS_SUCCESS) {
         NXPLOG_UCIHAL_E("Failed to apply DDFS_TONE_CONFIG, ddfs was not enabled.");
         ddfs_enable = 0;
@@ -683,16 +708,13 @@ static void extcal_do_tx_base_band(void)
   }
 
   // TX_BASE_BAND_CONTROL
-  {
-    uint8_t flag = 0;
-    if (ddfs_enable)
-      flag |= 0x01;
-    if (dc_suppress)
-      flag |= 0x02;
-    ret = nxpucihal_ctrl.uwb_chip->apply_calibration(EXTCAL_PARAM_TX_BASE_BAND_CONTROL, 0, &flag, 1);
-    if (ret) {
-      NXPLOG_UCIHAL_E("Failed to apply TX_BASE_BAND_CONTROL");
-    }
+  uint8_t flag = 0;
+  if (ddfs_enable) { flag |= 0x01; }
+  if (dc_suppress) { flag |= 0x02; }
+  tHAL_UWB_STATUS ret = nxpucihal_ctrl.uwb_chip->apply_calibration(EXTCAL_PARAM_TX_BASE_BAND_CONTROL,
+    /*ch=*/0, &flag, 1);
+  if (ret) {
+    NXPLOG_UCIHAL_E("Failed to apply TX_BASE_BAND_CONTROL");
   }
 }
 
@@ -707,16 +729,20 @@ static void extcal_do_tx_base_band(void)
 void phNxpUciHal_extcal_handle_coreinit(void)
 {
   // read rx_aantenna_mask, tx_antenna_mask
-  uint8_t rx_antenna_mask_n = 0x1;
-  uint8_t tx_antenna_mask_n = 0x1;
-  if (!NxpConfig_GetNum("cal.rx_antenna_mask", &rx_antenna_mask_n, 1)) {
-      NXPLOG_UCIHAL_E("cal.rx_antenna_mask is not specified, use default 0x%x", rx_antenna_mask_n);
+  auto res = NxpConfig_GetNum<uint8_t>("cal.rx_antenna_mask");
+  if (!res.has_value()) {
+    NXPLOG_UCIHAL_W("cal.tx_antenna_mask is not specified, use default value.");
   }
-  if (!NxpConfig_GetNum("cal.tx_antenna_mask", &tx_antenna_mask_n, 1)) {
-      NXPLOG_UCIHAL_E("cal.tx_antenna_mask is not specified, use default 0x%x", tx_antenna_mask_n);
+  nxpucihal_ctrl.cal_rx_antenna_mask = res.value_or(0x01);
+
+  res = NxpConfig_GetNum<uint8_t>("cal.tx_antenna_mask");
+  if (!res.has_value()) {
+      NXPLOG_UCIHAL_W("cal.tx_antenna_mask is not specified, use default value.");
   }
-  nxpucihal_ctrl.cal_rx_antenna_mask = rx_antenna_mask_n;
-  nxpucihal_ctrl.cal_tx_antenna_mask = tx_antenna_mask_n;
+  nxpucihal_ctrl.cal_tx_antenna_mask = res.value_or(0x01);
+
+  NXPLOG_UCIHAL_D("tx_antenna_mask=0x%x, rx_antenna_mask=0x%x",
+    nxpucihal_ctrl.cal_tx_antenna_mask, nxpucihal_ctrl.cal_rx_antenna_mask);
 
   extcal_do_xtal();
   extcal_do_ant_delay();
@@ -765,24 +791,23 @@ void phNxpUciHal_handle_set_country_code(const char country_code[2])
     phNxpUciHal_resetRuntimeSettings();
 
     // Load ExtraCal restrictions
-    uint16_t mask= 0;
-    if (NxpConfig_GetNum("cal.restricted_channels", &mask, sizeof(mask))) {
+    uint16_t mask = NxpConfig_GetNum<uint16_t>("cal.restricted_channels").value_or(0);
+    if (mask != 0) {
       NXPLOG_UCIHAL_D("Restriction flag, restricted channel mask=0x%x", mask);
       rt_set->restricted_channel_mask = mask;
     }
 
-    uint8_t uwb_disable = 0;
-    if (NxpConfig_GetNum("cal.uwb_disable", &uwb_disable, sizeof(uwb_disable))) {
-      NXPLOG_UCIHAL_D("Restriction flag, uwb_disable=%u", uwb_disable);
-      rt_set->uwb_enable = !uwb_disable;
+    if (NxpConfig_GetBool("cal.uwb_disable").value_or(false)) {
+      NXPLOG_UCIHAL_D("Restriction flag, uwb_disable set");
+      rt_set->uwb_enable = 0;
     }
 
     // Apply COUNTRY_CODE_CAPS
-    uint8_t cc_caps[UCI_MAX_DATA_LEN];
-    size_t retlen = 0;
-    if (NxpConfig_GetByteArray(NAME_NXP_UWB_COUNTRY_CODE_CAPS, cc_caps, sizeof(cc_caps), &retlen) && retlen) {
+    std::optional<std::span<const uint8_t>> cc_caps =
+      NxpConfig_GetByteArray(NAME_NXP_UWB_COUNTRY_CODE_CAPS);
+    if (cc_caps.has_value()) {
       NXPLOG_UCIHAL_D("COUNTRY_CODE_CAPS is provided.");
-      phNxpUciHal_applyCountryCaps(country_code, cc_caps, retlen);
+      phNxpUciHal_applyCountryCaps(country_code, (*cc_caps).data(), (*cc_caps).size());
     }
 
     // Check country code validity
@@ -974,15 +999,12 @@ bool phNxpUciHal_handle_get_caps_info(size_t data_len, const uint8_t *p_data)
   }
 
   // Append UWB_VENDOR_CAPABILITY from configuration files
-  {
-    std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
-    size_t retlen = 0;
-    if (NxpConfig_GetByteArray(NAME_UWB_VENDOR_CAPABILITY, buffer.data(),
-                               buffer.size(), &retlen) && retlen) {
-      auto vendorTlvs = decodeTlvBytes({}, buffer.data(), retlen);
-      for (auto const& [key, val] : vendorTlvs) {
-        tlvs[key] = val;
-      }
+  std::optional<std::span<const uint8_t>> vcaps =
+    NxpConfig_GetByteArray(NAME_UWB_VENDOR_CAPABILITY);
+  if (vcaps.has_value()) {
+    auto vendorTlvs = decodeTlvBytes(/*ext_ids=*/{}, (*vcaps).data(), (*vcaps).size());
+    for (auto const& [key, val] : vendorTlvs) {
+      tlvs[key] = val;
     }
   }
 
diff --git a/halimpl/hal/phNxpUciHal_ext.h b/halimpl/hal/phNxpUciHal_ext.h
index bff986e..6bd562f 100644
--- a/halimpl/hal/phNxpUciHal_ext.h
+++ b/halimpl/hal/phNxpUciHal_ext.h
@@ -35,6 +35,13 @@
 #define UCI_EXT_PARAM_TX_PULSE_SHAPE_CONFIG    0x28
 #define UCI_EXT_PARAM_CLK_CONFIG_CTRL          0x30
 
+#define EXT_UCI_MSG_DBG_DATA_LOGGER_NTF 0x01
+#define EXT_UCI_MSG_DBG_GET_ERROR_LOG 0x02
+#define EXT_UCI_MSG_DBG_PSDU_LOG_NTF 0x33
+#define EXT_UCI_MSG_DBG_CIR_LOG_NTF 0x34
+
+#define EXT_UCI_PROP_GEN_DEBUG_NTF_0x18        0x18
+
 #define UCI_PARAM_ID_LOW_POWER_MODE            0x01
 
 /* customer specific calib params */
diff --git a/halimpl/hal/sessionTrack.cc b/halimpl/hal/sessionTrack.cc
index af3ebdb..f033f4d 100644
--- a/halimpl/hal/sessionTrack.cc
+++ b/halimpl/hal/sessionTrack.cc
@@ -1,6 +1,8 @@
 #include <bit>
 #include <mutex>
 #include <random>
+#include <optional>
+#include <span>
 #include <thread>
 #include <unordered_map>
 #include <vector>
@@ -26,10 +28,12 @@ extern phNxpUciHal_Control_t nxpucihal_ctrl;
 //
 // 2. Issue URSK_DELETE_CMD on SESSION_DEINIT_RSP (optional/experimental)
 //
-// Calls URSK_DELETE_CMD for every CCC session closing,
-// for the cases where CCC session ID was created but not started.
-// (This is only activated when DELETE_URSK_FOR_CCC_SESSION=1 is set
-// from config)
+// Calls URSK_DELETE_CMD for every aliro or CCC session closing,
+// for the cases where aliro or CCC session ID was created but not started.
+// This behavior is controlled via configuration flags:
+// - DELETE_URSK_FOR_CCC_SESSION=1
+// - DELETE_URSK_FOR_ALIRO_SESSION=1
+// If enabled, the command will be issued accordingly.
 //
 // 3. Call suspend to kernel driver on idle (optional/experimental)
 //
@@ -95,6 +99,10 @@ private:
   static constexpr long kQueueTimeoutMs = 2000;
   static constexpr long kUrskDeleteNtfTimeoutMs = 500;
 
+  // used when unregistered session handle is processed.
+  static constexpr uint32_t kUnknownSessionId = 0xFFFFFFFF;
+  static constexpr uint8_t kUnknownSessionType = 0xFF;
+
 private:
   std::shared_ptr<phNxpUciHal_RxHandler> rx_handler_session_status_ntf_;
   std::unordered_map<uint32_t, std::shared_ptr<SessionInfo>> sessions_;
@@ -102,10 +110,11 @@ private:
 
   bool auto_suspend_enabled_;
   bool delete_ursk_ccc_enabled_;
+  bool delete_ursk_aliro_enabled_;
   bool calibration_delayed_;
   std::atomic<PowerState> power_state_;
   bool idle_timer_started_;
-  unsigned long idle_timeout_ms_;
+  uint32_t idle_timeout_ms_;
   bool override_sts_index_for_ccc_;
 
   std::thread worker_thread_;
@@ -115,34 +124,30 @@ private:
 
 public:
   SessionTrack() :
-    auto_suspend_enabled_(false),
-    delete_ursk_ccc_enabled_(false),
-    calibration_delayed_(false),
-    power_state_(PowerState::IDLE),
-    idle_timer_started_(false),
-    idle_timeout_ms_(kAutoSuspendTimeoutDefaultMs_),
-    override_sts_index_for_ccc_(true)
-  {
+      calibration_delayed_(false),
+      power_state_(PowerState::IDLE),
+      idle_timer_started_(false)  {
     sessions_.clear();
 
     msgq_ = std::make_unique<MessageQueue<SessionTrackMsg>>("SessionTrack");
     worker_thread_ = std::thread(&SessionTrack::PowerManagerWorker, this);
 
-    unsigned long numval = 0;
+    delete_ursk_ccc_enabled_ =
+        NxpConfig_GetBool(NAME_DELETE_URSK_FOR_CCC_SESSION).value_or(false);
 
-    if (NxpConfig_GetNum(NAME_DELETE_URSK_FOR_CCC_SESSION, &numval, sizeof(numval)) && numval) {
-      delete_ursk_ccc_enabled_ = true;
-    }
+    delete_ursk_aliro_enabled_ =
+        NxpConfig_GetBool(NAME_DELETE_URSK_FOR_ALIRO_SESSION).value_or(false);
 
     // Default on
-    if (NxpConfig_GetNum(NAME_OVERRIDE_STS_INDEX_FOR_CCC_SESSION, &numval, sizeof(numval)) && !numval) {
-      override_sts_index_for_ccc_ = false;
-    }
+    override_sts_index_for_ccc_ =
+      NxpConfig_GetBool(NAME_OVERRIDE_STS_INDEX_FOR_CCC_SESSION).value_or(true);
 
-    if (NxpConfig_GetNum(NAME_AUTO_SUSPEND_ENABLE, &numval, sizeof(numval)) && numval) {
-      auto_suspend_enabled_ = true;
+    auto_suspend_enabled_ =
+      NxpConfig_GetBool(NAME_AUTO_SUSPEND_ENABLE).value_or(false);
 
-      NxpConfig_GetNum(NAME_AUTO_SUSPEND_TIMEOUT_MS, &idle_timeout_ms_, sizeof(idle_timeout_ms_));
+    if (auto_suspend_enabled_) {
+      idle_timeout_ms_ = NxpConfig_GetNum<uint32_t>(
+        NAME_AUTO_SUSPEND_TIMEOUT_MS).value_or(kAutoSuspendTimeoutDefaultMs_);
 
       // Idle timer is only activated when AUTO_SUSPEND_ENABLED=1
       // device suspend won't be triggered when it's not activated.
@@ -180,28 +185,17 @@ public:
     auto session_init_rsp_cb =
       [this, session_id, session_type](size_t packet_len, const uint8_t *packet) -> bool
     {
-      if (packet_len != UCI_MSG_SESSION_STATE_INIT_RSP_LEN )
+      if (packet_len != UCI_MSG_SESSION_STATE_INIT_RSP_LEN) {
+        NXPLOG_UCIHAL_E("Unrecognized SessionInitRsp");
         return false;
+      }
 
       uint8_t status = packet[UCI_MSG_SESSION_STATE_INIT_RSP_STATUS_OFFSET];
-      uint32_t handle = le_bytes_to_cpu<uint32_t>(&packet[UCI_MSG_SESSION_STATE_INIT_RSP_HANDLE_OFFSET]);
       if (status != UWBSTATUS_SUCCESS)
         return false;
 
-      bool was_idle;
-      {
-        std::lock_guard<std::mutex> lock(sessions_lock_);
-
-        was_idle = IsDeviceIdle();
-
-        sessions_.emplace(std::make_pair(handle,
-                                         std::make_shared<SessionInfo>(session_id, session_type)));
-      }
-      if (was_idle) {
-        NXPLOG_UCIHAL_D("Queue Active");
-        QueueSessionTrackWork(SessionTrackWorkType::ACTIVATE);
-      }
-
+      uint32_t handle = le_bytes_to_cpu<uint32_t>(&packet[UCI_MSG_SESSION_STATE_INIT_RSP_HANDLE_OFFSET]);
+      AddNewSession(handle, session_id, session_type);
       return false;
     };
 
@@ -214,10 +208,11 @@ public:
   // Called by upper-layer's SetAppConfig command handler
   void OnChannelConfig(uint32_t session_handle, uint8_t channel) {
     // Update channel info
-    std::lock_guard<std::mutex> lock(sessions_lock_);
     auto pSessionInfo = GetSessionInfo(session_handle);
-    if (!pSessionInfo)
-      return;
+    if (!pSessionInfo) {
+      NXPLOG_UCIHAL_E("Unrecognized session app config detected, handle=0x%x", session_handle);
+      pSessionInfo = AddNewSession(session_handle, kUnknownSessionId, kUnknownSessionType);
+    }
     pSessionInfo->channel_ = channel;
   }
 
@@ -274,15 +269,18 @@ public:
 
     uint32_t session_handle = le_bytes_to_cpu<uint32_t>(&packet[UCI_MSG_SESSION_START_HANDLE_OFFSET]);
 
-    std::shared_ptr<SessionInfo> pSessionInfo;
-    {
-      std::lock_guard<std::mutex> lock(sessions_lock_);
-      pSessionInfo = GetSessionInfo(session_handle);
-    }
+    std::shared_ptr<SessionInfo> pSessionInfo = GetSessionInfo(session_handle);
 
     // Check STS_INDEX and fetch if it was not set by upper-layer
-    if (!pSessionInfo || pSessionInfo->session_type_ != kSessionType_CCCRanging)
+    if (!pSessionInfo) {
+      NXPLOG_UCIHAL_E("Unrecognized session start detected, handle=0x%x", session_handle);
+      pSessionInfo = AddNewSession(session_handle, kUnknownSessionId, kUnknownSessionType);
+    }
+
+    // Patches STS_INDEX only for CCC session.
+    if (pSessionInfo->session_type_ != kSessionType_CCCRanging) {
       return;
+    }
 
     auto result = QueryStsIndex(session_handle);
     if (!result.first) {
@@ -338,7 +336,7 @@ private:
       return;
 
     phNxpUciHal_Sem_t urskDeleteNtfWait;
-    phNxpUciHal_init_cb_data(&urskDeleteNtfWait, NULL);
+    phNxpUciHal_init_cb_data(&urskDeleteNtfWait);
 
     phNxpUciHal_rx_handler_add(UCI_MT_RSP, UCI_GID_PROPRIETARY_0X0F,
       UCI_MSG_URSK_DELETE, true,
@@ -523,39 +521,32 @@ private:
     uint32_t session_handle = le_bytes_to_cpu<uint32_t>(&packet[UCI_MSG_SESSION_STATUS_NTF_HANDLE_OFFSET]);
     uint8_t session_state = packet[UCI_MSG_SESSION_STATUS_NTF_STATE_OFFSET];
 
-    bool is_idle = false;
-    {
-      std::lock_guard<std::mutex> lock(sessions_lock_);
-
-      auto pSessionInfo = GetSessionInfo(session_handle);
-      if (pSessionInfo) {
-        NXPLOG_UCIHAL_D("SessionTrack: update session handle 0x%08x state %u", session_handle, session_state);
-        pSessionInfo->session_state_ = session_state;
-      }
+    auto pSessionInfo = GetSessionInfo(session_handle);
+    if (pSessionInfo == nullptr) {
+      NXPLOG_UCIHAL_E("SessionTrack: Unrecognized session status received, handle=0x%x", session_handle);
+      AddNewSession(session_handle, kUnknownSessionId, kUnknownSessionType);
+      pSessionInfo = GetSessionInfo(session_handle);
+    }
 
-      if (session_state == UCI_MSG_SESSION_STATE_DEINIT) {
-        NXPLOG_UCIHAL_D("SessionTrack: remove session handle 0x%08x", session_handle);
+    NXPLOG_UCIHAL_D("SessionTrack: update session handle 0x%08x state %u", session_handle, session_state);
+    pSessionInfo->session_state_ = session_state;
 
-        if (delete_ursk_ccc_enabled_ && pSessionInfo &&
-            pSessionInfo->session_type_ == kSessionType_CCCRanging) {
+    if (session_state == UCI_MSG_SESSION_STATE_DEINIT) {
+      if ((delete_ursk_ccc_enabled_ &&
+          pSessionInfo->session_type_ == kSessionType_CCCRanging)
+          || (delete_ursk_aliro_enabled_ &&
+            pSessionInfo->session_type_ == kSessionType_AliroRanging)) {
 
-          // If this CCC ranging session, issue DELETE_URSK_CMD for this session.
-          // This is executed on client thread, we shouldn't block the execution of this thread.
-          QueueDeleteUrsk(pSessionInfo);
-        }
-        sessions_.erase(session_handle);
-        is_idle = IsDeviceIdle();
-      } else if (session_state == UCI_MSG_SESSION_STATE_ACTIVE) {
-        // mark this session has been started at
-        pSessionInfo->ranging_started_ = true;
+        // If CCC or Aliro ranging session, issue DELETE_URSK_CMD for this
+        // session. This is executed on client thread, we shouldn't block the
+        // execution of this thread.
+        QueueDeleteUrsk(pSessionInfo);
       }
+      RemoveSession(session_handle);
+    } else if (session_state == UCI_MSG_SESSION_STATE_ACTIVE) {
+      // mark this session has been started at
+      pSessionInfo->ranging_started_ = true;
     }
-
-    if (is_idle) { // transition to IDLE
-      NXPLOG_UCIHAL_D("Queue Idle");
-      QueueSessionTrackWork(SessionTrackWorkType::IDLE);
-    }
-
     return false;
   }
 
@@ -580,7 +571,7 @@ private:
     if (!auto_suspend_enabled_)
       return;
 
-    NXPLOG_UCIHAL_D("SessionTrack: refresh idle timer, %lums", idle_timeout_ms_);
+    NXPLOG_UCIHAL_D("SessionTrack: refresh idle timer, %ums", idle_timeout_ms_);
     if (idle_timer_started_) {
       if (phOsalUwb_Timer_Stop(idle_timer_) != UWBSTATUS_SUCCESS) {
         NXPLOG_UCIHAL_E("SessionTrack: idle timer stop failed");
@@ -621,7 +612,7 @@ private:
       case SessionTrackWorkType::REFRESH_IDLE:
         if (power_state_ == PowerState::SUSPEND) {
           NXPLOG_UCIHAL_D("SessionTrack: resume");
-          phTmlUwb_Resume();
+          phNxpUciHal_hw_resume();
           power_state_ = PowerState::IDLE;
         }
         if (power_state_ == PowerState::IDLE) {
@@ -631,7 +622,7 @@ private:
       case SessionTrackWorkType::ACTIVATE:
         if (power_state_ == PowerState::SUSPEND) {
           NXPLOG_UCIHAL_E("SessionTrack: activated while in suspend!");
-          phTmlUwb_Resume();
+          phNxpUciHal_hw_resume();
         }
         PowerIdleTimerStop();
         power_state_ = PowerState::ACTIVE;
@@ -640,7 +631,7 @@ private:
         if (power_state_ == PowerState::IDLE) {
           NXPLOG_UCIHAL_D("SessionTrack: idle timer expired, go suspend");
           power_state_ = PowerState::SUSPEND;
-          phTmlUwb_Suspend();
+          phNxpUciHal_hw_suspend();
         } else {
           NXPLOG_UCIHAL_E("SessionTrack: idle timer expired while in %d",
             static_cast<int>(power_state_.load()));
@@ -699,11 +690,48 @@ private:
     QueueSessionTrackWork(msg);
   }
 
+  // Adds a new session info and transition to ACTIVE when it was in idle.
+  std::shared_ptr<SessionInfo> AddNewSession(uint32_t session_handle,
+                                             uint32_t session_id,
+                                             uint8_t session_type) {
+    NXPLOG_UCIHAL_D("SessionTrack: add session handle 0x%08x", session_handle);
+    std::lock_guard<std::mutex> lock(sessions_lock_);
+
+    bool was_idle = IsDeviceIdle();
+
+    std::shared_ptr<SessionInfo> info =
+      std::make_shared<SessionInfo>(session_id, session_type);
+    sessions_.emplace(std::make_pair(session_handle, info));
+
+    if (was_idle) {
+      NXPLOG_UCIHAL_D("Queue Active");
+      QueueSessionTrackWork(SessionTrackWorkType::ACTIVATE);
+    }
+    return info;
+  }
+
+  // Removes a session and transition to IDLE when it's IDLE.
+  // Called by SessionStatusNtf::DEINIT
+  void RemoveSession(uint32_t session_handle) {
+    NXPLOG_UCIHAL_D("SessionTrack: remove session handle 0x%08x", session_handle);
+
+    std::lock_guard<std::mutex> lock(sessions_lock_);
+
+    sessions_.erase(session_handle);
+
+    if (IsDeviceIdle()) {
+      NXPLOG_UCIHAL_D("Queue Idle");
+      QueueSessionTrackWork(SessionTrackWorkType::IDLE);
+    }
+  }
+
   std::shared_ptr<SessionInfo> GetSessionInfo(uint32_t session_handle) {
+    std::lock_guard<std::mutex> lock(sessions_lock_);
+
     auto it = sessions_.find(session_handle);
     if (it == sessions_.end()) {
       NXPLOG_UCIHAL_E("SessionTrack: Session 0x%08x not registered", session_handle);
-      return NULL;
+      return nullptr;
     }
     return it->second;
   }
diff --git a/halimpl/inc/NxpUwbChip.h b/halimpl/inc/NxpUwbChip.h
index f8cebe9..f6d950e 100644
--- a/halimpl/inc/NxpUwbChip.h
+++ b/halimpl/inc/NxpUwbChip.h
@@ -74,6 +74,10 @@ public:
 
   // Get supported channels
   virtual tHAL_UWB_STATUS get_supported_channels(const uint8_t **cal_channels, uint8_t *nr) = 0;
+
+  // Suspend/Resume, this is called only when configuration file has AUTO_SUSPEND_ENABLED=1.
+  virtual void suspend() {}
+  virtual void resume() {}
 };
 
 std::unique_ptr<NxpUwbChip> GetUwbChip();
diff --git a/halimpl/inc/common/phUwbTypes.h b/halimpl/inc/common/phUwbTypes.h
index 4d89a0d..d266132 100644
--- a/halimpl/inc/common/phUwbTypes.h
+++ b/halimpl/inc/common/phUwbTypes.h
@@ -107,19 +107,6 @@ struct phLibUwb_Message {
   phLibUwb_Message(uint32_t type, void *data) : eMsgType(type), pMsgData(data) {}
 };
 
-/*
- * Possible Hardware Configuration exposed to upper layer.
- * Typically this should be at least the communication link (Ex:"COM1","COM2")
- * the controller is connected to.
- */
-typedef struct phLibUwb_sConfig {
-  uint8_t* pLogFile; /* Log File Name*/
-  /* Hardware communication link to the controller */
-  phLibUwb_eConfigLinkType nLinkType;
-  /* message queue on the client thread */
-  std::shared_ptr<MessageQueue<phLibUwb_Message>> pClientMq;
-} phLibUwb_sConfig_t, *pphLibUwb_sConfig_t;
-
 /*
  * Deferred message specific info declaration.
  * This type of information is packed as message data when
diff --git a/halimpl/inc/phNxpUciHal_Adaptation.h b/halimpl/inc/phNxpUciHal_Adaptation.h
index 94eff2c..95192b7 100644
--- a/halimpl/inc/phNxpUciHal_Adaptation.h
+++ b/halimpl/inc/phNxpUciHal_Adaptation.h
@@ -42,6 +42,5 @@ uint16_t phNxpUciHal_open(uwb_stack_callback_t* p_cback,
 int32_t phNxpUciHal_write(size_t data_len, const uint8_t* p_data);
 uint16_t phNxpUciHal_close();
 uint16_t phNxpUciHal_coreInitialization();
-uint16_t phNxpUciHal_sessionInitialization(uint32_t sessionId);
 
 #endif /* _PHNXPUCIHAL_ADAPTATION_H_ */
diff --git a/halimpl/log/phNxpLog.cc b/halimpl/log/phNxpLog.cc
index 7fc5091..930df35 100644
--- a/halimpl/log/phNxpLog.cc
+++ b/halimpl/log/phNxpLog.cc
@@ -15,45 +15,36 @@
  */
 
 #define LOG_TAG "NxpUwbHal"
-#include "phNxpLog.h"
-#include "phNxpConfig.h"
+
+#include <string>
+
 #include <cutils/properties.h>
 #include <log/log.h>
-#include <stdio.h>
-#include <string.h>
 
+#include "phNxpLog.h"
+#include "phNxpConfig.h"
+
+// TODO: use constexpr and move to header
 const char* NXPLOG_ITEM_EXTNS = "NxpExtns";
 const char* NXPLOG_ITEM_UCIHAL = "NxpUwbHal";
 const char* NXPLOG_ITEM_UCIX = "NxpUciX";
 const char* NXPLOG_ITEM_UCIR = "NxpUciR";
 const char* NXPLOG_ITEM_FWDNLD = "NxpFwDnld";
 const char* NXPLOG_ITEM_TML = "NxpUwbTml";
-
-#ifdef NXP_HCI_REQ
-const char* NXPLOG_ITEM_HCPX = "NxpHcpX";
-const char* NXPLOG_ITEM_HCPR = "NxpHcpR";
-#endif /*NXP_HCI_REQ*/
+const char *NXP_HAL_ERROR = "NxpHalE";
 
 /* global log level structure */
 uci_log_level_t gLog_level;
+uci_debug_log_file_t gLogFile;
 
-/*******************************************************************************
- *
- * Function         phNxpLog_SetGlobalLogLevel
- *
- * Description      Sets the global log level for all modules.
- *                  This value is set by Android property
- *uwb.nxp_log_level_global.
- *                  If value can be overridden by module log level.
- *
- * Returns          The value of global log level
- *
- ******************************************************************************/
-static uint8_t phNxpLog_SetGlobalLogLevel(void) {
+namespace {
+
+uint8_t phNxpLog_SetGlobalLogLevel(void) {
   uint8_t level = NXPLOG_DEFAULT_LOGLEVEL;
   unsigned long num = 0;
   char valueStr[PROPERTY_VALUE_MAX] = {0};
 
+  // TODO: use property_get_int32()
   int len = property_get(PROP_NAME_NXPLOG_GLOBAL_LOGLEVEL, valueStr, "");
   if (len > 0) {
     // let Android property override .conf variable
@@ -64,148 +55,75 @@ static uint8_t phNxpLog_SetGlobalLogLevel(void) {
   return level;
 }
 
-/*******************************************************************************
- *
- * Function         phNxpLog_SetHALLogLevel
- *
- * Description      Sets the HAL layer log level.
- *
- * Returns          void
- *
- ******************************************************************************/
-static void phNxpLog_SetHALLogLevel(uint8_t level) {
-  unsigned long num = 0;
-  int len;
-  char valueStr[PROPERTY_VALUE_MAX] = {0};
-
-  if (NxpConfig_GetNum(NAME_NXPLOG_HAL_LOGLEVEL, &num, sizeof(num))) {
-    gLog_level.hal_log_level =
-        (level > (unsigned char)num) ? level : (unsigned char)num;
-    ;
+// TODO: add helper function for reading property + configuration
+void phNxpLog_SetHALLogLevel(uint8_t level) {
+  int32_t prop_level = property_get_int32(PROP_NAME_NXPLOG_HAL_LOGLEVEL, 0);
+  if (prop_level > 0) {
+    gLog_level.hal_log_level = prop_level;
+    return;
   }
+  uint8_t conf_level = NxpConfig_GetNum<uint8_t>(NAME_NXPLOG_HAL_LOGLEVEL).value_or(0);
+  gLog_level.hal_log_level = std::max(level, conf_level);
+}
 
-  len = property_get(PROP_NAME_NXPLOG_HAL_LOGLEVEL, valueStr, "");
-  if (len > 0) {
-    /* let Android property override .conf variable */
-    sscanf(valueStr, "%lu", &num);
-
-    gLog_level.hal_log_level = (unsigned char)num;
+void phNxpLog_SetExtnsLogLevel(uint8_t level) {
+  int32_t prop_level = property_get_int32(PROP_NAME_NXPLOG_EXTNS_LOGLEVEL, 0);
+  if (prop_level > 0) {
+    gLog_level.extns_log_level = prop_level;
+    return;
   }
+  uint8_t conf_level = NxpConfig_GetNum<uint8_t>(NAME_NXPLOG_EXTNS_LOGLEVEL).value_or(0);
+  gLog_level.extns_log_level = std::max(level, conf_level);
 }
 
-/*******************************************************************************
- *
- * Function         phNxpLog_SetExtnsLogLevel
- *
- * Description      Sets the Extensions layer log level.
- *
- * Returns          void
- *
- ******************************************************************************/
-static void phNxpLog_SetExtnsLogLevel(uint8_t level) {
-  unsigned long num = 0;
-  int len;
-  char valueStr[PROPERTY_VALUE_MAX] = {0};
-  if (NxpConfig_GetNum(NAME_NXPLOG_EXTNS_LOGLEVEL, &num, sizeof(num))) {
-    gLog_level.extns_log_level =
-        (level > (unsigned char)num) ? level : (unsigned char)num;
-    ;
+void phNxpLog_SetTmlLogLevel(uint8_t level) {
+  int32_t prop_level = property_get_int32(PROP_NAME_NXPLOG_TML_LOGLEVEL, 0);
+  if (prop_level > 0) {
+    gLog_level.tml_log_level = prop_level;
+    return;
   }
 
-  len = property_get(PROP_NAME_NXPLOG_EXTNS_LOGLEVEL, valueStr, "");
-  if (len > 0) {
-    /* let Android property override .conf variable */
-    sscanf(valueStr, "%lu", &num);
-    gLog_level.extns_log_level = (unsigned char)num;
-  }
+  uint8_t conf_level = NxpConfig_GetNum<uint8_t>(NAME_NXPLOG_TML_LOGLEVEL).value_or(0);
+  gLog_level.tml_log_level = std::max(level, conf_level);
 }
 
-/*******************************************************************************
- *
- * Function         phNxpLog_SetTmlLogLevel
- *
- * Description      Sets the Tml layer log level.
- *
- * Returns          void
- *
- ******************************************************************************/
-static void phNxpLog_SetTmlLogLevel(uint8_t level) {
-  unsigned long num = 0;
-  int len;
-  char valueStr[PROPERTY_VALUE_MAX] = {0};
-  if (NxpConfig_GetNum(NAME_NXPLOG_TML_LOGLEVEL, &num, sizeof(num))) {
-    gLog_level.tml_log_level =
-        (level > (unsigned char)num) ? level : (unsigned char)num;
-    ;
+void phNxpLog_SetDnldLogLevel(uint8_t level) {
+  int32_t prop_level = property_get_int32(PROP_NAME_NXPLOG_FWDNLD_LOGLEVEL, 0);
+  if (prop_level > 0) {
+    gLog_level.dnld_log_level = prop_level;
+    return;
   }
 
-  len = property_get(PROP_NAME_NXPLOG_TML_LOGLEVEL, valueStr, "");
-  if (len > 0) {
-    /* let Android property override .conf variable */
-    sscanf(valueStr, "%lu", &num);
-    gLog_level.tml_log_level = (unsigned char)num;
-  }
+  uint8_t conf_level = NxpConfig_GetNum<uint8_t>(NAME_NXPLOG_FWDNLD_LOGLEVEL).value_or(0);
+  gLog_level.dnld_log_level = std::max(level, conf_level);
 }
 
-/*******************************************************************************
- *
- * Function         phNxpLog_SetDnldLogLevel
- *
- * Description      Sets the FW download layer log level.
- *
- * Returns          void
- *
- ******************************************************************************/
-static void phNxpLog_SetDnldLogLevel(uint8_t level) {
-  unsigned long num = 0;
-  int len;
-  char valueStr[PROPERTY_VALUE_MAX] = {0};
-  if (NxpConfig_GetNum(NAME_NXPLOG_FWDNLD_LOGLEVEL, &num, sizeof(num))) {
-    gLog_level.dnld_log_level =
-        (level > (unsigned char)num) ? level : (unsigned char)num;
-    ;
+void phNxpLog_SetUciTxLogLevel(uint8_t level) {
+  int32_t prop_level = property_get_int32(PROP_NAME_NXPLOG_UCI_LOGLEVEL, 0);
+  if (prop_level > 0) {
+    gLog_level.ucix_log_level = prop_level;
+    gLog_level.ucir_log_level = prop_level;
+    return;
   }
 
-  len = property_get(PROP_NAME_NXPLOG_FWDNLD_LOGLEVEL, valueStr, "");
-  if (len > 0) {
-    /* let Android property override .conf variable */
-    sscanf(valueStr, "%lu", &num);
-    gLog_level.dnld_log_level = (unsigned char)num;
-  }
+  uint8_t conf_level_x = NxpConfig_GetNum<uint8_t>(NAME_NXPLOG_UCIX_LOGLEVEL).value_or(0);
+  uint8_t conf_level_r = NxpConfig_GetNum<uint8_t>(NAME_NXPLOG_UCIR_LOGLEVEL).value_or(0);
+  gLog_level.ucix_log_level = std::max(level, conf_level_x);
+  gLog_level.ucir_log_level = std::max(level, conf_level_r);
 }
 
-/*******************************************************************************
- *
- * Function         phNxpLog_SetUciTxLogLevel
- *
- * Description      Sets the UCI transaction layer log level.
- *
- * Returns          void
- *
- ******************************************************************************/
-static void phNxpLog_SetUciTxLogLevel(uint8_t level) {
-  unsigned long num = 0;
-  int len;
-  char valueStr[PROPERTY_VALUE_MAX] = {0};
-  if (NxpConfig_GetNum(NAME_NXPLOG_UCIX_LOGLEVEL, &num, sizeof(num))) {
-    gLog_level.ucix_log_level =
-        (level > (unsigned char)num) ? level : (unsigned char)num;
-  }
-  if (NxpConfig_GetNum(NAME_NXPLOG_UCIR_LOGLEVEL, &num, sizeof(num))) {
-    gLog_level.ucir_log_level =
-        (level > (unsigned char)num) ? level : (unsigned char)num;
-    ;
-  }
+void phNxpLog_EnableDebugLogFile() {
+  gLogFile.is_log_file_required =
+      NxpConfig_GetBool(NAME_UWB_UCIX_UCIR_ERROR_LOG).value_or(false);
+}
 
-  len = property_get(PROP_NAME_NXPLOG_UCI_LOGLEVEL, valueStr, "");
-  if (len > 0) {
-    /* let Android property override .conf variable */
-    sscanf(valueStr, "%lu", &num);
-    gLog_level.ucix_log_level = (unsigned char)num;
-    gLog_level.ucir_log_level = (unsigned char)num;
-  }
+void phNxpLog_MaxFileSize() {
+  gLogFile.fileSize =
+      NxpConfig_GetNum<uint32_t>(NAME_UWB_DEBUG_LOG_FILE_SIZE).value_or(0);
 }
 
+}   // namespace
+
 /******************************************************************************
  * Function         phNxpLog_InitializeLogLevel
  *
@@ -246,6 +164,8 @@ void phNxpLog_InitializeLogLevel(void) {
   phNxpLog_SetTmlLogLevel(level);
   phNxpLog_SetDnldLogLevel(level);
   phNxpLog_SetUciTxLogLevel(level);
+  phNxpLog_EnableDebugLogFile();
+  phNxpLog_MaxFileSize();
 
   ALOGV("%s: global =%u, Fwdnld =%u, extns =%u, \
                 hal =%u, tml =%u, ucir =%u, \
@@ -255,3 +175,30 @@ void phNxpLog_InitializeLogLevel(void) {
            gLog_level.tml_log_level, gLog_level.ucir_log_level,
            gLog_level.ucix_log_level);
 }
+
+void phNxpLog_printErrorLogsTime(const char *format, ...) {
+  char yy_time[20] = "";
+  time_t current_time = time(0);
+  tm *dd_mm_tm = localtime(&current_time);
+  if (gLogFile.is_log_file_required && gLogFile.debuglogFile != NULL) {
+    if ((ftell(gLogFile.debuglogFile) + strlen(yy_time) +
+         strlen(NXP_HAL_ERROR) + 100) > gLogFile.fileSize) {
+      if (fseek(gLogFile.debuglogFile, 9L, SEEK_SET)) {
+        NXPLOG_UCIHAL_E("phNxpUciHalProp_print_log: fseek() failed at %d",
+                        __LINE__);
+        return;
+      }
+      if (ftell(gLogFile.debuglogFile) > gLogFile.fileSize) {
+        return;
+      }
+    }
+
+    strftime(yy_time, sizeof(yy_time), "%x %T", dd_mm_tm);
+    fprintf(gLogFile.debuglogFile, "\n%s %s:", yy_time, NXP_HAL_ERROR);
+    va_list arg;
+    va_start(arg, format);
+    // fprintf (stdout, format, arg);
+    vfprintf(gLogFile.debuglogFile, format, arg);
+    va_end(arg);
+  }
+}
diff --git a/halimpl/log/phNxpLog.h b/halimpl/log/phNxpLog.h
index e69d2ff..5771df5 100644
--- a/halimpl/log/phNxpLog.h
+++ b/halimpl/log/phNxpLog.h
@@ -17,6 +17,7 @@
 #if !defined(NXPLOG__H_INCLUDED)
 #define NXPLOG__H_INCLUDED
 #include <log/log.h>
+#include <thread>
 
 typedef struct uci_log_level {
   uint8_t global_log_level;
@@ -28,8 +29,24 @@ typedef struct uci_log_level {
   uint8_t ucir_log_level;
 } uci_log_level_t;
 
+typedef struct {
+  std::thread log_thread_handler;
+  FILE *FwCrashLogFile;
+} phNxpUciHalLog_Control_t;
+
+typedef struct uci_debug_log_file {
+  FILE *debuglogFile;
+  bool is_log_file_required;
+  uint32_t fileSize;
+  bool init_sequence_started;
+} uci_debug_log_file_t;
+
 /* global log level Ref */
 extern uci_log_level_t gLog_level;
+extern uci_debug_log_file_t gLogFile;
+
+void phNxpLog_printErrorLogsTime(const char *format, ...);
+
 /* define log module included when compile */
 #define ENABLE_EXTNS_TRACES TRUE
 #define ENABLE_HAL_TRACES TRUE
@@ -146,10 +163,11 @@ extern const char* NXPLOG_ITEM_HCPR; /* Android logging tag for NxpHcpR   */
     if ((gLog_level.hal_log_level >= NXPLOG_LOG_WARN_LOGLEVEL))   \
       LOG_PRI(ANDROID_LOG_WARN, NXPLOG_ITEM_UCIHAL, __VA_ARGS__); \
   }
-#define NXPLOG_UCIHAL_E(...)                                       \
-  {                                                                \
-    if (gLog_level.hal_log_level >= NXPLOG_LOG_ERROR_LOGLEVEL)     \
-      LOG_PRI(ANDROID_LOG_ERROR, NXPLOG_ITEM_UCIHAL, __VA_ARGS__); \
+#define NXPLOG_UCIHAL_E(...)                                                   \
+  {                                                                            \
+    if (gLog_level.hal_log_level >= NXPLOG_LOG_ERROR_LOGLEVEL)                 \
+      LOG_PRI(ANDROID_LOG_ERROR, NXPLOG_ITEM_UCIHAL, __VA_ARGS__);             \
+    phNxpLog_printErrorLogsTime(__VA_ARGS__);                                  \
   }
 #else
 #define NXPLOG_UCIHAL_V(...)
@@ -359,5 +377,12 @@ extern const char* NXPLOG_ITEM_HCPR; /* Android logging tag for NxpHcpR   */
 #endif /* NXP_VRBS_REQ */
 
 void phNxpLog_InitializeLogLevel(void);
+/* Log functions */
+void phNxpUciHalProp_trigger_fw_crash_log_dump();
+bool phNxpUciHal_dump_log(size_t data_len, const uint8_t *p_rx_data);
+void phNxpUciLog_initialize();
+void phNxpUciLog_deinitialize();
+void phNxpUciHalProp_print_log(uint8_t what, const uint8_t *p_data,
+                               uint16_t len);
 
 #endif /* NXPLOG__H_INCLUDED */
diff --git a/halimpl/log/phNxpUciHal_extLog.cc b/halimpl/log/phNxpUciHal_extLog.cc
new file mode 100644
index 0000000..80d5e62
--- /dev/null
+++ b/halimpl/log/phNxpUciHal_extLog.cc
@@ -0,0 +1,316 @@
+/*
+ *
+ * Copyright 2025 NXP.
+ *
+ * NXP Confidential. This software is owned or controlled by NXP and may only be
+ * used strictly in accordance with the applicable license terms. By expressly
+ * accepting such terms or by downloading,installing, activating and/or
+ * otherwise using the software, you are agreeing that you have read,and that
+ * you agree to comply with and are bound by, such license terms. If you do not
+ * agree to be bound by the applicable license terms, then you may not retain,
+ * install, activate or otherwise use the software.
+ *
+ */
+
+#include "phNxpUciHal_ext.h"
+#include "phUwbTypes.h"
+#include <stdio.h>
+#include <sys/stat.h>
+#include <time.h>
+
+/******************* Global variables *****************************************/
+phNxpUciHalLog_Control_t nxpucihallog_ctrl;
+extern phNxpUciHal_Control_t nxpucihal_ctrl;
+extern uci_debug_log_file_t gLogFile;
+
+/******************************************************************************
+ * Function         phNxpUciLog_initialize
+ *
+ * Description      This function is called during the initialization of the UWB
+ *
+ * Returns          void
+ *
+ ******************************************************************************/
+void phNxpUciLog_initialize() {
+
+  char UCI_Logger_log_path[100] = {0};
+
+  if (!gLogFile.is_log_file_required) {
+    return;
+  }
+
+  gLogFile.debuglogFile = NULL;
+  sprintf(UCI_Logger_log_path, "%suci_debug_log.txt", debug_log_path);
+  if (NULL == (gLogFile.debuglogFile = fopen(UCI_Logger_log_path, "rb+"))) {
+    NXPLOG_UCIHAL_D("unable to open log file");
+    if (NULL == (gLogFile.debuglogFile = fopen(UCI_Logger_log_path, "wb"))) {
+      NXPLOG_UCIHAL_D("unable to create log file");
+    } else {
+      long offset = 0;
+      NXPLOG_UCIHAL_D("Created debug log file set 0 as offset");
+      fwrite(&offset, sizeof(offset), 1, gLogFile.debuglogFile);
+      fwrite("\n", sizeof(char), 1, gLogFile.debuglogFile);
+    }
+  } else {
+    long offset = 0;
+    NXPLOG_UCIHAL_D("debug log file exist set offset");
+    if (1 != fread(&offset, sizeof(long), 1, gLogFile.debuglogFile)) {
+      NXPLOG_UCIHAL_D("phNxpUciPropHal_initialize: fread() failed at %d",
+                      __LINE__);
+      return;
+    }
+    if (fseek(gLogFile.debuglogFile, offset, SEEK_SET)) {
+      NXPLOG_UCIHAL_E("phNxpUciHalProp_print_log: fseek() failed at %d",
+                      __LINE__);
+      return;
+    }
+  }
+
+  if (chmod(UCI_Logger_log_path, 0744) != 0) {
+    NXPLOG_UCIHAL_E("Can't change chmod log");
+  }
+}
+
+/******************************************************************************
+ * Function         phNxpUciHalProp_fw_crash
+ *
+ * Description      FW crash dump log function
+ *
+ * Returns          None
+ *
+ ******************************************************************************/
+static void phNxpUciHalProp_fw_crash() {
+  NXPLOG_UCIHAL_D("[%s]", __func__);
+  tHAL_UWB_STATUS status;
+  // Debug get error log command: GID = UCI_GID_PROPRIETARY
+  // OID = EXT_UCI_MSG_DBG_GET_ERROR_LOG
+  std::vector<uint8_t> payload = {0x2E, 0x02, 0x00, 0x00};
+  phNxpUciHal_rx_handler_add(UCI_MT_RSP, UCI_GID_PROPRIETARY,
+                             EXT_UCI_MSG_DBG_GET_ERROR_LOG, true,
+                             phNxpUciHal_dump_log);
+  status = phNxpUciHal_send_ext_cmd(payload.size(), payload.data());
+
+  if (status != HAL_UWB_STATUS_OK) {
+    NXPLOG_UCIHAL_E("Failed to send firmware crash command");
+    return;
+  }
+
+  /* Send FW crash NTF to upper layer for triggering MW recovery */
+  phNxpUciHal_send_dev_error_status_ntf();
+
+  NXPLOG_UCIHAL_D("[%s] Firmware crash handling completed", __func__);
+}
+
+/******************************************************************************
+ * Function         phNxpUciHalProp_trigger_fw_crash_log_dump
+ *
+ * Description      dump FW crash log when fw is crashed
+ *
+ *
+ ******************************************************************************/
+void phNxpUciHalProp_trigger_fw_crash_log_dump() {
+  nxpucihallog_ctrl.log_thread_handler = std::thread(&phNxpUciHalProp_fw_crash);
+  nxpucihallog_ctrl.log_thread_handler.detach();
+}
+
+/******************************************************************************
+ * Function         phNxpUciHalProp_dump_log
+ *
+ * Description      This function is responsible for collecting and processing
+ *                  debug logs. It is triggered whenever debug log data needs
+ *                  to be retrieved and analyzed.
+ *
+ * Returns          void.
+ *
+ ******************************************************************************/
+bool phNxpUciHal_dump_log(size_t data_len, const uint8_t *p_rx_data) {
+  int cmd_len, len;
+  bool isSkipPacket = false;
+  const uint8_t mt = ((p_rx_data[0]) & UCI_MT_MASK) >> UCI_MT_SHIFT;
+  const uint8_t gid = p_rx_data[0] & UCI_GID_MASK;
+  const uint8_t oid = p_rx_data[1] & UCI_OID_MASK;
+  const uint8_t pbf = (p_rx_data[0] & UCI_PBF_MASK) >> UCI_PBF_SHIFT;
+
+  uint8_t isExtendedLength =
+      (p_rx_data[EXTND_LEN_INDICATOR_OFFSET] & EXTND_LEN_INDICATOR_OFFSET_MASK);
+  cmd_len = p_rx_data[NORMAL_MODE_LENGTH_OFFSET];
+
+  if (isExtendedLength) {
+    cmd_len = ((cmd_len << EXTENDED_MODE_LEN_SHIFT) |
+               p_rx_data[EXTENDED_MODE_LEN_OFFSET]);
+  }
+
+  if ((gid == UCI_GID_PROPRIETARY) && (oid == EXT_UCI_MSG_DBG_GET_ERROR_LOG)) {
+    if (nxpucihal_ctrl.hal_ext_enabled == 1) {
+      char FW_crash_log_path[100] = {0};
+      sprintf(FW_crash_log_path, "%suwb_FW_crash.log", debug_log_path);
+      if (NULL ==
+          (nxpucihallog_ctrl.FwCrashLogFile = fopen(FW_crash_log_path, "wb"))) {
+        NXPLOG_UCIHAL_E("unable to open log file %s", FW_crash_log_path);
+        nxpucihal_ctrl.cmdrsp.WakeupError(UWBSTATUS_FAILED);
+      } else {
+        len = fwrite(&p_rx_data[UCI_NTF_PAYLOAD_OFFSET], 1, cmd_len,
+                     nxpucihallog_ctrl.FwCrashLogFile);
+        fflush(nxpucihallog_ctrl.FwCrashLogFile);
+        NXPLOG_UCIHAL_D("FW crash dump: %d bytes written", len);
+        fclose(nxpucihallog_ctrl.FwCrashLogFile);
+      }
+      if (!pbf) {
+        nxpucihal_ctrl.cmdrsp.Wakeup(gid, oid);
+      }
+    }
+    isSkipPacket = true;
+  }
+  return isSkipPacket;
+}
+
+void phNxpUciHalProp_print_log(uint8_t what, const uint8_t *p_data,
+                               uint16_t len) {
+  char print_buffer[len * 3 + 1];
+  char dd_mm_buffer[8];
+  char UCI_Logger_log_path[100] = {0};
+  const uint8_t mt = ((p_data[0]) & UCI_MT_MASK) >> UCI_MT_SHIFT;
+  const uint8_t gid = p_data[0] & UCI_GID_MASK;
+  const uint8_t oid = p_data[1] & UCI_OID_MASK;
+  bool is_range_ntf = false;
+  uint8_t status_index = 29;
+
+  if (!gLogFile.is_log_file_required) {
+    return;
+  }
+
+  if (gLogFile.debuglogFile == NULL) {
+    NXPLOG_UCIHAL_E("debuglogFile file pointer is null...");
+    return;
+  }
+
+  char yy_time[20];
+  time_t current_time = time(0);
+  tm *dd_mm_tm = localtime(&current_time);
+  strftime(yy_time, sizeof(yy_time), "%x %T", dd_mm_tm);
+  if (gLogFile.fileSize < 100000) {
+    if (!nxpucihal_ctrl.uwb_device_initialized) {
+      // Check file size
+      if (ftell(gLogFile.debuglogFile) + 5 + strlen(yy_time) +
+              strlen(NXPLOG_ITEM_UCIR) + 4 >
+          gLogFile.fileSize) {
+        if (fseek(gLogFile.debuglogFile, 9L, SEEK_SET)) {
+          NXPLOG_UCIHAL_E("phNxpUciHalProp_print_log: fseek() failed at %d",
+                          __LINE__);
+          return;
+        }
+        if (ftell(gLogFile.debuglogFile) > gLogFile.fileSize) {
+          return;
+        }
+      }
+      if (mt == UCI_MT_RSP && p_data[4] != UCI_STATUS_OK) {
+        fprintf(gLogFile.debuglogFile, "\n%s %s:", yy_time, NXPLOG_ITEM_UCIR);
+        len = fwrite(p_data, 1, len, gLogFile.debuglogFile);
+        fwrite("\n", 1, 1, gLogFile.debuglogFile);
+        gLogFile.init_sequence_started = false;
+      }
+      if (!gLogFile.init_sequence_started) {
+        fprintf(gLogFile.debuglogFile, "\n%s INIT", yy_time);
+      }
+      gLogFile.init_sequence_started = true;
+      return;
+    }
+    gLogFile.init_sequence_started = false;
+    if (((gid != UCI_GID_SESSION_MANAGE) ||
+         (oid != UCI_MSG_SESSION_SET_APP_CONFIG)) &&
+        ((gid != UCI_GID_PROPRIETARY_0X0F) ||
+         (oid != SET_VENDOR_SET_CALIBRATION))) {
+      switch (mt) {
+      case UCI_MT_CMD:
+        len = UCI_MSG_HDR_SIZE;
+        break;
+      case UCI_MT_RSP:
+        len = UCI_RESPONSE_PAYLOAD_OFFSET;
+        break;
+      case UCI_MT_NTF:
+        // Handle range data ntf
+        if ((gid == UCI_GID_SESSION_CONTROL) &&
+            (oid == UCI_OID_RANGE_DATA_NTF)) {
+          // Sequence number - 4
+          // first 4 bytes
+          // session handle - 4
+          // status
+          if (p_data[4 + 15] == 0x00) {
+            status_index += 2;
+          } else {
+            status_index += 8;
+          }
+          is_range_ntf = true;
+        }
+        break;
+      default:
+        break;
+      }
+    }
+  }
+
+  if ((gid == UCI_GID_PROPRIETARY && oid == EXT_UCI_MSG_DBG_DATA_LOGGER_NTF) ||
+      ((gid == UCI_GID_PROPRIETARY_0X0F) &&
+       (oid == EXT_UCI_MSG_DBG_PSDU_LOG_NTF)) ||
+      ((gid == UCI_GID_PROPRIETARY_0X0F) &&
+       (oid == EXT_UCI_MSG_DBG_CIR_LOG_NTF))) {
+    return;
+  }
+
+  uint32_t file_size = ftell(gLogFile.debuglogFile);
+
+  if ((file_size + (strlen(yy_time) + 1 + strlen(NXPLOG_ITEM_UCIX) + 1 + len) >=
+       gLogFile.fileSize)) {
+    int val = fseek(gLogFile.debuglogFile, 9L, SEEK_SET);
+    if (ftell(gLogFile.debuglogFile) > gLogFile.fileSize) {
+      return;
+    }
+  }
+
+  switch (what) {
+  case 0: {
+    fprintf(gLogFile.debuglogFile, "\n%s %s:", yy_time, NXPLOG_ITEM_UCIX);
+  } break;
+  case 1: {
+    fprintf(gLogFile.debuglogFile, "\n%s %s:", yy_time, NXPLOG_ITEM_UCIR);
+  } break;
+  default:
+    return;
+    break;
+  }
+  memset(print_buffer, 0, sizeof(print_buffer));
+  int i = 0, j = 0;
+  if (is_range_ntf) {
+    fwrite(&p_data[j], 1, 9, gLogFile.debuglogFile);
+    fwrite(&p_data[status_index], 1, 1, gLogFile.debuglogFile);
+  } else {
+
+    len = fwrite(&p_data[j], 1, len, gLogFile.debuglogFile);
+    fflush(gLogFile.debuglogFile);
+  }
+}
+
+/******************************************************************************
+ * Function         phNxpUciLog_deinitialize
+ *
+ * Description      This function close files and frees up memory used by
+ *                  proprietary hal.
+ *
+ * Returns          void
+ *
+ ******************************************************************************/
+void phNxpUciLog_deinitialize() {
+  /* FW debug log dump file closed */
+  if (nxpucihallog_ctrl.FwCrashLogFile != NULL) {
+    fclose(nxpucihallog_ctrl.FwCrashLogFile);
+  }
+
+  if (gLogFile.debuglogFile != NULL) {
+    long offset = ftell(gLogFile.debuglogFile);
+    fseek(gLogFile.debuglogFile, 0L, SEEK_SET);
+    fwrite(&offset, sizeof(long), 1, gLogFile.debuglogFile);
+    fwrite("\n", sizeof(char), 1, gLogFile.debuglogFile);
+    fclose(gLogFile.debuglogFile);
+    gLogFile.debuglogFile = NULL;
+  }
+}
diff --git a/halimpl/tml/phOsalUwb_Timer.cc b/halimpl/tml/phOsalUwb_Timer.cc
index f671130..3e73ae6 100644
--- a/halimpl/tml/phOsalUwb_Timer.cc
+++ b/halimpl/tml/phOsalUwb_Timer.cc
@@ -364,7 +364,7 @@ static void phOsalUwb_Timer_Expired(union sigval sv) {
 
   /* Post a message on the queue to invoke the function */
   auto msg = std::make_shared<phLibUwb_Message>(PH_LIBUWB_DEFERREDCALL_MSG, &pTimerHandle->tDeferredCallInfo);
-  nxpucihal_ctrl.gDrvCfg.pClientMq->send(msg);
+  nxpucihal_ctrl.pClientMq->send(msg);
 }
 
 /*******************************************************************************
diff --git a/halimpl/tml/phTmlUwb.cc b/halimpl/tml/phTmlUwb.cc
index 5f27afb..3dc1672 100644
--- a/halimpl/tml/phTmlUwb.cc
+++ b/halimpl/tml/phTmlUwb.cc
@@ -22,8 +22,6 @@
 #include <phNxpUciHal.h>
 #include <errno.h>
 
-extern phNxpUciHal_Control_t nxpucihal_ctrl;
-
 /*
  * Duration of Timer to wait after sending an Uci packet
  */
@@ -103,6 +101,8 @@ static void phTmlUwb_WaitWriteComplete(void);
 static void phTmlUwb_SignalWriteComplete(void);
 static int phTmlUwb_WaitReadInit(void);
 
+static void phTmlUwb_DeferredCall(std::shared_ptr<phLibUwb_Message> msg);
+
 /* Function definitions */
 
 /*******************************************************************************
@@ -166,7 +166,7 @@ tHAL_UWB_STATUS phTmlUwb_Init(const char* pDevName,
     return UWBSTATUS_FAILED;
   }
 
-  // Start TML thread (to handle write and read operations)
+  // Start TML writer thread.
   if (UWBSTATUS_SUCCESS != phTmlUwb_StartWriterThread()) {
     return PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_FAILED);
   }
@@ -672,7 +672,7 @@ static void phTmlUwb_StopWriterThread(void)
 ** Returns          None
 **
 *******************************************************************************/
-void phTmlUwb_DeferredCall(std::shared_ptr<phLibUwb_Message> msg)
+static void phTmlUwb_DeferredCall(std::shared_ptr<phLibUwb_Message> msg)
 {
   gpphTmlUwb_Context->pClientMq->send(msg);
 }
diff --git a/halimpl/tml/phTmlUwb.h b/halimpl/tml/phTmlUwb.h
index fcbf13e..18477b2 100644
--- a/halimpl/tml/phTmlUwb.h
+++ b/halimpl/tml/phTmlUwb.h
@@ -110,5 +110,4 @@ tHAL_UWB_STATUS phTmlUwb_StartRead(ReadCallback pTmlReadComplete, void* pContext
 void phTmlUwb_StopRead();
 
 void phTmlUwb_Chip_Reset(void);
-void phTmlUwb_DeferredCall(std::shared_ptr<phLibUwb_Message> msg);
 #endif /*  PHTMLUWB_H  */
diff --git a/halimpl/utils/phNxpConfig.cc b/halimpl/utils/phNxpConfig.cc
index 5bd2125..30522c0 100644
--- a/halimpl/utils/phNxpConfig.cc
+++ b/halimpl/utils/phNxpConfig.cc
@@ -19,17 +19,23 @@
 //#define LOG_NDEBUG 0
 #define LOG_TAG "NxpUwbConf"
 
+#include <filesystem>
 #include <limits.h>
 #include <sys/stat.h>
 
+#include <charconv>
+#include <cinttypes>
 #include <cstddef>
 #include <cstdint>
 #include <iomanip>
 #include <list>
 #include <memory>
+#include <optional>
+#include <span>
 #include <sstream>
 #include <sstream>
 #include <string>
+#include <string_view>
 #include <unordered_map>
 #include <unordered_set>
 #include <vector>
@@ -46,96 +52,142 @@
 
 namespace {
 
-static const char default_nxp_config_path[] = "/vendor/etc/libuwb-nxp.conf";
-static const char country_code_config_name[] = "libuwb-countrycode.conf";
-static const char nxp_uci_config_file[] = "libuwb-uci.conf";
-static const char default_uci_config_path[] = "/vendor/etc/";
+constexpr std::string_view default_nxp_config_path = "/vendor/etc/libuwb-nxp.conf";
+constexpr std::string_view country_code_config_name = "libuwb-countrycode.conf";
+constexpr std::string_view nxp_uci_config_file = "libuwb-uci.conf";
+constexpr std::string_view default_uci_config_path = "/vendor/etc/";
+constexpr std::string_view factory_file_prefix = "cal-factory";
 
-static const char country_code_specifier[] = "<country>";
-static const char sku_specifier[] = "<sku>";
-static const char extid_specifier[] = "<extid>";
-static const char revision_specifier[] = "<revision>";
+constexpr std::string_view country_code_specifier = "<country>";
+constexpr std::string_view sku_specifier = "<sku>";
+constexpr std::string_view extid_specifier = "<extid>";
+constexpr std::string_view revision_specifier = "<revision>";
 
-static const char extid_config_name[] = "cal.extid";
-static const char extid_default_value[] = "defaultextid";
+constexpr std::string_view extid_config_name = "cal.extid";
+constexpr std::string_view extid_default_value = "defaultextid";
 
-static const char prop_name_calsku[] = "persist.vendor.uwb.cal.sku";
-static const char prop_default_calsku[] = "defaultsku";
+constexpr char prop_name_calsku[] = "persist.vendor.uwb.cal.sku";
+constexpr char prop_default_calsku[] = "defaultsku";
 
-static const char prop_name_revision[] = "persist.vendor.uwb.cal.revision";
-static const char prop_default_revision[] = "defaultrevision";
-
-using namespace::std;
+constexpr char prop_name_revision[] = "persist.vendor.uwb.cal.revision";
+constexpr char prop_default_revision[] = "defaultrevision";
 
 class uwbParam
 {
 public:
     enum class type { STRING, NUMBER, BYTEARRAY, STRINGARRAY };
-    uwbParam();
-    uwbParam(const uwbParam& param);
-    uwbParam(uwbParam&& param);
 
-    uwbParam(const string& value);
-    uwbParam(vector<uint8_t>&& value);
-    uwbParam(unsigned long value);
-    uwbParam(vector<string>&& value);
+    uwbParam() : m_numValue(0), m_type(type::NUMBER) {}
+
+    // only movable.
+    uwbParam(const uwbParam &param)  = delete;
+
+    uwbParam(uwbParam &&param) :
+        m_numValue(param.m_numValue),
+        m_str_value(std::move(param.m_str_value)),
+        m_arrValue(std::move(param.m_arrValue)),
+        m_arrStrValue(std::move(param.m_arrStrValue)),
+        m_type(param.m_type) {}
+
+    uwbParam(const std::string& value) :
+        m_numValue(0),
+        m_str_value(value),
+        m_type(type::STRING) {}
+
+    uwbParam(uint64_t value) :
+        m_numValue(value),
+        m_type(type::NUMBER) {}
 
-    virtual ~uwbParam();
+    uwbParam(std::vector<uint8_t> &&value) :
+        m_arrValue(std::move(value)),
+        m_type(type::BYTEARRAY) {}
+
+    uwbParam(std::vector<std::string> &&value) :
+        m_arrStrValue(std::move(value)),
+        m_type(type::STRINGARRAY) {}
 
     type getType() const { return m_type; }
-    unsigned long numValue() const {return m_numValue;}
-    const char*   str_value() const {return m_str_value.c_str();}
-    size_t        str_len() const   {return m_str_value.length();}
-    const uint8_t* arr_value() const { return m_arrValue.data(); }
-    size_t arr_len() const { return m_arrValue.size(); }
 
-    size_t str_arr_len() const { return m_arrStrValue.size(); }
-    const char* str_arr_elem(const int index) const { return m_arrStrValue[index].c_str(); }
-    size_t str_arr_elem_len(const int index) const { return m_arrStrValue[index].length(); }
+    uint64_t numValue() const { return m_numValue; }
+
+    std::string_view str_value() const { return m_str_value; }
+
+    std::span<const uint8_t> arr_value() const { return m_arrValue; }
+
+    std::vector<std::string> str_arr_value() const { return m_arrStrValue; }
 
-    void dump(const string &tag) const;
+    void dump(const std::string &tag) const {
+        if (m_type == type::NUMBER) {
+            ALOGV(" - %s = 0x%" PRIx64, tag.c_str(), m_numValue);
+        } else if (m_type == type::STRING) {
+            ALOGV(" - %s = %s", tag.c_str(), m_str_value.c_str());
+        } else if (m_type == type::BYTEARRAY) {
+            std::stringstream ss_hex;
+            ss_hex.fill('0');
+            for (auto b : m_arrValue) {
+                ss_hex << std::setw(2) << std::hex << (int)b << " ";
+            }
+            ALOGV(" - %s = { %s}", tag.c_str(), ss_hex.str().c_str());
+        } else if (m_type == type::STRINGARRAY) {
+            std::stringstream ss;
+            for (auto s : m_arrStrValue) {
+                ss << "\"" << s << "\", ";
+            }
+            ALOGV(" - %s = { %s}", tag.c_str(), ss.str().c_str());
+        }
+    }
 private:
-    // TODO: use uint64_t or uint32_t instead of unsigned long.
-    unsigned long   m_numValue;
-    string          m_str_value;
-    vector<uint8_t>  m_arrValue;
-    vector<string>  m_arrStrValue;
+    uint64_t m_numValue;
+    std::string m_str_value;
+    std::vector<uint8_t>  m_arrValue;
+    std::vector<std::string>  m_arrStrValue;
     type m_type;
 };
 
 class CUwbNxpConfig
 {
 public:
+    using HashType = std::unordered_map<std::string, uwbParam>;
+
     CUwbNxpConfig();
+    CUwbNxpConfig(std::string_view filepath);
+
+    // only movable
     CUwbNxpConfig(CUwbNxpConfig&& config);
-    CUwbNxpConfig(const char *filepath);
-    virtual ~CUwbNxpConfig();
     CUwbNxpConfig& operator=(CUwbNxpConfig&& config);
 
-    bool open(const char *filepath);
+    CUwbNxpConfig(CUwbNxpConfig& config) = delete;
+    CUwbNxpConfig& operator=(CUwbNxpConfig& config) = delete;
+
+    virtual ~CUwbNxpConfig();
+
     bool isValid() const { return mValidFile; }
+    bool isFactory() const { return mFactoryFile; }
     void reset() {
         m_map.clear();
         mValidFile = false;
     }
 
-    const uwbParam*    find(const char* p_name) const;
-    void    setCountry(const string& strCountry);
+    const uwbParam* find(std::string_view key) const;
+    void    setCountry(const std::string& strCountry);
     const char* getFilePath() const {
         return mFilePath.c_str();
     }
 
-    void    dump() const;
+    void dump() const;
 
-    const unordered_map<string, uwbParam>& get_data() const {
+    const HashType& get_data() const {
         return m_map;
     }
+
 private:
-    bool    readConfig();
+    bool readConfig();
 
-    unordered_map<string, uwbParam> m_map;
-    bool    mValidFile;
-    string  mFilePath;
+    std::filesystem::path mFilePath;
+    bool mFactoryFile = false;
+    bool mValidFile = false;
+
+    HashType m_map;
 };
 
 /*******************************************************************************
@@ -230,11 +282,11 @@ bool CUwbNxpConfig::readConfig()
     };
 
     FILE*   fd;
-    string  token;
-    string  strValue;
+    std::string  token;
+    std::string  strValue;
     unsigned long    numValue = 0;
-    vector<uint8_t> arrValue;
-    vector<string> arrStr;
+    std::vector<uint8_t> arrValue;
+    std::vector<std::string> arrStr;
     int     base = 0;
     int     c;
     const char *name = mFilePath.c_str();
@@ -304,7 +356,7 @@ bool CUwbNxpConfig::readConfig()
                 base = 10;
                 numValue = getDigitValue(c, base);
             } else {
-                m_map.try_emplace(token, move(uwbParam(numValue)));
+                m_map.try_emplace(token, uwbParam(numValue));
                 state = END_LINE;
             }
             break;
@@ -312,7 +364,7 @@ bool CUwbNxpConfig::readConfig()
             if (isDigit(c, base)) {
                 numValue *= base;
                 numValue += getDigitValue(c, base);
-            } else {m_map.try_emplace(token, move(uwbParam(numValue)));
+            } else {m_map.try_emplace(token, uwbParam(numValue));
                 state = END_LINE;
             }
             break;
@@ -321,7 +373,8 @@ bool CUwbNxpConfig::readConfig()
                 numValue = getDigitValue(c, base);
                 state = ARR_NUM;
             } else if (c == '}') {
-                m_map.try_emplace(token, move(uwbParam(move(arrValue))));
+                m_map.try_emplace(token, uwbParam(std::move(arrValue)));
+                arrValue = {};
                 state = END_LINE;
             } else if (c == '"') {
                 state = ARR_STR;
@@ -331,7 +384,7 @@ bool CUwbNxpConfig::readConfig()
             break;
         case ARR_STR:
             if (c == '"') {
-                arrStr.emplace_back(move(strValue));
+                arrStr.emplace_back(strValue);
                 strValue.clear();
                 state = ARR_STR_SPACE;
             } else {
@@ -340,7 +393,8 @@ bool CUwbNxpConfig::readConfig()
             break;
         case ARR_STR_SPACE:
             if (c == '}') {
-                m_map.try_emplace(token, move(uwbParam(move(arrStr))));
+                m_map.try_emplace(token, uwbParam(std::move(arrStr)));
+                arrStr = {};
                 state = END_LINE;
             } else if (c == '"') {
                 state = ARR_STR;
@@ -357,14 +411,15 @@ bool CUwbNxpConfig::readConfig()
                 state = END_LINE;
             }
             if (c == '}') {
-                m_map.try_emplace(token, move(uwbParam(move(arrValue))));
+                m_map.try_emplace(token, uwbParam(std::move(arrValue)));
+                arrValue = {};
                 state = END_LINE;
             }
             break;
         case STR_VALUE:
             if (c == '"') {
                 state = END_LINE;
-                m_map.try_emplace(token, move(uwbParam(strValue)));
+                m_map.try_emplace(token, uwbParam(strValue));
             } else {
                 strValue.push_back(c);
             }
@@ -391,6 +446,12 @@ bool CUwbNxpConfig::readConfig()
         ALOGI("Extra calibration file %s opened.", name);
     }
 
+    // Checks if this is a factory calibrated file by filename matching
+    std::string filename = mFilePath.stem();
+    if (filename.starts_with(factory_file_prefix)) {
+        mFactoryFile = true;
+    }
+
     return mValidFile;
 }
 
@@ -403,10 +464,7 @@ bool CUwbNxpConfig::readConfig()
 ** Returns:     none
 **
 *******************************************************************************/
-CUwbNxpConfig::CUwbNxpConfig() :
-    mValidFile(false)
-{
-}
+CUwbNxpConfig::CUwbNxpConfig() : mFactoryFile(false), mValidFile(false) {}
 
 /*******************************************************************************
 **
@@ -421,53 +479,38 @@ CUwbNxpConfig::~CUwbNxpConfig()
 {
 }
 
-CUwbNxpConfig::CUwbNxpConfig(const char *filepath)
+CUwbNxpConfig::CUwbNxpConfig(std::string_view filepath) : mFilePath(filepath)
 {
-    open(filepath);
+    readConfig();
 }
 
 CUwbNxpConfig::CUwbNxpConfig(CUwbNxpConfig&& config)
 {
-    m_map = move(config.m_map);
+    m_map = std::move(config.m_map);
     mValidFile = config.mValidFile;
-    mFilePath = move(config.mFilePath);
+    mFilePath = std::move(config.mFilePath);
+    mFactoryFile = config.mFactoryFile;
 
     config.mValidFile = false;
 }
 
 CUwbNxpConfig& CUwbNxpConfig::operator=(CUwbNxpConfig&& config)
 {
-    m_map = move(config.m_map);
+    m_map = std::move(config.m_map);
     mValidFile = config.mValidFile;
-    mFilePath = move(config.mFilePath);
+    mFilePath = std::move(config.mFilePath);
+    mFactoryFile = config.mFactoryFile;
 
     config.mValidFile = false;
     return *this;
 }
 
-bool CUwbNxpConfig::open(const char *filepath)
+const uwbParam* CUwbNxpConfig::find(std::string_view key) const
 {
-    mValidFile = false;
-    mFilePath = filepath;
-
-    return readConfig();
-}
-
-/*******************************************************************************
-**
-** Function:    CUwbNxpConfig::find()
-**
-** Description: search if a setting exist in the setting array
-**
-** Returns:     pointer to the setting object
-**
-*******************************************************************************/
-const uwbParam* CUwbNxpConfig::find(const char* p_name) const
-{
-    const auto it = m_map.find(p_name);
-
+    // TODO: how can we use the same hash function for string and string_view?
+    const auto it = m_map.find(std::string(key));
     if (it == m_map.cend()) {
-        return NULL;
+        return nullptr;
     }
     return &it->second;
 }
@@ -493,117 +536,41 @@ void CUwbNxpConfig::dump() const
     }
 }
 
-/*******************************************************************************/
-uwbParam::uwbParam() :
-    m_numValue(0),
-    m_type(type::NUMBER)
-{
-}
-
-uwbParam::~uwbParam()
-{
-}
-
-uwbParam::uwbParam(const uwbParam &param) :
-    m_numValue(param.m_numValue),
-    m_str_value(param.m_str_value),
-    m_arrValue(param.m_arrValue),
-    m_arrStrValue(param.m_arrStrValue),
-    m_type(param.m_type)
-{
-}
-
-uwbParam::uwbParam(uwbParam &&param) :
-    m_numValue(param.m_numValue),
-    m_str_value(move(param.m_str_value)),
-    m_arrValue(move(param.m_arrValue)),
-    m_arrStrValue(move(param.m_arrStrValue)),
-    m_type(param.m_type)
-{
-}
-
-uwbParam::uwbParam(const string& value) :
-    m_numValue(0),
-    m_str_value(value),
-    m_type(type::STRING)
-{
-}
-
-uwbParam::uwbParam(unsigned long value) :
-    m_numValue(value),
-    m_type(type::NUMBER)
-{
-}
-
-uwbParam::uwbParam(vector<uint8_t> &&value) :
-    m_arrValue(move(value)),
-    m_type(type::BYTEARRAY)
-{
-}
-
-uwbParam::uwbParam(vector<string> &&value) :
-    m_arrStrValue(move(value)),
-    m_type(type::STRINGARRAY)
-{
-}
-
-
-void uwbParam::dump(const string &tag) const
-{
-    if (m_type == type::NUMBER) {
-        ALOGV(" - %s = 0x%lx", tag.c_str(), m_numValue);
-    } else if (m_type == type::STRING) {
-        ALOGV(" - %s = %s", tag.c_str(), m_str_value.c_str());
-    } else if (m_type == type::BYTEARRAY) {
-        stringstream ss_hex;
-        ss_hex.fill('0');
-        for (auto b : m_arrValue) {
-            ss_hex << setw(2) << hex << (int)b << " ";
-        }
-        ALOGV(" - %s = { %s}", tag.c_str(), ss_hex.str().c_str());
-    } else if (m_type == type::STRINGARRAY) {
-        stringstream ss;
-        for (auto s : m_arrStrValue) {
-            ss << "\"" << s << "\", ";
-        }
-        ALOGV(" - %s = { %s}", tag.c_str(), ss.str().c_str());
-    }
-}
 /*******************************************************************************/
 class RegionCodeMap {
 public:
-    void loadMapping(const char *filepath) {
+    void loadMapping(std::string_view filepath) {
         CUwbNxpConfig config(filepath);
         if (!config.isValid()) {
             ALOGW("Region mapping was not provided.");
             return;
         }
 
-        ALOGI("Region mapping was provided by %s", filepath);
+        ALOGI("Region mapping was provided by %s", std::string(filepath).c_str());
         auto &all_params = config.get_data();
         for (auto &it : all_params) {
             const auto &region_str = it.first;
             const uwbParam *param = &it.second;
 
             // split space-separated strings into set
-            stringstream ss(param->str_value());
-            string cc;
-            unordered_set<string> cc_set;
+            std::stringstream ss(std::string(param->str_value()));
+            std::string cc;
+            std::unordered_set<std::string> cc_set;
             while (ss >> cc) {
               if (cc.length() == 2 && isupper(cc[0]) && isupper(cc[1])) {
-                cc_set.emplace(move(cc));
+                cc_set.emplace(std::move(cc));
               }
             }
-            auto result = m_map.try_emplace(region_str, move(cc_set));
+            auto result = m_map.try_emplace(region_str, std::move(cc_set));
             if (!result.second) {
               // region conlifct : merge
-              result.first->second.merge(move(cc_set));
+              result.first->second.merge(std::move(cc_set));
             }
         }
-        m_config = move(config);
+        m_config = std::move(config);
     }
-    string xlateCountryCode(const char country_code[2]) {
-        string code{country_code[0], country_code[1]};
+    std::string xlateCountryCode(const char country_code[2]) {
+        std::string code{country_code[0], country_code[1]};
         if (m_config.isValid()) {
             for (auto &it : m_map) {
                 const auto &region_str = it.first;
@@ -626,7 +593,7 @@ public:
         for (auto &entry : m_map) {
             const auto &region_str = entry.first;
             const auto &cc_set = entry.second;
-            stringstream ss;
+            std::stringstream ss;
             for (const auto s : cc_set) {
                 ss << "\"" << s << "\", ";
             }
@@ -635,7 +602,7 @@ public:
     }
 private:
     CUwbNxpConfig m_config;
-    unordered_map<string, unordered_set<string>> m_map;
+    std::unordered_map<std::string, std::unordered_set<std::string>> m_map;
 };
 
 /*******************************************************************************/
@@ -643,14 +610,11 @@ class CascadeConfig {
 public:
     CascadeConfig();
 
-    void init(const char *main_config);
+    void init(std::string_view main_config);
     void deinit();
     bool setCountryCode(const char country_code[2]);
 
-    const uwbParam* find(const char *name)  const;
-    bool    getValue(const char* name, char* pValue, size_t len) const;
-    bool    getValue(const char* name, unsigned long& rValue) const;
-    bool    getValue(const char* name, uint8_t* pValue, size_t len, size_t* readlen) const;
+    const uwbParam* find(std::string_view key, bool include_factory)  const;
 private:
     // default_nxp_config_path
     CUwbNxpConfig mMainConfig;
@@ -659,7 +623,7 @@ private:
     CUwbNxpConfig mUciConfig;
 
     // EXTRA_CONF_PATH[N]
-    std::vector<std::pair<string, CUwbNxpConfig>> mExtraConfig;
+    std::vector<std::pair<std::string, CUwbNxpConfig>> mExtraConfig;
 
     // [COUNTRY_CODE_CAP_FILE_LOCATION]/country_code_config_name
     CUwbNxpConfig mCapsConfig;
@@ -669,10 +633,10 @@ private:
 
     // current set of specifiers for EXTRA_CONF_PATH[]
     struct ExtraConfPathSpecifiers {
-        string mCurSku;
-        string mCurExtid;
-        string mCurRegionCode;
-        string mCurRevision;
+        std::string mCurSku;
+        std::string mCurExtid;
+        std::string mCurRegionCode;
+        std::string mCurRevision;
         void reset() {
             mCurSku.clear();
             mCurExtid.clear();
@@ -704,43 +668,43 @@ CascadeConfig::CascadeConfig()
 
 bool CascadeConfig::evaluateExtraConfPaths()
 {
-    bool updated = false;
+    int nr_updated = 0;
 
     for (auto& [filename, config] : mExtraConfig) {
         std::string new_filename(filename);
 
-        auto posSku = filename.find(sku_specifier);
+        auto posSku = new_filename.find(sku_specifier);
         if (posSku != std::string::npos && !mExtraConfSpecifiers.mCurSku.empty()) {
-            new_filename.replace(posSku, strlen(sku_specifier), mExtraConfSpecifiers.mCurSku);
+            new_filename.replace(posSku, sku_specifier.length(), mExtraConfSpecifiers.mCurSku);
         }
 
-        auto posExtid = filename.find(extid_specifier);
+        auto posExtid = new_filename.find(extid_specifier);
         if (posExtid != std::string::npos && !mExtraConfSpecifiers.mCurExtid.empty()) {
-            new_filename.replace(posExtid, strlen(extid_specifier), mExtraConfSpecifiers.mCurExtid);
+            new_filename.replace(posExtid, extid_specifier.length(), mExtraConfSpecifiers.mCurExtid);
         }
 
-        auto posCountry = filename.find(country_code_specifier);
+        auto posCountry = new_filename.find(country_code_specifier);
         if (posCountry != std::string::npos && !mExtraConfSpecifiers.mCurRegionCode.empty()) {
-            new_filename.replace(posCountry, strlen(country_code_specifier), mExtraConfSpecifiers.mCurRegionCode);
+            new_filename.replace(posCountry, country_code_specifier.length(), mExtraConfSpecifiers.mCurRegionCode);
         }
 
-        auto posRevision = filename.find(revision_specifier);
+        auto posRevision = new_filename.find(revision_specifier);
         if (posRevision != std::string::npos && !mExtraConfSpecifiers.mCurRevision.empty()) {
-            new_filename.replace(posRevision, strlen(revision_specifier), mExtraConfSpecifiers.mCurRevision);
+            new_filename.replace(posRevision, revision_specifier.length(), mExtraConfSpecifiers.mCurRevision);
         }
-
         // re-open the file if filepath got re-evaluated.
         if (new_filename != config.getFilePath()) {
-            config.open(new_filename.c_str());
-            updated = true;
+            config = CUwbNxpConfig(new_filename.c_str());
+            ++nr_updated;
         }
     }
-    return updated;
+    ALOGI("%d new configuration files found.", nr_updated);
+    return (nr_updated > 0);
 }
 
-void CascadeConfig::init(const char *main_config)
+void CascadeConfig::init(std::string_view main_config)
 {
-    ALOGV("CascadeConfig initialize with %s", main_config);
+    ALOGV("CascadeConfig initialize with %s", std::string(main_config).c_str());
 
     // Main config file
     CUwbNxpConfig config(main_config);
@@ -748,19 +712,19 @@ void CascadeConfig::init(const char *main_config)
         ALOGW("Failed to load main config file");
         return;
     }
-    mMainConfig = move(config);
+    mMainConfig = std::move(config);
 
     {
         // UCI config file
-        std::string uciConfigFilePath = default_uci_config_path;
+        std::string uciConfigFilePath(default_uci_config_path);
         uciConfigFilePath += nxp_uci_config_file;
 
-        CUwbNxpConfig config(uciConfigFilePath.c_str());
+        CUwbNxpConfig config(uciConfigFilePath);
         if (!config.isValid()) {
             ALOGW("Failed to load uci config file:%s",
                     uciConfigFilePath.c_str());
         } else {
-            mUciConfig = move(config);
+            mUciConfig = std::move(config);
         }
     }
 
@@ -789,48 +753,51 @@ void CascadeConfig::init(const char *main_config)
     evaluateExtraConfPaths();
 
     // re-evaluate with "<extid>"
-    char extid_value[PROPERTY_VALUE_MAX];
-    if (!NxpConfig_GetStr(extid_config_name, extid_value, sizeof(extid_value))) {
-        strcpy(extid_value, extid_default_value);
-    }
-    mExtraConfSpecifiers.mCurExtid = extid_value;
+    mExtraConfSpecifiers.mCurExtid =
+        NxpConfig_GetStr(extid_config_name).value_or(extid_default_value);
     evaluateExtraConfPaths();
 
-    ALOGI("Provided specifiers: sku=[%s] revision=[%s] extid=[%s]", sku_value, revision_value, extid_value);
+    ALOGI("Provided specifiers: sku=[%s] revision=[%s] extid=[%s]", sku_value, revision_value,
+        mExtraConfSpecifiers.mCurExtid.c_str());
 
     // Pick one libuwb-countrycode.conf with the highest VERSION number
     // from multiple directories specified by COUNTRY_CODE_CAP_FILE_LOCATION
-    size_t arrLen = 0;
-    if (NxpConfig_GetStrArrayLen(NAME_COUNTRY_CODE_CAP_FILE_LOCATION, &arrLen) && arrLen > 0) {
-        constexpr size_t loc_max_len = 260;
-        auto loc = make_unique<char[]>(loc_max_len);
-        int version, max_version = -1;
-        string strPickedPath;
+    // XXX: Can't we just drop this feature of COUNTRY_CODE_CAP_FILE_LOCATION?
+    std::vector<std::string> locations = NxpConfig_GetStrArray(NAME_COUNTRY_CODE_CAP_FILE_LOCATION);
+    if ( locations.size() > 0) {
+        int max_version = -1;
+        std::string strPickedPath;
         bool foundCapFile = false;
         CUwbNxpConfig pickedConfig;
 
-        for (int i = 0; i < arrLen; i++) {
-            if (!NxpConfig_GetStrArrayVal(NAME_COUNTRY_CODE_CAP_FILE_LOCATION, i, loc.get(), loc_max_len)) {
-                continue;
-            }
-            string strPath(loc.get());
-            strPath += country_code_config_name;
+        for (const std::string& loc : locations) {
+            if (loc.empty()) { continue; }
 
+            std::string strPath(loc);
+            strPath += country_code_config_name;
             ALOGV("Try to load %s", strPath.c_str());
 
             CUwbNxpConfig config(strPath.c_str());
+            // This cannot be provided from factory cal file.
+            if (config.isFactory()) { continue; }
 
             const uwbParam *param = config.find(NAME_NXP_COUNTRY_CODE_VERSION);
-            version = param ? atoi(param->str_value()) : -2;
+            int version = -2;
+            if (param) {
+                std::string_view v = param->str_value();
+                int n;
+                auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
+                if (ec == std::errc()) { version = n; }
+            }
             if (version > max_version) {
                 foundCapFile = true;
-                pickedConfig = move(config);
-                strPickedPath = move(strPath);
+                pickedConfig = std::move(config);
+                strPickedPath = std::move(strPath);
                 max_version = version;
             }
         }
         if (foundCapFile) {
-            mCapsConfig = move(pickedConfig);
+            mCapsConfig = std::move(pickedConfig);
             ALOGI("CountryCodeCaps file %s loaded with VERSION=%d", strPickedPath.c_str(), max_version);
         } else {
             ALOGI("No CountryCodeCaps specified");
@@ -840,7 +807,7 @@ void CascadeConfig::init(const char *main_config)
     }
 
     // Load region mapping
-    const uwbParam *param = find(NAME_REGION_MAP_PATH);
+    const uwbParam *param = find(NAME_REGION_MAP_PATH, /*include_factory=*/false);
     if (param) {
         mRegionMap.loadMapping(param->str_value());
     }
@@ -862,7 +829,7 @@ void CascadeConfig::deinit()
 
 bool CascadeConfig::setCountryCode(const char country_code[2])
 {
-    string strRegion = mRegionMap.xlateCountryCode(country_code);
+    std::string strRegion = mRegionMap.xlateCountryCode(country_code);
 
     if (strRegion == mExtraConfSpecifiers.mCurRegionCode) {
         ALOGI("Same region code(%c%c --> %s), per-country configuration not updated.",
@@ -876,71 +843,30 @@ bool CascadeConfig::setCountryCode(const char country_code[2])
     return evaluateExtraConfPaths();
 }
 
-const uwbParam* CascadeConfig::find(const char *name) const
+const uwbParam* CascadeConfig::find(std::string_view key, bool include_factory) const
 {
     const uwbParam* param = NULL;
 
-    param = mCapsConfig.find(name);
+    param = mCapsConfig.find(key);
     if (param)
-      return param;
+        return param;
 
     for (auto it = mExtraConfig.rbegin(); it != mExtraConfig.rend(); it++) {
         auto &config = it->second;
-        param = config.find(name);
+        if (!include_factory && config.isFactory()) { continue; }
+        param = config.find(key);
         if (param)
             break;
     }
     if (!param) {
-        param = mMainConfig.find(name);
+        param = mMainConfig.find(key);
     }
     if (!param) {
-        param = mUciConfig.find(name);
+        param = mUciConfig.find(key);
     }
     return param;
 }
 
-// TODO: move these getValue() helpers out of the class
-bool CascadeConfig::getValue(const char* name, char* pValue, size_t len) const
-{
-    const uwbParam *param = find(name);
-    if (!param)
-        return false;
-    if (param->getType() != uwbParam::type::STRING)
-        return false;
-    if (len < (param->str_len() + 1))
-        return false;
-
-    strncpy(pValue, param->str_value(), len);
-    return true;
-}
-
-bool CascadeConfig::getValue(const char* name, uint8_t* pValue, size_t len, size_t* readlen) const
-{
-    const uwbParam *param = find(name);
-    if (!param)
-        return false;
-    if (param->getType() != uwbParam::type::BYTEARRAY)
-        return false;
-    if (len < param->arr_len())
-        return false;
-    memcpy(pValue, param->arr_value(), param->arr_len());
-    if (readlen)
-        *readlen = param->arr_len();
-    return true;
-}
-
-bool CascadeConfig::getValue(const char* name, unsigned long& rValue) const
-{
-    const uwbParam *param = find(name);
-    if (!param)
-        return false;
-    if (param->getType() != uwbParam::type::NUMBER)
-        return false;
-
-    rValue = param->numValue();
-    return true;
-}
-
 }   // namespace
 
 static CascadeConfig gConfig;
@@ -962,104 +888,48 @@ bool NxpConfig_SetCountryCode(const char country_code[2])
     return gConfig.setCountryCode(country_code);
 }
 
-/*******************************************************************************
-**
-** Function:    NxpConfig_GetStr
-**
-** Description: API function for getting a string value of a setting
-**
-** Returns:     True if found, otherwise False.
-**
-*******************************************************************************/
-bool NxpConfig_GetStr(const char* name, char* pValue, size_t len)
+std::optional<std::string_view> NxpConfig_GetStr(std::string_view key, bool include_factory)
 {
-    return gConfig.getValue(name, pValue, len);
+    const uwbParam *param = gConfig.find(key, include_factory);
+    if (param == nullptr || param->getType() != uwbParam::type::STRING) {
+        return std::nullopt;
+    }
+    return param->str_value();
 }
 
-/*******************************************************************************
-**
-** Function:    NxpConfig_GetByteArray()
-**
-** Description: Read byte array value from the config file.
-**
-** Parameters:
-**              name    - name of the config param to read.
-**              pValue  - pointer to input buffer.
-**              bufflen - input buffer length.
-**              len     - out parameter to return the number of bytes read from config file,
-**                        return -1 in case bufflen is not enough.
-**
-** Returns:     TRUE[1] if config param name is found in the config file, else FALSE[0]
-**
-*******************************************************************************/
-bool NxpConfig_GetByteArray(const char* name, uint8_t* pValue, size_t bufflen, size_t* len)
+std::optional<std::span<const uint8_t>> NxpConfig_GetByteArray(std::string_view key, bool include_factory)
 {
-    return gConfig.getValue(name, pValue, bufflen, len);
+    const uwbParam *param = gConfig.find(key, include_factory);
+    if (param == nullptr || param->getType() != uwbParam::type::BYTEARRAY) {
+        return std::nullopt;
+    }
+    return param->arr_value();
 }
 
-/*******************************************************************************
-**
-** Function:    NxpConfig_GetNum
-**
-** Description: API function for getting a numerical value of a setting
-**
-** Returns:     true, if successful
-**
-*******************************************************************************/
-bool NxpConfig_GetNum(const char* name, void* pValue, size_t len)
+std::optional<uint64_t> NxpConfig_GetUint64(std::string_view key, bool include_factory)
 {
-    if ((name == nullptr) || (pValue == nullptr)){
-        ALOGE("[%s] Invalid arguments", __func__);
-        return false;
-    }
-    const uwbParam* pParam = gConfig.find(name);
+    const uwbParam* pParam = gConfig.find(key, include_factory);
 
     if ((pParam == nullptr) || (pParam->getType() != uwbParam::type::NUMBER)) {
-        ALOGE("Config:%s not found in the config file", name);
-        return false;
-    }
-
-    unsigned long v = pParam->numValue();
-    switch (len)
-    {
-    case sizeof(unsigned long):
-        *(static_cast<unsigned long*>(pValue)) = (unsigned long)v;
-        break;
-    case sizeof(unsigned short):
-        *(static_cast<unsigned short*>(pValue)) = (unsigned short)v;
-        break;
-    case sizeof(unsigned char):
-        *(static_cast<unsigned char*> (pValue)) = (unsigned char)v;
-        break;
-    default:
-        ALOGE("[%s] unsupported length:%zu", __func__, len);
-        return false;
+        return std::nullopt;
     }
-    return true;
+    return pParam->numValue();
 }
 
-// Get the length of a 'string-array' type parameter
-bool NxpConfig_GetStrArrayLen(const char* name, size_t* pLen)
+std::optional<bool> NxpConfig_GetBool(std::string_view key, bool include_factory)
 {
-    const uwbParam* param = gConfig.find(name);
-    if (!param || param->getType() != uwbParam::type::STRINGARRAY)
-        return false;
-
-    *pLen = param->str_arr_len();
-    return true;
+    const uwbParam* pParam = gConfig.find(key, include_factory);
+    if (pParam == nullptr || pParam->getType() != uwbParam::type::NUMBER) {
+        return std::nullopt;
+    }
+    return pParam->numValue();
 }
 
-// Get a string value from 'string-array' type parameters, index zero-based
-bool NxpConfig_GetStrArrayVal(const char* name, int index, char* pValue, size_t len)
+std::vector<std::string> NxpConfig_GetStrArray(std::string_view key, bool include_factory)
 {
-    const uwbParam* param = gConfig.find(name);
-    if (!param || param->getType() != uwbParam::type::STRINGARRAY)
-        return false;
-    if (index < 0 || index >= param->str_arr_len())
-        return false;
-
-    if (len < param->str_arr_elem_len(index) + 1)
-        return false;
-    strncpy(pValue, param->str_arr_elem(index), len);
-    return true;
+    const uwbParam* param = gConfig.find(key, include_factory);
+    if (param == nullptr || param->getType() != uwbParam::type::STRINGARRAY) {
+        return std::vector<std::string>{};
+    }
+    return param->str_arr_value();
 }
diff --git a/halimpl/utils/phNxpConfig.h b/halimpl/utils/phNxpConfig.h
index 030fc03..1988664 100644
--- a/halimpl/utils/phNxpConfig.h
+++ b/halimpl/utils/phNxpConfig.h
@@ -1,7 +1,7 @@
 /******************************************************************************
  *
  *  Copyright (C) 2011-2012 Broadcom Corporation
- *  Copyright 2018-2019, 2023 NXP
+ *  Copyright 2018-2019, 2023-2025 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -22,22 +22,41 @@
 
 #include <cstddef>
 #include <cstdint>
+#include <limits>
+#include <optional>
+#include <span>
+#include <string_view>
+
+#include "phNxpLog.h"
 
 void NxpConfig_Init(void);
 void NxpConfig_Deinit(void);
 bool NxpConfig_SetCountryCode(const char country_code[2]);
 
-// TODO: use std::optional as return type.
-// TODO: use std::string_view instead of const char*.
-// TODO: add GetBool().
-// TODO: use template for GetNum() (uint8_t, uint16_t, uint32_t).
-bool NxpConfig_GetStr(const char* name, char* p_value, size_t len);
-bool NxpConfig_GetNum(const char* name, void* p_value, size_t len);
-bool NxpConfig_GetByteArray(const char* name, uint8_t* pValue, size_t bufflen, size_t *len);
+std::optional<std::string_view> NxpConfig_GetStr(std::string_view key, bool include_factory = true);
+
+std::optional<std::span<const uint8_t>> NxpConfig_GetByteArray(std::string_view key, bool include_factory = true);
+
+std::optional<uint64_t> NxpConfig_GetUint64(std::string_view key, bool include_factory = true);
+
+template <typename T>
+inline std::optional<T> NxpConfig_GetNum(std::string_view key, bool include_factory = true) {
+    static_assert(std::is_integral<T>::value);
+    auto res = NxpConfig_GetUint64(key, include_factory);
+    if (res.has_value() && *res > std::numeric_limits<T>::max()) {
+        std::string strkey(key);
+        NXPLOG_UCIHAL_W("Config %s overflow", strkey.c_str());
+    }
+    return res;
+}
+
+// Returns true or false if key is existed as a number type parameter.
+std::optional<bool> NxpConfig_GetBool(std::string_view key, bool include_factory = true);
 
-bool NxpConfig_GetStrArrayLen(const char* name, size_t* pLen);
-bool NxpConfig_GetStrArrayVal(const char* name, int index, char* pValue, size_t len);
+// Returns an array of string.
+std::vector<std::string> NxpConfig_GetStrArray(std::string_view key, bool include_factory = true);
 
+// TODO: use constexpr
 /* libuwb-nxp.conf parameters */
 #define NAME_UWB_BOARD_VARIANT_CONFIG "UWB_BOARD_VARIANT_CONFIG"
 #define NAME_UWB_BOARD_VARIANT_VERSION "UWB_BOARD_VARIANT_VERSION"
@@ -57,6 +76,8 @@ bool NxpConfig_GetStrArrayVal(const char* name, int index, char* pValue, size_t
 #define NAME_UWB_CORE_EXT_DEVICE_SR1XX_S_CONFIG "UWB_CORE_EXT_DEVICE_SR1XX_S_CONFIG"
 #define NAME_COUNTRY_CODE_CAP_FILE_LOCATION "COUNTRY_CODE_CAP_FILE_LOCATION"
 #define NAME_UWB_VENDOR_CAPABILITY "UWB_VENDOR_CAPABILITY"
+#define NAME_UWB_UCIX_UCIR_ERROR_LOG "UWB_UCIX_UCIR_ERROR_LOG"
+#define NAME_UWB_DEBUG_LOG_FILE_SIZE "UWB_DEBUG_LOG_FILE_SIZE"
 
 #define NAME_UWB_BINDING_LOCKING_ALLOWED "UWB_BINDING_LOCKING_ALLOWED"
 #define NAME_NXP_UWB_PROD_FW_FILENAME "NXP_UWB_PROD_FW_FILENAME"
@@ -85,6 +106,7 @@ bool NxpConfig_GetStrArrayVal(const char* name, int index, char* pValue, size_t
 #define NAME_AUTO_SUSPEND_TIMEOUT_MS    "AUTO_SUSPEND_TIMEOUT_MS"
 
 #define NAME_DELETE_URSK_FOR_CCC_SESSION    "DELETE_URSK_FOR_CCC_SESSION"
+#define NAME_DELETE_URSK_FOR_ALIRO_SESSION    "DELETE_URSK_FOR_ALIRO_SESSION"
 
 /* In case the HAL has to set STS index for CCC */
 #define NAME_OVERRIDE_STS_INDEX_FOR_CCC_SESSION    "OVERRIDE_STS_INDEX_FOR_CCC_SESSION"
diff --git a/halimpl/utils/phNxpUciHal_utils.cc b/halimpl/utils/phNxpUciHal_utils.cc
index 2db40b2..f396cd6 100644
--- a/halimpl/utils/phNxpUciHal_utils.cc
+++ b/halimpl/utils/phNxpUciHal_utils.cc
@@ -138,8 +138,7 @@ void phNxpUciHal_cleanup_monitor(void) {
 }
 
 /* Initialize the callback data */
-tHAL_UWB_STATUS phNxpUciHal_init_cb_data(phNxpUciHal_Sem_t* pCallbackData,
-                                   void* pContext) {
+tHAL_UWB_STATUS phNxpUciHal_init_cb_data(phNxpUciHal_Sem_t* pCallbackData) {
   /* Create semaphore */
   if (sem_init(&pCallbackData->sem, 0, 0) == -1) {
     NXPLOG_UCIHAL_E("Semaphore creation failed");
@@ -149,9 +148,6 @@ tHAL_UWB_STATUS phNxpUciHal_init_cb_data(phNxpUciHal_Sem_t* pCallbackData,
   /* Set default status value */
   pCallbackData->status = UWBSTATUS_FAILED;
 
-  /* Copy the context */
-  pCallbackData->pContext = pContext;
-
   /* Add to active semaphore list */
   if (nxpucihal_monitor != nullptr) {
     nxpucihal_monitor->AddSem(pCallbackData);
@@ -289,6 +285,8 @@ void phNxpUciHal_print_packet(enum phNxpUciHal_Pkt_Type what, const uint8_t* p_d
     break;
   }
 
+  phNxpUciHalProp_print_log(what, p_data, len);
+
   return;
 }
 
diff --git a/halimpl/utils/phNxpUciHal_utils.h b/halimpl/utils/phNxpUciHal_utils.h
index 501052a..29bb9a0 100644
--- a/halimpl/utils/phNxpUciHal_utils.h
+++ b/halimpl/utils/phNxpUciHal_utils.h
@@ -47,18 +47,11 @@ enum phNxpUciHal_Pkt_Type {
   NXP_TML_FW_DNLD_RSP_UWBS_2_AP,
 };
 
-
+// TODO: 1) use UciHalSemaphore, 2) use std::binary_semaphore
 /* Semaphore handling structure */
 typedef struct phNxpUciHal_Sem {
-  /* Semaphore used to wait for callback */
   sem_t sem;
-
-  /* Used to store the status sent by the callback */
   tHAL_UWB_STATUS status;
-
-  /* Used to provide a local context to the callback */
-  void* pContext;
-
 } phNxpUciHal_Sem_t;
 
 /* Semaphore helper macros */
@@ -77,8 +70,7 @@ static inline int SEM_POST(phNxpUciHal_Sem_t* pCallbackData)
 bool phNxpUciHal_init_monitor(void);
 void phNxpUciHal_cleanup_monitor(void);
 
-tHAL_UWB_STATUS phNxpUciHal_init_cb_data(phNxpUciHal_Sem_t* pCallbackData,
-                                         void* pContext);
+tHAL_UWB_STATUS phNxpUciHal_init_cb_data(phNxpUciHal_Sem_t* pCallbackData);
 
 int phNxpUciHal_sem_timed_wait_msec(phNxpUciHal_Sem_t* pCallbackData, long msec);
 
@@ -101,10 +93,7 @@ void phNxpUciHal_cleanup_cb_data(phNxpUciHal_Sem_t* pCallbackData);
 class UciHalSemaphore {
 public:
   UciHalSemaphore() {
-    phNxpUciHal_init_cb_data(&sem, NULL);
-  }
-  UciHalSemaphore(void *context) {
-    phNxpUciHal_init_cb_data(&sem, context);
+    phNxpUciHal_init_cb_data(&sem);
   }
   virtual ~UciHalSemaphore() {
     phNxpUciHal_cleanup_cb_data(&sem);
@@ -116,6 +105,7 @@ public:
     return phNxpUciHal_sem_timed_wait_msec(&sem, msec);
   }
   int post() {
+    sem.status = UWBSTATUS_SUCCESS;
     return sem_post(&sem.sem);
   }
   int post(tHAL_UWB_STATUS status) {
```

