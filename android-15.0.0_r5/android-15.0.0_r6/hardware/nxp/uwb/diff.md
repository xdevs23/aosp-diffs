```diff
diff --git a/extns/inc/uci_defs.h b/extns/inc/uci_defs.h
index c3bc9da..4acfd77 100644
--- a/extns/inc/uci_defs.h
+++ b/extns/inc/uci_defs.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2018-2023 NXP
+ * Copyright 2018-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -223,6 +223,7 @@ constexpr uint8_t kSessionType_CCCRanging = 0xA0;
 #define UCI_STATUS_COMMAND_RETRY 0x0A
 #define UCI_STATUS_UNKNOWN 0x0B
 #define UCI_STATUS_THERMAL_RUNAWAY 0x54
+#define UCI_STATUS_BUFFER_UNDERFLOW 0x58
 #define UCI_STATUS_LOW_VBAT 0x59
 #define UCI_STATUS_HW_RESET 0xFE
 
diff --git a/halimpl/config/README.md b/halimpl/config/README.md
index de62154..67c6a53 100644
--- a/halimpl/config/README.md
+++ b/halimpl/config/README.md
@@ -70,6 +70,8 @@ Main configuration can specifies additional extra calibrations with *EXTRA_CONF_
 * if the file path has `<country>` in it, `<country>` part will be replaced with country code (or region string)
 * if the file path has `<sku>` in it, `<sku>` part will be replace with the 'persist.vendor.uwb.cal.sku' property value.
   if `persist.vendor.uwb.cal.sku` is unspecified, HAL will try to use `defaultsku` as a default.
+* if the file path has `<revision>` in it, `<revision>` part will be replace with the 'persist.vendor.uwb.cal.revision' property value.
+  if `persist.vendor.uwb.cal.revision` is unspecified, HAL will try to use `defaultrevision` as a default.
 
 Example:
 
@@ -79,7 +81,8 @@ Example:
 EXTRA_CONF_PATH_1="/vendor/etc/uwb/cal-base.conf"
 EXTRA_CONF_PATH_2="/vendor/etc/uwb/cal-<sku>.conf"
 EXTRA_CONF_PATH_3="/vendor/etc/uwb/cal-<country>.conf"
-EXTRA_CONF_PATH_4="/mnt/vendor/persist/uwb/cal-factory.conf"
+EXTRA_CONF_PATH_4="/vendor/etc/uwb/cal-<revision>.conf"
+EXTRA_CONF_PATH_5="/mnt/vendor/persist/uwb/cal-factory.conf"
 ```
 
 #### Region mapping
@@ -131,9 +134,33 @@ Load the Crystal calibration value from OTP when it's 1. *cal.xtal* will be igno
 
 e.g. `cal.xtal={11 00 11 00 3f 00}`
 
-##### *cal.ant`<antenna-id>`.ch`<channel-number>`.ant_delay*`=<16bit unsigned>`
+##### RX antenna delay
 
-Per-country, RX antenna delay value in Q14.2. e.g. `cal.ant1.ch5.ant_delay=2000`
+* *cal.ant`<antenna-id>`.ch`<channel-number>`.ant_delay*`=<16bit unsigned>`
+
+  Default RX antenna delay value in Q14.2.
+
+* *cal.ant`<antenna-id>`.ch`<channel-number>`.ant_delay.force_version*`=<16bit unsigned>`
+
+  Forcefully override *...ant_delay* value by specifying version number.
+  Platform can specify multiple version numbers for selecting alternate delay values
+  using *...ant_delay.force_value.`<version>`* property.
+
+* *cal.ant`<antenna-id>`.ch`<channel-number>`.ant_delay.force_value.`<version>`*`=<16bit unsigned>`
+
+  Alternate RX antenna delay value in Q14.2.
+  HAL will take this value if *...ant_delay.force_version=`<version>`* and
+  and *ant_delay.force_value.`<version>`* are provided.
+
+e.g.
+```
+cal.ant1.ch5.ant_delay=2000
+cal.ant1.ch5.ant_delay.force_version=2
+cal.ant1.cht.ant_delay.force_value.1=2100
+cal.ant1.cht.ant_delay.force_value.2=2200
+```
+
+In the above example, HAL applies 2200 for the antenna delay.
 
 ##### *cal.ant`<antenna-id>`.ch`<channel-number>`.tx_power*`=<byte array>`
 
@@ -165,7 +192,8 @@ REGION_MAP_PATH="/vendor/etc/uwb/regions.conf"
 EXTRA_CONF_PATH_1="/vendor/etc/uwb/cal-base.conf"
 EXTRA_CONF_PATH_2="/vendor/etc/uwb/cal-<sku>.conf"
 EXTRA_CONF_PATH_3="/vendor/etc/uwb/cal-<country>.conf"
-EXTRA_CONF_PATH_4="/mnt/vendor/persist/uwb/cal-factory.conf"
+EXTRA_CONF_PATH_4="/vendor/etc/uwb/cal-<sku>-<revision>.conf"
+EXTRA_CONF_PATH_5="/mnt/vendor/persist/uwb/cal-factory.conf"
 
 # /vendor/etc/uwb/cal-base.conf:
 cal.rx_antenna_mask=0x03
@@ -205,4 +233,9 @@ cal.restricted_channels=0xffff
 CE="AT BE BG CH CY CZ DE DK EE ES FI FR GB GR HR HU IE IS IT LI LV LT LU MT NI NL NO PL PT RO SE SK SI"
 FCC="US CA"
 RESTRICTED="AR AM AZ BY ID KZ KG NP PK PY RU SB TJ TM UA UZ"
+
+# /vendor/etc/uwb/cal-modelA-EVT.conf:
+# effective when persist.vendor.uwb.cal.sku=modelA && persist.vendor.uwb.cal.revision=EVT
+cal.ant1.ch5.tx_power={02, 00, 11, 00}
+cal.ant1.ch9.tx_power={02, 00, 12, 00}
 ```
diff --git a/halimpl/config/SR1XX/libuwb-nxp-SR100S.conf b/halimpl/config/SR1XX/libuwb-nxp-SR100S.conf
index 57b0df4..6743e64 100644
--- a/halimpl/config/SR1XX/libuwb-nxp-SR100S.conf
+++ b/halimpl/config/SR1XX/libuwb-nxp-SR100S.conf
@@ -32,36 +32,24 @@ UWB_BOARD_VARIANT_VERSION=0x01
   ##Note: List of problematic channels in 5GHz Range, if required add
   ##      config (E4, 32, 03, 120, 124, 128) and update the
   ##      Length and number of parameters accordingly in header part.
-#TX_PULSE_SHAPE_CONFIG      E428
 # Refer the NXP UCI specification for below configs
 #ANTENNA_RX_IDX_DEFINE   E460
 #ANTENNA_TX_IDX_DEFINE   E461
+#ANTENNAS_CONFIGURATION_RX E465
 
-UWB_CORE_EXT_DEVICE_DEFAULT_CONFIG={20, 04, 00, 24, 05,
+UWB_CORE_EXT_DEVICE_DEFAULT_CONFIG={05,
     E4, 03, 01, b4,
     E4, 04, 02, f4, 01,
-    E4, 28, 04, 02, 02, 02, 00,
     E4, 60, 07, 01, 01, 02, 01, 00, 01, 00,
-    E4, 61, 06, 01, 01, 01, 00, 00, 00
+    E4, 61, 06, 01, 01, 01, 00, 00, 00,
+    E4, 65, 06, 01, 03, 03, 00, 01, 01
 }
 
-##Note: Session specific default app config configured here
-#ANTENNAS_CONFIGURATION_RX
-
-NXP_UWB_EXT_APP_DEFAULT_CONFIG={01, 03, 03, 01, 01, 01}
-
 ##Note: Below configs are applicable in User_Mode FW only
 ##Note: WIFI COEX CONFIG Disabled by default, if required add the
   ##      config (E4, 05, 04, 00, 3C, 1E, 1E) and update the
   ##      Lentgh and number of parameter accordingly in the header part.
   ##      WIFI COEX feature supports only in user binary.
-#WIFI_COEX_UART_USER_CFG E437
-  ## UART based WiFi-CoEx Interface User Configuration. default value 0
-#FREQ_OF_UWB_REQ_WLAN_CHANNEL_INFO E439
-  ## Configure the frequency of UWB Requests to WLAN for getting WLAN Channel Information. Default value 3
-  ## if required add the
-  ##      config (E4, 39, 01, 03) and update the
-  ##      Length and number of parameter accordingly in the header part
 #GPIO_USAGE_CONFIG E4 08
   ## Customer need to set the DPD_WAKEUP_SOURCE as 02 (GPIO1) before applying the GPIO_USAGE_CONFIG command to
   ## enable time sync notification feature
@@ -101,6 +89,16 @@ NXP_UWB_DEV_FW_FILENAME="libsr100t_dev_fw.bin"
 UWB_FW_DOWNLOAD_LOG=0x00
 ###############################################################################
 
+###############################################################################
+#enable or disable delete ursk for ccc session
+DELETE_URSK_FOR_CCC_SESSION=0x00
+###############################################################################
+
+###############################################################################
+#enable or disable sts index overriding for ccc session
+OVERRIDE_STS_INDEX_FOR_CCC_SESSION=0x01
+###############################################################################
+
 ###############################################################################
 # set Crystal calibration settings
 # byte[0] No Of registers
diff --git a/halimpl/config/SR1XX/libuwb-nxp.conf b/halimpl/config/SR1XX/libuwb-nxp.conf
index e759d7d..d4bd45d 100644
--- a/halimpl/config/SR1XX/libuwb-nxp.conf
+++ b/halimpl/config/SR1XX/libuwb-nxp.conf
@@ -38,6 +38,7 @@ UWB_BOARD_VARIANT_VERSION=0x01
 #ANTENNA_TX_IDX_DEFINE   E461
 #ANTENNA_RX_PAIR_DEFINE  E462
 #WIFI_CO_EX_CH_CFG       E464
+#ANTENNAS_CONFIGURATION_RX E465
  ## Note: Select wifi co-ex channel config
  ##       b0: Channel 5, Set to 1 enable Wifi Co-ex on Channel 5
  ##       b1: Channel 6, Set to 1 enable Wifi Co-ex on Channel 6
@@ -48,29 +49,30 @@ UWB_BOARD_VARIANT_VERSION=0x01
  ##       If required, add config(E4, 64, 01, 01) to update Wifi Co-ex for
  ##       all the channels and update the lentgh and number of parameter
  ##       accordingly in the header part.
-UWB_CORE_EXT_DEVICE_DEFAULT_CONFIG={20, 04, 00, 40, 06,
+UWB_CORE_EXT_DEVICE_DEFAULT_CONFIG={06,
     E4, 03, 01, b4,
     E4, 04, 02, f4, 01,
-    E4, 28, 04, 02, 02, 02, 00,
     E4, 60, 13, 03, 01, 01, 02, 00, 02, 00, 02, 02, 01, 00, 01, 00, 03, 01, 02, 00, 00, 00,
     E4, 61, 06, 01, 01, 01, 00, 00, 00,
-    E4, 62, 0D, 02, 01, 01, 02, 00, 00, 00, 02, 03, 02, 00, 00, 00
+    E4, 62, 0D, 02, 01, 01, 02, 00, 00, 00, 02, 03, 02, 00, 00, 00,
+    E4, 65, 07, 01, 03, 04, 01, 02, 01, 02
 }
 
-UWB_CORE_EXT_DEVICE_SR1XX_T_CONFIG={20, 04, 00, 40, 06,
+UWB_CORE_EXT_DEVICE_SR1XX_T_CONFIG={06,
     E4, 03, 01, b4,
     E4, 04, 02, f4, 01,
-    E4, 28, 04, 02, 02, 02, 00,
     E4, 60, 13, 03, 01, 01, 02, 00, 02, 00, 02, 02, 01, 00, 01, 00, 03, 01, 02, 00, 00, 00,
     E4, 61, 06, 01, 01, 01, 00, 00, 00,
-    E4, 62, 0D, 02, 01, 01, 02, 00, 00, 00, 02, 03, 02, 00, 00, 00
+    E4, 62, 0D, 02, 01, 01, 02, 00, 00, 00, 02, 03, 02, 00, 00, 00,
+    E4, 65, 07, 01, 03, 04, 01, 02, 01, 02
 }
-UWB_CORE_EXT_DEVICE_SR1XX_S_CONFIG={20, 04, 00, 24, 05,
+
+UWB_CORE_EXT_DEVICE_SR1XX_S_CONFIG={05,
     E4, 03, 01, b4,
     E4, 04, 02, f4, 01,
-    E4, 28, 04, 02, 02, 02, 00,
     E4, 60, 07, 01, 01, 02, 01, 00, 01, 00,
-    E4, 61, 06, 01, 01, 01, 00, 00, 00
+    E4, 61, 06, 01, 01, 01, 00, 00, 00,
+    E4, 65, 06, 01, 03, 03, 00, 01, 01
 }
 
 #LIST OF UWB CAPABILITY INFO NOT RECEIVED FROM UWBS
@@ -88,25 +90,11 @@ UWB_VENDOR_CAPABILITY={A7, 04, 01, 00, 00, 00,
   EA, 02, 09, 00
 }
 
-##Note: Session specific default app config configured here
-#ANTENNAS_CONFIGURATION_RX
-
-NXP_UWB_EXT_APP_DEFAULT_CONFIG={01, 03, 04, 01, 02, 01, 02}
-NXP_UWB_EXT_APP_SR1XX_T_CONFIG={01, 03, 04, 01, 02, 01, 02}
-NXP_UWB_EXT_APP_SR1XX_S_CONFIG={01, 03, 03, 00, 01, 01}
-
 ##Note: Below configs are applicable in User_Mode FW only
 ##Note: WIFI COEX CONFIG Disabled by default, if required add the
   ##      config (E4, 05, 04, 00, 3C, 1E, 1E) and update the
   ##      Lentgh and number of parameter accordingly in the header part.
   ##      WIFI COEX feature supports only in user binary.
-#WIFI_COEX_UART_USER_CFG E437
-  ## UART based WiFi-CoEx Interface User Configuration. default value 0
-#FREQ_OF_UWB_REQ_WLAN_CHANNEL_INFO E439
-  ## Configure the frequency of UWB Requests to WLAN for getting WLAN Channel Information. Default value 3
-  ## if required add the
-  ##      config (E4, 39, 01, 03) and update the
-  ##      Length and number of parameter accordingly in the header part
 #GPIO_USAGE_CONFIG E4 08
   ## Customer need to set the DPD_WAKEUP_SOURCE as 02 (GPIO1) before applying the GPIO_USAGE_CONFIG command to
   ## enable time sync notification feature
@@ -131,6 +119,16 @@ NXP_UWB_DEV_FW_FILENAME="libsr100t_dev_fw.bin"
 UWB_FW_DOWNLOAD_LOG=0x00
 ###############################################################################
 
+###############################################################################
+#enable or disable delete ursk for ccc session
+DELETE_URSK_FOR_CCC_SESSION=0x00
+###############################################################################
+
+###############################################################################
+#enable or disable sts index overriding for ccc session
+OVERRIDE_STS_INDEX_FOR_CCC_SESSION=0x01
+###############################################################################
+
 ###############################################################################
 # set Crystal calibration settings
 # byte[0] No Of registers
diff --git a/halimpl/hal/phNxpUciHal.cc b/halimpl/hal/phNxpUciHal.cc
index 1ea1163..0990d25 100644
--- a/halimpl/hal/phNxpUciHal.cc
+++ b/halimpl/hal/phNxpUciHal.cc
@@ -57,6 +57,8 @@ static void phNxpUciHal_write_complete(void* pContext,
                                        phTmlUwb_TransactInfo_t* pInfo);
 extern int phNxpUciHal_fw_download();
 static void phNxpUciHal_getVersionInfo();
+static tHAL_UWB_STATUS phNxpUciHal_sendCoreConfig(const uint8_t *p_cmd,
+                                                  long buffer_size);
 
 /*******************************************************************************
  * RX packet handler
@@ -491,7 +493,8 @@ void phNxpUciHal_read_complete(void* pContext, phTmlUwb_TransactInfo_t* pInfo)
     return;
   }
 
-  NXPLOG_UCIHAL_D("read successful status = 0x%x", pInfo->wStatus);
+  NXPLOG_UCIHAL_V("read successful status = 0x%x , total len = 0x%x",
+                  pInfo->wStatus, pInfo->wLength);
 
   for (int32_t index = 0; index < pInfo->wLength; )
   {
@@ -514,7 +517,8 @@ void phNxpUciHal_read_complete(void* pContext, phTmlUwb_TransactInfo_t* pInfo)
 
     nxpucihal_ctrl.isSkipPacket = 0;
 
-    phNxpUciHal_rx_handler_check(pInfo->wLength, pInfo->pBuff);
+    phNxpUciHal_rx_handler_check(nxpucihal_ctrl.rx_data_len,
+                                 nxpucihal_ctrl.p_rx_data);
 
     // mapping device caps according to Fira 2.0
     if (mt == UCI_MT_RSP && gid == UCI_GID_CORE && oid == UCI_MSG_CORE_GET_CAPS_INFO) {
@@ -546,8 +550,17 @@ void phNxpUciHal_read_complete(void* pContext, phTmlUwb_TransactInfo_t* pInfo)
           // Upper layer should take care of it.
           nxpucihal_ctrl.ext_cb_data.status = UWBSTATUS_COMMAND_RETRANSMIT;
           nxpucihal_ctrl.isSkipPacket = 1;
-          bWakeupExtCmd = true;
+        } else if (status_code == UCI_STATUS_BUFFER_UNDERFLOW) {
+          if (nxpucihal_ctrl.hal_ext_enabled) {
+            nxpucihal_ctrl.ext_cb_data.status = UWBSTATUS_COMMAND_RETRANSMIT;
+            nxpucihal_ctrl.isSkipPacket = 1;
+          } else {
+            // uci to handle retransmission
+            nxpucihal_ctrl.p_rx_data[UCI_RESPONSE_STATUS_OFFSET] =
+                UCI_STATUS_COMMAND_RETRY;
+          }
         }
+        bWakeupExtCmd = true;
       }
     }
 
@@ -678,7 +691,7 @@ static void parseAntennaConfig(const char *configName)
   const uint16_t dataLength = retlen;
   const uint8_t *data = buffer.data();
 
-  uint8_t index = UCI_MSG_HDR_SIZE + 1; // Excluding the header and number of params
+  uint8_t index = 1; // Excluding number of params
   uint8_t tagId, subTagId;
   int length;
   while (index < dataLength) {
@@ -706,7 +719,10 @@ static void parseAntennaConfig(const char *configName)
  ******************************************************************************/
 tHAL_UWB_STATUS phNxpUciHal_applyVendorConfig()
 {
-  std::vector<const char*> vendorParamNames;
+  std::vector<const char *> vendorParamNames;
+  std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
+  long retlen = 0;
+  tHAL_UWB_STATUS status = UWBSTATUS_FAILED;
 
   // Base parameter names
   if (nxpucihal_ctrl.fw_boot_mode == USER_FW_BOOT_MODE) {
@@ -721,7 +737,18 @@ tHAL_UWB_STATUS phNxpUciHal_applyVendorConfig()
   } else if (nxpucihal_ctrl.device_type == DEVICE_TYPE_SR1xxS) {
     per_chip_param = NAME_UWB_CORE_EXT_DEVICE_SR1XX_S_CONFIG;
   }
-  vendorParamNames.push_back(per_chip_param);
+
+  if (NxpConfig_GetByteArray(per_chip_param, buffer.data(), buffer.size(),
+                             &retlen)) {
+    if (retlen > 0 && retlen < UCI_MAX_DATA_LEN) {
+      NXPLOG_UCIHAL_D("VendorConfig: apply %s", per_chip_param);
+      status = phNxpUciHal_sendCoreConfig(buffer.data(), retlen);
+      if (status != UWBSTATUS_SUCCESS) {
+        NXPLOG_UCIHAL_E("VendorConfig: failed to apply %s", per_chip_param);
+        return status;
+      }
+    }
+  }
 
   // Parse Antenna config from chip-parameter
   parseAntennaConfig(per_chip_param);
@@ -741,12 +768,10 @@ tHAL_UWB_STATUS phNxpUciHal_applyVendorConfig()
 
   // Execute
   for (const auto paramName : vendorParamNames) {
-    std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
-    long retlen = 0;
     if (NxpConfig_GetByteArray(paramName, buffer.data(), buffer.size(), &retlen)) {
       if (retlen > 0 && retlen < UCI_MAX_DATA_LEN) {
         NXPLOG_UCIHAL_D("VendorConfig: apply %s", paramName);
-        tHAL_UWB_STATUS status = phNxpUciHal_send_ext_cmd(retlen, buffer.data());
+        status = phNxpUciHal_send_ext_cmd(retlen, buffer.data());
         if (status != UWBSTATUS_SUCCESS) {
           NXPLOG_UCIHAL_E("VendorConfig: failed to apply %s", paramName);
           return status;
@@ -873,16 +898,12 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
 
   uwb_device_initialized = false;
 
-  // FW download and enter UCI operating mode
-  status = nxpucihal_ctrl.uwb_chip->chip_init();
-  if (status != UWBSTATUS_SUCCESS) {
-    return status;
-  }
-
   // Device Status Notification
   UciHalSemaphore devStatusNtfWait;
   uint8_t dev_status = UWB_DEVICE_ERROR;
-  auto dev_status_ntf_cb = [&dev_status, &devStatusNtfWait](size_t packet_len, const uint8_t *packet) mutable {
+  auto dev_status_ntf_cb = [&dev_status,
+                            &devStatusNtfWait](size_t packet_len,
+                                               const uint8_t *packet) mutable {
     if (packet_len >= 5) {
       dev_status = packet[UCI_RESPONSE_STATUS_OFFSET];
       devStatusNtfWait.post();
@@ -891,6 +912,12 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
   UciHalRxHandler devStatusNtfHandler(UCI_MT_NTF, UCI_GID_CORE, UCI_MSG_CORE_DEVICE_STATUS_NTF,
                                       true, dev_status_ntf_cb);
 
+  // FW download and enter UCI operating mode
+  status = nxpucihal_ctrl.uwb_chip->chip_init();
+  if (status != UWBSTATUS_SUCCESS) {
+    return status;
+  }
+
   // Initiate UCI packet read
   status = phTmlUwb_StartRead( Rx_data, UCI_MAX_DATA_LEN,
             (pphTmlUwb_TransactCompletionCb_t)&phNxpUciHal_read_complete, NULL);
@@ -900,7 +927,7 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
   }
 
   // Wait for the first Device Status Notification
-  devStatusNtfWait.wait();
+  devStatusNtfWait.wait_timeout_msec(3000);
   if(dev_status != UWB_DEVICE_INIT && dev_status != UWB_DEVICE_READY) {
     NXPLOG_UCIHAL_E("First Device Status NTF was not received or it's invalid state. 0x%x", dev_status);
     return UWBSTATUS_FAILED;
@@ -912,7 +939,7 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
     NXPLOG_UCIHAL_E("%s: Set Board Config Failed", __func__);
     return status;
   }
-  devStatusNtfWait.wait();
+  devStatusNtfWait.wait_timeout_msec(3000);
   if (dev_status != UWB_DEVICE_READY) {
     NXPLOG_UCIHAL_E("Cannot receive UWB_DEVICE_READY");
     return UWBSTATUS_FAILED;
@@ -925,7 +952,7 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
     NXPLOG_UCIHAL_E("%s: device reset Failed", __func__);
     return status;
   }
-  devStatusNtfWait.wait();
+  devStatusNtfWait.wait_timeout_msec(3000);
   if(dev_status != UWB_DEVICE_READY) {
     NXPLOG_UCIHAL_E("UWB_DEVICE_READY not received uwbc_device_state = %x", dev_status);
     return UWBSTATUS_FAILED;
@@ -991,49 +1018,12 @@ tHAL_UWB_STATUS phNxpUciHal_coreInitialization()
  ******************************************************************************/
 tHAL_UWB_STATUS phNxpUciHal_sessionInitialization(uint32_t sessionId) {
   NXPLOG_UCIHAL_D(" %s: Enter", __func__);
-  std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
-  uint8_t vendorConfig[NXP_MAX_CONFIG_STRING_LEN] = {0x2F, 0x00, 0x00};
   tHAL_UWB_STATUS status = UWBSTATUS_SUCCESS;
-  buffer.fill(0);
-  int max_config_length = NXP_MAX_CONFIG_STRING_LEN - UCI_MSG_HDR_SIZE
-                            - sizeof(sessionId);
-  long retlen = 0, cmdlen = 0;
-  bool appConfigStatus = false;
 
   if (nxpucihal_ctrl.halStatus != HAL_STATUS_OPEN) {
     NXPLOG_UCIHAL_E("HAL not initialized");
     return UWBSTATUS_FAILED;
   }
-  if(nxpucihal_ctrl.device_type == DEVICE_TYPE_SR1xxT) {
-    appConfigStatus = NxpConfig_GetByteArray(NAME_NXP_UWB_EXT_APP_SR1XX_T_CONFIG,
-                                   buffer.data(), buffer.size(),
-                                   &retlen);
-  } else if (nxpucihal_ctrl.device_type == DEVICE_TYPE_SR1xxS) {
-    appConfigStatus = NxpConfig_GetByteArray(NAME_NXP_UWB_EXT_APP_SR1XX_S_CONFIG,
-                                   buffer.data(), buffer.size(),
-                                   &retlen);
-  } else {
-    appConfigStatus = NxpConfig_GetByteArray(NAME_NXP_UWB_EXT_APP_DEFAULT_CONFIG,
-                                   buffer.data(), buffer.size(),
-                                   &retlen);
-  }
-
-  if (appConfigStatus) {
-    if ((retlen > 0) && (retlen <= max_config_length)) {
-      vendorConfig[3] = sizeof(sessionId) + retlen;
-      memcpy(vendorConfig + 4, &sessionId, sizeof(sessionId));
-      memcpy(vendorConfig + 8, buffer.data(), retlen);
-      cmdlen = UCI_MSG_HDR_SIZE + sizeof(sessionId) + retlen;
-      status = phNxpUciHal_send_ext_cmd(cmdlen, vendorConfig);
-      if (status != UWBSTATUS_SUCCESS) {
-        NXPLOG_UCIHAL_D(" %s: Apply vendor App Config Failed", __func__);
-        return UWBSTATUS_SUCCESS;
-      }
-    } else {
-      NXPLOG_UCIHAL_D(" %s: Invalid retlen", __func__);
-      return UWBSTATUS_SUCCESS;
-    }
-  }
   return status;
 }
 
@@ -1089,6 +1079,43 @@ void phNxpUciHal_getVersionInfo() {
   }
 }
 
+/******************************************************************************
+ * Function         phNxpUciHal_sendCoreConfig
+ *
+ * Description      This function send set core config command in chunks when
+ *                  config size greater than 255 bytes.
+ *
+ * Returns          status
+ *
+ ******************************************************************************/
+tHAL_UWB_STATUS phNxpUciHal_sendCoreConfig(const uint8_t *p_cmd,
+                                           long buffer_size) {
+  std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> payload_data;
+  tHAL_UWB_STATUS status = UWBSTATUS_FAILED;
+  uint16_t i = 0;
+
+  while (buffer_size > 0) {
+    uint16_t chunk_size = (buffer_size <= UCI_MAX_CONFIG_PAYLOAD_LEN)
+                              ? buffer_size
+                              : UCI_MAX_CONFIG_PAYLOAD_LEN;
+
+    payload_data[0] = (buffer_size <= UCI_MAX_CONFIG_PAYLOAD_LEN) ? 0x20 : 0x30;
+    payload_data[1] = 0x04;
+    payload_data[2] = 0x00;
+    payload_data[3] = chunk_size;
+
+    std::memcpy(&payload_data[UCI_PKT_HDR_LEN], &p_cmd[i], chunk_size);
+
+    status = phNxpUciHal_send_ext_cmd(chunk_size + UCI_PKT_HDR_LEN,
+                                      payload_data.data());
+
+    i += chunk_size;
+    buffer_size -= chunk_size;
+  }
+
+  return status;
+}
+
 /*******************************************************************************
  * Function      phNxpUciHal_send_dev_error_status_ntf
  *
diff --git a/halimpl/hal/phNxpUciHal.h b/halimpl/hal/phNxpUciHal.h
index b3172cd..1b12546 100644
--- a/halimpl/hal/phNxpUciHal.h
+++ b/halimpl/hal/phNxpUciHal.h
@@ -30,6 +30,7 @@
 #define MAX_RETRY_COUNT 0x05
 #define UCI_MAX_DATA_LEN 4200 // maximum data packet size
 #define UCI_MAX_PAYLOAD_LEN 4200
+#define UCI_MAX_CONFIG_PAYLOAD_LEN 0xFF
 // #define UCI_RESPONSE_STATUS_OFFSET 0x04
 #define UCI_PKT_HDR_LEN 0x04
 #define UCI_PKT_PAYLOAD_STATUS_LEN 0x01
@@ -99,7 +100,7 @@
 const char debug_log_path[] = "/data/vendor/uwb/";
 
 /* UCI Data */
-#define NXP_MAX_CONFIG_STRING_LEN 260
+#define NXP_MAX_CONFIG_STRING_LEN 2052
 typedef struct uci_data {
   uint16_t len;
   uint8_t p_data[UCI_MAX_DATA_LEN];
diff --git a/halimpl/hal/phNxpUciHal_ext.cc b/halimpl/hal/phNxpUciHal_ext.cc
index e910e44..f5cc90d 100644
--- a/halimpl/hal/phNxpUciHal_ext.cc
+++ b/halimpl/hal/phNxpUciHal_ext.cc
@@ -127,8 +127,17 @@ tHAL_UWB_STATUS phNxpUciHal_process_ext_cmd_rsp(uint16_t cmd_len,
       nr_retries++;
       break;
     default:
-      status = nxpucihal_ctrl.ext_cb_data.status;
-      exit_loop = true;
+      // Check CMD/RSP gid/oid matching
+      uint8_t rsp_gid = nxpucihal_ctrl.p_rx_data[0] & UCI_GID_MASK;
+      uint8_t rsp_oid = nxpucihal_ctrl.p_rx_data[1] & UCI_OID_MASK;
+      if (gid != rsp_gid || oid != rsp_oid) {
+        NXPLOG_UCIHAL_E("Received incorrect response of GID:%x OID:%x, expected GID:%x OID:%x",
+            rsp_gid, rsp_oid, gid, oid);
+        nr_retries++;
+      } else {
+        status = nxpucihal_ctrl.ext_cb_data.status;
+        exit_loop = true;
+      }
       break;
     }
 
@@ -508,9 +517,6 @@ static bool CountryCodeCapsApplyTxPower(void)
   return true;
 }
 
-// Channels
-const static uint8_t cal_channels[] = {5, 6, 8, 9};
-
 static void extcal_do_xtal(void)
 {
   int ret;
@@ -548,18 +554,16 @@ static void extcal_do_ant_delay(void)
   std::bitset<8> rx_antenna_mask(nxpucihal_ctrl.cal_rx_antenna_mask);
   const uint8_t n_rx_antennas = rx_antenna_mask.size();
 
+  const uint8_t *cal_channels = NULL;
+  uint8_t nr_cal_channels = 0;
+  nxpucihal_ctrl.uwb_chip->get_supported_channels(&cal_channels, &nr_cal_channels);
+
   // RX_ANT_DELAY_CALIB
   // parameter: cal.ant<N>.ch<N>.ant_delay=X
   // N(1) + N * {AntennaID(1), Rxdelay(Q14.2)}
   if (n_rx_antennas) {
-
-    const int16_t extra_delay = nxpucihal_ctrl.uwb_chip->extra_group_delay();
-
-    if (extra_delay) {
-      NXPLOG_UCIHAL_D("RX_ANT_DELAY_CALIB: Extra compensation '%d'", extra_delay);
-    }
-
-    for (auto ch : cal_channels) {
+    for (int i = 0; i < nr_cal_channels; i++) {
+      uint8_t ch = cal_channels[i];
       std::vector<uint8_t> entries;
       uint8_t n_entries = 0;
 
@@ -568,15 +572,35 @@ static void extcal_do_ant_delay(void)
           continue;
 
         const uint8_t ant_id = i + 1;
-        uint16_t delay_value;
-        char key[32];
-        std::snprintf(key, sizeof(key), "cal.ant%u.ch%u.ant_delay", ant_id, ch);
 
-        if (!NxpConfig_GetNum(key, &delay_value, 2))
+        uint16_t delay_value, version_value;
+        bool value_provided = false;
+
+        const std::string key_ant_delay = std::format("cal.ant{}.ch{}.ant_delay", ant_id, ch);
+        const std::string key_force_version = key_ant_delay + std::format(".force_version", ant_id, ch);
+
+        // 1) try cal.ant{N}.ch{N}.ant_delay.force_value.{N}
+        if (NxpConfig_GetNum(key_force_version.c_str(), &version_value, 2)) {
+          const std::string key_force_value = key_ant_delay + std::format(".force_value.{}", ant_id, ch, version_value);
+          if (NxpConfig_GetNum(key_force_value.c_str(), &delay_value, 2)) {
+            value_provided = true;
+            NXPLOG_UCIHAL_D("Apply RX_ANT_DELAY_CALIB %s = %u", key_force_value.c_str(), delay_value);
+          }
+        }
+
+        // 2) try cal.ant{N}.ch{N}.ant_delay
+        if (!value_provided) {
+          if (NxpConfig_GetNum(key_ant_delay.c_str(), &delay_value, 2)) {
+            value_provided = true;
+            NXPLOG_UCIHAL_D("Apply RX_ANT_DELAY_CALIB: %s = %u", key_ant_delay.c_str(), delay_value);
+          }
+        }
+
+        if (!value_provided) {
+          NXPLOG_UCIHAL_V("%s was not provided from configuration files.", key_ant_delay.c_str());
           continue;
+        }
 
-        delay_value = delay_value + extra_delay;
-        NXPLOG_UCIHAL_D("Apply RX_ANT_DELAY_CALIB: %s = %u", key, delay_value);
         entries.push_back(ant_id);
         // Little Endian
         entries.push_back(delay_value & 0xff);
@@ -601,10 +625,15 @@ static void extcal_do_tx_power(void)
   std::bitset<8> tx_antenna_mask(nxpucihal_ctrl.cal_tx_antenna_mask);
   const uint8_t n_tx_antennas = tx_antenna_mask.size();
 
+  const uint8_t *cal_channels = NULL;
+  uint8_t nr_cal_channels = 0;
+  nxpucihal_ctrl.uwb_chip->get_supported_channels(&cal_channels, &nr_cal_channels);
+
   // TX_POWER
   // parameter: cal.ant<N>.ch<N>.tx_power={...}
   if (n_tx_antennas) {
-    for (auto ch : cal_channels) {
+    for (int i = 0; i < nr_cal_channels; i++) {
+      uint8_t ch = cal_channels[i];
       std::vector<uint8_t> entries;
       uint8_t n_entries = 0;
 
diff --git a/halimpl/hal/phNxpUwbCalib.cc b/halimpl/hal/phNxpUwbCalib.cc
index fdab160..2b1bdf5 100644
--- a/halimpl/hal/phNxpUwbCalib.cc
+++ b/halimpl/hal/phNxpUwbCalib.cc
@@ -15,20 +15,9 @@
  * limitations under the License.
  */
 
-
+#include "phNxpUciHal_ext.h"
 #include "phNxpUwbCalib.h"
 #include "phUwbStatus.h"
-#include "phNxpUciHal_ext.h"
-
-/* SR1XX is same as SR2XX */
-static tHAL_UWB_STATUS sr1xx_apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len);
-static tHAL_UWB_STATUS sr1xx_set_conf(const std::vector<uint8_t> &tlv);
-static tHAL_UWB_STATUS sr1xx_set_calibration(uint8_t channel, const std::vector<uint8_t> &tlv);
-
-
-tHAL_UWB_STATUS phNxpUwbCalib_apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len) {
-  return sr1xx_apply_calibration(id, ch, data, data_len);
-}
 
 //
 // SR1XX Device Calibrations:
@@ -62,7 +51,7 @@ static tHAL_UWB_STATUS sr1xx_set_conf(const std::vector<uint8_t> &tlv)
   return phNxpUciHal_send_ext_cmd(packet.size(), packet.data());
 }
 
-static tHAL_UWB_STATUS sr1xx_apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len)
+tHAL_UWB_STATUS sr1xx_apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len)
 {
   // Device Calibration
   const uint8_t UCI_PARAM_ID_RF_CLK_ACCURACY_CALIB    = 0x01;
@@ -94,6 +83,11 @@ static tHAL_UWB_STATUS sr1xx_apply_calibration(extcal_param_id_t id, const uint8
     }
   case EXTCAL_PARAM_RX_ANT_DELAY:
     {
+      // [0] = number of entries
+      // {
+      //   [0] = rx antenna id
+      //   [1,2] = rx delay
+      // }
       if (!ch || data_len < 1 || !data[0] || (data[0] * 3) != (data_len - 1)) {
         return UWBSTATUS_FAILED;
       }
diff --git a/halimpl/hal/phNxpUwbCalib.h b/halimpl/hal/phNxpUwbCalib.h
index a88a2b4..dc18c16 100644
--- a/halimpl/hal/phNxpUwbCalib.h
+++ b/halimpl/hal/phNxpUwbCalib.h
@@ -18,4 +18,4 @@
 
 #include "NxpUwbChip.h"
 
-tHAL_UWB_STATUS phNxpUwbCalib_apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len);
+tHAL_UWB_STATUS sr1xx_apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len);
diff --git a/halimpl/hal/sessionTrack.cc b/halimpl/hal/sessionTrack.cc
index 23bd6f6..be63067 100644
--- a/halimpl/hal/sessionTrack.cc
+++ b/halimpl/hal/sessionTrack.cc
@@ -79,13 +79,17 @@ private:
     SessionTrackWorkType type_;
     std::shared_ptr<SessionInfo> session_info_;
     bool sync_;
+    bool cond_flag;
     std::condition_variable cond_;
 
-    SessionTrackMsg(SessionTrackWorkType type, bool sync) : type_(type), sync_(sync) { }
+    SessionTrackMsg(SessionTrackWorkType type, bool sync)
+        : type_(type), sync_(sync), cond_flag(false) {}
 
     // Per-session work item
-    SessionTrackMsg(SessionTrackWorkType type, std::shared_ptr<SessionInfo> session_info, bool sync) :
-      type_(type), session_info_(session_info), sync_(sync) { }
+    SessionTrackMsg(SessionTrackWorkType type,
+                    std::shared_ptr<SessionInfo> session_info, bool sync)
+        : type_(type), session_info_(session_info), sync_(sync),
+          cond_flag(false) {}
   };
   static constexpr unsigned long kAutoSuspendTimeoutDefaultMs_ = (30 * 1000);
   static constexpr long kQueueTimeoutMs = 500;
@@ -649,8 +653,10 @@ private:
         NXPLOG_UCIHAL_E("SessionTrack: worker thread received a bad message!");
         break;
       }
-      if (msg->sync_)
+      if (msg->sync_) {
+        msg->cond_flag = true;
         msg->cond_.notify_one();
+      }
     }
     if (idle_timer_started_) {
       PowerIdleTimerStop();
@@ -664,7 +670,8 @@ private:
 
     if (msg->sync_) {
       std::unique_lock<std::mutex> lock(sync_mutex_);
-      if (msg->cond_.wait_for(lock, std::chrono::milliseconds(kQueueTimeoutMs)) == std::cv_status::timeout) {
+      if (!msg->cond_.wait_for(lock, std::chrono::milliseconds(kQueueTimeoutMs),
+                               [msg] { return msg->cond_flag; })) {
         NXPLOG_UCIHAL_E("SessionTrack: timeout to process %d", static_cast<int>(msg->type_));
       }
     }
diff --git a/halimpl/hal/sr1xx/NxpUwbChipSr1xx.cc b/halimpl/hal/sr1xx/NxpUwbChipSr1xx.cc
index 679e5a4..2299036 100644
--- a/halimpl/hal/sr1xx/NxpUwbChipSr1xx.cc
+++ b/halimpl/hal/sr1xx/NxpUwbChipSr1xx.cc
@@ -1,3 +1,5 @@
+#include <vector>
+
 #include "NxpUwbChip.h"
 #include "phNxpConfig.h"
 #include "phNxpUciHal.h"
@@ -261,6 +263,64 @@ exit_check_binding_status:
   return status;
 }
 
+// Group Delay Compensation, if any
+// SR1XX needs this, because it has
+// different handling during calibration with D48/D49 vs D50
+static int16_t sr1xx_extra_group_delay(const uint8_t ch)
+{
+  int16_t required_compensation = 0;
+  char calibrated_with_fw[15] = {0};
+
+  /* Calibrated with D4X and we are on D5X or later */
+  bool is_calibrated_with_d4x = false;
+
+  int has_calibrated_with_fw_config = NxpConfig_GetStr(
+    "cal.fw_version", calibrated_with_fw, sizeof(calibrated_with_fw) - 1);
+
+  if ( has_calibrated_with_fw_config ) {
+    // Conf file has entry of `cal.fw_version`
+    if ( ( 0 == memcmp("48.", calibrated_with_fw, 3)) ||
+         ( 0 == memcmp("49.", calibrated_with_fw, 3))) {
+      is_calibrated_with_d4x = true;
+    }
+  }
+  else
+  {
+    NXPLOG_UCIHAL_W("Could not get cal.fw_version. Assuming D48 used for calibration.");
+    is_calibrated_with_d4x = true;
+  }
+
+  if (is_calibrated_with_d4x) {
+    if (nxpucihal_ctrl.fw_version.major_version >= 0x50) {
+      required_compensation += (7*4); /*< 7 CM offset required... */
+    }
+    else
+    {
+      /* Running with D49. For testing purpose. +7cm Not needed */
+    }
+
+    // Calibrated with D49
+    // Required extra negative offset, Channel specific, but antenna agnostic.
+    unsigned short cal_chx_extra_d49_offset_n = 0;
+    char key[32];
+    std::snprintf(key, sizeof(key), "cal.ch%u.extra_d49_offset_n", ch);
+    int has_extra_d49_offset_n = NxpConfig_GetNum(
+      key, &cal_chx_extra_d49_offset_n, sizeof(cal_chx_extra_d49_offset_n));
+
+    if (has_extra_d49_offset_n) { /*< Extra correction from conf file ... */
+      required_compensation -= cal_chx_extra_d49_offset_n;
+    }
+  }
+  else
+  {
+    // calibrated with D50 or later.
+    // No compensation.
+  }
+
+  /* Its Q14.2 format, Actual CM impact is //4  */
+  return required_compensation;
+}
+
 class NxpUwbChipSr1xx final : public NxpUwbChip {
 public:
   NxpUwbChipSr1xx();
@@ -271,7 +331,7 @@ public:
   device_type_t get_device_type(const uint8_t *param, size_t param_len);
   tHAL_UWB_STATUS read_otp(extcal_param_id_t id, uint8_t *data, size_t data_len, size_t *retlen);
   tHAL_UWB_STATUS apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len);
-  int16_t extra_group_delay(void);
+  tHAL_UWB_STATUS get_supported_channels(const uint8_t **cal_channels, uint8_t *nr);
 
 private:
   tHAL_UWB_STATUS check_binding();
@@ -475,57 +535,55 @@ tHAL_UWB_STATUS NxpUwbChipSr1xx::read_otp(extcal_param_id_t id, uint8_t *data, s
   return sr1xx_read_otp(id, data, data_len, retlen);
 }
 
-tHAL_UWB_STATUS NxpUwbChipSr1xx::apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len)
-{
-  return phNxpUwbCalib_apply_calibration(id, ch, data, data_len);
-}
+tHAL_UWB_STATUS sr1xx_apply_calibration_ant_delay(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len) {
 
-int16_t NxpUwbChipSr1xx::extra_group_delay(void) {
-  bool need_7cm_offset = FALSE;
-  // + Compensation for D48/D49 calibration
-  // If calibration was done with D48 / D49
-  char calibrated_with_fw[15] = {0};
+  std::vector<uint8_t> patched_data;
+  std::copy(&data[0], &data[data_len], std::back_inserter(patched_data));
 
-  int has_calibrated_with_fw_config = NxpConfig_GetStr(
-    "cal.fw_version", calibrated_with_fw, sizeof(calibrated_with_fw) - 1);
-
-  if ( has_calibrated_with_fw_config ) {
-    // Conf file has entry of `cal.fw_version`
-    if (
-      ( 0 == memcmp("48.", calibrated_with_fw, 3)) ||
-      ( 0 == memcmp("49.", calibrated_with_fw, 3))) {
-      // Calibrated with D48 / D49.
-      if (nxpucihal_ctrl.fw_version.major_version == 0xFF) {
-        // Current FW seems to be Test FW
-        NXPLOG_UCIHAL_W("For Test FW, D49 -> D50+ 7cm Compensation is applied");
-        need_7cm_offset = TRUE;
-      }
-      else if (nxpucihal_ctrl.fw_version.major_version >= 0x50) {
-        // D50 and later fix is needed.
-        need_7cm_offset = TRUE;
-      }
+  const int16_t delay_compensation = sr1xx_extra_group_delay(ch);
+  const uint8_t nr_entries = patched_data[0];
+  for (uint8_t i = 0; i < nr_entries; i++) {
+    // Android ABI & UCI both are Little endian
+    int32_t rx_delay32 = patched_data[2 + i * 3] | (patched_data[3 + i * 3] << 8);
+    if ( 0 != delay_compensation ) {
+      NXPLOG_UCIHAL_D("RX_ANT_DELAY_CALIB: Extra compensation '%d'", delay_compensation);
+      rx_delay32 += delay_compensation;
     }
-    else
-    {
-      // Not calibrated with D48/D49
+
+    // clamp to 0 ~ 0xffff
+    if (rx_delay32 >= 0xFFFF) {
+      rx_delay32 = 0xFFFF;
+    } else if (rx_delay32 < 0) {
+      rx_delay32 = 0;
     }
+
+    const uint16_t rx_delay = rx_delay32;
+    patched_data[2 + i * 3] = rx_delay & 0xff;
+    patched_data[3 + i * 3] = rx_delay >> 8;
   }
-  else
-  {
-    // Missing Entry cal.fw_version
-    NXPLOG_UCIHAL_W("Could not get cal.fw_version. Assuming D48 used for calibration.");
-    need_7cm_offset = TRUE;
-  }
-  if (need_7cm_offset) {
-    /* Its Q14.2 format, hence << 2 */
-    return (7 << 2);
+  return sr1xx_apply_calibration(id, ch, patched_data.data(), data_len);
+}
+
+tHAL_UWB_STATUS NxpUwbChipSr1xx::apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len)
+{
+  if (id == EXTCAL_PARAM_RX_ANT_DELAY) {
+    return sr1xx_apply_calibration_ant_delay(id, ch, data, data_len);
   }
   else
   {
-    return 0;
+    return sr1xx_apply_calibration(id, ch, data, data_len);
   }
 }
 
+tHAL_UWB_STATUS
+NxpUwbChipSr1xx::get_supported_channels(const uint8_t **cal_channels, uint8_t *nr)
+{
+  static const uint8_t sr100_cal_channels[] = {5, 6, 8, 9};
+  *cal_channels = sr100_cal_channels;
+  *nr = std::size(sr100_cal_channels);
+  return UWBSTATUS_SUCCESS;
+}
+
 std::unique_ptr<NxpUwbChip> GetUwbChip()
 {
   return std::make_unique<NxpUwbChipSr1xx>();
diff --git a/halimpl/hal/sr200/NxpUwbChipSr200.cc b/halimpl/hal/sr200/NxpUwbChipSr200.cc
index 15afc9a..2b28127 100644
--- a/halimpl/hal/sr200/NxpUwbChipSr200.cc
+++ b/halimpl/hal/sr200/NxpUwbChipSr200.cc
@@ -24,11 +24,11 @@ public:
   device_type_t get_device_type(const uint8_t *param, size_t param_len);
   tHAL_UWB_STATUS read_otp(extcal_param_id_t id, uint8_t *data, size_t data_len, size_t *retlen);
   tHAL_UWB_STATUS apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len);
+  tHAL_UWB_STATUS get_supported_channels(const uint8_t **cal_channels, uint8_t *nr);
 private:
   void on_binding_status_ntf(size_t packet_len, const uint8_t* packet);
 
   tHAL_UWB_STATUS check_binding_done();
-  int16_t extra_group_delay(void);
 
   UciHalRxHandler bindingStatusNtfHandler_;
   UciHalSemaphore bindingStatusNtfWait_;
@@ -152,12 +152,28 @@ tHAL_UWB_STATUS
 NxpUwbChipSr200::apply_calibration(extcal_param_id_t id, const uint8_t ch,
                                    const uint8_t *data, size_t data_len)
 {
-  return phNxpUwbCalib_apply_calibration(id, ch, data, data_len);
+  switch (id) {
+  case EXTCAL_PARAM_TX_POWER:
+  case EXTCAL_PARAM_TX_BASE_BAND_CONTROL:
+  case EXTCAL_PARAM_DDFS_TONE_CONFIG:
+  case EXTCAL_PARAM_TX_PULSE_SHAPE:
+    return sr1xx_apply_calibration(id, ch, data, data_len);
+  case EXTCAL_PARAM_CLK_ACCURACY:
+  case EXTCAL_PARAM_RX_ANT_DELAY:
+    /* break through */
+  default:
+    NXPLOG_UCIHAL_E("Unsupported parameter: 0x%x", id);
+    return UWBSTATUS_FAILED;
+  }
 }
 
-int16_t NxpUwbChipSr200::extra_group_delay(void) {
-  // Only for SR100. Not for SR2XX
-  return 0;
+tHAL_UWB_STATUS
+NxpUwbChipSr200::get_supported_channels(const uint8_t **cal_channels, uint8_t *nr)
+{
+  static const uint8_t sr200_cal_channels[] = {5, 9, 10};
+  *cal_channels = sr200_cal_channels;
+  *nr = std::size(sr200_cal_channels);
+  return UWBSTATUS_SUCCESS;
 }
 
 std::unique_ptr<NxpUwbChip> GetUwbChip()
diff --git a/halimpl/inc/NxpUwbChip.h b/halimpl/inc/NxpUwbChip.h
index 52979a5..f8cebe9 100644
--- a/halimpl/inc/NxpUwbChip.h
+++ b/halimpl/inc/NxpUwbChip.h
@@ -72,10 +72,8 @@ public:
                                            const uint8_t *data,
                                            size_t data_len) = 0;
 
-  // Group Delay Compensation, if any
-  // SR1XX needs this, because it has
-  // different handling during calibration with D48/D49 vs D50
-  virtual int16_t extra_group_delay() = 0;
+  // Get supported channels
+  virtual tHAL_UWB_STATUS get_supported_channels(const uint8_t **cal_channels, uint8_t *nr) = 0;
 };
 
 std::unique_ptr<NxpUwbChip> GetUwbChip();
diff --git a/halimpl/tml/phTmlUwb.cc b/halimpl/tml/phTmlUwb.cc
index eff754e..7025e2a 100644
--- a/halimpl/tml/phTmlUwb.cc
+++ b/halimpl/tml/phTmlUwb.cc
@@ -276,6 +276,10 @@ static void* phTmlUwb_TmlWriterThread(void* pParam)
       break;
     }
 
+    if (gpphTmlUwb_Context->tWriteInfo.bThreadShouldStop) {
+      break;
+    }
+
     tHAL_UWB_STATUS wStatus = UWBSTATUS_SUCCESS;
 
     if (!gpphTmlUwb_Context->pDevHandle) {
diff --git a/halimpl/utils/phNxpConfig.cc b/halimpl/utils/phNxpConfig.cc
index 61b2f6e..b929a03 100644
--- a/halimpl/utils/phNxpConfig.cc
+++ b/halimpl/utils/phNxpConfig.cc
@@ -19,13 +19,13 @@
 //#define LOG_NDEBUG 0
 #define LOG_TAG "NxpUwbConf"
 
+#include <limits.h>
 #include <sys/stat.h>
 
 #include <iomanip>
+#include <list>
 #include <memory>
 #include <sstream>
-#include <limits.h>
-#include <stdio.h>
 #include <sstream>
 #include <string>
 #include <unordered_map>
@@ -49,10 +49,18 @@ static const char default_uci_config_path[] = "/vendor/etc/";
 
 static const char country_code_specifier[] = "<country>";
 static const char sku_specifier[] = "<sku>";
+static const char extid_specifier[] = "<extid>";
+static const char revision_specifier[] = "<revision>";
+
+static const char extid_config_name[] = "cal.extid";
+static const char extid_default_value[] = "defaultextid";
 
 static const char prop_name_calsku[] = "persist.vendor.uwb.cal.sku";
 static const char prop_default_calsku[] = "defaultsku";
 
+static const char prop_name_revision[] = "persist.vendor.uwb.cal.revision";
+static const char prop_default_revision[] = "defaultrevision";
+
 using namespace::std;
 
 class uwbParam
@@ -99,8 +107,8 @@ public:
     virtual ~CUwbNxpConfig();
     CUwbNxpConfig& operator=(CUwbNxpConfig&& config);
 
+    bool open(const char *filepath);
     bool isValid() const { return mValidFile; }
-    bool isCountrySpecific() const { return mCountrySpecific; }
     void reset() {
         m_map.clear();
         mValidFile = false;
@@ -108,6 +116,9 @@ public:
 
     const uwbParam*    find(const char* p_name) const;
     void    setCountry(const string& strCountry);
+    const char* getFilePath() const {
+        return mFilePath.c_str();
+    }
 
     void    dump() const;
 
@@ -120,8 +131,6 @@ private:
     unordered_map<string, uwbParam> m_map;
     bool    mValidFile;
     string  mFilePath;
-    string  mCurrentFile;
-    bool    mCountrySpecific;
 };
 
 /*******************************************************************************
@@ -223,7 +232,7 @@ bool CUwbNxpConfig::readConfig()
     vector<string> arrStr;
     int     base = 0;
     int     c;
-    const char *name = mCurrentFile.c_str();
+    const char *name = mFilePath.c_str();
     unsigned long state = BEGIN_LINE;
 
     mValidFile = false;
@@ -232,7 +241,7 @@ bool CUwbNxpConfig::readConfig()
     /* open config file, read it into a buffer */
     if ((fd = fopen(name, "r")) == NULL)
     {
-        ALOGD("%s Cannot open config file %s\n", __func__, name);
+        ALOGV("Extra calibration file %s failed to open.", name);
         return false;
     }
     ALOGV("%s Opened config %s\n", __func__, name);
@@ -372,6 +381,7 @@ bool CUwbNxpConfig::readConfig()
 
     if (m_map.size() > 0) {
         mValidFile = true;
+        ALOGI("Extra calibration file %s opened.", name);
     }
 
     return mValidFile;
@@ -387,8 +397,7 @@ bool CUwbNxpConfig::readConfig()
 **
 *******************************************************************************/
 CUwbNxpConfig::CUwbNxpConfig() :
-    mValidFile(false),
-    mCountrySpecific(false)
+    mValidFile(false)
 {
 }
 
@@ -405,26 +414,9 @@ CUwbNxpConfig::~CUwbNxpConfig()
 {
 }
 
-CUwbNxpConfig::CUwbNxpConfig(const char *filepath) :
-    mValidFile(false),
-    mFilePath(filepath),
-    mCountrySpecific(false)
+CUwbNxpConfig::CUwbNxpConfig(const char *filepath)
 {
-    auto pos = mFilePath.find(sku_specifier);
-    if (pos != string::npos) {
-        char prop_str[PROPERTY_VALUE_MAX];
-        property_get(prop_name_calsku, prop_str,prop_default_calsku);
-        mFilePath.replace(pos, strlen(sku_specifier), prop_str);
-    }
-
-    // country specifier will be evaluated later in setCountry() path
-    pos = mFilePath.find(country_code_specifier);
-    if (pos == string::npos) {
-        mCurrentFile = mFilePath;
-        readConfig();
-    } else {
-        mCountrySpecific = true;
-    }
+    open(filepath);
 }
 
 CUwbNxpConfig::CUwbNxpConfig(CUwbNxpConfig&& config)
@@ -432,8 +424,6 @@ CUwbNxpConfig::CUwbNxpConfig(CUwbNxpConfig&& config)
     m_map = move(config.m_map);
     mValidFile = config.mValidFile;
     mFilePath = move(config.mFilePath);
-    mCurrentFile = move(config.mCurrentFile);
-    mCountrySpecific = config.mCountrySpecific;
 
     config.mValidFile = false;
 }
@@ -443,26 +433,17 @@ CUwbNxpConfig& CUwbNxpConfig::operator=(CUwbNxpConfig&& config)
     m_map = move(config.m_map);
     mValidFile = config.mValidFile;
     mFilePath = move(config.mFilePath);
-    mCurrentFile = move(config.mCurrentFile);
-    mCountrySpecific = config.mCountrySpecific;
 
     config.mValidFile = false;
     return *this;
 }
 
-void CUwbNxpConfig::setCountry(const string& strCountry)
+bool CUwbNxpConfig::open(const char *filepath)
 {
-    if (!isCountrySpecific())
-        return;
-
-    mCurrentFile = mFilePath;
-    auto pos = mCurrentFile.find(country_code_specifier);
-    if (pos == string::npos) {
-        return;
-    }
+    mValidFile = false;
+    mFilePath = filepath;
 
-    mCurrentFile.replace(pos, strlen(country_code_specifier), strCountry);
-    readConfig();
+    return readConfig();
 }
 
 /*******************************************************************************
@@ -495,7 +476,7 @@ const uwbParam* CUwbNxpConfig::find(const char* p_name) const
 *******************************************************************************/
 void CUwbNxpConfig::dump() const
 {
-    ALOGV("Dump configuration file %s : %s, %zu entries", mCurrentFile.c_str(),
+    ALOGV("Dump configuration file %s : %s, %zu entries", mFilePath.c_str(),
         mValidFile ? "valid" : "invalid", m_map.size());
 
     for (auto &it : m_map) {
@@ -671,7 +652,7 @@ private:
     CUwbNxpConfig mUciConfig;
 
     // EXTRA_CONF_PATH[N]
-    vector<CUwbNxpConfig> mExtraConfig;
+    std::vector<std::pair<string, CUwbNxpConfig>> mExtraConfig;
 
     // [COUNTRY_CODE_CAP_FILE_LOCATION]/country_code_config_name
     CUwbNxpConfig mCapsConfig;
@@ -679,14 +660,30 @@ private:
     // Region Code mapping
     RegionCodeMap mRegionMap;
 
-    // Current region code
-    string mCurRegionCode;
+    // current set of specifiers for EXTRA_CONF_PATH[]
+    struct ExtraConfPathSpecifiers {
+        string mCurSku;
+        string mCurExtid;
+        string mCurRegionCode;
+        string mCurRevision;
+        void reset() {
+            mCurSku.clear();
+            mCurExtid.clear();
+            mCurRegionCode.clear();
+            mCurRevision.clear();
+        }
+    };
+    ExtraConfPathSpecifiers mExtraConfSpecifiers;
+
+    // Re-evaluate filepaths of mExtraConfig with mExtraConfSpecifiers, and re-load them.
+    // returns true if any of entries were updated.
+    bool evaluateExtraConfPaths();
 
     void dump() {
         mMainConfig.dump();
         mUciConfig.dump();
 
-        for (const auto &config : mExtraConfig)
+        for (const auto &[filename, config] : mExtraConfig)
             config.dump();
 
         mCapsConfig.dump();
@@ -698,6 +695,42 @@ CascadeConfig::CascadeConfig()
 {
 }
 
+bool CascadeConfig::evaluateExtraConfPaths()
+{
+    bool updated = false;
+
+    for (auto& [filename, config] : mExtraConfig) {
+        std::string new_filename(filename);
+
+        auto posSku = filename.find(sku_specifier);
+        if (posSku != std::string::npos && !mExtraConfSpecifiers.mCurSku.empty()) {
+            new_filename.replace(posSku, strlen(sku_specifier), mExtraConfSpecifiers.mCurSku);
+        }
+
+        auto posExtid = filename.find(extid_specifier);
+        if (posExtid != std::string::npos && !mExtraConfSpecifiers.mCurExtid.empty()) {
+            new_filename.replace(posExtid, strlen(extid_specifier), mExtraConfSpecifiers.mCurExtid);
+        }
+
+        auto posCountry = filename.find(country_code_specifier);
+        if (posCountry != std::string::npos && !mExtraConfSpecifiers.mCurRegionCode.empty()) {
+            new_filename.replace(posCountry, strlen(country_code_specifier), mExtraConfSpecifiers.mCurRegionCode);
+        }
+
+        auto posRevision = filename.find(revision_specifier);
+        if (posRevision != std::string::npos && !mExtraConfSpecifiers.mCurRevision.empty()) {
+            new_filename.replace(posRevision, strlen(revision_specifier), mExtraConfSpecifiers.mCurRevision);
+        }
+
+        // re-open the file if filepath got re-evaluated.
+        if (new_filename != config.getFilePath()) {
+            config.open(new_filename.c_str());
+            updated = true;
+        }
+    }
+    return updated;
+}
+
 void CascadeConfig::init(const char *main_config)
 {
     ALOGV("CascadeConfig initialize with %s", main_config);
@@ -724,6 +757,11 @@ void CascadeConfig::init(const char *main_config)
         }
     }
 
+    char sku_value[PROPERTY_VALUE_MAX];
+    char revision_value[PROPERTY_VALUE_MAX];
+    property_get(prop_name_calsku, sku_value, prop_default_calsku);
+    property_get(prop_name_revision, revision_value, prop_default_revision);
+
     // Read EXTRA_CONF_PATH[N]
     for (int i = 1; i <= 10; i++) {
         char key[32];
@@ -731,12 +769,27 @@ void CascadeConfig::init(const char *main_config)
         const uwbParam *param = mMainConfig.find(key);
         if (!param)
             continue;
-        CUwbNxpConfig config(param->str_value());
-        ALOGD("Extra calibration file %s : %svalid", param->str_value(), config.isValid() ? "" : "in");
-        if (config.isValid() || config.isCountrySpecific()) {
-            mExtraConfig.emplace_back(move(config));
-        }
+
+        std::string filename(param->str_value());
+
+        auto entry = std::make_pair(param->str_value(), CUwbNxpConfig(filename.c_str()));
+        mExtraConfig.emplace_back(std::move(entry));
+    }
+
+    // evaluate <sku> and <revision>
+    mExtraConfSpecifiers.mCurSku = sku_value;
+    mExtraConfSpecifiers.mCurRevision = revision_value;
+    evaluateExtraConfPaths();
+
+    // re-evaluate with "<extid>"
+    char extid_value[PROPERTY_VALUE_MAX];
+    if (!NxpConfig_GetStr(extid_config_name, extid_value, sizeof(extid_value))) {
+        strcpy(extid_value, extid_default_value);
     }
+    mExtraConfSpecifiers.mCurExtid = extid_value;
+    evaluateExtraConfPaths();
+
+    ALOGI("Provided specifiers: sku=[%s] revision=[%s] extid=[%s]", sku_value, revision_value, extid_value);
 
     // Pick one libuwb-countrycode.conf with the highest VERSION number
     // from multiple directories specified by COUNTRY_CODE_CAP_FILE_LOCATION
@@ -797,28 +850,23 @@ void CascadeConfig::deinit()
     mCapsConfig.reset();
     mRegionMap.reset();
     mUciConfig.reset();
-    mCurRegionCode.clear();
+    mExtraConfSpecifiers.reset();
 }
 
 bool CascadeConfig::setCountryCode(const char country_code[2])
 {
     string strRegion = mRegionMap.xlateCountryCode(country_code);
 
-    if (strRegion == mCurRegionCode) {
+    if (strRegion == mExtraConfSpecifiers.mCurRegionCode) {
         ALOGI("Same region code(%c%c --> %s), per-country configuration not updated.",
               country_code[0], country_code[1], strRegion.c_str());
         return false;
     }
 
     ALOGI("Apply country code %c%c --> %s\n", country_code[0], country_code[1], strRegion.c_str());
-    mCurRegionCode = strRegion;
-    for (auto &x : mExtraConfig) {
-        if (x.isCountrySpecific()) {
-            x.setCountry(mCurRegionCode);
-            x.dump();
-        }
-    }
-    return true;
+    mExtraConfSpecifiers.mCurRegionCode = strRegion;
+
+    return evaluateExtraConfPaths();
 }
 
 const uwbParam* CascadeConfig::find(const char *name) const
@@ -830,7 +878,8 @@ const uwbParam* CascadeConfig::find(const char *name) const
       return param;
 
     for (auto it = mExtraConfig.rbegin(); it != mExtraConfig.rend(); it++) {
-        param = it->find(name);
+        auto &config = it->second;
+        param = config.find(name);
         if (param)
             break;
     }
```

