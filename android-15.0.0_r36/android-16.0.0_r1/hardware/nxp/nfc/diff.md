```diff
diff --git a/OWNERS b/OWNERS
index f46dccd..47f209f 100755
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,2 @@
 # Bug component: 48448
-include platform/packages/apps/Nfc:/OWNERS
\ No newline at end of file
+include platform/packages/modules/Nfc:/OWNERS
\ No newline at end of file
diff --git a/snxxx/halimpl/common/Nxp_Features.h b/snxxx/halimpl/common/Nxp_Features.h
index 80a767c..1ad1241 100644
--- a/snxxx/halimpl/common/Nxp_Features.h
+++ b/snxxx/halimpl/common/Nxp_Features.h
@@ -1,6 +1,6 @@
 /******************************************************************************
  *
- *  Copyright 2022-2024 NXP
+ *  Copyright 2022-2025 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -318,6 +318,7 @@ extern tNfc_featureList nfcFL;
 #define CAP_POLL_FRAME_NTF_ID 0x01
 #define CAP_POWER_SAVING_MODE_ID 0x02
 #define CAP_AUTOTRANSACT_PLF_ID 0x03
+#define OBSERVE_MODE_SUPPORT_WITH_OUT_RF 0x02
 
 #define UPDATE_NFCC_CAPABILITY()                                             \
   {                                                                          \
@@ -338,7 +339,7 @@ extern tNfc_featureList nfcFL;
         GetNxpNumValue(NAME_NXP_EXTENDED_FIELD_DETECT_MODE,                  \
                        &extended_field_mode, sizeof(extended_field_mode))) { \
       if (extended_field_mode == 0x03) {                                     \
-        nfcFL.nfccCap.OBSERVE_MODE.val = 0x01;                               \
+        nfcFL.nfccCap.OBSERVE_MODE.val = OBSERVE_MODE_SUPPORT_WITH_OUT_RF;   \
       }                                                                      \
     }                                                                        \
     unsigned long num = 0;                                                   \
diff --git a/snxxx/halimpl/common/phNfcNciConstants.h b/snxxx/halimpl/common/phNfcNciConstants.h
index f9107aa..5a90a94 100644
--- a/snxxx/halimpl/common/phNfcNciConstants.h
+++ b/snxxx/halimpl/common/phNfcNciConstants.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2024 NXP
+ * Copyright 2024-2025 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -37,6 +37,7 @@
 #define NCI_ANDROID_POWER_SAVING 0x01
 #define NCI_ANDROID_OBSERVER_MODE 0x02
 #define NCI_ANDROID_GET_OBSERVER_MODE_STATUS 0x04
+#define NCI_ANDROID_SET_PASSIVE_OBSERVER_TECH 0x05
 
 /* Android Power Saving Params */
 #define NCI_ANDROID_POWER_SAVING_PARAM_SIZE 2
@@ -108,3 +109,19 @@
 #define TYPE_ALL_EVENTS 0x00
 #define TYPE_ONLY_MOD_EVENTS 0x01
 #define TYPE_ONLY_CMA_EVENTS 0x02
+#define NCI_ANDROID_PASSIVE_OBSERVE_PARAM_DISABLE 0x0
+#define NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_A 0x1
+#define NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_B 0x2
+#define NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_F 0x4
+#define NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_V 0x8
+
+#define OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG  \
+  (NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_A | \
+   NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_B | \
+   NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_V)
+
+#define OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG_FOR_ALL_TECH \
+  (NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_A |             \
+   NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_B |             \
+   NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_F |             \
+   NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_V)
diff --git a/snxxx/halimpl/hal/phNxpNciHal.cc b/snxxx/halimpl/hal/phNxpNciHal.cc
index f2ccce7..018a1ef 100644
--- a/snxxx/halimpl/hal/phNxpNciHal.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2012-2024 NXP
+ * Copyright 2012-2025 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -1150,12 +1150,16 @@ int phNxpNciHal_write(uint16_t data_len, const uint8_t* p_data) {
     phNxpNciHal_print_packet("SEND", p_data, data_len,
                              RfFwRegionDnld_handle == NULL);
     return phNxpNciHal_handleVendorSpecificCommand(data_len, p_data);
-  } else if (isObserveModeEnabled() &&
-             p_data[NCI_GID_INDEX] == NCI_RF_DISC_COMMD_GID &&
+  } else if (p_data[NCI_GID_INDEX] == NCI_RF_DISC_COMMD_GID &&
              p_data[NCI_OID_INDEX] == NCI_RF_DISC_COMMAND_OID) {
-    NciDiscoveryCommandBuilder builder;
-    vector<uint8_t> v_data = builder.reConfigRFDiscCmd(data_len, p_data);
-    return phNxpNciHal_write_internal(v_data.size(), v_data.data());
+    NciDiscoveryCommandBuilderInstance.setDiscoveryCommand(data_len, p_data);
+    if (isObserveModeEnabled()) {
+      vector<uint8_t> v_data =
+          NciDiscoveryCommandBuilderInstance.reConfigRFDiscCmd();
+      return phNxpNciHal_write_internal(v_data.size(), v_data.data());
+    } else {
+      return phNxpNciHal_write_internal(data_len, p_data);
+    }
   } else if (IS_HCI_PACKET(p_data)) {
     // Inform WiredSe service that HCI Pkt is sending from libnfc layer
     phNxpNciHal_WiredSeDispatchEvent(&gWiredSeHandle, SENDING_HCI_PKT);
@@ -1310,8 +1314,6 @@ retry:
     if (nxpncihal_ctrl.retry_cnt++ < MAX_RETRY_COUNT) {
       NXPLOG_NCIHAL_D(
           "write_unlocked failed - NFCC Maybe in Standby Mode - Retry");
-      /* 10ms delay to give NFCC wake up delay */
-      usleep(1000 * 10);
       goto retry;
     } else {
       NXPLOG_NCIHAL_E(
@@ -2717,12 +2719,13 @@ int phNxpNciHal_configDiscShutdown(void) {
         phNxpNciHal_getULPDetFlag() == false) {
       if (nxpncihal_ctrl.halStatus == HAL_STATUS_CLOSE) {
         NXPLOG_NCIHAL_D("phNxpNciHal_close is already closed, ignoring close");
+        CONCURRENCY_UNLOCK();
         return NFCSTATUS_FAILED;
       }
       NXPLOG_NCIHAL_D("Ulpdet supported");
       status = phNxpNciHal_propConfULPDetMode(true);
-      phNxpNciHal_clean_resources();
       CONCURRENCY_UNLOCK();
+      phNxpNciHal_clean_resources();
       return status;
     }
   }
diff --git a/snxxx/halimpl/hal/phNxpNciHal_ext.cc b/snxxx/halimpl/hal/phNxpNciHal_ext.cc
index 842920b..db579b4 100644
--- a/snxxx/halimpl/hal/phNxpNciHal_ext.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal_ext.cc
@@ -435,6 +435,7 @@ NFCSTATUS phNxpNciHal_process_ext_rsp(uint8_t* p_ntf, uint16_t* p_len) {
 static NFCSTATUS phNxpNciHal_ext_process_nfc_init_rsp(uint8_t* p_ntf,
                                                       uint16_t* p_len) {
   NFCSTATUS status = NFCSTATUS_SUCCESS;
+  bool is_abort_req = false;
   /* Parsing CORE_RESET_RSP and CORE_RESET_NTF to update NCI version.*/
   if (p_ntf == NULL || *p_len < 2) {
     return NFCSTATUS_FAILED;
@@ -443,7 +444,8 @@ static NFCSTATUS phNxpNciHal_ext_process_nfc_init_rsp(uint8_t* p_ntf,
       ((p_ntf[1] & NCI_OID_MASK) == NCI_MSG_CORE_RESET)) {
     if (*p_len < 4) {
       android_errorWriteLog(0x534e4554, "169258455");
-      return NFCSTATUS_FAILED;
+      NXPLOG_NCIHAL_E("%s invalid CORE_RESET_RSP len", __func__);
+      goto core_reset_err;
     }
     if (p_ntf[2] == 0x01 && p_ntf[3] == 0x00) {
       NXPLOG_NCIHAL_D("CORE_RESET_RSP NCI2.0");
@@ -454,22 +456,27 @@ static NFCSTATUS phNxpNciHal_ext_process_nfc_init_rsp(uint8_t* p_ntf,
     } else if (p_ntf[2] == 0x03 && p_ntf[3] == 0x00) {
       if (*p_len < 5) {
         android_errorWriteLog(0x534e4554, "169258455");
-        return NFCSTATUS_FAILED;
+        NXPLOG_NCIHAL_E("%s invalid CORE_RESET_RSP len", __func__);
+        goto core_reset_err;
       }
       NXPLOG_NCIHAL_D("CORE_RESET_RSP NCI1.0");
       nxpncihal_ctrl.nci_info.nci_version = p_ntf[4];
-    } else
-      status = NFCSTATUS_FAILED;
+    } else {
+      NXPLOG_NCIHAL_E("%s invalid CORE_RESET_RSP", __func__);
+      goto core_reset_err;
+    }
   } else if (p_ntf[0] == NCI_MT_NTF &&
              ((p_ntf[1] & NCI_OID_MASK) == NCI_MSG_CORE_RESET)) {
     if (*p_len < 4) {
       android_errorWriteLog(0x534e4554, "169258455");
-      return NFCSTATUS_FAILED;
+      NXPLOG_NCIHAL_E("%s invalid CORE_RESET_NTF len", __func__);
+      goto core_reset_err;
     }
     if (p_ntf[3] == CORE_RESET_TRIGGER_TYPE_CORE_RESET_CMD_RECEIVED) {
       if (*p_len < 6) {
         android_errorWriteLog(0x534e4554, "169258455");
-        return NFCSTATUS_FAILED;
+        NXPLOG_NCIHAL_E("%s invalid CORE_RESET_NTF len", __func__);
+        goto core_reset_err;
       }
       NXPLOG_NCIHAL_D("CORE_RESET_NTF NCI2.0 reason CORE_RESET_CMD received !");
       nxpncihal_ctrl.nci_info.nci_version = p_ntf[5];
@@ -477,17 +484,15 @@ static NFCSTATUS phNxpNciHal_ext_process_nfc_init_rsp(uint8_t* p_ntf,
         phNxpNciHal_configFeatureList(p_ntf, *p_len);
       int len = p_ntf[2] + 2; /*include 2 byte header*/
       if (len != *p_len - 1) {
-        NXPLOG_NCIHAL_E(
-            "phNxpNciHal_ext_process_nfc_init_rsp invalid NTF length");
         android_errorWriteLog(0x534e4554, "121263487");
-        return NFCSTATUS_FAILED;
+        NXPLOG_NCIHAL_E("%s invalid CORE_RESET_NTF len", __func__);
+        goto core_reset_err;
       }
       wFwVerRsp = (((uint32_t)p_ntf[len - 2]) << 16U) |
                   (((uint32_t)p_ntf[len - 1]) << 8U) | p_ntf[len];
       NXPLOG_NCIHAL_D("NxpNci> FW Version: %x.%x.%x", p_ntf[len - 2],
                       p_ntf[len - 1], p_ntf[len]);
     } else {
-      bool is_abort_req = true;
       if ((p_ntf[3] == CORE_RESET_TRIGGER_TYPE_WATCHDOG_RESET ||
            p_ntf[3] == CORE_RESET_TRIGGER_TYPE_FW_ASSERT) ||
           ((p_ntf[3] == CORE_RESET_TRIGGER_TYPE_UNRECOVERABLE_ERROR) &&
@@ -496,9 +501,11 @@ static NFCSTATUS phNxpNciHal_ext_process_nfc_init_rsp(uint8_t* p_ntf,
         /* WA : In some cases for Watchdog reset FW sends reset reason code as
          * unrecoverable error and config status as WATCHDOG_RESET */
         is_abort_req = phNxpNciHal_update_core_reset_ntf_prop();
+      } else {
+        is_abort_req = true;
       }
-      if (is_abort_req) phNxpNciHal_emergency_recovery(p_ntf[3]);
-      status = NFCSTATUS_FAILED;
+      NXPLOG_NCIHAL_E("%s NFC FW reset triggered", __func__);
+      goto core_reset_err;
     } /* Parsing CORE_INIT_RSP*/
   } else if (p_ntf[0] == NCI_MT_RSP &&
              ((p_ntf[1] & NCI_OID_MASK) == NCI_MSG_CORE_INIT)) {
@@ -514,18 +521,22 @@ static NFCSTATUS phNxpNciHal_ext_process_nfc_init_rsp(uint8_t* p_ntf,
       }
       if (*p_len < 3) {
         android_errorWriteLog(0x534e4554, "169258455");
-        return NFCSTATUS_FAILED;
+        NXPLOG_NCIHAL_E("%s invalid CORE_INIT_RSP len", __func__);
+        goto core_reset_err;
       }
       int len = p_ntf[2] + 2; /*include 2 byte header*/
       if (len != *p_len - 1) {
-        NXPLOG_NCIHAL_E(
-            "phNxpNciHal_ext_process_nfc_init_rsp invalid NTF length");
         android_errorWriteLog(0x534e4554, "121263487");
-        return NFCSTATUS_FAILED;
+        NXPLOG_NCIHAL_E("%s invalid CORE_INIT_RSP len", __func__);
+        goto core_reset_err;
       }
       wFwVerRsp = (((uint32_t)p_ntf[len - 2]) << 16U) |
                   (((uint32_t)p_ntf[len - 1]) << 8U) | p_ntf[len];
-      if (wFwVerRsp == 0) status = NFCSTATUS_FAILED;
+      if (wFwVerRsp == 0) {
+        NXPLOG_NCIHAL_E("%s invalid FW Version: %x.%x.%x", p_ntf[len - 2],
+                        p_ntf[len - 1], p_ntf[len]);
+        status = NFCSTATUS_FAILED;
+      }
       iCoreInitRspLen = *p_len;
       memcpy(bCoreInitRsp, p_ntf, *p_len);
       NXPLOG_NCIHAL_D("NxpNci> FW Version: %x.%x.%x", p_ntf[len - 2],
@@ -533,6 +544,19 @@ static NFCSTATUS phNxpNciHal_ext_process_nfc_init_rsp(uint8_t* p_ntf,
     }
   }
   return status;
+
+core_reset_err:
+  uint32_t i;
+  char print_buffer[*p_len * 3 + 1];
+
+  memset(print_buffer, 0, sizeof(print_buffer));
+  for (i = 0; i < *p_len; i++) {
+    snprintf(&print_buffer[i * 2], 3, "%02X", p_ntf[i]);
+  }
+  NXPLOG_NCIR_E("%s len = %3d > %s", __func__, *p_len, print_buffer);
+
+  if (is_abort_req) phNxpNciHal_emergency_recovery(p_ntf[3]);
+  return NFCSTATUS_FAILED;
 }
 
 /******************************************************************************
diff --git a/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc b/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc
index 4dd0376..16bc132 100755
--- a/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal_extOperations.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2019-2024 NXP
+ * Copyright 2019-2025 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -796,6 +796,9 @@ int phNxpNciHal_handleVendorSpecificCommand(uint16_t data_len,
   } else if (data_len > 4 &&
              p_data[NCI_MSG_INDEX_FOR_FEATURE] == NCI_ANDROID_OBSERVER_MODE) {
     return handleObserveMode(data_len, p_data);
+  } else if (data_len > 4 && p_data[NCI_MSG_INDEX_FOR_FEATURE] ==
+                                 NCI_ANDROID_SET_PASSIVE_OBSERVER_TECH) {
+    return handleObserveModeTechCommand(data_len, p_data);
   } else if (data_len >= 4 && p_data[NCI_MSG_INDEX_FOR_FEATURE] ==
                                   NCI_ANDROID_GET_OBSERVER_MODE_STATUS) {
     // 2F 0C 01 04 => ObserveMode Status Command length is 4 Bytes
diff --git a/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc b/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc
index 13235ba..98d2e54 100644
--- a/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc
+++ b/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2024 NXP
+ * Copyright 2024-2025 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -20,6 +20,11 @@
 
 using namespace std;
 
+NciDiscoveryCommandBuilder& NciDiscoveryCommandBuilder::getInstance() {
+  static NciDiscoveryCommandBuilder msNciDiscoveryCommandBuilder;
+  return msNciDiscoveryCommandBuilder;
+}
+
 /*****************************************************************************
  *
  * Function         parse
@@ -140,22 +145,17 @@ vector<uint8_t> NciDiscoveryCommandBuilder::build() {
  *
  * Function         reConfigRFDiscCmd
  *
- * Description      It parse the discovery command and alter the configuration
- *                  to enable Observe Mode
- *
- * Parameters       data - RF discovery command
+ * Description      It parse the current discovery command and alter
+ *                  the configuration to enable Observe Mode
  *
  * Returns          return the discovery command for Observe mode
  *
  ****************************************************************************/
-vector<uint8_t> NciDiscoveryCommandBuilder::reConfigRFDiscCmd(
-    uint16_t data_len, const uint8_t* p_data) {
-  if (!p_data) {
+vector<uint8_t> NciDiscoveryCommandBuilder::reConfigRFDiscCmd() {
+  if (size(currentDiscoveryCommand) <= 0) {
     return vector<uint8_t>();
   }
-
-  vector<uint8_t> discoveryCommand = vector<uint8_t>(p_data, p_data + data_len);
-  bool status = parse(std::move(discoveryCommand));
+  bool status = parse(currentDiscoveryCommand);
   if (status) {
     removeListenParams();
     addObserveModeParams();
@@ -164,3 +164,35 @@ vector<uint8_t> NciDiscoveryCommandBuilder::reConfigRFDiscCmd(
     return vector<uint8_t>();
   }
 }
+
+/*****************************************************************************
+ *
+ * Function         setDiscoveryCommand
+ *
+ * Description      It sets the current discovery command
+ *
+ * Parameters       data - RF discovery command
+ *
+ * Returns          return void
+ *
+ ****************************************************************************/
+void NciDiscoveryCommandBuilder::setDiscoveryCommand(uint16_t data_len,
+                                                     const uint8_t* p_data) {
+  if (!p_data || data_len <= 0) {
+    return;
+  }
+  currentDiscoveryCommand = vector<uint8_t>(p_data, p_data + data_len);
+}
+
+/*****************************************************************************
+ *
+ * Function         getDiscoveryCommand
+ *
+ * Description      It returns the current discovery command
+ *
+ * Returns          return current discovery command which is set
+ *
+ ****************************************************************************/
+vector<uint8_t> NciDiscoveryCommandBuilder::getDiscoveryCommand() {
+  return currentDiscoveryCommand;
+}
diff --git a/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.h b/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.h
index e8d2c35..87eaada 100644
--- a/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.h
+++ b/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2024 NXP
+ * Copyright 2024-2025 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -18,6 +18,9 @@
 
 using namespace std;
 
+#define NciDiscoveryCommandBuilderInstance \
+  (NciDiscoveryCommandBuilder::getInstance())
+
 /**
  * @brief DiscoveryConfiguration is the data class
  * which holds RF tech mode and Disc Frequency values
@@ -40,6 +43,7 @@ class DiscoveryConfiguration {
  */
 class NciDiscoveryCommandBuilder {
  private:
+  vector<uint8_t> currentDiscoveryCommand;
   vector<DiscoveryConfiguration> mRfDiscoverConfiguration;
 
   /*****************************************************************************
@@ -111,6 +115,30 @@ class NciDiscoveryCommandBuilder {
   friend class NciDiscoveryCommandBuilderTest;
 #endif
  public:
+  /*****************************************************************************
+   *
+   * Function         setDiscoveryCommand
+   *
+   * Description      It sets the current discovery command
+   *
+   * Parameters       data - RF discovery command
+   *
+   * Returns          return void
+   *
+   ****************************************************************************/
+  void setDiscoveryCommand(uint16_t data_len, const uint8_t* p_data);
+
+  /*****************************************************************************
+   *
+   * Function         getDiscoveryCommand
+   *
+   * Description      It returns the current discovery command
+   *
+   * Returns          return current discovery command which is set
+   *
+   ****************************************************************************/
+  vector<uint8_t> getDiscoveryCommand();
+
   /*****************************************************************************
    *
    * Function         reConfigRFDiscCmd
@@ -123,5 +151,6 @@ class NciDiscoveryCommandBuilder {
    * Returns          return the discovery command for Observe mode
    *
    ****************************************************************************/
-  vector<uint8_t> reConfigRFDiscCmd(uint16_t data_len, const uint8_t* p_data);
+  vector<uint8_t> reConfigRFDiscCmd();
+  static NciDiscoveryCommandBuilder& getInstance();
 };
diff --git a/snxxx/halimpl/observe_mode/ObserveMode.cc b/snxxx/halimpl/observe_mode/ObserveMode.cc
index 43315a3..498ae34 100644
--- a/snxxx/halimpl/observe_mode/ObserveMode.cc
+++ b/snxxx/halimpl/observe_mode/ObserveMode.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2024 NXP
+ * Copyright 2024-2025 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -18,6 +18,7 @@
 
 #include <vector>
 
+#include "NciDiscoveryCommandBuilder.h"
 #include "phNxpNciHal_extOperations.h"
 
 using namespace std;
@@ -77,6 +78,75 @@ int handleObserveMode(uint16_t data_len, const uint8_t* p_data) {
   return p_data[NCI_MSG_LEN_INDEX];
 }
 
+/*******************************************************************************
+ *
+ * Function         handleObserveModeTechCommand()
+ *
+ * Description      This handles the ObserveMode command and enables the observe
+ *                  Mode flag
+ *
+ * Returns          It returns number of bytes received.
+ *
+ ******************************************************************************/
+int handleObserveModeTechCommand(uint16_t data_len, const uint8_t* p_data) {
+  uint8_t status = NCI_RSP_FAIL;
+  if (phNxpNciHal_isObserveModeSupported() &&
+      (p_data[NCI_MSG_INDEX_FEATURE_VALUE] ==
+           OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG ||
+       p_data[NCI_MSG_INDEX_FEATURE_VALUE] ==
+           OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG_FOR_ALL_TECH ||
+       p_data[NCI_MSG_INDEX_FEATURE_VALUE] ==
+           NCI_ANDROID_PASSIVE_OBSERVE_PARAM_DISABLE)) {
+    bool flag = (p_data[NCI_MSG_INDEX_FEATURE_VALUE] ==
+                     OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG ||
+                 p_data[NCI_MSG_INDEX_FEATURE_VALUE] ==
+                     OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG_FOR_ALL_TECH)
+                    ? true
+                    : false;
+    uint8_t rf_deactivate_cmd[] = {0x21, 0x06, 0x01, 0x00};
+
+    // send RF Deactivate command
+    NFCSTATUS rfDeactivateStatus =
+        phNxpNciHal_send_ext_cmd(sizeof(rf_deactivate_cmd), rf_deactivate_cmd);
+    if (rfDeactivateStatus == NFCSTATUS_SUCCESS) {
+      if (flag) {
+        // send Observe Mode Tech command
+        NFCSTATUS nciStatus =
+            phNxpNciHal_send_ext_cmd(data_len, (uint8_t*)p_data);
+        if (nciStatus != NFCSTATUS_SUCCESS) {
+          NXPLOG_NCIHAL_E("%s ObserveMode tech command failed", __func__);
+        }
+      }
+
+      // send Discovery command
+      vector<uint8_t> discoveryCommand =
+          flag ? NciDiscoveryCommandBuilderInstance.reConfigRFDiscCmd()
+               : NciDiscoveryCommandBuilderInstance.getDiscoveryCommand();
+      NFCSTATUS rfDiscoveryStatus = phNxpNciHal_send_ext_cmd(
+          discoveryCommand.size(), &discoveryCommand[0]);
+
+      if (rfDiscoveryStatus == NFCSTATUS_SUCCESS) {
+        setObserveModeFlag(flag);
+        status = NCI_RSP_OK;
+      } else {
+        NXPLOG_NCIHAL_E("%s Rf Disovery command failed", __func__);
+      }
+
+    } else {
+      NXPLOG_NCIHAL_E("%s Rf Deactivate command failed", __func__);
+    }
+  } else {
+    NXPLOG_NCIHAL_E(
+        "%s ObserveMode feature or tech which is requested is not supported",
+        __func__);
+  }
+
+  phNxpNciHal_vendorSpecificCallback(
+      p_data[NCI_OID_INDEX], p_data[NCI_MSG_INDEX_FOR_FEATURE], {status});
+
+  return p_data[NCI_MSG_LEN_INDEX];
+}
+
 /*******************************************************************************
  *
  * Function         handleGetObserveModeStatus()
diff --git a/snxxx/halimpl/observe_mode/ObserveMode.h b/snxxx/halimpl/observe_mode/ObserveMode.h
index eec69fe..d99facb 100644
--- a/snxxx/halimpl/observe_mode/ObserveMode.h
+++ b/snxxx/halimpl/observe_mode/ObserveMode.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2024 NXP
+ * Copyright 2024-2025 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -53,6 +53,18 @@ bool isObserveModeEnabled();
  ******************************************************************************/
 int handleObserveMode(uint16_t data_len, const uint8_t* p_data);
 
+/*******************************************************************************
+ *
+ * Function         handleObserveModeTechCommand
+ *
+ * Description      This handles the ObserveMode command and enables the observe
+ *                  Mode flag
+ *
+ * Returns          It returns number of bytes received.
+ *
+ ******************************************************************************/
+int handleObserveModeTechCommand(uint16_t data_len, const uint8_t* p_data);
+
 /*******************************************************************************
  *
  * Function         handleGetObserveModeStatus()
diff --git a/snxxx/halimpl/utils/phNxpNciHal_utils.cc b/snxxx/halimpl/utils/phNxpNciHal_utils.cc
index 54d3757..f9d28d0 100644
--- a/snxxx/halimpl/utils/phNxpNciHal_utils.cc
+++ b/snxxx/halimpl/utils/phNxpNciHal_utils.cc
@@ -361,7 +361,9 @@ NFCSTATUS phNxpNciHal_init_cb_data(phNxpNciHal_Sem_t* pCallbackData,
   pCallbackData->pContext = pContext;
 
   /* Add to active semaphore list */
-  if (listAdd(&phNxpNciHal_get_monitor()->sem_list, pCallbackData) != 1) {
+  phNxpNciHal_Monitor_t* hal_monitor = phNxpNciHal_get_monitor();
+  if (hal_monitor == NULL ||
+      listAdd(&hal_monitor->sem_list, pCallbackData) != 1) {
     NXPLOG_NCIHAL_E("Failed to add the semaphore to the list");
   }
 
@@ -387,7 +389,9 @@ void phNxpNciHal_cleanup_cb_data(phNxpNciHal_Sem_t* pCallbackData) {
   }
 
   /* Remove from active semaphore list */
-  if (listRemove(&phNxpNciHal_get_monitor()->sem_list, pCallbackData) != 1) {
+  phNxpNciHal_Monitor_t* hal_monitor = phNxpNciHal_get_monitor();
+  if (hal_monitor == NULL ||
+      listRemove(&hal_monitor->sem_list, pCallbackData) != 1) {
     NXPLOG_NCIHAL_E(
         "phNxpNciHal_cleanup_cb_data: Failed to remove semaphore from the "
         "list");
@@ -407,9 +411,11 @@ void phNxpNciHal_cleanup_cb_data(phNxpNciHal_Sem_t* pCallbackData) {
 *******************************************************************************/
 void phNxpNciHal_releaseall_cb_data(void) {
   phNxpNciHal_Sem_t* pCallbackData;
+  phNxpNciHal_Monitor_t* hal_monitor = phNxpNciHal_get_monitor();
 
-  while (listGetAndRemoveNext(&phNxpNciHal_get_monitor()->sem_list,
-                              (void**)&pCallbackData)) {
+  if (hal_monitor == NULL) return;
+
+  while (listGetAndRemoveNext(&hal_monitor->sem_list, (void**)&pCallbackData)) {
     pCallbackData->status = NFCSTATUS_FAILED;
     sem_post(&pCallbackData->sem);
   }
```

