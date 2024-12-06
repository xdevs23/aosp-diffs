```diff
diff --git a/flags/flags.aconfig b/flags/flags.aconfig
index 4dcde334..002cd7e9 100644
--- a/flags/flags.aconfig
+++ b/flags/flags.aconfig
@@ -7,3 +7,10 @@ flag {
     description: "Support for a pure NFC Forum T5T tag"
     bug: "293959530"
 }
+
+flag {
+    name: "mfc_read_mad"
+    namespace: "nfc"
+    description: "Support for read MFC MAD sector"
+    bug: "340223581"
+}
diff --git a/src/Android.bp b/src/Android.bp
index 3b58ebae..0baf755c 100644
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -27,13 +27,17 @@ cc_library {
         "libbinder_ndk",
         "libstatssocket",
         "server_configurable_flags",
+        "libaconfig_storage_read_api_cc",
+    ],
+    defaults: [
+        "aconfig_lib_cc_shared_link.defaults",
     ],
     static_libs: [
         "android.hardware.nfc@1.0",
         "android.hardware.nfc@1.1",
         "android.hardware.nfc@1.2",
         // Add for AIDL
-        "android.hardware.nfc-V1-ndk",
+        "android.hardware.nfc-V2-ndk",
         "libnfcutils",
         "libstatslog_nfc",
         "libnfc-nci_flags",
diff --git a/src/adaptation/NfcAdaptation.cc b/src/adaptation/NfcAdaptation.cc
index a35666c3..7f9ad843 100644
--- a/src/adaptation/NfcAdaptation.cc
+++ b/src/adaptation/NfcAdaptation.cc
@@ -87,6 +87,7 @@ INfcClientCallback* NfcAdaptation::mCallback;
 std::shared_ptr<INfcAidlClientCallback> mAidlCallback;
 ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
 std::shared_ptr<INfcAidl> mAidlHal;
+int32_t mAidlHalVer;
 
 bool nfc_nci_reset_keep_cfg_enabled = false;
 uint8_t nfc_nci_reset_type = 0x00;
@@ -95,6 +96,7 @@ uint8_t appl_dta_mode_flag = 0x00;
 bool isDownloadFirmwareCompleted = false;
 bool use_aidl = false;
 uint8_t mute_tech_route_option = 0x00;
+unsigned int t5t_mute_legacy = 0;
 
 extern tNFA_DM_CFG nfa_dm_cfg;
 extern tNFA_PROPRIETARY_CFG nfa_proprietary_cfg;
@@ -242,6 +244,12 @@ class NfcAidlClientCallback
       case NfcAidlEvent::HCI_NETWORK_RESET:
         e_num = HAL_HCI_NETWORK_RESET;
         break;
+      case NfcAidlEvent::REQUEST_CONTROL:
+        e_num = HAL_NFC_REQUEST_CONTROL_EVT;
+        break;
+      case NfcAidlEvent::RELEASE_CONTROL:
+        e_num = HAL_NFC_RELEASE_CONTROL_EVT;
+        break;
       case NfcAidlEvent::ERROR:
       default:
         e_num = HAL_NFC_ERROR_EVT;
@@ -385,6 +393,10 @@ void NfcAdaptation::GetVendorConfigs(
     configMap.emplace(NAME_OFF_HOST_ESE_PIPE_ID,
                       ConfigValue((uint8_t)aidlConfigValue.offHostESEPipeId));
 
+    if (aidlConfigValue.offHostSimPipeIds.size() != 0) {
+      configMap.emplace(NAME_OFF_HOST_SIM_PIPE_IDS,
+                        ConfigValue(aidlConfigValue.offHostSimPipeIds));
+    }
     configMap.emplace(NAME_ISO_DEP_MAX_TRANSCEIVE,
                       ConfigValue(aidlConfigValue.maxIsoDepTransceiveLength));
     if (aidlConfigValue.hostAllowlist.size() != 0) {
@@ -538,6 +550,11 @@ void NfcAdaptation::Initialize() {
     nfa_hci_cfg.p_allowlist = &host_allowlist[0];
   }
 
+  if (NfcConfig::hasKey(NAME_ISO15693_SKIP_GET_SYS_INFO_CMD)) {
+    t5t_mute_legacy =
+        NfcConfig::getUnsigned(NAME_ISO15693_SKIP_GET_SYS_INFO_CMD);
+  }
+
   verify_stack_non_volatile_store();
   if (NfcConfig::hasKey(NAME_PRESERVE_STORAGE) &&
       NfcConfig::getUnsigned(NAME_PRESERVE_STORAGE) == 1) {
@@ -739,7 +756,9 @@ void NfcAdaptation::InitializeHalDeviceContext() {
       AIBinder_linkToDeath(mAidlHal->asBinder().get(), mDeathRecipient.get(),
                            nullptr /* cookie */);
       mHal = mHal_1_1 = mHal_1_2 = nullptr;
-      LOG(INFO) << StringPrintf("%s: INfcAidl::fromBinder returned", func);
+      mAidlHal->getInterfaceVersion(&mAidlHalVer);
+      LOG(INFO) << StringPrintf("%s: INfcAidl::fromBinder returned ver(%d)",
+                                func, mAidlHalVer);
     }
     LOG_ALWAYS_FATAL_IF(mAidlHal == nullptr,
                         "Failed to retrieve the NFC AIDL!");
@@ -934,7 +953,12 @@ void NfcAdaptation::HalControlGranted() {
   const char* func = "NfcAdaptation::HalControlGranted";
   LOG(VERBOSE) << StringPrintf("%s", func);
   if (mAidlHal != nullptr) {
-    LOG(ERROR) << StringPrintf("Unsupported function %s", func);
+    if (mAidlHalVer > 1) {
+      NfcAidlStatus aidl_status;
+      mAidlHal->controlGranted(&aidl_status);
+    } else {
+      LOG(ERROR) << StringPrintf("Unsupported function %s", func);
+    }
   } else if (mHal != nullptr) {
     mHal->controlGranted();
   }
diff --git a/src/fuzzers/fuzz_cmn.cc b/src/fuzzers/fuzz_cmn.cc
index d8d9765b..9afd7359 100644
--- a/src/fuzzers/fuzz_cmn.cc
+++ b/src/fuzzers/fuzz_cmn.cc
@@ -7,6 +7,7 @@ std::string nfc_storage_path;
 bool storeNfcSnoopLogs(std::string, off_t) { return true; };
 
 uint8_t appl_dta_mode_flag = 0;
+unsigned int t5t_mute_legacy = 0;
 bool nfc_nci_reset_keep_cfg_enabled = false;
 uint8_t nfc_nci_reset_type = 0x00;
 
diff --git a/src/fuzzers/integration/fakes/nfc_adaptation_fakes.cc b/src/fuzzers/integration/fakes/nfc_adaptation_fakes.cc
index 088b6e22..e3890425 100644
--- a/src/fuzzers/integration/fakes/nfc_adaptation_fakes.cc
+++ b/src/fuzzers/integration/fakes/nfc_adaptation_fakes.cc
@@ -1,6 +1,7 @@
 #include "NfcAdaptation.h"
 
 uint8_t appl_dta_mode_flag = 0;
+unsigned int t5t_mute_legacy = 0;
 bool nfc_nci_reset_keep_cfg_enabled = false;
 uint8_t nfc_nci_reset_type = 0x00;
 
diff --git a/src/fuzzers/nci/stubs.cc b/src/fuzzers/nci/stubs.cc
index 48a0cdee..65d56b4f 100644
--- a/src/fuzzers/nci/stubs.cc
+++ b/src/fuzzers/nci/stubs.cc
@@ -38,3 +38,4 @@ void rw_mfc_process_timeout(TIMER_LIST_ENT*) { abort(); }
 void ce_t4t_process_timeout(TIMER_LIST_ENT*) { abort(); }
 void nfa_sys_event(NFC_HDR*) { abort(); }
 void nfa_sys_timer_update() { abort(); }
+void nfa_sys_cback_notify_partial_enable_complete(uint8_t) {}
diff --git a/src/gki/ulinux/gki_ulinux.cc b/src/gki/ulinux/gki_ulinux.cc
index 585f0efd..1c9d8121 100644
--- a/src/gki/ulinux/gki_ulinux.cc
+++ b/src/gki/ulinux/gki_ulinux.cc
@@ -603,7 +603,7 @@ uint16_t GKI_wait(uint16_t flag, uint32_t timeout) {
       pthread_cond_timedwait(&gki_cb.os.thread_evt_cond[rtask],
                              &gki_cb.os.thread_evt_mutex[rtask], &abstime);
 
-    } else {
+    } else if (gki_cb.com.OSRdyTbl[rtask] != TASK_DEAD) {
       pthread_cond_wait(&gki_cb.os.thread_evt_cond[rtask],
                         &gki_cb.os.thread_evt_mutex[rtask]);
     }
diff --git a/src/include/nci_defs.h b/src/include/nci_defs.h
index 6043cb52..b3d55741 100644
--- a/src/include/nci_defs.h
+++ b/src/include/nci_defs.h
@@ -100,7 +100,7 @@
 
 /* parse byte0 of NCI packet */
 #define NCI_MSG_PRS_HDR0(p, mt, pbf, gid)       \
-  mt = (*(p)&NCI_MT_MASK) >> NCI_MT_SHIFT;      \
+  (mt) = (*(p)&NCI_MT_MASK) >> NCI_MT_SHIFT;    \
   (pbf) = (*(p)&NCI_PBF_MASK) >> NCI_PBF_SHIFT; \
   (gid) = *(p)++ & NCI_GID_MASK;
 
diff --git a/src/include/nfc_config.h b/src/include/nfc_config.h
index 0c265634..880777a2 100644
--- a/src/include/nfc_config.h
+++ b/src/include/nfc_config.h
@@ -58,10 +58,12 @@
 #define NAME_DEFAULT_ROUTE "DEFAULT_ROUTE"
 #define NAME_OFF_HOST_ESE_PIPE_ID "OFF_HOST_ESE_PIPE_ID"
 #define NAME_OFF_HOST_SIM_PIPE_ID "OFF_HOST_SIM_PIPE_ID"
+#define NAME_OFF_HOST_SIM_PIPE_IDS "OFF_HOST_SIM_PIPE_IDS"
 #define NAME_ISO_DEP_MAX_TRANSCEIVE "ISO_DEP_MAX_TRANSCEIVE"
 #define NAME_DEVICE_HOST_ALLOW_LIST "DEVICE_HOST_ALLOW_LIST"
 #define NAME_DEFAULT_ISODEP_ROUTE "DEFAULT_ISODEP_ROUTE"
 #define NAME_PRESENCE_CHECK_RETRY_COUNT "PRESENCE_CHECK_RETRY_COUNT"
+#define NAME_ISO15693_SKIP_GET_SYS_INFO_CMD "ISO15693_SKIP_GET_SYS_INFO_CMD"
 
 class NfcConfig {
  public:
diff --git a/src/nfa/dm/nfa_dm_act.cc b/src/nfa/dm/nfa_dm_act.cc
index 95248f3b..3162ef9c 100644
--- a/src/nfa/dm/nfa_dm_act.cc
+++ b/src/nfa/dm/nfa_dm_act.cc
@@ -342,10 +342,6 @@ static void nfa_dm_nfc_response_cback(tNFC_RESPONSE_EVT event,
       break;
 
     case NFC_EE_DISCOVER_REQ_REVT: /* EE Discover Req notification */
-      if (nfa_dm_is_active() &&
-          (nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_DISCOVERY)) {
-        nfa_dm_rf_deactivate(NFA_DEACTIVATE_TYPE_IDLE);
-      }
       nfa_ee_proc_evt(event, p_data);
       break;
 
diff --git a/src/nfa/dm/nfa_dm_api.cc b/src/nfa/dm/nfa_dm_api.cc
index bec6d6b9..81417a9a 100644
--- a/src/nfa/dm/nfa_dm_api.cc
+++ b/src/nfa/dm/nfa_dm_api.cc
@@ -30,6 +30,7 @@
 #include "nfa_api.h"
 #include "nfa_ce_int.h"
 #include "nfa_wlc_int.h"
+#include "nfc_int.h"
 
 using android::base::StringPrintf;
 
@@ -40,6 +41,60 @@ using android::base::StringPrintf;
 /*****************************************************************************
 **  APIs
 *****************************************************************************/
+/*******************************************************************************
+**
+** Function         NFA_SetNfccMode
+**
+** Description      This function sets the different NFC controller modes.
+**
+**                  mode ENABLE_MODE_DEFAULT or ENABLE_MODE_TRANSPARENT
+**                  or ENABLE_MODE_EE
+**
+** Returns          none
+**
+*******************************************************************************/
+extern void NFA_SetNfccMode(uint8_t mode) {
+  LOG(DEBUG) << StringPrintf("%s: (%d) -> (%d)", __func__, nfc_cb.nfcc_mode,
+                             mode);
+  nfc_cb.nfcc_mode = mode;
+}
+
+/*******************************************************************************
+**
+** Function         NFA_Partial_Init
+**
+** Description      This function initializes control blocks for NFA based on
+**                  mode
+**
+**                  p_hal_entry_tbl points to a table of HAL entry points
+**                  mode ENABLE_MODE_DEFAULT or ENABLE_MODE_TRANSPARENT
+**                  or ENABLE_MODE_EE
+**
+**                  NOTE: the buffer that p_hal_entry_tbl points must be
+**                  persistent until NFA is disabled.
+**
+** Returns          none
+**
+*******************************************************************************/
+extern void NFA_Partial_Init(tHAL_NFC_ENTRY* p_hal_entry_tbl, uint8_t mode) {
+  LOG(DEBUG) << StringPrintf("%s:enter ", __func__);
+  if (mode == ENABLE_MODE_TRANSPARENT) {
+    nfa_sys_init();
+    nfa_dm_init();
+  } else if (mode == ENABLE_MODE_EE) {
+    nfa_sys_init();
+    nfa_dm_init();
+    nfa_ee_init();
+  } else {
+    LOG(ERROR) << StringPrintf("Unknown Mode!");
+    return;
+  }
+  /* Initialize NFC module */
+  NFC_Init(p_hal_entry_tbl);
+  NFA_SetNfccMode(mode);
+  LOG(DEBUG) << StringPrintf("%s:exit ", __func__);
+}
+
 /*******************************************************************************
 **
 ** Function         NFA_Init
@@ -815,12 +870,6 @@ tNFA_STATUS NFA_SendRawFrame(uint8_t* p_raw_data, uint16_t data_len,
 
   LOG(VERBOSE) << StringPrintf("data_len:%d", data_len);
 
-  /* Validate parameters */
-  if (((data_len == 0) || (p_raw_data == nullptr)) &&
-      (!(nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_LISTEN_ACTIVE &&
-         nfa_dm_cb.disc_cb.activated_protocol == NFA_PROTOCOL_T3T)))
-    return (NFA_STATUS_INVALID_PARAM);
-
   size = NFC_HDR_SIZE + NCI_MSG_OFFSET_SIZE + NCI_DATA_HDR_SIZE + data_len;
   /* Check for integer overflow */
   if (size < data_len) {
@@ -835,7 +884,7 @@ tNFA_STATUS NFA_SendRawFrame(uint8_t* p_raw_data, uint16_t data_len,
     p_msg->len = data_len;
 
     p = (uint8_t*)(p_msg + 1) + p_msg->offset;
-    if (p_raw_data != nullptr) {
+    if ((data_len != 0) && (p_raw_data != nullptr)) {
       memcpy(p, p_raw_data, data_len);
     }
 
@@ -1187,6 +1236,21 @@ void NFA_EnableDtamode(tNFA_eDtaModes eDtaMode) {
   nfa_dm_cb.eDtaMode = eDtaMode;
 }
 
+/*******************************************************************************
+**
+** Function:        NFA_DisableDtamode
+**
+** Description:     Disable DTA Mode
+**
+** Returns:         none:
+**
+*******************************************************************************/
+void NFA_DisableDtamode(void) {
+  LOG(VERBOSE) << StringPrintf("%s: enter", __func__);
+  appl_dta_mode_flag = 0x0;
+  nfa_dm_cb.eDtaMode = NFA_DTA_APPL_MODE;
+}
+
 /*******************************************************************************
 **
 ** Function         NFA_ChangeDiscoveryTech
diff --git a/src/nfa/dm/nfa_dm_discover.cc b/src/nfa/dm/nfa_dm_discover.cc
index d9dc491a..0b3748f9 100644
--- a/src/nfa/dm/nfa_dm_discover.cc
+++ b/src/nfa/dm/nfa_dm_discover.cc
@@ -295,20 +295,26 @@ static uint8_t nfa_dm_get_rf_discover_config(
 
   /* Check polling B' */
   if (dm_disc_mask & NFA_DM_DISC_MASK_P_B_PRIME) {
-    disc_params[num_params].type = NFC_DISCOVERY_TYPE_POLL_B_PRIME;
-    disc_params[num_params].frequency = p_nfa_dm_rf_disc_freq_cfg->pbp;
-    num_params++;
-
-    if (num_params >= max_params) return num_params;
+    if (NFC_DISCOVERY_TYPE_POLL_B_PRIME != NFA_PROTOCOL_INVALID) {
+      disc_params[num_params].type = NFC_DISCOVERY_TYPE_POLL_B_PRIME;
+      disc_params[num_params].frequency = p_nfa_dm_rf_disc_freq_cfg->pbp;
+      num_params++;
+      if (num_params >= max_params) return num_params;
+    } else {
+      LOG(ERROR) << StringPrintf("Unsupported type POLL_B_PRIME!");
+    }
   }
 
   /* Check polling KOVIO */
   if (dm_disc_mask & NFA_DM_DISC_MASK_P_KOVIO) {
-    disc_params[num_params].type = NFC_DISCOVERY_TYPE_POLL_KOVIO;
-    disc_params[num_params].frequency = p_nfa_dm_rf_disc_freq_cfg->pk;
-    num_params++;
-
-    if (num_params >= max_params) return num_params;
+    if (NFC_DISCOVERY_TYPE_POLL_KOVIO != NFA_PROTOCOL_INVALID) {
+      disc_params[num_params].type = NFC_DISCOVERY_TYPE_POLL_KOVIO;
+      disc_params[num_params].frequency = p_nfa_dm_rf_disc_freq_cfg->pk;
+      num_params++;
+      if (num_params >= max_params) return num_params;
+    } else {
+      LOG(ERROR) << StringPrintf("Unsupported type POLL_KOVIO!");
+    }
   }
 
   /* Check listening ISO 15693 */
@@ -322,11 +328,14 @@ static uint8_t nfa_dm_get_rf_discover_config(
 
   /* Check listening B' */
   if (dm_disc_mask & NFA_DM_DISC_MASK_L_B_PRIME) {
-    disc_params[num_params].type = NFC_DISCOVERY_TYPE_LISTEN_B_PRIME;
-    disc_params[num_params].frequency = 1;
-    num_params++;
-
-    if (num_params >= max_params) return num_params;
+    if (NFC_DISCOVERY_TYPE_LISTEN_B_PRIME != NFA_PROTOCOL_INVALID) {
+      disc_params[num_params].type = NFC_DISCOVERY_TYPE_LISTEN_B_PRIME;
+      disc_params[num_params].frequency = 1;
+      num_params++;
+      if (num_params >= max_params) return num_params;
+    } else {
+      LOG(ERROR) << StringPrintf("Unsupported type LISTEN_B_PRIME!");
+    }
   }
 
   return num_params;
@@ -1504,6 +1513,13 @@ static void nfa_dm_disc_notify_deactivation(tNFA_DM_RF_DISC_SM_EVENT sm_event,
         /* restart timer and do not notify upper layer */
         nfa_sys_start_timer(&nfa_dm_cb.disc_cb.kovio_tle, 0,
                             NFA_DM_DISC_TIMEOUT_KOVIO_PRESENCE_CHECK);
+        /* clear activated information */
+        nfa_dm_cb.disc_cb.activated_tech_mode = 0;
+        nfa_dm_cb.disc_cb.activated_rf_disc_id = 0;
+        nfa_dm_cb.disc_cb.activated_rf_interface = 0;
+        nfa_dm_cb.disc_cb.activated_protocol = NFA_PROTOCOL_INVALID;
+        nfa_dm_cb.disc_cb.activated_handle = NFA_HANDLE_INVALID;
+        nfa_dm_cb.disc_cb.deact_notify_pending = false;
         return;
       }
       /* Otherwise, upper layer initiated deactivation. */
@@ -2203,6 +2219,7 @@ static void nfa_dm_disc_sm_poll_active(tNFA_DM_RF_DISC_SM_EVENT event,
       (nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING);
   bool sleep_wakeup_event = false;
   bool sleep_wakeup_event_processed = false;
+  tNFA_STATUS status;
 
   switch (event) {
     case NFA_DM_RF_DEACTIVATE_CMD:
@@ -2220,7 +2237,11 @@ static void nfa_dm_disc_sm_poll_active(tNFA_DM_RF_DISC_SM_EVENT event,
         nfa_dm_cb.disc_cb.deact_pending = true;
         nfa_dm_cb.disc_cb.pending_deact_type = p_data->deactivate_type;
       } else {
-        nfa_dm_send_deactivate_cmd(p_data->deactivate_type);
+        status = nfa_dm_send_deactivate_cmd(p_data->deactivate_type);
+        if (status != NFA_STATUS_OK) {
+          LOG(ERROR) << StringPrintf(
+              "%s; Error calling nfa_dm_send_deactivate_cmd()", __func__);
+        }
       }
 
       break;
diff --git a/src/nfa/ee/nfa_ee_api.cc b/src/nfa/ee/nfa_ee_api.cc
index 98f6346e..97b6acf6 100644
--- a/src/nfa/ee/nfa_ee_api.cc
+++ b/src/nfa/ee/nfa_ee_api.cc
@@ -112,6 +112,9 @@ tNFA_STATUS NFA_EeGetInfo(uint8_t* p_num_nfcee, tNFA_EE_INFO* p_info) {
     return (NFA_STATUS_FAILED);
   }
 
+  // Reset the target array as we may have less elements than in previous call
+  // if some activations failed.
+  memset(p_info, 0, sizeof(tNFA_EE_INFO) * max_ret);
   /* compose output */
   for (xx = 0; (xx < ret) && (num_ret < max_ret); xx++, p_cb++) {
     LOG(VERBOSE) << StringPrintf("xx:%d max_ret:%d, num_ret:%d ee_status:0x%x",
diff --git a/src/nfa/include/nfa_api.h b/src/nfa/include/nfa_api.h
index b7e0df7f..2984b0ce 100755
--- a/src/nfa/include/nfa_api.h
+++ b/src/nfa/include/nfa_api.h
@@ -259,6 +259,7 @@ typedef void(tNFA_DM_CBACK)(uint8_t event, tNFA_DM_CBACK_DATA* p_data);
 
 /* NFA Enable DTA Type Mode */
 typedef enum {
+  NFA_DTA_APPL_MODE = 0x00000000,
   NFA_DTA_DEFAULT_MODE = 0x00000001,
   NFA_DTA_LLCP_MODE = 0x00000002,
   NFA_DTA_HCEF_MODE = 0x00000004,
@@ -696,10 +697,27 @@ typedef void(tNFA_NDEF_CBACK)(tNFA_NDEF_EVT event, tNFA_NDEF_EVT_DATA* p_data);
 /* NFA VSC Callback */
 typedef void(tNFA_VSC_CBACK)(uint8_t event, uint16_t param_len,
                              uint8_t* p_param);
+/* Modes used by setNfcControllerAlwaysOn */
+#define ENABLE_MODE_DEFAULT 1
+#define ENABLE_MODE_TRANSPARENT 2
+#define ENABLE_MODE_EE 3
 
 /*****************************************************************************
 **  External Function Declarations
 *****************************************************************************/
+/*******************************************************************************
+**
+** Function         NFA_SetNfccMode
+**
+** Description      This function sets the control blocks nfcc mode
+**
+**                  mode ENABLE_MODE_DEFAULT or ENABLE_MODE_TRANSPARENT
+**                  or ENABLE_MODE_EE
+**
+** Returns          none
+**
+*******************************************************************************/
+extern void NFA_SetNfccMode(uint8_t mode);
 
 /*******************************************************************************
 **
@@ -718,6 +736,26 @@ typedef void(tNFA_VSC_CBACK)(uint8_t event, uint16_t param_len,
 *******************************************************************************/
 extern void NFA_Init(tHAL_NFC_ENTRY* p_hal_entry_tbl);
 
+/*******************************************************************************
+**
+** Function         NFA_Partial_Init
+**
+** Description      This function initializes control blocks for NFA based on
+**                  mode
+**
+**                  p_hal_entry_tbl points to a table of HAL entry points
+**                  mode ENABLE_MODE_DEFAULT or ENABLE_MODE_TRANSPARENT
+**                  or ENABLE_MODE_EE
+**
+**                  NOTE: the buffer that p_hal_entry_tbl points must be
+**                  persistent until NFA is disabled.
+**
+**
+** Returns          none
+**
+*******************************************************************************/
+extern void NFA_Partial_Init(tHAL_NFC_ENTRY* p_hal_entry_tbl, uint8_t mode);
+
 /*******************************************************************************
 **
 ** Function         NFA_Enable
@@ -1257,6 +1295,17 @@ extern tNFA_STATUS NFA_SendRawVsCommand(uint8_t cmd_params_len,
 *******************************************************************************/
 extern void NFA_EnableDtamode(tNFA_eDtaModes eDtaMode);
 
+/*******************************************************************************
+**
+** Function:        NFA_DisableDtamode
+**
+** Description:     Disable DTA Mode
+**
+** Returns:         none:
+**
+*******************************************************************************/
+extern void NFA_DisableDtamode(void);
+
 /*******************************************************************************
 ** Function         NFA_GetNCIVersion
 **
diff --git a/src/nfa/include/nfa_sys.h b/src/nfa/include/nfa_sys.h
index 86b428dc..48e506c2 100644
--- a/src/nfa/include/nfa_sys.h
+++ b/src/nfa/include/nfa_sys.h
@@ -118,5 +118,5 @@ extern void nfa_sys_notify_nfcc_power_mode(uint8_t nfcc_power_mode);
 extern void nfa_sys_cback_reg_nfcc_power_mode_proc_complete(
     tNFA_SYS_PROC_NFCC_PWR_MODE_CMPL* p_cback);
 extern void nfa_sys_cback_notify_nfcc_power_mode_proc_complete(uint8_t id);
-
+extern void nfa_sys_cback_notify_partial_enable_complete(uint8_t id);
 #endif /* NFA_SYS_H */
diff --git a/src/nfa/rw/nfa_rw_api.cc b/src/nfa/rw/nfa_rw_api.cc
index 0ea327d9..cfb1f7a0 100644
--- a/src/nfa/rw/nfa_rw_api.cc
+++ b/src/nfa/rw/nfa_rw_api.cc
@@ -344,8 +344,10 @@ tNFA_STATUS NFA_RwLocateTlv(uint8_t tlv_type) {
       p_msg->op = NFA_RW_OP_DETECT_MEM_TLV;
     } else if (tlv_type == TAG_NDEF_TLV) {
       p_msg->op = NFA_RW_OP_DETECT_NDEF;
-    } else
+    } else {
+      GKI_freebuf(p_msg);
       return (NFA_STATUS_FAILED);
+    }
 
     nfa_sys_sendmsg(p_msg);
 
diff --git a/src/nfa/sys/nfa_sys_cback.cc b/src/nfa/sys/nfa_sys_cback.cc
index bf1fd42c..74da1ba5 100644
--- a/src/nfa/sys/nfa_sys_cback.cc
+++ b/src/nfa/sys/nfa_sys_cback.cc
@@ -68,6 +68,23 @@ void nfa_sys_cback_notify_enable_complete(uint8_t id) {
   }
 }
 
+/*******************************************************************************
+**
+** Function         nfa_sys_cback_notify_partial_enable_complete
+**
+** Description      Called by other NFA SYS sub system to notify
+**                  NFC initialisation  is done .
+**
+** Returns          void
+**
+*******************************************************************************/
+void nfa_sys_cback_notify_partial_enable_complete(uint8_t id) {
+  if (nfa_sys_cb.p_enable_cback && id == NFA_ID_SYS) {
+    nfa_sys_cb.p_enable_cback();
+    nfa_sys_cb.p_enable_cback = nullptr;
+  }
+}
+
 /*******************************************************************************
 **
 ** Function         nfa_sys_cback_reg_nfcc_power_mode_proc_complete
diff --git a/src/nfc/include/nfc_int.h b/src/nfc/include/nfc_int.h
index 8140ffb6..67a97035 100644
--- a/src/nfc/include/nfc_int.h
+++ b/src/nfc/include/nfc_int.h
@@ -216,6 +216,8 @@ typedef struct {
 
   TIMER_LIST_ENT nci_mode_set_ntf_timer; /*Mode set notification timer*/
 
+  uint8_t nfcc_mode; /* NFC controller modes */
+
 } tNFC_CB;
 
 /*****************************************************************************
diff --git a/src/nfc/include/rw_int.h b/src/nfc/include/rw_int.h
index 866dd10b..cb4b478b 100644
--- a/src/nfc/include/rw_int.h
+++ b/src/nfc/include/rw_int.h
@@ -638,6 +638,8 @@ typedef struct {
 #define MFC_NDEF_DETECTED 0x01
 #define MFC_NDEF_READ 0x02
 
+#define MFC_MAX_SECTOR_NUMBER 40
+#define MFC_LAST_4BLOCK_SECTOR 32
 typedef uint8_t tRW_MFC_RW_STATE;
 typedef uint8_t tRW_MFC_RW_SUBSTATE;
 typedef struct {
@@ -666,6 +668,8 @@ typedef struct {
   NFC_HDR* p_cur_cmd_buf; /* Copy of current command, for retx/send after sector
                              change */
 
+  bool mifare_ndefsector[MFC_MAX_SECTOR_NUMBER]; /* buffer to check ndef
+                                                    compatible sector */
   uint8_t ndef_status; /* bitmap for NDEF status */
 } tRW_MFC_CB;
 
diff --git a/src/nfc/include/tags_defs.h b/src/nfc/include/tags_defs.h
index b9567b6d..6cb5ef3a 100644
--- a/src/nfc/include/tags_defs.h
+++ b/src/nfc/include/tags_defs.h
@@ -695,6 +695,13 @@ typedef uint8_t tT3T_POLL_RC;
  * or 0x200
  */
 #define I93_IC_REF_STM_ST25DVHIK 0x26
+/* IC Reference for ST25TV04K: 00110101(b), blockSize: 4, numberBlocks: 0x0200
+ */
+#define I93_IC_REF_STM_ST25TV04K_E 0x35
+/* IC Reference for ST25TV16K: 01001000(b), blockSize: 4, numberBlocks: 0x1000
+ * IC Reference for ST25TV64K: 01001000(b), blockSize: 4, numberBlocks: 0x4000
+ */
+#define I93_IC_REF_STM_ST25TV16K_64K 0x48
 
 /* Product code family for LRI2K */
 #define I93_PROD_CODE_STM_LRI2K_MASK I93_IC_REF_STM_LRI2K /* 0x20 */
@@ -710,6 +717,8 @@ typedef uint8_t tT3T_POLL_RC;
 #define I93_PROD_CODE_STM_M24LR16E_R_MASK 0x4C
 /* Product code family for M24LR64E_R */
 #define I93_PROD_CODE_STM_M24LR64E_R_MASK 0x5C
+/* Product code family for ST25DV04K/16K/64K */
+#define I93_PROD_CODE_STM_ST25DV_K_MASK I93_IC_REF_STM_ST25DV04K
 
 /* ONS, product version (IC manufacturer code) */
 /* IC Reference for N36RW02:  00011010(b), blockSize: 4, numberBlocks: 0x40 */
diff --git a/src/nfc/nfc/nfc_main.cc b/src/nfc/nfc/nfc_main.cc
index 2ec08806..996cc6d4 100644
--- a/src/nfc/nfc/nfc_main.cc
+++ b/src/nfc/nfc/nfc_main.cc
@@ -32,6 +32,7 @@
 #include "ce_int.h"
 #include "gki.h"
 #include "nci_hmsgs.h"
+#include "nfa_sys.h"
 #include "nfc_int.h"
 #include "nfc_target.h"
 #include "rw_int.h"
@@ -436,7 +437,10 @@ void nfc_main_handle_hal_evt(tNFC_HAL_EVT_MSG* p_msg) {
       break;
 
     case HAL_NFC_POST_INIT_CPLT_EVT:
-      if (nfc_cb.p_nci_init_rsp) {
+      if (nfc_cb.nfcc_mode == ENABLE_MODE_TRANSPARENT) {
+        nfc_set_state(NFC_STATE_IDLE);
+        nfa_sys_cback_notify_partial_enable_complete(NFA_ID_SYS);
+      } else if (nfc_cb.p_nci_init_rsp) {
         /*
         ** if NFC_Disable() is called before receiving
         ** HAL_NFC_POST_INIT_CPLT_EVT, then wait for HAL_NFC_CLOSE_CPLT_EVT.
diff --git a/src/nfc/nfc/nfc_ncif.cc b/src/nfc/nfc/nfc_ncif.cc
index 4f33a3de..9224d386 100644
--- a/src/nfc/nfc/nfc_ncif.cc
+++ b/src/nfc/nfc/nfc_ncif.cc
@@ -61,9 +61,6 @@ extern std::string nfc_storage_path;
 static struct timeval timer_start;
 static struct timeval timer_end;
 
-#define DEFAULT_CRASH_NFCSNOOP_PATH "/data/misc/nfc/logs/native_crash_logs"
-static const off_t NATIVE_CRASH_FILE_SIZE = (1024 * 1024);
-
 /*******************************************************************************
 **
 ** Function         nfc_ncif_update_window
@@ -384,6 +381,11 @@ bool nfc_ncif_process_event(NFC_HDR* p_msg) {
   uint16_t len;
   uint8_t *p_old, old_gid, old_oid, old_mt;
 
+  /* ignore all data while shutting down NFCC */
+  if (nfc_cb.nfc_state == NFC_STATE_W4_HAL_CLOSE) {
+    return free;
+  }
+
   p = (uint8_t*)(p_msg + 1) + p_msg->offset;
 
   if (p_msg->len < 3) {
@@ -677,9 +679,6 @@ uint8_t* nfc_ncif_decode_rf_params(tNFC_RF_TECH_PARAMS* p_param, uint8_t* p) {
   tNFC_RF_LF_PARAMS* p_lf;
   tNFC_RF_PF_PARAMS* p_pf;
   tNFC_RF_PISO15693_PARAMS* p_i93;
-  tNFC_RF_ACM_P_PARAMS* acm_p;
-  uint8_t mpl_idx = 0;
-  uint8_t gb_idx = 0, mpl;
   uint8_t plen;
   plen = len = *p++;
   p_start = p;
@@ -1783,6 +1782,10 @@ void nfc_data_event(tNFC_CONN_CB* p_cb) {
       }
 
       p_evt = (NFC_HDR*)GKI_dequeue(&p_cb->rx_q);
+      if (p_evt == nullptr) {
+        LOG(ERROR) << StringPrintf("%s; p_evt is null", __func__);
+        return;
+      }
       /* report data event */
       p_evt->offset += NCI_MSG_HDR_SIZE;
       p_evt->len -= NCI_MSG_HDR_SIZE;
diff --git a/src/nfc/tags/rw_i93.cc b/src/nfc/tags/rw_i93.cc
index c2af4797..e2639f79 100644
--- a/src/nfc/tags/rw_i93.cc
+++ b/src/nfc/tags/rw_i93.cc
@@ -30,6 +30,7 @@
 
 #include "bt_types.h"
 #include "nfc_api.h"
+#include "nfc_config.h"
 #include "nfc_int.h"
 #include "nfc_target.h"
 #include "rw_api.h"
@@ -39,6 +40,7 @@ using android::base::StringPrintf;
 using com::android::nfc::nci::flags::t5t_no_getsysinfo;
 
 extern unsigned char appl_dta_mode_flag;
+extern unsigned int t5t_mute_legacy;
 
 /* Response timeout     */
 #define RW_I93_TOUT_RESP 1000
@@ -4312,6 +4314,7 @@ tNFC_STATUS RW_I93PresenceCheck(void) {
 **
 *****************************************************************************/
 bool RW_I93CheckLegacyProduct(uint8_t ic_manuf, uint8_t pdt_code) {
+  if (t5t_mute_legacy) return false;
   if (appl_dta_mode_flag) return false;
   if (!t5t_no_getsysinfo()) return true;
   LOG(VERBOSE) << StringPrintf("%s - IC manufacturer:0x%x, Product code:0x%x",
@@ -4325,6 +4328,14 @@ bool RW_I93CheckLegacyProduct(uint8_t ic_manuf, uint8_t pdt_code) {
   }
 
   if (ic_manuf == I93_UID_IC_MFG_CODE_STM) {
+    switch (pdt_code) {
+      case I93_IC_REF_STM_ST25TV16K_64K:
+      case I93_IC_REF_STM_ST25TV04K_E:
+        LOG(VERBOSE) << StringPrintf("%s - ISO 15693 legacy product detected",
+                                     __func__);
+        return true;
+    }
+
     pdt_code_family = pdt_code & I93_IC_REF_STM_MASK;
     switch (pdt_code_family) {
       case I93_IC_REF_STM_LRI1K:
@@ -4335,6 +4346,7 @@ bool RW_I93CheckLegacyProduct(uint8_t ic_manuf, uint8_t pdt_code) {
       case I93_PROD_CODE_STM_M24LR16E_R_MASK:
       case I93_PROD_CODE_STM_M24LR64_R_MASK:
       case I93_PROD_CODE_STM_M24LR64E_R_MASK:
+      case I93_PROD_CODE_STM_ST25DV_K_MASK:
         LOG(VERBOSE) << StringPrintf("%s - ISO 15693 legacy product detected",
                                    __func__);
         return true;
diff --git a/src/nfc/tags/rw_mfc.cc b/src/nfc/tags/rw_mfc.cc
index 6d6b46ad..554403c8 100644
--- a/src/nfc/tags/rw_mfc.cc
+++ b/src/nfc/tags/rw_mfc.cc
@@ -22,6 +22,7 @@
  ******************************************************************************/
 #include <android-base/logging.h>
 #include <android-base/stringprintf.h>
+#include <com_android_nfc_nci_flags.h>
 #include <log/log.h>
 #include <string.h>
 
@@ -34,6 +35,8 @@
 #include "rw_int.h"
 #include "tags_int.h"
 
+using com::android::nfc::nci::flags::mfc_read_mad;
+
 #define MFC_KeyA 0x60
 #define MFC_KeyB 0x61
 #define MFC_Read 0x30
@@ -59,6 +62,7 @@
 /* NDef Format */
 #define RW_MFC_STATE_NDEF_FORMAT 0x8
 
+#define RW_MFC_STATE_DETECT_MAD 0x09
 #define RW_MFC_SUBSTATE_NONE 0x00
 #define RW_MFC_SUBSTATE_IDLE 0x01
 #define RW_MFC_SUBSTATE_WAIT_ACK 0x02
@@ -108,6 +112,9 @@ static void rw_mfc_handle_format_op();
 static tNFC_STATUS rw_mfc_writeBlock(int block);
 static void rw_mfc_handle_write_rsp(uint8_t* p_data);
 static void rw_mfc_handle_write_op();
+static tNFC_STATUS rw_MfcCheckMad();
+static void rw_mfc_handle_mad_detect_rsp(uint8_t* p_data);
+static bool rw_nfc_StoreMad(uint8_t* data);
 
 using android::base::StringPrintf;
 
@@ -194,16 +201,20 @@ static tNFC_STATUS rw_mfc_formatBlock(int block) {
 
   if (block == 1) {
     ARRAY_TO_BE_STREAM(p, MAD_B1, 16);
-  } else if (block == 2 || block == 65 || block == 66) {
+  } else if (block == 64) {
+    if (mfc_read_mad()) {
+      ARRAY_TO_BE_STREAM(p, MAD_B1, 16);
+    } else {
+      ARRAY_TO_BE_STREAM(p, MAD_B64, 16);
+    }
+  } else if ((block == 2) || (block == 65) || (block == 66)) {
     ARRAY_TO_BE_STREAM(p, MAD_B2, 16);
-  } else if (block == 3 || block == 67) {
+  } else if ((block == 3) || (block == 67)) {
     ARRAY_TO_BE_STREAM(p, KeyMAD, 6);
     ARRAY_TO_BE_STREAM(p, access_permission_mad, 4);
     ARRAY_TO_BE_STREAM(p, KeyDefault, 6);
   } else if (block == 4) {
     ARRAY_TO_BE_STREAM(p, NFC_B0, 16);
-  } else if (block == 64) {
-    ARRAY_TO_BE_STREAM(p, MAD_B64, 16);
   } else {
     ARRAY_TO_BE_STREAM(p, KeyNDEF, 6);
     ARRAY_TO_BE_STREAM(p, access_permission_nfc, 4);
@@ -237,7 +248,9 @@ static void rw_mfc_handle_format_rsp(uint8_t* p_data) {
         p_mfc->next_block.auth = true;
         p_mfc->last_block_accessed.auth = true;
 
-        if (p_mfc->next_block.block < 128) {
+        if (mfc_read_mad() && p_mfc->current_block < 127) {
+          p_mfc->sector_authentified = p_mfc->next_block.block / 4;
+        } else if (!mfc_read_mad() && p_mfc->next_block.block < 128) {
           p_mfc->sector_authentified = p_mfc->next_block.block / 4;
         } else {
           p_mfc->sector_authentified =
@@ -322,14 +335,39 @@ tNFC_STATUS RW_MfcWriteNDef(uint16_t buf_len, uint8_t* p_buffer) {
   tRW_MFC_CB* p_mfc = &rw_cb.tcb.mfc;
   tNFC_STATUS status = NFC_STATUS_OK;
 
+  int i = 0;
   if (p_mfc->state != RW_MFC_STATE_IDLE) {
     return NFC_STATUS_BUSY;
   }
 
   p_mfc->state = RW_MFC_STATE_UPDATE_NDEF;
   p_mfc->substate = RW_MFC_SUBSTATE_NONE;
-  p_mfc->last_block_accessed.block = 4;
-  p_mfc->next_block.block = 4;
+  if (mfc_read_mad()) {
+    for (i = 0; i < MFC_MAX_SECTOR_NUMBER; i++) {
+      // Search the 1st NDEF sector
+      if (p_mfc->mifare_ndefsector[i] == true) {
+        break;
+      }
+    }
+    if (i < MFC_LAST_4BLOCK_SECTOR) {
+      // Block of the 1st NDEF sector, if in the 4-blocks sector area
+      p_mfc->last_block_accessed.block = i * 4;  // 4 blocks per sector
+      p_mfc->next_block.block = i * 4;           // 4 blocks per sector
+    } else {
+      // block is in the 16blocks per sector area:
+      //  - skip the 4blocks * MFC_LAST_4BLOCK_SECTOR ( = 128 )
+      //  - then add 16 blocks for each additional sector
+      p_mfc->last_block_accessed.block =
+          (4 * MFC_LAST_4BLOCK_SECTOR) + (i - MFC_LAST_4BLOCK_SECTOR) * 16;
+      p_mfc->next_block.block =
+          (4 * MFC_LAST_4BLOCK_SECTOR) + (i - MFC_LAST_4BLOCK_SECTOR) * 16;
+    }
+    LOG(DEBUG) << __func__
+               << "; first ndef block : " << p_mfc->next_block.block;
+  } else {
+    p_mfc->last_block_accessed.block = 4;
+    p_mfc->next_block.block = 4;
+  }
 
   p_mfc->p_ndef_buffer = p_buffer;
   p_mfc->ndef_length = buf_len;
@@ -389,7 +427,7 @@ static tNFC_STATUS rw_mfc_writeBlock(int block) {
   int index = 0;
   while (index < RW_MFC_1K_BLOCK_SIZE) {
     if (p_mfc->work_offset == 0) {
-      if (p_mfc->ndef_length < 0xFF) {
+      if (p_mfc->ndef_length <= 0xFE) {
         UINT8_TO_BE_STREAM(p, 0x03);
         UINT8_TO_BE_STREAM(p, p_mfc->ndef_length);
         index = index + 2;
@@ -440,7 +478,9 @@ static void rw_mfc_handle_write_rsp(uint8_t* p_data) {
         p_mfc->next_block.auth = true;
         p_mfc->last_block_accessed.auth = true;
 
-        if (p_mfc->next_block.block < 128) {
+        if (mfc_read_mad() && p_mfc->current_block < 128) {
+          p_mfc->sector_authentified = p_mfc->next_block.block / 4;
+        } else if (!mfc_read_mad() && p_mfc->next_block.block < 128) {
           p_mfc->sector_authentified = p_mfc->next_block.block / 4;
         } else {
           p_mfc->sector_authentified =
@@ -526,8 +566,12 @@ static void rw_mfc_handle_write_op() {
  **
  *****************************************************************************/
 tNFC_STATUS RW_MfcDetectNDef(void) {
-  LOG(ERROR) << __func__;
-  return rw_MfcLocateTlv(TAG_NDEF_TLV);
+  LOG(DEBUG) << __func__;
+  if (mfc_read_mad()) {
+    return rw_MfcCheckMad();
+  } else {
+    return rw_MfcLocateTlv(TAG_NDEF_TLV);
+  }
 }
 
 /*******************************************************************************
@@ -559,13 +603,20 @@ tNFC_STATUS rw_mfc_select(uint8_t selres, uint8_t uid[MFC_UID_LEN]) {
   p_mfc->selres = selres;
   memcpy(p_mfc->uid, uid, MFC_UID_LEN);
 
+  if (mfc_read_mad()) {
+    memset(p_mfc->mifare_ndefsector, 0, 40);
+  }
   NFC_SetStaticRfCback(rw_mfc_conn_cback);
 
   p_mfc->state = RW_MFC_STATE_IDLE;
   p_mfc->substate = RW_MFC_SUBSTATE_IDLE;
   p_mfc->last_block_accessed.block = -1;
   p_mfc->last_block_accessed.auth = false;
-  p_mfc->next_block.block = 4;
+  if (mfc_read_mad()) {
+    p_mfc->next_block.block = 1;
+  } else {
+    p_mfc->next_block.block = 4;
+  }
   p_mfc->next_block.auth = false;
   p_mfc->sector_authentified = -1;
 
@@ -666,7 +717,7 @@ static void rw_mfc_conn_cback(uint8_t conn_id, tNFC_CONN_EVT event,
 
       p_mfc->state = RW_MFC_STATE_NOT_ACTIVATED;
       NFC_SetStaticRfCback(NULL);
-      break;
+      return;
 
     case NFC_DATA_CEVT:
       if ((p_data != NULL) && (p_data->data.status == NFC_STATUS_OK)) {
@@ -676,7 +727,6 @@ static void rw_mfc_conn_cback(uint8_t conn_id, tNFC_CONN_EVT event,
       /* Data event with error status...fall through to NFC_ERROR_CEVT case */
       FALLTHROUGH_INTENDED;
     case NFC_ERROR_CEVT:
-
       if ((p_mfc->state == RW_MFC_STATE_NOT_ACTIVATED) ||
           (p_mfc->state == RW_MFC_STATE_IDLE)) {
         if (event == NFC_ERROR_CEVT) {
@@ -715,6 +765,10 @@ static void rw_mfc_conn_cback(uint8_t conn_id, tNFC_CONN_EVT event,
         GKI_freebuf(mfc_data);
       }
       break;
+    case RW_MFC_STATE_DETECT_MAD:
+      rw_mfc_handle_mad_detect_rsp((uint8_t*)mfc_data);
+      GKI_freebuf(mfc_data);
+      break;
     case RW_MFC_STATE_DETECT_TLV:
       rw_mfc_handle_tlv_detect_rsp((uint8_t*)mfc_data);
       GKI_freebuf(mfc_data);
@@ -743,6 +797,46 @@ static void rw_mfc_conn_cback(uint8_t conn_id, tNFC_CONN_EVT event,
   }
 }
 
+/*******************************************************************************
+ **
+ ** Function         rw_MfcCheckMad
+ **
+ ** Description      This function checks the MAD sectors for NDEF capability.
+ **
+ **
+ ** Returns          NFC_STATUS_OK if success
+ **                  NFC_STATUS_FAILED if Mifare classic tag is busy or other
+ **                  error
+ **
+ *******************************************************************************/
+static tNFC_STATUS rw_MfcCheckMad() {
+  LOG(DEBUG) << __func__;
+
+  tRW_MFC_CB* p_mfc = &rw_cb.tcb.mfc;
+  tNFC_STATUS success = NFC_STATUS_OK;
+
+  if (p_mfc->state != RW_MFC_STATE_IDLE) {
+    LOG(ERROR) << __func__
+               << "; Mifare Classic tag not activated or Busy - State:"
+               << p_mfc->state;
+    return NFC_STATUS_BUSY;
+  }
+  p_mfc->next_block.block = 1;
+  p_mfc->substate = RW_MFC_SUBSTATE_READ_BLOCK;
+  p_mfc->state = RW_MFC_STATE_DETECT_MAD;
+  // MAD1 block
+  success = rw_mfc_readBlock(p_mfc->next_block.block);
+  if (success == NFC_STATUS_OK) {
+    p_mfc->state = RW_MFC_STATE_DETECT_MAD;
+    LOG(DEBUG) << __func__
+               << "; RW_MFC_STATE_DETECT_TLV state=" << p_mfc->state;
+  } else {
+    p_mfc->substate = RW_MFC_SUBSTATE_NONE;
+    LOG(DEBUG) << __func__ << "; rw_MfcLocateTlv state=" << p_mfc->state;
+  }
+
+  return NFC_STATUS_OK;
+}
 /*******************************************************************************
  **
  ** Function         rw_MfcLocateTlv
@@ -761,13 +855,22 @@ static tNFC_STATUS rw_MfcLocateTlv(uint8_t tlv_type) {
 
   tRW_MFC_CB* p_mfc = &rw_cb.tcb.mfc;
   tNFC_STATUS success = NFC_STATUS_OK;
+  if (mfc_read_mad()) {
+    if (p_mfc->state != RW_MFC_STATE_DETECT_MAD) {
+      LOG(ERROR) << StringPrintf(
+          "%s Mifare Classic tag not activated or Busy - State:%d", __func__,
+          p_mfc->state);
 
-  if (p_mfc->state != RW_MFC_STATE_IDLE) {
-    LOG(ERROR) << StringPrintf(
-        "%s Mifare Classic tag not activated or Busy - State:%d", __func__,
-        p_mfc->state);
+      return NFC_STATUS_BUSY;
+    }
+  } else {
+    if (p_mfc->state != RW_MFC_STATE_IDLE) {
+      LOG(ERROR) << StringPrintf(
+          "%s Mifare Classic tag not activated or Busy - State:%d", __func__,
+          p_mfc->state);
 
-    return NFC_STATUS_BUSY;
+      return NFC_STATUS_BUSY;
+    }
   }
 
   if ((tlv_type != TAG_LOCK_CTRL_TLV) && (tlv_type != TAG_MEM_CTRL_TLV) &&
@@ -783,7 +886,14 @@ static tNFC_STATUS rw_MfcLocateTlv(uint8_t tlv_type) {
     p_mfc->work_offset = 0;
     p_mfc->ndef_status = MFC_NDEF_NOT_DETECTED;
   }
-
+  if (mfc_read_mad()) {
+    for (int i = 0; i < 40; i++) {
+      if (p_mfc->mifare_ndefsector[i] == true) {
+        p_mfc->next_block.block = 4 * i;
+        break;
+      }
+    }
+  }
   p_mfc->substate = RW_MFC_SUBSTATE_READ_BLOCK;
   p_mfc->state = RW_MFC_STATE_DETECT_TLV;
 
@@ -842,10 +952,19 @@ static bool rw_mfc_authenticate(int block, bool KeyA) {
   if (p_mfc->state == RW_MFC_STATE_NDEF_FORMAT)
     KeyToUse = KeyDefault;
   else {
-    if (block >= 0 && block < 4) {
-      KeyToUse = KeyMAD;
+    if (mfc_read_mad()) {
+      // support large memory size mapping
+      if ((block >= 0 && block < 4) || (block >= 64 && block < 68)) {
+        KeyToUse = KeyMAD;
+      } else {
+        KeyToUse = KeyNDEF;
+      }
     } else {
-      KeyToUse = KeyNDEF;
+      if ((block >= 0 && block < 4)) {
+        KeyToUse = KeyMAD;
+      } else {
+        KeyToUse = KeyNDEF;
+      }
     }
   }
   ARRAY_TO_BE_STREAM(p, KeyToUse, 6);
@@ -886,7 +1005,7 @@ static tNFC_STATUS rw_mfc_readBlock(int block) {
 
   if (sectorlength != p_mfc->sector_authentified) {
     if (rw_mfc_authenticate(block, true) == true) {
-      LOG(ERROR) << __func__ << ": RW_MFC_SUBSTATE_WAIT_ACK";
+      LOG(DEBUG) << __func__ << ": RW_MFC_SUBSTATE_WAIT_ACK";
       return NFC_STATUS_OK;
     }
     return NFC_STATUS_FAILED;
@@ -915,6 +1034,58 @@ static tNFC_STATUS rw_mfc_readBlock(int block) {
 
   return status;
 }
+/*******************************************************************************
+ **
+ ** Function         rw_mfc_handle_mad_detect_rsp
+ **
+ ** Description      Handle MAD detection.
+ **
+ ** Returns          none
+ **
+ *******************************************************************************/
+static void rw_mfc_handle_mad_detect_rsp(uint8_t* p_data) {
+  tRW_MFC_CB* p_mfc = &rw_cb.tcb.mfc;
+  NFC_HDR* mfc_data;
+  uint8_t* p;
+
+  mfc_data = (NFC_HDR*)p_data;
+  /* Assume the data is just the response byte sequence */
+  p = (uint8_t*)(mfc_data + 1) + mfc_data->offset;
+
+  p_mfc->last_block_accessed.block = p_mfc->next_block.block;
+  switch (p_mfc->substate) {
+    case RW_MFC_SUBSTATE_WAIT_ACK:
+      /* Search for the tlv */
+      if (p[0] == 0x0) {
+        p_mfc->next_block.auth = true;
+        p_mfc->last_block_accessed.auth = true;
+        p_mfc->sector_authentified = p_mfc->next_block.block / 4;
+
+        rw_mfc_resume_op();
+      } else {
+        p_mfc->next_block.auth = false;
+        p_mfc->last_block_accessed.auth = false;
+        LOG(DEBUG) << __func__ << "; status=" << p[0];
+        nfc_stop_quick_timer(&p_mfc->timer);
+        rw_mfc_process_error();
+      }
+      break;
+
+    case RW_MFC_SUBSTATE_READ_BLOCK:
+      /* Search for the tlv */
+      if (mfc_data->len == 0x10) {
+        p_mfc->last_block_accessed.block = p_mfc->next_block.block;
+        p_mfc->next_block.block += 1;
+        p_mfc->next_block.auth = false;
+        rw_mfc_handle_read_op((uint8_t*)mfc_data);
+      } else if (mfc_read_mad()) {
+        LOG(DEBUG) << __func__ << "; inval len status=" << p[0];
+        nfc_stop_quick_timer(&p_mfc->timer);
+        rw_mfc_process_error();
+      }
+      break;
+  }
+}
 
 /*******************************************************************************
  **
@@ -960,6 +1131,10 @@ static void rw_mfc_handle_tlv_detect_rsp(uint8_t* p_data) {
         p_mfc->next_block.block += 1;
         p_mfc->next_block.auth = false;
         rw_mfc_handle_read_op((uint8_t*)mfc_data);
+      } else if (mfc_read_mad()) {
+        LOG(DEBUG) << __func__ << "; inval len status=" << p[0];
+        nfc_stop_quick_timer(&p_mfc->timer);
+        rw_mfc_process_error();
       }
       break;
   }
@@ -978,17 +1153,30 @@ static void rw_mfc_resume_op() {
   tRW_MFC_CB* p_mfc = &rw_cb.tcb.mfc;
 
   switch (p_mfc->state) {
+    case RW_MFC_STATE_DETECT_MAD:
+      if (rw_mfc_readBlock(p_mfc->next_block.block) != NFC_STATUS_OK) {
+        LOG(ERROR) << __func__ << "; Error calling rw_mfc_readBlock()";
+      }
+      break;
     case RW_MFC_STATE_DETECT_TLV:
-      rw_mfc_readBlock(p_mfc->next_block.block);
+      if (rw_mfc_readBlock(p_mfc->next_block.block) != NFC_STATUS_OK) {
+        LOG(ERROR) << __func__ << "; Error calling rw_mfc_readBlock()";
+      }
       break;
     case RW_MFC_STATE_READ_NDEF:
-      rw_mfc_readBlock(p_mfc->next_block.block);
+      if (rw_mfc_readBlock(p_mfc->next_block.block) != NFC_STATUS_OK) {
+        LOG(ERROR) << __func__ << "; Error calling rw_mfc_readBlock()";
+      }
       break;
     case RW_MFC_STATE_NDEF_FORMAT:
-      rw_mfc_formatBlock(p_mfc->next_block.block);
+      if (rw_mfc_formatBlock(p_mfc->next_block.block) != NFC_STATUS_OK) {
+        LOG(ERROR) << __func__ << "; Error calling rw_mfc_formatBlock()";
+      }
       break;
     case RW_MFC_STATE_UPDATE_NDEF:
-      rw_mfc_writeBlock(p_mfc->next_block.block);
+      if (rw_mfc_writeBlock(p_mfc->next_block.block) != NFC_STATUS_OK) {
+        LOG(ERROR) << __func__ << "; Error calling rw_mfc_writeBlock()";
+      }
       break;
   }
 }
@@ -1018,12 +1206,59 @@ static void rw_mfc_handle_read_op(uint8_t* data) {
   p = (uint8_t*)(mfc_data + 1) + mfc_data->offset;
 
   switch (p_mfc->state) {
+    case RW_MFC_STATE_DETECT_MAD:
+      rw_nfc_StoreMad(data);
+      if (p_mfc->current_block == 1 || p_mfc->current_block == 64 ||
+          p_mfc->current_block ==
+              65) {  // need to read next block (2 or 65 or 66)
+        if (rw_mfc_readBlock(p_mfc->next_block.block) != NFC_STATUS_OK) {
+          failed = true;
+          LOG(DEBUG) << __func__ << "; FAILED reading next";
+        }
+      } else if (p_mfc->current_block == 2 &&  // 2 is last block of MAD1
+                 !(p_mfc->selres & RW_MFC_4K_Support)) {
+        LOG(DEBUG) << __func__ << "; Finished reading the MAD1 sector";
+        for (int k = 0; k < 16; k++) {
+          LOG(DEBUG) << __func__ << "; k= " << k
+                     << " value = " << p_mfc->mifare_ndefsector[k];
+        }
+        rw_MfcLocateTlv(TAG_NDEF_TLV);
+
+      } else if (p_mfc->current_block == 2 &&  // 2 is last block of MAD1
+                 (p_mfc->selres & RW_MFC_4K_Support)) {
+        p_mfc->next_block.block = 64;
+        if (rw_mfc_readBlock(p_mfc->next_block.block) != NFC_STATUS_OK) {
+          failed = true;
+          LOG(DEBUG) << __func__ << "; FAILED reading next";
+        }
+      } else if (p_mfc->current_block == 66) {  // 66 is last block of MAD2
+        LOG(DEBUG) << __func__ << "; Finished reading the MAD1 & MAD2 sectors";
+        for (int k = 0; k < 40; k++) {
+          LOG(DEBUG) << __func__ << "; k= " << k
+                     << " value = " << p_mfc->mifare_ndefsector[k];
+        }
+        rw_MfcLocateTlv(TAG_NDEF_TLV);
+      }
+
+      break;
     case RW_MFC_STATE_DETECT_TLV:
       tlv_found = rw_nfc_decodeTlv(data);
       if (tlv_found) {
         p_mfc->ndef_status = MFC_NDEF_DETECTED;
         p_mfc->ndef_first_block = p_mfc->last_block_accessed.block;
         rw_mfc_ntf_tlv_detect_complete(NFC_STATUS_OK);
+      } else if (mfc_read_mad()) {
+        tRW_DETECT_NDEF_DATA ndef_data;
+        ndef_data.status = NFC_STATUS_FAILED;
+        ndef_data.protocol = NFC_PROTOCOL_MIFARE;
+        ndef_data.flags = RW_NDEF_FL_UNKNOWN;
+        ndef_data.max_size = 0;
+        ndef_data.cur_size = 0;
+        LOG(DEBUG) << __func__ << "; status=NFC_STATUS_FAILED";
+        /* If not Halt move to idle state */
+        rw_mfc_handle_op_complete();
+
+        (*rw_cb.p_cback)(RW_MFC_NDEF_DETECT_EVT, (tRW_DATA*)&ndef_data);
       }
       break;
 
@@ -1076,6 +1311,51 @@ static void rw_mfc_handle_read_op(uint8_t* data) {
       break;
   }
 }
+/*******************************************************************************
+ **
+ ** Function         rw_nfc_StoreMad
+ **
+ ** Description      Store the MAD data in the Mifare Classic tag
+ **
+ ** Returns          true if success
+ **
+ *******************************************************************************/
+static bool rw_nfc_StoreMad(uint8_t* data) {
+  tRW_MFC_CB* p_mfc = &rw_cb.tcb.mfc;
+  NFC_HDR* mfc_data;
+  uint8_t* p;
+  uint8_t start_position = 1;
+  uint8_t start_block = 0;
+  mfc_data = (NFC_HDR*)data;
+  p = (uint8_t*)(mfc_data + 1) + mfc_data->offset;
+  int i = 0;
+
+  switch (p_mfc->current_block) {
+    case 2:
+      start_position = 0;
+      start_block = 8;
+      break;
+    case 64:
+      start_position = 1;
+      start_block = 16;
+      break;
+    case 65:
+      start_position = 0;
+      start_block = 24;
+      break;
+    case 66:
+      start_position = 0;
+      start_block = 32;
+      break;
+  }
+
+  for (i = start_position; i < 8; i++) {
+    if ((p[2 * i] == 0x03) && (p[2 * i + 1] == 0xE1))
+      p_mfc->mifare_ndefsector[i + start_block] = true;
+  }
+  return true;
+}
+
 /*******************************************************************************
  **
  ** Function         rw_nfc_decodeTlv
@@ -1159,10 +1439,11 @@ static void rw_mfc_ntf_tlv_detect_complete(tNFC_STATUS status) {
 
     // TODO - calculate max size based on MAD sectr NFC_AID condition
     // Set max size as format condition
-    if (p_mfc->selres & RW_MFC_4K_Support)
-      ndef_data.max_size = 3356;
-    else
+    if (p_mfc->selres & RW_MFC_4K_Support) {
+      ndef_data.max_size = mfc_read_mad() ? 3360 : 3356;
+    } else {
       ndef_data.max_size = 716;
+    }
 
     rw_mfc_handle_op_complete();
     (*rw_cb.p_cback)(RW_MFC_NDEF_DETECT_EVT, (tRW_DATA*)&ndef_data);
@@ -1298,6 +1579,11 @@ static void rw_mfc_handle_ndef_read_rsp(uint8_t* p_data) {
       } else {
         p_mfc->next_block.auth = false;
         p_mfc->last_block_accessed.auth = false;
+        if (mfc_read_mad()) {
+          LOG(DEBUG) << __func__ << "; status=" << p[0];
+          nfc_stop_quick_timer(&p_mfc->timer);
+          rw_mfc_process_error();
+        }
       }
       break;
 
@@ -1329,6 +1615,10 @@ static void rw_mfc_handle_ndef_read_rsp(uint8_t* p_data) {
 
         p_mfc->next_block.auth = false;
         rw_mfc_handle_read_op((uint8_t*)mfc_data);
+      } else if (mfc_read_mad()) {
+        LOG(DEBUG) << __func__ << "; inval len status=" << p[0];
+        nfc_stop_quick_timer(&p_mfc->timer);
+        rw_mfc_process_error();
       }
       break;
   }
diff --git a/src/nfc/tags/rw_t4t.cc b/src/nfc/tags/rw_t4t.cc
index 58010d62..cc0f8c56 100644
--- a/src/nfc/tags/rw_t4t.cc
+++ b/src/nfc/tags/rw_t4t.cc
@@ -898,6 +898,7 @@ static bool rw_t4t_read_file(uint32_t offset, uint32_t length,
     } else {
       LOG(ERROR) << StringPrintf("%s - Cannot read above 0x7FFF for MV2.0",
                                  __func__);
+      GKI_freebuf(p_c_apdu);
       return false;
     }
   } else {
@@ -1010,6 +1011,7 @@ static bool rw_t4t_update_file(void) {
   if (length == 0) {
     LOG(ERROR) << StringPrintf("%s - Length to write can not be null",
                                __func__);
+    GKI_freebuf(p_c_apdu);
     return false;
   }
 
@@ -1034,6 +1036,7 @@ static bool rw_t4t_update_file(void) {
     } else {
       LOG(ERROR) << StringPrintf("%s - Cannot write above 0x7FFF for MV2.0",
                                  __func__);
+      GKI_freebuf(p_c_apdu);
       return false;
     }
   } else {
@@ -1174,6 +1177,7 @@ static bool rw_t4t_select_application(uint8_t version) {
 
     p_c_apdu->len = T4T_CMD_MAX_HDR_SIZE + T4T_V20_NDEF_TAG_AID_LEN + 1;
   } else {
+    GKI_freebuf(p_c_apdu);
     return false;
   }
 
@@ -1837,6 +1841,10 @@ static void rw_t4t_sm_read_ndef(NFC_HDR* p_r_apdu) {
   uint16_t r_apdu_len;
   tRW_DATA rw_data;
 
+  if (p_r_apdu == nullptr) {
+    LOG(ERROR) << StringPrintf("%s; p_r_apdu is null, exiting", __func__);
+    return;
+  }
   LOG(VERBOSE) << StringPrintf(
       "%s - sub_state:%s (%d)", __func__,
       rw_t4t_get_sub_state_name(p_t4t->sub_state).c_str(), p_t4t->sub_state);
@@ -1916,7 +1924,7 @@ static void rw_t4t_sm_read_ndef(NFC_HDR* p_r_apdu) {
             /* Content read length coded over 2 bytes in 2nd and 3rd bytes
              * of BER-TLV length field*/
             r_apdu_len = (uint16_t)(*(p + 2) << 8);
-            r_apdu_len |= (uint8_t) * (p + 3);
+            r_apdu_len |= (uint16_t) * (p + 3);
             if (r_apdu_len <= (p_t4t->max_read_size - 4)) {
               p_r_apdu->len -= 4;
               p_r_apdu->offset += 4;
diff --git a/tools/casimir/src/controller.rs b/tools/casimir/src/controller.rs
index 0911d4f0..b7f67a5b 100644
--- a/tools/casimir/src/controller.rs
+++ b/tools/casimir/src/controller.rs
@@ -1643,7 +1643,8 @@ impl<'a> Controller<'a> {
                     })
                     .await?
                 }
-                rf::Technology::NfcB => todo!(),
+                // TODO(b/346715736) implement support for NFC-B technology
+                rf::Technology::NfcB => (),
                 rf::Technology::NfcF => todo!(),
                 _ => (),
             }
```

